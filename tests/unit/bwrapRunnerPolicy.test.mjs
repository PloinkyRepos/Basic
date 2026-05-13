// Focused tests for the bwrap-runner policy/wrapper. The wrapper builds bwrap
// argv from a typed policy object and validates user-supplied input. These
// tests cover the safety-critical behaviours that v1 must hold.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
    POLICY_LIMITS,
    buildBwrapArgs,
    decideNetworkPolicy,
    getAllowedEnvKeys,
    getSystemReadOnlyPaths,
    truncateOutput,
    validateInput,
} from '../../bwrap-runner/lib/policy.mjs';
import {
    normalizeStagedFiles,
    stageFiles,
} from '../../bwrap-runner/lib/staging.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function makePaths() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bwrap-runner-test-'));
    const workDir = path.join(root, 'work');
    const outputsDir = path.join(root, 'outputs');
    fs.mkdirSync(workDir, { recursive: true });
    fs.mkdirSync(outputsDir, { recursive: true });
    return { root, workDir, outputsDir };
}

function findFlagValue(args, flag) {
    const idx = args.indexOf(flag);
    return idx >= 0 ? args[idx + 1] : null;
}

function hasFlag(args, flag) {
    return args.includes(flag);
}

function findAllFlagValues(args, flag) {
    const values = [];
    for (let i = 0; i < args.length - 1; i += 1) {
        if (args[i] === flag) values.push(args[i + 1]);
    }
    return values;
}

function findSetenv(args, key) {
    for (let i = 0; i < args.length - 2; i += 1) {
        if (args[i] === '--setenv' && args[i + 1] === key) {
            return args[i + 2];
        }
    }
    return null;
}

test('default policy enables --unshare-net and a fixed isolation set', () => {
    const validated = validateInput({ command: 'echo hi' });
    const { workDir, outputsDir } = makePaths();
    try {
        const args = buildBwrapArgs(validated, {
            workDir,
            outputsDir,
            existingSystemPaths: new Set(['/usr', '/bin']),
        });
        for (const flag of [
            '--die-with-parent',
            '--unshare-user',
            '--unshare-pid',
            '--unshare-ipc',
            '--unshare-uts',
            '--unshare-net',
            '--clearenv',
        ]) {
            assert.ok(hasFlag(args, flag), `expected ${flag} in argv`);
        }
        // /proc, /dev, /tmpfs handles are in place
        assert.strictEqual(findFlagValue(args, '--proc'), '/proc');
        assert.strictEqual(findFlagValue(args, '--dev'), '/dev');
        assert.strictEqual(findFlagValue(args, '--tmpfs'), '/tmp');
        assert.strictEqual(findFlagValue(args, '--chdir'), '/work');
    } finally {
        fs.rmSync(path.dirname(workDir), { recursive: true, force: true });
    }
});

test('--unshare-net is omitted only when allowNetwork=true', () => {
    const validated = validateInput({ command: 'echo hi' }, { allowNetwork: true });
    const { workDir } = makePaths();
    try {
        const args = buildBwrapArgs(validated, { workDir, existingSystemPaths: new Set() });
        assert.ok(!args.includes('--unshare-net'), 'network=inherit should drop --unshare-net');
        assert.strictEqual(validated.network, 'inherit');
    } finally {
        fs.rmSync(path.dirname(workDir), { recursive: true, force: true });
    }
});

test('--clearenv is set and only allowlisted env survives', () => {
    const validated = validateInput({
        command: 'env',
        env: { LANG: 'en_US.UTF-8' },
    });
    const { workDir } = makePaths();
    try {
        const args = buildBwrapArgs(validated, { workDir, existingSystemPaths: new Set() });
        const clearIdx = args.indexOf('--clearenv');
        assert.ok(clearIdx >= 0, '--clearenv must be present');

        // Every --setenv must be a known allowed key.
        const allowedKeys = getAllowedEnvKeys();
        // Defaults the policy always sets:
        for (const required of ['PATH', 'HOME', 'TMPDIR']) {
            assert.ok(findSetenv(args, required), `expected ${required} setenv`);
        }
        for (let i = 0; i < args.length - 2; i += 1) {
            if (args[i] === '--setenv') {
                assert.ok(allowedKeys.has(args[i + 1]), `unexpected env key ${args[i + 1]}`);
            }
        }
        // Caller-supplied value must override the default.
        assert.strictEqual(findSetenv(args, 'LANG'), 'en_US.UTF-8');

        // Setenv must appear after --clearenv (order matters; bwrap applies
        // --clearenv at sandbox setup).
        for (let i = 0; i < args.length - 1; i += 1) {
            if (args[i] === '--setenv') {
                assert.ok(i > clearIdx, '--setenv must come after --clearenv');
            }
        }
    } finally {
        fs.rmSync(path.dirname(workDir), { recursive: true, force: true });
    }
});

test('timeout handling caps user requests at the configured maximum', () => {
    const limits = { ...POLICY_LIMITS, maxTimeoutMs: 5_000, defaultTimeoutMs: 1_000 };
    const validated = validateInput({ command: 'sleep 1' }, { limits });
    assert.strictEqual(validated.timeoutMs, 1_000, 'default timeout must apply');

    assert.throws(
        () => validateInput({ command: 'sleep 1', timeoutMs: 999_999 }, { limits }),
        /timeoutMs must be a number between/,
    );
    assert.throws(
        () => validateInput({ command: 'sleep 1', timeoutMs: 50 }, { limits }),
        /timeoutMs must be a number between/,
    );

    const ok = validateInput({ command: 'sleep 1', timeoutMs: 3_000 }, { limits });
    assert.strictEqual(ok.timeoutMs, 3_000);
});

test('stdout/stderr truncation keeps the tail and reports the original byte length', () => {
    const big = 'a'.repeat(1024) + 'XYZ';
    const truncated = truncateOutput(big, 8);
    assert.strictEqual(truncated.text.length, 8);
    assert.strictEqual(truncated.text, 'aaaaaXYZ');
    assert.strictEqual(truncated.truncated, true);
    assert.strictEqual(truncated.byteLength, 1027);

    const small = truncateOutput('hello', 64);
    assert.strictEqual(small.text, 'hello');
    assert.strictEqual(small.truncated, false);
    assert.strictEqual(small.byteLength, 5);

    const retainedTail = truncateOutput('prefix-tail', 4, 10_000);
    assert.strictEqual(retainedTail.text, 'tail');
    assert.strictEqual(retainedTail.truncated, true);
    assert.strictEqual(retainedTail.byteLength, 10_000);
});

test('rejects unsafe payloads (null bytes, oversize, bad types, extra fields)', () => {
    assert.throws(
        () => validateInput({ command: 'echo\0hi' }),
        /command must not contain null bytes/,
    );
    assert.throws(
        () => validateInput({ command: 'echo', stdin: 12 }),
        /stdin must be a string/,
    );
    assert.throws(
        () => validateInput({ command: 'a'.repeat(4097), stdin: '' }, { limits: POLICY_LIMITS }),
        /command exceeds/,
    );
    assert.throws(
        () => validateInput({ command: 'echo', env: { 'BAD;ENV': '1' } }),
        /not in the allowlist/,
    );
    assert.throws(
        () => validateInput({ command: 'echo', env: { PATH: 'a\nb' } }),
        /disallowed characters/,
    );
    assert.throws(
        () => validateInput({ command: 'echo', mounts: ['/etc'] }),
        /unsupported field/,
    );
    assert.throws(
        () => validateInput({ command: '' }),
        /command must be a non-empty string/,
    );
    assert.throws(
        () => validateInput({ command: 'echo', stdin: 'x'.repeat(POLICY_LIMITS.maxStdinBytes + 1) }),
        /stdin exceeds/,
    );
});

test('staged files validate and write under /work', () => {
    const { root, workDir } = makePaths();
    try {
        const staged = normalizeStagedFiles([
            { path: 'prompt.md', content: 'hello from prompt' },
            { path: 'input/data.bin', content: Buffer.from('abc').toString('base64'), encoding: 'base64' },
        ], { limits: POLICY_LIMITS });
        const written = stageFiles(workDir, staged);

        assert.deepEqual(written.map((entry) => entry.path), ['prompt.md', 'input/data.bin']);
        assert.equal(fs.readFileSync(path.join(workDir, 'prompt.md'), 'utf8'), 'hello from prompt');
        assert.deepEqual(fs.readFileSync(path.join(workDir, 'input/data.bin')), Buffer.from('abc'));
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test('staged files reject unsafe or duplicate paths', () => {
    for (const badPath of ['/abs', '../x', 'a/../b', 'a//b', 'a/', './x', '']) {
        assert.throws(
            () => normalizeStagedFiles([{ path: badPath, content: 'x' }], { limits: POLICY_LIMITS }),
            /file path/,
            `expected ${badPath} to be rejected`,
        );
    }
    assert.throws(
        () => normalizeStagedFiles([
            { path: 'input/data.txt', content: 'a' },
            { path: 'input/data.txt', content: 'b' },
        ], { limits: POLICY_LIMITS }),
        /duplicate staged file path/,
    );
});

test('staged files enforce field, encoding, entry, and byte limits', () => {
    assert.throws(
        () => normalizeStagedFiles([{ path: 'x', content: 'x', mode: '0644' }], { limits: POLICY_LIMITS }),
        /unsupported file field/,
    );
    assert.throws(
        () => normalizeStagedFiles([{ path: 'x', content: 'x', encoding: 'hex' }], { limits: POLICY_LIMITS }),
        /unsupported encoding/,
    );
    assert.throws(
        () => normalizeStagedFiles([{ path: 'x', content: '!!!!', encoding: 'base64' }], { limits: POLICY_LIMITS }),
        /not valid base64/,
    );
    assert.throws(
        () => normalizeStagedFiles([{ path: 'x', content: 'abc' }], {
            limits: { ...POLICY_LIMITS, maxStagedFileBytes: 2 },
        }),
        /exceeds 2 bytes/,
    );
    assert.throws(
        () => normalizeStagedFiles([
            { path: 'a', content: 'aa' },
            { path: 'b', content: 'bb' },
        ], {
            limits: { ...POLICY_LIMITS, maxStagedTotalBytes: 3 },
        }),
        /exceed 3 bytes total/,
    );
    assert.throws(
        () => normalizeStagedFiles([
            { path: 'a', content: 'a' },
            { path: 'b', content: 'b' },
        ], {
            limits: { ...POLICY_LIMITS, maxStagedFiles: 1 },
        }),
        /files exceeds 1 entries/,
    );
});

test('paths argument must be absolute and free of traversal sequences', () => {
    const validated = validateInput({ command: 'echo hi' });
    assert.throws(
        () => buildBwrapArgs(validated, { workDir: 'relative/path' }),
        /paths.workDir must be an absolute path/,
    );
    assert.throws(
        () => buildBwrapArgs(validated, { workDir: '/abs/with/..//evil' }),
        /paths.workDir must not contain/,
    );
    assert.throws(
        () => buildBwrapArgs(validated, { workDir: '/abs', outputsDir: '/abs/with/..' }),
        /paths.outputsDir must not contain/,
    );
});

test('no arbitrary bind paths from the user input', () => {
    const validated = validateInput({ command: 'echo hi' });
    const { workDir, outputsDir } = makePaths();
    try {
        const allowedSystemPaths = new Set(['/usr', '/bin', '/lib']);
        const args = buildBwrapArgs(validated, {
            workDir,
            outputsDir,
            existingSystemPaths: allowedSystemPaths,
        });
        // Every --bind/--ro-bind source must be one of:
        //  - an entry in our system-RO allowlist (intersected with existence)
        //  - the per-job work or outputs dir
        const allowedSources = new Set([
            ...allowedSystemPaths,
            workDir,
            outputsDir,
        ]);
        const seenBindSources = [
            ...findAllFlagValues(args, '--bind'),
            ...findAllFlagValues(args, '--ro-bind'),
        ];
        for (const src of seenBindSources) {
            assert.ok(
                allowedSources.has(src),
                `unexpected bind source: ${src}`
            );
        }
        // Crucially: no system path that wasn't in our existing-paths set
        // appears, even though it's in the static SYSTEM_RO_PATHS list.
        for (const candidate of getSystemReadOnlyPaths()) {
            if (!allowedSystemPaths.has(candidate)) {
                assert.ok(!seenBindSources.includes(candidate),
                    `${candidate} should not be bound when missing from filesystem`);
            }
        }
    } finally {
        fs.rmSync(path.dirname(workDir), { recursive: true, force: true });
    }
});

test('decideNetworkPolicy treats only the canonical truthy strings as enabling network', () => {
    assert.strictEqual(decideNetworkPolicy('true'), true);
    assert.strictEqual(decideNetworkPolicy('TRUE'), true);
    assert.strictEqual(decideNetworkPolicy('1'), true);
    assert.strictEqual(decideNetworkPolicy('yes'), true);
    assert.strictEqual(decideNetworkPolicy('on'), true);
    assert.strictEqual(decideNetworkPolicy('false'), false);
    assert.strictEqual(decideNetworkPolicy(''), false);
    assert.strictEqual(decideNetworkPolicy(undefined), false);
    assert.strictEqual(decideNetworkPolicy('inherit'), false);
});

test('wrapper end-to-end: invalid input returns a structured, MCP-visible error', () => {
    // Run the actual wrapper module without depending on nested namespaces in CI.
    // We test that:
    //  - the wrapper validates input
    //  - it emits a single-line JSON record with the expected error shape
    //  - the top-level message is compatible with AgentServer's error parser
    const wrapper = path.resolve(__dirname, '../../bwrap-runner/bin/sandbox-exec.mjs');
    const state = fs.mkdtempSync(path.join(os.tmpdir(), 'bwrap-runner-state-'));
    try {
        // The wrapper invokes BWRAP_PATH directly. We can't override that path
        // without modifying the module, so this test only verifies the input
        // validation path: send an obviously-invalid payload and assert that
        // the wrapper returns a structured error response.
        const child = spawnSync(process.execPath, [wrapper], {
            input: JSON.stringify({ command: '' }),
            encoding: 'utf8',
            env: {
                ...process.env,
                BWRAP_RUNNER_STATE: state,
            },
            timeout: 15_000,
        });
        const stdout = String(child.stdout || '').trim();
        assert.ok(stdout, `wrapper produced no stdout. stderr=${child.stderr}`);
        const result = JSON.parse(stdout.split('\n').pop());
        assert.strictEqual(result.ok, false);
        assert.ok(result.error && typeof result.error.message === 'string');
        assert.strictEqual(result.message, result.error.message);
        assert.match(result.error.message, /command must be a non-empty string/);
    } finally {
        fs.rmSync(state, { recursive: true, force: true });
    }
});

test('wrapper end-to-end: invalid staged files return a structured, MCP-visible error', () => {
    const wrapper = path.resolve(__dirname, '../../bwrap-runner/bin/sandbox-exec.mjs');
    const state = fs.mkdtempSync(path.join(os.tmpdir(), 'bwrap-runner-state-'));
    try {
        const child = spawnSync(process.execPath, [wrapper], {
            input: JSON.stringify({
                command: 'echo should-not-run',
                files: [{ path: '../escape.txt', content: 'nope' }],
            }),
            encoding: 'utf8',
            env: {
                ...process.env,
                BWRAP_RUNNER_STATE: state,
            },
            timeout: 15_000,
        });
        const stdout = String(child.stdout || '').trim();
        assert.ok(stdout, `wrapper produced no stdout. stderr=${child.stderr}`);
        const result = JSON.parse(stdout.split('\n').pop());
        assert.strictEqual(result.ok, false);
        assert.match(result.error.message, /file path must not contain/);
        assert.strictEqual(result.message, result.error.message);
    } finally {
        fs.rmSync(state, { recursive: true, force: true });
    }
});

test('manifest gates AgentServer startup on nested-bwrap healthcheck and builds the local image', () => {
    const manifestPath = path.resolve(__dirname, '../../bwrap-runner/manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    assert.strictEqual(manifest.container, 'assistos/bwrap-runner:node24-bookworm');
    assert.deepStrictEqual(manifest.containerSecurity, { privileged: true });
    assert.strictEqual(
        manifest.profiles.default.env.BWRAP_RUNNER_IMAGE.default,
        'assistos/bwrap-runner:node24-bookworm',
    );
    assert.match(manifest.agent, /healthcheck\.mjs/);
    assert.match(manifest.agent, /AgentServer\.sh/);
    assert.strictEqual(manifest.profiles.default.preinstall, 'scripts/build-image.sh');
});

test('agent is catalogued as a normal Basic repository agent', () => {
    const agentDir = path.resolve(__dirname, '../../bwrap-runner');
    const manifestPath = path.join(agentDir, 'manifest.json');
    const mcpConfigPath = path.join(agentDir, 'mcp-config.json');
    const buildScriptPath = path.join(agentDir, 'scripts/build-image.sh');

    assert.ok(fs.existsSync(manifestPath), 'manifest.json must exist at the Basic agent root');
    assert.ok(fs.existsSync(mcpConfigPath), 'mcp-config.json must exist at the Basic agent root');
    assert.ok(fs.existsSync(buildScriptPath), 'image build preinstall script must exist');
    assert.ok((fs.statSync(buildScriptPath).mode & 0o111) !== 0, 'image build script must be executable');
});

test('publish workflow builds the Docker Hub image from Linux for both supported architectures', () => {
    const workflowPath = path.resolve(__dirname, '../../.github/workflows/publish-bwrap-runner.yml');
    const workflow = fs.readFileSync(workflowPath, 'utf8');

    assert.match(workflow, /^  workflow_dispatch:\s*$/m);
    assert.doesNotMatch(workflow, /^  push:\s*$/m);
    assert.match(workflow, /runs-on:\s*ubuntu-latest/);
    assert.match(workflow, /docker\/setup-buildx-action@v3/);
    assert.match(workflow, /docker\/login-action@v3/);
    assert.match(workflow, /docker\/build-push-action@v6/);
    assert.match(workflow, /IMAGE_NAME:\s*assistos\/bwrap-runner/);
    assert.match(workflow, /IMAGE_TAG:\s*node24-bookworm/);
    assert.match(workflow, /platforms:\s*linux\/amd64,linux\/arm64/);
    assert.match(workflow, /password:\s*\$\{\{\s*secrets\.DOCKERHUB_TOKEN\s*\}\}/);
});
