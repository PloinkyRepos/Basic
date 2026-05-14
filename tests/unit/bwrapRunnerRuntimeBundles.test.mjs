// Tests for runtime-bundle validation and bwrap argv generation.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    resolveRuntimeBundle,
    resolveRuntimeRoot,
    validateRuntimeBundleInput,
    RUNTIME_BUNDLE_INTERNALS,
} from '../../bwrap-runner/lib/runtime-bundles.mjs';
import { buildBwrapArgs, validateInput } from '../../bwrap-runner/lib/policy.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function mkRoot() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'bwrap-runtime-bundles-'));
}

function writeManifest(dir, manifest) {
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest), { mode: 0o600 });
}

function makeBundle(root, id, version, manifestOverrides = {}) {
    const bundleDir = path.join(root, id, version);
    fs.mkdirSync(bundleDir, { recursive: true });
    const manifest = {
        schema: RUNTIME_BUNDLE_INTERNALS.SUPPORTED_MANIFEST_SCHEMA,
        id,
        version,
        ...manifestOverrides,
    };
    writeManifest(bundleDir, manifest);
    return { bundleDir, manifest };
}

test('validateRuntimeBundleInput accepts narrow id/version/digest only', () => {
    assert.deepEqual(
        validateRuntimeBundleInput({ id: 'open-interpreter', version: '0.4.3' }),
        { id: 'open-interpreter', version: '0.4.3', digest: null },
    );
    assert.deepEqual(
        validateRuntimeBundleInput({ id: 'oi', version: '0.4.3', digest: 'sha256:abc' }),
        { id: 'oi', version: '0.4.3', digest: 'sha256:abc' },
    );
    assert.equal(validateRuntimeBundleInput(null), null);
    assert.equal(validateRuntimeBundleInput(undefined), null);
});

test('validateRuntimeBundleInput rejects path-shaped, traversal, null-byte, and uppercase identifiers', () => {
    for (const bad of [
        { id: '/abs', version: '1' },
        { id: '..', version: '1' },
        { id: 'a/b', version: '1' },
        { id: 'a\\b', version: '1' },
        { id: 'good', version: '../etc' },
        { id: 'good', version: '/abs' },
        { id: 'Bad-Case', version: '1' },
        { id: 'good', version: 'a\0b' },
    ]) {
        assert.throws(() => validateRuntimeBundleInput(bad), /runtimeBundle/);
    }
});

test('validateRuntimeBundleInput rejects extra fields and non-object inputs', () => {
    assert.throws(() => validateRuntimeBundleInput({ id: 'a', version: '1', mounts: ['/etc'] }), /unsupported runtimeBundle field/);
    assert.throws(() => validateRuntimeBundleInput('open-interpreter'), /runtimeBundle must be an object/);
    assert.throws(() => validateRuntimeBundleInput([]), /runtimeBundle must be an object/);
});

test('resolveRuntimeRoot defaults to /data/research-runtimes and accepts overrides', () => {
    assert.equal(resolveRuntimeRoot({}), '/data/research-runtimes');
    assert.equal(resolveRuntimeRoot({ BWRAP_RUNNER_RUNTIME_ROOT: '/var/lib/runtimes' }), '/var/lib/runtimes');
    assert.throws(
        () => resolveRuntimeRoot({ BWRAP_RUNNER_RUNTIME_ROOT: 'relative/path' }),
        /must be an absolute path/,
    );
});

test('resolveRuntimeBundle accepts a valid bundle and exposes manifest env', () => {
    const root = mkRoot();
    try {
        const { bundleDir } = makeBundle(root, 'open-interpreter', '0.4.3', {
            entrypoints: { default: '/runtime/bin/research-open-interpreter.py' },
            python: { pythonPath: ['/runtime/python'] },
        });
        const resolved = resolveRuntimeBundle(
            { id: 'open-interpreter', version: '0.4.3' },
            { env: { BWRAP_RUNNER_RUNTIME_ROOT: root } },
        );
        assert.equal(resolved.bundleDir, fs.realpathSync(bundleDir));
        assert.equal(resolved.containerMount, '/runtime');
        assert.equal(resolved.env.PYTHONPATH, '/runtime/python');
        assert.equal(resolved.entrypoints.default, '/runtime/bin/research-open-interpreter.py');
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test('resolveRuntimeBundle rejects missing manifest', () => {
    const root = mkRoot();
    try {
        const bundleDir = path.join(root, 'open-interpreter', '0.4.3');
        fs.mkdirSync(bundleDir, { recursive: true });
        assert.throws(
            () => resolveRuntimeBundle(
                { id: 'open-interpreter', version: '0.4.3' },
                { env: { BWRAP_RUNNER_RUNTIME_ROOT: root } },
            ),
            /manifest is missing/,
        );
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test('resolveRuntimeBundle rejects manifest id/version mismatch', () => {
    const root = mkRoot();
    try {
        makeBundle(root, 'open-interpreter', '0.4.3', {});
        const bundleDir = path.join(root, 'open-interpreter', '0.4.3');
        writeManifest(bundleDir, {
            schema: RUNTIME_BUNDLE_INTERNALS.SUPPORTED_MANIFEST_SCHEMA,
            id: 'something-else',
            version: '0.4.3',
        });
        assert.throws(
            () => resolveRuntimeBundle(
                { id: 'open-interpreter', version: '0.4.3' },
                { env: { BWRAP_RUNNER_RUNTIME_ROOT: root } },
            ),
            /manifest id 'something-else'/,
        );

        writeManifest(bundleDir, {
            schema: RUNTIME_BUNDLE_INTERNALS.SUPPORTED_MANIFEST_SCHEMA,
            id: 'open-interpreter',
            version: '9.9.9',
        });
        assert.throws(
            () => resolveRuntimeBundle(
                { id: 'open-interpreter', version: '0.4.3' },
                { env: { BWRAP_RUNNER_RUNTIME_ROOT: root } },
            ),
            /manifest version '9\.9\.9'/,
        );
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test('resolveRuntimeBundle rejects manifest with unsupported schema', () => {
    const root = mkRoot();
    try {
        makeBundle(root, 'open-interpreter', '0.4.3', {});
        writeManifest(path.join(root, 'open-interpreter', '0.4.3'), {
            schema: 'something.else',
            id: 'open-interpreter',
            version: '0.4.3',
        });
        assert.throws(
            () => resolveRuntimeBundle(
                { id: 'open-interpreter', version: '0.4.3' },
                { env: { BWRAP_RUNNER_RUNTIME_ROOT: root } },
            ),
            /schema must be/,
        );
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test('resolveRuntimeBundle rejects symlink escape from the bundle dir', () => {
    const root = mkRoot();
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'bwrap-outside-'));
    try {
        fs.mkdirSync(path.join(root, 'open-interpreter'), { recursive: true });
        fs.symlinkSync(outside, path.join(root, 'open-interpreter', '0.4.3'));
        fs.writeFileSync(path.join(outside, 'manifest.json'), JSON.stringify({
            schema: RUNTIME_BUNDLE_INTERNALS.SUPPORTED_MANIFEST_SCHEMA,
            id: 'open-interpreter',
            version: '0.4.3',
        }));
        assert.throws(
            () => resolveRuntimeBundle(
                { id: 'open-interpreter', version: '0.4.3' },
                { env: { BWRAP_RUNNER_RUNTIME_ROOT: root } },
            ),
            /resolves outside the runtime root/,
        );
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
        fs.rmSync(outside, { recursive: true, force: true });
    }
});

test('resolveRuntimeBundle rejects manifest symlinks that leave the selected bundle', () => {
    const root = mkRoot();
    try {
        const bundleDir = path.join(root, 'open-interpreter', '0.4.3');
        fs.mkdirSync(bundleDir, { recursive: true });
        const siblingDir = path.join(root, 'open-interpreter', 'other');
        fs.mkdirSync(siblingDir, { recursive: true });
        fs.writeFileSync(path.join(siblingDir, 'manifest.json'), JSON.stringify({
            schema: RUNTIME_BUNDLE_INTERNALS.SUPPORTED_MANIFEST_SCHEMA,
            id: 'open-interpreter',
            version: '0.4.3',
        }));
        fs.symlinkSync(path.join(siblingDir, 'manifest.json'), path.join(bundleDir, 'manifest.json'));
        assert.throws(
            () => resolveRuntimeBundle(
                { id: 'open-interpreter', version: '0.4.3' },
                { env: { BWRAP_RUNNER_RUNTIME_ROOT: root } },
            ),
            /manifest.*resolves outside the runtime root/,
        );
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test('resolveRuntimeBundle rejects digest mismatch when manifest declares a digest', () => {
    const root = mkRoot();
    try {
        makeBundle(root, 'oi', '1.0.0', { digest: 'sha256:expected' });
        assert.throws(
            () => resolveRuntimeBundle(
                { id: 'oi', version: '1.0.0', digest: 'sha256:wrong' },
                { env: { BWRAP_RUNNER_RUNTIME_ROOT: root } },
            ),
            /digest 'sha256:expected'/,
        );
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test('resolveRuntimeBundle requires a manifest digest when caller supplies runtimeBundle.digest', () => {
    const root = mkRoot();
    try {
        makeBundle(root, 'oi', '1.0.0');
        assert.throws(
            () => resolveRuntimeBundle(
                { id: 'oi', version: '1.0.0', digest: 'sha256:expected' },
                { env: { BWRAP_RUNNER_RUNTIME_ROOT: root } },
            ),
            /must declare digest 'sha256:expected'/,
        );
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test('buildBwrapArgs binds the resolved bundle dir read-only at /runtime and does not bind /shared', () => {
    const root = mkRoot();
    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bwrap-work-'));
    try {
        makeBundle(root, 'open-interpreter', '0.4.3', {
            entrypoints: { default: '/runtime/bin/research-open-interpreter.py' },
            python: { pythonPath: ['/runtime/python'] },
        });
        const resolved = resolveRuntimeBundle(
            { id: 'open-interpreter', version: '0.4.3' },
            { env: { BWRAP_RUNNER_RUNTIME_ROOT: root } },
        );

        const validated = validateInput({
            command: 'python3 /runtime/bin/research-open-interpreter.py /work/prompt.md',
            runtimeBundle: { id: 'open-interpreter', version: '0.4.3' },
        });

        const args = buildBwrapArgs(validated, {
            workDir,
            existingSystemPaths: new Set(['/usr', '/bin']),
            runtimeBundle: resolved,
        });

        const argv = args.join(' ');
        assert.ok(argv.includes(`--ro-bind ${resolved.bundleDir} /runtime`),
            `expected --ro-bind <bundle> /runtime; got: ${argv}`);
        assert.ok(!argv.includes('--bind /shared') && !argv.includes('--ro-bind /shared'),
            '/shared must not appear in bwrap argv');
        let pythonPathValue = null;
        for (let i = 0; i < args.length - 2; i += 1) {
            if (args[i] === '--setenv' && args[i + 1] === 'PYTHONPATH') {
                pythonPathValue = args[i + 2];
                break;
            }
        }
        assert.equal(pythonPathValue, '/runtime/python', 'PYTHONPATH must come from manifest, not caller env');
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
        fs.rmSync(workDir, { recursive: true, force: true });
    }
});

test('buildBwrapArgs omits /runtime bind when no bundle is provided', () => {
    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bwrap-work-'));
    try {
        const validated = validateInput({ command: 'echo hi' });
        const args = buildBwrapArgs(validated, {
            workDir,
            existingSystemPaths: new Set(['/usr', '/bin']),
        });
        assert.ok(!args.includes('/runtime'), '/runtime must not appear when no bundle is requested');
    } finally {
        fs.rmSync(workDir, { recursive: true, force: true });
    }
});

test('validateInput rejects unsupported fields but accepts runtimeBundle', () => {
    assert.throws(
        () => validateInput({ command: 'echo hi', mounts: ['/etc'] }),
        /unsupported field/,
    );
    const ok = validateInput({
        command: 'echo hi',
        runtimeBundle: { id: 'open-interpreter', version: '0.4.3' },
    });
    assert.deepEqual(ok.runtimeBundle, { id: 'open-interpreter', version: '0.4.3' });
});

test('sandbox-exec emits a structured error for a malformed runtimeBundle without crashing', async () => {
    const wrapper = path.resolve(__dirname, '../../bwrap-runner/bin/sandbox-exec.mjs');
    const state = fs.mkdtempSync(path.join(os.tmpdir(), 'bwrap-runner-state-'));
    const root = mkRoot();
    try {
        const { spawnSync } = await import('node:child_process');
        const child = spawnSync(process.execPath, [wrapper], {
            input: JSON.stringify({
                command: 'echo hi',
                runtimeBundle: { id: '../escape', version: '1' },
            }),
            encoding: 'utf8',
            env: {
                ...process.env,
                BWRAP_RUNNER_STATE: state,
                BWRAP_RUNNER_RUNTIME_ROOT: root,
            },
            timeout: 15_000,
        });
        const stdout = String(child.stdout || '').trim();
        assert.ok(stdout, `wrapper produced no stdout. stderr=${child.stderr}`);
        const result = JSON.parse(stdout.split('\n').pop());
        assert.equal(result.ok, false);
        assert.match(result.error.message, /runtimeBundle\.id/);
    } finally {
        fs.rmSync(state, { recursive: true, force: true });
        fs.rmSync(root, { recursive: true, force: true });
    }
});
