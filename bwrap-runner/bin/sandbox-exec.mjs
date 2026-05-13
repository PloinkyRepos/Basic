#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import {
    POLICY_LIMITS,
    buildBwrapArgs,
    decideNetworkPolicy,
    getSystemReadOnlyPaths,
    truncateOutput,
    validateInput,
} from '../lib/policy.mjs';

const BWRAP_PATH = '/usr/bin/bwrap';

function parseIntFromEnv(name, fallback) {
    const raw = process.env[name];
    if (raw == null || raw === '') return fallback;
    const parsed = Number.parseInt(raw, 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function readPayload() {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let total = 0;
        const maxBytes = parseIntFromEnv('BWRAP_RUNNER_MAX_STDIN_BYTES', POLICY_LIMITS.maxStdinBytes) + 8 * 1024;
        process.stdin.on('data', (chunk) => {
            total += chunk.length;
            if (total > maxBytes) {
                reject(Object.assign(new Error('stdin payload too large'), { code: 'BWRAP_RUNNER_PAYLOAD_TOO_LARGE' }));
                process.stdin.destroy();
                return;
            }
            chunks.push(chunk);
        });
        process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        process.stdin.on('error', reject);
    });
}

function parsePayload(raw) {
    const trimmed = String(raw || '').trim();
    if (!trimmed) return {};
    let parsed;
    try {
        parsed = JSON.parse(trimmed);
    } catch (err) {
        throw Object.assign(new Error('stdin payload was not valid JSON'), { code: 'BWRAP_RUNNER_INVALID_JSON' });
    }
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        if (parsed.input && typeof parsed.input === 'object' && !Array.isArray(parsed.input)) {
            return parsed.input;
        }
        return parsed;
    }
    throw Object.assign(new Error('stdin payload must be an object'), { code: 'BWRAP_RUNNER_INVALID_INPUT' });
}

function resolveStateDir() {
    const candidates = [
        process.env.BWRAP_RUNNER_STATE,
        process.env.PLOINKY_BWRAP_RUNNER_STATE,
        '/var/lib/ploinky-bwrap-runner',
    ];
    for (const candidate of candidates) {
        if (candidate && typeof candidate === 'string') return candidate;
    }
    return '/var/lib/ploinky-bwrap-runner';
}

function existingSystemPathsSet() {
    const set = new Set();
    for (const candidate of getSystemReadOnlyPaths()) {
        try {
            fs.accessSync(candidate, fs.constants.R_OK);
            set.add(candidate);
        } catch (_) {
            // path doesn't exist on this filesystem; bwrap would fail to bind it.
        }
    }
    return set;
}

function preparePerJobDirs(stateRoot) {
    const jobId = randomUUID();
    const jobRoot = path.join(stateRoot, 'jobs', jobId);
    const workDir = path.join(jobRoot, 'work');
    const outputsDir = path.join(jobRoot, 'outputs');
    fs.mkdirSync(workDir, { recursive: true });
    fs.mkdirSync(outputsDir, { recursive: true });
    try {
        fs.chmodSync(jobRoot, 0o700);
        fs.chmodSync(workDir, 0o700);
        fs.chmodSync(outputsDir, 0o700);
    } catch (_) {
        // chmod is best-effort; the runner container already owns these paths.
    }
    return { jobId, jobRoot, workDir, outputsDir };
}

function runBwrap(args, validated, limits) {
    return new Promise((resolve) => {
        const startedAt = Date.now();
        const child = spawn(BWRAP_PATH, args, {
            stdio: ['pipe', 'pipe', 'pipe'],
            env: {},
        });
        const stdoutChunks = [];
        const stderrChunks = [];
        let stdoutBytes = 0;
        let stderrBytes = 0;
        let stdoutRetainedBytes = 0;
        let stderrRetainedBytes = 0;
        let timedOut = false;
        const stdoutRetainBytes = Math.max(1, limits.maxStdoutBytes);
        const stderrRetainBytes = Math.max(1, limits.maxStderrBytes);

        function appendTail(chunks, chunk, retainBytes, retainedBytes) {
            let nextRetainedBytes = retainedBytes;
            if (chunk.length >= retainBytes) {
                chunks.length = 0;
                chunks.push(chunk.subarray(chunk.length - retainBytes));
                return retainBytes;
            }

            chunks.push(chunk);
            nextRetainedBytes += chunk.length;
            while (nextRetainedBytes > retainBytes && chunks.length) {
                const excess = nextRetainedBytes - retainBytes;
                const first = chunks[0];
                if (first.length <= excess) {
                    chunks.shift();
                    nextRetainedBytes -= first.length;
                } else {
                    chunks[0] = first.subarray(excess);
                    nextRetainedBytes -= excess;
                }
            }
            return nextRetainedBytes;
        }

        child.stdout.on('data', (chunk) => {
            stdoutBytes += chunk.length;
            stdoutRetainedBytes = appendTail(stdoutChunks, chunk, stdoutRetainBytes, stdoutRetainedBytes);
        });
        child.stderr.on('data', (chunk) => {
            stderrBytes += chunk.length;
            stderrRetainedBytes = appendTail(stderrChunks, chunk, stderrRetainBytes, stderrRetainedBytes);
        });

        const timer = setTimeout(() => {
            timedOut = true;
            try { child.kill('SIGKILL'); } catch (_) {}
        }, validated.timeoutMs);

        child.on('error', (err) => {
            clearTimeout(timer);
            resolve({
                spawnError: err?.message || String(err),
                stdoutBuffer: Buffer.concat(stdoutChunks),
                stderrBuffer: Buffer.concat(stderrChunks),
                stdoutBytes,
                stderrBytes,
                elapsedMs: Date.now() - startedAt,
                timedOut,
            });
        });

        child.on('close', (code, signal) => {
            clearTimeout(timer);
            resolve({
                exitCode: typeof code === 'number' ? code : null,
                signal: signal || null,
                stdoutBuffer: Buffer.concat(stdoutChunks),
                stderrBuffer: Buffer.concat(stderrChunks),
                stdoutBytes,
                stderrBytes,
                elapsedMs: Date.now() - startedAt,
                timedOut,
            });
        });

        if (validated.stdin != null) {
            try {
                child.stdin.end(validated.stdin);
            } catch (_) {
                // ignore broken pipe; child may have exited early
            }
        } else {
            try { child.stdin.end(); } catch (_) {}
        }
    });
}

function emit(result) {
    try {
        const normalized = (result && result.ok === false && !result.message && result.error?.message)
            ? { ...result, message: result.error.message }
            : result;
        process.stdout.write(`${JSON.stringify(normalized)}\n`);
    } catch (err) {
        process.stderr.write(`[bwrap-runner] failed to emit result: ${err?.message || err}\n`);
    }
}

async function main() {
    let payload;
    try {
        const raw = await readPayload();
        payload = parsePayload(raw);
    } catch (err) {
        emit({
            ok: false,
            error: { code: err.code || 'BWRAP_RUNNER_INPUT_ERROR', message: err.message || String(err) },
        });
        process.exit(1);
        return;
    }

    const limits = {
        maxCommandLength: parseIntFromEnv('BWRAP_RUNNER_MAX_COMMAND_LENGTH', POLICY_LIMITS.maxCommandLength),
        maxStdinBytes: parseIntFromEnv('BWRAP_RUNNER_MAX_STDIN_BYTES', POLICY_LIMITS.maxStdinBytes),
        maxTimeoutMs: parseIntFromEnv('BWRAP_RUNNER_MAX_TIMEOUT_MS', POLICY_LIMITS.maxTimeoutMs),
        minTimeoutMs: POLICY_LIMITS.minTimeoutMs,
        defaultTimeoutMs: parseIntFromEnv('BWRAP_RUNNER_DEFAULT_TIMEOUT_MS', POLICY_LIMITS.defaultTimeoutMs),
        maxStdoutBytes: parseIntFromEnv('BWRAP_RUNNER_MAX_STDOUT_BYTES', POLICY_LIMITS.maxStdoutBytes),
        maxStderrBytes: parseIntFromEnv('BWRAP_RUNNER_MAX_STDERR_BYTES', POLICY_LIMITS.maxStderrBytes),
        maxEnvEntries: POLICY_LIMITS.maxEnvEntries,
    };

    const allowNetwork = decideNetworkPolicy(process.env.BWRAP_RUNNER_ALLOW_NETWORK);

    let validated;
    try {
        validated = validateInput(payload, { limits, allowNetwork });
    } catch (err) {
        emit({
            ok: false,
            error: { code: err.code || 'BWRAP_RUNNER_INVALID_INPUT', message: err.message || String(err) },
        });
        process.exit(1);
        return;
    }

    const stateRoot = resolveStateDir();
    try {
        fs.mkdirSync(stateRoot, { recursive: true });
    } catch (err) {
        emit({
            ok: false,
            error: {
                code: 'BWRAP_RUNNER_STATE_UNAVAILABLE',
                message: `failed to create state directory '${stateRoot}': ${err?.message || err}`,
            },
        });
        process.exit(1);
        return;
    }

    let dirs;
    try {
        dirs = preparePerJobDirs(stateRoot);
    } catch (err) {
        emit({
            ok: false,
            error: {
                code: 'BWRAP_RUNNER_JOB_PREP_FAILED',
                message: `failed to prepare job directory: ${err?.message || err}`,
            },
        });
        process.exit(1);
        return;
    }

    const args = buildBwrapArgs(validated, {
        workDir: dirs.workDir,
        outputsDir: dirs.outputsDir,
        existingSystemPaths: existingSystemPathsSet(),
    });

    const result = await runBwrap(args, validated, validated.limits);
    const stdout = truncateOutput(
        result.stdoutBuffer || Buffer.alloc(0),
        validated.limits.maxStdoutBytes,
        result.stdoutBytes,
    );
    const stderr = truncateOutput(
        result.stderrBuffer || Buffer.alloc(0),
        validated.limits.maxStderrBytes,
        result.stderrBytes,
    );

    const payloadOut = {
        ok: !result.spawnError && (result.exitCode === 0),
        jobId: dirs.jobId,
        exitCode: result.exitCode ?? null,
        signal: result.signal ?? null,
        timedOut: Boolean(result.timedOut),
        elapsedMs: result.elapsedMs,
        network: validated.network,
        stdout: {
            text: stdout.text,
            truncated: stdout.truncated,
            byteLength: stdout.byteLength,
        },
        stderr: {
            text: stderr.text,
            truncated: stderr.truncated,
            byteLength: stderr.byteLength,
        },
    };
    if (result.spawnError) {
        payloadOut.error = {
            code: 'BWRAP_RUNNER_SPAWN_FAILED',
            message: result.spawnError,
        };
    }
    emit(payloadOut);
}

main().catch((err) => {
    emit({
        ok: false,
        error: {
            code: 'BWRAP_RUNNER_UNEXPECTED',
            message: err?.message || String(err),
        },
    });
    process.exit(1);
});
