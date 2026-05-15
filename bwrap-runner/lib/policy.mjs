// Policy builder for the bwrap-runner sandbox_exec tool.
//
// All argv generation lives here so it can be unit tested without invoking
// bwrap. The caller (sandbox-exec.mjs) is responsible for creating the
// per-job /work directory and passing absolute paths.

const ALLOWED_ENV_KEYS = new Set([
    'PATH',
    'HOME',
    'TMPDIR',
    'LANG',
    'LC_ALL',
    'LC_CTYPE',
]);

const ENV_KEY_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;
const ENV_VALUE_PATTERN = /^[\x20-\x7E]{0,4096}$/;

const DEFAULT_ENV = Object.freeze({
    PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    HOME: '/work',
    TMPDIR: '/tmp',
    LANG: 'C.UTF-8',
});

const SYSTEM_RO_PATHS = Object.freeze([
    '/usr',
    '/lib',
    '/lib64',
    '/bin',
    '/sbin',
    '/etc/resolv.conf',
    '/etc/hosts',
    '/etc/passwd',
    '/etc/group',
    '/etc/nsswitch.conf',
    '/etc/ld.so.cache',
    '/etc/ssl',
    '/etc/ca-certificates',
    '/etc/pki',
    '/etc/alternatives',
]);

export const POLICY_LIMITS = Object.freeze({
    maxCommandLength: 4096,
    maxStdinBytes: 1024 * 1024,
    maxTimeoutMs: 120 * 1000,
    minTimeoutMs: 100,
    defaultTimeoutMs: 30 * 1000,
    maxStdoutBytes: 64 * 1024,
    maxStderrBytes: 64 * 1024,
    maxEnvEntries: 16,
    maxStagedFiles: 64,
    maxStagedFileBytes: 256 * 1024,
    maxStagedTotalBytes: 1024 * 1024,
    maxStagedPathLength: 256,
});

export function getAllowedEnvKeys() {
    return new Set(ALLOWED_ENV_KEYS);
}

export function getSystemReadOnlyPaths() {
    return [...SYSTEM_RO_PATHS];
}

function clampNumber(value, min, max) {
    if (!Number.isFinite(value)) return null;
    if (value < min || value > max) return null;
    return Math.floor(value);
}

function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function normalizeLimits(limits) {
    const base = { ...POLICY_LIMITS };
    if (!isPlainObject(limits)) return base;
    for (const key of Object.keys(base)) {
        const raw = limits[key];
        const value = typeof raw === 'string' ? Number.parseInt(raw, 10) : raw;
        if (Number.isFinite(value) && value > 0) {
            base[key] = Math.floor(value);
        }
    }
    if (base.maxTimeoutMs < base.minTimeoutMs) {
        base.maxTimeoutMs = base.minTimeoutMs;
    }
    if (base.defaultTimeoutMs > base.maxTimeoutMs) {
        base.defaultTimeoutMs = base.maxTimeoutMs;
    }
    if (base.defaultTimeoutMs < base.minTimeoutMs) {
        base.defaultTimeoutMs = base.minTimeoutMs;
    }
    return base;
}

function rejectInput(reason) {
    const error = new Error(reason);
    error.code = 'BWRAP_RUNNER_INVALID_INPUT';
    return error;
}

export function validateInput(rawInput, options = {}) {
    const limits = normalizeLimits(options.limits);

    if (!isPlainObject(rawInput)) {
        throw rejectInput('input must be an object');
    }

    const command = rawInput.command;
    if (typeof command !== 'string' || !command.trim()) {
        throw rejectInput('command must be a non-empty string');
    }
    if (command.length > limits.maxCommandLength) {
        throw rejectInput(`command exceeds ${limits.maxCommandLength} characters`);
    }
    if (command.indexOf('\0') !== -1) {
        throw rejectInput('command must not contain null bytes');
    }

    let stdin = null;
    if (rawInput.stdin !== undefined && rawInput.stdin !== null) {
        if (typeof rawInput.stdin !== 'string') {
            throw rejectInput('stdin must be a string when provided');
        }
        const byteLength = Buffer.byteLength(rawInput.stdin, 'utf8');
        if (byteLength > limits.maxStdinBytes) {
            throw rejectInput(`stdin exceeds ${limits.maxStdinBytes} bytes`);
        }
        stdin = rawInput.stdin;
    }

    let timeoutMs = limits.defaultTimeoutMs;
    if (rawInput.timeoutMs !== undefined && rawInput.timeoutMs !== null) {
        const clamped = clampNumber(Number(rawInput.timeoutMs), limits.minTimeoutMs, limits.maxTimeoutMs);
        if (clamped === null) {
            throw rejectInput(`timeoutMs must be a number between ${limits.minTimeoutMs} and ${limits.maxTimeoutMs}`);
        }
        timeoutMs = clamped;
    }

    const env = {};
    if (rawInput.env !== undefined && rawInput.env !== null) {
        if (!isPlainObject(rawInput.env)) {
            throw rejectInput('env must be a plain object when provided');
        }
        const entries = Object.entries(rawInput.env);
        if (entries.length > limits.maxEnvEntries) {
            throw rejectInput(`env exceeds ${limits.maxEnvEntries} entries`);
        }
        for (const [key, value] of entries) {
            if (!ALLOWED_ENV_KEYS.has(key)) {
                throw rejectInput(`env key '${key}' is not in the allowlist`);
            }
            if (!ENV_KEY_PATTERN.test(key)) {
                throw rejectInput(`env key '${key}' is not a valid identifier`);
            }
            if (typeof value !== 'string') {
                throw rejectInput(`env value for '${key}' must be a string`);
            }
            if (!ENV_VALUE_PATTERN.test(value)) {
                throw rejectInput(`env value for '${key}' contains disallowed characters`);
            }
            env[key] = value;
        }
    }

    // Reject any attempt to smuggle extra fields like mounts/binds/network.
    for (const key of Object.keys(rawInput)) {
        if (!['command', 'stdin', 'timeoutMs', 'env', 'files', 'runtimeBundle'].includes(key)) {
            throw rejectInput(`unsupported field '${key}'`);
        }
    }

    const networkAllowed = options.allowNetwork === true;

    return {
        command,
        stdin,
        timeoutMs,
        env,
        files: rawInput.files,
        runtimeBundle: rawInput.runtimeBundle ?? null,
        network: networkAllowed ? 'inherit' : 'none',
        limits,
    };
}

function ensureAbsolutePath(label, value) {
    if (typeof value !== 'string' || value.length === 0) {
        throw rejectInput(`${label} must be a non-empty string`);
    }
    if (!value.startsWith('/')) {
        throw rejectInput(`${label} must be an absolute path`);
    }
    if (value.includes('\0')) {
        throw rejectInput(`${label} must not contain null bytes`);
    }
    if (value.includes('..')) {
        throw rejectInput(`${label} must not contain '..'`);
    }
    return value;
}

export function buildBwrapArgs(validated, paths) {
    if (!isPlainObject(paths)) {
        throw rejectInput('paths argument is required');
    }
    const workDir = ensureAbsolutePath('paths.workDir', paths.workDir);
    let outputsDir = null;
    if (paths.outputsDir !== undefined && paths.outputsDir !== null) {
        outputsDir = ensureAbsolutePath('paths.outputsDir', paths.outputsDir);
    }
    const existingPaths = paths.existingSystemPaths instanceof Set
        ? paths.existingSystemPaths
        : null;
    const runtimeBundle = paths.runtimeBundle && isPlainObject(paths.runtimeBundle)
        ? paths.runtimeBundle
        : null;
    let runtimeBundleDir = null;
    if (runtimeBundle) {
        runtimeBundleDir = ensureAbsolutePath('paths.runtimeBundle.bundleDir', runtimeBundle.bundleDir);
    }

    const args = [];
    args.push('--die-with-parent');
    args.push('--unshare-user');
    args.push('--unshare-pid');
    args.push('--unshare-ipc');
    args.push('--unshare-uts');
    if (validated.network !== 'inherit') {
        args.push('--unshare-net');
    }
    args.push('--clearenv');

    // Allowlisted env: defaults first, then manifest-derived runtime env, then
    // validated caller overrides. Runtime-derived env (e.g. PYTHONPATH from
    // manifest.python.pythonPath) is applied independently of the user env
    // allowlist because it comes from a validated bundle manifest, not caller
    // input.
    const finalEnv = { ...DEFAULT_ENV };
    if (runtimeBundle && isPlainObject(runtimeBundle.env)) {
        for (const [key, value] of Object.entries(runtimeBundle.env)) {
            if (typeof value === 'string') {
                finalEnv[key] = value;
            }
        }
    }
    for (const [key, value] of Object.entries(validated.env || {})) {
        finalEnv[key] = value;
    }
    for (const key of Object.keys(finalEnv).sort()) {
        args.push('--setenv', key, finalEnv[key]);
    }

    for (const systemPath of SYSTEM_RO_PATHS) {
        if (existingPaths && !existingPaths.has(systemPath)) continue;
        args.push('--ro-bind', systemPath, systemPath);
    }

    args.push('--proc', '/proc');
    args.push('--dev', '/dev');
    args.push('--tmpfs', '/tmp');

    args.push('--bind', workDir, '/work');
    if (outputsDir) {
        args.push('--bind', outputsDir, '/outputs');
    }
    if (runtimeBundleDir) {
        args.push('--ro-bind', runtimeBundleDir, '/runtime');
    }
    args.push('--chdir', '/work');

    args.push('--', '/bin/sh', '-lc', validated.command);
    return args;
}

export function truncateOutput(text, maxBytes, originalByteLength = null) {
    const buffer = Buffer.isBuffer(text)
        ? text
        : Buffer.from(String(text == null ? '' : text), 'utf8');
    const byteLength = Number.isFinite(originalByteLength) && originalByteLength >= buffer.length
        ? Math.floor(originalByteLength)
        : buffer.length;
    if (byteLength <= maxBytes) {
        return { text: buffer.toString('utf8'), truncated: false, byteLength };
    }
    return {
        text: buffer.subarray(buffer.length - maxBytes).toString('utf8'),
        truncated: true,
        byteLength,
    };
}

export function decideNetworkPolicy(envValue) {
    const normalized = String(envValue || '').trim().toLowerCase();
    return ['1', 'true', 'yes', 'on'].includes(normalized);
}
