// Runtime bundle resolution for the local sandbox runner.
//
// Provider agents prepare versioned runtimes under an agent-owned directory
// such as `/data/research-runtimes/<id>/<version>/`. The local runner accepts a
// typed `runtimeBundle: { id, version, digest? }` field and resolves it to a
// real path that is bound into the inner bwrap sandbox read-only at `/runtime`.
// The runtime root must be selected by provider configuration (env var
// `BWRAP_RUNNER_RUNTIME_ROOT`), never accepted from chat, relay, or
// agent-to-agent payloads. The runner does not bind `/shared` into inner jobs
// and does not accept caller-supplied raw mount paths.

import fs from 'node:fs';
import path from 'node:path';

const DEFAULT_RUNTIME_ROOT = '/data/research-runtimes';
const MANIFEST_BASENAME = 'manifest.json';
const ID_VERSION_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const SUPPORTED_MANIFEST_SCHEMA = 'ploinky.research-runtime';
const MAX_MANIFEST_BYTES = 64 * 1024;
const MAX_PYTHON_PATH_ENTRIES = 16;
const MAX_PYTHON_PATH_LENGTH = 1024;

function rejectInput(reason) {
    const error = new Error(reason);
    error.code = 'BWRAP_RUNNER_INVALID_RUNTIME_BUNDLE';
    return error;
}

function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function assertSafeIdentifier(label, value) {
    if (typeof value !== 'string' || value.length === 0) {
        throw rejectInput(`${label} must be a non-empty string`);
    }
    if (value.includes('\0')) {
        throw rejectInput(`${label} must not contain null bytes`);
    }
    if (value.includes('/') || value.includes('\\')) {
        throw rejectInput(`${label} must not contain path separators`);
    }
    if (value.includes('..')) {
        throw rejectInput(`${label} must not contain '..'`);
    }
    if (path.posix.isAbsolute(value) || path.win32.isAbsolute(value)) {
        throw rejectInput(`${label} must not be an absolute path`);
    }
    if (!ID_VERSION_PATTERN.test(value)) {
        throw rejectInput(`${label} must match ${ID_VERSION_PATTERN}`);
    }
    return value;
}

function assertSafeDigest(value) {
    if (value == null) return null;
    if (typeof value !== 'string' || !value.trim()) {
        throw rejectInput('runtimeBundle.digest must be a non-empty string when provided');
    }
    const normalized = value.trim();
    if (normalized.length > 256) {
        throw rejectInput('runtimeBundle.digest exceeds 256 characters');
    }
    if (!/^[A-Za-z0-9._:+\-]+$/.test(normalized)) {
        throw rejectInput('runtimeBundle.digest contains disallowed characters');
    }
    return normalized;
}

export function resolveRuntimeRoot(env = process.env) {
    const candidate = env && typeof env.BWRAP_RUNNER_RUNTIME_ROOT === 'string'
        ? env.BWRAP_RUNNER_RUNTIME_ROOT.trim()
        : '';
    const value = candidate || DEFAULT_RUNTIME_ROOT;
    if (!path.isAbsolute(value)) {
        throw rejectInput(`BWRAP_RUNNER_RUNTIME_ROOT must be an absolute path; got ${value}`);
    }
    if (value.includes('\0')) {
        throw rejectInput('BWRAP_RUNNER_RUNTIME_ROOT must not contain null bytes');
    }
    return path.posix.normalize(value);
}

export function validateRuntimeBundleInput(input) {
    if (input == null) return null;
    if (!isPlainObject(input)) {
        throw rejectInput('runtimeBundle must be an object when provided');
    }
    const allowedKeys = new Set(['id', 'version', 'digest']);
    for (const key of Object.keys(input)) {
        if (!allowedKeys.has(key)) {
            throw rejectInput(`unsupported runtimeBundle field '${key}'`);
        }
    }
    const id = assertSafeIdentifier('runtimeBundle.id', input.id);
    const version = assertSafeIdentifier('runtimeBundle.version', input.version);
    const digest = assertSafeDigest(input.digest);
    return { id, version, digest };
}

function readManifest(manifestPath) {
    let stat;
    try {
        stat = fs.statSync(manifestPath);
    } catch (err) {
        throw rejectInput(`runtime bundle manifest is missing at ${manifestPath}`);
    }
    if (!stat.isFile()) {
        throw rejectInput(`runtime bundle manifest at ${manifestPath} is not a regular file`);
    }
    if (stat.size > MAX_MANIFEST_BYTES) {
        throw rejectInput(`runtime bundle manifest exceeds ${MAX_MANIFEST_BYTES} bytes`);
    }
    let raw;
    try {
        raw = fs.readFileSync(manifestPath, 'utf8');
    } catch (err) {
        throw rejectInput(`failed to read runtime bundle manifest: ${err?.message || err}`);
    }
    let parsed;
    try {
        parsed = JSON.parse(raw);
    } catch (err) {
        throw rejectInput(`runtime bundle manifest is not valid JSON: ${err?.message || err}`);
    }
    if (!isPlainObject(parsed)) {
        throw rejectInput('runtime bundle manifest must be a JSON object');
    }
    return parsed;
}

function validateManifest(manifest, bundle) {
    if (manifest.schema !== SUPPORTED_MANIFEST_SCHEMA) {
        throw rejectInput(`runtime bundle manifest schema must be '${SUPPORTED_MANIFEST_SCHEMA}'`);
    }
    if (manifest.id !== bundle.id) {
        throw rejectInput(`runtime bundle manifest id '${manifest.id}' does not match requested id '${bundle.id}'`);
    }
    if (manifest.version !== bundle.version) {
        throw rejectInput(`runtime bundle manifest version '${manifest.version}' does not match requested version '${bundle.version}'`);
    }
    if (bundle.digest) {
        if (typeof manifest.digest !== 'string' || !manifest.digest.trim()) {
            throw rejectInput(`runtime bundle manifest must declare digest '${bundle.digest}' when runtimeBundle.digest is requested`);
        }
        if (manifest.digest !== bundle.digest) {
            throw rejectInput(`runtime bundle manifest digest '${manifest.digest}' does not match requested digest '${bundle.digest}'`);
        }
    }
    const env = extractManifestEnv(manifest);
    const entrypoints = extractManifestEntrypoints(manifest);
    return { env, entrypoints };
}

function extractManifestEnv(manifest) {
    const env = {};
    const python = manifest.python;
    if (python !== undefined && python !== null) {
        if (!isPlainObject(python)) {
            throw rejectInput('runtime bundle manifest python section must be an object');
        }
        const pythonPath = python.pythonPath;
        if (pythonPath !== undefined && pythonPath !== null) {
            if (!Array.isArray(pythonPath)) {
                throw rejectInput('runtime bundle manifest python.pythonPath must be an array');
            }
            if (pythonPath.length > MAX_PYTHON_PATH_ENTRIES) {
                throw rejectInput(`runtime bundle manifest python.pythonPath exceeds ${MAX_PYTHON_PATH_ENTRIES} entries`);
            }
            const cleaned = [];
            for (const entry of pythonPath) {
                if (typeof entry !== 'string' || !entry.trim()) {
                    throw rejectInput('runtime bundle manifest python.pythonPath entries must be non-empty strings');
                }
                if (entry.includes('\0')) {
                    throw rejectInput('runtime bundle manifest python.pythonPath entries must not contain null bytes');
                }
                if (!entry.startsWith('/runtime/') && entry !== '/runtime') {
                    throw rejectInput('runtime bundle manifest python.pythonPath entries must live under /runtime');
                }
                if (entry.includes('..')) {
                    throw rejectInput("runtime bundle manifest python.pythonPath entries must not contain '..'");
                }
                cleaned.push(entry);
            }
            const joined = cleaned.join(':');
            if (joined.length > MAX_PYTHON_PATH_LENGTH) {
                throw rejectInput(`runtime bundle manifest python.pythonPath joined value exceeds ${MAX_PYTHON_PATH_LENGTH} characters`);
            }
            if (joined) {
                env.PYTHONPATH = joined;
            }
        }
    }
    return env;
}

function extractManifestEntrypoints(manifest) {
    const out = {};
    if (manifest.entrypoints == null) {
        return out;
    }
    if (!isPlainObject(manifest.entrypoints)) {
        throw rejectInput('runtime bundle manifest entrypoints must be an object');
    }
    for (const [name, value] of Object.entries(manifest.entrypoints)) {
        if (typeof value !== 'string' || !value.trim()) {
            throw rejectInput(`runtime bundle manifest entrypoints.${name} must be a non-empty string`);
        }
        if (value.includes('\0')) {
            throw rejectInput(`runtime bundle manifest entrypoints.${name} must not contain null bytes`);
        }
        if (!value.startsWith('/runtime/')) {
            throw rejectInput(`runtime bundle manifest entrypoints.${name} must start with /runtime/`);
        }
        if (value.includes('..')) {
            throw rejectInput(`runtime bundle manifest entrypoints.${name} must not contain '..'`);
        }
        out[name] = value;
    }
    return out;
}

function ensureInsideRoot(realRoot, realPath, label) {
    const relative = path.relative(realRoot, realPath);
    if (relative === '' || relative === '.') return;
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
        throw rejectInput(`${label} resolves outside the runtime root`);
    }
}

export function resolveRuntimeBundle(input, options = {}) {
    const bundle = validateRuntimeBundleInput(input);
    if (!bundle) return null;
    const env = options.env || process.env;
    const runtimeRoot = options.runtimeRoot || resolveRuntimeRoot(env);

    let realRoot;
    try {
        realRoot = fs.realpathSync(runtimeRoot);
    } catch (err) {
        throw rejectInput(`runtime root '${runtimeRoot}' is not available: ${err?.message || err}`);
    }
    let realRootStat;
    try {
        realRootStat = fs.statSync(realRoot);
    } catch (err) {
        throw rejectInput(`runtime root '${runtimeRoot}' could not be stat'd: ${err?.message || err}`);
    }
    if (!realRootStat.isDirectory()) {
        throw rejectInput(`runtime root '${runtimeRoot}' is not a directory`);
    }

    const candidateBundleDir = path.join(realRoot, bundle.id, bundle.version);
    let realBundleDir;
    try {
        realBundleDir = fs.realpathSync(candidateBundleDir);
    } catch (err) {
        throw rejectInput(`runtime bundle '${bundle.id}@${bundle.version}' is not available under ${runtimeRoot}`);
    }
    ensureInsideRoot(realRoot, realBundleDir, `runtime bundle '${bundle.id}@${bundle.version}'`);

    let bundleStat;
    try {
        bundleStat = fs.statSync(realBundleDir);
    } catch (err) {
        throw rejectInput(`runtime bundle '${bundle.id}@${bundle.version}' is unavailable: ${err?.message || err}`);
    }
    if (!bundleStat.isDirectory()) {
        throw rejectInput(`runtime bundle '${bundle.id}@${bundle.version}' is not a directory`);
    }

    const manifestPath = path.join(realBundleDir, MANIFEST_BASENAME);
    let realManifestPath;
    try {
        realManifestPath = fs.realpathSync(manifestPath);
    } catch (err) {
        throw rejectInput(`runtime bundle manifest is missing at ${manifestPath}`);
    }
    ensureInsideRoot(realBundleDir, realManifestPath, `runtime bundle manifest for '${bundle.id}@${bundle.version}'`);

    const manifest = readManifest(realManifestPath);
    const { env: manifestEnv, entrypoints } = validateManifest(manifest, bundle);

    return {
        id: bundle.id,
        version: bundle.version,
        digest: bundle.digest || null,
        runtimeRoot: realRoot,
        bundleDir: realBundleDir,
        manifestPath: realManifestPath,
        manifest,
        env: manifestEnv,
        entrypoints,
        containerMount: '/runtime',
    };
}

export const RUNTIME_BUNDLE_INTERNALS = Object.freeze({
    DEFAULT_RUNTIME_ROOT,
    MANIFEST_BASENAME,
    SUPPORTED_MANIFEST_SCHEMA,
    ID_VERSION_PATTERN,
    MAX_MANIFEST_BYTES,
});
