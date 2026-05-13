import fs from 'node:fs';
import path from 'node:path';

const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const ALLOWED_ENCODINGS = new Set(['utf8', 'base64']);

function rejectStagedFile(reason) {
    const error = new Error(reason);
    error.code = 'BWRAP_RUNNER_INVALID_INPUT';
    return error;
}

function normalizeLimits(limits = {}) {
    return {
        maxStagedFiles: Number.isFinite(limits.maxStagedFiles) ? limits.maxStagedFiles : 64,
        maxStagedFileBytes: Number.isFinite(limits.maxStagedFileBytes) ? limits.maxStagedFileBytes : 256 * 1024,
        maxStagedTotalBytes: Number.isFinite(limits.maxStagedTotalBytes) ? limits.maxStagedTotalBytes : 1024 * 1024,
        maxStagedPathLength: Number.isFinite(limits.maxStagedPathLength) ? limits.maxStagedPathLength : 256,
    };
}

function normalizeStagedPath(rawPath, limits) {
    if (typeof rawPath !== 'string') {
        throw rejectStagedFile('file path must be a string');
    }
    if (!rawPath.trim()) {
        throw rejectStagedFile('file path must be non-empty');
    }
    if (rawPath.includes('\0')) {
        throw rejectStagedFile('file path must not contain null bytes');
    }

    const normalized = rawPath.trim().replace(/\\/g, '/');
    if (normalized.length > limits.maxStagedPathLength) {
        throw rejectStagedFile(`file path exceeds ${limits.maxStagedPathLength} characters`);
    }
    if (path.posix.isAbsolute(normalized)) {
        throw rejectStagedFile('file path must be relative');
    }
    if (normalized.endsWith('/')) {
        throw rejectStagedFile('file path must not end with a slash');
    }

    const segments = normalized.split('/');
    if (segments.some((segment) => !segment || segment === '.' || segment === '..')) {
        throw rejectStagedFile('file path must not contain empty, dot, or traversal segments');
    }
    if (path.posix.normalize(normalized) !== normalized) {
        throw rejectStagedFile('file path must be normalized');
    }
    return normalized;
}

function decodeContent(entry, normalizedPath, limits) {
    const encoding = entry.encoding == null ? 'utf8' : String(entry.encoding).trim().toLowerCase();
    if (!ALLOWED_ENCODINGS.has(encoding)) {
        throw rejectStagedFile(`file '${normalizedPath}' has unsupported encoding '${encoding}'`);
    }
    if (typeof entry.content !== 'string') {
        throw rejectStagedFile(`file '${normalizedPath}' content must be a string`);
    }

    let buffer;
    if (encoding === 'base64') {
        const content = entry.content.trim();
        if (content.length % 4 === 1 || !BASE64_PATTERN.test(content)) {
            throw rejectStagedFile(`file '${normalizedPath}' content is not valid base64`);
        }
        buffer = Buffer.from(content, 'base64');
    } else {
        buffer = Buffer.from(entry.content, 'utf8');
    }

    if (buffer.length > limits.maxStagedFileBytes) {
        throw rejectStagedFile(`file '${normalizedPath}' exceeds ${limits.maxStagedFileBytes} bytes`);
    }
    return { encoding, buffer };
}

export function normalizeStagedFiles(rawFiles, options = {}) {
    const limits = normalizeLimits(options.limits);
    if (rawFiles == null) return [];
    if (!Array.isArray(rawFiles)) {
        throw rejectStagedFile('files must be an array when provided');
    }
    if (rawFiles.length > limits.maxStagedFiles) {
        throw rejectStagedFile(`files exceeds ${limits.maxStagedFiles} entries`);
    }

    const seen = new Set();
    const staged = [];
    let totalBytes = 0;
    for (const rawEntry of rawFiles) {
        if (!rawEntry || typeof rawEntry !== 'object' || Array.isArray(rawEntry)) {
            throw rejectStagedFile('file entries must be objects');
        }
        for (const key of Object.keys(rawEntry)) {
            if (!['path', 'content', 'encoding'].includes(key)) {
                throw rejectStagedFile(`unsupported file field '${key}'`);
            }
        }

        const normalizedPath = normalizeStagedPath(rawEntry.path, limits);
        if (seen.has(normalizedPath)) {
            throw rejectStagedFile(`duplicate staged file path '${normalizedPath}'`);
        }
        seen.add(normalizedPath);

        const decoded = decodeContent(rawEntry, normalizedPath, limits);
        totalBytes += decoded.buffer.length;
        if (totalBytes > limits.maxStagedTotalBytes) {
            throw rejectStagedFile(`files exceed ${limits.maxStagedTotalBytes} bytes total`);
        }
        staged.push({
            path: normalizedPath,
            encoding: decoded.encoding,
            byteLength: decoded.buffer.length,
            buffer: decoded.buffer,
        });
    }
    return staged;
}

function assertInsideWorkDir(workDir, targetPath) {
    const relative = path.relative(workDir, targetPath);
    if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
        throw rejectStagedFile('resolved file path escapes work directory');
    }
}

export function stageFiles(workDir, stagedFiles) {
    if (!Array.isArray(stagedFiles) || stagedFiles.length === 0) {
        return [];
    }
    const root = path.resolve(workDir);
    const written = [];
    for (const file of stagedFiles) {
        const targetPath = path.resolve(root, ...file.path.split('/'));
        assertInsideWorkDir(root, targetPath);
        fs.mkdirSync(path.dirname(targetPath), { recursive: true, mode: 0o700 });
        fs.writeFileSync(targetPath, file.buffer, { mode: 0o600, flag: 'wx' });
        written.push({
            path: file.path,
            byteLength: file.byteLength,
            hostPath: targetPath,
        });
    }
    return written;
}
