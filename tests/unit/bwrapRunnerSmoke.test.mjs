// Smoke test for the bwrap-runner agent's nested-bwrap healthcheck.
//
// This test only runs when /usr/bin/bwrap exists AND a probing nested
// user-namespace command succeeds. Otherwise we skip cleanly; CI runners
// without nested-namespace support should not fail this test.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BWRAP_PATH = '/usr/bin/bwrap';
const HEALTHCHECK = path.resolve(__dirname, '../../bwrap-runner/bin/healthcheck.mjs');

function probeNestedBwrap() {
    if (!fs.existsSync(BWRAP_PATH)) {
        return { ok: false, reason: 'bwrap binary not installed at /usr/bin/bwrap' };
    }
    const probe = spawnSync(BWRAP_PATH, [
        '--unshare-user',
        '--unshare-pid',
        '--ro-bind', '/usr', '/usr',
        '--proc', '/proc',
        '--dev', '/dev',
        '--tmpfs', '/tmp',
        '--', '/bin/true',
    ], { encoding: 'utf8', timeout: 5_000 });
    if (probe.error) {
        return { ok: false, reason: `bwrap probe spawn error: ${probe.error.message}` };
    }
    if (probe.status !== 0) {
        return {
            ok: false,
            reason: `bwrap probe failed (exit=${probe.status}): ${String(probe.stderr || '').trim()}`,
        };
    }
    return { ok: true };
}

test('healthcheck.mjs reports OK when nested bwrap works', { concurrency: false }, (t) => {
    const probe = probeNestedBwrap();
    if (!probe.ok) {
        t.skip(`nested bwrap unavailable: ${probe.reason}`);
        return;
    }
    const result = spawnSync(process.execPath, [HEALTHCHECK], {
        encoding: 'utf8',
        timeout: 15_000,
    });
    assert.strictEqual(result.status, 0,
        `healthcheck failed: stdout=${result.stdout} stderr=${result.stderr}`);
    const line = String(result.stdout || '').trim().split('\n').pop();
    const record = JSON.parse(line);
    assert.strictEqual(record.ok, true);
});
