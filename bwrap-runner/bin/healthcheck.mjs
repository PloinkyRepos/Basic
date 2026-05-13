#!/usr/bin/env node
// Readiness health check for the bwrap-runner agent.
//
// Runs an actual nested bwrap smoke command and fails clearly if the host or
// outer container runtime blocks nested user namespaces. The script writes a
// short JSON record to stdout summarising the outcome.

import fs from 'node:fs';
import { spawnSync } from 'node:child_process';

const BWRAP_PATH = '/usr/bin/bwrap';

function emit(record) {
    try {
        process.stdout.write(`${JSON.stringify(record)}\n`);
    } catch (_) {}
}

function exitFail(message, extra = {}) {
    emit({ ok: false, message, ...extra });
    process.exit(1);
}

function exitOk(message, extra = {}) {
    emit({ ok: true, message, ...extra });
    process.exit(0);
}

if (!fs.existsSync(BWRAP_PATH)) {
    exitFail(`bubblewrap binary not found at ${BWRAP_PATH}`);
}

const args = [
    '--die-with-parent',
    '--unshare-user',
    '--unshare-pid',
    '--unshare-ipc',
    '--unshare-uts',
    '--unshare-net',
    '--clearenv',
    '--setenv', 'PATH', '/usr/bin:/bin',
    '--ro-bind', '/usr', '/usr',
];

if (fs.existsSync('/lib')) args.push('--ro-bind', '/lib', '/lib');
if (fs.existsSync('/lib64')) args.push('--ro-bind', '/lib64', '/lib64');
if (fs.existsSync('/bin')) args.push('--ro-bind', '/bin', '/bin');

args.push(
    '--proc', '/proc',
    '--dev', '/dev',
    '--tmpfs', '/tmp',
    '--', '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', '/bin/sh', '-c', 'echo bwrap-nested-ok'
);

const result = spawnSync(BWRAP_PATH, args, {
    encoding: 'utf8',
    timeout: 10_000,
});

if (result.error) {
    exitFail(`bwrap spawn failed: ${result.error.message || result.error}`, {
        stderr: (result.stderr || '').trim(),
    });
}

if (result.status !== 0) {
    const stderr = (result.stderr || '').trim();
    exitFail(`nested bwrap smoke command failed with exit code ${result.status}`, {
        stderr,
        guidance: [
            'Nested bubblewrap requires the host kernel to permit user namespace creation',
            'and the outer container runtime (docker/podman) to allow it.',
            'Common causes: kernel.unprivileged_userns_clone=0, restrictive seccomp/AppArmor profile,',
            'or rootless container settings that block CLONE_NEWUSER.',
            'This image cannot bake those host settings in; the operator must adjust them.',
        ].join(' '),
    });
}

const stdout = (result.stdout || '').trim();
if (stdout !== 'bwrap-nested-ok') {
    exitFail(`unexpected nested bwrap output: ${stdout || '<empty>'}`);
}

exitOk('nested bwrap smoke command succeeded');
