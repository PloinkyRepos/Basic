# bwrap-runner

Basic repository Ploinky agent that runs bounded one-off commands inside nested
bubblewrap sandboxes from a Debian-based Node container.

## Installation

The agent lives at the Basic repository root as `bwrap-runner/`. After the
Basic repository is installed or enabled in a Ploinky workspace, the usual
agent resolution path can address it by `basic/bwrap-runner` or by the
short name `bwrap-runner` when that name is unambiguous.

The default profile uses `BWRAP_RUNNER_IMAGE` with default value
`ploinky/bwrap-runner:node20-bookworm`. Its host `preinstall` hook runs
`scripts/build-image.sh`; if that image is missing locally, the script
builds it with Podman or Docker before container creation. Set
`BWRAP_RUNNER_IMAGE` to use a pre-published image instead.

## Scope

This agent is **sandboxed job delegation**, not a replacement for
`lite-sandbox: true`. The host `bwrap`/Seatbelt path that
`lite-sandbox: true` selects is unchanged. Callers that want to delegate
a risky command to a containerized inner-bwrap environment can invoke
the `sandbox_exec` MCP tool on this agent instead.

## Tool: `sandbox_exec`

Inputs:

- `command` (string, required) - shell command run via `/bin/sh -lc`.
- `stdin` (string, optional) - fed to the child process.
- `timeoutMs` (number, optional) - capped server-side by
  `BWRAP_RUNNER_MAX_TIMEOUT_MS`.
- `env` (object, optional) - only allowlisted keys (`PATH`, `HOME`,
  `TMPDIR`, `LANG`, `LC_ALL`, `LC_CTYPE`) are forwarded after value
  validation. Raw user binds, mounts, capabilities, and bwrap flags are
  not supported.

Default policy applied inside the inner sandbox:

- `--die-with-parent`, `--unshare-user`, `--unshare-pid`,
  `--unshare-ipc`, `--unshare-uts`.
- `--unshare-net` unless the runner profile opts in via
  `BWRAP_RUNNER_ALLOW_NETWORK=true`.
- `--clearenv` followed by `--setenv` for the validated allowlisted env
  only.
- Read-only binds for `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, and a
  curated set of `/etc` files that exist in the image.
- `--proc /proc`, `--dev /dev`, `--tmpfs /tmp`.
- Per-job read-write `/work` directory and a sibling `/outputs`
  directory, both created under
  `BWRAP_RUNNER_STATE/jobs/<jobId>/`.

The wrapper returns a single-line JSON record:

```
{
  "ok": true|false,
  "jobId": "<uuid>",
  "exitCode": 0,
  "signal": null,
  "timedOut": false,
  "elapsedMs": 12,
  "network": "none",
  "stdout": {"text": "...", "truncated": false, "byteLength": 12},
  "stderr": {"text": "...", "truncated": false, "byteLength": 0}
}
```

`stdout` and `stderr` are truncated to the configured caps
(`BWRAP_RUNNER_MAX_STDOUT_BYTES`, `BWRAP_RUNNER_MAX_STDERR_BYTES`); the
`byteLength` field reports the original size.

## Secrets policy

The runner intentionally clears the environment before invoking
`bwrap`. Ploinky-issued secrets such as `PLOINKY_DERIVED_MASTER_KEY`,
invocation tokens, and workspace secrets are **not** propagated into
inner jobs. If a tool needs credentials it must accept them through the
validated `env` allowlist (currently limited to the standard runtime
variables).

## Readiness health check

The manifest `agent` command runs `bin/healthcheck.mjs` before starting
`AgentServer.sh`, and `healthcheck.sh` wires the same probe into
Ploinky's readiness loop. Both paths run a real nested-bwrap smoke
command. If the host kernel or outer container runtime blocks
`CLONE_NEWUSER`, startup/readiness fails with stderr describing the
failure. This image cannot bake host sysctls such as
`kernel.unprivileged_userns_clone` in; operators must configure those
settings on the host.

## v1 limitations

- Nested bubblewrap requires the host and outer OCI runtime to permit
  user namespace creation. The image ships `bwrap` but cannot relax
  host kernel or runtime policy. Ploinky does not currently expose a
  manifest field for raw OCI flags, and adding one is out of scope for
  this iteration.
- Networked jobs require an explicit operator opt-in via
  `BWRAP_RUNNER_ALLOW_NETWORK=true`. Per-request network selection is
  intentionally not exposed.
- This v1 does not transparently replace host bwrap. The
  `getRuntimeForAgent()` selector is unchanged, and `lite-sandbox:
  true` still dispatches to host bwrap on Linux or Seatbelt on macOS.
