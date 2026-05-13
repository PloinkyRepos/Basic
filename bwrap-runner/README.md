# bwrap-runner

Basic repository Ploinky agent that runs bounded one-off commands inside nested
bubblewrap sandboxes from a Debian-based Node container.

## Installation

The agent lives at the Basic repository root as `bwrap-runner/`. After the
Basic repository is installed or enabled in a Ploinky workspace, the usual
agent resolution path can address it by `basic/bwrap-runner` or by the
short name `bwrap-runner` when that name is unambiguous.

The manifest uses the concrete image reference
`assistos/bwrap-runner:node24-bookworm`. The default profile also exposes
`BWRAP_RUNNER_IMAGE` with the same default for the host `preinstall` hook.
That hook runs `scripts/build-image.sh`; if the image is missing locally, the
script builds it with Podman or Docker before container creation.
The manifest requests `containerSecurity.privileged: true` so the outer OCI
runtime permits the inner bubblewrap sandbox to create namespaces and mount
`/proc`.

The canonical published image is built by the GitHub Actions workflow
`.github/workflows/publish-bwrap-runner.yml` on `ubuntu-latest` and pushed to
Docker Hub as `assistos/bwrap-runner:node24-bookworm` for both `linux/amd64`
and `linux/arm64`. Local image builds are still useful for development smoke
tests, but they are not the publishing authority.

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
- `files` (array, optional) - staged under `/work` before execution.
  Each entry is `{ "path": "relative/name", "content": "...",
  "encoding": "utf8"|"base64" }`. Paths must be normalized relative paths,
  are never interpreted as host paths, and are capped by the runner's staged
  file limits.
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

The `files` input is the preferred way for callers to provide prompts,
resources, and small driver configuration. Callers should not embed generated
runtime code in `command` just to create `/work` files; the runner owns that
staging responsibility and keeps it testable as policy code.

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
