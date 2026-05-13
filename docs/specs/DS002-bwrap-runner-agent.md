---
id: DS002
title: bwrap Runner Agent
status: implemented
owner: ploinky-team
summary: Defines the bwrap-runner agent contract for nested bubblewrap job delegation, startup health checks, policy validation, and output handling.
---

# DS002 bwrap Runner Agent

## Introduction

`bwrap-runner` is a Basic catalog agent that provides sandboxed job delegation
through a single MCP tool named `sandbox_exec`. It runs as a normal Ploinky
container agent and creates an inner bubblewrap sandbox for each accepted job.

## Core Content

The agent must not be documented or implemented as a transparent replacement
for Ploinky's `lite-sandbox: true` host-sandbox backend. `lite-sandbox: true`
continues to select the host sandbox path for an entire agent process. The
`bwrap-runner` agent instead lets callers delegate individual bounded commands
to a Linux container image that includes bubblewrap.

The manifest must use normal container execution. The image reference is
resolved through `BWRAP_RUNNER_IMAGE`, whose default is
`ploinky/bwrap-runner:node20-bookworm`. The default profile must run
`scripts/build-image.sh` as a host preinstall hook so a local Podman or Docker
image is available before Ploinky creates the container. Operators may override
`BWRAP_RUNNER_IMAGE` to use a published image.

Startup must gate AgentServer on a real nested-bwrap smoke check. The manifest
`agent` command must run `bin/healthcheck.mjs` before `AgentServer.sh`, and the
readiness script must expose the same health check through Ploinky's readiness
loop. A failed nested namespace probe must fail clearly with stderr and guidance
instead of letting MCP readiness report success.

The `sandbox_exec` tool must accept only a narrow typed payload:
`command`, optional `stdin`, optional `timeoutMs`, and optional `env`.
The wrapper must reject extra top-level fields, including user-provided mounts,
bind paths, network selectors, capabilities, or raw bubblewrap flags.
Environment forwarding must be allowlisted and value-validated.

The inner bubblewrap policy must be generated as a fixed argv policy by
`bwrap-runner/lib/policy.mjs`. The default policy must use `--die-with-parent`,
unshare user, PID, IPC, UTS, and network namespaces, clear the environment,
set only validated environment values, bind selected system paths read-only,
provide `/proc`, `/dev`, and a tmpfs `/tmp`, and bind per-job writable
directories at `/work` and `/outputs`. Network access may be enabled only by an
operator-wide `BWRAP_RUNNER_ALLOW_NETWORK=true` setting.

The wrapper must create per-job state under `BWRAP_RUNNER_STATE/jobs/<jobId>/`.
It must spawn bubblewrap with an empty outer environment so Ploinky secrets,
derived master keys, and invocation tokens are not inherited by the inner job.
It must enforce the validated timeout and emit one structured JSON record with
job id, exit code, signal, timeout state, elapsed time, network mode, stdout,
and stderr. Output truncation must retain the tail of each stream and report the
original byte length.

The agent image can install bubblewrap, but it cannot guarantee that nested
namespaces are permitted by the host kernel or by the outer Docker or Podman
runtime. Those host and OCI policies remain operator responsibilities.

## Decisions & Questions

### Question #1: Why is bwrap-runner a Basic catalog agent instead of Ploinky core code?

Response: The first useful behavior is sandboxed job delegation through MCP,
which fits the agent catalog model. Ploinky core owns runtime backend selection;
placing this implementation in Basic avoids changing the `lite-sandbox: true`
contract and keeps the runner installable like other baseline agents.

### Question #2: Why does startup run the nested-bwrap health check before AgentServer?

Response: Ploinky readiness can otherwise observe a running AgentServer even
when the inner bubblewrap primitive is unusable. Running `bin/healthcheck.mjs`
before `AgentServer.sh` makes the essential capability a startup gate and turns
host or OCI namespace failures into explicit operational errors.

### Question #3: Why is per-request network selection not exposed?

Response: Network access changes the sandbox risk profile. The implemented
contract permits only an operator-wide `BWRAP_RUNNER_ALLOW_NETWORK=true`
setting, so callers cannot request network inheritance through the tool
payload.

## Conclusion

`bwrap-runner` must remain a narrow, testable sandbox delegation agent. Its
security boundary comes from a fixed wrapper policy, clear startup health
checks, empty environment inheritance, per-job state, and explicit limits rather
than from caller-supplied bubblewrap flags.
