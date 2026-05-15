# basic — Sandbox/Runner Agents

Collection of containerized sandbox/runner agents used by Ploinky for safe code execution and file scanning. `AGENTS.md` is canonical for this subrepo.

## Subprojects

- `alpine-bash/`, `debian-bash/`, `fedora-bash/` — distro-specific shell containers.
- `bwrap-runner/` — bubblewrap-based isolation.
- `clamav-scanner/` — virus scan agent.
- `curl-agent/` — HTTP request agent.
- `docker-agent/` — Docker-in-Docker agent.

## Reading order

1. Parent `~/work/file-parser/CLAUDE.md` for workspace conventions.
2. `AGENTS.md` here for the full project guide.
3. The agent's `manifest.json` and entry point you're touching.

## Commit policy

Inherits workspace commit policy (no AI attribution). See `~/work/file-parser/CLAUDE.md`.
