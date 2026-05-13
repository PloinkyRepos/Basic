# Basic Agent Catalog Guidance

## Scope

This repository is the Basic Ploinky agent catalog. Each top-level agent
directory is a portable agent package with its own `manifest.json` and any
agent-local scripts, documentation, tests, and runtime support files.

The DS specifications under `docs/specs/` are the source of truth for repository
contracts. When source code or manifests change, update both the HTML
documentation and the relevant DS specifications in the same change set.
All documentation, specifications, and code comments must be written in English.

## Mandatory Reading Order

1. Read `docs/specs/DS000-vision.md` for the catalog boundary.
2. Read `docs/specs/DS001-coding-style.md` for coding style, module structure,
   file-size guidance, and test organization rules.
3. Read the relevant per-agent DS file before changing an agent with a dedicated
   specification, such as `docs/specs/DS002-bwrap-runner-agent.md`.
4. Read `docs/index.html` and the affected technical documentation page before
   documentation changes.

## Current Skill Catalog

This repository does not define repository-local Codex skills. It packages
Ploinky agents. If repository-local skills are added later, `AGENTS.md`,
`docs/index.html`, and `docs/specs/matrix.md` must be updated in the same
change set. Imported skills from downstream consumers must stay documented
inside their own skill folders and must not create imported-skill DS files or
standalone skill pages in this repository.

## Repository Rules

Agent directories live at the repository root. New agents must keep their
runtime files inside the agent directory and must expose a valid
`manifest.json`. Shared root source trees are not allowed for agent-local
runtime code because Basic agents must remain portable when copied or cloned as
individual catalog entries.

`DS001-coding-style.md` is the coding-style authority. DS numbering must remain
gap-free, starting with `DS000-vision.md` and `DS001-coding-style.md`.
`Decisions & Questions` sections use numbered question subchapters, and design
rationale belongs inside the affected DS file rather than in a separate
decision log.

The GAMP skill itself must be updated when new skill families, coding-style
rules, or project bootstrap rules are introduced.

## Runtime Defaults

Ploinky runs Basic agents through the normal agent catalog path under
`.ploinky/repos/basic/<agent>/`. Containerized agents declare their image,
profile hooks, ports, mounts, runtime resources, readiness behavior, and MCP
tools in their own manifests and support files.

The `bwrap-runner` agent is a normal containerized Basic agent. It is not a
replacement for Ploinky's `lite-sandbox: true` host-sandbox backend.

## Key Paths

- `docs/index.html` - HTML documentation entry point.
- `docs/bwrap-runner.html` - technical documentation for the bwrap runner.
- `docs/specs/` - DS specification source of truth.
- `docs/specs/matrix.md` - generated specification matrix.
- `docs/specsLoader.html?spec=matrix.md` - browser entry point for specs.
- `bwrap-runner/` - Basic catalog bwrap runner agent.
- `tests/unit/` - focused Node unit and smoke tests.
