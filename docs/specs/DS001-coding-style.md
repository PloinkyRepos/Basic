---
id: DS001
title: Coding Style
status: implemented
owner: ploinky-team
summary: Defines coding style, source layout, documentation synchronization, and test organization for the Basic agent catalog.
---

# DS001 Coding Style

## Introduction

This specification is the coding-style authority for the Basic repository. It
defines how agent files, JavaScript modules, shell scripts, documentation, and
tests must be organized.

## Core Content

Agent directories must live at the repository root and use descriptive
lowercase or hyphenated names. Every runnable agent must include a
`manifest.json`. Additional files should live beside the behavior they support:
MCP tool declarations in the agent directory, JavaScript helper modules under an
agent-local `lib/`, executable wrappers under an agent-local `bin/`, and host
hook scripts under an agent-local `scripts/` directory.

JavaScript must use ES module syntax with `import` and `export`. Use four-space
indentation and trailing commas for multi-line literals. Keep functions small
enough that policy validation, argument generation, process execution, and
formatting can be tested independently. Comments should explain non-obvious
policy or runtime decisions; they must not narrate obvious assignments.

Shell scripts must start with an explicit shebang, fail fast with `set -e` or
`set -eu` when appropriate, and avoid assuming a particular interactive shell.
Scripts invoked by Ploinky host lifecycle hooks must be executable.

Configuration JSON must be formatted with two-space indentation for simple
manifests and consistently formatted within agent-local files. Manifest fields
must describe only behavior supported by Ploinky's runtime. When a manifest
uses profile hooks, runtime resources, MCP tools, readiness probes, or mounted
paths, the related documentation and DS files must be updated in the same
change set.

Tests must live under `tests/unit/` unless a future broader harness is added.
Unit tests should validate agent-local policy and manifest invariants without
requiring a full Ploinky workspace. Smoke tests that depend on host tools or
kernel capabilities must skip cleanly when those capabilities are unavailable.

`fileSizesCheck.sh` is the repository file-size and line-length helper. Future
large additions should be split by responsibility rather than concentrated in a
single oversized module.

## Decisions & Questions

### Question #1: Why is `DS001-coding-style.md` the coding-style authority?

Response: Centralizing coding style, source layout, and test organization in
one DS file gives future agents a stable reference and avoids spreading style
rules across README files, proposal documents, and transient handoff notes.

### Question #2: How should tests handle platform-specific sandbox behavior?

Response: Tests that verify pure policy must run everywhere. Tests that require
Linux bubblewrap or nested user namespaces must first probe those capabilities
and skip with a clear reason when the host cannot provide them.

## Conclusion

Basic code must remain agent-local, portable, and directly testable. Any change
that modifies runtime behavior, manifest semantics, documentation, or tests
must keep the DS specifications and HTML documentation synchronized.
