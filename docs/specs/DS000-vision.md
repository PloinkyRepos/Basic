---
id: DS000
title: Vision
status: implemented
owner: ploinky-team
summary: Defines the Basic repository as a portable Ploinky agent catalog with self-contained agent directories and DS specifications as the source of truth.
---

# DS000 Vision

## Introduction

The Basic repository is a Ploinky agent catalog. Its primary responsibility is
to package useful baseline agents in a form that Ploinky can clone, inspect,
enable, and run through the normal workspace repository layout.

## Core Content

Each top-level agent directory must be self-contained. The agent directory owns
its `manifest.json` and any supporting scripts, MCP configuration, runtime
policy modules, local README files, and agent-specific assets. Shared runtime
services such as routing, workspace state management, profile resolution,
container startup, and host sandbox selection remain responsibilities of the
Ploinky runtime, not this catalog.

The catalog must avoid hidden cross-agent runtime dependencies. If an agent
needs executable support code, that code must live inside the agent directory
unless a dependency is intentionally supplied by the base container image or by
Ploinky's mounted `/Agent` runtime. This portability rule lets individual Basic
agents be copied into workspaces or external repositories without requiring a
separate root source tree.

The documentation set under `docs/` and the DS specifications under
`docs/specs/` must stay synchronized with implemented agent behavior. The DS
specifications are the source of truth for durable repository contracts. HTML
documentation explains those contracts for human readers but must not introduce
additional guarantees that are absent from the DS files or the implementation.

## Decisions & Questions

### Question #1: Why is Basic documented as an agent catalog rather than a runtime?

Response: Basic does not own Ploinky's router, lifecycle manager, host sandbox
backend, invocation security, or workspace registry. It contributes agent
packages that the runtime consumes. Keeping that boundary explicit prevents
agent manifests from being documented as if they could change runtime backend
selection or host policy by themselves.

### Question #2: Where should agent-specific executable code live?

Response: Agent-specific executable code must live inside the agent directory.
This keeps each Basic agent portable and prevents copied agents from depending
on an unstated repository-root `src/` tree.

## Conclusion

Basic must remain a portable, flat Ploinky agent catalog. Agent packages own
their local behavior, while Ploinky owns the runtime machinery that loads and
executes them.
