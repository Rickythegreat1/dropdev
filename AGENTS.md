# DevDrop Agent Rules

## Mission

DevDrop is a full MVP for "Dropbox for devs": workspace readiness, machine map,
env profile awareness, local object store, lazy hydration simulation, sync
queue, conflicts, agent workspaces, CLI, Tauri UI, MCP, hooks, and skills.

## Non-Negotiable Scope

- Do not collapse DevDrop into a doctor-only CLI.
- Do not skip UX/aesthetic design.
- Do not skip sync invariants.
- Do not skip conflict or tombstone semantics.
- Do not skip tests.
- Do not skip red-team loops.

## Safety Boundaries

- Never print, serialize, display, or send secret values to agents.
- Never delete, overwrite, or move user files without dry-run and explicit
  approval.
- Never treat file watcher events as source of truth.
- Never sync generated dependency directories such as `node_modules` as content.
- Never hide sync conflicts.

## Implementation Principles

- Rust owns filesystem access, hashing, local object store, daemon, and CLI.
- React/Tauri owns desktop UX.
- SQLite owns local metadata, not global truth.
- BLAKE3 hashes identify content but do not establish trust.
- Every sync operation must be replayable from an event log.
- Every destructive action must be reversible or blocked.

## UX Principles

- Design for trust before power.
- Make invisible workspace state visible.
- Show causes, not just statuses.
- Avoid generic AI-dashboard visuals.
- No meaningless gradients, vague cards, fake glass, or default shadcn sameness.
- Every screen must answer: "Can I safely work here?"

## Required Loop

Before coding:

- Restate the task.
- List touched files.
- Classify task risk.
- Define tests/evals.
- Identify UX/aesthetic risks.

After coding:

- Run tests.
- Update `docs/loop-log.md`.
- Update docs if behavior changed.
- Run UX red-team if UI changed.
- Run security review if filesystem/env/sync changed.

## Model Escalation

- Cheap subagents can do docs, simple UI, fixtures, and tests.
- Stronger models are required for sync, secrets, deletion, hydration,
  permissions, conflict resolution, architecture, and UX direction.

