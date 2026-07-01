---
name: devdrop-feature-slice
description: Plan or implement a gated DevDrop feature slice with scoped files, tests, risk class, UX criteria, design critique criteria, and required closeout.
---

# DevDrop Feature Slice

## When To Use

- Use for any DevDrop feature slice, scaffold expansion, CLI command, desktop route, core model, MCP tool, hook, fixture, or eval.
- Use when a request needs scope control across Rust, React/Tauri, docs, fixtures, or Codex automation.
- Use when the work must prove it does not collapse DevDrop into a doctor-only tool.

## When Not To Use

- Do not use for a pure code-review request; use the review posture instead.
- Do not use to approve destructive sync, deletion, overwrite, Git mutation, or hydration apply without preview, approval, rollback notes, and tests.
- Do not use as a substitute for the sync invariant, UX, or aesthetic red-team skills when those risks are present.

## Required Inputs

- User goal and slice name.
- Intended product surface: CLI, desktop, core engine, sync, env/profile, agent/Codex, MCP, hooks, docs, or evals.
- Expected touched files or directories.
- Safety-sensitive areas: secrets, filesystem mutation, Git mutation, object store writes, sync apply, tombstones, conflicts, hydration, permissions.
- UX/aesthetic surfaces if any UI or copy changes.

## Required Outputs

- Restated task.
- Touched files list.
- Risk class: low, medium, high, or blocked.
- Implementation scope and explicit non-goals.
- Tests/evals to add or run.
- UX criteria and aesthetic critique criteria when UI/copy changes.
- Required six-part DevDrop closeout.

## Checklist

- Read `AGENTS.md` before coding.
- Confirm the slice keeps the full MVP in view: registry, readiness, machine map, env profiles, CAS, hydration, queue, tombstones, conflicts, planner, handoff, CLI, desktop, MCP, hooks, skills, and evals.
- Mark destructive behavior as blocked or dry-run until safety gates exist.
- Keep env values, raw file contents, and secret-like values out of logs, CLI output, MCP responses, handoff JSON, and tests.
- Prefer deterministic fixture-backed tests before broad behavior.
- Update docs and loop log when behavior or contracts change.
- Run UX red-team for UI changes and security review for filesystem/env/sync changes.

## Examples

- "Implement Slice 2 readiness scanner" -> list core, CLI, fixture, docs, and eval files; classify env/Git observation as medium risk; require redaction tests.
- "Add Sync Queue page shell" -> touch desktop route and design docs; classify low runtime risk; require UX/aesthetic critique for trust copy and non-generic layout.
- "Add tombstone apply" -> classify high or blocked until preview, approval, rollback notes, and fixture tests exist.

## Failure Modes

- Treating DevDrop as only `devdrop doctor`.
- Shipping a mutating command with friendly copy but no rollback path.
- Adding UI that hides causes behind vague status labels.
- Forgetting docs, loop log, fixture tests, or red-team criteria.
- Letting secret values or generated paths enter a handoff, object model, or test snapshot.
