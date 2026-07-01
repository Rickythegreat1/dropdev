---
name: devdrop-sync-invariant-review
description: Review DevDrop sync, hydration, queue, tombstone, conflict, deletion, Git, CAS, and watcher code against non-negotiable safety invariants.
---

# DevDrop Sync Invariant Review

## When To Use

- Use before accepting changes to sync planning, sync apply, hydration, dehydration, CAS, queueing, tombstones, conflicts, watchers, reconciliation scans, Git observation, or Git mutation previews.
- Use when code touches ignored/generated path policy, env profile handling, event logs, machine state, or agent handoff safety.
- Use when a command might delete, overwrite, move, hydrate, dehydrate, write CAS objects, or mutate Git state.

## When Not To Use

- Do not use as a broad product-planning skill; use `devdrop-feature-slice` first.
- Do not use to waive safety gates.
- Do not use for purely visual critique unless sync truthfulness is affected.

## Required Inputs

- Files and functions changed.
- Operation type: read-only, dry-run, preview, approval-gated, or mutating.
- Relevant fixtures and expected before/after state.
- Env, ignored-path, Git, tombstone, conflict, hydration, and event-log implications.
- Tests proving invariants hold.

## Required Outputs

- Pass/fail findings ordered by severity.
- Exact invariant violated or satisfied.
- Required fixture or test gap.
- Whether the work is blocked, dry-run only, or safe to continue.
- Rollback or restore requirement for any destructive path.

## Checklist

- Watcher events are hints only; reconciliation scans are truth.
- Env values and raw file contents never enter CAS, MCP, handoff, logs, or test snapshots.
- Generated paths such as `node_modules`, `.next`, `dist`, `target`, `logs`, and `*.log` are excluded from content storage by default.
- Sync apply requires dry-run plan, explicit approval, dirty-file protection, rollback notes, and fixture tests.
- Deletions are tombstones before any removal is possible.
- Conflicts preserve both sides and never resolve silently.
- Hydration simulations do not masquerade as real local content.
- Git mutation is preview-only until explicit approval and tests exist.
- Event log entries are replayable and do not rely on wall-clock luck or watcher-only truth.

## Examples

- "Add queue preview" -> verify it is read-only, names blocked destructive actions, and does not claim apply succeeded.
- "Implement tombstone restore" -> require fixture tests for restore path and proof no unrelated file can be moved.
- "Add file watcher" -> verify watcher events enqueue scans and never become source of truth.

## Failure Modes

- Trusting watcher events as complete history.
- Treating a BLAKE3 content ID as proof of trust or authority.
- Serializing secret values under a harmless-looking key.
- Overwriting dirty files because remote state looks newer.
- Hiding conflicts behind a green status.
- Applying deletes without a tombstone, receipt, and restore path.
