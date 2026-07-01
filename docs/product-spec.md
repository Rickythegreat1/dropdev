# DevDrop Product Spec

## Product Promise

DevDrop is a local-first workspace coherence tool for developers who work across
machines and coding agents. It keeps project state understandable before any
sync action occurs.

## Slice 0/1 Goal

Create the runnable foundation: contracts, CLI stubs, desktop route shells,
Codex loop scaffolds, fixtures, safety tests, and docs. Slice 0/1 must not
perform real sync, deletion, overwrite, dehydration, Git mutation, or secret
capture.

## Full MVP Capabilities

- Local-first project registry with machine-aware roots.
- Readiness scanner for Git freshness, env shape, generated paths, and CAS
  eligibility.
- Machine map showing which machine has which workspace evidence.
- Git freshness detection with mutation previews only.
- Env profile awareness using key names and fingerprints, never raw values.
- Ignore policy for generated and secret paths.
- Local content-addressed store using BLAKE3 by default and SHA-256 as a modeled
  compatibility option.
- Lazy hydration simulation before any real file materialization.
- Sync queue with dry-run previews, retry semantics, and safety receipts.
- Sync engine that reconciles scans before apply; watcher events can only be
  hints.
- Tombstones for deletion semantics before any deletion exists.
- Conflict objects and conflict UI before any resolution apply exists.
- Agent workspace planner and redacted Codex handoff contract.
- CLI, Tauri desktop UI, MCP tools, hooks, skills, and deterministic evals.

## Non-Goals For Slice 0/1

- No live sync engine.
- No file deletion.
- No overwrite or merge apply.
- No Git mutation.
- No watcher-driven truth.
- No SQLite database creation beyond documented contracts.
- No metadata writes, WAL checkpoints, or sync apply execution.
- No capture, logging, display, or serialization of secret values.
