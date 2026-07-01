# Sync Invariants

These invariants define the full DevDrop MVP sync contract. They apply to CLI,
daemon, desktop, MCP, hooks, skills, tests, and agent handoff. If an
implementation cannot satisfy an invariant, the feature must remain read-only or
dry-run.

## Truth And Reconciliation

1. Watcher events are hints, never truth.
2. A reconciliation scan is truth for sync planning.
3. A sync plan must name the scan/event-log position it was built from.
4. A stale scan makes the plan stale.
5. Apply must refuse stale plans.
6. SQLite metadata is local evidence, not global truth.
7. Runtime state must be recoverable from the event log plus latest scan.

## Secrets And Ignored Paths

1. Never print secret values.
2. Never serialize secret values.
3. Never send secret values to agents, MCP tools, hooks, logs, tests, or UI.
4. Secret files may contribute key names and fingerprints only.
5. Ignored/generated paths do not upload content.
6. `node_modules`, `.next`, `dist`, `target`, logs, and `*.log` are excluded by
   default.
7. Secrets never enter object store.
8. Redaction failures fail closed.

## Planning And Apply Gates

1. Every sync operation begins with a dry-run sync plan.
2. A plan must list intended writes, deletes, moves, hydrations, conflict
   changes, tombstones, metadata writes, and Git previews.
3. A plan must list blocked actions and why they are blocked.
4. Apply requires explicit approval of a specific plan ID.
5. Apply must record an event-log receipt.
6. Apply must run post-apply verification.
7. Failed verification produces a failed receipt and recovery instructions.

## Object Store And Hydration

1. BLAKE3 content IDs identify bytes, not trust.
2. Object store writes are allowed only for eligible, non-ignored, non-secret
   content.
3. Object bytes must verify against their content ID after write.
4. Hydration stubs never masquerade as real content.
5. Hydration simulation never writes workspace files.
6. Hydration apply requires allowlist, object availability, dry-run plan, and
   explicit approval.
7. Missing or mismatched objects block hydration.
8. Sandbox hydration simulation is the only apply-like hydration path in the
   MVP. It may write only inside a recognized test sandbox copied from
   canonical fixtures.
9. Canonical `fixtures/repos/*` material and fixture object sources are
   read-only and must be refused directly by hydration apply.
10. `devdrop hydrate --dry-run <path>` may inspect target marker text only
    after the path is inside a recognized test sandbox. Unknown live paths,
    canonical fixtures, outside-sandbox paths, ignored paths, and secret paths
    must refuse before arbitrary file-content reads.
11. Hydration object IDs and registry keys are identifiers, not paths. They
    must reject path separators, traversal, drive prefixes, UNC prefixes,
    absolute path forms, control characters, invalid characters, and
    user-provided object-store locations.
12. Hydration apply must refuse dirty-local state, conflict state, ignored
    paths, secret paths, symlink targets, symlink parents, stale previews,
    missing objects, hash mismatches, malformed sandbox metadata, and
    non-test sandbox metadata.
13. A successful hydration receipt may report `mutated_files = true` only
    after the final write/rename succeeds and the target hash matches the
    expected source hash. Blocked and idempotent receipts must keep mutation
    flags false.

## Tombstones And Deletions

1. Never silently delete.
2. Deletion intent is represented as a Tombstone before delete apply exists.
3. Tombstones must include origin, path, restore evidence, and approval state.
4. Delete apply is blocked unless restore proof exists.
5. Deleting a dirty or untracked local file is blocked by default.
6. Tombstone propagation must be replayable from the event log.

## Conflicts

1. Never hide sync conflicts.
2. Conflict objects preserve both sides and provenance.
3. Conflict detection must happen before overwrite.
4. Conflict resolution starts as a dry-run preview.
5. Resolution apply requires explicit approval and event-log receipt.
6. Conflict UI and CLI must show unresolved conflicts until a verified
   resolution receipt exists.
7. Secret file conflicts must not expose raw secret content.

## Git

1. DevDrop observes installed `git`; it does not replace Git.
2. Git observation may read branch, dirty state, upstream, ahead/behind, and
   in-progress operation state.
3. Git mutation is preview-only until a dedicated safety gate exists.
4. No checkout, reset, clean, merge, pull, rebase, commit, or stash operation may
   run without dry-run preview and explicit approval.
5. Dirty Git state blocks sync apply unless the plan explicitly preserves local
   work.
6. Git previews must not imply that Git state changed.

## Event Log And Replay

1. Every sync plan, approval, apply, refusal, conflict, tombstone, hydration, and
   receipt is an event.
2. Every sync operation must be replayable from an event log.
3. Event log entries must not contain secret values.
4. Event IDs must be stable enough for receipts and stale-plan checks.
5. SQLite WAL checkpointing must be accounted for before metadata writes become
   authoritative.
6. Crash recovery must distinguish planned, approved, applying, verified,
   failed, and rolled-back states.

## Core Engine Model Contracts

1. `ProjectManifest` parsing in the core engine is for deterministic model tests
   only and does not decide the final user-facing manifest file format.
2. Manifest validation must fail with typed errors when required identity,
   branch, or path fields are invalid.
3. UTF-8 path types are used only where path semantics matter; display-only
   compatibility fields may remain strings.
4. `ObjectId` values must be stable for identical project, path, kind, and
   content-hash inputs, and must change when meaningful identity inputs change.
5. `WorkspaceObject` visibility must distinguish tracked, ignored/generated,
   and secret-metadata-only state.
6. `Event` entries must preserve project, machine, kind, optional path,
   previous hash, next hash, timestamp, and actor without secret values.
7. `Tombstone` models deletion intent and metadata only; it is not delete apply.
8. `Conflict` models must preserve both local and remote/mock versions.
9. `ReadinessReport` must serialize without claiming real sync completion unless
   a verified receipt exists.
10. `SyncPlan` approval or apply-preview methods may only produce refusal,
    preview, approval receipt, or dry-run summary models; they must not mutate
    files, object store state, hydration state, Git state, SQLite state, or
    workspace state.

## Machine And Agent Handoff

1. Machine state includes device ID, project path mapping, runtime availability,
   env profile availability, sync status, and last scan.
2. Machine identity and paths are sensitive metadata and must be minimized in
   agent handoff.
3. Agent workspaces require allowed files, forbidden files, env availability,
   stale-base status, readiness blockers, and task-scoped metadata.
4. Agent handoff never includes raw file contents unless a future explicit,
   scoped, reviewed feature allows it.
5. Agent create is blocked when stale-base, env, conflict, forbidden-path, or
   hydration blockers are unresolved.

## UI And UX Truthfulness

1. CLI and UI must not claim real sync completion without a verified receipt.
2. Readiness scores must link to causes and evidence.
3. Desktop warnings must explain cause, blocked action, and next safe step.
4. Conflict Center must not visually bias one side as safe to overwrite.
5. Hydration Center must distinguish real content from stubs and simulations.
6. Sync Queue must show destructive intent before approval.
7. Machine Map must explain trust and freshness, not act as decorative network
   art.
8. DevDrop UI must avoid generic AI-dashboard visuals, meaningless gradients,
   vague cards, fake glass, and default shadcn sameness.
