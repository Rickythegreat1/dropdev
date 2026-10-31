# Loop Log

## 2026-06-26 Slice 0/1

- Initialized foundation plan for full DevDrop MVP.
- Chose BLAKE3 as default content hash and modeled SHA-256 for compatibility.
- Kept SQLite WAL as an architecture contract only.
- Required hooks and MCP tools to be inert and dry-run by default.
- Required every risky command to state that no user files are mutated.

## 2026-06-26 Feature Inventory

- Expanded `docs/feature-inventory.md` into a full MVP surface inventory for
  CLI, desktop, core engine, sync, env profiles, Agent/Codex, and UX/aesthetic
  work.
- Added explicit owner and mutability mode for each feature so future slices do
  not collapse DevDrop into a doctor-only CLI.
- Added missing feature audit, dangerous assumptions, UX failure modes, and
  aesthetic failure modes.

## 2026-06-26 Architecture And Sync Invariants

- Expanded `docs/architecture.md` from Slice 0/1 notes into full MVP
  architecture across Rust crates, Tauri desktop, storage, sync, Git, machines,
  agents, MCP, hooks, and red-team loops.
- Added Mermaid diagrams for system architecture, sync event flow, hydration
  state, conflict resolution, and Codex loops.
- Rewrote `docs/sync-invariants.md` as grouped full-MVP invariants covering
  truth, secrets, planning/apply gates, object store, hydration, tombstones,
  conflicts, Git, event replay, machine/agent handoff, and UI truthfulness.

## 2026-06-26 Codex Automation Layer

- Created or replaced DevDrop skills for feature slicing, sync invariant
  review, UX red-team, aesthetic red-team, and MCP building with concise
  frontmatter and required operating sections.
- Kept project hooks disabled, dry-run, and untrusted while documenting future
  secret, destructive-command, and design-slop guard roles.
- Expanded `devdrop-mcp` into the canonical Rust JSON-over-STDIO scaffold with
  safe typed responses for doctor, scan, sync plan, conflicts, agent contract,
  design red-team, and UX red-team tools.
- Updated model routing guidance for cheap subagents, escalation boundaries,
  local MCP posture, and project-local config limits.

## 2026-06-26 Deterministic Subagent Routing

- Reworked `docs/model-routing.md` into a task-class routing matrix covering
  classes A through M with model tier, cheap subagent usage, reviewers, gates,
  retry limits, tests, escalation triggers, and human approval requirements.
- Added the highest-risk inheritance rule for mixed tasks so UI, docs, or test
  changes inherit deletion, sync, secrets, hydration, conflict, MCP, or
  architecture gates when they touch those domains.
- Created `docs/subagent-loop-spec.md` with the classify, assign, implement,
  test, red-team, repair, merge-or-escalate loop, bounded subagent prompts, and
  required subagent output schema.

## 2026-06-26 Core Engine Slice

- Refactored `devdrop-core` from a single contract file into focused modules
  for manifests, projects, machines, env profiles, ignore policy, content
  hashes, object IDs, event logs, tombstones, conflicts, hydration, readiness,
  and sync plans.
- Routed the slice by highest-risk classes G/I/J/K/M because it touches file
  scanning and hashing contracts, hydration, conflict/deletion/tombstone
  models, env/secrets, and architecture; sync invariant and security review are
  required.
- Added typed `CoreError`/`CoreResult`, deterministic JSON manifest parsing for
  tests only, stable BLAKE3-backed object IDs, and non-mutating sync-plan
  approval receipts.
- Updated sync invariants and decision log to keep manifest format and
  destructive-apply behavior explicit.

## 2026-06-26 CLI MVP

- Replaced the early CLI stubs with the requested MVP command surface for
  doctor, scan, status, hydrate, sync plan/apply, conflicts, machines, env
  checks, agent plan/contract, and MCP preview.
- Routed the slice by highest-risk classes E/G/I/J/K/L because CLI behavior
  touches command UX, fixture-backed scan contracts, hydration, conflicts,
  env/secrets, sync previews, and MCP handoff.
- Added a stable `CliReport` schema shared by JSON and human output, with
  mutation flags that remain false across all reports.
- Kept fixture lookup deterministic by path/name only; unknown paths produce an
  unknown fixture report rather than triggering live recursive scanning.
- Ran a CLI UX red-team assertion in tests to reject vague AI language, fake
  sync completion, hidden conflicts, and missing flight-checklist structure.

## 2026-06-30 Daemon MVP

- Routed the daemon slice as highest-risk class H with inherited G/J/K/M
  because it touches watcher scheduling, metadata scanning, sync truth,
  conflict/deletion boundaries, env/secrets, and architecture.
- Implemented an observer-only daemon library and binary with loopback-only
  bind validation, in-memory project/machine state, a debounced scan queue,
  watcher hints, metadata-only reconciliation scans, structured redaction
  posture, and safe shutdown support.
- Added a localhost API for health, projects, project status, scan enqueue,
  dry-run sync-plan preview, conflicts, hydration, and machines. Every
  applicable response carries a safety envelope with `mutated_files = false`,
  `dry_run` or `read_only`, and a redaction notice.
- Kept SQLite, CAS writes, hydration writes, Git mutation, conflict resolution,
  deletion, and real sync apply out of scope. Watcher events remain hints only;
  reconciliation scans are the daemon truth source.

## 2026-06-30 Lazy Hydration Simulation MVP

- Routed the hydration slice by highest-risk classes I/G/J/K/M plus CLI class E
  and UI critique classes B/C. Strong implementation, sync-invariant review,
  security/redaction review, and UX/aesthetic red-team review are required.
- Added sandbox-only hydration simulation: dry-run previews refuse arbitrary
  live paths before content reads, and apply can write only inside recognized
  temp test sandboxes copied from canonical fixtures.
- Kept canonical fixtures read-only, object IDs and registry keys path-safe,
  daemon hydration read-only, desktop apply disabled/CLI-only, and cloud sync,
  SQLite persistence, durable CAS, watcher apply, conflict resolution, and real
  workspace hydration out of scope.
- Ran UX/aesthetic red-team notes for Hydration Center: the route shows file
  state, preview evidence, dirty-local warning, and CLI-only apply language
  without generic dashboard cards, fake glass, vague pills, or decorative
  gradients.

## 2026-10-31 — Durable local sync and delivery candidate

1. **Task and scope.** Deliver a working local two-folder content-sync beta and
   prepare native/hosted delivery. The separate `Rickythegreat1/dropdev` checkout
   started at `0aae71ed246e75f5a8f78e977d24f1153b40f639`. The portfolio checkout
   was neither edited nor deployed. Files touched: `devdrop-core/local`, CLI/MCP
   adapters/tests, desktop routes/data/native bridge/tests/icons, lockfiles,
   CI/release workflows, browser packager and behavior/delivery documentation.
2. **Risk and gates.** High risk: filesystem writes, rollback, SQLite/CAS and
   secret boundaries. Registration and preview precede exact-plan approval;
   fresh scans/revision checks precede apply. Mutations use generated disposable
   folders in tests. No real project folders or secrets were synchronized.
3. **Implementation.** SQLite FULL/WAL and writer lock; verified eligible CAS;
   directional three-way content plans; conflicts with source/target/both
   resolution previews; tombstones; outgoing-inode quarantine; no-clobber
   install; interruption state and separately approved undo; redacted stdio MCP;
   native IPC; ten desktop routes and explicit virtual-data browser demo.
4. **Verification.** Final workspace run: 100 Rust tests passed (14 CLI legacy,
   2 CLI process workflows, 45 core, 9 independent safety regressions, 21 daemon,
   8 MCP library/protocol, 1 MCP process transport). Desktop: 12 tests, TypeScript
   checks and production build passed. Real Chromium virtual-workflow/mobile
   smoke passed. Rust all-target check and formatting passed. Portable static
   packaging checks passed. Native Linux check reached glib-sys and failed due
   to absent glib/GTK/WebKit development packages. Official apt installation
   failed with permission errors; sudo is unavailable. Windows/macOS packaging,
   clean-machine installer startup, signing, physical power loss and live
   hosted health were never run here.
5. **Red-team findings.** Independent review reproduced and fixed last-moment
   editor overwrite, ignored-file deletion, state-child symlink redirection,
   nested Git dirty-check bypass, Git filter execution and unsafe/nested ignore
   policy parsing. Added targeted regressions and retained quarantine evidence
   in native activity. UX/aesthetic review found evidence/approval separation
   and truthful demo labels; see `src/critique/mvp-redteam.md` and
   `docs/runtime-review.md`. No identified local-sync regression remains open.
6. **Closeout and remaining work.** Source is a reviewed beta; full remote
   machine transport, file metadata sync, env/runtime inventory/provisioning,
   live hydration and automated agent workspace execution remain unimplemented.
   The safe hosted component is only the disposable demo/guide. Owner-private
   Site `appgprj_6ae6574f8b948191bd7acb0f16a01fdf` exists, version 0,
   no deployment/live URL; missing required Sites source helper blocks push and
   publication. No costs, persistent credentials, Docker, signing identities,
   public filesystem APIs or PR approvals were created. Draft PR/portable bundle
   carry reviewable source and exact verification; release workflows need actual
   OS runs before installer claims.

Delivery update: Git source push succeeded. Draft PR creation was denied by
automatic approval review for lack of explicit user PR-publication permission;
no retry or workaround was attempted. CI is enabled on codex branches and calls
unsigned artifact-only packaging on public-repository pushes. A first remote
workflow validation failure was corrected by moving draft publication into a
separate manual workflow with its own write permission. Exact remote results are recorded with the portable handoff artifact.
