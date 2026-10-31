# Local MVP desktop review — 2026-10-31

Task: replace all ten foundation route placeholders with a usable local sync
control surface and an explicitly disposable browser demonstration.

Touched surfaces: `App`, typed native/demo data adapter, stylesheet, native IPC,
app icons/CSP, UI integration tests. Risk: high for approval and recovery UX;
filesystem behavior remains in the reviewed Rust engine.

## UX findings and corrections

- **Pass:** Browser mode identifies itself persistently as virtual-only. Demo
  receipts say no device files were accessed. Registration of arbitrary device
  paths is refused in this mode.
- **Pass:** A new preview shows exact relative paths, operation type, mutation
  side and both object identities before the approval checkbox. Apply remains
  disabled until a separate approval of that plan. Repeated clicks have an
  immediate in-flight guard.
- **Pass:** Conflicts remain visible and block approval. Native resolution is
  preview-only until the resulting plan passes the same approval gate.
- **Pass:** Recovery is a separate preview from a recorded verified or interrupted
  operation. A recovery receipt does not imply remote synchronization.
- **Pass:** Environment availability and network peer transport are explicitly
  uncollected/unconnected. No synthetic machine or runtime health is presented.
- **Fixed:** Native engine lists newest plans first. UI now uses that order to
  avoid reporting an older plan as current.
- **Fixed:** Narrow layouts initially overflowed because navigation's intrinsic
  width expanded the grid. Explicit zero minimum track and rail widths retain
  local horizontal nav scrolling at 390px.
- **Limitation:** Real environment key availability, Git freshness detail, remote
  peer integration, and live lazy hydration remain outside this folder workflow.
  Routes state these boundaries instead of fabricating evidence.

## Aesthetic findings

Pass against the repo bans: no gradients, glass, stock dashboard metrics, noisy
pills or ornamental charts. The restrained green/ivory workbench gives folder
roots, path ledgers, conflict evidence and the approval wall distinct physical
hierarchy. Status is always expressed in text as well as color. Native icons
share the same square-within-square mark.

## Verification

- TypeScript typecheck and Vite production build passed.
- Twelve Vitest tests passed: approval ID mismatch, idempotent apply, stale plan,
  conflict preservation, approved recovery, browser folder boundary, persistence,
  actual React approval flow, every navigation route, native IPC request binding, native error propagation, and allowlisted recovery metadata with unknown raw-byte fields omitted.
- Chromium/Playwright smoke passed against the production build: preview gate,
  repeated apply click, receipt wording, reload persistence, recovery preview and
  apply, conflict refusal, no runtime errors and no horizontal overflow at 390px.
- Screenshots inspected: `/tmp/devdrop-desktop.png`,
  `/tmp/devdrop-conflicts.png`, `/tmp/devdrop-mobile.png`.
- Native Rust/IPC build and platform installers require parent validation; browser
  results do not establish native packaging success.

## Recovery evidence follow-up

Native activity now renders only the quarantining event’s relative affected path, mutation side, recovery directory plus `previous`, and prior object identity. It shows all returned events instead of hiding older backup evidence after 50 rows. Backup copy names and relative locations are metadata only; raw event payloads and file contents are never rendered. The copy distinguishes preservation intent from verified backup existence and directs the user to preserve newer work and retained backups separately if rollback refuses. Browser-mode virtual-only wording remains unchanged. Typecheck, 12 tests, production build and Chromium smoke passed after the change.
