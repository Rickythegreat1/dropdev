# Local runtime safety review — 2026-10-31

Reviewed `crates/devdrop-core/src/local.rs`, the Tauri native bridge, and the
new CLI/MCP adapters against `AGENTS.md`, `docs/sync-invariants.md`, and
`skills/devdrop-sync-invariant-review/SKILL.md`.

This is a high-risk filesystem feature. Verification used generated folders
under `/tmp` and `tempfile`; no real user project or credential file was used.

## Findings and corrections

| Finding | Evidence | Correction / status |
| --- | --- | --- |
| Concurrent destination edits could be overwritten after a successful hash check. | A Linux inotify reproduction swapped the destination inode while the final hash reader held the old inode. The original implementation returned success and the editor version was absent from both target and CAS. | The runtime now moves the actual outgoing inode into an exclusive recovery directory, verifies the displaced bytes, and installs incoming content with a no-clobber hard link. Changed or recreated destinations block completion and retain both versions. Root-owned deterministic hook tests cover both critical windows. |
| Adding an ignore rule was interpreted as deletion of previously synced content. | A generated two-folder run added `keep.txt` to source `.gitignore` while leaving it present; the original implementation deleted the replica. | Both-root ignore policy now excludes corresponding entries and baseline omissions cannot create tombstones. The independent regression passes. `.ignore` handling is disabled so a second policy cannot recreate the bug. |
| A pre-existing metadata child symlink could redirect SQLite writes outside the state directory. | A generated `metadata.sqlite3` symlink caused `local list` to initialize tables in an unrelated generated database. | State children are checked before opening. Independent tests cover database, WAL, SHM, writer-lock, and objects-directory symlinks. |
| Registered subdirectories bypassed Git dirty-state checks. | A generated committed repository with a modified tracked file below the registered subdirectory produced no blocker. | Ancestor worktree detection now protects nested roots. Independent regression passes. |
| Read-only Git status could execute repository-configured filters. | A generated clean filter wrote an execution marker during `git -c core.fsmonitor=false status`. | Configured external clean/process filters are refused before status, fsmonitor is disabled, and inherited Git selectors are removed. Independent regression verifies the filter does not run. |
| Restore-object entries were not directory-synced. | CAS file sync alone did not persist its new directory entry before destructive operations. | Object and state directory synchronization was added on Unix. Windows power-loss behavior has not been verified. |
| Materialized registry/plan records and their replay events used separate autocommits. | A process crash between the two writes could leave state without its corresponding event. | An audit at `4852013` corrected the earlier review claim: preview creation still used separate writes. `new_plan` now wraps plan persistence and its preview event in one transaction. A SQLite trigger that aborts event insertion proves the orphan plan is rolled back, including across reopen; the regression failed before the fix and passes after it. |
| Ignore-policy reading needed its own preflight and size budget. | A generated `.gitignore` larger than 1 MiB was accepted and cached by the original scanner. Automatic walker policy parsing could precede symlink checks. | Automatic walker policy loading is now disabled; bounded explicit parsing rejects symlinks, special files, invalid UTF-8, and policies larger than 1 MiB. Both independent regressions pass. |
| Nested anchored ignore patterns were scoped to the root instead of their containing directory. | A generated `nested/.gitignore` containing `/private.txt` did not exclude `nested/private.txt`. | Each ignore matcher is now rooted at its own containing directory, with nested precedence and ignored-parent pruning. Independent anchored-rule and nested-whitelist regressions pass. |
| Replacement and rollback preserve bytes but do not preserve file metadata. | Incoming content is materialized as a new regular file; mode, executable bits, ownership, timestamps, ACLs, and extended attributes are not restored from CAS. | This remains an explicit beta limitation. Core apply and rollback entrypoints require a disposable-copy acknowledgement in addition to exact-plan approval. CLI and desktop show the restriction. The acknowledgement declares caller intent; it does not prove or technically sandbox the selected directories. |

## Verified boundaries

- The desktop uses native Tauri IPC. The hosted browser build has no
  filesystem-mutating localhost or public API.
- Applying a plan requires its exact ID, fresh source/target scans, and the
  baseline revision used by its preview. Both apply and rollback also require
  the explicit disposable-copy acknowledgement. Missing, false, string, or
  numeric acknowledgements are refused; only JSON boolean `true` passes the
  native dispatcher. Approved events record that acknowledgement. Repeated
  verified requests are inert.
- This is a byte-only beta for disposable copies. Primary working trees are
  outside its permitted use. The application cannot verify that a caller
  supplied a disposable copy; the acknowledgement is not a filesystem sandbox.
- Conflicts retain both hashes/objects and require a separate resolution
  preview and approval.
- Deletion records a tombstone with restore evidence before mutation.
- Interrupted operations remain visibly in recovery, and rollback refuses to
  overwrite new work.
- The MCP protocol exposes only bounded metadata tools. It strips roots,
  project names, relative paths, file text, and env values; no apply,
  registration, resolution, or shell tool is exposed.
- Errors returned to agents use fixed messages rather than raw OS diagnostics.

## Validation checkpoint

`cargo test -p devdrop-core --test security_regressions`: **9 passed, 0 failed**
after the reviewed corrections. Both `cargo test -p devdrop-core editor_race`
cases passed with the quarantine design. The subsequent
`preview_and_event_commit_atomically_when_event_insert_fails` and
`all_apply_entrypoints_require_explicit_disposable_copy_acknowledgement`
regressions were independently rerun and passed. A full core run before the
last acknowledgement regression passed 46 unit tests and these 9 integration
tests. The preview atomicity finding is closed; file-metadata preservation
remains outside the disposable-copy beta scope.
Final aggregate tests, native packaging, and hosted deployment verification are
owned by the parent implementation task and are not certified by this review.

Physical power-loss testing, Windows/macOS runtime behavior, and hostile
same-user processes continuously replacing state-directory entries were not
run. The application does not establish a security boundary against processes
with equivalent access to the user's private files and local metadata.
