# Local received-proposal import review — 2026-11-01

Status: source review and independent Linux disposable-fixture acceptance passed.
No critical outstanding issue was found in the bounded local bridge. Actual
loopback TLS admission, durable policy review, exact preview/apply, conflict,
deletion, supported permissions, interruption recovery, and rollback ran locally.
Native CI, CLI integration, UI, and any new VM/private-network execution are not
claimed by this review.

## Corrected findings

- Sparse staging was avoided: Core imports only explicit listed operations,
  retaining full real scans for stale detection and preserving unrelated pair
  history. Common-baseline entries change only when both actual roots agree on
  a selected path or both lack it; one-sided incoming values are not adopted as
  common history.
- Core state moves to schema 3, and received plans have metadata version 2.
  Earlier binaries cannot open this state and silently apply received plans as
  ordinary full-pair plans. Schema-2 migration preserves existing normal plans.
- Invalid/untracked deletion predecessors cannot be converted to deletion by a
  generic conflict choice. They produce an unresolvable blocker, refuse apply,
  and suppress mixed incoming payload CAS storage. A valid remote predecessor
  with newer local work remains an explicit resolvable conflict; approved
  deletion retains the newer original inode for rollback.
- Case-folded file/ancestor aliases, existing directory/parent-file collisions,
  and empty path components such as `a//b`/`a/b/` now fail before payload storage.
- An unchanged retry reuses its exact preview/receipt. Changed real snapshots,
  revision, or dirty-Git readiness produce a new immutable attempt, stale the
  old one atomically, and require a new approval. Recovery-required work blocks
  refreshing around recovery.
- Generic desktop dispatch refuses apply/rollback of received plan IDs. Generic
  pair conflict resolution also refuses any path selected by a current planned
  received context, including after dedicated resolution replaces its conflict
  operation. A stale generic UI row cannot redirect that work into the ordinary
  pair resolver; the typed local bridge remains the received mutation surface.

## Implemented trust and durability boundaries

The queue persists original scope in schema 2. Local bridge review revalidates
the complete bounded canonical payload chain against saved fingerprints,
channel, scope, predecessor, checkpoint, and byte accounting without reviving
expired/revoked RAM keys. Legacy contexts lacking scope retain their original
local raw-review API and bytes but cannot enter the new import bridge.

Bridge review exposes paths, identifiers, sizes, fingerprints, and supported
permissions, omitting raw payload, unrelated scans, and project-root paths.
Apply, resolution, and rollback load Core's persisted plan and bind exact local
pair/side, wire identity, predecessor, and semantic fingerprint before calling
Core. Resolution is limited to that received plan/local side; keep-both names
are visible in the new preview and checked for collisions. No protocol handler
calls a bridge mutation; transport still stops at private queue admission.

The peer queue remains unchanged throughout local import. Core alone records
origin binding, current immutable attempt, sequential import head/baseline,
receipt, and recovery state. Head/baseline advance and verified receipt share
one Core transaction. A file installation followed by receipt-commit failure
therefore remains recovery-required after reopen, with no consumed remote head;
an independently approved rollback restores the pre-state before fresh retry.
Verified rollback preserves remote acceptance history so replay does not silently
reapply a rolled-back delete or hide restored divergence.

Supported metadata, full scan/directory/inode checks, dirty-Git protection,
exact-plan approval, disposable intent, and separate access-widening consent
remain active. Known secret/excluded/generated input is refused; this is not a
universal secret classifier or proof that an acknowledged folder is physically
disposable.

## Independent execution

- `cargo test -p devdrop-core --lib received_ --locked`: **11 passed** at the
  import checkpoint.
- `cargo test -p devdrop-core --lib dispatch_ --locked`: **2 passed** after the
  final generic-dispatch guards, proving received-plan refusal while ordinary
  apply/rollback still works.
- `cargo test -p devdrop-peer --lib --locked`: **24 passed, 1 subprocess helper
  ignored**. This includes durable scope/chain validation, legacy migration,
  tamper rejection, and existing authentication/queue contracts.
- `cargo test -p devdrop-peer --example local_import --locked`: **1 passed**.
- `cargo run -p devdrop-peer --example local_import --locked`: **14 acceptance
  checks passed**, real loopback mTLS on one Linux x86_64 executor, five retained
  queued proposals, no sparse staging or network apply.

The example actually revokes/drops pairing keys and reopens the queue before
local review; injects a SQLite receipt-commit failure after actual installation;
reopens Core, rolls back, and retries with fresh approval; preserves unrelated
history and local conflicts; deletes and restores the original inode; and
requires separate permission-widening consent. An intermediate fixture assertion
failed while its author changed a post-rollback payload to test real divergence;
the corrected frozen example passed independently. No production defect was
identified from that intermediate failure. No physical power-loss, new VM run,
or full desktop workflow is inferred.

## Journal and version-control limits

This remains a verified local sync/recovery journal. CAS stores hashed file
blobs; plans/events and pair/import baselines do not provide commit/tree objects,
a commit DAG, named refs/branches/tags, merge-base computation, three-way merge,
arbitrary historical checkout, or reachability-based CAS collection. Packet
predecessor digests order one pairing session; they are not commit ancestry.
Retained-inode rollback deliberately refuses overwriting later work.

The queue retains accepted proposals and has a hard bounded quota; applying does
not consume or collect them. Persistent identity lifecycle, storage retention/
collection, and agent-facing version-control semantics need separate design.
Existing desktop controls do not provide received-plan UI integration; their
generic mutation path now refuses received plans. The dedicated bridge resolver
must be used for this workflow.

## Scope and authority

A locally selected, durably queued peer proposal may be reviewed, mapped into
an exact Core preview, and applied only by a separate local action approving
that immutable plan ID. Disposable-copy and permission-widening gates remain.
No transport request gains a project root, file-read, stage, conflict-resolution,
apply, or rollback method. Testing uses generated local disposable fixtures;
the previous VM-network approval has ended and authorizes no new run here.

The bridge returns sanitized proposal metadata only. Raw selected bytes remain
inside local queue/Core code, and known secret/generated/excluded paths/content
must be refused before object storage or mutation. Supported-metadata, symlink,
ownership, ACL/xattr/file-flag, dirty-Git, inode, and parent-directory protections
must remain enforced. A content digest identifies bytes; it is not user consent
or independent peer authentication.

