# Peer fixture simulation review — 2026-10-31

Status: static review and independent local Linux model checks passed. Actual
three-VM workflow execution remains pending at this review checkpoint. This
review does not certify production peer synchronization, pairing,
authentication, or a network service.

The scope is generated disposable fixtures only. The Rust example is separate
from the shipped CLI, desktop, daemon, and MCP. A is the fixture sender, B the
receiver, and C a fresh verifier. C is not a restarted original sender.

## Reviewed boundaries

- Only the exact `offer.json` and `reply.json` manifest names are read. Each is
  limited to 64 KiB, must be a regular non-symlink file, and is checked before
  and after opening. Unix uses no-follow/nonblocking opens; Windows reparse
  checks are present. Unknown JSON fields are rejected. Adjacent files are
  intentionally ignored, never imported or recursively scanned.
- Output roots must be new, separate from inputs, and free of symlink/reparse
  ancestors at validation. Existing paths are refused. Unix directories are
  private from creation, not chmodded after a public creation window. Windows
  requires a private canonical parent for generated output.
- The payload namespace is exactly `src/shared.txt`; only the three fixed
  generated revision/delete payloads are accepted. Envelopes bind schema,
  per-offer fixture session, sender/recipient, sequence, predecessor digest,
  path, policy, and payload. Artifact filesystem modes are not treated as
  source permission evidence.
- The public deterministic test tag is a fault-model mechanism. Anyone with the
  fixture code can forge it. It is not authentication, a credential, pairing,
  encryption, or proof of remote device identity. The session label is not a
  secret or cryptographic identity either.
- Packet and cursor updates use one SQLite transaction. A failure injected
  after journal commit leaves staging pending, blocks workspace preview, and
  is replayed into the private inbox on reopen. Staging file/directory sync
  precedes marking the packet staged. Exact duplicate replay is inert;
  same-sequence collisions and reordered/gapped frames are refused.
- Acceptance is a journal/staging receipt, not a workspace sync receipt.
  Workspace changes use the actual local Engine with exact-plan approval,
  disposable-copy acknowledgement, conflict protection, permission-widening
  consent, verified receipts, and retained-inode rollback. The harness
  deliberately supplies approvals for its generated fixtures; it is not a
  production remote-approval path or proof of human approval.
- The receiver preserves an offline local edit through an explicit keep-both
  conflict resolution. After approved deletion it explicitly rolls back, so
  the final workspace intentionally differs from the latest inbox deletion
  intent. The report exposes that difference instead of claiming convergence.
- Reports and errors are bounded and sanitized. They omit raw payloads, test
  tag keys, environment values, and local workspace paths. Wire artifacts
  intentionally contain only known generated payloads and public test tags.

The implementation assumes generated private roots are not concurrently
replaced by a hostile same-user process. Ancestor checks do not establish a
security boundary against such a process; final-file no-follow/type/budget
checks still protect ordinary malformed input.

## Static workflow review

The three jobs use standard `ubuntu-22.04` GitHub-hosted runners and each
requires a public repository. They request `contents: read` only and do not
persist checkout credentials. Artifact names bind the current run ID and
attempt; downloads use that run. Only the explicit manifest, sanitized evidence,
and runtime record are uploaded from A/B. SQLite, CAS, inboxes, and workspaces
are not relayed.

No hypervisor installation, privileged step, direct peer socket, persistent
credential creation, private runner, or paid cloud provisioning was found.
GitHub documents fresh VMs and free compute for these standard public-repository
runners. [GitHub runner reference](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job)

Runtime records bind role, source commit, run/attempt, Ubuntu version,
architecture, and a digest of the ephemeral Linux boot ID. The final check
requires distinct digests for all three roles. These are workflow observations,
not secure device attestation. C also verifies the reply's offer digest,
session/peer identity, accepted chain, expected scenario receipts, and expected
conflict/rollback hashes. Its public-tag receipt check is not independent proof
that B performed those workspace actions.

## Independent local validation

- `cargo test -p devdrop-core --example peer_simulation --locked`: **3 passed,
  0 failed** at this checkpoint.
- `cargo run -p devdrop-core --example peer_simulation --locked -- local`:
  **14 scenario checks passed** in one process using separate generated roots.
- Ran `offer`, `receive`, and `verify` in three separate local subprocesses,
  relaying only manifests/evidence and normalizing transported files to `0644`
  and directories to `0755`, following the documented
  [artifact permission behavior](https://github.com/actions/upload-artifact#permission-loss). The phases passed
  **3 sender, 14 receiver, and 5 verifier checks**, with distinct process IDs.
  All three processes still ran on the same Linux executor: this was not a VM
  or network-boundary test.

The scenario checks cover tamper/identity/path refusal; pending staging recovery;
packet acceptance without workspace mutation; exact approval and disposable
acknowledgement; initial apply; a withheld update and reordered deletion; local
edit conflict preservation; explicit keep-both; replay and sequence collision;
approved tombstone deletion; original-inode rollback; extra widening approval;
and durable receive-cursor evidence.

A helper hardening finding was corrected: Unix generated directories now use
creation-time `0700`. The implementation also replaced a non-Unix identity
placeholder with the real opened-file access guard and syncs staging before its
SQLite completion marker. Final receiver reopen now reparses all three accepted packet bodies and checks
sequence, digest, staged state, and exact offer equality. The implementation
owner and parent reported final focused checks passing after those corrections:
3 example tests, 14 local scenarios, and the three separate local phases. The
parent additionally reported its 123-test Rust workspace suite, all-target check,
optimized build, formatting, and diff checks passing. This review did not
duplicate that full-suite run or treat it as VM execution.

## Pending and outside scope

Actual VM workflow jobs/artifacts and final source SHA have not been verified
by this review at this checkpoint. Local test results must not be described as
multiple VMs. The parent task will record actual run evidence separately.

Offline/reconnect and reordering are controlled simulator faults, not physical
network outages. SQLite close/reopen inside B is not a guest reboot or power-loss
test. A/B bytes travel through GitHub Actions artifacts, not a direct peer
connection. Communicating Windows/macOS peers, native GUI sync across devices,
secure pairing, encrypted production transport, and VM power-loss behavior remain
outside this fixture simulation.

The existing denied PR and Sites hosting blocker are unchanged. No retry or
hosting action was attempted by this review.
