# Local received-proposal bridge checkpoint

This is a reusable Rust API and generated-fixture acceptance test. It is not a
desktop Inbox feature, a network apply endpoint, or version-control history.
The existing network receiver still admits private proposals only.

`devdrop_peer::bridge` provides sanitized review and separate `preview`,
`resolve_preview`, `apply` and `rollback_preview` actions. Each action binds an
exact pairing/sequence/digest to a locally chosen registered pair and side.
Preview/resolution require the confirmed proposal digest and disposable-copy
acknowledgment before remote content enters Core CAS. Apply additionally requires
the exact immutable plan ID and separate permission-widening consent when needed.

The bridge does not stage a sparse folder. Core creates operations only for
explicit received paths, preserves unrelated files and common baselines, and
keeps remote import history separate from ordinary folder-pair history. Both
roots still get full content/metadata/Git stale checks. A missing or invalid
remote deletion predecessor cannot be overridden through conflict resolution.
Valid remote history with local divergence produces a separately reviewed
conflict; keep-both affects only the chosen side and refuses preservation-path
collisions.

Core owns immutable origin/semantic bindings, sequence heads and verified receipts
in one SQLite transaction. Inbox proposals remain unchanged recovery evidence;
there is no cross-database consumed flag. A failure after filesystem installation
can leave an interrupted plan requiring an approved rollback. An error must not
be reported generically as proof that no files changed. Rollback preserves the
retained original inode and does not rewind the remote packet chain.

Core metadata schema 3 migrates schema 2 atomically and prevents old binaries
from ignoring received-plan context. Ordinary plans keep metadata version 1;
received plans use version 2. Inbox schema 2 retains admitted scope policy;
legacy scope-less proposals remain preserved for raw local recovery but cannot
enter this new import workflow. Generic folder/desktop dispatch refuses received
apply/rollback and cannot redirect an active received path through its ordinary
pair/path resolver. Use the checked typed bridge, not generic UI actions.

Run the bounded test, which accepts no user folders or device credentials:

```sh
cargo test -p devdrop-peer --example local_import --locked
cargo run -p devdrop-peer --example local_import --locked
```

It uses generated local folders and actual loopback mutual TLS, then closes and
reopens the private queue after dropping/revoking RAM pairing. It checks exact
approval, immutable replay, selected-side writes, unrelated baseline retention,
conflict preservation, deletion/restore, permission widening and a receipt-fault
after file installation followed by restart/rollback/retry. Its 14 checks are
local acceptance, not a new VM session or production pairing lifecycle.

No Inbox CLI/desktop expansion is included in this checkpoint. The product's
agent-facing version-history interface is being designed separately; packet
sequence, apply-plan ID, local event journal and retained-file rollback must not
be relabeled commits, branches or arbitrary historical checkout.

All prior beta limits remain: disposable copies only; never primary working
trees; constrained Unix rwx/execute and Windows readonly support; no complete
ACL/owner/xattr/timestamp replication. No new private guest networking, hosting,
production credentials or draft PR is authorized by this checkpoint.
