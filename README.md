# DevDrop

DevDrop keeps two local developer folders aligned through an inspectable,
approval-gated workflow. Rust owns filesystem access; SQLite WAL records project
pairs, previews, approvals, tombstones and receipts. React/Tauri provides the
native control surface. No Docker is required.

## Disposable-copy beta only

Do not register or sync primary working trees. Use disposable project copies
only. New permission-aware plans preserve Unix `rwx` bits (including executable
flags) and Windows read-only flags within the [supported access policy](docs/file-permissions.md).
Full ownership, ACL, audit-policy, timestamp and extended-metadata replication is
unsupported; custom access policies and metadata outside the policy are blocked.

Every apply and rollback requires exact-plan approval and an explicit
disposable-copy acknowledgement: the native checkbox or CLI `--disposable-copies`.
Any access increase additionally requires the unchecked native permission approval
or CLI `--allow-permission-widening`. This includes new Unix group/other grants,
added `rwx` bits and Windows read-only-to-writable changes, including rollback.
These confirmations declare intent; they do not verify or sandbox the copies.

## Implemented local workflow

- Register separate source and replica directories. Registration does not copy files.
- Scan eligible content into a verified BLAKE3 object cache and persist an exact preview.
- Approve that specific preview ID to copy, replace or tombstone-delete files.
- Refuse stale previews, dirty Git worktrees, symlinks, overlapping roots and unsupported paths.
- Preserve both conflict versions. Preview choosing source, target or keeping both before approval.
- Recover interrupted operations and undo verified operations through a new approved preview.
- Keep metadata across process restarts; serialize native app/CLI/MCP access with a writer lock.
- Inspect the same live native evidence in ten desktop routes.
- Use an actual local MCP stdio server for redacted evidence and previews; no MCP apply endpoint.

The browser build is a **disposable virtual-folder demo**. It cannot access real
projects or connect to the native filesystem engine. The observer daemon remains
loopback-only and separate from the durable native sync workflow.

## Try the local workflow

Use two disposable project-copy directories only. Install Rust and Git, then build:

```sh
cargo build --workspace --locked
./target/debug/devdrop local --state-dir /tmp/devdrop-state register \
  "Disposable workspace" /tmp/devdrop-source /tmp/devdrop-replica
./target/debug/devdrop local --state-dir /tmp/devdrop-state list
./target/debug/devdrop local --state-dir /tmp/devdrop-state preview PAIR_ID
./target/debug/devdrop local --state-dir /tmp/devdrop-state apply PLAN_ID --approve PLAN_ID --disposable-copies
# Only after reviewing every listed access increase, add --allow-permission-widening.
./target/debug/devdrop local --state-dir /tmp/devdrop-state rollback-preview PLAN_ID
# Review rollback permissions, then approve its ID and any listed access increase.
```

Create both project directories before registration and keep the state directory
separate. Every command emits JSON; it contains metadata and hashes, never file
bytes. `resolve-preview PAIR_ID RELATIVE_PATH source|target|both` creates a
separately approved conflict plan. `events` lists local receipts. `handoff PAIR_ID`
emits a reduced agent contract without root paths, names, file bytes or env values.

Legacy top-level `doctor`, `scan`, `sync`, `machine`, and related commands retain
fixture-only compatibility behavior. Use the **`local`** commands above for live
sync; legacy reports do not describe a real registered project.

## Desktop

```sh
pnpm install --frozen-lockfile
pnpm desktop:dev        # browser-only disposable demo
pnpm desktop:tauri      # native workflow; needs Tauri platform libraries
pnpm --filter @devdrop/desktop tauri build
```

The native app stores its metadata under its OS application-data directory in
`local/`. The First Launch route registers source and replica paths. Sync Queue
shows exact operations and requires a separate specific-plan approval. Activity
& recovery exposes receipts and retained backup locations.

## MCP

```sh
./target/debug/devdrop-mcp --state-dir /absolute/path/to/devdrop-state
```

Configure that executable and arguments as an MCP stdio server. It implements
newline JSON-RPC initialization, tool discovery/calls, ping, errors and shutdown
on EOF using protocol version `2024-11-05`. Tools expose reduced status, previews,
events and handoff evidence. Scanning previews may populate local SQLite and CAS;
they never mutate workspace files or invoke apply. Raw paths, project names, task
text and file contents are stripped from agent responses.

## Safety and current limits

Sync is directional source → replica; target-only edits become conflicts. Known
secret paths, generated directories and project-local `.gitignore` exclusions are
omitted. Both roots' ignore policies constrain a pair, so exclusion never means
deletion. Credential-path exclusions and private-key/token checks are safeguards,
not universal secret detection: review the files you choose to register.

Each replace/delete first preserves the actual outgoing file at
`.devdrop-recovery-<plan-id>-<operation-index>/previous` under its affected root.
These directories are excluded from sync and retained. Incoming inodes are also
retained privately in `.devdrop-incoming-*` to prove their identity after an
interruption. New Unix staging files/directories start at `0600`/`0700` before
bytes are written; new project parent directories use private permissions. If an editor races an
operation, DevDrop preserves its bytes and blocks rather than overwriting them.
Rollback validates and relinks the exact original inode instead of rebuilding
it from cached bytes, restoring its original destination metadata. A missing,
replaced or changed original blocks automatic rollback. Old byte-only plans
cannot apply or roll back; preserve old state/backups and create new permission-aware
previews (use fresh disposable copies/state if a legacy interrupted plan blocks progress).
Use Activity & recovery to locate backups. Preserve newer local edits before
manual recovery; do not delete the state directory or retained backups during
recovery. Verified object bytes are also retained in the state directory.

This beta synchronizes regular-file content and supported basic permissions.
Metadata-only permission changes are explicit preview operations. Ownership/group
changes, special bits, custom Unix ACLs/xattrs and nonstandard Windows access
policies are blocked. Windows has no Unix executable-bit mapping. Empty-directory
replication, remote machines and cloud objects remain unsupported. Environment values are never
transferred; env/runtime availability and agent workspace execution remain local
setup responsibilities. Hydration remains the existing bounded sandbox simulation.
External Git clean/process filters block sync observation rather than executing
repository-configured code. Git state itself is never mutated. On Windows,
SQLite uses FULL durability and file flushes; Unix additionally fsyncs directories.
This release remains a permission-aware beta for disposable project copies.

## Verification and delivery

```sh
cargo fmt --all --check
cargo test --workspace --locked
cargo check --workspace --all-targets --locked
pnpm typecheck
pnpm test
pnpm --filter @devdrop/desktop build
cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml --locked
```

CI runs the Rust, desktop and native gates. A separate manual workflow packages
Linux/Windows/macOS installers and command-line binaries; optional release
creation remains an unpublished draft. Native builds need GTK/WebKit on Linux.
See [deployment details](docs/deployment.md), [runtime review](docs/runtime-review.md)
and [implementation record](docs/loop-log.md) for verified outcomes and blockers.

## Cross-device simulation

The fixture-only peer example exercises independent identities/state, packet
delivery faults, local preview/approval, conflicts, recovery and permission gates.
It creates disposable data and does not import real projects:

```sh
cargo test -p devdrop-core --example peer_simulation --locked
cargo run -p devdrop-core --example peer_simulation --locked -- local
```

The separate VM simulation workflow relays generated packet artifacts from a
sender VM to a receiver VM and checks its reply on a third verifier VM. It is a
store-and-forward test, with simulated offline/reconnect faults. It does not
implement production peer networking, pairing or authentication. See the
[exact topology and acceptance boundary](docs/peer-simulation.md) before using
its results as cross-device evidence.
