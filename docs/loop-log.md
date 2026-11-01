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

## 2026-10-31 — Independent audit correction and disposable-copy gate

1. **Task/scope.** Correct the preview/event atomicity defect independently found
   at `4852013`, and enforce a clear disposable-copy-only beta boundary while
   permission/executable-bit restoration remains unsupported. Touched local
   runtime/tests, CLI request/help/process tests, desktop adapter/approval/banner
   and tests, MCP warning envelope, review and behavior docs.
2. **Risk/gates.** High-risk metadata consistency and apply approval. Inject a
   SQLite trigger failure after plan insertion and prove no orphan plan/event
   survives, including restart. Require exact boolean acknowledgement in the
   Rust public API and both dispatch aliases; UI/CLI alone are insufficient.
3. **Implementation.** `new_plan` now commits the saved plan and preview event in
   one transaction. Plans carry a fixed beta warning, and approved events record
   disposable-copy acknowledgement. Missing/false/non-boolean acknowledgements
   refuse apply and rollback. CLI requires `--disposable-copies`; native/browser
   adapters require explicit confirmation, and every screen warns against primary
   working trees. The acknowledgement declares intent and does not verify or
   sandbox root directories. Byte-only restore still does not preserve file
   permissions, executable bits, ownership or ACLs.
4. **Verification.** The injected-event regression failed against the earlier
   code with an orphan plan and passed after the transaction fix. Full local Rust
   run: 103 passed (14 legacy CLI, 3 process CLI, 47 core, 9 safety regressions,
   21 daemon, 8 MCP library/protocol, 1 MCP process). Desktop: 15 tests, typecheck,
   production build and real Chromium smoke passed. Rust formatting/all-target
   checking and optimized builds passed. The new platform CI result is recorded
   in the updated portable handoff; prior `4852013` artifacts are superseded.
5. **Reviews.** Independent sync review verified the transaction and core gate,
   corrected its premature earlier atomicity claim, and retained the explicit
   metadata limitation. Desktop UX/aesthetic review verified persistent warning,
   exact-plan-plus-disposable confirmation, disabled apply before confirmation,
   recovery guidance and browser-only truthfulness. No primary-worktree safety
   signoff or permission-preservation claim is made.
6. **Closeout.** Update the same Library handoff with the new source and final CI
   evidence. Hosting stays blocked on the supported Sites helper, existing private
   project identity unchanged. Draft PR creation remains denied pending explicit
   user permission; no retry. No real user directories, Docker, paid resources,
   persistent credentials or new hosting routes were used.

## 2026-10-31 — Supported file permissions and retained-inode rollback

1. **Task/scope.** User approved permission/executable-flag preservation. Add
   platform permission inspection/application, source-mode previews/baselines,
   metadata staleness, extra access-increase approval and exact original inode
   rollback. Touched core runtime/module/tests/dependencies, CLI/MCP adapters,
   desktop previews/approvals/demo/tests, lockfiles and permission/docs reviews.
2. **Risk/gates.** High-risk filesystem/security metadata. Disposable-copy intent
   remains required and does not prove a sandbox. Do not alter production ACLs,
   ownership or privileges. Only constrained supported access policies pass;
   separate exact-plan consent covers every access increase, including rollback.
3. **Implementation.** Unix ordinary0777 rwx and Windows read-only are captured
   with inode/security guards. Plain same-owner/group Unix files exclude special
   bits/ACL/xattrs. Windows requires canonical current-owner private DACL and
   supported integrity; streams/EAs/custom policies fail closed. Incoming data is
   private at creation and gets verified final flags before no-clobber linking.
   Mode-only changes are explicit operations. Rollback validates and relinks the
   original retained inode, never recreating old permissions from CAS defaults.
   Source/destination/directory identity and permissions guard stale plans. State
   schema2 adds permission baselines; legacy byte-only plans refuse mutation.
4. **Validation.** Local workspace: 122 Rust tests passed (14 CLI unit, 4 CLI process,
   52 core unit, 12 independent permission, 9 security, 21 daemon, 9 MCP unit, 1 MCP process).
   UI: 18 tests/typecheck/production build and expanded real Chromium smoke passed.
   Formatter/all-target checks and optimized builds run before publication. Linux
   behavior is tested; Windows module cross-compilation passed, while actual
   Windows/mac platform results are recorded in the updated CI handoff.
5. **Review corrections.** Tests caught Linux O_PATH descriptors unsuitable for
   ACL/xattr queries; readable captured-directory handles fixed it without
   weakening errors. Guards now include stable identities. Restore verifies full
   retained/installed guards across the link boundary. Cache/state ACLs are
   constrained before content writes, incoming identity is durably recorded
   before linking, and special/private creation modes apply before any bytes.
   Independent review passed the Linux permission suite; see permissions-review.
6. **Limitations/closeout.** Ordinary source flags are preserved; complete ACL,
   ownership, audit-SACL, xattr and timestamp replication is not implemented.
   Windows audit-only SACLs are not queried/copied without additional privileges;
   no privilege is enabled. Primary trees remain prohibited. Preserve original
   evidence on recovery refusals. Same Library handoff will carry new source and
   final platform artifacts. No PR retry, new credentials, Docker, hosting route,
   real project mutation or paid resources were used.

### Corrective native-platform validation pass

The first permission CI run (`82256df`) passed Linux and exposed two platform
assumptions: macOS no-ACL results were ambiguous through `acl_get_fd_np`, and
elevated Windows creation ownership can differ from TokenUser. Before changing
code, scope was limited to file_permissions.rs, permission documentation/review,
and removal of an unused test helper. Risk remains high because these guards
control file-access evidence. Tests require proven no-ACL admission, extended-ACL
refusal, constrained TokenOwner matching, new default-owner files admitted, and
mismatched ownership refused. No UI changes are required; previews keep the
existing supported-flags and extra-consent flow. The correction uses successful
fd-bound extended-stat/property queries and admits only an absent ACL property.
Windows accepts creation ownership only when it is TokenUser or BUILTIN Admin,
without changing production owners, tokens or DACL principals. Linux workspace
tests, all-target checking, optimized builds and the real CLI mode/retained-inode
proof pass. A final review additionally requires immutable/append flag detection;
the final guard now refuses nonzero macOS BSD flags and requires successful Linux
GETFLAGS with only extents/index layout bits. No flags were written or privileges
enabled. The final local suite passed 123 Rust tests, all-target checks, optimized
builds and generated-folder CLI copy/mode/widening/original-inode rollback proof;
18 UI tests and Chromium checks remain valid because UI did not change in this
correction. Native-platform results are recorded with the exact-commit handoff.

## 2026-10-31 — Cross-device fixture exchange on independent CI VMs

1. **Task/scope before coding.** User requested multiple-VM cross-device
   simulation. Verify actual capability first; local executor has no hypervisor,
   VM runtime, guest image, peer network or cloud provisioning identity. DevDrop
   has no production peer transport/pairing. Touched files are the standalone
   core Rust example `examples/peer_simulation.rs`, a new three-job VM simulation
   workflow, and simulation/verification documentation. Production runtime and
   UI are outside this slice.
2. **Risk.** High for filesystem/permission model, medium for CI artifact/evidence
   integrity. Only generated disposable fixtures. No Docker, real project paths,
   secret values, new credentials, accounts, firewall changes, services or paid
   resources. Public-repository standard hosted VMs only. Preserve the exact-plan,
   disposable intent and widening gates; fixed test tags are not authentication.
3. **Planned implementation.** Independent sender/receiver identities, SQLite
   state, CAS and generated workspaces; bounded serialized fixture envelopes;
   journaled sequence/digest checks; exact local preview/approved apply and
   retained-inode recovery. New CI jobs pass fixture artifacts A -> B -> verifier
   C with distinct boot fingerprints and same run/SHA. C is not original A.
4. **Tests/evals.** Local deterministic scenario and explicit example tests;
   initial transfer, withheld/reordered packet, reconnect, conflicts retaining
   versions, deletion/rollback, restart/replay idempotence, altered frames,
   wrong identity/path and permission-consent refusal. Then actual three-VM
   artifact exchange, separately from ordinary platform build jobs. No claim of
   direct sockets, physical network outage/reboot or production security.
5. **UX/review criteria.** No application UI change. Docs and reports must say
   simulator vs actual VM artifact relay, identify exact topology and never show
   raw content or test keys. Required sync/security review covers validation,
   staging-only acceptance, local mutation gates and durable replay evidence.
6. **Closeout pending.** Run affected tests and both VM/standard CI to terminal;
   update the same portable Library handoff with exact source/evidence. Record
   failed and never-run checks truthfully. No denied PR retry, Sites bypass,
   permission expansion or unsupported claim of completed cross-device sync.

### Local implementation and review checkpoint

The standalone example now passes three unit tests and fourteen receiver-scenario
checks. Independent review also ran offer/receive/verify as three local subprocesses
with only the relayed manifests copied and artifact-style mode normalization;
all 3/14/5 phase checks passed. These are single-executor results, not VM proof.
The full workspace still passes 123 Rust tests, all-target checking, formatting
and optimized builds. No production UI/runtime/dependency/lock changes occurred.

Review corrections made Unix private directory creation atomic, validated full
opened-file access guards for rollback on supported platforms, and reread every
accepted serialized packet plus staged flag after final SQLite reopen. Named
manifest reads are bounded, strict, non-symlink regular files; adjacent files are
ignored. Output roots must be new and separate from inputs. Only exact generated
payloads/path/policy are accepted. Automated fixture approvals do not establish a
remote human-approval path. Source-mode metadata is reconstructed from the fixed
fixture intent; artifact modes are not source permission evidence.

The CI workflow now relays only manifest/evidence/runtime files, preserving
separate sender/receiver workspaces, SQLite state and object stores. Its third
verifier checks distinct boot fingerprints, Ubuntu22.04/x86_64, role, source SHA,
run and attempt. It emits sanitized prefixed proof only. Actual hosted VM execution
and ordinary platform jobs must finish successfully for the exact source before
being marked passed in the portable handoff. Physical network interruption,
guest reboot, direct sockets, secure pairing/transport and communicating mixed-OS
peers remain never-run or unimplemented. No denied operation was retried.

An optional strict Clippy run stopped on existing production-core style findings
(`derivable_impls` in content_hash.rs and `too_many_arguments` in local.rs).
Production files were kept unchanged. This is recorded separately from the
passing runtime/test gates; a scoped example lint pass may allow those known
style categories, without treating that as a clean strict whole-core lint.
The scoped example Clippy pass succeeded with command-line allowances for those
two existing style categories; it reported no additional example warnings.

## 2026-10-31 — Authenticated local peer transport and explicit pairing

1. **Task/scope.** Implement real mutually authenticated proposal transport and
   explicit fingerprint pairing, within ephemeral/disposable localhost scope.
   Touched files: new devdrop-peer crate (pairing, wire, transport, private queue,
   acceptance example/tests), workspace manifest/lockfile, existing CI evidence
   step, transport documentation/review and this log. No application UI or
   filesystem-mutating daemon endpoint is added.
2. **Risk and authority.** High: authentication, network input, data persistence,
   quotas and sync approvals. Use standard Rustls TLS1.3 with mandatory client
   certificates and exact leaf pins approved locally on both ends. Ephemeral
   private keys stay in RAM; no production credentials, real devices, user
   projects, Docker, public listener, firewall/VPN change or paid provisioning.
3. **Implementation plan.** Expiring/revocable pairing binds random offers,
   fingerprints and exact bounded scope. Strict framed proposals bind identity,
   channel, sequence/predecessor and integrity; per-path/deletion/data quotas.
   TLS acceptance stores a private proposal plus replay cursor in one SQLite
   transaction. It never applies a workspace change. Local generated acceptance
   fixtures explicitly review/stage then call existing Engine preview, exact
   plan/disposable/widening approvals, conflict resolution and rollback.
4. **Tests/evals.** Real loopback TLS handshake and transfer, two-way explicit
   pairing, unpaired/wrong certificate/pin/scope/expiry/revocation failures,
   invalid/oversize/hash-tampered frames and remote-apply refusal, ACK loss and
   reconnect/idempotent replay/collision, durable queue reopen and quotas. Real
   Engine fixture checks for offline edit conflicts, tombstone deletion,
   original-inode recovery and separate permission consent. Redaction canary
   ensures reports/debug/errors omit payload and private key material.
5. **UX/truthfulness.** No UI changes. Reports distinguish authenticated
   localhost prototype from earlier multi-VM artifact relay. Receiving/queueing
   is not applying; pairing is not unattended-write authority. No production
   credential lifecycle or network-device acceptance is claimed. Required
   independent security/sync review covers these boundaries.
6. **Closeout pending.** Run targeted/full/platform checks and update same
   portable handoff with exact evidence. Current managed executor has no KVM,
   VM runtime, VPN, peer TCP grants or cloud identity; standard CI VM jobs lack
   a configured approved private peer route. Real VM TLS acceptance needs two
   approved privately reachable disposable endpoints and permission to bind
   their private interfaces; no public-port/VPN workaround will be attempted.
   Existing denied PR and Sites-helper blocker are unchanged.

### Local transport implementation checkpoint

The new peer library passed 18 tests; the authenticated localhost Engine example
passed 1 test plus 14 acceptance checks. Independent review ran both and found no
auth bypass in this scope. Full workspace tests, all-target checking, optimized
builds and scoped Clippy passed. Scope/digest/cursor/payload/event persistence is
transactional, including a trigger-abort regression and reopen. Receipt counts
were corrected to be per pair, tested with two grants sharing a private queue.
Exact leafpin rejection is tested after otherwise-valid WebPKI both directions;
no-client/unpaired cert failures occur in mandatory TLS authentication itself.

The fixture example stops its actual loopback listener, reopens the durable queue
and reconnects with the same RAM-only pairing. It validates local staging digest,
disposable intent, stale-delete predecessor, Core conflict/keep both and exact
approved apply, original inode/metadata rollback and separate widening approval.
Neither packet receipt nor pairing authorizes workspace writes. Native CI now
runs this acceptance example on each existing OS job; dedicated Linux JSON/log
proof is clearly localhost, not an additional VM or direct-device test.

Targeted primary advisory checking found the old workspace Tokio 1.52.3 falls in
the AsyncFd I/O-safety advisory range. Only Tokio was advanced to 1.54.1 among
preexisting package versions; unrelated lockfile updates were discarded. The
separate Tauri lockfile already used 1.54.1. New TLS minimums require Rustls 0.23.46,
tokio-rustls 0.26.6 and ring 0.17.14; locked WebPKI 0.103.16 has the current fix.
No claim of a complete dependency audit is made. Tests/checks/release/scoped lint
were rerun after the targeted update. Strict whole-core Clippy still has the
previously documented unrelated production style findings; the scoped pass
allows only those two existing categories.

Revocation is local to each grant and stops new admissions; an already-admitted
transaction can finish. Network timeout/lost acknowledgement outcome is unknown until exact
retry and does not imply no proposal was stored. Pending recovery evidence stays
reviewable after expiry/revocation. Keys and sender retry outbox remain RAM-only;
no process-kill, persistent-device lifecycle or cross-VM TLS guarantee is made.
Final exact-source CI/platform and previous artifactrelay results belong in the
updated handoff. No denied PR, Sites route, account or security change was retried.

Final local correction checks passed: **142 workspace tests**, including 19 peer
tests on Unix, plus **1 localhost integration test and 14 acceptance checks**.
Windows has 18 peer tests because the generated FIFO regression is Unix-only.
State paths now reject special files before open and use nonblocking/no-follow
handles, with a generated FIFO regression. Formatting, all-target checking,
scoped Clippy and optimized workspace builds passed after these corrections.
Native platform results remain pending until the exact-source CI run is terminal.

## 2026-11-01 — Process faults, installed Linux runtime and isolated VM readiness

1. **Task and scope.** Continue the v5 testing request from `9308532`, concentrating
   on independent peer processes, actual connection faults, installed-package
   startup and available VM capability. Direct cross-machine TLS remains an
   acceptance goal, conditional on specific private-network approval. Do not
   reinterpret artifact relay, localhost or NIC-less boot as cross-device TLS.
2. **Touched files.** Add `crates/devdrop-peer/examples/process_localhost.rs`,
   `scripts/smoke-linux-package.py` and its safety tests, download-only
   `scripts/isolated-vm-readiness.py` and its safety tests, the separate readiness
   workflow, ordinary/release workflow checks, `docs/peer-test-plan.md` and
   `docs/peer-fault-test-review.md`. No production transport bind policy or
   filesystem mutation API is broadened.
3. **Risk.** High for test-harness process/network/privileged installer cleanup;
   blocked for nonloopback listeners and guest networking until scoped approval.
   Use only generated fixtures, RAM-only test keys, bounded pipes and public
   disposable CI VMs. Never disable the WebKit sandbox, change firewall settings,
   persist device credentials, touch user projects or retry the denied PR.
4. **Tests and evaluation.** Run full existing Rust/UI checks plus process hard
   kills, lost acknowledgments, encrypted TLS record damage, stream cuts, stale
   pairing, durable queue reopen and exact retry. Run pure installer/refusal tests
   locally and install/window/IPC/remove only in fresh hosted Linux CI. Separately
   test two TCG Linux guests with zero NICs and a real guest kernel reboot; this
   does not test peer persistence across VM reboot. Preserve exact CI evidence.
5. **UX and truthfulness.** No product UI change. Evidence must label one OS with
   multiple processes, connection interruption, two guest kernels and real guest
   reboot separately. No network approval or successful install/runtime claim is
   inferred from preparation or static tests. Keep disposable-copy and incomplete
   ACL/ownership/xattr restrictions visible in the existing handoff.
6. **Closeout.** Independent safety review passed; local validation passed 144 workspace tests,
   18 UI tests, two process example tests plus its invoked helper, 12 standalone
   process fault checks, 11 installer safety tests and five readiness safety
   tests. Formatting, typechecking, all-target checking and scoped Clippy passed;
   final exact-source platform, fresh installed-runtime and NIC-less guest runs
   must reach terminal results before the same Library handoff is replaced.
   Report failures and never-run cross-device/VM-state tests separately, with
   exact action-time prerequisites and no duplicate Sites project or PR retry.

The first readiness CI run at `69dc1d4` failed with a 90-second guest-readiness
timeout. Package extraction and QEMU launch completed, but no validated guest
record arrived; no boot or reboot success was inferred. The follow-up removes
kernel `quiet` and retains only fixed allowlisted boot-signature categories and
byte count on timeout, never raw console/environment/data, to diagnose this
generated blank guest without changing isolation or security settings.

### Corrective platform pass after fd27f53

Native CI at `fd27f535db47deb23460c4ce1d7106cc94682a6c` passed Windows tests,
authenticated localhost acceptance and packaging, but Linux/macOS exposed false
writer-busy errors immediately after owner drop. macOS additionally exposed raw
`/var` aliases in generated fixture paths. No all-green handoff was published.

A deterministic generated child holding a duplicate writer descriptor reproduced
the false-busy error before the correction. Both peer queue and Core Engine now
use an explicit-unlock RAII guard declared after SQLite, so the database closes
before the owner's lock is released. It is wrapped immediately after acquisition,
including constructor-error cleanup. Genuine active writers still exclude a new
writer. No lock retry or weakened refusal was introduced. macOS test helpers now
canonicalize only generated roots; production symlink/reparse refusal stays.

Both inherited-descriptor regressions invoke their intentionally ignored child
helpers explicitly with `--ignored`, wait for a flushed readiness marker, and use
RAII kill/wait cleanup. They prove durable metadata survives owner drop while a
child is still alive, and closing the old child cannot unlock a new writer.
Peer/Core focused regressions passed; final full checks and new exact-source CI
must pass before updating the same handoff. The two ignored entries are subprocess
utilities exercised through their parent regressions, not omitted product tests.

Final corrective local run passed **144 workspace tests**, with the two subprocess
helpers intentionally ignored by the ordinary runner and exercised by their
parent regressions. Peer all-target tests, the prior three simulator tests,
14 authenticated localhost acceptance checks, all-target compilation, scoped
Clippy, formatting and optimized builds passed. Exact native rerun remains the
release gate; earlier fd27f53 failures are preserved as a corrected checkpoint.

The diagnostic run at `736ea30` again timed out, now proving only 141 console
bytes and no Linux boot milestone. Inspection found extracted QEMU had an
explicit BIOS path but lacked its task-local option-ROM data search path. The
next change adds `-L` for the extracted official QEMU data and requires its Linux
loader ROM; the no-NIC command safety test now verifies that path. This changes
package asset resolution only, with no host installation or isolation change.

Readiness checkpoint `0d23328` passed all three CI checks: two independent Linux
5.15.0-202 guest kernels under official QEMU 6.2 TCG on one hosted runner, guest B
actually rebooted with a new boot identity in the same emulator, and host package
state digest unchanged. Both guests had zero NICs; no DevDrop peer or durable
queue ran in them. This proves the two-guests-on-one-host software-emulation
path without relying on KVM. Direct guest-to-guest TLS still needs the precise
approval scope in `docs/peer-test-plan.md`.

The first installed-package attempt stopped before installation: the exact
Tauri Debian name is `dev-drop` (kebab-case of `DevDrop`), whereas the original
guard had expected Cargo-style names. The guard now permits only that confirmed
name and explicitly rejects the prior guesses/unrelated packages. No payload,
dependency or maintainer-hook gate was relaxed. Root GNU timeout supervises all
privileged smoke package commands with a 15-second outer grace. Readiness's
sole privileged index refresh discards unused output and reports unexpected
outer timeout as uncertain cleanup. The updated pure safety suites passed
12 installer checks and six readiness checks without privileged local execution.

## 2026-11-01 — Approved isolated guest-to-guest TLS acceptance

1. **Restatement.** Run real authenticated proposal transfer between two QEMU
   Linux guests on one existing public CI runner, following explicit action-time
   approval of this exact isolated network. Preserve the passing `54e0cd2`
   checkpoint. Proposal receipt never authorizes workspace application.
2. **Touched files.** Peer crate Cargo feature/config, a separately gated
   transport adapter and `examples/vm_peer.rs`; new isolated transport Python
   driver/safety tests, opt-in CI workflow, this log, peer test plan and independent
   `docs/isolated-vm-transport-review.md`. Default desktop/CLI/peer binding policy
   stays loopback-only. No production pairing or public endpoint is added.
3. **Risk and boundaries.** High: guest networking, temporary disks and process
   control. Exact guests A `10.77.0.1/30`, B `10.77.0.2/30`; only B TLS port 37431
   accepts A. Use an AF_UNIX socketpair virtual cable, one vCPU/512 MiB per guest,
   generated disks, RAM-only identities, no bridge/NAT/DNS/default gateway,
   host firewall/VPN change, public listener, persistent access, spending or real
   projects. Network lifetime is bounded at 30 minutes; stop/wait both emulators,
   close cable FDs and delete generated assets on every path. PID1 init owns
   fixed guest controls; no generic shell/address/path API is exposed.
4. **Tests.** Unit-check default refusal and exact test-only address/source
   allowlist, strict public serial schema, CI refusal, package/module/library
   extraction paths, fixed QEMU network flags, deadlines and cleanup. In actual
   guests verify independent kernels/state/identities, mutual TLS transfer,
   replay, tamper/scope refusal, NIC down/up, actual worker kill/restart, real B
   kernel reboot with durable queue and fresh explicit pairing. Distinguish
   interruption from process death, guest reboot and power-loss guarantees.
5. **UX/truthfulness.** No product UI change. Fixed fixture confirmations are
   test approvals, not real-device human pairing. Report proposal-only behavior,
   RAM sender-outbox loss and incomplete production identity/UI integration.
   Preserve primary-tree prohibition and constrained permission policy.
6. **Closeout gate.** Independent sync/security review before enabling the CI
   network job. Use explicit opt-in commit marker on the existing branch so
   unrelated future pushes do not automatically run this network lab. Keep exact
   commands/commit/run proofs, failed checkpoints and never-run cases in the same
   Library handoff. No denied PR retry or Sites workaround is authorized.

Pre-CI implementation closeout: full local workspace passed145tests (two internal
child helpers intentionally ignored by the ordinary runner and invoked by parent
regressions); feature-enabled peer passed22 plus localhost1/process2/worker2
tests. Python transport safety/model tests passed13. Formatting/scoped Clippy
passed with only the two previously documented core style categories allowed.
Independent review found no critical outstanding issue, and corrected per-pair
versus total queue receipt checks and specific old-pin failure evidence. Actual
guest networking remains unrun until the explicit opt-in CI commit executes.
