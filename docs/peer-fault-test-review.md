# Peer process-fault and Linux installer review — 2026-11-01

Status: process harness reviewed statically and independently executed on Linux:
two tests and 12 standalone acceptance checks passed. Installer smoke and CI
source review passed, and 12 pure safety tests passed independently.
Installation/startup and native CI execution remain pending.
This checkpoint is not full package or cross-device acceptance evidence.

## Process findings and evidence

`process_localhost.rs` accepts no coordinator paths, addresses, or credentials.
It creates canonical private generated roots and fixed markers, starts workers
with anonymous stdin/stdout pipes, and uses fixed selected fixture bytes. Each
worker generates its own ephemeral identity; public offers cross the control
pipes, while private keys remain worker RAM. Bounded control reads enforce their
64 KiB limit before appending. Errors are fixed/redacted and child stderr is
discarded. Evidence contains public fingerprints/PIDs, byte counts, and flags,
not certificates, ciphertext, private keys, raw selected bytes, or paths.

The parent-coordinator control pipes are trusted fixture channels, not a
production pairing UI or an authorization boundary against a hostile same-user
process. The exact marker/name policy constrains fixture execution; it is not
proof that a caller-created directory is physically disposable.

The proxy forwards TLS records without terminating TLS or knowing private keys.
It flips or truncates the first encrypted client record, which can be encrypted
handshake traffic; this is not proof of targeted application-record corruption.
The acknowledgement-loss claim separately requires observed queue count one,
followed by an authenticated exact-retry duplicate receipt with count one.
Fault names alone are not treated as success.

The fixture actually hard-kills and waits for receiver and sender workers,
reopens private SQLite with new worker certificates, verifies retained local
review, rejects the old sender's trust against the fresh receiver, confirms RAM
sender outbox loss, and requires fresh explicit pairing before a new queue
admission. Kills occur after the accepted proposal has been committed and
reviewed; this is not interruption inside a SQLite transaction or a filesystem
apply. This harness never stages or applies a workspace; the separate
`localhost.rs` example covers real Engine plan/apply gates.

A corrected finding: Serde accepted an unknown `read_path` field for the unit
`status` control variant despite enum `deny_unknown_fields`. The ignored field
did not grant file access, but violated the advertised strict control schema.
No-argument command/reply variants now use empty structs; the unknown-field
regression passes. A separate `SpawnGuard` also closes the initial
spawn-to-`Process` guard gap, so failures while taking configured pipes still
kill and wait for the fixture child. `Process` cleanup covers later errors and
the total 40-second acceptance deadline. Control requests have seven-second
deadlines; production transport requests retain their own shorter deadlines.

Independent corrected executions:

- `cargo test -p devdrop-peer --example process_localhost --locked`: **2 passed,
  0 failed, 1 ignored**. The ignored subprocess helper is selected explicitly by
  its parent test and is not counted as a separate passing assertion.
- `cargo run -p devdrop-peer --example process_localhost --locked`: **12 checks
  passed**, five distinct observed worker PIDs/fingerprints across restarts,
  one coordinator plus two concurrent peers on Linux x86_64. The proxy observed
  encrypted-record counts 1/1/3/3 across bit flip, truncation, lost ACK, and
  transparent retry. Durable queue counts were one after ACK-loss retry and two
  only after the new explicit pairing.

The earlier failing command had one pass, one strict-schema failure, and one
ignored helper. It is retained here as the discovery checkpoint, not a current
failure. These are source/local observations, not native three-platform CI or
private-VM results.

## Linux installer smoke review checkpoint

The script refuses before subprocess execution unless invoked by the exact
public-repository push job on a GitHub-hosted, non-root Ubuntu 22.04 x86_64
runner. It checks source SHA/event agreement, fixed runner-temp artifact/report
paths, one bounded checksum-matching `.deb`, expected own-project package
identity, and regular archive members. Maintainer hooks, links, special files,
set-ID/group/world-write modes, non-library dependencies, and package conflict/
replacement declarations are refused before privileged installation.

Review identified that shared directory payloads needed the same namespace and
metadata protection as files. The script now permits only ancestors of app
payloads or private app directories and requires shared directories to be
0755. An independent synthetic `usr/bin` mode-0000 payload is refused. Command
timeout cleanup now targets only the newly created command process group,
using the existing noninteractive sudo authority for a root-owned install
command; it does not search for or kill unrelated system package processes.

The final narrow review found that an outer sudo process-group kill alone
cannot prove cleanup when sudo places its workload in a separate PTY/session.
Privileged package commands now run an inner root GNU `timeout` supervisor
with TERM and a five-second forced-kill grace. The bounded outer deadline adds
15 seconds, and its existing targeted cleanup remains a fallback. All current
privileged call sites discard output, so an early output-budget fault does not
cut off the root supervisor. Pure tests verify apt/environment argument order,
dpkg removal wrapping, and unchanged nonprivileged commands. No privileged
timeout or package operation was run locally by this review.

The application receives a reduced environment preserving the actual HOME;
scratch XDG directories, cwd, Xauth, and a private D-Bus isolate this generated
run. Xvfb listens without TCP and uses an authentication cookie, not access
control disablement. No WebKit sandbox flag, security-policy edit, or native
application smoke hook was added. A mapped DevDrop window must belong to the
actual installed executable PID and remain stable for five seconds. The new
SQLite schema with zero pairs/plans demonstrates frontend-triggered native IPC
initialization; it does not demonstrate project registration or the full UI
workflow. Known sandbox-denial diagnostics cause failure, not a bypass.

Another corrected finding was the report new-file check: a dangling symlink
could satisfy `not exists()`. The guard now rejects links and the final report
uses exclusive creation; the regression proves a linked target is not created.

The script stops app/display/bus process groups, uninstalls the own package, and
removes scratch state in `finally`; cleanup failures make the report fail.
Installation/startup/uninstall have **not run** in this executor, which lacks
the required CI context. Independent guard invocation refused with
`github_actions_required` before creating a report or launching subprocesses.
Actual package payload compatibility and GUI/runtime results remain CI work.

Independent `python3 -B scripts/test_smoke_linux_package.py`: **12 passed**.
These tests exercise archive/checksum/metadata and maintainer-hook refusals,
preserved HOME and reduced app environment, read-only empty SQLite observation,
mapped window PID, redacted diagnostics, exclusive report creation, bounded
command output/timeout, and targeted process-group cleanup. They never install
a package, launch a GUI, or pretend those actions occurred.

The reviewed workflow downloads only this run's generated Linux artifact after
the package job, under a public-push-only, `contents: read` Ubuntu 22 job. It
uploads a fixed runtime-evidence file even on failure. The native package matrix
also runs the process example on Ubuntu, Windows, and macOS. Linux process
evidence logging validates and reconstructs bounded public fields before
printing; no raw control/IPC/ciphertext output is logged. The old three-VM relay
workflow does not become a direct TLS acceptance by adding these jobs.

No critical outstanding defect was found in the reviewed process/smoke scope.
Continuing to the authorized disposable hosted CI is appropriate. Successful
package installation, sandbox-compatible GUI startup, uninstallation, and native
process portability require the actual new workflow results before claiming
them passed.

## Network-disabled VM readiness review

The separate `isolated-vm-readiness.yml` uses a fresh public GitHub-hosted Ubuntu
22 job. Its helper guards the exact repository/job and new runner-temp report
path. Normal signed APT refresh is the only privileged operation; package
resolution is simulated, and QEMU/firmware/kernel/static BusyBox packages are
downloaded and extracted under task-local scratch without host installation or
maintainer hooks. The final check compares installed dpkg state before/after.
Package hashes and bounded public boot metadata are reported, not keys/content.

QEMU uses TCG, two fixed guest names, 512 MiB/one vCPU each, no default/user
configuration, monitor, display, NIC, host share, or host disk. The generated
initramfs has only fixed paths and control actions `reboot`/`poweroff`; device
node metadata stays inside the archive. Readiness requires only loopback in
guest interfaces. The reboot assertion requires a changed guest boot-ID digest
while the same emulator PID remains alive. This would prove actual guest boot
and kernel reboot if CI passes; it never starts DevDrop peers or TLS and cannot
prove cross-VM sync or peer-queue recovery through a guest reboot.

Initial review found unbounded command capture, incomplete descendant cleanup,
cleanup stopping after the first guest failure, and overwrite/follow behavior
for an output path. Corrections cap command output at 2 MiB, supervise deadlines
and owned process groups, retain root `timeout` supervision for index refresh,
attempt cleanup of both emulators before aggregating failures, and create the
exact report exclusively with no-follow mode 0600. Cleanup uncertainty fails
and calls for disposable-runner teardown; it is not treated as success.

Independent `python3 -B scripts/test-isolated-vm-readiness.py`: **5 passed**,
covering fixed no-NIC/no-share arguments, exact archive namespace/no network
setup, outside-CI refusal before commands, output-budget cleanup, and a real
bounded timeout of an owned nonprivileged fixture process. No privileged
command, package download/extraction, emulator launch, guest boot, or reboot was
run locally by this review.

Before `0d23328`, the parent reports the first two hosted readiness attempts timed
out before any Linux boot signature; the diagnostic retry saw only 141 console
bytes. The corrective delta supplies QEMU `-L` with its extracted official data
directory and requires `linuxboot_dma.bin` before launch. This changes firmware
asset lookup only: no NIC, host share, privileged install, or security-policy
change was added. Static review found no safety issue in this delta; the updated
five pure safety tests passed independently. The parent subsequently reports
the `0d23328` hosted CI passed all three readiness assertions: two independent
Linux guest boots, guest B reboot with a changed boot identity in the same
emulator, and unchanged host installed-package state. This review did not run or
independently retrieve that CI execution. Zero-NIC guests ran no DevDrop peers
or durable queues. A private networked VM lab remains a proposal requiring the
separate approvals below.

## Authorized test boundary

The harness runs one coordinator and two real peer child processes on
one operating-system instance. Child peers own their ephemeral identities in
RAM and exchange only public offers through bounded anonymous control pipes.
Production peer client/server code remains loopback-only. A byte-forwarding
loopback fault proxy may drop, truncate, or corrupt encrypted traffic; it must
not terminate TLS, export identities, or print payloads/ciphertext.

Process kill/wait/restart with new certificates and explicit re-pairing tests
process failure and local queue recovery. It is not a VM reboot, power failure,
physical network outage, durable sender outbox, or separate-machine transport.
The existing three-hosted-VM artifact relay exercises a different boundary.

The Linux package smoke is limited to a disposable hosted Ubuntu 22 runner:
install the generated own-project package, start with Xvfb and scratch XDG
directories, query local SQLite IPC for zero registered pairs, and uninstall.
No HOME/CODEX_HOME override, WebKit sandbox disablement, firewall/VPN change,
public listener, user-project selection, or credential setup is authorized.

## Reviewed invariant checklist

- Fixed/bounded control schemas and arguments; no path, shell, or raw-content
  authority from a child/control reply.
- Public-only offers and redacted errors/evidence; child private keys stay in
  the owning process, with no environment/file/log serialization.
- Timeout-bounded commands, actual kill plus wait, cleanup on assertion/error,
  and explicit observed child restart and identity change.
- Unmodified mutual TLS and exact pin checks through the proxy; failed/tampered
  traffic creates no accepted queue proposal, uncertain acknowledgement uses
  exact replay, and no network proposal gains workspace-apply authority.
- Private generated roots, durable queue reopen/pending review after receiver
  restart, old-grant refusal after fresh re-pairing, and truthful RAM outbox loss.
- CI-only package/startup hooks, package selection/maintainer-hook inspection,
  bounded IPC response, fresh zero-pair state, uninstall and child cleanup,
  without bypassing a security protection.

## Actual private-machine transport prerequisite

No configured compatible private machines, hypervisor, VPN route, cloud identity,
or approved private bind was established in the parent infrastructure check.
Inventory, addresses, and access must be supplied rather than invented. The next
acceptance request needs two approved disposable machines, compatible metadata
policy, exact private addresses and TCP port, execution access, test duration,
and a reviewed private bind/peer allowlist plus network-policy change and cleanup
plan. Merely having two machines does not make the current loopback-only library
communicate between them. No package-install or network-policy denial was
bypassed to manufacture this setup.
