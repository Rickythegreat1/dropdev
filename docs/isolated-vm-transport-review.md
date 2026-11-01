# Isolated two-guest TLS review — 2026-11-01

Status: feature, worker, scenario, and workflow reviewed statically; independent
pure/model tests passed. No critical outstanding issue was found in the exact
approved fixture scope. Proceeding to its fresh hosted CI is appropriate. Actual
guest TLS, NIC interruption, worker restart, kernel reboot recovery, and cleanup
have not yet been executed by this review and remain CI-pending.

## Reviewed adapter and worker

The `vm-fixture` feature is off by default and required explicitly for the
`vm_peer` example. Normal client/server entrypoints retain loopback checks.
The fixture adapter binds its client to A and connects only to B's fixed port,
then verifies both socket addresses. B refuses every accepted source except A
before handing the stream to TLS. Both paths reuse the production TLS exchange
and authenticated-request functions: standard mutual authentication, negotiated
TLS/ALPN checks, exact approved certificate pins, validation, deadlines, and
durable queue admission are retained. No insecure certificate verifier or
arbitrary private-address API was added.

The adapter requires the exact fixture scope, selected path, and generated
bytes. Three fixed negative mutations test content-hash, deletion-scope, and
sequence/quota rejection; they still pass through the full receiving TLS and
validation path. The serial worker has no mount, route, reboot, process-kill,
project-read, stage, or apply commands. It accepts fixed role arguments only,
requires Linux/environment/kernel markers, and validates a fixed private state
directory/disk marker before opening the generated receiver queue. Markers are
fixture intent gates, not defenses against a hostile guest root process. The
compile feature is an intentional test opt-in, not a sandbox against a developer
deliberately compiling/reusing it outside the harness.

Private identities are generated and retained in worker RAM. Only public
offers, exact receipt identifiers, counts, and fixed fixture hashes cross the
control channel. Strict empty-struct command variants reject extra fields;
control reads cap 64 KiB before appending. Parent/PID1 infrastructure commands
remain separate from worker commands and are never exposed through TLS.

## Harness and corrected findings

The host uses signed package index refresh, unprivileged download, and scratch
extraction of recognized QEMU/firmware/kernel/BusyBox/modules. No package install
or maintainer hook is run. Worker dependencies use an exact GNU library
allowlist and fixed guest archive paths. Module dependencies are ordered from
official ELF metadata, bounded, and refused on missing/cyclic/escaping paths.
The initramfs uses fixed paths only; guest init verifies PID1 before mounting,
addressing, or controlling its owned child. Neither source offers a shell or
arbitrary host/guest path command.

Disks are exclusive no-follow regular files of exactly 64 MiB, mode 0600,
formatted only at the generated paths; their namespace/type/size is checked again
before QEMU launch. Each emulator inherits exactly its own AF_UNIX endpoint.
The parent closes its copies after launch. There is no host IP socket, TAP,
bridge, NAT, forwarding, DNS, host mount, or filesystem share. Guest init checks
the two expected interfaces, exact static address, absent default route, and
absent resolver configuration. The listener remains B:37431/A-only.

Scenario review corrected two actual evidence-contract bugs before CI: fresh
pairing receipts must report per-pair pending count one, while the local global
queue progresses to two/three; and a generic timeout must not satisfy the
specific old-certificate-pin rejection assertion. The harness now preserves
that count distinction and checks the appropriate TLS/pin failure category.

The scenario plans actual authenticated negative proposals, exact duplicate
retry, NIC down/up with the same worker and boot identity, hard worker kill and
fresh identity/re-pairing, and B kernel reboot with durable local queue review.
Kernel reboot uses `sync; reboot -f`; it is not sudden power loss or a kill
inside a queue commit. All receipts remain proposals: no apply endpoint,
workspace registration, filesystem staging, or target mutation is introduced.

The network deadline is 1,740 seconds, reserving one minute for stop/wait and FD
cleanup inside the approved 30 minutes. Command/control/console sizes and waits
are bounded. The cleanup `finally` attempts both emulators and both endpoints
even after scenario/second-launch failure, then scratch deletion removes disks,
initramfs, and queue state. Failed/uncertain cleanup fails visibly; success also
checks stopped QEMUs, closed FDs, removed scratch, network duration, and unchanged
host installed-package state. Reports are exclusive no-follow files, bounded to
128 KiB, with fixed errors and public metadata only. QEMU receives a reduced
environment; keys remain guest RAM, core dumping is disabled, and no identity
export, snapshot, or raw console/ciphertext logging is used.

The workflow requires the exact public repository branch and an explicit
`[isolated-vm-test]` commit opt-in; ordinary pushes cannot start this lab. It
uses the separately feature-gated worker and read-only repository permissions.
This opt-in implements the current approved scope, not standing approval for
arbitrary future network labs.

## Independent pure/model verification

- Exact cable address-policy unit test: **1 passed**. This opens no guest socket.
- Default-transport private-endpoint refusal unit test: **1 passed** without
  enabling the VM feature.
- `cargo test -p devdrop-peer --features vm-fixture --example vm_peer --locked`:
  **2 passed**, covering strict control, boot gates, and bounded control reads.
- `python3 -B scripts/test-isolated-vm-transport.py`: **13 passed**, covering
  no-host-network QEMU arguments, guest-PID1 guard/fixed controls, archive paths,
  new regular 64 MiB disk formatting targets with formatter mocked, module
  dependency/path rules, runtime-library allowlist, control deadlines, and an
  ordinary local AF_UNIX socketpair, the complete modeled scenario with
  per-pair/global count separation, mid-scenario/second-launch cleanup, and
  exclusive sanitized report creation.

These checks did not boot guests, format a real disk, download packages, invoke
sudo, bind private IPs, or execute guest networking. Model guests prove Python
orchestration/contract checks only; they are not substitute VM/TLS evidence.
The earlier process-localhost, artifact-relay, and no-NIC readiness runs remain
separate tests and do not establish the new scenario's unrun assertions.

## Exact approved boundary

One existing public GitHub Actions Ubuntu 22 runner hosts two generated QEMU
TCG guests, each one vCPU and 512 MiB RAM. Guest A is `10.77.0.1/30`; guest B is
`10.77.0.2/30`, with TLS port `37431` accepting A only. The virtual cable is a
host AF_UNIX socketpair passed as inherited descriptors to the emulators. The
network lifetime is at most 30 minutes. There is no host bridge, NAT, default
gateway, DNS, firewall/VPN change, public listener, persistent access, purchase,
or user-file selection.

Ephemeral identities remain in guest RAM. Generated 64 MiB fixture disks and
all guest/cable resources must be removed after use. Accepted proposals are
queued for local review only; the test must grant no file-apply authority.
Actual networked execution is limited to the reviewed fresh CI job, with pure
tests only in this executor.

## Review requirements

- The private-address adapter is an explicitly named test-only feature, disabled
  by default; production loopback constraints remain enforced.
- B's exact source-IP check happens before TLS. Standard mutual TLS, ALPN, both
  approved leaf pins, bounded proposals, and durable replay checks remain active.
- The serial worker accepts fixed bounded commands, fixed fixture roots/content,
  and public offers only; it exports no keys, raw payload, or arbitrary path/file
  operation. Parent approvals must bind both offers and the exact scope.
- Guest binaries, libraries, modules, firmware, and initramfs stay within
  generated namespaces; extraction must not follow a route into host paths.
- QEMU's only guest cable is the inherited AF_UNIX pair. Explicit static guest
  addresses have no default route/DNS, and no host policy is changed.
- Deadlines bound commands, console/control frames, peer requests, and the whole
  lab. Every failure path stops and waits both QEMUs, closes cable descriptors,
  and removes generated disks/scratch; uncertain cleanup fails visibly.
- Evidence distinguishes actual two-guest TLS, queue acceptance/review/replay,
  reboot recovery if actually tested, and all unrun fault cases. It must not
  combine earlier process/relay/readiness results into unexecuted assertions.
