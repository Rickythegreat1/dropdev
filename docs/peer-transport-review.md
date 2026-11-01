# Authenticated localhost transport review — 2026-11-01

Status: static review, independent Linux TLS/library tests, and the generated
localhost Engine acceptance passed. This is a real authenticated TCP/TLS
prototype, not production device synchronization. Direct cross-VM TLS and native
Windows/macOS acceptance have not been verified by this review.

## Scope and trust

The `devdrop-peer` library is separate from the desktop/daemon/MCP mutation
surfaces. Client and server reject non-loopback addresses. The demonstration
accepts no paths, devices, credentials, or listen-address arguments and uses
only generated `TempDir` fixtures and OS-assigned loopback ports.

Pairing generates fresh certificates/private keys in RAM. The local flow is
consumed by explicit approval of the other certificate's exact fingerprint and
a bounded scope. Both endpoints independently approve; the context ID binds
both offers/nonces, fingerprints, expiry, and the same scope. An outsider
approving one public offer cannot make the other endpoint approve it. The API
requires explicit caller confirmations; the fixture driver supplies them
intentionally and does not prove a human pairing UI exists.

Rustls/ring performs standard TLS 1.3 certificate/signature verification with
mandatory client certificates. Both endpoints then check ALPN and the exact
approved leaf pin before handling application proposals. No custom/insecure
certificate verifier was found. Early data, client resumption, server session
storage, tickets, half-RTT data, and key logging are disabled. Actual tests
exercise pin failures even when standard certificate roots are valid.

Grants last at most five minutes and use both wall-clock expiry and a monotonic
deadline. Revocation is local shared state, including that endpoint's clones;
it is not a remote revocation broadcast or global device unlink. It prevents
new local sends/admissions. An already admitted queue transaction may finish.
Likewise, a five-second network timeout can leave an admitted blocking queue
operation finishing in the background: the outcome is unknown until exact
retry/acknowledgement. Timeout never means workspace apply and must not be
interpreted as proof that nothing was queued.

Private keys have no public serialization/export API and are not written to
files. Conversion to rustls key representation occurs only inside RAM. Public
certificate offers/fingerprints are distinct from private keys. Debug output
for flows, grants, clients, servers, envelopes, changes, and inboxes is redacted.
Wire/storage serialization intentionally carries selected proposal bytes, while
errors and evidence omit those bytes and private identity material.

## Capabilities, bounds, and durable queue

A grant authorizes exact portable relative paths and a channel, not a prefix or
arbitrary project root. Hidden, generated, reserved, traversal, and known
credential paths are refused. Known private-key/token formats are checked,
including encrypted PEM headers. These checks are not a universal secret
classifier: caller-side local selection authorization and normal project policy
remain necessary. There is no network filesystem scanner or file-read endpoint.

Hard limits are 16 paths, 16 proposals per pairing, 16 KiB of selected data per
proposal, 32 KiB of canonical encoded proposal bytes, and 256 KiB of retained
encoded proposal bytes per pairing. A frame is at most 64 KiB; the whole
send/serve operation has a five-second caller deadline. These retained-byte
quotas do not claim to count all TLS/network overhead. The private queue also
caps total stored proposals at 64 and encoded proposal bytes at 1 MiB.

Envelope validation binds version, pairing/channel, sender and receiver
direction, sequence, predecessor digest, content hashes, exact paths, delete
permission, and supported OS permission metadata. Digests identify bytes;
authentication comes from TLS and the approved certificate context.

The queue creates a new private root and reopens only a marked queue with the
expected SQLite application/schema identifiers. Ancestors, children, ownership,
ACL/xattr/file flags, and private modes are checked; one writer lock is held.
The final correction refuses non-directory roots and non-regular children before
opening them. Unix handles also use directory/no-follow/nonblocking flags where
appropriate; Windows opens reparse points for inspection rather than following
them. FIFO paths therefore cannot stall a supposedly regular queue-file open.
SQL uses bound parameters and fixed redacted errors. Accepted payload, cursor,
quota accounting, and event share one transaction. Trigger-injected failure
rolls them back together, including after reopen. Exact canonical byte/digest
replay is inert; changed same-sequence messages and predecessor gaps fail.

A review finding was corrected: network receipt counts originally included
other local pairings, while the client validated against its own grant quota.
Receipts now report per-pairing counts. Both a store regression and a real TLS
two-session regression exercise one-message grants sharing the same inbox,
including duplicate retry; the local aggregate count remains separately usable.

The local review API confirms an exact stored digest before returning private
payload to local code. Expiry/revocation does not erase previously queued
recovery evidence. The queue has no project-root parameter or apply method.
It is OS-permission-protected SQLite storage; no at-rest encryption is claimed.

## Final state-path and dependency corrections

The root-owned correction adds a Unix generated-FIFO regression after this
review's original 18-test library run. The resulting library test count is 19 on
Unix and 18 on Windows. The correction was reviewed statically; final-source
full-suite execution is owned by the parent task and was not duplicated here.
No interface or workspace-mutation authority was added.

The workspace now requires Tokio `1.54.1`, outside the published AsyncFd
I/O-safety affected range and the separate `1.54.0` Interval issue.
[RustSec AsyncFd advisory](https://rustsec.org/advisories/RUSTSEC-2026-0386.html),
[RustSec Interval advisory](https://rustsec.org/advisories/RUSTSEC-2026-0384.html)
The TLS minimum is Rustls `0.23.46`, containing its session-value Debug redaction
fix, and the lockfile selects WebPKI `0.103.16`, containing the intermediate
certificate fix.
[RustSec Rustls advisory](https://rustsec.org/advisories/RUSTSEC-2026-0346.html),
[RustSec WebPKI advisory](https://rustsec.org/advisories/RUSTSEC-2026-0382.html)
The inspected manifest/lockfile also select tokio-rustls `0.26.6` and ring
`0.17.14`. This is a targeted dependency/source check, not a full dependency audit
or a claim that the old application had a demonstrated exploit.

## Local Engine acceptance

Network acceptance returns only `queued` or `duplicate`. It does not stage,
chmod, run a shell, resolve conflicts, or change a working tree. A raw remote
`apply` request fails the strict envelope schema.

The example's staging adapter is private fixture code, never a wire method.
It requires exact proposal-digest confirmation plus disposable intent and only
supports the fixed generated path. `Delete.previous_hash` is a local staging
precondition: a mismatched newer predecessor is preserved and deletion refused.
The real Core Engine then separately enforces exact plan ID, disposable-copy
acknowledgement, supported metadata, explicit access-increase consent, conflict
preservation, tombstone preview, verified receipt, and original-inode rollback.

The demonstration actually stops its loopback listener, closes/reopens the
receiver's SQLite queue, reconnects with the still-in-memory paired identity,
and preserves an offline target edit through explicit keep-both resolution.
A separate authenticated channel carries a permission-only change; target
permissions remain unchanged until local widening approval. Final rollback
compares the original access/identity guard. Sender retry data remains in RAM;
sender process-kill recovery is not implemented.

## Independent verification

- `cargo test -p devdrop-peer --lib --locked`: **18 passed, 0 failed** at the
  independent checkpoint before the final root-owned FIFO regression above.
- `cargo test -p devdrop-peer --example localhost --locked`: **1 passed,
  0 failed**.
- `cargo run -p devdrop-peer --example localhost --locked`: **14 acceptance
  checks passed**, reporting one Linux machine/process and real IPv4-loopback
  TCP with mutual TLS 1.3.

The tests cover approved transfer, mandatory client authentication, unpaired
clients, exact pins on both endpoints, disabled early-data/session mechanisms,
wrong scope and no-delete grants, malformed/oversized/hash-invalid proposals,
remote-apply refusal, lost acknowledgement/reconnect/exact retry, cross-session
receipt isolation, quota refusal, transactional journal failure, durable reopen,
private queue path/marker/schema guards, revocation after handshake, and idle
request timeout. Pairing expiry branches are tested without waiting five
minutes; no physical clock-fault test is claimed.

No critical outstanding issue was identified in this reviewed localhost scope.
This does not certify arbitrary hostile same-user replacement of private state,
production credential lifecycle, or unattended working-tree sync.

## Cross-device prerequisite and never-run cases

The previous three-VM artifact relay is a different test and does not establish
acceptance of this TLS protocol between machines. This review did not run direct
cross-VM TLS, communicating Windows/macOS/Linux peers, physical VM network
interruption/reboot/power loss, native pairing UI, durable identity rotation or
recovery, or a durable sender outbox. Primary working trees remain prohibited
by the disposable-copy beta scope.

The smallest next acceptance setup needs two approved disposable machines with
compatible metadata policy, a mutually reachable private TCP route, execution
access, and explicit private addresses/port. It also needs a reviewed
private-address bind/peer-allowlist extension and matching network-policy
approval: this deliberately loopback-only code cannot cross VMs merely because
a route becomes available. No public listener, policy bypass, new accounts,
firewall/VPN change, or paid VM provisioning was used as a substitute.

No PR or Sites hosting retry was attempted by this review.
