# Authenticated peer transport — local prototype

The devdrop-peer library implements a real TLS proposal channel and explicit
pairing. This slice is tested only with ephemeral identities and disposable
localhost fixtures. The previous three-VM artifact relay remains a different
simulation: it does not establish that this TLS protocol works between devices.

## Pairing and trust

Each pairing flow generates an ephemeral certificate/private key in RAM and a
random public offer nonce. Both peers must explicitly confirm the other's exact
certificate fingerprint and the same bounded scope. There is no automatic
trust-on-first-use endpoint. The session binds both offers and the scope, expires
within five minutes and can be revoked locally. Each endpoint owns its own
grant; local revocation is not a broadcast unlink operation. It prevents new
admissions at that endpoint; an already admitted queue transaction may finish. Restarting without the in-memory identity
requires new pairing; no persistent production identity files are created.

Rustls performs standard TLS 1.3 certificate/signature verification with mandatory
client certificates. Both endpoints additionally require the presented leaf
certificate to match the approved pin. ALPN separates the DevDrop protocol.
Early data and session resumption are disabled. Private keys may be converted
between library representations inside RAM; they are never exported to files,
serialized through public APIs, printed, or included in reports/artifacts.

## Capabilities and data flow

A pairing grant names a channel and exact relative file paths, permits or denies
deletion proposals, and caps paths, messages, proposal bytes and retained bytes.
Hidden/env/credential/generated paths, traversal and unsupported permission
metadata are refused. Obvious private-key/token markers are also refused; these
checks are conservative filters, not proof that arbitrary source content is
secret-free. The API accepts explicitly supplied proposal bytes; it is
not a remote filesystem scanner or arbitrary project-read endpoint. Selected
content still requires the caller's local authorization and normal project policy.

Framed messages have strict schemas and bounded lengths/timeouts. They bind both
peer fingerprints, pairing/channel, sequence, previous digest and content hashes.
TLS authenticates/encrypts the connection; BLAKE3 alone is not authentication.
A private SQLite queue commits accepted payload and replay state together.
Timeout or a lost acknowledgement leaves the queue outcome unknown: an already
admitted blocking SQLite operation can finish after the network deadline. The
caller must retain and retry the exact proposal to obtain an idempotent receipt;
it must not infer that a timeout means nothing was stored. Duplicate delivery
is inert; a different message at the same sequence, a gap,
wrong predecessor, expired/revoked grant or scope violation is rejected.

Receiving a proposal does not authorize a workspace write. There is no network
apply, stage, chmod, shell, local-file read or conflict-resolution method. Only
local code can review pending data and decide what to stage. The acceptance
example uses generated fixture roots and supplies local approvals deliberately,
then exercises the existing Core Engine. It does not install an unattended sync
agent or expose a new desktop/daemon mutation endpoint.

## Network and acceptance boundary

Client and server reject non-loopback addresses in this slice. Tests open only
short-lived localhost listeners with OS-assigned ports. No firewall changes,
public endpoints, VPN, new accounts or paid VM resources are used.

The managed executor has no KVM device/VM runtime or approved peer network. The
existing CI VM jobs have no configured shared private peer route. The smallest
additional prerequisite for real VM TLS acceptance is two approved disposable
machines on a reachable private network, plus permission to bind the specific
private interfaces for the test. That would require an explicit controlled
private-address allowlist/bind extension to this deliberately loopback-only
prototype and the environment network policy; no public listener or policy bypass is an alternative.

A production rollout additionally needs approval and design for durable identity
storage/rotation/revocation, device pairing UI, project-grant integration and a
reviewed private/hosted transport topology. Those are outside the present
credential and device-pairing authorization. Primary working trees remain
prohibited by the existing disposable-copy beta boundary.

## Verification

Final exact-source results and never-run cases are recorded in the portable
handoff and CI. The dedicated report is explicitly named authenticated localhost
evidence. Physical VM network interruption/reboot, direct cross-device TLS and
production credentials remain untested; earlier artifact relay must not be
substituted for them.

## Dependency and source checks

The workspace requires Tokio 1.54.1 or newer: this avoids the published AsyncFd
I/O-safety issue and the 1.54.0 Interval regression. Rustls 0.23.46 and the locked
WebPKI 0.103.16 include the relevant current certificate/session fixes. This was a
targeted advisory/source check, not a claim of a complete dependency audit.
The desktop's separate lockfile already used Tokio 1.54.1.

- [Tokio I/O safety advisory](https://rustsec.org/advisories/RUSTSEC-2026-0386.html)
- [Tokio Interval advisory](https://rustsec.org/advisories/RUSTSEC-2026-0384.html)
- [Rustls session-secret Debug advisory](https://rustsec.org/advisories/RUSTSEC-2026-0346.html)
- [WebPKI intermediate-certificate fix](https://rustsec.org/advisories/RUSTSEC-2026-0382.html)
- [Rustls mandatory client-certificate verifier](https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html)

Repeatable commands:

```sh
cargo test -p devdrop-peer --all-targets --locked
cargo run -p devdrop-peer --example localhost --locked
```

Reports contain public fingerprints and bounded outcome metadata only. The
localhost example accepts no real project folders, listen addresses, device IDs
or credentials. Automated fixture approvals are test instructions, not evidence
that a human reviewed a real project or paired a device.
