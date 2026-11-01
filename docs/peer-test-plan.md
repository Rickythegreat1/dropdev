# Peer fault and direct-device acceptance plan

This slice extends v5 (`9308532d6af5bd9f2ccef6129d6f74e375b2774a`). The
production authenticated transport still refuses nonloopback binds and peers.
Receiving a proposal never authorizes project writes. Disposable-copy approval,
local staging, exact preview and explicit apply remain separate gates.

## Tests that can run now

```sh
cargo test --workspace --locked
cargo test -p devdrop-peer --all-targets --locked
cargo run -p devdrop-peer --example localhost --locked
cargo run -p devdrop-peer --example process_localhost --locked
python3 scripts/test_smoke_linux_package.py
python3 scripts/test-isolated-vm-readiness.py
```

`process_localhost` launches independent sender/receiver OS processes under one
coordinator on **one OS**. Each peer makes its own ephemeral identity. Actual
hard kills restart peers and reopen a durable SQLite proposal queue, require
fresh explicit pairing and demonstrate that a sender retry outbox does not
survive its process. A transparent TCP proxy cuts streams, damages an encrypted
TLS record, and withholds an acknowledgment after commit. Exact retry determines
the committed outcome. These are actual loopback connection faults, not a
physical network outage, independent machines, a mid-transaction power failure
or a VM reboot. The JSON proof has `cross_device=false` and `vm_reboot=false`.

The ordinary public CI workflow repeats process tests on Linux, Windows and
macOS. A fresh Ubuntu 22.04 job installs **that run's** checksum-verified `.deb`,
starts the installed binary under an authenticated Xvfb/private D-Bus session,
requires a mapped application window and renderer/native IPC-created schema-2
database, then terminates/removes it. It registers no folders and performs no
apply. This is a standard hosted runner, not a bare OS; Windows/macOS installer
execution and physical desktop acceptance remain separate.

`isolated-vm-readiness.yml` uses configured signed APT indexes to download and
extract official QEMU, BusyBox and Ubuntu virtual-kernel packages. It installs
no system packages or maintainer hooks. Two generated Linux guests use software
TCG, one vCPU and 512 MiB each, **no NIC**, no disk, host share, monitor, SSH or
credentials. Serial pipes prove different kernel boot identities and a new guest
B kernel boot identity in the same emulator after reboot. This is real VM
boot/reboot readiness, **not peer transport, cross-VM TLS or durable peer recovery
after VM reboot**. The host package-state digest must stay unchanged.

## Current infrastructure and exact missing approval

The managed executor has no `/dev/kvm`, VM manager, configured VM hosts, VPN,
runtime secrets, cloud identity or outbound TCP target grants. Its managed APT
metadata read returned permission denied for the managed retry config and no
package candidates. That restriction was not bypassed. Existing CI platform
runners do not provide a verified private route to one another. The older
three-runner artifact relay validates a model, not communicating TLS peers.

The smallest proposed independent-kernel lab is **two new disposable TCG guests
inside one existing public CI runner**, named `devdrop-a` and `devdrop-b`. The
following addresses are a proposed approval scope, **not currently configured
machines or assigned IPs**:

| Item | Proposed scope |
| --- | --- |
| Guest A | `devdrop-a`, `10.77.0.1/30` |
| Guest B | `devdrop-b`, `10.77.0.2/30` |
| Listener | Guest B only, TCP `37431`, authenticated TLS 1.3/mTLS |
| Duration | At most 30 minutes for one bounded test run |
| Virtual link | Private AF_UNIX socketpair as an isolated virtual Ethernet cable; no host bridge, NAT, public listener or external route |
| Changes needing approval | Enable one guest NIC per guest, assign those guest addresses, and add a reviewed explicit test-only private-bind/peer allowlist to the currently loopback-only transport |
| Keys and data | RAM-only test identities, generated fixture payloads and private per-guest proposal state; no user credentials/folders |
| Cleanup | Stop/wait both QEMU processes, destroy RAM keys and generated guest disks/initrds/reports containing fixture data; restore no host configuration because none is changed |

Readiness must pass first. The minimal boot images do not yet contain NIC
modules, a durable data disk or the peer worker; preparing those is part of a
reviewed follow-on harness after scope approval. No network test is claimed from
the readiness job. The approval request is for this precise isolated lab, not
public exposure or production device pairing. If actual existing remote VMs are
preferred instead, their verified machine identifiers, private IPs and supported
execution access are still missing and must be supplied before an actionable
remote-machine request can be made.

## Acceptance after approval

Require separate kernel/boot identities and independent queues; explicit
fingerprint pairing and bounded path/deletion/quota scope; actual A-to-B TLS
transfer; exact replay; rejected stale pairing/tampering/scope violations;
disconnect/reconnect and unknown-ack recovery; preserved conflict/delete/restore
behavior through the separately approved local Core workflow. Reboot guest B
with a generated persistent data disk, verify a changed kernel boot identity,
reopen its queue, and explicitly re-pair fresh RAM keys. A process kill or NIC
disconnect must never be labeled a VM reboot. No listener or guest network is
enabled by this document or the current readiness workflow.
