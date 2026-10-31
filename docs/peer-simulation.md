# Cross-device simulation and VM evidence

This is a fixture-only test harness. DevDrop still has no production peer
transport, pairing, remote authentication, or direct VM-to-VM TCP acceptance.
The desktop remains a local disposable-copy beta. Never register primary
working trees for these tests.

## Verified executor capability

The managed executor is one Linux x86_64 kernel. It has no `/dev/kvm` or
`/dev/vmm`; QEMU system emulators, libvirt, VirtualBox, Multipass, Vagrant,
Firecracker and cloud-hypervisor are unavailable. No configured VPN, outbound
cloud identity, peer TCP destinations or VM provisioning connector is available.
No hypervisor, guest image, accounts, credentials, Docker, firewall changes or
paid resources were installed or provisioned.

Separate local folders, processes or SQLite files are **not multiple VMs**.
Local simulator results prove a model plus the real local sync engine only.

## Supported CI topology

The new `peer-vm-simulation.yml` workflow uses three standard GitHub-hosted
`ubuntu-22.04` jobs in the existing public repository. Each job has a fresh VM;
standard hosted runners are free for public repositories. The workflow refuses
private repositories rather than drawing on billable private-runner minutes.
See [GitHub runner documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job).

| VM role | Input | Operation | Output |
| --- | --- | --- | --- |
| A: fixture sender | Fixed generated content | Create bounded sequence of fixture packets and independent sender state | Offer artifact, sanitized runtime evidence |
| B: fixture receiver | Download A's artifact from this workflow run | Verify/import fixture packets into its own durable journal and staging area; exercise the actual preview/approved-apply/conflict/rollback engine | Reply bound to the offer, scenario evidence, separate runtime evidence |
| C: receipt verifier | Download A and B artifacts from this workflow run | Verify the reply's offer binding and distinct runtime boot fingerprints | Final sanitized evidence |

A and B exchange bytes through GitHub's artifact store. This is store-and-forward
transport between independent CI VMs, not a direct peer socket. C is a third
verifier, **not** a restarted original A device. Runtime evidence binds role,
run ID and source SHA and hashes Linux's ephemeral boot ID; raw machine IDs and
secrets are not reported. The verifier requires distinct VM boot fingerprints.

Offline/reconnect and reordered messages are controlled simulator faults. They
do not represent physically disabling/re-enabling a VM's network. SQLite reopen
and replay checks exercise durable receiver state within B; they do not establish
reboot/power-loss recovery across multiple operating systems.

## Simulation boundary

The Rust example is separate from the shipped CLI, desktop, daemon and MCP API.
It creates generated disposable workspaces and uses the real local Engine for
previews, conflict resolution, explicit approval, permission consent and rollback.
It accepts a bounded fixture namespace, not arbitrary user project import.
It reads only the exact bounded `offer.json` or `reply.json` manifest; adjacent
files are ignored rather than scanned or imported. A/B artifacts include only
their manifest, sanitized evidence and runtime record. Their workspaces,
SQLite journals and object stores remain separate on their originating VMs.

Fixture envelopes bind version, a per-offer fixture session label,
sender/recipient, sequence, prior digest and payload integrity. The session label
is nonsecret and does not establish authentication. Public deterministic test tags model rejection
of altered frames; they are **not production credentials or authentication**.
Knowledge of the fixture code permits constructing valid test tags. No secret
pairing keys are created, published, persisted or claimed secure. A production
transport needs an independently reviewed authenticated encrypted session and
identity provisioning before real projects can be exchanged.

Accepted fixture packets update the receiver's journal/staging view. They do
not authorize writes to its workspace. Workspace changes still require the exact
local preview ID, disposable-copy acknowledgement and separate access-increase
consent where applicable. Raw file contents and test tag keys are not printed
in reports. Artifacts intentionally contain only the generated fixture packets;
no real projects, environment values, credentials or local user state are included.
The test harness deliberately supplies approvals for its generated fixtures;
this is not a remote approval API. The fixture declares a fixed local permission
policy. Receiver metadata is recreated under that policy; artifact filesystem
modes are not trusted as source access evidence. This does not test arbitrary
source-mode transfer or cross-platform permission translation between peers.

## Repeatable commands

```sh
cargo test -p devdrop-core --example peer_simulation --locked
cargo run -p devdrop-core --example peer_simulation --locked -- local
```

The workflow runs the `offer`, `receive` and `verify` phases on separate VMs and
retains their generated artifacts and sanitized reports. Output directories must
be new. Input directories must contain only the expected bounded fixture inputs.
The final handoff records exact commit, workflow runs, artifacts, passed checks,
failures and never-run acceptance separately. Until the new workflow completes,
VM-to-VM fixture exchange remains pending rather than passed.

## Acceptance still needed

- Production pairing, encrypted peer transport and credential lifecycle.
- Direct peer-to-peer communication on an approved private network.
- Actual VM network interruption/reconnect and guest reboot/power-loss tests.
- Communicating Windows/macOS/Linux peers; separate platform jobs do not prove this.
- Native desktop installation and GUI sync on clean target machines.
- Full metadata/ACL preservation beyond the constrained supported permission policy.

The prior Sites helper blocker and denied draft PR are unchanged. This workflow
neither hosts DevDrop nor publishes a filesystem-mutating network service.
