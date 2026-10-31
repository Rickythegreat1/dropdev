# Permission preservation review — 2026-10-31

Status: the Linux permission-aware local workflow passed independent review and
regression tests. Windows and macOS native behavior was not executed in this
environment; cross-compilation is not runtime certification.

This follows the earlier byte-only checkpoint in `runtime-review.md`. New
`metadata_version: 1` plans preserve the supported permissions described below;
legacy plans without trustworthy metadata snapshots cannot apply or roll back.
The application remains a disposable-copy beta. Exact plan approval and the
explicit disposable-copy acknowledgement are still required. The
acknowledgement declares caller intent; it does not prove that a directory is
disposable or establish a filesystem sandbox.

## Reviewed policy

- Unix: preserve ordinary owner/group/other `rwx` bits. Refuse setuid, setgid,
  sticky bits, foreign ownership/group, extended attributes, ACLs, and failed
  metadata inspection. macOS rejects nonzero BSD file flags; Linux permits only
  known storage-layout flags after a successful descriptor-bound query. File and directory guards pin device/inode identity,
  current ownership, and supported access metadata. They deliberately exclude
  timestamps and hard-link count, which change during normal reconciliation.
- Windows: preserve read-only within a constrained private policy. Supported
  files and directories require an owner equal to the process default creation
  owner (`TokenOwner`) and group equal to `TokenPrimaryGroup`. The creation
  owner must be `TokenUser` or BUILTIN Administrators; arbitrary owner groups
  are refused. The DACL still grants effective full control to exactly
  `TokenUser`, SYSTEM, and Administrators. Production never rewrites ownership,
  groups, or ACLs to make a source fit this policy.
  Unsupported principals, partial/custom/deny/object ACEs, alternate streams,
  extended attributes, and unsupported filesystem attributes fail closed.
  Access-related SACL inspection accepts implicit/default medium `NO_WRITE_UP`
  integrity only and rejects custom labels/resource policies. Audit-only SACLs
  are not inspected or copied; this is not complete Windows ACL replication.
- Any added Unix permission bit on an existing file, any group/other bit on a
  new file, or Windows read-only-to-writable change requires separate permission
  widening consent for the reviewed plan. The same rule applies to rollback.
  Consent cannot waive unsupported metadata checks.
- Metadata-only sync is an explicit `permissions` operation with equal
  before/after content hashes. It replaces using a new inode rather than
  changing the outgoing inode, so unrelated hard links retain their metadata.
- Source, destination, retained original, and in-scope directories have metadata
  evidence. Metadata-only changes can stale a plan even when bytes are equal.
  Registered roots and visited directories are guarded; unrelated external
  ancestors such as `/tmp` are outside that policy.
- Rollback validates and relinks the retained original inode. Missing, changed,
  or substituted recovery evidence blocks automatic rollback. It does not
  reconstruct an original file from CAS bytes when inode evidence is missing.
- Schema-one registries migrate transactionally to permission baselines.
  Unexplained existing mode divergence remains a conflict; old byte-only plans
  are never silently upgraded into permission-aware mutation authority.

## Findings corrected during review

| Finding | Verified correction |
| --- | --- |
| A metadata guard containing only owner/group/mode could not detect an equivalent-mode inode or directory substitution. | Unix guards now include device/inode; Windows guards include volume/file identity. Independent directory-swap and retained-inode-substitution regressions pass on Linux. |
| Linux `cap_std::Dir` handles can use `O_PATH`; fd-based xattr checks then fail with `EBADF`. | Inspection reopens a readable directory descriptor through the captured capability. Ten initially failing permission tests subsequently passed without weakening inspection errors. |
| A restored inode was validated early, but its identity was discarded at the installation boundary. | Restore revalidates retained metadata before linking and compares the installed full guard to that retained evidence. The substitution-at-install-boundary regression passes. |
| A private-principal subset DACL could inherit a broader supported subset on Windows. | The Windows policy requires the exact effective current-user/SYSTEM/Administrators full-control set and constrained inheritance. This is a code-reviewed policy; native Windows verification remains pending. |
| Elevated Windows creation can default to Administrators ownership rather than `TokenUser`, so accepting a user-owned source could fail only after quarantine. | The guard now requires actual ownership equal to the constrained `TokenOwner` creation default, with exact primary-group matching. A mismatched source is refused before mutation; no production ownership transfer or token change is introduced. This policy does not add a principal beyond the canonical full-control set. |
| A public inherited Windows state/cache ACL could expose cached source content. | State, object-store directories, and existing metadata files are validated before content writes. New CAS files are protected and inspected before filling. Native Windows validation remains pending. |
| A prepared incoming inode could otherwise be treated as its own recovery proof. | A durable `incoming_prepared` event records the actual guard before installation. Interruption recovery checks that evidence rather than deriving trust from current staging contents alone. |

Temporary Unix files are created with mode `0600`, and new directories with
`0700`, before content is written. Supported final file permissions are applied
through the opened handle before no-clobber installation. The private incoming
inode is retained, avoiding deletion of a read-only temporary file and removing
the originally proposed Windows post-install attribute-setting window.

Unix metadata inspection uses opened descriptors. The macOS check combines
fd-bound extended stat with explicit ACL-property presence inspection.
[Apple extended-stat implementation](https://github.com/apple-oss-distributions/Libc/blob/main/sys/statx_np.c),
[Apple security-property implementation](https://github.com/apple-oss-distributions/Libc/blob/main/gen/filesec.c)
Windows integrity/resource-policy queries use the documented `READ_CONTROL`
query rights; full audit-SACL retrieval requires additional access and is outside
this implementation's preservation scope. [Microsoft security information rights](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information)
The Windows owner policy follows the token field that governs newly created
objects, rather than assuming it always equals the user SID.
[Microsoft default creation-owner definition](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_owner)

## Filesystem flag finding: corrected

BSD immutable/append flags and analogous Linux inode flags are separate from
rwx, xattrs, and ACLs. Their earlier omission could have copied a locked but
owner-writable source into an unlocked destination without changing its mode.
The reviewed correction rejects any nonzero macOS `st_flags`. Linux now requires
a successful descriptor-bound `FS_IOC_GETFLAGS` query and permits only directory
indexing (`0x1000`) and extent storage (`0x80000`) bits; all other or unknown
bits fail closed. No filesystem flags are changed and no privileges are added.
The kernel query returns a 32-bit flag value. [Linux flag-query implementation](https://github.com/torvalds/linux/blob/master/fs/file_attr.c)

The permitted bits describe storage layout, rather than access rights, and may
change during ordinary directory growth. They are intentionally excluded from
identity/access guards. The module regression checks rejected flag masks and
queries ordinary generated file/directory handles; it does not set privileged
immutable or append flags. The module owner reported those tests passing, and
the parent reported its subsequent full Rust suite passing 123 tests after the
correction. This review inspected the final guard code without duplicating that
full-suite run.

## Independent validation

`cargo test -p devdrop-core` passed: **52 unit tests, 12 permission integration
tests, and 9 security integration tests; 0 failed** at this checkpoint.

The independent permission tests exercised executable and read-only copies;
new group/other access consent; explicit metadata-only changes; source, target,
and directory metadata staleness; equivalent-mode directory swaps; unsupported
special bits and xattrs; retained original inode/mode restoration; rollback
widening consent; missing, modified, or substituted recovery evidence; unrelated
hard-link isolation; and legacy-plan refusal.

Root-owned tests additionally passed for permission edits at quarantine,
retained-inode substitution at installation, interruption/restart recovery,
transactional preview/event insertion failure, and schema-one migration without
trusting legacy permission authority. All files, attributes, and mode changes
in these tests were generated under temporary disposable directories.

The later platform compatibility correction was reviewed statically: macOS uses
fd-based `fstatx_np`/`FILESEC_ACL` presence inspection and rejects any present
extended ACL, including an empty ACL with unsupported inheritance flags;
Windows uses the constrained creation-owner policy above. Module-owner checks
reported Windows GNU test cross-compilation and macOS arm64/x86_64 harness
typechecks passing. Those checks do not prove native platform behavior.

Not run in this independent review environment: physical power-loss tests; native Windows DACL, integrity-label,
read-only, or stream behavior; native macOS ACL behavior; and foreign-owner
mutation or immutable/append flag-setting tests requiring privileges. The review does not certify primary
working-tree use, complete metadata replication, or a security boundary against
processes with equivalent access to the user's files and private state.
