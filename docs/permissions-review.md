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
  metadata inspection. File and directory guards pin device/inode identity,
  current ownership, and supported access metadata. They deliberately exclude
  timestamps and hard-link count, which change during normal reconciliation.
- Windows: preserve read-only within a constrained private policy. Supported
  files and directories require the current user's owner/group and effective
  full-control grants to exactly the current user, SYSTEM, and Administrators.
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
| A public inherited Windows state/cache ACL could expose cached source content. | State, object-store directories, and existing metadata files are validated before content writes. New CAS files are protected and inspected before filling. Native Windows validation remains pending. |
| A prepared incoming inode could otherwise be treated as its own recovery proof. | A durable `incoming_prepared` event records the actual guard before installation. Interruption recovery checks that evidence rather than deriving trust from current staging contents alone. |

Temporary Unix files are created with mode `0600`, and new directories with
`0700`, before content is written. Supported final file permissions are applied
through the opened handle before no-clobber installation. The private incoming
inode is retained, avoiding deletion of a read-only temporary file and removing
the originally proposed Windows post-install attribute-setting window.

Unix metadata inspection uses opened descriptors. macOS has an ACL-specific
native check in addition to xattr inspection; Apple's API retrieves an ACL for
the opened descriptor. [Apple ACL descriptor API](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/acl_get_fd_np.3.html)
Windows integrity/resource-policy queries use the documented `READ_CONTROL`
query rights; full audit-SACL retrieval requires additional access and is outside
this implementation's preservation scope. [Microsoft security information rights](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information)

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

Not run here: physical power-loss tests; native Windows DACL, integrity-label,
read-only, or stream behavior; native macOS ACL behavior; and foreign-owner
mutation tests requiring privileges. The review does not certify primary
working-tree use, complete metadata replication, or a security boundary against
processes with equivalent access to the user's files and private state.
