# File permission scope

Permission preservation is a local, platform-specific feature. Disposable-copy
acknowledgement and exact-plan approval remain required; permission increases
also need separate approval. These checks do not prove that a directory is a
sandbox or make primary working trees supported.

## Unix

Supported regular files retain ordinary `rwx` bits (`0000`–`0777`), including
executable flags. Files and directories must belong to the process's effective
user and primary group. DevDrop does not transfer ownership or group IDs.
Setuid, setgid and sticky bits are rejected. Extended attributes and extended
ACLs are rejected, including default directory ACLs. Linux ACLs are detected via
fd-based attribute enumeration; macOS additionally queries its native extended
ACL through the open descriptor. Inspection errors fail closed.

The guard includes device/inode identity, owner/group and permission bits. It
excludes timestamps and link count so retaining an inode through rename/hardlink
can be verified. Incoming Unix files must be created with mode `0600` atomically,
before writing bytes; new directories use `0700` atomically. A later chmod alone
would leave a window in which a different user could retain an open read handle.

## Windows

The supported file flag is read-only. Unix execute bits have no equivalent in
this policy. Windows file owner and primary group must match the current
process token. DevDrop does not assign owner/group or copy arbitrary DACLs.

The accepted DACL has full control for exactly the current user, SYSTEM and
Administrators, with no additional access principals or deny/object/partial ACEs.
Directories must inherit those grants to files and child directories. An
inherit-only CREATOR_OWNER rule is accepted only on directories; it cannot add
an effective principal. This exact semantic set prevents a copied file from
silently gaining a previously absent principal through target inheritance.

Access-related security metadata is queried without enabling privileges:
mandatory integrity labels must be implicit medium or medium `NO_WRITE_UP`;
custom labels, resource-attribute ACEs and central access policy entries are
rejected. Alternate data streams, NT extended attributes, encrypted/compressed,
reparse/system and other unsupported file attributes are rejected. Stable guards
include volume/file identity and hashes of the actual owner/group, accepted DACL
and queried access-related security metadata. Inspection errors fail closed.

Audit-only SACL entries are **not** queried or copied for new files: that would
require `ACCESS_SYSTEM_SECURITY`/security privilege. No privilege is enabled.
Consequently this is not full security-descriptor, audit-policy, timestamp or
extended-metadata preservation. Files that depend on unqueried auditing or other
unsupported security policy must stay outside this beta. Windows tests use only
new empty generated directories, explicitly provisioned with the accepted private
DACL and inheritable medium integrity policy; production code does not rewrite a
user directory's ACL to make it pass.

## Replacement and rollback

Normal copy/replacement requests the source's supported mode/flag. The engine
must show before/after permissions, compare metadata during stale-plan checks,
and refuse a widening without explicit approval. New Unix group/other bits also
count as widening because target parent directories may have different exposure.

Rollback restores the retained original inode when one existed, rather than
recreating bytes with default metadata. This preserves that destination's actual
original metadata without inventing ownership/ACL writes. Its identity and
supported access guard must still match; a changed/missing retained file blocks
automatic rollback. Unsupported metadata does not become supported merely
because a backup exists.

## Sources and validation

- [Microsoft GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
  documents handle-based owner/DACL queries and returned-buffer lifetime.
- [Microsoft SECURITY_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information)
  distinguishes ordinary `READ_CONTROL` access-policy queries from privileged
  full-SACL queries.
- [Microsoft NtQueryInformationFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile)
  defines extended-attribute size inspection.
- [Apple ACL API](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/acl_get_fd.3.html)
  and its [public header](https://raw.githubusercontent.com/apple-oss-distributions/Libc/main/include/sys/acl.h)
  define the native fd-based extended-ACL check.

The module's Linux tests and Windows cross-target compilation are local checks;
Windows/macOS runtime behavior requires the platform CI fixtures and remains
unverified until those runs succeed.
