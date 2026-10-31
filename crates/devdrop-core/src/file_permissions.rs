//! Supported file access metadata. All inspection and mutation uses opened handles.
//! Unix rwx bits and Windows read-only are portable within their own platform only.
//! Extended ACLs/xattrs and foreign ownership are blocked rather than discarded.
use serde::{Deserialize, Serialize};
use std::fs::File;

type Result<T> = std::result::Result<T, &'static str>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case")]
pub enum FilePermissions {
    Unix { mode: u32 },
    Windows { readonly: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessMetadata {
    pub permissions: FilePermissions,
    /// Fingerprint only; no account names, ACL entries or attribute values are exposed.
    pub guard: String,
}

/// A separate approval is needed when an existing file gains any supported right.
/// New Unix files with group/other bits also need approval because a replica's
/// parent directories may expose them more broadly than the source location.
pub fn permission_widening(
    before: Option<&FilePermissions>,
    after: Option<&FilePermissions>,
) -> bool {
    match (before, after) {
        (_, None) => false,
        (None, Some(FilePermissions::Unix { mode })) => mode & 0o077 != 0,
        (
            Some(FilePermissions::Unix { mode: before }),
            Some(FilePermissions::Unix { mode: after }),
        ) => after & !before & 0o777 != 0,
        (
            Some(FilePermissions::Windows { readonly: true }),
            Some(FilePermissions::Windows { readonly: false }),
        ) => true,
        (None, Some(FilePermissions::Windows { .. }))
        | (Some(FilePermissions::Windows { .. }), Some(FilePermissions::Windows { .. })) => false,
        _ => true,
    }
}

pub fn inspect_file(file: &File) -> Result<AccessMetadata> {
    platform::inspect_file(file)
}
pub fn inspect_directory(file: &File) -> Result<String> {
    platform::inspect_directory(file)
}
pub fn apply_permissions(file: &File, permissions: &FilePermissions) -> Result<()> {
    platform::apply_permissions(file, permissions)
}
pub fn make_private(file: &File) -> Result<()> {
    platform::make_private(file)
}
pub fn make_directory_private(file: &File) -> Result<()> {
    platform::make_directory_private(file)
}

#[cfg(windows)]
pub fn make_disposable_test_directory_private(path: &std::path::Path) -> Result<()> {
    platform::make_disposable_test_directory_private(path)
}

#[cfg(unix)]
mod platform {
    use super::*;
    #[cfg(target_os = "macos")]
    use std::os::macos::fs::MetadataExt as _;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    use std::os::unix::io::AsRawFd;
    use xattr::FileExt;

    fn inspect(file: &File, directory: bool) -> Result<(u32, String)> {
        let metadata = file
            .metadata()
            .map_err(|_| "Cannot inspect permission metadata.")?;
        if metadata.is_dir() != directory || (!directory && !metadata.is_file()) {
            return Err("Permission metadata requires a regular file or directory.");
        }
        // SAFETY: these process identity queries do not access pointers or modify state.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        if metadata.uid() != uid || metadata.gid() != gid {
            return Err(
                "Foreign file ownership/group is unsupported; use a current-user disposable copy.",
            );
        }
        let mode = metadata.mode();
        if mode & 0o7000 != 0 {
            return Err("Special permission bits are unsupported; setuid, setgid and sticky entries are blocked.");
        }
        #[cfg(target_os = "macos")]
        if metadata.st_flags() != 0 {
            return Err("BSD file flags are unsupported; locked, append-only and other flagged entries are blocked.");
        }
        #[cfg(target_os = "linux")]
        inspect_linux_flags(file)?;
        if file
            .list_xattr()
            .map_err(|_| {
                "Extended attribute inspection failed; permission preservation is blocked."
            })?
            .next()
            .is_some()
        {
            return Err("Extended attributes or ACLs are unsupported; preserve them outside this disposable-copy beta.");
        }
        #[cfg(target_os = "macos")]
        reject_macos_acl(file)?;
        // Stable through rename and hard-link creation. Excludes atime/ctime/nlink.
        let guard = blake3::hash(
            format!(
                "unix:{}:{}:{}:{}:{:o}:plain",
                metadata.dev(),
                metadata.ino(),
                metadata.uid(),
                metadata.gid(),
                mode & 0o777
            )
            .as_bytes(),
        )
        .to_hex()
        .to_string();
        Ok((mode & 0o777, guard))
    }

    #[cfg(target_os = "linux")]
    fn supported_linux_flags(flags: u32) -> bool {
        // Linux uapi/linux/fs.h: these describe directory indexing / on-disk
        // extent storage, not access rights. They need not survive a copy and
        // may change as directory contents grow. All other flags fail closed,
        // including IMMUTABLE, APPEND, ENCRYPT, VERITY, DAX and unknown bits.
        const STORAGE_LAYOUT_ONLY: u32 = 0x0000_1000 | 0x0008_0000;
        flags & !STORAGE_LAYOUT_ONLY == 0
    }

    #[cfg(target_os = "linux")]
    fn inspect_linux_flags(file: &File) -> Result<()> {
        let mut flags: libc::c_int = 0;
        // SAFETY: GETFLAGS is a read-only query against the already opened
        // descriptor. Linux expects a writable int output (not a path).
        let result = unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) };
        if result != 0 {
            return Err("Filesystem flag inspection failed; permission preservation is blocked.");
        }
        if !supported_linux_flags(flags as u32) {
            return Err("Unsupported filesystem flags; immutable, append-only and other flagged entries are blocked.");
        }
        Ok(())
    }

    #[cfg(all(test, target_os = "linux"))]
    mod flag_tests {
        use super::*;

        #[test]
        fn access_flags_and_unknown_bits_are_refused_without_setting_them() {
            assert!(supported_linux_flags(0));
            assert!(supported_linux_flags(0x0008_1000));
            for flag in [0x10, 0x20, 0x800, 0x100000, 0x2000000, 0x80000000] {
                assert!(!supported_linux_flags(flag));
                assert!(!supported_linux_flags(flag | 0x0008_1000));
            }
            let temp = tempfile::tempdir().unwrap();
            inspect_linux_flags(&File::open(temp.path()).unwrap()).unwrap();
            let file = File::create(temp.path().join("generated-flag-fixture")).unwrap();
            inspect_linux_flags(&file).unwrap();
        }
    }
    pub fn inspect_file(file: &File) -> Result<AccessMetadata> {
        let (mode, guard) = inspect(file, false)?;
        Ok(AccessMetadata {
            permissions: FilePermissions::Unix { mode },
            guard,
        })
    }
    pub fn inspect_directory(file: &File) -> Result<String> {
        inspect(file, true).map(|(_, guard)| guard)
    }
    pub fn apply_permissions(file: &File, permissions: &FilePermissions) -> Result<()> {
        let FilePermissions::Unix { mode } = permissions else {
            return Err("Permission metadata belongs to another operating system.");
        };
        if *mode & !0o777 != 0 {
            return Err("Only ordinary Unix rwx permission bits may be applied.");
        }
        inspect(file, false)?;
        file.set_permissions(std::fs::Permissions::from_mode(*mode))
            .map_err(|_| "Permission update failed.")?;
        if inspect_file(file)?.permissions != *permissions {
            return Err("Applied permissions did not verify.");
        }
        Ok(())
    }
    pub fn make_private(file: &File) -> Result<()> {
        inspect(file, false)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| "Cannot protect the incoming file before content write.")?;
        if inspect_file(file)?.permissions != (FilePermissions::Unix { mode: 0o600 }) {
            return Err("Private incoming permissions did not verify.");
        }
        Ok(())
    }
    pub fn make_directory_private(file: &File) -> Result<()> {
        inspect(file, true)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "Cannot protect a new directory.")?;
        if inspect(file, true)?.0 != 0o700 {
            return Err("Private directory permissions did not verify.");
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn reject_macos_acl(file: &File) -> Result<()> {
        use std::ffi::c_void;
        // Apple FILESEC_ACL=5. Presence itself is unsupported, even for an
        // empty ACE list, because inheritance flags are outside this policy.
        extern "C" {
            fn filesec_init() -> *mut c_void;
            fn filesec_free(filesec: *mut c_void);
            #[cfg_attr(
                any(target_arch = "x86", target_arch = "x86_64"),
                link_name = "fstatx_np$INODE64"
            )]
            fn fstatx_np(
                fd: libc::c_int,
                stat: *mut libc::stat,
                filesec: *mut c_void,
            ) -> libc::c_int;
            fn filesec_query_property(
                filesec: *mut c_void,
                property: libc::c_int,
                present: *mut libc::c_int,
            ) -> libc::c_int;
        }
        // SAFETY: the native filesec object is live for these fd-bound calls and
        // freed exactly once. The uninitialized stat output is never read.
        unsafe {
            let filesec = filesec_init();
            if filesec.is_null() {
                return Err("Native ACL inspection failed; permission preservation is blocked.");
            }
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            let inspected = fstatx_np(file.as_raw_fd(), stat.as_mut_ptr(), filesec);
            let mut present = 0;
            let queried = if inspected == 0 {
                filesec_query_property(filesec, 5, &mut present)
            } else {
                -1
            };
            filesec_free(filesec);
            if inspected != 0 || queried != 0 {
                return Err("Native ACL inspection failed; permission preservation is blocked.");
            }
            if present != 0 {
                return Err("Extended ACLs are unsupported; preserve them outside this disposable-copy beta.");
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        ffi::c_void,
        mem::{size_of, zeroed},
        os::windows::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
        path::Path,
        ptr, slice,
    };
    use windows_sys::Wdk::Storage::FileSystem::{
        FileEaInformation, NtQueryInformationFile, FILE_EA_INFORMATION,
    };
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, GetLastError, LocalFree, ERROR_BAD_LENGTH, ERROR_HANDLE_EOF,
            ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, HANDLE,
        },
        Security::{Authorization::*, *},
        Storage::FileSystem::*,
        System::{
            Threading::{GetCurrentProcess, OpenProcessToken},
            IO::IO_STATUS_BLOCK,
        },
    };

    struct LocalMemory(*mut c_void);
    impl Drop for LocalMemory {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    fn handle(file: &File) -> HANDLE {
        file.as_raw_handle() as HANDLE
    }
    unsafe fn sid_bytes(sid: PSID) -> Result<Vec<u8>> {
        if sid.is_null() || IsValidSid(sid) == 0 {
            return Err("Unsupported Windows security identity.");
        }
        let len = GetLengthSid(sid) as usize;
        if !(8..=68).contains(&len) {
            return Err("Unsupported Windows security identity.");
        }
        Ok(slice::from_raw_parts(sid.cast(), len).to_vec())
    }
    fn token_information(class: TOKEN_INFORMATION_CLASS) -> Result<Vec<usize>> {
        unsafe {
            let mut raw = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) == 0 {
                return Err("Cannot inspect the current Windows identity.");
            }
            let token = Token(raw);
            let mut length = 0;
            GetTokenInformation(token.0, class, ptr::null_mut(), 0, &mut length);
            if length == 0 || length > 65536 {
                return Err("Windows identity metadata exceeds its budget.");
            }
            let mut buffer =
                vec![0usize; (length as usize + size_of::<usize>() - 1) / size_of::<usize>()];
            if GetTokenInformation(
                token.0,
                class,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            ) == 0
            {
                return Err("Cannot inspect the current Windows identity.");
            }
            Ok(buffer)
        }
    }
    struct Identity {
        user: Vec<u8>,
        creation_owner: Vec<u8>,
        primary_group: Vec<u8>,
    }
    fn identity() -> Result<Identity> {
        unsafe {
            let user = token_information(TokenUser)?;
            let owner = token_information(TokenOwner)?;
            let group = token_information(TokenPrimaryGroup)?;
            let identity = Identity {
                user: sid_bytes((*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid)?,
                creation_owner: sid_bytes((*(owner.as_ptr().cast::<TOKEN_OWNER>())).Owner)?,
                primary_group: sid_bytes(
                    (*(group.as_ptr().cast::<TOKEN_PRIMARY_GROUP>())).PrimaryGroup,
                )?,
            };
            // Ownership itself can grant WRITE_DAC. Do not admit a token's
            // arbitrary default-owner group outside the canonical private set.
            if identity.creation_owner != identity.user
                && identity.creation_owner != known_sid(WinBuiltinAdministratorsSid)?
            {
                return Err(
                    "Windows default creation owner is outside the supported private principals.",
                );
            }
            Ok(identity)
        }
    }
    fn known_sid(kind: WELL_KNOWN_SID_TYPE) -> Result<Vec<u8>> {
        unsafe {
            let mut bytes = vec![0u32; 17];
            let mut size = (bytes.len() * 4) as u32;
            if CreateWellKnownSid(kind, ptr::null_mut(), bytes.as_mut_ptr().cast(), &mut size) == 0
            {
                return Err("Cannot inspect a well-known Windows identity.");
            }
            Ok(slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), size as usize).to_vec())
        }
    }

    // READ_CONTROL permits querying these access-related SACL components without
    // enabling SeSecurityPrivilege. Audit ACEs are deliberately not queried/copied.
    fn access_sacl(file: &File) -> Result<String> {
        let medium = known_sid(WinMediumLabelSid)?;
        unsafe {
            let mut sacl = ptr::null_mut();
            let mut descriptor = ptr::null_mut();
            let result = GetSecurityInfo(
                handle(file),
                SE_FILE_OBJECT,
                LABEL_SECURITY_INFORMATION
                    | ATTRIBUTE_SECURITY_INFORMATION
                    | SCOPE_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut sacl,
                &mut descriptor,
            );
            let _allocation = LocalMemory(descriptor);
            if result != 0 || descriptor.is_null() {
                return Err("Windows integrity/resource-policy inspection failed.");
            }
            if sacl.is_null() {
                return Ok(blake3::hash(b"implicit-medium-integrity")
                    .to_hex()
                    .to_string());
            }
            if IsValidAcl(sacl) == 0 || (*sacl).AceCount > 1 {
                return Err("Custom Windows integrity or resource policies are unsupported.");
            }
            if (*sacl).AceCount == 0 {
                return Ok(blake3::hash(b"implicit-medium-integrity")
                    .to_hex()
                    .to_string());
            }
            let mut ace = ptr::null_mut();
            if GetAce(sacl, 0, &mut ace) == 0 || ace.is_null() {
                return Err("Windows integrity-policy inspection failed.");
            }
            let header = &*ace.cast::<ACE_HEADER>();
            // SYSTEM_MANDATORY_LABEL_ACE_TYPE=17; only medium NO_WRITE_UP is supported.
            if header.AceType != 17 || header.AceSize < 16 || header.AceFlags & !0x13 != 0 {
                return Err("Custom Windows integrity or resource policies are unsupported.");
            }
            let label = &*ace.cast::<SYSTEM_MANDATORY_LABEL_ACE>();
            let sid_pointer = ace.cast::<u8>().add(8);
            let sid_length = 8usize + 4 * (*sid_pointer.add(1) as usize);
            if sid_length > 68 || sid_length + 8 > header.AceSize as usize {
                return Err("Windows integrity-policy metadata is invalid.");
            }
            let sid = sid_bytes(sid_pointer.cast())?;
            if sid.len() + 8 > header.AceSize as usize || sid != medium || label.Mask != 1 {
                return Err("Only default medium NO_WRITE_UP Windows integrity is supported.");
            }
            Ok(blake3::hash(slice::from_raw_parts(
                ace.cast::<u8>(),
                header.AceSize as usize,
            ))
            .to_hex()
            .to_string())
        }
    }

    /// Require the same effective grants on source, destination and inherited files:
    /// full control to exactly the current user, SYSTEM and Administrators.
    fn private_security(file: &File, directory: bool) -> Result<String> {
        let Identity {
            user,
            creation_owner,
            primary_group,
        } = identity()?;
        let system = known_sid(WinLocalSystemSid)?;
        let admins = known_sid(WinBuiltinAdministratorsSid)?;
        let creator = known_sid(WinCreatorOwnerSid)?;
        unsafe {
            let mut owner = ptr::null_mut();
            let mut group = ptr::null_mut();
            let mut dacl = ptr::null_mut();
            let mut descriptor = ptr::null_mut();
            let result = GetSecurityInfo(
                handle(file),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                &mut group,
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            );
            let allocation = LocalMemory(descriptor);
            if result != 0 || allocation.0.is_null() {
                return Err("Cannot inspect Windows owner/ACL metadata.");
            }
            let owner = sid_bytes(owner)?;
            let group = sid_bytes(group)?;
            if owner != creation_owner || group != primary_group {
                return Err("Windows ownership/group differs from this process's creation defaults; use a disposable copy created by this process.");
            }
            if dacl.is_null()
                || IsValidAcl(dacl) == 0
                || (*dacl).AceCount == 0
                || (*dacl).AceCount > 64
            {
                return Err("A canonical private Windows ACL is required.");
            }
            let mut control = 0u16;
            let mut revision = 0;
            if GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0 {
                return Err("Cannot inspect Windows ACL control metadata.");
            }
            let access_policy = access_sacl(file)?;
            let mut fingerprint = blake3::Hasher::new();
            fingerprint.update(b"private-windows-v1");
            fingerprint.update(access_policy.as_bytes());
            fingerprint.update(&owner);
            fingerprint.update(&group);
            fingerprint.update(&control.to_le_bytes());
            let mut present = 0u8;
            for index in 0..(*dacl).AceCount as u32 {
                let mut ace = ptr::null_mut();
                if GetAce(dacl, index, &mut ace) == 0 || ace.is_null() {
                    return Err("Cannot inspect a Windows access rule.");
                }
                let header = &*ace.cast::<ACE_HEADER>();
                let size = header.AceSize as usize;
                if header.AceType != 0 || size < 16 || header.AceFlags & !0x1b != 0 {
                    return Err("Custom, deny or object Windows access rules are unsupported.");
                }
                let allow = &*ace.cast::<ACCESS_ALLOWED_ACE>();
                let sid_pointer = ace.cast::<u8>().add(8);
                let sid_length = 8usize + 4 * (*sid_pointer.add(1) as usize);
                if sid_length > 68 || sid_length + 8 > size {
                    return Err("Windows access-rule metadata is invalid.");
                }
                let sid = sid_bytes(sid_pointer.cast())?;
                if sid.len() + 8 > size {
                    return Err("Windows access-rule metadata is invalid.");
                }
                if allow.Mask != FILE_ALL_ACCESS && allow.Mask != 0x10000000 {
                    return Err("Partial Windows access rules are unsupported; a private full-control ACL is required.");
                }
                let inheritance_only = header.AceFlags & 0x08 != 0;
                let role = if sid == user {
                    1
                } else if sid == system {
                    2
                } else if sid == admins {
                    4
                } else if directory && sid == creator && inheritance_only {
                    0
                } else {
                    return Err("Additional Windows access principals are unsupported; use private disposable folders.");
                };
                if directory {
                    if header.AceFlags & 0x03 != 0x03 {
                        return Err("Windows folder ACLs must privately inherit full access to files and child folders.");
                    }
                } else if inheritance_only || header.AceFlags & 0x03 != 0 {
                    return Err("Unexpected inheritance rules on a Windows file are unsupported.");
                }
                if !inheritance_only {
                    present |= role;
                }
                fingerprint.update(slice::from_raw_parts(ace.cast::<u8>(), size));
            }
            if present != 7 {
                return Err("Windows ACLs must grant exactly current-user, SYSTEM and Administrators full control.");
            }
            Ok(fingerprint.finalize().to_hex().to_string())
        }
    }
    fn reject_extra_metadata(file: &File, directory: bool) -> Result<()> {
        let metadata = file
            .metadata()
            .map_err(|_| "Cannot inspect Windows attributes.")?;
        let allowed = FILE_ATTRIBUTE_READONLY
            | FILE_ATTRIBUTE_ARCHIVE
            | FILE_ATTRIBUTE_NORMAL
            | if directory {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                0
            };
        if metadata.file_attributes() & !allowed != 0 {
            return Err("Unsupported Windows file attributes are present; encrypted/compressed/reparse/system metadata is blocked.");
        }
        unsafe {
            let mut status: Box<IO_STATUS_BLOCK> = Box::new(zeroed());
            let mut ea: Box<FILE_EA_INFORMATION> = Box::new(zeroed());
            let result = NtQueryInformationFile(
                handle(file),
                &mut *status,
                (&mut *ea as *mut FILE_EA_INFORMATION).cast(),
                size_of::<FILE_EA_INFORMATION>() as u32,
                FileEaInformation,
            );
            if result == 0x103 {
                // Rooted runtime handles are synchronous. An unsupported asynchronous
                // handle must not leave the kernel pointing into freed Rust storage.
                std::mem::forget(status);
                std::mem::forget(ea);
                return Err("Asynchronous Windows metadata handles are unsupported.");
            }
            if result < 0 {
                return Err("Windows extended-attribute inspection failed.");
            }
            if ea.EaSize != 0 {
                return Err(
                    "Windows extended attributes are unsupported; preserve them outside this beta.",
                );
            }
            let mut words = vec![0u64; 8192];
            loop {
                if GetFileInformationByHandleEx(
                    handle(file),
                    FileStreamInfo,
                    words.as_mut_ptr().cast(),
                    (words.len() * 8) as u32,
                ) != 0
                {
                    break;
                }
                let error = GetLastError();
                if error == ERROR_HANDLE_EOF {
                    return Ok(());
                }
                if ![ERROR_MORE_DATA, ERROR_INSUFFICIENT_BUFFER, ERROR_BAD_LENGTH].contains(&error)
                    || words.len() * 8 >= 1024 * 1024
                {
                    return Err("Windows alternate-stream inspection failed.");
                }
                words.resize(words.len() * 2, 0);
            }
            let bytes = slice::from_raw_parts(words.as_ptr().cast::<u8>(), words.len() * 8);
            let stream = &*words.as_ptr().cast::<FILE_STREAM_INFO>();
            let length = stream.StreamNameLength as usize;
            if stream.NextEntryOffset != 0
                || length % 2 != 0
                || length > bytes.len().saturating_sub(24)
            {
                return Err("Windows alternate data streams are unsupported.");
            }
            let name = slice::from_raw_parts(bytes.as_ptr().add(24).cast::<u16>(), length / 2);
            if name != [58, 58, 36, 68, 65, 84, 65] {
                return Err("Windows alternate data streams are unsupported.");
            }
        }
        Ok(())
    }
    fn inspect(file: &File, directory: bool) -> Result<AccessMetadata> {
        let metadata = file
            .metadata()
            .map_err(|_| "Cannot inspect Windows permission metadata.")?;
        if metadata.is_dir() != directory || (!directory && !metadata.is_file()) {
            return Err("Permission metadata requires a regular file or directory.");
        }
        reject_extra_metadata(file, directory)?;
        let security = private_security(file, directory)?;
        let readonly = metadata.permissions().readonly();
        let mut identity: FILE_ID_INFO = unsafe { zeroed() };
        if unsafe {
            GetFileInformationByHandleEx(
                handle(file),
                FileIdInfo,
                (&mut identity as *mut FILE_ID_INFO).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        } == 0
        {
            return Err("Windows file identity inspection failed.");
        }
        if identity.VolumeSerialNumber == 0
            || identity.FileId.Identifier.iter().all(|byte| *byte == 0)
        {
            return Err("Windows filesystem identity is not stable enough for safe replacement.");
        }
        let mut fingerprint = blake3::Hasher::new();
        fingerprint.update(security.as_bytes());
        fingerprint.update(&identity.VolumeSerialNumber.to_le_bytes());
        fingerprint.update(&identity.FileId.Identifier);
        fingerprint.update(&[readonly as u8]);
        Ok(AccessMetadata {
            permissions: FilePermissions::Windows { readonly },
            guard: fingerprint.finalize().to_hex().to_string(),
        })
    }
    pub fn inspect_file(file: &File) -> Result<AccessMetadata> {
        inspect(file, false)
    }
    pub fn inspect_directory(file: &File) -> Result<String> {
        inspect(file, true).map(|m| m.guard)
    }
    pub fn apply_permissions(file: &File, permissions: &FilePermissions) -> Result<()> {
        let FilePermissions::Windows { readonly } = permissions else {
            return Err("Permission metadata belongs to another operating system.");
        };
        inspect(file, false)?;
        let mut current = file
            .metadata()
            .map_err(|_| "Cannot inspect Windows permissions.")?
            .permissions();
        current.set_readonly(*readonly);
        file.set_permissions(current)
            .map_err(|_| "Cannot update the Windows read-only flag.")?;
        if inspect_file(file)?.permissions != *permissions {
            return Err("Applied Windows permissions did not verify.");
        }
        Ok(())
    }
    pub fn make_private(file: &File) -> Result<()> {
        inspect(file, false).map(|_| ())
    }
    pub fn make_directory_private(file: &File) -> Result<()> {
        inspect(file, true).map(|_| ())
    }

    /// Fixture provisioning only: no production path changes an existing ACL.
    pub fn make_disposable_test_directory_private(path: &Path) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| "Cannot inspect a generated Windows fixture directory.")?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || std::fs::read_dir(path)
                .map_err(|_| "Cannot inspect a generated Windows fixture directory.")?
                .next()
                .is_some()
        {
            return Err("Private fixture provisioning requires a new empty non-symlink directory.");
        }
        unsafe {
            let Identity {
                user,
                creation_owner,
                primary_group,
            } = identity()?;
            let mut sid_string = ptr::null_mut();
            if ConvertSidToStringSidW(user.as_ptr() as PSID, &mut sid_string) == 0 {
                return Err("Cannot format generated Windows fixture identity.");
            }
            let sid_allocation = LocalMemory(sid_string.cast());
            let mut length = 0;
            while *sid_string.add(length) != 0 {
                length += 1;
                if length > 256 {
                    return Err("Generated Windows fixture identity exceeds its budget.");
                }
            }
            let sid = String::from_utf16(slice::from_raw_parts(sid_string, length))
                .map_err(|_| "Cannot format generated Windows fixture identity.")?;
            drop(sid_allocation);
            let sddl = format!(
                "D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)S:(ML;OICI;NW;;;ME)"
            );
            let mut wide: Vec<u16> = sddl.encode_utf16().collect();
            wide.push(0);
            let mut descriptor = ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            ) == 0
            {
                return Err("Cannot build a private generated Windows fixture ACL.");
            }
            let _allocation = LocalMemory(descriptor);
            let mut present = 0;
            let mut defaulted = 0;
            let mut dacl = ptr::null_mut();
            if GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) == 0
                || present == 0
                || dacl.is_null()
            {
                return Err("Cannot build a private generated Windows fixture ACL.");
            }
            let file = std::fs::OpenOptions::new()
                .read(true)
                .access_mode(FILE_GENERIC_READ | WRITE_DAC | WRITE_OWNER)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(path)
                .map_err(|_| "Cannot open a generated Windows fixture directory.")?;
            if SetSecurityInfo(
                handle(&file),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                creation_owner.as_ptr() as PSID,
                primary_group.as_ptr() as PSID,
                dacl,
                ptr::null(),
            ) != 0
            {
                return Err("Cannot protect a generated Windows fixture directory.");
            }
            let mut sacl_present = 0;
            let mut sacl_defaulted = 0;
            let mut sacl = ptr::null_mut();
            if GetSecurityDescriptorSacl(
                descriptor,
                &mut sacl_present,
                &mut sacl,
                &mut sacl_defaulted,
            ) == 0
                || sacl_present == 0
                || sacl.is_null()
            {
                return Err("Cannot build generated Windows fixture integrity policy.");
            }
            if SetSecurityInfo(
                handle(&file),
                SE_FILE_OBJECT,
                LABEL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
                sacl,
            ) != 0
            {
                return Err("Cannot set generated Windows fixture integrity policy.");
            }
            inspect_directory(&file)?;
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn elevated_creation_owner_admits_new_files_and_rejects_user_owned_sources() {
            let identity = identity().unwrap();
            let temp = tempfile::tempdir().unwrap();
            make_disposable_test_directory_private(temp.path()).unwrap();
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_OWNER)
                .open(temp.path().join("generated-owner-fixture"))
                .unwrap();
            // Default-created children must satisfy the same ownership policy
            // as source/destination files; no owner transfer is part of sync.
            inspect_file(&file).unwrap();
            if identity.creation_owner != identity.user {
                // Taking ownership as the current token user needs no restored
                // privilege; this touches only the generated fixture inode.
                let result = unsafe {
                    SetSecurityInfo(
                        handle(&file),
                        SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION,
                        identity.user.as_ptr() as PSID,
                        ptr::null_mut(),
                        ptr::null(),
                        ptr::null(),
                    )
                };
                assert_eq!(result, 0);
                let error = inspect_file(&file).unwrap_err();
                assert!(error.contains("creation defaults"), "{error}");
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use super::*;
    pub fn inspect_file(_: &File) -> Result<AccessMetadata> {
        Err("Permission preservation is unsupported on this operating system.")
    }
    pub fn inspect_directory(_: &File) -> Result<String> {
        Err("Permission preservation is unsupported on this operating system.")
    }
    pub fn apply_permissions(_: &File, _: &FilePermissions) -> Result<()> {
        Err("Permission preservation is unsupported on this operating system.")
    }
    pub fn make_private(_: &File) -> Result<()> {
        Err("Permission preservation is unsupported on this operating system.")
    }
    pub fn make_directory_private(_: &File) -> Result<()> {
        Err("Permission preservation is unsupported on this operating system.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn widening_requires_added_rights_not_narrowing_or_delete() {
        let p = |mode| FilePermissions::Unix { mode };
        assert!(permission_widening(None, Some(&p(0o644))));
        assert!(!permission_widening(None, Some(&p(0o600))));
        assert!(permission_widening(Some(&p(0o600)), Some(&p(0o644))));
        assert!(permission_widening(Some(&p(0o644)), Some(&p(0o755))));
        assert!(!permission_widening(Some(&p(0o755)), Some(&p(0o644))));
        assert!(!permission_widening(Some(&p(0o755)), None));
        assert!(permission_widening(
            Some(&FilePermissions::Windows { readonly: true }),
            Some(&FilePermissions::Windows { readonly: false })
        ));
    }
    #[cfg(unix)]
    #[test]
    fn unix_modes_stable_guards_and_unsupported_metadata() {
        use std::os::unix::fs::PermissionsExt;
        use xattr::FileExt;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("file");
        std::fs::write(&path, b"generated mode fixture").unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        make_private(&file).unwrap();
        assert_eq!(
            inspect_file(&file).unwrap().permissions,
            FilePermissions::Unix { mode: 0o600 }
        );
        apply_permissions(&file, &FilePermissions::Unix { mode: 0o755 }).unwrap();
        let before = inspect_file(&file).unwrap();
        let moved = temp.path().join("moved");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::hard_link(&moved, temp.path().join("linked")).unwrap();
        assert_eq!(inspect_file(&file).unwrap(), before);
        let other = temp.path().join("different-inode");
        std::fs::write(&other, b"generated mode fixture").unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_ne!(
            inspect_file(&File::open(other).unwrap()).unwrap().guard,
            before.guard
        );
        file.set_permissions(std::fs::Permissions::from_mode(0o4755))
            .unwrap();
        assert!(inspect_file(&file).is_err());
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        file.set_xattr("user.devdrop-generated", b"fixture")
            .unwrap();
        assert!(inspect_file(&file).is_err());
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_plain_files_and_directories_are_admitted_but_native_acls_are_blocked() {
        let temp = tempfile::tempdir().unwrap();
        let directory_path = temp.path().join("plain-directory");
        std::fs::create_dir(&directory_path).unwrap();
        let directory = File::open(&directory_path).unwrap();
        inspect_directory(&directory).unwrap();
        let path = temp.path().join("acl-fixture");
        std::fs::write(&path, b"generated native ACL fixture").unwrap();
        let file = File::open(&path).unwrap();
        inspect_file(&file).unwrap();
        let result = std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(inspect_file(&file).is_err());
        let result = std::process::Command::new("chmod")
            .args(["+a", "everyone allow list"])
            .arg(&directory_path)
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(inspect_directory(&directory).is_err());
    }
    #[cfg(windows)]
    #[test]
    fn windows_private_fixture_readonly_guard_and_ads() {
        let temp = tempfile::tempdir().unwrap();
        make_disposable_test_directory_private(temp.path()).unwrap();
        let path = temp.path().join("file");
        std::fs::write(&path, b"generated Windows fixture").unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let before = inspect_file(&file).unwrap();
        apply_permissions(&file, &FilePermissions::Windows { readonly: true }).unwrap();
        let readonly = inspect_file(&file).unwrap();
        assert_ne!(before.guard, readonly.guard);
        assert_eq!(
            readonly.permissions,
            FilePermissions::Windows { readonly: true }
        );
        apply_permissions(&file, &FilePermissions::Windows { readonly: false }).unwrap();
        std::fs::write(path.with_file_name("file:generated-stream"), b"fixture").unwrap();
        assert!(inspect_file(&file).is_err());
    }
}
