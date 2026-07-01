use crate::content_hash::{ContentHash, HashAlgorithm};
use crate::hydration::HydrationState;
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};

/// Stable workspace object identifier derived from project, path, kind, and hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectId {
    /// Hash algorithm used for the identifier.
    pub algorithm: HashAlgorithm,
    /// Hex digest.
    pub digest: String,
}

impl ObjectId {
    /// Produces a stable BLAKE3 object ID from model inputs.
    pub fn stable(
        project_id: &str,
        path: &Utf8Path,
        kind: WorkspaceObjectKind,
        content_hash: Option<&ContentHash>,
    ) -> Self {
        let normalized_path = path.as_str().replace('\\', "/");
        let hash_part = content_hash
            .map(|hash| hash.digest.as_str())
            .unwrap_or("<no-content>");
        let payload =
            format!("devdrop-object-v1\0{project_id}\0{normalized_path}\0{kind:?}\0{hash_part}");
        Self {
            algorithm: HashAlgorithm::Blake3,
            digest: blake3::hash(payload.as_bytes()).to_hex().to_string(),
        }
    }
}

/// Workspace object kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkspaceObjectKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Hydration placeholder.
    HydrationStub,
}

/// Visibility of a workspace object under DevDrop policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectVisibility {
    /// Object is tracked.
    Tracked,
    /// Object is ignored/generated.
    Ignored,
    /// Object is secret metadata only.
    SecretMetadataOnly,
}

/// Platform applicability rule for a workspace object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlatformRule {
    /// Applies on all platforms.
    Any,
    /// Applies to Windows only.
    WindowsOnly,
    /// Applies to Unix-like platforms only.
    UnixOnly,
    /// Requires case-sensitive path semantics.
    CaseSensitiveOnly,
}

/// Dirty state observed for a workspace object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirtyState {
    /// Object matches known state.
    Clean,
    /// Object differs from known state.
    Dirty,
    /// Object is untracked.
    Untracked,
    /// Dirty state has not been observed.
    Unknown,
}

/// Modeled workspace object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceObject {
    /// Stable object identifier.
    pub object_id: ObjectId,
    /// Workspace-relative path.
    pub path: Utf8PathBuf,
    /// Object kind.
    pub kind: WorkspaceObjectKind,
    /// Content hash when content is eligible and known.
    pub content_hash: Option<ContentHash>,
    /// Byte size when known.
    pub size: u64,
    /// Hydration state.
    pub hydration_state: HydrationState,
    /// Visibility under ignore/secret policy.
    pub visibility: ObjectVisibility,
    /// Platform rule.
    pub platform_rule: PlatformRule,
    /// Dirty state.
    pub dirty_state: DirtyState,
}

/// Content-addressed store object model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasObject {
    /// Content hash.
    pub hash: ContentHash,
    /// Byte length.
    pub byte_len: u64,
    /// Non-authoritative source path hint.
    pub source_path_hint: Option<String>,
    /// Hydration state associated with the object.
    pub hydration_state: HydrationState,
}
