use crate::content_hash::ContentHash;
use crate::event_log::Actor;
use crate::object_id::ObjectId;
use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};

/// Conflict object preserving both sides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    /// Conflict identifier.
    pub conflict_id: String,
    /// Conflicted path.
    pub path: Utf8PathBuf,
    /// Local version.
    pub local_version: ConflictVersion,
    /// Remote/mock version.
    pub remote_mock_version: ConflictVersion,
    /// Detection reason.
    pub detected_reason: ConflictReason,
    /// Resolution status.
    pub resolution_status: ConflictResolutionStatus,
}

/// Version captured for one side of a conflict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictVersion {
    /// Version label.
    pub label: String,
    /// Object identifier when known.
    pub object_id: Option<ObjectId>,
    /// Content hash when known.
    pub content_hash: ContentHash,
    /// Actor associated with the version.
    pub actor: Option<Actor>,
    /// Timestamp as deterministic serialized data.
    pub timestamp: Option<String>,
}

impl ConflictVersion {
    /// Builds a conflict version from a content hash.
    pub fn from_hash(label: impl Into<String>, content_hash: ContentHash) -> Self {
        Self {
            label: label.into(),
            object_id: None,
            content_hash,
            actor: None,
            timestamp: None,
        }
    }
}

/// Reason a conflict was detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictReason {
    /// Both local and remote/mock sides changed.
    BothModified,
    /// Local dirty state blocks overwrite.
    LocalDirty,
    /// Delete/update conflict.
    DeleteModify,
    /// Hydration state mismatch.
    HydrationMismatch,
}

/// Resolution status for a conflict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictResolutionStatus {
    /// Needs human review.
    NeedsReview,
    /// Resolution can only be previewed.
    PreviewOnly,
    /// Resolved in a future slice.
    ResolvedInFutureSlice,
    /// Resolution receipt exists.
    Resolved,
}
