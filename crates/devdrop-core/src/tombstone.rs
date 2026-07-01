use crate::event_log::Actor;
use crate::object_id::ObjectId;
use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};

/// Deletion intent metadata. A tombstone is not a delete apply operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    /// Workspace path marked for deletion semantics.
    pub path: Utf8PathBuf,
    /// Deleted object identifier.
    pub deleted_object_id: ObjectId,
    /// Event that recorded deletion intent.
    pub deletion_event_id: String,
    /// Actor that requested deletion semantics.
    pub actor: Actor,
    /// Timestamp as deterministic serialized data.
    pub timestamp: String,
    /// Whether restore is modeled as possible.
    pub reversible: bool,
}
