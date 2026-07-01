use crate::content_hash::ContentHash;
use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};

/// Event log entry for replayable workspace state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Event identifier.
    pub event_id: String,
    /// Project identifier.
    pub project_id: String,
    /// Machine identifier.
    pub machine_id: String,
    /// Event kind.
    pub event_kind: EventKind,
    /// Optional path affected by the event.
    pub path: Option<Utf8PathBuf>,
    /// Previous content hash when known.
    pub previous_hash: Option<ContentHash>,
    /// Next content hash when known.
    pub next_hash: Option<ContentHash>,
    /// Timestamp as deterministic serialized data.
    pub timestamp: String,
    /// Actor that caused or proposed the event.
    pub actor: Actor,
}

/// Event kinds modeled by the core engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    /// Readiness scan event.
    ScanObserved,
    /// Sync plan created.
    SyncPlanCreated,
    /// Sync approval preview produced.
    SyncApprovalPreviewed,
    /// Tombstone created.
    TombstoneCreated,
    /// Conflict detected.
    ConflictDetected,
    /// Hydration simulated.
    HydrationSimulated,
    /// Git state observed.
    GitObserved,
}

/// Event actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// Actor kind.
    pub kind: ActorKind,
    /// Actor identifier.
    pub id: String,
}

impl Actor {
    /// Creates a user actor.
    pub fn user(id: impl Into<String>) -> Self {
        Self {
            kind: ActorKind::User,
            id: id.into(),
        }
    }

    /// Creates a system actor.
    pub fn system(id: impl Into<String>) -> Self {
        Self {
            kind: ActorKind::System,
            id: id.into(),
        }
    }
}

/// Actor kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActorKind {
    /// Human user.
    User,
    /// DevDrop system process.
    System,
    /// Coding agent.
    Agent,
}
