use crate::conflict::Conflict;
use crate::error::{CoreError, CoreResult};
use crate::hydration::HydrationOperation;
use crate::tombstone::Tombstone;
use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};

/// Safety mode for preview and stub behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyMode {
    /// Operation is dry-run only.
    DryRunOnly,
    /// Operation is unavailable in this slice.
    StubbedUnavailable,
}

/// Sync plan model. It does not apply operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncPlan {
    /// Plan identifier.
    pub plan_id: String,
    /// Project identifier.
    pub project_id: String,
    /// Operations in the plan.
    pub operations: Vec<SyncPlanOperation>,
    /// Human-readable dry-run summary.
    pub dry_run_summary: String,
    /// Whether destructive operations are present.
    pub destructive_operations_flagged: bool,
    /// Conflicts included in the plan.
    pub conflicts: Vec<Conflict>,
    /// Tombstones included in the plan.
    pub tombstones: Vec<Tombstone>,
    /// Hydration operations included in the plan.
    pub hydration_ops: Vec<HydrationOperation>,
}

impl SyncPlan {
    /// Returns an approval/refusal receipt model without applying anything.
    pub fn approval_preview(&self, approval: ApprovalFlag) -> CoreResult<SyncPlanReceipt> {
        if self.destructive_operations_flagged && !approval.approved {
            return Err(CoreError::ApprovalRequired {
                plan_id: self.plan_id.clone(),
            });
        }

        Ok(SyncPlanReceipt {
            plan_id: self.plan_id.clone(),
            approved: approval.approved,
            approver: approval.approver,
            operations_count: self.operations.len(),
            destructive_operations_count: self
                .operations
                .iter()
                .filter(|operation| operation.destructive)
                .count(),
            mutated_files: false,
            mutated_git: false,
            wrote_object_store: false,
            wrote_sqlite: false,
            changed_hydration_state: false,
            summary: "Approval preview generated. No apply was performed and no state was mutated."
                .to_string(),
        })
    }

    /// Deterministic fixture containing one destructive delete preview.
    pub fn fixture_with_delete() -> Self {
        Self {
            plan_id: "sync-plan:delete-preview".to_string(),
            project_id: "project:sample".to_string(),
            operations: vec![SyncPlanOperation {
                operation_id: "op:delete-preview".to_string(),
                kind: SyncPlanOperationKind::DeleteFile,
                path: Some(Utf8PathBuf::from("src/lib.rs")),
                destructive: true,
                summary: "Delete preview only; no file removal is available.".to_string(),
            }],
            dry_run_summary: "One destructive operation is flagged for approval.".to_string(),
            destructive_operations_flagged: true,
            conflicts: Vec::new(),
            tombstones: Vec::new(),
            hydration_ops: Vec::new(),
        }
    }
}

/// Sync plan operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncPlanOperation {
    /// Operation identifier.
    pub operation_id: String,
    /// Operation kind.
    pub kind: SyncPlanOperationKind,
    /// Optional workspace path.
    pub path: Option<Utf8PathBuf>,
    /// Whether operation is destructive.
    pub destructive: bool,
    /// Human-readable summary.
    pub summary: String,
}

/// Sync plan operation kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncPlanOperationKind {
    /// Metadata-only operation.
    MetadataOnly,
    /// Future object write preview.
    WriteObject,
    /// Future file delete preview.
    DeleteFile,
    /// Future file move preview.
    MoveFile,
    /// Future hydration preview.
    HydrateFile,
    /// Future dehydration preview.
    DehydrateFile,
    /// Tombstone preview.
    Tombstone,
    /// Conflict review preview.
    ConflictReview,
    /// Git observation only.
    GitObservation,
}

/// Explicit approval flag for preview receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalFlag {
    /// Whether explicit approval was provided.
    pub approved: bool,
    /// Optional approver.
    pub approver: Option<String>,
}

impl ApprovalFlag {
    /// Not approved.
    pub fn not_approved() -> Self {
        Self {
            approved: false,
            approver: None,
        }
    }

    /// Approved by a named actor.
    pub fn approved_by(approver: impl Into<String>) -> Self {
        Self {
            approved: true,
            approver: Some(approver.into()),
        }
    }
}

/// Non-mutating sync plan approval receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncPlanReceipt {
    /// Plan identifier.
    pub plan_id: String,
    /// Whether approval was present.
    pub approved: bool,
    /// Optional approver.
    pub approver: Option<String>,
    /// Number of operations.
    pub operations_count: usize,
    /// Number of destructive operations.
    pub destructive_operations_count: usize,
    /// Always false in this slice.
    pub mutated_files: bool,
    /// Always false in this slice.
    pub mutated_git: bool,
    /// Always false in this slice.
    pub wrote_object_store: bool,
    /// Always false in this slice.
    pub wrote_sqlite: bool,
    /// Always false in this slice.
    pub changed_hydration_state: bool,
    /// Receipt summary.
    pub summary: String,
}

/// Queue preview item for CLI and handoff compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueItem {
    /// Queue item identifier.
    pub id: String,
    /// Project identifier.
    pub project_id: String,
    /// Queue action.
    pub action: QueueAction,
    /// Safety mode.
    pub mode: SafetyMode,
    /// Summary.
    pub summary: String,
}

/// Queue preview action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueAction {
    /// Snapshot preview.
    SnapshotPreview,
    /// Hydration simulation.
    HydrationSimulation,
    /// Handoff preview.
    HandoffPreview,
    /// Tombstone preview.
    TombstonePreview,
    /// Conflict review.
    ConflictReview,
}

/// Legacy sync preview retained for MCP compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncPreview {
    /// Preview identifier.
    pub id: String,
    /// Project identifier.
    pub project_id: String,
    /// Safety mode.
    pub mode: SafetyMode,
    /// Action previews.
    pub actions: Vec<SyncActionPreview>,
    /// Whether reconciliation is required.
    pub requires_reconciliation_scan: bool,
    /// Whether watcher events are only hints.
    pub watcher_events_are_hints: bool,
    /// Whether a future SQLite WAL checkpoint is required.
    pub sqlite_wal_checkpoint_required_before_apply: bool,
}

impl SyncPreview {
    /// Foundation preview for read-only MCP/CLI surfaces.
    pub fn foundation_stub(project_id: impl Into<String>) -> Self {
        let project_id = project_id.into();
        Self {
            id: format!("sync-preview:{project_id}"),
            project_id,
            mode: SafetyMode::DryRunOnly,
            actions: vec![
                SyncActionPreview::non_mutating(
                    SyncActionKind::GitObservation,
                    "Observe Git freshness only; no Git mutation is available.",
                ),
                SyncActionPreview::non_mutating(
                    SyncActionKind::CasWritePreview,
                    "Preview CAS eligibility only; no objects are written.",
                ),
                SyncActionPreview::non_mutating(
                    SyncActionKind::QueuePreview,
                    "Preview queue shape only; no queue item is applied.",
                ),
            ],
            requires_reconciliation_scan: true,
            watcher_events_are_hints: true,
            sqlite_wal_checkpoint_required_before_apply: true,
        }
    }
}

/// Legacy sync action preview retained for MCP compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncActionPreview {
    /// Action kind.
    pub kind: SyncActionKind,
    /// Summary.
    pub summary: String,
    /// Whether this action mutates files.
    pub mutates_files: bool,
    /// Whether this action mutates Git.
    pub mutates_git: bool,
    /// Whether this action writes metadata.
    pub writes_metadata: bool,
}

impl SyncActionPreview {
    /// Creates a non-mutating action preview.
    pub fn non_mutating(kind: SyncActionKind, summary: impl Into<String>) -> Self {
        Self {
            kind,
            summary: summary.into(),
            mutates_files: false,
            mutates_git: false,
            writes_metadata: false,
        }
    }
}

/// Legacy action kinds retained for MCP compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncActionKind {
    /// Registry observation.
    RegistryObservation,
    /// Git observation.
    GitObservation,
    /// CAS write preview.
    CasWritePreview,
    /// Hydration simulation.
    HydrationSimulation,
    /// Queue preview.
    QueuePreview,
    /// Tombstone preview.
    TombstonePreview,
    /// Conflict review.
    ConflictReview,
}
