use crate::SLICE_LABEL;
use serde::{Deserialize, Serialize};

/// Readiness report for a project/workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessReport {
    /// Slice label that produced the report.
    pub slice: String,
    /// Short summary.
    pub summary: String,
    /// Whether real sync is complete; false in this core slice.
    pub sync_complete: bool,
    /// Overall readiness boolean.
    pub ready: bool,
    /// Blocking findings.
    pub blockers: Vec<ReadinessFinding>,
    /// Warning findings.
    pub warnings: Vec<ReadinessFinding>,
    /// Compatibility finding list.
    pub findings: Vec<ReadinessFinding>,
    /// Placeholder Git state.
    pub git_state: GitState,
    /// Env readiness state.
    pub env_state: EnvReadinessState,
    /// Runtime readiness state.
    pub runtime_state: RuntimeReadinessState,
    /// Sync readiness state.
    pub sync_state: SyncReadinessState,
    /// Agent safety state.
    pub agent_safety_state: AgentSafetyState,
}

impl ReadinessReport {
    /// Foundation report that makes no real sync claim.
    pub fn foundation_stub() -> Self {
        let sync_finding = ReadinessFinding {
            area: "sync".to_string(),
            message: "No file mutation or sync apply is available in this core slice.".to_string(),
            severity: FindingSeverity::Info,
        };
        let secret_finding = ReadinessFinding {
            area: "secrets".to_string(),
            message: "Env values are represented only by key names and fingerprints.".to_string(),
            severity: FindingSeverity::Info,
        };

        Self {
            slice: SLICE_LABEL.to_string(),
            summary: "Core engine contracts are present; real sync is not implemented.".to_string(),
            sync_complete: false,
            ready: false,
            blockers: vec![ReadinessFinding {
                area: "scanner".to_string(),
                message: "Fixture-backed readiness scanner has not run.".to_string(),
                severity: FindingSeverity::Blocked,
            }],
            warnings: vec![sync_finding.clone(), secret_finding.clone()],
            findings: vec![sync_finding, secret_finding],
            git_state: GitState {
                summary: "Git observation placeholder only.".to_string(),
                branch: None,
                dirty: None,
                ahead_behind: None,
            },
            env_state: EnvReadinessState {
                required_keys: Vec::new(),
                available_keys: Vec::new(),
                missing_keys: Vec::new(),
                raw_values_captured: false,
            },
            runtime_state: RuntimeReadinessState {
                summary: "Runtime checks are not implemented in this slice.".to_string(),
                missing_requirements: Vec::new(),
            },
            sync_state: SyncReadinessState {
                summary: "Sync planning is dry-run only.".to_string(),
                queue_blocked: true,
                conflicts_present: false,
                tombstones_present: false,
            },
            agent_safety_state: AgentSafetyState {
                summary: "Agent handoff must remain redacted.".to_string(),
                safe_to_start_agent: false,
                blocked_reasons: vec!["Readiness scanner is not implemented.".to_string()],
            },
        }
    }
}

/// Readiness finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessFinding {
    /// Finding area.
    pub area: String,
    /// Finding message.
    pub message: String,
    /// Finding severity.
    pub severity: FindingSeverity,
}

/// Finding severity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingSeverity {
    /// Informational.
    Info,
    /// Needs attention but is not necessarily blocking.
    NeedsAttention,
    /// Blocks safe work.
    Blocked,
}

/// Git readiness placeholder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitState {
    /// Human-readable summary.
    pub summary: String,
    /// Current branch if observed.
    pub branch: Option<String>,
    /// Dirty state if observed.
    pub dirty: Option<bool>,
    /// Ahead/behind summary if observed.
    pub ahead_behind: Option<String>,
}

/// Environment readiness without secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvReadinessState {
    /// Required env key names.
    pub required_keys: Vec<String>,
    /// Available env key names.
    pub available_keys: Vec<String>,
    /// Missing env key names.
    pub missing_keys: Vec<String>,
    /// Must remain false unless future reviewed code permits value capture.
    pub raw_values_captured: bool,
}

/// Runtime readiness state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeReadinessState {
    /// Human-readable summary.
    pub summary: String,
    /// Missing runtime requirements.
    pub missing_requirements: Vec<String>,
}

/// Sync readiness state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReadinessState {
    /// Human-readable summary.
    pub summary: String,
    /// Whether queue/apply is blocked.
    pub queue_blocked: bool,
    /// Whether conflicts are present.
    pub conflicts_present: bool,
    /// Whether tombstones are present.
    pub tombstones_present: bool,
}

/// Agent safety state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSafetyState {
    /// Human-readable summary.
    pub summary: String,
    /// Whether safe agent work may start.
    pub safe_to_start_agent: bool,
    /// Reasons agent work is blocked.
    pub blocked_reasons: Vec<String>,
}
