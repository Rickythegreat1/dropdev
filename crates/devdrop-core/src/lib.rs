//! Core DevDrop contracts for local-first workspace state.
//!
//! This crate contains the original model contracts and sandbox hydration plus
//! `local`, the durable approval-gated filesystem runtime. It never mutates Git
//! state or exposes a remotely callable write service.

pub mod conflict;
pub mod content_hash;
pub mod env_profile;
pub mod error;
pub mod event_log;
pub mod hydration;
pub mod ignore_policy;
pub mod local;
pub mod machine;
pub mod manifest;
pub mod object_id;
pub mod project;
pub mod readiness;
pub mod sync_plan;
pub mod tombstone;

pub use conflict::{
    Conflict, ConflictReason, ConflictResolutionStatus as ConflictResolutionState,
    ConflictResolutionStatus, ConflictVersion,
};
pub use content_hash::{ContentHash, HashAlgorithm};
pub use env_profile::{EnvFileSummary, EnvProfile, EnvVariableSummary, ValueCaptureMode};
pub use error::{CoreError, CoreResult};
pub use event_log::{Actor, ActorKind, Event, EventKind};
pub use hydration::{
    apply_hydration, apply_hydration_preview, apply_hydration_preview_with_options,
    exact_stub_marker, fixture_object_bytes, hydration_counts, parse_stub_marker,
    preview_hydration, HydrationApplyOptions, HydrationApplyReceipt, HydrationBlocker,
    HydrationCounts, HydrationOperation, HydrationOperationKind, HydrationPreview,
    HydrationRegistryEntry, HydrationSandboxMetadata, HydrationSource, HydrationState,
    HydrationStubMarker, FIXTURE_OBJECT_ALPHA_ID, FIXTURE_OBJECT_ALPHA_KEY, HYDRATION_SANDBOX_FILE,
    HYDRATION_SANDBOX_SCHEMA, HYDRATION_SANDBOX_VERSION, STUB_MARKER_PREFIX,
};
pub use ignore_policy::{IgnorePolicy, PathClassification};
pub use machine::{Machine, ProjectPathMapping};
pub use manifest::{HydrationRules, ProjectManifest, RuntimeRequirement, SyncRules};
pub use object_id::{
    CasObject, DirtyState, ObjectId, ObjectVisibility, PlatformRule, WorkspaceObject,
    WorkspaceObjectKind,
};
pub use project::{Project, ProjectRegistry};
pub use readiness::{
    AgentSafetyState, EnvReadinessState, FindingSeverity, GitState, ReadinessFinding,
    ReadinessReport, RuntimeReadinessState, SyncReadinessState,
};
pub use sync_plan::{
    ApprovalFlag, QueueAction, QueueItem, SafetyMode, SyncActionKind, SyncActionPreview, SyncPlan,
    SyncPlanOperation, SyncPlanOperationKind, SyncPlanReceipt, SyncPreview,
};
pub use tombstone::Tombstone;

use serde::{Deserialize, Serialize};

/// Current visible slice label used by CLI and MCP placeholder output.
pub const SLICE_LABEL: &str = "Slice 0/1 foundation";

/// Planner output intended for a future agent workspace recommendation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannerOutput {
    /// Project identifier the plan is scoped to.
    pub project_id: String,
    /// Human-readable next safe step.
    pub recommended_next_step: String,
    /// Whether destructive actions are blocked.
    pub destructive_actions_blocked: bool,
    /// Queue preview items; never applied by this model.
    pub queue_preview: Vec<QueueItem>,
}

/// Redacted handoff contract for Codex or another coding agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexHandoff {
    /// Project summary.
    pub project: Project,
    /// Optional machine summary.
    pub machine: Option<Machine>,
    /// Optional env profile with names and fingerprints only.
    pub env_profile: Option<EnvProfile>,
    /// Readiness report.
    pub readiness: ReadinessReport,
    /// Planner output.
    pub planner: PlannerOutput,
    /// Explicit redaction notice for consumers.
    pub redaction_notice: String,
}

impl CodexHandoff {
    /// Builds a deterministic redacted sample handoff for tests and MCP stubs.
    pub fn sample_redacted(project: Project, env_profile: EnvProfile) -> Self {
        let project_id = project.id.clone();
        Self {
            project,
            machine: None,
            env_profile: Some(env_profile),
            readiness: ReadinessReport::foundation_stub(),
            planner: PlannerOutput {
                project_id,
                recommended_next_step: "Run the readiness scanner before any sync behavior."
                    .to_string(),
                destructive_actions_blocked: true,
                queue_preview: vec![QueueItem {
                    id: "queue:preview-only".to_string(),
                    project_id: "project:sample".to_string(),
                    action: QueueAction::HandoffPreview,
                    mode: SafetyMode::DryRunOnly,
                    summary: "Handoff is a redacted preview only.".to_string(),
                }],
            },
            redaction_notice:
                "Raw env values and file contents are intentionally absent from this handoff."
                    .to_string(),
        }
    }
}

/// Returns standard dry-run wording for dangerous command placeholders.
pub fn dry_run_message(action: &str) -> String {
    format!(
        "{action} is dry-run/stubbed in Slice Core Engine. No user files, Git state, CAS objects, SQLite metadata, hydration state, or workspace contents were mutated."
    )
}

/// Returns a safe readiness report string for the CLI doctor command.
pub fn doctor_report_text() -> String {
    let report = ReadinessReport::foundation_stub();
    format!(
        "DevDrop {slice}\nStatus: {summary}\nReal sync complete: {sync_complete}\nSafety: destructive operations are unavailable or dry-run only.\nSecret handling: env values are never printed, persisted, serialized, or displayed.\nNext: implement fixture-backed readiness scanning before sync apply.\n",
        slice = report.slice,
        summary = report.summary,
        sync_complete = report.sync_complete
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;

    fn canary_value() -> String {
        ["redact", "this", "value"].join("-")
    }

    fn valid_manifest_json() -> &'static str {
        r#"{
          "project_name": "ready-project",
          "root_path": "fixtures/repos/ready-project",
          "base_branch": "main",
          "required_env_keys": ["DEV_DROP_TOKEN"],
          "runtime_requirements": [
            { "name": "node", "version_requirement": ">=20" },
            { "name": "rust", "version_requirement": ">=1.78" }
          ],
          "ignored_path_policy": {
            "generated_paths": ["node_modules", ".next", "dist", "target", "*.log", "logs"],
            "secret_paths": [".env", ".env.*"]
          },
          "sync_rules": {
            "require_clean_git": true,
            "allow_destructive_apply": false,
            "sync_ignored_paths": false
          },
          "hydration_rules": {
            "lazy_by_default": true,
            "hydrate_ignored_paths": false
          }
        }"#
    }

    #[test]
    fn manifest_parses_valid_fixtures() {
        let manifest = ProjectManifest::from_json(valid_manifest_json()).expect("valid manifest");
        assert_eq!(manifest.project_name, "ready-project");
        assert_eq!(manifest.base_branch, "main");
        assert_eq!(manifest.root_path.as_str(), "fixtures/repos/ready-project");
        assert_eq!(manifest.required_env_keys, vec!["DEV_DROP_TOKEN"]);
        assert!(!manifest.sync_rules.allow_destructive_apply);
        assert!(manifest.hydration_rules.lazy_by_default);
    }

    #[test]
    fn invalid_manifest_returns_typed_error() {
        let err = ProjectManifest::from_json(
            r#"{
              "project_name": "",
              "root_path": "fixtures/repos/ready-project",
              "base_branch": "main",
              "required_env_keys": [],
              "runtime_requirements": [],
              "ignored_path_policy": {
                "generated_paths": ["node_modules"],
                "secret_paths": [".env"]
              },
              "sync_rules": {
                "require_clean_git": true,
                "allow_destructive_apply": false,
                "sync_ignored_paths": false
              },
              "hydration_rules": {
                "lazy_by_default": true,
                "hydrate_ignored_paths": false
              }
            }"#,
        )
        .expect_err("empty project name should fail validation");

        assert!(matches!(
            err,
            CoreError::ManifestValidation {
                field: "project_name",
                ..
            }
        ));
    }

    #[test]
    fn env_values_are_not_printed_in_doctor() {
        let report = doctor_report_text();
        assert!(!report.contains(&canary_value()));
        assert!(report.contains("env values are never printed"));
    }

    #[test]
    fn env_values_are_not_serialized() {
        let value = canary_value();
        let profile = EnvProfile::redacted_from_pairs(
            "env:local",
            "project:sample",
            ".env",
            &[("DEV_DROP_TOKEN", value.as_str())],
        );
        let json = serde_json::to_string(&profile).expect("profile serializes");
        assert!(json.contains("DEV_DROP_TOKEN"));
        assert!(!json.contains(&value));
        assert!(json.contains("value_fingerprint"));
    }

    #[test]
    fn ignored_paths_are_classified_correctly() {
        let policy = IgnorePolicy::default();
        for path in [
            "node_modules/react/index.js",
            ".next/server/app.js",
            "dist/bundle.js",
            "target/debug/devdrop.exe",
            "logs/devdrop.log",
            "workspace/build.log",
            r"C:\Users\Home\Documents\GitHub\dropdev\node_modules\pkg\index.js",
        ] {
            assert_eq!(
                policy.classify(path),
                PathClassification::Generated,
                "{path} should be generated"
            );
            assert!(policy.excludes(path), "{path} should be excluded");
        }

        for path in [".env", ".env.local", r"C:\repo\.env.production"] {
            assert_eq!(
                policy.classify(path),
                PathClassification::Secret,
                "{path} should be secret"
            );
        }

        assert_eq!(policy.classify("src/main.rs"), PathClassification::Tracked);
    }

    #[test]
    fn object_ids_are_stable() {
        let hash = ContentHash::hash_bytes(b"fixture");
        let path = Utf8PathBuf::from("src/lib.rs");
        let one = ObjectId::stable(
            "project:sample",
            &path,
            WorkspaceObjectKind::File,
            Some(&hash),
        );
        let two = ObjectId::stable(
            "project:sample",
            &path,
            WorkspaceObjectKind::File,
            Some(&hash),
        );
        let changed = ObjectId::stable(
            "project:sample",
            &Utf8PathBuf::from("src/main.rs"),
            WorkspaceObjectKind::File,
            Some(&hash),
        );

        assert_eq!(one, two);
        assert_ne!(one, changed);
        assert_eq!(one.algorithm, HashAlgorithm::Blake3);
    }

    #[test]
    fn tombstone_preserves_deletion_metadata() {
        let object_id = ObjectId::stable(
            "project:sample",
            &Utf8PathBuf::from("src/lib.rs"),
            WorkspaceObjectKind::File,
            Some(&ContentHash::hash_bytes(b"fixture")),
        );
        let tombstone = Tombstone {
            path: Utf8PathBuf::from("src/lib.rs"),
            deleted_object_id: object_id.clone(),
            deletion_event_id: "event:delete-1".to_string(),
            actor: Actor::user("alice"),
            timestamp: "2026-06-26T00:00:00Z".to_string(),
            reversible: true,
        };

        assert_eq!(tombstone.deleted_object_id, object_id);
        assert_eq!(tombstone.deletion_event_id, "event:delete-1");
        assert!(tombstone.reversible);
    }

    #[test]
    fn conflict_preserves_both_versions() {
        let local_hash = ContentHash::hash_bytes(b"local");
        let remote_hash = ContentHash::hash_bytes(b"remote");
        let conflict = Conflict {
            conflict_id: "conflict:1".to_string(),
            path: Utf8PathBuf::from("src/lib.rs"),
            local_version: ConflictVersion::from_hash("local", local_hash.clone()),
            remote_mock_version: ConflictVersion::from_hash("remote", remote_hash.clone()),
            detected_reason: ConflictReason::BothModified,
            resolution_status: ConflictResolutionStatus::NeedsReview,
        };

        assert_eq!(conflict.local_version.content_hash, local_hash);
        assert_eq!(conflict.remote_mock_version.content_hash, remote_hash);
        assert_ne!(
            conflict.local_version.content_hash,
            conflict.remote_mock_version.content_hash
        );
    }

    #[test]
    fn sync_plan_refuses_destructive_approval_without_flag() {
        let plan = SyncPlan::fixture_with_delete();
        let err = plan
            .approval_preview(ApprovalFlag::not_approved())
            .expect_err("destructive plan should need approval");

        assert!(matches!(err, CoreError::ApprovalRequired { .. }));
    }

    #[test]
    fn sync_plan_approval_preview_is_non_mutating_even_when_approved() {
        let plan = SyncPlan::fixture_with_delete();
        let receipt = plan
            .approval_preview(ApprovalFlag::approved_by("alice"))
            .expect("approval produces a receipt model");

        assert!(receipt.approved);
        assert_eq!(receipt.destructive_operations_count, 1);
        assert!(!receipt.mutated_files);
        assert!(!receipt.mutated_git);
        assert!(!receipt.wrote_object_store);
        assert!(!receipt.wrote_sqlite);
        assert!(!receipt.changed_hydration_state);
        assert!(receipt.summary.contains("No apply was performed"));
    }

    #[test]
    fn readiness_report_serializes_to_json() {
        let report = ReadinessReport::foundation_stub();
        let json = serde_json::to_string_pretty(&report).expect("readiness serializes");
        assert!(json.contains("\"ready\": false"));
        assert!(json.contains("agent_safety_state"));
        assert!(json.contains("sync_state"));
    }

    #[test]
    fn dangerous_operations_are_dry_run_only() {
        let message = dry_run_message("snapshot");
        assert!(message.contains("dry-run/stubbed"));
        assert!(message.contains("No user files"));
    }

    #[test]
    fn handoff_json_redacts_env_values() {
        let value = canary_value();
        let project = Project::fixture("sample", r"C:\Users\Home\Documents\GitHub\dropdev");
        let profile = EnvProfile::redacted_from_pairs(
            "env:local",
            &project.id,
            ".env",
            &[("API_KEY", &value)],
        );
        let handoff = CodexHandoff::sample_redacted(project, profile);
        let json = serde_json::to_string_pretty(&handoff).expect("handoff serializes");
        assert!(json.contains("API_KEY"));
        assert!(!json.contains(&value));
        assert!(json.contains("Raw env values"));
    }

    #[test]
    fn sync_preview_model_serializes_without_mutation_claims() {
        let preview = SyncPreview::foundation_stub("project:sample");
        let json = serde_json::to_string_pretty(&preview).expect("sync preview serializes");
        assert!(json.contains("DryRunOnly"));
        assert!(json.contains("watcher_events_are_hints"));
        assert!(preview.requires_reconciliation_scan);
        for action in preview.actions {
            assert!(!action.mutates_files);
            assert!(!action.mutates_git);
            assert!(!action.writes_metadata);
        }
    }

    #[test]
    fn cli_placeholder_text_does_not_claim_sync_completion() {
        let text = doctor_report_text();
        assert!(text.contains("Real sync complete: false"));
        assert!(!text.contains("sync is complete"));
        assert!(!text.contains("successfully synced"));
    }

    #[test]
    fn windows_paths_serialize_safely() {
        let project = Project::fixture("windows", r"C:\Users\Home\Documents\GitHub\dropdev");
        let json = serde_json::to_string(&project).expect("project serializes");
        assert!(json.contains("C:"));
        assert!(json.contains("dropdev"));
    }

    #[test]
    fn blake3_is_default_hash_algorithm() {
        let hash = ContentHash::hash_bytes(b"devdrop");
        assert_eq!(hash.algorithm, HashAlgorithm::Blake3);
        assert_eq!(HashAlgorithm::default(), HashAlgorithm::Blake3);
        let future = HashAlgorithm::Sha256;
        assert_eq!(future, HashAlgorithm::Sha256);
    }
}
