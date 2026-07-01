use crate::error::{CoreError, CoreResult};
use crate::ignore_policy::IgnorePolicy;
use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};

/// Project manifest contract for deterministic core model tests.
///
/// This slice parses JSON only to keep tests deterministic. It does not decide
/// the final user-facing manifest file format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectManifest {
    /// Project display name.
    pub project_name: String,
    /// Project root path.
    pub root_path: Utf8PathBuf,
    /// Base branch expected for freshness checks.
    pub base_branch: String,
    /// Required env key names.
    pub required_env_keys: Vec<String>,
    /// Runtime requirements.
    pub runtime_requirements: Vec<RuntimeRequirement>,
    /// Ignored/generated and secret path policy.
    pub ignored_path_policy: IgnorePolicy,
    /// Sync rules.
    pub sync_rules: SyncRules,
    /// Hydration rules.
    pub hydration_rules: HydrationRules,
}

impl ProjectManifest {
    /// Parses a manifest from JSON for deterministic core tests.
    pub fn from_json(input: &str) -> CoreResult<Self> {
        let manifest: Self = serde_json::from_str(input)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validates required manifest fields.
    pub fn validate(&self) -> CoreResult<()> {
        if self.project_name.trim().is_empty() {
            return Err(CoreError::ManifestValidation {
                field: "project_name",
                message: "project name is required".to_string(),
            });
        }

        if self.root_path.as_str().trim().is_empty() {
            return Err(CoreError::ManifestValidation {
                field: "root_path",
                message: "root path is required".to_string(),
            });
        }

        if self.base_branch.trim().is_empty() {
            return Err(CoreError::ManifestValidation {
                field: "base_branch",
                message: "base branch is required".to_string(),
            });
        }

        Ok(())
    }
}

/// Runtime requirement from a project manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeRequirement {
    /// Runtime name.
    pub name: String,
    /// Version requirement string.
    pub version_requirement: String,
}

/// Sync rules from a project manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRules {
    /// Whether Git must be clean for future apply.
    pub require_clean_git: bool,
    /// Whether destructive apply is permitted by manifest policy.
    pub allow_destructive_apply: bool,
    /// Whether ignored paths may be synced.
    pub sync_ignored_paths: bool,
}

/// Hydration rules from a project manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HydrationRules {
    /// Whether lazy hydration is the default.
    pub lazy_by_default: bool,
    /// Whether ignored paths may be hydrated.
    pub hydrate_ignored_paths: bool,
}
