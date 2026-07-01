use crate::content_hash::ContentHash;
use serde::{Deserialize, Serialize};

/// Environment profile metadata with no raw secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvProfile {
    /// Profile identifier.
    pub id: String,
    /// Project identifier.
    pub project_id: String,
    /// Env files summarized without values.
    pub files: Vec<EnvFileSummary>,
    /// Variables summarized by key name and fingerprint only.
    pub variables: Vec<EnvVariableSummary>,
    /// Human-readable redaction policy.
    pub redaction_policy: String,
}

impl EnvProfile {
    /// Builds a redacted profile from test pairs by fingerprinting values.
    pub fn redacted_from_pairs(
        id: impl Into<String>,
        project_id: impl Into<String>,
        file_path: impl Into<String>,
        pairs: &[(&str, &str)],
    ) -> Self {
        Self {
            id: id.into(),
            project_id: project_id.into(),
            files: vec![EnvFileSummary {
                path: file_path.into(),
                present: true,
                value_capture: ValueCaptureMode::Never,
            }],
            variables: pairs
                .iter()
                .map(|(name, value)| EnvVariableSummary {
                    name: (*name).to_string(),
                    value_present: true,
                    value_fingerprint: Some(ContentHash::hash_bytes(value.as_bytes()).digest),
                })
                .collect(),
            redaction_policy: "names and fingerprints only; raw values are never stored"
                .to_string(),
        }
    }
}

/// Env file summary with value capture policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvFileSummary {
    /// Env file path.
    pub path: String,
    /// Whether the file exists according to a scanner.
    pub present: bool,
    /// Raw value capture mode.
    pub value_capture: ValueCaptureMode,
}

/// Raw value capture mode for env files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueCaptureMode {
    /// Raw env values are never captured.
    Never,
}

/// Env variable summary with no raw value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvVariableSummary {
    /// Variable key name.
    pub name: String,
    /// Whether a value was present.
    pub value_present: bool,
    /// Fingerprint of the value when needed for comparison.
    pub value_fingerprint: Option<String>,
}
