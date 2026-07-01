use thiserror::Error;

/// Result alias for DevDrop core model and validation operations.
pub type CoreResult<T> = Result<T, CoreError>;

/// Typed errors returned by DevDrop core contracts.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Manifest JSON could not be parsed for deterministic model tests.
    #[error("manifest parse failed: {0}")]
    ManifestParse(#[from] serde_json::Error),
    /// Manifest parsed but violated a model validation rule.
    #[error("manifest validation failed for {field}: {message}")]
    ManifestValidation {
        /// Field that failed validation.
        field: &'static str,
        /// Human-readable validation message.
        message: String,
    },
    /// A sync plan contains destructive operations and lacks explicit approval.
    #[error("sync plan {plan_id} requires explicit approval before preview receipt")]
    ApprovalRequired {
        /// Plan identifier that needs approval.
        plan_id: String,
    },
}
