use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};

/// Machine identity and project path mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Machine {
    /// Stable machine identifier.
    pub id: String,
    /// Friendly label retained for compatibility.
    pub label: String,
    /// Hostname.
    pub hostname: String,
    /// Operating system.
    pub os: String,
    /// CPU architecture.
    pub arch: String,
    /// Compatibility workspace roots.
    pub workspace_roots: Vec<String>,
    /// Project path mappings on this machine.
    pub project_path_mappings: Vec<ProjectPathMapping>,
    /// Last scan timestamp as deterministic serialized data.
    pub last_scan_time: Option<String>,
}

/// Mapping from a project to a local path on a machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectPathMapping {
    /// Project identifier.
    pub project_id: String,
    /// Local project path.
    pub local_path: Utf8PathBuf,
}
