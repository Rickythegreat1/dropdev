use crate::machine::Machine;
use crate::readiness::ReadinessReport;
use serde::{Deserialize, Serialize};

/// Local-first project registry model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRegistry {
    /// Registry schema version.
    pub schema_version: u32,
    /// Registered projects.
    pub projects: Vec<Project>,
    /// Known machines.
    pub machines: Vec<Machine>,
}

impl Default for ProjectRegistry {
    fn default() -> Self {
        Self {
            schema_version: 1,
            projects: Vec::new(),
            machines: Vec::new(),
        }
    }
}

/// Registered project summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    /// Project identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Display root path kept as a string for compatibility.
    pub root: String,
    /// Last readiness report.
    pub readiness: ReadinessReport,
}

impl Project {
    /// Builds a deterministic fixture project.
    pub fn fixture(name: impl Into<String>, root: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            id: format!("project:{name}"),
            name,
            root: root.into(),
            readiness: ReadinessReport::foundation_stub(),
        }
    }
}
