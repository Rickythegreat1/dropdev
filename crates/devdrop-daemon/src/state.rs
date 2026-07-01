use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use devdrop_core::{IgnorePolicy, ReadinessReport, SyncPreview};
use serde::{Deserialize, Serialize};

use crate::{
    config::DaemonConfig,
    error::{DaemonError, DaemonResult},
    queue::{ScanQueue, ScanQueueDecision, ScanReason, ScanRequest},
    scanner::{scan_project_metadata, ScanReport},
};

/// Registered project held in daemon memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredProject {
    /// Project ID used by route parameters and queue requests.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Registered root path. Route parameters never override this.
    pub root: PathBuf,
    /// Last metadata-only scan report.
    pub latest_scan: Option<ScanReport>,
}

impl RegisteredProject {
    /// Creates a registered project record.
    pub fn new(id: impl Into<String>, name: impl Into<String>, root: impl Into<PathBuf>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            root: root.into(),
            latest_scan: None,
        }
    }
}

/// Minimal machine summary for the local daemon API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineSummary {
    /// Machine ID.
    pub id: String,
    /// Hostname or local label.
    pub label: String,
    /// Whether this machine is local to the daemon.
    pub local: bool,
    /// Last scan summary.
    pub last_scan_summary: Option<String>,
}

/// In-memory daemon state.
#[derive(Debug, Clone)]
pub struct DaemonState {
    config: DaemonConfig,
    queue: ScanQueue,
    projects: Arc<RwLock<HashMap<String, RegisteredProject>>>,
    machines: Arc<RwLock<Vec<MachineSummary>>>,
}

impl DaemonState {
    /// Creates empty in-memory state.
    pub fn new(config: DaemonConfig) -> Self {
        Self {
            queue: ScanQueue::new(config.debounce_duration()),
            config,
            projects: Arc::new(RwLock::new(HashMap::new())),
            machines: Arc::new(RwLock::new(vec![MachineSummary {
                id: "machine:local".to_string(),
                label: "local daemon host".to_string(),
                local: true,
                last_scan_summary: None,
            }])),
        }
    }

    /// Returns daemon config.
    pub fn config(&self) -> &DaemonConfig {
        &self.config
    }

    /// Returns the queue.
    pub fn queue(&self) -> &ScanQueue {
        &self.queue
    }

    /// Registers or replaces an in-memory project.
    pub fn register_project(&self, project: RegisteredProject) {
        self.projects
            .write()
            .expect("project state lock")
            .insert(project.id.clone(), project);
    }

    /// Returns all registered projects.
    pub fn projects(&self) -> Vec<RegisteredProject> {
        let mut projects: Vec<_> = self
            .projects
            .read()
            .expect("project state lock")
            .values()
            .cloned()
            .collect();
        projects.sort_by(|left, right| left.id.cmp(&right.id));
        projects
    }

    /// Returns one registered project.
    pub fn project(&self, project_id: &str) -> DaemonResult<RegisteredProject> {
        self.projects
            .read()
            .expect("project state lock")
            .get(project_id)
            .cloned()
            .ok_or_else(|| DaemonError::UnknownProject {
                project_id: project_id.to_string(),
            })
    }

    /// Enqueues a scan for a registered project.
    pub fn enqueue_scan(
        &self,
        project_id: &str,
        reason: ScanReason,
    ) -> DaemonResult<ScanQueueDecision> {
        self.project(project_id)?;
        Ok(self
            .queue
            .enqueue(ScanRequest::new(project_id.to_string(), reason)))
    }

    /// Runs a metadata-only reconciliation scan for a registered project.
    pub fn run_metadata_scan(&self, project_id: &str) -> DaemonResult<ScanReport> {
        let mut project = self.project(project_id)?;
        let report = scan_project_metadata(
            &project,
            &IgnorePolicy::default(),
            self.config.scan_budget_entries,
        );
        project.latest_scan = Some(report.clone());
        self.projects
            .write()
            .expect("project state lock")
            .insert(project.id.clone(), project);
        self.update_local_machine_scan_summary(format!(
            "Last metadata-only scan inspected {} entries.",
            report.inspected_entries
        ));
        Ok(report)
    }

    /// Returns local machine summaries.
    pub fn machines(&self) -> Vec<MachineSummary> {
        self.machines.read().expect("machine state lock").clone()
    }

    /// Returns placeholder readiness status for a registered project.
    pub fn readiness_status(&self, project_id: &str) -> DaemonResult<ReadinessReport> {
        self.project(project_id)?;
        Ok(ReadinessReport::foundation_stub())
    }

    /// Returns a dry-run sync preview for a registered project.
    pub fn sync_preview(&self, project_id: &str) -> DaemonResult<SyncPreview> {
        self.project(project_id)?;
        Ok(SyncPreview::foundation_stub(project_id))
    }

    fn update_local_machine_scan_summary(&self, summary: String) {
        if let Some(machine) = self
            .machines
            .write()
            .expect("machine state lock")
            .iter_mut()
            .find(|machine| machine.local)
        {
            machine.last_scan_summary = Some(summary);
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn unknown_project_does_not_enqueue_scan() {
        let state = DaemonState::new(DaemonConfig::default());
        let before = state.queue().len();
        let err = state
            .enqueue_scan("project:missing", ScanReason::Manual)
            .expect_err("unknown project rejected");

        assert!(matches!(err, DaemonError::UnknownProject { .. }));
        assert_eq!(state.queue().len(), before);
    }

    #[test]
    fn registered_project_scan_is_non_mutating() {
        let dir = tempdir().expect("tempdir");
        std::fs::write(dir.path().join("keep.txt"), "keep").expect("write file");
        let state = DaemonState::new(DaemonConfig::default());
        state.register_project(RegisteredProject::new(
            "project:ready",
            "ready",
            dir.path().to_path_buf(),
        ));

        let report = state
            .run_metadata_scan("project:ready")
            .expect("scan registered project");

        assert!(!report.mutated_files);
        assert!(dir.path().join("keep.txt").exists());
        assert!(state
            .project("project:ready")
            .expect("registered")
            .latest_scan
            .is_some());
    }
}
