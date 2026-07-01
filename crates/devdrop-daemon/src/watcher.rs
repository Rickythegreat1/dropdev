use std::path::{Path, PathBuf};

use notify::Event;
use serde::{Deserialize, Serialize};

use crate::{
    queue::{ScanQueueDecision, ScanReason},
    scanner::{path_is_contained, relative_path},
    state::DaemonState,
};

/// Sanitized watcher hint accepted for a registered project root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatcherHint {
    /// Registered project ID.
    pub project_id: String,
    /// Project-relative path that caused the hint.
    pub relative_path: String,
    /// Watcher events are never truth.
    pub source_is_truth: bool,
    /// Scan queue decision.
    pub decision: ScanQueueDecision,
}

/// Accepts a watcher path only when it is contained in a registered project.
pub fn watcher_hint_for_path(state: &DaemonState, path: impl AsRef<Path>) -> Option<WatcherHint> {
    let path = path.as_ref();
    for project in state.projects() {
        if path_is_contained(&project.root, path) {
            let decision = state
                .enqueue_scan(&project.id, ScanReason::WatcherHint)
                .ok()?;
            return Some(WatcherHint {
                project_id: project.id,
                relative_path: relative_path(&project.root, path),
                source_is_truth: false,
                decision,
            });
        }
    }

    None
}

/// Converts a notify-rs event into sanitized watcher hints.
pub fn watcher_hints_for_event(state: &DaemonState, event: &Event) -> Vec<WatcherHint> {
    event
        .paths
        .iter()
        .filter_map(|path| watcher_hint_for_path(state, path))
        .collect()
}

/// Minimal watcher event receiver input for tests and future runtime wiring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatcherEventEnvelope {
    /// Raw paths from notify-rs, retained only in memory before sanitization.
    pub paths: Vec<PathBuf>,
}

impl WatcherEventEnvelope {
    /// Converts the envelope to sanitized hints.
    pub fn into_hints(self, state: &DaemonState) -> Vec<WatcherHint> {
        self.paths
            .iter()
            .filter_map(|path| watcher_hint_for_path(state, path))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::{config::DaemonConfig, state::RegisteredProject};

    #[test]
    fn watcher_hint_enqueues_only_for_registered_root() {
        let root = tempdir().expect("root");
        let outside = tempdir().expect("outside");
        let state = DaemonState::new(DaemonConfig::default());
        state.register_project(RegisteredProject::new(
            "project:ready",
            "ready",
            root.path().to_path_buf(),
        ));

        let inside_hint = watcher_hint_for_path(&state, root.path().join("src/lib.rs"))
            .expect("inside root accepted");
        let outside_hint = watcher_hint_for_path(&state, outside.path().join("src/lib.rs"));

        assert_eq!(inside_hint.project_id, "project:ready");
        assert!(!inside_hint.source_is_truth);
        assert!(inside_hint.decision.queued);
        assert!(outside_hint.is_none());
        assert_eq!(state.queue().len(), 1);
    }
}
