//! Observer-only DevDrop daemon.
//!
//! This crate owns local daemon scheduling, watcher hints, metadata-only
//! reconciliation scans, and a localhost API. It does not delete, overwrite,
//! move, hydrate, sync-apply, mutate Git, write CAS, or persist SQLite state.

pub mod api;
pub mod config;
pub mod error;
pub mod queue;
pub mod scanner;
pub mod shutdown;
pub mod state;
pub mod watcher;

pub use api::{build_router, ApiResponse, SafetyEnvelope};
pub use config::DaemonConfig;
pub use error::{DaemonError, DaemonResult};
pub use queue::{ScanQueue, ScanQueueDecision, ScanReason, ScanRequest};
pub use scanner::{scan_project_metadata, ScanReport};
pub use shutdown::Shutdown;
pub use state::{DaemonState, MachineSummary, RegisteredProject};
pub use watcher::{watcher_hint_for_path, WatcherHint};

use axum::Router;
use devdrop_core::SLICE_LABEL;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::info;

/// Compatibility plan retained for earlier slice tests and docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonPlan {
    pub slice: String,
    pub watcher_truth: bool,
    pub reconciliation_required: bool,
    pub note: String,
}

/// Returns the daemon safety posture.
pub fn daemon_plan() -> DaemonPlan {
    DaemonPlan {
        slice: SLICE_LABEL.to_string(),
        watcher_truth: false,
        reconciliation_required: true,
        note: "notify-rs watcher events are hints only; reconciliation scans remain the source of truth."
            .to_string(),
    }
}

/// Runs the local daemon API until Ctrl-C.
pub async fn run_daemon(config: DaemonConfig) -> DaemonResult<()> {
    config.validate_bind_addr()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "devdrop_daemon=info".into()),
        )
        .with_target(false)
        .try_init()
        .ok();

    let state = DaemonState::new(config.clone());
    let router = build_router(state);
    serve_router(config, router).await
}

/// Serves a prepared router with graceful Ctrl-C shutdown.
pub async fn serve_router(config: DaemonConfig, router: Router) -> DaemonResult<()> {
    config.validate_bind_addr()?;
    let listener = TcpListener::bind(config.bind_addr).await?;
    info!(
        bind_addr = %config.bind_addr,
        safety_header = %config.safety_header_name,
        "starting observer-only DevDrop daemon API"
    );

    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_is_not_watcher_truth() {
        let plan = daemon_plan();
        assert!(!plan.watcher_truth);
        assert!(plan.reconciliation_required);
    }
}
