use std::net::SocketAddr;

use thiserror::Error;

/// Daemon result type.
pub type DaemonResult<T> = Result<T, DaemonError>;

/// Errors produced by the observer-only daemon.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// The requested bind address would expose the local API outside loopback.
    #[error(
        "refusing non-loopback bind address {addr}; this slice supports loopback-only local API"
    )]
    NonLoopbackBind { addr: SocketAddr },

    /// A project ID was not registered in the in-memory daemon state.
    #[error("unknown project id {project_id}")]
    UnknownProject { project_id: String },

    /// A filesystem path is outside the registered project root.
    #[error("path is outside registered project root")]
    PathOutsideRegisteredRoot,

    /// A request used an unsupported content type.
    #[error("POST endpoints require Content-Type: application/json")]
    UnsupportedContentType,

    /// An I/O error occurred while observing metadata.
    #[error("metadata observation failed: {0}")]
    Io(#[from] std::io::Error),

    /// HTTP server error.
    #[error("local API server failed: {0}")]
    Hyper(#[from] axum::Error),

    /// Invalid CLI/config input.
    #[error("{0}")]
    InvalidConfig(String),
}
