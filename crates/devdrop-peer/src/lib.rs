//! Authenticated, explicitly paired local prototype. Network receipt only queues
//! a proposal; no remote API applies files, changes permissions or reads projects.
//! Identity keys remain in RAM and are intentionally not production credentials.
#![forbid(unsafe_code)]

pub mod bridge;
pub mod pairing;
pub mod store;
pub mod transport;
pub mod wire;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PeerError(pub &'static str);
pub type PeerResult<T> = std::result::Result<T, PeerError>;
