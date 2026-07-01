use tokio_util::sync::CancellationToken;

/// Cooperative shutdown handle for daemon tasks.
#[derive(Debug, Clone)]
pub struct Shutdown {
    token: CancellationToken,
}

impl Shutdown {
    /// Creates a new shutdown handle.
    pub fn new() -> Self {
        Self {
            token: CancellationToken::new(),
        }
    }

    /// Requests shutdown.
    pub fn request(&self) {
        self.token.cancel();
    }

    /// Waits for shutdown.
    pub async fn cancelled(&self) {
        self.token.cancelled().await;
    }

    /// Returns whether shutdown has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_can_be_requested() {
        let shutdown = Shutdown::new();
        assert!(!shutdown.is_cancelled());
        shutdown.request();
        shutdown.cancelled().await;
        assert!(shutdown.is_cancelled());
    }
}
