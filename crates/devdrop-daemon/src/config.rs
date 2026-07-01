use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::{
    error::{DaemonError, DaemonResult},
    scanner::DEFAULT_SCAN_BUDGET,
};

/// Default local daemon API bind address.
pub const DEFAULT_BIND_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 37_431);

/// Placeholder header name for future local API token enforcement.
pub const DEFAULT_SAFETY_HEADER: &str = "X-DevDrop-Local-Session";

/// Runtime configuration for the observer-only daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Local API bind address. Must be loopback in this slice.
    pub bind_addr: SocketAddr,
    /// Debounce window for watcher hints and repeated scan requests.
    pub debounce_ms: u64,
    /// Periodic reconciliation interval.
    pub reconciliation_interval_secs: u64,
    /// Maximum metadata entries inspected per scan.
    pub scan_budget_entries: usize,
    /// Placeholder local API safety header.
    pub safety_header_name: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            bind_addr: DEFAULT_BIND_ADDR,
            debounce_ms: 250,
            reconciliation_interval_secs: 30,
            scan_budget_entries: DEFAULT_SCAN_BUDGET,
            safety_header_name: DEFAULT_SAFETY_HEADER.to_string(),
        }
    }
}

impl DaemonConfig {
    /// Validates that the daemon does not bind outside loopback.
    pub fn validate_bind_addr(&self) -> DaemonResult<()> {
        if self.bind_addr.ip().is_loopback() {
            return Ok(());
        }

        Err(DaemonError::NonLoopbackBind {
            addr: self.bind_addr,
        })
    }

    /// Debounce duration.
    pub fn debounce_duration(&self) -> Duration {
        Duration::from_millis(self.debounce_ms)
    }

    /// Periodic reconciliation duration.
    pub fn reconciliation_interval(&self) -> Duration {
        Duration::from_secs(self.reconciliation_interval_secs)
    }

    /// Parses minimal daemon CLI args.
    pub fn from_args<I, S>(args: I) -> DaemonResult<Option<Self>>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut config = Self::default();
        let mut iter = args.into_iter().map(Into::into);

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--help" | "-h" => return Ok(None),
                "--bind" => {
                    let value = iter.next().ok_or_else(|| {
                        DaemonError::InvalidConfig("--bind requires an address".to_string())
                    })?;
                    config.bind_addr = value.parse().map_err(|_| {
                        DaemonError::InvalidConfig(format!("invalid bind address {value}"))
                    })?;
                }
                "--debounce-ms" => {
                    let value = iter.next().ok_or_else(|| {
                        DaemonError::InvalidConfig("--debounce-ms requires a value".to_string())
                    })?;
                    config.debounce_ms = value.parse().map_err(|_| {
                        DaemonError::InvalidConfig(format!("invalid debounce value {value}"))
                    })?;
                }
                "--scan-budget" => {
                    let value = iter.next().ok_or_else(|| {
                        DaemonError::InvalidConfig("--scan-budget requires a value".to_string())
                    })?;
                    config.scan_budget_entries = value.parse().map_err(|_| {
                        DaemonError::InvalidConfig(format!("invalid scan budget {value}"))
                    })?;
                }
                _ => {
                    return Err(DaemonError::InvalidConfig(format!(
                        "unknown daemon argument {arg}"
                    )))
                }
            }
        }

        config.validate_bind_addr()?;
        Ok(Some(config))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv6Addr, SocketAddr};

    use super::*;

    #[test]
    fn accepts_loopback_binds_only() {
        let mut config = DaemonConfig::default();
        assert!(config.validate_bind_addr().is_ok());

        config.bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 37_431);
        assert!(config.validate_bind_addr().is_ok());

        config.bind_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 37_431);
        assert!(config.validate_bind_addr().is_ok());
    }

    #[test]
    fn rejects_non_loopback_and_unspecified_binds() {
        for addr in [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 37_431),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 37_431),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 37_431),
            SocketAddr::new(
                IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().expect("valid IPv6")),
                37_431,
            ),
        ] {
            let config = DaemonConfig {
                bind_addr: addr,
                ..DaemonConfig::default()
            };
            assert!(matches!(
                config.validate_bind_addr(),
                Err(DaemonError::NonLoopbackBind { .. })
            ));
        }
    }
}
