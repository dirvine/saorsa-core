// Network configuration types for MessagingService
//
// This module provides flexible port configuration options to support:
// - OS-assigned random ports (port 0)
// - Explicit port selection
// - Port range selection with fallback
// - IPv4/IPv6 mode configuration
// - Multiple instances on the same machine

use serde::{Deserialize, Serialize};

/// Configuration for network port binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Port configuration for networking
    pub port: PortConfig,

    /// IP stack configuration
    pub ip_mode: IpMode,

    /// Retry behavior on port conflicts
    pub retry_behavior: RetryBehavior,
}

/// Port configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortConfig {
    /// Let OS assign random available port (port 0)
    ///
    /// This is the recommended default for most use cases as it:
    /// - Avoids port conflicts
    /// - Allows multiple instances on same machine
    /// - Works with NAT traversal
    OsAssigned,

    /// Use specific port
    ///
    /// # Example
    /// ```
    /// use saorsa_core::messaging::PortConfig;
    /// let config = PortConfig::Explicit(9000);
    /// ```
    Explicit(u16),

    /// Try ports in range, use first available
    ///
    /// # Example
    /// ```
    /// use saorsa_core::messaging::PortConfig;
    /// let config = PortConfig::Range(9000, 9010);
    /// ```
    Range(u16, u16),
}

/// IP stack mode configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpMode {
    /// Both IPv4 and IPv6 on same port (if platform supports it)
    ///
    /// Note: May fail on some platforms due to dual-stack binding conflicts
    DualStack,

    /// IPv4 and IPv6 on different ports
    ///
    /// This avoids dual-stack binding conflicts by using separate ports
    DualStackSeparate {
        ipv4_port: PortConfig,
        ipv6_port: PortConfig,
    },

    /// IPv4 only (recommended default)
    ///
    /// This is the safest option as it:
    /// - Works on all platforms
    /// - Avoids dual-stack conflicts
    /// - Simplifies configuration
    IPv4Only,

    /// IPv6 only
    IPv6Only,
}

/// Retry behavior on port conflicts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RetryBehavior {
    /// Fail immediately if port unavailable
    ///
    /// Use this when you need explicit control over the port
    FailFast,

    /// Fall back to OS-assigned port on conflict
    ///
    /// Use this for more flexible deployments
    FallbackToOsAssigned,

    /// Try next port in range
    ///
    /// Only applicable when using `PortConfig::Range`
    TryNext,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            // Use OS-assigned port to avoid conflicts
            port: PortConfig::OsAssigned,
            // Use IPv4-only to avoid dual-stack binding conflicts
            ip_mode: IpMode::IPv4Only,
            // Fail fast by default for predictable behavior
            retry_behavior: RetryBehavior::FailFast,
        }
    }
}

impl NetworkConfig {
    /// Create configuration with explicit port
    pub fn with_port(port: u16) -> Self {
        Self {
            port: PortConfig::Explicit(port),
            ..Default::default()
        }
    }

    /// Create configuration with port range
    pub fn with_port_range(start: u16, end: u16) -> Self {
        Self {
            port: PortConfig::Range(start, end),
            retry_behavior: RetryBehavior::TryNext,
            ..Default::default()
        }
    }

    /// Create configuration for dual-stack mode
    pub fn with_dual_stack() -> Self {
        Self {
            ip_mode: IpMode::DualStack,
            ..Default::default()
        }
    }

    /// Create configuration for dual-stack with separate ports
    pub fn with_dual_stack_separate() -> Self {
        Self {
            ip_mode: IpMode::DualStackSeparate {
                ipv4_port: PortConfig::OsAssigned,
                ipv6_port: PortConfig::OsAssigned,
            },
            ..Default::default()
        }
    }
}

/// Error types for network configuration
#[derive(Debug, thiserror::Error)]
pub enum NetworkConfigError {
    #[error("Port {0} is already in use. Try using PortConfig::OsAssigned to let the OS choose.")]
    PortInUse(u16),

    #[error("Invalid port number: {0}. Port must be in range 0-65535.")]
    InvalidPort(u16),

    #[error("No available port in range {0}-{1}")]
    NoPortInRange(u16, u16),

    #[error("Dual-stack not supported on this platform. Use IpMode::IPv4Only or IpMode::IPv6Only.")]
    DualStackNotSupported,

    #[error("Failed to bind socket: {0}")]
    BindFailed(String),

    #[error("IPv6 not available on this system. Use IpMode::IPv4Only.")]
    Ipv6NotAvailable,

    #[error("Cannot bind to port {0}: Permission denied. Use port 1024 or higher.")]
    PermissionDenied(u16),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NetworkConfig::default();
        assert!(matches!(config.port, PortConfig::OsAssigned));
        assert!(matches!(config.ip_mode, IpMode::IPv4Only));
        assert!(matches!(config.retry_behavior, RetryBehavior::FailFast));
    }

    #[test]
    fn test_with_port() {
        let config = NetworkConfig::with_port(9000);
        assert!(matches!(config.port, PortConfig::Explicit(9000)));
    }

    #[test]
    fn test_with_port_range() {
        let config = NetworkConfig::with_port_range(9000, 9010);
        assert!(matches!(config.port, PortConfig::Range(9000, 9010)));
        assert!(matches!(config.retry_behavior, RetryBehavior::TryNext));
    }

    #[test]
    fn test_with_dual_stack() {
        let config = NetworkConfig::with_dual_stack();
        assert!(matches!(config.ip_mode, IpMode::DualStack));
    }
}
