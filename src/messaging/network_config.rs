// Network configuration types for MessagingService
//
// This module provides flexible port configuration options to support:
// - OS-assigned random ports (port 0)
// - Explicit port selection
// - Port range selection with fallback
// - IPv4/IPv6 mode configuration
// - Multiple instances on the same machine
// - P2P NAT traversal configuration

use serde::{Deserialize, Serialize};

// Import ant-quic NAT traversal types
use ant_quic::nat_traversal_api::{EndpointRole, NatTraversalConfig as AntNatConfig};

/// Configuration for network port binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Port configuration for networking
    pub port: PortConfig,

    /// IP stack configuration
    pub ip_mode: IpMode,

    /// Retry behavior on port conflicts
    pub retry_behavior: RetryBehavior,

    /// NAT traversal configuration (None disables NAT traversal)
    pub nat_traversal: Option<NatTraversalMode>,
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

/// NAT traversal mode for this node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NatTraversalMode {
    /// Act as client only (no incoming path validations)
    ClientOnly,

    /// Act as P2P node (both send and receive path validations)
    ///
    /// Concurrency limit controls max simultaneous path validation attempts.
    /// Must be 1-100. Recommended: 5-10 for typical nodes, 20-50 for high-traffic.
    P2PNode {
        /// Maximum concurrent path validation attempts
        concurrency_limit: u32,
    },
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
            // Enable P2P NAT traversal with recommended concurrency limit
            nat_traversal: Some(NatTraversalMode::P2PNode {
                concurrency_limit: 10,
            }),
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

    /// Create configuration with P2P NAT traversal
    pub fn p2p_node(concurrency_limit: u32) -> Self {
        Self {
            nat_traversal: Some(NatTraversalMode::P2PNode { concurrency_limit }),
            ..Default::default()
        }
    }

    /// Create configuration with client-only NAT traversal
    pub fn client_only() -> Self {
        Self {
            nat_traversal: Some(NatTraversalMode::ClientOnly),
            ..Default::default()
        }
    }

    /// Create configuration with NAT traversal disabled
    pub fn no_nat_traversal() -> Self {
        Self {
            nat_traversal: None,
            ..Default::default()
        }
    }

    /// Convert to ant-quic NAT configuration
    pub fn to_ant_config(&self) -> Option<AntNatConfig> {
        self.nat_traversal.as_ref().map(|mode| {
            let role = match mode {
                NatTraversalMode::ClientOnly => EndpointRole::Client,
                NatTraversalMode::P2PNode {
                    concurrency_limit: _,
                } => EndpointRole::Server {
                    can_coordinate: true,
                },
            };

            AntNatConfig {
                role,
                ..Default::default()
            }
        })
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

    #[error("Invalid NAT traversal concurrency limit: {0}. Must be between 1 and 100.")]
    InvalidConcurrencyLimit(u32),
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

    #[test]
    fn test_default_has_p2p_nat() {
        let config = NetworkConfig::default();
        assert!(matches!(
            config.nat_traversal,
            Some(NatTraversalMode::P2PNode {
                concurrency_limit: 10
            })
        ));
    }

    #[test]
    fn test_p2p_node() {
        let config = NetworkConfig::p2p_node(20);
        assert!(matches!(
            config.nat_traversal,
            Some(NatTraversalMode::P2PNode {
                concurrency_limit: 20
            })
        ));
    }

    #[test]
    fn test_client_only() {
        let config = NetworkConfig::client_only();
        assert!(matches!(
            config.nat_traversal,
            Some(NatTraversalMode::ClientOnly)
        ));
    }

    #[test]
    fn test_no_nat_traversal() {
        let config = NetworkConfig::no_nat_traversal();
        assert!(config.nat_traversal.is_none());
    }

    #[test]
    fn test_to_ant_config_p2p() {
        let config = NetworkConfig::p2p_node(15);
        let ant_config = config.to_ant_config();
        assert!(ant_config.is_some());
    }

    #[test]
    fn test_to_ant_config_client() {
        let config = NetworkConfig::client_only();
        let ant_config = config.to_ant_config();
        assert!(ant_config.is_some());
    }

    #[test]
    fn test_to_ant_config_none() {
        let config = NetworkConfig::no_nat_traversal();
        let ant_config = config.to_ant_config();
        assert!(ant_config.is_none());
    }
}
