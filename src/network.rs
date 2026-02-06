// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Network module
//!
//! This module provides core networking functionality for the P2P Foundation.
//! It handles peer connections, network events, and node lifecycle management.

#[cfg(feature = "adaptive-ml")]
use crate::adaptive::{EigenTrustEngine, NodeId as AdaptiveNodeId, NodeStatisticsUpdate};
use crate::bgp_geo_provider::BgpGeoProvider;
use crate::bootstrap::{BootstrapManager, ContactEntry, QualityMetrics};
use crate::config::Config;
use crate::dht::DHT;
use crate::error::{NetworkError, P2PError, P2pResult as Result};
use crate::security::GeoProvider;

use crate::production::{ProductionConfig, ResourceManager, ResourceMetrics};
use crate::transport::ant_quic_adapter::{DualStackNetworkNode, ant_peer_id_to_string};
use crate::validation::RateLimitConfig;
use crate::validation::RateLimiter;
use crate::{NetworkAddress, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::{RwLock, broadcast};
use tokio::time::{Instant, interval};
use tracing::{debug, info, trace, warn};

/// Wire protocol message format for P2P communication.
///
/// Serialized with bincode for compact binary encoding.
/// Replaces the previous JSON format for better performance
/// and smaller wire size.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireMessage {
    /// Protocol/topic identifier
    protocol: String,
    /// Raw payload bytes
    data: Vec<u8>,
    /// Sender's peer ID (verified against transport-level identity)
    from: String,
    /// Unix timestamp in seconds
    timestamp: u64,
}

/// Payload bytes used for keepalive messages to prevent connection timeouts.
const KEEPALIVE_PAYLOAD: &[u8] = b"keepalive";

/// Capacity of the internal channel used by the message receiving system.
const MESSAGE_RECV_CHANNEL_CAPACITY: usize = 256;

/// Configuration for a P2P node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Local peer ID for this node
    pub peer_id: Option<PeerId>,

    /// Addresses to listen on for incoming connections
    pub listen_addrs: Vec<std::net::SocketAddr>,

    /// Primary listen address (for compatibility)
    pub listen_addr: std::net::SocketAddr,

    /// Bootstrap peers to connect to on startup (legacy)
    pub bootstrap_peers: Vec<std::net::SocketAddr>,

    /// Bootstrap peers as strings (for integration tests)
    pub bootstrap_peers_str: Vec<String>,

    /// Enable IPv6 support
    pub enable_ipv6: bool,

    // MCP removed; will be redesigned later
    /// Connection timeout duration
    pub connection_timeout: Duration,

    /// Keep-alive interval for connections
    pub keep_alive_interval: Duration,

    /// Maximum number of concurrent connections
    pub max_connections: usize,

    /// Maximum number of incoming connections
    pub max_incoming_connections: usize,

    /// DHT configuration
    pub dht_config: DHTConfig,

    /// Security configuration
    pub security_config: SecurityConfig,

    /// Production hardening configuration
    pub production_config: Option<ProductionConfig>,

    /// Bootstrap cache configuration
    pub bootstrap_cache_config: Option<crate::bootstrap::CacheConfig>,

    /// Optional IP diversity configuration for Sybil protection tuning.
    ///
    /// When set, this configuration is used by bootstrap peer discovery and
    /// other diversity-enforcing subsystems. If `None`, defaults are used.
    pub diversity_config: Option<crate::security::IPDiversityConfig>,

    /// Stale peer threshold - peers with no activity for this duration are considered stale.
    /// Defaults to 60 seconds. Can be reduced for testing purposes.
    #[serde(default = "default_stale_peer_threshold")]
    pub stale_peer_threshold: Duration,
}

/// Default stale peer threshold (60 seconds)
fn default_stale_peer_threshold() -> Duration {
    Duration::from_secs(60)
}

/// DHT-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTConfig {
    /// Kademlia K parameter (bucket size)
    pub k_value: usize,

    /// Kademlia alpha parameter (parallelism)
    pub alpha_value: usize,

    /// DHT record TTL
    pub record_ttl: Duration,

    /// DHT refresh interval
    pub refresh_interval: Duration,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable noise protocol for encryption
    pub enable_noise: bool,

    /// Enable TLS for secure transport
    pub enable_tls: bool,

    /// Trust level for peer verification
    pub trust_level: TrustLevel,
}

/// Trust level for peer verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustLevel {
    /// No verification required
    None,
    /// Basic peer ID verification
    Basic,
    /// Full cryptographic verification
    Full,
}

// ============================================================================
// Address Construction Helpers
// ============================================================================

/// Build listen addresses based on port and IPv6 preference
///
/// This helper consolidates the duplicated address construction logic.
#[inline]
fn build_listen_addrs(port: u16, ipv6_enabled: bool) -> Vec<std::net::SocketAddr> {
    let mut addrs = Vec::with_capacity(if ipv6_enabled { 2 } else { 1 });

    if ipv6_enabled {
        addrs.push(std::net::SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            port,
        ));
    }

    addrs.push(std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        port,
    ));

    addrs
}

impl NodeConfig {
    /// Create a new NodeConfig with default values
    ///
    /// # Errors
    ///
    /// Returns an error if default addresses cannot be parsed
    pub fn new() -> Result<Self> {
        let config = Config::default();
        let listen_addr = config.listen_socket_addr()?;

        Ok(Self {
            peer_id: None,
            listen_addrs: build_listen_addrs(listen_addr.port(), config.network.ipv6_enabled),
            listen_addr,
            bootstrap_peers: Vec::new(),
            bootstrap_peers_str: config.network.bootstrap_nodes.clone(),
            enable_ipv6: config.network.ipv6_enabled,
            connection_timeout: Duration::from_secs(config.network.connection_timeout),
            keep_alive_interval: Duration::from_secs(config.network.keepalive_interval),
            max_connections: config.network.max_connections,
            max_incoming_connections: config.security.connection_limit as usize,
            dht_config: DHTConfig::default(),
            security_config: SecurityConfig::default(),
            production_config: None,
            bootstrap_cache_config: None,
            diversity_config: None,
            stale_peer_threshold: default_stale_peer_threshold(),
        })
    }

    /// Create a builder for customized NodeConfig construction
    pub fn builder() -> NodeConfigBuilder {
        NodeConfigBuilder::default()
    }
}

// ============================================================================
// NodeConfig Builder Pattern
// ============================================================================

/// Builder for constructing NodeConfig with fluent API
#[derive(Debug, Clone, Default)]
pub struct NodeConfigBuilder {
    peer_id: Option<PeerId>,
    listen_port: Option<u16>,
    enable_ipv6: Option<bool>,
    bootstrap_peers: Vec<std::net::SocketAddr>,
    max_connections: Option<usize>,
    connection_timeout: Option<Duration>,
    keep_alive_interval: Option<Duration>,
    dht_config: Option<DHTConfig>,
    security_config: Option<SecurityConfig>,
    production_config: Option<ProductionConfig>,
}

impl NodeConfigBuilder {
    /// Set the peer ID
    pub fn peer_id(mut self, peer_id: PeerId) -> Self {
        self.peer_id = Some(peer_id);
        self
    }

    /// Set the listen port
    pub fn listen_port(mut self, port: u16) -> Self {
        self.listen_port = Some(port);
        self
    }

    /// Enable or disable IPv6
    pub fn ipv6(mut self, enabled: bool) -> Self {
        self.enable_ipv6 = Some(enabled);
        self
    }

    /// Add a bootstrap peer
    pub fn bootstrap_peer(mut self, addr: std::net::SocketAddr) -> Self {
        self.bootstrap_peers.push(addr);
        self
    }

    /// Set maximum connections
    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = Some(max);
        self
    }

    /// Set connection timeout
    pub fn connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = Some(timeout);
        self
    }

    /// Set keep-alive interval
    pub fn keep_alive_interval(mut self, interval: Duration) -> Self {
        self.keep_alive_interval = Some(interval);
        self
    }

    /// Set DHT configuration
    pub fn dht_config(mut self, config: DHTConfig) -> Self {
        self.dht_config = Some(config);
        self
    }

    /// Set security configuration
    pub fn security_config(mut self, config: SecurityConfig) -> Self {
        self.security_config = Some(config);
        self
    }

    /// Set production configuration
    pub fn production_config(mut self, config: ProductionConfig) -> Self {
        self.production_config = Some(config);
        self
    }

    /// Build the NodeConfig
    ///
    /// # Errors
    ///
    /// Returns an error if address construction fails
    pub fn build(self) -> Result<NodeConfig> {
        let base_config = Config::default();
        let default_port = base_config
            .listen_socket_addr()
            .map(|addr| addr.port())
            .unwrap_or(9000);
        let port = self.listen_port.unwrap_or(default_port);
        let ipv6_enabled = self.enable_ipv6.unwrap_or(base_config.network.ipv6_enabled);

        let listen_addr =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port);

        Ok(NodeConfig {
            peer_id: self.peer_id,
            listen_addrs: build_listen_addrs(port, ipv6_enabled),
            listen_addr,
            bootstrap_peers: self.bootstrap_peers.clone(),
            bootstrap_peers_str: self.bootstrap_peers.iter().map(|a| a.to_string()).collect(),
            enable_ipv6: ipv6_enabled,
            connection_timeout: self
                .connection_timeout
                .unwrap_or(Duration::from_secs(base_config.network.connection_timeout)),
            keep_alive_interval: self
                .keep_alive_interval
                .unwrap_or(Duration::from_secs(base_config.network.keepalive_interval)),
            max_connections: self
                .max_connections
                .unwrap_or(base_config.network.max_connections),
            max_incoming_connections: base_config.security.connection_limit as usize,
            dht_config: self.dht_config.unwrap_or_default(),
            security_config: self.security_config.unwrap_or_default(),
            production_config: self.production_config,
            bootstrap_cache_config: None,
            diversity_config: None,
            stale_peer_threshold: default_stale_peer_threshold(),
        })
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        let config = Config::default();
        let listen_addr = config.listen_socket_addr().unwrap_or_else(|_| {
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 9000)
        });

        Self {
            peer_id: None,
            listen_addrs: build_listen_addrs(listen_addr.port(), config.network.ipv6_enabled),
            listen_addr,
            bootstrap_peers: Vec::new(),
            bootstrap_peers_str: Vec::new(),
            enable_ipv6: config.network.ipv6_enabled,
            connection_timeout: Duration::from_secs(config.network.connection_timeout),
            keep_alive_interval: Duration::from_secs(config.network.keepalive_interval),
            max_connections: config.network.max_connections,
            max_incoming_connections: config.security.connection_limit as usize,
            dht_config: DHTConfig::default(),
            security_config: SecurityConfig::default(),
            production_config: None,
            bootstrap_cache_config: None,
            diversity_config: None,
            stale_peer_threshold: default_stale_peer_threshold(),
        }
    }
}

impl NodeConfig {
    /// Create NodeConfig from Config
    pub fn from_config(config: &Config) -> Result<Self> {
        let listen_addr = config.listen_socket_addr()?;
        let bootstrap_addrs = config.bootstrap_addrs()?;

        let mut node_config = Self {
            peer_id: None,
            listen_addrs: vec![listen_addr],
            listen_addr,
            bootstrap_peers: bootstrap_addrs
                .iter()
                .map(|addr| addr.socket_addr())
                .collect(),
            bootstrap_peers_str: config
                .network
                .bootstrap_nodes
                .iter()
                .map(|addr| addr.to_string())
                .collect(),
            enable_ipv6: config.network.ipv6_enabled,

            connection_timeout: Duration::from_secs(config.network.connection_timeout),
            keep_alive_interval: Duration::from_secs(config.network.keepalive_interval),
            max_connections: config.network.max_connections,
            max_incoming_connections: config.security.connection_limit as usize,
            dht_config: DHTConfig {
                k_value: 20,
                alpha_value: 3,
                record_ttl: Duration::from_secs(3600),
                refresh_interval: Duration::from_secs(900),
            },
            security_config: SecurityConfig {
                enable_noise: true,
                enable_tls: true,
                trust_level: TrustLevel::Basic,
            },
            production_config: Some(ProductionConfig {
                max_connections: config.network.max_connections,
                max_memory_bytes: 0,  // unlimited
                max_bandwidth_bps: 0, // unlimited
                connection_timeout: Duration::from_secs(config.network.connection_timeout),
                keep_alive_interval: Duration::from_secs(config.network.keepalive_interval),
                health_check_interval: Duration::from_secs(30),
                metrics_interval: Duration::from_secs(60),
                enable_performance_tracking: true,
                enable_auto_cleanup: true,
                shutdown_timeout: Duration::from_secs(30),
                rate_limits: crate::production::RateLimitConfig::default(),
            }),
            bootstrap_cache_config: None,
            diversity_config: None,
            stale_peer_threshold: default_stale_peer_threshold(),
        };

        // Add IPv6 listen address if enabled
        if config.network.ipv6_enabled {
            node_config.listen_addrs.push(std::net::SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                listen_addr.port(),
            ));
        }

        Ok(node_config)
    }

    /// Try to build a NodeConfig from a listen address string
    pub fn with_listen_addr(addr: &str) -> Result<Self> {
        let listen_addr: std::net::SocketAddr = addr
            .parse()
            .map_err(|e: std::net::AddrParseError| {
                NetworkError::InvalidAddress(e.to_string().into())
            })
            .map_err(P2PError::Network)?;
        let cfg = NodeConfig {
            listen_addr,
            listen_addrs: vec![listen_addr],
            diversity_config: None,
            ..Default::default()
        };
        Ok(cfg)
    }
}

impl Default for DHTConfig {
    fn default() -> Self {
        Self {
            k_value: 20,
            alpha_value: 5,
            record_ttl: Duration::from_secs(3600), // 1 hour
            refresh_interval: Duration::from_secs(600), // 10 minutes
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_noise: true,
            enable_tls: true,
            trust_level: TrustLevel::Basic,
        }
    }
}

/// Information about a connected peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer identifier
    pub peer_id: PeerId,

    /// Peer's addresses
    pub addresses: Vec<String>,

    /// Connection timestamp
    pub connected_at: Instant,

    /// Last seen timestamp
    pub last_seen: Instant,

    /// Connection status
    pub status: ConnectionStatus,

    /// Supported protocols
    pub protocols: Vec<String>,

    /// Number of heartbeats received
    pub heartbeat_count: u64,
}

/// Connection status for a peer
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionStatus {
    /// Connection is being established
    Connecting,
    /// Connection is established and active
    Connected,
    /// Connection is being closed
    Disconnecting,
    /// Connection is closed
    Disconnected,
    /// Connection failed
    Failed(String),
}

/// Network events that can occur
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A new peer has connected
    PeerConnected {
        /// The identifier of the newly connected peer
        peer_id: PeerId,
        /// The network addresses where the peer can be reached
        addresses: Vec<String>,
    },

    /// A peer has disconnected
    PeerDisconnected {
        /// The identifier of the disconnected peer
        peer_id: PeerId,
        /// The reason for the disconnection
        reason: String,
    },

    /// A message was received from a peer
    MessageReceived {
        /// The identifier of the sending peer
        peer_id: PeerId,
        /// The protocol used for the message
        protocol: String,
        /// The raw message data
        data: Vec<u8>,
    },

    /// A connection attempt failed
    ConnectionFailed {
        /// The identifier of the peer (if known)
        peer_id: Option<PeerId>,
        /// The address where connection was attempted
        address: String,
        /// The error message describing the failure
        error: String,
    },

    /// DHT record was stored
    DHTRecordStored {
        /// The DHT key where the record was stored
        key: Vec<u8>,
        /// The value that was stored
        value: Vec<u8>,
    },

    /// DHT record was retrieved
    DHTRecordRetrieved {
        /// The DHT key that was queried
        key: Vec<u8>,
        /// The retrieved value, if found
        value: Option<Vec<u8>>,
    },
}

/// Network events that can occur in the P2P system
///
/// Events are broadcast to all listeners and provide real-time
/// notifications of network state changes and message arrivals.
#[derive(Debug, Clone)]
pub enum P2PEvent {
    /// Message received from a peer on a specific topic
    Message {
        /// Topic or channel the message was sent on
        topic: String,
        /// Peer ID of the message sender
        source: PeerId,
        /// Raw message data payload
        data: Vec<u8>,
    },
    /// A new peer has connected to the network
    PeerConnected(PeerId),
    /// A peer has disconnected from the network
    PeerDisconnected(PeerId),
}

/// Main P2P node structure
/// Main P2P network node that manages connections, routing, and communication
///
/// This struct represents a complete P2P network participant that can:
/// - Connect to other peers via QUIC transport
/// - Participate in distributed hash table (DHT) operations
/// - Send and receive messages through various protocols
/// - Handle network events and peer lifecycle
/// - Provide MCP (Model Context Protocol) services
pub struct P2PNode {
    /// Node configuration
    config: NodeConfig,

    /// Our peer ID
    peer_id: PeerId,

    /// Connected peers
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,

    /// Network event broadcaster
    event_tx: broadcast::Sender<P2PEvent>,

    /// Listen addresses
    listen_addrs: RwLock<Vec<std::net::SocketAddr>>,

    /// Node start time
    start_time: Instant,

    /// Running state
    running: RwLock<bool>,

    /// DHT instance (optional)
    dht: Option<Arc<RwLock<DHT>>>,

    /// Production resource manager (optional)
    resource_manager: Option<Arc<ResourceManager>>,

    /// Bootstrap cache manager for peer discovery
    bootstrap_manager: Option<Arc<RwLock<BootstrapManager>>>,

    /// Dual-stack ant-quic nodes (IPv6 + IPv4) with Happy Eyeballs dialing
    dual_node: Arc<DualStackNetworkNode>,

    /// Rate limiter for connection and request throttling
    rate_limiter: Arc<RateLimiter>,

    /// Active connections (tracked by peer_id)
    /// This set is synchronized with ant-quic's connection state via event monitoring
    active_connections: Arc<RwLock<HashSet<PeerId>>>,

    /// Security dashboard for monitoring
    pub security_dashboard: Option<Arc<crate::dht::metrics::SecurityDashboard>>,

    /// Connection lifecycle monitor task handle
    #[allow(dead_code)]
    connection_monitor_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,

    /// Keepalive task handle
    #[allow(dead_code)]
    keepalive_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,

    /// Periodic maintenance task handle
    #[allow(dead_code)]
    periodic_tasks_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,

    /// Shutdown flag for background tasks
    shutdown: Arc<AtomicBool>,

    /// Message receive task handles (recv tasks + consumer)
    recv_handles: Arc<RwLock<Vec<tokio::task::JoinHandle<()>>>>,

    /// Accept loop task handle for graceful shutdown
    listener_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,

    /// GeoIP provider for connection validation
    #[allow(dead_code)]
    geo_provider: Arc<BgpGeoProvider>,

    /// Bootstrap state tracking - indicates whether peer discovery has completed
    is_bootstrapped: Arc<AtomicBool>,

    /// EigenTrust engine for reputation management
    ///
    /// Used to track peer reliability based on data availability outcomes.
    /// Consumers (like saorsa-node) should report successes and failures
    /// via `report_peer_success()` and `report_peer_failure()` methods.
    #[cfg(feature = "adaptive-ml")]
    trust_engine: Option<Arc<EigenTrustEngine>>,
}

/// Normalize wildcard bind addresses to localhost loopback addresses
///
/// ant-quic correctly rejects "unspecified" addresses (0.0.0.0 and [::]) for remote connections
/// because you cannot connect TO an unspecified address - these are only valid for BINDING.
///
/// This function converts wildcard addresses to appropriate loopback addresses for local connections:
/// - IPv6 [::]:port → ::1:port (IPv6 loopback)
/// - IPv4 0.0.0.0:port → 127.0.0.1:port (IPv4 loopback)
/// - All other addresses pass through unchanged
///
/// # Arguments
/// * `addr` - The SocketAddr to normalize
///
/// # Returns
/// * Normalized SocketAddr suitable for remote connections
fn normalize_wildcard_to_loopback(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    if addr.ip().is_unspecified() {
        // Convert unspecified addresses to loopback
        let loopback_ip = match addr {
            std::net::SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST), // ::1
            std::net::SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST), // 127.0.0.1
        };
        std::net::SocketAddr::new(loopback_ip, addr.port())
    } else {
        // Not a wildcard address, pass through unchanged
        addr
    }
}

impl P2PNode {
    /// Minimal constructor for tests that avoids real networking
    pub fn new_for_tests() -> Result<Self> {
        let (event_tx, _) = broadcast::channel(16);
        Ok(Self {
            config: NodeConfig::default(),
            peer_id: "test_peer".to_string(),
            peers: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            listen_addrs: RwLock::new(Vec::new()),
            start_time: Instant::now(),
            running: RwLock::new(false),
            dht: None,
            resource_manager: None,
            bootstrap_manager: None,
            dual_node: {
                // Bind dual-stack nodes on ephemeral ports for tests
                let v6: Option<std::net::SocketAddr> = "[::1]:0"
                    .parse()
                    .ok()
                    .or(Some(std::net::SocketAddr::from(([0, 0, 0, 0], 0))));
                let v4: Option<std::net::SocketAddr> = "127.0.0.1:0".parse().ok();
                let handle = tokio::runtime::Handle::current();
                let dual_attempt = handle.block_on(
                    crate::transport::ant_quic_adapter::DualStackNetworkNode::new(v6, v4),
                );
                let dual = match dual_attempt {
                    Ok(d) => d,
                    Err(_e1) => {
                        // Fallback to IPv4-only ephemeral bind
                        let fallback = handle.block_on(
                            crate::transport::ant_quic_adapter::DualStackNetworkNode::new(
                                None,
                                "127.0.0.1:0".parse().ok(),
                            ),
                        );
                        match fallback {
                            Ok(d) => d,
                            Err(e2) => {
                                return Err(P2PError::Network(NetworkError::BindError(
                                    format!("Failed to create dual-stack network node: {}", e2)
                                        .into(),
                                )));
                            }
                        }
                    }
                };
                Arc::new(dual)
            },
            rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig {
                max_requests: 100,
                burst_size: 100,
                window: std::time::Duration::from_secs(1),
                ..Default::default()
            })),
            active_connections: Arc::new(RwLock::new(HashSet::new())),
            connection_monitor_handle: Arc::new(RwLock::new(None)),
            keepalive_handle: Arc::new(RwLock::new(None)),
            periodic_tasks_handle: Arc::new(RwLock::new(None)),
            shutdown: Arc::new(AtomicBool::new(false)),
            recv_handles: Arc::new(RwLock::new(Vec::new())),
            listener_handle: Arc::new(RwLock::new(None)),
            geo_provider: Arc::new(BgpGeoProvider::new()),
            security_dashboard: None,
            is_bootstrapped: Arc::new(AtomicBool::new(false)),
            #[cfg(feature = "adaptive-ml")]
            trust_engine: None,
        })
    }
    /// Create a new P2P node with the given configuration
    pub async fn new(config: NodeConfig) -> Result<Self> {
        let peer_id = config.peer_id.clone().unwrap_or_else(|| {
            // Generate a random peer ID for now
            // Safe: UUID v4 canonical format is always 36 characters
            let uuid_str = uuid::Uuid::new_v4().to_string();
            format!("peer_{}", &uuid_str[..8])
        });

        let (event_tx, _) = broadcast::channel(1000);

        // Initialize and register a TrustWeightedKademlia DHT for the global API
        // Use a deterministic local NodeId derived from the peer_id
        {
            use blake3::Hasher;
            let mut hasher = Hasher::new();
            hasher.update(peer_id.as_bytes());
            let digest = hasher.finalize();
            let mut nid = [0u8; 32];
            nid.copy_from_slice(digest.as_bytes());
            let _twdht = std::sync::Arc::new(crate::dht::TrustWeightedKademlia::new(
                crate::identity::node_identity::NodeId::from_bytes(nid),
            ));
            // TODO: Update to use new clean API
            // let _ = crate::api::set_dht_instance(twdht);
        }

        // Initialize DHT if needed
        let (dht, security_dashboard) = if true {
            // Assuming DHT is always enabled for now, or check config
            let _dht_config = crate::dht::DHTConfig {
                replication_factor: config.dht_config.k_value,
                bucket_size: config.dht_config.k_value,
                alpha: config.dht_config.alpha_value,
                record_ttl: config.dht_config.record_ttl,
                bucket_refresh_interval: config.dht_config.refresh_interval,
                republish_interval: config.dht_config.refresh_interval,
                max_distance: 160,
            };
            // Convert peer_id String to NodeId
            let peer_bytes = peer_id.as_bytes();
            let mut node_id_bytes = [0u8; 32];
            let len = peer_bytes.len().min(32);
            node_id_bytes[..len].copy_from_slice(&peer_bytes[..len]);
            let node_id = crate::dht::core_engine::NodeId::from_bytes(node_id_bytes);
            let dht_instance = DHT::new(node_id).map_err(|e| {
                crate::error::P2PError::Dht(crate::error::DhtError::StoreFailed(
                    e.to_string().into(),
                ))
            })?;
            dht_instance.start_maintenance_tasks();

            // Create Security Dashboard
            let security_metrics = dht_instance.security_metrics();
            let dashboard = crate::dht::metrics::SecurityDashboard::new(
                security_metrics,
                Arc::new(crate::dht::metrics::DhtMetricsCollector::new()),
                Arc::new(crate::dht::metrics::TrustMetricsCollector::new()),
                Arc::new(crate::dht::metrics::PlacementMetricsCollector::new()),
            );

            (
                Some(Arc::new(RwLock::new(dht_instance))),
                Some(Arc::new(dashboard)),
            )
        } else {
            (None, None)
        };

        // MCP removed

        // Initialize production resource manager if configured
        let resource_manager = config
            .production_config
            .clone()
            .map(|prod_config| Arc::new(ResourceManager::new(prod_config)));

        // Initialize bootstrap cache manager
        let diversity_config = config.diversity_config.clone().unwrap_or_default();
        let bootstrap_manager = if let Some(ref cache_config) = config.bootstrap_cache_config {
            match BootstrapManager::with_full_config(
                cache_config.clone(),
                crate::rate_limit::JoinRateLimiterConfig::default(),
                diversity_config.clone(),
            )
            .await
            {
                Ok(manager) => Some(Arc::new(RwLock::new(manager))),
                Err(e) => {
                    warn!(
                        "Failed to initialize bootstrap manager: {}, continuing without cache",
                        e
                    );
                    None
                }
            }
        } else {
            match BootstrapManager::with_full_config(
                crate::bootstrap::CacheConfig::default(),
                crate::rate_limit::JoinRateLimiterConfig::default(),
                diversity_config,
            )
            .await
            {
                Ok(manager) => Some(Arc::new(RwLock::new(manager))),
                Err(e) => {
                    warn!(
                        "Failed to initialize bootstrap manager: {}, continuing without cache",
                        e
                    );
                    None
                }
            }
        };

        // Initialize EigenTrust engine for reputation management (only with adaptive-ml feature)
        // Pre-trusted nodes are the bootstrap nodes (they start with high trust)
        #[cfg(feature = "adaptive-ml")]
        let trust_engine = {
            use crate::adaptive::NodeId;
            use std::collections::HashSet;

            // Convert bootstrap peers to NodeIds for pre-trusted set
            // TODO: Bootstrap peer addresses are hashed to create placeholder NodeIds here.
            // The actual peer IDs differ from these hashes. This is a temporary solution -
            // the pre-trusted set will be updated with real peer IDs when actual connections
            // are established. A proper fix requires passing real peer IDs from the connection
            // layer, which needs architectural changes.
            let mut pre_trusted = HashSet::new();
            for bootstrap_peer in &config.bootstrap_peers_str {
                // Hash the bootstrap peer address to create a placeholder NodeId
                let hash = blake3::hash(bootstrap_peer.as_bytes());
                let mut node_id_bytes = [0u8; 32];
                node_id_bytes.copy_from_slice(hash.as_bytes());
                pre_trusted.insert(NodeId::from_bytes(node_id_bytes));
            }

            let engine = Arc::new(EigenTrustEngine::new(pre_trusted));
            // Start background trust computation (every 5 minutes)
            engine.clone().start_background_updates();
            Some(engine)
        };

        // Initialize dual-stack ant-quic nodes
        // Determine bind addresses
        let (v6_opt, v4_opt) = {
            let port = config.listen_addr.port();
            let ip = config.listen_addr.ip();

            let v4_addr = if ip.is_ipv4() {
                Some(std::net::SocketAddr::new(ip, port))
            } else {
                // If config is IPv6, we still might want IPv4 on UNSPECIFIED if dual stack is desired
                // But for now let's just stick to defaults if not specified
                Some(std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    port,
                ))
            };

            let v6_addr = if config.enable_ipv6 {
                if ip.is_ipv6() {
                    Some(std::net::SocketAddr::new(ip, port))
                } else {
                    Some(std::net::SocketAddr::new(
                        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                        port,
                    ))
                }
            } else {
                None
            };
            (v6_addr, v4_addr)
        };

        let dual_node = Arc::new(
            DualStackNetworkNode::new_with_max_connections(v6_opt, v4_opt, config.max_connections)
                .await
                .map_err(|e| {
                    P2PError::Transport(crate::error::TransportError::SetupFailed(
                        format!("Failed to create dual-stack network nodes: {}", e).into(),
                    ))
                })?,
        );

        // Initialize rate limiter with default config
        let rate_limiter = Arc::new(RateLimiter::new(
            crate::validation::RateLimitConfig::default(),
        ));

        // Create active connections tracker
        let active_connections = Arc::new(RwLock::new(HashSet::new()));

        // Initialize GeoIP provider
        let geo_provider = Arc::new(BgpGeoProvider::new());

        // Create peers map
        let peers = Arc::new(RwLock::new(HashMap::new()));

        // Start connection lifecycle monitor
        // CRITICAL: Subscribe to connection events BEFORE spawning the task
        // to avoid race condition where early connections are missed
        let connection_event_rx = dual_node.subscribe_connection_events();

        let connection_monitor_handle = {
            let active_conns = Arc::clone(&active_connections);
            let peers_map = Arc::clone(&peers);
            let event_tx_clone = event_tx.clone();
            let dual_node_clone = Arc::clone(&dual_node);
            let geo_provider_clone = Arc::clone(&geo_provider);
            let peer_id_clone = peer_id.clone();

            let handle = tokio::spawn(async move {
                Self::connection_lifecycle_monitor_with_rx(
                    dual_node_clone,
                    connection_event_rx,
                    active_conns,
                    peers_map,
                    event_tx_clone,
                    geo_provider_clone,
                    peer_id_clone,
                )
                .await;
            });

            Arc::new(RwLock::new(Some(handle)))
        };

        // Spawn keepalive task
        let shutdown = Arc::new(AtomicBool::new(false));
        let keepalive_handle = {
            let active_conns = Arc::clone(&active_connections);
            let dual_node_clone = Arc::clone(&dual_node);
            let shutdown_clone = Arc::clone(&shutdown);

            let handle = tokio::spawn(async move {
                Self::keepalive_task(active_conns, dual_node_clone, shutdown_clone).await;
            });

            Arc::new(RwLock::new(Some(handle)))
        };

        // Spawn periodic maintenance task for stale peer detection
        let periodic_tasks_handle = {
            let peers_clone = Arc::clone(&peers);
            let active_conns_clone = Arc::clone(&active_connections);
            let event_tx_clone = event_tx.clone();
            let stale_threshold = config.stale_peer_threshold;
            let shutdown_clone = Arc::clone(&shutdown);

            let handle = tokio::spawn(async move {
                Self::periodic_maintenance_task(
                    peers_clone,
                    active_conns_clone,
                    event_tx_clone,
                    stale_threshold,
                    shutdown_clone,
                )
                .await;
            });

            Arc::new(RwLock::new(Some(handle)))
        };

        let node = Self {
            config,
            peer_id,
            peers,
            event_tx,
            listen_addrs: RwLock::new(Vec::new()),
            start_time: Instant::now(),
            running: RwLock::new(false),
            dht,
            resource_manager,
            bootstrap_manager,
            dual_node,
            rate_limiter,
            active_connections,
            security_dashboard,
            connection_monitor_handle,
            keepalive_handle,
            periodic_tasks_handle,
            shutdown,
            recv_handles: Arc::new(RwLock::new(Vec::new())),
            listener_handle: Arc::new(RwLock::new(None)),
            geo_provider,
            is_bootstrapped: Arc::new(AtomicBool::new(false)),
            #[cfg(feature = "adaptive-ml")]
            trust_engine,
        };
        info!(
            "Created P2P node with peer ID: {} (call start() to begin networking)",
            node.peer_id
        );

        Ok(node)
    }

    /// Create a new node builder
    pub fn builder() -> NodeBuilder {
        NodeBuilder::new()
    }

    /// Get the peer ID of this node
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Get the hex-encoded transport-level peer ID.
    ///
    /// This is the ID used in `P2PEvent::Message.source`, `connected_peers()`,
    /// and `send_message()`. It differs from `peer_id()` which is the app-level ID.
    ///
    /// Returns the transport peer ID from whichever stack (v4 or v6) is active.
    pub fn transport_peer_id(&self) -> Option<String> {
        if let Some(ref v4) = self.dual_node.v4 {
            return Some(ant_peer_id_to_string(&v4.our_peer_id()));
        }
        if let Some(ref v6) = self.dual_node.v6 {
            return Some(ant_peer_id_to_string(&v6.our_peer_id()));
        }
        None
    }

    pub fn local_addr(&self) -> Option<String> {
        self.listen_addrs
            .try_read()
            .ok()
            .and_then(|addrs| addrs.first().map(|a| a.to_string()))
    }

    /// Check if the node has completed the initial bootstrap process
    ///
    /// Returns `true` if the node has successfully connected to at least one
    /// bootstrap peer and performed peer discovery (FIND_NODE).
    pub fn is_bootstrapped(&self) -> bool {
        self.is_bootstrapped.load(Ordering::SeqCst)
    }

    /// Manually trigger re-bootstrap (useful for recovery or network rejoin)
    ///
    /// This clears the bootstrapped state and attempts to reconnect to
    /// bootstrap peers and discover new peers.
    pub async fn re_bootstrap(&self) -> Result<()> {
        self.is_bootstrapped.store(false, Ordering::SeqCst);
        self.connect_bootstrap_peers().await
    }

    // =========================================================================
    // Trust API - EigenTrust Reputation System (requires adaptive-ml feature)
    // =========================================================================

    /// Get the EigenTrust engine for direct trust operations
    ///
    /// This provides access to the underlying trust engine for advanced use cases.
    /// For simple success/failure reporting, prefer `report_peer_success()` and
    /// `report_peer_failure()`.
    ///
    /// Requires the `adaptive-ml` feature to be enabled.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if let Some(engine) = node.trust_engine() {
    ///     // Update node statistics directly
    ///     engine.update_node_stats(&peer_id, NodeStatisticsUpdate::StorageContributed(1024)).await;
    ///
    ///     // Get global trust scores
    ///     let scores = engine.compute_global_trust().await;
    /// }
    /// ```
    #[cfg(feature = "adaptive-ml")]
    pub fn trust_engine(&self) -> Option<Arc<EigenTrustEngine>> {
        self.trust_engine.clone()
    }

    /// Canonical conversion from PeerId string to adaptive NodeId for trust.
    ///
    /// PeerId strings are hex-encoded 32-byte identifiers. This decodes them
    /// back to raw bytes, matching the DHT NodeId representation used by
    /// `trust_peer_selector`. Falls back to blake3 hash for non-hex IDs.
    #[cfg(feature = "adaptive-ml")]
    fn peer_id_to_trust_node_id(peer_id: &str) -> AdaptiveNodeId {
        if let Ok(bytes) = hex::decode(peer_id)
            && bytes.len() == 32
        {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return AdaptiveNodeId::from_bytes(arr);
        }
        // Non-hex or wrong length: hash to 32 bytes as fallback
        let hash = blake3::hash(peer_id.as_bytes());
        AdaptiveNodeId::from_bytes(*hash.as_bytes())
    }

    /// Report a successful interaction with a peer
    ///
    /// Call this after successful data operations to increase the peer's trust score.
    /// This is the primary method for saorsa-node to report positive outcomes.
    ///
    /// Requires the `adaptive-ml` feature to be enabled.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer ID (as a string) of the node that performed well
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // After successfully retrieving a chunk from a peer
    /// if let Ok(chunk) = fetch_chunk_from(&peer_id).await {
    ///     node.report_peer_success(&peer_id).await?;
    /// }
    /// ```
    #[cfg(feature = "adaptive-ml")]
    pub async fn report_peer_success(&self, peer_id: &str) -> Result<()> {
        if let Some(ref engine) = self.trust_engine {
            let node_id = Self::peer_id_to_trust_node_id(peer_id);

            engine
                .update_node_stats(&node_id, NodeStatisticsUpdate::CorrectResponse)
                .await;
            Ok(())
        } else {
            // Trust engine not initialized - this is not an error, just a no-op
            Ok(())
        }
    }

    /// Report a failed interaction with a peer
    ///
    /// Call this after failed data operations to decrease the peer's trust score.
    /// This includes timeouts, corrupted data, or refused connections.
    ///
    /// Requires the `adaptive-ml` feature to be enabled.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer ID (as a string) of the node that failed
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // After a chunk retrieval fails
    /// match fetch_chunk_from(&peer_id).await {
    ///     Ok(chunk) => node.report_peer_success(&peer_id).await?,
    ///     Err(_) => node.report_peer_failure(&peer_id).await?,
    /// }
    /// ```
    #[cfg(feature = "adaptive-ml")]
    pub async fn report_peer_failure(&self, peer_id: &str) -> Result<()> {
        if let Some(ref engine) = self.trust_engine {
            let node_id = Self::peer_id_to_trust_node_id(peer_id);

            engine
                .update_node_stats(&node_id, NodeStatisticsUpdate::FailedResponse)
                .await;
            Ok(())
        } else {
            // Trust engine not initialized - this is not an error, just a no-op
            Ok(())
        }
    }

    /// Get the current trust score for a peer
    ///
    /// Returns a value between 0.0 (untrusted) and 1.0 (fully trusted).
    /// Unknown peers return 0.0 by default.
    ///
    /// Requires the `adaptive-ml` feature to be enabled.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer ID (as a string) to query
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let trust = node.peer_trust(&peer_id);
    /// if trust < 0.3 {
    ///     tracing::warn!("Low trust peer: {}", peer_id);
    /// }
    /// ```
    #[cfg(feature = "adaptive-ml")]
    pub fn peer_trust(&self, peer_id: &str) -> f64 {
        if let Some(ref engine) = self.trust_engine {
            let node_id = Self::peer_id_to_trust_node_id(peer_id);

            use crate::adaptive::TrustProvider;
            engine.get_trust(&node_id)
        } else {
            // Trust engine not initialized - return neutral trust
            0.5
        }
    }

    pub async fn subscribe(&self, topic: &str) -> Result<()> {
        // In a real implementation, this would register the topic with the pubsub mechanism.
        // For now, we just log it.
        info!("Subscribed to topic: {}", topic);
        Ok(())
    }

    pub async fn publish(&self, topic: &str, data: &[u8]) -> Result<()> {
        info!(
            "Publishing message to topic: {} ({} bytes)",
            topic,
            data.len()
        );

        // Get list of connected peers
        let peer_list: Vec<PeerId> = {
            let peers_guard = self.peers.read().await;
            peers_guard.keys().cloned().collect()
        };

        if peer_list.is_empty() {
            debug!("No peers connected, message will only be sent to local subscribers");
        } else {
            // Send message to all connected peers
            let mut send_count = 0;
            for peer_id in &peer_list {
                match self.send_message(peer_id, topic, data.to_vec()).await {
                    Ok(_) => {
                        send_count += 1;
                        debug!("Sent message to peer: {}", peer_id);
                    }
                    Err(e) => {
                        warn!("Failed to send message to peer {}: {}", peer_id, e);
                    }
                }
            }
            info!(
                "Published message to {}/{} connected peers",
                send_count,
                peer_list.len()
            );
        }

        // Also send to local subscribers (for local echo and testing)
        self.send_event(P2PEvent::Message {
            topic: topic.to_string(),
            source: self.peer_id.clone(),
            data: data.to_vec(),
        });

        Ok(())
    }

    /// Get the node configuration
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Start the P2P node
    pub async fn start(&self) -> Result<()> {
        info!("Starting P2P node...");

        // Start production resource manager if configured
        if let Some(ref resource_manager) = self.resource_manager {
            resource_manager.start().await.map_err(|e| {
                P2PError::Network(crate::error::NetworkError::ProtocolError(
                    format!("Failed to start resource manager: {e}").into(),
                ))
            })?;
            info!("Production resource manager started");
        }

        // Start bootstrap manager background tasks
        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
            let mut manager = bootstrap_manager.write().await;
            manager.start_background_tasks().await.map_err(|e| {
                P2PError::Network(crate::error::NetworkError::ProtocolError(
                    format!("Failed to start bootstrap manager: {e}").into(),
                ))
            })?;
            info!("Bootstrap cache manager started");
        }

        // Set running state
        *self.running.write().await = true;

        // Start listening on configured addresses using transport layer
        self.start_network_listeners().await?;

        // Update the connection monitor with actual peers reference
        self.start_connection_monitor().await;

        // Log current listen addresses
        let listen_addrs = self.listen_addrs.read().await;
        info!("P2P node started on addresses: {:?}", *listen_addrs);

        // NOTE: Message receiving is now integrated into the accept loop in start_network_listeners()
        // The old start_message_receiving_system() is no longer needed as it competed with the accept
        // loop for incoming connections, causing messages to be lost.

        // Connect to bootstrap peers
        self.connect_bootstrap_peers().await?;

        Ok(())
    }

    /// Start network listeners on configured addresses
    async fn start_network_listeners(&self) -> Result<()> {
        info!("Starting dual-stack listeners (ant-quic)...");
        // Update our listen_addrs from the dual node bindings
        let addrs = self.dual_node.local_addrs().await.map_err(|e| {
            P2PError::Transport(crate::error::TransportError::SetupFailed(
                format!("Failed to get local addresses: {}", e).into(),
            ))
        })?;
        {
            let mut la = self.listen_addrs.write().await;
            *la = addrs.clone();
        }

        // Spawn a background accept loop that handles incoming connections from either stack.
        // This only handles peer registration. Message data is received separately
        // via start_message_receiving_system() which uses endpoint().recv().
        let event_tx = self.event_tx.clone();
        let peers = self.peers.clone();
        let active_connections = self.active_connections.clone();
        let rate_limiter = self.rate_limiter.clone();
        let dual = self.dual_node.clone();
        let handle = tokio::spawn(async move {
            loop {
                let Some((ant_peer_id, remote_sock)) = dual.accept_any().await else {
                    // Transport shut down — exit the accept loop.
                    break;
                };

                // Enforce rate limiting
                if let Err(e) = rate_limiter.check_ip(&remote_sock.ip()) {
                    warn!(
                        "Rate-limited incoming connection from {}: {}",
                        remote_sock, e
                    );
                    continue;
                }

                let peer_id =
                    crate::transport::ant_quic_adapter::ant_peer_id_to_string(&ant_peer_id);
                let remote_addr = NetworkAddress::from(remote_sock);
                broadcast_event(&event_tx, P2PEvent::PeerConnected(peer_id.clone()));
                register_new_peer(&peers, &peer_id, &remote_addr).await;
                active_connections.write().await.insert(peer_id);
            }
        });
        *self.listener_handle.write().await = Some(handle);

        // Start the recv-based message receiving system.
        // This uses endpoint().recv() which matches endpoint().send() used by send_message().
        // The accept loop above handles incoming connections (peer registration) and DHT
        // typed streams, while this handles general P2P messaging via the raw endpoint API.
        self.start_message_receiving_system().await?;

        info!("Dual-stack listeners active on: {:?}", addrs);
        Ok(())
    }

    /// Spawns per-stack recv tasks that feed into a single mpsc channel,
    /// then a dispatcher task that parses incoming bytes and emits P2P events.
    async fn start_message_receiving_system(&self) -> Result<()> {
        info!("Starting message receiving system");

        let (tx, mut rx) = tokio::sync::mpsc::channel(MESSAGE_RECV_CHANNEL_CAPACITY);
        let shutdown = Arc::clone(&self.shutdown);

        let mut handles = Vec::new();

        // Spawn per-stack recv tasks — both feed into the same channel
        if let Some(v6) = self.dual_node.v6.as_ref() {
            handles.push(v6.spawn_recv_task(tx.clone(), Arc::clone(&shutdown)));
        }
        if let Some(v4) = self.dual_node.v4.as_ref() {
            handles.push(v4.spawn_recv_task(tx.clone(), Arc::clone(&shutdown)));
        }
        drop(tx); // drop original sender so rx closes when all tasks exit

        let event_tx = self.event_tx.clone();
        handles.push(tokio::spawn(async move {
            info!("Message receive loop started");
            while let Some((peer_id, bytes)) = rx.recv().await {
                let transport_peer_id =
                    crate::transport::ant_quic_adapter::ant_peer_id_to_string(&peer_id);
                trace!(
                    "Received {} bytes from peer {}",
                    bytes.len(),
                    transport_peer_id
                );

                if bytes == KEEPALIVE_PAYLOAD {
                    trace!("Received keepalive from {}", transport_peer_id);
                    continue;
                }

                match parse_protocol_message(&bytes, &transport_peer_id) {
                    Some(event) => broadcast_event(&event_tx, event),
                    None => {
                        warn!("Failed to parse protocol message ({} bytes)", bytes.len());
                    }
                }
            }
            info!("Message receive loop ended — channel closed");
        }));

        *self.recv_handles.write().await = handles;

        Ok(())
    }

    /// Run the P2P node (blocks until shutdown)
    pub async fn run(&self) -> Result<()> {
        if !*self.running.read().await {
            self.start().await?;
        }

        info!("P2P node running...");

        // Main event loop
        loop {
            if !*self.running.read().await {
                break;
            }

            // Perform periodic tasks
            self.periodic_tasks().await?;

            // Sleep for a short interval
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        info!("P2P node stopped");
        Ok(())
    }

    /// Stop the P2P node
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping P2P node...");

        // Signal all background tasks to stop
        self.shutdown.store(true, Ordering::Relaxed);
        // signal_shutdown() removed: shutdown is fully handled by
        // the CancellationToken via shutdown_endpoints() below.

        // Set running state to false
        *self.running.write().await = false;

        // Shut down the transport endpoints first. This cancels the
        // endpoint CancellationToken which unblocks any recv() calls
        // and aborts per-connection reader tasks inside ant-quic.
        // Note: ant-quic >=0.20 races recv() against the shutdown token
        // internally, so this is belt-and-suspenders -- but calling it
        // first is still the safest ordering.
        self.dual_node.shutdown_endpoints().await;

        // Await recv system tasks
        let handles: Vec<_> = self.recv_handles.write().await.drain(..).collect();
        for handle in handles {
            match handle.await {
                Ok(()) => {}
                Err(e) if e.is_cancelled() => {
                    tracing::debug!("Recv task was cancelled during shutdown");
                }
                Err(e) if e.is_panic() => {
                    tracing::error!("Recv task panicked during shutdown: {:?}", e);
                }
                Err(e) => {
                    tracing::warn!("Recv task join error during shutdown: {:?}", e);
                }
            }
        }

        // Await accept loop task
        if let Some(handle) = self.listener_handle.write().await.take() {
            match handle.await {
                Ok(()) => {}
                Err(e) if e.is_cancelled() => {
                    tracing::debug!("Listener task was cancelled during shutdown");
                }
                Err(e) if e.is_panic() => {
                    tracing::error!("Listener task panicked during shutdown: {:?}", e);
                }
                Err(e) => {
                    tracing::warn!("Listener task join error during shutdown: {:?}", e);
                }
            }
        }

        // Disconnect all peers
        self.disconnect_all_peers().await?;

        // Shutdown production resource manager if configured
        if let Some(ref resource_manager) = self.resource_manager {
            resource_manager.shutdown().await.map_err(|e| {
                P2PError::Network(crate::error::NetworkError::ProtocolError(
                    format!("Failed to shutdown resource manager: {e}").into(),
                ))
            })?;
            info!("Production resource manager stopped");
        }

        info!("P2P node stopped");
        Ok(())
    }

    /// Graceful shutdown alias for tests
    pub async fn shutdown(&self) -> Result<()> {
        self.stop().await
    }

    /// Check if the node is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Get the current listen addresses
    pub async fn listen_addrs(&self) -> Vec<std::net::SocketAddr> {
        self.listen_addrs.read().await.clone()
    }

    /// Get connected peers
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        // "Connected" is defined as currently active at the transport layer.
        // The peers map may contain historical peers with Disconnected/Failed status.
        self.active_connections
            .read()
            .await
            .iter()
            .cloned()
            .collect()
    }

    /// Get peer count
    pub async fn peer_count(&self) -> usize {
        self.active_connections.read().await.len()
    }

    /// Get peer info
    pub async fn peer_info(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        self.peers.read().await.get(peer_id).cloned()
    }

    /// Get the peer ID for a given socket address, if connected
    ///
    /// This method searches through all connected peers to find one that has
    /// the specified address in its address list.
    ///
    /// # Arguments
    /// * `addr` - The socket address to search for (e.g., "192.168.1.100:9000")
    ///
    /// # Returns
    /// * `Some(PeerId)` - The peer ID if a matching connected peer is found
    /// * `None` - If no peer with this address is currently connected
    pub async fn get_peer_id_by_address(&self, addr: &str) -> Option<PeerId> {
        // Parse the address to a SocketAddr for comparison
        let socket_addr: std::net::SocketAddr = addr.parse().ok()?;

        let peers = self.peers.read().await;

        // Search through all connected peers
        for (peer_id, peer_info) in peers.iter() {
            // Check if this peer has a matching address
            for peer_addr in &peer_info.addresses {
                if let Ok(peer_socket) = peer_addr.parse::<std::net::SocketAddr>()
                    && peer_socket == socket_addr
                {
                    return Some(peer_id.clone());
                }
            }
        }

        None
    }

    /// List all active connections with their peer IDs and addresses
    ///
    /// # Returns
    /// A vector of tuples containing `(PeerId, Vec<String>)` where the `Vec<String>`
    /// contains all known addresses for that peer.
    pub async fn list_active_connections(&self) -> Vec<(PeerId, Vec<String>)> {
        let active = self.active_connections.read().await;
        let peers = self.peers.read().await;

        active
            .iter()
            .map(|peer_id| {
                let addresses = peers
                    .get(peer_id)
                    .map(|info| info.addresses.clone())
                    .unwrap_or_default();
                (peer_id.clone(), addresses)
            })
            .collect()
    }

    /// Remove a peer from the peers map
    ///
    /// This method removes a peer from the internal peers map. It should be used
    /// when a connection is no longer valid (e.g., after detecting that the underlying
    /// ant-quic connection has closed).
    ///
    /// # Arguments
    /// * `peer_id` - The ID of the peer to remove
    ///
    /// # Returns
    /// `true` if the peer was found and removed, `false` if the peer was not in the map
    pub async fn remove_peer(&self, peer_id: &PeerId) -> bool {
        // Remove from active connections tracking
        self.active_connections.write().await.remove(peer_id);
        // Remove from peers map and return whether it existed
        self.peers.write().await.remove(peer_id).is_some()
    }

    /// Check if a peer is connected
    ///
    /// This method checks if the peer ID exists in the peers map. Note that this
    /// only verifies the peer is registered - it does not guarantee the underlying
    /// ant-quic connection is still active. For connection validation, use `send_message`
    /// which will fail if the connection is closed.
    ///
    /// # Arguments
    /// * `peer_id` - The ID of the peer to check
    ///
    /// # Returns
    /// `true` if the peer exists in the peers map, `false` otherwise
    pub async fn is_peer_connected(&self, peer_id: &PeerId) -> bool {
        self.peers.read().await.contains_key(peer_id)
    }

    /// Connect to a peer
    pub async fn connect_peer(&self, address: &str) -> Result<PeerId> {
        // Check production limits if resource manager is enabled
        let _connection_guard = if let Some(ref resource_manager) = self.resource_manager {
            Some(resource_manager.acquire_connection().await?)
        } else {
            None
        };

        // Parse the address to SocketAddr format
        let socket_addr: std::net::SocketAddr = address.parse().map_err(|e| {
            P2PError::Network(crate::error::NetworkError::InvalidAddress(
                format!("{}: {}", address, e).into(),
            ))
        })?;

        // Normalize wildcard addresses to loopback for local connections
        // This converts [::]:port → ::1:port and 0.0.0.0:port → 127.0.0.1:port
        let normalized_addr = normalize_wildcard_to_loopback(socket_addr);

        // Establish a real connection via dual-stack Happy Eyeballs, but cap the wait
        let addr_list = vec![normalized_addr];
        let peer_id = match tokio::time::timeout(
            self.config.connection_timeout,
            self.dual_node.connect_happy_eyeballs(&addr_list),
        )
        .await
        {
            Ok(Ok(peer)) => {
                let connected_peer_id = ant_peer_id_to_string(&peer);

                // Prevent self-connections by checking if remote peer_id matches our own
                if connected_peer_id == self.peer_id {
                    warn!(
                        "Detected self-connection to own address {} (peer_id: {}), rejecting",
                        address, connected_peer_id
                    );
                    // Actively close the QUIC connection instead of leaking it
                    // until idle timeout
                    self.dual_node.disconnect_peer(&peer).await;
                    return Err(P2PError::Network(
                        crate::error::NetworkError::InvalidAddress(
                            format!("Cannot connect to self ({})", address).into(),
                        ),
                    ));
                }

                info!("Successfully connected to peer: {}", connected_peer_id);
                connected_peer_id
            }
            Ok(Err(e)) => {
                warn!(
                    "connect_happy_eyeballs failed for {}: {}",
                    address, e
                );
                return Err(P2PError::Transport(
                    crate::error::TransportError::ConnectionFailed {
                        addr: normalized_addr,
                        reason: e.to_string().into(),
                    },
                ));
            }
            Err(_) => {
                warn!(
                    "connect_happy_eyeballs timed out for {} after {:?}",
                    address, self.config.connection_timeout
                );
                return Err(P2PError::Timeout(self.config.connection_timeout));
            }
        };

        // Create peer info with connection details
        let peer_info = PeerInfo {
            peer_id: peer_id.clone(),
            addresses: vec![address.to_string()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["p2p-foundation/1.0".to_string()],
            heartbeat_count: 0,
        };

        // Store peer information
        self.peers.write().await.insert(peer_id.clone(), peer_info);

        // Add to active connections tracking
        // This is critical for is_connection_active() to work correctly
        self.active_connections
            .write()
            .await
            .insert(peer_id.clone());

        // Record bandwidth usage if resource manager is enabled
        if let Some(ref resource_manager) = self.resource_manager {
            resource_manager.record_bandwidth(0, 0); // Placeholder for handshake data
        }

        // Emit connection event
        self.send_event(P2PEvent::PeerConnected(peer_id.clone()));

        info!("Successfully connected to peer: {}", peer_id);
        Ok(peer_id)
    }

    /// Disconnect from a peer
    ///
    /// Actively closes the underlying QUIC connection via
    /// `P2pEndpoint::disconnect()` and removes the peer from all
    /// local tracking maps.
    pub async fn disconnect_peer(&self, peer_id: &PeerId) -> Result<()> {
        info!("Disconnecting from peer: {}", peer_id);

        // Close the actual QUIC connection so the remote side is notified
        // immediately rather than waiting for idle timeout.
        self.dual_node.disconnect_peer_string(peer_id).await.ok();

        // Remove from active connections
        self.active_connections.write().await.remove(peer_id);

        if let Some(mut peer_info) = self.peers.write().await.remove(peer_id) {
            peer_info.status = ConnectionStatus::Disconnected;

            // Emit event
            let _ = self
                .event_tx
                .send(P2PEvent::PeerDisconnected(peer_id.clone()));

            info!("Disconnected from peer: {}", peer_id);
        }

        Ok(())
    }

    /// Check if a connection to a peer is active
    pub async fn is_connection_active(&self, peer_id: &str) -> bool {
        self.active_connections.read().await.contains(peer_id)
    }

    /// Send a message to a peer
    pub async fn send_message(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        debug!(
            "Sending message to peer {} on protocol {}",
            peer_id, protocol
        );

        // Check rate limits if resource manager is enabled
        if let Some(ref resource_manager) = self.resource_manager
            && !resource_manager
                .check_rate_limit(peer_id, "message")
                .await?
        {
            return Err(P2PError::ResourceExhausted(
                format!("Rate limit exceeded for peer {}", peer_id).into(),
            ));
        }

        // Check if peer exists in peers map
        if !self.peers.read().await.contains_key(peer_id) {
            return Err(P2PError::Network(crate::error::NetworkError::PeerNotFound(
                peer_id.to_string().into(),
            )));
        }

        // Check if the ant-quic connection is actually active
        // This is the critical fix for the connection state synchronization issue
        if !self.is_connection_active(peer_id).await {
            // Clean up stale peer entry
            self.remove_peer(peer_id).await;

            return Err(P2PError::Network(
                crate::error::NetworkError::ConnectionClosed {
                    peer_id: peer_id.to_string().into(),
                },
            ));
        }

        // MCP removed: no special-case protocol validation

        // Record bandwidth usage if resource manager is enabled
        if let Some(ref resource_manager) = self.resource_manager {
            resource_manager.record_bandwidth(data.len() as u64, 0);
        }

        // Create protocol message wrapper
        let raw_data_len = data.len();
        let _message_data = self.create_protocol_message(protocol, data)?;
        info!(
            "Sending {} bytes to peer {} on protocol {} (raw data: {} bytes)",
            _message_data.len(),
            peer_id,
            protocol,
            raw_data_len
        );

        // Send via ant-quic dual-node using the raw endpoint send method.
        // This uses endpoint().send() which corresponds with endpoint().recv()
        // in the message receiving system.
        let send_fut = self
            .dual_node
            .send_to_peer_string_optimized(peer_id, &_message_data);
        let result = tokio::time::timeout(self.config.connection_timeout, send_fut)
            .await
            .map_err(|_| {
                P2PError::Transport(crate::error::TransportError::StreamError(
                    "Timed out sending message".into(),
                ))
            })?
            .map_err(|e| {
                P2PError::Transport(crate::error::TransportError::StreamError(
                    e.to_string().into(),
                ))
            });

        if result.is_ok() {
            info!(
                "Successfully sent {} bytes to peer {}",
                _message_data.len(),
                peer_id
            );
        } else {
            warn!("Failed to send message to peer {}", peer_id);
        }

        result
    }

    /// Create a protocol message wrapper
    fn create_protocol_message(&self, protocol: &str, data: Vec<u8>) -> Result<Vec<u8>> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| {
                P2PError::Network(NetworkError::ProtocolError(
                    format!("System time error: {}", e).into(),
                ))
            })?
            .as_secs();

        let message = WireMessage {
            protocol: protocol.to_string(),
            data,
            from: self.peer_id.clone(),
            timestamp,
        };

        postcard::to_stdvec(&message).map_err(|e| {
            P2PError::Transport(crate::error::TransportError::StreamError(
                format!("Failed to serialize message: {e}").into(),
            ))
        })
    }

    // Note: async listen_addrs() already exists above for fetching listen addresses
}

/// Parse a postcard-encoded protocol message into a `P2PEvent::Message`.
///
/// Returns `None` if the bytes cannot be deserialized as a valid `WireMessage`.
///
/// The `from` field is a required part of the wire protocol but is **not**
/// used as the event source. Instead, `source` — the transport-level peer ID
/// derived from the authenticated QUIC connection — is used so that consumers
/// can pass it directly to `send_message()`. This eliminates a spoofing
/// vector where a peer could claim an arbitrary identity via the payload.
///
/// Maximum allowed clock skew for message timestamps (5 minutes).
/// This is intentionally lenient for initial deployment to accommodate nodes with
/// misconfigured clocks or high-latency network conditions. Can be tightened (e.g., to 60s)
/// once the network stabilizes and node clock synchronization improves.
const MAX_MESSAGE_AGE_SECS: u64 = 300;
/// Maximum allowed future timestamp (30 seconds to account for clock drift)
const MAX_FUTURE_SECS: u64 = 30;

/// Helper to send an event via a broadcast sender, logging at trace level if no receivers.
fn broadcast_event(tx: &broadcast::Sender<P2PEvent>, event: P2PEvent) {
    if let Err(e) = tx.send(event) {
        tracing::trace!("Event broadcast has no receivers: {e}");
    }
}

fn parse_protocol_message(bytes: &[u8], source: &str) -> Option<P2PEvent> {
    let message: WireMessage = postcard::from_bytes(bytes).ok()?;

    // Validate timestamp to prevent replay attacks
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Reject messages that are too old (potential replay)
    if message.timestamp < now.saturating_sub(MAX_MESSAGE_AGE_SECS) {
        tracing::warn!(
            "Rejecting stale message from {} (timestamp {} is {} seconds old)",
            source,
            message.timestamp,
            now.saturating_sub(message.timestamp)
        );
        return None;
    }

    // Reject messages too far in the future (clock manipulation)
    if message.timestamp > now + MAX_FUTURE_SECS {
        tracing::warn!(
            "Rejecting future-dated message from {} (timestamp {} is {} seconds ahead)",
            source,
            message.timestamp,
            message.timestamp.saturating_sub(now)
        );
        return None;
    }

    debug!(
        "Parsed P2PEvent::Message - topic: {}, source: {} (logical: {}), payload_len: {}",
        message.protocol,
        source,
        message.from,
        message.data.len()
    );

    Some(P2PEvent::Message {
        topic: message.protocol,
        source: source.to_string(),
        data: message.data,
    })
}

impl P2PNode {
    /// Subscribe to network events
    pub fn subscribe_events(&self) -> broadcast::Receiver<P2PEvent> {
        self.event_tx.subscribe()
    }

    /// Backwards-compat event stream accessor for tests
    pub fn events(&self) -> broadcast::Receiver<P2PEvent> {
        self.subscribe_events()
    }

    /// Send an event to all subscribers, logging at trace level if no receivers are present.
    fn send_event(&self, event: P2PEvent) {
        if let Err(e) = self.event_tx.send(event) {
            tracing::trace!("Event broadcast has no receivers: {e}");
        }
    }

    /// Get node uptime
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    // MCP removed: all MCP tool/service methods removed

    // /// Handle MCP remote tool call with network integration

    // /// List tools available on a specific remote peer

    // /// Get MCP server statistics

    /// Get production resource metrics
    pub async fn resource_metrics(&self) -> Result<ResourceMetrics> {
        if let Some(ref resource_manager) = self.resource_manager {
            Ok(resource_manager.get_metrics().await)
        } else {
            Err(P2PError::Network(
                crate::error::NetworkError::ProtocolError(
                    "Production resource manager not enabled".to_string().into(),
                ),
            ))
        }
    }

    /// Connection lifecycle monitor task - processes ant-quic connection events
    /// and updates active_connections HashSet and peers map.
    ///
    /// This version accepts a pre-subscribed receiver to avoid the race condition
    /// where early connections could be missed if subscription happens after the task starts.
    #[allow(clippy::too_many_arguments)]
    async fn connection_lifecycle_monitor_with_rx(
        dual_node: Arc<DualStackNetworkNode>,
        mut event_rx: broadcast::Receiver<crate::transport::ant_quic_adapter::ConnectionEvent>,
        active_connections: Arc<RwLock<HashSet<String>>>,
        peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
        event_tx: broadcast::Sender<P2PEvent>,
        geo_provider: Arc<BgpGeoProvider>,
        _local_peer_id: String,
    ) {
        use crate::transport::ant_quic_adapter::ConnectionEvent;

        info!("Connection lifecycle monitor started (pre-subscribed receiver)");

        loop {
            match event_rx.recv().await {
                Ok(event) => {
                    match event {
                        ConnectionEvent::Established {
                            peer_id,
                            remote_address,
                        } => {
                            let peer_id_str = ant_peer_id_to_string(&peer_id);
                            debug!(
                                "Connection established: peer={}, addr={}",
                                peer_id_str, remote_address
                            );

                            // **GeoIP Validation**
                            let ip = remote_address.ip();
                            let is_rejected = match ip {
                                std::net::IpAddr::V4(v4) => {
                                    if let Some(asn) = geo_provider.lookup_ipv4_asn(v4) {
                                        geo_provider.is_hosting_asn(asn)
                                            || geo_provider.is_vpn_asn(asn)
                                    } else {
                                        false
                                    }
                                }
                                std::net::IpAddr::V6(v6) => {
                                    let info = geo_provider.lookup(v6);
                                    info.is_hosting_provider || info.is_vpn_provider
                                }
                            };

                            if is_rejected {
                                info!(
                                    "Rejecting connection from {} ({}) due to GeoIP policy",
                                    peer_id_str, remote_address
                                );
                                // Actively close the QUIC connection instead of
                                // leaking it until idle timeout
                                dual_node.disconnect_peer(&peer_id).await;
                                continue;
                            }

                            // Add to active connections
                            active_connections.write().await.insert(peer_id_str.clone());

                            // Update peer info or insert new
                            let mut peers_lock = peers.write().await;
                            if let Some(peer_info) = peers_lock.get_mut(&peer_id_str) {
                                peer_info.status = ConnectionStatus::Connected;
                                peer_info.connected_at = Instant::now();
                            } else {
                                debug!("Registering new incoming peer: {}", peer_id_str);
                                peers_lock.insert(
                                    peer_id_str.clone(),
                                    PeerInfo {
                                        peer_id: peer_id_str.clone(),
                                        addresses: vec![remote_address.to_string()],
                                        status: ConnectionStatus::Connected,
                                        last_seen: Instant::now(),
                                        connected_at: Instant::now(),
                                        protocols: Vec::new(),
                                        heartbeat_count: 0,
                                    },
                                );
                            }

                            // Broadcast connection event
                            broadcast_event(&event_tx, P2PEvent::PeerConnected(peer_id_str));
                        }
                        ConnectionEvent::Lost { peer_id, reason } => {
                            let peer_id_str = ant_peer_id_to_string(&peer_id);
                            debug!("Connection lost: peer={peer_id_str}, reason={reason}");

                            // Remove from active connections
                            active_connections.write().await.remove(&peer_id_str);

                            // Update peer info status
                            if let Some(peer_info) = peers.write().await.get_mut(&peer_id_str) {
                                peer_info.status = ConnectionStatus::Disconnected;
                                peer_info.last_seen = Instant::now();
                            }

                            // Broadcast disconnection event
                            broadcast_event(&event_tx, P2PEvent::PeerDisconnected(peer_id_str));
                        }
                        ConnectionEvent::Failed { peer_id, reason } => {
                            let peer_id_str = ant_peer_id_to_string(&peer_id);
                            debug!("Connection failed: peer={peer_id_str}, reason={reason}");

                            // Remove from active connections
                            active_connections.write().await.remove(&peer_id_str);

                            // Update peer info status
                            if let Some(peer_info) = peers.write().await.get_mut(&peer_id_str) {
                                peer_info.status = ConnectionStatus::Disconnected;
                                peer_info.last_seen = Instant::now();
                            }

                            // Broadcast disconnection event
                            broadcast_event(&event_tx, P2PEvent::PeerDisconnected(peer_id_str));
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(
                        "Connection event receiver lagged, skipped {} events",
                        skipped
                    );
                }
                Err(broadcast::error::RecvError::Closed) => {
                    info!("Connection event channel closed, stopping lifecycle monitor");
                    break;
                }
            }
        }
    }

    /// Start connection monitor (called after node initialization)
    async fn start_connection_monitor(&self) {
        // The monitor task is already spawned in new() with a temporary peers map
        // This method is a placeholder for future enhancements where we might
        // need to restart the monitor or provide it with updated references
        debug!("Connection monitor already running from initialization");
    }

    /// Keepalive task - sends periodic pings to prevent 30-second idle timeout
    ///
    /// ant-quic has a 30-second max_idle_timeout. This task sends a small keepalive
    /// message every 15 seconds (half the timeout) to all active connections to prevent
    /// them from timing out during periods of inactivity.
    async fn keepalive_task(
        active_connections: Arc<RwLock<HashSet<String>>>,
        dual_node: Arc<DualStackNetworkNode>,
        shutdown: Arc<AtomicBool>,
    ) {
        const KEEPALIVE_INTERVAL_SECS: u64 = 15; // Half of 30-second timeout

        let mut interval = interval(Duration::from_secs(KEEPALIVE_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!(
            "Keepalive task started (interval: {}s)",
            KEEPALIVE_INTERVAL_SECS
        );

        loop {
            // Check shutdown flag first
            if shutdown.load(Ordering::Relaxed) {
                info!("Keepalive task shutting down");
                break;
            }

            interval.tick().await;

            // Get snapshot of active connections
            let peers: Vec<String> = { active_connections.read().await.iter().cloned().collect() };

            if peers.is_empty() {
                trace!("Keepalive: no active connections");
                continue;
            }

            debug!("Sending keepalive to {} active connections", peers.len());

            // Send keepalives concurrently so one slow/stuck peer doesn't
            // delay keepalives to all others and cause cascading timeouts.
            let futs: Vec<_> = peers
                .into_iter()
                .map(|peer_id| {
                    let node = Arc::clone(&dual_node);
                    async move {
                        if let Err(e) = node
                            .send_to_peer_string_optimized(&peer_id, KEEPALIVE_PAYLOAD)
                            .await
                        {
                            debug!(
                                "Failed to send keepalive to peer {}: {} (connection may have closed)",
                                peer_id, e
                            );
                        } else {
                            trace!("Keepalive sent to peer: {}", peer_id);
                        }
                    }
                })
                .collect();
            futures::future::join_all(futs).await;
        }

        info!("Keepalive task stopped");
    }

    /// Periodic maintenance task - detects stale peers and removes them
    ///
    /// This task runs every 100ms and:
    /// 1. Detects peers that haven't been seen for longer than stale_threshold
    /// 2. Marks them as disconnected and emits PeerDisconnected events
    /// 3. Removes fully disconnected peers after cleanup_threshold (2x stale_threshold)
    async fn periodic_maintenance_task(
        peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
        active_connections: Arc<RwLock<HashSet<PeerId>>>,
        event_tx: broadcast::Sender<P2PEvent>,
        stale_threshold: Duration,
        shutdown: Arc<AtomicBool>,
    ) {
        let cleanup_threshold = stale_threshold * 2;
        let mut interval = interval(Duration::from_millis(100));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!(
            "Periodic maintenance task started (stale threshold: {:?})",
            stale_threshold
        );

        loop {
            interval.tick().await;

            if shutdown.load(Ordering::SeqCst) {
                break;
            }

            let now = Instant::now();
            let mut peers_to_remove: Vec<PeerId> = Vec::new();
            let mut peers_to_mark_disconnected: Vec<PeerId> = Vec::new();

            // Phase 1: Identify stale and disconnected peers
            {
                let peers_lock = peers.read().await;
                for (peer_id, peer_info) in peers_lock.iter() {
                    let elapsed = now.duration_since(peer_info.last_seen);

                    match &peer_info.status {
                        ConnectionStatus::Connected => {
                            if elapsed > stale_threshold {
                                debug!(
                                    peer_id = %peer_id,
                                    elapsed_secs = elapsed.as_secs(),
                                    "Peer went stale - marking for disconnection"
                                );
                                peers_to_mark_disconnected.push(peer_id.clone());
                            }
                        }
                        ConnectionStatus::Disconnected | ConnectionStatus::Failed(_) => {
                            if elapsed > cleanup_threshold {
                                trace!(
                                    peer_id = %peer_id,
                                    elapsed_secs = elapsed.as_secs(),
                                    "Removing disconnected peer from tracking"
                                );
                                peers_to_remove.push(peer_id.clone());
                            }
                        }
                        ConnectionStatus::Connecting | ConnectionStatus::Disconnecting => {
                            if elapsed > stale_threshold {
                                debug!(
                                    peer_id = %peer_id,
                                    status = ?peer_info.status,
                                    "Connection timed out in transitional state"
                                );
                                peers_to_mark_disconnected.push(peer_id.clone());
                            }
                        }
                    }
                }
            }

            // Phase 2: Mark stale peers as disconnected
            // Note: We do NOT reset last_seen here. The cleanup timer uses the original
            // last_seen timestamp, so disconnected peers are removed after cleanup_threshold
            // from when they were last actually seen, not from when they were marked disconnected.
            if !peers_to_mark_disconnected.is_empty() {
                let mut peers_lock = peers.write().await;
                for peer_id in &peers_to_mark_disconnected {
                    if let Some(peer_info) = peers_lock.get_mut(peer_id) {
                        peer_info.status = ConnectionStatus::Disconnected;
                    }
                }
            }

            // Phase 3: Remove from active_connections and emit events
            for peer_id in &peers_to_mark_disconnected {
                active_connections.write().await.remove(peer_id);
                broadcast_event(&event_tx, P2PEvent::PeerDisconnected(peer_id.clone()));
                info!(peer_id = %peer_id, "Stale peer disconnected");
            }

            // Phase 4: Remove fully cleaned up peers from tracking
            if !peers_to_remove.is_empty() {
                let mut peers_lock = peers.write().await;
                for peer_id in &peers_to_remove {
                    peers_lock.remove(peer_id);
                    trace!(peer_id = %peer_id, "Peer removed from tracking");
                }
            }
        }

        info!("Periodic maintenance task stopped");
    }

    /// Check system health
    pub async fn health_check(&self) -> Result<()> {
        if let Some(ref resource_manager) = self.resource_manager {
            resource_manager.health_check().await
        } else {
            // Basic health check without resource manager
            let peer_count = self.peer_count().await;
            if peer_count > self.config.max_connections {
                Err(P2PError::Network(
                    crate::error::NetworkError::ProtocolError(
                        format!("Too many connections: {peer_count}").into(),
                    ),
                ))
            } else {
                Ok(())
            }
        }
    }

    /// Get production configuration (if enabled)
    pub fn production_config(&self) -> Option<&ProductionConfig> {
        self.config.production_config.as_ref()
    }

    /// Check if production hardening is enabled
    pub fn is_production_mode(&self) -> bool {
        self.resource_manager.is_some()
    }

    /// Get DHT reference
    pub fn dht(&self) -> Option<&Arc<RwLock<DHT>>> {
        self.dht.as_ref()
    }

    /// Store a value in the local DHT
    ///
    /// This method stores data in the local DHT instance only. For network-wide
    /// replication across multiple nodes, use `DhtNetworkManager` instead,
    /// which owns a P2PNode for transport and coordinates replication.
    pub async fn dht_put(&self, key: crate::dht::Key, value: Vec<u8>) -> Result<()> {
        if let Some(ref dht) = self.dht {
            let mut dht_instance = dht.write().await;
            let dht_key = crate::dht::DhtKey::from_bytes(key);
            dht_instance.store(&dht_key, value).await.map_err(|e| {
                P2PError::Dht(crate::error::DhtError::StoreFailed(
                    format!("{:?}: {e}", key).into(),
                ))
            })?;

            Ok(())
        } else {
            Err(P2PError::Dht(crate::error::DhtError::RoutingError(
                "DHT not enabled".to_string().into(),
            )))
        }
    }

    /// Retrieve a value from the local DHT
    ///
    /// This method retrieves data from the local DHT instance only. For network-wide
    /// lookups across multiple nodes, use `DhtNetworkManager` instead,
    /// which owns a P2PNode for transport and coordinates distributed queries.
    pub async fn dht_get(&self, key: crate::dht::Key) -> Result<Option<Vec<u8>>> {
        if let Some(ref dht) = self.dht {
            let dht_instance = dht.read().await;
            let dht_key = crate::dht::DhtKey::from_bytes(key);
            let record_result = dht_instance.retrieve(&dht_key).await.map_err(|e| {
                P2PError::Dht(crate::error::DhtError::StoreFailed(
                    format!("Retrieve failed: {e}").into(),
                ))
            })?;

            Ok(record_result)
        } else {
            Err(P2PError::Dht(crate::error::DhtError::RoutingError(
                "DHT not enabled".to_string().into(),
            )))
        }
    }

    /// Add a discovered peer to the bootstrap cache
    pub async fn add_discovered_peer(&self, peer_id: PeerId, addresses: Vec<String>) -> Result<()> {
        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
            let manager = bootstrap_manager.write().await;
            let socket_addresses: Vec<std::net::SocketAddr> = addresses
                .iter()
                .filter_map(|addr| addr.parse().ok())
                .collect();
            let contact = ContactEntry::new(peer_id, socket_addresses);
            manager.add_contact(contact).await.map_err(|e| {
                P2PError::Network(crate::error::NetworkError::ProtocolError(
                    format!("Failed to add peer to bootstrap cache: {e}").into(),
                ))
            })?;
        }
        Ok(())
    }

    /// Update connection metrics for a peer in the bootstrap cache
    pub async fn update_peer_metrics(
        &self,
        peer_id: &PeerId,
        success: bool,
        latency_ms: Option<u64>,
        _error: Option<String>,
    ) -> Result<()> {
        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
            let manager = bootstrap_manager.write().await;

            // Create quality metrics based on the connection result
            let metrics = QualityMetrics {
                success_rate: if success { 1.0 } else { 0.0 },
                avg_latency_ms: latency_ms.unwrap_or(0) as f64,
                quality_score: if success { 0.8 } else { 0.2 }, // Initial score
                last_connection_attempt: chrono::Utc::now(),
                last_successful_connection: if success {
                    chrono::Utc::now()
                } else {
                    chrono::Utc::now() - chrono::Duration::hours(1)
                },
                uptime_score: 0.5,
            };

            manager
                .update_contact_metrics(peer_id, metrics)
                .await
                .map_err(|e| {
                    P2PError::Network(crate::error::NetworkError::ProtocolError(
                        format!("Failed to update peer metrics: {e}").into(),
                    ))
                })?;
        }
        Ok(())
    }

    /// Get bootstrap cache statistics
    pub async fn get_bootstrap_cache_stats(&self) -> Result<Option<crate::bootstrap::CacheStats>> {
        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
            let manager = bootstrap_manager.read().await;
            let stats = manager.get_stats().await.map_err(|e| {
                P2PError::Network(crate::error::NetworkError::ProtocolError(
                    format!("Failed to get bootstrap stats: {e}").into(),
                ))
            })?;
            Ok(Some(stats))
        } else {
            Ok(None)
        }
    }

    /// Get the number of cached bootstrap peers
    pub async fn cached_peer_count(&self) -> usize {
        if let Some(ref _bootstrap_manager) = self.bootstrap_manager
            && let Ok(Some(stats)) = self.get_bootstrap_cache_stats().await
        {
            return stats.total_contacts;
        }
        0
    }

    /// Discover peers from a connected bootstrap peer using FIND_NODE
    ///
    /// Sends a FIND_NODE request for our own peer ID to discover nearby peers
    /// and populate the routing table. This is the core of Kademlia peer discovery.
    async fn discover_peers_from(&self, peer_id: &PeerId) -> Result<usize> {
        use crate::dht::network_integration::DhtMessage;

        info!("Discovering peers from bootstrap peer: {}", peer_id);

        // Create our node ID as a DhtKey for the FIND_NODE query
        // We query for ourselves to find nodes closest to us
        let our_id_bytes = {
            use blake3::Hasher;
            let mut hasher = Hasher::new();
            hasher.update(self.peer_id.as_bytes());
            let digest = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(digest.as_bytes());
            bytes
        };
        let target_key = crate::dht::DhtKey::from_bytes(our_id_bytes);

        // Create FIND_NODE message
        let find_node_msg = DhtMessage::FindNode {
            target: target_key,
            count: 20, // Request up to 20 closest nodes
        };

        // Serialize the message
        let message_bytes = postcard::to_allocvec(&find_node_msg).map_err(|e| {
            P2PError::Network(NetworkError::ProtocolError(
                format!("Failed to serialize FIND_NODE message: {e}").into(),
            ))
        })?;

        // Send the FIND_NODE request
        self.send_message(peer_id, "/dht/1.0.0", message_bytes)
            .await?;

        // Note: Response handling is asynchronous through the message handler.
        // For now, we log the request and let the response handler populate
        // the routing table when it receives FindNodeReply.
        //
        // TODO: Implement request-response correlation with a timeout to get
        // actual discovered peer count. For now, return 0 to indicate we sent
        // the request but don't have immediate response data.

        info!("Sent FIND_NODE request to {} for peer discovery", peer_id);

        Ok(0) // Actual count would require awaiting the response
    }

    /// Connect to bootstrap peers and perform initial peer discovery
    async fn connect_bootstrap_peers(&self) -> Result<()> {
        let mut bootstrap_contacts = Vec::new();
        let mut used_cache = false;
        let mut seen_addresses = std::collections::HashSet::new();

        // CLI-provided bootstrap peers take priority - always include them first
        let cli_bootstrap_peers = if !self.config.bootstrap_peers_str.is_empty() {
            self.config.bootstrap_peers_str.clone()
        } else {
            // Convert Multiaddr to strings
            self.config
                .bootstrap_peers
                .iter()
                .map(|addr| addr.to_string())
                .collect::<Vec<_>>()
        };

        if !cli_bootstrap_peers.is_empty() {
            info!(
                "Using {} CLI-provided bootstrap peers (priority)",
                cli_bootstrap_peers.len()
            );
            for addr in &cli_bootstrap_peers {
                if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
                    seen_addresses.insert(socket_addr);
                    let contact = ContactEntry::new(
                        format!("cli_peer_{}", addr.chars().take(8).collect::<String>()),
                        vec![socket_addr],
                    );
                    bootstrap_contacts.push(contact);
                } else {
                    warn!("Invalid bootstrap address format: {}", addr);
                }
            }
        }

        // Supplement with cached bootstrap peers (after CLI peers)
        // Use QUIC-specific peer selection since we're using ant-quic transport
        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
            let manager = bootstrap_manager.read().await;
            match manager.get_quic_bootstrap_peers(20).await {
                // Try to get top 20 quality QUIC-enabled peers
                Ok(contacts) => {
                    if !contacts.is_empty() {
                        let mut added_from_cache = 0;
                        for contact in contacts {
                            // Only add if we haven't already added this address from CLI
                            let new_addresses: Vec<_> = contact
                                .addresses
                                .iter()
                                .filter(|addr| !seen_addresses.contains(addr))
                                .copied()
                                .collect();

                            if !new_addresses.is_empty() {
                                for addr in &new_addresses {
                                    seen_addresses.insert(*addr);
                                }
                                let mut contact = contact.clone();
                                contact.addresses = new_addresses;
                                bootstrap_contacts.push(contact);
                                added_from_cache += 1;
                            }
                        }
                        if added_from_cache > 0 {
                            info!(
                                "Added {} cached bootstrap peers (supplementing CLI peers)",
                                added_from_cache
                            );
                            used_cache = true;
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to get cached bootstrap peers: {}", e);
                }
            }
        }

        if bootstrap_contacts.is_empty() {
            info!("No bootstrap peers configured and no cached peers available");
            return Ok(());
        }

        // Connect to bootstrap peers and perform peer discovery
        let mut successful_connections = 0;
        let mut connected_peer_ids: Vec<PeerId> = Vec::new();

        for (contact_idx, contact) in bootstrap_contacts.iter().enumerate() {
            for (addr_idx, addr) in contact.addresses.iter().enumerate() {
                match self.connect_peer(&addr.to_string()).await {
                    Ok(peer_id) => {
                        successful_connections += 1;
                        connected_peer_ids.push(peer_id.clone());

                        // Update bootstrap cache with successful connection
                        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
                            let manager = bootstrap_manager.write().await;
                            let mut updated_contact = contact.clone();
                            updated_contact.peer_id = peer_id.clone();
                            updated_contact.update_connection_result(true, Some(100), None); // Assume 100ms latency for now

                            if let Err(e) = manager.add_contact(updated_contact).await {
                                warn!("Failed to update bootstrap cache: {}", e);
                            }
                        }
                        break; // Successfully connected, move to next contact
                    }
                    Err(e) => {
                        warn!("Failed to connect to bootstrap peer {}: {}", addr, e);

                        // Update bootstrap cache with failed connection
                        if used_cache && let Some(ref bootstrap_manager) = self.bootstrap_manager {
                            let manager = bootstrap_manager.write().await;
                            let mut updated_contact = contact.clone();
                            updated_contact.update_connection_result(
                                false,
                                None,
                                Some(e.to_string()),
                            );

                            if let Err(e) = manager.add_contact(updated_contact).await {
                                warn!("Failed to update bootstrap cache: {}", e);
                            }
                        }
                    }
                }
            }
        }

        if successful_connections == 0 {
            if !used_cache {
                warn!("Failed to connect to any bootstrap peers");
            }
            // Starting a node should not be gated on immediate bootstrap connectivity.
            // Keep running and allow background discovery / retries to populate peers later.
            return Ok(());
        }

        info!(
            "Successfully connected to {} bootstrap peers",
            successful_connections
        );

        // Perform peer discovery from connected bootstrap peers
        // Send FIND_NODE(self) to discover nearby peers and populate routing table
        for peer_id in &connected_peer_ids {
            match self.discover_peers_from(peer_id).await {
                Ok(_) => {
                    info!("Peer discovery initiated from bootstrap peer: {}", peer_id);
                }
                Err(e) => {
                    warn!("Failed to discover peers from {}: {}", peer_id, e);
                }
            }
        }

        // Mark node as bootstrapped - we have connected to bootstrap peers
        // and initiated peer discovery
        self.is_bootstrapped.store(true, Ordering::SeqCst);
        info!(
            "Bootstrap complete: connected to {} peers, initiated {} discovery requests",
            successful_connections,
            connected_peer_ids.len()
        );

        Ok(())
    }

    /// Disconnect from all peers
    async fn disconnect_all_peers(&self) -> Result<()> {
        let peer_ids: Vec<PeerId> = self.peers.read().await.keys().cloned().collect();

        for peer_id in peer_ids {
            self.disconnect_peer(&peer_id).await?;
        }

        Ok(())
    }

    /// Perform periodic maintenance tasks
    ///
    /// This function is called periodically (every 100ms) to:
    /// 1. Detect and remove stale peers (no activity for configured threshold)
    /// 2. Clean up disconnected peers from tracking structures
    /// 3. Emit PeerDisconnected events for removed peers
    async fn periodic_tasks(&self) -> Result<()> {
        // Stale peer threshold from config (default 60s, can be reduced for tests)
        let stale_threshold = self.config.stale_peer_threshold;
        // Cleanup threshold - disconnected peers are removed after 2x the stale threshold
        let cleanup_threshold = stale_threshold * 2;

        let now = Instant::now();
        let mut peers_to_remove: Vec<PeerId> = Vec::new();
        let mut peers_to_mark_disconnected: Vec<PeerId> = Vec::new();

        // Phase 1: Identify stale and disconnected peers
        {
            let peers = self.peers.read().await;
            for (peer_id, peer_info) in peers.iter() {
                let elapsed = now.duration_since(peer_info.last_seen);

                match &peer_info.status {
                    ConnectionStatus::Connected => {
                        // Check if connected peer has gone stale
                        if elapsed > stale_threshold {
                            debug!(
                                peer_id = %peer_id,
                                elapsed_secs = elapsed.as_secs(),
                                "Peer went stale - marking for disconnection"
                            );
                            peers_to_mark_disconnected.push(peer_id.clone());
                        }
                    }
                    ConnectionStatus::Disconnected | ConnectionStatus::Failed(_) => {
                        // Remove disconnected/failed peers after cleanup threshold
                        if elapsed > cleanup_threshold {
                            trace!(
                                peer_id = %peer_id,
                                elapsed_secs = elapsed.as_secs(),
                                "Removing disconnected peer from tracking"
                            );
                            peers_to_remove.push(peer_id.clone());
                        }
                    }
                    ConnectionStatus::Connecting | ConnectionStatus::Disconnecting => {
                        // Transitional states - check for timeout
                        if elapsed > stale_threshold {
                            debug!(
                                peer_id = %peer_id,
                                status = ?peer_info.status,
                                "Connection timed out in transitional state"
                            );
                            peers_to_mark_disconnected.push(peer_id.clone());
                        }
                    }
                }
            }
        }

        // Phase 2: Mark stale peers as disconnected
        if !peers_to_mark_disconnected.is_empty() {
            let mut peers = self.peers.write().await;
            for peer_id in &peers_to_mark_disconnected {
                if let Some(peer_info) = peers.get_mut(peer_id) {
                    peer_info.status = ConnectionStatus::Disconnected;
                    // Preserve last_seen timestamp for cleanup logic
                }
            }
        }

        // Phase 3: Remove from active_connections and emit events for disconnected peers
        for peer_id in &peers_to_mark_disconnected {
            // Remove from active connections set
            self.active_connections.write().await.remove(peer_id);

            // Broadcast disconnection event
            let _ = self
                .event_tx
                .send(P2PEvent::PeerDisconnected(peer_id.clone()));

            info!(
                peer_id = %peer_id,
                "Stale peer disconnected"
            );
        }

        // Phase 4: Remove fully cleaned up peers from tracking
        if !peers_to_remove.is_empty() {
            let mut peers = self.peers.write().await;
            for peer_id in &peers_to_remove {
                peers.remove(peer_id);
                trace!(peer_id = %peer_id, "Peer removed from tracking");
            }
        }

        Ok(())
    }
}

/// Network sender trait for sending messages
#[async_trait::async_trait]
pub trait NetworkSender: Send + Sync {
    /// Send a message to a specific peer
    async fn send_message(&self, peer_id: &PeerId, protocol: &str, data: Vec<u8>) -> Result<()>;

    /// Get our local peer ID
    fn local_peer_id(&self) -> &PeerId;
}

/// Lightweight wrapper for P2PNode to implement NetworkSender
#[derive(Clone)]
pub struct P2PNetworkSender {
    peer_id: PeerId,
    // Use channels for async communication with the P2P node
    send_tx: tokio::sync::mpsc::UnboundedSender<(PeerId, String, Vec<u8>)>,
}

impl P2PNetworkSender {
    pub fn new(
        peer_id: PeerId,
        send_tx: tokio::sync::mpsc::UnboundedSender<(PeerId, String, Vec<u8>)>,
    ) -> Self {
        Self { peer_id, send_tx }
    }
}

/// Implementation of NetworkSender trait for P2PNetworkSender
#[async_trait::async_trait]
impl NetworkSender for P2PNetworkSender {
    /// Send a message to a specific peer via the P2P network
    async fn send_message(&self, peer_id: &PeerId, protocol: &str, data: Vec<u8>) -> Result<()> {
        self.send_tx
            .send((peer_id.clone(), protocol.to_string(), data))
            .map_err(|_| {
                P2PError::Network(crate::error::NetworkError::ProtocolError(
                    "Failed to send message via channel".to_string().into(),
                ))
            })?;
        Ok(())
    }

    /// Get our local peer ID
    fn local_peer_id(&self) -> &PeerId {
        &self.peer_id
    }
}

/// Builder pattern for creating P2P nodes
pub struct NodeBuilder {
    config: NodeConfig,
}

impl Default for NodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeBuilder {
    /// Create a new node builder
    pub fn new() -> Self {
        Self {
            config: NodeConfig::default(),
        }
    }

    /// Set the peer ID
    pub fn with_peer_id(mut self, peer_id: PeerId) -> Self {
        self.config.peer_id = Some(peer_id);
        self
    }

    /// Add a listen address
    pub fn listen_on(mut self, addr: &str) -> Self {
        if let Ok(multiaddr) = addr.parse() {
            self.config.listen_addrs.push(multiaddr);
        }
        self
    }

    /// Add a bootstrap peer
    pub fn with_bootstrap_peer(mut self, addr: &str) -> Self {
        if let Ok(multiaddr) = addr.parse() {
            self.config.bootstrap_peers.push(multiaddr);
        }
        self.config.bootstrap_peers_str.push(addr.to_string());
        self
    }

    /// Enable IPv6 support
    pub fn with_ipv6(mut self, enable: bool) -> Self {
        self.config.enable_ipv6 = enable;
        self
    }

    // MCP removed: builder methods deleted

    /// Set connection timeout
    pub fn with_connection_timeout(mut self, timeout: Duration) -> Self {
        self.config.connection_timeout = timeout;
        self
    }

    /// Set maximum connections
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.config.max_connections = max;
        self
    }

    /// Enable production mode with default configuration
    pub fn with_production_mode(mut self) -> Self {
        self.config.production_config = Some(ProductionConfig::default());
        self
    }

    /// Configure production settings
    pub fn with_production_config(mut self, production_config: ProductionConfig) -> Self {
        self.config.production_config = Some(production_config);
        self
    }

    /// Configure IP diversity limits for Sybil protection.
    pub fn with_diversity_config(
        mut self,
        diversity_config: crate::security::IPDiversityConfig,
    ) -> Self {
        self.config.diversity_config = Some(diversity_config);
        self
    }

    /// Configure DHT settings
    pub fn with_dht(mut self, dht_config: DHTConfig) -> Self {
        self.config.dht_config = dht_config;
        self
    }

    /// Enable DHT with default configuration
    pub fn with_default_dht(mut self) -> Self {
        self.config.dht_config = DHTConfig::default();
        self
    }

    /// Build the P2P node
    pub async fn build(self) -> Result<P2PNode> {
        P2PNode::new(self.config).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod diversity_tests {
    use super::*;
    use crate::security::IPDiversityConfig;

    async fn build_bootstrap_manager_like_prod(config: &NodeConfig) -> BootstrapManager {
        let diversity_config = config.diversity_config.clone().unwrap_or_default();
        // Use a temp dir to avoid conflicts with cached files from old format
        let temp_dir = tempfile::TempDir::new().expect("temp dir");
        let mut cache_config = config.bootstrap_cache_config.clone().unwrap_or_default();
        cache_config.cache_dir = temp_dir.path().to_path_buf();

        BootstrapManager::with_full_config(
            cache_config,
            crate::rate_limit::JoinRateLimiterConfig::default(),
            diversity_config,
        )
        .await
        .expect("bootstrap manager")
    }

    #[tokio::test]
    async fn test_nodeconfig_diversity_config_used_for_bootstrap() {
        let config = NodeConfig {
            diversity_config: Some(IPDiversityConfig::testnet()),
            ..Default::default()
        };

        let manager = build_bootstrap_manager_like_prod(&config).await;
        assert!(manager.diversity_config().is_relaxed());
        assert_eq!(manager.diversity_config().max_nodes_per_asn, 5000);
    }
}

/// Helper function to register a new peer
async fn register_new_peer(
    peers: &Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    peer_id: &PeerId,
    remote_addr: &NetworkAddress,
) {
    let mut peers_guard = peers.write().await;
    let peer_info = PeerInfo {
        peer_id: peer_id.clone(),
        addresses: vec![remote_addr.to_string()],
        connected_at: tokio::time::Instant::now(),
        last_seen: tokio::time::Instant::now(),
        status: ConnectionStatus::Connected,
        protocols: vec!["p2p-core/1.0.0".to_string()],
        heartbeat_count: 0,
    };
    peers_guard.insert(peer_id.clone(), peer_info);
}

#[cfg(test)]
mod tests {
    use super::*;
    // MCP removed from tests
    use std::time::Duration;
    use tokio::time::timeout;

    // Test tool handler for network tests

    // MCP removed

    /// Helper function to create a test node configuration
    fn create_test_node_config() -> NodeConfig {
        NodeConfig {
            peer_id: Some("test_peer_123".to_string()),
            listen_addrs: vec![
                std::net::SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 0),
                std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0),
            ],
            listen_addr: std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                0,
            ),
            bootstrap_peers: vec![],
            bootstrap_peers_str: vec![],
            enable_ipv6: true,

            connection_timeout: Duration::from_secs(2),
            keep_alive_interval: Duration::from_secs(30),
            max_connections: 100,
            max_incoming_connections: 50,
            dht_config: DHTConfig::default(),
            security_config: SecurityConfig::default(),
            production_config: None,
            bootstrap_cache_config: None,
            diversity_config: None,
            stale_peer_threshold: default_stale_peer_threshold(),
        }
    }

    /// Helper function to create a test tool
    // MCP removed: test tool helper deleted

    #[tokio::test]
    async fn test_node_config_default() {
        let config = NodeConfig::default();

        assert!(config.peer_id.is_none());
        assert_eq!(config.listen_addrs.len(), 2);
        assert!(config.enable_ipv6);
        assert_eq!(config.max_connections, 10000); // Fixed: matches actual default
        assert_eq!(config.max_incoming_connections, 100);
        assert_eq!(config.connection_timeout, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_dht_config_default() {
        let config = DHTConfig::default();

        assert_eq!(config.k_value, 20);
        assert_eq!(config.alpha_value, 5);
        assert_eq!(config.record_ttl, Duration::from_secs(3600));
        assert_eq!(config.refresh_interval, Duration::from_secs(600));
    }

    #[tokio::test]
    async fn test_security_config_default() {
        let config = SecurityConfig::default();

        assert!(config.enable_noise);
        assert!(config.enable_tls);
        assert_eq!(config.trust_level, TrustLevel::Basic);
    }

    #[test]
    fn test_trust_level_variants() {
        // Test that all trust level variants can be created
        let _none = TrustLevel::None;
        let _basic = TrustLevel::Basic;
        let _full = TrustLevel::Full;

        // Test equality
        assert_eq!(TrustLevel::None, TrustLevel::None);
        assert_eq!(TrustLevel::Basic, TrustLevel::Basic);
        assert_eq!(TrustLevel::Full, TrustLevel::Full);
        assert_ne!(TrustLevel::None, TrustLevel::Basic);
    }

    #[test]
    fn test_connection_status_variants() {
        let connecting = ConnectionStatus::Connecting;
        let connected = ConnectionStatus::Connected;
        let disconnecting = ConnectionStatus::Disconnecting;
        let disconnected = ConnectionStatus::Disconnected;
        let failed = ConnectionStatus::Failed("test error".to_string());

        assert_eq!(connecting, ConnectionStatus::Connecting);
        assert_eq!(connected, ConnectionStatus::Connected);
        assert_eq!(disconnecting, ConnectionStatus::Disconnecting);
        assert_eq!(disconnected, ConnectionStatus::Disconnected);
        assert_ne!(connecting, connected);

        if let ConnectionStatus::Failed(msg) = failed {
            assert_eq!(msg, "test error");
        } else {
            panic!("Expected Failed status");
        }
    }

    #[tokio::test]
    async fn test_node_creation() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        assert_eq!(node.peer_id(), "test_peer_123");
        assert!(!node.is_running().await);
        assert_eq!(node.peer_count().await, 0);
        assert!(node.connected_peers().await.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_node_creation_without_peer_id() -> Result<()> {
        let mut config = create_test_node_config();
        config.peer_id = None;

        let node = P2PNode::new(config).await?;

        // Should have generated a peer ID
        assert!(node.peer_id().starts_with("peer_"));
        assert!(!node.is_running().await);

        Ok(())
    }

    #[tokio::test]
    async fn test_node_lifecycle() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Initially not running
        assert!(!node.is_running().await);

        // Start the node
        node.start().await?;
        assert!(node.is_running().await);

        // Check listen addresses were set (at least one)
        let listen_addrs = node.listen_addrs().await;
        assert!(
            !listen_addrs.is_empty(),
            "Expected at least one listening address"
        );

        // Stop the node
        node.stop().await?;
        assert!(!node.is_running().await);

        Ok(())
    }

    #[tokio::test]
    async fn test_peer_connection() -> Result<()> {
        let config1 = create_test_node_config();
        let mut config2 = create_test_node_config();
        config2.peer_id = Some("test_peer_456".to_string());

        let node1 = P2PNode::new(config1).await?;
        let node2 = P2PNode::new(config2).await?;

        node1.start().await?;
        node2.start().await?;

        let node2_addr = node2
            .listen_addrs()
            .await
            .into_iter()
            .find(|a| a.ip().is_ipv4())
            .ok_or_else(|| {
                P2PError::Network(crate::error::NetworkError::InvalidAddress(
                    "Node 2 did not expose an IPv4 listen address".into(),
                ))
            })?;

        // Connect to a real peer
        let peer_id = node1.connect_peer(&node2_addr.to_string()).await?;

        // Check peer count
        assert_eq!(node1.peer_count().await, 1);

        // Check connected peers
        let connected_peers = node1.connected_peers().await;
        assert_eq!(connected_peers.len(), 1);
        assert_eq!(connected_peers[0], peer_id);

        // Get peer info
        let peer_info = node1.peer_info(&peer_id).await;
        assert!(peer_info.is_some());
        let info = peer_info.expect("Peer info should exist after adding peer");
        assert_eq!(info.peer_id, peer_id);
        assert_eq!(info.status, ConnectionStatus::Connected);
        assert!(info.protocols.contains(&"p2p-foundation/1.0".to_string()));

        // Disconnect from peer
        node1.disconnect_peer(&peer_id).await?;
        assert_eq!(node1.peer_count().await, 0);

        node1.stop().await?;
        node2.stop().await?;

        Ok(())
    }

    // TODO(windows): Investigate QUIC connection issues on Windows CI
    // This test consistently fails on Windows GitHub Actions runners with
    // "All connect attempts failed" even with IPv4-only config, long delays,
    // and multiple retry attempts. The underlying ant-quic library may have
    // issues on Windows that need investigation.
    // See: https://github.com/dirvine/saorsa-core/issues/TBD
    #[cfg_attr(target_os = "windows", ignore)]
    #[tokio::test]
    async fn test_event_subscription() -> Result<()> {
        // Configure both nodes to use only IPv4 for reliable cross-platform testing
        // This is important because:
        // 1. local_addr() returns the first address from listen_addrs
        // 2. The default config puts IPv6 first, which may not work on all Windows setups
        let ipv4_localhost =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);

        let mut config1 = create_test_node_config();
        config1.listen_addr = ipv4_localhost;
        config1.listen_addrs = vec![ipv4_localhost];
        config1.enable_ipv6 = false;

        let mut config2 = create_test_node_config();
        config2.peer_id = Some("test_peer_456".to_string());
        config2.listen_addr = ipv4_localhost;
        config2.listen_addrs = vec![ipv4_localhost];
        config2.enable_ipv6 = false;

        let node1 = P2PNode::new(config1).await?;
        let node2 = P2PNode::new(config2).await?;

        node1.start().await?;
        node2.start().await?;

        // Wait for nodes to fully bind their listening sockets
        // Windows network stack initialization can be significantly slower
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        let mut events = node1.subscribe_events();

        // Get the actual listening address using local_addr() for reliability
        let node2_addr = node2.local_addr().ok_or_else(|| {
            P2PError::Network(crate::error::NetworkError::ProtocolError(
                "No listening address".to_string().into(),
            ))
        })?;

        // Connect to a peer with retry logic for Windows reliability
        // The QUIC library may need additional time to fully initialize
        let mut peer_id = None;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            }
            match timeout(Duration::from_secs(2), node1.connect_peer(&node2_addr)).await {
                Ok(Ok(id)) => {
                    peer_id = Some(id);
                    break;
                }
                Ok(Err(_)) | Err(_) => continue,
            }
        }
        let peer_id = peer_id.ok_or_else(|| {
            P2PError::Network(crate::error::NetworkError::ProtocolError(
                "Failed to connect after 3 attempts".to_string().into(),
            ))
        })?;

        // Check for PeerConnected event
        let event = timeout(Duration::from_secs(2), events.recv()).await;
        assert!(event.is_ok());

        let event_result = event
            .expect("Should receive event")
            .expect("Event should not be error");
        match event_result {
            P2PEvent::PeerConnected(event_peer_id) => {
                assert_eq!(event_peer_id, peer_id);
            }
            _ => panic!("Expected PeerConnected event"),
        }

        // Disconnect from peer (this should emit another event)
        node1.disconnect_peer(&peer_id).await?;

        // Check for PeerDisconnected event
        let event = timeout(Duration::from_secs(2), events.recv()).await;
        assert!(event.is_ok());

        let event_result = event
            .expect("Should receive event")
            .expect("Event should not be error");
        match event_result {
            P2PEvent::PeerDisconnected(event_peer_id) => {
                assert_eq!(event_peer_id, peer_id);
            }
            _ => panic!("Expected PeerDisconnected event"),
        }

        node1.stop().await?;
        node2.stop().await?;

        Ok(())
    }

    // TODO(windows): Same QUIC connection issues as test_event_subscription
    #[cfg_attr(target_os = "windows", ignore)]
    #[tokio::test]
    async fn test_message_sending() -> Result<()> {
        // Create two nodes
        let mut config1 = create_test_node_config();
        config1.listen_addr =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
        let node1 = P2PNode::new(config1).await?;
        node1.start().await?;

        let mut config2 = create_test_node_config();
        config2.listen_addr =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
        let node2 = P2PNode::new(config2).await?;
        node2.start().await?;

        // Wait a bit for nodes to start listening
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Get actual listening address of node2
        let node2_addr = node2.local_addr().ok_or_else(|| {
            P2PError::Network(crate::error::NetworkError::ProtocolError(
                "No listening address".to_string().into(),
            ))
        })?;

        // Connect node1 to node2
        let peer_id =
            match timeout(Duration::from_millis(500), node1.connect_peer(&node2_addr)).await {
                Ok(res) => res?,
                Err(_) => return Err(P2PError::Network(NetworkError::Timeout)),
            };

        // Wait a bit for connection to establish
        tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

        // Send a message
        let message_data = b"Hello, peer!".to_vec();
        let result = match timeout(
            Duration::from_millis(500),
            node1.send_message(&peer_id, "test-protocol", message_data),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => return Err(P2PError::Network(NetworkError::Timeout)),
        };
        // For now, we'll just check that we don't get a "not connected" error
        // The actual send might fail due to no handler on the other side
        if let Err(e) = &result {
            assert!(!e.to_string().contains("not connected"), "Got error: {}", e);
        }

        // Try to send to non-existent peer
        let non_existent_peer = "non_existent_peer".to_string();
        let result = node1
            .send_message(&non_existent_peer, "test-protocol", vec![])
            .await;
        assert!(result.is_err(), "Sending to non-existent peer should fail");

        Ok(())
    }

    #[tokio::test]
    async fn test_remote_mcp_operations() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // MCP removed; test reduced to simple start/stop
        node.start().await?;
        node.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_health_check() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Health check should pass with no connections
        let result = node.health_check().await;
        assert!(result.is_ok());

        // Note: We're not actually connecting to real peers here
        // since that would require running bootstrap nodes.
        // The health check should still pass with no connections.

        Ok(())
    }

    #[tokio::test]
    async fn test_node_uptime() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        let uptime1 = node.uptime();
        assert!(uptime1 >= Duration::from_secs(0));

        // Wait a bit
        tokio::time::sleep(Duration::from_millis(10)).await;

        let uptime2 = node.uptime();
        assert!(uptime2 > uptime1);

        Ok(())
    }

    #[tokio::test]
    async fn test_node_config_access() -> Result<()> {
        let config = create_test_node_config();
        let expected_peer_id = config.peer_id.clone();
        let node = P2PNode::new(config).await?;

        let node_config = node.config();
        assert_eq!(node_config.peer_id, expected_peer_id);
        assert_eq!(node_config.max_connections, 100);
        // MCP removed

        Ok(())
    }

    #[tokio::test]
    async fn test_mcp_server_access() -> Result<()> {
        let config = create_test_node_config();
        let _node = P2PNode::new(config).await?;

        // MCP removed
        Ok(())
    }

    #[tokio::test]
    async fn test_dht_access() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Should have DHT
        assert!(node.dht().is_some());

        Ok(())
    }

    #[tokio::test]
    async fn test_node_builder() -> Result<()> {
        // Create a config using the builder but don't actually build a real node
        let builder = P2PNode::builder()
            .with_peer_id("builder_test_peer".to_string())
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .listen_on("/ip6/::1/tcp/0")
            .with_bootstrap_peer("/ip4/127.0.0.1/tcp/9000") // Use a valid port number
            .with_ipv6(true)
            .with_connection_timeout(Duration::from_secs(15))
            .with_max_connections(200);

        // Test the configuration that was built
        let config = builder.config;
        assert_eq!(config.peer_id, Some("builder_test_peer".to_string()));
        assert_eq!(config.listen_addrs.len(), 2); // 2 added by builder (no defaults)
        assert_eq!(config.bootstrap_peers_str.len(), 1); // Check bootstrap_peers_str instead
        assert!(config.enable_ipv6);
        assert_eq!(config.connection_timeout, Duration::from_secs(15));
        assert_eq!(config.max_connections, 200);

        Ok(())
    }

    #[tokio::test]
    async fn test_bootstrap_peers() -> Result<()> {
        let mut config = create_test_node_config();
        config.bootstrap_peers = vec![
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9200),
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9201),
        ];

        let node = P2PNode::new(config).await?;

        // Start node (which attempts to connect to bootstrap peers)
        node.start().await?;

        // In a test environment, bootstrap peers may not be available
        // The test verifies the node starts correctly with bootstrap configuration
        // Peer count may include local/internal tracking, so we just verify it's reasonable
        let _peer_count = node.peer_count().await;

        node.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_production_mode_disabled() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        assert!(!node.is_production_mode());
        assert!(node.production_config().is_none());

        // Resource metrics should fail when production mode is disabled
        let result = node.resource_metrics().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not enabled"));

        Ok(())
    }

    #[tokio::test]
    async fn test_network_event_variants() {
        // Test that all network event variants can be created
        let peer_id = "test_peer".to_string();
        let address = "/ip4/127.0.0.1/tcp/9000".to_string();

        let _peer_connected = NetworkEvent::PeerConnected {
            peer_id: peer_id.clone(),
            addresses: vec![address.clone()],
        };

        let _peer_disconnected = NetworkEvent::PeerDisconnected {
            peer_id: peer_id.clone(),
            reason: "test disconnect".to_string(),
        };

        let _message_received = NetworkEvent::MessageReceived {
            peer_id: peer_id.clone(),
            protocol: "test-protocol".to_string(),
            data: vec![1, 2, 3],
        };

        let _connection_failed = NetworkEvent::ConnectionFailed {
            peer_id: Some(peer_id.clone()),
            address: address.clone(),
            error: "connection refused".to_string(),
        };

        let _dht_stored = NetworkEvent::DHTRecordStored {
            key: vec![1, 2, 3],
            value: vec![4, 5, 6],
        };

        let _dht_retrieved = NetworkEvent::DHTRecordRetrieved {
            key: vec![1, 2, 3],
            value: Some(vec![4, 5, 6]),
        };
    }

    #[tokio::test]
    async fn test_peer_info_structure() {
        let peer_info = PeerInfo {
            peer_id: "test_peer".to_string(),
            addresses: vec!["/ip4/127.0.0.1/tcp/9000".to_string()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        assert_eq!(peer_info.peer_id, "test_peer");
        assert_eq!(peer_info.addresses.len(), 1);
        assert_eq!(peer_info.status, ConnectionStatus::Connected);
        assert_eq!(peer_info.protocols.len(), 1);
    }

    #[tokio::test]
    async fn test_serialization() -> Result<()> {
        // Test that configs can be serialized/deserialized
        let config = create_test_node_config();
        let serialized = serde_json::to_string(&config)?;
        let deserialized: NodeConfig = serde_json::from_str(&serialized)?;

        assert_eq!(config.peer_id, deserialized.peer_id);
        assert_eq!(config.listen_addrs, deserialized.listen_addrs);
        assert_eq!(config.enable_ipv6, deserialized.enable_ipv6);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_peer_id_by_address_found() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Manually insert a peer for testing
        let test_peer_id = "peer_test_123".to_string();
        let test_address = "192.168.1.100:9000".to_string();

        let peer_info = PeerInfo {
            peer_id: test_peer_id.clone(),
            addresses: vec![test_address.clone()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        node.peers
            .write()
            .await
            .insert(test_peer_id.clone(), peer_info);

        // Test: Find peer by address
        let found_peer_id = node.get_peer_id_by_address(&test_address).await;
        assert_eq!(found_peer_id, Some(test_peer_id));

        Ok(())
    }

    #[tokio::test]
    async fn test_get_peer_id_by_address_not_found() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Test: Try to find a peer that doesn't exist
        let result = node.get_peer_id_by_address("192.168.1.200:9000").await;
        assert_eq!(result, None);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_peer_id_by_address_invalid_format() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Test: Invalid address format should return None
        let result = node.get_peer_id_by_address("invalid-address").await;
        assert_eq!(result, None);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_peer_id_by_address_multiple_peers() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Add multiple peers with different addresses
        let peer1_id = "peer_1".to_string();
        let peer1_addr = "192.168.1.101:9001".to_string();

        let peer2_id = "peer_2".to_string();
        let peer2_addr = "192.168.1.102:9002".to_string();

        let peer1_info = PeerInfo {
            peer_id: peer1_id.clone(),
            addresses: vec![peer1_addr.clone()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        let peer2_info = PeerInfo {
            peer_id: peer2_id.clone(),
            addresses: vec![peer2_addr.clone()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        node.peers
            .write()
            .await
            .insert(peer1_id.clone(), peer1_info);
        node.peers
            .write()
            .await
            .insert(peer2_id.clone(), peer2_info);

        // Test: Find each peer by their unique address
        let found_peer1 = node.get_peer_id_by_address(&peer1_addr).await;
        let found_peer2 = node.get_peer_id_by_address(&peer2_addr).await;

        assert_eq!(found_peer1, Some(peer1_id));
        assert_eq!(found_peer2, Some(peer2_id));

        Ok(())
    }

    #[tokio::test]
    async fn test_list_active_connections_empty() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Test: No connections initially
        let connections = node.list_active_connections().await;
        assert!(connections.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_list_active_connections_with_peers() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Add multiple peers
        let peer1_id = "peer_1".to_string();
        let peer1_addrs = vec![
            "192.168.1.101:9001".to_string(),
            "192.168.1.101:9002".to_string(),
        ];

        let peer2_id = "peer_2".to_string();
        let peer2_addrs = vec!["192.168.1.102:9003".to_string()];

        let peer1_info = PeerInfo {
            peer_id: peer1_id.clone(),
            addresses: peer1_addrs.clone(),
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        let peer2_info = PeerInfo {
            peer_id: peer2_id.clone(),
            addresses: peer2_addrs.clone(),
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        node.peers
            .write()
            .await
            .insert(peer1_id.clone(), peer1_info);
        node.peers
            .write()
            .await
            .insert(peer2_id.clone(), peer2_info);

        // Also add to active_connections (list_active_connections iterates over this)
        node.active_connections
            .write()
            .await
            .insert(peer1_id.clone());
        node.active_connections
            .write()
            .await
            .insert(peer2_id.clone());

        // Test: List all active connections
        let connections = node.list_active_connections().await;
        assert_eq!(connections.len(), 2);

        // Verify peer1 and peer2 are in the list
        let peer1_conn = connections.iter().find(|(id, _)| id == &peer1_id);
        let peer2_conn = connections.iter().find(|(id, _)| id == &peer2_id);

        assert!(peer1_conn.is_some());
        assert!(peer2_conn.is_some());

        // Verify addresses match
        assert_eq!(peer1_conn.unwrap().1, peer1_addrs);
        assert_eq!(peer2_conn.unwrap().1, peer2_addrs);

        Ok(())
    }

    #[tokio::test]
    async fn test_remove_peer_success() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Add a peer
        let peer_id = "peer_to_remove".to_string();
        let peer_info = PeerInfo {
            peer_id: peer_id.clone(),
            addresses: vec!["192.168.1.100:9000".to_string()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        node.peers.write().await.insert(peer_id.clone(), peer_info);

        // Verify peer exists
        assert!(node.is_peer_connected(&peer_id).await);

        // Remove the peer
        let removed = node.remove_peer(&peer_id).await;
        assert!(removed);

        // Verify peer no longer exists
        assert!(!node.is_peer_connected(&peer_id).await);

        Ok(())
    }

    #[tokio::test]
    async fn test_remove_peer_nonexistent() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Try to remove a peer that doesn't exist
        let removed = node.remove_peer(&"nonexistent_peer".to_string()).await;
        assert!(!removed);

        Ok(())
    }

    #[tokio::test]
    async fn test_is_peer_connected() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        let peer_id = "test_peer".to_string();

        // Initially not connected
        assert!(!node.is_peer_connected(&peer_id).await);

        // Add peer
        let peer_info = PeerInfo {
            peer_id: peer_id.clone(),
            addresses: vec!["192.168.1.100:9000".to_string()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        node.peers.write().await.insert(peer_id.clone(), peer_info);

        // Now connected
        assert!(node.is_peer_connected(&peer_id).await);

        // Remove peer
        node.remove_peer(&peer_id).await;

        // No longer connected
        assert!(!node.is_peer_connected(&peer_id).await);

        Ok(())
    }

    #[test]
    fn test_normalize_ipv6_wildcard() {
        use std::net::{IpAddr, Ipv6Addr, SocketAddr};

        let wildcard = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 8080);
        let normalized = normalize_wildcard_to_loopback(wildcard);

        assert_eq!(normalized.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(normalized.port(), 8080);
    }

    #[test]
    fn test_normalize_ipv4_wildcard() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let wildcard = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000);
        let normalized = normalize_wildcard_to_loopback(wildcard);

        assert_eq!(normalized.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(normalized.port(), 9000);
    }

    #[test]
    fn test_normalize_specific_address_unchanged() {
        let specific: std::net::SocketAddr = "192.168.1.100:3000".parse().unwrap();
        let normalized = normalize_wildcard_to_loopback(specific);

        assert_eq!(normalized, specific);
    }

    #[test]
    fn test_normalize_loopback_unchanged() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

        let loopback_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5000);
        let normalized_v6 = normalize_wildcard_to_loopback(loopback_v6);
        assert_eq!(normalized_v6, loopback_v6);

        let loopback_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        let normalized_v4 = normalize_wildcard_to_loopback(loopback_v4);
        assert_eq!(normalized_v4, loopback_v4);
    }

    // ---- parse_protocol_message regression tests ----

    /// Get current Unix timestamp for tests
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Helper to create a postcard-serialized WireMessage for tests
    fn make_wire_bytes(protocol: &str, data: Vec<u8>, from: &str, timestamp: u64) -> Vec<u8> {
        let msg = WireMessage {
            protocol: protocol.to_string(),
            data,
            from: from.to_string(),
            timestamp,
        };
        postcard::to_stdvec(&msg).unwrap()
    }

    #[test]
    fn test_parse_protocol_message_uses_transport_peer_id_as_source() {
        // Regression: P2PEvent::Message.source must be the transport peer ID,
        // NOT the "from" field from the wire message.  This ensures consumers
        // can pass source directly to send_message().
        let transport_id = "abcdef0123456789";
        let logical_id = "spoofed-logical-id";
        let bytes = make_wire_bytes("test/v1", vec![1, 2, 3], logical_id, current_timestamp());

        let event =
            parse_protocol_message(&bytes, transport_id).expect("valid message should parse");

        match event {
            P2PEvent::Message {
                topic,
                source,
                data,
            } => {
                assert_eq!(source, transport_id, "source must be the transport peer ID");
                assert_ne!(
                    source, logical_id,
                    "source must NOT be the logical 'from' field"
                );
                assert_eq!(topic, "test/v1");
                assert_eq!(data, vec![1u8, 2, 3]);
            }
            other => panic!("expected P2PEvent::Message, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_protocol_message_rejects_invalid_bytes() {
        // Random bytes that are not valid bincode should be rejected
        assert!(parse_protocol_message(b"not valid bincode", "peer-id").is_none());
    }

    #[test]
    fn test_parse_protocol_message_rejects_truncated_message() {
        // A truncated bincode message should fail to deserialize
        let full_bytes = make_wire_bytes("test/v1", vec![1, 2, 3], "sender", current_timestamp());
        let truncated = &full_bytes[..full_bytes.len() / 2];
        assert!(parse_protocol_message(truncated, "peer-id").is_none());
    }

    #[test]
    fn test_parse_protocol_message_empty_payload() {
        let bytes = make_wire_bytes("ping", vec![], "sender", current_timestamp());

        let event = parse_protocol_message(&bytes, "transport-peer")
            .expect("valid message with empty data should parse");

        match event {
            P2PEvent::Message { data, .. } => assert!(data.is_empty()),
            other => panic!("expected P2PEvent::Message, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_protocol_message_preserves_binary_payload() {
        // Verify that arbitrary byte values (including 0xFF, 0x00) survive round-trip
        let payload: Vec<u8> = (0..=255).collect();
        let bytes = make_wire_bytes("binary/v1", payload.clone(), "sender", current_timestamp());

        let event = parse_protocol_message(&bytes, "peer-id")
            .expect("valid message with full byte range should parse");

        match event {
            P2PEvent::Message { data, topic, .. } => {
                assert_eq!(topic, "binary/v1");
                assert_eq!(
                    data, payload,
                    "payload must survive bincode round-trip exactly"
                );
            }
            other => panic!("expected P2PEvent::Message, got {:?}", other),
        }
    }
}
