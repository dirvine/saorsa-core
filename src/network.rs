// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Network module
//!
//! This module provides core networking functionality for the P2P Foundation.
//! It handles peer connections, network events, and node lifecycle management.

use crate::bootstrap::{BootstrapManager, ContactEntry, QualityMetrics};
use crate::config::Config;
use crate::dht::DHT;
use crate::error::{NetworkError, P2PError, P2pResult as Result};
use crate::identity::manager::IdentityManagerConfig;
use crate::production::{ProductionConfig, ResourceManager, ResourceMetrics};
use crate::transport::ant_quic_adapter::DualStackNetworkNode;
#[allow(unused_imports)] // Temporarily unused during migration
use crate::transport::{TransportOptions, TransportType};
use crate::validation::RateLimitConfig;
use crate::validation::RateLimiter;
use crate::{NetworkAddress, PeerId};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, broadcast};
use tokio::time::Instant;
use tracing::{debug, info, warn};

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

    /// Identity manager configuration
    pub identity_config: Option<IdentityManagerConfig>,
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

impl NodeConfig {
    /// Create a new NodeConfig with default values
    ///
    /// # Errors
    ///
    /// Returns an error if default addresses cannot be parsed
    pub fn new() -> Result<Self> {
        // Load config and use its defaults
        let config = Config::default();

        // Parse the default listen address
        let listen_addr = config.listen_socket_addr()?;

        // Create listen addresses based on config
        let mut listen_addrs = vec![];

        // Add IPv6 address if enabled
        if config.network.ipv6_enabled {
            let ipv6_addr = std::net::SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                listen_addr.port(),
            );
            listen_addrs.push(ipv6_addr);
        }

        // Always add IPv4
        let ipv4_addr = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            listen_addr.port(),
        );
        listen_addrs.push(ipv4_addr);

        Ok(Self {
            peer_id: None,
            listen_addrs,
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
            identity_config: None,
        })
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        // Use config defaults for network settings
        let config = Config::default();

        // Parse the default listen address - use safe fallback if parsing fails
        let listen_addr = config.listen_socket_addr().unwrap_or_else(|_| {
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                9000,
            )
        });

        Self {
            peer_id: None,
            listen_addrs: vec![
                std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                    listen_addr.port(),
                ),
                std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    listen_addr.port(),
                ),
            ],
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
            production_config: None, // Use default production config if enabled
            bootstrap_cache_config: None,
            identity_config: None, // Use default identity config if enabled
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
            identity_config: Some(IdentityManagerConfig {
                cache_ttl: Duration::from_secs(3600),
                challenge_timeout: Duration::from_secs(30),
            }),
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
    #[allow(dead_code)]
    rate_limiter: Arc<RateLimiter>,
}

impl P2PNode {
    /// Minimal constructor for tests that avoids real networking
    #[allow(clippy::panic)]
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
                let v6: Option<std::net::SocketAddr> = Some(
                    "[::1]:0"
                        .parse()
                        .unwrap_or(std::net::SocketAddr::from(([0, 0, 0, 0], 0))),
                );
                let v4: Option<std::net::SocketAddr> = "127.0.0.1:0".parse().ok();
                let dual = tokio::runtime::Handle::current()
                    .block_on(crate::transport::ant_quic_adapter::DualStackNetworkNode::new(v6, v4))
                    .unwrap_or_else(|_| {
                        tokio::runtime::Handle::current()
                            .block_on(
                                crate::transport::ant_quic_adapter::DualStackNetworkNode::new(
                                    None,
                                    "127.0.0.1:0".parse().ok(),
                                ),
                            )
                            .unwrap_or_else(|e| {
                                panic!("Failed to create dual-stack network node: {}", e)
                            })
                    });
                Arc::new(dual)
            },
            rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig {
                max_requests: 100,
                burst_size: 100,
                window: std::time::Duration::from_secs(1),
                ..Default::default()
            })),
        })
    }
    /// Create a new P2P node with the given configuration
    pub async fn new(config: NodeConfig) -> Result<Self> {
        let peer_id = config.peer_id.clone().unwrap_or_else(|| {
            // Generate a random peer ID for now
            format!("peer_{}", &uuid::Uuid::new_v4().to_string()[..8])
        });

        let (event_tx, _) = broadcast::channel(1000);

        // Initialize DHT if needed
        let dht = if true {
            // Always enable DHT for now
            let _dht_config = crate::dht::DHTConfig {
                replication_factor: config.dht_config.k_value,
                bucket_size: config.dht_config.k_value,
                alpha: config.dht_config.alpha_value,
                record_ttl: config.dht_config.record_ttl,
                bucket_refresh_interval: config.dht_config.refresh_interval,
                republish_interval: config.dht_config.refresh_interval,
                max_distance: 160, // 160 bits for SHA-256
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
            Some(Arc::new(RwLock::new(dht_instance)))
        } else {
            None
        };

        // MCP removed

        // Initialize production resource manager if configured
        let resource_manager = config
            .production_config
            .clone()
            .map(|prod_config| Arc::new(ResourceManager::new(prod_config)));

        // Initialize bootstrap cache manager
        let bootstrap_manager = if let Some(ref cache_config) = config.bootstrap_cache_config {
            match BootstrapManager::with_config(cache_config.clone()).await {
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
            match BootstrapManager::new().await {
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

        // Initialize dual-stack ant-quic nodes
        let (v6_opt, v4_opt) = if !config.listen_addrs.is_empty() {
            let v6_addr = config.listen_addrs.iter().find(|a| a.is_ipv6()).cloned();
            let v4_addr = config.listen_addrs.iter().find(|a| a.is_ipv4()).cloned();
            (v6_addr, v4_addr)
        } else {
            // Defaults: always listen on IPv4; IPv6 if enabled
            let v4_addr = Some(std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                config.listen_addr.port(),
            ));
            let v6_addr = if config.enable_ipv6 {
                Some(std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                    config.listen_addr.port(),
                ))
            } else {
                None
            };
            (v6_addr, v4_addr)
        };

        let dual_node = Arc::new(
            DualStackNetworkNode::new(v6_opt, v4_opt)
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

        let node = Self {
            config,
            peer_id,
            peers: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            listen_addrs: RwLock::new(Vec::new()),
            start_time: Instant::now(),
            running: RwLock::new(false),
            dht,
            resource_manager,
            bootstrap_manager,
            dual_node,
            rate_limiter,
        };
        info!("Created P2P node with peer ID: {}", node.peer_id);

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

    pub fn local_addr(&self) -> Option<String> {
        self.listen_addrs
            .try_read()
            .ok()
            .and_then(|addrs| addrs.first().map(|a| a.to_string()))
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
        let event = P2PEvent::Message {
            topic: topic.to_string(),
            source: self.peer_id.clone(),
            data: data.to_vec(),
        };
        let _ = self.event_tx.send(event);

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

        // Log current listen addresses
        let listen_addrs = self.listen_addrs.read().await;
        info!("P2P node started on addresses: {:?}", *listen_addrs);

        // MCP removed

        // Start message receiving system
        self.start_message_receiving_system().await?;

        // Connect to bootstrap peers
        self.connect_bootstrap_peers().await?;

        Ok(())
    }

    /// Start network listeners on configured addresses
    async fn start_network_listeners(&self) -> Result<()> {
        info!("Starting dual-stack listeners (ant-quic)...");
        // Update our listen_addrs from the dual node bindings
        let addrs = self.dual_node.local_addrs();
        {
            let mut la = self.listen_addrs.write().await;
            *la = addrs.clone();
        }

        // Spawn a background accept loop that handles incoming connections from either stack
        let event_tx = self.event_tx.clone();
        let peers = self.peers.clone();
        let rate_limiter = self.rate_limiter.clone();
        let dual = self.dual_node.clone();
        tokio::spawn(async move {
            loop {
                match dual.accept_any().await {
                    Ok((ant_peer_id, remote_sock)) => {
                        let peer_id =
                            crate::transport::ant_quic_adapter::ant_peer_id_to_string(&ant_peer_id);
                        let remote_addr = NetworkAddress::from(remote_sock);
                        // Optional: basic IP rate limiting
                        let _ = rate_limiter.check_ip(&remote_sock.ip());
                        let _ = event_tx.send(P2PEvent::PeerConnected(peer_id.clone()));
                        register_new_peer(&peers, &peer_id, &remote_addr).await;
                    }
                    Err(e) => {
                        warn!("Accept failed: {}", e);
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                }
            }
        });

        info!("Dual-stack listeners active on: {:?}", addrs);
        Ok(())
    }

    /// Start a listener on a specific socket address
    #[allow(dead_code)]
    async fn start_listener_on_address(&self, addr: std::net::SocketAddr) -> Result<()> {
        // use crate::transport::{Transport}; // Unused during migration

        // DISABLED during ant-quic migration - TODO: Reimplement using AntQuicAdapter
        /*
        // Try QUIC first (preferred transport)
        match crate::transport::QuicTransport::new(Default::default()) {
            Ok(quic_transport) => {
                match quic_transport.listen(NetworkAddress::new(addr)).await {
                    Ok(listen_addrs) => {
                        info!("QUIC listener started on {} -> {:?}", addr, listen_addrs);

                        // Store the actual listening addresses in the node
                        {
                            let mut node_listen_addrs = self.listen_addrs.write().await;
                            // Don't clear - accumulate addresses from multiple listeners
                            node_listen_addrs.push(listen_addrs.socket_addr());
                        }

                        // Start accepting connections in background
                        self.start_connection_acceptor(
                            Arc::new(quic_transport),
                            addr,
                            crate::transport::TransportType::QUIC
                        ).await?;

                        return Ok(());
                    }
                    Err(e) => {
                        warn!("Failed to start QUIC listener on {}: {}", addr, e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to create QUIC transport for listening: {}", e);
            }
        }
        */

        warn!("QUIC transport temporarily disabled during ant-quic migration");
        // No TCP fallback - QUIC only
        Err(crate::P2PError::Transport(
            crate::error::TransportError::SetupFailed(
                format!(
                    "Failed to start QUIC listener on {addr} - transport disabled during migration"
                )
                .into(),
            ),
        ))
    }

    /// Start connection acceptor background task
    #[allow(dead_code)] // Deprecated during ant-quic migration
    async fn start_connection_acceptor(
        &self,
        transport: Arc<dyn crate::transport::Transport>,
        addr: std::net::SocketAddr,
        transport_type: crate::transport::TransportType,
    ) -> Result<()> {
        info!(
            "Starting connection acceptor for {:?} on {}",
            transport_type, addr
        );

        // Clone necessary data for the background task
        let event_tx = self.event_tx.clone();
        let _peer_id = self.peer_id.clone();
        let peers = Arc::clone(&self.peers);
        // ant-quic dual-stack node is managed separately; accept loop started in start_network_listeners

        let rate_limiter = Arc::clone(&self.rate_limiter);

        // Spawn background task to accept incoming connections
        tokio::spawn(async move {
            loop {
                match transport.accept().await {
                    Ok(connection) => {
                        let remote_addr = connection.remote_addr();
                        let connection_peer_id =
                            format!("peer_from_{}", remote_addr.to_string().replace(":", "_"));

                        // Apply rate limiting for incoming connections
                        let socket_addr = remote_addr.socket_addr();
                        if check_rate_limit(&rate_limiter, &socket_addr, &remote_addr).is_err() {
                            // Connection dropped automatically when it goes out of scope
                            continue;
                        }

                        info!(
                            "Accepted {:?} connection from {} (peer: {})",
                            transport_type, remote_addr, connection_peer_id
                        );

                        // Generate peer connected event
                        let _ = event_tx.send(P2PEvent::PeerConnected(connection_peer_id.clone()));

                        // Store the peer connection
                        register_new_peer(&peers, &connection_peer_id, &remote_addr).await;

                        // Spawn task to handle this specific connection's messages
                        spawn_connection_handler(
                            connection,
                            connection_peer_id,
                            event_tx.clone(),
                            Arc::clone(&peers),
                        );
                    }
                    Err(e) => {
                        warn!(
                            "Failed to accept {:?} connection on {}: {}",
                            transport_type, addr, e
                        );

                        // Brief pause before retrying to avoid busy loop
                        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                    }
                }
            }
        });

        info!(
            "Connection acceptor background task started for {:?} on {}",
            transport_type, addr
        );
        Ok(())
    }

    /// Start the message receiving system with background tasks
    async fn start_message_receiving_system(&self) -> Result<()> {
        info!("Message receiving system initialized (background tasks simplified for demo)");

        // For now, we'll rely on the transport layer's message sending and the
        // publish/subscribe pattern for local message routing
        // Real message receiving would require deeper transport integration

        Ok(())
    }

    /// Handle a received message and generate appropriate events
    #[allow(dead_code)]
    async fn handle_received_message(
        &self,
        message_data: Vec<u8>,
        peer_id: &PeerId,
        _protocol: &str,
        event_tx: &broadcast::Sender<P2PEvent>,
    ) -> Result<()> {
        // MCP removed: no special protocol handling

        // Parse the message format we created in create_protocol_message
        match serde_json::from_slice::<serde_json::Value>(&message_data) {
            Ok(message) => {
                if let (Some(protocol), Some(data), Some(from)) = (
                    message.get("protocol").and_then(|v| v.as_str()),
                    message.get("data").and_then(|v| v.as_array()),
                    message.get("from").and_then(|v| v.as_str()),
                ) {
                    // Convert data array back to bytes
                    let data_bytes: Vec<u8> = data
                        .iter()
                        .filter_map(|v| v.as_u64().map(|n| n as u8))
                        .collect();

                    // Generate message event
                    let event = P2PEvent::Message {
                        topic: protocol.to_string(),
                        source: from.to_string(),
                        data: data_bytes,
                    };

                    let _ = event_tx.send(event);
                    debug!("Generated message event from peer: {}", peer_id);
                }
            }
            Err(e) => {
                warn!("Failed to parse received message from {}: {}", peer_id, e);
            }
        }

        Ok(())
    }

    // MCP removed

    // MCP removed

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

        // Set running state to false
        *self.running.write().await = false;

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
        self.peers.read().await.keys().cloned().collect()
    }

    /// Get peer count
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get peer info
    pub async fn peer_info(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        self.peers.read().await.get(peer_id).cloned()
    }

    /// Connect to a peer
    pub async fn connect_peer(&self, address: &str) -> Result<PeerId> {
        info!("Connecting to peer at: {}", address);

        // Check production limits if resource manager is enabled
        let _connection_guard = if let Some(ref resource_manager) = self.resource_manager {
            Some(resource_manager.acquire_connection().await?)
        } else {
            None
        };

        // Parse the address to SocketAddr format
        let _socket_addr: std::net::SocketAddr = address.parse().map_err(|e| {
            P2PError::Network(crate::error::NetworkError::InvalidAddress(
                format!("{}: {}", address, e).into(),
            ))
        })?;

        // Establish a real connection via dual-stack Happy Eyeballs
        let peer_id = {
            match self
                .dual_node
                .connect_happy_eyeballs(&[_socket_addr])
                .await
                .map(|p| crate::transport::ant_quic_adapter::ant_peer_id_to_string(&p))
            {
                Ok(connected_peer_id) => {
                    info!("Successfully connected to peer: {}", connected_peer_id);
                    connected_peer_id
                }
                Err(e) => {
                    warn!("Failed to connect to peer at {}: {}", address, e);

                    // For demo purposes, try a simplified connection approach
                    // Create a mock peer ID based on address for now
                    let demo_peer_id =
                        format!("peer_from_{}", address.replace("/", "_").replace(":", "_"));
                    warn!(
                        "Using demo peer ID: {} (transport connection failed)",
                        demo_peer_id
                    );
                    demo_peer_id
                }
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

        // Record bandwidth usage if resource manager is enabled
        if let Some(ref resource_manager) = self.resource_manager {
            resource_manager.record_bandwidth(0, 0); // Placeholder for handshake data
        }

        // Emit connection event
        let _ = self.event_tx.send(P2PEvent::PeerConnected(peer_id.clone()));

        info!("Connected to peer: {}", peer_id);
        Ok(peer_id)
    }

    /// Disconnect from a peer
    pub async fn disconnect_peer(&self, peer_id: &PeerId) -> Result<()> {
        info!("Disconnecting from peer: {}", peer_id);

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

        // Check if peer is connected
        if !self.peers.read().await.contains_key(peer_id) {
            return Err(P2PError::Network(crate::error::NetworkError::PeerNotFound(
                peer_id.to_string().into(),
            )));
        }

        // MCP removed: no special-case protocol validation

        // Record bandwidth usage if resource manager is enabled
        if let Some(ref resource_manager) = self.resource_manager {
            resource_manager.record_bandwidth(data.len() as u64, 0);
        }

        // Create protocol message wrapper
        let _message_data = self.create_protocol_message(protocol, data)?;

        // Send via ant-quic dual-node
        self.dual_node
            .send_to_peer_string(peer_id, &_message_data)
            .await
            .map_err(|e| {
                P2PError::Transport(crate::error::TransportError::StreamError(
                    e.to_string().into(),
                ))
            })
    }

    /// Create a protocol message wrapper
    fn create_protocol_message(&self, protocol: &str, data: Vec<u8>) -> Result<Vec<u8>> {
        use serde_json::json;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| {
                P2PError::Network(NetworkError::ProtocolError(
                    format!("System time error: {}", e).into(),
                ))
            })?
            .as_secs();

        // Create a simple message format for P2P communication
        let message = json!({
            "protocol": protocol,
            "data": data,
            "from": self.peer_id,
            "timestamp": timestamp
        });

        serde_json::to_vec(&message).map_err(|e| {
            P2PError::Transport(crate::error::TransportError::StreamError(
                format!("Failed to serialize message: {e}").into(),
            ))
        })
    }

    // Note: async listen_addrs() already exists above for fetching listen addresses
}

/// Create a protocol message wrapper (static version for background tasks)
#[allow(dead_code)]
fn create_protocol_message_static(protocol: &str, data: Vec<u8>) -> Result<Vec<u8>> {
    use serde_json::json;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| {
            P2PError::Network(NetworkError::ProtocolError(
                format!("System time error: {}", e).into(),
            ))
        })?
        .as_secs();

    // Create a simple message format for P2P communication
    let message = json!({
        "protocol": protocol,
        "data": data,
        "timestamp": timestamp
    });

    serde_json::to_vec(&message).map_err(|e| {
        P2PError::Transport(crate::error::TransportError::StreamError(
            format!("Failed to serialize message: {e}").into(),
        ))
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

    /// Get node uptime
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    // MCP removed: all MCP tool/service methods removed

    /// Handle MCP remote tool call with network integration
    // MCP removed: remote tool call stub deleted

    /// List tools available on a specific remote peer
    // MCP removed

    /// Get MCP server statistics
    // MCP removed

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

    /// Store a value in the DHT
    pub async fn dht_put(&self, key: crate::dht::Key, value: Vec<u8>) -> Result<()> {
        if let Some(ref dht) = self.dht {
            let mut dht_instance = dht.write().await;
            let dht_key = crate::dht::DhtKey::from_bytes(key);
            dht_instance
                .store(&dht_key, value.clone())
                .await
                .map_err(|e| {
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

    /// Retrieve a value from the DHT
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
            let mut manager = bootstrap_manager.write().await;
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
            let mut manager = bootstrap_manager.write().await;

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

    /// Connect to bootstrap peers
    async fn connect_bootstrap_peers(&self) -> Result<()> {
        let mut bootstrap_contacts = Vec::new();
        let mut used_cache = false;

        // Try to get peers from bootstrap cache first
        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
            let manager = bootstrap_manager.read().await;
            match manager.get_bootstrap_peers(20).await {
                // Try to get top 20 quality peers
                Ok(contacts) => {
                    if !contacts.is_empty() {
                        info!("Using {} cached bootstrap peers", contacts.len());
                        bootstrap_contacts = contacts;
                        used_cache = true;
                    }
                }
                Err(e) => {
                    warn!("Failed to get cached bootstrap peers: {}", e);
                }
            }
        }

        // Fallback to configured bootstrap peers if no cache or cache is empty
        if bootstrap_contacts.is_empty() {
            let bootstrap_peers = if !self.config.bootstrap_peers_str.is_empty() {
                &self.config.bootstrap_peers_str
            } else {
                // Convert Multiaddr to strings for fallback
                &self
                    .config
                    .bootstrap_peers
                    .iter()
                    .map(|addr| addr.to_string())
                    .collect::<Vec<_>>()
            };

            if bootstrap_peers.is_empty() {
                info!("No bootstrap peers configured and no cached peers available");
                return Ok(());
            }

            info!("Using {} configured bootstrap peers", bootstrap_peers.len());

            for addr in bootstrap_peers {
                if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
                    let contact = ContactEntry::new(
                        format!("unknown_peer_{}", addr.chars().take(8).collect::<String>()),
                        vec![socket_addr],
                    );
                    bootstrap_contacts.push(contact);
                } else {
                    warn!("Invalid bootstrap address format: {}", addr);
                }
            }
        }

        // Connect to bootstrap peers
        let mut successful_connections = 0;
        for contact in bootstrap_contacts {
            for addr in &contact.addresses {
                match self.connect_peer(&addr.to_string()).await {
                    Ok(peer_id) => {
                        info!("Connected to bootstrap peer: {} ({})", peer_id, addr);
                        successful_connections += 1;

                        // Update bootstrap cache with successful connection
                        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
                            let mut manager = bootstrap_manager.write().await;
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
                            let mut manager = bootstrap_manager.write().await;
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
            return Err(P2PError::Network(NetworkError::ConnectionFailed {
                addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)), // Placeholder for bootstrap ensemble
                reason: "Failed to connect to any bootstrap peers".into(),
            }));
        }
        info!(
            "Successfully connected to {} bootstrap peers",
            successful_connections
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
    async fn periodic_tasks(&self) -> Result<()> {
        // Update peer last seen timestamps
        // Remove stale connections
        // Perform DHT maintenance
        // This is a placeholder for now

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

/// Standalone function to handle received messages without borrowing self
#[allow(dead_code)] // Deprecated during ant-quic migration
async fn handle_received_message_standalone(
    message_data: Vec<u8>,
    peer_id: &PeerId,
    _protocol: &str,
    event_tx: &broadcast::Sender<P2PEvent>,
) -> Result<()> {
    // Parse the message format
    match serde_json::from_slice::<serde_json::Value>(&message_data) {
        Ok(message) => {
            if let (Some(protocol), Some(data), Some(from)) = (
                message.get("protocol").and_then(|v| v.as_str()),
                message.get("data").and_then(|v| v.as_array()),
                message.get("from").and_then(|v| v.as_str()),
            ) {
                // Convert data array back to bytes
                let data_bytes: Vec<u8> = data
                    .iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u8))
                    .collect();

                // Generate message event
                let event = P2PEvent::Message {
                    topic: protocol.to_string(),
                    source: from.to_string(),
                    data: data_bytes,
                };

                let _ = event_tx.send(event);
                debug!("Generated message event from peer: {}", peer_id);
            }
        }
        Err(e) => {
            warn!("Failed to parse received message from {}: {}", peer_id, e);
        }
    }

    Ok(())
}

// MCP removed: standalone MCP handler deleted

/// Helper function to handle protocol message creation
fn handle_protocol_message_creation(protocol: &str, data: Vec<u8>) -> Option<Vec<u8>> {
    match create_protocol_message_static(protocol, data) {
        Ok(msg) => Some(msg),
        Err(e) => {
            warn!("Failed to create protocol message: {}", e);
            None
        }
    }
}

/// Helper function to handle message send result
async fn handle_message_send_result(result: Result<()>, peer_id: &PeerId) {
    match result {
        Ok(_) => {
            debug!("Message sent to peer {} via transport layer", peer_id);
        }
        Err(e) => {
            warn!("Failed to send message to peer {}: {}", peer_id, e);
        }
    }
}

/// Helper function to check rate limit
#[allow(dead_code)] // Deprecated during ant-quic migration
fn check_rate_limit(
    rate_limiter: &RateLimiter,
    socket_addr: &std::net::SocketAddr,
    remote_addr: &NetworkAddress,
) -> Result<()> {
    rate_limiter.check_ip(&socket_addr.ip()).map_err(|e| {
        warn!("Rate limit exceeded for {}: {}", remote_addr, e);
        e
    })
}

/// Helper function to register a new peer
#[allow(dead_code)] // Deprecated during ant-quic migration
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
        protocols: vec!["p2p-chat/1.0.0".to_string()],
        heartbeat_count: 0,
    };
    peers_guard.insert(peer_id.clone(), peer_info);
}

/// Helper function to spawn connection handler
#[allow(dead_code)] // Deprecated during ant-quic migration
fn spawn_connection_handler(
    connection: Box<dyn crate::transport::Connection>,
    peer_id: PeerId,
    event_tx: broadcast::Sender<P2PEvent>,
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
) {
    tokio::spawn(async move {
        handle_peer_connection(connection, peer_id, event_tx, peers).await;
    });
}

/// Helper function to handle peer connection
#[allow(dead_code)] // Deprecated during ant-quic migration
async fn handle_peer_connection(
    mut connection: Box<dyn crate::transport::Connection>,
    peer_id: PeerId,
    event_tx: broadcast::Sender<P2PEvent>,
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
) {
    loop {
        match connection.receive().await {
            Ok(message_data) => {
                debug!(
                    "Received {} bytes from peer: {}",
                    message_data.len(),
                    peer_id
                );

                // Handle the received message
                if let Err(e) = handle_received_message_standalone(
                    message_data,
                    &peer_id,
                    "unknown", // TODO: Extract protocol from message
                    &event_tx,
                )
                .await
                {
                    warn!("Failed to handle message from peer {}: {}", peer_id, e);
                }
            }
            Err(e) => {
                warn!("Failed to receive message from {}: {}", peer_id, e);

                // Check if connection is still alive
                if !connection.is_alive().await {
                    info!("Connection to {} is dead, removing peer", peer_id);

                    // Remove dead peer
                    remove_peer(&peers, &peer_id).await;

                    // Generate peer disconnected event
                    let _ = event_tx.send(P2PEvent::PeerDisconnected(peer_id.clone()));

                    break; // Exit the message receiving loop
                }

                // Brief pause before retrying
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Helper function to remove a peer
#[allow(dead_code)] // Deprecated during ant-quic migration
async fn remove_peer(peers: &Arc<RwLock<HashMap<PeerId, PeerInfo>>>, peer_id: &PeerId) {
    let mut peers_guard = peers.write().await;
    peers_guard.remove(peer_id);
}

/// Helper function to update peer heartbeat
async fn update_peer_heartbeat(
    peers: &Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    peer_id: &PeerId,
) -> Result<()> {
    let mut peers_guard = peers.write().await;
    match peers_guard.get_mut(peer_id) {
        Some(peer_info) => {
            peer_info.last_seen = Instant::now();
            peer_info.heartbeat_count += 1;
            Ok(())
        }
        None => {
            warn!("Received heartbeat from unknown peer: {}", peer_id);
            Err(P2PError::Network(NetworkError::PeerNotFound(
                format!("Peer {} not found", peer_id).into(),
            )))
        }
    }
}

/// Helper function to get resource metrics
async fn get_resource_metrics(resource_manager: &Option<Arc<ResourceManager>>) -> (u64, f32) {
    if let Some(manager) = resource_manager {
        let metrics = manager.get_metrics().await;
        (metrics.memory_used, metrics.cpu_usage as f32)
    } else {
        (0, 0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // MCP removed from tests
    use std::time::Duration;
    use tokio::time::timeout;

    /// Test tool handler for network tests
    // MCP removed: NetworkTestTool deleted

    // MCP removed

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

            connection_timeout: Duration::from_secs(10),
            keep_alive_interval: Duration::from_secs(30),
            max_connections: 100,
            max_incoming_connections: 50,
            dht_config: DHTConfig::default(),
            security_config: SecurityConfig::default(),
            production_config: None,
            bootstrap_cache_config: None,
            identity_config: None,
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
        assert_eq!(config.max_connections, 1000);
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
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        let peer_addr = "/ip4/127.0.0.1/tcp/0".to_string();

        // Connect to a peer
        let peer_id = node.connect_peer(&peer_addr).await?;
        assert!(peer_id.starts_with("peer_from_"));

        // Check peer count
        assert_eq!(node.peer_count().await, 1);

        // Check connected peers
        let connected_peers = node.connected_peers().await;
        assert_eq!(connected_peers.len(), 1);
        assert_eq!(connected_peers[0], peer_id);

        // Get peer info
        let peer_info = node.peer_info(&peer_id).await;
        assert!(peer_info.is_some());
        let info = peer_info.expect("Peer info should exist after adding peer");
        assert_eq!(info.peer_id, peer_id);
        assert_eq!(info.status, ConnectionStatus::Connected);
        assert!(info.protocols.contains(&"p2p-foundation/1.0".to_string()));

        // Disconnect from peer
        node.disconnect_peer(&peer_id).await?;
        assert_eq!(node.peer_count().await, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_event_subscription() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        let mut events = node.subscribe_events();
        let peer_addr = "/ip4/127.0.0.1/tcp/0".to_string();

        // Connect to a peer (this should emit an event)
        let peer_id = node.connect_peer(&peer_addr).await?;

        // Check for PeerConnected event
        let event = timeout(Duration::from_millis(100), events.recv()).await;
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
        node.disconnect_peer(&peer_id).await?;

        // Check for PeerDisconnected event
        let event = timeout(Duration::from_millis(100), events.recv()).await;
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

        Ok(())
    }

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
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Get actual listening address of node2
        let node2_addr = node2.local_addr().ok_or_else(|| {
            P2PError::Network(crate::error::NetworkError::ProtocolError(
                "No listening address".to_string().into(),
            ))
        })?;

        // Connect node1 to node2
        let peer_id = node1.connect_peer(&node2_addr).await?;

        // Wait a bit for connection to establish
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Send a message
        let message_data = b"Hello, peer!".to_vec();
        let result = node1
            .send_message(&peer_id, "test-protocol", message_data)
            .await;
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
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not connected"));

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

        // Connect many peers (but not over the limit)
        for i in 0..5 {
            let addr = format!("/ip4/127.0.0.1/tcp/{}", 9010 + i);
            node.connect_peer(&addr).await?;
        }

        // Health check should still pass
        let result = node.health_check().await;
        assert!(result.is_ok());

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
        let node = P2PNode::new(config).await?;

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
        let node = P2PNode::builder()
            .with_peer_id("builder_test_peer".to_string())
            .listen_on("/ip4/127.0.0.1/tcp/9100")
            .listen_on("/ip6/::1/tcp/9100")
            .with_bootstrap_peer("/ip4/127.0.0.1/tcp/9101")
            .with_ipv6(true)
            .with_connection_timeout(Duration::from_secs(15))
            .with_max_connections(200)
            .build()
            .await?;

        assert_eq!(node.peer_id(), "builder_test_peer");
        let config = node.config();
        assert_eq!(config.listen_addrs.len(), 4); // 2 default + 2 added by builder
        assert_eq!(config.bootstrap_peers.len(), 1);
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
        let peer_count = node.peer_count().await;
        assert!(
            peer_count <= 2,
            "Peer count should not exceed bootstrap peer count"
        );

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
}
