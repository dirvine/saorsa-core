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

//! Transport handle module
//!
//! Encapsulates transport-level concerns (QUIC connections, peer registry,
//! message I/O, events) extracted from [`P2PNode`] to enable sharing between
//! `P2PNode` and [`DhtNetworkManager`] without coupling to the full node.

use crate::bgp_geo_provider::BgpGeoProvider;
use crate::error::{NetworkError, P2PError, P2pResult as Result};
use crate::network::{
    ConnectionStatus, KEEPALIVE_PAYLOAD, MAX_ACTIVE_REQUESTS, MAX_REQUEST_TIMEOUT,
    MESSAGE_RECV_CHANNEL_CAPACITY, NetworkSender, P2PEvent, PeerInfo, PeerResponse, PendingRequest,
    RequestResponseEnvelope, WireMessage, broadcast_event, normalize_wildcard_to_loopback,
    parse_protocol_message, register_new_peer,
};
use crate::production::{ProductionConfig, ResourceManager};
use crate::security::GeoProvider;
use crate::transport::ant_quic_adapter::{
    ConnectionEvent, DualStackNetworkNode, ant_peer_id_to_string,
};
use crate::validation::{RateLimitConfig, RateLimiter};
use crate::{NetworkAddress, PeerId};

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, broadcast};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

/// Background task maintenance interval in milliseconds.
const MAINTENANCE_INTERVAL_MS: u64 = 100;

/// Stale peer cleanup uses this multiplier on the stale threshold.
const CLEANUP_THRESHOLD_MULTIPLIER: u32 = 2;

// Test configuration defaults (used by `new_for_tests()` which is available in all builds)
const TEST_EVENT_CHANNEL_CAPACITY: usize = 16;
const TEST_MAX_REQUESTS: u32 = 100;
const TEST_BURST_SIZE: u32 = 100;
const TEST_RATE_LIMIT_WINDOW_SECS: u64 = 1;
const TEST_CONNECTION_TIMEOUT_SECS: u64 = 30;
const TEST_STALE_PEER_THRESHOLD_SECS: u64 = 60;

/// Configuration for transport initialization, derived from [`NodeConfig`](crate::network::NodeConfig).
pub struct TransportConfig {
    /// Application-level peer ID (pre-computed, possibly random).
    pub peer_id: PeerId,
    /// Primary listen address.
    pub listen_addr: SocketAddr,
    /// Whether IPv6 dual-stack is enabled.
    pub enable_ipv6: bool,
    /// Connection timeout for outbound dials and sends.
    pub connection_timeout: Duration,
    /// Stale peer threshold for maintenance sweeps.
    pub stale_peer_threshold: Duration,
    /// Maximum concurrent connections.
    pub max_connections: usize,
    /// Optional production hardening config.
    pub production_config: Option<ProductionConfig>,
    /// Broadcast channel capacity for P2P events.
    pub event_channel_capacity: usize,
}

/// Encapsulates transport-level concerns: QUIC connections, peer registry,
/// message I/O, and network events.
///
/// Both [`P2PNode`](crate::network::P2PNode) and
/// [`DhtNetworkManager`](crate::dht_network_manager::DhtNetworkManager)
/// hold `Arc<TransportHandle>` so they share the same transport state.
pub struct TransportHandle {
    peer_id: PeerId,
    dual_node: Arc<DualStackNetworkNode>,
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    active_connections: Arc<RwLock<HashSet<PeerId>>>,
    event_tx: broadcast::Sender<P2PEvent>,
    listen_addrs: RwLock<Vec<SocketAddr>>,
    rate_limiter: Arc<RateLimiter>,
    active_requests: Arc<RwLock<HashMap<String, PendingRequest>>>,
    // Held to keep the Arc alive for background tasks that captured a clone.
    #[allow(dead_code)]
    geo_provider: Arc<BgpGeoProvider>,
    shutdown: CancellationToken,
    resource_manager: Option<Arc<ResourceManager>>,
    connection_timeout: Duration,
    stale_peer_threshold: Duration,
    connection_monitor_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
    keepalive_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
    periodic_tasks_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
    recv_handles: Arc<RwLock<Vec<JoinHandle<()>>>>,
    listener_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
}

// ============================================================================
// Construction
// ============================================================================

impl TransportHandle {
    /// Create a new transport handle with the given configuration.
    ///
    /// This performs the transport-level initialization that was previously
    /// embedded in `P2PNode::new()`: dual-stack QUIC binding, rate limiter,
    /// GeoIP provider, and background tasks (connection monitor, keepalive,
    /// periodic maintenance).
    pub async fn new(config: TransportConfig) -> Result<Self> {
        let (event_tx, _) = broadcast::channel(config.event_channel_capacity);

        // Initialize dual-stack ant-quic nodes
        let (v6_opt, v4_opt) = {
            let port = config.listen_addr.port();
            let ip = config.listen_addr.ip();

            let v4_addr = if ip.is_ipv4() {
                Some(SocketAddr::new(ip, port))
            } else {
                Some(SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    port,
                ))
            };

            let v6_addr = if config.enable_ipv6 {
                if ip.is_ipv6() {
                    Some(SocketAddr::new(ip, port))
                } else {
                    Some(SocketAddr::new(
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

        let rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig::default()));
        let active_connections = Arc::new(RwLock::new(HashSet::new()));
        let geo_provider = Arc::new(BgpGeoProvider::new());
        let peers = Arc::new(RwLock::new(HashMap::new()));

        // Initialize production resource manager if configured
        let resource_manager = config
            .production_config
            .map(|prod_config| Arc::new(ResourceManager::new(prod_config)));

        let shutdown = CancellationToken::new();

        // Subscribe to connection events BEFORE spawning the monitor task
        let connection_event_rx = dual_node.subscribe_connection_events();

        let connection_monitor_handle = {
            let active_conns = Arc::clone(&active_connections);
            let peers_map = Arc::clone(&peers);
            let event_tx_clone = event_tx.clone();
            let dual_node_clone = Arc::clone(&dual_node);
            let geo_provider_clone = Arc::clone(&geo_provider);
            let peer_id_clone = config.peer_id.clone();
            let shutdown_token = shutdown.clone();

            let handle = tokio::spawn(async move {
                Self::connection_lifecycle_monitor_with_rx(
                    dual_node_clone,
                    connection_event_rx,
                    active_conns,
                    peers_map,
                    event_tx_clone,
                    geo_provider_clone,
                    peer_id_clone,
                    shutdown_token,
                )
                .await;
            });
            Arc::new(RwLock::new(Some(handle)))
        };

        let keepalive_handle = {
            let active_conns = Arc::clone(&active_connections);
            let dual_node_clone = Arc::clone(&dual_node);
            let token = shutdown.clone();

            let handle = tokio::spawn(async move {
                Self::keepalive_task(active_conns, dual_node_clone, token).await;
            });
            Arc::new(RwLock::new(Some(handle)))
        };

        let periodic_tasks_handle = {
            let peers_clone = Arc::clone(&peers);
            let active_conns_clone = Arc::clone(&active_connections);
            let event_tx_clone = event_tx.clone();
            let stale_threshold = config.stale_peer_threshold;
            let token = shutdown.clone();

            let handle = tokio::spawn(async move {
                Self::periodic_maintenance_task(
                    peers_clone,
                    active_conns_clone,
                    event_tx_clone,
                    stale_threshold,
                    token,
                )
                .await;
            });
            Arc::new(RwLock::new(Some(handle)))
        };

        Ok(Self {
            peer_id: config.peer_id,
            dual_node,
            peers,
            active_connections,
            event_tx,
            listen_addrs: RwLock::new(Vec::new()),
            rate_limiter,
            active_requests: Arc::new(RwLock::new(HashMap::new())),
            geo_provider,
            shutdown,
            resource_manager,
            connection_timeout: config.connection_timeout,
            stale_peer_threshold: config.stale_peer_threshold,
            connection_monitor_handle,
            keepalive_handle,
            periodic_tasks_handle,
            recv_handles: Arc::new(RwLock::new(Vec::new())),
            listener_handle: Arc::new(RwLock::new(None)),
        })
    }

    /// Minimal constructor for tests that avoids real networking.
    pub fn new_for_tests() -> Result<Self> {
        let (event_tx, _) = broadcast::channel(TEST_EVENT_CHANNEL_CAPACITY);
        let dual_node = {
            let v6: Option<SocketAddr> = "[::1]:0"
                .parse()
                .ok()
                .or(Some(SocketAddr::from(([0, 0, 0, 0], 0))));
            let v4: Option<SocketAddr> = "127.0.0.1:0".parse().ok();
            let handle = tokio::runtime::Handle::current();
            let dual_attempt = handle.block_on(DualStackNetworkNode::new(v6, v4));
            let dual = match dual_attempt {
                Ok(d) => d,
                Err(_e1) => {
                    let fallback = handle
                        .block_on(DualStackNetworkNode::new(None, "127.0.0.1:0".parse().ok()));
                    match fallback {
                        Ok(d) => d,
                        Err(e2) => {
                            return Err(P2PError::Network(NetworkError::BindError(
                                format!("Failed to create dual-stack network node: {}", e2).into(),
                            )));
                        }
                    }
                }
            };
            Arc::new(dual)
        };

        Ok(Self {
            peer_id: "test_peer".to_string(),
            dual_node,
            peers: Arc::new(RwLock::new(HashMap::new())),
            active_connections: Arc::new(RwLock::new(HashSet::new())),
            event_tx,
            listen_addrs: RwLock::new(Vec::new()),
            rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig {
                max_requests: TEST_MAX_REQUESTS,
                burst_size: TEST_BURST_SIZE,
                window: std::time::Duration::from_secs(TEST_RATE_LIMIT_WINDOW_SECS),
                ..Default::default()
            })),
            active_requests: Arc::new(RwLock::new(HashMap::new())),
            geo_provider: Arc::new(BgpGeoProvider::new()),
            shutdown: CancellationToken::new(),
            resource_manager: None,
            connection_timeout: Duration::from_secs(TEST_CONNECTION_TIMEOUT_SECS),
            stale_peer_threshold: Duration::from_secs(TEST_STALE_PEER_THRESHOLD_SECS),
            connection_monitor_handle: Arc::new(RwLock::new(None)),
            keepalive_handle: Arc::new(RwLock::new(None)),
            periodic_tasks_handle: Arc::new(RwLock::new(None)),
            recv_handles: Arc::new(RwLock::new(Vec::new())),
            listener_handle: Arc::new(RwLock::new(None)),
        })
    }
}

// ============================================================================
// Identity & Address Accessors
// ============================================================================

impl TransportHandle {
    /// Get the application-level peer ID.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Get the hex-encoded transport-level peer ID.
    ///
    /// This is the ID used in `P2PEvent::Message.source`, `connected_peers()`,
    /// and `send_message()`. It differs from `peer_id()` which is the app-level ID.
    pub fn transport_peer_id(&self) -> Option<String> {
        if let Some(ref v4) = self.dual_node.v4 {
            return Some(ant_peer_id_to_string(&v4.our_peer_id()));
        }
        if let Some(ref v6) = self.dual_node.v6 {
            return Some(ant_peer_id_to_string(&v6.our_peer_id()));
        }
        None
    }

    /// Get the first listen address as a string.
    pub fn local_addr(&self) -> Option<String> {
        self.listen_addrs
            .try_read()
            .ok()
            .and_then(|addrs| addrs.first().map(|a| a.to_string()))
    }

    /// Get all current listen addresses.
    pub async fn listen_addrs(&self) -> Vec<SocketAddr> {
        self.listen_addrs.read().await.clone()
    }

    /// Get the connection timeout duration.
    pub fn connection_timeout(&self) -> Duration {
        self.connection_timeout
    }

    /// Get a reference to the resource manager, if configured.
    pub fn resource_manager(&self) -> Option<&Arc<ResourceManager>> {
        self.resource_manager.as_ref()
    }
}

// ============================================================================
// Peer Management
// ============================================================================

impl TransportHandle {
    /// Get list of connected peer IDs.
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.active_connections
            .read()
            .await
            .iter()
            .cloned()
            .collect()
    }

    /// Get count of active connections.
    pub async fn peer_count(&self) -> usize {
        self.active_connections.read().await.len()
    }

    /// Get info for a specific peer.
    pub async fn peer_info(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        self.peers.read().await.get(peer_id).cloned()
    }

    /// Get the peer ID for a given socket address, if connected.
    pub async fn get_peer_id_by_address(&self, addr: &str) -> Option<PeerId> {
        let socket_addr: SocketAddr = addr.parse().ok()?;
        let peers = self.peers.read().await;

        for (peer_id, peer_info) in peers.iter() {
            for peer_addr in &peer_info.addresses {
                if let Ok(peer_socket) = peer_addr.parse::<SocketAddr>()
                    && peer_socket == socket_addr
                {
                    return Some(peer_id.clone());
                }
            }
        }
        None
    }

    /// List all active connections with peer IDs and addresses.
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

    /// Remove a peer from the tracking maps.
    pub async fn remove_peer(&self, peer_id: &PeerId) -> bool {
        self.active_connections.write().await.remove(peer_id);
        self.peers.write().await.remove(peer_id).is_some()
    }

    /// Check if a peer exists in the peers map.
    pub async fn is_peer_connected(&self, peer_id: &PeerId) -> bool {
        self.peers.read().await.contains_key(peer_id)
    }

    /// Check if a connection to a peer is active at the transport layer.
    pub async fn is_connection_active(&self, peer_id: &str) -> bool {
        self.active_connections.read().await.contains(peer_id)
    }
}

// ============================================================================
// Connection Management
// ============================================================================

impl TransportHandle {
    /// Connect to a peer at the given address.
    pub async fn connect_peer(&self, address: &str) -> Result<PeerId> {
        // Check production limits if resource manager is enabled
        let _connection_guard = if let Some(ref resource_manager) = self.resource_manager {
            Some(resource_manager.acquire_connection().await?)
        } else {
            None
        };

        let socket_addr: SocketAddr = address.parse().map_err(|e| {
            P2PError::Network(NetworkError::InvalidAddress(
                format!("{}: {}", address, e).into(),
            ))
        })?;

        let normalized_addr = normalize_wildcard_to_loopback(socket_addr);
        let addr_list = vec![normalized_addr];

        let peer_id = match tokio::time::timeout(
            self.connection_timeout,
            self.dual_node.connect_happy_eyeballs(&addr_list),
        )
        .await
        {
            Ok(Ok(peer)) => {
                let connected_peer_id = ant_peer_id_to_string(&peer);

                // Prevent self-connections
                if connected_peer_id == self.peer_id {
                    warn!(
                        "Detected self-connection to own address {} (peer_id: {}), rejecting",
                        address, connected_peer_id
                    );
                    self.dual_node.disconnect_peer(&peer).await;
                    return Err(P2PError::Network(NetworkError::InvalidAddress(
                        format!("Cannot connect to self ({})", address).into(),
                    )));
                }

                info!("Successfully connected to peer: {}", connected_peer_id);
                connected_peer_id
            }
            Ok(Err(e)) => {
                warn!("connect_happy_eyeballs failed for {}: {}", address, e);
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
                    address, self.connection_timeout
                );
                return Err(P2PError::Timeout(self.connection_timeout));
            }
        };

        let peer_info = PeerInfo {
            peer_id: peer_id.clone(),
            addresses: vec![address.to_string()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["p2p-foundation/1.0".to_string()],
            heartbeat_count: 0,
        };

        self.peers.write().await.insert(peer_id.clone(), peer_info);
        self.active_connections
            .write()
            .await
            .insert(peer_id.clone());

        if let Some(ref resource_manager) = self.resource_manager {
            resource_manager.record_bandwidth(0, 0);
        }

        self.send_event(P2PEvent::PeerConnected(peer_id.clone()));
        info!("Successfully connected to peer: {}", peer_id);
        Ok(peer_id)
    }

    /// Disconnect from a peer, closing the underlying QUIC connection.
    pub async fn disconnect_peer(&self, peer_id: &PeerId) -> Result<()> {
        info!("Disconnecting from peer: {}", peer_id);

        self.dual_node.disconnect_peer_string(peer_id).await.ok();
        self.active_connections.write().await.remove(peer_id);

        if let Some(mut peer_info) = self.peers.write().await.remove(peer_id) {
            peer_info.status = ConnectionStatus::Disconnected;
            let _ = self
                .event_tx
                .send(P2PEvent::PeerDisconnected(peer_id.clone()));
            info!("Disconnected from peer: {}", peer_id);
        }

        Ok(())
    }

    /// Disconnect from all peers.
    async fn disconnect_all_peers(&self) -> Result<()> {
        let peer_ids: Vec<PeerId> = self.peers.read().await.keys().cloned().collect();
        for peer_id in peer_ids {
            self.disconnect_peer(&peer_id).await?;
        }
        Ok(())
    }
}

// ============================================================================
// Messaging
// ============================================================================

impl TransportHandle {
    /// Send a message to a peer (raw, no trust reporting).
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

        if !self.peers.read().await.contains_key(peer_id) {
            return Err(P2PError::Network(NetworkError::PeerNotFound(
                peer_id.to_string().into(),
            )));
        }

        if !self.is_connection_active(peer_id).await {
            self.remove_peer(peer_id).await;
            return Err(P2PError::Network(NetworkError::ConnectionClosed {
                peer_id: peer_id.to_string().into(),
            }));
        }

        if let Some(ref resource_manager) = self.resource_manager {
            resource_manager.record_bandwidth(data.len() as u64, 0);
        }

        let raw_data_len = data.len();
        let message_data = self.create_protocol_message(protocol, data)?;
        info!(
            "Sending {} bytes to peer {} on protocol {} (raw data: {} bytes)",
            message_data.len(),
            peer_id,
            protocol,
            raw_data_len
        );

        let send_fut = self
            .dual_node
            .send_to_peer_string_optimized(peer_id, &message_data);
        let result = tokio::time::timeout(self.connection_timeout, send_fut)
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
                message_data.len(),
                peer_id
            );
        } else {
            warn!("Failed to send message to peer {}", peer_id);
        }

        result
    }

    /// Send a request and wait for a response (no trust reporting).
    ///
    /// This is the raw request-response correlation mechanism. Callers that
    /// need trust feedback should wrap this method (as `P2PNode` does).
    pub async fn send_request(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Result<PeerResponse> {
        let timeout = timeout.min(MAX_REQUEST_TIMEOUT);

        validate_protocol_name(protocol)?;

        let message_id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let started_at = Instant::now();

        {
            let mut reqs = self.active_requests.write().await;
            if reqs.len() >= MAX_ACTIVE_REQUESTS {
                return Err(P2PError::Transport(
                    crate::error::TransportError::StreamError(
                        format!(
                            "Too many active requests ({MAX_ACTIVE_REQUESTS}); try again later"
                        )
                        .into(),
                    ),
                ));
            }
            reqs.insert(
                message_id.clone(),
                PendingRequest {
                    response_tx: tx,
                    expected_peer: peer_id.to_string(),
                },
            );
        }

        let envelope = RequestResponseEnvelope {
            message_id: message_id.clone(),
            is_response: false,
            payload: data,
        };
        let envelope_bytes = match postcard::to_allocvec(&envelope) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.active_requests.write().await.remove(&message_id);
                return Err(P2PError::Serialization(
                    format!("Failed to serialize request envelope: {e}").into(),
                ));
            }
        };

        let wire_protocol = format!("/rr/{}", protocol);
        if let Err(e) = self
            .send_message(peer_id, &wire_protocol, envelope_bytes)
            .await
        {
            self.active_requests.write().await.remove(&message_id);
            return Err(e);
        }

        let result = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response_bytes)) => {
                let latency = started_at.elapsed();
                Ok(PeerResponse {
                    peer_id: peer_id.clone(),
                    data: response_bytes,
                    latency,
                })
            }
            Ok(Err(_)) => Err(P2PError::Network(NetworkError::ConnectionClosed {
                peer_id: peer_id.to_string().into(),
            })),
            Err(_) => Err(P2PError::Transport(
                crate::error::TransportError::StreamError(
                    format!(
                        "Request to {} on {} timed out after {:?}",
                        peer_id, protocol, timeout
                    )
                    .into(),
                ),
            )),
        };

        self.active_requests.write().await.remove(&message_id);
        result
    }

    /// Send a response to a previously received request.
    pub async fn send_response(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        message_id: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        validate_protocol_name(protocol)?;

        let envelope = RequestResponseEnvelope {
            message_id: message_id.to_string(),
            is_response: true,
            payload: data,
        };
        let envelope_bytes = postcard::to_allocvec(&envelope).map_err(|e| {
            P2PError::Serialization(format!("Failed to serialize response envelope: {e}").into())
        })?;

        let wire_protocol = format!("/rr/{}", protocol);
        self.send_message(peer_id, &wire_protocol, envelope_bytes)
            .await
    }

    /// Parse a request/response envelope from incoming message bytes.
    pub fn parse_request_envelope(data: &[u8]) -> Option<(String, bool, Vec<u8>)> {
        let envelope: RequestResponseEnvelope = postcard::from_bytes(data).ok()?;
        Some((envelope.message_id, envelope.is_response, envelope.payload))
    }

    /// Create a protocol message wrapper (WireMessage serialized with postcard).
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
}

// ============================================================================
// Pub/Sub
// ============================================================================

impl TransportHandle {
    /// Subscribe to a topic (currently a no-op stub).
    pub async fn subscribe(&self, topic: &str) -> Result<()> {
        info!("Subscribed to topic: {}", topic);
        Ok(())
    }

    /// Publish a message to all connected peers on the given topic.
    pub async fn publish(&self, topic: &str, data: &[u8]) -> Result<()> {
        info!(
            "Publishing message to topic: {} ({} bytes)",
            topic,
            data.len()
        );

        let peer_list: Vec<PeerId> = {
            let peers_guard = self.peers.read().await;
            peers_guard.keys().cloned().collect()
        };

        if peer_list.is_empty() {
            debug!("No peers connected, message will only be sent to local subscribers");
        } else {
            let mut send_count = 0;
            for peer_id in &peer_list {
                match self.send_message(peer_id, topic, data.to_vec()).await {
                    Ok(()) => {
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

        self.send_event(P2PEvent::Message {
            topic: topic.to_string(),
            source: self.peer_id.clone(),
            data: data.to_vec(),
        });

        Ok(())
    }
}

// ============================================================================
// Events
// ============================================================================

impl TransportHandle {
    /// Subscribe to network events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<P2PEvent> {
        self.event_tx.subscribe()
    }

    /// Send an event to all subscribers.
    pub(crate) fn send_event(&self, event: P2PEvent) {
        if let Err(e) = self.event_tx.send(event) {
            tracing::trace!("Event broadcast has no receivers: {e}");
        }
    }
}

// ============================================================================
// Network Listeners & Receive System
// ============================================================================

impl TransportHandle {
    /// Start network listeners on the dual-stack transport.
    pub async fn start_network_listeners(&self) -> Result<()> {
        info!("Starting dual-stack listeners (ant-quic)...");
        let addrs = self.dual_node.local_addrs().await.map_err(|e| {
            P2PError::Transport(crate::error::TransportError::SetupFailed(
                format!("Failed to get local addresses: {}", e).into(),
            ))
        })?;
        {
            let mut la = self.listen_addrs.write().await;
            *la = addrs.clone();
        }

        let event_tx = self.event_tx.clone();
        let peers = self.peers.clone();
        let active_connections = self.active_connections.clone();
        let rate_limiter = self.rate_limiter.clone();
        let dual = self.dual_node.clone();

        let handle = tokio::spawn(async move {
            loop {
                let Some((ant_peer_id, remote_sock)) = dual.accept_any().await else {
                    break;
                };

                if let Err(e) = rate_limiter.check_ip(&remote_sock.ip()) {
                    warn!(
                        "Rate-limited incoming connection from {}: {}",
                        remote_sock, e
                    );
                    continue;
                }

                let peer_id = ant_peer_id_to_string(&ant_peer_id);
                let remote_addr = NetworkAddress::from(remote_sock);
                broadcast_event(&event_tx, P2PEvent::PeerConnected(peer_id.clone()));
                register_new_peer(&peers, &peer_id, &remote_addr).await;
                active_connections.write().await.insert(peer_id);
            }
        });
        *self.listener_handle.write().await = Some(handle);

        self.start_message_receiving_system().await?;

        info!("Dual-stack listeners active on: {:?}", addrs);
        Ok(())
    }

    /// Spawns per-stack recv tasks and a dispatcher that routes incoming messages.
    async fn start_message_receiving_system(&self) -> Result<()> {
        info!("Starting message receiving system");

        let (tx, mut rx) = tokio::sync::mpsc::channel(MESSAGE_RECV_CHANNEL_CAPACITY);

        let mut handles = Vec::new();

        if let Some(v6) = self.dual_node.v6.as_ref() {
            handles.push(v6.spawn_recv_task(tx.clone(), self.shutdown.clone()));
        }
        if let Some(v4) = self.dual_node.v4.as_ref() {
            handles.push(v4.spawn_recv_task(tx.clone(), self.shutdown.clone()));
        }
        drop(tx);

        let event_tx = self.event_tx.clone();
        let active_requests = Arc::clone(&self.active_requests);
        handles.push(tokio::spawn(async move {
            info!("Message receive loop started");
            while let Some((peer_id, bytes)) = rx.recv().await {
                let transport_peer_id = ant_peer_id_to_string(&peer_id);
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
                    Some(event) => {
                        if let P2PEvent::Message {
                            ref topic,
                            ref data,
                            ..
                        } = event
                            && topic.starts_with("/rr/")
                            && let Ok(envelope) =
                                postcard::from_bytes::<RequestResponseEnvelope>(data)
                            && envelope.is_response
                        {
                            let mut reqs = active_requests.write().await;
                            let expected_peer = match reqs.get(&envelope.message_id) {
                                Some(pending) => pending.expected_peer.clone(),
                                None => {
                                    trace!(
                                        message_id = %envelope.message_id,
                                        "Unmatched /rr/ response (likely timed out) — suppressing"
                                    );
                                    continue;
                                }
                            };
                            if expected_peer != transport_peer_id {
                                warn!(
                                    message_id = %envelope.message_id,
                                    expected = %expected_peer,
                                    actual = %transport_peer_id,
                                    "Response origin mismatch — ignoring"
                                );
                                continue;
                            }
                            if let Some(pending) = reqs.remove(&envelope.message_id) {
                                if pending.response_tx.send(envelope.payload).is_err() {
                                    warn!(
                                        message_id = %envelope.message_id,
                                        "Response receiver dropped before delivery"
                                    );
                                }
                                continue;
                            }
                            trace!(
                                message_id = %envelope.message_id,
                                "Unmatched /rr/ response (likely timed out) — suppressing"
                            );
                            continue;
                        }
                        broadcast_event(&event_tx, event);
                    }
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
}

// ============================================================================
// Shutdown
// ============================================================================

impl TransportHandle {
    /// Stop the transport layer: shutdown endpoints, join tasks, disconnect peers.
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping transport...");

        self.shutdown.cancel();
        self.dual_node.shutdown_endpoints().await;

        // Await recv system tasks
        let handles: Vec<_> = self.recv_handles.write().await.drain(..).collect();
        Self::join_task_handles(handles, "recv").await;
        Self::join_task_slot(&self.listener_handle, "listener").await;
        Self::join_task_slot(&self.connection_monitor_handle, "connection monitor").await;
        Self::join_task_slot(&self.keepalive_handle, "keepalive").await;
        Self::join_task_slot(&self.periodic_tasks_handle, "periodic maintenance").await;

        self.disconnect_all_peers().await?;

        info!("Transport stopped");
        Ok(())
    }

    async fn join_task_slot(handle_slot: &RwLock<Option<JoinHandle<()>>>, task_name: &str) {
        let handle = handle_slot.write().await.take();
        if let Some(handle) = handle {
            Self::join_task_handle(handle, task_name).await;
        }
    }

    async fn join_task_handles(handles: Vec<JoinHandle<()>>, task_name: &str) {
        for handle in handles {
            Self::join_task_handle(handle, task_name).await;
        }
    }

    async fn join_task_handle(handle: JoinHandle<()>, task_name: &str) {
        match handle.await {
            Ok(()) => {}
            Err(e) if e.is_cancelled() => {
                tracing::debug!("{task_name} task was cancelled during shutdown");
            }
            Err(e) if e.is_panic() => {
                tracing::error!("{task_name} task panicked during shutdown: {:?}", e);
            }
            Err(e) => {
                tracing::warn!("{task_name} task join error during shutdown: {:?}", e);
            }
        }
    }

    /// Run periodic maintenance: detect stale peers and clean up.
    ///
    /// Called from `P2PNode::run()` and `P2PNode::periodic_tasks()`.
    pub async fn maintenance_tick(&self) -> Result<()> {
        let stale_threshold = self.stale_peer_threshold;
        let cleanup_threshold = stale_threshold * CLEANUP_THRESHOLD_MULTIPLIER;

        let (peers_to_remove, peers_to_mark_disconnected) = {
            let peers = self.peers.read().await;
            categorize_stale_peers(&peers, Instant::now(), stale_threshold, cleanup_threshold)
        };

        if !peers_to_mark_disconnected.is_empty() {
            let mut peers = self.peers.write().await;
            for peer_id in &peers_to_mark_disconnected {
                if let Some(peer_info) = peers.get_mut(peer_id) {
                    peer_info.status = ConnectionStatus::Disconnected;
                }
            }
        }

        for peer_id in &peers_to_mark_disconnected {
            self.active_connections.write().await.remove(peer_id);
            let _ = self
                .event_tx
                .send(P2PEvent::PeerDisconnected(peer_id.clone()));
            info!(peer_id = %peer_id, "Stale peer disconnected");
        }

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

// ============================================================================
// Background Tasks (static)
// ============================================================================

impl TransportHandle {
    /// Connection lifecycle monitor — processes ant-quic connection events.
    #[allow(clippy::too_many_arguments)]
    async fn connection_lifecycle_monitor_with_rx(
        dual_node: Arc<DualStackNetworkNode>,
        mut event_rx: broadcast::Receiver<crate::transport::ant_quic_adapter::ConnectionEvent>,
        active_connections: Arc<RwLock<HashSet<String>>>,
        peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
        event_tx: broadcast::Sender<P2PEvent>,
        geo_provider: Arc<BgpGeoProvider>,
        _local_peer_id: String,
        shutdown: CancellationToken,
    ) {
        info!("Connection lifecycle monitor started (pre-subscribed receiver)");

        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    info!("Connection lifecycle monitor shutting down");
                    break;
                }
                recv = event_rx.recv() => {
                    match recv {
                        Ok(event) => match event {
                            ConnectionEvent::Established {
                                peer_id,
                                remote_address,
                            } => {
                                let peer_id_str = ant_peer_id_to_string(&peer_id);
                                debug!(
                                    "Connection established: peer={}, addr={}",
                                    peer_id_str, remote_address
                                );

                                let ip = remote_address.ip();
                                let is_rejected = match ip {
                                    std::net::IpAddr::V4(v4) => {
                                        if let Some(asn) = geo_provider.lookup_ipv4_asn(v4) {
                                            geo_provider.is_hosting_asn(asn) || geo_provider.is_vpn_asn(asn)
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
                                    dual_node.disconnect_peer(&peer_id).await;
                                    continue;
                                }

                                active_connections.write().await.insert(peer_id_str.clone());

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

                                broadcast_event(&event_tx, P2PEvent::PeerConnected(peer_id_str));
                            }
                            ConnectionEvent::Lost { peer_id, reason }
                            | ConnectionEvent::Failed { peer_id, reason } => {
                                let peer_id_str = ant_peer_id_to_string(&peer_id);
                                debug!("Connection lost/failed: peer={peer_id_str}, reason={reason}");

                                active_connections.write().await.remove(&peer_id_str);
                                if let Some(peer_info) = peers.write().await.get_mut(&peer_id_str) {
                                    peer_info.status = ConnectionStatus::Disconnected;
                                    peer_info.last_seen = Instant::now();
                                }
                                broadcast_event(&event_tx, P2PEvent::PeerDisconnected(peer_id_str));
                            }
                        },
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
        }
    }

    /// Keepalive task — sends periodic pings to prevent idle timeout.
    async fn keepalive_task(
        active_connections: Arc<RwLock<HashSet<String>>>,
        dual_node: Arc<DualStackNetworkNode>,
        shutdown: CancellationToken,
    ) {
        const KEEPALIVE_INTERVAL_SECS: u64 = 15;

        let mut interval = tokio::time::interval(Duration::from_secs(KEEPALIVE_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!(
            "Keepalive task started (interval: {}s)",
            KEEPALIVE_INTERVAL_SECS
        );

        loop {
            tokio::select! {
                _ = interval.tick() => {}
                () = shutdown.cancelled() => {
                    info!("Keepalive task shutting down");
                    break;
                }
            }

            let peers: Vec<String> = { active_connections.read().await.iter().cloned().collect() };

            if peers.is_empty() {
                trace!("Keepalive: no active connections");
                continue;
            }

            debug!("Sending keepalive to {} active connections", peers.len());

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

    /// Periodic maintenance task — detects stale peers and removes them.
    async fn periodic_maintenance_task(
        peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
        active_connections: Arc<RwLock<HashSet<PeerId>>>,
        event_tx: broadcast::Sender<P2PEvent>,
        stale_threshold: Duration,
        shutdown: CancellationToken,
    ) {
        let cleanup_threshold = stale_threshold * CLEANUP_THRESHOLD_MULTIPLIER;
        let mut interval = tokio::time::interval(Duration::from_millis(MAINTENANCE_INTERVAL_MS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!(
            "Periodic maintenance task started (stale threshold: {:?})",
            stale_threshold
        );

        loop {
            tokio::select! {
                _ = interval.tick() => {}
                () = shutdown.cancelled() => break,
            }

            let (peers_to_remove, peers_to_mark_disconnected) = {
                let peers_lock = peers.read().await;
                categorize_stale_peers(
                    &peers_lock,
                    Instant::now(),
                    stale_threshold,
                    cleanup_threshold,
                )
            };

            if !peers_to_mark_disconnected.is_empty() {
                let mut peers_lock = peers.write().await;
                for peer_id in &peers_to_mark_disconnected {
                    if let Some(peer_info) = peers_lock.get_mut(peer_id) {
                        peer_info.status = ConnectionStatus::Disconnected;
                    }
                }
            }

            for peer_id in &peers_to_mark_disconnected {
                active_connections.write().await.remove(peer_id);
                broadcast_event(&event_tx, P2PEvent::PeerDisconnected(peer_id.clone()));
                info!(peer_id = %peer_id, "Stale peer disconnected");
            }

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
}

// ============================================================================
// Free helper functions
// ============================================================================

/// Validate that a protocol name is non-empty and contains no path separators or null bytes.
fn validate_protocol_name(protocol: &str) -> Result<()> {
    if protocol.is_empty() || protocol.contains(&['/', '\\', '\0'][..]) {
        return Err(P2PError::Transport(
            crate::error::TransportError::StreamError(
                format!("Invalid protocol name: {:?}", protocol).into(),
            ),
        ));
    }
    Ok(())
}

/// Categorize peers into those needing removal vs disconnection based on staleness.
///
/// Returns `(peers_to_remove, peers_to_mark_disconnected)`.
fn categorize_stale_peers(
    peers: &HashMap<PeerId, PeerInfo>,
    now: Instant,
    stale_threshold: Duration,
    cleanup_threshold: Duration,
) -> (Vec<PeerId>, Vec<PeerId>) {
    let mut peers_to_remove = Vec::new();
    let mut peers_to_mark_disconnected = Vec::new();

    for (peer_id, peer_info) in peers.iter() {
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

    (peers_to_remove, peers_to_mark_disconnected)
}

// ============================================================================
// NetworkSender impl
// ============================================================================

#[async_trait::async_trait]
impl NetworkSender for TransportHandle {
    async fn send_message(&self, peer_id: &PeerId, protocol: &str, data: Vec<u8>) -> Result<()> {
        TransportHandle::send_message(self, peer_id, protocol, data).await
    }

    fn local_peer_id(&self) -> &PeerId {
        self.peer_id()
    }
}

// Test-only helpers for injecting state
#[cfg(test)]
impl TransportHandle {
    /// Insert a peer into the peers map (test helper)
    pub(crate) async fn inject_peer(&self, peer_id: PeerId, info: PeerInfo) {
        self.peers.write().await.insert(peer_id, info);
    }

    /// Insert a peer ID into the active_connections set (test helper)
    pub(crate) async fn inject_active_connection(&self, peer_id: PeerId) {
        self.active_connections.write().await.insert(peer_id);
    }
}
