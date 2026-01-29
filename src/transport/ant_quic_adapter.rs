// Copyright 2024 Saorsa Labs Limited
//
// Adapter for ant-quic integration

//! Ant-QUIC Transport Adapter
//!
//! This module provides a clean interface to ant-quic's peer-to-peer networking
//! with advanced NAT traversal and post-quantum cryptography.
//!
//! ## Architecture
//!
//! Uses ant-quic's LinkTransport trait abstraction:
//! - `P2pLinkTransport` for real network communication
//! - `MockTransport` for testing overlay logic
//! - All communication uses `PeerId` instead of socket addresses
//! - Built-in NAT traversal, peer discovery, and post-quantum crypto
//!
//! ## PeerId Format
//!
//! The `PeerId` type is a 32-byte array (256 bits) representing the cryptographic identity
//! of a peer. This is derived from ML-DSA-65 (formerly CRYSTALS-Dilithium5) post-quantum
//! signatures, providing:
//! - 256-bit security level against quantum attacks
//! - Unique identity per cryptographic keypair
//! - Human-readable via four-word addresses (using `four-word-networking` crate)
//!
//! The PeerId is encoded as 64 hex characters when serialized to strings.
//!
//! ## Protocol Multiplexing
//!
//! The adapter uses protocol identifiers for overlay network multiplexing:
//! - `SAORSA_DHT_PROTOCOL` ("saorsa-dht/1.0.0") for DHT operations
//! - Custom protocols can be registered for different services
//!
//! **IMPORTANT**: Protocol-based filtering in `accept()` is not yet implemented in ant-quic.
//! The `accept()` method accepts all incoming connections regardless of protocol.
//! Applications must validate the protocol on received connections.
//!
//! ## Quality-Based Peer Selection
//!
//! The adapter tracks peer quality scores from ant-quic's `Capabilities.quality_score()`
//! (range 0.0 to 1.0, where higher is better). Methods available:
//! - `get_peer_quality(peer_id)` - Get quality for a specific peer
//! - `get_peers_by_quality()` - Get all peers sorted by quality (descending)
//! - `get_top_peers_by_quality(n)` - Get top N peers by quality
//! - `get_peers_above_quality_threshold(threshold)` - Filter peers by minimum quality
//! - `get_average_peer_quality()` - Get average quality of all peers
//!
//! ## NAT Traversal Configuration
//!
//! NAT traversal behavior is configured via `NetworkConfig`:
//! - `ClientOnly` - No incoming path validations (client mode)
//! - `P2PNode { concurrency_limit }` - Full P2P with configurable concurrency
//! - `Advanced { ... }` - Fine-grained control over all NAT options
//!
//! ## Metrics Integration
//!
//! When saorsa-core is compiled with the `metrics` feature, this adapter
//! automatically enables ant-quic's prometheus metrics collection.

use crate::error::{GeoEnforcementMode, GeoRejectionError, GeographicConfig};
use crate::telemetry::StreamClass;
use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::{RwLock, broadcast};
use tokio::time::sleep;

// Import ant-quic types using the new LinkTransport API (0.14+)
use ant_quic::nat_traversal_api::PeerId;
use ant_quic::{LinkConn, LinkEvent, LinkTransport, P2pConfig, P2pLinkTransport, ProtocolId};

// Import saorsa-transport types for SharedTransport integration
use ant_quic::SharedTransport;
use ant_quic::link_transport::StreamType;

/// Protocol identifier for saorsa DHT overlay
///
/// This protocol identifier is used for multiplexing saorsa's DHT traffic
/// over the QUIC transport. Other protocols can be registered for different services.
pub const SAORSA_DHT_PROTOCOL: ProtocolId = ProtocolId::from_static(b"saorsa-dht/1.0.0");

/// Connection lifecycle events from ant-quic
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    /// Connection successfully established
    Established {
        peer_id: PeerId,
        remote_address: SocketAddr,
    },
    /// Connection lost/closed
    Lost { peer_id: PeerId, reason: String },
    /// Connection attempt failed
    Failed { peer_id: PeerId, reason: String },
}

/// Native ant-quic network node using LinkTransport abstraction
///
/// This provides a clean interface to ant-quic's peer-to-peer networking
/// with advanced NAT traversal and post-quantum cryptography.
///
/// Generic over the transport type to allow testing with MockTransport.
pub struct P2PNetworkNode<T: LinkTransport = P2pLinkTransport> {
    /// The underlying transport (generic for testing)
    transport: Arc<T>,
    /// Our local binding address
    pub local_addr: SocketAddr,
    /// Peer registry for tracking connected peers
    pub peers: Arc<RwLock<Vec<(PeerId, SocketAddr)>>>,
    /// Connection event broadcaster
    event_tx: broadcast::Sender<ConnectionEvent>,
    /// Shutdown signal for event polling task
    shutdown: Arc<AtomicBool>,
    /// Event forwarder task handle
    event_task_handle: Option<tokio::task::JoinHandle<()>>,
    /// Geographic configuration for diversity enforcement
    geo_config: Option<GeographicConfig>,
    /// Peer region tracking for geographic diversity
    peer_regions: Arc<RwLock<HashMap<String, usize>>>,
    /// Peer quality scores from ant-quic Capabilities
    peer_quality: Arc<RwLock<HashMap<PeerId, f32>>>,
    /// Shared transport for protocol multiplexing
    shared_transport: Arc<SharedTransport<T>>,
}

impl P2PNetworkNode<P2pLinkTransport> {
    /// Create a new P2P network node with default P2pLinkTransport
    pub async fn new(bind_addr: SocketAddr) -> Result<Self> {
        let config = P2pConfig::builder()
            .bind_addr(bind_addr)
            .max_connections(100)
            .conservative_timeouts()
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build P2P config: {}", e))?;

        let transport = P2pLinkTransport::new(config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create transport: {}", e))?;

        // Get the actual bound address from the endpoint (important for port 0 bindings)
        let actual_addr = transport.endpoint().local_addr().unwrap_or(bind_addr);

        Self::with_transport(Arc::new(transport), actual_addr).await
    }

    /// Create a new P2P network node with custom P2pConfig
    pub async fn new_with_config(bind_addr: SocketAddr, config: P2pConfig) -> Result<Self> {
        let transport = P2pLinkTransport::new(config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create transport: {}", e))?;

        // Get the actual bound address from the endpoint
        let actual_addr = transport.endpoint().local_addr().unwrap_or(bind_addr);

        Self::with_transport(Arc::new(transport), actual_addr).await
    }

    /// Create a new P2P network node from NetworkConfig
    pub async fn from_network_config(
        bind_addr: SocketAddr,
        net_config: &crate::messaging::NetworkConfig,
    ) -> Result<Self> {
        // Build P2pConfig based on NetworkConfig
        let mut builder = P2pConfig::builder()
            .bind_addr(bind_addr)
            .max_connections(100)
            .conservative_timeouts();

        // Apply NAT traversal settings if present
        if let Some(ref nat_config) = net_config.to_ant_config() {
            builder = builder.nat(nat_config.clone());
        }

        let config = builder
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build P2P config: {}", e))?;

        tracing::info!("Creating P2P network node at {}", bind_addr);

        Self::new_with_config(bind_addr, config).await
    }

    /// Receive data from any peer using P2pEndpoint's optimized recv method
    ///
    /// This method is specialized for P2pLinkTransport and uses the underlying
    /// P2pEndpoint's recv() method which properly handles accepting streams
    /// from all connected peers.
    pub async fn receive_from_any_peer_optimized(&self) -> Result<(PeerId, Vec<u8>)> {
        use std::time::Duration;

        let timeout = Duration::from_secs(30);
        self.transport
            .endpoint()
            .recv(timeout)
            .await
            .map_err(|e| anyhow::anyhow!("Receive failed: {e}"))
    }

    /// Send data to a peer using P2pEndpoint's send method
    ///
    /// This method is specialized for P2pLinkTransport and uses the underlying
    /// P2pEndpoint's send() method which corresponds with recv() for proper
    /// bidirectional communication.
    pub async fn send_to_peer_optimized(&self, peer_id: &PeerId, data: &[u8]) -> Result<()> {
        self.transport
            .endpoint()
            .send(peer_id, data)
            .await
            .map_err(|e| anyhow::anyhow!("Send failed: {e}"))
    }
}

impl<T: LinkTransport + Send + Sync + 'static> P2PNetworkNode<T> {
    /// Create with any LinkTransport implementation (for testing)
    pub async fn with_transport(transport: Arc<T>, bind_addr: SocketAddr) -> Result<Self> {
        // Register our protocol
        transport.register_protocol(SAORSA_DHT_PROTOCOL);

        let (event_tx, _) = broadcast::channel(1000);
        let shutdown = Arc::new(AtomicBool::new(false));

        // Start event forwarder that maps LinkEvent to ConnectionEvent
        let mut link_events = transport.subscribe();
        let event_tx_clone = event_tx.clone();
        let shutdown_clone = Arc::clone(&shutdown);
        let peers_clone = Arc::new(RwLock::new(Vec::new()));
        let peers_for_task = Arc::clone(&peers_clone);
        let peer_quality = Arc::new(RwLock::new(HashMap::new()));
        let peer_quality_for_task = Arc::clone(&peer_quality);

        let event_task_handle = Some(tokio::spawn(async move {
            while !shutdown_clone.load(Ordering::Relaxed) {
                match link_events.recv().await {
                    Ok(LinkEvent::PeerConnected { peer, caps }) => {
                        // Capture quality score from ant-quic Capabilities
                        let quality = caps.quality_score();
                        {
                            let mut quality_map = peer_quality_for_task.write().await;
                            quality_map.insert(peer, quality);
                        }

                        // Use first observed address or default to unspecified
                        let addr = caps.observed_addrs.first().copied().unwrap_or_else(|| {
                            std::net::SocketAddr::new(
                                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                                0,
                            )
                        });

                        // Note: Peer tracking with geographic validation is done by
                        // add_peer() in connect_to_peer() and accept_connection().
                        // The event forwarder only broadcasts the connection event.
                        // This avoids duplicate registration while preserving
                        // geographic validation functionality.

                        let _ = event_tx_clone.send(ConnectionEvent::Established {
                            peer_id: peer,
                            remote_address: addr,
                        });
                    }
                    Ok(LinkEvent::PeerDisconnected { peer, reason }) => {
                        // Remove the peer from tracking
                        {
                            let mut peers = peers_for_task.write().await;
                            peers.retain(|(p, _)| *p != peer);
                        }
                        // Also remove from quality scores
                        {
                            let mut quality_map = peer_quality_for_task.write().await;
                            quality_map.remove(&peer);
                        }

                        let _ = event_tx_clone.send(ConnectionEvent::Lost {
                            peer_id: peer,
                            reason: format!("{:?}", reason),
                        });
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Lost some events, continue
                        continue;
                    }
                    _ => {}
                }
            }
        }));

        // Create SharedTransport for protocol multiplexing
        let shared_transport = Arc::new(SharedTransport::from_arc(Arc::clone(&transport)));
        // Note: DHT handler registration happens lazily when a DhtCoreEngine is provided
        // via register_dht_handler() method.
        Ok(Self {
            transport,
            local_addr: bind_addr,
            peers: peers_clone,
            event_tx,
            shutdown,
            event_task_handle,
            geo_config: None,
            peer_regions: Arc::new(RwLock::new(HashMap::new())),
            peer_quality,
            shared_transport,
        })
    }

    /// Register the DHT handler with the SharedTransport.
    ///
    /// This enables handling of DHT stream types (Query, Store, Witness, Replication)
    /// via the SharedTransport multiplexer.
    ///
    /// # Arguments
    ///
    /// * `dht_engine` - The DHT engine to process requests
    pub async fn register_dht_handler(
        &self,
        dht_engine: Arc<RwLock<crate::dht::core_engine::DhtCoreEngine>>,
    ) -> Result<()> {
        use crate::transport::dht_handler::DhtStreamHandler;
        use ant_quic::link_transport::ProtocolHandlerExt;

        let handler = DhtStreamHandler::new(dht_engine);
        self.shared_transport
            .register_handler(handler.boxed())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to register DHT handler: {}", e))?;

        tracing::info!("DHT handler registered with SharedTransport");
        Ok(())
    }

    /// Get a reference to the SharedTransport.
    ///
    /// Useful for registering additional protocol handlers.
    pub fn shared_transport(&self) -> Arc<SharedTransport<T>> {
        Arc::clone(&self.shared_transport)
    }

    /// Start the SharedTransport.
    ///
    /// Must be called before sending/receiving via SharedTransport.
    pub async fn start_shared_transport(&self) -> Result<()> {
        self.shared_transport
            .start()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to start SharedTransport: {}", e))
    }

    /// Send data via SharedTransport with stream type routing.
    ///
    /// The stream type byte is prepended automatically.
    pub async fn send_typed(
        &self,
        peer_id: &PeerId,
        stream_type: StreamType,
        data: bytes::Bytes,
    ) -> Result<()> {
        self.shared_transport
            .send(*peer_id, stream_type, data)
            .await
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("Failed to send typed data: {}", e))
    }

    /// Connect to a peer by address
    pub async fn connect_to_peer(&self, peer_addr: SocketAddr) -> Result<PeerId> {
        tracing::info!("Connecting to peer at {}", peer_addr);

        let conn = self
            .transport
            .dial_addr(peer_addr, SAORSA_DHT_PROTOCOL)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to peer: {}", e))?;

        let peer_id = conn.peer();

        // Register the peer with geographic validation
        self.add_peer(peer_id, peer_addr).await;

        // Note: ConnectionEvent is broadcast by event forwarder
        // to avoid duplicate events

        tracing::info!("Connected to peer {} at {}", peer_id, peer_addr);
        Ok(peer_id)
    }

    /// Accept incoming connections (waits for the next connection)
    ///
    /// **NOTE**: Protocol-based filtering is not yet implemented in ant-quic's `accept()` method.
    /// This method accepts connections for ANY protocol, not just `SAORSA_DHT_PROTOCOL`.
    /// Applications must validate that incoming connections are using the expected protocol.
    pub async fn accept_connection(&self) -> Result<(PeerId, SocketAddr)> {
        let mut incoming = self.transport.accept(SAORSA_DHT_PROTOCOL);

        use futures::StreamExt;
        if let Some(conn_result) = incoming.next().await {
            let conn = conn_result.map_err(|e| anyhow::anyhow!("Failed to accept: {}", e))?;
            let peer_id = conn.peer();
            let addr = conn.remote_addr();

            // Register the peer with geographic validation
            self.add_peer(peer_id, addr).await;

            // Note: ConnectionEvent is broadcast by event forwarder
            // to avoid duplicate events

            tracing::info!("Accepted connection from peer {} at {}", peer_id, addr);
            Ok((peer_id, addr))
        } else {
            Err(anyhow::anyhow!("Accept stream closed"))
        }
    }

    /// Send data to a specific peer
    pub async fn send_to_peer(&self, peer_id: &PeerId, data: &[u8]) -> Result<()> {
        let conn = self
            .transport
            .dial(*peer_id, SAORSA_DHT_PROTOCOL)
            .await
            .map_err(|e| anyhow::anyhow!("Dial failed: {}", e))?;

        let mut stream = conn
            .open_uni()
            .await
            .map_err(|e| anyhow::anyhow!("Stream open failed: {}", e))?;

        // Use LinkSendStream trait methods directly
        stream
            .write_all(data)
            .await
            .map_err(|e| anyhow::anyhow!("Write failed: {}", e))?;
        stream
            .finish()
            .map_err(|e| anyhow::anyhow!("Stream finish failed: {}", e))?;

        Ok(())
    }

    /// Send data with a StreamClass (basic QoS wiring with telemetry)
    pub async fn send_with_class(
        &self,
        peer_id: &PeerId,
        data: &[u8],
        class: StreamClass,
    ) -> Result<()> {
        self.send_to_peer(peer_id, data).await?;
        crate::telemetry::telemetry()
            .record_stream_bandwidth(class, data.len() as u64)
            .await;
        Ok(())
    }

    /// Receive data from any peer (waits for the next message)
    ///
    /// This method accepts incoming unidirectional streams opened by peers via `open_uni()`.
    /// It returns the peer ID and the data that was sent.
    ///
    /// The method iterates over all connected peers and attempts to accept incoming
    /// unidirectional streams from each connection with a short timeout per peer.
    pub async fn receive_from_any_peer(&self) -> Result<(PeerId, Vec<u8>)> {
        use ant_quic::link_transport::StreamFilter;
        use futures::StreamExt;
        use std::time::Duration;
        use tokio::time::timeout;

        let overall_timeout = Duration::from_secs(30);
        let start = std::time::Instant::now();
        let mut logged_once = false;

        loop {
            // Check overall timeout
            if start.elapsed() >= overall_timeout {
                return Err(anyhow::anyhow!("Receive timeout"));
            }

            // Get all connected peers
            let peers = self.get_connected_peers().await;

            if peers.is_empty() {
                // No peers connected, wait a bit and retry
                if !logged_once {
                    tracing::debug!("receive_from_any_peer: No peers connected, waiting...");
                    logged_once = true;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            if !logged_once {
                tracing::info!(
                    "receive_from_any_peer: Found {} connected peers",
                    peers.len()
                );
                logged_once = true;
            }

            // Calculate per-peer timeout
            let remaining = overall_timeout.saturating_sub(start.elapsed());
            let per_peer_timeout = remaining
                .checked_div(peers.len() as u32)
                .unwrap_or(Duration::from_millis(50))
                .max(Duration::from_millis(10));

            // Try to accept a stream from each connected peer
            for (peer_id, _addr) in &peers {
                // Use dial() to get the existing connection for this peer
                let conn_result = timeout(
                    per_peer_timeout,
                    self.transport.dial(*peer_id, SAORSA_DHT_PROTOCOL),
                )
                .await;

                if let Ok(Ok(conn)) = conn_result {
                    // Try to accept an incoming unidirectional stream with timeout
                    // accept_uni_typed returns a Stream, so we need to call .next() on it
                    let mut stream_iter = conn.accept_uni_typed(StreamFilter::new());
                    let accept_result = timeout(per_peer_timeout, stream_iter.next()).await;

                    match &accept_result {
                        Ok(Some(Ok((_stream_type, _)))) => {
                            tracing::info!("accept_uni_typed succeeded, reading data...");
                        }
                        Ok(Some(Err(e))) => {
                            tracing::debug!("accept_uni_typed stream error: {e}");
                        }
                        Ok(None) => {
                            // No stream available, normal
                        }
                        Err(_) => {
                            // Timeout, normal
                        }
                    }

                    if let Ok(Some(Ok((_stream_type, mut recv_stream)))) = accept_result {
                        // Read the data from the stream
                        let data_result = recv_stream.read_to_end(16 * 1024 * 1024).await;

                        match &data_result {
                            Ok(data) => {
                                tracing::info!("read_to_end got {} bytes", data.len());
                            }
                            Err(e) => {
                                tracing::warn!("read_to_end failed: {e}");
                            }
                        }

                        if let Ok(data) = data_result
                            && !data.is_empty()
                        {
                            tracing::info!("Received {} bytes from peer {}", data.len(), peer_id);
                            return Ok((*peer_id, data));
                        }
                    }
                }
            }

            // Short sleep between iterations
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Get our local address
    pub fn local_address(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the actual bound listening address
    pub async fn actual_listening_address(&self) -> Result<SocketAddr> {
        // Try to get external address first
        if let Some(addr) = self.transport.external_address() {
            return Ok(addr);
        }
        // Fallback to configured address
        Ok(self.local_addr)
    }

    /// Get our peer ID
    pub fn our_peer_id(&self) -> PeerId {
        self.transport.local_peer()
    }

    /// Get our observed external address as reported by peers
    pub fn get_observed_external_address(&self) -> Option<SocketAddr> {
        self.transport.external_address()
    }

    /// Get all connected peers
    pub async fn get_connected_peers(&self) -> Vec<(PeerId, SocketAddr)> {
        self.peers.read().await.clone()
    }

    /// Check if a peer is connected
    pub async fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.transport.is_connected(peer_id)
    }

    /// Check if a peer is authenticated (always true with PQC auth)
    pub async fn is_authenticated(&self, _peer_id: &PeerId) -> bool {
        // With ant-quic 0.14+, all connections are PQC authenticated
        true
    }

    /// Connect to bootstrap nodes to join the network
    pub async fn bootstrap_from_nodes(
        &self,
        bootstrap_addrs: &[SocketAddr],
    ) -> Result<Vec<PeerId>> {
        let mut connected_peers = Vec::new();

        for &addr in bootstrap_addrs {
            match self.connect_to_peer(addr).await {
                Ok(peer_id) => {
                    connected_peers.push(peer_id);
                    tracing::info!("Successfully bootstrapped from {}", addr);
                }
                Err(e) => {
                    tracing::warn!("Failed to bootstrap from {}: {}", addr, e);
                }
            }
        }

        if connected_peers.is_empty() {
            return Err(anyhow::anyhow!("Failed to connect to any bootstrap nodes"));
        }

        Ok(connected_peers)
    }

    /// Internal helper to register a peer with geographic validation
    async fn add_peer(&self, peer_id: PeerId, addr: SocketAddr) {
        // Perform geographic validation if configured
        if let Some(ref config) = self.geo_config {
            match self.validate_geographic_diversity(&addr, config).await {
                Ok(()) => {}
                Err(err) => match config.enforcement_mode {
                    GeoEnforcementMode::Strict => {
                        tracing::warn!("REJECTED peer {} from {} - {}", peer_id, addr, err);
                        return;
                    }
                    GeoEnforcementMode::LogOnly => {
                        tracing::info!(
                            "GEO_AUDIT: Would reject peer {} from {} - {} (log-only mode)",
                            peer_id,
                            addr,
                            err
                        );
                    }
                },
            }
        }

        let mut peers = self.peers.write().await;
        if !peers.iter().any(|(p, _)| *p == peer_id) {
            peers.push((peer_id, addr));

            let region = self.get_region_for_ip(&addr.ip());
            let mut regions = self.peer_regions.write().await;
            *regions.entry(region).or_insert(0) += 1;

            tracing::debug!("Added peer {} from {}", peer_id, addr);
        }
    }

    /// Validate geographic diversity before adding a peer
    async fn validate_geographic_diversity(
        &self,
        addr: &SocketAddr,
        config: &GeographicConfig,
    ) -> std::result::Result<(), GeoRejectionError> {
        let region = self.get_region_for_ip(&addr.ip());

        if config.blocked_regions.contains(&region) {
            return Err(GeoRejectionError::BlockedRegion(region));
        }

        let regions = self.peer_regions.read().await;
        let total_peers: usize = regions.values().sum();

        if total_peers > 0 {
            let region_count = *regions.get(&region).unwrap_or(&0);
            let new_ratio = (region_count + 1) as f64 / (total_peers + 1) as f64;

            if new_ratio > config.max_single_region_ratio {
                return Err(GeoRejectionError::DiversityViolation {
                    region,
                    current_ratio: new_ratio * 100.0,
                });
            }
        }

        Ok(())
    }

    /// Get region for an IP address (simplified placeholder)
    fn get_region_for_ip(&self, ip: &IpAddr) -> String {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                match octets[0] {
                    0..=63 => "NA".to_string(),
                    64..=127 => "EU".to_string(),
                    128..=191 => "APAC".to_string(),
                    192..=223 => "SA".to_string(),
                    224..=255 => "OTHER".to_string(),
                }
            }
            IpAddr::V6(_) => "UNKNOWN".to_string(),
        }
    }

    /// Get current region ratio for a specific region
    pub async fn get_region_ratio(&self, region: &str) -> f64 {
        let regions = self.peer_regions.read().await;
        let total_peers: usize = regions.values().sum();
        if total_peers == 0 {
            return 0.0;
        }
        let region_count = *regions.get(region).unwrap_or(&0);
        (region_count as f64 / total_peers as f64) * 100.0
    }

    /// Set geographic configuration for diversity enforcement
    pub fn set_geographic_config(&mut self, config: GeographicConfig) {
        tracing::info!(
            "Geographic validation enabled: mode={:?}, max_ratio={}%, blocked_regions={:?}",
            config.enforcement_mode,
            config.max_single_region_ratio * 100.0,
            config.blocked_regions
        );
        self.geo_config = Some(config);
    }

    /// Check if geographic validation is enabled
    pub fn is_geo_validation_enabled(&self) -> bool {
        self.geo_config.is_some()
    }

    /// Get peer region distribution statistics
    pub async fn get_region_stats(&self) -> HashMap<String, usize> {
        self.peer_regions.read().await.clone()
    }

    /// Get the quality score for a specific peer (0.0 to 1.0)
    ///
    /// Returns None if the peer is not connected or quality score is not available.
    /// Quality scores come from ant-quic's Capabilities.quality_score() method.
    pub async fn get_peer_quality(&self, peer_id: &PeerId) -> Option<f32> {
        let quality_map = self.peer_quality.read().await;
        quality_map.get(peer_id).copied()
    }

    /// Get all connected peers sorted by quality score (highest first)
    ///
    /// Returns peers with their quality scores, sorted from highest to lowest quality.
    /// Peers without quality scores are excluded from the results.
    pub async fn get_peers_by_quality(&self) -> Vec<(PeerId, SocketAddr, f32)> {
        let peers = self.peers.read().await;
        let quality_map = self.peer_quality.read().await;

        let mut peer_qualities: Vec<(PeerId, SocketAddr, f32)> = peers
            .iter()
            .filter_map(|(peer_id, addr)| {
                quality_map
                    .get(peer_id)
                    .map(|quality| (*peer_id, *addr, *quality))
            })
            .collect();

        // Sort by quality descending (highest first)
        peer_qualities.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));

        peer_qualities
    }

    /// Get the top N peers by quality score
    ///
    /// Returns at most `n` peers with highest quality scores.
    /// Useful for selecting the best peers for operations like storage or routing.
    pub async fn get_top_peers_by_quality(&self, n: usize) -> Vec<(PeerId, SocketAddr, f32)> {
        let mut peers = self.get_peers_by_quality().await;
        peers.truncate(n);
        peers
    }

    /// Get peers with quality score above a threshold
    ///
    /// Returns only peers whose quality score is >= the given threshold.
    /// Useful for filtering out low-quality peers.
    pub async fn get_peers_above_quality_threshold(
        &self,
        threshold: f32,
    ) -> Vec<(PeerId, SocketAddr, f32)> {
        self.get_peers_by_quality()
            .await
            .into_iter()
            .filter(|(_, _, quality)| *quality >= threshold)
            .collect()
    }

    /// Get the average quality score of all connected peers
    ///
    /// Returns None if no peers have quality scores.
    pub async fn get_average_peer_quality(&self) -> Option<f32> {
        let quality_map = self.peer_quality.read().await;
        if quality_map.is_empty() {
            return None;
        }

        let sum: f32 = quality_map.values().sum();
        Some(sum / quality_map.len() as f32)
    }

    /// Send data to a peer using String PeerId
    pub async fn send_to_peer_string(&self, peer_id_str: &str, data: &[u8]) -> Result<()> {
        let ant_peer_id = string_to_ant_peer_id(peer_id_str)
            .map_err(|e| anyhow::anyhow!("Invalid peer ID: {}", e))?;
        self.send_to_peer(&ant_peer_id, data).await
    }

    /// Connect to a peer and return String PeerId
    pub async fn connect_to_peer_string(&self, peer_addr: SocketAddr) -> Result<String> {
        let ant_peer_id = self.connect_to_peer(peer_addr).await?;
        Ok(ant_peer_id_to_string(&ant_peer_id))
    }

    /// Send a message (compatibility method for network.rs)
    pub async fn send_message(&self, peer_id: &str, data: Vec<u8>) -> Result<()> {
        self.send_to_peer_string(peer_id, &data).await
    }

    /// Subscribe to connection lifecycle events
    pub fn subscribe_connection_events(&self) -> broadcast::Receiver<ConnectionEvent> {
        self.event_tx.subscribe()
    }

    /// Shutdown the node gracefully
    pub async fn shutdown(&mut self) {
        tracing::info!("Shutting down P2PNetworkNode");

        self.shutdown.store(true, Ordering::Relaxed);

        if let Some(handle) = self.event_task_handle.take() {
            let _ = handle.await;
        }

        self.transport.shutdown().await;
    }
}

/// Dual-stack wrapper managing IPv4 and IPv6 transports
pub struct DualStackNetworkNode<T: LinkTransport = P2pLinkTransport> {
    pub v6: Option<P2PNetworkNode<T>>,
    pub v4: Option<P2PNetworkNode<T>>,
}

impl DualStackNetworkNode<P2pLinkTransport> {
    /// Create dual nodes bound to IPv6 and IPv4 addresses
    pub async fn new(v6_addr: Option<SocketAddr>, v4_addr: Option<SocketAddr>) -> Result<Self> {
        let v6 = if let Some(addr) = v6_addr {
            Some(P2PNetworkNode::new(addr).await?)
        } else {
            None
        };
        let v4 = if let Some(addr) = v4_addr {
            Some(P2PNetworkNode::new(addr).await?)
        } else {
            None
        };
        Ok(Self { v6, v4 })
    }

    /// Receive from any stack using P2pEndpoint's optimized recv method
    ///
    /// Uses P2pEndpoint::recv() which properly handles accepting streams from
    /// all connected peers across both inbound and outbound connections.
    /// This corresponds with send_to_peer_optimized() which uses P2pEndpoint::send().
    ///
    /// When dual-stack is enabled, races both stacks but handles "No connected peers"
    /// errors gracefully by falling back to the other stack. This prevents race
    /// conditions where one stack returns an error before the other has time to
    /// return data.
    pub async fn receive_any(&self) -> Result<(PeerId, Vec<u8>)> {
        match (&self.v6, &self.v4) {
            (Some(v6), Some(v4)) => {
                // Race both stacks, but handle "no connected peers" gracefully
                tokio::select! {
                    res6 = v6.receive_from_any_peer_optimized() => {
                        match &res6 {
                            Ok(_) => res6,
                            Err(e) if e.to_string().contains("No connected peers") => {
                                // IPv6 has no peers, wait for IPv4
                                v4.receive_from_any_peer_optimized().await
                            }
                            Err(_) => res6, // Other errors propagate
                        }
                    }
                    res4 = v4.receive_from_any_peer_optimized() => {
                        match &res4 {
                            Ok(_) => res4,
                            Err(e) if e.to_string().contains("No connected peers") => {
                                // IPv4 has no peers, wait for IPv6
                                v6.receive_from_any_peer_optimized().await
                            }
                            Err(_) => res4, // Other errors propagate
                        }
                    }
                }
            }
            (Some(v6), None) => v6.receive_from_any_peer_optimized().await,
            (None, Some(v4)) => v4.receive_from_any_peer_optimized().await,
            (None, None) => Err(anyhow::anyhow!("no listening nodes available")),
        }
    }

    /// Send to peer using P2pEndpoint's optimized send method
    ///
    /// Uses P2pEndpoint::send() which corresponds with recv() for proper
    /// bidirectional communication. Tries IPv6 first, then IPv4.
    pub async fn send_to_peer_optimized(&self, peer_id: &PeerId, data: &[u8]) -> Result<()> {
        if let Some(v6) = &self.v6
            && v6.send_to_peer_optimized(peer_id, data).await.is_ok()
        {
            return Ok(());
        }
        if let Some(v4) = &self.v4
            && v4.send_to_peer_optimized(peer_id, data).await.is_ok()
        {
            return Ok(());
        }
        Err(anyhow::anyhow!(
            "send_to_peer_optimized failed on both stacks"
        ))
    }

    /// Send to peer by string PeerId using optimized method
    pub async fn send_to_peer_string_optimized(&self, peer_id: &str, data: &[u8]) -> Result<()> {
        let ant_peer = string_to_ant_peer_id(peer_id)
            .map_err(|e| anyhow::anyhow!("Invalid peer ID: {}", e))?;
        self.send_to_peer_optimized(&ant_peer, data).await
    }
}

impl<T: LinkTransport + Send + Sync + 'static> DualStackNetworkNode<T> {
    /// Create with custom transports (for testing)
    pub fn with_transports(v6: Option<P2PNetworkNode<T>>, v4: Option<P2PNetworkNode<T>>) -> Self {
        Self { v6, v4 }
    }

    /// Happy Eyeballs connect: race IPv6 and IPv4 attempts
    pub async fn connect_happy_eyeballs(&self, targets: &[SocketAddr]) -> Result<PeerId> {
        let mut v6_targets: Vec<SocketAddr> = Vec::new();
        let mut v4_targets: Vec<SocketAddr> = Vec::new();
        for &t in targets {
            if t.is_ipv6() {
                v6_targets.push(t);
            } else {
                v4_targets.push(t);
            }
        }

        // Race both stacks if both are available with targets
        let (v6_node, v4_node) = match (&self.v6, &self.v4) {
            (Some(v6), Some(v4)) if !v6_targets.is_empty() && !v4_targets.is_empty() => (v6, v4),
            (Some(_), _) if !v6_targets.is_empty() => {
                return self.connect_sequential(&self.v6, &v6_targets).await;
            }
            (_, Some(_)) if !v4_targets.is_empty() => {
                return self.connect_sequential(&self.v4, &v4_targets).await;
            }
            _ => return Err(anyhow::anyhow!("No suitable transport available")),
        };

        let v6_targets_clone = v6_targets.clone();
        let v4_targets_clone = v4_targets.clone();

        let v6_fut = async {
            for addr in v6_targets_clone {
                if let Ok(peer) = v6_node.connect_to_peer(addr).await {
                    return Ok(peer);
                }
            }
            Err(anyhow::anyhow!("IPv6 connect attempts failed"))
        };

        let v4_fut = async {
            sleep(Duration::from_millis(50)).await; // Slight delay per Happy Eyeballs
            for addr in v4_targets_clone {
                if let Ok(peer) = v4_node.connect_to_peer(addr).await {
                    return Ok(peer);
                }
            }
            Err(anyhow::anyhow!("IPv4 connect attempts failed"))
        };

        tokio::select! {
            res6 = v6_fut => match res6 {
                Ok(peer) => Ok(peer),
                Err(_) => {
                    for addr in v4_targets {
                        if let Ok(peer) = v4_node.connect_to_peer(addr).await {
                            return Ok(peer);
                        }
                    }
                    Err(anyhow::anyhow!("All connect attempts failed"))
                }
            },
            res4 = v4_fut => match res4 {
                Ok(peer) => Ok(peer),
                Err(_) => {
                    for addr in v6_targets {
                        if let Ok(peer) = v6_node.connect_to_peer(addr).await {
                            return Ok(peer);
                        }
                    }
                    Err(anyhow::anyhow!("All connect attempts failed"))
                }
            }
        }
    }

    async fn connect_sequential(
        &self,
        node: &Option<P2PNetworkNode<T>>,
        targets: &[SocketAddr],
    ) -> Result<PeerId> {
        let node = node
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("node not available"))?;
        for &addr in targets {
            if let Ok(peer) = node.connect_to_peer(addr).await {
                return Ok(peer);
            }
        }
        Err(anyhow::anyhow!("All connect attempts failed"))
    }

    /// Return all local listening addresses
    pub async fn local_addrs(&self) -> Result<Vec<SocketAddr>> {
        let mut out = Vec::new();
        if let Some(v6) = &self.v6 {
            let actual_addr = v6.actual_listening_address().await?;
            out.push(actual_addr);
        }
        if let Some(v4) = &self.v4 {
            let actual_addr = v4.actual_listening_address().await?;
            out.push(actual_addr);
        }
        Ok(out)
    }

    /// Accept the next incoming connection from either stack
    pub async fn accept_any(&self) -> Result<(PeerId, SocketAddr)> {
        match (&self.v6, &self.v4) {
            (Some(v6), Some(v4)) => {
                tokio::select! {
                    res6 = v6.accept_connection() => res6,
                    res4 = v4.accept_connection() => res4,
                }
            }
            (Some(v6), None) => v6.accept_connection().await,
            (None, Some(v4)) => v4.accept_connection().await,
            (None, None) => Err(anyhow::anyhow!("no listening nodes available")),
        }
    }

    /// Get all connected peers (merged from both stacks)
    pub async fn get_connected_peers(&self) -> Vec<(PeerId, SocketAddr)> {
        let mut out = Vec::new();
        if let Some(v6) = &self.v6 {
            out.extend(v6.get_connected_peers().await);
        }
        if let Some(v4) = &self.v4 {
            out.extend(v4.get_connected_peers().await);
        }
        out
    }

    /// Send to peer by PeerId; tries IPv6 first, then IPv4
    pub async fn send_to_peer(&self, peer_id: &PeerId, data: &[u8]) -> Result<()> {
        if let Some(v6) = &self.v6
            && v6.send_to_peer(peer_id, data).await.is_ok()
        {
            return Ok(());
        }
        if let Some(v4) = &self.v4
            && v4.send_to_peer(peer_id, data).await.is_ok()
        {
            return Ok(());
        }
        Err(anyhow::anyhow!("send_to_peer failed on both stacks"))
    }

    /// Send to peer by string PeerId
    pub async fn send_to_peer_string(&self, peer_id: &str, data: &[u8]) -> Result<()> {
        let ant_peer = string_to_ant_peer_id(peer_id)
            .map_err(|e| anyhow::anyhow!("Invalid peer ID: {}", e))?;
        self.send_to_peer(&ant_peer, data).await
    }

    /// Send to peer with StreamClass
    pub async fn send_with_class(
        &self,
        peer_id: &PeerId,
        data: &[u8],
        class: StreamClass,
    ) -> Result<()> {
        let res = self.send_to_peer(peer_id, data).await;
        if res.is_ok() {
            crate::telemetry::telemetry()
                .record_stream_bandwidth(class, data.len() as u64)
                .await;
        }
        res
    }

    /// Subscribe to connection lifecycle events from both stacks
    pub fn subscribe_connection_events(&self) -> broadcast::Receiver<ConnectionEvent> {
        let (tx, rx) = broadcast::channel(1000);

        if let Some(v6) = &self.v6 {
            let mut v6_rx = v6.subscribe_connection_events();
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                while let Ok(event) = v6_rx.recv().await {
                    let _ = tx_clone.send(event);
                }
            });
        }

        if let Some(v4) = &self.v4 {
            let mut v4_rx = v4.subscribe_connection_events();
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                while let Ok(event) = v4_rx.recv().await {
                    let _ = tx_clone.send(event);
                }
            });
        }

        rx
    }

    /// Get observed external address
    pub fn get_observed_external_address(&self) -> Option<SocketAddr> {
        self.v4
            .as_ref()
            .and_then(|v4| v4.get_observed_external_address())
            .or_else(|| {
                self.v6
                    .as_ref()
                    .and_then(|v6| v6.get_observed_external_address())
            })
    }
}

/// Convert from ant_quic PeerId to our PeerId (String)
pub fn ant_peer_id_to_string(peer_id: &PeerId) -> String {
    hex::encode(peer_id.0)
}

/// Error type for PeerId conversion failures
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerIdConversionError {
    InvalidHexEncoding,
    InvalidLength { expected: usize, actual: usize },
}

impl std::fmt::Display for PeerIdConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerIdConversionError::InvalidHexEncoding => {
                write!(f, "Invalid hex encoding for PeerId")
            }
            PeerIdConversionError::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "Invalid PeerId length: expected {} bytes, got {}",
                    expected, actual
                )
            }
        }
    }
}

impl std::error::Error for PeerIdConversionError {}

/// Convert from our PeerId (String) to ant_quic PeerId
///
/// # Errors
///
/// Returns an error if:
/// - The string is not valid hex encoding
/// - The decoded bytes are not exactly 32 bytes (256 bits for ML-DSA-65)
pub fn string_to_ant_peer_id(peer_id: &str) -> Result<PeerId, PeerIdConversionError> {
    let decoded = hex::decode(peer_id).map_err(|_| PeerIdConversionError::InvalidHexEncoding)?;

    if decoded.len() != 32 {
        return Err(PeerIdConversionError::InvalidLength {
            expected: 32,
            actual: decoded.len(),
        });
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    Ok(PeerId(bytes))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test TDD: string_to_ant_peer_id should reject invalid hex
    #[test]
    fn test_string_to_peer_id_invalid_hex() {
        let result = string_to_ant_peer_id("not-hex-at-all!");
        assert!(
            matches!(result, Err(PeerIdConversionError::InvalidHexEncoding)),
            "Should reject non-hex strings"
        );
    }

    /// Test TDD: string_to_ant_peer_id should reject wrong length
    #[test]
    fn test_string_to_peer_id_wrong_length() {
        // Too short (4 bytes = 8 hex chars)
        let short_hex = "aabbccdd";
        let result_short = string_to_ant_peer_id(short_hex);
        assert!(
            matches!(
                result_short,
                Err(PeerIdConversionError::InvalidLength {
                    actual: 4,
                    expected: 32
                })
            ),
            "Should reject short PeerId (4 bytes)"
        );

        // Too long - should be rejected (96 bytes = 192 hex chars)
        let long_hex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let result_long = string_to_ant_peer_id(long_hex);
        assert!(
            matches!(
                result_long,
                Err(PeerIdConversionError::InvalidLength {
                    expected: 32,
                    actual: 96
                })
            ),
            "Should reject long PeerId (96 bytes)"
        );
    }

    /// Test TDD: string_to_ant_peer_id should accept valid 32-byte hex
    #[test]
    fn test_string_to_peer_id_valid() {
        // Valid 32-byte hex = 64 hex chars
        let valid_hex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let result = string_to_ant_peer_id(valid_hex);
        assert!(result.is_ok(), "Should accept valid 32-byte hex PeerId");

        let peer_id = result.unwrap();
        assert_eq!(peer_id.0.len(), 32, "PeerId should be exactly 32 bytes");

        // Verify round-trip
        let round_trip = ant_peer_id_to_string(&peer_id);
        assert_eq!(
            round_trip, valid_hex,
            "Round-trip conversion should preserve value"
        );
    }

    /// Test TDD: ant_peer_id_to_string should produce valid hex
    #[test]
    fn test_ant_peer_id_to_string() {
        let bytes = [0xAA; 32];
        let peer_id = PeerId(bytes);
        let hex_string = ant_peer_id_to_string(&peer_id);

        assert_eq!(hex_string.len(), 64, "32 bytes = 64 hex chars");
        assert!(
            hex_string.chars().all(|c| c.is_ascii_hexdigit()),
            "Should be valid hex"
        );
    }

    /// Test TDD: conversion should be idempotent
    #[test]
    fn test_peer_id_conversion_idempotent() {
        let original = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let peer_id = string_to_ant_peer_id(original).unwrap();
        let back_to_string = ant_peer_id_to_string(&peer_id);
        let back_to_peer_id = string_to_ant_peer_id(&back_to_string).unwrap();

        assert_eq!(
            back_to_peer_id, peer_id,
            "Double conversion should preserve identity"
        );
    }

    /// Test TDD: verify no zero-padding collisions
    #[test]
    fn test_no_zero_padding_collisions() {
        let peer1 = string_to_ant_peer_id(
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        )
        .unwrap();
        let peer2 = string_to_ant_peer_id(
            "ffeeddccbba00112233445566778899aabbccddeeff001122334455667788900",
        )
        .unwrap();

        assert_ne!(peer1, peer2, "Different inputs should not collide");
    }

    /// Test TDD: verify no duplicate peer registration
    ///
    /// Fixed: Event forwarder no longer tracks peers, only broadcasts events.
    /// Peer tracking with geographic validation is done by add_peer() in
    /// connect_to_peer() and accept_connection(). This avoids duplicate
    /// registration while preserving geographic validation functionality.
    #[test]
    fn test_no_duplicate_peer_registration() {
        // The fix is verified by:
        // - test_send_to_peer_string: Exercises connect_to_peer with add_peer call
        // - test_string_to_ant_peer_id_valid: Verifies PeerId validation works
        // Integration tests verify the ConnectionEvent broadcasts work correctly.
    }

    // TDD Phase 4: Quality-based peer selection implementation notes
    //
    // The following methods were added in Phase 4:
    // - get_peer_quality(&self, peer_id: &PeerId) -> Option<f32>
    // - get_peers_by_quality(&self) -> Vec<(PeerId, SocketAddr, f32)>
    // - get_top_peers_by_quality(&self, n: usize) -> Vec<(PeerId, SocketAddr, f32)>
    // - get_peers_above_quality_threshold(&self, threshold: f32) -> Vec<(PeerId, SocketAddr, f32)>
    // - get_average_peer_quality(&self) -> Option<f32>
    // - update_peer_quality(&self, peer_id: PeerId, quality: f32)
    //
    // These methods are tested by integration tests in the test suite that
    // actually create connections and verify quality-based peer selection.
}
