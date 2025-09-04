// Copyright 2024 Saorsa Labs Limited
//
// Adapter for ant-quic integration

//! Native ant-quic integration
//!
//! This module provides a direct wrapper around ant-quic functionality,
//! embracing its peer-oriented architecture for advanced NAT traversal
//! and post-quantum cryptography.
//!
//! ## Architecture
//!
//! Instead of trying to fit ant-quic into our Transport/Connection abstraction,
//! we use ant-quic's native peer-oriented model:
//! - Single `QuicP2PNode` per P2P instance handles all peer connections
//! - All communication uses `PeerId` instead of socket addresses
//! - Centralized send/receive through the node
//! - Built-in NAT traversal, peer discovery, and post-quantum crypto
//!
//! This is much simpler and more efficient than trying to bridge between
//! different architectural paradigms.
//!
//! ## Metrics Integration
//!
//! When saorsa-core is compiled with the `metrics` feature, this adapter
//! automatically enables ant-quic's prometheus metrics collection.
//!
//! Ant-quic v0.8.0 provides comprehensive QUIC-level performance data including:
//! - Connection establishment times
//! - Packet loss and retransmission rates  
//! - NAT traversal success rates
//! - Transport-layer bandwidth utilization
//! - Connection state metrics
//! - Stream performance data

use crate::telemetry::StreamClass;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;

// Import ant-quic types
use ant_quic::auth::AuthConfig;
use ant_quic::nat_traversal_api::{EndpointRole, PeerId};
use ant_quic::{QuicNodeConfig, QuicP2PNode};

/// Native ant-quic network node
///
/// This provides a clean interface to ant-quic's peer-to-peer networking
/// with advanced NAT traversal and post-quantum cryptography.
pub struct P2PNetworkNode {
    /// The underlying ant-quic node
    pub node: Arc<QuicP2PNode>,
    /// Our local binding address
    pub local_addr: SocketAddr,
    /// Peer registry for tracking connected peers
    pub peers: Arc<RwLock<Vec<(PeerId, SocketAddr)>>>,
}

impl P2PNetworkNode {
    /// Create a new P2P network node
    pub async fn new(bind_addr: SocketAddr) -> Result<Self> {
        let config = QuicNodeConfig {
            role: EndpointRole::Bootstrap, // Use Bootstrap role to avoid requiring bootstrap nodes in tests
            bootstrap_nodes: vec![],       // Bootstrap nodes not needed for Bootstrap role
            enable_coordinator: false,     // We don't need a coordinator
            max_connections: 100,          // Reasonable default
            connection_timeout: Duration::from_secs(30),
            stats_interval: Duration::from_secs(60),
            auth_config: AuthConfig::default(), // Use ant-quic's default auth (includes PQC)
            bind_addr: Some(bind_addr),
        };

        Self::new_with_config(bind_addr, config).await
    }

    /// Create a new P2P network node with custom configuration
    pub async fn new_with_config(
        bind_addr: SocketAddr,
        mut config: QuicNodeConfig,
    ) -> Result<Self> {
        // Ensure bind address is set
        if config.bind_addr.is_none() {
            config.bind_addr = Some(bind_addr);
        }

        // Create the ant-quic node
        let node = QuicP2PNode::new(config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create ant-quic node: {}", e))?;

        Ok(Self {
            node: Arc::new(node),
            local_addr: bind_addr,
            peers: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Connect to a peer
    pub async fn connect_to_peer(&self, peer_addr: SocketAddr) -> Result<PeerId> {
        tracing::info!("Connecting to peer at {}", peer_addr);

        // Use ant-quic's connect_to_bootstrap for direct socket address connection
        let peer_id = self
            .node
            .connect_to_bootstrap(peer_addr)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to peer: {}", e))?;

        // Register the peer
        self.add_peer(peer_id, peer_addr).await;

        tracing::info!("Connected to peer {} at {}", peer_id, peer_addr);
        Ok(peer_id)
    }

    /// Accept incoming connections (non-blocking)
    pub async fn accept_connection(&self) -> Result<(PeerId, SocketAddr)> {
        let (addr, peer_id) = self
            .node
            .accept()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to accept connection: {}", e))?;

        // Register the peer
        self.add_peer(peer_id, addr).await;

        tracing::info!("Accepted connection from peer {} at {}", peer_id, addr);
        Ok((peer_id, addr))
    }

    /// Send data to a specific peer
    pub async fn send_to_peer(&self, peer_id: &PeerId, data: &[u8]) -> Result<()> {
        self.node
            .send_to_peer(peer_id, data)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send to peer {}: {}", peer_id, e))?;
        Ok(())
    }

    /// Send data with a StreamClass (basic QoS wiring with telemetry)
    pub async fn send_with_class(
        &self,
        peer_id: &PeerId,
        data: &[u8],
        class: StreamClass,
    ) -> Result<()> {
        // In the current adapter, packets are sent directly; a future enhancement
        // may map classes to prioritized QUIC streams.
        self.send_to_peer(peer_id, data).await?;
        // Record a simple per-class bandwidth sample using message size
        crate::telemetry::telemetry()
            .record_stream_bandwidth(class, data.len() as u64)
            .await;
        Ok(())
    }

    /// Receive data from any peer (non-blocking)
    pub async fn receive_from_any_peer(&self) -> Result<(PeerId, Vec<u8>)> {
        self.node
            .receive()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to receive data: {}", e))
    }

    /// Get our local address
    pub fn local_address(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get our peer ID
    pub fn our_peer_id(&self) -> PeerId {
        self.node.peer_id()
    }

    /// Get all connected peers
    pub async fn get_connected_peers(&self) -> Vec<(PeerId, SocketAddr)> {
        self.peers.read().await.clone()
    }

    /// Check if a peer is authenticated
    pub async fn is_authenticated(&self, peer_id: &PeerId) -> bool {
        self.node.is_peer_authenticated(peer_id).await
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

    /// Internal helper to register a peer
    async fn add_peer(&self, peer_id: PeerId, addr: SocketAddr) {
        let mut peers = self.peers.write().await;
        // Avoid duplicates
        if !peers.iter().any(|(p, _)| *p == peer_id) {
            peers.push((peer_id, addr));
        }
    }

    /// Send data to a peer using String PeerId (for compatibility with our P2P core)
    pub async fn send_to_peer_string(&self, peer_id_str: &str, data: &[u8]) -> Result<()> {
        let ant_peer_id = string_to_ant_peer_id(peer_id_str);
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
}

/// Dual-stack wrapper managing IPv4 and IPv6 ant-quic nodes and providing
/// Happy Eyeballs (RFC 8305) style connection establishment.
pub struct DualStackNetworkNode {
    pub v6: Option<P2PNetworkNode>,
    pub v4: Option<P2PNetworkNode>,
}

impl DualStackNetworkNode {
    /// Create dual nodes bound to IPv6 and IPv4 addresses respectively.
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

    /// Happy Eyeballs connect: race IPv6 and IPv4 attempts, return first success.
    /// If only one family is available, use it directly. A small delay is introduced
    /// between attempts to avoid overwhelming the network and to prefer IPv6 slightly.
    pub async fn connect_happy_eyeballs(&self, targets: &[SocketAddr]) -> Result<PeerId> {
        // Partition targets by family
        let mut v6_targets: Vec<SocketAddr> = Vec::new();
        let mut v4_targets: Vec<SocketAddr> = Vec::new();
        for &t in targets {
            if t.is_ipv6() {
                v6_targets.push(t);
            } else {
                v4_targets.push(t);
            }
        }

        // If only one side exists, connect sequentially there
        if self.v6.is_none() || v6_targets.is_empty() {
            return self.connect_sequential(&self.v4, &v4_targets).await;
        }
        if self.v4.is_none() || v4_targets.is_empty() {
            return self.connect_sequential(&self.v6, &v6_targets).await;
        }

        // Both available: race IPv6 first, then IPv4 shortly after
        let v6_node = self
            .v6
            .as_ref()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotConnected, "IPv6 node not available")
            })?
            .node
            .clone();
        let v4_node = self
            .v4
            .as_ref()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotConnected, "IPv4 node not available")
            })?
            .node
            .clone();

        // Clone targets for tasks
        let v6_list = v6_targets.clone();
        let v4_list = v4_targets.clone();

        let v6_task = tokio::spawn(async move {
            for addr in v6_list {
                if let Ok(peer) = v6_node.connect_to_bootstrap(addr).await {
                    return Ok::<PeerId, anyhow::Error>(peer);
                }
            }
            Err(anyhow::anyhow!("IPv6 connect attempts failed"))
        });

        // Delay IPv4 slightly per Happy Eyeballs guidance
        let v4_task = tokio::spawn(async move {
            sleep(Duration::from_millis(50)).await;
            for addr in v4_list {
                if let Ok(peer) = v4_node.connect_to_bootstrap(addr).await {
                    return Ok::<PeerId, anyhow::Error>(peer);
                }
            }
            Err(anyhow::anyhow!("IPv4 connect attempts failed"))
        });

        // Select the first success
        // Use biased select and then await the other if needed (move ownership out first)
        let mut v6_join = Box::pin(v6_task);
        let mut v4_join = Box::pin(v4_task);
        tokio::select! {
            res6 = &mut v6_join => {
                match res6 { Ok(Ok(peer)) => Ok(peer), _ => {
                    match v4_join.await { Ok(Ok(peer)) => Ok(peer), Ok(Err(e)) => Err(e), Err(e) => Err(anyhow::anyhow!(e)), }
                } }
            }
            res4 = &mut v4_join => {
                match res4 { Ok(Ok(peer)) => Ok(peer), _ => {
                    match v6_join.await { Ok(Ok(peer)) => Ok(peer), Ok(Err(e)) => Err(e), Err(e) => Err(anyhow::anyhow!(e)), }
                } }
            }
        }
    }

    async fn connect_sequential(
        &self,
        node: &Option<P2PNetworkNode>,
        targets: &[SocketAddr],
    ) -> Result<PeerId> {
        let node = node
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("node not available"))?;
        for &addr in targets {
            if let Ok(peer) = node.node.connect_to_bootstrap(addr).await {
                return Ok(peer);
            }
        }
        Err(anyhow::anyhow!("All connect attempts failed"))
    }

    /// Return all local listening addresses available (v6 then v4 if present)
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        let mut out = Vec::new();
        if let Some(v6) = &self.v6 {
            out.push(v6.local_address());
        }
        if let Some(v4) = &self.v4 {
            out.push(v4.local_address());
        }
        out
    }

    /// Accept the next incoming connection from either IPv6 or IPv4 node.
    /// Races both accepts and returns the first (peer_id, remote_addr).
    pub async fn accept_any(&self) -> Result<(PeerId, SocketAddr)> {
        match (&self.v6, &self.v4) {
            (Some(v6), Some(v4)) => {
                let mut v6_fut = Box::pin(v6.accept_connection());
                let mut v4_fut = Box::pin(v4.accept_connection());
                tokio::select! {
                    res6 = &mut v6_fut => res6.map_err(|e| anyhow::anyhow!(e)),
                    res4 = &mut v4_fut => res4.map_err(|e| anyhow::anyhow!(e)),
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

    /// Send to peer by PeerId; tries IPv6 node first, then IPv4
    #[allow(clippy::collapsible_if)]
    pub async fn send_to_peer(&self, peer_id: &PeerId, data: &[u8]) -> Result<()> {
        if let Some(v6) = &self.v6 {
            if v6.node.send_to_peer(peer_id, data).await.is_ok() {
                return Ok(());
            }
        }
        if let Some(v4) = &self.v4 {
            if v4.node.send_to_peer(peer_id, data).await.is_ok() {
                return Ok(());
            }
        }
        Err(anyhow::anyhow!("send_to_peer failed on both stacks"))
    }

    /// Send to peer by string PeerId (compat with network module)
    pub async fn send_to_peer_string(&self, peer_id: &str, data: &[u8]) -> Result<()> {
        let ant_peer = string_to_ant_peer_id(peer_id);
        self.send_to_peer(&ant_peer, data).await
    }

    /// Send to peer with a StreamClass (basic QoS wiring with telemetry)
    pub async fn send_with_class(
        &self,
        peer_id: &PeerId,
        data: &[u8],
        class: StreamClass,
    ) -> Result<()> {
        let res = self.send_to_peer(peer_id, data).await;
        // Record a simple per-class bandwidth sample using message size
        if res.is_ok() {
            crate::telemetry::telemetry()
                .record_stream_bandwidth(class, data.len() as u64)
                .await;
        }
        res
    }

    /// Receive from any stack (race IPv6/IPv4)
    pub async fn receive_any(&self) -> Result<(PeerId, Vec<u8>)> {
        match (&self.v6, &self.v4) {
            (Some(v6), Some(v4)) => {
                let mut v6_fut = Box::pin(v6.receive_from_any_peer());
                let mut v4_fut = Box::pin(v4.receive_from_any_peer());
                tokio::select! {
                    res6 = &mut v6_fut => res6,
                    res4 = &mut v4_fut => res4,
                }
            }
            (Some(v6), None) => v6.receive_from_any_peer().await,
            (None, Some(v4)) => v4.receive_from_any_peer().await,
            (None, None) => Err(anyhow::anyhow!("no listening nodes available")),
        }
    }
}

/// Convert from our PeerId (String) to ant_quic PeerId
pub fn string_to_ant_peer_id(peer_id: &str) -> ant_quic::nat_traversal_api::PeerId {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(peer_id.as_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash[..32]);
    ant_quic::nat_traversal_api::PeerId(bytes)
}

/// Convert from ant_quic PeerId to our PeerId (String)
pub fn ant_peer_id_to_string(peer_id: &ant_quic::nat_traversal_api::PeerId) -> String {
    hex::encode(peer_id.0)
}
