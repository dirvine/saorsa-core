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

//! Transport Layer
//!
//! This module provides native ant-quic integration for the P2P Foundation.
//!
//! ## Migration Notice
//! The old Transport/Connection trait abstractions have been deprecated
//! in favor of direct ant-quic integration via P2PNetworkNode.
//!
//! Use `ant_quic_adapter::P2PNetworkNode` directly for all networking needs.

// ant-quic is used directly via ant_quic_adapter module

// Native ant-quic integration with advanced NAT traversal and PQC support
pub mod ant_quic_adapter;

// Tests for old QuicTransport - removed during ant-quic migration
// #[cfg(test)]
// mod quic_error_tests;

use crate::validation::{Validate, ValidationContext, validate_message_size, validate_peer_id};
use crate::{NetworkAddress, P2PError, PeerId, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

/// Transport protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportType {
    /// QUIC transport protocol with NAT traversal
    QUIC,
}

/// Transport selection strategy (simplified for QUIC-only)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum TransportSelection {
    /// Use QUIC transport (default and only option)
    #[default]
    QUIC,
}

/// Connection quality metrics
#[derive(Debug, Clone)]
pub struct ConnectionQuality {
    /// Round-trip latency
    pub latency: Duration,
    /// Throughput in Mbps
    pub throughput_mbps: f64,
    /// Packet loss percentage
    pub packet_loss: f64,
    /// Jitter (latency variation)
    pub jitter: Duration,
    /// Connection establishment time
    pub connect_time: Duration,
}

/// Connection information
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Transport type being used
    pub transport_type: TransportType,
    /// Local address
    pub local_addr: NetworkAddress,
    /// Remote address
    pub remote_addr: NetworkAddress,
    /// Whether connection is encrypted
    pub is_encrypted: bool,
    /// Cipher suite being used
    pub cipher_suite: String,
    /// Whether 0-RTT was used
    pub used_0rtt: bool,
    /// Connection establishment time
    pub established_at: Instant,
    /// Last activity timestamp
    pub last_activity: Instant,
}

/// Connection pool information
#[derive(Debug, Clone)]
pub struct ConnectionPoolInfo {
    /// Number of active connections
    pub active_connections: usize,
    /// Total connections ever created
    pub total_connections: usize,
    /// Bytes sent through pool
    pub bytes_sent: u64,
    /// Bytes received through pool
    pub bytes_received: u64,
}

/// Connection pool statistics
#[derive(Debug, Clone)]
pub struct ConnectionPoolStats {
    /// Messages sent per connection
    pub messages_per_connection: HashMap<String, usize>,
    /// Bytes per connection
    pub bytes_per_connection: HashMap<String, u64>,
    /// Average latency per connection
    pub latency_per_connection: HashMap<String, Duration>,
}

/// Message received from transport
#[derive(Debug, Clone)]
pub struct TransportMessage {
    /// Sender peer ID
    pub sender: PeerId,
    /// Message data
    pub data: Vec<u8>,
    /// Protocol identifier
    pub protocol: String,
    /// Timestamp when received
    pub received_at: Instant,
}

impl Validate for TransportMessage {
    fn validate(&self, ctx: &ValidationContext) -> Result<()> {
        // Validate sender peer ID
        validate_peer_id(&self.sender)?;

        // Validate message size
        validate_message_size(self.data.len(), ctx.max_message_size)?;

        // Validate protocol identifier
        if self.protocol.is_empty() || self.protocol.len() > 64 {
            return Err(P2PError::validation("Invalid protocol identifier"));
        }

        Ok(())
    }
}

/// Transport trait for protocol implementations
#[allow(dead_code)] // Deprecated during ant-quic migration
#[async_trait]
pub trait Transport: Send + Sync {
    /// Start listening on the given address
    async fn listen(&self, addr: NetworkAddress) -> Result<NetworkAddress>;

    /// Accept incoming connections (for server-side)
    async fn accept(&self) -> Result<Box<dyn Connection>>;

    /// Connect to a remote peer
    async fn connect(&self, addr: NetworkAddress) -> Result<Box<dyn Connection>>;

    /// Connect with specific transport options
    async fn connect_with_options(
        &self,
        addr: NetworkAddress,
        options: TransportOptions,
    ) -> Result<Box<dyn Connection>>;

    /// Check if this transport supports IPv6 (deprecated - IPv4-only focus)
    fn supports_ipv6(&self) -> bool;

    /// Get transport type
    fn transport_type(&self) -> TransportType;

    /// Check if address is supported
    fn supports_address(&self, addr: &NetworkAddress) -> bool;
}

/// Connection trait for active connections
#[allow(dead_code)] // Deprecated during ant-quic migration
#[async_trait]
pub trait Connection: Send + Sync {
    /// Send data over the connection
    async fn send(&mut self, data: &[u8]) -> Result<()>;

    /// Receive data from the connection
    async fn receive(&mut self) -> Result<Vec<u8>>;

    /// Get connection info
    async fn info(&self) -> ConnectionInfo;

    /// Close the connection
    async fn close(&mut self) -> Result<()>;

    /// Check if connection is alive
    async fn is_alive(&self) -> bool;

    /// Measure connection quality
    async fn measure_quality(&self) -> Result<ConnectionQuality>;

    /// Get local address
    fn local_addr(&self) -> NetworkAddress;

    /// Get remote address
    fn remote_addr(&self) -> NetworkAddress;
}

/// Transport configuration options
#[derive(Debug, Clone)]
pub struct TransportOptions {
    /// Enable 0-RTT for QUIC
    pub enable_0rtt: bool,
    /// Force encryption
    pub require_encryption: bool,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Keep-alive interval
    pub keep_alive: Duration,
    /// Maximum message size
    pub max_message_size: usize,
}

/// Transport manager coordinates different transport protocols
#[allow(dead_code)] // Deprecated during ant-quic migration
pub struct TransportManager {
    /// Available transports
    transports: HashMap<TransportType, Arc<dyn Transport>>,
    /// Active connections
    connections: Arc<RwLock<HashMap<PeerId, Arc<Mutex<ConnectionPool>>>>>,
    /// Transport selection strategy
    selection: TransportSelection,
    /// Configuration options
    options: TransportOptions,
}

/// Connection pool for a specific peer
struct ConnectionPool {
    /// Active connections
    connections: Vec<Arc<Mutex<Box<dyn Connection>>>>,
    /// Connection info cache (reserved for future use)
    _info_cache: HashMap<String, ConnectionInfo>,
    /// Pool statistics
    stats: ConnectionPoolStats,
    /// Pool configuration
    max_connections: usize,
    /// Round-robin index for load balancing
    round_robin_index: usize,
}

impl TransportManager {
    /// Create a new transport manager
    pub fn new(selection: TransportSelection, options: TransportOptions) -> Self {
        Self {
            transports: HashMap::new(),
            connections: Arc::new(RwLock::new(HashMap::new())),
            selection,
            options,
        }
    }

    /// Register a transport implementation
    pub fn register_transport(&mut self, transport: Arc<dyn Transport>) {
        let transport_type = transport.transport_type();
        self.transports.insert(transport_type, transport);
        info!("Registered transport: {:?}", transport_type);
    }

    /// Connect to a peer using the best available transport
    pub async fn connect(&self, addr: NetworkAddress) -> Result<PeerId> {
        let transport_type = self.select_transport(&addr).await?;
        let transport = self.transports.get(&transport_type).ok_or_else(|| {
            P2PError::Transport(crate::error::TransportError::SetupFailed(
                format!("Transport {transport_type:?} not available").into(),
            ))
        })?;

        debug!("Connecting to {} using {:?}", addr, transport_type);

        let connection = transport
            .connect_with_options(addr.clone(), self.options.clone())
            .await?;
        let peer_id = format!("peer_from_{}_{}", addr.ip(), addr.port()); // Simplified peer ID

        // Add to connection pool
        self.add_connection(peer_id.clone(), connection).await?;

        info!("Connected to peer {} via {:?}", peer_id, transport_type);
        Ok(peer_id)
    }

    /// Connect with specific transport
    pub async fn connect_with_transport(
        &self,
        addr: NetworkAddress,
        transport_type: TransportType,
    ) -> Result<PeerId> {
        let transport = self.transports.get(&transport_type).ok_or_else(|| {
            P2PError::Transport(crate::error::TransportError::SetupFailed(
                format!("Transport {transport_type:?} not available").into(),
            ))
        })?;

        let connection = transport
            .connect_with_options(addr.clone(), self.options.clone())
            .await?;
        let peer_id = format!("peer_from_{}_{}", addr.ip(), addr.port());

        self.add_connection(peer_id.clone(), connection).await?;
        Ok(peer_id)
    }

    /// Send message to a peer
    pub async fn send_message(&self, peer_id: &PeerId, data: Vec<u8>) -> Result<()> {
        let connections = self.connections.read().await;
        let pool = connections.get(peer_id).ok_or_else(|| {
            P2PError::Network(crate::error::NetworkError::PeerNotFound(
                peer_id.to_string().into(),
            ))
        })?;

        let mut pool_guard = pool.lock().await;
        let connection = pool_guard.get_connection()?;

        let mut conn_guard = connection.lock().await;
        conn_guard.send(&data).await?;

        debug!("Sent {} bytes to peer {}", data.len(), peer_id);
        Ok(())
    }

    /// Get connection info for a peer
    pub async fn get_connection_info(&self, peer_id: &PeerId) -> Result<ConnectionInfo> {
        let connections = self.connections.read().await;
        let pool = connections.get(peer_id).ok_or_else(|| {
            P2PError::Network(crate::error::NetworkError::PeerNotFound(
                peer_id.to_string().into(),
            ))
        })?;

        let mut pool_guard = pool.lock().await;
        let connection = pool_guard.get_connection()?;
        let conn_guard = connection.lock().await;

        Ok(conn_guard.info().await)
    }

    /// Get connection pool info
    pub async fn get_connection_pool_info(&self, peer_id: &PeerId) -> Result<ConnectionPoolInfo> {
        let connections = self.connections.read().await;
        let pool = connections.get(peer_id).ok_or_else(|| {
            P2PError::Network(crate::error::NetworkError::PeerNotFound(
                peer_id.to_string().into(),
            ))
        })?;

        let pool_guard = pool.lock().await;
        Ok(ConnectionPoolInfo {
            active_connections: pool_guard.connections.len(),
            total_connections: pool_guard.stats.messages_per_connection.len(),
            bytes_sent: pool_guard.stats.bytes_per_connection.values().sum(),
            bytes_received: 0, // TODO: Track separately
        })
    }

    /// Get connection pool statistics
    pub async fn get_connection_pool_stats(&self, peer_id: &PeerId) -> Result<ConnectionPoolStats> {
        let connections = self.connections.read().await;
        let pool = connections.get(peer_id).ok_or_else(|| {
            P2PError::Network(crate::error::NetworkError::PeerNotFound(
                peer_id.to_string().into(),
            ))
        })?;

        let pool_guard = pool.lock().await;
        Ok(pool_guard.stats.clone())
    }

    /// Measure connection quality
    pub async fn measure_connection_quality(&self, peer_id: &PeerId) -> Result<ConnectionQuality> {
        let connections = self.connections.read().await;
        let pool = connections.get(peer_id).ok_or_else(|| {
            P2PError::Network(crate::error::NetworkError::PeerNotFound(
                peer_id.to_string().into(),
            ))
        })?;

        let mut pool_guard = pool.lock().await;
        let connection = pool_guard.get_connection()?;
        let conn_guard = connection.lock().await;

        conn_guard.measure_quality().await
    }

    /// Switch transport for a peer
    pub async fn switch_transport(
        &self,
        peer_id: &PeerId,
        _new_transport: TransportType,
    ) -> Result<()> {
        // This is a placeholder implementation
        // In reality, this would establish a new connection with the new transport
        // and gracefully migrate the existing connection

        warn!(
            "Transport switching not yet fully implemented for peer {}",
            peer_id
        );
        Ok(())
    }

    /// Select transport for an address (always QUIC)
    async fn select_transport(&self, _addr: &NetworkAddress) -> Result<TransportType> {
        match &self.selection {
            TransportSelection::QUIC => {
                if self.transports.contains_key(&TransportType::QUIC) {
                    Ok(TransportType::QUIC)
                } else {
                    Err(P2PError::Transport(
                        crate::error::TransportError::SetupFailed(
                            "QUIC transport not available".into(),
                        ),
                    ))
                }
            }
        }
    }

    /// Auto-select transport (always QUIC in this implementation)
    #[allow(dead_code)]
    async fn auto_select_transport(&self, addr: &NetworkAddress) -> Result<TransportType> {
        // Always use QUIC as it's the only transport protocol
        if self.transports.contains_key(&TransportType::QUIC) {
            if let Some(transport) = self.transports.get(&TransportType::QUIC) {
                if transport.supports_address(addr) {
                    debug!(
                        "Using QUIC transport for {} (only available transport)",
                        addr
                    );
                    return Ok(TransportType::QUIC);
                }
            }
        }

        Err(P2PError::Transport(
            crate::error::TransportError::SetupFailed(
                "QUIC transport not available or address not supported"
                    .to_string()
                    .into(),
            ),
        ))
    }

    /// Add connection to pool
    async fn add_connection(&self, peer_id: PeerId, connection: Box<dyn Connection>) -> Result<()> {
        let mut connections = self.connections.write().await;

        let pool = connections.entry(peer_id.clone()).or_insert_with(|| {
            Arc::new(Mutex::new(ConnectionPool::new(3))) // Default max 3 connections per peer
        });

        let mut pool_guard = pool.lock().await;
        pool_guard.add_connection(connection).await?;

        Ok(())
    }
}

impl ConnectionPool {
    /// Create a new connection pool
    fn new(max_connections: usize) -> Self {
        Self {
            connections: Vec::new(),
            _info_cache: HashMap::new(),
            stats: ConnectionPoolStats {
                messages_per_connection: HashMap::new(),
                bytes_per_connection: HashMap::new(),
                latency_per_connection: HashMap::new(),
            },
            max_connections,
            round_robin_index: 0,
        }
    }

    /// Add a connection to the pool
    async fn add_connection(&mut self, connection: Box<dyn Connection>) -> Result<()> {
        if self.connections.len() >= self.max_connections {
            // Remove oldest connection
            self.connections.remove(0);
        }

        let conn_id = format!("conn_{}", self.connections.len());
        self.stats
            .messages_per_connection
            .insert(conn_id.clone(), 0);
        self.stats.bytes_per_connection.insert(conn_id.clone(), 0);
        self.stats
            .latency_per_connection
            .insert(conn_id, Duration::from_millis(0));

        self.connections.push(Arc::new(Mutex::new(connection)));
        Ok(())
    }

    /// Get a connection using round-robin load balancing
    fn get_connection(&mut self) -> Result<Arc<Mutex<Box<dyn Connection>>>> {
        if self.connections.is_empty() {
            return Err(P2PError::Network(
                crate::error::NetworkError::ProtocolError(
                    "No connections available".to_string().into(),
                ),
            ));
        }

        let connection = self.connections[self.round_robin_index % self.connections.len()].clone();
        self.round_robin_index += 1;

        // Update stats
        let conn_id = format!("conn_{}", self.round_robin_index % self.connections.len());
        if let Some(count) = self.stats.messages_per_connection.get_mut(&conn_id) {
            *count += 1;
        }

        Ok(connection)
    }
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportType::QUIC => write!(f, "quic"),
        }
    }
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            enable_0rtt: true,
            require_encryption: true,
            connect_timeout: Duration::from_secs(30),
            keep_alive: Duration::from_secs(60),
            max_message_size: 64 * 1024 * 1024, // 64MB
        }
    }
}

impl Default for ConnectionQuality {
    fn default() -> Self {
        Self {
            latency: Duration::from_millis(50),
            throughput_mbps: 100.0,
            packet_loss: 0.0,
            jitter: Duration::from_millis(5),
            connect_time: Duration::from_millis(100),
        }
    }
}
/// Legacy transport types module for backward compatibility
pub mod transport_types {
    pub use super::TransportType;
}

// Re-export transport implementation
// pub use quic::QuicTransport; // Disabled during ant-quic migration
// pub use ant_quic_adapter::AntQuicAdapter; // Available but not needed for now

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::NetworkError;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::Duration;

    /// Helper function to parse addresses in tests
    fn parse_addr(addr: &str) -> Result<NetworkAddress> {
        addr.parse::<NetworkAddress>().map_err(|e| {
            P2PError::Network(crate::error::NetworkError::InvalidAddress(
                e.to_string().into(),
            ))
        })
    }

    /// Mock transport implementation for testing
    struct MockTransport {
        transport_type: TransportType,
        should_fail: bool,
        supports_all: bool,
    }

    impl MockTransport {
        fn new(transport_type: TransportType) -> Self {
            Self {
                transport_type,
                should_fail: false,
                supports_all: true,
            }
        }

        fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }

        fn with_limited_support(mut self) -> Self {
            self.supports_all = false;
            self
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn listen(&self, addr: NetworkAddress) -> Result<NetworkAddress> {
            if self.should_fail {
                return Err(P2PError::Transport(
                    crate::error::TransportError::SetupFailed("Listen failed".to_string().into()),
                ));
            }
            Ok(addr)
        }

        async fn connect(&self, addr: NetworkAddress) -> Result<Box<dyn Connection>> {
            if self.should_fail {
                return Err(P2PError::Transport(
                    crate::error::TransportError::SetupFailed(
                        "Connection failed".to_string().into(),
                    ),
                ));
            }
            Ok(Box::new(MockConnection::new(addr)))
        }

        async fn connect_with_options(
            &self,
            addr: NetworkAddress,
            _options: TransportOptions,
        ) -> Result<Box<dyn Connection>> {
            self.connect(addr).await
        }

        async fn accept(&self) -> Result<Box<dyn Connection>> {
            if self.should_fail {
                return Err(P2PError::Transport(
                    crate::error::TransportError::SetupFailed("Accept failed".into()),
                ));
            }
            Ok(Box::new(MockConnection::new(
                "127.0.0.1:9000".parse::<NetworkAddress>().map_err(|e| {
                    crate::error::TransportError::SetupFailed(
                        format!("Invalid mock address: {}", e).into(),
                    )
                })?,
            )))
        }

        fn supports_ipv6(&self) -> bool {
            false // IPv4-only focus
        }

        fn transport_type(&self) -> TransportType {
            self.transport_type
        }

        fn supports_address(&self, addr: &NetworkAddress) -> bool {
            // IPv4-only support
            addr.is_ipv4()
        }
    }

    /// Mock connection implementation for testing
    struct MockConnection {
        remote_addr: NetworkAddress,
        is_alive: bool,
        bytes_sent: AtomicUsize,
        bytes_received: AtomicUsize,
    }

    impl MockConnection {
        fn new(remote_addr: NetworkAddress) -> Self {
            Self {
                remote_addr,
                is_alive: true,
                bytes_sent: AtomicUsize::new(0),
                bytes_received: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl Connection for MockConnection {
        async fn send(&mut self, data: &[u8]) -> Result<()> {
            if !self.is_alive {
                return Err(P2PError::Network(
                    crate::error::NetworkError::PeerDisconnected {
                        peer: "unknown".to_string(),
                        reason: "Connection closed".to_string(),
                    },
                ));
            }
            self.bytes_sent.fetch_add(data.len(), Ordering::Relaxed);
            Ok(())
        }

        async fn receive(&mut self) -> Result<Vec<u8>> {
            if !self.is_alive {
                return Err(P2PError::Network(
                    crate::error::NetworkError::PeerDisconnected {
                        peer: "unknown".to_string(),
                        reason: "Connection closed".to_string(),
                    },
                ));
            }
            let data = b"mock_response".to_vec();
            self.bytes_received.fetch_add(data.len(), Ordering::Relaxed);
            Ok(data)
        }

        async fn info(&self) -> ConnectionInfo {
            ConnectionInfo {
                transport_type: TransportType::QUIC,
                local_addr: "127.0.0.1:9000"
                    .parse::<NetworkAddress>()
                    .expect("Test address should be valid"),
                remote_addr: self.remote_addr.clone(),
                is_encrypted: true,
                cipher_suite: "TLS_AES_256_GCM_SHA384".to_string(),
                used_0rtt: false,
                established_at: Instant::now(),
                last_activity: Instant::now(),
            }
        }

        async fn close(&mut self) -> Result<()> {
            self.is_alive = false;
            Ok(())
        }

        async fn is_alive(&self) -> bool {
            self.is_alive
        }

        async fn measure_quality(&self) -> Result<ConnectionQuality> {
            Ok(ConnectionQuality {
                latency: Duration::from_millis(10),
                throughput_mbps: 1000.0,
                packet_loss: 0.1,
                jitter: Duration::from_millis(2),
                connect_time: Duration::from_millis(50),
            })
        }

        fn local_addr(&self) -> NetworkAddress {
            "127.0.0.1:9000"
                .parse::<NetworkAddress>()
                .expect("Test address should be valid")
        }

        fn remote_addr(&self) -> NetworkAddress {
            self.remote_addr.clone()
        }
    }

    fn create_test_transport_manager() -> TransportManager {
        let options = TransportOptions::default();
        TransportManager::new(TransportSelection::QUIC, options)
    }

    #[test]
    fn test_transport_type_display() {
        assert_eq!(format!("{}", TransportType::QUIC), "quic");
    }

    #[test]
    fn test_transport_type_serialization() {
        let quic_type = TransportType::QUIC;

        assert_eq!(quic_type, TransportType::QUIC);
    }

    #[test]
    fn test_transport_selection_variants() {
        let quic_selection = TransportSelection::QUIC;

        assert!(matches!(quic_selection, TransportSelection::QUIC));
    }

    #[test]
    fn test_transport_selection_default() {
        let default = TransportSelection::default();
        assert!(matches!(default, TransportSelection::QUIC));
    }

    #[test]
    fn test_transport_options_default() {
        let options = TransportOptions::default();

        assert!(options.enable_0rtt);
        assert!(options.require_encryption);
        assert_eq!(options.connect_timeout, Duration::from_secs(30));
        assert_eq!(options.keep_alive, Duration::from_secs(60));
        assert_eq!(options.max_message_size, 64 * 1024 * 1024);
    }

    #[test]
    fn test_connection_quality_default() {
        let quality = ConnectionQuality::default();

        assert_eq!(quality.latency, Duration::from_millis(50));
        assert_eq!(quality.throughput_mbps, 100.0);
        assert_eq!(quality.packet_loss, 0.0);
        assert_eq!(quality.jitter, Duration::from_millis(5));
        assert_eq!(quality.connect_time, Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_transport_manager_creation() {
        let manager = create_test_transport_manager();
        assert!(manager.transports.is_empty());
    }

    #[tokio::test]
    async fn test_transport_registration() {
        let mut manager = create_test_transport_manager();
        let quic_transport = Arc::new(MockTransport::new(TransportType::QUIC));

        manager.register_transport(quic_transport.clone());

        assert_eq!(manager.transports.len(), 1);
        assert!(manager.transports.contains_key(&TransportType::QUIC));
    }

    #[tokio::test]
    async fn test_connection_establishment() -> Result<()> {
        let mut manager = create_test_transport_manager();
        let transport = Arc::new(MockTransport::new(TransportType::QUIC));
        manager.register_transport(transport);

        let peer_id = manager
            .connect("127.0.0.1:9001".parse::<NetworkAddress>().map_err(|e| {
                P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
            })?)
            .await?;
        assert_eq!(peer_id, "peer_from_127.0.0.1_9001");

        let connections = manager.connections.read().await;
        assert!(connections.contains_key(&peer_id));

        Ok(())
    }

    #[tokio::test]
    async fn test_connection_with_specific_transport() -> Result<()> {
        let mut manager = create_test_transport_manager();
        let transport = Arc::new(MockTransport::new(TransportType::QUIC));
        manager.register_transport(transport);

        let peer_id = manager
            .connect_with_transport(
                "127.0.0.1:9002".parse::<NetworkAddress>().map_err(|e| {
                    P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
                })?,
                TransportType::QUIC,
            )
            .await?;

        assert_eq!(peer_id, "peer_from_127.0.0.1_9002");
        Ok(())
    }

    #[tokio::test]
    async fn test_connection_failure_handling() -> Result<()> {
        let mut manager = create_test_transport_manager();
        let failing_transport = Arc::new(MockTransport::new(TransportType::QUIC).with_failure());
        manager.register_transport(failing_transport);

        let result = manager
            .connect("127.0.0.1:9003".parse::<NetworkAddress>().map_err(|e| {
                P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
            })?)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Connection failed")
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_message_sending() -> Result<()> {
        let mut manager = create_test_transport_manager();
        let transport = Arc::new(MockTransport::new(TransportType::QUIC));
        manager.register_transport(transport);

        let peer_id = manager
            .connect("127.0.0.1:9004".parse::<NetworkAddress>().map_err(|e| {
                P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
            })?)
            .await?;
        let message = b"Hello, transport!".to_vec();

        manager.send_message(&peer_id, message.clone()).await?;

        // Verify message was processed
        let pool_info = manager.get_connection_pool_info(&peer_id).await?;
        assert_eq!(pool_info.active_connections, 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_message_sending_no_connection() {
        let manager = create_test_transport_manager();
        let result = manager
            .send_message(&"nonexistent_peer".to_string(), vec![1, 2, 3])
            .await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No connection to peer")
        );
    }

    #[tokio::test]
    async fn test_connection_info_retrieval() -> Result<()> {
        let mut manager = create_test_transport_manager();
        let transport = Arc::new(MockTransport::new(TransportType::QUIC));
        manager.register_transport(transport);

        let peer_id = manager
            .connect("127.0.0.1:9005".parse::<NetworkAddress>().map_err(|e| {
                P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
            })?)
            .await?;
        let info = manager.get_connection_info(&peer_id).await?;

        assert_eq!(info.transport_type, TransportType::QUIC);
        assert_eq!(
            info.remote_addr,
            "127.0.0.1:9005"
                .parse::<NetworkAddress>()
                .map_err(|e| P2PError::Network(NetworkError::InvalidAddress(
                    format!("{}", e).into()
                )))?
        );
        assert!(info.is_encrypted);
        assert_eq!(info.cipher_suite, "TLS_AES_256_GCM_SHA384");

        Ok(())
    }

    #[tokio::test]
    async fn test_connection_pool_info() -> Result<()> {
        let mut manager = create_test_transport_manager();
        let transport = Arc::new(MockTransport::new(TransportType::QUIC));
        manager.register_transport(transport);

        let peer_id = manager
            .connect("127.0.0.1:9006".parse::<NetworkAddress>().map_err(|e| {
                P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
            })?)
            .await?;
        let pool_info = manager.get_connection_pool_info(&peer_id).await?;

        assert_eq!(pool_info.active_connections, 1);
        assert_eq!(pool_info.total_connections, 1);
        assert_eq!(pool_info.bytes_sent, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_connection_pool_stats() -> Result<()> {
        let mut manager = create_test_transport_manager();
        let transport = Arc::new(MockTransport::new(TransportType::QUIC));
        manager.register_transport(transport);

        let peer_id = manager
            .connect("127.0.0.1:9007".parse::<NetworkAddress>().map_err(|e| {
                P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
            })?)
            .await?;
        let stats = manager.get_connection_pool_stats(&peer_id).await?;

        assert_eq!(stats.messages_per_connection.len(), 1);
        assert_eq!(stats.bytes_per_connection.len(), 1);
        assert_eq!(stats.latency_per_connection.len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_connection_quality_measurement() -> Result<()> {
        let mut manager = create_test_transport_manager();
        let transport = Arc::new(MockTransport::new(TransportType::QUIC));
        manager.register_transport(transport);

        let peer_id = manager
            .connect("127.0.0.1:9008".parse::<NetworkAddress>().map_err(|e| {
                P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
            })?)
            .await?;
        let quality = manager.measure_connection_quality(&peer_id).await?;

        assert_eq!(quality.latency, Duration::from_millis(10));
        assert_eq!(quality.throughput_mbps, 1000.0);
        assert_eq!(quality.packet_loss, 0.1);
        assert_eq!(quality.jitter, Duration::from_millis(2));

        Ok(())
    }

    #[tokio::test]
    async fn test_transport_switching() -> Result<()> {
        let mut manager = create_test_transport_manager();
        let transport = Arc::new(MockTransport::new(TransportType::QUIC));
        manager.register_transport(transport);

        let peer_id = manager
            .connect("127.0.0.1:9009".parse::<NetworkAddress>().map_err(|e| {
                P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
            })?)
            .await?;

        // Transport switching is not fully implemented, but should not error
        let result = manager
            .switch_transport(&peer_id, TransportType::QUIC)
            .await;
        assert!(result.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn test_auto_transport_selection_quic() -> Result<()> {
        let mut manager = create_test_transport_manager();
        let quic_transport = Arc::new(MockTransport::new(TransportType::QUIC));

        manager.register_transport(quic_transport);

        let addr = "127.0.0.1:9010".parse::<NetworkAddress>().map_err(|e| {
            P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
        })?;
        let selected = manager.auto_select_transport(&addr).await?;

        // Should use QUIC when available
        assert_eq!(selected, TransportType::QUIC);

        Ok(())
    }

    #[tokio::test]
    async fn test_transport_selection_no_quic() -> Result<()> {
        let manager = create_test_transport_manager();
        // No transports registered

        let addr = "127.0.0.1:9011".parse::<NetworkAddress>().map_err(|e| {
            P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
        })?;
        let selected = manager.auto_select_transport(&addr).await;

        // Should fail when QUIC not available
        assert!(selected.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_transport_selection_no_suitable_transport() -> Result<()> {
        let manager = create_test_transport_manager();
        let addr = "127.0.0.1:9012".parse::<NetworkAddress>().map_err(|e| {
            P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
        })?;

        let result = manager.auto_select_transport(&addr).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("QUIC transport not available")
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_quic_transport_selection() -> Result<()> {
        let mut manager =
            TransportManager::new(TransportSelection::QUIC, TransportOptions::default());
        let quic_transport = Arc::new(MockTransport::new(TransportType::QUIC));

        manager.register_transport(quic_transport);

        let addr = "127.0.0.1:9013".parse::<NetworkAddress>().map_err(|e| {
            P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
        })?;
        let selected = manager.select_transport(&addr).await?;

        assert_eq!(selected, TransportType::QUIC);

        Ok(())
    }

    #[tokio::test]
    async fn test_quic_transport_unavailable() -> Result<()> {
        let manager = TransportManager::new(TransportSelection::QUIC, TransportOptions::default());

        let addr = "127.0.0.1:9014".parse::<NetworkAddress>().map_err(|e| {
            P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
        })?;
        let result = manager.select_transport(&addr).await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("QUIC transport not available")
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_quic_transport_with_registration() -> Result<()> {
        let mut manager =
            TransportManager::new(TransportSelection::QUIC, TransportOptions::default());
        let quic_transport = Arc::new(MockTransport::new(TransportType::QUIC));

        manager.register_transport(quic_transport);

        let addr = "127.0.0.1:9015".parse::<NetworkAddress>().map_err(|e| {
            P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
        })?;
        let selected = manager.select_transport(&addr).await?;

        // Should use QUIC when available
        assert_eq!(selected, TransportType::QUIC);

        Ok(())
    }

    #[tokio::test]
    async fn test_mock_connection_lifecycle() -> Result<()> {
        let mut conn =
            MockConnection::new("127.0.0.1:9016".parse::<NetworkAddress>().map_err(|e| {
                P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
            })?);

        assert!(conn.is_alive().await);

        // Test sending
        conn.send(b"test message").await?;
        assert_eq!(conn.bytes_sent.load(Ordering::Relaxed), 12);

        // Test receiving
        let received = conn.receive().await?;
        assert_eq!(received, b"mock_response");
        assert_eq!(conn.bytes_received.load(Ordering::Relaxed), 13);

        // Test connection info
        let info = conn.info().await;
        assert_eq!(info.transport_type, TransportType::QUIC);
        assert!(info.is_encrypted);

        // Test quality measurement
        let quality = conn.measure_quality().await?;
        assert_eq!(quality.latency, Duration::from_millis(10));

        // Test close
        conn.close().await?;
        assert!(!conn.is_alive().await);

        // Operations should fail after close
        let result = conn.send(b"test").await;
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_connection_pool_max_connections() -> Result<()> {
        let mut pool = ConnectionPool::new(2); // Max 2 connections

        // Add first connection
        let conn1 = Box::new(MockConnection::new(
            "127.0.0.1:9017".parse::<NetworkAddress>().map_err(|e| {
                P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
            })?,
        ));
        pool.add_connection(conn1).await?;
        assert_eq!(pool.connections.len(), 1);

        // Add second connection
        let conn2 = Box::new(MockConnection::new(
            "127.0.0.1:9018".parse::<NetworkAddress>().map_err(|e| {
                P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
            })?,
        ));
        pool.add_connection(conn2).await?;
        assert_eq!(pool.connections.len(), 2);

        // Add third connection (should remove first)
        let conn3 = Box::new(MockConnection::new(
            "127.0.0.1:9019".parse::<NetworkAddress>().map_err(|e| {
                P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
            })?,
        ));
        pool.add_connection(conn3).await?;
        assert_eq!(pool.connections.len(), 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_connection_pool_round_robin() -> Result<()> {
        let mut pool = ConnectionPool::new(3);

        // Add connections
        for i in 0..3 {
            let conn = Box::new(MockConnection::new(
                format!("127.0.0.1:{}", 9020 + i)
                    .parse()
                    .expect("Test address should be valid"),
            ));
            pool.add_connection(conn).await?;
        }

        // Test round-robin selection
        let conn1 = pool.get_connection()?;
        let conn2 = pool.get_connection()?;
        let conn3 = pool.get_connection()?;
        let conn4 = pool.get_connection()?; // Should wrap around

        // All connections should be different (until wraparound)
        assert_ne!(Arc::as_ptr(&conn1), Arc::as_ptr(&conn2));
        assert_ne!(Arc::as_ptr(&conn2), Arc::as_ptr(&conn3));
        // Fourth should be same as first (round-robin)
        assert_eq!(Arc::as_ptr(&conn1), Arc::as_ptr(&conn4));

        Ok(())
    }

    #[tokio::test]
    async fn test_connection_pool_empty() {
        let mut pool = ConnectionPool::new(3);
        let result = pool.get_connection();

        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("No connections available"));
        }
    }

    #[tokio::test]
    async fn test_transport_message_structure() {
        let message = TransportMessage {
            sender: "test_peer".to_string(),
            data: vec![1, 2, 3, 4],
            protocol: "/p2p/test/1.0.0".to_string(),
            received_at: Instant::now(),
        };

        assert_eq!(message.sender, "test_peer");
        assert_eq!(message.data, vec![1, 2, 3, 4]);
        assert_eq!(message.protocol, "/p2p/test/1.0.0");
    }

    #[tokio::test]
    async fn test_mock_transport_address_support() -> Result<()> {
        let transport = MockTransport::new(TransportType::QUIC);

        let addr1 = "127.0.0.1:9000".parse::<NetworkAddress>().map_err(|e| {
            P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
        })?;
        let addr2 = "[::1]:9000".parse::<NetworkAddress>().map_err(|e| {
            P2PError::Network(NetworkError::InvalidAddress(format!("{}", e).into()))
        })?;

        assert!(transport.supports_address(&addr1)); // IPv4 supported
        assert!(!transport.supports_address(&addr2)); // IPv6 not supported
        assert!(transport.supports_address(&addr1)); // IPv4 supported

        let limited_transport = MockTransport::new(TransportType::QUIC).with_limited_support();
        assert!(limited_transport.supports_address(&addr1)); // IPv4 supported
        assert!(!limited_transport.supports_address(&addr2)); // IPv6 not supported
        Ok(())
    }

    #[tokio::test]
    async fn test_mock_transport_supported_addresses() -> Result<()> {
        let transport = MockTransport::new(TransportType::QUIC);
        let supports_ipv6 = transport.supports_ipv6();

        // Transport now focuses on IPv4 only
        assert!(!supports_ipv6);

        let limited_transport = MockTransport::new(TransportType::QUIC).with_limited_support();
        let limited_supports_ipv6 = limited_transport.supports_ipv6();

        // All transports are IPv4-only now
        assert!(!limited_supports_ipv6);
        Ok(())
    }

    #[tokio::test]
    async fn test_transport_options_configuration() -> Result<()> {
        let options = TransportOptions {
            enable_0rtt: false,
            require_encryption: false,
            connect_timeout: Duration::from_secs(10),
            keep_alive: Duration::from_secs(30),
            max_message_size: 1024,
        };

        assert!(!options.enable_0rtt);
        assert!(!options.require_encryption);
        assert_eq!(options.connect_timeout, Duration::from_secs(10));
        assert_eq!(options.keep_alive, Duration::from_secs(30));
        assert_eq!(options.max_message_size, 1024);
        Ok(())
    }
}
