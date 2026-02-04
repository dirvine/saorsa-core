// Network transport layer for messaging
// Integrates with the existing P2P network infrastructure

use super::DhtClient;
use super::key_exchange::KeyExchangeMessage;
use super::types::*;
use crate::identity::FourWordAddress;
use crate::network::P2PNode;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tokio::time::{Duration, interval};
use tracing::{debug, info, warn};

/// Message transport layer for real-time messaging
pub struct MessageTransport {
    /// Reference to the P2P network node
    network: Arc<P2PNode>,
    /// DHT client for distributed storage
    dht_client: DhtClient,
    /// Connection pool for efficient message delivery
    connections: Arc<RwLock<ConnectionPool>>,
    /// Message queue for offline delivery
    message_queue: Arc<RwLock<MessageQueue>>,
    /// Delivery confirmations tracking
    confirmations: Arc<RwLock<HashMap<MessageId, DeliveryStatus>>>,
    /// Network metrics
    metrics: Arc<RwLock<NetworkMetrics>>,
    /// Event broadcaster
    event_tx: broadcast::Sender<TransportEvent>,
    /// Key exchange message broadcaster
    key_exchange_tx: broadcast::Sender<KeyExchangeMessage>,
}

impl MessageTransport {
    /// Create new message transport
    pub async fn new(network: Arc<P2PNode>, dht_client: DhtClient) -> Result<Self> {
        let (event_tx, _) = broadcast::channel(1000);
        let (key_exchange_tx, _) = broadcast::channel(100);

        Ok(Self {
            network,
            dht_client,
            connections: Arc::new(RwLock::new(ConnectionPool::new())),
            message_queue: Arc::new(RwLock::new(MessageQueue::new())),
            confirmations: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(NetworkMetrics::default())),
            event_tx,
            key_exchange_tx,
        })
    }

    /// Get reference to underlying P2P node
    pub fn network(&self) -> &Arc<P2PNode> {
        &self.network
    }

    /// Send a message to recipients
    pub async fn send_message(
        &self,
        message: &EncryptedMessage,
        recipients: Vec<FourWordAddress>,
    ) -> Result<DeliveryReceipt> {
        debug!(
            "Sending message {} to {} recipients",
            message.id,
            recipients.len()
        );

        let mut delivery_results = Vec::new();
        let mut metrics = self.metrics.write().await;

        for recipient in recipients {
            // Try direct delivery first
            match self.try_direct_delivery(&recipient, message).await {
                Ok(status) => {
                    delivery_results.push((recipient.clone(), status));
                    metrics.messages_sent += 1;
                }
                Err(e) => {
                    debug!("Direct delivery failed for {}: {}, queuing", recipient, e);

                    // Queue for later delivery
                    self.queue_message(&recipient, message).await?;
                    delivery_results.push((recipient.clone(), DeliveryStatus::Queued));
                    metrics.messages_queued += 1;
                }
            }
        }

        // Store in DHT for persistence
        self.store_in_dht(message).await?;

        // Create delivery receipt
        let receipt = DeliveryReceipt {
            message_id: message.id,
            timestamp: Utc::now(),
            delivery_status: delivery_results,
        };

        // Track confirmations
        let mut confirmations = self.confirmations.write().await;
        for (_recipient, status) in &receipt.delivery_status {
            confirmations.insert(message.id, status.clone());
        }

        Ok(receipt)
    }

    /// Receive messages from the network
    pub async fn receive_messages(&self) -> broadcast::Receiver<ReceivedMessage> {
        let (tx, rx) = broadcast::channel(256);

        // Subscribe to network events and forward "messaging" topic messages
        let mut events = self.network.subscribe_events();
        let kex_tx = self.key_exchange_tx.clone();

        tokio::spawn(async move {
            while let Ok(event) = events.recv().await {
                if let crate::network::P2PEvent::Message {
                    topic,
                    source,
                    data,
                } = event
                {
                    if topic == "messaging" {
                        // Repackage for messaging consumers
                        let encrypted_msg = EncryptedMessage {
                            id: MessageId::new(),
                            channel_id: ChannelId::new(),
                            sender: FourWordAddress::parse_str(&source)
                                .unwrap_or_else(|_| FourWordAddress("unknown".to_string())),
                            ciphertext: data,
                            nonce: vec![], // TODO: Generate proper nonce
                            key_id: "default".to_string(),
                        };
                        let _ = tx.send(ReceivedMessage {
                            message: encrypted_msg,
                            received_at: Utc::now(),
                        });
                    } else if topic == "key_exchange" {
                        // Handle key exchange messages
                        match postcard::from_bytes::<KeyExchangeMessage>(&data) {
                            Ok(kex_msg) => {
                                debug!("Received key exchange message from {}", source);
                                let _ = kex_tx.send(kex_msg);
                            }
                            Err(e) => {
                                warn!("Failed to deserialize key exchange message: {}", e);
                            }
                        }
                    }
                }
            }
        });

        rx
    }

    /// Establish a direct connection to a peer
    pub async fn connect_to_peer(&self, peer: &FourWordAddress) -> Result<()> {
        debug!("Establishing connection to {}", peer);

        // Resolve peer address through DHT
        let peer_info = self.resolve_peer_address(peer).await?;

        // Create connection
        let mut pool = self.connections.write().await;
        pool.add_connection(peer.clone(), peer_info).await?;

        // Send presence update
        self.broadcast_presence(PresenceStatus::Online).await?;

        Ok(())
    }

    /// Monitor network quality and adapt behavior
    pub async fn monitor_network_quality(&self) {
        let metrics = self.metrics.clone();
        let connections = self.connections.clone();

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(10));

            loop {
                ticker.tick().await;

                // Calculate network quality metrics
                let mut metrics = metrics.write().await;
                let pool = connections.read().await;

                metrics.update_quality(&pool);

                // Adapt behavior based on quality
                if metrics.average_latency > Duration::from_millis(500) {
                    debug!("High latency detected, adjusting parameters");
                    // Implement adaptive behavior
                }

                if metrics.packet_loss > 0.05 {
                    warn!("High packet loss: {:.2}%", metrics.packet_loss * 100.0);
                    // Implement recovery strategies
                }
            }
        });
    }

    /// Process queued messages
    pub async fn process_message_queue(&self) {
        let queue = self.message_queue.clone();
        let transport = Arc::new(self.clone());

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(30));

            loop {
                ticker.tick().await;

                let mut queue = queue.write().await;
                let messages = queue.get_pending_messages();

                for (recipient, message) in messages {
                    // Retry delivery
                    if let Ok(_status) = transport.try_direct_delivery(&recipient, &message).await {
                        queue.mark_delivered(&message.id);
                        info!("Delivered queued message {} to {}", message.id, recipient);
                    }
                }

                // Clean up old messages
                queue.cleanup_expired().await;
            }
        });
    }

    /// Try direct delivery to a peer
    async fn try_direct_delivery(
        &self,
        recipient: &FourWordAddress,
        message: &EncryptedMessage,
    ) -> Result<DeliveryStatus> {
        // Serialize payload
        let data = serde_json::to_vec(message)?;

        // Resolve peer addresses from DHT
        let peer_info = self.resolve_peer_address(recipient).await?;

        // Try each address, checking for existing connections first
        for addr in &peer_info.addresses {
            // Check if we already have an active connection to this address
            let peer_id =
                if let Some(existing_peer_id) = self.network.get_peer_id_by_address(addr).await {
                    debug!(
                        "Reusing existing connection to {} at {} (peer {})",
                        recipient, addr, existing_peer_id
                    );
                    existing_peer_id
                } else {
                    // No existing connection, establish a new one
                    match self.network.connect_peer(addr).await {
                        Ok(peer_id) => {
                            debug!(
                                "Established new connection to {} at {} (peer {})",
                                recipient, addr, peer_id
                            );
                            peer_id
                        }
                        Err(e) => {
                            debug!("Cannot connect to {} at {}: {}", recipient, addr, e);
                            continue; // Try next address
                        }
                    }
                };

            // Send message using the connection (either reused or new)
            // P2PNode's send_message() now validates connection state via is_connection_active()
            // and automatically cleans up stale connections, so we don't need reconnection logic here
            match self
                .network
                .send_message(&peer_id, "messaging", data.clone())
                .await
            {
                Ok(_) => {
                    debug!(
                        "Message {} delivered to {} (peer {})",
                        message.id, recipient, peer_id
                    );
                    return Ok(DeliveryStatus::Delivered(Utc::now()));
                }
                Err(e) => {
                    // P2PNode already validated connection and cleaned up if needed
                    // Just log and try next address
                    warn!(
                        "Failed to send message {} to {} (peer {}) at {}: {}",
                        message.id, recipient, peer_id, addr, e
                    );
                    continue; // Try next address
                }
            }
        }

        Err(anyhow::anyhow!(
            "Delivery failed: no reachable endpoints for {}",
            recipient
        ))
    }

    /// Queue message for later delivery
    async fn queue_message(
        &self,
        recipient: &FourWordAddress,
        message: &EncryptedMessage,
    ) -> Result<()> {
        let mut queue = self.message_queue.write().await;
        queue.add_message(recipient.clone(), message.clone());
        debug!("Queued message {} for {}", message.id, recipient);
        Ok(())
    }

    /// Store message in DHT for persistence
    async fn store_in_dht(&self, message: &EncryptedMessage) -> Result<()> {
        let key = format!("msg:{}", message.id);
        let value = serde_json::to_vec(message)?;

        self.dht_client.put(key, value).await?;
        debug!("Stored message {} in DHT", message.id);

        Ok(())
    }

    /// Resolve peer address through DHT
    async fn resolve_peer_address(&self, peer: &FourWordAddress) -> Result<PeerInfo> {
        let key = format!("peer:{}", peer);

        if let Some(data) = self.dht_client.get(key).await? {
            let info: PeerInfo = serde_json::from_slice(&data)?;
            Ok(info)
        } else {
            Err(anyhow::anyhow!("Peer {} not found in DHT", peer))
        }
    }

    /// Broadcast presence status
    async fn broadcast_presence(&self, status: PresenceStatus) -> Result<()> {
        let event = TransportEvent::PresenceUpdate {
            status,
            timestamp: Utc::now(),
        };

        let _ = self.event_tx.send(event);
        Ok(())
    }

    /// Subscribe to transport events
    pub fn subscribe_events(&self) -> broadcast::Receiver<TransportEvent> {
        self.event_tx.subscribe()
    }

    /// Get network metrics
    pub async fn get_metrics(&self) -> NetworkMetrics {
        self.metrics.read().await.clone()
    }

    // ===== Key Exchange Methods =====

    /// Send a key exchange message to a peer
    pub async fn send_key_exchange_message(
        &self,
        recipient: &FourWordAddress,
        message: KeyExchangeMessage,
    ) -> Result<()> {
        debug!("Sending key exchange message to {}", recipient);

        // Serialize the key exchange message
        let data = postcard::to_stdvec(&message)
            .map_err(|e| anyhow::anyhow!("Failed to serialize key exchange message: {}", e))?;

        // Resolve peer address through DHT
        let peer_info = self.resolve_peer_address(recipient).await?;

        // Try to send via each known address
        let mut last_error: Option<anyhow::Error> = None;
        for addr in &peer_info.addresses {
            match self.network.connect_peer(addr).await {
                Ok(peer_id) => {
                    // Send via the key_exchange topic
                    match self
                        .network
                        .send_message(&peer_id, "key_exchange", data.clone())
                        .await
                    {
                        Ok(_) => {
                            info!(
                                "Key exchange message sent to {} (peer {})",
                                recipient, peer_id
                            );
                            return Ok(());
                        }
                        Err(e) => {
                            warn!(
                                "Failed sending key exchange to {} via {}: {}",
                                recipient, addr, e
                            );
                            last_error = Some(anyhow::Error::from(e));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed connecting to {} at {}: {}", recipient, addr, e);
                    last_error = Some(anyhow::Error::from(e));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Failed to send key exchange message")))
    }

    /// Subscribe to incoming key exchange messages
    pub fn subscribe_key_exchange(&self) -> broadcast::Receiver<KeyExchangeMessage> {
        self.key_exchange_tx.subscribe()
    }

    // ===== P2P Networking Methods =====

    /// Get the local network address(es) this node is listening on
    pub async fn listen_addrs(&self) -> Vec<std::net::SocketAddr> {
        self.network.listen_addrs().await
    }

    /// Get the list of currently connected peer IDs
    pub async fn connected_peers(&self) -> Vec<crate::PeerId> {
        self.network.connected_peers().await
    }

    /// Get the count of currently connected peers
    pub async fn peer_count(&self) -> usize {
        self.network.peer_count().await
    }

    /// Connect to a peer via their network address
    ///
    /// # Arguments
    /// * `address` - Network address in format "ip:port" or "\[ipv6\]:port"
    ///
    /// # Returns
    /// The peer ID of the connected peer
    pub async fn connect_peer(&self, address: &str) -> Result<crate::PeerId> {
        self.network
            .connect_peer(address)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to peer: {}", e))
    }

    /// Disconnect from a specific peer
    ///
    /// # Arguments
    /// * `peer_id` - The peer ID to disconnect from
    pub async fn disconnect_peer(&self, peer_id: &crate::PeerId) -> Result<()> {
        self.network
            .disconnect_peer(peer_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to disconnect from peer: {}", e))
    }
}

/// Connection pool for managing peer connections
#[derive(Debug, Clone)]
struct ConnectionPool {
    connections: HashMap<FourWordAddress, PeerConnection>,
    max_connections: usize,
}

impl ConnectionPool {
    fn new() -> Self {
        Self {
            connections: HashMap::new(),
            max_connections: 100,
        }
    }

    async fn add_connection(&mut self, peer: FourWordAddress, info: PeerInfo) -> Result<()> {
        // Check connection limit
        if self.connections.len() >= self.max_connections {
            // Remove least recently used
            self.evict_lru();
        }

        let connection = PeerConnection {
            _peer: peer.clone(),
            _info: info,
            _established_at: Utc::now(),
            last_activity: Utc::now(),
            quality: ConnectionQuality::default(),
        };

        self.connections.insert(peer, connection);
        Ok(())
    }

    fn evict_lru(&mut self) {
        // Find and remove least recently used connection
        if let Some((peer, _)) = self
            .connections
            .iter()
            .min_by_key(|(_, conn)| conn.last_activity)
        {
            let peer = peer.clone();
            self.connections.remove(&peer);
        }
    }
}

/// Individual peer connection
#[derive(Debug, Clone)]
struct PeerConnection {
    _peer: FourWordAddress,
    _info: PeerInfo,
    _established_at: DateTime<Utc>,
    last_activity: DateTime<Utc>,
    quality: ConnectionQuality,
}

impl PeerConnection {
    #[allow(dead_code)]
    async fn send(&self, _data: Vec<u8>) -> Result<()> {
        Ok(())
    }
}

/// Peer information stored in DHT
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PeerInfo {
    addresses: Vec<String>,
    public_key: Vec<u8>,
    capabilities: Vec<String>,
    last_seen: DateTime<Utc>,
}

/// Connection quality metrics
#[derive(Debug, Clone, Default)]
struct ConnectionQuality {
    latency: Duration,
    packet_loss: f32,
    _bandwidth: u64,
}

/// Message queue for offline delivery
#[derive(Debug)]
struct MessageQueue {
    messages: HashMap<MessageId, QueuedMessage>,
    by_recipient: HashMap<FourWordAddress, Vec<MessageId>>,
}

impl MessageQueue {
    fn new() -> Self {
        Self {
            messages: HashMap::new(),
            by_recipient: HashMap::new(),
        }
    }

    fn add_message(&mut self, recipient: FourWordAddress, message: EncryptedMessage) {
        let queued = QueuedMessage {
            message: message.clone(),
            recipient: recipient.clone(),
            queued_at: Utc::now(),
            retry_count: 0,
        };

        self.messages.insert(message.id, queued);
        self.by_recipient
            .entry(recipient)
            .or_default()
            .push(message.id);
    }

    fn get_pending_messages(&self) -> Vec<(FourWordAddress, EncryptedMessage)> {
        self.messages
            .values()
            .filter(|q| q.retry_count < 5)
            .map(|q| (q.recipient.clone(), q.message.clone()))
            .collect()
    }

    fn mark_delivered(&mut self, message_id: &MessageId) {
        self.messages.remove(message_id);

        // Remove from recipient index
        for ids in self.by_recipient.values_mut() {
            ids.retain(|id| id != message_id);
        }
    }

    async fn cleanup_expired(&mut self) {
        let cutoff = Utc::now() - chrono::Duration::days(7);

        self.messages.retain(|_, q| q.queued_at > cutoff);

        // Clean up empty recipient entries
        self.by_recipient.retain(|_, ids| !ids.is_empty());
    }
}

/// Queued message
#[derive(Debug, Clone)]
struct QueuedMessage {
    message: EncryptedMessage,
    recipient: FourWordAddress,
    queued_at: DateTime<Utc>,
    retry_count: u32,
}

/// Delivery status for a message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeliveryStatus {
    Delivered(DateTime<Utc>),
    Queued,
    Failed(String),
    Pending,
}

/// Delivery receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    pub message_id: MessageId,
    pub timestamp: DateTime<Utc>,
    pub delivery_status: Vec<(FourWordAddress, DeliveryStatus)>,
}

/// Received message wrapper
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    pub message: EncryptedMessage,
    pub received_at: DateTime<Utc>,
}

/// Transport event types
#[derive(Debug, Clone)]
pub enum TransportEvent {
    MessageReceived(ReceivedMessage),
    MessageDelivered(MessageId),
    ConnectionEstablished(FourWordAddress),
    ConnectionLost(FourWordAddress),
    PresenceUpdate {
        status: PresenceStatus,
        timestamp: DateTime<Utc>,
    },
}

/// Network metrics
#[derive(Debug, Clone, Default)]
pub struct NetworkMetrics {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub messages_queued: u64,
    pub active_connections: usize,
    pub average_latency: Duration,
    pub packet_loss: f32,
    pub bandwidth_used: u64,
}

impl NetworkMetrics {
    fn update_quality(&mut self, pool: &ConnectionPool) {
        self.active_connections = pool.connections.len();

        if !pool.connections.is_empty() {
            let total_latency: Duration =
                pool.connections.values().map(|c| c.quality.latency).sum();

            self.average_latency = total_latency / pool.connections.len() as u32;

            let total_loss: f32 = pool
                .connections
                .values()
                .map(|c| c.quality.packet_loss)
                .sum();

            self.packet_loss = total_loss / pool.connections.len() as f32;
        }
    }
}

// Implement Clone for MessageTransport (needed for spawning)
impl Clone for MessageTransport {
    fn clone(&self) -> Self {
        Self {
            network: self.network.clone(),
            dht_client: self.dht_client.clone(),
            connections: self.connections.clone(),
            message_queue: self.message_queue.clone(),
            confirmations: self.confirmations.clone(),
            metrics: self.metrics.clone(),
            event_tx: self.event_tx.clone(),
            key_exchange_tx: self.key_exchange_tx.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_transport_creation() {
        // This would need a mock network and DHT client
        // For now, just verify the types compile
        assert!(std::mem::size_of::<MessageTransport>() > 0);
    }

    #[tokio::test]
    async fn test_delivery_status() {
        let status = DeliveryStatus::Delivered(Utc::now());

        match status {
            DeliveryStatus::Delivered(time) => {
                assert!(time <= Utc::now());
            }
            _ => panic!("Expected Delivered status"),
        }
    }

    #[tokio::test]
    async fn test_message_queue() {
        let mut queue = MessageQueue::new();

        let recipient = FourWordAddress::from("test-user-address-here");
        let message = EncryptedMessage {
            id: MessageId::new(),
            channel_id: ChannelId::new(),
            sender: FourWordAddress::from("sender-address-here"),
            ciphertext: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
            key_id: "test-key".to_string(),
        };

        queue.add_message(recipient.clone(), message.clone());

        let pending = queue.get_pending_messages();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, recipient);

        queue.mark_delivered(&message.id);
        let pending = queue.get_pending_messages();
        assert_eq!(pending.len(), 0);
    }

    #[tokio::test]
    async fn test_network_metrics() {
        let metrics = NetworkMetrics {
            messages_sent: 100,
            messages_received: 95,
            packet_loss: 0.02,
            ..Default::default()
        };
        assert_eq!(metrics.messages_sent, 100);
        assert!(metrics.packet_loss < 0.05); // Less than 5% loss
    }
}
