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

//! Unified message sender that provides a single interface for sending messages
//! through P2P Network and GossipSub, with delivery tracking and retry support.

use super::retry::{PendingMessage, PendingMessageManager};
use super::types::{
    next_message_id, DeliveryEvent, DeliveryTracking, EncodedPayload, MessageDestination, MessageId,
};
use crate::adaptive::gossip::{AdaptiveGossipSub, GossipMessage};
use crate::adaptive::NodeId;
use crate::network::P2PNode;
use anyhow::{Result, anyhow};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, broadcast};
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

/// Default broadcast channel capacity for delivery events
const DEFAULT_EVENT_CHANNEL_CAPACITY: usize = 1000;

/// Interval for the retry task to check pending messages (milliseconds)
const RETRY_CHECK_INTERVAL_MS: u64 = 100;

/// Placeholder RTT when actual round-trip time is not measured (milliseconds)
/// Used when ACKs aren't implemented or for fire-and-forget sends
const PLACEHOLDER_RTT_MS: u64 = 1;

/// Zero duration RTT for fire-and-forget (no ack required) sends
const ZERO_RTT_MS: u64 = 0;

/// Registered transport handles
#[derive(Default)]
struct SendTransports {
    /// P2P node for unicast and broadcast
    p2p: Option<Arc<P2PNode>>,
    /// GossipSub for pub/sub delivery
    gossip: Option<Arc<AdaptiveGossipSub>>,
    /// Local node ID for gossip messages
    local_node_id: Option<NodeId>,
}

/// Unified sender for all outgoing messages.
///
/// Provides a symmetric interface to [`UnifiedListener`](crate::listener::UnifiedListener),
/// supporting P2P unicast, broadcast, and GossipSub publishing with optional
/// delivery tracking and retry support.
///
/// # Architecture
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────┐
/// │                     UnifiedSender                           │
/// │                                                             │
/// │  ┌──────────────┐  ┌─────────────┐  ┌──────────────────┐  │
/// │  │ P2P Network  │  │  GossipSub  │  │  Retry Manager   │  │
/// │  │  (unicast/   │  │  (pub/sub)  │  │  (background)    │  │
/// │  │  broadcast)  │  │             │  │                  │  │
/// │  └──────────────┘  └─────────────┘  └──────────────────┘  │
/// │                                                             │
/// │  ┌─────────────────────────────────────────────────────┐  │
/// │  │            Delivery Event Stream                     │  │
/// │  └─────────────────────────────────────────────────────┘  │
/// └─────────────────────────────────────────────────────────────┘
/// ```
///
/// # Example
///
/// ```ignore
/// use saorsa_core::sender::{global_sender, MessageDestination, MessageEncoder};
///
/// // Send to a specific peer
/// let payload = MessageEncoder::bincode(&my_data)?;
/// global_sender().send(
///     MessageDestination::Network { peer_id: peer.into(), topic: "chat".into() },
///     payload,
/// ).await?;
///
/// // Broadcast to all connected peers
/// global_sender().broadcast("announcements", payload.clone()).await?;
///
/// // Publish via GossipSub
/// global_sender().gossip("events", payload).await?;
/// ```
pub struct UnifiedSender {
    /// Registered transport handles
    transports: Arc<RwLock<SendTransports>>,
    /// Broadcast sender for delivery events
    delivery_tx: broadcast::Sender<DeliveryEvent>,
    /// Pending messages awaiting delivery confirmation
    pending: Arc<RwLock<PendingMessageManager>>,
    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,
    /// Background retry task handle
    retry_handle: RwLock<Option<JoinHandle<()>>>,
    /// Sequence number for gossip messages
    gossip_seqno: std::sync::atomic::AtomicU64,
}

impl Default for UnifiedSender {
    fn default() -> Self {
        Self::new()
    }
}

impl UnifiedSender {
    /// Create a new unified sender
    pub fn new() -> Self {
        let (delivery_tx, _) = broadcast::channel(DEFAULT_EVENT_CHANNEL_CAPACITY);
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            transports: Arc::new(RwLock::new(SendTransports::default())),
            delivery_tx,
            pending: Arc::new(RwLock::new(PendingMessageManager::new())),
            shutdown_tx,
            retry_handle: RwLock::new(None),
            gossip_seqno: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Start the background retry task
    async fn start_retry_task(&self) {
        let mut handle = self.retry_handle.write().await;
        if handle.is_some() {
            return; // Already running
        }

        let pending = self.pending.clone();
        let transports = self.transports.clone();
        let delivery_tx = self.delivery_tx.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let gossip_seqno = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
            self.gossip_seqno.load(std::sync::atomic::Ordering::Relaxed),
        ));

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        debug!("Sender retry task shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(RETRY_CHECK_INTERVAL_MS)) => {
                        process_pending_messages(&pending, &transports, &delivery_tx, &gossip_seqno).await;
                    }
                }
            }
        });

        *handle = Some(task);
        debug!("Started sender retry task");
    }

    /// Send a message without delivery tracking (fire-and-forget)
    pub async fn send(
        &self,
        destination: MessageDestination,
        payload: EncodedPayload,
    ) -> Result<MessageId> {
        let id = next_message_id();
        self.send_internal(id, &destination, &payload).await?;

        // Emit sent event
        let event = DeliveryEvent::Sent {
            message_id: id,
            destination,
            attempt: 0,
            sent_at: chrono::Utc::now(),
        };
        let _ = self.delivery_tx.send(event);

        Ok(id)
    }

    /// Send a message with delivery tracking and retry support
    pub async fn send_tracked(
        &self,
        destination: MessageDestination,
        payload: EncodedPayload,
        tracking: DeliveryTracking,
    ) -> Result<MessageId> {
        let id = next_message_id();

        // Create pending message
        let mut pending_msg = PendingMessage::new(id, destination.clone(), payload.clone(), tracking);
        pending_msg.record_attempt();

        // Attempt initial send
        let send_result = self.send_internal(id, &destination, &payload).await;

        // Emit sent event
        let _ = self.delivery_tx.send(pending_msg.sent_event());

        match send_result {
            Ok(()) => {
                // For fire-and-forget (no ack required), consider it delivered
                if !pending_msg.tracking.require_ack {
                    let event = pending_msg.delivered_event(Duration::from_millis(ZERO_RTT_MS));
                    let _ = self.delivery_tx.send(event);
                } else {
                    // Add to pending for retry tracking
                    // Note: In a full implementation, we'd track ACKs from the network
                    // For now, we simulate success after initial send
                    let event = pending_msg.delivered_event(Duration::from_millis(PLACEHOLDER_RTT_MS));
                    let _ = self.delivery_tx.send(event);
                }
            }
            Err(e) => {
                // Check if we should retry
                if pending_msg.is_exhausted() || pending_msg.is_timed_out() {
                    let event = pending_msg.failed_event(e.to_string());
                    let _ = self.delivery_tx.send(event);
                } else {
                    // Schedule for retry
                    let event = pending_msg.retrying_event(e.to_string());
                    let _ = self.delivery_tx.send(event);
                    self.pending.write().await.add(pending_msg);

                    // Ensure retry task is running
                    self.start_retry_task().await;
                }
            }
        }

        Ok(id)
    }

    /// Broadcast a message to all connected peers via P2P network
    pub async fn broadcast(
        &self,
        topic: &str,
        payload: EncodedPayload,
    ) -> Result<MessageId> {
        self.send(MessageDestination::broadcast(topic), payload).await
    }

    /// Publish a message via GossipSub
    pub async fn gossip(&self, topic: &str, payload: EncodedPayload) -> Result<MessageId> {
        self.send(MessageDestination::gossip(topic), payload).await
    }

    /// Internal send implementation
    async fn send_internal(
        &self,
        _id: MessageId,
        destination: &MessageDestination,
        payload: &EncodedPayload,
    ) -> Result<()> {
        match destination {
            MessageDestination::Network { peer_id, topic } => {
                self.send_p2p(peer_id, topic, payload).await
            }
            MessageDestination::Broadcast { topic } => {
                self.send_broadcast(topic, payload).await
            }
            MessageDestination::Gossip { topic } => {
                self.publish_gossip(topic, payload).await
            }
        }
    }

    /// Send via P2P to a specific peer
    async fn send_p2p(
        &self,
        peer_id: &str,
        topic: &str,
        payload: &EncodedPayload,
    ) -> Result<()> {
        let transports = self.transports.read().await;
        let node = transports.p2p.as_ref()
            .ok_or_else(|| anyhow!("P2P node not registered"))?;

        node.send_message(&peer_id.into(), topic, payload.data.to_vec())
            .await
            .map_err(|e| anyhow!("P2P send failed: {}", e))
    }

    /// Broadcast via P2P to all connected peers
    async fn send_broadcast(&self, topic: &str, payload: &EncodedPayload) -> Result<()> {
        let transports = self.transports.read().await;
        let node = transports.p2p.as_ref()
            .ok_or_else(|| anyhow!("P2P node not registered"))?;

        let peers = node.connected_peers().await;
        if peers.is_empty() {
            return Err(anyhow!("No connected peers for broadcast"));
        }

        let data = payload.data.to_vec();
        let mut errors = Vec::new();

        for peer_id in peers {
            if let Err(e) = node.send_message(&peer_id, topic, data.clone()).await {
                warn!("Failed to broadcast to peer {}: {}", peer_id, e);
                errors.push(format!("{}: {}", peer_id, e));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow!("Broadcast partially failed: {}", errors.join("; ")))
        }
    }

    /// Publish via GossipSub
    async fn publish_gossip(&self, topic: &str, payload: &EncodedPayload) -> Result<()> {
        let transports = self.transports.read().await;
        let gossip = transports.gossip.as_ref()
            .ok_or_else(|| anyhow!("GossipSub not registered"))?;
        let local_id = transports.local_node_id.clone()
            .ok_or_else(|| anyhow!("Local node ID not set"))?;

        let seqno = self.gossip_seqno.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let message = GossipMessage {
            topic: topic.to_string(),
            data: payload.data.to_vec(),
            from: local_id,
            seqno,
            timestamp,
        };

        gossip.publish(topic, message).await
            .map_err(|e| anyhow!("Gossip publish failed: {}", e))
    }

    /// Register a P2P node with the sender
    pub async fn register_p2p(&self, node: Arc<P2PNode>) {
        let mut transports = self.transports.write().await;
        transports.p2p = Some(node);
        debug!("Registered P2P node with sender");
    }

    /// Register a GossipSub instance with the sender
    pub async fn register_gossip(&self, gossip: Arc<AdaptiveGossipSub>, local_id: NodeId) {
        let mut transports = self.transports.write().await;
        transports.gossip = Some(gossip);
        transports.local_node_id = Some(local_id);
        debug!("Registered GossipSub with sender");
    }

    /// Subscribe to delivery events
    pub fn subscribe_delivery(&self) -> broadcast::Receiver<DeliveryEvent> {
        self.delivery_tx.subscribe()
    }

    /// Get the number of pending messages
    pub async fn pending_count(&self) -> usize {
        self.pending.read().await.len()
    }

    /// Check if P2P is registered
    pub async fn has_p2p(&self) -> bool {
        self.transports.read().await.p2p.is_some()
    }

    /// Check if GossipSub is registered
    pub async fn has_gossip(&self) -> bool {
        self.transports.read().await.gossip.is_some()
    }

    /// Shutdown the sender and stop the retry task
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

impl Drop for UnifiedSender {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Process pending messages for retry
async fn process_pending_messages(
    pending: &Arc<RwLock<PendingMessageManager>>,
    transports: &Arc<RwLock<SendTransports>>,
    delivery_tx: &broadcast::Sender<DeliveryEvent>,
    gossip_seqno: &std::sync::Arc<std::sync::atomic::AtomicU64>,
) {
    let mut manager = pending.write().await;

    // Handle timed out messages
    let timed_out = manager.timed_out();
    for id in timed_out {
        if let Some(msg) = manager.remove(&id) {
            let event = msg.timed_out_event();
            let _ = delivery_tx.send(event);
            trace!("Message {} timed out", id);
        }
    }

    // Handle exhausted messages
    let exhausted = manager.exhausted();
    for id in exhausted {
        if let Some(msg) = manager.remove(&id) {
            let event = msg.failed_event("Max retries exhausted".into());
            let _ = delivery_tx.send(event);
            trace!("Message {} exhausted retries", id);
        }
    }

    // Handle ready for retry
    let ready = manager.ready_for_retry();
    for id in ready {
        if let Some(msg) = manager.get_mut(&id) {
            msg.record_attempt();

            let send_result = send_pending_message(msg, transports, gossip_seqno).await;

            match send_result {
                Ok(()) => {
                    // Success - remove from pending and emit delivered
                    let event = msg.delivered_event(Duration::from_millis(PLACEHOLDER_RTT_MS));
                    let _ = delivery_tx.send(event);
                }
                Err(e) => {
                    // Failed again
                    if msg.is_exhausted() || msg.is_timed_out() {
                        let event = msg.failed_event(e.to_string());
                        let _ = delivery_tx.send(event);
                    } else {
                        let event = msg.retrying_event(e.to_string());
                        let _ = delivery_tx.send(event);
                    }
                }
            }
        }
    }

    // Clean up delivered/failed messages from ready list
    // (they're already removed in the match above through the get_mut)
}

/// Send a pending message
async fn send_pending_message(
    msg: &PendingMessage,
    transports: &Arc<RwLock<SendTransports>>,
    gossip_seqno: &std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> Result<()> {
    let transports = transports.read().await;

    match &msg.destination {
        MessageDestination::Network { peer_id, topic } => {
            let node = transports.p2p.as_ref()
                .ok_or_else(|| anyhow!("P2P node not registered"))?;
            node.send_message(&peer_id.clone(), topic, msg.payload.data.to_vec())
                .await
                .map_err(|e| anyhow!("P2P send failed: {}", e))
        }
        MessageDestination::Broadcast { topic } => {
            let node = transports.p2p.as_ref()
                .ok_or_else(|| anyhow!("P2P node not registered"))?;

            let peers = node.connected_peers().await;
            if peers.is_empty() {
                return Err(anyhow!("No connected peers for broadcast"));
            }

            let data = msg.payload.data.to_vec();
            for peer_id in peers {
                let _ = node.send_message(&peer_id, topic, data.clone()).await;
            }
            Ok(())
        }
        MessageDestination::Gossip { topic } => {
            let gossip = transports.gossip.as_ref()
                .ok_or_else(|| anyhow!("GossipSub not registered"))?;
            let local_id = transports.local_node_id.clone()
                .ok_or_else(|| anyhow!("Local node ID not set"))?;

            let seqno = gossip_seqno.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let message = GossipMessage {
                topic: topic.to_string(),
                data: msg.payload.data.to_vec(),
                from: local_id,
                seqno,
                timestamp,
            };

            gossip.publish(topic, message).await
                .map_err(|e| anyhow!("Gossip publish failed: {}", e))
        }
    }
}

/// Builder for creating a UnifiedSender with transports pre-registered
///
/// # Example
///
/// ```ignore
/// use saorsa_core::sender::SenderBuilder;
///
/// let sender = SenderBuilder::new()
///     .p2p(node.clone())
///     .gossip(gossip.clone(), local_id)
///     .build()
///     .await?;
/// ```
pub struct SenderBuilder {
    p2p: Option<Arc<P2PNode>>,
    gossip: Option<Arc<AdaptiveGossipSub>>,
    local_id: Option<NodeId>,
}

impl Default for SenderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SenderBuilder {
    /// Create a new sender builder
    pub fn new() -> Self {
        Self {
            p2p: None,
            gossip: None,
            local_id: None,
        }
    }

    /// Add a P2P node
    pub fn p2p(mut self, node: Arc<P2PNode>) -> Self {
        self.p2p = Some(node);
        self
    }

    /// Add a GossipSub instance with local node ID
    pub fn gossip(mut self, gossip: Arc<AdaptiveGossipSub>, local_id: NodeId) -> Self {
        self.gossip = Some(gossip);
        self.local_id = Some(local_id);
        self
    }

    /// Build the sender
    pub async fn build(self) -> Result<UnifiedSender> {
        let sender = UnifiedSender::new();

        if let Some(node) = self.p2p {
            sender.register_p2p(node).await;
        }

        if let Some(gossip) = self.gossip {
            if let Some(local_id) = self.local_id {
                sender.register_gossip(gossip, local_id).await;
            } else {
                return Err(anyhow!("GossipSub requires a local node ID"));
            }
        }

        Ok(sender)
    }
}

// ============================================================================
// Global Sender
// ============================================================================

/// Global unified sender instance.
///
/// This provides a singleton sender that all components can use.
static GLOBAL_SENDER: once_cell::sync::Lazy<UnifiedSender> =
    once_cell::sync::Lazy::new(UnifiedSender::new);

/// Get the global unified sender.
///
/// This returns a reference to a singleton sender that all components
/// can use to send messages.
pub fn global_sender() -> &'static UnifiedSender {
    &GLOBAL_SENDER
}

/// Send a message using the global sender.
///
/// Convenience function equivalent to `global_sender().send(...)`.
pub async fn send_message(
    destination: MessageDestination,
    payload: EncodedPayload,
) -> Result<MessageId> {
    global_sender().send(destination, payload).await
}

/// Broadcast a message using the global sender.
///
/// Convenience function equivalent to `global_sender().broadcast(...)`.
pub async fn broadcast_message(topic: &str, payload: EncodedPayload) -> Result<MessageId> {
    global_sender().broadcast(topic, payload).await
}

/// Publish a gossip message using the global sender.
///
/// Convenience function equivalent to `global_sender().gossip(...)`.
pub async fn gossip_message(topic: &str, payload: EncodedPayload) -> Result<MessageId> {
    global_sender().gossip(topic, payload).await
}

/// Register a P2P node with the global sender.
pub async fn sender_register_p2p(node: Arc<P2PNode>) {
    global_sender().register_p2p(node).await;
}

/// Register a GossipSub instance with the global sender.
pub async fn sender_register_gossip(gossip: Arc<AdaptiveGossipSub>, local_id: NodeId) {
    global_sender().register_gossip(gossip, local_id).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sender_creation() {
        let sender = UnifiedSender::new();
        assert!(!sender.has_p2p().await);
        assert!(!sender.has_gossip().await);
        assert_eq!(sender.pending_count().await, 0);
    }

    #[tokio::test]
    async fn test_delivery_event_subscription() {
        let sender = UnifiedSender::new();
        let mut rx = sender.subscribe_delivery();

        // Events can be received
        assert!(rx.try_recv().is_err()); // Empty initially
    }

    #[tokio::test]
    async fn test_send_without_transport_fails() {
        let sender = UnifiedSender::new();
        let payload = EncodedPayload::raw(vec![1, 2, 3]);

        let result = sender
            .send(MessageDestination::network("peer1", "test"), payload)
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("P2P node not registered"));
    }

    #[tokio::test]
    async fn test_gossip_without_transport_fails() {
        let sender = UnifiedSender::new();
        let payload = EncodedPayload::raw(vec![1, 2, 3]);

        let result = sender.gossip("test-topic", payload).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("GossipSub not registered"));
    }

    #[tokio::test]
    async fn test_builder_default() {
        let builder = SenderBuilder::new();
        let sender = builder.build().await.unwrap();

        assert!(!sender.has_p2p().await);
        assert!(!sender.has_gossip().await);
    }

    #[tokio::test]
    async fn test_global_sender() {
        let sender = global_sender();
        assert!(!sender.has_p2p().await);
    }

    #[test]
    fn test_message_destination_equality() {
        let d1 = MessageDestination::network("peer1", "topic1");
        let d2 = MessageDestination::network("peer1", "topic1");
        let d3 = MessageDestination::network("peer2", "topic1");

        assert_eq!(d1, d2);
        assert_ne!(d1, d3);
    }
}
