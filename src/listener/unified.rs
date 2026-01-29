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

//! Unified message listener that aggregates messages from all layers.

use super::protocol::Protocol;
use super::types::IncomingMessage;
use crate::adaptive::gossip::{AdaptiveGossipSub, GossipEvent, GossipEventSender};
use crate::network::{P2PEvent, P2PNode};
use crate::transport::dht_handler::{DhtStreamEvent, DhtStreamHandler};
use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, error, warn};

/// Default broadcast channel capacity
const DEFAULT_CHANNEL_CAPACITY: usize = 10_000;

/// Unified listener that aggregates messages from all network layers
///
/// This provides a single point to receive messages from:
/// - P2P network (topic-based messages)
/// - Transport layer
/// - DHT layer
/// - Custom protocols
///
/// # Example
///
/// ```ignore
/// use saorsa_core::listener::UnifiedListener;
///
/// let listener = UnifiedListener::new();
///
/// // Connect to P2P node
/// listener.connect_p2p(node.clone()).await?;
///
/// // Subscribe to all messages
/// let mut rx = listener.subscribe();
/// while let Ok(msg) = rx.recv().await {
///     println!("Received from {}: {:?}", msg.peer_id, msg.source);
/// }
/// ```
pub struct UnifiedListener {
    /// Broadcast sender for unified messages
    tx: broadcast::Sender<IncomingMessage>,
    /// Registered protocol handlers
    protocols: Arc<RwLock<HashMap<String, Arc<dyn Protocol>>>>,
    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,
}

impl Default for UnifiedListener {
    fn default() -> Self {
        Self::new()
    }
}

impl UnifiedListener {
    /// Create a new unified listener with default channel capacity (10,000)
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CHANNEL_CAPACITY)
    }

    /// Create a new unified listener with specified channel capacity
    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            tx,
            protocols: Arc::new(RwLock::new(HashMap::new())),
            shutdown_tx,
        }
    }

    /// Subscribe to receive all incoming messages
    ///
    /// Returns a broadcast receiver that will receive all messages from
    /// connected sources.
    pub fn subscribe(&self) -> broadcast::Receiver<IncomingMessage> {
        self.tx.subscribe()
    }

    /// Register a custom protocol handler
    ///
    /// The protocol will be invoked when messages arrive matching its
    /// protocol_id (for topic-based routing) or stream_type (for DHT routing).
    pub async fn register_protocol<P: Protocol>(&self, protocol: P) -> Result<()> {
        let protocol_id = protocol.protocol_id().to_string();
        let mut protocols = self.protocols.write().await;

        if protocols.contains_key(&protocol_id) {
            return Err(anyhow::anyhow!(
                "Protocol '{}' is already registered",
                protocol_id
            ));
        }

        debug!("Registering protocol: {}", protocol_id);
        protocols.insert(protocol_id, Arc::new(protocol));
        Ok(())
    }

    /// Unregister a protocol handler
    pub async fn unregister_protocol(&self, protocol_id: &str) -> Result<()> {
        let mut protocols = self.protocols.write().await;

        if protocols.remove(protocol_id).is_some() {
            debug!("Unregistered protocol: {}", protocol_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Protocol '{}' not found", protocol_id))
        }
    }

    /// Get the list of registered protocol IDs
    pub async fn registered_protocols(&self) -> Vec<String> {
        self.protocols.read().await.keys().cloned().collect()
    }

    /// Connect to a P2P node and start receiving its events
    ///
    /// This spawns a background task that listens to the node's event stream
    /// and republishes relevant events to the unified listener.
    pub async fn connect_p2p(&self, node: Arc<P2PNode>) -> Result<()> {
        let tx = self.tx.clone();
        let protocols = self.protocols.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        let mut event_rx = node.subscribe_events();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        debug!("P2P listener shutting down");
                        break;
                    }
                    result = event_rx.recv() => {
                        match result {
                            Ok(event) => {
                                Self::handle_p2p_event(&tx, &protocols, event).await;
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                debug!("P2P event channel closed");
                                break;
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!("P2P listener lagged by {} messages", n);
                            }
                        }
                    }
                }
            }
        });

        debug!("Connected to P2P node");
        Ok(())
    }

    /// Handle a P2P event
    async fn handle_p2p_event(
        tx: &broadcast::Sender<IncomingMessage>,
        protocols: &Arc<RwLock<HashMap<String, Arc<dyn Protocol>>>>,
        event: P2PEvent,
    ) {
        match event {
            P2PEvent::Message {
                topic,
                source,
                data,
            } => {
                let msg = IncomingMessage::network(source.clone(), topic.clone(), data.clone());

                // Try to dispatch to registered protocol
                let protocols_guard = protocols.read().await;
                if let Some(protocol) = protocols_guard.get(&topic) {
                    match protocol.handle(&source, Bytes::from(data)).await {
                        Ok(response) => {
                            if let Some(_response_data) = response {
                                // Response handling would require sending back to peer
                                // This is left as a TODO for transport integration
                                debug!("Protocol {} produced response (not sent)", topic);
                            }
                        }
                        Err(e) => {
                            error!("Protocol {} handler error: {}", topic, e);
                        }
                    }
                }
                drop(protocols_guard);

                // Always publish to the unified stream
                if let Err(e) = tx.send(msg) {
                    // This is normal if there are no subscribers
                    debug!("No subscribers for unified messages: {}", e);
                }
            }
            P2PEvent::PeerConnected(_) | P2PEvent::PeerDisconnected(_) => {
                // These events are not message events, ignore
            }
        }
    }

    /// Connect to a DHT stream handler and start receiving its events.
    ///
    /// This spawns a background task that listens to the DHT handler's event stream
    /// and republishes relevant events to the unified listener.
    pub fn connect_dht(&self, handler: &DhtStreamHandler) {
        let event_rx = handler.subscribe();
        self.connect_dht_receiver(event_rx);
    }

    /// Connect to a DHT event receiver directly.
    ///
    /// Use this when you have the broadcast receiver from `DhtStreamHandler::with_event_broadcast()`.
    pub fn connect_dht_receiver(&self, mut event_rx: broadcast::Receiver<DhtStreamEvent>) {
        let tx = self.tx.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        debug!("DHT listener shutting down");
                        break;
                    }
                    result = event_rx.recv() => {
                        match result {
                            Ok(event) => {
                                // Convert ant-quic PeerId (tuple struct) to hex string
                                let peer_id = hex::encode(event.peer_id.0);
                                let stream_type = event.stream_type.as_byte();
                                let msg = IncomingMessage::dht(peer_id, stream_type, event.data);

                                if let Err(e) = tx.send(msg) {
                                    debug!("No subscribers for unified messages: {}", e);
                                }
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                debug!("DHT event channel closed");
                                break;
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!("DHT listener lagged by {} messages", n);
                            }
                        }
                    }
                }
            }
        });

        debug!("Connected to DHT handler");
    }

    /// Connect to an AdaptiveGossipSub instance and start receiving its events.
    ///
    /// This spawns a background task that listens to the gossip system's event stream
    /// and republishes relevant events to the unified listener.
    pub fn connect_gossip(&self, gossip: &AdaptiveGossipSub) {
        let event_rx = gossip.subscribe_events();
        self.connect_gossip_receiver(event_rx);
    }

    /// Connect to a gossip event sender directly.
    ///
    /// Use this when you have the sender from `AdaptiveGossipSub::event_sender()`.
    pub fn connect_gossip_sender(&self, sender: GossipEventSender) {
        let event_rx = sender.subscribe();
        self.connect_gossip_receiver(event_rx);
    }

    /// Connect to a gossip event receiver directly.
    pub fn connect_gossip_receiver(&self, mut event_rx: broadcast::Receiver<GossipEvent>) {
        let tx = self.tx.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        debug!("Gossip listener shutting down");
                        break;
                    }
                    result = event_rx.recv() => {
                        match result {
                            Ok(event) => {
                                let peer_id = hex::encode(event.message.from.hash);
                                let topic = event.message.topic.clone();
                                let msg = IncomingMessage::network(peer_id, topic, event.message.data);

                                if let Err(e) = tx.send(msg) {
                                    debug!("No subscribers for unified messages: {}", e);
                                }
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                debug!("Gossip event channel closed");
                                break;
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!("Gossip listener lagged by {} messages", n);
                            }
                        }
                    }
                }
            }
        });

        debug!("Connected to GossipSub");
    }

    /// Manually inject a message into the unified stream
    ///
    /// This is useful for testing or for custom integrations that don't
    /// use the built-in connect methods.
    pub fn inject_message(&self, msg: IncomingMessage) -> Result<()> {
        self.tx.send(msg)?;
        Ok(())
    }

    /// Create a message injector that can be used from other contexts
    ///
    /// Returns a sender that can be cloned and used to inject messages
    /// into the unified stream.
    pub fn message_injector(&self) -> MessageInjector {
        MessageInjector {
            tx: self.tx.clone(),
        }
    }

    /// Shutdown the listener and all connected sources
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Get the number of active subscribers
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Drop for UnifiedListener {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// A clonable handle for injecting messages into the unified stream
#[derive(Clone)]
pub struct MessageInjector {
    tx: broadcast::Sender<IncomingMessage>,
}

impl MessageInjector {
    /// Inject a message into the unified stream
    pub fn inject(&self, msg: IncomingMessage) -> Result<()> {
        self.tx.send(msg)?;
        Ok(())
    }

    /// Inject a network message
    pub fn inject_network(
        &self,
        peer_id: String,
        topic: String,
        data: impl Into<Bytes>,
    ) -> Result<()> {
        self.inject(IncomingMessage::network(peer_id, topic, data))
    }

    /// Inject a transport message
    pub fn inject_transport(&self, peer_id: String, data: impl Into<Bytes>) -> Result<()> {
        self.inject(IncomingMessage::transport(peer_id, data))
    }

    /// Inject a custom protocol message
    pub fn inject_custom(
        &self,
        peer_id: String,
        protocol_id: String,
        data: impl Into<Bytes>,
    ) -> Result<()> {
        self.inject(IncomingMessage::custom(peer_id, protocol_id, data))
    }
}

/// Builder for creating a unified listener with all network sources connected.
///
/// This provides a simple way to create a listener that receives messages from
/// all available network layers without manually connecting each one.
///
/// # Example
///
/// ```ignore
/// use saorsa_core::listener::ListenerBuilder;
///
/// let listener = ListenerBuilder::new()
///     .p2p(node.clone())
///     .dht_handler(dht_handler)
///     .gossip(gossip)
///     .build()
///     .await?;
///
/// let mut rx = listener.subscribe();
/// while let Ok(msg) = rx.recv().await {
///     // Handle messages from any source
/// }
/// ```
pub struct ListenerBuilder {
    capacity: usize,
    p2p: Option<Arc<crate::network::P2PNode>>,
    dht_handler: Option<Arc<DhtStreamHandler>>,
    gossip: Option<Arc<AdaptiveGossipSub>>,
}

impl Default for ListenerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ListenerBuilder {
    /// Create a new listener builder with default settings.
    pub fn new() -> Self {
        Self {
            capacity: DEFAULT_CHANNEL_CAPACITY,
            p2p: None,
            dht_handler: None,
            gossip: None,
        }
    }

    /// Set the channel capacity for the listener.
    pub fn capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    /// Add a P2P node to receive network messages from.
    pub fn p2p(mut self, node: Arc<crate::network::P2PNode>) -> Self {
        self.p2p = Some(node);
        self
    }

    /// Add a DHT stream handler to receive DHT messages from.
    ///
    /// Note: The handler must have been created with `with_event_broadcast()`
    /// for this to work.
    pub fn dht_handler(mut self, handler: Arc<DhtStreamHandler>) -> Self {
        self.dht_handler = Some(handler);
        self
    }

    /// Add a GossipSub instance to receive gossip messages from.
    pub fn gossip(mut self, gossip: Arc<AdaptiveGossipSub>) -> Self {
        self.gossip = Some(gossip);
        self
    }

    /// Build the unified listener and connect all configured sources.
    ///
    /// This will automatically connect to:
    /// - P2P node (if provided)
    /// - DHT handler (if provided and has event broadcasting enabled)
    /// - GossipSub (if provided)
    pub async fn build(self) -> Result<UnifiedListener> {
        let listener = UnifiedListener::with_capacity(self.capacity);

        // Connect P2P if provided
        if let Some(node) = self.p2p {
            listener.connect_p2p(node).await?;
        }

        // Connect DHT if provided
        if let Some(handler) = self.dht_handler {
            listener.connect_dht_receiver(handler.subscribe());
        }

        // Connect GossipSub if provided
        if let Some(gossip) = self.gossip {
            listener.connect_gossip(&gossip);
        }

        Ok(listener)
    }
}

// ============================================================================
// Global Listener
// ============================================================================

/// Global unified listener instance.
///
/// This provides a singleton listener that all network components can
/// automatically register with. Use `global_listener()` to access it.
static GLOBAL_LISTENER: once_cell::sync::Lazy<UnifiedListener> =
    once_cell::sync::Lazy::new(UnifiedListener::new);

/// Get the global unified listener.
///
/// This returns a reference to a singleton listener that all network
/// components can register with. Messages from any registered source
/// will be available to all subscribers.
///
/// # Example
///
/// ```ignore
/// use saorsa_core::listener::{global_listener, subscribe_all};
///
/// // Subscribe to receive all messages
/// let mut rx = subscribe_all();
///
/// // Messages from P2P, DHT, and Gossip will all arrive here
/// while let Ok(msg) = rx.recv().await {
///     println!("Received: {:?}", msg);
/// }
/// ```
pub fn global_listener() -> &'static UnifiedListener {
    &GLOBAL_LISTENER
}

/// Subscribe to receive all messages from the global listener.
///
/// This is a convenience function equivalent to `global_listener().subscribe()`.
pub fn subscribe_all() -> broadcast::Receiver<IncomingMessage> {
    global_listener().subscribe()
}

/// Get a message injector for the global listener.
///
/// This allows injecting messages into the global stream from anywhere.
pub fn global_injector() -> MessageInjector {
    global_listener().message_injector()
}

/// Register a P2P node with the global listener.
///
/// Call this when creating a P2P node to automatically route its messages
/// to the global listener.
pub async fn register_p2p(node: Arc<crate::network::P2PNode>) -> Result<()> {
    global_listener().connect_p2p(node).await
}

/// Register a DHT handler with the global listener.
///
/// Note: DHT handlers now auto-register on construction, so calling this
/// manually is typically not needed.
pub fn register_dht(handler: &DhtStreamHandler) {
    global_listener().connect_dht(handler)
}

/// Register a GossipSub instance with the global listener.
///
/// Call this when creating a GossipSub instance to automatically route
/// its messages to the global listener.
pub fn register_gossip(gossip: &AdaptiveGossipSub) {
    global_listener().connect_gossip(gossip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener::ProtocolBuilder;

    #[tokio::test]
    async fn test_listener_creation() {
        let listener = UnifiedListener::new();
        assert_eq!(listener.subscriber_count(), 0);

        let _rx = listener.subscribe();
        assert_eq!(listener.subscriber_count(), 1);
    }

    #[tokio::test]
    async fn test_message_injection() {
        use crate::listener::MessageSource;

        let listener = UnifiedListener::new();
        let mut rx = listener.subscribe();

        let msg = IncomingMessage::network("peer1".to_string(), "test".to_string(), vec![1, 2, 3]);
        listener.inject_message(msg).unwrap();

        let received = rx.try_recv().unwrap();
        assert_eq!(received.peer_id, "peer1");
        assert!(matches!(received.source, MessageSource::Network { topic } if topic == "test"));
    }

    #[tokio::test]
    async fn test_protocol_registration() {
        let listener = UnifiedListener::new();

        let protocol = ProtocolBuilder::new("test/v1")
            .handler(|_peer, _data| async { Ok(None) })
            .build()
            .unwrap();

        listener.register_protocol(protocol).await.unwrap();

        let protocols = listener.registered_protocols().await;
        assert!(protocols.contains(&"test/v1".to_string()));

        // Duplicate registration should fail
        let protocol2 = ProtocolBuilder::new("test/v1")
            .handler(|_peer, _data| async { Ok(None) })
            .build()
            .unwrap();

        let result = listener.register_protocol(protocol2).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_protocol_unregistration() {
        let listener = UnifiedListener::new();

        let protocol = ProtocolBuilder::new("test/v1")
            .handler(|_peer, _data| async { Ok(None) })
            .build()
            .unwrap();

        listener.register_protocol(protocol).await.unwrap();
        listener.unregister_protocol("test/v1").await.unwrap();

        let protocols = listener.registered_protocols().await;
        assert!(!protocols.contains(&"test/v1".to_string()));

        // Unregistering non-existent protocol should fail
        let result = listener.unregister_protocol("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_message_injector() {
        let listener = UnifiedListener::new();
        let mut rx = listener.subscribe();

        let injector = listener.message_injector();
        injector
            .inject_network("peer1".to_string(), "chat".to_string(), vec![1, 2, 3])
            .unwrap();

        let received = rx.try_recv().unwrap();
        assert_eq!(received.peer_id, "peer1");
    }

    #[tokio::test]
    async fn test_shutdown() {
        let listener = UnifiedListener::new();
        let _rx = listener.subscribe();

        assert_eq!(listener.subscriber_count(), 1);
        listener.shutdown();

        // Shutdown is signaled, but subscribers still exist
        // They will receive a closed error on next recv
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let listener = UnifiedListener::new();
        let mut rx1 = listener.subscribe();
        let mut rx2 = listener.subscribe();

        assert_eq!(listener.subscriber_count(), 2);

        listener
            .inject_message(IncomingMessage::transport("peer1".to_string(), vec![42]))
            .unwrap();

        let received1 = rx1.try_recv().unwrap();
        let received2 = rx2.try_recv().unwrap();

        assert_eq!(received1.peer_id, received2.peer_id);
        assert_eq!(received1.data(), received2.data());
    }
}
