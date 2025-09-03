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

//! Async event bus for watches and topology changes.
//!
//! This module provides subscription-based event handling for
//! state changes throughout the system.

use crate::fwid::Key;
use bytes::Bytes;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use crate::types::Forward;

/// A subscription handle for receiving events
pub struct Subscription<T> {
    receiver: broadcast::Receiver<T>,
}

impl<T: Clone> Subscription<T> {
    /// Create a new subscription with a receiver
    fn new(receiver: broadcast::Receiver<T>) -> Self {
        Self { receiver }
    }

    /// Receive the next event
    pub async fn recv(&mut self) -> Result<T> {
        self.receiver
            .recv()
            .await
            .map_err(|e| anyhow::anyhow!("Subscription error: {}", e))
    }

    /// Try to receive without blocking
    pub fn try_recv(&mut self) -> Result<T> {
        self.receiver
            .try_recv()
            .map_err(|e| anyhow::anyhow!("Subscription error: {}", e))
    }
}

/// Network topology change events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TopologyEvent {
    /// A new peer joined the network
    PeerJoined { peer_id: Vec<u8>, address: String },
    /// A peer left the network
    PeerLeft { peer_id: Vec<u8>, reason: String },
    /// Network partition detected
    PartitionDetected {
        partition_id: u64,
        affected_peers: Vec<Vec<u8>>,
    },
    /// Network partition healed
    PartitionHealed { partition_id: u64 },
    /// Routing table updated
    RoutingTableUpdated {
        added: Vec<Vec<u8>>,
        removed: Vec<Vec<u8>>,
    },
}

/// DHT key watch events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtWatchEvent {
    /// Value stored at key
    ValueStored { key: Key, value: Vec<u8> },
    /// Value updated at key
    ValueUpdated {
        key: Key,
        old_value: Vec<u8>,
        new_value: Vec<u8>,
    },
    /// Value deleted at key
    ValueDeleted { key: Key },
    /// Key expired
    KeyExpired { key: Key },
}

// ForwardEvent removed; we publish Forward values scoped by identity key

/// The main event bus for the system
pub struct EventBus {
    /// Topology event broadcaster
    topology_tx: broadcast::Sender<TopologyEvent>,

    /// DHT watch broadcasters by key
    dht_watches: Arc<RwLock<HashMap<Key, broadcast::Sender<Bytes>>>>,

    /// Forward event broadcasters by identity key
    forward_watches: Arc<RwLock<HashMap<Key, broadcast::Sender<Forward>>>>,
}

impl EventBus {
    /// Create a new event bus
    pub fn new() -> Self {
        let (topology_tx, _) = broadcast::channel(1000);

        Self {
            topology_tx,
            dht_watches: Arc::new(RwLock::new(HashMap::new())),
            forward_watches: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Subscribe to topology events
    pub fn subscribe_topology(&self) -> Subscription<TopologyEvent> {
        Subscription::new(self.topology_tx.subscribe())
    }

    /// Publish a topology event
    pub async fn publish_topology(&self, event: TopologyEvent) -> Result<()> {
        self.topology_tx
            .send(event)
            .map_err(|_| anyhow::anyhow!("No topology subscribers"))?;
        Ok(())
    }

    /// Subscribe to DHT key watches
    pub async fn subscribe_dht_key(&self, key: Key) -> Subscription<Bytes> {
        let mut watches = self.dht_watches.write().await;

        let tx = watches
            .entry(key)
            .or_insert_with(|| {
                let (tx, _) = broadcast::channel(100);
                tx
            });

        Subscription::new(tx.subscribe())
    }

    /// Publish a DHT key update
    pub async fn publish_dht_update(&self, key: Key, value: Bytes) -> Result<()> {
        let watches = self.dht_watches.read().await;

        if let Some(tx) = watches.get(&key) {
            let _ = tx.send(value); // Ignore if no subscribers
        }

        Ok(())
    }

    /// Subscribe to forward announcements for an identity
    pub async fn subscribe_forwards(&self, identity_key: Key) -> Subscription<Forward> {
        let mut watches = self.forward_watches.write().await;

        let tx = watches.entry(identity_key).or_insert_with(|| {
            let (tx, _) = broadcast::channel(100);
            tx
        });

        Subscription::new(tx.subscribe())
    }

    /// Publish a forward announcement scoped to identity
    pub async fn publish_forward_for(&self, identity_key: Key, forward: Forward) -> Result<()> {
        let watches = self.forward_watches.read().await;

        if let Some(tx) = watches.get(&identity_key) {
            let _ = tx.send(forward); // Ignore if no subscribers
        }

        Ok(())
    }

    /// Clean up expired subscriptions
    pub async fn cleanup_expired(&self) {
        let mut dht_watches = self.dht_watches.write().await;
        dht_watches.retain(|_, tx| tx.receiver_count() > 0);

        let mut forward_watches = self.forward_watches.write().await;
        forward_watches.retain(|_, tx| tx.receiver_count() > 0);
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Global event bus instance (for convenience)
static GLOBAL_BUS: once_cell::sync::Lazy<EventBus> = once_cell::sync::Lazy::new(EventBus::new);

/// Get the global event bus
pub fn global_bus() -> &'static EventBus {
    &GLOBAL_BUS
}

/// Helper function to subscribe to topology events
pub fn subscribe_topology() -> Subscription<TopologyEvent> {
    global_bus().subscribe_topology()
}

/// Helper function to subscribe to DHT key
pub async fn dht_watch(key: Key) -> Subscription<Bytes> {
    global_bus().subscribe_dht_key(key).await
}

/// Helper function to subscribe to device forwards
pub async fn device_subscribe(identity_key: Key) -> Subscription<Forward> {
    global_bus().subscribe_forwards(identity_key).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_topology_events() {
        let bus = EventBus::new();
        let mut sub = bus.subscribe_topology();

        let event = TopologyEvent::PeerJoined {
            peer_id: vec![1, 2, 3],
            address: "127.0.0.1:9000".to_string(),
        };

        bus.publish_topology(event.clone()).await.unwrap();

        let received = sub.recv().await.unwrap();
        match received {
            TopologyEvent::PeerJoined { peer_id, address } => {
                assert_eq!(peer_id, vec![1, 2, 3]);
                assert_eq!(address, "127.0.0.1:9000");
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[tokio::test]
    async fn test_dht_watch() {
        let bus = EventBus::new();
        let key = Key::new([42u8; 32]);

        let mut sub = bus.subscribe_dht_key(key.clone()).await;

        let value = Bytes::from_static(&[1, 2, 3, 4]);
        bus.publish_dht_update(key, value.clone()).await.unwrap();

        let received = sub.recv().await.unwrap();
        assert_eq!(received, value);
    }

    #[tokio::test]
    async fn test_forward_events() {
        let bus = EventBus::new();
        let identity_key = Key::new([99u8; 32]);

        let mut sub = bus.subscribe_forwards(identity_key.clone()).await;

        let fwd = Forward { proto: "ant-quic".to_string(), addr: "quic://example.com:9000".to_string(), exp: 1234567890 };

        bus.publish_forward_for(identity_key.clone(), fwd.clone()).await.unwrap();

        let received = sub.recv().await.unwrap();
        assert_eq!(received.proto, "ant-quic");
        assert_eq!(received.addr, "quic://example.com:9000");
    }

    #[tokio::test]
    async fn test_cleanup() {
        let bus = EventBus::new();
        let key = Key::new([1u8; 32]);

        // Create subscription then drop it
        {
            let _sub = bus.subscribe_dht_key(key.clone()).await;
        }

        // Check that watch exists
        assert_eq!(bus.dht_watches.read().await.len(), 1);

        // Clean up
        bus.cleanup_expired().await;

        // Watch should be removed
        assert_eq!(bus.dht_watches.read().await.len(), 0);
    }
}
