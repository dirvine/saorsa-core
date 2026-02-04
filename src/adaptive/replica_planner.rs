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

//! Replica planner helpers for saorsa-node.
//!
//! This module keeps saorsa-core focused on peer discovery and trust signals.
//! saorsa-node owns application data storage/replication and uses these helpers
//! to select target peers and react to churn events.

use super::{AdaptiveDHT, ContentHash, NodeDescriptor, NodeId, Result};
use crate::{DhtNetworkEvent, DhtNetworkManager};
use std::sync::Arc;
use tokio::sync::broadcast;

/// Helper for replica target selection and churn event subscription.
///
/// Note: This does **not** store data. saorsa-node should replicate chunks over
/// `send_message` and report outcomes back to EigenTrust.
#[derive(Clone)]
pub struct ReplicaPlanner {
    dht: Arc<AdaptiveDHT>,
    dht_manager: Arc<DhtNetworkManager>,
}

impl ReplicaPlanner {
    /// Create a new planner backed by AdaptiveDHT and DhtNetworkManager.
    pub fn new(dht: Arc<AdaptiveDHT>, dht_manager: Arc<DhtNetworkManager>) -> Self {
        Self { dht, dht_manager }
    }

    /// Select replica target peers for a content hash.
    ///
    /// This uses AdaptiveDHT's layered scoring (trust, geo, churn, hyperbolic, SOM).
    pub async fn select_replica_targets(
        &self,
        content_hash: ContentHash,
        count: usize,
    ) -> Result<Vec<NodeDescriptor>> {
        let target = NodeId::from_bytes(content_hash.0);
        self.dht.find_closest_nodes(&target, count).await
    }

    /// Select replica target peers for an explicit node id.
    pub async fn select_replica_targets_for_node(
        &self,
        target: &NodeId,
        count: usize,
    ) -> Result<Vec<NodeDescriptor>> {
        self.dht.find_closest_nodes(target, count).await
    }

    /// Subscribe to DHT network events.
    ///
    /// Churn hints are emitted as `DhtNetworkEvent::PeerDisconnected`.
    pub fn subscribe_churn(&self) -> broadcast::Receiver<DhtNetworkEvent> {
        self.dht_manager.subscribe_events()
    }
}
