//! Capacity signaling and histogram aggregation for DHT pricing
//!
//! Implements capacity gossip, histogram aggregation, and provider selection
//! based on available storage capacity for PUT pricing.

use crate::dht::trust_weighted_dht::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Capacity gossip message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityGossip {
    pub peer: PeerId,
    pub free_bytes: u64,
    pub total_bytes: u64,
    pub epoch: u64,
}

/// Capacity histogram for pricing decisions
#[derive(Debug, Clone)]
pub struct CapacityHistogram {
    /// Buckets: (min_capacity, max_capacity) -> count
    pub buckets: HashMap<(u64, u64), usize>,
    /// Total free capacity across all providers
    pub total_free: u64,
    /// Total providers
    pub total_providers: usize,
}

impl CapacityHistogram {
    /// Create empty histogram
    pub fn new() -> Self {
        Self {
            buckets: HashMap::new(),
            total_free: 0,
            total_providers: 0,
        }
    }

    /// Add capacity data to histogram
    pub fn add_capacity(&mut self, free_bytes: u64) {
        self.total_free += free_bytes;
        self.total_providers += 1;

        // Bucket by capacity ranges (in GB)
        let gb_capacity = free_bytes / 1_000_000_000;
        let bucket = match gb_capacity {
            0..=1 => (0, 1),
            2..=5 => (2, 5),
            6..=10 => (6, 10),
            11..=50 => (11, 50),
            51..=100 => (51, 100),
            _ => (101, u64::MAX),
        };

        *self.buckets.entry(bucket).or_insert(0) += 1;
    }

    /// Get pricing multiplier based on capacity utilization
    pub fn pricing_multiplier(&self) -> f64 {
        if self.total_providers == 0 {
            return 2.0; // High multiplier when no capacity available
        }

        let avg_free_per_provider = self.total_free as f64 / self.total_providers as f64;
        let target_capacity = 5_000_000_000.0; // 5GB target per provider

        // Higher multiplier when capacity is scarce
        if avg_free_per_provider < target_capacity * 0.1 {
            3.0 // Very scarce
        } else if avg_free_per_provider < target_capacity * 0.5 {
            1.5 // Somewhat scarce
        } else {
            1.0 // Adequate capacity
        }
    }

    /// Get capacity distribution as string for debugging
    pub fn distribution_string(&self) -> String {
        let mut buckets: Vec<_> = self.buckets.iter().collect();
        buckets.sort_by_key(|((min, _), _)| *min);

        let mut result = String::new();
        for ((min, max), count) in buckets {
            if *max == u64::MAX {
                result.push_str(&format!("{}GB+: {} providers\n", min, count));
            } else {
                result.push_str(&format!("{}GB-{}GB: {} providers\n", min, max, count));
            }
        }
        result
    }
}

/// Capacity manager for DHT nodes
pub struct CapacityManager {
    /// Local capacity information
    local_capacity: CapacityGossip,
    /// Known capacities from other peers
    peer_capacities: Arc<RwLock<HashMap<PeerId, CapacityGossip>>>,
    /// Capacity histogram
    histogram: Arc<RwLock<CapacityHistogram>>,
}

impl CapacityManager {
    /// Create new capacity manager
    pub fn new(local_peer: PeerId, total_bytes: u64) -> Self {
        let local_capacity = CapacityGossip {
            peer: local_peer,
            free_bytes: total_bytes,
            total_bytes,
            epoch: 0,
        };

        Self {
            local_capacity,
            peer_capacities: Arc::new(RwLock::new(HashMap::new())),
            histogram: Arc::new(RwLock::new(CapacityHistogram::new())),
        }
    }

    /// Update local capacity
    pub async fn update_local_capacity(&mut self, free_bytes: u64) {
        self.local_capacity.free_bytes = free_bytes;
        self.local_capacity.epoch += 1;
    }

    /// Get local capacity gossip
    pub fn local_gossip(&self) -> &CapacityGossip {
        &self.local_capacity
    }

    /// Receive capacity gossip from peer
    pub async fn receive_gossip(&self, gossip: CapacityGossip) {
        let mut peer_capacities = self.peer_capacities.write().await;

        // Only update if epoch is newer
        if let Some(existing) = peer_capacities.get(&gossip.peer) {
            if gossip.epoch <= existing.epoch {
                return;
            }
        }

        peer_capacities.insert(gossip.peer.clone(), gossip);
        drop(peer_capacities);

        // Update histogram
        self.update_histogram().await;
    }

    /// Update capacity histogram
    async fn update_histogram(&self) {
        let peer_capacities = self.peer_capacities.read().await;
        let mut histogram = self.histogram.write().await;

        // Clear and rebuild histogram
        *histogram = CapacityHistogram::new();

        // Add local capacity
        histogram.add_capacity(self.local_capacity.free_bytes);

        // Add peer capacities
        for gossip in peer_capacities.values() {
            histogram.add_capacity(gossip.free_bytes);
        }
    }

    /// Get current capacity histogram
    pub async fn get_histogram(&self) -> CapacityHistogram {
        self.histogram.read().await.clone()
    }

    /// Select providers based on capacity and pricing
    pub async fn select_providers(&self, required_count: usize) -> Vec<PeerId> {
        let peer_capacities = self.peer_capacities.read().await;
        let histogram = self.histogram.read().await;

        let _pricing_multiplier = histogram.pricing_multiplier();

        // Sort peers by capacity (prioritize higher capacity)
        let mut candidates: Vec<_> = peer_capacities
            .values()
            .filter(|gossip| gossip.free_bytes > 0)
            .collect();

        candidates.sort_by(|a, b| b.free_bytes.cmp(&a.free_bytes));

        // Take top candidates
        candidates
            .into_iter()
            .take(required_count)
            .map(|gossip| gossip.peer.clone())
            .collect()
    }

    /// Get capacity statistics for monitoring
    pub async fn get_stats(&self) -> CapacityStats {
        let histogram = self.histogram.read().await;
        let peer_capacities = self.peer_capacities.read().await;

        CapacityStats {
            total_providers: histogram.total_providers,
            total_free_capacity: histogram.total_free,
            avg_free_per_provider: if histogram.total_providers > 0 {
                histogram.total_free as f64 / histogram.total_providers as f64
            } else {
                0.0
            },
            pricing_multiplier: histogram.pricing_multiplier(),
            known_peers: peer_capacities.len(),
        }
    }
}

/// Capacity statistics for monitoring
#[derive(Debug, Clone)]
pub struct CapacityStats {
    pub total_providers: usize,
    pub total_free_capacity: u64,
    pub avg_free_per_provider: f64,
    pub pricing_multiplier: f64,
    pub known_peers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::node_identity::NodeId;

    #[tokio::test]
    async fn test_capacity_histogram() {
        let peer1 = NodeId::from_bytes([1u8; 32]);
        let peer2 = NodeId::from_bytes([2u8; 32]);
        let peer3 = NodeId::from_bytes([3u8; 32]);

        let manager = CapacityManager::new(peer1.clone(), 10_000_000_000); // 10GB

        // Add peer capacities
        manager
            .receive_gossip(CapacityGossip {
                peer: peer2.clone(),
                free_bytes: 5_000_000_000, // 5GB
                total_bytes: 10_000_000_000,
                epoch: 1,
            })
            .await;

        manager
            .receive_gossip(CapacityGossip {
                peer: peer3.clone(),
                free_bytes: 1_000_000_000, // 1GB
                total_bytes: 5_000_000_000,
                epoch: 1,
            })
            .await;

        let histogram = manager.get_histogram().await;
        assert_eq!(histogram.total_providers, 3);
        assert_eq!(histogram.total_free, 16_000_000_000); // 16GB total

        // Test provider selection
        let providers = manager.select_providers(2).await;
        assert_eq!(providers.len(), 2);
        // Should select peers with highest capacity first
    }

    #[test]
    fn test_pricing_multiplier() {
        let mut histogram = CapacityHistogram::new();

        // Test scarce capacity
        histogram.add_capacity(100_000_000); // 100MB
        assert!(histogram.pricing_multiplier() > 2.0);

        // Test adequate capacity
        let mut histogram2 = CapacityHistogram::new();
        histogram2.add_capacity(10_000_000_000); // 10GB
        assert_eq!(histogram2.pricing_multiplier(), 1.0);
    }
}
