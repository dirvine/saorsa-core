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

//! Geographic Routing Table for DHT
//!
//! Combines geographic awareness with Kademlia routing for optimized
//! peer discovery and routing decisions in P2P networks.

use super::geographic_routing::{GeographicRegion, PeerQualityMetrics, RegionalBucket};
use super::latency_aware_selection::{
    LatencyAwarePeerSelection, LatencySelectionConfig, SelectedPeer,
};
use crate::PeerId;
use crate::dht::Key;
use crate::error::{P2PError, P2pResult as Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;

/// Configuration for geographic routing table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicRoutingConfig {
    /// Maximum peers per regional bucket
    pub max_peers_per_region: usize,
    /// Minimum peers to maintain per region
    pub min_peers_per_region: usize,
    /// Interval for routing table maintenance
    pub maintenance_interval: Duration,
    /// Maximum age for peer metrics before refresh
    pub peer_metrics_max_age: Duration,
    /// Configuration for latency-aware selection
    pub selection_config: LatencySelectionConfig,
    /// Enable cross-region routing optimization
    pub enable_cross_region_optimization: bool,
    /// Preferred regions for routing (in priority order)
    pub preferred_regions: Vec<GeographicRegion>,
}

impl Default for GeographicRoutingConfig {
    fn default() -> Self {
        Self {
            max_peers_per_region: 50,
            min_peers_per_region: 5,
            maintenance_interval: Duration::from_secs(60),
            peer_metrics_max_age: Duration::from_secs(300),
            selection_config: LatencySelectionConfig::default(),
            enable_cross_region_optimization: true,
            preferred_regions: vec![
                GeographicRegion::Europe,
                GeographicRegion::NorthAmerica,
                GeographicRegion::AsiaPacific,
            ],
        }
    }
}

/// Thread-safe wrapper for geographic routing table
pub type SafeGeographicRoutingTable = Arc<RwLock<GeographicRoutingTable>>;

/// Geographic routing table combining regional buckets with latency-aware selection
#[derive(Debug)]
pub struct GeographicRoutingTable {
    /// Regional buckets for peer organization
    regional_buckets: HashMap<GeographicRegion, RegionalBucket>,
    /// Latency-aware peer selection system
    peer_selector: LatencyAwarePeerSelection,
    /// Local node's region
    local_region: GeographicRegion,
    /// Configuration
    config: GeographicRoutingConfig,
    /// Last maintenance timestamp  
    last_maintenance: Instant,
    /// Routing statistics
    stats: RoutingTableStats,
}

/// Statistics for the geographic routing table
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutingTableStats {
    pub total_peers: usize,
    pub peers_by_region: HashMap<GeographicRegion, usize>,
    pub successful_selections: u64,
    pub failed_selections: u64,
    pub cross_region_routes: u64,
    pub average_selection_latency: Duration,
    pub last_maintenance: Option<SystemTime>,
}

impl GeographicRoutingTable {
    /// Create a new geographic routing table
    pub fn new(local_region: GeographicRegion, config: GeographicRoutingConfig) -> Self {
        let peer_selector =
            LatencyAwarePeerSelection::new(config.selection_config.clone(), local_region);

        // Initialize regional buckets
        let mut regional_buckets = HashMap::new();
        for region in GeographicRegion::all_regions() {
            regional_buckets.insert(
                region,
                RegionalBucket::new(region, config.max_peers_per_region),
            );
        }

        Self {
            regional_buckets,
            peer_selector,
            local_region,
            config,
            last_maintenance: Instant::now(),
            stats: RoutingTableStats::default(),
        }
    }

    /// Add a peer to the routing table with geographic awareness
    pub fn add_peer(
        &mut self,
        peer_id: PeerId,
        region: GeographicRegion,
        metrics: PeerQualityMetrics,
    ) -> Result<bool> {
        // Add to regional bucket
        let added = if let Some(bucket) = self.regional_buckets.get_mut(&region) {
            bucket.add_peer(peer_id.clone(), metrics.clone())
        } else {
            false
        };

        // Update peer selector cache
        self.peer_selector.update_peer_metrics(peer_id, metrics)?;

        // Update statistics
        self.update_peer_stats();

        Ok(added)
    }

    /// Remove a peer from the routing table
    pub fn remove_peer(&mut self, peer_id: &PeerId, region: GeographicRegion) -> bool {
        // Remove from regional bucket
        let removed = if let Some(bucket) = self.regional_buckets.get_mut(&region) {
            bucket.remove_peer(peer_id)
        } else {
            false
        };

        // Remove from peer selector
        self.peer_selector.remove_peer(peer_id);

        // Update statistics
        if removed {
            self.update_peer_stats();
        }

        removed
    }

    /// Select optimal peers for a DHT operation
    pub fn select_peers_for_key(&mut self, _key: &Key, count: usize) -> Result<Vec<SelectedPeer>> {
        let start = Instant::now();

        // For DHT operations, we want peers close to the key
        // Use local region as preference if no specific targeting is needed
        let selected_peers = self
            .peer_selector
            .select_peers(Some(self.local_region), Some(count))?;

        // Update selection statistics
        self.stats.average_selection_latency = start.elapsed();
        if selected_peers.is_empty() {
            self.stats.failed_selections += 1;
        } else {
            self.stats.successful_selections += 1;
        }

        Ok(selected_peers)
    }

    /// Select peers for cross-region routing
    pub fn select_cross_region_peers(
        &mut self,
        source_region: GeographicRegion,
        target_region: GeographicRegion,
        count: usize,
    ) -> Result<Vec<SelectedPeer>> {
        if !self.config.enable_cross_region_optimization {
            // Fall back to regular selection
            return self
                .peer_selector
                .select_peers(Some(target_region), Some(count));
        }

        let selected_peers =
            self.peer_selector
                .select_cross_region_peers(source_region, target_region, count)?;

        // Update cross-region statistics
        if !selected_peers.is_empty() {
            self.stats.cross_region_routes += 1;
        }

        Ok(selected_peers)
    }

    /// Get the best peer from a specific region
    pub fn get_best_peer_in_region(&mut self, region: GeographicRegion) -> Option<SelectedPeer> {
        self.peer_selector.get_best_regional_peer(region)
    }

    /// Get all peers from a specific region
    pub fn get_regional_peers(
        &self,
        region: GeographicRegion,
    ) -> Vec<(PeerId, PeerQualityMetrics)> {
        self.regional_buckets
            .get(&region)
            .map(|bucket| {
                bucket
                    .peers
                    .iter()
                    .map(|(peer_id, metrics)| (peer_id.clone(), metrics.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find closest peers to a DHT key across all regions
    pub fn find_closest_peers(&mut self, key: &Key, count: usize) -> Result<Vec<SelectedPeer>> {
        // In a real implementation, this would calculate XOR distance to the key
        // For now, we'll use our geographic selection as a proxy
        self.select_peers_for_key(key, count)
    }

    /// Perform maintenance on the routing table
    pub fn maintenance(&mut self) -> Result<()> {
        let now = Instant::now();

        // Only run maintenance if enough time has passed
        if now.duration_since(self.last_maintenance) < self.config.maintenance_interval {
            return Ok(());
        }

        // Maintain regional buckets
        for bucket in self.regional_buckets.values_mut() {
            bucket.maintenance(self.config.peer_metrics_max_age);
        }

        // Maintain peer selector
        self.peer_selector.maintenance()?;

        // Update statistics
        self.update_peer_stats();
        self.stats.last_maintenance = Some(SystemTime::now());
        self.last_maintenance = now;

        Ok(())
    }

    /// Get routing table statistics
    pub fn get_stats(&self) -> RoutingTableStats {
        self.stats.clone()
    }

    /// Get detailed regional statistics
    pub fn get_regional_stats(&self) -> Vec<RegionalStats> {
        self.regional_buckets
            .iter()
            .map(|(region, bucket)| {
                let bucket_stats = bucket.stats();
                RegionalStats {
                    region: *region,
                    peer_count: bucket_stats.peer_count,
                    average_reliability: bucket_stats.avg_reliability,
                    average_rtt: bucket_stats.avg_rtt,
                    last_maintenance: bucket_stats.last_maintenance,
                    is_preferred: self.config.preferred_regions.contains(region),
                }
            })
            .collect()
    }

    /// Check if the routing table has sufficient peers for reliable operation
    pub fn is_sufficiently_populated(&self) -> bool {
        let total_peers = self.stats.total_peers;
        let min_total = self.config.min_peers_per_region
            * std::cmp::min(GeographicRegion::all_regions().len(), 3);

        total_peers >= min_total
    }

    /// Get the local node's region
    pub fn get_local_region(&self) -> GeographicRegion {
        self.local_region
    }

    /// Update configuration
    pub fn update_config(&mut self, config: GeographicRoutingConfig) -> Result<()> {
        // Validate new configuration
        if config.max_peers_per_region == 0 || config.min_peers_per_region == 0 {
            return Err(P2PError::validation("Invalid peer count configuration"));
        }

        if config.min_peers_per_region > config.max_peers_per_region {
            return Err(P2PError::validation(
                "Minimum peers cannot exceed maximum peers",
            ));
        }

        self.config = config;
        Ok(())
    }

    /// Export routing table state for debugging
    pub fn export_state(&self) -> RoutingTableState {
        let regional_states: HashMap<GeographicRegion, RegionalBucketState> = self
            .regional_buckets
            .iter()
            .map(|(region, bucket)| {
                let peers: Vec<_> = bucket
                    .peers
                    .iter()
                    .map(|(peer_id, metrics)| (peer_id.clone(), metrics.clone()))
                    .collect();

                (
                    *region,
                    RegionalBucketState {
                        region: *region,
                        peers,
                        last_maintenance: SystemTime::now() - bucket.last_maintenance.elapsed(),
                    },
                )
            })
            .collect();

        RoutingTableState {
            local_region: self.local_region,
            regional_buckets: regional_states,
            stats: self.stats.clone(),
            config: self.config.clone(),
        }
    }

    /// Import routing table state (for testing/recovery)
    pub fn import_state(&mut self, state: RoutingTableState) -> Result<()> {
        // Validate state
        if state.regional_buckets.is_empty() {
            return Err(P2PError::validation(
                "Cannot import empty routing table state",
            ));
        }

        // Update regional buckets
        for (region, bucket_state) in state.regional_buckets {
            if let Some(bucket) = self.regional_buckets.get_mut(&region) {
                // Clear existing peers
                bucket.peers.clear();

                // Add peers from state
                for (peer_id, metrics) in bucket_state.peers {
                    bucket.add_peer(peer_id.clone(), metrics.clone());
                    // Also update peer selector
                    self.peer_selector.update_peer_metrics(peer_id, metrics)?;
                }

                // Use checked_sub for Windows compatibility (restored elapsed time may exceed process uptime)
                bucket.last_maintenance = Instant::now()
                    .checked_sub(bucket_state.last_maintenance.elapsed().unwrap_or_default())
                    .unwrap_or_else(Instant::now);
            }
        }

        // Update configuration and statistics
        self.config = state.config;
        self.stats = state.stats;
        self.local_region = state.local_region;

        Ok(())
    }

    /// Update internal peer statistics
    fn update_peer_stats(&mut self) {
        let mut total_peers = 0;
        let mut peers_by_region = HashMap::new();

        for (region, bucket) in &self.regional_buckets {
            let count = bucket.peers.len();
            total_peers += count;
            peers_by_region.insert(*region, count);
        }

        self.stats.total_peers = total_peers;
        self.stats.peers_by_region = peers_by_region;
    }
}

/// Statistics for a specific region
#[derive(Debug, Clone)]
pub struct RegionalStats {
    pub region: GeographicRegion,
    pub peer_count: usize,
    pub average_reliability: f64,
    pub average_rtt: Option<Duration>,
    pub last_maintenance: SystemTime,
    pub is_preferred: bool,
}

/// Serializable state of the routing table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingTableState {
    pub local_region: GeographicRegion,
    pub regional_buckets: HashMap<GeographicRegion, RegionalBucketState>,
    pub stats: RoutingTableStats,
    pub config: GeographicRoutingConfig,
}

/// Serializable state of a regional bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionalBucketState {
    pub region: GeographicRegion,
    pub peers: Vec<(PeerId, PeerQualityMetrics)>,
    pub last_maintenance: SystemTime,
}

/// Helper function for creating thread-safe routing table
pub fn create_safe_geographic_routing_table(
    local_region: GeographicRegion,
    config: GeographicRoutingConfig,
) -> SafeGeographicRoutingTable {
    Arc::new(RwLock::new(GeographicRoutingTable::new(
        local_region,
        config,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_geographic_routing_table_creation() {
        let config = GeographicRoutingConfig::default();
        let table = GeographicRoutingTable::new(GeographicRegion::Europe, config);

        assert_eq!(table.local_region, GeographicRegion::Europe);
        assert_eq!(
            table.regional_buckets.len(),
            GeographicRegion::all_regions().len()
        );
    }

    #[test]
    fn test_peer_addition_and_removal() {
        let config = GeographicRoutingConfig::default();
        let mut table = GeographicRoutingTable::new(GeographicRegion::Europe, config);

        let peer_id = "test_peer".to_string();
        let metrics = PeerQualityMetrics::new(GeographicRegion::Europe);

        // Add peer
        let added = table
            .add_peer(peer_id.clone(), GeographicRegion::Europe, metrics)
            .unwrap();
        assert!(added);

        let stats = table.get_stats();
        assert_eq!(stats.total_peers, 1);
        assert_eq!(
            stats.peers_by_region.get(&GeographicRegion::Europe),
            Some(&1)
        );

        // Remove peer
        let removed = table.remove_peer(&peer_id, GeographicRegion::Europe);
        assert!(removed);

        let stats = table.get_stats();
        assert_eq!(stats.total_peers, 0);
    }

    #[test]
    fn test_cross_region_peer_selection() {
        let config = GeographicRoutingConfig::default();
        let mut table = GeographicRoutingTable::new(GeographicRegion::Europe, config);

        // Add peers in different regions
        let mut eu_metrics = PeerQualityMetrics::new(GeographicRegion::Europe);
        eu_metrics.record_request(true);
        eu_metrics.record_rtt(Duration::from_millis(50));

        let mut na_metrics = PeerQualityMetrics::new(GeographicRegion::NorthAmerica);
        na_metrics.record_request(true);
        na_metrics.record_rtt(Duration::from_millis(100));

        table
            .add_peer("eu_peer".to_string(), GeographicRegion::Europe, eu_metrics)
            .unwrap();
        table
            .add_peer(
                "na_peer".to_string(),
                GeographicRegion::NorthAmerica,
                na_metrics,
            )
            .unwrap();

        // Test cross-region selection
        let selected = table
            .select_cross_region_peers(GeographicRegion::Europe, GeographicRegion::NorthAmerica, 2)
            .unwrap();

        assert!(!selected.is_empty());
        // Should include North American peer for target region
        assert!(
            selected
                .iter()
                .any(|p| p.region == GeographicRegion::NorthAmerica)
        );
    }

    #[tokio::test]
    async fn test_thread_safe_operations() {
        let config = GeographicRoutingConfig::default();
        let table = create_safe_geographic_routing_table(GeographicRegion::Europe, config);

        let metrics = PeerQualityMetrics::new(GeographicRegion::Europe);

        // Test concurrent operations
        let added = {
            let mut table_guard = table.write().await;
            table_guard.add_peer("test_peer".to_string(), GeographicRegion::Europe, metrics)
        };
        assert!(added.is_ok());

        let stats = {
            let table_guard = table.read().await;
            table_guard.get_stats()
        };
        assert_eq!(stats.total_peers, 1);
    }
}
