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

//! Latency-Aware Peer Selection for Geographic DHT Routing
//!
//! Implements intelligent peer selection based on latency measurements,
//! success rates, and geographic proximity for optimal P2P network performance.

use super::geographic_routing::{GeographicRegion, PeerQualityMetrics};
use crate::PeerId;
use crate::error::{P2PError, P2pResult as Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Configuration for latency-aware peer selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencySelectionConfig {
    /// Maximum number of peers to cache per region
    pub max_peers_per_region: usize,
    /// Minimum reliability score to consider a peer
    pub min_reliability_threshold: f64,
    /// Maximum age for cached measurements
    pub measurement_max_age: Duration,
    /// Preferred region bonus for selection scoring
    pub region_preference_bonus: f64,
    /// Number of peers to return for selection requests
    pub default_selection_count: usize,
}

impl Default for LatencySelectionConfig {
    fn default() -> Self {
        Self {
            max_peers_per_region: 20,
            min_reliability_threshold: 0.3,
            measurement_max_age: Duration::from_secs(300), // 5 minutes
            region_preference_bonus: 0.2,
            default_selection_count: 8,
        }
    }
}

/// Cache entry with LRU tracking
#[derive(Debug, Clone)]
struct CacheEntry {
    peer_id: PeerId,
    metrics: PeerQualityMetrics,
    last_accessed: Instant,
}

/// LRU cache for peer quality metrics
#[derive(Debug)]
pub struct PeerMetricsCache {
    /// Cache entries by peer ID
    entries: HashMap<PeerId, CacheEntry>,
    /// Access order for LRU eviction
    access_order: VecDeque<PeerId>,
    /// Maximum cache size
    max_size: usize,
    /// Regional organization of cached peers
    regional_peers: HashMap<GeographicRegion, Vec<PeerId>>,
}

impl PeerMetricsCache {
    /// Create a new LRU cache
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            access_order: VecDeque::new(),
            max_size,
            regional_peers: HashMap::new(),
        }
    }

    /// Add or update a peer in the cache
    pub fn insert(&mut self, peer_id: PeerId, metrics: PeerQualityMetrics) {
        let now = Instant::now();

        // Remove from old position if exists
        if self.entries.contains_key(&peer_id) {
            self.remove_from_access_order(&peer_id);
            self.remove_from_regional_index(&peer_id);
        }

        // Add to cache
        self.entries.insert(
            peer_id.clone(),
            CacheEntry {
                peer_id: peer_id.clone(),
                metrics: metrics.clone(),
                last_accessed: now,
            },
        );

        // Update access order
        self.access_order.push_back(peer_id.clone());

        // Update regional index
        self.regional_peers
            .entry(metrics.region)
            .or_default()
            .push(peer_id.clone());

        // Evict if over capacity
        while self.entries.len() > self.max_size {
            self.evict_lru();
        }
    }

    /// Get a peer from the cache
    pub fn get(&mut self, peer_id: &PeerId) -> Option<PeerQualityMetrics> {
        if self.entries.contains_key(peer_id) {
            // Update access order first
            self.remove_from_access_order(peer_id);
            self.access_order.push_back(peer_id.clone());

            // Now update the entry and return the metrics
            if let Some(entry) = self.entries.get_mut(peer_id) {
                entry.last_accessed = Instant::now();
                Some(entry.metrics.clone())
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get peers from a specific region
    pub fn get_regional_peers(
        &self,
        region: GeographicRegion,
    ) -> Vec<(PeerId, PeerQualityMetrics)> {
        self.regional_peers
            .get(&region)
            .map(|peer_ids| {
                peer_ids
                    .iter()
                    .filter_map(|id| self.entries.get(id))
                    .map(|entry| (entry.peer_id.clone(), entry.metrics.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Remove a peer from the cache
    pub fn remove(&mut self, peer_id: &PeerId) -> bool {
        if let Some(_entry) = self.entries.remove(peer_id) {
            self.remove_from_access_order(peer_id);
            self.remove_from_regional_index(peer_id);
            true
        } else {
            false
        }
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&mut self, max_age: Duration) {
        let now = Instant::now();
        let expired_peers: Vec<PeerId> = self
            .entries
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.last_accessed) > max_age)
            .map(|(peer_id, _)| peer_id.clone())
            .collect();

        for peer_id in expired_peers {
            self.remove(&peer_id);
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let regional_counts: HashMap<GeographicRegion, usize> = self
            .regional_peers
            .iter()
            .map(|(region, peers)| (*region, peers.len()))
            .collect();

        CacheStats {
            total_peers: self.entries.len(),
            max_capacity: self.max_size,
            regional_distribution: regional_counts,
            hit_ratio: 0.0, // Would need to track hits/misses for this
        }
    }

    /// Evict least recently used entry
    fn evict_lru(&mut self) {
        if let Some(peer_id) = self.access_order.pop_front()
            && let Some(entry) = self.entries.remove(&peer_id)
        {
            self.remove_from_regional_index(&entry.peer_id);
        }
    }

    /// Remove peer from access order tracking
    fn remove_from_access_order(&mut self, peer_id: &PeerId) {
        if let Some(pos) = self.access_order.iter().position(|id| id == peer_id) {
            self.access_order.remove(pos);
        }
    }

    /// Remove peer from regional index
    fn remove_from_regional_index(&mut self, peer_id: &PeerId) {
        for peers in self.regional_peers.values_mut() {
            if let Some(pos) = peers.iter().position(|id| id == peer_id) {
                peers.remove(pos);
                break;
            }
        }
    }
}

/// Statistics for the peer metrics cache
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_peers: usize,
    pub max_capacity: usize,
    pub regional_distribution: HashMap<GeographicRegion, usize>,
    pub hit_ratio: f64,
}

/// Latency-aware peer selection system
#[derive(Debug)]
pub struct LatencyAwarePeerSelection {
    /// Configuration
    pub config: LatencySelectionConfig,
    /// LRU cache for peer metrics
    cache: PeerMetricsCache,
    /// Local node's region
    local_region: GeographicRegion,
    /// Selection statistics
    stats: SelectionStats,
}

/// Selection statistics
#[derive(Debug, Clone, Default)]
pub struct SelectionStats {
    pub total_selections: u64,
    pub cache_hits: u64,
    pub regional_selections: HashMap<GeographicRegion, u64>,
    pub average_selection_score: f64,
}

impl LatencyAwarePeerSelection {
    /// Create a new latency-aware peer selection system
    pub fn new(config: LatencySelectionConfig, local_region: GeographicRegion) -> Self {
        let cache_size = config.max_peers_per_region * GeographicRegion::all_regions().len();

        Self {
            config,
            cache: PeerMetricsCache::new(cache_size),
            local_region,
            stats: SelectionStats::default(),
        }
    }

    /// Update metrics for a peer
    pub fn update_peer_metrics(
        &mut self,
        peer_id: PeerId,
        metrics: PeerQualityMetrics,
    ) -> Result<()> {
        // Validate metrics quality
        if metrics.get_reliability_score() < 0.0 || metrics.get_reliability_score() > 1.0 {
            return Err(P2PError::validation("Invalid reliability score"));
        }

        // Update cache
        self.cache.insert(peer_id, metrics);
        Ok(())
    }

    /// Select best peers for a request
    pub fn select_peers(
        &mut self,
        target_region: Option<GeographicRegion>,
        count: Option<usize>,
    ) -> Result<Vec<SelectedPeer>> {
        let selection_count = count.unwrap_or(self.config.default_selection_count);
        let preferred_region = target_region.unwrap_or(self.local_region);

        // Collect all suitable peers from cache
        let mut candidates = Vec::new();

        // Start with preferred region
        let regional_peers = self.cache.get_regional_peers(preferred_region);
        for (peer_id, metrics) in regional_peers {
            if metrics.get_reliability_score() >= self.config.min_reliability_threshold {
                candidates.push((peer_id, metrics, preferred_region));
            }
        }

        // If we need more peers, look in other regions
        if candidates.len() < selection_count {
            for region in GeographicRegion::all_regions() {
                if region != preferred_region {
                    let regional_peers = self.cache.get_regional_peers(region);
                    for (peer_id, metrics) in regional_peers {
                        if metrics.get_reliability_score() >= self.config.min_reliability_threshold
                        {
                            candidates.push((peer_id, metrics, region));
                        }
                    }
                }
            }
        }

        // Score and sort candidates
        let mut scored_peers: Vec<_> = candidates
            .into_iter()
            .map(|(peer_id, metrics, region)| {
                let score = self.calculate_selection_score(&metrics, region, preferred_region);
                (peer_id, metrics, region, score)
            })
            .collect();

        use std::cmp::Ordering;
        scored_peers.sort_by(|a, b| b.3.partial_cmp(&a.3).unwrap_or(Ordering::Equal));

        // Select top peers
        let selected_peers: Vec<SelectedPeer> = scored_peers
            .into_iter()
            .take(selection_count)
            .map(|(peer_id, metrics, region, score)| SelectedPeer {
                peer_id,
                metrics,
                region,
                selection_score: score,
                selection_reason: self.get_selection_reason(region, preferred_region),
            })
            .collect();

        // Update statistics
        self.update_selection_stats(&selected_peers, preferred_region);

        Ok(selected_peers)
    }

    /// Select peers specifically for cross-region routing
    pub fn select_cross_region_peers(
        &mut self,
        source_region: GeographicRegion,
        target_region: GeographicRegion,
        count: usize,
    ) -> Result<Vec<SelectedPeer>> {
        // Look for peers that can bridge between regions
        let mut bridge_candidates = Vec::new();

        // Prefer peers in target region
        let target_peers = self.cache.get_regional_peers(target_region);
        for (peer_id, metrics) in target_peers {
            if metrics.get_reliability_score() >= self.config.min_reliability_threshold {
                let preference_score = source_region.preference_score(&target_region);
                bridge_candidates.push((peer_id, metrics, target_region, preference_score));
            }
        }

        // Add peers from intermediate regions if needed
        if bridge_candidates.len() < count {
            for region in GeographicRegion::all_regions() {
                if region != source_region && region != target_region {
                    let preference_score = source_region.preference_score(&region)
                        * region.preference_score(&target_region);

                    let regional_peers = self.cache.get_regional_peers(region);
                    for (peer_id, metrics) in regional_peers {
                        if metrics.get_reliability_score() >= self.config.min_reliability_threshold
                        {
                            bridge_candidates.push((peer_id, metrics, region, preference_score));
                        }
                    }
                }
            }
        }

        // Sort by preference score and reliability
        bridge_candidates.sort_by(|a, b| {
            let score_a = a.3 * a.1.get_reliability_score();
            let score_b = b.3 * b.1.get_reliability_score();
            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let selected_peers: Vec<SelectedPeer> = bridge_candidates
            .into_iter()
            .take(count)
            .map(|(peer_id, metrics, region, preference_score)| {
                let selection_score = preference_score * metrics.get_reliability_score();
                SelectedPeer {
                    peer_id,
                    metrics,
                    region,
                    selection_score,
                    selection_reason: format!(
                        "Cross-region bridge: {} -> {}",
                        source_region.to_string(),
                        target_region.to_string()
                    ),
                }
            })
            .collect();

        Ok(selected_peers)
    }

    /// Remove a peer from selection (e.g., if it becomes unavailable)
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> bool {
        self.cache.remove(peer_id)
    }

    /// Get the best peer from a specific region
    pub fn get_best_regional_peer(&mut self, region: GeographicRegion) -> Option<SelectedPeer> {
        let regional_peers = self.cache.get_regional_peers(region);

        regional_peers
            .into_iter()
            .filter(|(_, metrics)| {
                metrics.get_reliability_score() >= self.config.min_reliability_threshold
            })
            .max_by(|(_, a), (_, b)| {
                a.get_reliability_score()
                    .partial_cmp(&b.get_reliability_score())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(peer_id, metrics)| SelectedPeer {
                peer_id,
                region,
                selection_score: metrics.get_reliability_score(),
                selection_reason: "Best in region".to_string(),
                metrics,
            })
    }

    /// Perform maintenance on the peer selection system
    pub fn maintenance(&mut self) -> Result<()> {
        // Clean up expired cache entries
        self.cache.cleanup_expired(self.config.measurement_max_age);
        Ok(())
    }

    /// Get current statistics
    pub fn get_stats(&self) -> SelectionSystemStats {
        SelectionSystemStats {
            cache_stats: self.cache.stats(),
            selection_stats: self.stats.clone(),
            local_region: self.local_region,
            config: self.config.clone(),
        }
    }

    /// Calculate selection score for a peer
    fn calculate_selection_score(
        &self,
        metrics: &PeerQualityMetrics,
        peer_region: GeographicRegion,
        preferred_region: GeographicRegion,
    ) -> f64 {
        let mut score = metrics.get_reliability_score();

        // Add region preference bonus
        if peer_region == preferred_region {
            score += self.config.region_preference_bonus;
        } else {
            // Apply cross-region penalty based on preference
            let region_score = preferred_region.preference_score(&peer_region);
            score *= region_score;
        }

        // RTT bonus/penalty
        if let Some(avg_rtt) = metrics.average_rtt() {
            let (min_expected, max_expected) = peer_region.expected_latency_range();
            if avg_rtt <= min_expected {
                score += 0.1; // Excellent RTT bonus
            } else if avg_rtt >= max_expected {
                score -= 0.2; // Poor RTT penalty
            }
        }

        score.clamp(0.0, 1.0)
    }

    /// Get human-readable selection reason
    fn get_selection_reason(
        &self,
        peer_region: GeographicRegion,
        preferred_region: GeographicRegion,
    ) -> String {
        if peer_region == preferred_region {
            format!("Same region ({})", peer_region.to_string())
        } else {
            format!(
                "Cross-region ({} -> {})",
                preferred_region.to_string(),
                peer_region.to_string()
            )
        }
    }

    /// Update selection statistics
    fn update_selection_stats(
        &mut self,
        selected_peers: &[SelectedPeer],
        _preferred_region: GeographicRegion,
    ) {
        self.stats.total_selections += 1;

        for peer in selected_peers {
            *self
                .stats
                .regional_selections
                .entry(peer.region)
                .or_insert(0) += 1;
        }

        if !selected_peers.is_empty() {
            let total_score: f64 = selected_peers.iter().map(|p| p.selection_score).sum();
            self.stats.average_selection_score = total_score / selected_peers.len() as f64;
        }
    }
}

/// A selected peer with its selection metadata
#[derive(Debug, Clone)]
pub struct SelectedPeer {
    pub peer_id: PeerId,
    pub metrics: PeerQualityMetrics,
    pub region: GeographicRegion,
    pub selection_score: f64,
    pub selection_reason: String,
}

/// Complete statistics for the selection system
#[derive(Debug, Clone)]
pub struct SelectionSystemStats {
    pub cache_stats: CacheStats,
    pub selection_stats: SelectionStats,
    pub local_region: GeographicRegion,
    pub config: LatencySelectionConfig,
}

/// Convenience trait for string conversion
impl GeographicRegion {
    pub fn to_string(&self) -> &'static str {
        match self {
            GeographicRegion::NorthAmerica => "NorthAmerica",
            GeographicRegion::Europe => "Europe",
            GeographicRegion::AsiaPacific => "AsiaPacific",
            GeographicRegion::SouthAmerica => "SouthAmerica",
            GeographicRegion::Africa => "Africa",
            GeographicRegion::Oceania => "Oceania",
            GeographicRegion::Unknown => "Unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_peer_metrics_cache() {
        let mut cache = PeerMetricsCache::new(3);

        let peer1 = "peer1".to_string();
        let peer2 = "peer2".to_string();
        let peer3 = "peer3".to_string();
        let peer4 = "peer4".to_string();

        let metrics = PeerQualityMetrics::new(GeographicRegion::Europe);

        cache.insert(peer1.clone(), metrics.clone());
        cache.insert(peer2.clone(), metrics.clone());
        cache.insert(peer3.clone(), metrics.clone());

        assert_eq!(cache.entries.len(), 3);

        // This should evict peer1 (LRU)
        cache.insert(peer4.clone(), metrics);
        assert_eq!(cache.entries.len(), 3);
        assert!(!cache.entries.contains_key(&peer1));
        assert!(cache.entries.contains_key(&peer4));
    }

    #[test]
    fn test_latency_aware_peer_selection() {
        let config = LatencySelectionConfig::default();
        let mut selector = LatencyAwarePeerSelection::new(config, GeographicRegion::Europe);

        // Add some test peers
        let mut metrics1 = PeerQualityMetrics::new(GeographicRegion::Europe);
        metrics1.record_request(true);
        metrics1.record_rtt(Duration::from_millis(50));

        let mut metrics2 = PeerQualityMetrics::new(GeographicRegion::NorthAmerica);
        metrics2.record_request(true);
        metrics2.record_rtt(Duration::from_millis(100));

        selector
            .update_peer_metrics("peer1".to_string(), metrics1)
            .unwrap();
        selector
            .update_peer_metrics("peer2".to_string(), metrics2)
            .unwrap();

        // Select peers - should prefer European peer
        let selected = selector
            .select_peers(Some(GeographicRegion::Europe), Some(1))
            .unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].peer_id, "peer1");
        assert_eq!(selected[0].region, GeographicRegion::Europe);
    }

    #[test]
    fn test_cross_region_peer_selection() {
        let config = LatencySelectionConfig::default();
        let mut selector = LatencyAwarePeerSelection::new(config, GeographicRegion::Europe);

        // Add peers in different regions
        let mut eu_metrics = PeerQualityMetrics::new(GeographicRegion::Europe);
        eu_metrics.record_request(true);

        let mut na_metrics = PeerQualityMetrics::new(GeographicRegion::NorthAmerica);
        na_metrics.record_request(true);

        selector
            .update_peer_metrics("eu_peer".to_string(), eu_metrics)
            .unwrap();
        selector
            .update_peer_metrics("na_peer".to_string(), na_metrics)
            .unwrap();

        // Select cross-region peers
        let selected = selector
            .select_cross_region_peers(GeographicRegion::Europe, GeographicRegion::NorthAmerica, 2)
            .unwrap();

        // Should get the NA peer first (target region)
        assert!(!selected.is_empty());
        assert!(
            selected
                .iter()
                .any(|p| p.region == GeographicRegion::NorthAmerica)
        );
    }
}
