// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com

//! Witness Selection System for S/Kademlia Byzantine Fault Tolerance
//!
//! This module provides secure witness node selection for DHT operations.
//! Witnesses are selected based on:
//! - XOR distance to target key (closest nodes are preferred)
//! - Geographic diversity (anti-Sybil protection)
//! - Trust scores from EigenTrust system
//! - Node availability and responsiveness

use crate::PeerId;
use crate::dht::geographic_routing::GeographicRegion;
use crate::dht::{DhtKey, NodeInfo};
use crate::error::{P2PError, P2pResult as Result};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Instant;

/// A candidate witness node with metadata for selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessCandidate {
    /// The peer ID of the witness candidate
    pub peer_id: PeerId,
    /// XOR distance to target key (as bytes for comparison)
    pub distance_to_target: [u8; 32],
    /// Geographic region of the node
    pub region: GeographicRegion,
    /// Trust score from EigenTrust (0.0 to 1.0)
    pub trust_score: f64,
    /// Last time the node was seen active
    #[serde(skip)]
    pub last_seen: Option<Instant>,
    /// Whether the node is currently reachable
    pub is_reachable: bool,
}

impl WitnessCandidate {
    /// Create a new witness candidate
    pub fn new(
        peer_id: PeerId,
        distance_to_target: [u8; 32],
        region: GeographicRegion,
        trust_score: f64,
    ) -> Result<Self> {
        // Validate trust score is in valid range
        if !(0.0..=1.0).contains(&trust_score) {
            return Err(P2PError::InvalidInput(format!(
                "Trust score must be between 0.0 and 1.0, got {}",
                trust_score
            )));
        }

        Ok(Self {
            peer_id,
            distance_to_target,
            region,
            trust_score,
            last_seen: Some(Instant::now()),
            is_reachable: true,
        })
    }

    /// Create from a NodeInfo and target key
    pub fn from_node_info(
        node: &NodeInfo,
        target_key: &[u8; 32],
        trust_score: f64,
    ) -> Result<Self> {
        let node_key = DhtKey::from_bytes(*node.id.as_bytes());
        let target = DhtKey::from_bytes(*target_key);
        let distance = node_key.distance(&target);

        // Determine region from node's address if available
        let region = node
            .address
            .parse::<std::net::SocketAddr>()
            .ok()
            .map(|sock| GeographicRegion::from_ip(sock.ip()))
            .unwrap_or(GeographicRegion::Unknown);

        Self::new(node.id.to_string(), distance, region, trust_score)
    }

    /// Calculate a composite score for witness selection
    /// Higher scores are better candidates
    pub fn selection_score(&self) -> f64 {
        // Base score from trust (0.0 to 0.5)
        let trust_component = self.trust_score * 0.5;

        // Distance component: closer is better (0.0 to 0.3)
        // Use leading zeros as a quick distance metric
        let leading_zeros = self
            .distance_to_target
            .iter()
            .take_while(|&&b| b == 0)
            .count();
        let distance_component = (leading_zeros as f64 / 32.0) * 0.3;

        // Reachability component (0.0 or 0.2)
        let reachability_component = if self.is_reachable { 0.2 } else { 0.0 };

        trust_component + distance_component + reachability_component
    }
}

/// Configuration for witness selection
#[derive(Debug, Clone)]
pub struct WitnessSelectorConfig {
    /// Minimum number of witnesses required
    pub min_witnesses: usize,
    /// Maximum number of witnesses to select
    pub max_witnesses: usize,
    /// Minimum trust score required for a witness
    pub min_trust_score: f64,
    /// Minimum number of distinct geographic regions required
    pub min_distinct_regions: usize,
    /// Whether to exclude the source node from witnesses
    pub exclude_source: bool,
    /// Whether to exclude the target node from witnesses
    pub exclude_target: bool,
}

impl Default for WitnessSelectorConfig {
    fn default() -> Self {
        Self {
            min_witnesses: 3,
            max_witnesses: 7,
            min_trust_score: 0.3,
            min_distinct_regions: 2,
            exclude_source: true,
            exclude_target: true,
        }
    }
}

/// Result of witness selection
#[derive(Debug, Clone)]
pub struct WitnessSelection {
    /// Selected witness candidates
    pub witnesses: Vec<WitnessCandidate>,
    /// Number of distinct regions represented
    pub distinct_regions: usize,
    /// Average trust score of selected witnesses
    pub avg_trust_score: f64,
    /// Whether the selection meets Byzantine fault tolerance requirements
    pub meets_bft_requirements: bool,
}

impl WitnessSelection {
    /// Check if this selection is valid for the given config
    pub fn is_valid(&self, config: &WitnessSelectorConfig) -> bool {
        self.witnesses.len() >= config.min_witnesses
            && self.distinct_regions >= config.min_distinct_regions
            && self.avg_trust_score >= config.min_trust_score
    }
}

/// Witness selector for S/Kademlia operations
pub struct WitnessSelector {
    config: WitnessSelectorConfig,
}

impl WitnessSelector {
    /// Create a new witness selector with default config
    pub fn new() -> Self {
        Self {
            config: WitnessSelectorConfig::default(),
        }
    }

    /// Create a new witness selector with custom config
    pub fn with_config(config: WitnessSelectorConfig) -> Self {
        Self { config }
    }

    /// Get the configuration
    pub fn config(&self) -> &WitnessSelectorConfig {
        &self.config
    }

    /// Select witnesses from a list of candidates
    ///
    /// This method implements the core witness selection algorithm:
    /// 1. Filter by minimum trust score
    /// 2. Exclude source and target nodes if configured
    /// 3. Sort by selection score (distance + trust + reachability)
    /// 4. Ensure geographic diversity
    /// 5. Return the top candidates meeting all requirements
    pub fn select_witnesses(
        &self,
        candidates: &[WitnessCandidate],
        source_peer: Option<&PeerId>,
        target_peer: Option<&PeerId>,
    ) -> Result<WitnessSelection> {
        // Filter candidates by trust score
        let mut filtered: Vec<_> = candidates
            .iter()
            .filter(|c| c.trust_score >= self.config.min_trust_score)
            .filter(|c| c.is_reachable)
            .filter(|c| {
                // Exclude source if configured
                !(self.config.exclude_source
                    && source_peer.is_some_and(|source| &c.peer_id == source))
            })
            .filter(|c| {
                // Exclude target if configured
                !(self.config.exclude_target
                    && target_peer.is_some_and(|target| &c.peer_id == target))
            })
            .cloned()
            .collect();

        // Sort by selection score (highest first)
        filtered.sort_by(|a, b| {
            b.selection_score()
                .partial_cmp(&a.selection_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Select witnesses ensuring geographic diversity
        let selected = self.select_with_diversity(filtered);

        // Calculate metrics
        let distinct_regions: HashSet<_> = selected.iter().map(|w| w.region).collect();
        let avg_trust = if selected.is_empty() {
            0.0
        } else {
            selected.iter().map(|w| w.trust_score).sum::<f64>() / selected.len() as f64
        };

        // Check BFT requirements: need f+1 witnesses for f Byzantine faults
        // With 3 witnesses, can tolerate 1 Byzantine fault
        let meets_bft = selected.len() >= self.config.min_witnesses
            && distinct_regions.len() >= self.config.min_distinct_regions;

        Ok(WitnessSelection {
            witnesses: selected,
            distinct_regions: distinct_regions.len(),
            avg_trust_score: avg_trust,
            meets_bft_requirements: meets_bft,
        })
    }

    /// Select witnesses while ensuring geographic diversity
    fn select_with_diversity(&self, candidates: Vec<WitnessCandidate>) -> Vec<WitnessCandidate> {
        let mut selected = Vec::new();
        let mut regions_used: HashSet<GeographicRegion> = HashSet::new();

        // First pass: select one witness from each region (up to min_distinct_regions)
        for candidate in candidates.iter() {
            if selected.len() >= self.config.max_witnesses {
                break;
            }

            if !regions_used.contains(&candidate.region)
                && regions_used.len() < self.config.min_distinct_regions
            {
                selected.push(candidate.clone());
                regions_used.insert(candidate.region);
            }
        }

        // Second pass: fill remaining slots with best candidates
        for candidate in candidates.iter() {
            if selected.len() >= self.config.max_witnesses {
                break;
            }

            // Check if already selected
            if selected.iter().any(|s| s.peer_id == candidate.peer_id) {
                continue;
            }

            selected.push(candidate.clone());
        }

        selected
    }

    /// Select witnesses from NodeInfo list (convenience method)
    pub fn select_from_nodes(
        &self,
        nodes: &[NodeInfo],
        target_key: &[u8; 32],
        trust_scores: &std::collections::HashMap<String, f64>,
        source_peer: Option<&PeerId>,
        target_peer: Option<&PeerId>,
    ) -> Result<WitnessSelection> {
        let candidates: Vec<_> = nodes
            .iter()
            .filter_map(|node| {
                let trust = trust_scores
                    .get(&node.id.to_string())
                    .copied()
                    .unwrap_or(0.5);
                WitnessCandidate::from_node_info(node, target_key, trust).ok()
            })
            .collect();

        self.select_witnesses(&candidates, source_peer, target_peer)
    }

    /// Select witnesses using Efraimidis-Spirakis weighted random sampling
    ///
    /// This algorithm provides weighted random sampling without replacement,
    /// where each candidate's probability of selection is proportional to their
    /// trust score. Unlike deterministic sorting, this adds unpredictability
    /// that makes Sybil attacks harder to execute.
    ///
    /// The algorithm works by:
    /// 1. Computing a key for each candidate: `key = random^(1/weight)`
    /// 2. Sorting by key (highest first)
    /// 3. Taking the top N candidates
    ///
    /// Higher weights produce higher keys on average, so high-trust nodes
    /// are more likely to be selected, but there's always randomness.
    ///
    /// # Arguments
    /// * `candidates` - List of witness candidates
    /// * `source_peer` - Optional source peer to exclude
    /// * `target_peer` - Optional target peer to exclude
    /// * `seed` - Seed for deterministic random number generation (for testing)
    pub fn select_witnesses_weighted_seeded(
        &self,
        candidates: &[WitnessCandidate],
        source_peer: Option<&PeerId>,
        target_peer: Option<&PeerId>,
        seed: u64,
    ) -> Result<WitnessSelection> {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        // Filter candidates by trust score, reachability, and exclusions
        let filtered: Vec<_> = candidates
            .iter()
            .filter(|c| c.trust_score >= self.config.min_trust_score)
            .filter(|c| c.is_reachable)
            .filter(|c| {
                !(self.config.exclude_source
                    && source_peer.is_some_and(|source| &c.peer_id == source))
            })
            .filter(|c| {
                !(self.config.exclude_target
                    && target_peer.is_some_and(|target| &c.peer_id == target))
            })
            .cloned()
            .collect();

        if filtered.is_empty() {
            return Ok(WitnessSelection {
                witnesses: vec![],
                distinct_regions: 0,
                avg_trust_score: 0.0,
                meets_bft_requirements: false,
            });
        }

        // Apply Efraimidis-Spirakis algorithm: key = random^(1/weight)
        // Use trust_score as weight (avoiding zero weights)
        let mut weighted: Vec<(f64, WitnessCandidate)> = filtered
            .into_iter()
            .map(|c| {
                let weight = c.trust_score.max(0.001); // Avoid division by zero
                let r: f64 = rng.r#gen();
                // E-S key: r^(1/w) - higher weight means higher key on average
                let key = r.powf(1.0 / weight);
                (key, c)
            })
            .collect();

        // Sort by E-S key (highest first = most likely to be selected)
        weighted.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        // Select witnesses while ensuring geographic diversity
        let selected = self.select_with_diversity_from_weighted(weighted);

        // Calculate metrics
        let distinct_regions: HashSet<_> = selected.iter().map(|w| w.region).collect();
        let avg_trust = if selected.is_empty() {
            0.0
        } else {
            selected.iter().map(|w| w.trust_score).sum::<f64>() / selected.len() as f64
        };

        let meets_bft = selected.len() >= self.config.min_witnesses
            && distinct_regions.len() >= self.config.min_distinct_regions;

        Ok(WitnessSelection {
            witnesses: selected,
            distinct_regions: distinct_regions.len(),
            avg_trust_score: avg_trust,
            meets_bft_requirements: meets_bft,
        })
    }

    /// Select witnesses from weighted candidates while maintaining geographic diversity
    ///
    /// This method ensures that witnesses come from multiple geographic regions
    /// to prevent concentration attacks, while respecting the weighted order.
    fn select_with_diversity_from_weighted(
        &self,
        weighted: Vec<(f64, WitnessCandidate)>,
    ) -> Vec<WitnessCandidate> {
        let mut selected = Vec::new();
        let mut regions_used: HashSet<GeographicRegion> = HashSet::new();

        // First pass: ensure geographic diversity by selecting from different regions
        // following the weighted order but prioritizing regions we haven't seen
        for (_, candidate) in weighted.iter() {
            if selected.len() >= self.config.max_witnesses {
                break;
            }

            // If we haven't met diversity requirements yet, prioritize new regions
            if regions_used.len() < self.config.min_distinct_regions
                && !regions_used.contains(&candidate.region)
            {
                selected.push(candidate.clone());
                regions_used.insert(candidate.region);
            }
        }

        // Second pass: fill remaining slots in weighted order
        for (_, candidate) in weighted.iter() {
            if selected.len() >= self.config.max_witnesses {
                break;
            }

            // Check if already selected
            if selected.iter().any(|s| s.peer_id == candidate.peer_id) {
                continue;
            }

            selected.push(candidate.clone());
            regions_used.insert(candidate.region);
        }

        selected
    }

    /// Select witnesses using weighted random sampling with system RNG
    ///
    /// Production version that uses a random seed from the system.
    /// Provides unpredictable selection while still favoring high-trust nodes.
    #[allow(dead_code)]
    pub fn select_witnesses_weighted(
        &self,
        candidates: &[WitnessCandidate],
        source_peer: Option<&PeerId>,
        target_peer: Option<&PeerId>,
    ) -> Result<WitnessSelection> {
        // Use system random for production
        let seed: u64 = rand::thread_rng().r#gen();
        self.select_witnesses_weighted_seeded(candidates, source_peer, target_peer, seed)
    }
}

impl Default for WitnessSelector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create test candidates
    fn create_test_candidate(
        id: &str,
        distance: u8,
        region: GeographicRegion,
        trust: f64,
    ) -> WitnessCandidate {
        let mut distance_bytes = [0u8; 32];
        distance_bytes[0] = distance;
        WitnessCandidate::new(id.to_string(), distance_bytes, region, trust).unwrap()
    }

    // ==================== WitnessCandidate Tests ====================

    #[test]
    fn test_witness_candidate_creation_valid() {
        let candidate = WitnessCandidate::new(
            "peer1".to_string(),
            [0u8; 32],
            GeographicRegion::Europe,
            0.8,
        );
        assert!(candidate.is_ok());
        let c = candidate.unwrap();
        assert_eq!(c.peer_id, "peer1");
        assert_eq!(c.trust_score, 0.8);
        assert_eq!(c.region, GeographicRegion::Europe);
        assert!(c.is_reachable);
    }

    #[test]
    fn test_witness_candidate_creation_invalid_trust_high() {
        let candidate = WitnessCandidate::new(
            "peer1".to_string(),
            [0u8; 32],
            GeographicRegion::Europe,
            1.5, // Invalid: > 1.0
        );
        assert!(candidate.is_err());
    }

    #[test]
    fn test_witness_candidate_creation_invalid_trust_negative() {
        let candidate = WitnessCandidate::new(
            "peer1".to_string(),
            [0u8; 32],
            GeographicRegion::Europe,
            -0.1, // Invalid: < 0.0
        );
        assert!(candidate.is_err());
    }

    #[test]
    fn test_witness_candidate_selection_score() {
        // High trust, close distance, reachable
        let good_candidate = create_test_candidate("good", 0, GeographicRegion::Europe, 0.9);
        let good_score = good_candidate.selection_score();

        // Low trust, far distance, reachable
        let bad_candidate = create_test_candidate("bad", 255, GeographicRegion::Europe, 0.1);
        let bad_score = bad_candidate.selection_score();

        assert!(
            good_score > bad_score,
            "Good candidate should have higher score"
        );
        assert!((0.0..=1.0).contains(&good_score));
        assert!((0.0..=1.0).contains(&bad_score));
    }

    #[test]
    fn test_witness_candidate_unreachable_score() {
        let reachable = create_test_candidate("r", 0, GeographicRegion::Europe, 0.8);
        let mut unreachable = create_test_candidate("u", 0, GeographicRegion::Europe, 0.8);
        unreachable.is_reachable = false;

        assert!(reachable.selection_score() > unreachable.selection_score());
    }

    // ==================== WitnessSelector Tests ====================

    #[test]
    fn test_witness_selector_default_config() {
        let selector = WitnessSelector::new();
        let config = selector.config();

        assert_eq!(config.min_witnesses, 3);
        assert_eq!(config.max_witnesses, 7);
        assert_eq!(config.min_trust_score, 0.3);
        assert_eq!(config.min_distinct_regions, 2);
    }

    #[test]
    fn test_witness_selector_select_basic() {
        let selector = WitnessSelector::new();

        let candidates = vec![
            create_test_candidate("peer1", 1, GeographicRegion::Europe, 0.8),
            create_test_candidate("peer2", 2, GeographicRegion::NorthAmerica, 0.7),
            create_test_candidate("peer3", 3, GeographicRegion::AsiaPacific, 0.9),
            create_test_candidate("peer4", 4, GeographicRegion::Europe, 0.6),
        ];

        let result = selector.select_witnesses(&candidates, None, None);
        assert!(result.is_ok());

        let selection = result.unwrap();
        assert!(selection.witnesses.len() >= 3);
        assert!(selection.distinct_regions >= 2);
        assert!(selection.meets_bft_requirements);
    }

    #[test]
    fn test_witness_selector_excludes_low_trust() {
        let config = WitnessSelectorConfig {
            min_trust_score: 0.5,
            min_witnesses: 2,
            min_distinct_regions: 1,
            ..Default::default()
        };
        let selector = WitnessSelector::with_config(config);

        let candidates = vec![
            create_test_candidate("low_trust", 1, GeographicRegion::Europe, 0.2),
            create_test_candidate("high_trust", 2, GeographicRegion::Europe, 0.8),
        ];

        let selection = selector.select_witnesses(&candidates, None, None).unwrap();

        // Should only include high trust candidate
        assert_eq!(selection.witnesses.len(), 1);
        assert_eq!(selection.witnesses[0].peer_id, "high_trust");
    }

    #[test]
    fn test_witness_selector_excludes_source() {
        let selector = WitnessSelector::new();

        let candidates = vec![
            create_test_candidate("source", 1, GeographicRegion::Europe, 0.8),
            create_test_candidate("peer2", 2, GeographicRegion::NorthAmerica, 0.7),
            create_test_candidate("peer3", 3, GeographicRegion::AsiaPacific, 0.9),
        ];

        let source = "source".to_string();
        let selection = selector
            .select_witnesses(&candidates, Some(&source), None)
            .unwrap();

        // Source should be excluded
        assert!(!selection.witnesses.iter().any(|w| w.peer_id == "source"));
    }

    #[test]
    fn test_witness_selector_excludes_target() {
        let selector = WitnessSelector::new();

        let candidates = vec![
            create_test_candidate("peer1", 1, GeographicRegion::Europe, 0.8),
            create_test_candidate("target", 2, GeographicRegion::NorthAmerica, 0.7),
            create_test_candidate("peer3", 3, GeographicRegion::AsiaPacific, 0.9),
        ];

        let target = "target".to_string();
        let selection = selector
            .select_witnesses(&candidates, None, Some(&target))
            .unwrap();

        // Target should be excluded
        assert!(!selection.witnesses.iter().any(|w| w.peer_id == "target"));
    }

    #[test]
    fn test_witness_selector_geographic_diversity() {
        let config = WitnessSelectorConfig {
            min_witnesses: 3,
            max_witnesses: 5,
            min_distinct_regions: 3,
            min_trust_score: 0.3,
            ..Default::default()
        };
        let selector = WitnessSelector::with_config(config);

        // All candidates from same region
        let candidates = vec![
            create_test_candidate("peer1", 1, GeographicRegion::Europe, 0.9),
            create_test_candidate("peer2", 2, GeographicRegion::Europe, 0.8),
            create_test_candidate("peer3", 3, GeographicRegion::Europe, 0.7),
        ];

        let selection = selector.select_witnesses(&candidates, None, None).unwrap();

        // Should select all but fail BFT requirements (only 1 region)
        assert!(!selection.meets_bft_requirements);
        assert_eq!(selection.distinct_regions, 1);
    }

    #[test]
    fn test_witness_selector_respects_max_witnesses() {
        let config = WitnessSelectorConfig {
            min_witnesses: 2,
            max_witnesses: 3,
            min_distinct_regions: 1,
            ..Default::default()
        };
        let selector = WitnessSelector::with_config(config);

        let candidates = vec![
            create_test_candidate("peer1", 1, GeographicRegion::Europe, 0.8),
            create_test_candidate("peer2", 2, GeographicRegion::NorthAmerica, 0.7),
            create_test_candidate("peer3", 3, GeographicRegion::AsiaPacific, 0.9),
            create_test_candidate("peer4", 4, GeographicRegion::Africa, 0.6),
            create_test_candidate("peer5", 5, GeographicRegion::Oceania, 0.5),
        ];

        let selection = selector.select_witnesses(&candidates, None, None).unwrap();

        // Should not exceed max_witnesses
        assert!(selection.witnesses.len() <= 3);
    }

    #[test]
    fn test_witness_selector_excludes_unreachable() {
        let selector = WitnessSelector::new();

        let mut unreachable =
            create_test_candidate("unreachable", 1, GeographicRegion::Europe, 0.9);
        unreachable.is_reachable = false;

        let candidates = vec![
            unreachable,
            create_test_candidate("reachable1", 2, GeographicRegion::NorthAmerica, 0.7),
            create_test_candidate("reachable2", 3, GeographicRegion::AsiaPacific, 0.8),
        ];

        let selection = selector.select_witnesses(&candidates, None, None).unwrap();

        // Unreachable should be excluded
        assert!(
            !selection
                .witnesses
                .iter()
                .any(|w| w.peer_id == "unreachable")
        );
    }

    #[test]
    fn test_witness_selection_validity() {
        let config = WitnessSelectorConfig {
            min_witnesses: 3,
            min_distinct_regions: 2,
            min_trust_score: 0.5,
            ..Default::default()
        };

        let valid_selection = WitnessSelection {
            witnesses: vec![
                create_test_candidate("p1", 1, GeographicRegion::Europe, 0.7),
                create_test_candidate("p2", 2, GeographicRegion::NorthAmerica, 0.8),
                create_test_candidate("p3", 3, GeographicRegion::AsiaPacific, 0.6),
            ],
            distinct_regions: 3,
            avg_trust_score: 0.7,
            meets_bft_requirements: true,
        };

        assert!(valid_selection.is_valid(&config));

        let invalid_selection = WitnessSelection {
            witnesses: vec![create_test_candidate(
                "p1",
                1,
                GeographicRegion::Europe,
                0.7,
            )],
            distinct_regions: 1,
            avg_trust_score: 0.7,
            meets_bft_requirements: false,
        };

        assert!(!invalid_selection.is_valid(&config));
    }

    #[test]
    fn test_witness_selector_empty_candidates() {
        let selector = WitnessSelector::new();
        let selection = selector.select_witnesses(&[], None, None).unwrap();

        assert!(selection.witnesses.is_empty());
        assert!(!selection.meets_bft_requirements);
        assert_eq!(selection.avg_trust_score, 0.0);
    }

    #[test]
    fn test_witness_selector_prioritizes_diverse_regions() {
        let config = WitnessSelectorConfig {
            min_witnesses: 3,
            max_witnesses: 3,
            min_distinct_regions: 3,
            min_trust_score: 0.3,
            ..Default::default()
        };
        let selector = WitnessSelector::with_config(config);

        // First candidate is best by score but we should prioritize diversity
        let candidates = vec![
            create_test_candidate("eu_best", 0, GeographicRegion::Europe, 0.95),
            create_test_candidate("eu_good", 1, GeographicRegion::Europe, 0.9),
            create_test_candidate("na_good", 2, GeographicRegion::NorthAmerica, 0.85),
            create_test_candidate("ap_good", 3, GeographicRegion::AsiaPacific, 0.8),
        ];

        let selection = selector.select_witnesses(&candidates, None, None).unwrap();

        // Should have 3 distinct regions
        assert_eq!(selection.distinct_regions, 3);
        assert!(selection.meets_bft_requirements);
    }

    // ==================== Efraimidis-Spirakis Algorithm Tests (TDD) ====================
    //
    // These tests define the expected behavior for trust-weighted random sampling.
    // The Efraimidis-Spirakis algorithm provides weighted random sampling without
    // replacement using the formula: key = random()^(1/weight)
    //
    // Key properties:
    // 1. Higher weights have higher probability of selection
    // 2. Selection is non-deterministic (unlike sorting)
    // 3. Can be seeded for reproducibility in tests

    #[test]
    fn test_weighted_selection_with_seed_is_reproducible() {
        // With the same seed, weighted selection should produce identical results
        let config = WitnessSelectorConfig {
            min_witnesses: 3,
            max_witnesses: 3,
            min_distinct_regions: 1,
            min_trust_score: 0.3,
            ..Default::default()
        };
        let selector = WitnessSelector::with_config(config);

        let candidates = vec![
            create_test_candidate("peer1", 1, GeographicRegion::Europe, 0.9),
            create_test_candidate("peer2", 2, GeographicRegion::NorthAmerica, 0.8),
            create_test_candidate("peer3", 3, GeographicRegion::AsiaPacific, 0.7),
            create_test_candidate("peer4", 4, GeographicRegion::Africa, 0.6),
            create_test_candidate("peer5", 5, GeographicRegion::SouthAmerica, 0.5),
        ];

        // Two selections with the same seed should be identical
        let selection1 = selector
            .select_witnesses_weighted_seeded(&candidates, None, None, 12345)
            .unwrap();
        let selection2 = selector
            .select_witnesses_weighted_seeded(&candidates, None, None, 12345)
            .unwrap();

        let ids1: Vec<_> = selection1.witnesses.iter().map(|w| &w.peer_id).collect();
        let ids2: Vec<_> = selection2.witnesses.iter().map(|w| &w.peer_id).collect();

        assert_eq!(ids1, ids2, "Same seed should produce same selection");
    }

    #[test]
    fn test_weighted_selection_different_seeds_may_differ() {
        // Different seeds should (likely) produce different results
        let config = WitnessSelectorConfig {
            min_witnesses: 3,
            max_witnesses: 3,
            min_distinct_regions: 1,
            min_trust_score: 0.3,
            ..Default::default()
        };
        let selector = WitnessSelector::with_config(config);

        let candidates = vec![
            create_test_candidate("peer1", 1, GeographicRegion::Europe, 0.9),
            create_test_candidate("peer2", 2, GeographicRegion::NorthAmerica, 0.8),
            create_test_candidate("peer3", 3, GeographicRegion::AsiaPacific, 0.7),
            create_test_candidate("peer4", 4, GeographicRegion::Africa, 0.6),
            create_test_candidate("peer5", 5, GeographicRegion::SouthAmerica, 0.5),
        ];

        // Try multiple different seeds and check if at least one differs
        let selection_base = selector
            .select_witnesses_weighted_seeded(&candidates, None, None, 12345)
            .unwrap();
        let ids_base: Vec<_> = selection_base
            .witnesses
            .iter()
            .map(|w| &w.peer_id)
            .collect();

        let mut found_different = false;
        for seed in [99999, 11111, 77777, 33333] {
            let selection = selector
                .select_witnesses_weighted_seeded(&candidates, None, None, seed)
                .unwrap();
            let ids: Vec<_> = selection.witnesses.iter().map(|w| &w.peer_id).collect();
            if ids != ids_base {
                found_different = true;
                break;
            }
        }

        assert!(
            found_different,
            "Different seeds should produce different results (probabilistic)"
        );
    }

    #[test]
    fn test_weighted_selection_high_trust_selected_more_frequently() {
        // Over many trials, higher trust nodes should be selected more often
        let config = WitnessSelectorConfig {
            min_witnesses: 2,
            max_witnesses: 2,
            min_distinct_regions: 1,
            min_trust_score: 0.1,
            ..Default::default()
        };
        let selector = WitnessSelector::with_config(config);

        // Candidate with much higher trust should dominate selection
        let candidates = vec![
            create_test_candidate("high_trust", 1, GeographicRegion::Europe, 0.95),
            create_test_candidate("low_trust", 2, GeographicRegion::Europe, 0.15),
        ];

        let mut high_trust_count = 0;
        let trials = 100;

        for seed in 0..trials {
            let selection = selector
                .select_witnesses_weighted_seeded(&candidates, None, None, seed)
                .unwrap();
            if selection
                .witnesses
                .iter()
                .any(|w| w.peer_id == "high_trust")
            {
                high_trust_count += 1;
            }
        }

        // High trust node should be selected in vast majority of cases
        // With 0.95 vs 0.15 trust, high_trust should win > 80% of the time
        let high_trust_ratio = high_trust_count as f64 / trials as f64;
        assert!(
            high_trust_ratio > 0.8,
            "High trust node should be selected more often. Got ratio: {high_trust_ratio}"
        );
    }

    #[test]
    fn test_weighted_selection_statistical_distribution() {
        // Verify that selection frequency roughly matches trust weight ratios
        let config = WitnessSelectorConfig {
            min_witnesses: 1,
            max_witnesses: 1,
            min_distinct_regions: 1,
            min_trust_score: 0.1,
            ..Default::default()
        };
        let selector = WitnessSelector::with_config(config);

        // Three candidates with trust ratio 3:2:1
        let candidates = vec![
            create_test_candidate("high", 1, GeographicRegion::Europe, 0.6), // weight 3x
            create_test_candidate("medium", 2, GeographicRegion::Europe, 0.4), // weight 2x
            create_test_candidate("low", 3, GeographicRegion::Europe, 0.2),  // weight 1x
        ];

        let mut counts = std::collections::HashMap::new();
        let trials = 1000;

        for seed in 0..trials {
            let selection = selector
                .select_witnesses_weighted_seeded(&candidates, None, None, seed)
                .unwrap();
            if let Some(winner) = selection.witnesses.first() {
                *counts.entry(winner.peer_id.clone()).or_insert(0) += 1;
            }
        }

        let high_count = *counts.get("high").unwrap_or(&0) as f64;
        let medium_count = *counts.get("medium").unwrap_or(&0) as f64;
        let low_count = *counts.get("low").unwrap_or(&0) as f64;

        // Check relative ordering: high > medium > low
        assert!(
            high_count > medium_count,
            "High trust should be selected more than medium. Got high={high_count}, medium={medium_count}"
        );
        assert!(
            medium_count > low_count,
            "Medium trust should be selected more than low. Got medium={medium_count}, low={low_count}"
        );

        // Rough ratio check: high should be ~3x low (with some tolerance)
        let high_to_low_ratio = high_count / low_count.max(1.0);
        assert!(
            high_to_low_ratio > 1.5 && high_to_low_ratio < 6.0,
            "High/low ratio should be roughly 3:1 (got {high_to_low_ratio})"
        );
    }

    #[test]
    fn test_weighted_selection_respects_minimum_trust() {
        // Candidates below min_trust should never be selected
        let config = WitnessSelectorConfig {
            min_witnesses: 2,
            max_witnesses: 2,
            min_distinct_regions: 1,
            min_trust_score: 0.5,
            ..Default::default()
        };
        let selector = WitnessSelector::with_config(config);

        let candidates = vec![
            create_test_candidate("good1", 1, GeographicRegion::Europe, 0.9),
            create_test_candidate("good2", 2, GeographicRegion::Europe, 0.7),
            create_test_candidate("bad", 3, GeographicRegion::Europe, 0.3), // Below min
        ];

        // Verify low trust never selected across many trials
        for seed in 0..50 {
            let selection = selector
                .select_witnesses_weighted_seeded(&candidates, None, None, seed)
                .unwrap();
            assert!(
                !selection.witnesses.iter().any(|w| w.peer_id == "bad"),
                "Low trust candidate should never be selected"
            );
        }
    }

    #[test]
    fn test_weighted_selection_maintains_geographic_diversity() {
        // Even with weighted selection, geographic diversity should be maintained
        let config = WitnessSelectorConfig {
            min_witnesses: 3,
            max_witnesses: 3,
            min_distinct_regions: 2,
            min_trust_score: 0.3,
            ..Default::default()
        };
        let selector = WitnessSelector::with_config(config);

        // High trust in Europe, but we still need diversity
        let candidates = vec![
            create_test_candidate("eu1", 1, GeographicRegion::Europe, 0.95),
            create_test_candidate("eu2", 2, GeographicRegion::Europe, 0.9),
            create_test_candidate("na1", 3, GeographicRegion::NorthAmerica, 0.5),
            create_test_candidate("ap1", 4, GeographicRegion::AsiaPacific, 0.5),
        ];

        for seed in 0..20 {
            let selection = selector
                .select_witnesses_weighted_seeded(&candidates, None, None, seed)
                .unwrap();
            assert!(
                selection.distinct_regions >= 2,
                "Should maintain geographic diversity. Got {} regions",
                selection.distinct_regions
            );
        }
    }

    #[test]
    fn test_weighted_selection_handles_equal_weights() {
        // When all weights are equal, selection should be uniform random
        let config = WitnessSelectorConfig {
            min_witnesses: 1,
            max_witnesses: 1,
            min_distinct_regions: 1,
            min_trust_score: 0.1,
            ..Default::default()
        };
        let selector = WitnessSelector::with_config(config);

        let candidates = vec![
            create_test_candidate("peer1", 1, GeographicRegion::Europe, 0.5),
            create_test_candidate("peer2", 2, GeographicRegion::Europe, 0.5),
            create_test_candidate("peer3", 3, GeographicRegion::Europe, 0.5),
        ];

        let mut counts = std::collections::HashMap::new();
        let trials = 300;

        for seed in 0..trials {
            let selection = selector
                .select_witnesses_weighted_seeded(&candidates, None, None, seed)
                .unwrap();
            if let Some(winner) = selection.witnesses.first() {
                *counts.entry(winner.peer_id.clone()).or_insert(0) += 1;
            }
        }

        // Each should be selected roughly 1/3 of the time (with tolerance)
        for (peer, count) in &counts {
            let ratio = *count as f64 / trials as f64;
            assert!(
                ratio > 0.15 && ratio < 0.5,
                "Peer {peer} selected {ratio:.2}%, expected ~33%"
            );
        }
    }

    #[test]
    fn test_weighted_selection_excludes_source_and_target() {
        // Source and target exclusion should still work with weighted selection
        let config = WitnessSelectorConfig {
            min_witnesses: 2,
            max_witnesses: 2,
            min_distinct_regions: 1,
            min_trust_score: 0.1,
            exclude_source: true,
            exclude_target: true,
        };
        let selector = WitnessSelector::with_config(config);

        let candidates = vec![
            create_test_candidate("source", 1, GeographicRegion::Europe, 0.99),
            create_test_candidate("target", 2, GeographicRegion::Europe, 0.98),
            create_test_candidate("other1", 3, GeographicRegion::Europe, 0.5),
            create_test_candidate("other2", 4, GeographicRegion::Europe, 0.5),
        ];

        let source = "source".to_string();
        let target = "target".to_string();

        for seed in 0..20 {
            let selection = selector
                .select_witnesses_weighted_seeded(&candidates, Some(&source), Some(&target), seed)
                .unwrap();
            assert!(
                !selection.witnesses.iter().any(|w| w.peer_id == "source"),
                "Source should be excluded"
            );
            assert!(
                !selection.witnesses.iter().any(|w| w.peer_id == "target"),
                "Target should be excluded"
            );
        }
    }

    #[test]
    fn test_efraimidis_spirakis_key_calculation() {
        // Test the core E-S formula: key = random^(1/weight)
        // Higher weights should produce higher keys on average
        use rand::Rng;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let high_weight = 0.9_f64;
        let low_weight = 0.1_f64;

        let mut high_keys = Vec::new();
        let mut low_keys = Vec::new();

        for _ in 0..1000 {
            let r: f64 = rng.r#gen();
            high_keys.push(r.powf(1.0 / high_weight));
            low_keys.push(r.powf(1.0 / low_weight));
        }

        let high_avg: f64 = high_keys.iter().sum::<f64>() / high_keys.len() as f64;
        let low_avg: f64 = low_keys.iter().sum::<f64>() / low_keys.len() as f64;

        // Higher weights should produce higher keys on average
        assert!(
            high_avg > low_avg,
            "Higher weights should produce higher E-S keys. Got high={high_avg}, low={low_avg}"
        );
    }
}
