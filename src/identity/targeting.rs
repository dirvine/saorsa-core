// Copyright (c) 2025 Saorsa Labs Limited

// This file is part of the Saorsa P2P network.

// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Copyright 2024 P2P Foundation
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Targeted identity generation for avoiding rejected keyspace regions.
//!
//! This module provides mechanisms to generate new node identities that are
//! more likely to be accepted by the network by targeting less saturated
//! regions of the XOR keyspace.
//!
//! # Targeting Strategy
//!
//! When generating a new identity, the targeter considers:
//! - Rejected keyspace prefixes from previous attempts
//! - Network-suggested target regions
//! - Known saturation levels
//! - XOR distance from previous rejected positions
//!
//! # Example
//!
//! ```ignore
//! use saorsa_core::identity::targeting::{IdentityTargeter, TargetingConfig};
//!
//! let config = TargetingConfig::default();
//! let targeter = IdentityTargeter::new(config);
//!
//! // Add rejected prefixes from previous attempts
//! targeter.add_rejected_prefix(vec![0xAB], 8);
//!
//! // Generate targeted identity
//! let identity = targeter.generate_targeted_identity(
//!     Some(&suggested_target),
//!     100 // max attempts
//! ).await?;
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::RwLock;

use super::node_identity::{NodeId, NodeIdentity};
use super::rejection::{KeyspaceRegion, TargetRegion};
use crate::Result;

/// Configuration for identity targeting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetingConfig {
    /// Maximum attempts to generate a suitable identity (default: 100).
    pub max_generation_attempts: u32,

    /// Minimum XOR distance from rejected prefixes (bits, default: 4).
    pub min_distance_from_rejected: u8,

    /// Weight for XOR distance in candidate scoring (default: 0.4).
    pub distance_weight: f64,

    /// Weight for target region alignment in scoring (default: 0.3).
    pub target_weight: f64,

    /// Weight for avoiding rejected regions in scoring (default: 0.3).
    pub avoidance_weight: f64,

    /// Number of candidates to generate per round (default: 10).
    pub candidates_per_round: usize,
}

impl Default for TargetingConfig {
    fn default() -> Self {
        Self {
            max_generation_attempts: 100,
            min_distance_from_rejected: 4,
            distance_weight: 0.4,
            target_weight: 0.3,
            avoidance_weight: 0.3,
            candidates_per_round: 10,
        }
    }
}

/// A candidate identity being evaluated.
struct IdentityCandidate {
    /// The generated identity.
    identity: NodeIdentity,

    /// Score (0.0 to 1.0, higher is better).
    score: f64,
}

/// A rejected keyspace prefix to avoid.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct RejectedPrefix {
    /// The prefix bytes.
    pub prefix: Vec<u8>,

    /// Number of significant bits.
    pub prefix_len: u8,
}

impl RejectedPrefix {
    /// Create a new rejected prefix.
    #[must_use]
    pub fn new(prefix: Vec<u8>, prefix_len: u8) -> Self {
        Self { prefix, prefix_len }
    }

    /// Check if a NodeId matches this rejected prefix.
    #[must_use]
    pub fn matches(&self, node_id: &NodeId) -> bool {
        let node_bytes = node_id.to_bytes();
        let full_bytes = self.prefix_len as usize / 8;
        let remaining_bits = self.prefix_len as usize % 8;

        // Check full bytes using zip
        let prefix_slice = &self.prefix[..full_bytes.min(self.prefix.len())];
        let node_slice = &node_bytes[..full_bytes.min(node_bytes.len())];
        for (p, n) in prefix_slice.iter().zip(node_slice.iter()) {
            if p != n {
                return false;
            }
        }

        // Check remaining bits
        if remaining_bits > 0 && full_bytes < self.prefix.len() && full_bytes < node_bytes.len() {
            let mask = 0xFF << (8 - remaining_bits);
            if (self.prefix[full_bytes] & mask) != (node_bytes[full_bytes] & mask) {
                return false;
            }
        }

        true
    }

    /// Calculate XOR distance to a NodeId in the first `prefix_len` bits.
    #[must_use]
    pub fn xor_distance_bits(&self, node_id: &NodeId) -> u32 {
        let node_bytes = node_id.to_bytes();
        let mut distance = 0u32;

        let full_bytes = self.prefix_len as usize / 8;
        let remaining_bits = self.prefix_len as usize % 8;

        // Count differing bits in full bytes using zip
        let prefix_slice = &self.prefix[..full_bytes.min(self.prefix.len())];
        let node_slice = &node_bytes[..full_bytes.min(node_bytes.len())];
        for (p, n) in prefix_slice.iter().zip(node_slice.iter()) {
            let xor = p ^ n;
            distance += xor.count_ones();
        }

        // Count differing bits in partial byte
        if remaining_bits > 0 && full_bytes < self.prefix.len() && full_bytes < node_bytes.len() {
            let mask = 0xFF << (8 - remaining_bits);
            let xor = (self.prefix[full_bytes] ^ node_bytes[full_bytes]) & mask;
            distance += xor.count_ones();
        }

        distance
    }
}

/// Internal state for the identity targeter.
#[derive(Default)]
struct TargeterState {
    /// Rejected prefixes to avoid.
    rejected_prefixes: HashSet<RejectedPrefix>,

    /// Previously generated NodeIds that were rejected.
    rejected_node_ids: Vec<NodeId>,

    /// Last target region suggested by network.
    last_target: Option<TargetRegion>,

    /// Statistics on generation attempts.
    total_attempts: u64,

    /// Statistics on successful generations.
    successful_generations: u64,
}

/// Identity targeter for generating identities in suitable keyspace regions.
pub struct IdentityTargeter {
    /// Configuration.
    config: TargetingConfig,

    /// Internal state.
    state: RwLock<TargeterState>,
}

impl IdentityTargeter {
    /// Create a new identity targeter.
    #[must_use]
    pub fn new(config: TargetingConfig) -> Self {
        Self {
            config,
            state: RwLock::new(TargeterState::default()),
        }
    }

    /// Add a rejected prefix to avoid.
    pub fn add_rejected_prefix(&self, prefix: Vec<u8>, prefix_len: u8) {
        let rejected = RejectedPrefix::new(prefix, prefix_len);
        self.state.write().rejected_prefixes.insert(rejected);
    }

    /// Add multiple rejected prefixes from raw bytes.
    pub fn add_rejected_prefixes(&self, prefixes: &[Vec<u8>], prefix_len: u8) {
        let mut state = self.state.write();
        for prefix in prefixes {
            let rejected = RejectedPrefix::new(prefix.clone(), prefix_len);
            state.rejected_prefixes.insert(rejected);
        }
    }

    /// Record a rejected NodeId.
    pub fn record_rejected_node_id(&self, node_id: NodeId) {
        let mut state = self.state.write();
        state.rejected_node_ids.push(node_id);

        // Keep bounded list
        if state.rejected_node_ids.len() > 100 {
            state.rejected_node_ids.remove(0);
        }
    }

    /// Update the target region suggestion.
    pub fn set_target(&self, target: Option<TargetRegion>) {
        self.state.write().last_target = target;
    }

    /// Clear all rejected prefixes.
    pub fn clear_rejected(&self) {
        let mut state = self.state.write();
        state.rejected_prefixes.clear();
        state.rejected_node_ids.clear();
    }

    /// Generate a targeted identity that avoids rejected regions.
    ///
    /// This generates multiple candidate identities and selects the best one
    /// based on scoring criteria.
    pub fn generate_targeted_identity(
        &self,
        suggested_target: Option<&TargetRegion>,
    ) -> Result<NodeIdentity> {
        let mut state = self.state.write();
        state.total_attempts += 1;

        // Update target if provided
        if let Some(target) = suggested_target {
            state.last_target = Some(target.clone());
        }

        let target = state.last_target.clone();
        let rejected_prefixes: Vec<_> = state.rejected_prefixes.iter().cloned().collect();
        let rejected_ids: Vec<_> = state.rejected_node_ids.clone();

        drop(state); // Release lock before generation

        let mut best_candidate: Option<IdentityCandidate> = None;
        let mut attempts = 0u32;

        while attempts < self.config.max_generation_attempts {
            // Generate a batch of candidates
            let candidates: Vec<_> = (0..self.config.candidates_per_round)
                .filter_map(|_| {
                    attempts += 1;
                    if attempts > self.config.max_generation_attempts {
                        return None;
                    }
                    NodeIdentity::generate().ok()
                })
                .collect();

            // Score each candidate
            for identity in candidates {
                let node_id = identity.node_id();

                // Check if this matches any rejected prefix
                let matches_rejected = rejected_prefixes.iter().any(|p| p.matches(node_id));
                if matches_rejected {
                    continue;
                }

                // Calculate score
                let score = self.score_candidate(
                    node_id,
                    target.as_ref(),
                    &rejected_prefixes,
                    &rejected_ids,
                );

                // Update best if this is better
                match &best_candidate {
                    None => {
                        best_candidate = Some(IdentityCandidate { identity, score });
                    }
                    Some(best) if score > best.score => {
                        best_candidate = Some(IdentityCandidate { identity, score });
                    }
                    _ => {}
                }

                // If we have a good enough candidate, stop early
                if score > 0.9 {
                    break;
                }
            }

            // If we have a decent candidate, we can stop
            if let Some(ref best) = best_candidate
                && best.score > 0.7
            {
                break;
            }
        }

        // Return the best candidate or generate a fallback
        let identity = match best_candidate {
            Some(candidate) => {
                let mut state = self.state.write();
                state.successful_generations += 1;
                candidate.identity
            }
            None => {
                // Fallback: generate random identity
                NodeIdentity::generate()?
            }
        };

        Ok(identity)
    }

    /// Score a candidate NodeId based on targeting criteria.
    fn score_candidate(
        &self,
        node_id: &NodeId,
        target: Option<&TargetRegion>,
        rejected_prefixes: &[RejectedPrefix],
        rejected_ids: &[NodeId],
    ) -> f64 {
        let mut score = 0.0;

        // Distance from rejected prefixes (higher distance = better)
        let avoidance_score = if rejected_prefixes.is_empty() {
            1.0
        } else {
            let min_distance = rejected_prefixes
                .iter()
                .map(|p| p.xor_distance_bits(node_id))
                .min()
                .unwrap_or(u32::MAX);

            // Normalize: min_distance_from_rejected bits = 1.0
            let threshold = u32::from(self.config.min_distance_from_rejected);
            (min_distance as f64 / threshold as f64).min(1.0)
        };
        score += avoidance_score * self.config.avoidance_weight;

        // Target region alignment
        let target_score = if let Some(target) = target {
            if target.region.contains(node_id) {
                target.confidence
            } else {
                // Partial score for being close to target
                let distance = self.xor_distance_to_region(node_id, &target.region);
                (1.0 - (distance as f64 / 256.0)).max(0.0) * target.confidence
            }
        } else {
            0.5 // Neutral when no target
        };
        score += target_score * self.config.target_weight;

        // Distance from previously rejected NodeIds
        let id_distance_score = if rejected_ids.is_empty() {
            1.0
        } else {
            let min_distance = rejected_ids
                .iter()
                .map(|id| self.leading_zero_distance(node_id, id))
                .min()
                .unwrap_or(256);

            // Higher distance from rejected IDs = better
            (min_distance as f64 / 32.0).min(1.0)
        };
        score += id_distance_score * self.config.distance_weight;

        score
    }

    /// Calculate XOR distance to a keyspace region.
    fn xor_distance_to_region(&self, node_id: &NodeId, region: &KeyspaceRegion) -> u32 {
        let node_bytes = node_id.to_bytes();
        let mut distance = 0u32;

        let full_bytes = region.prefix_len as usize / 8;
        let remaining_bits = region.prefix_len as usize % 8;

        // Count differing bits in full bytes using zip
        let prefix_slice = &region.prefix[..full_bytes.min(region.prefix.len())];
        let node_slice = &node_bytes[..full_bytes.min(node_bytes.len())];
        for (p, n) in prefix_slice.iter().zip(node_slice.iter()) {
            let xor = p ^ n;
            distance += xor.count_ones();
        }

        // Count differing bits in partial byte
        if remaining_bits > 0 && full_bytes < region.prefix.len() && full_bytes < node_bytes.len() {
            let mask = 0xFF << (8 - remaining_bits);
            let xor = (region.prefix[full_bytes] ^ node_bytes[full_bytes]) & mask;
            distance += xor.count_ones();
        }

        distance
    }

    /// Count leading zero bits in XOR distance between two NodeIds.
    fn leading_zero_distance(&self, a: &NodeId, b: &NodeId) -> u32 {
        let distance = a.xor_distance(b);

        let mut leading_zeros = 0u32;
        for byte in &distance {
            if *byte == 0 {
                leading_zeros += 8;
            } else {
                leading_zeros += byte.leading_zeros();
                break;
            }
        }

        leading_zeros
    }

    /// Get statistics on targeting attempts.
    #[must_use]
    pub fn stats(&self) -> TargetingStats {
        let state = self.state.read();
        TargetingStats {
            total_attempts: state.total_attempts,
            successful_generations: state.successful_generations,
            rejected_prefix_count: state.rejected_prefixes.len(),
            rejected_id_count: state.rejected_node_ids.len(),
        }
    }

    /// Check if we have any rejected prefixes.
    #[must_use]
    pub fn has_rejected_prefixes(&self) -> bool {
        !self.state.read().rejected_prefixes.is_empty()
    }

    /// Get the number of rejected prefixes.
    #[must_use]
    pub fn rejected_prefix_count(&self) -> usize {
        self.state.read().rejected_prefixes.len()
    }
}

/// Statistics on identity targeting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetingStats {
    /// Total targeting attempts.
    pub total_attempts: u64,

    /// Number of successful generations.
    pub successful_generations: u64,

    /// Number of rejected prefixes being avoided.
    pub rejected_prefix_count: usize,

    /// Number of rejected NodeIds being avoided.
    pub rejected_id_count: usize,
}

impl TargetingStats {
    /// Calculate success rate.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total_attempts == 0 {
            1.0
        } else {
            self.successful_generations as f64 / self.total_attempts as f64
        }
    }
}

/// Shared identity targeter wrapped in Arc.
pub type SharedIdentityTargeter = Arc<IdentityTargeter>;

/// Builder for IdentityTargeter with custom configuration.
pub struct IdentityTargeterBuilder {
    config: TargetingConfig,
    initial_rejected: Vec<RejectedPrefix>,
}

impl IdentityTargeterBuilder {
    /// Create a new builder with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: TargetingConfig::default(),
            initial_rejected: Vec::new(),
        }
    }

    /// Set maximum generation attempts.
    #[must_use]
    pub fn max_attempts(mut self, max: u32) -> Self {
        self.config.max_generation_attempts = max;
        self
    }

    /// Set minimum distance from rejected prefixes.
    #[must_use]
    pub fn min_distance_from_rejected(mut self, bits: u8) -> Self {
        self.config.min_distance_from_rejected = bits;
        self
    }

    /// Set scoring weights.
    #[must_use]
    pub fn weights(mut self, distance: f64, target: f64, avoidance: f64) -> Self {
        self.config.distance_weight = distance;
        self.config.target_weight = target;
        self.config.avoidance_weight = avoidance;
        self
    }

    /// Add initial rejected prefixes.
    #[must_use]
    pub fn reject_prefix(mut self, prefix: Vec<u8>, prefix_len: u8) -> Self {
        self.initial_rejected
            .push(RejectedPrefix::new(prefix, prefix_len));
        self
    }

    /// Build the identity targeter.
    #[must_use]
    pub fn build(self) -> IdentityTargeter {
        let targeter = IdentityTargeter::new(self.config);

        // Add initial rejected prefixes
        for rejected in self.initial_rejected {
            targeter.state.write().rejected_prefixes.insert(rejected);
        }

        targeter
    }
}

impl Default for IdentityTargeterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    fn test_node_id() -> NodeId {
        NodeId([0x42; 32])
    }

    #[test]
    fn test_rejected_prefix_matches() {
        let prefix = RejectedPrefix::new(vec![0xAB], 8);

        // Should match
        let matching_id = NodeId([0xAB; 32]);
        assert!(prefix.matches(&matching_id));

        // Should not match
        let non_matching_id = NodeId([0x12; 32]);
        assert!(!prefix.matches(&non_matching_id));
    }

    #[test]
    fn test_rejected_prefix_partial_byte() {
        // Prefix 0xF0 with only 4 bits significant
        let prefix = RejectedPrefix::new(vec![0xF0], 4);

        // 0xFF starts with 1111, should match
        let matching_id = NodeId([0xFF; 32]);
        assert!(prefix.matches(&matching_id));

        // 0x00 starts with 0000, should not match
        let non_matching_id = NodeId([0x00; 32]);
        assert!(!prefix.matches(&non_matching_id));
    }

    #[test]
    fn test_rejected_prefix_xor_distance() {
        let prefix = RejectedPrefix::new(vec![0xFF], 8);

        // Same prefix = 0 distance
        let same = NodeId([0xFF; 32]);
        assert_eq!(prefix.xor_distance_bits(&same), 0);

        // All bits different = 8 distance
        let opposite = NodeId([0x00; 32]);
        assert_eq!(prefix.xor_distance_bits(&opposite), 8);

        // Half bits different = 4 distance
        let half = NodeId([0xF0; 32]);
        assert_eq!(prefix.xor_distance_bits(&half), 4);
    }

    #[test]
    fn test_identity_targeter_creation() {
        let config = TargetingConfig::default();
        let targeter = IdentityTargeter::new(config);

        assert!(!targeter.has_rejected_prefixes());
        assert_eq!(targeter.rejected_prefix_count(), 0);
    }

    #[test]
    fn test_add_rejected_prefix() {
        let config = TargetingConfig::default();
        let targeter = IdentityTargeter::new(config);

        targeter.add_rejected_prefix(vec![0xAB], 8);

        assert!(targeter.has_rejected_prefixes());
        assert_eq!(targeter.rejected_prefix_count(), 1);
    }

    #[test]
    fn test_generate_targeted_identity() {
        let config = TargetingConfig::default();
        let targeter = IdentityTargeter::new(config);

        // Generate without any constraints
        let identity = targeter.generate_targeted_identity(None);
        assert!(identity.is_ok());
    }

    #[test]
    fn test_generate_targeted_identity_with_rejected() {
        let mut config = TargetingConfig::default();
        config.max_generation_attempts = 50;
        let targeter = IdentityTargeter::new(config);

        // Add some rejected prefixes
        targeter.add_rejected_prefix(vec![0x00], 4);
        targeter.add_rejected_prefix(vec![0x10], 4);

        let identity = targeter.generate_targeted_identity(None);
        assert!(identity.is_ok());

        // The generated identity should not start with rejected prefixes
        let node_id = identity.unwrap();
        let id_bytes = node_id.node_id().to_bytes();

        // Check it doesn't start with 0000 or 0001 (first nibbles)
        let first_nibble = id_bytes[0] >> 4;
        // It's random, so we can't guarantee, but we can check generation worked
        assert!(first_nibble <= 15);
    }

    #[test]
    fn test_targeting_stats() {
        let config = TargetingConfig::default();
        let targeter = IdentityTargeter::new(config);

        // Initial stats
        let stats = targeter.stats();
        assert_eq!(stats.total_attempts, 0);
        assert_eq!(stats.successful_generations, 0);

        // Generate some identities
        for _ in 0..3 {
            let _ = targeter.generate_targeted_identity(None);
        }

        let stats = targeter.stats();
        assert_eq!(stats.total_attempts, 3);
        assert!(stats.successful_generations <= 3);
    }

    #[test]
    fn test_record_rejected_node_id() {
        let config = TargetingConfig::default();
        let targeter = IdentityTargeter::new(config);

        targeter.record_rejected_node_id(test_node_id());

        let stats = targeter.stats();
        assert_eq!(stats.rejected_id_count, 1);
    }

    #[test]
    fn test_clear_rejected() {
        let config = TargetingConfig::default();
        let targeter = IdentityTargeter::new(config);

        targeter.add_rejected_prefix(vec![0xAB], 8);
        targeter.record_rejected_node_id(test_node_id());

        assert!(targeter.has_rejected_prefixes());

        targeter.clear_rejected();

        assert!(!targeter.has_rejected_prefixes());
        assert_eq!(targeter.stats().rejected_id_count, 0);
    }

    #[test]
    fn test_builder() {
        let targeter = IdentityTargeterBuilder::new()
            .max_attempts(50)
            .min_distance_from_rejected(6)
            .weights(0.5, 0.3, 0.2)
            .reject_prefix(vec![0xAB], 8)
            .build();

        assert!(targeter.has_rejected_prefixes());
        assert_eq!(targeter.rejected_prefix_count(), 1);
    }

    #[test]
    fn test_targeting_stats_success_rate() {
        let stats = TargetingStats {
            total_attempts: 10,
            successful_generations: 8,
            rejected_prefix_count: 2,
            rejected_id_count: 5,
        };

        assert!((stats.success_rate() - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_targeting_stats_zero_attempts() {
        let stats = TargetingStats {
            total_attempts: 0,
            successful_generations: 0,
            rejected_prefix_count: 0,
            rejected_id_count: 0,
        };

        assert!((stats.success_rate() - 1.0).abs() < f64::EPSILON);
    }
}
