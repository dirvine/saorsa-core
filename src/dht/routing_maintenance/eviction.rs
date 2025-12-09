//! Reputation-based node eviction
//!
//! Manages eviction decisions based on:
//! - Consecutive communication failures
//! - Low trust scores (EigenTrust integration)
//! - Failed data attestation challenges
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use std::collections::HashMap;

use crate::dht::DhtNodeId;

use super::config::MaintenanceConfig;
use super::liveness::NodeLivenessState;

/// Reasons why a node might be evicted
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvictionReason {
    /// Too many consecutive communication failures
    ConsecutiveFailures(u32),
    /// Trust score fell below minimum threshold
    LowTrust(String), // String representation of f64 for Eq
    /// Failed data attestation challenge
    FailedAttestation,
    /// Close group consensus: node is no longer valid
    CloseGroupRejection,
    /// Node is stale (no activity for too long)
    Stale,
}

/// Manages eviction decisions for nodes
pub struct EvictionManager {
    /// Configuration for eviction thresholds
    config: MaintenanceConfig,
    /// Liveness state for each tracked node
    liveness_states: HashMap<DhtNodeId, NodeLivenessState>,
    /// Trust scores (from EigenTrust integration)
    trust_scores: HashMap<DhtNodeId, f64>,
    /// Nodes that have failed attestation
    failed_attestations: HashMap<DhtNodeId, u32>,
    /// Nodes explicitly marked for eviction with reason
    marked_for_eviction: HashMap<DhtNodeId, EvictionReason>,
}

impl EvictionManager {
    /// Create a new eviction manager
    #[must_use]
    pub fn new(config: MaintenanceConfig) -> Self {
        Self {
            config,
            liveness_states: HashMap::new(),
            trust_scores: HashMap::new(),
            failed_attestations: HashMap::new(),
            marked_for_eviction: HashMap::new(),
        }
    }

    /// Create with pre-populated trust scores
    #[must_use]
    pub fn with_trust(config: MaintenanceConfig, trust_scores: HashMap<DhtNodeId, f64>) -> Self {
        Self {
            config,
            liveness_states: HashMap::new(),
            trust_scores,
            failed_attestations: HashMap::new(),
            marked_for_eviction: HashMap::new(),
        }
    }

    /// Record a communication failure for a node
    pub fn record_failure(&mut self, node_id: &DhtNodeId) {
        let state = self.liveness_states.entry(node_id.clone()).or_default();
        state.record_failure();
    }

    /// Record a successful communication with a node
    pub fn record_success(&mut self, node_id: &DhtNodeId) {
        let state = self.liveness_states.entry(node_id.clone()).or_default();
        state.record_success();
    }

    /// Record an attestation failure
    pub fn record_attestation_failure(&mut self, node_id: &DhtNodeId) {
        *self.failed_attestations.entry(node_id.clone()).or_insert(0) += 1;
    }

    /// Mark a node for eviction with a specific reason
    ///
    /// This is used when a node fails validation during close group
    /// validation or other explicit eviction scenarios.
    pub fn record_eviction(&mut self, node_id: &DhtNodeId, reason: EvictionReason) {
        self.marked_for_eviction.insert(node_id.clone(), reason);
    }

    /// Reset attestation failures (e.g., after successful attestation)
    pub fn reset_attestation_failures(&mut self, node_id: &DhtNodeId) {
        self.failed_attestations.remove(node_id);
    }

    /// Update trust score for a node
    pub fn update_trust_score(&mut self, node_id: &DhtNodeId, score: f64) {
        self.trust_scores.insert(node_id.clone(), score);
    }

    /// Get trust score for a node
    ///
    /// Returns the cached EigenTrust score for a node, or None if unknown.
    /// This cache is populated by the EigenTrust engine via `update_trust_score()`.
    #[must_use]
    pub fn get_trust_score(&self, node_id: &DhtNodeId) -> Option<f64> {
        self.trust_scores.get(node_id).copied()
    }

    /// Get consecutive failure count for a node
    #[must_use]
    pub fn get_consecutive_failures(&self, node_id: &DhtNodeId) -> u32 {
        self.liveness_states
            .get(node_id)
            .map(|s| s.consecutive_failures)
            .unwrap_or(0)
    }

    /// Check if a node should be evicted based on failures
    #[must_use]
    pub fn should_evict(&self, node_id: &DhtNodeId) -> bool {
        self.liveness_states
            .get(node_id)
            .map(|s| s.should_evict(&self.config))
            .unwrap_or(false)
    }

    /// Check if a node should be evicted due to low trust
    #[must_use]
    pub fn should_evict_for_trust(&self, node_id: &DhtNodeId) -> bool {
        self.trust_scores
            .get(node_id)
            .map(|&score| score < self.config.min_trust_threshold)
            .unwrap_or(false) // No score means we can't evict for trust
    }

    /// Check if a node has too many attestation failures
    #[must_use]
    pub fn has_attestation_failures(&self, node_id: &DhtNodeId) -> bool {
        // More than one attestation failure is suspicious
        self.failed_attestations
            .get(node_id)
            .map(|&count| count > 1)
            .unwrap_or(false)
    }

    /// Get the eviction reason if any
    #[must_use]
    pub fn get_eviction_reason(&self, node_id: &DhtNodeId) -> Option<EvictionReason> {
        // Check explicitly marked nodes first (highest priority)
        if let Some(reason) = self.marked_for_eviction.get(node_id) {
            return Some(reason.clone());
        }

        // Check consecutive failures (most common)
        if let Some(state) = self
            .liveness_states
            .get(node_id)
            .filter(|s| s.should_evict(&self.config))
        {
            return Some(EvictionReason::ConsecutiveFailures(
                state.consecutive_failures,
            ));
        }

        // Check trust score
        if let Some(&score) = self
            .trust_scores
            .get(node_id)
            .filter(|&&s| s < self.config.min_trust_threshold)
        {
            return Some(EvictionReason::LowTrust(format!("{:.4}", score)));
        }

        // Check attestation failures
        if self.has_attestation_failures(node_id) {
            return Some(EvictionReason::FailedAttestation);
        }

        None
    }

    /// Get list of all nodes that should be evicted
    #[must_use]
    pub fn get_eviction_candidates(&self) -> Vec<(DhtNodeId, EvictionReason)> {
        let mut candidates = Vec::new();

        // Check explicitly marked nodes first (highest priority)
        for (node_id, reason) in &self.marked_for_eviction {
            candidates.push((node_id.clone(), reason.clone()));
        }

        // Check all nodes in liveness states
        for node_id in self.liveness_states.keys() {
            // Skip if already marked
            if self.marked_for_eviction.contains_key(node_id) {
                continue;
            }
            if let Some(reason) = self.get_eviction_reason(node_id) {
                candidates.push((node_id.clone(), reason));
            }
        }

        // Also check nodes only in trust scores
        for node_id in self.trust_scores.keys() {
            // Skip if already marked or in liveness states
            if self.marked_for_eviction.contains_key(node_id)
                || self.liveness_states.contains_key(node_id)
            {
                continue;
            }
            if let Some(reason) = self.get_eviction_reason(node_id) {
                candidates.push((node_id.clone(), reason));
            }
        }

        candidates
    }

    /// Remove a node from tracking (after eviction)
    pub fn remove_node(&mut self, node_id: &DhtNodeId) {
        self.liveness_states.remove(node_id);
        self.trust_scores.remove(node_id);
        self.failed_attestations.remove(node_id);
        self.marked_for_eviction.remove(node_id);
    }

    /// Get liveness state for a node
    #[must_use]
    pub fn get_liveness_state(&self, node_id: &DhtNodeId) -> Option<&NodeLivenessState> {
        self.liveness_states.get(node_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_id() -> DhtNodeId {
        DhtNodeId::random()
    }

    #[test]
    fn test_evict_after_consecutive_failures() {
        let config = MaintenanceConfig {
            max_consecutive_failures: 3,
            ..Default::default()
        };
        let mut manager = EvictionManager::new(config);

        let node_id = make_node_id();
        manager.record_failure(&node_id);
        manager.record_failure(&node_id);
        assert!(!manager.should_evict(&node_id));

        manager.record_failure(&node_id);
        assert!(manager.should_evict(&node_id));
    }

    #[test]
    fn test_evict_for_low_trust() {
        let config = MaintenanceConfig {
            min_trust_threshold: 0.15,
            ..Default::default()
        };
        let node_id = make_node_id();
        let mut trust_scores = HashMap::new();
        trust_scores.insert(node_id.clone(), 0.10); // Below threshold

        let manager = EvictionManager::with_trust(config, trust_scores);
        assert!(manager.should_evict_for_trust(&node_id));
    }

    #[test]
    fn test_no_evict_for_good_trust() {
        let config = MaintenanceConfig {
            min_trust_threshold: 0.15,
            ..Default::default()
        };
        let node_id = make_node_id();
        let mut trust_scores = HashMap::new();
        trust_scores.insert(node_id.clone(), 0.50); // Above threshold

        let manager = EvictionManager::with_trust(config, trust_scores);
        assert!(!manager.should_evict_for_trust(&node_id));
    }

    #[test]
    fn test_success_resets_failure_count() {
        let config = MaintenanceConfig::default();
        let mut manager = EvictionManager::new(config);

        let node_id = make_node_id();
        manager.record_failure(&node_id);
        manager.record_failure(&node_id);
        manager.record_success(&node_id);

        assert_eq!(manager.get_consecutive_failures(&node_id), 0);
    }

    #[test]
    fn test_eviction_reason_consecutive_failures() {
        let config = MaintenanceConfig {
            max_consecutive_failures: 3,
            ..Default::default()
        };
        let mut manager = EvictionManager::new(config);

        let node_id = make_node_id();
        for _ in 0..3 {
            manager.record_failure(&node_id);
        }

        let reason = manager.get_eviction_reason(&node_id);
        assert!(matches!(
            reason,
            Some(EvictionReason::ConsecutiveFailures(3))
        ));
    }

    #[test]
    fn test_eviction_reason_low_trust() {
        let config = MaintenanceConfig {
            min_trust_threshold: 0.15,
            max_consecutive_failures: 10, // High so it doesn't trigger
            ..Default::default()
        };
        let node_id = make_node_id();
        let mut trust_scores = HashMap::new();
        trust_scores.insert(node_id.clone(), 0.05);

        let manager = EvictionManager::with_trust(config, trust_scores);
        let reason = manager.get_eviction_reason(&node_id);
        assert!(matches!(reason, Some(EvictionReason::LowTrust(_))));
    }

    #[test]
    fn test_attestation_failure_tracking() {
        let config = MaintenanceConfig::default();
        let mut manager = EvictionManager::new(config);

        let node_id = make_node_id();
        assert!(!manager.has_attestation_failures(&node_id));

        manager.record_attestation_failure(&node_id);
        assert!(!manager.has_attestation_failures(&node_id)); // Only 1

        manager.record_attestation_failure(&node_id);
        assert!(manager.has_attestation_failures(&node_id)); // Now 2
    }

    #[test]
    fn test_reset_attestation_failures() {
        let config = MaintenanceConfig::default();
        let mut manager = EvictionManager::new(config);

        let node_id = make_node_id();
        manager.record_attestation_failure(&node_id);
        manager.record_attestation_failure(&node_id);
        assert!(manager.has_attestation_failures(&node_id));

        manager.reset_attestation_failures(&node_id);
        assert!(!manager.has_attestation_failures(&node_id));
    }

    #[test]
    fn test_get_eviction_candidates() {
        let config = MaintenanceConfig {
            max_consecutive_failures: 3,
            min_trust_threshold: 0.15,
            ..Default::default()
        };
        let mut manager = EvictionManager::new(config);

        let failing_node = make_node_id();
        for _ in 0..3 {
            manager.record_failure(&failing_node);
        }

        let low_trust_node = make_node_id();
        manager.update_trust_score(&low_trust_node, 0.05);

        let good_node = make_node_id();
        manager.record_success(&good_node);
        manager.update_trust_score(&good_node, 0.90);

        let candidates = manager.get_eviction_candidates();
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn test_remove_node() {
        let config = MaintenanceConfig::default();
        let mut manager = EvictionManager::new(config);

        let node_id = make_node_id();
        manager.record_failure(&node_id);
        manager.update_trust_score(&node_id, 0.5);
        manager.record_attestation_failure(&node_id);

        manager.remove_node(&node_id);

        assert_eq!(manager.get_consecutive_failures(&node_id), 0);
        assert!(manager.get_liveness_state(&node_id).is_none());
        assert!(!manager.should_evict_for_trust(&node_id));
        assert!(!manager.has_attestation_failures(&node_id));
    }

    #[test]
    fn test_update_trust_score() {
        let config = MaintenanceConfig {
            min_trust_threshold: 0.15,
            ..Default::default()
        };
        let mut manager = EvictionManager::new(config);

        let node_id = make_node_id();

        // Initially no eviction (no score)
        assert!(!manager.should_evict_for_trust(&node_id));

        // Low trust triggers eviction
        manager.update_trust_score(&node_id, 0.05);
        assert!(manager.should_evict_for_trust(&node_id));

        // Updating to good trust removes eviction
        manager.update_trust_score(&node_id, 0.50);
        assert!(!manager.should_evict_for_trust(&node_id));
    }
}
