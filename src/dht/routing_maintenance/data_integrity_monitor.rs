//! Data integrity monitor for continuous health checking
//!
//! Provides:
//! - Periodic attestation challenges to storage nodes
//! - Data health scoring based on replica availability
//! - Automatic repair recommendations for degraded data
//! - Integration with security coordinator for trust-weighted decisions
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime};

use rand::prelude::*;
use rand_chacha::ChaCha8Rng;

use crate::dht::geographic_routing::GeographicRegion;
use crate::dht::{DhtKey, DhtNodeId};

/// Configuration for data integrity monitoring
#[derive(Debug, Clone)]
pub struct DataIntegrityConfig {
    /// Interval between attestation checks
    pub check_interval: Duration,
    /// Minimum healthy replicas required
    pub min_healthy_replicas: usize,
    /// Attestation success threshold (0.0-1.0)
    pub attestation_success_threshold: f64,
    /// Time after which data is considered stale without verification
    pub stale_data_threshold: Duration,
    /// Maximum concurrent attestation challenges
    pub max_concurrent_challenges: usize,
    /// Minimum trust score for storage nodes
    pub min_storage_trust: f64,
}

impl Default for DataIntegrityConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(300), // 5 minutes
            min_healthy_replicas: 3,
            attestation_success_threshold: 0.9,
            stale_data_threshold: Duration::from_secs(3600), // 1 hour
            max_concurrent_challenges: 10,
            min_storage_trust: 0.3,
        }
    }
}

/// Health status for a piece of stored data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataHealthStatus {
    /// All replicas healthy, above minimum threshold
    Healthy,
    /// Some replicas failed but above minimum
    Degraded,
    /// Below minimum replicas, at risk of data loss
    AtRisk,
    /// Critical - immediate action needed
    Critical,
    /// Unknown - no recent verification
    Unknown,
}

impl DataHealthStatus {
    /// Get status from replica counts
    #[must_use]
    pub fn from_counts(valid: usize, expected: usize, min_required: usize) -> Self {
        if valid == 0 {
            DataHealthStatus::Critical
        } else if valid < min_required {
            DataHealthStatus::AtRisk
        } else if valid < expected {
            DataHealthStatus::Degraded
        } else {
            DataHealthStatus::Healthy
        }
    }

    /// Check if repair is needed
    #[must_use]
    pub fn needs_repair(&self) -> bool {
        matches!(
            self,
            DataHealthStatus::Critical | DataHealthStatus::AtRisk | DataHealthStatus::Degraded
        )
    }

    /// Get priority level (0 = highest priority)
    #[must_use]
    pub fn priority(&self) -> u8 {
        match self {
            DataHealthStatus::Critical => 0,
            DataHealthStatus::AtRisk => 1,
            DataHealthStatus::Degraded => 2,
            DataHealthStatus::Unknown => 3,
            DataHealthStatus::Healthy => 4,
        }
    }
}

/// Health score for stored data
#[derive(Debug, Clone)]
pub struct DataHealthScore {
    /// Number of valid (verified) replicas
    pub valid_replicas: usize,
    /// Total expected replicas
    pub expected_replicas: usize,
    /// Number of geographic regions with replicas
    pub geographic_diversity: usize,
    /// Average trust score of storage nodes
    pub average_trust: f64,
    /// Last verification timestamp
    pub last_verified: Option<SystemTime>,
    /// Health status
    pub status: DataHealthStatus,
    /// Health percentage (0.0 - 1.0)
    pub health_percentage: f64,
    /// Attestation success rate
    pub attestation_success_rate: f64,
}

impl Default for DataHealthScore {
    fn default() -> Self {
        Self {
            valid_replicas: 0,
            expected_replicas: 0,
            geographic_diversity: 0,
            average_trust: 0.0,
            last_verified: None,
            status: DataHealthStatus::Unknown,
            health_percentage: 0.0,
            attestation_success_rate: 0.0,
        }
    }
}

impl DataHealthScore {
    /// Create a new health score
    #[must_use]
    pub fn new(valid_replicas: usize, expected_replicas: usize, min_required: usize) -> Self {
        let status = DataHealthStatus::from_counts(valid_replicas, expected_replicas, min_required);
        let health_percentage = if expected_replicas > 0 {
            valid_replicas as f64 / expected_replicas as f64
        } else {
            0.0
        };

        Self {
            valid_replicas,
            expected_replicas,
            status,
            health_percentage,
            last_verified: Some(SystemTime::now()),
            ..Default::default()
        }
    }

    /// Update with attestation result
    pub fn update_attestation(&mut self, successes: usize, total: usize) {
        if total > 0 {
            self.attestation_success_rate = successes as f64 / total as f64;
        }
        self.last_verified = Some(SystemTime::now());
    }

    /// Check if data is stale (no recent verification)
    #[must_use]
    pub fn is_stale(&self, threshold: Duration) -> bool {
        self.last_verified
            .and_then(|t| t.elapsed().ok())
            .is_none_or(|elapsed| elapsed > threshold)
    }
}

/// Record of an attestation challenge result
#[derive(Debug, Clone)]
pub struct AttestationResult {
    /// Node that was challenged
    pub node_id: DhtNodeId,
    /// The data key
    pub key: DhtKey,
    /// Whether the attestation succeeded
    pub success: bool,
    /// Response latency
    pub latency: Duration,
    /// When the attestation was performed
    pub timestamp: Instant,
    /// Failure reason (if any)
    pub failure_reason: Option<String>,
}

/// Tracks failed attestations for a node
#[derive(Debug, Clone, Default)]
pub struct NodeAttestationHistory {
    /// Total successful attestations
    pub successes: u64,
    /// Total failed attestations
    pub failures: u64,
    /// Recent results (for trend analysis)
    pub recent_results: Vec<bool>,
    /// Last attestation time
    pub last_attestation: Option<Instant>,
}

impl NodeAttestationHistory {
    /// Record an attestation result
    pub fn record(&mut self, success: bool) {
        if success {
            self.successes += 1;
        } else {
            self.failures += 1;
        }

        // Keep last 20 results for trend
        if self.recent_results.len() >= 20 {
            self.recent_results.remove(0);
        }
        self.recent_results.push(success);
        self.last_attestation = Some(Instant::now());
    }

    /// Get success rate (0.0-1.0)
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let total = self.successes + self.failures;
        if total == 0 {
            return 1.0; // No failures means perfect (default)
        }
        self.successes as f64 / total as f64
    }

    /// Get recent trend (-1.0 to 1.0, negative means declining)
    #[must_use]
    pub fn recent_trend(&self) -> f64 {
        if self.recent_results.len() < 4 {
            return 0.0; // Not enough data
        }

        let half = self.recent_results.len() / 2;
        let first_half_rate: f64 = self.recent_results[..half]
            .iter()
            .map(|&s| if s { 1.0 } else { 0.0 })
            .sum::<f64>()
            / half as f64;

        let second_half_rate: f64 = self.recent_results[half..]
            .iter()
            .map(|&s| if s { 1.0 } else { 0.0 })
            .sum::<f64>()
            / (self.recent_results.len() - half) as f64;

        second_half_rate - first_half_rate
    }
}

/// Repair recommendation for degraded data
#[derive(Debug, Clone)]
pub struct RepairRecommendation {
    /// Data key needing repair
    pub key: DhtKey,
    /// Current health status
    pub status: DataHealthStatus,
    /// Number of additional replicas needed
    pub replicas_needed: usize,
    /// Nodes that have valid data (can be source)
    pub source_nodes: Vec<DhtNodeId>,
    /// Recommended target nodes for new replicas
    pub target_nodes: Vec<DhtNodeId>,
    /// Priority level
    pub priority: u8,
    /// Estimated repair time
    pub estimated_duration: Duration,
}

/// Candidate node for data repair operations
///
/// Contains information needed to evaluate a node for repair target selection,
/// using trust-weighted random sampling (Efraimidis-Spirakis algorithm).
#[derive(Debug, Clone)]
pub struct RepairNodeCandidate {
    /// Node identifier
    pub node_id: DhtNodeId,
    /// Trust score for this node (0.0-1.0)
    pub trust_score: f64,
    /// Geographic region of the node
    pub region: GeographicRegion,
    /// Available storage capacity in bytes
    pub available_capacity: u64,
    /// Network latency in milliseconds
    pub latency_ms: u32,
}

/// Data integrity monitor
pub struct DataIntegrityMonitor {
    /// Configuration
    config: DataIntegrityConfig,
    /// Health scores per data key
    health_scores: HashMap<DhtKey, DataHealthScore>,
    /// Attestation history per node
    node_history: HashMap<DhtNodeId, NodeAttestationHistory>,
    /// Storage nodes per data key
    storage_map: HashMap<DhtKey, Vec<DhtNodeId>>,
    /// Pending challenges (key -> timestamp)
    pending_challenges: HashMap<DhtKey, Instant>,
    /// Total attestations performed
    total_attestations: u64,
    /// Successful attestations
    successful_attestations: u64,
    /// Last check time
    last_check: Option<Instant>,
    /// Minimum number of distinct geographic regions required for repair selection
    repair_diversity_requirement: usize,
}

impl DataIntegrityMonitor {
    /// Create a new data integrity monitor
    #[must_use]
    pub fn new(config: DataIntegrityConfig) -> Self {
        Self {
            config,
            health_scores: HashMap::new(),
            node_history: HashMap::new(),
            storage_map: HashMap::new(),
            pending_challenges: HashMap::new(),
            total_attestations: 0,
            successful_attestations: 0,
            last_check: None,
            repair_diversity_requirement: 1, // Default: no diversity requirement
        }
    }

    /// Create with default configuration
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DataIntegrityConfig::default())
    }

    /// Track new content storage
    pub fn track_content(&mut self, key: DhtKey, nodes: Vec<DhtNodeId>) {
        self.storage_map.insert(key, nodes);
    }

    /// Register storage nodes for a data key
    pub fn register_storage(
        &mut self,
        key: DhtKey,
        nodes: Vec<DhtNodeId>,
        expected_replicas: usize,
    ) {
        self.storage_map.insert(key.clone(), nodes.clone());

        // Initialize health score
        let score = DataHealthScore::new(
            nodes.len(),
            expected_replicas,
            self.config.min_healthy_replicas,
        );
        self.health_scores.insert(key, score);
    }

    /// Record an attestation result
    pub fn record_attestation_result(&mut self, result: AttestationResult) {
        self.total_attestations += 1;
        if result.success {
            self.successful_attestations += 1;
        }

        // Update node history
        let history = self.node_history.entry(result.node_id.clone()).or_default();
        history.record(result.success);

        // Update health score for this key
        if let Some(score) = self.health_scores.get_mut(&result.key) {
            // Recalculate based on attestation
            if !result.success {
                score.valid_replicas = score.valid_replicas.saturating_sub(1);
                score.status = DataHealthStatus::from_counts(
                    score.valid_replicas,
                    score.expected_replicas,
                    self.config.min_healthy_replicas,
                );
                score.health_percentage = if score.expected_replicas > 0 {
                    score.valid_replicas as f64 / score.expected_replicas as f64
                } else {
                    0.0
                };
            }
        }

        // Clear pending challenge
        self.pending_challenges.remove(&result.key);
    }

    /// Get health score for a data key
    #[must_use]
    pub fn get_health(&self, key: &DhtKey) -> Option<&DataHealthScore> {
        self.health_scores.get(key)
    }

    /// Get overall attestation success rate
    #[must_use]
    pub fn overall_success_rate(&self) -> f64 {
        if self.total_attestations == 0 {
            return 1.0;
        }
        self.successful_attestations as f64 / self.total_attestations as f64
    }

    /// Get node attestation history
    #[must_use]
    pub fn get_node_history(&self, node_id: &DhtNodeId) -> Option<&NodeAttestationHistory> {
        self.node_history.get(node_id)
    }

    /// Check if a check cycle is due
    #[must_use]
    pub fn is_check_due(&self) -> bool {
        self.last_check
            .is_none_or(|t| t.elapsed() >= self.config.check_interval)
    }

    /// Mark check as started
    pub fn mark_check_started(&mut self) {
        self.last_check = Some(Instant::now());
    }

    /// Get keys that need attestation checking
    #[must_use]
    pub fn get_keys_needing_check(&self) -> Vec<DhtKey> {
        let mut keys: Vec<_> = self
            .health_scores
            .iter()
            .filter(|(key, score)| {
                // Not already pending
                !self.pending_challenges.contains_key(*key)
                    // And either stale or degraded
                    && (score.is_stale(self.config.stale_data_threshold)
                        || score.status.needs_repair())
            })
            .map(|(key, score)| (key.clone(), score.status.priority()))
            .collect();

        // Sort by priority (lower = more urgent)
        keys.sort_by_key(|(_, priority)| *priority);

        // Take up to max concurrent
        keys.into_iter()
            .take(
                self.config
                    .max_concurrent_challenges
                    .saturating_sub(self.pending_challenges.len()),
            )
            .map(|(key, _)| key)
            .collect()
    }

    /// Mark a challenge as pending
    pub fn mark_challenge_pending(&mut self, key: DhtKey) {
        self.pending_challenges.insert(key, Instant::now());
    }

    /// Get repair recommendations for degraded data
    #[must_use]
    pub fn get_repair_recommendations(&self) -> Vec<RepairRecommendation> {
        let mut recommendations = Vec::new();

        for (key, score) in &self.health_scores {
            if !score.status.needs_repair() {
                continue;
            }

            let replicas_needed = self
                .config
                .min_healthy_replicas
                .saturating_sub(score.valid_replicas);
            if replicas_needed == 0 {
                continue;
            }

            // Get source nodes (ones that have passed attestation)
            let source_nodes: Vec<_> = self
                .storage_map
                .get(key)
                .map(|nodes| {
                    nodes
                        .iter()
                        .filter(|n| {
                            self.node_history
                                .get(*n)
                                .is_none_or(|h| h.success_rate() >= 0.9)
                        })
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();

            recommendations.push(RepairRecommendation {
                key: key.clone(),
                status: score.status,
                replicas_needed,
                source_nodes,
                target_nodes: Vec::new(), // To be filled by caller
                priority: score.status.priority(),
                estimated_duration: Duration::from_secs(60), // Placeholder
            });
        }

        // Sort by priority
        recommendations.sort_by_key(|r| r.priority);
        recommendations
    }

    /// Get data health metrics summary
    #[must_use]
    pub fn get_metrics_summary(&self) -> DataIntegrityMetrics {
        let total_keys = self.health_scores.len();
        let healthy_keys = self
            .health_scores
            .values()
            .filter(|s| s.status == DataHealthStatus::Healthy)
            .count();
        let degraded_keys = self
            .health_scores
            .values()
            .filter(|s| s.status == DataHealthStatus::Degraded)
            .count();
        let at_risk_keys = self
            .health_scores
            .values()
            .filter(|s| s.status == DataHealthStatus::AtRisk)
            .count();
        let critical_keys = self
            .health_scores
            .values()
            .filter(|s| s.status == DataHealthStatus::Critical)
            .count();

        let avg_replicas: f64 = if total_keys > 0 {
            self.health_scores
                .values()
                .map(|s| s.valid_replicas as f64)
                .sum::<f64>()
                / total_keys as f64
        } else {
            0.0
        };

        DataIntegrityMetrics {
            total_keys,
            healthy_keys,
            degraded_keys,
            at_risk_keys,
            critical_keys,
            average_replicas: avg_replicas,
            attestation_success_rate: self.overall_success_rate(),
            total_attestations: self.total_attestations,
            pending_challenges: self.pending_challenges.len(),
        }
    }

    /// Get nodes with poor attestation performance
    #[must_use]
    pub fn get_underperforming_nodes(&self, threshold: f64) -> Vec<(DhtNodeId, f64)> {
        self.node_history
            .iter()
            .filter(|(_, h)| h.success_rate() < threshold && h.successes + h.failures >= 5)
            .map(|(id, h)| (id.clone(), h.success_rate()))
            .collect()
    }

    /// Remove a data key from monitoring
    pub fn remove_key(&mut self, key: &DhtKey) {
        self.health_scores.remove(key);
        self.storage_map.remove(key);
        self.pending_challenges.remove(key);
    }

    /// Clean up stale pending challenges
    pub fn cleanup_stale_challenges(&mut self, timeout: Duration) {
        let now = Instant::now();
        self.pending_challenges
            .retain(|_, started| now.duration_since(*started) < timeout);
    }

    /// Set the minimum number of distinct geographic regions required for repair node selection
    ///
    /// This improves Byzantine fault tolerance by ensuring repairs are distributed
    /// across multiple regions, preventing single-region failure from affecting all replicas.
    pub fn set_repair_diversity_requirement(&mut self, min_regions: usize) {
        self.repair_diversity_requirement = min_regions;
    }

    /// Select repair nodes using trust-weighted random sampling (Efraimidis-Spirakis algorithm)
    ///
    /// This method selects candidate nodes for data repair operations with:
    /// - Trust-weighted probability proportional to node trust scores
    /// - Exclusion of source nodes (already storing the data)
    /// - Minimum trust threshold filtering
    /// - Optional geographic diversity enforcement
    ///
    /// # Arguments
    /// * `candidates` - Available nodes for repair placement
    /// * `count` - Number of repair nodes to select
    /// * `exclude_nodes` - Node IDs to exclude (e.g., source nodes already storing data)
    /// * `seed` - Random seed for reproducible selection (useful for testing)
    ///
    /// # Algorithm
    /// Uses Efraimidis-Spirakis weighted random sampling:
    /// For each candidate, compute key = random^(1/weight), then select top-k by key.
    /// This provides exact weighted random sampling without replacement.
    #[must_use]
    pub fn select_repair_nodes_seeded(
        &self,
        candidates: &[RepairNodeCandidate],
        count: usize,
        exclude_nodes: &[DhtNodeId],
        seed: u64,
    ) -> Vec<RepairNodeCandidate> {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let min_trust = self.config.min_storage_trust;

        // Filter candidates: exclude specified nodes and those below minimum trust
        let filtered: Vec<&RepairNodeCandidate> = candidates
            .iter()
            .filter(|c| !exclude_nodes.contains(&c.node_id) && c.trust_score >= min_trust)
            .collect();

        if filtered.is_empty() {
            return Vec::new();
        }

        // Apply Efraimidis-Spirakis algorithm: key = random^(1/weight)
        // Higher trust = higher weight = higher key = more likely to be selected
        let mut weighted: Vec<(f64, &RepairNodeCandidate)> = filtered
            .into_iter()
            .map(|c| {
                let weight = c.trust_score.max(0.001); // Avoid division by zero
                let r: f64 = rng.r#gen();
                let key = r.powf(1.0 / weight);
                (key, c)
            })
            .collect();

        // Sort descending by key (higher key = more likely to be selected first)
        weighted.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        // Apply diversity requirement if configured
        if self.repair_diversity_requirement > 1 {
            self.select_with_diversity(weighted, count)
        } else {
            // No diversity requirement - just take top N
            weighted
                .into_iter()
                .take(count)
                .map(|(_, c)| c.clone())
                .collect()
        }
    }

    /// Select candidates while ensuring geographic diversity
    fn select_with_diversity(
        &self,
        weighted_candidates: Vec<(f64, &RepairNodeCandidate)>,
        count: usize,
    ) -> Vec<RepairNodeCandidate> {
        let mut selected = Vec::with_capacity(count);
        let mut regions_covered: HashSet<GeographicRegion> = HashSet::new();
        let mut remaining: Vec<_> = weighted_candidates;

        // Phase 1: Select to achieve minimum diversity
        while selected.len() < count && !remaining.is_empty() {
            // Find first candidate from a new region if we haven't met diversity requirement
            let needs_diversity = regions_covered.len() < self.repair_diversity_requirement;

            let idx = if needs_diversity {
                remaining
                    .iter()
                    .position(|(_, c)| !regions_covered.contains(&c.region))
            } else {
                Some(0) // Take the highest weighted remaining candidate
            };

            match idx {
                Some(i) => {
                    let (_, candidate) = remaining.remove(i);
                    regions_covered.insert(candidate.region);
                    selected.push(candidate.clone());
                }
                None => {
                    // Can't find a new region, fall back to highest weighted
                    let (_, candidate) = remaining.remove(0);
                    regions_covered.insert(candidate.region);
                    selected.push(candidate.clone());
                }
            }
        }

        selected
    }
}

/// Summary metrics for data integrity
#[derive(Debug, Clone, Default)]
pub struct DataIntegrityMetrics {
    /// Total data keys being monitored
    pub total_keys: usize,
    /// Keys with healthy status
    pub healthy_keys: usize,
    /// Keys with degraded status
    pub degraded_keys: usize,
    /// Keys at risk
    pub at_risk_keys: usize,
    /// Keys in critical status
    pub critical_keys: usize,
    /// Average replica count
    pub average_replicas: f64,
    /// Overall attestation success rate
    pub attestation_success_rate: f64,
    /// Total attestations performed
    pub total_attestations: u64,
    /// Currently pending challenges
    pub pending_challenges: usize,
}

impl DataIntegrityMetrics {
    /// Get health ratio (healthy / total)
    #[must_use]
    pub fn health_ratio(&self) -> f64 {
        if self.total_keys == 0 {
            return 1.0;
        }
        self.healthy_keys as f64 / self.total_keys as f64
    }

    /// Check if system is healthy (above threshold)
    #[must_use]
    pub fn is_healthy(&self, threshold: f64) -> bool {
        self.health_ratio() >= threshold && self.critical_keys == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key() -> DhtKey {
        DhtKey::random()
    }

    fn random_node_id() -> DhtNodeId {
        DhtNodeId::random()
    }

    #[test]
    fn test_data_health_status_from_counts() {
        assert_eq!(
            DataHealthStatus::from_counts(8, 8, 3),
            DataHealthStatus::Healthy
        );
        assert_eq!(
            DataHealthStatus::from_counts(5, 8, 3),
            DataHealthStatus::Degraded
        );
        assert_eq!(
            DataHealthStatus::from_counts(2, 8, 3),
            DataHealthStatus::AtRisk
        );
        assert_eq!(
            DataHealthStatus::from_counts(0, 8, 3),
            DataHealthStatus::Critical
        );
    }

    #[test]
    fn test_data_health_score_new() {
        let score = DataHealthScore::new(5, 8, 3);
        assert_eq!(score.valid_replicas, 5);
        assert_eq!(score.expected_replicas, 8);
        assert_eq!(score.status, DataHealthStatus::Degraded);
        assert!((score.health_percentage - 0.625).abs() < 0.001);
    }

    #[test]
    fn test_node_attestation_history() {
        let mut history = NodeAttestationHistory::default();

        // Record some results
        for _ in 0..8 {
            history.record(true);
        }
        for _ in 0..2 {
            history.record(false);
        }

        assert_eq!(history.successes, 8);
        assert_eq!(history.failures, 2);
        assert!((history.success_rate() - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_data_integrity_monitor_creation() {
        let monitor = DataIntegrityMonitor::with_defaults();
        assert_eq!(monitor.total_attestations, 0);
        assert!((monitor.overall_success_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_register_storage() {
        let mut monitor = DataIntegrityMonitor::with_defaults();
        let key = random_key();
        let nodes: Vec<_> = (0..5).map(|_| random_node_id()).collect();

        monitor.register_storage(key.clone(), nodes.clone(), 8);

        let health = monitor.get_health(&key);
        assert!(health.is_some());
        assert_eq!(health.unwrap().valid_replicas, 5);
        assert_eq!(health.unwrap().expected_replicas, 8);
    }

    #[test]
    fn test_record_attestation_result() {
        let mut monitor = DataIntegrityMonitor::with_defaults();
        let key = random_key();
        let node = random_node_id();

        monitor.register_storage(key.clone(), vec![node.clone()], 3);

        let result = AttestationResult {
            node_id: node.clone(),
            key: key.clone(),
            success: true,
            latency: Duration::from_millis(50),
            timestamp: Instant::now(),
            failure_reason: None,
        };

        monitor.record_attestation_result(result);

        assert_eq!(monitor.total_attestations, 1);
        assert_eq!(monitor.successful_attestations, 1);

        let history = monitor.get_node_history(&node);
        assert!(history.is_some());
        assert_eq!(history.unwrap().successes, 1);
    }

    #[test]
    fn test_failed_attestation_updates_health() {
        let mut monitor = DataIntegrityMonitor::with_defaults();
        let key = random_key();
        let node = random_node_id();

        monitor.register_storage(key.clone(), vec![node.clone()], 3);

        // Initial state - 1 replica
        assert_eq!(monitor.get_health(&key).unwrap().valid_replicas, 1);

        // Record failure
        let result = AttestationResult {
            node_id: node.clone(),
            key: key.clone(),
            success: false,
            latency: Duration::from_millis(50),
            timestamp: Instant::now(),
            failure_reason: Some("timeout".to_string()),
        };

        monitor.record_attestation_result(result);

        // Now 0 valid replicas
        assert_eq!(monitor.get_health(&key).unwrap().valid_replicas, 0);
        assert_eq!(
            monitor.get_health(&key).unwrap().status,
            DataHealthStatus::Critical
        );
    }

    #[test]
    fn test_repair_recommendations() {
        let mut monitor = DataIntegrityMonitor::new(DataIntegrityConfig {
            min_healthy_replicas: 3,
            ..Default::default()
        });

        // Create degraded data
        let key = random_key();
        let node = random_node_id();

        monitor.register_storage(key.clone(), vec![node.clone()], 8);
        // Manually set to degraded
        if let Some(score) = monitor.health_scores.get_mut(&key) {
            score.valid_replicas = 2;
            score.status = DataHealthStatus::AtRisk;
        }

        let recommendations = monitor.get_repair_recommendations();

        assert!(!recommendations.is_empty());
        assert_eq!(recommendations[0].key, key);
        assert_eq!(recommendations[0].replicas_needed, 1);
    }

    #[test]
    fn test_metrics_summary() {
        let mut monitor = DataIntegrityMonitor::with_defaults();

        // Add some keys with different statuses
        for i in 0..5 {
            let key = random_key();
            let nodes: Vec<_> = (0..(5 - i)).map(|_| random_node_id()).collect();
            monitor.register_storage(key, nodes, 5);
        }

        let metrics = monitor.get_metrics_summary();

        assert_eq!(metrics.total_keys, 5);
        assert!(metrics.healthy_keys > 0);
    }

    #[test]
    fn test_underperforming_nodes() {
        let mut monitor = DataIntegrityMonitor::with_defaults();
        let key = random_key();
        let bad_node = random_node_id();

        monitor.register_storage(key.clone(), vec![bad_node.clone()], 3);

        // Record many failures for the bad node
        for _ in 0..10 {
            let result = AttestationResult {
                node_id: bad_node.clone(),
                key: key.clone(),
                success: false,
                latency: Duration::from_millis(50),
                timestamp: Instant::now(),
                failure_reason: Some("timeout".to_string()),
            };
            monitor.record_attestation_result(result);
        }

        let underperformers = monitor.get_underperforming_nodes(0.5);

        assert!(!underperformers.is_empty());
        assert_eq!(underperformers[0].0, bad_node);
    }

    #[test]
    fn test_is_check_due() {
        let mut monitor = DataIntegrityMonitor::new(DataIntegrityConfig {
            check_interval: Duration::from_millis(10),
            ..Default::default()
        });

        // Initially due
        assert!(monitor.is_check_due());

        // Mark started
        monitor.mark_check_started();

        // Not immediately due
        assert!(!monitor.is_check_due());

        // Wait and check again
        std::thread::sleep(Duration::from_millis(15));
        assert!(monitor.is_check_due());
    }

    #[test]
    fn test_metrics_health_ratio() {
        let metrics = DataIntegrityMetrics {
            total_keys: 100,
            healthy_keys: 95,
            degraded_keys: 4,
            at_risk_keys: 1,
            critical_keys: 0,
            average_replicas: 7.5,
            attestation_success_rate: 0.98,
            total_attestations: 1000,
            pending_challenges: 5,
        };

        assert!((metrics.health_ratio() - 0.95).abs() < 0.001);
        assert!(metrics.is_healthy(0.9));
    }

    // ==================== Trust-Weighted Repair Node Selection Tests (TDD) ====================
    //
    // These tests define the expected behavior for selecting repair nodes with:
    // 1. Trust-weighted random selection (Efraimidis-Spirakis algorithm)
    // 2. Geographic diversity requirements
    // 3. Exclusion of source and failed nodes

    #[test]
    fn test_select_repair_nodes_with_seed_is_reproducible() {
        use crate::dht::geographic_routing::GeographicRegion;

        let monitor = DataIntegrityMonitor::with_defaults();

        let candidates: Vec<_> = (0..10)
            .map(|i| RepairNodeCandidate {
                node_id: random_node_id(),
                trust_score: 0.3 + (i as f64 * 0.05),
                region: match i % 3 {
                    0 => GeographicRegion::Europe,
                    1 => GeographicRegion::NorthAmerica,
                    _ => GeographicRegion::AsiaPacific,
                },
                available_capacity: 1000,
                latency_ms: 50,
            })
            .collect();

        // Same seed should produce same selection
        let selection1 = monitor.select_repair_nodes_seeded(&candidates, 3, &[], 12345);
        let selection2 = monitor.select_repair_nodes_seeded(&candidates, 3, &[], 12345);

        assert_eq!(selection1.len(), 3);
        assert_eq!(
            selection1.iter().map(|n| &n.node_id).collect::<Vec<_>>(),
            selection2.iter().map(|n| &n.node_id).collect::<Vec<_>>(),
            "Same seed should produce identical selection"
        );
    }

    #[test]
    fn test_select_repair_nodes_different_seeds_may_differ() {
        use crate::dht::geographic_routing::GeographicRegion;

        let monitor = DataIntegrityMonitor::with_defaults();

        let candidates: Vec<_> = (0..10)
            .map(|i| RepairNodeCandidate {
                node_id: random_node_id(),
                trust_score: 0.5 + (i as f64 * 0.03),
                region: GeographicRegion::Europe,
                available_capacity: 1000,
                latency_ms: 50,
            })
            .collect();

        let selection_base = monitor.select_repair_nodes_seeded(&candidates, 3, &[], 12345);

        let mut found_different = false;
        for seed in [99999u64, 11111, 77777, 33333] {
            let selection = monitor.select_repair_nodes_seeded(&candidates, 3, &[], seed);
            let ids: Vec<_> = selection.iter().map(|n| &n.node_id).collect();
            let ids_base: Vec<_> = selection_base.iter().map(|n| &n.node_id).collect();
            if ids != ids_base {
                found_different = true;
                break;
            }
        }

        assert!(
            found_different,
            "Different seeds should produce different results"
        );
    }

    #[test]
    fn test_select_repair_nodes_prefers_high_trust() {
        use crate::dht::geographic_routing::GeographicRegion;

        let monitor = DataIntegrityMonitor::with_defaults();

        // Create candidates with very different trust scores
        let high_trust_id = random_node_id();
        let low_trust_id = random_node_id();

        let candidates = vec![
            RepairNodeCandidate {
                node_id: high_trust_id.clone(),
                trust_score: 0.95,
                region: GeographicRegion::Europe,
                available_capacity: 1000,
                latency_ms: 50,
            },
            RepairNodeCandidate {
                node_id: low_trust_id.clone(),
                trust_score: 0.15,
                region: GeographicRegion::Europe,
                available_capacity: 1000,
                latency_ms: 50,
            },
        ];

        let mut high_trust_selected = 0;
        let trials = 100;

        for seed in 0..trials {
            let selection = monitor.select_repair_nodes_seeded(&candidates, 1, &[], seed);
            if selection.iter().any(|n| n.node_id == high_trust_id) {
                high_trust_selected += 1;
            }
        }

        // High trust should be selected much more often
        let high_trust_ratio = high_trust_selected as f64 / trials as f64;
        assert!(
            high_trust_ratio > 0.7,
            "High trust node should be selected more often. Got ratio: {high_trust_ratio}"
        );
    }

    #[test]
    fn test_select_repair_nodes_excludes_source_nodes() {
        use crate::dht::geographic_routing::GeographicRegion;

        let monitor = DataIntegrityMonitor::with_defaults();

        let source_id = random_node_id();
        let other_id = random_node_id();

        let candidates = vec![
            RepairNodeCandidate {
                node_id: source_id.clone(),
                trust_score: 0.99, // Highest trust
                region: GeographicRegion::Europe,
                available_capacity: 1000,
                latency_ms: 50,
            },
            RepairNodeCandidate {
                node_id: other_id.clone(),
                trust_score: 0.5,
                region: GeographicRegion::Europe,
                available_capacity: 1000,
                latency_ms: 50,
            },
        ];

        // Source nodes should be excluded
        for seed in 0..20 {
            let selection =
                monitor.select_repair_nodes_seeded(&candidates, 1, &[source_id.clone()], seed);
            assert!(
                !selection.iter().any(|n| n.node_id == source_id),
                "Source node should be excluded"
            );
        }
    }

    #[test]
    fn test_select_repair_nodes_ensures_geographic_diversity() {
        use crate::dht::geographic_routing::GeographicRegion;

        let mut monitor = DataIntegrityMonitor::new(DataIntegrityConfig {
            min_healthy_replicas: 3,
            ..Default::default()
        });
        monitor.set_repair_diversity_requirement(2); // Require 2 regions

        // All high-trust nodes in Europe, but lower-trust nodes in other regions
        let candidates = vec![
            RepairNodeCandidate {
                node_id: random_node_id(),
                trust_score: 0.95,
                region: GeographicRegion::Europe,
                available_capacity: 1000,
                latency_ms: 50,
            },
            RepairNodeCandidate {
                node_id: random_node_id(),
                trust_score: 0.90,
                region: GeographicRegion::Europe,
                available_capacity: 1000,
                latency_ms: 50,
            },
            RepairNodeCandidate {
                node_id: random_node_id(),
                trust_score: 0.6,
                region: GeographicRegion::NorthAmerica,
                available_capacity: 1000,
                latency_ms: 50,
            },
            RepairNodeCandidate {
                node_id: random_node_id(),
                trust_score: 0.5,
                region: GeographicRegion::AsiaPacific,
                available_capacity: 1000,
                latency_ms: 50,
            },
        ];

        for seed in 0..20 {
            let selection = monitor.select_repair_nodes_seeded(&candidates, 3, &[], seed);

            // Count unique regions
            let regions: std::collections::HashSet<_> =
                selection.iter().map(|n| n.region).collect();

            assert!(
                regions.len() >= 2,
                "Should select nodes from at least 2 regions. Got: {:?}",
                regions
            );
        }
    }

    #[test]
    fn test_select_repair_nodes_respects_minimum_trust() {
        use crate::dht::geographic_routing::GeographicRegion;

        let monitor = DataIntegrityMonitor::new(DataIntegrityConfig {
            min_storage_trust: 0.5,
            ..Default::default()
        });

        let candidates = vec![
            RepairNodeCandidate {
                node_id: random_node_id(),
                trust_score: 0.9,
                region: GeographicRegion::Europe,
                available_capacity: 1000,
                latency_ms: 50,
            },
            RepairNodeCandidate {
                node_id: random_node_id(),
                trust_score: 0.3, // Below minimum
                region: GeographicRegion::Europe,
                available_capacity: 1000,
                latency_ms: 50,
            },
        ];

        for seed in 0..20 {
            let selection = monitor.select_repair_nodes_seeded(&candidates, 2, &[], seed);

            // Low trust node should never be selected
            assert!(
                selection.iter().all(|n| n.trust_score >= 0.5),
                "Nodes below minimum trust should not be selected"
            );
        }
    }

    #[test]
    fn test_select_repair_nodes_returns_empty_when_no_candidates() {
        use crate::dht::geographic_routing::GeographicRegion;

        let monitor = DataIntegrityMonitor::with_defaults();

        // All candidates are excluded
        let node_id = random_node_id();
        let candidates = vec![RepairNodeCandidate {
            node_id: node_id.clone(),
            trust_score: 0.9,
            region: GeographicRegion::Europe,
            available_capacity: 1000,
            latency_ms: 50,
        }];

        let selection = monitor.select_repair_nodes_seeded(&candidates, 1, &[node_id], 12345);
        assert!(
            selection.is_empty(),
            "Should return empty when no valid candidates"
        );
    }

    #[test]
    fn test_select_repair_nodes_statistical_distribution() {
        use crate::dht::geographic_routing::GeographicRegion;

        let monitor = DataIntegrityMonitor::with_defaults();

        // Three candidates with trust ratio roughly 3:2:1
        let id_high = random_node_id();
        let id_medium = random_node_id();
        let id_low = random_node_id();

        let candidates = vec![
            RepairNodeCandidate {
                node_id: id_high.clone(),
                trust_score: 0.6,
                region: GeographicRegion::Europe,
                available_capacity: 1000,
                latency_ms: 50,
            },
            RepairNodeCandidate {
                node_id: id_medium.clone(),
                trust_score: 0.4,
                region: GeographicRegion::Europe,
                available_capacity: 1000,
                latency_ms: 50,
            },
            RepairNodeCandidate {
                node_id: id_low.clone(),
                trust_score: 0.2,
                region: GeographicRegion::Europe,
                available_capacity: 1000,
                latency_ms: 50,
            },
        ];

        let mut counts = std::collections::HashMap::new();
        let trials = 1000;

        for seed in 0..trials {
            let selection = monitor.select_repair_nodes_seeded(&candidates, 1, &[], seed);
            if let Some(winner) = selection.first() {
                *counts.entry(winner.node_id.clone()).or_insert(0) += 1;
            }
        }

        let high_count = *counts.get(&id_high).unwrap_or(&0) as f64;
        let medium_count = *counts.get(&id_medium).unwrap_or(&0) as f64;
        let low_count = *counts.get(&id_low).unwrap_or(&0) as f64;

        // Check relative ordering: high > medium > low
        assert!(
            high_count > medium_count,
            "High trust should be selected more than medium. Got high={high_count}, medium={medium_count}"
        );
        assert!(
            medium_count > low_count,
            "Medium trust should be selected more than low. Got medium={medium_count}, low={low_count}"
        );
    }
}
