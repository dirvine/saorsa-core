// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com

//! Security metrics for DHT attack detection and prevention
//!
//! Tracks metrics for:
//! - Eclipse attack detection and scoring
//! - Sybil attack detection
//! - Witness collusion detection
//! - Routing manipulation attempts
//! - BFT mode escalation
//! - Sibling broadcast validation
//! - Close group consensus

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::RwLock;

/// Security metrics data structure
#[derive(Debug, Clone, Default)]
pub struct SecurityMetrics {
    // Attack risk scores (0.0 - 1.0)
    /// Current eclipse attack risk score
    pub eclipse_score: f64,
    /// Current Sybil attack risk score
    pub sybil_score: f64,
    /// Current collusion risk score
    pub collusion_score: f64,
    /// Routing manipulation risk score
    pub routing_manipulation_score: f64,

    // Attack event counters
    /// Total eclipse attack attempts detected
    pub eclipse_attempts_total: u64,
    /// Total Sybil nodes detected
    pub sybil_nodes_detected_total: u64,
    /// Total collusion groups detected
    pub collusion_groups_detected_total: u64,

    // BFT mode metrics
    /// Whether BFT consensus mode is currently active
    pub bft_mode_active: bool,
    /// Total number of BFT mode escalations
    pub bft_escalations_total: u64,

    // Sibling broadcast metrics
    /// Total sibling broadcasts validated successfully
    pub sibling_broadcasts_validated_total: u64,
    /// Total sibling broadcasts rejected
    pub sibling_broadcasts_rejected_total: u64,
    /// Average sibling list overlap ratio
    pub sibling_overlap_ratio: f64,

    // Close group validation metrics
    /// Total close group validations performed
    pub close_group_validations_total: u64,
    /// Total close group consensus failures
    pub close_group_consensus_failures_total: u64,

    // Witness validation metrics
    /// Total witness validations performed
    pub witness_validations_total: u64,
    /// Total witness validation failures
    pub witness_failures_total: u64,

    // Node eviction metrics
    /// Total nodes evicted from routing table
    pub nodes_evicted_total: u64,
    /// Evictions broken down by reason
    pub eviction_by_reason: HashMap<String, u64>,

    // Churn metrics
    /// Node churn rate over 5 minutes (percentage)
    pub churn_rate_5m: f64,
    /// Total high churn alerts triggered
    pub high_churn_alerts_total: u64,

    // Diversity enforcement metrics
    /// Total nodes rejected due to IP diversity limits
    pub ip_diversity_rejections_total: u64,
    /// Total nodes rejected due to geographic diversity limits
    pub geographic_diversity_rejections_total: u64,
    /// Node counts per geographic region
    pub nodes_per_region: HashMap<String, u64>,
}

/// Thread-safe security metrics collector
pub struct SecurityMetricsCollector {
    // Attack scores (stored as millipercent for atomic operations)
    eclipse_score: AtomicU64,
    sybil_score: AtomicU64,
    collusion_score: AtomicU64,
    routing_manipulation_score: AtomicU64,

    // Event counters
    eclipse_attempts_total: AtomicU64,
    sybil_nodes_detected_total: AtomicU64,
    collusion_groups_detected_total: AtomicU64,

    // BFT mode
    bft_mode_active: AtomicBool,
    bft_escalations_total: AtomicU64,

    // Sibling broadcast
    sibling_broadcasts_validated_total: AtomicU64,
    sibling_broadcasts_rejected_total: AtomicU64,
    sibling_overlap_ratio: AtomicU64,

    // Close group validation
    close_group_validations_total: AtomicU64,
    close_group_consensus_failures_total: AtomicU64,

    // Witness validation
    witness_validations_total: AtomicU64,
    witness_failures_total: AtomicU64,

    // Node eviction
    nodes_evicted_total: AtomicU64,
    eviction_by_reason: Arc<RwLock<HashMap<String, u64>>>,

    // Churn metrics
    churn_rate_5m: AtomicU64,
    high_churn_alerts_total: AtomicU64,

    // Diversity enforcement
    ip_diversity_rejections_total: AtomicU64,
    geographic_diversity_rejections_total: AtomicU64,
    nodes_per_region: Arc<RwLock<HashMap<String, u64>>>,
}

impl SecurityMetricsCollector {
    /// Create a new security metrics collector
    pub fn new() -> Self {
        Self {
            eclipse_score: AtomicU64::new(0),
            sybil_score: AtomicU64::new(0),
            collusion_score: AtomicU64::new(0),
            routing_manipulation_score: AtomicU64::new(0),
            eclipse_attempts_total: AtomicU64::new(0),
            sybil_nodes_detected_total: AtomicU64::new(0),
            collusion_groups_detected_total: AtomicU64::new(0),
            bft_mode_active: AtomicBool::new(false),
            bft_escalations_total: AtomicU64::new(0),
            sibling_broadcasts_validated_total: AtomicU64::new(0),
            sibling_broadcasts_rejected_total: AtomicU64::new(0),
            sibling_overlap_ratio: AtomicU64::new(1000), // Default 1.0 (stored as millipercent)
            close_group_validations_total: AtomicU64::new(0),
            close_group_consensus_failures_total: AtomicU64::new(0),
            witness_validations_total: AtomicU64::new(0),
            witness_failures_total: AtomicU64::new(0),
            nodes_evicted_total: AtomicU64::new(0),
            eviction_by_reason: Arc::new(RwLock::new(HashMap::new())),
            churn_rate_5m: AtomicU64::new(0),
            high_churn_alerts_total: AtomicU64::new(0),
            ip_diversity_rejections_total: AtomicU64::new(0),
            geographic_diversity_rejections_total: AtomicU64::new(0),
            nodes_per_region: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Update eclipse attack score (0.0 - 1.0)
    pub fn set_eclipse_score(&self, score: f64) {
        let millipercent = (score.clamp(0.0, 1.0) * 1000.0) as u64;
        self.eclipse_score.store(millipercent, Ordering::Relaxed);
    }

    /// Update Sybil attack score (0.0 - 1.0)
    pub fn set_sybil_score(&self, score: f64) {
        let millipercent = (score.clamp(0.0, 1.0) * 1000.0) as u64;
        self.sybil_score.store(millipercent, Ordering::Relaxed);
    }

    /// Update collusion score (0.0 - 1.0)
    pub fn set_collusion_score(&self, score: f64) {
        let millipercent = (score.clamp(0.0, 1.0) * 1000.0) as u64;
        self.collusion_score.store(millipercent, Ordering::Relaxed);
    }

    /// Update routing manipulation score (0.0 - 1.0)
    pub fn set_routing_manipulation_score(&self, score: f64) {
        let millipercent = (score.clamp(0.0, 1.0) * 1000.0) as u64;
        self.routing_manipulation_score
            .store(millipercent, Ordering::Relaxed);
    }

    /// Record an eclipse attack attempt
    pub fn record_eclipse_attempt(&self) {
        self.eclipse_attempts_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record detected Sybil nodes
    pub fn record_sybil_detection(&self, count: u64) {
        self.sybil_nodes_detected_total
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Record detected collusion group
    pub fn record_collusion_detection(&self) {
        self.collusion_groups_detected_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Set BFT mode status
    pub fn set_bft_mode(&self, active: bool) {
        let was_active = self.bft_mode_active.swap(active, Ordering::Relaxed);
        if active && !was_active {
            // Escalation occurred
            self.bft_escalations_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record sibling broadcast validation result
    pub fn record_sibling_broadcast(&self, validated: bool) {
        if validated {
            self.sibling_broadcasts_validated_total
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.sibling_broadcasts_rejected_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Update sibling overlap ratio (0.0 - 1.0)
    pub fn set_sibling_overlap_ratio(&self, ratio: f64) {
        let millipercent = (ratio.clamp(0.0, 1.0) * 1000.0) as u64;
        self.sibling_overlap_ratio
            .store(millipercent, Ordering::Relaxed);
    }

    /// Record close group validation result
    pub fn record_close_group_validation(&self, success: bool) {
        self.close_group_validations_total
            .fetch_add(1, Ordering::Relaxed);
        if !success {
            self.close_group_consensus_failures_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record witness validation result
    pub fn record_witness_validation(&self, success: bool) {
        self.witness_validations_total
            .fetch_add(1, Ordering::Relaxed);
        if !success {
            self.witness_failures_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record node eviction
    pub async fn record_eviction(&self, reason: &str) {
        self.nodes_evicted_total.fetch_add(1, Ordering::Relaxed);
        let mut reasons = self.eviction_by_reason.write().await;
        *reasons.entry(reason.to_string()).or_insert(0) += 1;
    }

    /// Update churn rate (0.0 - 1.0)
    pub fn set_churn_rate(&self, rate: f64) {
        let millipercent = (rate.clamp(0.0, 1.0) * 1000.0) as u64;
        self.churn_rate_5m.store(millipercent, Ordering::Relaxed);

        // Check for high churn threshold (30%)
        if rate > 0.3 {
            self.high_churn_alerts_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a node rejection due to IP diversity limits
    pub fn record_ip_diversity_rejection(&self) {
        self.ip_diversity_rejections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a node rejection due to geographic diversity limits
    pub fn record_geographic_diversity_rejection(&self) {
        self.geographic_diversity_rejections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Update node count for a geographic region
    pub async fn set_region_node_count(&self, region: &str, count: u64) {
        let mut regions = self.nodes_per_region.write().await;
        regions.insert(region.to_string(), count);
    }

    /// Increment node count for a geographic region
    pub async fn increment_region_node_count(&self, region: &str) {
        let mut regions = self.nodes_per_region.write().await;
        *regions.entry(region.to_string()).or_insert(0) += 1;
    }

    /// Decrement node count for a geographic region
    pub async fn decrement_region_node_count(&self, region: &str) {
        let mut regions = self.nodes_per_region.write().await;
        if let Some(count) = regions.get_mut(region) {
            *count = count.saturating_sub(1);
        }
    }

    /// Get current metrics snapshot
    pub async fn get_metrics(&self) -> SecurityMetrics {
        let eviction_by_reason = self.eviction_by_reason.read().await.clone();
        let nodes_per_region = self.nodes_per_region.read().await.clone();

        SecurityMetrics {
            eclipse_score: self.eclipse_score.load(Ordering::Relaxed) as f64 / 1000.0,
            sybil_score: self.sybil_score.load(Ordering::Relaxed) as f64 / 1000.0,
            collusion_score: self.collusion_score.load(Ordering::Relaxed) as f64 / 1000.0,
            routing_manipulation_score: self.routing_manipulation_score.load(Ordering::Relaxed)
                as f64
                / 1000.0,
            eclipse_attempts_total: self.eclipse_attempts_total.load(Ordering::Relaxed),
            sybil_nodes_detected_total: self.sybil_nodes_detected_total.load(Ordering::Relaxed),
            collusion_groups_detected_total: self
                .collusion_groups_detected_total
                .load(Ordering::Relaxed),
            bft_mode_active: self.bft_mode_active.load(Ordering::Relaxed),
            bft_escalations_total: self.bft_escalations_total.load(Ordering::Relaxed),
            sibling_broadcasts_validated_total: self
                .sibling_broadcasts_validated_total
                .load(Ordering::Relaxed),
            sibling_broadcasts_rejected_total: self
                .sibling_broadcasts_rejected_total
                .load(Ordering::Relaxed),
            sibling_overlap_ratio: self.sibling_overlap_ratio.load(Ordering::Relaxed) as f64
                / 1000.0,
            close_group_validations_total: self
                .close_group_validations_total
                .load(Ordering::Relaxed),
            close_group_consensus_failures_total: self
                .close_group_consensus_failures_total
                .load(Ordering::Relaxed),
            witness_validations_total: self.witness_validations_total.load(Ordering::Relaxed),
            witness_failures_total: self.witness_failures_total.load(Ordering::Relaxed),
            nodes_evicted_total: self.nodes_evicted_total.load(Ordering::Relaxed),
            eviction_by_reason,
            churn_rate_5m: self.churn_rate_5m.load(Ordering::Relaxed) as f64 / 1000.0,
            high_churn_alerts_total: self.high_churn_alerts_total.load(Ordering::Relaxed),
            ip_diversity_rejections_total: self
                .ip_diversity_rejections_total
                .load(Ordering::Relaxed),
            geographic_diversity_rejections_total: self
                .geographic_diversity_rejections_total
                .load(Ordering::Relaxed),
            nodes_per_region,
        }
    }

    /// Reset all counters (useful for testing)
    pub async fn reset(&self) {
        self.eclipse_score.store(0, Ordering::Relaxed);
        self.sybil_score.store(0, Ordering::Relaxed);
        self.collusion_score.store(0, Ordering::Relaxed);
        self.routing_manipulation_score.store(0, Ordering::Relaxed);
        self.eclipse_attempts_total.store(0, Ordering::Relaxed);
        self.sybil_nodes_detected_total.store(0, Ordering::Relaxed);
        self.collusion_groups_detected_total
            .store(0, Ordering::Relaxed);
        self.bft_mode_active.store(false, Ordering::Relaxed);
        self.bft_escalations_total.store(0, Ordering::Relaxed);
        self.sibling_broadcasts_validated_total
            .store(0, Ordering::Relaxed);
        self.sibling_broadcasts_rejected_total
            .store(0, Ordering::Relaxed);
        self.sibling_overlap_ratio.store(1000, Ordering::Relaxed);
        self.close_group_validations_total
            .store(0, Ordering::Relaxed);
        self.close_group_consensus_failures_total
            .store(0, Ordering::Relaxed);
        self.witness_validations_total.store(0, Ordering::Relaxed);
        self.witness_failures_total.store(0, Ordering::Relaxed);
        self.nodes_evicted_total.store(0, Ordering::Relaxed);
        self.eviction_by_reason.write().await.clear();
        self.churn_rate_5m.store(0, Ordering::Relaxed);
        self.high_churn_alerts_total.store(0, Ordering::Relaxed);
        self.ip_diversity_rejections_total
            .store(0, Ordering::Relaxed);
        self.geographic_diversity_rejections_total
            .store(0, Ordering::Relaxed);
        self.nodes_per_region.write().await.clear();
    }
}

impl Default for SecurityMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_metrics_creation() {
        let collector = SecurityMetricsCollector::new();
        let metrics = collector.get_metrics().await;

        assert_eq!(metrics.eclipse_score, 0.0);
        assert_eq!(metrics.sybil_score, 0.0);
        assert!(!metrics.bft_mode_active);
    }

    #[tokio::test]
    async fn test_attack_score_updates() {
        let collector = SecurityMetricsCollector::new();

        collector.set_eclipse_score(0.75);
        collector.set_sybil_score(0.5);
        collector.set_collusion_score(0.25);

        let metrics = collector.get_metrics().await;
        assert!((metrics.eclipse_score - 0.75).abs() < 0.01);
        assert!((metrics.sybil_score - 0.5).abs() < 0.01);
        assert!((metrics.collusion_score - 0.25).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_bft_escalation() {
        let collector = SecurityMetricsCollector::new();

        // First escalation
        collector.set_bft_mode(true);
        let metrics = collector.get_metrics().await;
        assert!(metrics.bft_mode_active);
        assert_eq!(metrics.bft_escalations_total, 1);

        // De-escalate
        collector.set_bft_mode(false);
        let metrics = collector.get_metrics().await;
        assert!(!metrics.bft_mode_active);
        assert_eq!(metrics.bft_escalations_total, 1);

        // Second escalation
        collector.set_bft_mode(true);
        let metrics = collector.get_metrics().await;
        assert!(metrics.bft_mode_active);
        assert_eq!(metrics.bft_escalations_total, 2);
    }

    #[tokio::test]
    async fn test_sibling_broadcast_tracking() {
        let collector = SecurityMetricsCollector::new();

        collector.record_sibling_broadcast(true);
        collector.record_sibling_broadcast(true);
        collector.record_sibling_broadcast(false);

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.sibling_broadcasts_validated_total, 2);
        assert_eq!(metrics.sibling_broadcasts_rejected_total, 1);
    }

    #[tokio::test]
    async fn test_eviction_tracking() {
        let collector = SecurityMetricsCollector::new();

        collector.record_eviction("liveness_failure").await;
        collector.record_eviction("liveness_failure").await;
        collector.record_eviction("sybil_detected").await;

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.nodes_evicted_total, 3);
        assert_eq!(
            metrics.eviction_by_reason.get("liveness_failure").copied(),
            Some(2)
        );
        assert_eq!(
            metrics.eviction_by_reason.get("sybil_detected").copied(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn test_churn_rate_alerts() {
        let collector = SecurityMetricsCollector::new();

        // Below threshold
        collector.set_churn_rate(0.2);
        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.high_churn_alerts_total, 0);

        // Above threshold (30%)
        collector.set_churn_rate(0.35);
        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.high_churn_alerts_total, 1);

        // Another high churn
        collector.set_churn_rate(0.5);
        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.high_churn_alerts_total, 2);
    }

    #[tokio::test]
    async fn test_close_group_validation() {
        let collector = SecurityMetricsCollector::new();

        collector.record_close_group_validation(true);
        collector.record_close_group_validation(true);
        collector.record_close_group_validation(false);

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.close_group_validations_total, 3);
        assert_eq!(metrics.close_group_consensus_failures_total, 1);
    }

    #[tokio::test]
    async fn test_witness_validation() {
        let collector = SecurityMetricsCollector::new();

        collector.record_witness_validation(true);
        collector.record_witness_validation(false);
        collector.record_witness_validation(true);

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.witness_validations_total, 3);
        assert_eq!(metrics.witness_failures_total, 1);
    }

    #[tokio::test]
    async fn test_reset() {
        let collector = SecurityMetricsCollector::new();

        collector.set_eclipse_score(0.9);
        collector.record_eclipse_attempt();
        collector.record_eviction("test").await;

        collector.reset().await;

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.eclipse_score, 0.0);
        assert_eq!(metrics.eclipse_attempts_total, 0);
        assert_eq!(metrics.nodes_evicted_total, 0);
        assert!(metrics.eviction_by_reason.is_empty());
    }

    #[tokio::test]
    async fn test_score_clamping() {
        let collector = SecurityMetricsCollector::new();

        // Test upper bound clamping
        collector.set_eclipse_score(1.5);
        let metrics = collector.get_metrics().await;
        assert!((metrics.eclipse_score - 1.0).abs() < 0.01);

        // Test lower bound clamping
        collector.set_sybil_score(-0.5);
        let metrics = collector.get_metrics().await;
        assert!((metrics.sybil_score - 0.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_diversity_metrics() {
        let collector = SecurityMetricsCollector::new();

        // Test IP diversity rejection tracking
        collector.record_ip_diversity_rejection();
        collector.record_ip_diversity_rejection();

        // Test geographic diversity rejection tracking
        collector.record_geographic_diversity_rejection();
        collector.record_geographic_diversity_rejection();
        collector.record_geographic_diversity_rejection();

        // Test region node count tracking
        collector.increment_region_node_count("NorthAmerica").await;
        collector.increment_region_node_count("NorthAmerica").await;
        collector.increment_region_node_count("Europe").await;
        collector.set_region_node_count("AsiaPacific", 5).await;

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.ip_diversity_rejections_total, 2);
        assert_eq!(metrics.geographic_diversity_rejections_total, 3);
        assert_eq!(
            metrics.nodes_per_region.get("NorthAmerica").copied(),
            Some(2)
        );
        assert_eq!(metrics.nodes_per_region.get("Europe").copied(), Some(1));
        assert_eq!(
            metrics.nodes_per_region.get("AsiaPacific").copied(),
            Some(5)
        );

        // Test decrement
        collector.decrement_region_node_count("NorthAmerica").await;
        let metrics = collector.get_metrics().await;
        assert_eq!(
            metrics.nodes_per_region.get("NorthAmerica").copied(),
            Some(1)
        );
    }
}
