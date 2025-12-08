// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com

//! Trust metrics for EigenTrust reputation and witness validation
//!
//! Tracks metrics for:
//! - EigenTrust scores (min, max, average, distribution)
//! - Witness receipt issuance and verification
//! - Peer interaction tracking
//! - Trust score trends

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Trust metrics data structure
#[derive(Debug, Clone, Default)]
pub struct TrustMetrics {
    // EigenTrust metrics
    /// Average EigenTrust score across all peers
    pub eigentrust_avg: f64,
    /// Minimum EigenTrust score
    pub eigentrust_min: f64,
    /// Maximum EigenTrust score
    pub eigentrust_max: f64,
    /// Total EigenTrust epochs processed
    pub eigentrust_epochs_total: u64,
    /// Number of nodes below trust threshold
    pub low_trust_nodes: u64,

    // Witness validation metrics
    /// Total witness receipts issued
    pub witness_receipts_issued_total: u64,
    /// Total witness receipts verified successfully
    pub witness_receipts_verified_total: u64,
    /// Total witness receipts rejected
    pub witness_receipts_rejected_total: u64,

    // Interaction tracking metrics
    /// Total peer interactions recorded
    pub interactions_recorded_total: u64,
    /// Total positive interactions
    pub positive_interactions_total: u64,
    /// Total negative interactions
    pub negative_interactions_total: u64,

    // Trust distribution (bucket -> count)
    /// Distribution of trust scores across buckets
    pub trust_distribution: HashMap<String, u64>,
}

/// Thread-safe trust metrics collector
pub struct TrustMetricsCollector {
    // EigenTrust scores (stored as millipercent)
    eigentrust_avg: AtomicU64,
    eigentrust_min: AtomicU64,
    eigentrust_max: AtomicU64,
    eigentrust_epochs_total: AtomicU64,
    low_trust_nodes: AtomicU64,

    // Witness metrics
    witness_receipts_issued_total: AtomicU64,
    witness_receipts_verified_total: AtomicU64,
    witness_receipts_rejected_total: AtomicU64,

    // Interaction metrics
    interactions_recorded_total: AtomicU64,
    positive_interactions_total: AtomicU64,
    negative_interactions_total: AtomicU64,

    // Trust distribution
    trust_distribution: Arc<RwLock<HashMap<String, u64>>>,

    // Trust score threshold for "low trust"
    low_trust_threshold: f64,
}

impl TrustMetricsCollector {
    /// Create a new trust metrics collector
    pub fn new() -> Self {
        Self::with_threshold(0.3) // Default low trust threshold at 0.3
    }

    /// Create a new trust metrics collector with custom low trust threshold
    pub fn with_threshold(low_trust_threshold: f64) -> Self {
        Self {
            eigentrust_avg: AtomicU64::new(500), // Default 0.5
            eigentrust_min: AtomicU64::new(0),
            eigentrust_max: AtomicU64::new(1000), // Default 1.0
            eigentrust_epochs_total: AtomicU64::new(0),
            low_trust_nodes: AtomicU64::new(0),
            witness_receipts_issued_total: AtomicU64::new(0),
            witness_receipts_verified_total: AtomicU64::new(0),
            witness_receipts_rejected_total: AtomicU64::new(0),
            interactions_recorded_total: AtomicU64::new(0),
            positive_interactions_total: AtomicU64::new(0),
            negative_interactions_total: AtomicU64::new(0),
            trust_distribution: Arc::new(RwLock::new(Self::initialize_distribution())),
            low_trust_threshold,
        }
    }

    /// Initialize trust distribution buckets
    fn initialize_distribution() -> HashMap<String, u64> {
        let mut dist = HashMap::new();
        dist.insert("0.0-0.2".to_string(), 0);
        dist.insert("0.2-0.4".to_string(), 0);
        dist.insert("0.4-0.6".to_string(), 0);
        dist.insert("0.6-0.8".to_string(), 0);
        dist.insert("0.8-1.0".to_string(), 0);
        dist
    }

    /// Update EigenTrust statistics
    pub async fn update_eigentrust_stats(&self, avg: f64, min: f64, max: f64) {
        self.eigentrust_avg
            .store((avg.clamp(0.0, 1.0) * 1000.0) as u64, Ordering::Relaxed);
        self.eigentrust_min
            .store((min.clamp(0.0, 1.0) * 1000.0) as u64, Ordering::Relaxed);
        self.eigentrust_max
            .store((max.clamp(0.0, 1.0) * 1000.0) as u64, Ordering::Relaxed);
    }

    /// Record an EigenTrust epoch completion
    pub fn record_eigentrust_epoch(&self) {
        self.eigentrust_epochs_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Update low trust node count
    pub fn set_low_trust_nodes(&self, count: u64) {
        self.low_trust_nodes.store(count, Ordering::Relaxed);
    }

    /// Record witness receipt issuance
    pub fn record_witness_receipt_issued(&self) {
        self.witness_receipts_issued_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record witness receipt verification result
    pub fn record_witness_receipt_verification(&self, verified: bool) {
        if verified {
            self.witness_receipts_verified_total
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.witness_receipts_rejected_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a peer interaction
    pub fn record_interaction(&self, positive: bool) {
        self.interactions_recorded_total
            .fetch_add(1, Ordering::Relaxed);
        if positive {
            self.positive_interactions_total
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.negative_interactions_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Update trust distribution from a set of peer scores
    pub async fn update_trust_distribution(&self, scores: &[f64]) {
        let mut dist = self.trust_distribution.write().await;

        // Reset counts
        for count in dist.values_mut() {
            *count = 0;
        }

        // Count low trust nodes and populate distribution
        let mut low_trust_count = 0u64;

        for &score in scores {
            let clamped = score.clamp(0.0, 1.0);

            // Check low trust threshold
            if clamped < self.low_trust_threshold {
                low_trust_count += 1;
            }

            // Bucket the score
            let bucket = if clamped < 0.2 {
                "0.0-0.2"
            } else if clamped < 0.4 {
                "0.2-0.4"
            } else if clamped < 0.6 {
                "0.4-0.6"
            } else if clamped < 0.8 {
                "0.6-0.8"
            } else {
                "0.8-1.0"
            };

            *dist.entry(bucket.to_string()).or_insert(0) += 1;
        }

        self.low_trust_nodes
            .store(low_trust_count, Ordering::Relaxed);

        // Calculate and update statistics
        if !scores.is_empty() {
            let avg = scores.iter().sum::<f64>() / scores.len() as f64;
            let min = scores
                .iter()
                .cloned()
                .fold(f64::INFINITY, |a, b| a.min(b));
            let max = scores
                .iter()
                .cloned()
                .fold(f64::NEG_INFINITY, |a, b| a.max(b));

            self.eigentrust_avg
                .store((avg.clamp(0.0, 1.0) * 1000.0) as u64, Ordering::Relaxed);
            self.eigentrust_min
                .store((min.clamp(0.0, 1.0) * 1000.0) as u64, Ordering::Relaxed);
            self.eigentrust_max
                .store((max.clamp(0.0, 1.0) * 1000.0) as u64, Ordering::Relaxed);
        }
    }

    /// Get current metrics snapshot
    pub async fn get_metrics(&self) -> TrustMetrics {
        let trust_distribution = self.trust_distribution.read().await.clone();

        TrustMetrics {
            eigentrust_avg: self.eigentrust_avg.load(Ordering::Relaxed) as f64 / 1000.0,
            eigentrust_min: self.eigentrust_min.load(Ordering::Relaxed) as f64 / 1000.0,
            eigentrust_max: self.eigentrust_max.load(Ordering::Relaxed) as f64 / 1000.0,
            eigentrust_epochs_total: self.eigentrust_epochs_total.load(Ordering::Relaxed),
            low_trust_nodes: self.low_trust_nodes.load(Ordering::Relaxed),
            witness_receipts_issued_total: self
                .witness_receipts_issued_total
                .load(Ordering::Relaxed),
            witness_receipts_verified_total: self
                .witness_receipts_verified_total
                .load(Ordering::Relaxed),
            witness_receipts_rejected_total: self
                .witness_receipts_rejected_total
                .load(Ordering::Relaxed),
            interactions_recorded_total: self.interactions_recorded_total.load(Ordering::Relaxed),
            positive_interactions_total: self.positive_interactions_total.load(Ordering::Relaxed),
            negative_interactions_total: self.negative_interactions_total.load(Ordering::Relaxed),
            trust_distribution,
        }
    }

    /// Reset all counters and distributions
    pub async fn reset(&self) {
        self.eigentrust_avg.store(500, Ordering::Relaxed);
        self.eigentrust_min.store(0, Ordering::Relaxed);
        self.eigentrust_max.store(1000, Ordering::Relaxed);
        self.eigentrust_epochs_total.store(0, Ordering::Relaxed);
        self.low_trust_nodes.store(0, Ordering::Relaxed);
        self.witness_receipts_issued_total.store(0, Ordering::Relaxed);
        self.witness_receipts_verified_total
            .store(0, Ordering::Relaxed);
        self.witness_receipts_rejected_total
            .store(0, Ordering::Relaxed);
        self.interactions_recorded_total.store(0, Ordering::Relaxed);
        self.positive_interactions_total.store(0, Ordering::Relaxed);
        self.negative_interactions_total.store(0, Ordering::Relaxed);

        let mut dist = self.trust_distribution.write().await;
        *dist = Self::initialize_distribution();
    }
}

impl Default for TrustMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_trust_metrics_creation() {
        let collector = TrustMetricsCollector::new();
        let metrics = collector.get_metrics().await;

        assert!((metrics.eigentrust_avg - 0.5).abs() < 0.01);
        assert!((metrics.eigentrust_min - 0.0).abs() < 0.01);
        assert!((metrics.eigentrust_max - 1.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_eigentrust_stats_update() {
        let collector = TrustMetricsCollector::new();

        collector.update_eigentrust_stats(0.75, 0.2, 0.95).await;

        let metrics = collector.get_metrics().await;
        assert!((metrics.eigentrust_avg - 0.75).abs() < 0.01);
        assert!((metrics.eigentrust_min - 0.2).abs() < 0.01);
        assert!((metrics.eigentrust_max - 0.95).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_eigentrust_epochs() {
        let collector = TrustMetricsCollector::new();

        collector.record_eigentrust_epoch();
        collector.record_eigentrust_epoch();
        collector.record_eigentrust_epoch();

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.eigentrust_epochs_total, 3);
    }

    #[tokio::test]
    async fn test_witness_receipts() {
        let collector = TrustMetricsCollector::new();

        collector.record_witness_receipt_issued();
        collector.record_witness_receipt_issued();
        collector.record_witness_receipt_verification(true);
        collector.record_witness_receipt_verification(false);

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.witness_receipts_issued_total, 2);
        assert_eq!(metrics.witness_receipts_verified_total, 1);
        assert_eq!(metrics.witness_receipts_rejected_total, 1);
    }

    #[tokio::test]
    async fn test_interaction_tracking() {
        let collector = TrustMetricsCollector::new();

        collector.record_interaction(true);
        collector.record_interaction(true);
        collector.record_interaction(false);

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.interactions_recorded_total, 3);
        assert_eq!(metrics.positive_interactions_total, 2);
        assert_eq!(metrics.negative_interactions_total, 1);
    }

    #[tokio::test]
    async fn test_trust_distribution() {
        let collector = TrustMetricsCollector::new();

        let scores = vec![
            0.1, 0.15, // 0.0-0.2 bucket (2)
            0.3, 0.35, 0.38, // 0.2-0.4 bucket (3)
            0.5, // 0.4-0.6 bucket (1)
            0.7, 0.75, // 0.6-0.8 bucket (2)
            0.9, 0.95, // 0.8-1.0 bucket (2)
        ];

        collector.update_trust_distribution(&scores).await;

        let metrics = collector.get_metrics().await;
        assert_eq!(
            metrics.trust_distribution.get("0.0-0.2").copied(),
            Some(2)
        );
        assert_eq!(
            metrics.trust_distribution.get("0.2-0.4").copied(),
            Some(3)
        );
        assert_eq!(
            metrics.trust_distribution.get("0.4-0.6").copied(),
            Some(1)
        );
        assert_eq!(
            metrics.trust_distribution.get("0.6-0.8").copied(),
            Some(2)
        );
        assert_eq!(
            metrics.trust_distribution.get("0.8-1.0").copied(),
            Some(2)
        );
    }

    #[tokio::test]
    async fn test_low_trust_detection() {
        let collector = TrustMetricsCollector::with_threshold(0.3);

        // Scores: 2 below 0.3, 3 above 0.3
        let scores = vec![0.1, 0.25, 0.4, 0.6, 0.8];
        collector.update_trust_distribution(&scores).await;

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.low_trust_nodes, 2);
    }

    #[tokio::test]
    async fn test_stats_from_distribution() {
        let collector = TrustMetricsCollector::new();

        let scores = vec![0.2, 0.4, 0.6, 0.8];
        collector.update_trust_distribution(&scores).await;

        let metrics = collector.get_metrics().await;
        // Average should be 0.5
        assert!((metrics.eigentrust_avg - 0.5).abs() < 0.01);
        // Min should be 0.2
        assert!((metrics.eigentrust_min - 0.2).abs() < 0.01);
        // Max should be 0.8
        assert!((metrics.eigentrust_max - 0.8).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_reset() {
        let collector = TrustMetricsCollector::new();

        collector.update_eigentrust_stats(0.9, 0.5, 0.99).await;
        collector.record_eigentrust_epoch();
        collector.record_witness_receipt_issued();
        collector.record_interaction(true);

        collector.reset().await;

        let metrics = collector.get_metrics().await;
        assert!((metrics.eigentrust_avg - 0.5).abs() < 0.01);
        assert_eq!(metrics.eigentrust_epochs_total, 0);
        assert_eq!(metrics.witness_receipts_issued_total, 0);
        assert_eq!(metrics.interactions_recorded_total, 0);
    }

    #[tokio::test]
    async fn test_empty_distribution() {
        let collector = TrustMetricsCollector::new();

        // Empty scores should not panic
        collector.update_trust_distribution(&[]).await;

        let metrics = collector.get_metrics().await;
        // Should maintain default values
        assert!((metrics.eigentrust_avg - 0.5).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_score_clamping() {
        let collector = TrustMetricsCollector::new();

        // Test clamping with out-of-range values
        collector.update_eigentrust_stats(1.5, -0.5, 2.0).await;

        let metrics = collector.get_metrics().await;
        assert!((metrics.eigentrust_avg - 1.0).abs() < 0.01);
        assert!((metrics.eigentrust_min - 0.0).abs() < 0.01);
        assert!((metrics.eigentrust_max - 1.0).abs() < 0.01);
    }
}
