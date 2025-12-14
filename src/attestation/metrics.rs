// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Attestation metrics for proof verification timing and statistics.
//!
//! Tracks metrics for:
//! - Proof verification timing (generation, verification, total)
//! - Verification success/failure rates
//! - Enforcement mode transitions
//! - Peer attestation status distribution

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Attestation metrics data structure.
#[derive(Debug, Clone, Default)]
pub struct AttestationMetrics {
    // Verification counters
    /// Total attestation handshakes initiated
    pub handshakes_initiated_total: u64,
    /// Total attestation handshakes completed successfully
    pub handshakes_completed_total: u64,
    /// Total attestation verifications performed
    pub verifications_total: u64,
    /// Successful attestation verifications
    pub verifications_success_total: u64,
    /// Failed attestation verifications (proof invalid)
    pub verifications_failed_total: u64,
    /// Stale attestation proofs rejected
    pub verifications_stale_total: u64,
    /// Binary not allowed rejections
    pub verifications_binary_rejected_total: u64,
    /// ID mismatch rejections
    pub verifications_id_mismatch_total: u64,

    // Timing metrics (in microseconds)
    /// Average proof verification time in microseconds
    pub verification_time_us_avg: u64,
    /// Maximum proof verification time in microseconds
    pub verification_time_us_max: u64,
    /// Minimum proof verification time in microseconds
    pub verification_time_us_min: u64,
    /// Total verification time accumulated
    pub verification_time_us_total: u64,

    // Proof generation metrics
    /// Total proofs generated
    pub proofs_generated_total: u64,
    /// Average proof generation time in microseconds
    pub proof_generation_time_us_avg: u64,
    /// Maximum proof generation time in microseconds
    pub proof_generation_time_us_max: u64,

    // Enforcement mode metrics
    /// Current enforcement mode (0=Off, 1=Soft, 2=Hard)
    pub enforcement_mode_current: u64,
    /// Total enforcement mode changes
    pub enforcement_mode_changes_total: u64,
    /// Connections rejected due to hard enforcement
    pub hard_enforcement_rejections_total: u64,

    // Peer status metrics
    /// Current number of verified peers
    pub verified_peers_current: u64,
    /// Current number of unverified peers
    pub unverified_peers_current: u64,
    /// Current number of failed verification peers
    pub failed_peers_current: u64,

    // Cache metrics
    /// Proof cache hits
    pub cache_hits_total: u64,
    /// Proof cache misses
    pub cache_misses_total: u64,
    /// Current cache size
    pub cache_size_current: u64,
}

/// Thread-safe attestation metrics collector.
pub struct AttestationMetricsCollector {
    // Verification counters
    handshakes_initiated_total: AtomicU64,
    handshakes_completed_total: AtomicU64,
    verifications_total: AtomicU64,
    verifications_success_total: AtomicU64,
    verifications_failed_total: AtomicU64,
    verifications_stale_total: AtomicU64,
    verifications_binary_rejected_total: AtomicU64,
    verifications_id_mismatch_total: AtomicU64,

    // Timing metrics (in microseconds)
    verification_time_us_total: AtomicU64,
    verification_time_us_max: AtomicU64,
    verification_time_us_min: AtomicU64,
    verification_count_for_avg: AtomicU64,

    // Proof generation metrics
    proofs_generated_total: AtomicU64,
    proof_generation_time_us_total: AtomicU64,
    proof_generation_time_us_max: AtomicU64,
    proof_generation_count: AtomicU64,

    // Enforcement mode metrics
    enforcement_mode_current: AtomicU64,
    enforcement_mode_changes_total: AtomicU64,
    hard_enforcement_rejections_total: AtomicU64,

    // Peer status metrics
    verified_peers_current: AtomicU64,
    unverified_peers_current: AtomicU64,
    failed_peers_current: AtomicU64,

    // Cache metrics
    cache_hits_total: AtomicU64,
    cache_misses_total: AtomicU64,
    cache_size_current: AtomicU64,
}

impl AttestationMetricsCollector {
    /// Create a new attestation metrics collector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handshakes_initiated_total: AtomicU64::new(0),
            handshakes_completed_total: AtomicU64::new(0),
            verifications_total: AtomicU64::new(0),
            verifications_success_total: AtomicU64::new(0),
            verifications_failed_total: AtomicU64::new(0),
            verifications_stale_total: AtomicU64::new(0),
            verifications_binary_rejected_total: AtomicU64::new(0),
            verifications_id_mismatch_total: AtomicU64::new(0),
            verification_time_us_total: AtomicU64::new(0),
            verification_time_us_max: AtomicU64::new(0),
            verification_time_us_min: AtomicU64::new(u64::MAX),
            verification_count_for_avg: AtomicU64::new(0),
            proofs_generated_total: AtomicU64::new(0),
            proof_generation_time_us_total: AtomicU64::new(0),
            proof_generation_time_us_max: AtomicU64::new(0),
            proof_generation_count: AtomicU64::new(0),
            enforcement_mode_current: AtomicU64::new(0), // Off by default
            enforcement_mode_changes_total: AtomicU64::new(0),
            hard_enforcement_rejections_total: AtomicU64::new(0),
            verified_peers_current: AtomicU64::new(0),
            unverified_peers_current: AtomicU64::new(0),
            failed_peers_current: AtomicU64::new(0),
            cache_hits_total: AtomicU64::new(0),
            cache_misses_total: AtomicU64::new(0),
            cache_size_current: AtomicU64::new(0),
        }
    }

    /// Record a handshake initiation.
    pub fn record_handshake_initiated(&self) {
        self.handshakes_initiated_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a handshake completion.
    pub fn record_handshake_completed(&self) {
        self.handshakes_completed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a verification attempt with result and timing.
    pub fn record_verification(&self, success: bool, duration_us: u64) {
        self.verifications_total.fetch_add(1, Ordering::Relaxed);
        self.verification_count_for_avg
            .fetch_add(1, Ordering::Relaxed);
        self.verification_time_us_total
            .fetch_add(duration_us, Ordering::Relaxed);

        // Update max
        loop {
            let current_max = self.verification_time_us_max.load(Ordering::Relaxed);
            if duration_us <= current_max {
                break;
            }
            if self
                .verification_time_us_max
                .compare_exchange_weak(
                    current_max,
                    duration_us,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }

        // Update min
        loop {
            let current_min = self.verification_time_us_min.load(Ordering::Relaxed);
            if duration_us >= current_min {
                break;
            }
            if self
                .verification_time_us_min
                .compare_exchange_weak(
                    current_min,
                    duration_us,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }

        if success {
            self.verifications_success_total
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.verifications_failed_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a stale proof rejection.
    pub fn record_stale_proof(&self) {
        self.verifications_stale_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a binary not allowed rejection.
    pub fn record_binary_rejected(&self) {
        self.verifications_binary_rejected_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record an ID mismatch rejection.
    pub fn record_id_mismatch(&self) {
        self.verifications_id_mismatch_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record proof generation with timing.
    pub fn record_proof_generation(&self, duration_us: u64) {
        self.proofs_generated_total.fetch_add(1, Ordering::Relaxed);
        self.proof_generation_count.fetch_add(1, Ordering::Relaxed);
        self.proof_generation_time_us_total
            .fetch_add(duration_us, Ordering::Relaxed);

        // Update max
        loop {
            let current_max = self.proof_generation_time_us_max.load(Ordering::Relaxed);
            if duration_us <= current_max {
                break;
            }
            if self
                .proof_generation_time_us_max
                .compare_exchange_weak(
                    current_max,
                    duration_us,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }
    }

    /// Record an enforcement mode change.
    pub fn record_enforcement_mode_change(&self, new_mode: u64) {
        self.enforcement_mode_current
            .store(new_mode, Ordering::Relaxed);
        self.enforcement_mode_changes_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a hard enforcement rejection.
    pub fn record_hard_enforcement_rejection(&self) {
        self.hard_enforcement_rejections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Update verified peer count.
    pub fn set_verified_peers(&self, count: u64) {
        self.verified_peers_current.store(count, Ordering::Relaxed);
    }

    /// Update unverified peer count.
    pub fn set_unverified_peers(&self, count: u64) {
        self.unverified_peers_current
            .store(count, Ordering::Relaxed);
    }

    /// Update failed peer count.
    pub fn set_failed_peers(&self, count: u64) {
        self.failed_peers_current.store(count, Ordering::Relaxed);
    }

    /// Record a cache hit.
    pub fn record_cache_hit(&self) {
        self.cache_hits_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss.
    pub fn record_cache_miss(&self) {
        self.cache_misses_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Update cache size.
    pub fn set_cache_size(&self, size: u64) {
        self.cache_size_current.store(size, Ordering::Relaxed);
    }

    /// Get current metrics snapshot.
    pub async fn get_metrics(&self) -> AttestationMetrics {
        let verification_count = self.verification_count_for_avg.load(Ordering::Relaxed);
        let verification_time_total = self.verification_time_us_total.load(Ordering::Relaxed);
        let verification_time_avg = if verification_count > 0 {
            verification_time_total / verification_count
        } else {
            0
        };

        let proof_gen_count = self.proof_generation_count.load(Ordering::Relaxed);
        let proof_gen_time_total = self.proof_generation_time_us_total.load(Ordering::Relaxed);
        let proof_gen_time_avg = if proof_gen_count > 0 {
            proof_gen_time_total / proof_gen_count
        } else {
            0
        };

        let verification_time_min = self.verification_time_us_min.load(Ordering::Relaxed);
        let verification_time_min = if verification_time_min == u64::MAX {
            0
        } else {
            verification_time_min
        };

        AttestationMetrics {
            handshakes_initiated_total: self.handshakes_initiated_total.load(Ordering::Relaxed),
            handshakes_completed_total: self.handshakes_completed_total.load(Ordering::Relaxed),
            verifications_total: self.verifications_total.load(Ordering::Relaxed),
            verifications_success_total: self.verifications_success_total.load(Ordering::Relaxed),
            verifications_failed_total: self.verifications_failed_total.load(Ordering::Relaxed),
            verifications_stale_total: self.verifications_stale_total.load(Ordering::Relaxed),
            verifications_binary_rejected_total: self
                .verifications_binary_rejected_total
                .load(Ordering::Relaxed),
            verifications_id_mismatch_total: self
                .verifications_id_mismatch_total
                .load(Ordering::Relaxed),
            verification_time_us_avg: verification_time_avg,
            verification_time_us_max: self.verification_time_us_max.load(Ordering::Relaxed),
            verification_time_us_min: verification_time_min,
            verification_time_us_total: verification_time_total,
            proofs_generated_total: self.proofs_generated_total.load(Ordering::Relaxed),
            proof_generation_time_us_avg: proof_gen_time_avg,
            proof_generation_time_us_max: self.proof_generation_time_us_max.load(Ordering::Relaxed),
            enforcement_mode_current: self.enforcement_mode_current.load(Ordering::Relaxed),
            enforcement_mode_changes_total: self
                .enforcement_mode_changes_total
                .load(Ordering::Relaxed),
            hard_enforcement_rejections_total: self
                .hard_enforcement_rejections_total
                .load(Ordering::Relaxed),
            verified_peers_current: self.verified_peers_current.load(Ordering::Relaxed),
            unverified_peers_current: self.unverified_peers_current.load(Ordering::Relaxed),
            failed_peers_current: self.failed_peers_current.load(Ordering::Relaxed),
            cache_hits_total: self.cache_hits_total.load(Ordering::Relaxed),
            cache_misses_total: self.cache_misses_total.load(Ordering::Relaxed),
            cache_size_current: self.cache_size_current.load(Ordering::Relaxed),
        }
    }
}

impl Default for AttestationMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper for timing verification operations.
pub struct VerificationTimer {
    start: Instant,
}

impl VerificationTimer {
    /// Start a new verification timer.
    #[must_use]
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Get elapsed time in microseconds.
    #[must_use]
    pub fn elapsed_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collector_basic() {
        let collector = AttestationMetricsCollector::new();

        collector.record_handshake_initiated();
        collector.record_handshake_completed();
        collector.record_verification(true, 100);
        collector.record_verification(false, 200);

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.handshakes_initiated_total, 1);
        assert_eq!(metrics.handshakes_completed_total, 1);
        assert_eq!(metrics.verifications_total, 2);
        assert_eq!(metrics.verifications_success_total, 1);
        assert_eq!(metrics.verifications_failed_total, 1);
        assert_eq!(metrics.verification_time_us_avg, 150); // (100 + 200) / 2
        assert_eq!(metrics.verification_time_us_max, 200);
        assert_eq!(metrics.verification_time_us_min, 100);
    }

    #[tokio::test]
    async fn test_verification_timing() {
        let collector = AttestationMetricsCollector::new();

        // Record various timing values
        collector.record_verification(true, 50);
        collector.record_verification(true, 100);
        collector.record_verification(true, 150);
        collector.record_verification(true, 200);

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.verification_time_us_min, 50);
        assert_eq!(metrics.verification_time_us_max, 200);
        assert_eq!(metrics.verification_time_us_avg, 125); // (50+100+150+200)/4
    }

    #[tokio::test]
    async fn test_proof_generation_metrics() {
        let collector = AttestationMetricsCollector::new();

        collector.record_proof_generation(1000);
        collector.record_proof_generation(2000);
        collector.record_proof_generation(3000);

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.proofs_generated_total, 3);
        assert_eq!(metrics.proof_generation_time_us_avg, 2000);
        assert_eq!(metrics.proof_generation_time_us_max, 3000);
    }

    #[tokio::test]
    async fn test_enforcement_mode_changes() {
        let collector = AttestationMetricsCollector::new();

        assert_eq!(collector.get_metrics().await.enforcement_mode_current, 0);

        collector.record_enforcement_mode_change(1); // Soft
        collector.record_enforcement_mode_change(2); // Hard

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.enforcement_mode_current, 2);
        assert_eq!(metrics.enforcement_mode_changes_total, 2);
    }

    #[tokio::test]
    async fn test_cache_metrics() {
        let collector = AttestationMetricsCollector::new();

        collector.record_cache_hit();
        collector.record_cache_hit();
        collector.record_cache_miss();
        collector.set_cache_size(10);

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.cache_hits_total, 2);
        assert_eq!(metrics.cache_misses_total, 1);
        assert_eq!(metrics.cache_size_current, 10);
    }

    #[test]
    fn test_verification_timer() {
        let timer = VerificationTimer::start();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let elapsed = timer.elapsed_us();
        assert!(elapsed >= 1000); // At least 1000 microseconds (1ms)
    }

    #[tokio::test]
    async fn test_rejection_counters() {
        let collector = AttestationMetricsCollector::new();

        collector.record_stale_proof();
        collector.record_stale_proof();
        collector.record_binary_rejected();
        collector.record_id_mismatch();
        collector.record_hard_enforcement_rejection();

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.verifications_stale_total, 2);
        assert_eq!(metrics.verifications_binary_rejected_total, 1);
        assert_eq!(metrics.verifications_id_mismatch_total, 1);
        assert_eq!(metrics.hard_enforcement_rejections_total, 1);
    }

    #[tokio::test]
    async fn test_peer_status_metrics() {
        let collector = AttestationMetricsCollector::new();

        collector.set_verified_peers(10);
        collector.set_unverified_peers(5);
        collector.set_failed_peers(2);

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.verified_peers_current, 10);
        assert_eq!(metrics.unverified_peers_current, 5);
        assert_eq!(metrics.failed_peers_current, 2);
    }
}
