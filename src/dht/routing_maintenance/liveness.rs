//! Node liveness tracking and eviction logic
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use std::time::Instant;

use super::config::MaintenanceConfig;

/// Tracks liveness state for a single node
#[derive(Debug, Clone)]
pub struct NodeLivenessState {
    /// Last time we successfully communicated with this node
    pub last_seen: Instant,
    /// Number of consecutive failed communication attempts
    pub consecutive_failures: u32,
    /// Total successful communications
    pub total_successes: u64,
    /// Total failed communications
    pub total_failures: u64,
}

impl Default for NodeLivenessState {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeLivenessState {
    /// Create a new liveness state for a node
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_seen: Instant::now(),
            consecutive_failures: 0,
            total_successes: 0,
            total_failures: 0,
        }
    }

    /// Record a failed communication attempt
    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        self.total_failures += 1;
    }

    /// Record a successful communication
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.total_successes += 1;
        self.last_seen = Instant::now();
    }

    /// Check if this node should be evicted based on consecutive failures
    #[must_use]
    pub fn should_evict(&self, config: &MaintenanceConfig) -> bool {
        self.consecutive_failures >= config.max_consecutive_failures
    }

    /// Get the success rate (0.0-1.0)
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let total = self.total_successes + self.total_failures;
        if total == 0 {
            1.0 // No data yet, assume good
        } else {
            self.total_successes as f64 / total as f64
        }
    }

    /// Check if the node is considered stale (no recent activity)
    #[must_use]
    pub fn is_stale(&self, max_age: std::time::Duration) -> bool {
        self.last_seen.elapsed() > max_age
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_liveness_state_new() {
        let state = NodeLivenessState::new();
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.total_successes, 0);
        assert_eq!(state.total_failures, 0);
    }

    #[test]
    fn test_liveness_state_tracks_failures() {
        let mut state = NodeLivenessState::new();
        state.record_failure();
        state.record_failure();
        assert_eq!(state.consecutive_failures, 2);
        assert_eq!(state.total_failures, 2);
    }

    #[test]
    fn test_liveness_state_resets_on_success() {
        let mut state = NodeLivenessState::new();
        state.record_failure();
        state.record_failure();
        assert_eq!(state.consecutive_failures, 2);

        state.record_success();
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.total_successes, 1);
        assert_eq!(state.total_failures, 2); // Total failures unchanged
    }

    #[test]
    fn test_should_evict_after_max_failures() {
        let config = MaintenanceConfig {
            max_consecutive_failures: 3,
            ..Default::default()
        };
        let mut state = NodeLivenessState::new();

        // Not enough failures yet
        state.record_failure();
        state.record_failure();
        assert!(!state.should_evict(&config));

        // Now at threshold
        state.record_failure();
        assert!(state.should_evict(&config));
    }

    #[test]
    fn test_success_rate_calculation() {
        let mut state = NodeLivenessState::new();

        // No data yet - assume good
        assert!((state.success_rate() - 1.0).abs() < f64::EPSILON);

        // 50% success rate
        state.record_success();
        state.record_failure();
        assert!((state.success_rate() - 0.5).abs() < f64::EPSILON);

        // 2/3 success rate
        state.record_success();
        let expected = 2.0 / 3.0;
        assert!((state.success_rate() - expected).abs() < 0.01);
    }

    #[test]
    fn test_success_resets_consecutive_but_not_total() {
        let config = MaintenanceConfig::default();
        let mut state = NodeLivenessState::new();

        // Build up failures
        for _ in 0..2 {
            state.record_failure();
        }
        assert_eq!(state.consecutive_failures, 2);
        assert!(!state.should_evict(&config));

        // Success resets consecutive
        state.record_success();
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.total_failures, 2); // Still tracked

        // Can fail again without immediate eviction
        state.record_failure();
        assert!(!state.should_evict(&config));
    }

    #[test]
    fn test_is_stale() {
        let state = NodeLivenessState::new();
        // Just created, should not be stale
        assert!(!state.is_stale(Duration::from_secs(60)));

        // Would be stale if we set max_age to 0
        assert!(state.is_stale(Duration::from_nanos(0)));
    }
}
