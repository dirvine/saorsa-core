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

//! Identity regeneration trigger with loop prevention.
//!
//! This module provides the decision logic for when to regenerate a node's identity,
//! with sophisticated loop prevention mechanisms to avoid infinite regeneration cycles.
//!
//! # Loop Prevention
//!
//! The system uses multiple strategies to prevent regeneration loops:
//! - **Exponential Backoff**: Increasing delays between attempts (60s base, 1 hour max)
//! - **Maximum Attempts**: Hard limit of 10 consecutive regeneration attempts
//! - **Circuit Breaker**: Blocks regeneration after persistent failures
//! - **Rejection Tracking**: Avoids regenerating to similar rejected regions
//!
//! # Example
//!
//! ```ignore
//! use saorsa_core::identity::regeneration::{RegenerationTrigger, RegenerationConfig};
//!
//! let config = RegenerationConfig::default();
//! let trigger = RegenerationTrigger::new(config);
//!
//! let decision = trigger.should_regenerate(&rejection_info).await;
//! match decision {
//!     RegenerationDecision::Proceed { urgency, target } => {
//!         // Perform regeneration
//!     }
//!     RegenerationDecision::Wait { remaining } => {
//!         // Wait before retrying
//!     }
//!     RegenerationDecision::Blocked { reason } => {
//!         // Cannot regenerate
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use super::fitness::{FitnessMetrics, FitnessVerdict};
use super::node_identity::NodeId;
use super::rejection::{RejectionHistory, RejectionInfo, RejectionReason, TargetRegion};

/// Configuration for regeneration trigger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegenerationConfig {
    /// Base delay for exponential backoff (default: 60 seconds).
    pub base_delay: Duration,

    /// Maximum delay for exponential backoff (default: 1 hour).
    pub max_delay: Duration,

    /// Maximum consecutive regeneration attempts (default: 10).
    pub max_consecutive_attempts: u32,

    /// Time window for counting consecutive attempts (default: 1 hour).
    pub attempt_window: Duration,

    /// Circuit breaker threshold - failures before tripping (default: 5).
    pub circuit_breaker_threshold: u32,

    /// Circuit breaker reset time (default: 30 minutes).
    pub circuit_breaker_reset: Duration,

    /// Jitter factor for backoff delays (0.0 to 1.0, default: 0.2).
    pub jitter_factor: f64,

    /// Whether to track and avoid rejected NodeId prefixes.
    pub track_rejected_prefixes: bool,

    /// Number of prefix bits to track for rejection avoidance.
    pub rejection_prefix_bits: u8,
}

impl Default for RegenerationConfig {
    fn default() -> Self {
        Self {
            base_delay: Duration::from_secs(60),
            max_delay: Duration::from_secs(3600), // 1 hour
            max_consecutive_attempts: 10,
            attempt_window: Duration::from_secs(3600), // 1 hour
            circuit_breaker_threshold: 5,
            circuit_breaker_reset: Duration::from_secs(1800), // 30 minutes
            jitter_factor: 0.2,
            track_rejected_prefixes: true,
            rejection_prefix_bits: 8,
        }
    }
}

/// How urgent a regeneration is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegenerationUrgency {
    /// Low urgency - can wait for optimal conditions.
    Low,

    /// Medium urgency - should regenerate when convenient.
    Medium,

    /// High urgency - regenerate soon.
    High,

    /// Critical urgency - regenerate immediately.
    Critical,
}

impl RegenerationUrgency {
    /// Convert from fitness verdict.
    #[must_use]
    pub fn from_fitness(verdict: FitnessVerdict) -> Option<Self> {
        match verdict {
            FitnessVerdict::Healthy => None,
            FitnessVerdict::Marginal => Some(Self::Low),
            FitnessVerdict::Unfit => Some(Self::Medium),
            FitnessVerdict::Critical => Some(Self::Critical),
        }
    }

    /// Get numeric priority (0-3).
    #[must_use]
    pub fn priority(&self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Critical => 3,
        }
    }
}

impl fmt::Display for RegenerationUrgency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Reason why regeneration is blocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockReason {
    /// Maximum consecutive attempts reached.
    MaxAttemptsReached {
        /// Number of attempts made.
        attempts: u32,
        /// Maximum allowed.
        max: u32,
    },

    /// Diversity constraint prevents regeneration from helping.
    DiversityConstraint {
        /// The specific constraint.
        constraint: RejectionReason,
    },

    /// Node is blocklisted - regeneration won't help.
    Blocklisted,

    /// Circuit breaker is open due to persistent failures.
    CircuitBreakerOpen {
        /// Seconds until the circuit breaker will reset.
        resets_in_secs: u64,
    },

    /// Backoff period not yet elapsed.
    BackoffActive {
        /// Time remaining in backoff.
        remaining: Duration,
    },

    /// Manual regeneration is disabled.
    ManuallyDisabled,
}

impl fmt::Display for BlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaxAttemptsReached { attempts, max } => {
                write!(f, "max attempts reached ({}/{})", attempts, max)
            }
            Self::DiversityConstraint { constraint } => {
                write!(f, "diversity constraint: {}", constraint)
            }
            Self::Blocklisted => write!(f, "node is blocklisted"),
            Self::CircuitBreakerOpen { .. } => write!(f, "circuit breaker open"),
            Self::BackoffActive { remaining } => {
                write!(
                    f,
                    "backoff active ({:.0}s remaining)",
                    remaining.as_secs_f64()
                )
            }
            Self::ManuallyDisabled => write!(f, "regeneration manually disabled"),
        }
    }
}

/// Decision on whether to regenerate identity.
#[derive(Debug, Clone)]
pub enum RegenerationDecision {
    /// Proceed with regeneration.
    Proceed {
        /// How urgent the regeneration is.
        urgency: RegenerationUrgency,
        /// Suggested target region (if available).
        target: Option<TargetRegion>,
    },

    /// Wait before attempting regeneration.
    Wait {
        /// How long to wait.
        remaining: Duration,
    },

    /// Regeneration is recommended but not required.
    Recommend {
        /// Reason for recommendation.
        reason: String,
        /// Suggested target region.
        target: Option<TargetRegion>,
    },

    /// Regeneration is blocked.
    Blocked {
        /// Why regeneration is blocked.
        reason: BlockReason,
    },

    /// No regeneration needed.
    NotNeeded,
}

impl RegenerationDecision {
    /// Check if regeneration should proceed.
    #[must_use]
    pub fn should_proceed(&self) -> bool {
        matches!(self, Self::Proceed { .. })
    }

    /// Check if decision indicates waiting.
    #[must_use]
    pub fn should_wait(&self) -> bool {
        matches!(self, Self::Wait { .. })
    }

    /// Check if regeneration is blocked.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }
}

/// Record of a regeneration attempt.
#[derive(Debug, Clone)]
pub struct RegenerationAttempt {
    /// When the attempt was made (not serializable).
    pub timestamp: Instant,

    /// The old NodeId (before regeneration).
    pub old_node_id: NodeId,

    /// The new NodeId (after regeneration).
    pub new_node_id: Option<NodeId>,

    /// Whether the attempt succeeded (node accepted).
    pub succeeded: bool,

    /// Reason for regeneration.
    pub reason: RegenerationReason,
}

impl RegenerationAttempt {
    /// Create a new regeneration attempt record.
    #[must_use]
    pub fn new(old_id: NodeId, reason: RegenerationReason) -> Self {
        Self {
            timestamp: Instant::now(),
            old_node_id: old_id,
            new_node_id: None,
            succeeded: false,
            reason,
        }
    }

    /// Mark the attempt as completed.
    pub fn complete(&mut self, new_id: NodeId, succeeded: bool) {
        self.new_node_id = Some(new_id);
        self.succeeded = succeeded;
    }
}

/// Reason for triggering regeneration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegenerationReason {
    /// Network rejection.
    Rejection(RejectionReason),

    /// Proactive fitness detection.
    FitnessCheck(FitnessVerdict),

    /// Manual request by user/admin.
    Manual,

    /// Scheduled maintenance.
    Scheduled,
}

impl fmt::Display for RegenerationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejection(r) => write!(f, "rejection: {}", r),
            Self::FitnessCheck(v) => write!(f, "fitness: {}", v),
            Self::Manual => write!(f, "manual request"),
            Self::Scheduled => write!(f, "scheduled"),
        }
    }
}

/// State of the circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitState {
    /// Circuit is closed - normal operation.
    Closed,

    /// Circuit is open - blocking regeneration.
    Open {
        /// When the circuit was opened.
        opened_at: Instant,
    },

    /// Circuit is half-open - testing if regeneration works.
    /// Reserved for future use in gradual recovery strategy.
    #[allow(dead_code)]
    HalfOpen,
}

/// Internal state for the regeneration trigger.
struct TriggerState {
    /// History of regeneration attempts.
    attempts: Vec<RegenerationAttempt>,

    /// Rejected NodeId prefixes to avoid.
    rejected_prefixes: HashSet<Vec<u8>>,

    /// Circuit breaker state.
    circuit_state: CircuitState,

    /// Consecutive failures since last success.
    consecutive_failures: u32,

    /// Last successful regeneration time.
    last_success: Option<Instant>,

    /// Time of last regeneration attempt.
    last_attempt: Option<Instant>,

    /// Current backoff delay.
    current_backoff: Duration,

    /// Whether regeneration is manually disabled.
    disabled: bool,
}

impl Default for TriggerState {
    fn default() -> Self {
        Self {
            attempts: Vec::new(),
            rejected_prefixes: HashSet::new(),
            circuit_state: CircuitState::Closed,
            consecutive_failures: 0,
            last_success: None,
            last_attempt: None,
            current_backoff: Duration::ZERO,
            disabled: false,
        }
    }
}

/// Regeneration trigger with loop prevention.
pub struct RegenerationTrigger {
    /// Configuration.
    config: RegenerationConfig,

    /// Internal state.
    state: RwLock<TriggerState>,

    /// Rejection history.
    rejection_history: RwLock<RejectionHistory>,
}

impl RegenerationTrigger {
    /// Create a new regeneration trigger.
    #[must_use]
    pub fn new(config: RegenerationConfig) -> Self {
        Self {
            config,
            state: RwLock::new(TriggerState::default()),
            rejection_history: RwLock::new(RejectionHistory::new()),
        }
    }

    /// Evaluate whether to regenerate based on rejection info.
    pub fn evaluate_rejection(&self, rejection: &RejectionInfo) -> RegenerationDecision {
        // Record the rejection
        self.rejection_history.write().record(rejection.clone());

        // Check if blocklisted first (special case)
        if rejection.reason == RejectionReason::Blocklisted {
            return RegenerationDecision::Blocked {
                reason: BlockReason::Blocklisted,
            };
        }

        // Check if regeneration can help (diversity constraints)
        if !rejection.reason.regeneration_may_help() {
            return RegenerationDecision::Blocked {
                reason: BlockReason::DiversityConstraint {
                    constraint: rejection.reason,
                },
            };
        }

        // Check for blocking conditions
        if let Some(blocked) = self.check_blocking_conditions() {
            return RegenerationDecision::Blocked { reason: blocked };
        }

        // Check backoff
        if let Some(remaining) = self.check_backoff() {
            return RegenerationDecision::Wait { remaining };
        }

        // Determine urgency based on rejection
        let urgency = match rejection.reason {
            RejectionReason::NodeIdCollision => RegenerationUrgency::Critical,
            RejectionReason::KeyspaceSaturation => RegenerationUrgency::High,
            RejectionReason::CloseGroupFull => RegenerationUrgency::Medium,
            _ => RegenerationUrgency::Low,
        };

        RegenerationDecision::Proceed {
            urgency,
            target: rejection.suggested_target.clone(),
        }
    }

    /// Evaluate whether to regenerate based on fitness metrics.
    pub fn evaluate_fitness(&self, metrics: &FitnessMetrics) -> RegenerationDecision {
        // Only regenerate for fitness if verdict indicates it
        if !metrics.verdict.should_regenerate() {
            return if metrics.verdict.may_benefit_from_regeneration() {
                RegenerationDecision::Recommend {
                    reason: format!("Fitness is {}", metrics.verdict),
                    target: None,
                }
            } else {
                RegenerationDecision::NotNeeded
            };
        }

        // Check blocking conditions
        if let Some(blocked) = self.check_blocking_conditions() {
            return RegenerationDecision::Blocked { reason: blocked };
        }

        // Check backoff
        if let Some(remaining) = self.check_backoff() {
            return RegenerationDecision::Wait { remaining };
        }

        // Determine urgency from fitness verdict
        let urgency = RegenerationUrgency::from_fitness(metrics.verdict)
            .unwrap_or(RegenerationUrgency::Medium);

        RegenerationDecision::Proceed {
            urgency,
            target: None,
        }
    }

    /// Check for conditions that block regeneration.
    fn check_blocking_conditions(&self) -> Option<BlockReason> {
        let state = self.state.read();

        // Check if manually disabled
        if state.disabled {
            return Some(BlockReason::ManuallyDisabled);
        }

        // Check circuit breaker
        if let CircuitState::Open { opened_at } = state.circuit_state {
            let elapsed = opened_at.elapsed();
            if elapsed < self.config.circuit_breaker_reset {
                let remaining = self.config.circuit_breaker_reset - elapsed;
                return Some(BlockReason::CircuitBreakerOpen {
                    resets_in_secs: remaining.as_secs(),
                });
            }
        }

        // Check max attempts
        let recent_attempts = self.count_recent_attempts();
        if recent_attempts >= self.config.max_consecutive_attempts {
            return Some(BlockReason::MaxAttemptsReached {
                attempts: recent_attempts,
                max: self.config.max_consecutive_attempts,
            });
        }

        None
    }

    /// Check if backoff period is active.
    fn check_backoff(&self) -> Option<Duration> {
        let state = self.state.read();

        if let Some(last) = state.last_attempt {
            let elapsed = last.elapsed();
            if elapsed < state.current_backoff {
                return Some(state.current_backoff - elapsed);
            }
        }

        None
    }

    /// Count recent regeneration attempts within the attempt window.
    fn count_recent_attempts(&self) -> u32 {
        let state = self.state.read();
        let cutoff = Instant::now()
            .checked_sub(self.config.attempt_window)
            .unwrap_or_else(Instant::now);

        state
            .attempts
            .iter()
            .filter(|a| a.timestamp >= cutoff)
            .count() as u32
    }

    /// Record a regeneration attempt.
    pub fn record_attempt(&self, old_id: NodeId, reason: RegenerationReason) {
        let mut state = self.state.write();

        let attempt = RegenerationAttempt::new(old_id, reason);
        state.attempts.push(attempt);

        // Update last attempt time
        state.last_attempt = Some(Instant::now());

        // Increase backoff for next attempt
        state.current_backoff = self.calculate_next_backoff(state.consecutive_failures);
    }

    /// Record the result of a regeneration attempt.
    pub fn record_result(&self, new_id: NodeId, succeeded: bool) {
        let mut state = self.state.write();

        // Update the last attempt
        if let Some(last) = state.attempts.last_mut() {
            last.complete(new_id.clone(), succeeded);
        }

        if succeeded {
            // Reset on success
            state.consecutive_failures = 0;
            state.last_success = Some(Instant::now());
            state.current_backoff = self.config.base_delay;
            state.circuit_state = CircuitState::Closed;
        } else {
            // Track failure
            state.consecutive_failures += 1;

            // Track rejected prefix
            if self.config.track_rejected_prefixes {
                let prefix = self.extract_prefix(&new_id);
                state.rejected_prefixes.insert(prefix);
            }

            // Check if circuit breaker should trip
            if state.consecutive_failures >= self.config.circuit_breaker_threshold {
                state.circuit_state = CircuitState::Open {
                    opened_at: Instant::now(),
                };
            }
        }
    }

    /// Calculate next backoff delay with exponential growth and jitter.
    fn calculate_next_backoff(&self, failures: u32) -> Duration {
        let base_secs = self.config.base_delay.as_secs_f64();
        let max_secs = self.config.max_delay.as_secs_f64();

        // Exponential backoff: base * 2^failures
        let exp_delay = base_secs * (2.0_f64).powi(failures as i32);
        let clamped = exp_delay.min(max_secs);

        // Add jitter
        let jitter_range = clamped * self.config.jitter_factor;
        let jitter = (fastrand::f64() - 0.5) * 2.0 * jitter_range;
        let with_jitter = (clamped + jitter).max(base_secs);

        Duration::from_secs_f64(with_jitter)
    }

    /// Extract prefix bits from a NodeId.
    fn extract_prefix(&self, node_id: &NodeId) -> Vec<u8> {
        let bytes = node_id.to_bytes();
        let full_bytes = self.config.rejection_prefix_bits as usize / 8;
        let remaining_bits = self.config.rejection_prefix_bits as usize % 8;

        let mut prefix = bytes[..full_bytes].to_vec();

        if remaining_bits > 0 && full_bytes < bytes.len() {
            let mask = 0xFF << (8 - remaining_bits);
            prefix.push(bytes[full_bytes] & mask);
        }

        prefix
    }

    /// Check if a NodeId prefix is in the rejected set.
    #[must_use]
    pub fn is_prefix_rejected(&self, node_id: &NodeId) -> bool {
        let prefix = self.extract_prefix(node_id);
        self.state.read().rejected_prefixes.contains(&prefix)
    }

    /// Get rejected prefixes for targeting.
    #[must_use]
    pub fn rejected_prefixes(&self) -> Vec<Vec<u8>> {
        self.state
            .read()
            .rejected_prefixes
            .iter()
            .cloned()
            .collect()
    }

    /// Manually disable regeneration.
    pub fn disable(&self) {
        self.state.write().disabled = true;
    }

    /// Re-enable regeneration.
    pub fn enable(&self) {
        self.state.write().disabled = false;
    }

    /// Check if regeneration is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.state.read().disabled
    }

    /// Reset the trigger state (for testing or recovery).
    pub fn reset(&self) {
        let mut state = self.state.write();
        state.attempts.clear();
        state.rejected_prefixes.clear();
        state.circuit_state = CircuitState::Closed;
        state.consecutive_failures = 0;
        state.last_success = None;
        state.last_attempt = None;
        state.current_backoff = Duration::ZERO;
        state.disabled = false;
    }

    /// Get current consecutive failure count.
    #[must_use]
    pub fn consecutive_failures(&self) -> u32 {
        self.state.read().consecutive_failures
    }

    /// Get current backoff duration.
    #[must_use]
    pub fn current_backoff(&self) -> Duration {
        self.state.read().current_backoff
    }

    /// Check if circuit breaker is open.
    #[must_use]
    pub fn is_circuit_open(&self) -> bool {
        matches!(self.state.read().circuit_state, CircuitState::Open { .. })
    }

    /// Get number of regeneration attempts.
    #[must_use]
    pub fn attempt_count(&self) -> usize {
        self.state.read().attempts.len()
    }
}

/// Shared regeneration trigger wrapped in Arc.
pub type SharedRegenerationTrigger = Arc<RegenerationTrigger>;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id() -> NodeId {
        NodeId([0x42; 32])
    }

    fn test_rejection(reason: RejectionReason) -> RejectionInfo {
        RejectionInfo::new(reason)
    }

    #[test]
    fn test_regeneration_urgency_from_fitness() {
        assert_eq!(
            RegenerationUrgency::from_fitness(FitnessVerdict::Healthy),
            None
        );
        assert_eq!(
            RegenerationUrgency::from_fitness(FitnessVerdict::Marginal),
            Some(RegenerationUrgency::Low)
        );
        assert_eq!(
            RegenerationUrgency::from_fitness(FitnessVerdict::Unfit),
            Some(RegenerationUrgency::Medium)
        );
        assert_eq!(
            RegenerationUrgency::from_fitness(FitnessVerdict::Critical),
            Some(RegenerationUrgency::Critical)
        );
    }

    #[test]
    fn test_regeneration_trigger_creation() {
        let config = RegenerationConfig::default();
        let trigger = RegenerationTrigger::new(config);

        assert!(trigger.is_enabled());
        assert_eq!(trigger.consecutive_failures(), 0);
        assert!(!trigger.is_circuit_open());
    }

    #[test]
    fn test_evaluate_rejection_keyspace_saturation() {
        let config = RegenerationConfig::default();
        let trigger = RegenerationTrigger::new(config);

        let rejection = test_rejection(RejectionReason::KeyspaceSaturation);
        let decision = trigger.evaluate_rejection(&rejection);

        assert!(decision.should_proceed());
        if let RegenerationDecision::Proceed { urgency, .. } = decision {
            assert_eq!(urgency, RegenerationUrgency::High);
        }
    }

    #[test]
    fn test_evaluate_rejection_diversity_constraint() {
        let config = RegenerationConfig::default();
        let trigger = RegenerationTrigger::new(config);

        let rejection = test_rejection(RejectionReason::Subnet64Limit);
        let decision = trigger.evaluate_rejection(&rejection);

        assert!(decision.is_blocked());
        if let RegenerationDecision::Blocked { reason } = decision {
            assert!(matches!(reason, BlockReason::DiversityConstraint { .. }));
        }
    }

    #[test]
    fn test_evaluate_rejection_blocklisted() {
        let config = RegenerationConfig::default();
        let trigger = RegenerationTrigger::new(config);

        let rejection = test_rejection(RejectionReason::Blocklisted);
        let decision = trigger.evaluate_rejection(&rejection);

        assert!(decision.is_blocked());
        if let RegenerationDecision::Blocked { reason } = decision {
            assert!(matches!(reason, BlockReason::Blocklisted));
        }
    }

    #[test]
    fn test_max_attempts_blocking() {
        let mut config = RegenerationConfig::default();
        config.max_consecutive_attempts = 3;
        config.attempt_window = Duration::from_secs(3600);
        config.base_delay = Duration::from_millis(1); // Fast backoff for testing
        let trigger = RegenerationTrigger::new(config);

        // Record max attempts
        for _ in 0..3 {
            trigger.record_attempt(test_node_id(), RegenerationReason::Manual);
        }

        let rejection = test_rejection(RejectionReason::KeyspaceSaturation);
        let decision = trigger.evaluate_rejection(&rejection);

        assert!(decision.is_blocked());
        if let RegenerationDecision::Blocked { reason } = decision {
            assert!(matches!(reason, BlockReason::MaxAttemptsReached { .. }));
        }
    }

    #[test]
    fn test_circuit_breaker() {
        let mut config = RegenerationConfig::default();
        config.circuit_breaker_threshold = 2;
        let trigger = RegenerationTrigger::new(config);

        // Record failures to trip circuit breaker
        trigger.record_attempt(test_node_id(), RegenerationReason::Manual);
        trigger.record_result(NodeId([0x01; 32]), false);
        trigger.record_attempt(test_node_id(), RegenerationReason::Manual);
        trigger.record_result(NodeId([0x02; 32]), false);

        assert!(trigger.is_circuit_open());
    }

    #[test]
    fn test_success_resets_state() {
        let config = RegenerationConfig::default();
        let trigger = RegenerationTrigger::new(config);

        // Record some failures
        trigger.record_attempt(test_node_id(), RegenerationReason::Manual);
        trigger.record_result(NodeId([0x01; 32]), false);
        trigger.record_attempt(test_node_id(), RegenerationReason::Manual);
        trigger.record_result(NodeId([0x02; 32]), false);

        assert_eq!(trigger.consecutive_failures(), 2);

        // Record success
        trigger.record_attempt(test_node_id(), RegenerationReason::Manual);
        trigger.record_result(NodeId([0x03; 32]), true);

        assert_eq!(trigger.consecutive_failures(), 0);
        assert!(!trigger.is_circuit_open());
    }

    #[test]
    fn test_prefix_rejection_tracking() {
        let mut config = RegenerationConfig::default();
        config.track_rejected_prefixes = true;
        config.rejection_prefix_bits = 8;
        let trigger = RegenerationTrigger::new(config);

        let node_id = NodeId([0xAB; 32]);
        trigger.record_attempt(test_node_id(), RegenerationReason::Manual);
        trigger.record_result(node_id.clone(), false);

        assert!(trigger.is_prefix_rejected(&node_id));

        // Different prefix should not be rejected
        let other_id = NodeId([0x12; 32]);
        assert!(!trigger.is_prefix_rejected(&other_id));
    }

    #[test]
    fn test_disable_enable() {
        let config = RegenerationConfig::default();
        let trigger = RegenerationTrigger::new(config);

        assert!(trigger.is_enabled());

        trigger.disable();
        assert!(!trigger.is_enabled());

        let rejection = test_rejection(RejectionReason::KeyspaceSaturation);
        let decision = trigger.evaluate_rejection(&rejection);
        assert!(decision.is_blocked());

        trigger.enable();
        assert!(trigger.is_enabled());
    }

    #[test]
    fn test_reset() {
        let config = RegenerationConfig::default();
        let trigger = RegenerationTrigger::new(config);

        // Add some state
        trigger.record_attempt(test_node_id(), RegenerationReason::Manual);
        trigger.record_result(NodeId([0x01; 32]), false);
        trigger.disable();

        assert!(!trigger.is_enabled());
        assert_eq!(trigger.consecutive_failures(), 1);
        assert_eq!(trigger.attempt_count(), 1);

        // Reset
        trigger.reset();

        assert!(trigger.is_enabled());
        assert_eq!(trigger.consecutive_failures(), 0);
        assert_eq!(trigger.attempt_count(), 0);
    }

    #[test]
    fn test_evaluate_fitness_healthy() {
        let config = RegenerationConfig::default();
        let trigger = RegenerationTrigger::new(config);

        let mut metrics = FitnessMetrics::default();
        metrics.verdict = FitnessVerdict::Healthy;

        let decision = trigger.evaluate_fitness(&metrics);
        assert!(matches!(decision, RegenerationDecision::NotNeeded));
    }

    #[test]
    fn test_evaluate_fitness_marginal() {
        let config = RegenerationConfig::default();
        let trigger = RegenerationTrigger::new(config);

        let mut metrics = FitnessMetrics::default();
        metrics.verdict = FitnessVerdict::Marginal;

        let decision = trigger.evaluate_fitness(&metrics);
        assert!(matches!(decision, RegenerationDecision::Recommend { .. }));
    }

    #[test]
    fn test_evaluate_fitness_critical() {
        let config = RegenerationConfig::default();
        let trigger = RegenerationTrigger::new(config);

        let mut metrics = FitnessMetrics::default();
        metrics.verdict = FitnessVerdict::Critical;

        let decision = trigger.evaluate_fitness(&metrics);
        assert!(decision.should_proceed());
        if let RegenerationDecision::Proceed { urgency, .. } = decision {
            assert_eq!(urgency, RegenerationUrgency::Critical);
        }
    }
}
