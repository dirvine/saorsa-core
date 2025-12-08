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

//! Proactive fitness monitoring for node identity.
//!
//! This module provides mechanisms to proactively detect when a node's identity
//! is not well-suited for the current network state. This enables early detection
//! of potential issues before the node experiences repeated rejections.
//!
//! # Fitness Indicators
//!
//! The fitness system monitors several key metrics:
//! - **Position Quality**: How well the node fits in its close group
//! - **Stability Score**: Membership stability in close groups
//! - **Saturation Level**: Local keyspace congestion
//! - **Diversity Compliance**: Whether node meets diversity requirements
//!
//! # Example
//!
//! ```ignore
//! use saorsa_core::identity::fitness::{FitnessMonitor, FitnessConfig};
//!
//! let config = FitnessConfig::default();
//! let monitor = FitnessMonitor::new(config, node_id);
//!
//! // Check current fitness
//! let verdict = monitor.evaluate().await;
//! if verdict == FitnessVerdict::Unfit {
//!     // Consider regenerating identity
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use super::node_identity::NodeId;

/// Verdict on the node's current fitness for the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FitnessVerdict {
    /// Node is well-positioned and functioning optimally.
    Healthy,

    /// Node is functional but not optimally positioned.
    /// May benefit from regeneration during low-activity periods.
    Marginal,

    /// Node is poorly positioned and experiencing issues.
    /// Should consider regeneration.
    Unfit,

    /// Node is in a critical state and needs immediate regeneration.
    /// Continued operation is severely impacted.
    Critical,
}

impl FitnessVerdict {
    /// Returns whether regeneration is recommended for this verdict.
    #[must_use]
    pub fn should_regenerate(&self) -> bool {
        matches!(self, Self::Unfit | Self::Critical)
    }

    /// Returns whether regeneration might be beneficial.
    #[must_use]
    pub fn may_benefit_from_regeneration(&self) -> bool {
        matches!(self, Self::Marginal | Self::Unfit | Self::Critical)
    }

    /// Returns a priority level (0-3, higher = more urgent).
    #[must_use]
    pub fn priority(&self) -> u8 {
        match self {
            Self::Healthy => 0,
            Self::Marginal => 1,
            Self::Unfit => 2,
            Self::Critical => 3,
        }
    }
}

impl fmt::Display for FitnessVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Marginal => write!(f, "marginal"),
            Self::Unfit => write!(f, "unfit"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Configuration for fitness monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FitnessConfig {
    /// How often to evaluate fitness (default: 60 seconds).
    pub evaluation_interval: Duration,

    /// Position quality threshold below which node is marginal (default: 0.6).
    pub marginal_position_threshold: f64,

    /// Position quality threshold below which node is unfit (default: 0.4).
    pub unfit_position_threshold: f64,

    /// Stability score threshold for marginal (default: 0.7).
    pub marginal_stability_threshold: f64,

    /// Stability score threshold for unfit (default: 0.5).
    pub unfit_stability_threshold: f64,

    /// Maximum membership events to track.
    pub max_membership_history: usize,

    /// Time window for considering membership stability.
    pub stability_window: Duration,

    /// Saturation level above which regeneration is recommended (default: 0.9).
    pub high_saturation_threshold: f64,

    /// Minimum time between fitness evaluations to prevent thrashing.
    pub min_evaluation_gap: Duration,
}

impl Default for FitnessConfig {
    fn default() -> Self {
        Self {
            evaluation_interval: Duration::from_secs(60),
            marginal_position_threshold: 0.6,
            unfit_position_threshold: 0.4,
            marginal_stability_threshold: 0.7,
            unfit_stability_threshold: 0.5,
            max_membership_history: 100,
            stability_window: Duration::from_secs(300), // 5 minutes
            high_saturation_threshold: 0.9,
            min_evaluation_gap: Duration::from_secs(10),
        }
    }
}

/// A membership event in a close group.
#[derive(Debug, Clone)]
pub struct MembershipEvent {
    /// When the event occurred (not serializable).
    pub timestamp: Instant,

    /// Type of membership change.
    pub event_type: MembershipEventType,

    /// Close group key that changed.
    pub close_group_key: Option<[u8; 32]>,
}

/// Type of membership change event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipEventType {
    /// Node joined a close group.
    Joined,

    /// Node left a close group.
    Left,

    /// Node was evicted from a close group.
    Evicted,

    /// Close group membership refreshed (no change).
    Refreshed,
}

/// Current fitness metrics for the node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FitnessMetrics {
    /// Quality of node's position in keyspace (0.0 to 1.0).
    /// Higher values indicate better positioning.
    pub position_quality: f64,

    /// Stability of close group memberships (0.0 to 1.0).
    /// Higher values indicate more stable memberships.
    pub stability_score: f64,

    /// Current saturation level of local keyspace (0.0 to 1.0).
    pub local_saturation: f64,

    /// Whether node meets diversity requirements.
    pub diversity_compliant: bool,

    /// Number of active close group memberships.
    pub active_memberships: u32,

    /// Number of membership changes in stability window.
    pub recent_churn: u32,

    /// Average XOR distance to closest peers (lower = better).
    pub avg_peer_distance: f64,

    /// When these metrics were last updated.
    #[serde(skip)]
    pub last_updated: Option<Instant>,

    /// Overall fitness verdict based on all metrics.
    pub verdict: FitnessVerdict,
}

impl Default for FitnessMetrics {
    fn default() -> Self {
        Self {
            position_quality: 1.0,
            stability_score: 1.0,
            local_saturation: 0.0,
            diversity_compliant: true,
            active_memberships: 0,
            recent_churn: 0,
            avg_peer_distance: 0.0,
            last_updated: None,
            verdict: FitnessVerdict::Healthy,
        }
    }
}

impl FitnessMetrics {
    /// Create new metrics with initial values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate overall fitness score (0.0 to 1.0).
    #[must_use]
    pub fn overall_score(&self) -> f64 {
        // Weighted combination of metrics
        const POSITION_WEIGHT: f64 = 0.35;
        const STABILITY_WEIGHT: f64 = 0.30;
        const SATURATION_WEIGHT: f64 = 0.20;
        const DIVERSITY_WEIGHT: f64 = 0.15;

        let saturation_score = 1.0 - self.local_saturation;
        let diversity_score = if self.diversity_compliant { 1.0 } else { 0.0 };

        (self.position_quality * POSITION_WEIGHT)
            + (self.stability_score * STABILITY_WEIGHT)
            + (saturation_score * SATURATION_WEIGHT)
            + (diversity_score * DIVERSITY_WEIGHT)
    }
}

/// Proactive fitness monitor for node identity.
///
/// This monitors various health indicators and provides verdicts on whether
/// the node's current identity is well-suited for the network.
pub struct FitnessMonitor {
    /// Configuration.
    config: FitnessConfig,

    /// Node ID being monitored.
    node_id: NodeId,

    /// History of membership events.
    membership_history: RwLock<VecDeque<MembershipEvent>>,

    /// Current fitness metrics.
    current_metrics: RwLock<FitnessMetrics>,

    /// Last evaluation time.
    last_evaluation: RwLock<Option<Instant>>,
}

impl FitnessMonitor {
    /// Create a new fitness monitor.
    #[must_use]
    pub fn new(config: FitnessConfig, node_id: NodeId) -> Self {
        Self {
            config,
            node_id,
            membership_history: RwLock::new(VecDeque::with_capacity(100)),
            current_metrics: RwLock::new(FitnessMetrics::default()),
            last_evaluation: RwLock::new(None),
        }
    }

    /// Get the node ID being monitored.
    #[must_use]
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Get current fitness metrics.
    #[must_use]
    pub fn current_metrics(&self) -> FitnessMetrics {
        self.current_metrics.read().clone()
    }

    /// Get the current fitness verdict.
    #[must_use]
    pub fn current_verdict(&self) -> FitnessVerdict {
        self.current_metrics.read().verdict
    }

    /// Record a membership event.
    pub fn record_membership_event(&self, event_type: MembershipEventType, key: Option<[u8; 32]>) {
        let event = MembershipEvent {
            timestamp: Instant::now(),
            event_type,
            close_group_key: key,
        };

        let mut history = self.membership_history.write();
        history.push_back(event);

        // Trim old events
        while history.len() > self.config.max_membership_history {
            history.pop_front();
        }
    }

    /// Update position quality metric.
    pub fn update_position_quality(&self, quality: f64) {
        let mut metrics = self.current_metrics.write();
        metrics.position_quality = quality.clamp(0.0, 1.0);
        metrics.last_updated = Some(Instant::now());
    }

    /// Update local saturation metric.
    pub fn update_saturation(&self, saturation: f64) {
        let mut metrics = self.current_metrics.write();
        metrics.local_saturation = saturation.clamp(0.0, 1.0);
        metrics.last_updated = Some(Instant::now());
    }

    /// Update diversity compliance status.
    pub fn update_diversity_compliance(&self, compliant: bool) {
        let mut metrics = self.current_metrics.write();
        metrics.diversity_compliant = compliant;
        metrics.last_updated = Some(Instant::now());
    }

    /// Update active membership count.
    pub fn update_active_memberships(&self, count: u32) {
        let mut metrics = self.current_metrics.write();
        metrics.active_memberships = count;
        metrics.last_updated = Some(Instant::now());
    }

    /// Update average peer distance.
    pub fn update_peer_distance(&self, avg_distance: f64) {
        let mut metrics = self.current_metrics.write();
        metrics.avg_peer_distance = avg_distance;
        metrics.last_updated = Some(Instant::now());
    }

    /// Calculate stability score from membership history.
    fn calculate_stability(&self) -> f64 {
        let history = self.membership_history.read();
        let now = Instant::now();
        let window_start = now.checked_sub(self.config.stability_window).unwrap_or(now);

        // Count events in window
        let recent_events: Vec<_> = history
            .iter()
            .filter(|e| e.timestamp >= window_start)
            .collect();

        if recent_events.is_empty() {
            return 1.0; // No events = stable
        }

        // Count churn (joins and leaves/evictions)
        let joins = recent_events
            .iter()
            .filter(|e| e.event_type == MembershipEventType::Joined)
            .count();
        let leaves = recent_events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    MembershipEventType::Left | MembershipEventType::Evicted
                )
            })
            .count();

        // Churn rate normalized to window
        let total_churn = joins + leaves;
        let window_secs = self.config.stability_window.as_secs_f64();
        let churn_rate = total_churn as f64 / window_secs;

        // Convert to stability score (lower churn = higher stability)
        // Assuming 1 event per minute is "normal", scale accordingly
        let normalized_rate = churn_rate * 60.0;
        (1.0 - normalized_rate.min(1.0)).max(0.0)
    }

    /// Evaluate current fitness and update verdict.
    ///
    /// Returns the updated fitness metrics with verdict.
    pub fn evaluate(&self) -> FitnessMetrics {
        // Check if we should skip (too soon since last evaluation)
        {
            let last_eval = self.last_evaluation.read();
            if let Some(last) = *last_eval
                && last.elapsed() < self.config.min_evaluation_gap
            {
                return self.current_metrics.read().clone();
            }
        }

        // Calculate stability from history
        let stability = self.calculate_stability();

        // Count recent churn
        let recent_churn = {
            let history = self.membership_history.read();
            let now = Instant::now();
            let window_start = now.checked_sub(self.config.stability_window).unwrap_or(now);

            history
                .iter()
                .filter(|e| e.timestamp >= window_start)
                .filter(|e| e.event_type != MembershipEventType::Refreshed)
                .count() as u32
        };

        // Update metrics and calculate verdict
        let mut metrics = self.current_metrics.write();
        metrics.stability_score = stability;
        metrics.recent_churn = recent_churn;
        metrics.last_updated = Some(Instant::now());

        // Determine verdict
        let verdict = self.calculate_verdict(&metrics);
        metrics.verdict = verdict;

        // Update last evaluation time
        *self.last_evaluation.write() = Some(Instant::now());

        metrics.clone()
    }

    /// Calculate fitness verdict from metrics.
    fn calculate_verdict(&self, metrics: &FitnessMetrics) -> FitnessVerdict {
        // Critical: Diversity non-compliance is always critical
        if !metrics.diversity_compliant {
            return FitnessVerdict::Critical;
        }

        // Check for critical conditions
        if metrics.position_quality < self.config.unfit_position_threshold
            && metrics.stability_score < self.config.unfit_stability_threshold
        {
            return FitnessVerdict::Critical;
        }

        // Check for unfit conditions
        if metrics.position_quality < self.config.unfit_position_threshold
            || metrics.stability_score < self.config.unfit_stability_threshold
            || metrics.local_saturation > self.config.high_saturation_threshold
        {
            return FitnessVerdict::Unfit;
        }

        // Check for marginal conditions
        if metrics.position_quality < self.config.marginal_position_threshold
            || metrics.stability_score < self.config.marginal_stability_threshold
        {
            return FitnessVerdict::Marginal;
        }

        FitnessVerdict::Healthy
    }

    /// Check if immediate regeneration is recommended.
    #[must_use]
    pub fn should_regenerate_immediately(&self) -> bool {
        let metrics = self.current_metrics.read();
        metrics.verdict == FitnessVerdict::Critical
    }

    /// Check if regeneration should be considered.
    #[must_use]
    pub fn should_consider_regeneration(&self) -> bool {
        let metrics = self.current_metrics.read();
        metrics.verdict.should_regenerate()
    }

    /// Get a human-readable status report.
    #[must_use]
    pub fn status_report(&self) -> String {
        let metrics = self.current_metrics.read();
        format!(
            "Fitness: {} | Position: {:.1}% | Stability: {:.1}% | Saturation: {:.1}% | Score: {:.1}%",
            metrics.verdict,
            metrics.position_quality * 100.0,
            metrics.stability_score * 100.0,
            metrics.local_saturation * 100.0,
            metrics.overall_score() * 100.0
        )
    }
}

/// Shared fitness monitor wrapped in Arc.
pub type SharedFitnessMonitor = Arc<FitnessMonitor>;

/// Builder for FitnessMonitor with custom configuration.
pub struct FitnessMonitorBuilder {
    config: FitnessConfig,
    node_id: Option<NodeId>,
}

impl FitnessMonitorBuilder {
    /// Create a new builder with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: FitnessConfig::default(),
            node_id: None,
        }
    }

    /// Set the node ID to monitor.
    #[must_use]
    pub fn node_id(mut self, id: NodeId) -> Self {
        self.node_id = Some(id);
        self
    }

    /// Set evaluation interval.
    #[must_use]
    pub fn evaluation_interval(mut self, interval: Duration) -> Self {
        self.config.evaluation_interval = interval;
        self
    }

    /// Set position thresholds.
    #[must_use]
    pub fn position_thresholds(mut self, marginal: f64, unfit: f64) -> Self {
        self.config.marginal_position_threshold = marginal;
        self.config.unfit_position_threshold = unfit;
        self
    }

    /// Set stability thresholds.
    #[must_use]
    pub fn stability_thresholds(mut self, marginal: f64, unfit: f64) -> Self {
        self.config.marginal_stability_threshold = marginal;
        self.config.unfit_stability_threshold = unfit;
        self
    }

    /// Set saturation threshold.
    #[must_use]
    pub fn saturation_threshold(mut self, threshold: f64) -> Self {
        self.config.high_saturation_threshold = threshold;
        self
    }

    /// Set stability window.
    #[must_use]
    pub fn stability_window(mut self, window: Duration) -> Self {
        self.config.stability_window = window;
        self
    }

    /// Build the fitness monitor.
    ///
    /// # Errors
    ///
    /// Returns `None` if node_id was not set.
    #[must_use]
    pub fn build(self) -> Option<FitnessMonitor> {
        self.node_id.map(|id| FitnessMonitor::new(self.config, id))
    }
}

impl Default for FitnessMonitorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id() -> NodeId {
        NodeId([0x42; 32])
    }

    #[test]
    fn test_fitness_verdict_properties() {
        assert!(!FitnessVerdict::Healthy.should_regenerate());
        assert!(!FitnessVerdict::Marginal.should_regenerate());
        assert!(FitnessVerdict::Unfit.should_regenerate());
        assert!(FitnessVerdict::Critical.should_regenerate());

        assert!(!FitnessVerdict::Healthy.may_benefit_from_regeneration());
        assert!(FitnessVerdict::Marginal.may_benefit_from_regeneration());
    }

    #[test]
    fn test_fitness_metrics_overall_score() {
        let mut metrics = FitnessMetrics::default();
        assert!((metrics.overall_score() - 1.0).abs() < 0.01);

        metrics.position_quality = 0.5;
        metrics.stability_score = 0.5;
        metrics.local_saturation = 0.5;
        metrics.diversity_compliant = true;

        let score = metrics.overall_score();
        assert!(score > 0.4 && score < 0.7);
    }

    #[test]
    fn test_fitness_monitor_creation() {
        let config = FitnessConfig::default();
        let monitor = FitnessMonitor::new(config, test_node_id());

        assert_eq!(monitor.current_verdict(), FitnessVerdict::Healthy);
    }

    #[test]
    fn test_fitness_monitor_update_metrics() {
        let config = FitnessConfig::default();
        let monitor = FitnessMonitor::new(config, test_node_id());

        monitor.update_position_quality(0.3);
        monitor.update_saturation(0.8);

        let metrics = monitor.current_metrics();
        assert!((metrics.position_quality - 0.3).abs() < f64::EPSILON);
        assert!((metrics.local_saturation - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fitness_evaluation_healthy() {
        let config = FitnessConfig::default();
        let monitor = FitnessMonitor::new(config, test_node_id());

        monitor.update_position_quality(0.9);
        monitor.update_saturation(0.2);
        monitor.update_diversity_compliance(true);

        let metrics = monitor.evaluate();
        assert_eq!(metrics.verdict, FitnessVerdict::Healthy);
    }

    #[test]
    fn test_fitness_evaluation_unfit() {
        let config = FitnessConfig::default();
        let monitor = FitnessMonitor::new(config, test_node_id());

        monitor.update_position_quality(0.3); // Below unfit threshold
        monitor.update_diversity_compliance(true);

        let metrics = monitor.evaluate();
        assert_eq!(metrics.verdict, FitnessVerdict::Unfit);
    }

    #[test]
    fn test_fitness_evaluation_critical() {
        let config = FitnessConfig::default();
        let monitor = FitnessMonitor::new(config, test_node_id());

        // Diversity non-compliance is always critical
        monitor.update_diversity_compliance(false);

        let metrics = monitor.evaluate();
        assert_eq!(metrics.verdict, FitnessVerdict::Critical);
    }

    #[test]
    fn test_membership_event_recording() {
        // Use a short stability window to avoid Instant::checked_sub issues on Windows
        // (checked_sub can fail if the duration exceeds what's representable from the epoch)
        let config = FitnessConfig {
            stability_window: Duration::from_secs(1),
            ..FitnessConfig::default()
        };
        let monitor = FitnessMonitor::new(config, test_node_id());

        monitor.record_membership_event(MembershipEventType::Joined, None);
        monitor.record_membership_event(MembershipEventType::Left, None);
        monitor.record_membership_event(MembershipEventType::Evicted, None);

        // After recording churn events, stability should decrease
        let metrics = monitor.evaluate();
        assert!(metrics.stability_score < 1.0);
    }

    #[test]
    fn test_fitness_monitor_builder() {
        let monitor = FitnessMonitorBuilder::new()
            .node_id(test_node_id())
            .evaluation_interval(Duration::from_secs(30))
            .position_thresholds(0.7, 0.5)
            .saturation_threshold(0.85)
            .build()
            .unwrap();

        assert_eq!(monitor.node_id(), &test_node_id());
    }

    #[test]
    fn test_fitness_monitor_builder_missing_id() {
        let result = FitnessMonitorBuilder::new().build();
        assert!(result.is_none());

        let result = FitnessMonitorBuilder::new().node_id(test_node_id()).build();
        assert!(result.is_some());
    }

    #[test]
    fn test_status_report() {
        let config = FitnessConfig::default();
        let monitor = FitnessMonitor::new(config, test_node_id());

        monitor.update_position_quality(0.85);
        monitor.update_saturation(0.3);

        let report = monitor.status_report();
        assert!(report.contains("healthy"));
        assert!(report.contains("Position"));
    }
}
