// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Network Resilience for Heartbeat System.
//!
//! This module provides intelligent handling of network disruptions to prevent
//! cascading failures during partitions, outages, or quiescent periods.
//!
//! ## Key Principles
//!
//! 1. **Suspect Self Before Blaming Others**: When many peers go silent,
//!    check own connectivity before penalizing them.
//!
//! 2. **Preserve State During Quiescence**: The network should be able to
//!    go offline for extended periods and resume without reputation loss.
//!
//! 3. **Gradual Trust Decay**: Use proportional penalties instead of
//!    binary eviction to allow recovery from transient issues.
//!
//! ## Downtime Types
//!
//! | Type | Detection | Action |
//! |------|-----------|--------|
//! | Single peer down | One peer silent | Normal eviction |
//! | We're offline | No external connectivity | Freeze (we're the problem) |
//! | Network partition | Sudden 30%+ drop | Freeze scores |
//! | Network quiescent | All silent, we have connectivity | Preserve state |
//! | Startup | Just recovered | Grace period |

use super::signed_heartbeat_manager::SignedPeerStatus;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for network resilience behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResilienceConfig {
    /// Startup grace period - no evictions during this time (seconds).
    pub startup_grace_secs: u64,

    /// Minimum healthy peers required to make eviction decisions.
    pub min_peers_for_eviction: usize,

    /// Threshold for "sudden drop" detection (0.0-1.0).
    /// If healthy ratio drops by more than this, suspect partition.
    pub sudden_drop_threshold: f64,

    /// Time without activity before entering quiescence mode (seconds).
    pub quiescence_threshold_secs: u64,

    /// How often to check external connectivity (seconds).
    pub connectivity_check_interval_secs: u64,

    /// Maximum time to stay in network disruption mode (seconds).
    /// Safety valve to prevent permanent freeze.
    pub max_disruption_duration_secs: u64,

    /// Gradual trust decay rate per missed heartbeat.
    pub gradual_decay_rate: f64,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            startup_grace_secs: 300, // 5 minutes
            min_peers_for_eviction: 3,
            sudden_drop_threshold: 0.3,           // 30% drop
            quiescence_threshold_secs: 600,       // 10 minutes
            connectivity_check_interval_secs: 60, // 1 minute
            max_disruption_duration_secs: 3600,   // 1 hour max freeze
            gradual_decay_rate: 0.05,             // 5% per miss
        }
    }
}

impl ResilienceConfig {
    /// Configuration for testing with faster timeouts.
    #[must_use]
    pub fn fast() -> Self {
        Self {
            startup_grace_secs: 10,
            min_peers_for_eviction: 2,
            sudden_drop_threshold: 0.3,
            quiescence_threshold_secs: 30,
            connectivity_check_interval_secs: 5,
            max_disruption_duration_secs: 120,
            gradual_decay_rate: 0.1,
        }
    }

    /// Strict configuration with minimal grace periods.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            startup_grace_secs: 60,
            min_peers_for_eviction: 1,
            sudden_drop_threshold: 0.5,
            quiescence_threshold_secs: 300,
            connectivity_check_interval_secs: 30,
            max_disruption_duration_secs: 1800,
            gradual_decay_rate: 0.1,
        }
    }
}

// ============================================================================
// Network Health Context
// ============================================================================

/// Runtime context for network health decisions.
///
/// This struct captures the current state of the network from this node's
/// perspective, enabling intelligent decisions about peer status.
#[derive(Debug, Clone, Default)]
pub struct NetworkHealthContext {
    // === Peer Statistics ===
    /// Total number of tracked peers.
    pub total_tracked_peers: usize,

    /// Number of healthy peers (recent valid heartbeats).
    pub healthy_peers: usize,

    /// Number of suspect peers (missed some heartbeats).
    pub suspect_peers: usize,

    /// Number of unresponsive peers (too many missed heartbeats).
    pub unresponsive_peers: usize,

    /// Number of unknown peers (no heartbeats yet).
    pub unknown_peers: usize,

    // === Connectivity Indicators ===
    /// Can we reach external endpoints?
    pub external_connectivity: bool,

    /// How many bootstrap nodes can we reach?
    pub bootstrap_nodes_reachable: usize,

    /// Current gossip mesh size (connected peers).
    pub gossip_mesh_size: usize,

    /// Successful connections in last check period.
    pub recent_connection_successes: usize,

    // === Trend Detection ===
    /// Healthy ratio now (0.0-1.0).
    pub healthy_ratio_now: f64,

    /// Healthy ratio 1 epoch ago.
    pub healthy_ratio_1_epoch: f64,

    /// Healthy ratio 5 epochs ago.
    pub healthy_ratio_5_epochs: f64,

    // === Startup State ===
    /// Time since we started (or recovered) in seconds.
    pub uptime_secs: u64,

    /// Are we in startup grace period?
    pub in_startup_grace: bool,

    /// Did we just recover from downtime?
    pub recovered_from_downtime: bool,

    /// Time when we entered disruption mode (if any).
    pub disruption_started: Option<Instant>,
}

impl NetworkHealthContext {
    /// Create a new context with the given peer counts.
    pub fn new(healthy: usize, suspect: usize, unresponsive: usize, unknown: usize) -> Self {
        let total = healthy + suspect + unresponsive + unknown;
        let healthy_ratio = if total > 0 {
            healthy as f64 / total as f64
        } else {
            1.0 // No peers = assume healthy
        };

        Self {
            total_tracked_peers: total,
            healthy_peers: healthy,
            suspect_peers: suspect,
            unresponsive_peers: unresponsive,
            unknown_peers: unknown,
            healthy_ratio_now: healthy_ratio,
            healthy_ratio_1_epoch: healthy_ratio,
            healthy_ratio_5_epochs: healthy_ratio,
            external_connectivity: true, // Assume true until checked
            ..Default::default()
        }
    }

    /// Update healthy ratios for trend detection.
    pub fn update_healthy_ratios(&mut self, new_ratio: f64) {
        self.healthy_ratio_5_epochs = self.healthy_ratio_1_epoch;
        self.healthy_ratio_1_epoch = self.healthy_ratio_now;
        self.healthy_ratio_now = new_ratio;
    }

    /// Calculate the current healthy ratio from peer counts.
    #[must_use]
    pub fn calculate_healthy_ratio(&self) -> f64 {
        if self.total_tracked_peers == 0 {
            return 1.0;
        }
        self.healthy_peers as f64 / self.total_tracked_peers as f64
    }

    /// Are we likely experiencing connectivity issues ourselves?
    #[must_use]
    pub fn likely_self_problem(&self) -> bool {
        !self.external_connectivity
            && self.bootstrap_nodes_reachable == 0
            && self.gossip_mesh_size == 0
    }

    /// Did we experience a sudden drop in healthy peers?
    #[must_use]
    pub fn sudden_drop_detected(&self, threshold: f64) -> bool {
        let drop = self.healthy_ratio_5_epochs - self.healthy_ratio_now;
        drop > threshold && self.healthy_ratio_5_epochs > 0.5
    }

    /// Are we in a state where eviction decisions are safe?
    #[must_use]
    pub fn eviction_safe(&self, config: &ResilienceConfig) -> bool {
        // Not safe if we're in startup grace period
        if self.in_startup_grace {
            return false;
        }

        // Not safe if we just recovered from downtime
        if self.recovered_from_downtime && self.uptime_secs < config.startup_grace_secs {
            return false;
        }

        // Not safe if we appear to have connectivity issues
        if self.likely_self_problem() {
            return false;
        }

        // Not safe if sudden mass drop (likely partition)
        if self.sudden_drop_detected(config.sudden_drop_threshold) {
            return false;
        }

        // Not safe if not enough peers to form consensus
        if self.healthy_peers < config.min_peers_for_eviction {
            return false;
        }

        true
    }

    /// Check if we should exit disruption mode.
    #[must_use]
    pub fn should_exit_disruption(&self, config: &ResilienceConfig) -> bool {
        if let Some(started) = self.disruption_started {
            // Exit if healthy ratio recovered
            if self.healthy_ratio_now > 0.7 {
                return true;
            }

            // Exit if we've been frozen too long (safety valve)
            if started.elapsed() > Duration::from_secs(config.max_disruption_duration_secs) {
                return true;
            }
        }

        false
    }
}

// ============================================================================
// Heartbeat Decision Engine
// ============================================================================

/// Action to take for a peer's heartbeat status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatAction {
    /// Normal processing - update status as usual.
    Normal,

    /// Grace period - don't penalize missed heartbeats.
    Grace,

    /// Freeze - don't change any status (network disruption).
    Freeze,

    /// Recovery mode - reset to unknown, try to reconnect.
    Reconnect,
}

/// Engine for making intelligent heartbeat decisions.
pub struct HeartbeatDecisionEngine {
    config: ResilienceConfig,
}

impl HeartbeatDecisionEngine {
    /// Create a new decision engine with the given configuration.
    #[must_use]
    pub fn new(config: ResilienceConfig) -> Self {
        Self { config }
    }

    /// Decide what action to take for heartbeat processing.
    ///
    /// This is called before processing missed heartbeats to determine
    /// whether we should proceed normally or apply protective measures.
    #[must_use]
    pub fn decide(&self, context: &NetworkHealthContext) -> HeartbeatAction {
        // Priority 1: Startup grace period
        if context.in_startup_grace {
            tracing::debug!("In startup grace period, not penalizing peers");
            return HeartbeatAction::Grace;
        }

        // Priority 2: Recovery from downtime
        if context.recovered_from_downtime && context.uptime_secs < self.config.startup_grace_secs {
            tracing::debug!(
                uptime_secs = context.uptime_secs,
                "Recovering from downtime, entering reconnect mode"
            );
            return HeartbeatAction::Reconnect;
        }

        // Priority 3: We're offline
        if context.likely_self_problem() {
            tracing::warn!(
                external = context.external_connectivity,
                bootstrap = context.bootstrap_nodes_reachable,
                mesh = context.gossip_mesh_size,
                "Connectivity issues detected, freezing peer status"
            );
            return HeartbeatAction::Freeze;
        }

        // Priority 4: Network partition / mass drop
        if context.sudden_drop_detected(self.config.sudden_drop_threshold) {
            tracing::warn!(
                ratio_5_epochs = format!("{:.1}%", context.healthy_ratio_5_epochs * 100.0),
                ratio_now = format!("{:.1}%", context.healthy_ratio_now * 100.0),
                "Sudden drop in healthy peers detected, freezing status"
            );
            return HeartbeatAction::Freeze;
        }

        // Priority 5: Not enough peers for consensus
        if context.healthy_peers < self.config.min_peers_for_eviction {
            tracing::info!(
                healthy = context.healthy_peers,
                required = self.config.min_peers_for_eviction,
                "Below minimum peer threshold, using grace mode"
            );
            return HeartbeatAction::Grace;
        }

        // Normal operation
        HeartbeatAction::Normal
    }

    /// Get the configuration.
    #[must_use]
    pub fn config(&self) -> &ResilienceConfig {
        &self.config
    }
}

// ============================================================================
// Quiescence Detector
// ============================================================================

/// Detector for network quiescence (planned/unplanned total outage).
///
/// Quiescence is when the entire network goes silent, but we still have
/// external connectivity. This could be planned maintenance or a widespread
/// outage that doesn't affect us specifically.
pub struct QuiescenceDetector {
    /// Last time we saw healthy network activity.
    last_healthy_activity: Instant,

    /// Configuration.
    config: ResilienceConfig,

    /// Are we currently in quiescent mode?
    is_quiescent: bool,
}

impl QuiescenceDetector {
    /// Create a new quiescence detector.
    #[must_use]
    pub fn new(config: ResilienceConfig) -> Self {
        Self {
            last_healthy_activity: Instant::now(),
            config,
            is_quiescent: false,
        }
    }

    /// Record healthy network activity.
    pub fn record_activity(&mut self) {
        self.last_healthy_activity = Instant::now();

        if self.is_quiescent {
            tracing::info!("Network activity resumed, exiting quiescent mode");
            self.is_quiescent = false;
        }
    }

    /// Check if network appears quiescent.
    ///
    /// Returns true if the network seems to be in a quiescent state.
    #[must_use]
    pub fn check_quiescence(&mut self, context: &NetworkHealthContext) -> bool {
        // Network is quiescent if:
        // 1. Very few or no active peers
        // 2. No successful heartbeat exchanges for a while
        // 3. But we still have external connectivity (so it's not us)

        let low_activity = context.healthy_peers == 0 && context.recent_connection_successes == 0;

        let we_are_ok = context.external_connectivity;

        if low_activity && we_are_ok {
            let threshold = Duration::from_secs(self.config.quiescence_threshold_secs);

            if self.last_healthy_activity.elapsed() > threshold {
                if !self.is_quiescent {
                    tracing::info!(
                        elapsed_secs = self.last_healthy_activity.elapsed().as_secs(),
                        "Network appears quiescent (no activity), preserving state"
                    );
                    self.is_quiescent = true;
                }
                return true;
            }
        }

        false
    }

    /// Is the network currently quiescent?
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.is_quiescent
    }

    /// How long since last healthy activity?
    #[must_use]
    pub fn time_since_activity(&self) -> Duration {
        self.last_healthy_activity.elapsed()
    }
}

// ============================================================================
// Persistence
// ============================================================================

/// Persisted network state that survives restarts.
///
/// This allows the node to resume without penalizing peers for
/// the node's own downtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedNetworkState {
    /// When we last had healthy network activity (Unix timestamp).
    pub last_healthy_activity: u64,

    /// When we shut down (set on graceful shutdown).
    pub shutdown_timestamp: Option<u64>,

    /// Peer states at last save.
    pub peer_states: HashMap<[u8; 32], PersistedPeerState>,

    /// Was this a graceful shutdown?
    pub graceful_shutdown: bool,

    /// Version for format compatibility.
    pub version: u32,
}

impl Default for PersistedNetworkState {
    fn default() -> Self {
        Self {
            last_healthy_activity: current_timestamp(),
            shutdown_timestamp: None,
            peer_states: HashMap::new(),
            graceful_shutdown: false,
            version: 1,
        }
    }
}

impl PersistedNetworkState {
    /// Current persistence format version.
    pub const CURRENT_VERSION: u32 = 1;

    /// Calculate how long we were down.
    #[must_use]
    pub fn downtime_secs(&self) -> u64 {
        let now = current_timestamp();
        let last_active = self
            .shutdown_timestamp
            .unwrap_or(self.last_healthy_activity);
        now.saturating_sub(last_active)
    }

    /// Mark as graceful shutdown (call before shutting down).
    pub fn prepare_shutdown(&mut self) {
        self.shutdown_timestamp = Some(current_timestamp());
        self.graceful_shutdown = true;
    }

    /// Serialize to bytes for storage.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        serde_cbor::to_vec(self).map_err(|e| format!("Failed to serialize network state: {}", e))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        serde_cbor::from_slice(data)
            .map_err(|e| format!("Failed to deserialize network state: {}", e))
    }
}

/// Persisted state for a single peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPeerState {
    /// Peer's EntangledId.
    pub entangled_id: [u8; 32],

    /// Peer's public key.
    pub public_key: Vec<u8>,

    /// Last verified heartbeat epoch.
    pub last_heartbeat_epoch: u64,

    /// Heartbeat streak at last save.
    pub streak: u32,

    /// Status at last save.
    pub last_known_status: SignedPeerStatus,
}

// ============================================================================
// Recovery Handler
// ============================================================================

/// Handles recovery from node downtime.
///
/// Key principle: Don't penalize peers for our own downtime.
pub struct RecoveryHandler {
    /// When we started (or recovered).
    startup_time: Instant,

    /// Persisted state we recovered from.
    persisted_state: Option<PersistedNetworkState>,

    /// Configuration.
    config: ResilienceConfig,
}

impl RecoveryHandler {
    /// Create a new recovery handler.
    #[must_use]
    pub fn new(config: ResilienceConfig) -> Self {
        Self {
            startup_time: Instant::now(),
            persisted_state: None,
            config,
        }
    }

    /// Create from persisted state.
    #[must_use]
    pub fn from_persisted(state: PersistedNetworkState, config: ResilienceConfig) -> Self {
        let downtime = state.downtime_secs();
        tracing::info!(
            downtime_secs = downtime,
            graceful = state.graceful_shutdown,
            peer_count = state.peer_states.len(),
            "Recovering from persisted state"
        );

        Self {
            startup_time: Instant::now(),
            persisted_state: Some(state),
            config,
        }
    }

    /// How long since startup?
    #[must_use]
    pub fn uptime(&self) -> Duration {
        self.startup_time.elapsed()
    }

    /// Are we in the startup grace period?
    #[must_use]
    pub fn in_grace_period(&self) -> bool {
        self.uptime() < Duration::from_secs(self.config.startup_grace_secs)
    }

    /// Did we recover from downtime?
    #[must_use]
    pub fn recovered_from_downtime(&self) -> bool {
        self.persisted_state.is_some()
    }

    /// Get the persisted state (if any).
    #[must_use]
    pub fn persisted_state(&self) -> Option<&PersistedNetworkState> {
        self.persisted_state.as_ref()
    }

    /// Build a NetworkHealthContext with recovery information.
    #[must_use]
    pub fn build_context(
        &self,
        healthy: usize,
        suspect: usize,
        unresponsive: usize,
        unknown: usize,
    ) -> NetworkHealthContext {
        let mut context = NetworkHealthContext::new(healthy, suspect, unresponsive, unknown);

        context.uptime_secs = self.uptime().as_secs();
        context.in_startup_grace = self.in_grace_period();
        context.recovered_from_downtime = self.recovered_from_downtime();

        context
    }
}

// ============================================================================
// Healthy Ratio Tracker
// ============================================================================

/// Tracks healthy peer ratios over time for trend detection.
pub struct HealthyRatioTracker {
    /// Historical ratios (most recent last).
    history: Vec<f64>,

    /// Maximum history size.
    max_history: usize,
}

impl HealthyRatioTracker {
    /// Create a new tracker.
    #[must_use]
    pub fn new(max_history: usize) -> Self {
        Self {
            history: Vec::with_capacity(max_history),
            max_history,
        }
    }

    /// Record a new ratio.
    pub fn record(&mut self, ratio: f64) {
        if self.history.len() >= self.max_history {
            self.history.remove(0);
        }
        self.history.push(ratio);
    }

    /// Get the most recent ratio.
    #[must_use]
    pub fn current(&self) -> f64 {
        self.history.last().copied().unwrap_or(1.0)
    }

    /// Get ratio from N samples ago.
    #[must_use]
    pub fn ago(&self, n: usize) -> f64 {
        if n >= self.history.len() {
            return self.history.first().copied().unwrap_or(1.0);
        }
        self.history[self.history.len() - 1 - n]
    }

    /// Populate a context with historical ratios.
    pub fn populate_context(&self, context: &mut NetworkHealthContext) {
        context.healthy_ratio_now = self.current();
        context.healthy_ratio_1_epoch = self.ago(1);
        context.healthy_ratio_5_epochs = self.ago(5);
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_health_context_creation() {
        let context = NetworkHealthContext::new(8, 2, 1, 1);

        assert_eq!(context.total_tracked_peers, 12);
        assert_eq!(context.healthy_peers, 8);
        assert!((context.healthy_ratio_now - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_sudden_drop_detection() {
        let mut context = NetworkHealthContext::new(8, 0, 0, 0);
        context.healthy_ratio_5_epochs = 0.9;
        context.healthy_ratio_now = 0.4;

        assert!(context.sudden_drop_detected(0.3));

        // No drop
        context.healthy_ratio_now = 0.8;
        assert!(!context.sudden_drop_detected(0.3));
    }

    #[test]
    fn test_likely_self_problem() {
        // All indicators good
        let mut context = NetworkHealthContext {
            external_connectivity: true,
            bootstrap_nodes_reachable: 2,
            gossip_mesh_size: 5,
            ..Default::default()
        };
        assert!(!context.likely_self_problem());

        // All indicators bad - we're the problem
        context.external_connectivity = false;
        context.bootstrap_nodes_reachable = 0;
        context.gossip_mesh_size = 0;
        assert!(context.likely_self_problem());

        // External connectivity but no mesh - not necessarily our problem
        context.external_connectivity = true;
        assert!(!context.likely_self_problem());
    }

    #[test]
    fn test_decision_engine_startup_grace() {
        let engine = HeartbeatDecisionEngine::new(ResilienceConfig::default());

        let mut context = NetworkHealthContext::new(10, 0, 0, 0);
        context.in_startup_grace = true;

        assert_eq!(engine.decide(&context), HeartbeatAction::Grace);
    }

    #[test]
    fn test_decision_engine_self_problem() {
        let engine = HeartbeatDecisionEngine::new(ResilienceConfig::default());

        let mut context = NetworkHealthContext::new(0, 0, 10, 0);
        context.external_connectivity = false;
        context.bootstrap_nodes_reachable = 0;
        context.gossip_mesh_size = 0;

        assert_eq!(engine.decide(&context), HeartbeatAction::Freeze);
    }

    #[test]
    fn test_decision_engine_sudden_drop() {
        let engine = HeartbeatDecisionEngine::new(ResilienceConfig::default());

        let mut context = NetworkHealthContext::new(2, 0, 8, 0);
        context.healthy_ratio_5_epochs = 0.9;
        context.healthy_ratio_now = 0.2;
        context.external_connectivity = true;

        assert_eq!(engine.decide(&context), HeartbeatAction::Freeze);
    }

    #[test]
    fn test_decision_engine_normal_operation() {
        let engine = HeartbeatDecisionEngine::new(ResilienceConfig::default());

        let mut context = NetworkHealthContext::new(10, 1, 1, 0);
        context.external_connectivity = true;
        context.healthy_ratio_5_epochs = 0.8;
        context.healthy_ratio_now = 0.83;

        assert_eq!(engine.decide(&context), HeartbeatAction::Normal);
    }

    #[test]
    fn test_decision_engine_min_peers() {
        let engine = HeartbeatDecisionEngine::new(ResilienceConfig::default());

        let mut context = NetworkHealthContext::new(2, 0, 0, 0);
        context.external_connectivity = true;

        // Below min_peers_for_eviction (default 3)
        assert_eq!(engine.decide(&context), HeartbeatAction::Grace);

        // At threshold
        context.healthy_peers = 3;
        context.total_tracked_peers = 3;
        assert_eq!(engine.decide(&context), HeartbeatAction::Normal);
    }

    #[test]
    fn test_quiescence_detector() {
        let config = ResilienceConfig {
            quiescence_threshold_secs: 0, // Immediate for testing
            ..Default::default()
        };
        let mut detector = QuiescenceDetector::new(config);

        // Initially not quiescent
        assert!(!detector.is_quiescent());

        // With no activity and external connectivity, becomes quiescent
        let context = NetworkHealthContext {
            healthy_peers: 0,
            recent_connection_successes: 0,
            external_connectivity: true,
            ..Default::default()
        };

        // Wait a tiny bit and check
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(detector.check_quiescence(&context));
        assert!(detector.is_quiescent());

        // Activity resumes
        detector.record_activity();
        assert!(!detector.is_quiescent());
    }

    #[test]
    fn test_persisted_state_serialization() {
        let mut state = PersistedNetworkState::default();
        state.peer_states.insert(
            [1u8; 32],
            PersistedPeerState {
                entangled_id: [1u8; 32],
                public_key: vec![2u8; 100],
                last_heartbeat_epoch: 42,
                streak: 10,
                last_known_status: SignedPeerStatus::Healthy,
            },
        );

        let bytes = state.to_bytes().expect("serialize");
        let recovered = PersistedNetworkState::from_bytes(&bytes).expect("deserialize");

        assert_eq!(recovered.peer_states.len(), 1);
        assert_eq!(recovered.peer_states[&[1u8; 32]].streak, 10);
    }

    #[test]
    fn test_recovery_handler_grace_period() {
        let config = ResilienceConfig {
            startup_grace_secs: 1, // 1 second for testing
            ..Default::default()
        };
        let handler = RecoveryHandler::new(config);

        assert!(handler.in_grace_period());

        // After waiting, should exit grace period
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(!handler.in_grace_period());
    }

    #[test]
    fn test_healthy_ratio_tracker() {
        let mut tracker = HealthyRatioTracker::new(10);

        tracker.record(0.9);
        tracker.record(0.8);
        tracker.record(0.7);

        assert!((tracker.current() - 0.7).abs() < 0.001);
        assert!((tracker.ago(1) - 0.8).abs() < 0.001);
        assert!((tracker.ago(2) - 0.9).abs() < 0.001);
        assert!((tracker.ago(10) - 0.9).abs() < 0.001); // Beyond history
    }

    #[test]
    fn test_eviction_safe() {
        let config = ResilienceConfig::default();

        // Safe scenario
        let mut context = NetworkHealthContext::new(10, 1, 0, 0);
        context.external_connectivity = true;
        context.healthy_ratio_5_epochs = 0.9;
        assert!(context.eviction_safe(&config));

        // Not safe: startup grace
        context.in_startup_grace = true;
        assert!(!context.eviction_safe(&config));
        context.in_startup_grace = false;

        // Not safe: sudden drop
        context.healthy_ratio_now = 0.3;
        assert!(!context.eviction_safe(&config));
    }

    #[test]
    fn test_should_exit_disruption() {
        let config = ResilienceConfig {
            max_disruption_duration_secs: 0, // Immediate exit for testing
            ..Default::default()
        };

        let mut context = NetworkHealthContext {
            disruption_started: Some(Instant::now()),
            healthy_ratio_now: 0.3,
            ..Default::default()
        };

        // Should exit due to max duration exceeded
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(context.should_exit_disruption(&config));

        // Or if healthy ratio recovers
        context.healthy_ratio_now = 0.8;
        assert!(context.should_exit_disruption(&config));
    }
}
