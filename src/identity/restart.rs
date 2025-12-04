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

//! Identity restart manager and orchestrator.
//!
//! This module provides the main orchestration layer for the identity restart
//! system. It coordinates between fitness monitoring, regeneration triggering,
//! and identity targeting to provide a seamless identity restart experience.
//!
//! # State Persistence
//!
//! The restart manager persists critical state across restarts:
//! - Bootstrap cache contacts
//! - Peer quality metrics
//! - EigenTrust reputation data
//! - Configuration settings
//! - Rejection history (to avoid regenerating similar IDs)
//!
//! # Events
//!
//! The system publishes events via broadcast channels:
//! - `FitnessChanged` - Fitness verdict changed
//! - `RegenerationTriggered` - Regeneration process started
//! - `IdentityChanged` - New identity generated
//! - `RestartRequested` - Full restart requested
//!
//! # Example
//!
//! ```ignore
//! use saorsa_core::identity::restart::{RestartManager, RestartConfig};
//!
//! let config = RestartConfig::default();
//! let manager = RestartManager::new(config, identity).await?;
//!
//! // Subscribe to events
//! let mut rx = manager.subscribe();
//!
//! // Start monitoring
//! let handle = manager.start_monitoring().await?;
//!
//! // Handle events
//! while let Ok(event) = rx.recv().await {
//!     match event {
//!         IdentitySystemEvent::RegenerationTriggered { reason, .. } => {
//!             // Handle regeneration
//!         }
//!         _ => {}
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use super::fitness::{
    FitnessConfig, FitnessMetrics, FitnessMonitor, FitnessVerdict, SharedFitnessMonitor,
};
use super::node_identity::{NodeId, NodeIdentity};
use super::regeneration::{
    RegenerationConfig, RegenerationDecision, RegenerationReason, RegenerationTrigger,
    SharedRegenerationTrigger,
};
use super::rejection::{RejectionHistory, RejectionInfo, TargetRegion};
use super::targeting::{IdentityTargeter, SharedIdentityTargeter, TargetingConfig};
use crate::Result;

/// Configuration for the restart manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartConfig {
    /// Fitness monitoring configuration.
    pub fitness: FitnessConfig,

    /// Regeneration trigger configuration.
    pub regeneration: RegenerationConfig,

    /// Identity targeting configuration.
    pub targeting: TargetingConfig,

    /// Path for persisting state (default: ~/.saorsa/restart_state.json).
    pub state_path: PathBuf,

    /// Whether to auto-start monitoring (default: true).
    pub auto_start_monitoring: bool,

    /// Event channel capacity (default: 100).
    pub event_channel_capacity: usize,

    /// Whether to persist state on shutdown (default: true).
    pub persist_on_shutdown: bool,
}

impl Default for RestartConfig {
    fn default() -> Self {
        let state_path = dirs::home_dir()
            .map(|h| h.join(".saorsa").join("restart_state.json"))
            .unwrap_or_else(|| PathBuf::from("restart_state.json"));

        Self {
            fitness: FitnessConfig::default(),
            regeneration: RegenerationConfig::default(),
            targeting: TargetingConfig::default(),
            state_path,
            auto_start_monitoring: true,
            event_channel_capacity: 100,
            persist_on_shutdown: true,
        }
    }
}

/// Events emitted by the identity restart system.
#[derive(Debug, Clone)]
pub enum IdentitySystemEvent {
    /// Fitness verdict changed.
    FitnessChanged {
        /// Previous verdict.
        previous: FitnessVerdict,
        /// New verdict.
        current: FitnessVerdict,
        /// Current metrics.
        metrics: FitnessMetrics,
    },

    /// Regeneration was triggered.
    RegenerationTriggered {
        /// Reason for regeneration.
        reason: RegenerationReason,
        /// Old node ID.
        old_node_id: NodeId,
        /// Target region (if any).
        target: Option<TargetRegion>,
    },

    /// Identity was changed (regeneration completed).
    IdentityChanged {
        /// Old node ID.
        old_node_id: NodeId,
        /// New node ID.
        new_node_id: NodeId,
        /// Whether it succeeded (was accepted by network).
        succeeded: bool,
    },

    /// Full restart was requested.
    RestartRequested {
        /// Reason for restart.
        reason: String,
        /// New identity to use.
        new_identity: NodeId,
    },

    /// Rejection received from network.
    RejectionReceived {
        /// The rejection info.
        rejection: RejectionInfo,
        /// Regeneration decision made.
        decision: String,
    },

    /// Monitoring started.
    MonitoringStarted,

    /// Monitoring stopped.
    MonitoringStopped {
        /// Reason for stopping.
        reason: String,
    },

    /// State was persisted.
    StatePersisted {
        /// Path where state was saved.
        path: PathBuf,
    },

    /// State was loaded.
    StateLoaded {
        /// Path from which state was loaded.
        path: PathBuf,
    },
}

/// Persistent state that survives restarts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistentState {
    /// Rejection history.
    pub rejection_history: RejectionHistory,

    /// Rejected NodeId prefixes.
    pub rejected_prefixes: Vec<Vec<u8>>,

    /// Last target region suggestion.
    pub last_target: Option<TargetRegion>,

    /// Number of consecutive regeneration failures.
    pub consecutive_failures: u32,

    /// Total regeneration attempts.
    pub total_regeneration_attempts: u64,

    /// Successful regenerations.
    pub successful_regenerations: u64,

    /// Version of the state format.
    pub version: u32,
}

impl PersistentState {
    /// Current state format version.
    pub const CURRENT_VERSION: u32 = 1;

    /// Create a new persistent state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            ..Default::default()
        }
    }
}

/// The main identity restart system orchestrator.
pub struct RestartManager {
    /// Configuration.
    config: RestartConfig,

    /// Current node identity.
    current_identity: RwLock<NodeIdentity>,

    /// Fitness monitor.
    fitness_monitor: SharedFitnessMonitor,

    /// Regeneration trigger.
    regeneration_trigger: SharedRegenerationTrigger,

    /// Identity targeter.
    identity_targeter: SharedIdentityTargeter,

    /// Persistent state.
    persistent_state: RwLock<PersistentState>,

    /// Event broadcaster.
    event_tx: broadcast::Sender<IdentitySystemEvent>,

    /// Whether monitoring is active.
    monitoring_active: RwLock<bool>,
}

impl RestartManager {
    /// Create a new restart manager.
    pub fn new(config: RestartConfig, identity: NodeIdentity) -> Result<Arc<Self>> {
        let node_id = identity.node_id().clone();

        let fitness_monitor =
            Arc::new(FitnessMonitor::new(config.fitness.clone(), node_id.clone()));

        let regeneration_trigger =
            Arc::new(RegenerationTrigger::new(config.regeneration.clone()));

        let identity_targeter = Arc::new(IdentityTargeter::new(config.targeting.clone()));

        let (event_tx, _) = broadcast::channel(config.event_channel_capacity);

        let manager = Arc::new(Self {
            config,
            current_identity: RwLock::new(identity),
            fitness_monitor,
            regeneration_trigger,
            identity_targeter,
            persistent_state: RwLock::new(PersistentState::new()),
            event_tx,
            monitoring_active: RwLock::new(false),
        });

        // Try to load persisted state
        if let Err(e) = manager.load_state() {
            tracing::debug!("No persisted state to load: {}", e);
        }

        Ok(manager)
    }

    /// Get the current node ID.
    #[must_use]
    pub fn current_node_id(&self) -> NodeId {
        self.current_identity.read().node_id().clone()
    }

    /// Get the fitness monitor.
    #[must_use]
    pub fn fitness_monitor(&self) -> &SharedFitnessMonitor {
        &self.fitness_monitor
    }

    /// Get the regeneration trigger.
    #[must_use]
    pub fn regeneration_trigger(&self) -> &SharedRegenerationTrigger {
        &self.regeneration_trigger
    }

    /// Get the identity targeter.
    #[must_use]
    pub fn identity_targeter(&self) -> &SharedIdentityTargeter {
        &self.identity_targeter
    }

    /// Get current fitness metrics.
    #[must_use]
    pub fn get_fitness(&self) -> FitnessMetrics {
        self.fitness_monitor.current_metrics()
    }

    /// Check if regeneration should occur.
    pub fn check_regeneration(&self) -> RegenerationDecision {
        let metrics = self.fitness_monitor.evaluate();
        self.regeneration_trigger.evaluate_fitness(&metrics)
    }

    /// Handle a network rejection.
    pub fn handle_rejection(&self, rejection: RejectionInfo) -> RegenerationDecision {
        // Record in persistent state
        {
            let mut state = self.persistent_state.write();
            state.rejection_history.record(rejection.clone());
        }

        // Evaluate regeneration decision
        let decision = self.regeneration_trigger.evaluate_rejection(&rejection);

        // Update targeter if we have a suggested target
        if let Some(target) = &rejection.suggested_target {
            self.identity_targeter.set_target(Some(target.clone()));
        }

        // Emit event
        let decision_str = match &decision {
            RegenerationDecision::Proceed { urgency, .. } => format!("proceed ({})", urgency),
            RegenerationDecision::Wait { remaining } => {
                format!("wait ({:.0}s)", remaining.as_secs_f64())
            }
            RegenerationDecision::Recommend { reason, .. } => format!("recommend: {}", reason),
            RegenerationDecision::Blocked { reason } => format!("blocked: {}", reason),
            RegenerationDecision::NotNeeded => "not needed".to_string(),
        };

        let _ = self.event_tx.send(IdentitySystemEvent::RejectionReceived {
            rejection,
            decision: decision_str,
        });

        decision
    }

    /// Perform identity regeneration.
    ///
    /// This generates a new identity targeting better keyspace regions.
    pub fn regenerate(&self, reason: RegenerationReason) -> Result<NodeIdentity> {
        let old_node_id = self.current_node_id();

        // Get target from persistent state
        let target = self.persistent_state.read().last_target.clone();

        // Emit regeneration triggered event
        let _ = self.event_tx.send(IdentitySystemEvent::RegenerationTriggered {
            reason: reason.clone(),
            old_node_id: old_node_id.clone(),
            target: target.clone(),
        });

        // Record attempt
        self.regeneration_trigger
            .record_attempt(old_node_id.clone(), reason);

        // Generate targeted identity
        let new_identity = self
            .identity_targeter
            .generate_targeted_identity(target.as_ref())?;

        let new_node_id = new_identity.node_id().clone();

        // Export the identity data so we can create a copy for the caller
        let identity_data = new_identity.export();

        // Update persistent state
        {
            let mut state = self.persistent_state.write();
            state.total_regeneration_attempts += 1;
        }

        // Emit identity changed event (success TBD by network acceptance)
        let _ = self.event_tx.send(IdentitySystemEvent::IdentityChanged {
            old_node_id,
            new_node_id: new_node_id.clone(),
            succeeded: true, // Will be updated by record_regeneration_result
        });

        // Update current identity (move, not clone - NodeIdentity contains secret keys)
        *self.current_identity.write() = new_identity;

        // Import the identity data to create a copy for the caller
        let return_identity = NodeIdentity::import(&identity_data)?;

        Ok(return_identity)
    }

    /// Record the result of a regeneration attempt.
    pub fn record_regeneration_result(&self, new_node_id: &NodeId, succeeded: bool) {
        self.regeneration_trigger
            .record_result(new_node_id.clone(), succeeded);

        let mut state = self.persistent_state.write();
        if succeeded {
            state.successful_regenerations += 1;
            state.consecutive_failures = 0;
        } else {
            state.consecutive_failures += 1;

            // Record as rejected for targeting
            self.identity_targeter
                .record_rejected_node_id(new_node_id.clone());
        }
    }

    /// Request a full restart with the current identity.
    pub fn request_restart(&self, reason: impl Into<String>) -> Result<()> {
        let new_node_id = self.current_node_id();

        let _ = self.event_tx.send(IdentitySystemEvent::RestartRequested {
            reason: reason.into(),
            new_identity: new_node_id,
        });

        // Persist state before restart
        self.save_state()?;

        Ok(())
    }

    /// Subscribe to system events.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<IdentitySystemEvent> {
        self.event_tx.subscribe()
    }

    /// Start the fitness monitoring background task.
    pub fn start_monitoring(self: &Arc<Self>) -> JoinHandle<()> {
        let manager = Arc::clone(self);
        *manager.monitoring_active.write() = true;

        let _ = manager.event_tx.send(IdentitySystemEvent::MonitoringStarted);

        tokio::spawn(async move {
            let mut last_verdict = FitnessVerdict::Healthy;
            let interval = manager.config.fitness.evaluation_interval;

            while *manager.monitoring_active.read() {
                tokio::time::sleep(interval).await;

                if !*manager.monitoring_active.read() {
                    break;
                }

                // Evaluate fitness
                let metrics = manager.fitness_monitor.evaluate();

                // Check for verdict change
                if metrics.verdict != last_verdict {
                    let _ = manager.event_tx.send(IdentitySystemEvent::FitnessChanged {
                        previous: last_verdict,
                        current: metrics.verdict,
                        metrics: metrics.clone(),
                    });
                    last_verdict = metrics.verdict;
                }

                // Check if regeneration is needed
                if metrics.verdict.should_regenerate() {
                    let decision = manager.check_regeneration();
                    if decision.should_proceed() {
                        let reason = RegenerationReason::FitnessCheck(metrics.verdict);
                        if let Err(e) = manager.regenerate(reason) {
                            tracing::warn!("Automatic regeneration failed: {}", e);
                        }
                    }
                }
            }

            let _ = manager.event_tx.send(IdentitySystemEvent::MonitoringStopped {
                reason: "normal shutdown".to_string(),
            });
        })
    }

    /// Stop the monitoring task.
    pub fn stop_monitoring(&self) {
        *self.monitoring_active.write() = false;
    }

    /// Check if monitoring is active.
    #[must_use]
    pub fn is_monitoring(&self) -> bool {
        *self.monitoring_active.read()
    }

    /// Save state to disk.
    pub fn save_state(&self) -> Result<()> {
        let state = self.persistent_state.read().clone();

        // Ensure parent directory exists
        if let Some(parent) = self.config.state_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                crate::P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                    format!("Failed to create state directory: {}", e).into(),
                ))
            })?;
        }

        let json = serde_json::to_string_pretty(&state).map_err(|e| {
            crate::P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                format!("Failed to serialize state: {}", e).into(),
            ))
        })?;

        std::fs::write(&self.config.state_path, json).map_err(|e| {
            crate::P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                format!("Failed to write state file: {}", e).into(),
            ))
        })?;

        let _ = self.event_tx.send(IdentitySystemEvent::StatePersisted {
            path: self.config.state_path.clone(),
        });

        Ok(())
    }

    /// Load state from disk.
    pub fn load_state(&self) -> Result<()> {
        if !self.config.state_path.exists() {
            return Err(crate::P2PError::Identity(
                crate::error::IdentityError::InvalidFormat("No state file exists".into()),
            ));
        }

        let json = std::fs::read_to_string(&self.config.state_path).map_err(|e| {
            crate::P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                format!("Failed to read state file: {}", e).into(),
            ))
        })?;

        let state: PersistentState = serde_json::from_str(&json).map_err(|e| {
            crate::P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                format!("Failed to deserialize state: {}", e).into(),
            ))
        })?;

        // Version migration would go here if needed
        if state.version != PersistentState::CURRENT_VERSION {
            tracing::warn!(
                "State version mismatch: {} vs {}",
                state.version,
                PersistentState::CURRENT_VERSION
            );
        }

        // Apply state to components
        for prefix in &state.rejected_prefixes {
            self.identity_targeter
                .add_rejected_prefix(prefix.clone(), 8);
        }

        if let Some(target) = &state.last_target {
            self.identity_targeter.set_target(Some(target.clone()));
        }

        *self.persistent_state.write() = state;

        let _ = self.event_tx.send(IdentitySystemEvent::StateLoaded {
            path: self.config.state_path.clone(),
        });

        Ok(())
    }

    /// Get a status summary.
    #[must_use]
    pub fn status_summary(&self) -> RestartManagerStatus {
        let metrics = self.get_fitness();
        let state = self.persistent_state.read();

        RestartManagerStatus {
            node_id: self.current_node_id(),
            fitness_verdict: metrics.verdict,
            overall_fitness_score: metrics.overall_score(),
            monitoring_active: self.is_monitoring(),
            consecutive_failures: state.consecutive_failures,
            total_regeneration_attempts: state.total_regeneration_attempts,
            successful_regenerations: state.successful_regenerations,
            rejected_prefix_count: self.identity_targeter.rejected_prefix_count(),
            circuit_breaker_open: self.regeneration_trigger.is_circuit_open(),
        }
    }
}

impl Drop for RestartManager {
    fn drop(&mut self) {
        if self.config.persist_on_shutdown
            && let Err(e) = self.save_state()
        {
            tracing::warn!("Failed to persist state on shutdown: {}", e);
        }
    }
}

/// Status summary for the restart manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartManagerStatus {
    /// Current node ID.
    pub node_id: NodeId,

    /// Current fitness verdict.
    pub fitness_verdict: FitnessVerdict,

    /// Overall fitness score (0.0 to 1.0).
    pub overall_fitness_score: f64,

    /// Whether monitoring is active.
    pub monitoring_active: bool,

    /// Number of consecutive failures.
    pub consecutive_failures: u32,

    /// Total regeneration attempts.
    pub total_regeneration_attempts: u64,

    /// Successful regenerations.
    pub successful_regenerations: u64,

    /// Number of rejected prefixes.
    pub rejected_prefix_count: usize,

    /// Whether circuit breaker is open.
    pub circuit_breaker_open: bool,
}

impl RestartManagerStatus {
    /// Calculate regeneration success rate.
    #[must_use]
    pub fn regeneration_success_rate(&self) -> f64 {
        if self.total_regeneration_attempts == 0 {
            1.0
        } else {
            self.successful_regenerations as f64 / self.total_regeneration_attempts as f64
        }
    }

    /// Check if system is healthy overall.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.fitness_verdict == FitnessVerdict::Healthy
            && !self.circuit_breaker_open
            && self.consecutive_failures < 3
    }
}

/// Builder for RestartManager with custom configuration.
pub struct RestartManagerBuilder {
    config: RestartConfig,
    identity: Option<NodeIdentity>,
}

impl RestartManagerBuilder {
    /// Create a new builder with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: RestartConfig::default(),
            identity: None,
        }
    }

    /// Set the node identity.
    #[must_use]
    pub fn identity(mut self, identity: NodeIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Set the state persistence path.
    #[must_use]
    pub fn state_path(mut self, path: PathBuf) -> Self {
        self.config.state_path = path;
        self
    }

    /// Set fitness monitoring configuration.
    #[must_use]
    pub fn fitness_config(mut self, config: FitnessConfig) -> Self {
        self.config.fitness = config;
        self
    }

    /// Set regeneration trigger configuration.
    #[must_use]
    pub fn regeneration_config(mut self, config: RegenerationConfig) -> Self {
        self.config.regeneration = config;
        self
    }

    /// Set identity targeting configuration.
    #[must_use]
    pub fn targeting_config(mut self, config: TargetingConfig) -> Self {
        self.config.targeting = config;
        self
    }

    /// Set whether to auto-start monitoring.
    #[must_use]
    pub fn auto_start_monitoring(mut self, auto_start: bool) -> Self {
        self.config.auto_start_monitoring = auto_start;
        self
    }

    /// Set event channel capacity.
    #[must_use]
    pub fn event_channel_capacity(mut self, capacity: usize) -> Self {
        self.config.event_channel_capacity = capacity;
        self
    }

    /// Build the restart manager.
    ///
    /// # Errors
    ///
    /// Returns an error if identity was not set.
    pub fn build(self) -> Result<Arc<RestartManager>> {
        let identity = self.identity.ok_or_else(|| {
            crate::P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                "Identity must be set before building".into(),
            ))
        })?;

        RestartManager::new(self.config, identity)
    }
}

impl Default for RestartManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_identity() -> NodeIdentity {
        NodeIdentity::generate().unwrap()
    }

    #[test]
    fn test_restart_manager_creation() {
        let config = RestartConfig::default();
        let identity = test_identity();

        let manager = RestartManager::new(config, identity);
        assert!(manager.is_ok());

        let manager = manager.unwrap();
        assert!(!manager.is_monitoring());
    }

    #[test]
    fn test_get_fitness() {
        let config = RestartConfig::default();
        let identity = test_identity();
        let manager = RestartManager::new(config, identity).unwrap();

        let metrics = manager.get_fitness();
        assert_eq!(metrics.verdict, FitnessVerdict::Healthy);
    }

    #[test]
    fn test_handle_rejection() {
        let config = RestartConfig::default();
        let identity = test_identity();
        let manager = RestartManager::new(config, identity).unwrap();

        let rejection =
            RejectionInfo::new(super::super::rejection::RejectionReason::KeyspaceSaturation);

        let decision = manager.handle_rejection(rejection);
        assert!(decision.should_proceed());
    }

    #[test]
    fn test_regenerate() {
        let config = RestartConfig::default();
        let identity = test_identity();
        let old_node_id = identity.node_id().clone();
        let manager = RestartManager::new(config, identity).unwrap();

        let new_identity = manager.regenerate(RegenerationReason::Manual);
        assert!(new_identity.is_ok());

        // Node ID should have changed
        let new_node_id = manager.current_node_id();
        assert_ne!(old_node_id, new_node_id);
    }

    #[test]
    fn test_state_persistence() {
        let temp_dir = tempdir().unwrap();
        let state_path = temp_dir.path().join("test_state.json");

        let mut config = RestartConfig::default();
        config.state_path = state_path.clone();

        let identity = test_identity();
        let manager = RestartManager::new(config, identity).unwrap();

        // Save state
        let result = manager.save_state();
        assert!(result.is_ok());
        assert!(state_path.exists());

        // Load state
        let result = manager.load_state();
        assert!(result.is_ok());
    }

    #[test]
    fn test_status_summary() {
        let config = RestartConfig::default();
        let identity = test_identity();
        let manager = RestartManager::new(config, identity).unwrap();

        let status = manager.status_summary();
        assert_eq!(status.fitness_verdict, FitnessVerdict::Healthy);
        assert!(!status.monitoring_active);
        assert!(status.is_healthy());
    }

    #[test]
    fn test_subscribe() {
        let config = RestartConfig::default();
        let identity = test_identity();
        let manager = RestartManager::new(config, identity).unwrap();

        let _rx = manager.subscribe();
        // Just verify we can subscribe
    }

    #[test]
    fn test_builder() {
        let temp_dir = tempdir().unwrap();
        let state_path = temp_dir.path().join("test_state.json");

        let manager = RestartManagerBuilder::new()
            .identity(test_identity())
            .state_path(state_path)
            .auto_start_monitoring(false)
            .event_channel_capacity(50)
            .build();

        assert!(manager.is_ok());
    }

    #[test]
    fn test_builder_missing_identity() {
        let manager = RestartManagerBuilder::new().build();
        assert!(manager.is_err());
    }

    #[test]
    fn test_persistent_state() {
        let mut state = PersistentState::new();
        assert_eq!(state.version, PersistentState::CURRENT_VERSION);

        state.consecutive_failures = 3;
        state.total_regeneration_attempts = 10;
        state.successful_regenerations = 7;

        // Serialize and deserialize
        let json = serde_json::to_string(&state).unwrap();
        let restored: PersistentState = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.consecutive_failures, 3);
        assert_eq!(restored.total_regeneration_attempts, 10);
        assert_eq!(restored.successful_regenerations, 7);
    }

    #[test]
    fn test_restart_manager_status_is_healthy() {
        let status = RestartManagerStatus {
            node_id: NodeId([0; 32]),
            fitness_verdict: FitnessVerdict::Healthy,
            overall_fitness_score: 0.95,
            monitoring_active: true,
            consecutive_failures: 0,
            total_regeneration_attempts: 5,
            successful_regenerations: 5,
            rejected_prefix_count: 0,
            circuit_breaker_open: false,
        };

        assert!(status.is_healthy());
        assert!((status.regeneration_success_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_restart_manager_status_unhealthy() {
        let status = RestartManagerStatus {
            node_id: NodeId([0; 32]),
            fitness_verdict: FitnessVerdict::Unfit,
            overall_fitness_score: 0.3,
            monitoring_active: true,
            consecutive_failures: 5,
            total_regeneration_attempts: 10,
            successful_regenerations: 5,
            rejected_prefix_count: 3,
            circuit_breaker_open: true,
        };

        assert!(!status.is_healthy());
        assert!((status.regeneration_success_rate() - 0.5).abs() < f64::EPSILON);
    }
}
