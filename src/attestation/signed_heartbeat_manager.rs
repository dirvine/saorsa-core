// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Signed Heartbeat Manager for lightweight liveness proofs.
//!
//! This module provides a simplified heartbeat system using ML-DSA signatures
//! instead of VDF proofs. It's designed for:
//! - Resource-constrained devices (Raspberry Pi, etc.)
//! - Multi-node-per-device deployments
//! - Networks where EntangledId binding provides software integrity
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                  SignedHeartbeatManager                         │
//! │                                                                 │
//! │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
//! │  │ HeartbeatSigner │  │ PeerTracker     │  │ GossipPublisher │ │
//! │  │ (sign/verify)   │  │ (track peers)   │  │ (propagate)     │ │
//! │  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘ │
//! │           │                    │                    │          │
//! │           └────────────────────┴────────────────────┘          │
//! │                              │                                  │
//! │  ┌───────────────────────────┴───────────────────────────────┐ │
//! │  │                    Epoch Scheduler                        │ │
//! │  │  (triggers heartbeats at interval_secs)                   │ │
//! │  └───────────────────────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use super::network_resilience::{
    HeartbeatAction, HeartbeatDecisionEngine, HealthyRatioTracker, NetworkHealthContext,
    PersistedNetworkState, PersistedPeerState, QuiescenceDetector, RecoveryHandler,
    ResilienceConfig,
};
use super::signed_heartbeat::{HeartbeatConfig, HeartbeatSigner, HeartbeatVerifyResult, SignedHeartbeat};
use super::AttestationError;
use crate::quantum_crypto::ant_quic_integration::MlDsaPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Gossip topic for signed heartbeats.
pub const SIGNED_HEARTBEAT_GOSSIP_TOPIC: &str = "saorsa/heartbeat/v2";

/// Maximum heartbeat proofs to cache per peer.
const MAX_CACHED_EPOCHS_PER_PEER: usize = 3;

// ============================================================================
// Heartbeat Message Types
// ============================================================================

/// A signed heartbeat gossiped to the network.
///
/// This wraps a `SignedHeartbeat` with the peer's public key for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHeartbeatMessage {
    /// The signed heartbeat.
    pub heartbeat: SignedHeartbeat,

    /// The sender's ML-DSA-65 public key (for verification).
    pub public_key: Vec<u8>,
}

impl SignedHeartbeatMessage {
    /// Create a new signed heartbeat message.
    pub fn new(heartbeat: SignedHeartbeat, public_key: &[u8]) -> Self {
        Self {
            heartbeat,
            public_key: public_key.to_vec(),
        }
    }
}

/// Heartbeat exchange during handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHeartbeatHello {
    /// Current epoch number.
    pub current_epoch: u64,

    /// Latest heartbeat (if available).
    pub latest_heartbeat: Option<SignedHeartbeatMessage>,

    /// Number of consecutive successful heartbeats.
    pub streak: u32,
}

impl Default for SignedHeartbeatHello {
    fn default() -> Self {
        Self {
            current_epoch: current_epoch(HeartbeatConfig::default().interval_secs),
            latest_heartbeat: None,
            streak: 0,
        }
    }
}

// ============================================================================
// Peer Heartbeat Tracking
// ============================================================================

/// Tracked heartbeat state for a peer.
#[derive(Debug, Clone, Default)]
pub struct SignedPeerHeartbeatState {
    /// The peer's EntangledId.
    pub entangled_id: Option<[u8; 32]>,

    /// The peer's public key (for verification).
    pub public_key: Option<Vec<u8>>,

    /// Last verified epoch.
    pub last_verified_epoch: u64,

    /// Number of consecutive successful heartbeats.
    pub streak: u32,

    /// Number of missed heartbeats.
    pub missed_count: u32,

    /// Total verified heartbeats.
    pub total_verified: u64,

    /// Recent epochs (for deduplication).
    pub recent_epochs: Vec<u64>,

    /// Current status.
    pub status: SignedPeerStatus,
}

/// Peer heartbeat status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SignedPeerStatus {
    /// Unknown - no heartbeats received yet.
    #[default]
    Unknown,

    /// Healthy - recent valid heartbeats.
    Healthy,

    /// Suspect - missed some heartbeats.
    Suspect,

    /// Unresponsive - too many missed heartbeats.
    Unresponsive,
}

impl SignedPeerHeartbeatState {
    /// Create new state for a peer.
    #[must_use]
    pub fn new(entangled_id: [u8; 32], public_key: Vec<u8>) -> Self {
        Self {
            entangled_id: Some(entangled_id),
            public_key: Some(public_key),
            ..Default::default()
        }
    }

    /// Record a successful heartbeat verification.
    pub fn record_success(&mut self, epoch: u64) {
        self.last_verified_epoch = epoch;
        self.streak += 1;
        self.total_verified += 1;
        self.missed_count = 0;
        self.status = SignedPeerStatus::Healthy;

        // Track recent epochs for deduplication
        self.recent_epochs.push(epoch);
        if self.recent_epochs.len() > MAX_CACHED_EPOCHS_PER_PEER {
            self.recent_epochs.remove(0);
        }
    }

    /// Record a missed heartbeat.
    pub fn record_miss(&mut self, config: &HeartbeatConfig) {
        self.missed_count += 1;
        self.streak = 0;

        if self.missed_count >= config.eviction_threshold {
            self.status = SignedPeerStatus::Unresponsive;
        } else if self.missed_count >= config.suspect_threshold {
            self.status = SignedPeerStatus::Suspect;
        }
    }

    /// Check if we've already seen a heartbeat for this epoch.
    #[must_use]
    pub fn has_heartbeat_for_epoch(&self, epoch: u64) -> bool {
        self.recent_epochs.contains(&epoch)
    }
}

// ============================================================================
// Heartbeat Manager
// ============================================================================

/// Manager for coordinating signed heartbeats.
///
/// This is a lightweight alternative to VDF-based heartbeats, suitable for
/// resource-constrained devices and multi-node deployments.
///
/// ## Network Resilience
///
/// The manager includes built-in network resilience to handle:
/// - Startup grace periods (don't penalize peers on our startup)
/// - Network partitions (detect sudden drops, freeze status)
/// - Our own connectivity issues (don't blame peers when we're offline)
/// - Network quiescence (preserve state when entire network is silent)
pub struct SignedHeartbeatManager {
    /// Heartbeat signer for generating signed heartbeats.
    signer: HeartbeatSigner,

    /// Configuration.
    config: HeartbeatConfig,

    /// Our latest heartbeat.
    latest_heartbeat: Arc<RwLock<Option<SignedHeartbeatMessage>>>,

    /// Peer heartbeat states.
    peer_states: Arc<RwLock<HashMap<[u8; 32], SignedPeerHeartbeatState>>>,

    /// Consecutive successful heartbeats (streak).
    streak: Arc<RwLock<u32>>,

    /// Total heartbeats generated.
    total_generated: Arc<RwLock<u64>>,

    // === Network Resilience ===
    /// Decision engine for handling network disruptions.
    decision_engine: HeartbeatDecisionEngine,

    /// Quiescence detector.
    quiescence_detector: Arc<RwLock<QuiescenceDetector>>,

    /// Recovery handler for startup/restart.
    recovery_handler: RecoveryHandler,

    /// Healthy ratio tracker for trend detection.
    ratio_tracker: Arc<RwLock<HealthyRatioTracker>>,

    /// External connectivity status (set externally).
    external_connectivity: Arc<RwLock<bool>>,

    /// Bootstrap nodes reachable (set externally).
    bootstrap_nodes_reachable: Arc<RwLock<usize>>,

    /// Gossip mesh size (set externally).
    gossip_mesh_size: Arc<RwLock<usize>>,

    /// When we entered disruption mode (if at all).
    disruption_started: Arc<RwLock<Option<Instant>>>,
}

impl SignedHeartbeatManager {
    /// Create a new signed heartbeat manager.
    pub fn new(signer: HeartbeatSigner, config: HeartbeatConfig) -> Self {
        Self::with_resilience(signer, config, ResilienceConfig::default())
    }

    /// Create a new manager with custom resilience configuration.
    pub fn with_resilience(
        signer: HeartbeatSigner,
        config: HeartbeatConfig,
        resilience_config: ResilienceConfig,
    ) -> Self {
        Self {
            signer,
            config,
            latest_heartbeat: Arc::new(RwLock::new(None)),
            peer_states: Arc::new(RwLock::new(HashMap::new())),
            streak: Arc::new(RwLock::new(0)),
            total_generated: Arc::new(RwLock::new(0)),
            decision_engine: HeartbeatDecisionEngine::new(resilience_config.clone()),
            quiescence_detector: Arc::new(RwLock::new(QuiescenceDetector::new(
                resilience_config.clone(),
            ))),
            recovery_handler: RecoveryHandler::new(resilience_config),
            ratio_tracker: Arc::new(RwLock::new(HealthyRatioTracker::new(10))),
            external_connectivity: Arc::new(RwLock::new(true)),
            bootstrap_nodes_reachable: Arc::new(RwLock::new(0)),
            gossip_mesh_size: Arc::new(RwLock::new(0)),
            disruption_started: Arc::new(RwLock::new(None)),
        }
    }

    /// Create from persisted state (for recovery after restart).
    pub fn from_persisted(
        signer: HeartbeatSigner,
        config: HeartbeatConfig,
        mut persisted: PersistedNetworkState,
    ) -> Self {
        let resilience_config = ResilienceConfig::default();

        // Get values before consuming peer_states
        let downtime = persisted.downtime_secs();
        let peer_count = persisted.peer_states.len();

        // Take peer states out of persisted (so persisted can be moved to recovery_handler)
        let persisted_peer_states = std::mem::take(&mut persisted.peer_states);

        // Restore peer states from persisted data
        let mut peer_states = HashMap::new();
        for (id, state) in persisted_peer_states {
            peer_states.insert(
                id,
                SignedPeerHeartbeatState {
                    entangled_id: Some(state.entangled_id),
                    public_key: Some(state.public_key),
                    last_verified_epoch: state.last_heartbeat_epoch,
                    streak: state.streak,
                    status: state.last_known_status,
                    ..Default::default()
                },
            );
        }

        tracing::info!(
            peers = peer_count,
            downtime_secs = downtime,
            "Restoring SignedHeartbeatManager from persisted state"
        );

        Self {
            signer,
            config,
            latest_heartbeat: Arc::new(RwLock::new(None)),
            peer_states: Arc::new(RwLock::new(peer_states)),
            streak: Arc::new(RwLock::new(0)),
            total_generated: Arc::new(RwLock::new(0)),
            decision_engine: HeartbeatDecisionEngine::new(resilience_config.clone()),
            quiescence_detector: Arc::new(RwLock::new(QuiescenceDetector::new(
                resilience_config.clone(),
            ))),
            recovery_handler: RecoveryHandler::from_persisted(persisted, resilience_config),
            ratio_tracker: Arc::new(RwLock::new(HealthyRatioTracker::new(10))),
            external_connectivity: Arc::new(RwLock::new(true)),
            bootstrap_nodes_reachable: Arc::new(RwLock::new(0)),
            gossip_mesh_size: Arc::new(RwLock::new(0)),
            disruption_started: Arc::new(RwLock::new(None)),
        }
    }

    /// Get our EntangledId.
    #[must_use]
    pub fn entangled_id(&self) -> &[u8; 32] {
        self.signer.entangled_id()
    }

    /// Get our public key bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        self.signer.public_key_bytes()
    }

    /// Get current epoch number.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        current_epoch(self.config.interval_secs)
    }

    /// Generate a heartbeat for the current epoch.
    ///
    /// This is fast - just a signature operation.
    pub async fn generate_heartbeat(&mut self) -> Result<SignedHeartbeatMessage, AttestationError> {
        let heartbeat = self.signer.create_heartbeat()?;
        let public_key_bytes = self.signer.public_key_bytes().to_vec();

        // Update streak
        {
            let mut streak = self.streak.write().await;
            *streak += 1;
        }

        // Update total
        {
            let mut total = self.total_generated.write().await;
            *total += 1;
        }

        let message = SignedHeartbeatMessage::new(heartbeat, &public_key_bytes);

        // Cache latest
        {
            let mut latest = self.latest_heartbeat.write().await;
            *latest = Some(message.clone());
        }

        tracing::info!(
            epoch = message.heartbeat.epoch,
            entangled_id = %hex::encode(&self.signer.entangled_id()[..8]),
            "Generated signed heartbeat"
        );

        Ok(message)
    }

    /// Verify a heartbeat message from a peer.
    pub async fn verify_message(
        &self,
        message: &SignedHeartbeatMessage,
    ) -> Result<HeartbeatVerifyResult, AttestationError> {
        // Check if we've already processed this
        {
            let states = self.peer_states.read().await;
            let already_seen = states
                .get(&message.heartbeat.entangled_id)
                .is_some_and(|state| state.has_heartbeat_for_epoch(message.heartbeat.epoch));

            if already_seen {
                tracing::debug!(
                    epoch = message.heartbeat.epoch,
                    "Duplicate heartbeat, skipping"
                );
                return Ok(HeartbeatVerifyResult::Valid);
            }
        }

        // Verify the signature using the provided public key
        let result = message
            .heartbeat
            .verify_from_bytes(&message.public_key, &self.config)?;

        // Update peer state if valid
        if result.is_valid() {
            let mut states = self.peer_states.write().await;
            let state = states
                .entry(message.heartbeat.entangled_id)
                .or_insert_with(|| {
                    SignedPeerHeartbeatState::new(
                        message.heartbeat.entangled_id,
                        message.public_key.clone(),
                    )
                });
            state.record_success(message.heartbeat.epoch);

            tracing::debug!(
                epoch = message.heartbeat.epoch,
                peer = %hex::encode(&message.heartbeat.entangled_id[..8]),
                streak = state.streak,
                "Verified peer signed heartbeat"
            );
        }

        Ok(result)
    }

    /// Verify a heartbeat with a known public key.
    ///
    /// Use this when you already have the peer's public key cached.
    pub fn verify_with_key(
        &self,
        heartbeat: &SignedHeartbeat,
        public_key: &MlDsaPublicKey,
    ) -> Result<HeartbeatVerifyResult, AttestationError> {
        heartbeat.verify(public_key, &self.config)
    }

    /// Create a HeartbeatHello for handshake exchange.
    pub async fn create_hello(&self) -> SignedHeartbeatHello {
        let latest = self.latest_heartbeat.read().await;
        let streak = *self.streak.read().await;

        SignedHeartbeatHello {
            current_epoch: self.current_epoch(),
            latest_heartbeat: latest.clone(),
            streak,
        }
    }

    /// Process a HeartbeatHello from a peer during handshake.
    pub async fn process_hello(
        &self,
        hello: &SignedHeartbeatHello,
    ) -> Result<SignedPeerStatus, AttestationError> {
        if let Some(ref message) = hello.latest_heartbeat {
            let result = self.verify_message(message).await?;

            if result.is_valid() {
                let states = self.peer_states.read().await;
                if let Some(state) = states.get(&message.heartbeat.entangled_id) {
                    return Ok(state.status);
                }
            }
        }

        Ok(SignedPeerStatus::Unknown)
    }

    /// Register a peer (for tracking before receiving heartbeats).
    pub async fn register_peer(&self, entangled_id: [u8; 32], public_key: Vec<u8>) {
        let mut states = self.peer_states.write().await;
        states
            .entry(entangled_id)
            .or_insert_with(|| SignedPeerHeartbeatState::new(entangled_id, public_key));
    }

    /// Check all peers for missed heartbeats with network resilience.
    ///
    /// Call this periodically (e.g., every epoch). The method uses the decision
    /// engine to determine the appropriate action based on network health context.
    ///
    /// Returns the action that was taken.
    pub async fn check_missed_heartbeats(&self) -> HeartbeatAction {
        let current = self.current_epoch();
        let mut states = self.peer_states.write().await;

        // Build health context
        let context = self.build_health_context(&states).await;

        // Update ratio tracker
        {
            let mut tracker = self.ratio_tracker.write().await;
            tracker.record(context.healthy_ratio_now);
        }

        // Decide action
        let action = self.decision_engine.decide(&context);

        // Update disruption tracking
        match action {
            HeartbeatAction::Freeze => {
                let mut started = self.disruption_started.write().await;
                if started.is_none() {
                    *started = Some(Instant::now());
                }
            }
            HeartbeatAction::Normal => {
                let mut started = self.disruption_started.write().await;
                *started = None;
            }
            _ => {}
        }

        // Check quiescence
        {
            let mut detector = self.quiescence_detector.write().await;
            if detector.check_quiescence(&context) {
                tracing::info!("Network is quiescent, preserving peer state");
                return HeartbeatAction::Freeze;
            }
        }

        // Apply action
        match action {
            HeartbeatAction::Normal => {
                // Normal processing - check for missed heartbeats
                for (peer_id, state) in states.iter_mut() {
                    if state.last_verified_epoch < current.saturating_sub(1) {
                        state.record_miss(&self.config);

                        if state.status == SignedPeerStatus::Suspect {
                            tracing::warn!(
                                peer = %hex::encode(&peer_id[..8]),
                                missed = state.missed_count,
                                "Peer marked as suspect"
                            );
                        } else if state.status == SignedPeerStatus::Unresponsive {
                            tracing::warn!(
                                peer = %hex::encode(&peer_id[..8]),
                                missed = state.missed_count,
                                "Peer marked as unresponsive"
                            );
                        }
                    }
                }
            }
            HeartbeatAction::Grace => {
                tracing::debug!("Grace mode - not penalizing missed heartbeats");
                // Don't penalize, just log
            }
            HeartbeatAction::Freeze => {
                tracing::info!("Freeze mode - network disruption detected, preserving state");
                // Don't change anything
            }
            HeartbeatAction::Reconnect => {
                tracing::info!("Reconnect mode - recovering from downtime");
                // Reset all peers to Unknown to allow fresh start
                for state in states.values_mut() {
                    if state.status != SignedPeerStatus::Healthy {
                        state.status = SignedPeerStatus::Unknown;
                        state.missed_count = 0;
                    }
                }
            }
        }

        action
    }

    /// Build network health context from current state.
    async fn build_health_context(
        &self,
        states: &HashMap<[u8; 32], SignedPeerHeartbeatState>,
    ) -> NetworkHealthContext {
        let healthy = states
            .values()
            .filter(|s| s.status == SignedPeerStatus::Healthy)
            .count();
        let suspect = states
            .values()
            .filter(|s| s.status == SignedPeerStatus::Suspect)
            .count();
        let unresponsive = states
            .values()
            .filter(|s| s.status == SignedPeerStatus::Unresponsive)
            .count();
        let unknown = states
            .values()
            .filter(|s| s.status == SignedPeerStatus::Unknown)
            .count();

        let mut context = self
            .recovery_handler
            .build_context(healthy, suspect, unresponsive, unknown);

        // Add connectivity info
        context.external_connectivity = *self.external_connectivity.read().await;
        context.bootstrap_nodes_reachable = *self.bootstrap_nodes_reachable.read().await;
        context.gossip_mesh_size = *self.gossip_mesh_size.read().await;
        context.disruption_started = *self.disruption_started.read().await;

        // Add ratio history
        {
            let tracker = self.ratio_tracker.read().await;
            tracker.populate_context(&mut context);
        }

        context
    }

    // === Connectivity setters (called by network layer) ===

    /// Update external connectivity status.
    pub async fn set_external_connectivity(&self, connected: bool) {
        let mut conn = self.external_connectivity.write().await;
        *conn = connected;
    }

    /// Update bootstrap nodes reachable count.
    pub async fn set_bootstrap_nodes_reachable(&self, count: usize) {
        let mut nodes = self.bootstrap_nodes_reachable.write().await;
        *nodes = count;
    }

    /// Update gossip mesh size.
    pub async fn set_gossip_mesh_size(&self, size: usize) {
        let mut mesh = self.gossip_mesh_size.write().await;
        *mesh = size;

        // Record activity when mesh is healthy
        if size > 0 {
            let mut detector = self.quiescence_detector.write().await;
            detector.record_activity();
        }
    }

    /// Check if we're in startup grace period.
    #[must_use]
    pub fn in_grace_period(&self) -> bool {
        self.recovery_handler.in_grace_period()
    }

    /// Check if network appears quiescent.
    pub async fn is_quiescent(&self) -> bool {
        self.quiescence_detector.read().await.is_quiescent()
    }

    /// Get the status of a peer.
    pub async fn get_peer_status(&self, entangled_id: &[u8; 32]) -> Option<SignedPeerHeartbeatState> {
        let states = self.peer_states.read().await;
        states.get(entangled_id).cloned()
    }

    /// Get all peers with a specific status.
    pub async fn get_peers_by_status(&self, status: SignedPeerStatus) -> Vec<[u8; 32]> {
        let states = self.peer_states.read().await;
        states
            .iter()
            .filter(|(_, s)| s.status == status)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get heartbeat statistics.
    pub async fn get_stats(&self) -> SignedHeartbeatStats {
        let states = self.peer_states.read().await;
        let streak = *self.streak.read().await;
        let total = *self.total_generated.read().await;

        let healthy = states
            .values()
            .filter(|s| s.status == SignedPeerStatus::Healthy)
            .count();
        let suspect = states
            .values()
            .filter(|s| s.status == SignedPeerStatus::Suspect)
            .count();
        let unresponsive = states
            .values()
            .filter(|s| s.status == SignedPeerStatus::Unresponsive)
            .count();

        SignedHeartbeatStats {
            current_epoch: self.current_epoch(),
            local_streak: streak,
            local_total_generated: total,
            peer_count: states.len(),
            healthy_peers: healthy,
            suspect_peers: suspect,
            unresponsive_peers: unresponsive,
        }
    }

    /// Create persisted state for graceful shutdown.
    ///
    /// Call this before shutdown to preserve peer state across restarts.
    pub async fn create_persisted_state(&self) -> PersistedNetworkState {
        let states = self.peer_states.read().await;

        let mut persisted_peers = std::collections::HashMap::new();
        for (id, state) in states.iter() {
            if let (Some(entangled_id), Some(public_key)) =
                (state.entangled_id, state.public_key.clone())
            {
                persisted_peers.insert(
                    *id,
                    PersistedPeerState {
                        entangled_id,
                        public_key,
                        last_heartbeat_epoch: state.last_verified_epoch,
                        streak: state.streak,
                        last_known_status: state.status,
                    },
                );
            }
        }

        let mut persisted = PersistedNetworkState {
            peer_states: persisted_peers,
            ..Default::default()
        };

        // Mark as graceful shutdown
        persisted.prepare_shutdown();

        tracing::info!(
            peers = persisted.peer_states.len(),
            "Created persisted network state for shutdown"
        );

        persisted
    }

    /// Serialize a heartbeat message for gossip.
    pub fn serialize_message(
        message: &SignedHeartbeatMessage,
    ) -> Result<Vec<u8>, AttestationError> {
        serde_cbor::to_vec(message).map_err(|e| {
            AttestationError::SerializationError(format!("Failed to serialize heartbeat: {}", e))
        })
    }

    /// Deserialize a heartbeat message from gossip.
    pub fn deserialize_message(data: &[u8]) -> Result<SignedHeartbeatMessage, AttestationError> {
        serde_cbor::from_slice(data).map_err(|e| {
            AttestationError::SerializationError(format!("Failed to deserialize heartbeat: {}", e))
        })
    }

    /// Handle an incoming heartbeat from gossip.
    ///
    /// Returns true if the heartbeat was valid and should be forwarded.
    pub async fn handle_gossip_heartbeat(&self, data: &[u8]) -> Result<bool, AttestationError> {
        let message = Self::deserialize_message(data)?;

        // Don't process our own heartbeats
        if message.heartbeat.entangled_id == *self.signer.entangled_id() {
            return Ok(false);
        }

        // Verify the message
        let result = self.verify_message(&message).await?;

        if result.is_valid() {
            tracing::debug!(
                peer = %hex::encode(&message.heartbeat.entangled_id[..8]),
                epoch = message.heartbeat.epoch,
                "Valid signed heartbeat received via gossip"
            );

            Ok(true) // Forward to other peers
        } else {
            tracing::warn!(
                peer = %hex::encode(&message.heartbeat.entangled_id[..8]),
                epoch = message.heartbeat.epoch,
                result = ?result,
                "Invalid signed heartbeat received via gossip"
            );

            Ok(false) // Don't forward invalid heartbeats
        }
    }
}

/// Signed heartbeat statistics.
#[derive(Debug, Clone, Default)]
pub struct SignedHeartbeatStats {
    /// Current epoch number.
    pub current_epoch: u64,

    /// Our consecutive successful heartbeats.
    pub local_streak: u32,

    /// Total heartbeats we've generated.
    pub local_total_generated: u64,

    /// Number of tracked peers.
    pub peer_count: usize,

    /// Healthy peers.
    pub healthy_peers: usize,

    /// Suspect peers.
    pub suspect_peers: usize,

    /// Unresponsive peers.
    pub unresponsive_peers: usize,
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get current epoch number based on heartbeat interval.
#[must_use]
pub fn current_epoch(interval_secs: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now / interval_secs
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quantum_crypto::ant_quic_integration::generate_ml_dsa_keypair;

    fn create_test_signer(entangled_id: [u8; 32]) -> HeartbeatSigner {
        let (pk, sk) = generate_ml_dsa_keypair().expect("keygen");
        HeartbeatSigner::new(entangled_id, pk, sk)
    }

    #[tokio::test]
    async fn test_manager_creation() {
        let signer = create_test_signer([1u8; 32]);
        let config = HeartbeatConfig::fast();
        let manager = SignedHeartbeatManager::new(signer, config);

        assert_eq!(*manager.entangled_id(), [1u8; 32]);
    }

    #[tokio::test]
    async fn test_heartbeat_generation() {
        let signer = create_test_signer([1u8; 32]);
        let config = HeartbeatConfig::fast();
        let mut manager = SignedHeartbeatManager::new(signer, config);

        let message = manager.generate_heartbeat().await.expect("generate");

        assert_eq!(message.heartbeat.entangled_id, [1u8; 32]);
        assert!(!message.heartbeat.signature.is_empty());
        assert!(!message.public_key.is_empty());
    }

    #[tokio::test]
    async fn test_heartbeat_verification() {
        let signer1 = create_test_signer([1u8; 32]);
        let signer2 = create_test_signer([2u8; 32]);
        let config = HeartbeatConfig::fast();

        let mut manager1 = SignedHeartbeatManager::new(signer1, config.clone());
        let manager2 = SignedHeartbeatManager::new(signer2, config);

        // Generate heartbeat from manager1
        let message = manager1.generate_heartbeat().await.expect("generate");

        // Verify on manager2
        let result = manager2.verify_message(&message).await.expect("verify");

        assert!(result.is_valid());
    }

    #[tokio::test]
    async fn test_hello_exchange() {
        let signer1 = create_test_signer([1u8; 32]);
        let signer2 = create_test_signer([2u8; 32]);
        let config = HeartbeatConfig::fast();

        let mut manager1 = SignedHeartbeatManager::new(signer1, config.clone());
        let manager2 = SignedHeartbeatManager::new(signer2, config);

        // Generate heartbeat
        manager1.generate_heartbeat().await.expect("generate");

        // Create hello
        let hello = manager1.create_hello().await;
        assert!(hello.latest_heartbeat.is_some());
        assert_eq!(hello.streak, 1);

        // Process on manager2
        let status = manager2.process_hello(&hello).await.expect("process");

        assert_eq!(status, SignedPeerStatus::Healthy);
    }

    #[tokio::test]
    async fn test_duplicate_detection() {
        let signer1 = create_test_signer([1u8; 32]);
        let signer2 = create_test_signer([2u8; 32]);
        let config = HeartbeatConfig::fast();

        let mut manager1 = SignedHeartbeatManager::new(signer1, config.clone());
        let manager2 = SignedHeartbeatManager::new(signer2, config);

        // Generate heartbeat
        let message = manager1.generate_heartbeat().await.expect("generate");

        // Verify twice
        let result1 = manager2.verify_message(&message).await.expect("verify1");
        let result2 = manager2.verify_message(&message).await.expect("verify2");

        // Both should be valid (second is deduplicated)
        assert!(result1.is_valid());
        assert!(result2.is_valid());
    }

    #[tokio::test]
    async fn test_serialization() {
        let signer = create_test_signer([1u8; 32]);
        let config = HeartbeatConfig::fast();
        let mut manager = SignedHeartbeatManager::new(signer, config);

        let message = manager.generate_heartbeat().await.expect("generate");

        // Serialize and deserialize
        let bytes = SignedHeartbeatManager::serialize_message(&message).expect("serialize");
        let recovered = SignedHeartbeatManager::deserialize_message(&bytes).expect("deserialize");

        assert_eq!(recovered.heartbeat.entangled_id, message.heartbeat.entangled_id);
        assert_eq!(recovered.heartbeat.epoch, message.heartbeat.epoch);
        assert_eq!(recovered.public_key, message.public_key);
    }

    #[tokio::test]
    async fn test_stats() {
        let signer = create_test_signer([1u8; 32]);
        let config = HeartbeatConfig::fast();
        let mut manager = SignedHeartbeatManager::new(signer, config);

        // Generate a few heartbeats
        manager.generate_heartbeat().await.expect("gen1");
        manager.generate_heartbeat().await.expect("gen2");

        let stats = manager.get_stats().await;

        assert_eq!(stats.local_streak, 2);
        assert_eq!(stats.local_total_generated, 2);
    }

    // === Network Resilience Tests ===

    #[tokio::test]
    async fn test_grace_period_on_startup() {
        let signer = create_test_signer([1u8; 32]);
        let config = HeartbeatConfig::fast();
        let resilience_config = ResilienceConfig {
            startup_grace_secs: 300, // 5 minutes
            ..ResilienceConfig::fast()
        };
        let manager = SignedHeartbeatManager::with_resilience(signer, config, resilience_config);

        // Should be in grace period on startup
        assert!(manager.in_grace_period());

        // Checking missed heartbeats should return Grace action
        let action = manager.check_missed_heartbeats().await;
        assert_eq!(action, HeartbeatAction::Grace);
    }

    #[tokio::test]
    async fn test_connectivity_tracking() {
        let signer = create_test_signer([1u8; 32]);
        let config = HeartbeatConfig::fast();
        let resilience_config = ResilienceConfig {
            startup_grace_secs: 0, // No startup grace for this test
            ..ResilienceConfig::fast()
        };
        let manager = SignedHeartbeatManager::with_resilience(signer, config, resilience_config);

        // Initially connected
        manager.set_external_connectivity(true).await;
        manager.set_gossip_mesh_size(5).await;

        // Register some peers to reach min_peers_for_eviction
        for i in 0..5 {
            manager.register_peer([i; 32], vec![i; 100]).await;
        }

        // Should not be quiescent with active mesh
        assert!(!manager.is_quiescent().await);
    }

    #[tokio::test]
    async fn test_persistence_roundtrip() {
        let signer1 = create_test_signer([1u8; 32]);
        let config = HeartbeatConfig::fast();

        let mut manager1 = SignedHeartbeatManager::new(signer1, config.clone());

        // Generate heartbeat and receive from peer
        let _message = manager1.generate_heartbeat().await.expect("generate");
        manager1.register_peer([3u8; 32], vec![3u8; 100]).await;

        // Create persisted state
        let persisted = manager1.create_persisted_state().await;

        // Verify persistence data
        assert!(persisted.graceful_shutdown);

        // Serialize and deserialize
        let bytes = persisted.to_bytes().expect("serialize");
        let recovered = PersistedNetworkState::from_bytes(&bytes).expect("deserialize");

        // Create manager from recovered state
        let signer_recovered = create_test_signer([1u8; 32]);
        let manager2 = SignedHeartbeatManager::from_persisted(
            signer_recovered,
            config,
            recovered,
        );

        // Verify recovery - should start in grace period after restart
        assert!(manager2.in_grace_period());
    }

    #[tokio::test]
    async fn test_freeze_on_connectivity_loss() {
        let signer = create_test_signer([1u8; 32]);
        let config = HeartbeatConfig::fast();
        let resilience_config = ResilienceConfig {
            startup_grace_secs: 0,
            min_peers_for_eviction: 1,
            ..ResilienceConfig::fast()
        };
        let manager = SignedHeartbeatManager::with_resilience(signer, config, resilience_config);

        // Register peers
        manager.register_peer([2u8; 32], vec![2u8; 100]).await;

        // Simulate connectivity loss
        manager.set_external_connectivity(false).await;
        manager.set_bootstrap_nodes_reachable(0).await;
        manager.set_gossip_mesh_size(0).await;

        // Should freeze when we appear to be offline
        let action = manager.check_missed_heartbeats().await;
        assert_eq!(action, HeartbeatAction::Freeze);
    }
}
