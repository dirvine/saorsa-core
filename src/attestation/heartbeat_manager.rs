// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Heartbeat Manager for VDF-based liveness proofs.
//!
//! This module implements Phase 5 of the Entangled Attestation system:
//! coordination of VDF heartbeats across the network.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     HeartbeatManager                            │
//! │                                                                 │
//! │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
//! │  │ VdfHeartbeat    │  │ PeerTracker     │  │ GossipPublisher │ │
//! │  │ (solve/verify)  │  │ (track peers)   │  │ (propagate)     │ │
//! │  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘ │
//! │           │                    │                    │          │
//! │           └────────────────────┴────────────────────┘          │
//! │                              │                                  │
//! │  ┌───────────────────────────┴───────────────────────────────┐ │
//! │  │                    Epoch Scheduler                        │ │
//! │  │  (triggers challenges at heartbeat_interval)              │ │
//! │  └───────────────────────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Epoch-Based Heartbeats
//!
//! - Each epoch is `heartbeat_interval` seconds long
//! - Nodes must produce one VDF proof per epoch
//! - Proofs are gossiped to the network
//! - Missed heartbeats affect trust scores
//!
//! ## Integration Points
//!
//! - **Handshake**: Exchange latest heartbeat during connection
//! - **Gossip**: Propagate heartbeats on `saorsa/heartbeat/v1` topic
//! - **EigenTrust**: Update trust scores based on heartbeat compliance

use super::vdf::{
    HeartbeatChallenge, HeartbeatProof, HeartbeatVerificationResult,
    NodeHeartbeatStatus, VdfConfig, VdfHeartbeat,
};
use super::AttestationError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Gossip topic for heartbeat proofs.
pub const HEARTBEAT_GOSSIP_TOPIC: &str = "saorsa/heartbeat/v1";

/// Maximum heartbeat proofs to cache per peer.
const MAX_CACHED_PROOFS_PER_PEER: usize = 3;

// ============================================================================
// Heartbeat Message Types
// ============================================================================

/// A heartbeat announcement gossiped to the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatAnnouncement {
    /// The sender's EntangledId.
    pub entangled_id: [u8; 32],

    /// The challenge this heartbeat responds to.
    pub challenge: HeartbeatChallenge,

    /// The VDF proof.
    pub proof: HeartbeatProof,

    /// Signature over (entangled_id || challenge || proof_hash) using ML-DSA.
    /// This prevents replay attacks and proves ownership.
    pub signature: Vec<u8>,
}

impl HeartbeatAnnouncement {
    /// Create the signing payload for this announcement.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(96);
        payload.extend_from_slice(&self.entangled_id);
        payload.extend_from_slice(&self.challenge.to_seed());
        // Hash the proof to keep payload small
        let proof_hash = blake3::hash(&self.proof.vdf_output);
        payload.extend_from_slice(proof_hash.as_bytes());
        payload
    }
}

/// Heartbeat exchange during handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatHello {
    /// Current epoch number.
    pub current_epoch: u64,

    /// Latest heartbeat proof (if available).
    pub latest_proof: Option<HeartbeatAnnouncement>,

    /// Number of consecutive successful heartbeats.
    pub streak: u32,
}

impl Default for HeartbeatHello {
    fn default() -> Self {
        Self {
            current_epoch: current_epoch(VdfConfig::default().heartbeat_interval_secs),
            latest_proof: None,
            streak: 0,
        }
    }
}

// ============================================================================
// Peer Heartbeat Tracking
// ============================================================================

/// Tracked heartbeat state for a peer.
#[derive(Debug, Clone, Default)]
pub struct PeerHeartbeatState {
    /// The peer's EntangledId.
    pub entangled_id: Option<[u8; 32]>,

    /// Last verified epoch.
    pub last_verified_epoch: u64,

    /// Number of consecutive successful heartbeats.
    pub streak: u32,

    /// Number of missed heartbeats.
    pub missed_count: u32,

    /// Total verified heartbeats.
    pub total_verified: u64,

    /// Recent proofs (for deduplication).
    pub recent_proofs: Vec<u64>, // epochs

    /// Current status.
    pub status: PeerHeartbeatStatus,
}

/// Peer heartbeat status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PeerHeartbeatStatus {
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

impl PeerHeartbeatState {
    /// Create new state for a peer.
    #[must_use]
    pub fn new(entangled_id: [u8; 32]) -> Self {
        Self {
            entangled_id: Some(entangled_id),
            ..Default::default()
        }
    }

    /// Record a successful heartbeat verification.
    pub fn record_success(&mut self, epoch: u64) {
        self.last_verified_epoch = epoch;
        self.streak += 1;
        self.total_verified += 1;
        self.missed_count = 0;
        self.status = PeerHeartbeatStatus::Healthy;

        // Track recent epochs for deduplication
        self.recent_proofs.push(epoch);
        if self.recent_proofs.len() > MAX_CACHED_PROOFS_PER_PEER {
            self.recent_proofs.remove(0);
        }
    }

    /// Record a missed heartbeat.
    pub fn record_miss(&mut self, config: &VdfConfig) {
        self.missed_count += 1;
        self.streak = 0;

        if self.missed_count >= config.eviction_threshold {
            self.status = PeerHeartbeatStatus::Unresponsive;
        } else if self.missed_count >= config.suspect_threshold {
            self.status = PeerHeartbeatStatus::Suspect;
        }
    }

    /// Check if we've already seen a proof for this epoch.
    #[must_use]
    pub fn has_proof_for_epoch(&self, epoch: u64) -> bool {
        self.recent_proofs.contains(&epoch)
    }
}

// ============================================================================
// Heartbeat Manager
// ============================================================================

/// Manager for coordinating VDF heartbeats.
pub struct HeartbeatManager {
    /// Our EntangledId.
    local_entangled_id: [u8; 32],

    /// VDF heartbeat generator/verifier.
    vdf: VdfHeartbeat,

    /// Configuration.
    config: VdfConfig,

    /// Our current heartbeat status.
    local_status: Arc<RwLock<NodeHeartbeatStatus>>,

    /// Our latest proof.
    latest_proof: Arc<RwLock<Option<HeartbeatAnnouncement>>>,

    /// Peer heartbeat states.
    peer_states: Arc<RwLock<HashMap<[u8; 32], PeerHeartbeatState>>>,

    /// Consecutive successful heartbeats (streak).
    streak: Arc<RwLock<u32>>,
}

impl HeartbeatManager {
    /// Create a new heartbeat manager.
    pub fn new(
        local_entangled_id: [u8; 32],
        config: VdfConfig,
    ) -> Result<Self, AttestationError> {
        let vdf = VdfHeartbeat::new(config.clone())?;

        Ok(Self {
            local_entangled_id,
            vdf,
            config,
            local_status: Arc::new(RwLock::new(NodeHeartbeatStatus::new(local_entangled_id))),
            latest_proof: Arc::new(RwLock::new(None)),
            peer_states: Arc::new(RwLock::new(HashMap::new())),
            streak: Arc::new(RwLock::new(0)),
        })
    }

    /// Get current epoch number.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        current_epoch(self.config.heartbeat_interval_secs)
    }

    /// Generate a heartbeat for the current epoch.
    ///
    /// This is computationally intensive for real VDF proofs.
    pub async fn generate_heartbeat(&self) -> Result<HeartbeatAnnouncement, AttestationError> {
        let epoch = self.current_epoch();
        let challenge = HeartbeatChallenge::new(self.local_entangled_id, epoch);

        // Generate VDF proof (this is the slow part)
        let proof = self.vdf.solve(&challenge)?;

        // Update local status
        {
            let mut status = self.local_status.write().await;
            status.record_success(epoch, current_timestamp());
        }

        // Update streak
        {
            let mut streak = self.streak.write().await;
            *streak += 1;
        }

        let announcement = HeartbeatAnnouncement {
            entangled_id: self.local_entangled_id,
            challenge,
            proof,
            signature: Vec::new(), // TODO: Sign with ML-DSA in Phase 5.2
        };

        // Cache latest proof
        {
            let mut latest = self.latest_proof.write().await;
            *latest = Some(announcement.clone());
        }

        tracing::info!(
            epoch = epoch,
            entangled_id = %hex::encode(&self.local_entangled_id[..8]),
            "Generated heartbeat"
        );

        Ok(announcement)
    }

    /// Verify a heartbeat announcement from a peer.
    pub async fn verify_announcement(
        &self,
        announcement: &HeartbeatAnnouncement,
    ) -> Result<HeartbeatVerificationResult, AttestationError> {
        // Check if we've already processed this
        {
            let states = self.peer_states.read().await;
            let already_seen = states
                .get(&announcement.entangled_id)
                .is_some_and(|state| state.has_proof_for_epoch(announcement.challenge.epoch));

            if already_seen {
                tracing::debug!(
                    epoch = announcement.challenge.epoch,
                    "Duplicate heartbeat, skipping"
                );
                return Ok(HeartbeatVerificationResult::Valid);
            }
        }

        // Verify the challenge matches the entangled_id
        if announcement.challenge.entangled_id != announcement.entangled_id {
            return Ok(HeartbeatVerificationResult::ChallengeMismatch);
        }

        // Verify the VDF proof
        let result = self.vdf.verify(&announcement.challenge, &announcement.proof)?;

        // Update peer state
        if result.is_valid() {
            let mut states = self.peer_states.write().await;
            let state = states
                .entry(announcement.entangled_id)
                .or_insert_with(|| PeerHeartbeatState::new(announcement.entangled_id));
            state.record_success(announcement.challenge.epoch);

            tracing::debug!(
                epoch = announcement.challenge.epoch,
                peer = %hex::encode(&announcement.entangled_id[..8]),
                streak = state.streak,
                "Verified peer heartbeat"
            );
        }

        Ok(result)
    }

    /// Create a HeartbeatHello for handshake exchange.
    pub async fn create_hello(&self) -> HeartbeatHello {
        let latest = self.latest_proof.read().await;
        let streak = *self.streak.read().await;

        HeartbeatHello {
            current_epoch: self.current_epoch(),
            latest_proof: latest.clone(),
            streak,
        }
    }

    /// Process a HeartbeatHello from a peer during handshake.
    pub async fn process_hello(
        &self,
        hello: &HeartbeatHello,
    ) -> Result<PeerHeartbeatStatus, AttestationError> {
        if let Some(ref announcement) = hello.latest_proof {
            let result = self.verify_announcement(announcement).await?;

            if result.is_valid() {
                let states = self.peer_states.read().await;
                if let Some(state) = states.get(&announcement.entangled_id) {
                    return Ok(state.status);
                }
            }
        }

        Ok(PeerHeartbeatStatus::Unknown)
    }

    /// Check all peers for missed heartbeats.
    ///
    /// Call this periodically (e.g., every epoch).
    pub async fn check_missed_heartbeats(&self) {
        let current = self.current_epoch();
        let mut states = self.peer_states.write().await;

        for (peer_id, state) in states.iter_mut() {
            // If peer hasn't submitted a heartbeat for this epoch
            if state.last_verified_epoch < current.saturating_sub(1) {
                state.record_miss(&self.config);

                if state.status == PeerHeartbeatStatus::Suspect {
                    tracing::warn!(
                        peer = %hex::encode(&peer_id[..8]),
                        missed = state.missed_count,
                        "Peer marked as suspect"
                    );
                } else if state.status == PeerHeartbeatStatus::Unresponsive {
                    tracing::warn!(
                        peer = %hex::encode(&peer_id[..8]),
                        missed = state.missed_count,
                        "Peer marked as unresponsive"
                    );
                }
            }
        }
    }

    /// Get the status of a peer.
    pub async fn get_peer_status(&self, entangled_id: &[u8; 32]) -> Option<PeerHeartbeatState> {
        let states = self.peer_states.read().await;
        states.get(entangled_id).cloned()
    }

    /// Get all peers with a specific status.
    pub async fn get_peers_by_status(&self, status: PeerHeartbeatStatus) -> Vec<[u8; 32]> {
        let states = self.peer_states.read().await;
        states
            .iter()
            .filter(|(_, s)| s.status == status)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get heartbeat statistics.
    pub async fn get_stats(&self) -> HeartbeatStats {
        let states = self.peer_states.read().await;
        let local_status = self.local_status.read().await;
        let streak = *self.streak.read().await;

        let healthy = states.values().filter(|s| s.status == PeerHeartbeatStatus::Healthy).count();
        let suspect = states.values().filter(|s| s.status == PeerHeartbeatStatus::Suspect).count();
        let unresponsive = states.values().filter(|s| s.status == PeerHeartbeatStatus::Unresponsive).count();

        HeartbeatStats {
            current_epoch: self.current_epoch(),
            local_streak: streak,
            local_total_verified: local_status.total_verified,
            peer_count: states.len(),
            healthy_peers: healthy,
            suspect_peers: suspect,
            unresponsive_peers: unresponsive,
        }
    }
}

// ============================================================================
// Gossip Integration
// ============================================================================

/// Callback for publishing heartbeat announcements to gossip.
///
/// Implement this trait and register with `HeartbeatManager` to enable
/// gossip propagation of heartbeats.
#[async_trait::async_trait]
pub trait HeartbeatGossipPublisher: Send + Sync {
    /// Publish a heartbeat announcement to the network.
    ///
    /// This should serialize the announcement and publish it to
    /// the `HEARTBEAT_GOSSIP_TOPIC` topic.
    async fn publish_heartbeat(&self, announcement: &HeartbeatAnnouncement) -> Result<(), AttestationError>;
}

/// Callback for trust score updates based on heartbeat compliance.
///
/// Implement this trait to integrate heartbeat status with the trust system.
#[async_trait::async_trait]
pub trait HeartbeatTrustCallback: Send + Sync {
    /// Called when a peer's heartbeat status changes.
    ///
    /// Use this to adjust EigenTrust scores based on heartbeat compliance.
    async fn on_status_change(
        &self,
        entangled_id: &[u8; 32],
        old_status: PeerHeartbeatStatus,
        new_status: PeerHeartbeatStatus,
    );

    /// Called when a peer produces a successful heartbeat.
    ///
    /// Use this to give positive feedback to the trust system.
    async fn on_heartbeat_success(&self, entangled_id: &[u8; 32], streak: u32);

    /// Called when a peer misses a heartbeat.
    ///
    /// Use this to give negative feedback to the trust system.
    async fn on_heartbeat_miss(&self, entangled_id: &[u8; 32], missed_count: u32);
}

impl HeartbeatManager {
    /// Serialize a heartbeat announcement for gossip.
    ///
    /// Returns CBOR-encoded bytes suitable for a `GossipMessage`.
    pub fn serialize_announcement(
        announcement: &HeartbeatAnnouncement,
    ) -> Result<Vec<u8>, AttestationError> {
        serde_cbor::to_vec(announcement).map_err(|e| {
            AttestationError::SerializationError(format!("Failed to serialize heartbeat: {}", e))
        })
    }

    /// Deserialize a heartbeat announcement from gossip.
    ///
    /// Parses CBOR-encoded bytes from a `GossipMessage`.
    pub fn deserialize_announcement(
        data: &[u8],
    ) -> Result<HeartbeatAnnouncement, AttestationError> {
        serde_cbor::from_slice(data).map_err(|e| {
            AttestationError::SerializationError(format!("Failed to deserialize heartbeat: {}", e))
        })
    }

    /// Handle an incoming heartbeat from gossip.
    ///
    /// This verifies the announcement and updates peer state.
    /// Returns true if the heartbeat was valid and should be forwarded.
    pub async fn handle_gossip_heartbeat(
        &self,
        data: &[u8],
        trust_callback: Option<&dyn HeartbeatTrustCallback>,
    ) -> Result<bool, AttestationError> {
        let announcement = Self::deserialize_announcement(data)?;

        // Don't process our own heartbeats
        if announcement.entangled_id == self.local_entangled_id {
            return Ok(false);
        }

        // Get old status for comparison
        let old_status = {
            let states = self.peer_states.read().await;
            states.get(&announcement.entangled_id)
                .map(|s| s.status)
                .unwrap_or(PeerHeartbeatStatus::Unknown)
        };

        // Verify the announcement
        let result = self.verify_announcement(&announcement).await?;

        if result.is_valid() {
            // Get new status and streak
            let (new_status, streak) = {
                let states = self.peer_states.read().await;
                states.get(&announcement.entangled_id)
                    .map(|s| (s.status, s.streak))
                    .unwrap_or((PeerHeartbeatStatus::Unknown, 0))
            };

            // Notify trust callback
            if let Some(callback) = trust_callback {
                if old_status != new_status {
                    callback.on_status_change(&announcement.entangled_id, old_status, new_status).await;
                }
                callback.on_heartbeat_success(&announcement.entangled_id, streak).await;
            }

            tracing::debug!(
                peer = %hex::encode(&announcement.entangled_id[..8]),
                epoch = announcement.challenge.epoch,
                "Valid heartbeat received via gossip"
            );

            Ok(true) // Forward to other peers
        } else {
            tracing::warn!(
                peer = %hex::encode(&announcement.entangled_id[..8]),
                epoch = announcement.challenge.epoch,
                result = ?result,
                "Invalid heartbeat received via gossip"
            );

            Ok(false) // Don't forward invalid heartbeats
        }
    }

    /// Generate and publish a heartbeat to gossip.
    ///
    /// This generates a new heartbeat and publishes it via the provided publisher.
    pub async fn generate_and_publish(
        &self,
        publisher: &dyn HeartbeatGossipPublisher,
    ) -> Result<HeartbeatAnnouncement, AttestationError> {
        let announcement = self.generate_heartbeat().await?;
        publisher.publish_heartbeat(&announcement).await?;

        tracing::info!(
            epoch = announcement.challenge.epoch,
            "Published heartbeat to gossip"
        );

        Ok(announcement)
    }

    /// Check missed heartbeats and notify trust callback.
    ///
    /// Call this periodically (e.g., every epoch).
    pub async fn check_missed_heartbeats_with_callback(
        &self,
        trust_callback: Option<&dyn HeartbeatTrustCallback>,
    ) {
        // Collect notifications to make outside the lock
        let notifications: Vec<_> = {
            let current = self.current_epoch();
            let mut states = self.peer_states.write().await;
            let mut notifications = Vec::new();

            for (peer_id, state) in states.iter_mut() {
                // If peer hasn't submitted a heartbeat for this epoch
                if state.last_verified_epoch < current.saturating_sub(1) {
                    let old_status = state.status;
                    state.record_miss(&self.config);
                    let new_status = state.status;

                    // Collect notification data
                    if old_status != new_status {
                        notifications.push((*peer_id, old_status, new_status, state.missed_count));
                    }

                    if new_status == PeerHeartbeatStatus::Suspect {
                        tracing::warn!(
                            peer = %hex::encode(&peer_id[..8]),
                            missed = state.missed_count,
                            "Peer marked as suspect"
                        );
                    } else if new_status == PeerHeartbeatStatus::Unresponsive {
                        tracing::warn!(
                            peer = %hex::encode(&peer_id[..8]),
                            missed = state.missed_count,
                            "Peer marked as unresponsive"
                        );
                    }
                }
            }

            notifications
        };

        // Now make async calls outside the lock
        if let Some(callback) = trust_callback {
            for (peer_id, old_status, new_status, missed) in notifications {
                callback.on_status_change(&peer_id, old_status, new_status).await;
                callback.on_heartbeat_miss(&peer_id, missed).await;
            }
        }
    }
}

/// Heartbeat statistics.
#[derive(Debug, Clone, Default)]
pub struct HeartbeatStats {
    /// Current epoch number.
    pub current_epoch: u64,

    /// Our consecutive successful heartbeats.
    pub local_streak: u32,

    /// Total heartbeats we've generated.
    pub local_total_verified: u64,

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
pub fn current_epoch(heartbeat_interval_secs: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now / heartbeat_interval_secs
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_heartbeat_manager_creation() {
        let entangled_id = [42u8; 32];
        let config = VdfConfig::development();

        let manager = HeartbeatManager::new(entangled_id, config).expect("create manager");
        assert!(manager.current_epoch() > 0);
    }

    #[tokio::test]
    async fn test_heartbeat_generation() {
        let entangled_id = [42u8; 32];
        let config = VdfConfig::development();

        let manager = HeartbeatManager::new(entangled_id, config).expect("create manager");
        let announcement = manager.generate_heartbeat().await.expect("generate");

        assert_eq!(announcement.entangled_id, entangled_id);
        assert!(!announcement.proof.vdf_output.iter().all(|&b| b == 0));
    }

    #[tokio::test]
    async fn test_heartbeat_verification() {
        let entangled_id = [42u8; 32];
        let config = VdfConfig::development();

        let manager = HeartbeatManager::new(entangled_id, config).expect("create manager");
        let announcement = manager.generate_heartbeat().await.expect("generate");

        let result = manager.verify_announcement(&announcement).await.expect("verify");
        assert!(result.is_valid());
    }

    #[tokio::test]
    async fn test_peer_tracking() {
        let local_id = [1u8; 32];
        let peer_id = [2u8; 32];
        let config = VdfConfig::development();

        let manager = HeartbeatManager::new(local_id, config.clone()).expect("create manager");
        let peer_manager = HeartbeatManager::new(peer_id, config).expect("create peer manager");

        // Peer generates heartbeat
        let announcement = peer_manager.generate_heartbeat().await.expect("generate");

        // We verify it
        let result = manager.verify_announcement(&announcement).await.expect("verify");
        assert!(result.is_valid());

        // Check peer state
        let state = manager.get_peer_status(&peer_id).await;
        assert!(state.is_some());
        assert_eq!(state.as_ref().map(|s| s.status), Some(PeerHeartbeatStatus::Healthy));
    }

    #[tokio::test]
    async fn test_hello_exchange() {
        let local_id = [1u8; 32];
        let config = VdfConfig::development();

        let manager = HeartbeatManager::new(local_id, config).expect("create manager");

        // Generate a heartbeat first
        let _ = manager.generate_heartbeat().await.expect("generate");

        // Create hello
        let hello = manager.create_hello().await;
        assert!(hello.latest_proof.is_some());
        assert_eq!(hello.streak, 1);
    }

    #[test]
    fn test_epoch_calculation() {
        let interval = 60; // 1 minute epochs
        let epoch = current_epoch(interval);
        assert!(epoch > 0);

        // Epoch should be roughly current_time / 60
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(epoch, now / interval);
    }

    #[tokio::test]
    async fn test_announcement_serialization() {
        let entangled_id = [42u8; 32];
        let config = VdfConfig::development();

        let manager = HeartbeatManager::new(entangled_id, config).expect("create manager");
        let announcement = manager.generate_heartbeat().await.expect("generate");

        // Serialize
        let bytes = HeartbeatManager::serialize_announcement(&announcement).expect("serialize");
        assert!(!bytes.is_empty());

        // Deserialize
        let restored = HeartbeatManager::deserialize_announcement(&bytes).expect("deserialize");
        assert_eq!(restored.entangled_id, announcement.entangled_id);
        assert_eq!(restored.challenge.epoch, announcement.challenge.epoch);
    }

    #[tokio::test]
    async fn test_handle_gossip_heartbeat() {
        let local_id = [1u8; 32];
        let peer_id = [2u8; 32];
        let config = VdfConfig::development();

        let local_manager = HeartbeatManager::new(local_id, config.clone()).expect("create manager");
        let peer_manager = HeartbeatManager::new(peer_id, config).expect("create peer manager");

        // Peer generates heartbeat
        let announcement = peer_manager.generate_heartbeat().await.expect("generate");

        // Serialize for gossip
        let bytes = HeartbeatManager::serialize_announcement(&announcement).expect("serialize");

        // Local node handles the gossip message
        let should_forward = local_manager
            .handle_gossip_heartbeat(&bytes, None)
            .await
            .expect("handle");

        // Should forward valid heartbeats
        assert!(should_forward);

        // Peer should now be tracked
        let state = local_manager.get_peer_status(&peer_id).await;
        assert!(state.is_some());
        assert_eq!(state.as_ref().map(|s| s.status), Some(PeerHeartbeatStatus::Healthy));
    }

    #[tokio::test]
    async fn test_ignore_own_heartbeat() {
        let local_id = [1u8; 32];
        let config = VdfConfig::development();

        let manager = HeartbeatManager::new(local_id, config).expect("create manager");

        // Generate our own heartbeat
        let announcement = manager.generate_heartbeat().await.expect("generate");

        // Serialize for gossip
        let bytes = HeartbeatManager::serialize_announcement(&announcement).expect("serialize");

        // Handle our own heartbeat (e.g., received via gossip loop)
        let should_forward = manager
            .handle_gossip_heartbeat(&bytes, None)
            .await
            .expect("handle");

        // Should not forward our own heartbeats
        assert!(!should_forward);
    }
}
