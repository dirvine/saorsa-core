// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Attestation handshake extension for P2P connections.
//!
//! This module provides the protocol for exchanging attestation proofs
//! during peer connection establishment.
//!
//! ## Protocol Flow
//!
//! ```text
//! Node A                                    Node B
//!   |                                          |
//!   |  1. AttestationHello (EntangledId, Proof)|
//!   |----------------------------------------->|
//!   |                                          |
//!   |  2. AttestationHello (EntangledId, Proof)|
//!   |<-----------------------------------------|
//!   |                                          |
//!   |  3. Both verify proofs                   |
//!   |      - If valid: proceed                 |
//!   |      - If invalid: log (soft enforce)    |
//!   |                                          |
//! ```
//!
//! ## Enforcement Modes
//!
//! - **Soft Enforcement (Phase 1)**: Invalid proofs are logged but connections proceed
//! - **Hard Enforcement (Future)**: Invalid proofs result in connection rejection
//!
//! ## Security Note
//!
//! The attestation proof demonstrates that the peer is running authorized software
//! bound to their cryptographic identity, without revealing the full public key
//! or derivation nonce.

use super::{
    AttestationConfig, AttestationProof, AttestationProofResult, AttestationVerifier,
    AttestationVerifierConfig, EnforcementMode, EntangledId,
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Attestation hello message exchanged during handshake.
///
/// This is sent by both peers during connection establishment to
/// prove they are running authorized software.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationHello {
    /// The sender's EntangledId (software-attested identity).
    pub entangled_id: [u8; 32],

    /// Zero-knowledge proof of correct EntangledId derivation.
    ///
    /// This proves the sender knows inputs that hash to `entangled_id`
    /// without revealing the full public key or nonce.
    pub proof: AttestationProof,

    /// Protocol version for future compatibility.
    /// - v1: Original attestation proof only
    /// - v2: Includes optional heartbeat extension (Phase 5)
    pub protocol_version: u8,

    /// Optional heartbeat information (Phase 5).
    ///
    /// Present when protocol_version >= 2.
    /// Contains the sender's latest VDF heartbeat proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<HeartbeatExtension>,
}

/// Heartbeat extension for AttestationHello (Phase 5).
///
/// Contains VDF heartbeat information exchanged during handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatExtension {
    /// Current epoch number.
    pub current_epoch: u64,

    /// Latest heartbeat proof (if available).
    pub latest_proof: Option<super::HeartbeatAnnouncement>,

    /// Number of consecutive successful heartbeats (streak).
    pub streak: u32,

    /// Peer's heartbeat status.
    pub status: super::PeerHeartbeatStatus,
}

/// Result of verifying a peer's attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationVerificationResult {
    /// Proof verified successfully.
    Valid,

    /// Proof verification failed.
    Invalid(String),

    /// Proof is stale (too old).
    Stale,

    /// Binary not in allowed list.
    BinaryNotAllowed,

    /// No proof provided (legacy peer).
    NoProof,
}

impl AttestationVerificationResult {
    /// Check if verification was successful.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Check if the connection should proceed based on enforcement mode.
    #[must_use]
    pub fn should_proceed(&self, enforcement: EnforcementMode) -> bool {
        match enforcement {
            EnforcementMode::Off => true,
            EnforcementMode::Soft => {
                // Log but proceed
                if !self.is_valid() {
                    tracing::warn!(
                        "Attestation verification failed (soft enforcement): {:?}",
                        self
                    );
                }
                true
            }
            EnforcementMode::Hard => self.is_valid(),
        }
    }
}

/// Peer attestation status tracking.
#[derive(Debug, Clone, Default)]
pub struct PeerAttestationStatus {
    /// The peer's EntangledId if provided.
    pub entangled_id: Option<[u8; 32]>,

    /// Whether the peer's proof was valid.
    pub proof_valid: bool,

    /// When the proof was verified.
    pub verified_at: Option<u64>,

    /// Binary hash from the proof (if available).
    pub binary_hash: Option<[u8; 32]>,

    /// Number of verification attempts.
    pub verification_attempts: u32,

    /// Last verification failure reason.
    pub last_failure_reason: Option<String>,

    // --- Phase 5: Heartbeat tracking ---

    /// Peer's heartbeat status (Phase 5).
    pub heartbeat_status: super::PeerHeartbeatStatus,

    /// Last heartbeat epoch verified.
    pub last_heartbeat_epoch: u64,

    /// Peer's heartbeat streak.
    pub heartbeat_streak: u32,

    /// Protocol version used by peer.
    pub protocol_version: u8,
}

impl PeerAttestationStatus {
    /// Create a new attestation status for a verified peer.
    #[must_use]
    pub fn verified(entangled_id: [u8; 32], binary_hash: [u8; 32]) -> Self {
        Self {
            entangled_id: Some(entangled_id),
            proof_valid: true,
            verified_at: Some(current_timestamp()),
            binary_hash: Some(binary_hash),
            verification_attempts: 1,
            last_failure_reason: None,
            // Phase 5: Heartbeat fields default to unknown
            heartbeat_status: super::PeerHeartbeatStatus::Unknown,
            last_heartbeat_epoch: 0,
            heartbeat_streak: 0,
            protocol_version: 1,
        }
    }

    /// Create a new attestation status for a verified peer with heartbeat info (v2).
    #[must_use]
    pub fn verified_with_heartbeat(
        entangled_id: [u8; 32],
        binary_hash: [u8; 32],
        heartbeat: &HeartbeatExtension,
    ) -> Self {
        Self {
            entangled_id: Some(entangled_id),
            proof_valid: true,
            verified_at: Some(current_timestamp()),
            binary_hash: Some(binary_hash),
            verification_attempts: 1,
            last_failure_reason: None,
            // Phase 5: Heartbeat fields from extension
            heartbeat_status: heartbeat.status,
            last_heartbeat_epoch: heartbeat.current_epoch,
            heartbeat_streak: heartbeat.streak,
            protocol_version: 2,
        }
    }

    /// Create a status for failed verification.
    #[must_use]
    pub fn failed(reason: String) -> Self {
        Self {
            entangled_id: None,
            proof_valid: false,
            verified_at: Some(current_timestamp()),
            binary_hash: None,
            verification_attempts: 1,
            last_failure_reason: Some(reason),
            // Phase 5: Heartbeat fields default to unknown
            heartbeat_status: super::PeerHeartbeatStatus::Unknown,
            last_heartbeat_epoch: 0,
            heartbeat_streak: 0,
            protocol_version: 0,
        }
    }

    /// Record a verification attempt.
    pub fn record_attempt(&mut self, valid: bool, reason: Option<String>) {
        self.verification_attempts += 1;
        self.proof_valid = valid;
        self.verified_at = Some(current_timestamp());
        if !valid {
            self.last_failure_reason = reason;
        }
    }
}

/// Attestation handshake handler.
///
/// Manages the attestation proof exchange during connection establishment.
#[derive(Debug)]
pub struct AttestationHandshake {
    /// Our EntangledId.
    local_entangled_id: EntangledId,

    /// Our attestation proof.
    local_proof: AttestationProof,

    /// Verifier for peer proofs.
    verifier: AttestationVerifier,

    /// Enforcement configuration.
    config: AttestationConfig,
}

impl AttestationHandshake {
    /// Create a new attestation handshake handler.
    ///
    /// # Arguments
    ///
    /// * `entangled_id` - Our EntangledId
    /// * `proof` - Our attestation proof
    /// * `config` - Attestation configuration
    #[must_use]
    pub fn new(
        entangled_id: EntangledId,
        proof: AttestationProof,
        config: AttestationConfig,
    ) -> Self {
        // Map from AttestationConfig to AttestationVerifierConfig
        let verifier_config = AttestationVerifierConfig {
            max_proof_age_secs: 3600, // Default 1 hour
            allowed_binaries: config.allowed_binary_hashes.clone(),
            expected_vkey_hash: None, // Accept any vkey for now
            require_pq_secure: false, // Accept mock proofs during development
        };

        Self {
            local_entangled_id: entangled_id,
            local_proof: proof,
            verifier: AttestationVerifier::new(verifier_config),
            config,
        }
    }

    /// Create our attestation hello message (v1, no heartbeat).
    #[must_use]
    pub fn create_hello(&self) -> AttestationHello {
        AttestationHello {
            entangled_id: *self.local_entangled_id.id(),
            proof: self.local_proof.clone(),
            protocol_version: 1,
            heartbeat: None,
        }
    }

    /// Create our attestation hello message with heartbeat extension (v2).
    ///
    /// Use this when you have a HeartbeatManager to provide liveness proofs.
    #[must_use]
    pub fn create_hello_with_heartbeat(
        &self,
        heartbeat_hello: super::HeartbeatHello,
    ) -> AttestationHello {
        AttestationHello {
            entangled_id: *self.local_entangled_id.id(),
            proof: self.local_proof.clone(),
            protocol_version: 2,
            heartbeat: Some(HeartbeatExtension {
                current_epoch: heartbeat_hello.current_epoch,
                latest_proof: heartbeat_hello.latest_proof,
                streak: heartbeat_hello.streak,
                status: super::PeerHeartbeatStatus::Healthy,
            }),
        }
    }

    /// Verify a peer's attestation hello.
    ///
    /// # Arguments
    ///
    /// * `hello` - The peer's attestation hello message
    ///
    /// # Returns
    ///
    /// Verification result and peer attestation status.
    ///
    /// # Protocol Versions
    ///
    /// - v1: Attestation proof only
    /// - v2: Attestation proof + heartbeat extension
    pub fn verify_hello(
        &self,
        hello: &AttestationHello,
    ) -> (AttestationVerificationResult, PeerAttestationStatus) {
        let current_time = current_timestamp();

        // Check protocol version (accept v1 and v2)
        if hello.protocol_version == 0 || hello.protocol_version > 2 {
            let reason = format!("Unsupported protocol version: {}", hello.protocol_version);
            tracing::warn!("{}", reason);
            return (
                AttestationVerificationResult::Invalid(reason.clone()),
                PeerAttestationStatus::failed(reason),
            );
        }

        // Verify the proof
        let proof_result = self
            .verifier
            .verify(&hello.proof, &hello.entangled_id, current_time);

        match proof_result {
            AttestationProofResult::Valid => {
                tracing::debug!(
                    entangled_id = hex::encode(&hello.entangled_id[..8]),
                    binary_hash = hex::encode(&hello.proof.public_inputs.binary_hash[..8]),
                    protocol_version = hello.protocol_version,
                    has_heartbeat = hello.heartbeat.is_some(),
                    "Peer attestation verified successfully"
                );

                // Build status based on protocol version
                let status = if let Some(heartbeat) = &hello.heartbeat {
                    // v2: Include heartbeat information
                    tracing::debug!(
                        epoch = heartbeat.current_epoch,
                        streak = heartbeat.streak,
                        heartbeat_status = ?heartbeat.status,
                        "Peer heartbeat info received"
                    );
                    PeerAttestationStatus::verified_with_heartbeat(
                        hello.entangled_id,
                        hello.proof.public_inputs.binary_hash,
                        heartbeat,
                    )
                } else {
                    // v1: Attestation only
                    PeerAttestationStatus::verified(
                        hello.entangled_id,
                        hello.proof.public_inputs.binary_hash,
                    )
                };

                (AttestationVerificationResult::Valid, status)
            }
            AttestationProofResult::Stale => {
                let reason = "Proof is stale (too old)".to_string();
                tracing::warn!(
                    entangled_id = hex::encode(&hello.entangled_id[..8]),
                    "{}",
                    reason
                );
                (
                    AttestationVerificationResult::Stale,
                    PeerAttestationStatus::failed(reason),
                )
            }
            AttestationProofResult::BinaryNotAllowed => {
                let reason = format!(
                    "Binary not allowed: {}",
                    hex::encode(&hello.proof.public_inputs.binary_hash[..8])
                );
                tracing::warn!(
                    entangled_id = hex::encode(&hello.entangled_id[..8]),
                    "{}",
                    reason
                );
                (
                    AttestationVerificationResult::BinaryNotAllowed,
                    PeerAttestationStatus::failed(reason),
                )
            }
            AttestationProofResult::InvalidProof => {
                let reason = "Invalid proof (cryptographic verification failed)".to_string();
                tracing::warn!(
                    entangled_id = hex::encode(&hello.entangled_id[..8]),
                    "{}",
                    reason
                );
                (
                    AttestationVerificationResult::Invalid(reason.clone()),
                    PeerAttestationStatus::failed(reason),
                )
            }
            AttestationProofResult::IdMismatch => {
                let reason = "EntangledId mismatch".to_string();
                tracing::warn!(
                    entangled_id = hex::encode(&hello.entangled_id[..8]),
                    "{}",
                    reason
                );
                (
                    AttestationVerificationResult::Invalid(reason.clone()),
                    PeerAttestationStatus::failed(reason),
                )
            }
        }
    }

    /// Check if a connection should proceed based on verification result.
    #[must_use]
    pub fn should_proceed(&self, result: &AttestationVerificationResult) -> bool {
        result.should_proceed(self.config.enforcement_mode)
    }

    /// Get the enforcement mode.
    #[must_use]
    pub fn enforcement_mode(&self) -> EnforcementMode {
        self.config.enforcement_mode
    }

    /// Get our EntangledId.
    #[must_use]
    pub fn local_entangled_id(&self) -> &EntangledId {
        &self.local_entangled_id
    }
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
    use crate::attestation::{AttestationProofPublicInputs, PeerHeartbeatStatus, ProofType};
    use crate::quantum_crypto::generate_ml_dsa_keypair;

    fn create_test_proof(entangled_id: [u8; 32], binary_hash: [u8; 32]) -> AttestationProof {
        AttestationProof {
            proof_bytes: vec![0u8; 32],
            public_inputs: AttestationProofPublicInputs {
                entangled_id,
                binary_hash,
                public_key_hash: [0u8; 32],
                proof_timestamp: current_timestamp(),
            },
            vkey_hash: [0u8; 32],
            proof_type: ProofType::Mock,
        }
    }

    #[test]
    fn test_attestation_hello_creation() {
        let (pk, _) = generate_ml_dsa_keypair().expect("keygen");
        let binary_hash = [0x42u8; 32];
        let entangled_id = EntangledId::derive(&pk, &binary_hash, 12345);
        let proof = create_test_proof(*entangled_id.id(), binary_hash);

        let config = AttestationConfig::development();
        let handshake = AttestationHandshake::new(entangled_id.clone(), proof.clone(), config);

        let hello = handshake.create_hello();
        assert_eq!(hello.entangled_id, *entangled_id.id());
        assert_eq!(hello.protocol_version, 1);
    }

    #[test]
    fn test_verify_valid_hello() {
        let (pk, _) = generate_ml_dsa_keypair().expect("keygen");
        let binary_hash = [0x42u8; 32];
        let entangled_id = EntangledId::derive(&pk, &binary_hash, 12345);
        let proof = create_test_proof(*entangled_id.id(), binary_hash);

        let config = AttestationConfig::development();
        let handshake = AttestationHandshake::new(entangled_id.clone(), proof.clone(), config);

        let hello = AttestationHello {
            entangled_id: *entangled_id.id(),
            proof: proof.clone(),
            protocol_version: 1,
            heartbeat: None,
        };

        let (result, status) = handshake.verify_hello(&hello);
        assert!(result.is_valid());
        assert!(status.proof_valid);
        assert_eq!(status.entangled_id, Some(*entangled_id.id()));
    }

    #[test]
    fn test_verify_id_mismatch() {
        let (pk, _) = generate_ml_dsa_keypair().expect("keygen");
        let binary_hash = [0x42u8; 32];
        let entangled_id = EntangledId::derive(&pk, &binary_hash, 12345);
        let proof = create_test_proof(*entangled_id.id(), binary_hash);

        let config = AttestationConfig::development();
        let handshake = AttestationHandshake::new(entangled_id.clone(), proof.clone(), config);

        // Create hello with mismatched ID
        let wrong_id = [0x99u8; 32];
        let hello = AttestationHello {
            entangled_id: wrong_id,
            proof: proof.clone(),
            protocol_version: 1,
            heartbeat: None,
        };

        let (result, status) = handshake.verify_hello(&hello);
        assert!(!result.is_valid());
        assert!(!status.proof_valid);
    }

    #[test]
    fn test_soft_enforcement_proceeds() {
        let result = AttestationVerificationResult::Invalid("test".to_string());
        assert!(result.should_proceed(EnforcementMode::Soft));
        assert!(!result.should_proceed(EnforcementMode::Hard));
    }

    #[test]
    fn test_off_enforcement_always_proceeds() {
        let result = AttestationVerificationResult::Invalid("test".to_string());
        assert!(result.should_proceed(EnforcementMode::Off));
    }

    #[test]
    fn test_valid_always_proceeds() {
        let result = AttestationVerificationResult::Valid;
        assert!(result.should_proceed(EnforcementMode::Off));
        assert!(result.should_proceed(EnforcementMode::Soft));
        assert!(result.should_proceed(EnforcementMode::Hard));
    }

    #[test]
    fn test_verify_hello_v2_with_heartbeat() {
        let (pk, _) = generate_ml_dsa_keypair().expect("keygen");
        let binary_hash = [0x42u8; 32];
        let entangled_id = EntangledId::derive(&pk, &binary_hash, 12345);
        let proof = create_test_proof(*entangled_id.id(), binary_hash);

        let config = AttestationConfig::development();
        let handshake = AttestationHandshake::new(entangled_id.clone(), proof.clone(), config);

        // Create v2 hello with heartbeat extension
        let hello = AttestationHello {
            entangled_id: *entangled_id.id(),
            proof: proof.clone(),
            protocol_version: 2,
            heartbeat: Some(HeartbeatExtension {
                current_epoch: 100,
                latest_proof: None,
                streak: 5,
                status: PeerHeartbeatStatus::Healthy,
            }),
        };

        let (result, status) = handshake.verify_hello(&hello);
        assert!(result.is_valid());
        assert!(status.proof_valid);
        assert_eq!(status.entangled_id, Some(*entangled_id.id()));
        // Check heartbeat fields from extension
        assert_eq!(status.protocol_version, 2);
        assert_eq!(status.last_heartbeat_epoch, 100);
        assert_eq!(status.heartbeat_streak, 5);
        assert_eq!(status.heartbeat_status, PeerHeartbeatStatus::Healthy);
    }

    #[test]
    fn test_reject_unsupported_protocol_version() {
        let (pk, _) = generate_ml_dsa_keypair().expect("keygen");
        let binary_hash = [0x42u8; 32];
        let entangled_id = EntangledId::derive(&pk, &binary_hash, 12345);
        let proof = create_test_proof(*entangled_id.id(), binary_hash);

        let config = AttestationConfig::development();
        let handshake = AttestationHandshake::new(entangled_id.clone(), proof.clone(), config);

        // Protocol version 0 should be rejected
        let hello_v0 = AttestationHello {
            entangled_id: *entangled_id.id(),
            proof: proof.clone(),
            protocol_version: 0,
            heartbeat: None,
        };
        let (result, _) = handshake.verify_hello(&hello_v0);
        assert!(!result.is_valid());

        // Protocol version 3+ should be rejected
        let hello_v3 = AttestationHello {
            entangled_id: *entangled_id.id(),
            proof: proof.clone(),
            protocol_version: 3,
            heartbeat: None,
        };
        let (result, _) = handshake.verify_hello(&hello_v3);
        assert!(!result.is_valid());
    }
}
