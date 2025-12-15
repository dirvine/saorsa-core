// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Signed Heartbeat system for lightweight liveness proofs.
//!
//! This module implements a simple, efficient heartbeat system that proves:
//! 1. **Liveness** - The node is still running
//! 2. **Key ownership** - The node controls the private key for its EntangledId
//!
//! ## Design Rationale
//!
//! Unlike VDF-based heartbeats (which prove sequential CPU work), signed heartbeats
//! are designed for networks where:
//! - Multiple nodes may run on the same device
//! - Resource-constrained devices (Raspberry Pi, etc.) must participate
//! - The EntangledId binding already enforces software integrity
//!
//! ## Security Model
//!
//! The EntangledId is derived from:
//! ```text
//! EntangledId = BLAKE3(public_key || binary_hash || nonce)
//! ```
//!
//! If a node changes its software:
//! - The `binary_hash` changes
//! - The `EntangledId` changes
//! - The node's reputation resets to zero
//!
//! This binding is the primary enforcement mechanism. Heartbeats simply prove
//! continued key ownership and liveness.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use saorsa_core::attestation::{SignedHeartbeat, HeartbeatSigner};
//!
//! // Create a signer with your ML-DSA keypair
//! let signer = HeartbeatSigner::new(entangled_id, public_key, secret_key);
//!
//! // Generate heartbeats periodically
//! let heartbeat = signer.create_heartbeat()?;
//!
//! // Verify received heartbeats
//! let is_valid = SignedHeartbeat::verify(&heartbeat, &peer_public_key)?;
//! ```

use crate::quantum_crypto::ant_quic_integration::{
    ml_dsa_sign, ml_dsa_verify, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
};
use super::AttestationError;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for signed heartbeats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatConfig {
    /// Heartbeat interval in seconds.
    /// Nodes should produce one heartbeat per interval.
    pub interval_secs: u64,

    /// Maximum acceptable heartbeat age in seconds.
    /// Heartbeats older than this are rejected as stale.
    pub max_age_secs: u64,

    /// Number of missed heartbeats before marking node as suspect.
    pub suspect_threshold: u32,

    /// Number of missed heartbeats before eviction.
    pub eviction_threshold: u32,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self::standard()
    }
}

impl HeartbeatConfig {
    /// Standard configuration for production use.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            interval_secs: 60,        // 1 minute heartbeats
            max_age_secs: 120,        // 2 minute max age
            suspect_threshold: 3,     // 3 missed = suspect
            eviction_threshold: 5,    // 5 missed = evicted
        }
    }

    /// Fast configuration for testing.
    #[must_use]
    pub fn fast() -> Self {
        Self {
            interval_secs: 5,         // 5 second heartbeats
            max_age_secs: 15,         // 15 second max age
            suspect_threshold: 2,
            eviction_threshold: 3,
        }
    }

    /// Relaxed configuration for low-bandwidth scenarios.
    #[must_use]
    pub fn relaxed() -> Self {
        Self {
            interval_secs: 300,       // 5 minute heartbeats
            max_age_secs: 600,        // 10 minute max age
            suspect_threshold: 3,
            eviction_threshold: 6,
        }
    }
}

// ============================================================================
// Signed Heartbeat
// ============================================================================

/// A signed heartbeat proving liveness and key ownership.
///
/// This is a lightweight alternative to VDF heartbeats, suitable for:
/// - Resource-constrained devices
/// - Multi-node-per-device deployments
/// - Networks where EntangledId binding provides software integrity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHeartbeat {
    /// The sender's EntangledId.
    pub entangled_id: [u8; 32],

    /// Epoch number (heartbeat sequence).
    pub epoch: u64,

    /// Unix timestamp when heartbeat was created.
    pub timestamp: u64,

    /// Random nonce to prevent replay attacks within same epoch.
    pub nonce: [u8; 16],

    /// ML-DSA-65 signature over the heartbeat payload.
    pub signature: Vec<u8>,
}

impl SignedHeartbeat {
    /// Create the payload bytes for signing/verification.
    #[must_use]
    pub fn payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&self.entangled_id);
        payload.extend_from_slice(&self.epoch.to_le_bytes());
        payload.extend_from_slice(&self.timestamp.to_le_bytes());
        payload.extend_from_slice(&self.nonce);
        payload
    }

    /// Verify this heartbeat's signature.
    ///
    /// # Arguments
    /// * `public_key` - The ML-DSA-65 public key of the claimed sender
    ///
    /// # Returns
    /// `Ok(())` if signature is valid, error otherwise.
    pub fn verify_signature(&self, public_key: &MlDsaPublicKey) -> Result<(), AttestationError> {
        let payload = self.payload();

        // Convert signature bytes to MlDsaSignature type
        let signature = MlDsaSignature::from_bytes(&self.signature).map_err(|e| {
            AttestationError::VerificationFailed {
                reason: format!("Invalid signature format: {}", e),
            }
        })?;

        let is_valid = ml_dsa_verify(public_key, &payload, &signature).map_err(|e| {
            AttestationError::VerificationFailed {
                reason: format!("Heartbeat signature verification failed: {}", e),
            }
        })?;

        if is_valid {
            Ok(())
        } else {
            Err(AttestationError::VerificationFailed {
                reason: "Heartbeat signature invalid".to_string(),
            })
        }
    }

    /// Check if this heartbeat is fresh (not stale).
    #[must_use]
    pub fn is_fresh(&self, max_age_secs: u64) -> bool {
        let now = current_timestamp();
        now.saturating_sub(self.timestamp) <= max_age_secs
    }

    /// Full verification: signature + freshness.
    pub fn verify(
        &self,
        public_key: &MlDsaPublicKey,
        config: &HeartbeatConfig,
    ) -> Result<HeartbeatVerifyResult, AttestationError> {
        // Check freshness first (cheap)
        if !self.is_fresh(config.max_age_secs) {
            return Ok(HeartbeatVerifyResult::Stale);
        }

        // Verify signature
        match self.verify_signature(public_key) {
            Ok(()) => Ok(HeartbeatVerifyResult::Valid),
            Err(e) => Ok(HeartbeatVerifyResult::InvalidSignature(e.to_string())),
        }
    }

    /// Verify from raw public key bytes (convenience method for network received keys).
    pub fn verify_from_bytes(
        &self,
        public_key_bytes: &[u8],
        config: &HeartbeatConfig,
    ) -> Result<HeartbeatVerifyResult, AttestationError> {
        let public_key = MlDsaPublicKey::from_bytes(public_key_bytes).map_err(|e| {
            AttestationError::VerificationFailed {
                reason: format!("Invalid public key format: {}", e),
            }
        })?;
        self.verify(&public_key, config)
    }
}

/// Result of heartbeat verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatVerifyResult {
    /// Heartbeat is valid.
    Valid,
    /// Heartbeat signature is invalid.
    InvalidSignature(String),
    /// Heartbeat is too old.
    Stale,
    /// EntangledId mismatch.
    IdMismatch,
}

impl HeartbeatVerifyResult {
    /// Check if verification succeeded.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

// ============================================================================
// Heartbeat Signer
// ============================================================================

/// Signer for creating heartbeats.
///
/// Holds the node's identity and keys for generating signed heartbeats.
pub struct HeartbeatSigner {
    /// Our EntangledId.
    entangled_id: [u8; 32],

    /// Our ML-DSA-65 public key.
    public_key: MlDsaPublicKey,

    /// Our ML-DSA-65 secret key.
    secret_key: MlDsaSecretKey,

    /// Current epoch counter.
    current_epoch: u64,
}

impl HeartbeatSigner {
    /// Create a new heartbeat signer from typed keys.
    ///
    /// # Arguments
    /// * `entangled_id` - The node's EntangledId
    /// * `public_key` - ML-DSA-65 public key
    /// * `secret_key` - ML-DSA-65 secret key
    pub fn new(
        entangled_id: [u8; 32],
        public_key: MlDsaPublicKey,
        secret_key: MlDsaSecretKey,
    ) -> Self {
        Self {
            entangled_id,
            public_key,
            secret_key,
            current_epoch: current_epoch(HeartbeatConfig::default().interval_secs),
        }
    }

    /// Create a new heartbeat signer from raw key bytes.
    ///
    /// # Arguments
    /// * `entangled_id` - The node's EntangledId
    /// * `public_key_bytes` - ML-DSA-65 public key bytes
    /// * `secret_key_bytes` - ML-DSA-65 secret key bytes
    pub fn from_bytes(
        entangled_id: [u8; 32],
        public_key_bytes: &[u8],
        secret_key_bytes: &[u8],
    ) -> Result<Self, AttestationError> {
        let public_key = MlDsaPublicKey::from_bytes(public_key_bytes).map_err(|e| {
            AttestationError::CryptoError(format!("Invalid public key: {}", e))
        })?;
        let secret_key = MlDsaSecretKey::from_bytes(secret_key_bytes).map_err(|e| {
            AttestationError::CryptoError(format!("Invalid secret key: {}", e))
        })?;

        Ok(Self {
            entangled_id,
            public_key,
            secret_key,
            current_epoch: current_epoch(HeartbeatConfig::default().interval_secs),
        })
    }

    /// Get our EntangledId.
    #[must_use]
    pub fn entangled_id(&self) -> &[u8; 32] {
        &self.entangled_id
    }

    /// Get our public key.
    #[must_use]
    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }

    /// Get our public key as bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    /// Get current epoch.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Create a new signed heartbeat.
    pub fn create_heartbeat(&mut self) -> Result<SignedHeartbeat, AttestationError> {
        let epoch = current_epoch(HeartbeatConfig::default().interval_secs);
        self.current_epoch = epoch;

        let timestamp = current_timestamp();

        // Generate random nonce
        let mut nonce = [0u8; 16];
        for byte in &mut nonce {
            *byte = fastrand::u8(..);
        }

        // Create heartbeat without signature first
        let mut heartbeat = SignedHeartbeat {
            entangled_id: self.entangled_id,
            epoch,
            timestamp,
            nonce,
            signature: Vec::new(),
        };

        // Sign the payload
        let payload = heartbeat.payload();
        let signature = ml_dsa_sign(&self.secret_key, &payload)
            .map_err(|e| AttestationError::CryptoError(format!("Signing failed: {}", e)))?;

        heartbeat.signature = signature.as_bytes().to_vec();

        Ok(heartbeat)
    }

    /// Create a heartbeat for a specific epoch (for testing).
    pub fn create_heartbeat_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<SignedHeartbeat, AttestationError> {
        let timestamp = current_timestamp();

        let mut nonce = [0u8; 16];
        for byte in &mut nonce {
            *byte = fastrand::u8(..);
        }

        let mut heartbeat = SignedHeartbeat {
            entangled_id: self.entangled_id,
            epoch,
            timestamp,
            nonce,
            signature: Vec::new(),
        };

        let payload = heartbeat.payload();
        let signature = ml_dsa_sign(&self.secret_key, &payload)
            .map_err(|e| AttestationError::CryptoError(format!("Signing failed: {}", e)))?;

        heartbeat.signature = signature.as_bytes().to_vec();

        Ok(heartbeat)
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

/// Get current epoch number based on interval.
fn current_epoch(interval_secs: u64) -> u64 {
    current_timestamp() / interval_secs
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quantum_crypto::ant_quic_integration::generate_ml_dsa_keypair;

    #[test]
    fn test_heartbeat_creation_and_verification() {
        let (pk, sk) = generate_ml_dsa_keypair().expect("keygen");
        let entangled_id = [42u8; 32];

        let mut signer = HeartbeatSigner::new(entangled_id, pk.clone(), sk);
        let heartbeat = signer.create_heartbeat().expect("create heartbeat");

        assert_eq!(heartbeat.entangled_id, entangled_id);
        assert!(!heartbeat.signature.is_empty());

        // Verify signature
        heartbeat.verify_signature(&pk).expect("signature should be valid");
    }

    #[test]
    fn test_heartbeat_full_verification() {
        let (pk, sk) = generate_ml_dsa_keypair().expect("keygen");
        let entangled_id = [42u8; 32];

        let mut signer = HeartbeatSigner::new(entangled_id, pk.clone(), sk);
        let heartbeat = signer.create_heartbeat().expect("create heartbeat");

        let config = HeartbeatConfig::standard();
        let result = heartbeat.verify(&pk, &config).expect("verify");

        assert!(result.is_valid());
    }

    #[test]
    fn test_heartbeat_wrong_key_fails() {
        let (pk1, sk1) = generate_ml_dsa_keypair().expect("keygen");
        let (pk2, _sk2) = generate_ml_dsa_keypair().expect("keygen");
        let entangled_id = [42u8; 32];

        let mut signer = HeartbeatSigner::new(entangled_id, pk1, sk1);
        let heartbeat = signer.create_heartbeat().expect("create heartbeat");

        // Verify with wrong key should fail
        let config = HeartbeatConfig::standard();
        let result = heartbeat.verify(&pk2, &config).expect("verify");

        assert!(!result.is_valid());
        assert!(matches!(result, HeartbeatVerifyResult::InvalidSignature(_)));
    }

    #[test]
    fn test_heartbeat_tampered_fails() {
        let (pk, sk) = generate_ml_dsa_keypair().expect("keygen");
        let entangled_id = [42u8; 32];

        let mut signer = HeartbeatSigner::new(entangled_id, pk.clone(), sk);
        let mut heartbeat = signer.create_heartbeat().expect("create heartbeat");

        // Tamper with the heartbeat
        heartbeat.epoch += 1;

        // Verification should fail
        let config = HeartbeatConfig::standard();
        let result = heartbeat.verify(&pk, &config).expect("verify");

        assert!(!result.is_valid());
    }

    #[test]
    fn test_heartbeat_freshness() {
        let heartbeat = SignedHeartbeat {
            entangled_id: [0u8; 32],
            epoch: 0,
            timestamp: current_timestamp(),
            nonce: [0u8; 16],
            signature: vec![],
        };

        assert!(heartbeat.is_fresh(60));  // Should be fresh within 60 seconds

        let old_heartbeat = SignedHeartbeat {
            entangled_id: [0u8; 32],
            epoch: 0,
            timestamp: current_timestamp().saturating_sub(120),  // 2 minutes ago
            nonce: [0u8; 16],
            signature: vec![],
        };

        assert!(!old_heartbeat.is_fresh(60));  // Should be stale
    }

    #[test]
    fn test_config_presets() {
        let standard = HeartbeatConfig::standard();
        assert_eq!(standard.interval_secs, 60);

        let fast = HeartbeatConfig::fast();
        assert_eq!(fast.interval_secs, 5);

        let relaxed = HeartbeatConfig::relaxed();
        assert_eq!(relaxed.interval_secs, 300);
    }

    #[test]
    fn test_payload_deterministic() {
        let heartbeat = SignedHeartbeat {
            entangled_id: [1u8; 32],
            epoch: 100,
            timestamp: 1234567890,
            nonce: [2u8; 16],
            signature: vec![],
        };

        let payload1 = heartbeat.payload();
        let payload2 = heartbeat.payload();

        assert_eq!(payload1, payload2);
        assert_eq!(payload1.len(), 64);  // 32 + 8 + 8 + 16
    }
}
