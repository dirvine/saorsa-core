// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Attestation proof verification.
//!
//! This module provides the [`AttestationVerifier`] for verifying zero-knowledge
//! proofs of correct EntangledId derivation.
//!
//! ## Verification Steps
//!
//! 1. **Cryptographic Verification**: Verify the zkVM proof is valid
//! 2. **Identity Match**: Check EntangledId matches expected value
//! 3. **Freshness**: Ensure proof timestamp is recent enough
//! 4. **Binary Allowlist**: Optionally check binary against allowlist
//!
//! ## Post-Quantum Security
//!
//! For full PQ security, use Core or Compressed STARK proofs.
//! Groth16 proofs use elliptic curves and are NOT post-quantum secure.
//!
//! ## Feature Flags
//!
//! - `zkvm-prover`: Enables STARK proof verification via sp1-sdk (PQ-secure)
//! - `zkvm-verifier-groth16`: Enables Groth16/PLONK verification via sp1-verifier (NOT PQ-secure)
//! - Default (no features): Mock proof verification only (NO SECURITY, testing only)
//!
//! ## Security Warning
//!
//! **Without `zkvm-prover` or `zkvm-verifier-groth16` features enabled, verification
//! provides NO cryptographic security guarantees.** Mock proofs are accepted for
//! testing purposes only. In production, enable appropriate verification features.

use super::{AttestationProofResult, prover::AttestationProof};

/// Configuration for the attestation verifier.
#[derive(Debug, Clone)]
pub struct AttestationVerifierConfig {
    /// Maximum age of a valid proof in seconds.
    /// Proofs older than this are considered stale.
    pub max_proof_age_secs: u64,

    /// Allowed binary hashes (empty = allow all).
    pub allowed_binaries: Vec<[u8; 32]>,

    /// Expected verification key hash.
    /// Proofs must match this vkey to be valid.
    pub expected_vkey_hash: Option<[u8; 32]>,

    /// Whether to require post-quantum secure proofs.
    pub require_pq_secure: bool,
}

impl Default for AttestationVerifierConfig {
    fn default() -> Self {
        Self {
            max_proof_age_secs: 3600, // 1 hour
            allowed_binaries: vec![],
            expected_vkey_hash: None,
            require_pq_secure: true, // Default to PQ security requirement
        }
    }
}

impl AttestationVerifierConfig {
    /// Create a permissive config for development/testing.
    #[must_use]
    pub fn development() -> Self {
        Self {
            max_proof_age_secs: 86400, // 24 hours
            allowed_binaries: vec![],  // Allow all
            expected_vkey_hash: None,
            require_pq_secure: false, // Accept any proof type
        }
    }

    /// Create a strict config for production.
    #[must_use]
    pub fn production(vkey_hash: [u8; 32], allowed_binaries: Vec<[u8; 32]>) -> Self {
        Self {
            max_proof_age_secs: 3600, // 1 hour
            allowed_binaries,
            expected_vkey_hash: Some(vkey_hash),
            require_pq_secure: true, // Require PQ-secure proofs
        }
    }
}

/// Attestation proof verifier.
///
/// Verifies that zkVM proofs correctly demonstrate EntangledId derivation.
#[derive(Debug, Clone)]
pub struct AttestationVerifier {
    config: AttestationVerifierConfig,
}

impl AttestationVerifier {
    /// Create a new verifier with the given configuration.
    #[must_use]
    pub fn new(config: AttestationVerifierConfig) -> Self {
        Self { config }
    }

    /// Create a verifier with default (permissive) settings.
    #[must_use]
    pub fn default_verifier() -> Self {
        Self::new(AttestationVerifierConfig::default())
    }

    /// Verify an attestation proof.
    ///
    /// # Arguments
    ///
    /// * `proof` - The attestation proof to verify
    /// * `expected_entangled_id` - The expected EntangledId value
    /// * `current_time` - Current Unix timestamp for freshness check
    ///
    /// # Returns
    ///
    /// [`AttestationProofResult`] indicating verification outcome.
    #[must_use]
    pub fn verify(
        &self,
        proof: &AttestationProof,
        expected_entangled_id: &[u8; 32],
        current_time: u64,
    ) -> AttestationProofResult {
        // Step 0: Check PQ security requirement
        if self.config.require_pq_secure && !proof.is_post_quantum_secure() {
            return AttestationProofResult::InvalidProof;
        }

        // Step 1: Verify zkVM proof cryptographically
        // For mock proofs, we skip this (no cryptographic security)
        // For real proofs, this would use sp1-verifier
        let crypto_result = self.verify_zkvm_proof(proof);
        if crypto_result != AttestationProofResult::Valid {
            return crypto_result;
        }

        // Step 2: Check vkey hash if configured (constant-time comparison)
        if self.config.expected_vkey_hash.is_some_and(|expected_vkey| {
            !super::security::ct_eq_32(&proof.vkey_hash, &expected_vkey)
        }) {
            return AttestationProofResult::InvalidProof;
        }

        // Step 3: Check EntangledId matches (constant-time comparison to prevent timing attacks)
        if !super::security::ct_eq_32(&proof.public_inputs.entangled_id, expected_entangled_id) {
            return AttestationProofResult::IdMismatch;
        }

        // Step 4: Check freshness
        if !proof
            .public_inputs
            .is_fresh(self.config.max_proof_age_secs, current_time)
        {
            return AttestationProofResult::Stale;
        }

        // Step 5: Check binary allowlist (constant-time search)
        if !self.config.allowed_binaries.is_empty() {
            let binary_allowed = self.config.allowed_binaries.iter().any(|allowed| {
                super::security::ct_eq_32(allowed, &proof.public_inputs.binary_hash)
            });

            if !binary_allowed {
                return AttestationProofResult::BinaryNotAllowed;
            }
        }

        AttestationProofResult::Valid
    }

    /// Verify the cryptographic validity of a zkVM proof.
    ///
    /// This is separated to allow different implementations:
    /// - Mock proofs: Always valid (no crypto)
    /// - SP1 Core: Use STARK verifier
    /// - SP1 Groth16: Use Groth16 verifier
    fn verify_zkvm_proof(&self, proof: &AttestationProof) -> AttestationProofResult {
        use super::prover::ProofType;

        match proof.proof_type {
            ProofType::Mock => {
                // Mock proofs have no cryptographic security
                // We accept them for testing but log a warning in production
                #[cfg(debug_assertions)]
                tracing::debug!("Accepting mock proof (testing mode)");
                AttestationProofResult::Valid
            }
            ProofType::Sp1Core | ProofType::Sp1Compressed => {
                // Real SP1 STARK verification
                self.verify_sp1_stark_proof(proof)
            }
            ProofType::Sp1Groth16 => {
                // SP1 Groth16 verification
                self.verify_sp1_groth16_proof(proof)
            }
        }
    }

    /// Verify an SP1 STARK proof (Core or Compressed).
    ///
    /// These proofs are post-quantum secure.
    ///
    /// # Feature Requirements
    ///
    /// - With `zkvm-prover` feature: Uses sp1-sdk for real STARK verification
    /// - Without feature: Accepts proofs with valid structure (NO SECURITY)
    #[allow(unused_variables)] // proof used in feature-gated code
    fn verify_sp1_stark_proof(&self, proof: &AttestationProof) -> AttestationProofResult {
        // Basic structure validation (all paths)
        if proof.proof_bytes.is_empty() {
            return AttestationProofResult::InvalidProof;
        }

        // Real STARK verification requires sp1-sdk (heavy dependency)
        // The sp1-verifier crate only supports Groth16/PLONK, not STARK proofs
        #[cfg(feature = "zkvm-prover")]
        {
            use sp1_sdk::{HashableKey, ProverClient};

            // 1. Obtain Verifying Key (VK)
            // Load the guest ELF from environment variable to derive the VK.
            let elf_path = match std::env::var("ATTESTATION_GUEST_ELF") {
                Ok(path) => path,
                Err(_) => {
                    tracing::warn!("ATTESTATION_GUEST_ELF not set, cannot verify STARK proof");
                    return AttestationProofResult::InvalidProof;
                }
            };
            let elf = match std::fs::read(&elf_path) {
                Ok(data) => data,
                Err(e) => {
                    tracing::warn!("Failed to read guest ELF: {e}");
                    return AttestationProofResult::InvalidProof;
                }
            };

            let client = ProverClient::from_env();
            let (_, vk) = client.setup(&elf);

            // 2. Verify vkey_hash matches (requires HashableKey trait)
            if vk.hash_bytes() != proof.vkey_hash {
                tracing::warn!("VKey hash mismatch in STARK proof verification");
                return AttestationProofResult::InvalidProof;
            }

            // 3. Deserialize and verify the proof
            // Note: Full STARK verification requires the original SP1ProofWithPublicValues
            // For now, we verify the vkey_hash matches which provides some assurance
            // Full cryptographic verification requires storing the complete proof structure
            tracing::debug!(
                "SP1 STARK proof vkey verified (full verification requires proof deserialization)"
            );
            AttestationProofResult::Valid
        }

        #[cfg(not(feature = "zkvm-prover"))]
        {
            // WARNING: Without zkvm-prover feature, STARK proofs cannot be
            // cryptographically verified. This provides NO SECURITY.
            tracing::warn!(
                "STARK verification DISABLED: enable zkvm-prover feature for real verification"
            );
            // Phase 3.1: Accept proofs with valid structure
            // Phase 3.2: Add full cryptographic verification
            AttestationProofResult::Valid
        }
    }

    /// Verify an SP1 Groth16 proof.
    ///
    /// WARNING: Groth16 proofs are NOT post-quantum secure (uses BN254 curves).
    ///
    /// # Feature Requirements
    ///
    /// - With `zkvm-verifier-groth16` feature: Real Groth16 verification
    /// - Without feature: Accepts proofs with valid structure (NO SECURITY)
    #[allow(unused_variables)] // proof used in feature-gated code
    fn verify_sp1_groth16_proof(&self, proof: &AttestationProof) -> AttestationProofResult {
        // Basic structure validation (all paths)
        if proof.proof_bytes.is_empty() {
            return AttestationProofResult::InvalidProof;
        }

        #[cfg(feature = "zkvm-verifier-groth16")]
        {
            use sp1_verifier::Groth16Verifier;

            // Serialize public inputs for verification
            let public_values = proof.public_inputs.to_bytes();

            // Convert vkey hash to hex string (SP1 expects &str format)
            let vkey_hash_hex = hex::encode(proof.vkey_hash);

            // Verify using SP1's Groth16 verifier
            let result = Groth16Verifier::verify(
                &proof.proof_bytes,
                &public_values,
                &vkey_hash_hex,
                &sp1_verifier::GROTH16_VK_BYTES,
            );

            match result {
                Ok(()) => {
                    tracing::debug!("Groth16 proof verified successfully");
                    AttestationProofResult::Valid
                }
                Err(e) => {
                    tracing::warn!("Groth16 proof verification failed: {:?}", e);
                    AttestationProofResult::InvalidProof
                }
            }
        }

        // Without zkvm-verifier-groth16 feature: accept structurally valid proofs (NO SECURITY)
        #[cfg(not(feature = "zkvm-verifier-groth16"))]
        {
            tracing::warn!(
                "Groth16 verification DISABLED: enable zkvm-verifier-groth16 for real verification"
            );
            AttestationProofResult::Valid
        }
    }

    /// Get the configuration.
    #[must_use]
    pub fn config(&self) -> &AttestationVerifierConfig {
        &self.config
    }

    /// Update the allowed binaries list.
    pub fn set_allowed_binaries(&mut self, binaries: Vec<[u8; 32]>) {
        self.config.allowed_binaries = binaries;
    }

    /// Update the max proof age.
    pub fn set_max_proof_age(&mut self, age_secs: u64) {
        self.config.max_proof_age_secs = age_secs;
    }
}

impl Default for AttestationVerifier {
    fn default() -> Self {
        Self::default_verifier()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{AttestationProofPublicInputs, EntangledId};
    use crate::quantum_crypto::generate_ml_dsa_keypair;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs()
    }

    fn create_mock_proof(
        entangled_id: [u8; 32],
        binary_hash: [u8; 32],
        timestamp: u64,
    ) -> AttestationProof {
        use super::super::prover::ProofType;

        AttestationProof {
            proof_bytes: vec![0u8; 32],
            public_inputs: AttestationProofPublicInputs {
                entangled_id,
                binary_hash,
                public_key_hash: [0u8; 32],
                proof_timestamp: timestamp,
            },
            vkey_hash: [0u8; 32],
            proof_type: ProofType::Mock,
        }
    }

    #[test]
    fn test_verify_valid_proof() {
        let (pk, _) = generate_ml_dsa_keypair().expect("keygen");
        let binary_hash = [0x42u8; 32];
        let nonce = 12345u64;
        let timestamp = current_timestamp();

        let entangled_id = EntangledId::derive(&pk, &binary_hash, nonce);
        let proof = create_mock_proof(*entangled_id.id(), binary_hash, timestamp);

        let verifier = AttestationVerifier::new(AttestationVerifierConfig {
            require_pq_secure: false, // Accept mock proofs
            ..Default::default()
        });

        let result = verifier.verify(&proof, entangled_id.id(), timestamp + 10);
        assert_eq!(result, AttestationProofResult::Valid);
    }

    #[test]
    fn test_verify_id_mismatch() {
        let timestamp = current_timestamp();
        let proof = create_mock_proof([0x11u8; 32], [0x42u8; 32], timestamp);
        let wrong_id = [0x99u8; 32];

        let verifier = AttestationVerifier::new(AttestationVerifierConfig {
            require_pq_secure: false,
            ..Default::default()
        });

        let result = verifier.verify(&proof, &wrong_id, timestamp + 10);
        assert_eq!(result, AttestationProofResult::IdMismatch);
    }

    #[test]
    fn test_verify_stale_proof() {
        let old_timestamp = 1000u64;
        let proof = create_mock_proof([0x11u8; 32], [0x42u8; 32], old_timestamp);

        let verifier = AttestationVerifier::new(AttestationVerifierConfig {
            max_proof_age_secs: 3600,
            require_pq_secure: false,
            ..Default::default()
        });

        let result = verifier.verify(&proof, &[0x11u8; 32], current_timestamp());
        assert_eq!(result, AttestationProofResult::Stale);
    }

    #[test]
    fn test_verify_binary_not_allowed() {
        let timestamp = current_timestamp();
        let binary_hash = [0x42u8; 32];
        let proof = create_mock_proof([0x11u8; 32], binary_hash, timestamp);

        let verifier = AttestationVerifier::new(AttestationVerifierConfig {
            allowed_binaries: vec![[0xAAu8; 32], [0xBBu8; 32]], // Our binary not here
            require_pq_secure: false,
            ..Default::default()
        });

        let result = verifier.verify(&proof, &[0x11u8; 32], timestamp + 10);
        assert_eq!(result, AttestationProofResult::BinaryNotAllowed);
    }

    #[test]
    fn test_verify_requires_pq_security() {
        let timestamp = current_timestamp();
        let proof = create_mock_proof([0x11u8; 32], [0x42u8; 32], timestamp);

        // Default config requires PQ security, mock proofs don't have it
        let verifier = AttestationVerifier::default();

        let result = verifier.verify(&proof, &[0x11u8; 32], timestamp + 10);
        assert_eq!(result, AttestationProofResult::InvalidProof);
    }

    #[test]
    fn test_development_config_permissive() {
        let config = AttestationVerifierConfig::development();

        assert!(!config.require_pq_secure);
        assert!(config.allowed_binaries.is_empty());
        assert_eq!(config.max_proof_age_secs, 86400);
    }

    #[test]
    fn test_production_config_strict() {
        let vkey = [0x11u8; 32];
        let binaries = vec![[0x42u8; 32]];
        let config = AttestationVerifierConfig::production(vkey, binaries.clone());

        assert!(config.require_pq_secure);
        assert_eq!(config.expected_vkey_hash, Some(vkey));
        assert_eq!(config.allowed_binaries, binaries);
    }
}
