// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Integration tests for zkVM attestation proof generation and verification.
//!
//! These tests verify the SP1-based zero-knowledge proof system for Entangled
//! Attestation. The proofs demonstrate correct derivation of EntangledId without
//! revealing the full public key or nonce.
//!
//! ## Test Strategy (TDD)
//!
//! 1. Tests are written FIRST before implementation
//! 2. Tests initially fail (no prover/verifier implemented)
//! 3. Implementation makes tests pass
//! 4. Refactor while keeping tests green
//!
//! ## Security Properties Tested
//!
//! - Correct derivation is provable
//! - Invalid derivations cannot be proven
//! - Proofs are bound to specific EntangledIds
//! - Stale proofs are rejected
//! - Binary allowlist enforcement works

use saorsa_core::attestation::{
    AttestationConfig, AttestationProofPublicInputs, AttestationProofResult,
    AttestationProofWitness, EntangledId,
};
use saorsa_core::quantum_crypto::generate_ml_dsa_keypair;
use std::time::{SystemTime, UNIX_EPOCH};

/// Helper to get current Unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(std::time::Duration::from_secs(0))
        .as_secs()
}

// ============================================================================
// Module: Mock Prover/Verifier for Initial TDD Phase
// ============================================================================
//
// These mock implementations allow tests to compile and define expected behavior.
// They will be replaced with real SP1 implementations.

mod mock_zkvm {
    use super::*;

    /// Mock proof structure (will be replaced with SP1CoreProof)
    ///
    /// Fields are intentionally kept for API compatibility with real SP1 proofs,
    /// even though they're not used in the mock implementation.
    #[derive(Clone, Debug)]
    #[allow(dead_code)]
    pub struct AttestationProof {
        /// Serialized proof bytes
        pub proof_bytes: Vec<u8>,
        /// Public values committed to the proof
        pub public_inputs: AttestationProofPublicInputs,
        /// Verification key hash
        pub vkey_hash: [u8; 32],
    }

    /// Mock prover for TDD (will be replaced with SP1 ProverClient)
    pub struct MockAttestationProver;

    impl MockAttestationProver {
        pub fn new() -> Self {
            Self
        }

        /// Generate a mock proof that computes the correct public outputs
        /// In the real implementation, this runs the SP1 guest program
        pub fn generate_proof(
            &self,
            witness: &AttestationProofWitness,
        ) -> Result<AttestationProof, String> {
            // Compute expected outputs (same as zkVM would compute)
            let public_inputs = witness.compute_public_outputs();

            Ok(AttestationProof {
                proof_bytes: vec![0u8; 32], // Mock proof
                public_inputs,
                vkey_hash: [0u8; 32],
            })
        }
    }

    /// Mock verifier for TDD (will be replaced with sp1-verifier)
    pub struct MockAttestationVerifier {
        pub allowed_binaries: Vec<[u8; 32]>,
        pub max_proof_age_secs: u64,
    }

    impl MockAttestationVerifier {
        pub fn new(allowed_binaries: Vec<[u8; 32]>, max_proof_age_secs: u64) -> Self {
            Self {
                allowed_binaries,
                max_proof_age_secs,
            }
        }

        /// Verify a proof against an expected EntangledId
        pub fn verify(
            &self,
            proof: &AttestationProof,
            expected_entangled_id: &[u8; 32],
            current_time: u64,
        ) -> AttestationProofResult {
            // In mock, we skip cryptographic verification of proof_bytes
            // Real implementation uses sp1_verifier::CoreProofVerifier

            // 1. Check EntangledId matches
            if &proof.public_inputs.entangled_id != expected_entangled_id {
                return AttestationProofResult::IdMismatch;
            }

            // 2. Check freshness
            if !proof
                .public_inputs
                .is_fresh(self.max_proof_age_secs, current_time)
            {
                return AttestationProofResult::Stale;
            }

            // 3. Check binary allowlist
            if !self.allowed_binaries.is_empty()
                && !self
                    .allowed_binaries
                    .contains(&proof.public_inputs.binary_hash)
            {
                return AttestationProofResult::BinaryNotAllowed;
            }

            AttestationProofResult::Valid
        }
    }
}

use mock_zkvm::{MockAttestationProver, MockAttestationVerifier};

// ============================================================================
// Test: Basic Proof Generation
// ============================================================================

#[test]
fn test_proof_generation_produces_valid_public_outputs() {
    // Arrange
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let binary_hash = [0x42u8; 32];
    let nonce = 12345u64;
    let timestamp = current_timestamp();

    let witness =
        AttestationProofWitness::new(pk.as_bytes().to_vec(), binary_hash, nonce, timestamp);

    let prover = MockAttestationProver::new();

    // Act
    let proof = prover
        .generate_proof(&witness)
        .expect("proof generation failed");

    // Assert: Public outputs match expected values
    let expected_id =
        saorsa_logic::attestation::derive_entangled_id(pk.as_bytes(), &binary_hash, nonce);
    assert_eq!(proof.public_inputs.entangled_id, expected_id);
    assert_eq!(proof.public_inputs.binary_hash, binary_hash);
    assert_eq!(proof.public_inputs.proof_timestamp, timestamp);

    // Public key hash should be BLAKE3(public_key)
    let expected_pk_hash = *blake3::hash(pk.as_bytes()).as_bytes();
    assert_eq!(proof.public_inputs.public_key_hash, expected_pk_hash);
}

#[test]
fn test_proof_generation_with_allowlist() {
    // Arrange
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let binary_hash = [0x42u8; 32];
    let allowlist = vec![[0x41u8; 32], binary_hash, [0x43u8; 32]];

    let witness =
        AttestationProofWitness::new(pk.as_bytes().to_vec(), binary_hash, 0, current_timestamp())
            .with_allowlist(allowlist);

    let prover = MockAttestationProver::new();

    // Act
    let proof = prover.generate_proof(&witness);

    // Assert: Proof succeeds when binary is in allowlist
    assert!(proof.is_ok());
}

// ============================================================================
// Test: Proof Verification - Valid Proofs
// ============================================================================

#[test]
fn test_verification_succeeds_for_valid_proof() {
    // Arrange
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let binary_hash = [0x42u8; 32];
    let nonce = 12345u64;
    let timestamp = current_timestamp();

    let witness =
        AttestationProofWitness::new(pk.as_bytes().to_vec(), binary_hash, nonce, timestamp);

    let prover = MockAttestationProver::new();
    let proof = prover
        .generate_proof(&witness)
        .expect("proof generation failed");

    // Derive the expected EntangledId
    let entangled_id = EntangledId::derive(&pk, &binary_hash, nonce);

    // Create verifier with permissive settings
    let verifier = MockAttestationVerifier::new(vec![], 3600); // 1 hour max age

    // Act
    let result = verifier.verify(&proof, entangled_id.id(), timestamp + 10);

    // Assert
    assert_eq!(result, AttestationProofResult::Valid);
}

#[test]
fn test_verification_with_binary_allowlist() {
    // Arrange
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let binary_hash = [0x42u8; 32];
    let timestamp = current_timestamp();

    let witness = AttestationProofWitness::new(pk.as_bytes().to_vec(), binary_hash, 0, timestamp);

    let prover = MockAttestationProver::new();
    let proof = prover
        .generate_proof(&witness)
        .expect("proof generation failed");

    let entangled_id = EntangledId::derive(&pk, &binary_hash, 0);

    // Verifier requires specific binaries
    let verifier =
        MockAttestationVerifier::new(vec![[0x41u8; 32], binary_hash, [0x43u8; 32]], 3600);

    // Act
    let result = verifier.verify(&proof, entangled_id.id(), timestamp + 10);

    // Assert
    assert_eq!(result, AttestationProofResult::Valid);
}

// ============================================================================
// Test: Proof Verification - Invalid Proofs
// ============================================================================

#[test]
fn test_verification_fails_for_wrong_entangled_id() {
    // Arrange
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let binary_hash = [0x42u8; 32];
    let timestamp = current_timestamp();

    let witness =
        AttestationProofWitness::new(pk.as_bytes().to_vec(), binary_hash, 12345, timestamp);

    let prover = MockAttestationProver::new();
    let proof = prover
        .generate_proof(&witness)
        .expect("proof generation failed");

    // Use a different EntangledId for verification
    let wrong_id = [0x99u8; 32];

    let verifier = MockAttestationVerifier::new(vec![], 3600);

    // Act
    let result = verifier.verify(&proof, &wrong_id, timestamp + 10);

    // Assert
    assert_eq!(result, AttestationProofResult::IdMismatch);
}

#[test]
fn test_verification_fails_for_stale_proof() {
    // Arrange
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let binary_hash = [0x42u8; 32];
    let old_timestamp = 1000u64; // Very old timestamp

    let witness =
        AttestationProofWitness::new(pk.as_bytes().to_vec(), binary_hash, 0, old_timestamp);

    let prover = MockAttestationProver::new();
    let proof = prover
        .generate_proof(&witness)
        .expect("proof generation failed");

    let entangled_id = EntangledId::derive(&pk, &binary_hash, 0);

    // Verifier with 1 hour max age
    let verifier = MockAttestationVerifier::new(vec![], 3600);

    // Act: Verify with current time far in the future
    let result = verifier.verify(&proof, entangled_id.id(), current_timestamp());

    // Assert
    assert_eq!(result, AttestationProofResult::Stale);
}

#[test]
fn test_verification_fails_for_disallowed_binary() {
    // Arrange
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let binary_hash = [0x42u8; 32];
    let timestamp = current_timestamp();

    let witness = AttestationProofWitness::new(pk.as_bytes().to_vec(), binary_hash, 0, timestamp);

    let prover = MockAttestationProver::new();
    let proof = prover
        .generate_proof(&witness)
        .expect("proof generation failed");

    let entangled_id = EntangledId::derive(&pk, &binary_hash, 0);

    // Verifier with restrictive allowlist (doesn't include our binary)
    let verifier = MockAttestationVerifier::new(
        vec![[0x11u8; 32], [0x22u8; 32]], // Different binaries
        3600,
    );

    // Act
    let result = verifier.verify(&proof, entangled_id.id(), timestamp + 10);

    // Assert
    assert_eq!(result, AttestationProofResult::BinaryNotAllowed);
}

// ============================================================================
// Test: Proof Properties
// ============================================================================

#[test]
fn test_proof_hides_full_public_key() {
    // Arrange
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let binary_hash = [0x42u8; 32];

    let witness =
        AttestationProofWitness::new(pk.as_bytes().to_vec(), binary_hash, 0, current_timestamp());

    let prover = MockAttestationProver::new();
    let proof = prover
        .generate_proof(&witness)
        .expect("proof generation failed");

    // Assert: Proof public inputs don't contain the full public key
    // Only the 32-byte hash is revealed, not the 1952-byte key
    assert_eq!(proof.public_inputs.public_key_hash.len(), 32);

    // The public key hash should NOT allow recovery of the full key
    // (BLAKE3 is a one-way function)
    let pk_bytes = pk.as_bytes();
    assert_eq!(pk_bytes.len(), 1952); // Full key is much larger
    assert_ne!(&proof.public_inputs.public_key_hash[..], &pk_bytes[..32]);
}

#[test]
fn test_same_inputs_produce_same_proof_outputs() {
    // Arrange
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let binary_hash = [0x42u8; 32];
    let nonce = 12345u64;
    let timestamp = 1700000000u64;

    let witness1 =
        AttestationProofWitness::new(pk.as_bytes().to_vec(), binary_hash, nonce, timestamp);

    let witness2 =
        AttestationProofWitness::new(pk.as_bytes().to_vec(), binary_hash, nonce, timestamp);

    let prover = MockAttestationProver::new();

    // Act
    let proof1 = prover.generate_proof(&witness1).expect("proof1 failed");
    let proof2 = prover.generate_proof(&witness2).expect("proof2 failed");

    // Assert: Deterministic computation
    assert_eq!(
        proof1.public_inputs.entangled_id,
        proof2.public_inputs.entangled_id
    );
    assert_eq!(
        proof1.public_inputs.public_key_hash,
        proof2.public_inputs.public_key_hash
    );
}

#[test]
fn test_different_nonces_produce_different_entangled_ids() {
    // Arrange
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let binary_hash = [0x42u8; 32];
    let timestamp = current_timestamp();

    let witness1 =
        AttestationProofWitness::new(pk.as_bytes().to_vec(), binary_hash, 12345, timestamp);

    let witness2 = AttestationProofWitness::new(
        pk.as_bytes().to_vec(),
        binary_hash,
        67890, // Different nonce
        timestamp,
    );

    let prover = MockAttestationProver::new();

    // Act
    let proof1 = prover.generate_proof(&witness1).expect("proof1 failed");
    let proof2 = prover.generate_proof(&witness2).expect("proof2 failed");

    // Assert: Different nonces produce different IDs
    assert_ne!(
        proof1.public_inputs.entangled_id,
        proof2.public_inputs.entangled_id
    );
    // But same public key hash (key didn't change)
    assert_eq!(
        proof1.public_inputs.public_key_hash,
        proof2.public_inputs.public_key_hash
    );
}

// ============================================================================
// Test: Integration with Existing AttestationConfig
// ============================================================================

#[test]
fn test_proof_verification_respects_config_enforcement() {
    // Arrange
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let binary_hash = [0x42u8; 32];
    let timestamp = current_timestamp();

    let witness = AttestationProofWitness::new(pk.as_bytes().to_vec(), binary_hash, 0, timestamp);

    // Create production config with specific allowed binaries
    let config = AttestationConfig::production(vec![binary_hash]);

    let prover = MockAttestationProver::new();
    let proof = prover
        .generate_proof(&witness)
        .expect("proof generation failed");

    // Use config's allowlist for verification
    let verifier = MockAttestationVerifier::new(config.allowed_binary_hashes.clone(), 3600);

    let entangled_id = EntangledId::derive(&pk, &binary_hash, 0);

    // Act
    let result = verifier.verify(&proof, entangled_id.id(), timestamp + 10);

    // Assert
    assert_eq!(result, AttestationProofResult::Valid);
}

#[test]
fn test_proof_verification_with_development_config() {
    // Arrange
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let any_binary = [0x99u8; 32]; // Any binary hash
    let timestamp = current_timestamp();

    let witness = AttestationProofWitness::new(pk.as_bytes().to_vec(), any_binary, 0, timestamp);

    // Development config allows all binaries
    let config = AttestationConfig::development();

    let prover = MockAttestationProver::new();
    let proof = prover
        .generate_proof(&witness)
        .expect("proof generation failed");

    // Empty allowlist means all binaries allowed
    let verifier = MockAttestationVerifier::new(config.allowed_binary_hashes.clone(), 3600);

    let entangled_id = EntangledId::derive(&pk, &any_binary, 0);

    // Act
    let result = verifier.verify(&proof, entangled_id.id(), timestamp + 10);

    // Assert
    assert_eq!(result, AttestationProofResult::Valid);
}

// ============================================================================
// Test: Edge Cases
// ============================================================================

#[test]
fn test_proof_with_future_timestamp_rejected() {
    // Arrange
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let binary_hash = [0x42u8; 32];
    let future_timestamp = current_timestamp() + 10000; // Far in the future

    let witness =
        AttestationProofWitness::new(pk.as_bytes().to_vec(), binary_hash, 0, future_timestamp);

    let prover = MockAttestationProver::new();
    let proof = prover
        .generate_proof(&witness)
        .expect("proof generation failed");

    let entangled_id = EntangledId::derive(&pk, &binary_hash, 0);
    let verifier = MockAttestationVerifier::new(vec![], 3600);

    // Act: Verify with current time (proof claims to be from the future)
    let result = verifier.verify(&proof, entangled_id.id(), current_timestamp());

    // Assert: Future timestamps should fail freshness check
    // (is_fresh returns false if current_time < proof_timestamp)
    assert_eq!(result, AttestationProofResult::Stale);
}

#[test]
fn test_empty_allowlist_allows_any_binary() {
    // Arrange
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let random_binary = [0xFFu8; 32];
    let timestamp = current_timestamp();

    let witness = AttestationProofWitness::new(pk.as_bytes().to_vec(), random_binary, 0, timestamp);

    let prover = MockAttestationProver::new();
    let proof = prover
        .generate_proof(&witness)
        .expect("proof generation failed");

    let entangled_id = EntangledId::derive(&pk, &random_binary, 0);

    // Verifier with empty allowlist (permissive mode)
    let verifier = MockAttestationVerifier::new(vec![], 3600);

    // Act
    let result = verifier.verify(&proof, entangled_id.id(), timestamp + 10);

    // Assert
    assert_eq!(result, AttestationProofResult::Valid);
}
