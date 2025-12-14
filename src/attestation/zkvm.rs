// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! zkVM proof structures for Entangled Attestation.
//!
//! This module defines the types and structures needed for generating and
//! verifying zero-knowledge proofs of correct EntangledId derivation.
//!
//! ## Overview
//!
//! The Entangled Attestation system allows nodes to prove they are running
//! authorized software without revealing sensitive information. The proof
//! demonstrates:
//!
//! 1. **Correct Derivation**: `EntangledId = BLAKE3(PK || binary_hash || nonce)`
//! 2. **Binary Authorization**: `binary_hash ∈ allowed_binaries` (optional)
//! 3. **Key Binding**: The prover knows the full public key
//!
//! ## zkVM Execution Model
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────┐
//! │                        zkVM Guest Program                               │
//! ├────────────────────────────────────────────────────────────────────────┤
//! │  Private Inputs (witness - known only to prover):                      │
//! │    - public_key: [u8; 1952]     (ML-DSA-65 public key)                 │
//! │    - nonce: u64                  (unique per derivation)               │
//! │    - allowed_binaries: Vec<[u8;32]> (optional allowlist)              │
//! │                                                                        │
//! │  Computation (proven in zero-knowledge):                               │
//! │    1. entangled_id = BLAKE3(public_key || binary_hash || nonce)       │
//! │    2. public_key_hash = BLAKE3(public_key)                             │
//! │    3. if allowlist: assert!(binary_hash ∈ allowed_binaries)           │
//! │                                                                        │
//! │  Public Outputs (committed to proof):                                   │
//! │    - entangled_id: [u8; 32]                                            │
//! │    - binary_hash: [u8; 32]                                             │
//! │    - public_key_hash: [u8; 32]                                         │
//! │    - proof_timestamp: u64                                              │
//! └────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Security Properties
//!
//! - **Zero-Knowledge**: Verifiers learn only the public outputs, not the
//!   full public key, nonce, or which specific binary from the allowlist
//! - **Soundness**: A valid proof guarantees correct computation
//! - **Binding**: The EntangledId is cryptographically bound to the inputs
//!
//! ## Usage
//!
//! ### Phase 3 Integration (Future)
//!
//! ```ignore
//! // In zkVM guest program (e.g., SP1 or RISC Zero)
//! use saorsa_logic::attestation::{derive_entangled_id, verify_binary_allowlist};
//!
//! fn main() {
//!     // Read private inputs from prover
//!     let witness: AttestationProofWitness = sp1_zkvm::io::read();
//!
//!     // Perform computation
//!     let entangled_id = derive_entangled_id(
//!         &witness.public_key,
//!         &witness.binary_hash,
//!         witness.nonce,
//!     );
//!
//!     // Verify binary if allowlist provided
//!     if !witness.allowed_binaries.is_empty() {
//!         verify_binary_allowlist(&witness.binary_hash, &witness.allowed_binaries)
//!             .expect("binary not in allowlist");
//!     }
//!
//!     // Commit public outputs
//!     let output = AttestationProofPublicInputs {
//!         entangled_id,
//!         binary_hash: witness.binary_hash,
//!         public_key_hash: blake3::hash(&witness.public_key).into(),
//!         proof_timestamp: witness.timestamp,
//!     };
//!     sp1_zkvm::io::commit(&output);
//! }
//! ```

use serde::{Deserialize, Serialize};

/// Public inputs committed to a zkVM attestation proof.
///
/// These values are visible to verifiers and committed to the proof.
/// They establish what the proof demonstrates without revealing
/// the private witness data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationProofPublicInputs {
    /// The derived EntangledId: `BLAKE3(PK || binary_hash || nonce)`
    pub entangled_id: [u8; 32],

    /// Hash of the binary this identity is bound to.
    ///
    /// This is public so verifiers can check it against their allowlist.
    pub binary_hash: [u8; 32],

    /// Hash of the public key: `BLAKE3(public_key)`
    ///
    /// This binds the proof to a specific key without revealing
    /// the full 1952-byte ML-DSA-65 public key.
    pub public_key_hash: [u8; 32],

    /// Unix timestamp when the proof was generated.
    ///
    /// Used for freshness checks and preventing replay attacks.
    pub proof_timestamp: u64,
}

/// Private witness data for proof generation.
///
/// These values are known only to the prover and are NOT revealed
/// in the proof. The zkVM proves correct computation over this
/// data without exposing it.
#[derive(Debug, Clone)]
pub struct AttestationProofWitness {
    /// Full ML-DSA-65 public key (1952 bytes).
    ///
    /// The prover knows this key, proving they control the identity.
    pub public_key: Vec<u8>,

    /// The binary hash this identity is bound to.
    pub binary_hash: [u8; 32],

    /// Nonce used in derivation.
    ///
    /// This adds uniqueness to each derivation, preventing
    /// correlation of proofs from the same key/binary.
    pub nonce: u64,

    /// Optional allowlist of authorized binary hashes.
    ///
    /// If non-empty, the proof also verifies that `binary_hash`
    /// is in this list. The verifier doesn't learn which specific
    /// binary from the list.
    pub allowed_binaries: Vec<[u8; 32]>,

    /// Timestamp for proof generation.
    pub timestamp: u64,
}

impl AttestationProofWitness {
    /// Create a new attestation proof witness.
    #[must_use]
    pub fn new(public_key: Vec<u8>, binary_hash: [u8; 32], nonce: u64, timestamp: u64) -> Self {
        Self {
            public_key,
            binary_hash,
            nonce,
            allowed_binaries: Vec::new(),
            timestamp,
        }
    }

    /// Add an allowlist for binary verification.
    #[must_use]
    pub fn with_allowlist(mut self, allowlist: Vec<[u8; 32]>) -> Self {
        self.allowed_binaries = allowlist;
        self
    }

    /// Compute the expected public outputs from this witness.
    ///
    /// This is useful for testing and verification outside zkVM.
    #[must_use]
    pub fn compute_public_outputs(&self) -> AttestationProofPublicInputs {
        let entangled_id = saorsa_logic::attestation::derive_entangled_id(
            &self.public_key,
            &self.binary_hash,
            self.nonce,
        );
        let public_key_hash = *blake3::hash(&self.public_key).as_bytes();

        AttestationProofPublicInputs {
            entangled_id,
            binary_hash: self.binary_hash,
            public_key_hash,
            proof_timestamp: self.timestamp,
        }
    }

    /// Verify that the binary hash is in the allowlist (if provided).
    ///
    /// Returns `Ok(())` if the allowlist is empty or the binary is allowed.
    pub fn verify_allowlist(&self) -> Result<(), saorsa_logic::error::LogicError> {
        if self.allowed_binaries.is_empty() {
            return Ok(());
        }
        saorsa_logic::attestation::verify_binary_allowlist(
            &self.binary_hash,
            &self.allowed_binaries,
        )
    }
}

impl AttestationProofPublicInputs {
    /// Serialize public inputs to bytes for verification.
    ///
    /// This format is used by SP1 verifiers to check the proof.
    /// Layout: entangled_id || binary_hash || public_key_hash || timestamp (big-endian)
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 32 + 32 + 8);
        bytes.extend_from_slice(&self.entangled_id);
        bytes.extend_from_slice(&self.binary_hash);
        bytes.extend_from_slice(&self.public_key_hash);
        bytes.extend_from_slice(&self.proof_timestamp.to_be_bytes());
        bytes
    }

    /// Verify that this proof output matches an expected EntangledId.
    ///
    /// This is used by verifiers who already know the EntangledId
    /// and want to confirm the proof is for that identity.
    #[must_use]
    pub fn matches_entangled_id(&self, expected: &[u8; 32]) -> bool {
        &self.entangled_id == expected
    }

    /// Check if the proof is fresh (within a time window).
    ///
    /// # Arguments
    ///
    /// * `max_age_secs` - Maximum age of the proof in seconds
    /// * `current_time` - Current Unix timestamp
    #[must_use]
    pub fn is_fresh(&self, max_age_secs: u64, current_time: u64) -> bool {
        if current_time < self.proof_timestamp {
            return false; // Future timestamp
        }
        current_time - self.proof_timestamp <= max_age_secs
    }
}

/// Result of verifying an attestation proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationProofResult {
    /// Proof is valid and fresh.
    Valid,
    /// Proof is valid but stale (older than max age).
    Stale,
    /// Binary hash is not in the verifier's allowlist.
    BinaryNotAllowed,
    /// Proof verification failed (invalid zkVM proof).
    InvalidProof,
    /// EntangledId doesn't match expected value.
    IdMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quantum_crypto::generate_ml_dsa_keypair;

    #[test]
    fn test_witness_compute_public_outputs() {
        let (pk, _) = generate_ml_dsa_keypair().expect("keygen failed");
        let binary_hash = [0x42u8; 32];
        let nonce = 12345u64;
        let timestamp = 1700000000u64;

        let witness =
            AttestationProofWitness::new(pk.as_bytes().to_vec(), binary_hash, nonce, timestamp);

        let outputs = witness.compute_public_outputs();

        // Verify the entangled ID matches direct derivation
        let expected_id =
            saorsa_logic::attestation::derive_entangled_id(pk.as_bytes(), &binary_hash, nonce);
        assert_eq!(outputs.entangled_id, expected_id);

        // Verify the public key hash
        let expected_pk_hash = *blake3::hash(pk.as_bytes()).as_bytes();
        assert_eq!(outputs.public_key_hash, expected_pk_hash);

        // Verify other fields
        assert_eq!(outputs.binary_hash, binary_hash);
        assert_eq!(outputs.proof_timestamp, timestamp);
    }

    #[test]
    fn test_witness_with_allowlist() {
        let (pk, _) = generate_ml_dsa_keypair().expect("keygen failed");
        let binary_hash = [0x42u8; 32];
        let allowlist = vec![[0x41u8; 32], [0x42u8; 32], [0x43u8; 32]];

        let witness = AttestationProofWitness::new(pk.as_bytes().to_vec(), binary_hash, 0, 0)
            .with_allowlist(allowlist);

        // Should pass - binary is in allowlist
        assert!(witness.verify_allowlist().is_ok());
    }

    #[test]
    fn test_witness_allowlist_failure() {
        let (pk, _) = generate_ml_dsa_keypair().expect("keygen failed");
        let binary_hash = [0x99u8; 32]; // Not in allowlist
        let allowlist = vec![[0x41u8; 32], [0x42u8; 32], [0x43u8; 32]];

        let witness = AttestationProofWitness::new(pk.as_bytes().to_vec(), binary_hash, 0, 0)
            .with_allowlist(allowlist);

        // Should fail - binary not in allowlist
        assert!(witness.verify_allowlist().is_err());
    }

    #[test]
    fn test_public_inputs_freshness() {
        let inputs = AttestationProofPublicInputs {
            entangled_id: [0u8; 32],
            binary_hash: [0u8; 32],
            public_key_hash: [0u8; 32],
            proof_timestamp: 1000,
        };

        // Fresh: within 60 seconds
        assert!(inputs.is_fresh(60, 1050));

        // Stale: more than 60 seconds old
        assert!(!inputs.is_fresh(60, 1100));

        // Future timestamp is invalid
        assert!(!inputs.is_fresh(60, 900));
    }

    #[test]
    fn test_public_inputs_matches_id() {
        let expected = [0x42u8; 32];
        let inputs = AttestationProofPublicInputs {
            entangled_id: expected,
            binary_hash: [0u8; 32],
            public_key_hash: [0u8; 32],
            proof_timestamp: 0,
        };

        assert!(inputs.matches_entangled_id(&expected));
        assert!(!inputs.matches_entangled_id(&[0x99u8; 32]));
    }
}
