// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Attestation proof generation.
//!
//! This module provides the [`AttestationProver`] for generating zero-knowledge
//! proofs of correct EntangledId derivation.
//!
//! ## Architecture
//!
//! The prover uses the SP1 zkVM to execute the `saorsa-attestation-guest` program,
//! which proves correct derivation without revealing:
//! - The full ML-DSA-65 public key (only hash revealed)
//! - The derivation nonce
//! - Which specific binary from an allowlist
//!
//! ## Feature Flags
//!
//! - `zkvm-prover`: Enable real SP1 proof generation (requires SP1 SDK)
//! - Default: Mock prover for testing (computes correct outputs without zkVM)
//!
//! ## Post-Quantum Security
//!
//! Proofs use STARKs (not Groth16/PLONK) for post-quantum security.
//! The underlying cryptography doesn't rely on elliptic curve assumptions.

use super::{AttestationError, AttestationProofPublicInputs, AttestationProofWitness};
use serde::{Deserialize, Serialize};

/// Serialized attestation proof.
///
/// This structure contains all data needed to verify a proof off-chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationProof {
    /// Serialized SP1 proof bytes (Core STARK proof for PQ security).
    pub proof_bytes: Vec<u8>,

    /// Public values committed to the proof.
    pub public_inputs: AttestationProofPublicInputs,

    /// Hash of the verification key.
    /// Used to identify which program generated this proof.
    pub vkey_hash: [u8; 32],

    /// Proof type indicator.
    pub proof_type: ProofType,
}

/// Type of zkVM proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofType {
    /// Mock proof for testing (no cryptographic security).
    Mock,
    /// SP1 Core STARK proof (post-quantum secure).
    Sp1Core,
    /// SP1 Compressed STARK proof (smaller, still PQ-secure).
    Sp1Compressed,
    /// SP1 Groth16 wrapped proof (NOT post-quantum secure).
    Sp1Groth16,
}

impl AttestationProof {
    /// Check if this proof type is post-quantum secure.
    #[must_use]
    pub fn is_post_quantum_secure(&self) -> bool {
        match self.proof_type {
            ProofType::Mock => false, // No cryptographic security
            ProofType::Sp1Core | ProofType::Sp1Compressed => true, // STARKs are PQ-secure
            ProofType::Sp1Groth16 => false, // Uses BN254 elliptic curves
        }
    }
}

// ============================================================================
// Mock Prover (Default - for testing without SP1 SDK)
// ============================================================================

/// Mock attestation prover for testing.
///
/// This prover computes the correct public outputs but doesn't generate
/// cryptographic proofs. Use only for development and testing.
///
/// For production, enable the `zkvm-prover` feature to use real SP1 proofs.
#[derive(Debug, Default)]
pub struct MockAttestationProver;

impl MockAttestationProver {
    /// Create a new mock prover.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Generate a mock proof.
    ///
    /// This computes the correct public outputs using `saorsa-logic` but
    /// doesn't actually run the zkVM or generate cryptographic proofs.
    ///
    /// # Errors
    ///
    /// Returns an error if the witness allowlist verification fails.
    pub fn generate_proof(
        &self,
        witness: &AttestationProofWitness,
    ) -> Result<AttestationProof, AttestationError> {
        // Verify allowlist if provided (same check zkVM would do)
        witness
            .verify_allowlist()
            .map_err(|_| AttestationError::BinaryNotAllowed {
                hash: hex::encode(witness.binary_hash),
            })?;

        // Compute expected outputs (same computation as zkVM guest)
        let public_inputs = witness.compute_public_outputs();

        Ok(AttestationProof {
            proof_bytes: vec![0u8; 32], // Mock proof placeholder
            public_inputs,
            vkey_hash: [0u8; 32], // Mock vkey
            proof_type: ProofType::Mock,
        })
    }

    /// Get the verification key hash for mock proofs.
    #[must_use]
    pub fn vkey_hash(&self) -> [u8; 32] {
        [0u8; 32]
    }
}

// ============================================================================
// SP1 Prover (Feature-gated)
// ============================================================================

/// SP1 attestation prover configuration.
#[cfg(feature = "zkvm-prover")]
#[derive(Debug, Clone)]
pub struct Sp1ProverConfig {
    /// Use Succinct's prover network instead of local proving.
    pub use_network: bool,

    /// Proof type to generate.
    pub proof_type: ProofType,
}

#[cfg(feature = "zkvm-prover")]
impl Default for Sp1ProverConfig {
    fn default() -> Self {
        Self {
            use_network: false,
            proof_type: ProofType::Sp1Core, // Default to PQ-secure proofs
        }
    }
}

/// SP1 attestation prover.
///
/// Generates real zero-knowledge proofs using the SP1 zkVM.
///
/// # Requirements
///
/// - SP1 toolchain must be installed (`cargo prove install`)
/// - The `saorsa-attestation-guest` ELF must be built and `ATTESTATION_GUEST_ELF` env var set
/// - For local proving: adequate CPU/GPU resources
/// - For network proving: `SUCCINCT_API_KEY` environment variable
#[cfg(feature = "zkvm-prover")]
pub struct Sp1AttestationProver {
    client: sp1_sdk::EnvProver,
    pk: sp1_sdk::SP1ProvingKey,
    vk: sp1_sdk::SP1VerifyingKey,
    config: Sp1ProverConfig,
}

#[cfg(feature = "zkvm-prover")]
impl Sp1AttestationProver {
    /// Create a new SP1 prover.
    ///
    /// This loads the guest program ELF and generates proving/verifying keys.
    ///
    /// # Environment Variables
    ///
    /// - `ATTESTATION_GUEST_ELF`: Path to the compiled guest program ELF
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The `ATTESTATION_GUEST_ELF` environment variable is not set
    /// - The guest ELF cannot be loaded
    /// - Key generation fails
    pub fn new(config: Sp1ProverConfig) -> Result<Self, AttestationError> {
        let client = sp1_sdk::ProverClient::from_env();

        // Load the guest program ELF from environment variable path
        let elf_path = std::env::var("ATTESTATION_GUEST_ELF").map_err(|_| {
            AttestationError::InvalidProof(
                "ATTESTATION_GUEST_ELF environment variable not set".to_string(),
            )
        })?;
        let elf = std::fs::read(&elf_path).map_err(|e| {
            AttestationError::InvalidProof(format!("Failed to read guest ELF from {elf_path}: {e}"))
        })?;

        let (pk, vk) = client.setup(&elf);

        Ok(Self {
            client,
            pk,
            vk,
            config,
        })
    }

    /// Generate a real SP1 proof.
    ///
    /// # Performance
    ///
    /// Local proving can take 10-60 seconds depending on hardware.
    /// Network proving is typically faster but requires API access.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Witness allowlist verification fails
    /// - SP1 proof generation fails
    pub fn generate_proof(
        &self,
        witness: &AttestationProofWitness,
    ) -> Result<AttestationProof, AttestationError> {
        use sp1_sdk::{HashableKey, SP1Stdin};

        // Prepare input for zkVM
        let mut stdin = SP1Stdin::new();
        stdin.write(&witness);

        // Generate proof based on configured type
        let mut sp1_proof = match self.config.proof_type {
            ProofType::Sp1Core => {
                self.client
                    .prove(&self.pk, &stdin)
                    .core()
                    .run()
                    .map_err(|e| {
                        AttestationError::InvalidProof(format!("SP1 core proof failed: {e}"))
                    })?
            }
            ProofType::Sp1Compressed => self
                .client
                .prove(&self.pk, &stdin)
                .compressed()
                .run()
                .map_err(|e| {
                    AttestationError::InvalidProof(format!("SP1 compressed proof failed: {e}"))
                })?,
            ProofType::Sp1Groth16 => self
                .client
                .prove(&self.pk, &stdin)
                .groth16()
                .run()
                .map_err(|e| {
                    AttestationError::InvalidProof(format!("SP1 groth16 proof failed: {e}"))
                })?,
            ProofType::Mock => {
                return Err(AttestationError::InvalidProof(
                    "Mock proof type not supported by SP1 prover".to_string(),
                ));
            }
        };

        // Extract public values from the proof
        let public_inputs: AttestationProofPublicInputs = sp1_proof.public_values.read();

        Ok(AttestationProof {
            proof_bytes: sp1_proof.bytes(),
            public_inputs,
            vkey_hash: self.vk.hash_bytes(),
            proof_type: self.config.proof_type,
        })
    }

    /// Get the verification key hash.
    #[must_use]
    pub fn vkey_hash(&self) -> [u8; 32] {
        use sp1_sdk::HashableKey;
        self.vk.hash_bytes()
    }

    /// Get the verification key.
    #[must_use]
    pub fn verifying_key(&self) -> &sp1_sdk::SP1VerifyingKey {
        &self.vk
    }
}

// ============================================================================
// Unified Prover Interface
// ============================================================================

/// Attestation prover that selects implementation based on available features.
///
/// # Usage
///
/// ```rust,ignore
/// use saorsa_core::attestation::{AttestationProver, AttestationProofWitness};
///
/// let prover = AttestationProver::new()?;
/// let witness = AttestationProofWitness::new(public_key, binary_hash, nonce, timestamp);
/// let proof = prover.generate_proof(&witness)?;
/// ```
pub enum AttestationProver {
    /// Mock prover for testing.
    Mock(MockAttestationProver),
    /// Real SP1 prover (requires `zkvm-prover` feature).
    /// Boxed to avoid large enum variant size difference.
    #[cfg(feature = "zkvm-prover")]
    Sp1(Box<Sp1AttestationProver>),
}

impl std::fmt::Debug for AttestationProver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mock(m) => f.debug_tuple("Mock").field(m).finish(),
            #[cfg(feature = "zkvm-prover")]
            Self::Sp1(_) => f.debug_struct("Sp1").finish_non_exhaustive(),
        }
    }
}

impl AttestationProver {
    /// Create a new prover using the best available implementation.
    ///
    /// - With `zkvm-prover` feature: Uses SP1 prover
    /// - Without feature: Uses mock prover
    ///
    /// # Errors
    ///
    /// Returns an error if SP1 prover initialization fails.
    #[cfg(feature = "zkvm-prover")]
    pub fn new() -> Result<Self, AttestationError> {
        let config = Sp1ProverConfig::default();
        let prover = Sp1AttestationProver::new(config)?;
        Ok(Self::Sp1(Box::new(prover)))
    }

    /// Create a new prover (mock implementation when zkvm-prover is disabled).
    #[cfg(not(feature = "zkvm-prover"))]
    pub fn new() -> Result<Self, AttestationError> {
        Ok(Self::Mock(MockAttestationProver::new()))
    }

    /// Create a mock prover explicitly (for testing).
    #[must_use]
    pub fn mock() -> Self {
        Self::Mock(MockAttestationProver::new())
    }

    /// Generate a proof.
    ///
    /// # Errors
    ///
    /// Returns an error if proof generation fails.
    pub fn generate_proof(
        &self,
        witness: &AttestationProofWitness,
    ) -> Result<AttestationProof, AttestationError> {
        match self {
            Self::Mock(prover) => prover.generate_proof(witness),
            #[cfg(feature = "zkvm-prover")]
            Self::Sp1(prover) => prover.generate_proof(witness),
        }
    }

    /// Get the verification key hash.
    #[must_use]
    pub fn vkey_hash(&self) -> [u8; 32] {
        match self {
            Self::Mock(prover) => prover.vkey_hash(),
            #[cfg(feature = "zkvm-prover")]
            Self::Sp1(prover) => prover.vkey_hash(),
        }
    }

    /// Check if using real zkVM proofs.
    #[must_use]
    pub fn is_real_prover(&self) -> bool {
        match self {
            Self::Mock(_) => false,
            #[cfg(feature = "zkvm-prover")]
            Self::Sp1(_) => true,
        }
    }
}

impl Default for AttestationProver {
    fn default() -> Self {
        Self::mock()
    }
}

// Helper for tests
#[cfg(test)]
impl ProofType {
    fn into_proof(self) -> AttestationProof {
        AttestationProof {
            proof_bytes: vec![],
            public_inputs: AttestationProofPublicInputs {
                entangled_id: [0; 32],
                binary_hash: [0; 32],
                public_key_hash: [0; 32],
                proof_timestamp: 0,
            },
            vkey_hash: [0; 32],
            proof_type: self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quantum_crypto::generate_ml_dsa_keypair;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs()
    }

    #[test]
    fn test_mock_prover_generates_valid_outputs() {
        let (pk, _) = generate_ml_dsa_keypair().expect("keygen");
        let binary_hash = [0x42u8; 32];
        let nonce = 12345u64;
        let timestamp = current_timestamp();

        let witness =
            AttestationProofWitness::new(pk.as_bytes().to_vec(), binary_hash, nonce, timestamp);

        let prover = MockAttestationProver::new();
        let proof = prover.generate_proof(&witness).expect("proof");

        // Verify public outputs match expected derivation
        let expected_id =
            saorsa_logic::attestation::derive_entangled_id(pk.as_bytes(), &binary_hash, nonce);
        assert_eq!(proof.public_inputs.entangled_id, expected_id);
        assert_eq!(proof.proof_type, ProofType::Mock);
    }

    #[test]
    fn test_mock_prover_rejects_invalid_allowlist() {
        let (pk, _) = generate_ml_dsa_keypair().expect("keygen");
        let binary_hash = [0x42u8; 32];
        let allowlist = vec![[0x11u8; 32], [0x22u8; 32]]; // Binary not in list

        let witness = AttestationProofWitness::new(
            pk.as_bytes().to_vec(),
            binary_hash,
            0,
            current_timestamp(),
        )
        .with_allowlist(allowlist);

        let prover = MockAttestationProver::new();
        let result = prover.generate_proof(&witness);

        assert!(result.is_err());
    }

    #[test]
    fn test_attestation_prover_default_is_mock() {
        let prover = AttestationProver::default();
        assert!(!prover.is_real_prover());
    }

    #[test]
    fn test_proof_post_quantum_security() {
        assert!(!ProofType::Mock.into_proof().is_post_quantum_secure());
        // Sp1Core and Sp1Compressed are PQ-secure (tested via AttestationProof)
    }
}
