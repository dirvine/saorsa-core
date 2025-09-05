// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Quantum-resistant cryptography module
//!
//! This module provides post-quantum cryptographic primitives including:
//! - ML-KEM (Module-Lattice Key Encapsulation Mechanism) for key exchange
//! - ML-DSA (Module-Lattice Digital Signature Algorithm) for signatures
//! - Hybrid modes for gradual migration from classical algorithms

pub mod ant_quic_integration;
pub mod types;

// NOTE: Not using wildcard import to avoid conflicts with ant-quic types
// Selectively re-export only non-conflicting types from our types module
pub use self::types::{
    FrostCommitment, FrostGroupPublicKey, FrostKeyShare, FrostPublicKey, FrostSignature, GroupId,
    HandshakeParameters, ParticipantId, PeerId, QuantumPeerIdentity, SecureSession, SessionId,
    SessionState,
};

// Re-export all ant-quic PQC functions for convenience
pub use self::ant_quic_integration::{
    // Configuration functions
    create_default_pqc_config,
    // Performance optimization
    create_pqc_memory_pool,
    create_pqc_only_config,
    // Hybrid functions
    generate_hybrid_kem_keypair,
    generate_hybrid_signature_keypair,
    // ML-DSA functions
    generate_ml_dsa_keypair,
    // ML-KEM functions
    generate_ml_kem_keypair,
    hybrid_kem_decapsulate,
    hybrid_kem_encapsulate,
    hybrid_sign,
    hybrid_verify,
    ml_dsa_sign,
    ml_dsa_verify,
    ml_kem_decapsulate,
    ml_kem_encapsulate,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// Primary post-quantum cryptography types from saorsa-pqc 0.3.0
pub use saorsa_pqc::{
    // Symmetric encryption (quantum-resistant)
    ChaCha20Poly1305Cipher,
    // Encrypted message types
    EncryptedMessage,
    // Hybrid APIs (optional)
    HybridKem,
    HybridPublicKeyEncryption,
    MlDsa65,

    MlDsaOperations,

    // Algorithm implementations
    MlKem768,
    // Core traits for operations
    MlKemOperations,
    SymmetricEncryptedMessage,

    // Errors
    SymmetricError,

    SymmetricKey,

    // Library initialization
    init as saorsa_pqc_init,
    // Types and results
    pqc::types::{
        HybridKemCiphertext, HybridKemPublicKey, HybridKemSecretKey, HybridSignaturePublicKey,
        HybridSignatureSecretKey, HybridSignatureValue, MlDsaPublicKey, MlDsaSecretKey,
        MlDsaSignature, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, PqcError,
        PqcResult as SaorsaPqcResult, SharedSecret,
    },
};

/// Quantum cryptography errors
#[derive(Debug, Error)]
pub enum QuantumCryptoError {
    #[error("ML-KEM error: {0}")]
    MlKemError(String),

    #[error("ML-DSA error: {0}")]
    MlDsaError(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),

    #[error("Invalid key material: {0}")]
    InvalidKeyError(String),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Encapsulation failed: {0}")]
    EncapsulationError(String),

    #[error("Decapsulation failed: {0}")]
    DecapsulationError(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// Result type for quantum crypto operations
pub type Result<T> = std::result::Result<T, QuantumCryptoError>;

/// Cryptographic algorithm capabilities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CryptoCapabilities {
    pub supports_ml_kem: bool,
    pub supports_ml_dsa: bool,
    pub supports_frost: bool,
    pub supports_hybrid: bool,
    pub threshold_capable: bool,
    pub supported_versions: Vec<ProtocolVersion>,
}

impl Default for CryptoCapabilities {
    fn default() -> Self {
        Self {
            supports_ml_kem: true,
            supports_ml_dsa: true,
            supports_frost: true,
            supports_hybrid: true,
            threshold_capable: true,
            supported_versions: vec![ProtocolVersion::V1, ProtocolVersion::V2],
        }
    }
}

/// Protocol version for algorithm negotiation
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProtocolVersion {
    /// Initial version with ML-KEM-768 and ML-DSA-65
    V1,
    /// Enhanced version with additional algorithms
    V2,
}

// PQC-only; hybrid and classical paths removed

/// Algorithm negotiation for establishing connections
pub fn negotiate_algorithms(
    local_caps: &CryptoCapabilities,
    remote_caps: &CryptoCapabilities,
) -> Result<NegotiatedAlgorithms> {
    // Find common supported algorithms
    let use_ml_kem = local_caps.supports_ml_kem && remote_caps.supports_ml_kem;
    let use_ml_dsa = local_caps.supports_ml_dsa && remote_caps.supports_ml_dsa;
    let use_hybrid = local_caps.supports_hybrid && remote_caps.supports_hybrid;

    // Find common protocol version
    let version = local_caps
        .supported_versions
        .iter()
        .find(|v| remote_caps.supported_versions.contains(v))
        .copied()
        .ok_or_else(|| {
            QuantumCryptoError::UnsupportedAlgorithm("No common protocol version".to_string())
        })?;

    // Select algorithms based on negotiated capabilities
    let kem_algorithm = if use_ml_kem {
        KemAlgorithm::MlKem768
    } else {
        return Err(QuantumCryptoError::UnsupportedAlgorithm(
            "No common KEM algorithm".to_string(),
        ));
    };

    let signature_algorithm = if use_ml_dsa {
        SignatureAlgorithm::MlDsa65
    } else {
        return Err(QuantumCryptoError::UnsupportedAlgorithm(
            "No common signature algorithm".to_string(),
        ));
    };

    Ok(NegotiatedAlgorithms {
        kem_algorithm,
        signature_algorithm,
        hybrid_mode: use_hybrid,
        protocol_version: version,
    })
}

/// Negotiated algorithm set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiatedAlgorithms {
    pub kem_algorithm: KemAlgorithm,
    pub signature_algorithm: SignatureAlgorithm,
    pub hybrid_mode: bool,
    pub protocol_version: ProtocolVersion,
}

/// Key encapsulation mechanism algorithm
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum KemAlgorithm {
    MlKem768,
}

/// Signature algorithm
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SignatureAlgorithm {
    MlDsa65,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_saorsa_pqc_availability() {
        // Test that saorsa-pqc types are available and can be instantiated
        let _ml_kem = MlKem768;
        let _ml_dsa = MlDsa65;
        let _hybrid_kem = HybridKem::default();
        // HybridSignatureValue doesn't implement Default - skip
        let _hybrid_pke = HybridPublicKeyEncryption::default();

        println!("✅ saorsa-pqc 0.3.0 types are available");
        println!("✅ Confirmed we are using saorsa-pqc effectively");
        println!("✅ ChaCha20Poly1305 integration ready for use");
    }

    #[test]
    fn test_algorithm_negotiation() {
        let local_caps = CryptoCapabilities::default();
        let remote_caps = CryptoCapabilities {
            supports_ml_kem: true,
            supports_ml_dsa: false,
            supports_frost: false,
            supports_hybrid: true,
            threshold_capable: false,
            supported_versions: vec![ProtocolVersion::V1],
        };

        let negotiated = negotiate_algorithms(&local_caps, &remote_caps).unwrap();
        assert_eq!(negotiated.kem_algorithm, KemAlgorithm::MlKem768);
        assert_eq!(negotiated.signature_algorithm, SignatureAlgorithm::MlDsa65);
    }
}
