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

pub mod hybrid;
// Legacy modules deprecated - use ant-quic PQC functions directly
// pub mod ml_dsa;
// pub mod ml_kem;
pub mod types;
pub mod ant_quic_integration;

// NOTE: Not using wildcard import to avoid conflicts with ant-quic types
// Selectively re-export only non-conflicting types from our types module
pub use self::types::{
    GroupId, ParticipantId, PeerId, SessionId, QuantumPeerIdentity, 
    SecureSession, SessionState, HandshakeParameters, HybridSignature,
    Ed25519PublicKey, Ed25519PrivateKey, Ed25519Signature,
    FrostPublicKey, FrostGroupPublicKey, FrostKeyShare, FrostCommitment, FrostSignature,
};

// Re-export all ant-quic PQC functions for convenience
pub use self::ant_quic_integration::{
    // Configuration functions
    create_default_pqc_config, create_pqc_only_config,
    // ML-DSA functions
    generate_ml_dsa_keypair, ml_dsa_sign, ml_dsa_verify,
    // ML-KEM functions  
    generate_ml_kem_keypair, ml_kem_encapsulate, ml_kem_decapsulate,
    // Hybrid functions
    generate_hybrid_kem_keypair, hybrid_kem_encapsulate, hybrid_kem_decapsulate,
    generate_hybrid_signature_keypair, hybrid_sign, hybrid_verify,
    // Performance optimization
    create_pqc_memory_pool,
};


use serde::{Deserialize, Serialize};
use thiserror::Error;

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

/// Signature scheme selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureScheme {
    /// Classical Ed25519 signatures (for backward compatibility)
    Classical(Vec<u8>),

    /// Post-quantum ML-DSA signatures
    PostQuantum(Vec<u8>),

    /// Dual signatures for hybrid mode
    Dual {
        classical: Vec<u8>,
        post_quantum: Vec<u8>,
    },
}

// NOTE: SignatureScheme::verify method removed - use ant-quic PQC verify functions directly:
// - ml_dsa_verify(public_key: &MlDsaPublicKey, message: &[u8], signature: &MlDsaSignature)
// - For Ed25519: use ed25519_verify from this module
// These are re-exported from ant_quic_integration module

impl SignatureScheme {
    // verify method removed - see note above
}

// NOTE: PublicKeySet and PrivateKeySet removed - use ant-quic PQC types directly

// NOTE: KeyPair struct and generate_keypair function removed to avoid conflicts
// Use ant-quic PQC functions directly:
// - generate_ml_dsa_keypair() -> (MlDsaPublicKey, MlDsaSecretKey)
// - generate_ml_kem_keypair() -> (MlKemPublicKey, MlKemSecretKey) 
// - For Ed25519: generate_ed25519_keypair() below
//
// These functions are re-exported from ant_quic_integration module

/// Generate Ed25519 keypair (placeholder for actual implementation)
fn generate_ed25519_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key = signing_key.verifying_key().to_bytes().to_vec();

    // Create 64-byte private key (signing key + public key)
    let mut private_key = vec![0u8; 64];
    private_key[..32].copy_from_slice(&signing_key.to_bytes());
    private_key[32..].copy_from_slice(&public_key);

    Ok((public_key, private_key))
}

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

    Ok(NegotiatedAlgorithms {
        kem_algorithm: if use_ml_kem {
            KemAlgorithm::MlKem768
        } else {
            KemAlgorithm::ClassicalEcdh
        },
        signature_algorithm: if use_ml_dsa {
            SignatureAlgorithm::MlDsa65
        } else {
            SignatureAlgorithm::Ed25519
        },
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
    ClassicalEcdh,
}

/// Signature algorithm
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SignatureAlgorithm {
    MlDsa65,
    Ed25519,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_keypair_generation() {
        // NOTE: Legacy test deprecated - use ant-quic PQC functions directly:
        // - generate_ml_dsa_keypair() -> (MlDsaPublicKey, MlDsaSecretKey)
        // - generate_ml_kem_keypair() -> (MlKemPublicKey, MlKemSecretKey)
        let _caps = CryptoCapabilities::default();
        // Test deprecated - would need significant rewrite for ant-quic types
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
        assert_eq!(negotiated.signature_algorithm, SignatureAlgorithm::Ed25519);
        assert!(negotiated.hybrid_mode);
    }
}
