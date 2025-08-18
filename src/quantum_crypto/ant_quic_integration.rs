// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com

//! Integration with ant-quic's post-quantum cryptography
//!
//! This module provides integration with ant-quic 0.8.1's post-quantum
//! cryptography features, making them available to saorsa-core applications.

use anyhow::Result;

// Re-export ant-quic PQC module and types for applications
pub use ant_quic::crypto::pqc;

// Re-export key ant-quic PQC types from types module
pub use ant_quic::crypto::pqc::types::{
    // Hybrid types for combined classical + post-quantum crypto
    HybridKemCiphertext,
    HybridKemPublicKey,
    HybridKemSecretKey,
    HybridSignaturePublicKey,
    HybridSignatureSecretKey,
    HybridSignatureValue,
    MlDsaPublicKey,
    MlDsaSecretKey,
    MlDsaSignature,
    MlKemCiphertext,
    MlKemPublicKey,
    MlKemSecretKey,
    // Error and result types
    PqcError,
    PqcResult,
    SharedSecret as PqcSharedSecret,
};

// Re-export config types and algorithm implementations
pub use ant_quic::crypto::pqc::{
    // Hybrid implementations
    HybridKem,
    HybridPreference,
    HybridSignature,
    MlDsa65,
    MlKem768,
    // Additional enums and types
    NamedGroup,
    // Memory pool types for performance
    PoolConfig,
    PqcConfig,
    PqcConfigBuilder,
    PqcMemoryPool,
    PqcMode,
    SignatureScheme,
};

// Re-export PQC traits for advanced users
pub use ant_quic::crypto::pqc::{MlDsaOperations, MlKemOperations, PqcProvider};

/// Create a default PQC configuration with quantum-resistant algorithms enabled
pub fn create_default_pqc_config() -> Result<PqcConfig> {
    let config = PqcConfigBuilder::new()
        .hybrid_preference(HybridPreference::PreferPqc)
        .mode(PqcMode::Hybrid)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build PQC config: {}", e))?;

    Ok(config)
}

/// Create a PQC-only configuration (no classical algorithms)
pub fn create_pqc_only_config() -> Result<PqcConfig> {
    let config = PqcConfigBuilder::new()
        .hybrid_preference(HybridPreference::PreferPqc)
        .mode(PqcMode::PqcOnly)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build PQC-only config: {}", e))?;

    Ok(config)
}

/// Generate ML-DSA-65 key pair using ant-quic's implementation
pub fn generate_ml_dsa_keypair() -> Result<(MlDsaPublicKey, MlDsaSecretKey)> {
    let ml_dsa = MlDsa65::new();
    let (public_key, secret_key) = ml_dsa
        .generate_keypair()
        .map_err(|e| anyhow::anyhow!("Failed to generate ML-DSA keypair: {}", e))?;
    Ok((public_key, secret_key))
}

/// Generate ML-KEM-768 key pair using ant-quic's implementation
pub fn generate_ml_kem_keypair() -> Result<(MlKemPublicKey, MlKemSecretKey)> {
    let ml_kem = MlKem768::new();
    let (public_key, secret_key) = ml_kem
        .generate_keypair()
        .map_err(|e| anyhow::anyhow!("Failed to generate ML-KEM keypair: {}", e))?;
    Ok((public_key, secret_key))
}

/// Sign a message using ML-DSA-65 with ant-quic's implementation
pub fn ml_dsa_sign(secret_key: &MlDsaSecretKey, message: &[u8]) -> Result<MlDsaSignature> {
    let ml_dsa = MlDsa65::new();
    ml_dsa
        .sign(secret_key, message)
        .map_err(|e| anyhow::anyhow!("Failed to sign with ML-DSA: {}", e))
}

/// Verify a signature using ML-DSA-65 with ant-quic's implementation
pub fn ml_dsa_verify(
    public_key: &MlDsaPublicKey,
    message: &[u8],
    signature: &MlDsaSignature,
) -> Result<bool> {
    let ml_dsa = MlDsa65::new();
    match ml_dsa.verify(public_key, message, signature) {
        Ok(is_valid) => Ok(is_valid),
        Err(e) => Err(anyhow::anyhow!("ML-DSA verification failed: {}", e)),
    }
}

/// Encapsulate a shared secret using ML-KEM-768 with ant-quic's implementation
pub fn ml_kem_encapsulate(
    public_key: &MlKemPublicKey,
) -> Result<(MlKemCiphertext, PqcSharedSecret)> {
    let ml_kem = MlKem768::new();
    ml_kem
        .encapsulate(public_key)
        .map_err(|e| anyhow::anyhow!("Failed to encapsulate with ML-KEM: {}", e))
}

/// Decapsulate a shared secret using ML-KEM-768 with ant-quic's implementation  
pub fn ml_kem_decapsulate(
    secret_key: &MlKemSecretKey,
    ciphertext: &MlKemCiphertext,
) -> Result<PqcSharedSecret> {
    let ml_kem = MlKem768::new();
    ml_kem
        .decapsulate(secret_key, ciphertext)
        .map_err(|e| anyhow::anyhow!("Failed to decapsulate with ML-KEM: {}", e))
}

/// Generate hybrid KEM key pair combining classical and post-quantum algorithms
pub fn generate_hybrid_kem_keypair() -> Result<(HybridKemPublicKey, HybridKemSecretKey)> {
    let hybrid_kem = HybridKem::new();
    hybrid_kem
        .generate_keypair()
        .map_err(|e| anyhow::anyhow!("Failed to generate hybrid KEM keypair: {}", e))
}

/// Encapsulate using hybrid KEM (classical + post-quantum)
pub fn hybrid_kem_encapsulate(
    public_key: &HybridKemPublicKey,
) -> Result<(HybridKemCiphertext, PqcSharedSecret)> {
    let hybrid_kem = HybridKem::new();
    hybrid_kem
        .encapsulate(public_key)
        .map_err(|e| anyhow::anyhow!("Failed to encapsulate with hybrid KEM: {}", e))
}

/// Decapsulate using hybrid KEM (classical + post-quantum)
pub fn hybrid_kem_decapsulate(
    secret_key: &HybridKemSecretKey,
    ciphertext: &HybridKemCiphertext,
) -> Result<PqcSharedSecret> {
    let hybrid_kem = HybridKem::new();
    hybrid_kem
        .decapsulate(secret_key, ciphertext)
        .map_err(|e| anyhow::anyhow!("Failed to decapsulate with hybrid KEM: {}", e))
}

/// Generate hybrid signature key pair combining classical and post-quantum signatures
pub fn generate_hybrid_signature_keypair()
-> Result<(HybridSignaturePublicKey, HybridSignatureSecretKey)> {
    let hybrid_sig = HybridSignature::new();
    hybrid_sig
        .generate_keypair()
        .map_err(|e| anyhow::anyhow!("Failed to generate hybrid signature keypair: {}", e))
}

/// Sign using hybrid signatures (classical + post-quantum)
pub fn hybrid_sign(
    secret_key: &HybridSignatureSecretKey,
    message: &[u8],
) -> Result<HybridSignatureValue> {
    let hybrid_sig = HybridSignature::new();
    hybrid_sig
        .sign(secret_key, message)
        .map_err(|e| anyhow::anyhow!("Failed to sign with hybrid signature: {}", e))
}

/// Verify hybrid signature (classical + post-quantum)
pub fn hybrid_verify(
    public_key: &HybridSignaturePublicKey,
    message: &[u8],
    signature: &HybridSignatureValue,
) -> Result<bool> {
    let hybrid_sig = HybridSignature::new();
    match hybrid_sig.verify(public_key, message, signature) {
        Ok(is_valid) => Ok(is_valid),
        Err(e) => Err(anyhow::anyhow!(
            "Hybrid signature verification failed: {}",
            e
        )),
    }
}

/// Create a PQC memory pool for performance optimization
pub fn create_pqc_memory_pool(config: PoolConfig) -> Result<PqcMemoryPool> {
    Ok(PqcMemoryPool::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_config_creation() {
        let config = create_default_pqc_config();
        assert!(config.is_ok(), "Should create default PQC config");

        let pqc_only_config = create_pqc_only_config();
        assert!(pqc_only_config.is_ok(), "Should create PQC-only config");
    }

    #[test]
    fn test_ml_dsa_roundtrip() {
        let keypair = generate_ml_dsa_keypair();
        assert!(keypair.is_ok(), "Should generate ML-DSA keypair");

        let (public_key, secret_key) = keypair.unwrap();
        let message = b"test message for ML-DSA";

        let signature = ml_dsa_sign(&secret_key, message);
        assert!(signature.is_ok(), "Should sign message with ML-DSA");

        let sig = signature.unwrap();
        let verification = ml_dsa_verify(&public_key, message, &sig);
        assert!(verification.is_ok(), "Should verify ML-DSA signature");
        assert!(verification.unwrap(), "Signature should be valid");
    }

    #[test]
    fn test_ml_kem_roundtrip() {
        let keypair = generate_ml_kem_keypair();
        assert!(keypair.is_ok(), "Should generate ML-KEM keypair");

        let (public_key, secret_key) = keypair.unwrap();

        let encapsulation = ml_kem_encapsulate(&public_key);
        assert!(encapsulation.is_ok(), "Should encapsulate with ML-KEM");

        let (ciphertext, shared_secret1) = encapsulation.unwrap();

        let decapsulation = ml_kem_decapsulate(&secret_key, &ciphertext);
        assert!(decapsulation.is_ok(), "Should decapsulate with ML-KEM");

        let shared_secret2 = decapsulation.unwrap();
        assert_eq!(
            shared_secret1.0, shared_secret2.0,
            "Shared secrets should match"
        );
    }

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let keypair = generate_hybrid_kem_keypair();
        assert!(keypair.is_ok(), "Should generate hybrid KEM keypair");

        let (public_key, secret_key) = keypair.unwrap();

        let encapsulation = hybrid_kem_encapsulate(&public_key);
        assert!(encapsulation.is_ok(), "Should encapsulate with hybrid KEM");

        let (ciphertext, shared_secret1) = encapsulation.unwrap();

        let decapsulation = hybrid_kem_decapsulate(&secret_key, &ciphertext);
        assert!(decapsulation.is_ok(), "Should decapsulate with hybrid KEM");

        let shared_secret2 = decapsulation.unwrap();
        assert_eq!(
            shared_secret1.0, shared_secret2.0,
            "Hybrid shared secrets should match"
        );
    }

    #[test]
    fn test_hybrid_signature_roundtrip() {
        let keypair = generate_hybrid_signature_keypair();
        assert!(keypair.is_ok(), "Should generate hybrid signature keypair");

        let (public_key, secret_key) = keypair.unwrap();
        let message = b"test message for hybrid signatures";

        let signature = hybrid_sign(&secret_key, message);
        assert!(
            signature.is_ok(),
            "Should sign message with hybrid signature"
        );

        let sig = signature.unwrap();
        let verification = hybrid_verify(&public_key, message, &sig);
        assert!(verification.is_ok(), "Should verify hybrid signature");
        assert!(verification.unwrap(), "Hybrid signature should be valid");
    }

    #[test]
    fn test_pqc_memory_pool_creation() {
        let pool_config = PoolConfig::default();
        let pool = create_pqc_memory_pool(pool_config);
        assert!(pool.is_ok(), "Should create PQC memory pool");
    }
}
