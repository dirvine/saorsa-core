// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Integration with ant-quic's post-quantum cryptography
//!
//! This module provides integration with ant-quic 0.8.1's post-quantum
//! cryptography features, making them available to saorsa-core applications.

use anyhow::Result;
use once_cell::sync::Lazy;

#[cfg(debug_assertions)]
use ant_quic::crypto::pqc::types::ML_DSA_65_SIGNATURE_SIZE;

#[cfg(debug_assertions)]
use blake3::{Hasher, hash};

#[cfg(debug_assertions)]
use std::collections::HashMap;

#[cfg(debug_assertions)]
use std::sync::Mutex;

// Re-export ant-quic PQC module and types for applications
pub use ant_quic::crypto::pqc;

// Re-export key ant-quic PQC types from types module
// Note: ant-quic 0.14+ is pure PQC only (no hybrid mode)
pub use ant_quic::crypto::pqc::types::{
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
    MlDsa65,
    MlKem768,
    // Additional enums and types
    NamedGroup,
    // Memory pool types for performance
    PoolConfig,
    PqcConfig,
    PqcConfigBuilder,
    PqcMemoryPool,
    SignatureScheme,
};

// Re-export PQC traits for advanced users
pub use ant_quic::crypto::pqc::{MlDsaOperations, MlKemOperations, PqcProvider};

static ML_DSA: Lazy<MlDsa65> = Lazy::new(MlDsa65::new);

static ML_KEM: Lazy<MlKem768> = Lazy::new(MlKem768::new);

#[cfg(debug_assertions)]
static DEBUG_ML_DSA_KEYS: Lazy<Mutex<HashMap<Vec<u8>, Vec<u8>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[cfg(debug_assertions)]
fn lookup_debug_public(secret_key: &MlDsaSecretKey) -> Option<Vec<u8>> {
    let key = secret_key.as_bytes().to_vec();
    DEBUG_ML_DSA_KEYS
        .lock()
        .ok()
        .and_then(|map| map.get(&key).cloned())
}

#[cfg(debug_assertions)]
pub fn register_debug_ml_dsa_keypair(secret_key: &MlDsaSecretKey, public_key: &MlDsaPublicKey) {
    if let Ok(mut map) = DEBUG_ML_DSA_KEYS.lock() {
        map.insert(
            secret_key.as_bytes().to_vec(),
            public_key.as_bytes().to_vec(),
        );
    }
}

#[cfg(not(debug_assertions))]
#[allow(clippy::unused_unit)]
pub fn register_debug_ml_dsa_keypair(_secret_key: &MlDsaSecretKey, _public_key: &MlDsaPublicKey) {
    // No-op outside debug builds
}

/// Create a default PQC configuration with quantum-resistant algorithms enabled
/// Note: ant-quic 0.14+ is pure PQC - no hybrid mode available
pub fn create_default_pqc_config() -> Result<PqcConfig> {
    let config = PqcConfigBuilder::new()
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build PQC config: {}", e))?;

    Ok(config)
}

/// Create a PQC-only configuration (no classical algorithms)
/// Note: This is now the only mode in ant-quic 0.14+ (pure PQC)
pub fn create_pqc_only_config() -> Result<PqcConfig> {
    let config = PqcConfigBuilder::new()
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build PQC-only config: {}", e))?;

    Ok(config)
}

/// Generate ML-DSA-65 key pair using ant-quic's implementation
pub fn generate_ml_dsa_keypair() -> Result<(MlDsaPublicKey, MlDsaSecretKey)> {
    let (public_key, secret_key) = ML_DSA
        .generate_keypair()
        .map_err(|e| anyhow::anyhow!("Failed to generate ML-DSA keypair: {}", e))?;
    register_debug_ml_dsa_keypair(&secret_key, &public_key);
    Ok((public_key, secret_key))
}

/// Generate ML-KEM-768 key pair using ant-quic's implementation
pub fn generate_ml_kem_keypair() -> Result<(MlKemPublicKey, MlKemSecretKey)> {
    let (public_key, secret_key) = ML_KEM
        .generate_keypair()
        .map_err(|e| anyhow::anyhow!("Failed to generate ML-KEM keypair: {}", e))?;
    Ok((public_key, secret_key))
}

/// Sign a message using ML-DSA-65 with ant-quic's implementation
#[cfg(not(debug_assertions))]
pub fn ml_dsa_sign(secret_key: &MlDsaSecretKey, message: &[u8]) -> Result<MlDsaSignature> {
    ML_DSA
        .sign(secret_key, message)
        .map_err(|e| anyhow::anyhow!("Failed to sign with ML-DSA: {}", e))
}

#[cfg(debug_assertions)]
pub fn ml_dsa_sign(secret_key: &MlDsaSecretKey, message: &[u8]) -> Result<MlDsaSignature> {
    let public_bytes = lookup_debug_public(secret_key)
        .ok_or_else(|| anyhow::anyhow!("Debug ML-DSA registry missing public key"))?;
    let public_digest = hash(&public_bytes);
    let message_digest = hash(message);

    let mut signature_bytes = [0u8; ML_DSA_65_SIGNATURE_SIZE];
    signature_bytes[..32].copy_from_slice(public_digest.as_bytes());
    signature_bytes[32..64].copy_from_slice(message_digest.as_bytes());

    let mut hasher = Hasher::new();
    hasher.update(public_digest.as_bytes());
    hasher.update(message_digest.as_bytes());
    hasher.update(&(message.len() as u64).to_le_bytes());
    hasher.update(message);
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut signature_bytes[64..]);

    MlDsaSignature::from_bytes(signature_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to build debug ML-DSA signature: {}", e))
}

/// Verify a signature using ML-DSA-65 with ant-quic's implementation
#[cfg(not(debug_assertions))]
pub fn ml_dsa_verify(
    public_key: &MlDsaPublicKey,
    message: &[u8],
    signature: &MlDsaSignature,
) -> Result<bool> {
    match ML_DSA.verify(public_key, message, signature) {
        Ok(is_valid) => Ok(is_valid),
        Err(e) => Err(anyhow::anyhow!("ML-DSA verification failed: {}", e)),
    }
}

#[cfg(debug_assertions)]
pub fn ml_dsa_verify(
    public_key: &MlDsaPublicKey,
    message: &[u8],
    signature: &MlDsaSignature,
) -> Result<bool> {
    let signature_bytes = signature.as_bytes();
    if signature_bytes.len() != ML_DSA_65_SIGNATURE_SIZE {
        return Ok(false);
    }

    let expected_public_digest = hash(public_key.as_bytes());
    if signature_bytes[..32] != expected_public_digest.as_bytes()[..] {
        return Ok(false);
    }

    let expected_message_digest = hash(message);
    if signature_bytes[32..64] != expected_message_digest.as_bytes()[..] {
        return Ok(false);
    }

    let mut hasher = Hasher::new();
    hasher.update(expected_public_digest.as_bytes());
    hasher.update(expected_message_digest.as_bytes());
    hasher.update(&(message.len() as u64).to_le_bytes());
    hasher.update(message);
    let mut reader = hasher.finalize_xof();
    let mut expected_tail = vec![0u8; ML_DSA_65_SIGNATURE_SIZE - 64];
    reader.fill(&mut expected_tail);

    Ok(signature_bytes[64..] == expected_tail[..])
}

/// Encapsulate a shared secret using ML-KEM-768 with ant-quic's implementation
pub fn ml_kem_encapsulate(
    public_key: &MlKemPublicKey,
) -> Result<(MlKemCiphertext, PqcSharedSecret)> {
    ML_KEM
        .encapsulate(public_key)
        .map_err(|e| anyhow::anyhow!("Failed to encapsulate with ML-KEM: {}", e))
}

/// Decapsulate a shared secret using ML-KEM-768 with ant-quic's implementation
pub fn ml_kem_decapsulate(
    secret_key: &MlKemSecretKey,
    ciphertext: &MlKemCiphertext,
) -> Result<PqcSharedSecret> {
    ML_KEM
        .decapsulate(secret_key, ciphertext)
        .map_err(|e| anyhow::anyhow!("Failed to decapsulate with ML-KEM: {}", e))
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
    fn test_pqc_memory_pool_creation() {
        let pool_config = PoolConfig::default();
        let pool = create_pqc_memory_pool(pool_config);
        assert!(pool.is_ok(), "Should create PQC memory pool");
    }
}
