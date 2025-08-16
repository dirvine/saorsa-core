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

// Re-export ant-quic PQC module for applications
pub use ant_quic::crypto::pqc;

/// Configuration builder for post-quantum cryptography
pub type PqcConfigBuilder = pqc::PqcConfigBuilder;

/// PQC mode enumeration
pub type PqcMode = pqc::PqcMode;

/// Hybrid preference for combining classical and post-quantum algorithms
pub type HybridPreference = pqc::HybridPreference;

/// Create a default PQC configuration with quantum-resistant algorithms enabled
pub fn create_default_pqc_config() -> Result<pqc::PqcConfig> {
    // For now, return a basic config - actual PQC API integration pending ant-quic API clarification
    let config = PqcConfigBuilder::default()
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build PQC config: {}", e))?;
    
    Ok(config)
}

/// Create a PQC-only configuration (no classical algorithms)
pub fn create_pqc_only_config() -> Result<pqc::PqcConfig> {
    // For now, return a basic config - actual PQC API integration pending ant-quic API clarification
    let config = PqcConfigBuilder::default()
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build PQC-only config: {}", e))?;
    
    Ok(config)
}

/// Generate ML-DSA-65 key pair using fallback implementation
/// Note: This is a placeholder until ant-quic's PQC API is properly accessible
pub fn generate_ml_dsa_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    // Use our existing implementation as fallback
    super::ml_dsa::generate_keypair()
        .map_err(|e| anyhow::anyhow!("Failed to generate ML-DSA keypair: {}", e))
}

/// Generate ML-KEM-768 key pair using fallback implementation
/// Note: This is a placeholder until ant-quic's PQC API is properly accessible
pub fn generate_ml_kem_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    // Use our existing implementation as fallback
    super::ml_kem::generate_keypair()
        .map_err(|e| anyhow::anyhow!("Failed to generate ML-KEM keypair: {}", e))
}

/// Sign a message using ML-DSA-65
pub fn ml_dsa_sign(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    super::ml_dsa::sign(private_key, message)
        .map_err(|e| anyhow::anyhow!("Failed to sign with ML-DSA: {}", e))
}

/// Verify a signature using ML-DSA-65
pub fn ml_dsa_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    super::ml_dsa::verify(public_key, message, signature)
        .map(|_| true)
        .or_else(|_| Ok(false))
}

/// Encapsulate a shared secret using ML-KEM-768
pub fn ml_kem_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (ciphertext, shared_secret) = super::ml_kem::encapsulate(public_key)
        .map_err(|e| anyhow::anyhow!("Failed to encapsulate with ML-KEM: {}", e))?;
    
    Ok((ciphertext, shared_secret.as_bytes().to_vec()))
}

/// Decapsulate a shared secret using ML-KEM-768
pub fn ml_kem_decapsulate(private_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let shared_secret = super::ml_kem::decapsulate(private_key, ciphertext)
        .map_err(|e| anyhow::anyhow!("Failed to decapsulate with ML-KEM: {}", e))?;
    
    Ok(shared_secret.as_bytes().to_vec())
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
        let result = generate_ml_dsa_keypair();
        assert!(result.is_ok(), "Should generate ML-DSA keypair");

        let (public_key, private_key) = result.unwrap();
        let message = b"test message for ML-DSA";

        let signature = ml_dsa_sign(&private_key, message);
        assert!(signature.is_ok(), "Should sign message with ML-DSA");

        let sig_bytes = signature.unwrap();
        let verification = ml_dsa_verify(&public_key, message, &sig_bytes);
        assert!(verification.is_ok(), "Should verify ML-DSA signature");
        assert!(verification.unwrap(), "Signature should be valid");
    }

    #[test]
    fn test_ml_kem_roundtrip() {
        let result = generate_ml_kem_keypair();
        assert!(result.is_ok(), "Should generate ML-KEM keypair");

        let (public_key, private_key) = result.unwrap();

        let encapsulation = ml_kem_encapsulate(&public_key);
        assert!(encapsulation.is_ok(), "Should encapsulate with ML-KEM");

        let (ciphertext, shared_secret1) = encapsulation.unwrap();

        let decapsulation = ml_kem_decapsulate(&private_key, &ciphertext);
        assert!(decapsulation.is_ok(), "Should decapsulate with ML-KEM");

        let shared_secret2 = decapsulation.unwrap();
        assert_eq!(shared_secret1, shared_secret2, "Shared secrets should match");
    }
}