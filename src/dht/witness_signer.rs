// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Witness Signer for S/Kademlia Byzantine Fault Tolerance
//!
//! This module provides ML-DSA-65 based signing and verification for witness attestations.
//! Uses post-quantum cryptography for long-term security.

use crate::dht::witness_protocol::{WitnessAttestation, WitnessResponse};
use crate::error::{P2PError, P2pResult as Result};
// Import types from ant_quic_integration to ensure consistency with functions
use crate::quantum_crypto::ant_quic_integration::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
use crate::quantum_crypto::{generate_ml_dsa_keypair, ml_dsa_sign, ml_dsa_verify};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Configuration for the witness signer
#[derive(Debug, Clone)]
pub struct WitnessSignerConfig {
    /// Maximum age of cached public keys before refresh
    pub key_cache_ttl: Duration,
    /// Maximum size of the public key cache
    pub max_cache_size: usize,
    /// Whether to enable signature caching
    pub enable_signature_cache: bool,
}

impl Default for WitnessSignerConfig {
    fn default() -> Self {
        Self {
            key_cache_ttl: Duration::from_secs(3600), // 1 hour
            max_cache_size: 1000,
            enable_signature_cache: true,
        }
    }
}

/// Cached public key with expiry
struct CachedPublicKey {
    key: MlDsaPublicKey,
    cached_at: Instant,
}

/// Keypair storage for the signer
struct SignerKeypair {
    public_key: MlDsaPublicKey,
    secret_key: MlDsaSecretKey,
}

/// Witness signer for ML-DSA-65 based attestation signing and verification
pub struct WitnessSigner {
    config: WitnessSignerConfig,
    /// Our keypair
    keypair: Arc<RwLock<SignerKeypair>>,
    /// Cache of peer public keys for verification
    key_cache: Arc<RwLock<HashMap<String, CachedPublicKey>>>,
}

impl WitnessSigner {
    /// Create a new witness signer with default config
    pub fn new() -> Result<Self> {
        Self::with_config(WitnessSignerConfig::default())
    }

    /// Create a new witness signer with custom config
    pub fn with_config(config: WitnessSignerConfig) -> Result<Self> {
        // Generate keypair
        let (public_key, secret_key) = generate_ml_dsa_keypair().map_err(|e| {
            P2PError::Internal(format!("Failed to generate ML-DSA keypair: {}", e).into())
        })?;

        Ok(Self {
            config,
            keypair: Arc::new(RwLock::new(SignerKeypair {
                public_key,
                secret_key,
            })),
            key_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Get our public key
    pub async fn public_key(&self) -> Result<MlDsaPublicKey> {
        let keypair = self.keypair.read().await;
        Ok(keypair.public_key.clone())
    }

    /// Sign a witness attestation
    pub async fn sign_attestation(&self, attestation: &mut WitnessAttestation) -> Result<()> {
        let bytes = attestation.to_bytes_for_signing();

        let keypair = self.keypair.read().await;
        let signature = ml_dsa_sign(&keypair.secret_key, &bytes)
            .map_err(|e| P2PError::Internal(format!("Failed to sign attestation: {}", e).into()))?;

        attestation.signature = signature.as_bytes().to_vec();
        Ok(())
    }

    /// Verify a signed attestation
    pub async fn verify_attestation(&self, attestation: &WitnessAttestation) -> Result<bool> {
        if attestation.signature.is_empty() {
            return Ok(false);
        }

        // Try to get public key from cache
        let public_key = self.get_cached_key(&attestation.witness_node).await;

        match public_key {
            Some(key) => {
                let bytes = attestation.to_bytes_for_signing();

                // Convert signature bytes to MlDsaSignature
                let signature = match MlDsaSignature::from_bytes(&attestation.signature) {
                    Ok(sig) => sig,
                    Err(_) => return Ok(false),
                };

                match ml_dsa_verify(&key, &bytes, &signature) {
                    Ok(true) => Ok(true),
                    Ok(false) => Ok(false),
                    Err(_) => Ok(false),
                }
            }
            None => {
                // No public key available - can't verify
                // In a real implementation, we'd fetch the key from DHT
                Ok(false)
            }
        }
    }

    /// Register a peer's public key for verification
    pub async fn register_peer_key(&self, peer_id: &str, public_key: MlDsaPublicKey) {
        let mut cache = self.key_cache.write().await;

        // Evict oldest entries if cache is full
        if cache.len() >= self.config.max_cache_size {
            // Find and remove the oldest entry
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, v)| v.cached_at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            }
        }

        cache.insert(
            peer_id.to_string(),
            CachedPublicKey {
                key: public_key,
                cached_at: Instant::now(),
            },
        );
    }

    /// Get cached public key for a peer
    async fn get_cached_key(&self, peer_id: &str) -> Option<MlDsaPublicKey> {
        let cache = self.key_cache.read().await;

        cache.get(peer_id).and_then(|cached| {
            // Check if still valid
            if cached.cached_at.elapsed() < self.config.key_cache_ttl {
                Some(cached.key.clone())
            } else {
                None
            }
        })
    }

    /// Sign a witness response
    pub async fn sign_response(&self, response: &mut WitnessResponse) -> Result<()> {
        if response.accepted {
            self.sign_attestation(&mut response.attestation).await?;
        }
        Ok(())
    }

    /// Verify a witness response
    pub async fn verify_response(&self, response: &WitnessResponse) -> Result<bool> {
        if response.accepted {
            self.verify_attestation(&response.attestation).await
        } else {
            // Rejections don't need signature verification
            Ok(true)
        }
    }

    /// Verify multiple attestations in batch
    pub async fn verify_batch(&self, attestations: &[WitnessAttestation]) -> Result<Vec<bool>> {
        let mut results = Vec::with_capacity(attestations.len());

        for attestation in attestations {
            let result = self.verify_attestation(attestation).await?;
            results.push(result);
        }

        Ok(results)
    }

    /// Clear expired entries from key cache
    pub async fn cleanup_expired_keys(&self) {
        let mut cache = self.key_cache.write().await;

        cache.retain(|_, v| v.cached_at.elapsed() < self.config.key_cache_ttl);
    }

    /// Get the size of the key cache
    pub async fn cache_size(&self) -> usize {
        self.key_cache.read().await.len()
    }
}

// Note: No Default impl because WitnessSigner::new() can fail.
// Use WitnessSigner::new() explicitly to handle errors properly.

/// Signed witness data for transport
#[derive(Debug, Clone)]
pub struct SignedWitnessData {
    /// The attestation data
    pub attestation: WitnessAttestation,
    /// The signer's public key (serialized)
    pub signer_public_key: Vec<u8>,
}

impl SignedWitnessData {
    /// Create signed witness data
    pub fn new(attestation: WitnessAttestation, signer_public_key: Vec<u8>) -> Self {
        Self {
            attestation,
            signer_public_key,
        }
    }

    /// Verify the signature using the embedded public key
    pub fn verify(&self) -> Result<bool> {
        if self.attestation.signature.is_empty() {
            return Ok(false);
        }

        let bytes = self.attestation.to_bytes_for_signing();
        let public_key = MlDsaPublicKey::from_bytes(&self.signer_public_key)
            .map_err(|e| P2PError::Internal(format!("Invalid public key: {}", e).into()))?;

        // Convert signature bytes to MlDsaSignature
        let signature = match MlDsaSignature::from_bytes(&self.attestation.signature) {
            Ok(sig) => sig,
            Err(_) => return Ok(false),
        };

        match ml_dsa_verify(&public_key, &bytes, &signature) {
            Ok(valid) => Ok(valid),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::witness_protocol::{WitnessOperationId, WitnessResponse};

    fn create_test_attestation() -> WitnessAttestation {
        WitnessAttestation::new(
            WitnessOperationId::new(),
            "test-witness".to_string(),
            [1u8; 32],
        )
        .unwrap()
    }

    // ==================== WitnessSignerConfig Tests ====================

    #[test]
    fn test_config_defaults() {
        let config = WitnessSignerConfig::default();

        assert_eq!(config.key_cache_ttl, Duration::from_secs(3600));
        assert_eq!(config.max_cache_size, 1000);
        assert!(config.enable_signature_cache);
    }

    // ==================== WitnessSigner Creation Tests ====================

    #[tokio::test]
    async fn test_signer_creation() {
        let signer = WitnessSigner::new();
        assert!(signer.is_ok());
    }

    #[tokio::test]
    async fn test_signer_has_public_key() {
        let signer = WitnessSigner::new().unwrap();
        let public_key = signer.public_key().await;

        assert!(public_key.is_ok());
        // MlDsaPublicKey should be non-empty when valid
        let pk = public_key.unwrap();
        assert!(!pk.as_bytes().is_empty());
    }

    // ==================== Signing Tests ====================

    #[tokio::test]
    async fn test_sign_attestation() {
        let signer = WitnessSigner::new().unwrap();
        let mut attestation = create_test_attestation();

        assert!(attestation.signature.is_empty());

        let result = signer.sign_attestation(&mut attestation).await;

        assert!(result.is_ok());
        assert!(!attestation.signature.is_empty());
    }

    #[tokio::test]
    async fn test_sign_response_accepted() {
        let signer = WitnessSigner::new().unwrap();
        let attestation = create_test_attestation();
        let mut response = WitnessResponse::accept(attestation, 10);

        let result = signer.sign_response(&mut response).await;

        assert!(result.is_ok());
        assert!(!response.attestation.signature.is_empty());
    }

    #[tokio::test]
    async fn test_sign_response_rejected() {
        let signer = WitnessSigner::new().unwrap();
        let mut response =
            WitnessResponse::reject(WitnessOperationId::new(), "witness".to_string(), "reason")
                .unwrap();

        let result = signer.sign_response(&mut response).await;

        assert!(result.is_ok());
        // Rejected responses don't get signed
        assert!(response.attestation.signature.is_empty());
    }

    // ==================== Verification Tests ====================

    #[tokio::test]
    async fn test_verify_own_signature() {
        let signer = WitnessSigner::new().unwrap();
        let mut attestation = create_test_attestation();

        // Sign attestation
        signer.sign_attestation(&mut attestation).await.unwrap();

        // Register our own public key
        let public_key = signer.public_key().await.unwrap();
        signer
            .register_peer_key(&attestation.witness_node, public_key)
            .await;

        // Verify
        let result = signer.verify_attestation(&attestation).await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_verify_unsigned_attestation() {
        let signer = WitnessSigner::new().unwrap();
        let attestation = create_test_attestation();

        // Verify unsigned attestation
        let result = signer.verify_attestation(&attestation).await;

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should fail - no signature
    }

    #[tokio::test]
    async fn test_verify_unknown_peer() {
        let signer = WitnessSigner::new().unwrap();
        let mut attestation = create_test_attestation();

        // Sign with one signer
        signer.sign_attestation(&mut attestation).await.unwrap();

        // Create new signer (doesn't have peer's public key)
        let verifier = WitnessSigner::new().unwrap();

        // Verify without registered key
        let result = verifier.verify_attestation(&attestation).await;

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should fail - unknown peer
    }

    #[tokio::test]
    async fn test_verify_tampered_attestation() {
        let signer = WitnessSigner::new().unwrap();
        let mut attestation = create_test_attestation();

        // Sign attestation
        signer.sign_attestation(&mut attestation).await.unwrap();

        // Register public key
        let public_key = signer.public_key().await.unwrap();
        signer
            .register_peer_key(&attestation.witness_node, public_key)
            .await;

        // Tamper with attestation
        attestation.observed_distance = [99u8; 32];

        // Verify should fail
        let result = signer.verify_attestation(&attestation).await;

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should fail - signature doesn't match
    }

    // ==================== Batch Verification Tests ====================

    #[tokio::test]
    async fn test_verify_batch() {
        let signer = WitnessSigner::new().unwrap();
        let public_key = signer.public_key().await.unwrap();

        // Create and sign multiple attestations
        let mut attestations = Vec::new();
        for i in 0..3 {
            let mut attestation = WitnessAttestation::new(
                WitnessOperationId::new(),
                format!("witness-{}", i),
                [i as u8; 32],
            )
            .unwrap();
            signer.sign_attestation(&mut attestation).await.unwrap();
            signer
                .register_peer_key(&attestation.witness_node, public_key.clone())
                .await;
            attestations.push(attestation);
        }

        // Verify batch
        let results = signer.verify_batch(&attestations).await.unwrap();

        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|&r| r));
    }

    // ==================== Key Cache Tests ====================

    #[tokio::test]
    async fn test_register_peer_key() {
        let signer = WitnessSigner::new().unwrap();
        let public_key = signer.public_key().await.unwrap();

        signer.register_peer_key("peer1", public_key).await;

        assert_eq!(signer.cache_size().await, 1);
    }

    #[tokio::test]
    async fn test_cache_eviction() {
        let config = WitnessSignerConfig {
            max_cache_size: 3,
            ..Default::default()
        };
        let signer = WitnessSigner::with_config(config).unwrap();
        let public_key = signer.public_key().await.unwrap();

        // Register more than max_cache_size peers
        for i in 0..5 {
            signer
                .register_peer_key(&format!("peer{}", i), public_key.clone())
                .await;
        }

        // Should be capped at max_cache_size
        assert!(signer.cache_size().await <= 3);
    }

    #[tokio::test]
    async fn test_cleanup_expired_keys() {
        let config = WitnessSignerConfig {
            key_cache_ttl: Duration::from_millis(1), // Very short TTL
            ..Default::default()
        };
        let signer = WitnessSigner::with_config(config).unwrap();
        let public_key = signer.public_key().await.unwrap();

        signer.register_peer_key("peer1", public_key).await;
        assert_eq!(signer.cache_size().await, 1);

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Cleanup
        signer.cleanup_expired_keys().await;

        assert_eq!(signer.cache_size().await, 0);
    }

    // ==================== SignedWitnessData Tests ====================

    #[tokio::test]
    async fn test_signed_witness_data_verify() {
        let signer = WitnessSigner::new().unwrap();
        let mut attestation = create_test_attestation();
        signer.sign_attestation(&mut attestation).await.unwrap();

        let public_key = signer.public_key().await.unwrap();
        let signed_data = SignedWitnessData::new(attestation, public_key.as_bytes().to_vec());

        let result = signed_data.verify();

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_signed_witness_data_verify_unsigned() {
        let attestation = create_test_attestation();
        let signed_data = SignedWitnessData::new(attestation, vec![1, 2, 3]);

        let result = signed_data.verify();

        assert!(result.is_ok());
        assert!(!result.unwrap()); // No signature
    }

    // ==================== Response Verification Tests ====================

    #[tokio::test]
    async fn test_verify_signed_response() {
        let signer = WitnessSigner::new().unwrap();
        let attestation = create_test_attestation();
        let mut response = WitnessResponse::accept(attestation, 10);

        // Sign the response
        signer.sign_response(&mut response).await.unwrap();

        // Register public key
        let public_key = signer.public_key().await.unwrap();
        signer
            .register_peer_key(&response.attestation.witness_node, public_key)
            .await;

        // Verify
        let result = signer.verify_response(&response).await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_verify_rejected_response() {
        let signer = WitnessSigner::new().unwrap();
        let response =
            WitnessResponse::reject(WitnessOperationId::new(), "witness".to_string(), "reason")
                .unwrap();

        // Verify rejected response (no signature needed)
        let result = signer.verify_response(&response).await;

        assert!(result.is_ok());
        assert!(result.unwrap()); // Rejections always pass
    }
}
