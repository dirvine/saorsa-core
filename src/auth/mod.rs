// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Authentication system for multi-writer records.
//!
//! This module provides the WriteAuth trait and various adapters
//! for different authentication schemes.

use crate::quantum_crypto::{MlDsa65, MlDsaOperations, MlDsaPublicKey, MlDsaSignature};
use anyhow::Result;
use async_trait::async_trait;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::Arc;

/// A cryptographic signature
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sig(Vec<u8>);

/// A public key
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PubKey(Vec<u8>);

impl Sig {
    /// Create a new signature
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the signature bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl PubKey {
    /// Create a new public key
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the public key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Trait for verifying write authority on records.
///
/// This trait enables pluggable authentication mechanisms
/// for multi-writer records in the DHT.
#[async_trait]
pub trait WriteAuth: Send + Sync + Debug {
    /// Verify that the given signatures authorize the write operation
    /// for the given record data.
    async fn verify(&self, record: &[u8], sigs: &[Sig]) -> Result<bool>;

    /// Get a unique identifier for this auth method
    fn auth_type(&self) -> &str;
}

/// Verifier interface for MLS proofs. External integrations (e.g., saorsa-mls)
/// should register an implementation at startup using `set_mls_verifier`.
pub trait MlsProofVerifier: Send + Sync {
    /// Verify a proof for the given group/epoch over the provided record bytes
    fn verify(&self, group_id: &[u8], epoch: u64, proof: &[u8], record: &[u8]) -> Result<bool>;
}

static MLS_VERIFIER: OnceCell<Arc<dyn MlsProofVerifier>> = OnceCell::new();

/// Register a global MLS proof verifier
pub fn set_mls_verifier(verifier: Arc<dyn MlsProofVerifier>) -> bool {
    MLS_VERIFIER.set(verifier).is_ok()
}

/// Single-writer authentication using a single public key
#[derive(Debug, Clone)]
pub struct SingleWriteAuth {
    pub_key: PubKey,
}

impl SingleWriteAuth {
    /// Create a new single-writer auth
    pub fn new(pub_key: PubKey) -> Self {
        Self { pub_key }
    }
}

#[async_trait]
impl WriteAuth for SingleWriteAuth {
    async fn verify(&self, record: &[u8], sigs: &[Sig]) -> Result<bool> {
        if sigs.is_empty() {
            return Ok(false);
        }

        let pk = MlDsaPublicKey::from_bytes(self.pub_key.as_bytes())
            .map_err(|e| anyhow::anyhow!("invalid ML-DSA public key: {e}"))?;
        const SIG_LEN: usize = 3309;
        let sig_bytes = sigs[0].as_bytes();
        if sig_bytes.len() != SIG_LEN {
            return Ok(false);
        }
        let mut arr = [0u8; SIG_LEN];
        arr.copy_from_slice(sig_bytes);
        let sig = MlDsaSignature(Box::new(arr));
        let ml = MlDsa65::new();
        let ok = ml
            .verify(&pk, record, &sig)
            .map_err(|e| anyhow::anyhow!("ML-DSA verify failed: {e}"))?;
        Ok(ok)
    }

    fn auth_type(&self) -> &str {
        "single"
    }
}

/// Delegated authentication allowing multiple authorized writers
#[derive(Debug, Clone)]
pub struct DelegatedWriteAuth {
    authorized_keys: Vec<PubKey>,
}

impl DelegatedWriteAuth {
    /// Create a new delegated auth with authorized keys
    pub fn new(authorized_keys: Vec<PubKey>) -> Self {
        Self { authorized_keys }
    }

    /// Add an authorized key
    pub fn add_key(&mut self, key: PubKey) {
        if !self.authorized_keys.contains(&key) {
            self.authorized_keys.push(key);
        }
    }
}

#[async_trait]
impl WriteAuth for DelegatedWriteAuth {
    async fn verify(&self, record: &[u8], sigs: &[Sig]) -> Result<bool> {
        if sigs.is_empty() || self.authorized_keys.is_empty() {
            return Ok(false);
        }
        const SIG_LEN: usize = 3309;
        let sig_bytes = sigs[0].as_bytes();
        if sig_bytes.len() != SIG_LEN {
            return Ok(false);
        }
        let mut arr = [0u8; SIG_LEN];
        arr.copy_from_slice(sig_bytes);
        let sig = MlDsaSignature(Box::new(arr));
        let ml = MlDsa65::new();
        for ak in &self.authorized_keys {
            if let Ok(pk) = MlDsaPublicKey::from_bytes(ak.as_bytes())
                && let Ok(valid) = ml.verify(&pk, record, &sig)
                && valid
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn auth_type(&self) -> &str {
        "delegated"
    }
}

/// MLS (Message Layer Security) proof-based authentication
/// This is a placeholder for integration with saorsa-mls
#[derive(Debug, Clone)]
pub struct MlsWriteAuth {
    group_id: Vec<u8>,
    epoch: u64,
}

impl MlsWriteAuth {
    /// Create a new MLS write auth
    pub fn new(group_id: Vec<u8>, epoch: u64) -> Self {
        Self { group_id, epoch }
    }
}

#[async_trait]
impl WriteAuth for MlsWriteAuth {
    async fn verify(&self, record: &[u8], sigs: &[Sig]) -> Result<bool> {
        // Require a registered verifier
        let verifier = match MLS_VERIFIER.get() {
            Some(v) => v.clone(),
            None => return Ok(false),
        };

        // Expect at least one proof signature
        let proof = match sigs.first() {
            Some(s) => s.as_bytes(),
            None => return Ok(false),
        };

        verifier.verify(&self.group_id, self.epoch, proof, record)
    }

    fn auth_type(&self) -> &str {
        "mls"
    }
}

/// Threshold authentication requiring t-of-n signatures
/// NOTE: saorsa-seal 0.1.1 doesn't export the expected types (ThresholdVerifier, ShareSignature, PublicKeyShare)
/// This is a placeholder implementation until the proper types are available
#[derive(Debug, Clone)]
pub struct ThresholdWriteAuth {
    threshold: usize,
    total: usize,
    pub_keys: Vec<PubKey>,
}

impl ThresholdWriteAuth {
    /// Create a new threshold auth with public keys
    pub fn new(threshold: usize, total: usize, pub_keys: Vec<PubKey>) -> Result<Self> {
        if threshold > total {
            anyhow::bail!("Threshold cannot exceed total");
        }
        if threshold == 0 {
            anyhow::bail!("Threshold must be at least 1");
        }
        if pub_keys.len() != total {
            anyhow::bail!("Public keys count must equal total");
        }

        Ok(Self {
            threshold,
            total,
            pub_keys,
        })
    }

    /// Create from raw public keys (alias for compatibility)
    pub fn from_pub_keys(threshold: usize, total: usize, pub_keys: Vec<PubKey>) -> Result<Self> {
        Self::new(threshold, total, pub_keys)
    }
}

#[async_trait]
impl WriteAuth for ThresholdWriteAuth {
    async fn verify(&self, _record: &[u8], sigs: &[Sig]) -> Result<bool> {
        // Verify we have at least threshold signatures
        if sigs.len() < self.threshold {
            return Ok(false);
        }

        // Verify we dont exceed total possible signatures
        if sigs.len() > self.total {
            return Ok(false);
        }

        // TODO: Implement actual threshold signature verification once saorsa-seal exports proper types
        // For now, this is a placeholder that validates signature count against our public keys
        // In production, this would use proper threshold cryptography with self.pub_keys
        Ok(sigs.len() >= self.threshold && self.pub_keys.len() == self.total)
    }

    fn auth_type(&self) -> &str {
        "threshold"
    }
}

/// Composite authentication that requires multiple auth methods to pass
#[derive(Debug)]
pub struct CompositeWriteAuth {
    auths: Vec<Box<dyn WriteAuth>>,
    require_all: bool,
}

impl CompositeWriteAuth {
    /// Create a new composite auth requiring all methods
    pub fn all(auths: Vec<Box<dyn WriteAuth>>) -> Self {
        Self {
            auths,
            require_all: true,
        }
    }

    /// Create a new composite auth requiring any method
    pub fn any(auths: Vec<Box<dyn WriteAuth>>) -> Self {
        Self {
            auths,
            require_all: false,
        }
    }
}

#[async_trait]
impl WriteAuth for CompositeWriteAuth {
    async fn verify(&self, record: &[u8], sigs: &[Sig]) -> Result<bool> {
        if self.require_all {
            // All must pass
            for auth in &self.auths {
                if !auth.verify(record, sigs).await? {
                    return Ok(false);
                }
            }
            Ok(true)
        } else {
            // Any can pass
            for auth in &self.auths {
                if auth.verify(record, sigs).await? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }

    fn auth_type(&self) -> &str {
        if self.require_all {
            "composite_all"
        } else {
            "composite_any"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_single_write_auth() {
        // ML-DSA-65 public key is 1952 bytes
        let pub_key = PubKey::new(vec![0u8; 1952]);
        let auth = SingleWriteAuth::new(pub_key);

        let record = b"test record";
        // ML-DSA-65 signature is 3309 bytes
        let sig = Sig::new(vec![0u8; 3309]);

        // This will fail because we're using dummy keys/signatures
        // Just verify it doesn't panic
        let result = auth.verify(record, &[sig]).await;
        assert!(result.is_err() || !result.unwrap());

        assert_eq!(auth.auth_type(), "single");
    }

    #[tokio::test]
    async fn test_delegated_write_auth() {
        // ML-DSA-65 public keys are 1952 bytes each
        let key1 = PubKey::new(vec![0u8; 1952]);
        let key2 = PubKey::new(vec![1u8; 1952]);
        let mut auth = DelegatedWriteAuth::new(vec![key1.clone()]);
        auth.add_key(key2);

        let record = b"test record";
        // ML-DSA-65 signature is 3309 bytes
        let sig = Sig::new(vec![0u8; 3309]);

        // This will fail because we're using dummy keys/signatures
        // Just verify it doesn't panic
        let result = auth.verify(record, &[sig]).await;
        assert!(result.is_err() || !result.unwrap());

        assert_eq!(auth.auth_type(), "delegated");
    }

    #[tokio::test]
    async fn test_threshold_auth() {
        // For testing, create mock public keys
        // In production, these would come from a proper DKG
        let keys = vec![
            PubKey::new(vec![1; 32]),
            PubKey::new(vec![2; 32]),
            PubKey::new(vec![3; 32]),
        ];

        let auth = ThresholdWriteAuth::from_pub_keys(2, 3, keys).unwrap();

        // Create mock signatures (just need threshold count for now)
        let sigs = vec![Sig::new(vec![1; 64]), Sig::new(vec![2; 64])];

        let record = b"test";
        // This will pass with placeholder implementation
        let result = auth.verify(record, &sigs).await.unwrap();
        assert!(result); // Should pass since we have 2 sigs and threshold is 2

        assert_eq!(auth.threshold, 2);
        assert_eq!(auth.total, 3);

        // Test with insufficient signatures
        let insufficient_sigs = vec![Sig::new(vec![1; 64])];
        let result2 = auth.verify(record, &insufficient_sigs).await.unwrap();
        assert!(!result2); // Should fail since we only have 1 sig but need 2
    }

    #[tokio::test]
    async fn test_composite_auth_all() {
        // ML-DSA-65 public keys are 1952 bytes
        let auth1 = Box::new(SingleWriteAuth::new(PubKey::new(vec![0u8; 1952])));
        let auth2 = Box::new(SingleWriteAuth::new(PubKey::new(vec![1u8; 1952])));

        let composite = CompositeWriteAuth::all(vec![auth1, auth2]);

        // ML-DSA-65 signature is 3309 bytes
        let sig = Sig::new(vec![0u8; 3309]);
        // This will fail because we're using dummy keys/signatures
        // Just verify it doesn't panic
        let result = composite.verify(b"test", &[sig]).await;
        assert!(result.is_err() || !result.unwrap());

        assert_eq!(composite.auth_type(), "composite_all");
    }
}
