// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com

//! Identity types for the network

use crate::fwid::Key;
use crate::quantum_crypto::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// User identity in the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Four-word human-readable address
    pub words: [String; 4],
    /// Identity key (hash of words)
    pub key: Key,
    /// Public key for signature verification
    pub public_key: Vec<u8>,
}

impl Identity {
    /// Create identity from words and public key (panic-free)
    pub fn new(words: [String; 4], public_key: Vec<u8>) -> Result<Self, crate::error::P2PError> {
        let key = crate::fwid::fw_to_key(words.clone()).map_err(|e| {
            crate::error::P2PError::Identity(crate::error::IdentityError::InvalidFourWordAddress(
                e.to_string().into(),
            ))
        })?;

        Ok(Self {
            words,
            key,
            public_key,
        })
    }
}

/// Handle for authenticated identity operations
#[derive(Clone)]
pub struct IdentityHandle {
    /// The identity
    pub identity: Arc<Identity>,
    /// Secret key for signing (not serialized)
    secret_key: Arc<Vec<u8>>,
}

impl IdentityHandle {
    /// Create new identity handle
    pub fn new(identity: Identity, keypair: MlDsaKeyPair) -> Self {
        Self {
            identity: Arc::new(identity),
            secret_key: Arc::new(keypair.secret_key),
        }
    }

    /// Get the identity
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Get the identity key
    pub fn key(&self) -> Key {
        self.identity.key.clone()
    }

    /// Sign data with the identity's secret key
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, crate::error::P2PError> {
        use crate::quantum_crypto::{MlDsa65, MlDsaOperations};

        let ml = MlDsa65::new();
        let sk = MlDsaSecretKey::from_bytes(&self.secret_key).map_err(|e| {
            crate::error::P2PError::Crypto(crate::error::CryptoError::KeyGenerationFailed(
                format!("Invalid secret key: {:?}", e).into(),
            ))
        })?;

        let sig = ml.sign(&sk, data).map_err(|e| {
            crate::error::P2PError::Crypto(crate::error::CryptoError::EncryptionFailed(
                format!("Signing failed: {:?}", e).into(),
            ))
        })?;

        Ok(sig.as_bytes().to_vec())
    }

    /// Verify a signature with the identity's public key
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, crate::error::P2PError> {
        use crate::quantum_crypto::{MlDsa65, MlDsaOperations};

        let ml = MlDsa65::new();
        let pk = MlDsaPublicKey::from_bytes(&self.identity.public_key).map_err(|e| {
            crate::error::P2PError::Crypto(crate::error::CryptoError::KeyGenerationFailed(
                format!("Invalid public key: {:?}", e).into(),
            ))
        })?;
        let sig = MlDsaSignature::from_bytes(signature).map_err(|_e| {
            crate::error::P2PError::Crypto(crate::error::CryptoError::SignatureVerificationFailed)
        })?;

        ml.verify(&pk, data, &sig).map_err(|_| {
            crate::error::P2PError::Crypto(crate::error::CryptoError::SignatureVerificationFailed)
        })
    }
}

/// ML-DSA keypair for identity operations
#[derive(Clone)]
pub struct MlDsaKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl MlDsaKeyPair {
    /// Generate a new keypair
    pub fn generate() -> Result<Self, crate::error::P2PError> {
        use crate::quantum_crypto::{MlDsa65, MlDsaOperations};

        let ml = MlDsa65::new();
        let (pk, sk) = ml.generate_keypair().map_err(|e| {
            crate::error::P2PError::Crypto(crate::error::CryptoError::KeyGenerationFailed(
                format!("Keypair generation failed: {:?}", e).into(),
            ))
        })?;

        Ok(Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        })
    }
}
