// Copyright (c) 2025 Saorsa Labs Limited

// This file is part of the Saorsa P2P network.

// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Copyright 2024 P2P Foundation
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Node Identity (no embedded word address)
//!
//! Implements the core identity system for P2P nodes with:
//! - ML-DSA-65 post-quantum cryptographic keys
//! - Four-word human-readable addresses
//! - Deterministic generation from seeds

use crate::error::IdentityError;
use crate::{P2PError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

// Import PQC types from ant_quic via quantum_crypto module
use crate::quantum_crypto::ant_quic_integration::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};

// No four-word address tied to identity; addressing is handled elsewhere.

/// Node ID derived from public key (256-bit)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Create from ML-DSA public key
    pub fn from_public_key(public_key: &MlDsaPublicKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        let hash = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&hash);
        Self(id)
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// XOR distance to another node ID (for Kademlia)
    pub fn xor_distance(&self, other: &NodeId) -> [u8; 32] {
        let mut distance = [0u8; 32];
        for (i, out) in distance.iter_mut().enumerate() {
            *out = self.0[i] ^ other.0[i];
        }
        distance
    }

    /// Create from public key bytes
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<Self> {
        // ML-DSA-65 public key is 1952 bytes
        if bytes.len() != 1952 {
            return Err(P2PError::Identity(IdentityError::InvalidFormat(
                "Invalid ML-DSA public key length".to_string().into(),
            )));
        }

        // Create ML-DSA public key from bytes
        let public_key = MlDsaPublicKey::from_bytes(bytes).map_err(|e| {
            IdentityError::InvalidFormat(format!("Invalid ML-DSA public key: {:?}", e).into())
        })?;

        Ok(NodeId::from_public_key(&public_key))
    }

    /// Helper for tests/backwards-compat: construct from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8])) // First 8 bytes for brevity
    }
}

/// Public node identity information (without secret keys) - safe to clone
#[derive(Clone)]
pub struct PublicNodeIdentity {
    /// ML-DSA public key
    public_key: MlDsaPublicKey,
    /// Node ID derived from public key
    node_id: NodeId,
}

impl PublicNodeIdentity {
    /// Get node ID
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Get public key
    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }

    // Word addresses are not part of identity; use bootstrap/transport layers
}

/// Core node identity with cryptographic keys
pub struct NodeIdentity {
    /// ML-DSA-65 secret key (private)
    secret_key: MlDsaSecretKey,
    /// ML-DSA-65 public key
    public_key: MlDsaPublicKey,
    /// Node ID derived from public key
    node_id: NodeId,
}

impl NodeIdentity {
    /// Generate new identity
    pub fn generate() -> Result<Self> {
        // Generate ML-DSA-65 key pair (ant-quic integration)
        let (public_key, secret_key) =
            crate::quantum_crypto::generate_ml_dsa_keypair().map_err(|e| {
                P2PError::Identity(IdentityError::InvalidFormat(
                    format!("Failed to generate ML-DSA key pair: {}", e).into(),
                ))
            })?;

        let node_id = NodeId::from_public_key(&public_key);

        crate::quantum_crypto::ant_quic_integration::register_debug_ml_dsa_keypair(
            &secret_key,
            &public_key,
        );

        Ok(Self {
            secret_key,
            public_key,
            node_id,
        })
    }

    /// Convert this identity's NodeId to a UserId for use in adaptive modules
    pub fn to_user_id(&self) -> crate::peer_record::UserId {
        crate::peer_record::UserId::from_bytes(self.node_id.0)
    }

    /// Generate from seed (deterministic)
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        // Deterministically derive key material via HKDF-SHA3
        use saorsa_pqc::{HkdfSha3_256, api::traits::Kdf};

        // ML-DSA-65 public/secret key sizes (bytes)
        const ML_DSA_PUB_LEN: usize = 1952;
        const ML_DSA_SEC_LEN: usize = 4032;

        let mut derived = vec![0u8; ML_DSA_PUB_LEN + ML_DSA_SEC_LEN];
        HkdfSha3_256::derive(seed, None, b"saorsa-node-identity-seed", &mut derived).map_err(
            |_| P2PError::Identity(IdentityError::InvalidFormat("HKDF expand failed".into())),
        )?;

        let pub_bytes = &derived[..ML_DSA_PUB_LEN];
        let sec_bytes = &derived[ML_DSA_PUB_LEN..];

        // Construct keys from bytes; these constructors accept byte slices in our integration
        let public_key =
            crate::quantum_crypto::ant_quic_integration::MlDsaPublicKey::from_bytes(pub_bytes)
                .map_err(|e| {
                    P2PError::Identity(IdentityError::InvalidFormat(
                        format!("Invalid ML-DSA public key bytes: {e}").into(),
                    ))
                })?;
        let secret_key =
            crate::quantum_crypto::ant_quic_integration::MlDsaSecretKey::from_bytes(sec_bytes)
                .map_err(|e| {
                    P2PError::Identity(IdentityError::InvalidFormat(
                        format!("Invalid ML-DSA secret key bytes: {e}").into(),
                    ))
                })?;

        let node_id = NodeId::from_public_key(&public_key);

        crate::quantum_crypto::ant_quic_integration::register_debug_ml_dsa_keypair(
            &secret_key,
            &public_key,
        );

        Ok(Self {
            secret_key,
            public_key,
            node_id,
        })
    }

    /// Get node ID
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Get public key
    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }

    // No Proof-of-Work in this crate

    /// Get secret key bytes (for raw key authentication)
    pub fn secret_key_bytes(&self) -> &[u8] {
        self.secret_key.as_bytes()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<MlDsaSignature> {
        crate::quantum_crypto::ml_dsa_sign(&self.secret_key, message).map_err(|e| {
            P2PError::Identity(IdentityError::InvalidFormat(
                format!("ML-DSA signing failed: {:?}", e).into(),
            ))
        })
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &MlDsaSignature) -> Result<bool> {
        crate::quantum_crypto::ml_dsa_verify(&self.public_key, message, signature).map_err(|e| {
            P2PError::Identity(IdentityError::InvalidFormat(
                format!("ML-DSA verification failed: {:?}", e).into(),
            ))
        })
    }

    /// Create a public version of this identity (safe to clone)
    pub fn to_public(&self) -> PublicNodeIdentity {
        PublicNodeIdentity {
            public_key: self.public_key.clone(),
            node_id: self.node_id.clone(),
        }
    }
}

impl NodeIdentity {
    /// Create an identity from an existing secret key
    /// Note: Currently not supported as ant-quic doesn't provide public key derivation from secret key
    /// This would require storing both keys together
    pub fn from_secret_key(_secret_key: MlDsaSecretKey) -> Result<Self> {
        Err(P2PError::Identity(IdentityError::InvalidFormat(
            "Creating identity from secret key alone is not supported"
                .to_string()
                .into(),
        )))
    }
}

impl NodeIdentity {
    /// Save identity to a JSON file (async)
    pub async fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        use tokio::fs;
        let data = self.export();
        let json = serde_json::to_string_pretty(&data).map_err(|e| {
            P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                format!("Failed to serialize identity: {}", e).into(),
            ))
        })?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                    format!("Failed to create directory: {}", e).into(),
                ))
            })?;
        }

        tokio::fs::write(path, json).await.map_err(|e| {
            P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                format!("Failed to write identity file: {}", e).into(),
            ))
        })?;
        Ok(())
    }

    /// Load identity from a JSON file (async)
    pub async fn load_from_file(path: &std::path::Path) -> Result<Self> {
        let json = tokio::fs::read_to_string(path).await.map_err(|e| {
            P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                format!("Failed to read identity file: {}", e).into(),
            ))
        })?;
        let data: IdentityData = serde_json::from_str(&json).map_err(|e| {
            P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                format!("Failed to deserialize identity: {}", e).into(),
            ))
        })?;
        Self::import(&data)
    }
}

/// Serializable identity data for persistence
#[derive(Serialize, Deserialize)]
pub struct IdentityData {
    /// ML-DSA secret key bytes (4032 bytes for ML-DSA-65)
    pub secret_key: Vec<u8>,
    /// ML-DSA public key bytes (1952 bytes for ML-DSA-65)
    pub public_key: Vec<u8>,
}

impl NodeIdentity {
    /// Export identity for persistence
    pub fn export(&self) -> IdentityData {
        IdentityData {
            secret_key: self.secret_key.as_bytes().to_vec(),
            public_key: self.public_key.as_bytes().to_vec(),
        }
    }

    /// Import identity from persisted data
    pub fn import(data: &IdentityData) -> Result<Self> {
        // Reconstruct keys from bytes
        let secret_key = crate::quantum_crypto::ant_quic_integration::MlDsaSecretKey::from_bytes(
            &data.secret_key,
        )
        .map_err(|e| {
            P2PError::Identity(IdentityError::InvalidFormat(
                format!("Invalid ML-DSA secret key: {e}").into(),
            ))
        })?;
        let public_key = crate::quantum_crypto::ant_quic_integration::MlDsaPublicKey::from_bytes(
            &data.public_key,
        )
        .map_err(|e| {
            P2PError::Identity(IdentityError::InvalidFormat(
                format!("Invalid ML-DSA public key: {e}").into(),
            ))
        })?;

        let node_id = NodeId::from_public_key(&public_key);

        crate::quantum_crypto::ant_quic_integration::register_debug_ml_dsa_keypair(
            &secret_key,
            &public_key,
        );

        Ok(Self {
            secret_key,
            public_key,
            node_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_generation() {
        let (public_key, _secret_key) = crate::quantum_crypto::generate_ml_dsa_keypair()
            .expect("ML-DSA key generation should succeed");
        let node_id = NodeId::from_public_key(&public_key);

        // Should be 32 bytes
        assert_eq!(node_id.to_bytes().len(), 32);

        // Should be deterministic
        let node_id2 = NodeId::from_public_key(&public_key);
        assert_eq!(node_id, node_id2);
    }

    #[test]
    fn test_xor_distance() {
        let id1 = NodeId([0u8; 32]);
        let mut id2_bytes = [0u8; 32];
        id2_bytes[0] = 0xFF;
        let id2 = NodeId(id2_bytes);

        let distance = id1.xor_distance(&id2);
        assert_eq!(distance[0], 0xFF);
        for byte in &distance[1..] {
            assert_eq!(*byte, 0);
        }
    }

    #[test]
    fn test_proof_of_work() {
        // PoW removed: this test no longer applicable
    }

    #[test]
    fn test_identity_generation() {
        let identity = NodeIdentity::generate().expect("Identity generation should succeed");

        // Test signing and verification
        let message = b"Hello, P2P!";
        let signature = identity.sign(message).unwrap();
        assert!(identity.verify(message, &signature).unwrap());

        // Wrong message should fail with original signature
        assert!(!identity.verify(b"Wrong message", &signature).unwrap());
    }

    #[test]
    fn test_deterministic_generation() {
        let seed = [0x42; 32];
        let identity1 = NodeIdentity::from_seed(&seed).expect("Identity from seed should succeed");
        let identity2 = NodeIdentity::from_seed(&seed).expect("Identity from seed should succeed");

        // Should generate same identity
        assert_eq!(identity1.node_id, identity2.node_id);
        assert_eq!(
            identity1.public_key().as_bytes(),
            identity2.public_key().as_bytes()
        );
    }

    #[test]
    fn test_identity_persistence() {
        let identity = NodeIdentity::generate().expect("Identity generation should succeed");

        // Export
        let data = identity.export();

        // Import
        let imported = NodeIdentity::import(&data).expect("Import should succeed with valid data");

        // Should be the same
        assert_eq!(identity.node_id, imported.node_id);
        assert_eq!(
            identity.public_key().as_bytes(),
            imported.public_key().as_bytes()
        );

        // Should be able to sign with imported identity
        let message = b"Test message";
        let signature = imported.sign(message);
        assert!(identity.verify(message, &signature.unwrap()).unwrap());
    }
}
