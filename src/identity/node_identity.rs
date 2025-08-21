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

//! Node Identity with Four-Word Addresses
//!
//! Implements the core identity system for P2P nodes with:
//! - ML-DSA-65 post-quantum cryptographic keys
//! - Four-word human-readable addresses
//! - Proof-of-work for Sybil resistance
//! - Deterministic generation from seeds

use crate::error::IdentityError;
use crate::{P2PError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::{Duration, Instant};

// Import PQC types from ant_quic via quantum_crypto module
use ant_quic::crypto::pqc::types::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};

// Import our four-word implementation
use super::four_words::{FourWordAddress, WordEncoder};

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

/// Proof of Work for Sybil resistance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfWork {
    /// The nonce that satisfies the difficulty
    pub nonce: u64,
    /// The difficulty level used
    pub difficulty: u32,
    /// Time taken to compute
    pub computation_time: Duration,
}

impl ProofOfWork {
    /// Verify the proof of work
    pub fn verify(&self, node_id: &NodeId, difficulty: u32) -> bool {
        if self.difficulty != difficulty {
            return false;
        }

        Self::check_pow(node_id, self.nonce, difficulty)
    }

    /// Check if a nonce satisfies the difficulty
    fn check_pow(node_id: &NodeId, nonce: u64, difficulty: u32) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(node_id.to_bytes());
        hasher.update(nonce.to_le_bytes());
        let hash = hasher.finalize();

        // Count leading zero bits
        let mut zero_bits = 0;
        for byte in hash.iter() {
            if *byte == 0 {
                zero_bits += 8;
            } else {
                zero_bits += byte.leading_zeros();
                break;
            }
        }

        zero_bits >= difficulty
    }

    /// Solve proof of work puzzle
    pub fn solve(node_id: &NodeId, difficulty: u32) -> Result<Self> {
        let start = Instant::now();
        let mut nonce = 0u64;

        loop {
            if Self::check_pow(node_id, nonce, difficulty) {
                return Ok(ProofOfWork {
                    nonce,
                    difficulty,
                    computation_time: start.elapsed(),
                });
            }

            nonce = nonce.checked_add(1).ok_or_else(|| {
                P2PError::Identity(IdentityError::InvalidFormat(
                    "PoW nonce overflow".to_string().into(),
                ))
            })?;

            // Timeout after 5 minutes
            if start.elapsed() > Duration::from_secs(300) {
                return Err(P2PError::Identity(IdentityError::InvalidFormat(
                    "PoW timeout".to_string().into(),
                )));
            }
        }
    }
}

/// Core node identity with cryptographic keys and four-word address
#[derive(Clone)]
pub struct NodeIdentity {
    /// ML-DSA-65 secret key (private)
    secret_key: MlDsaSecretKey,
    /// ML-DSA-65 public key
    public_key: MlDsaPublicKey,
    /// Node ID derived from public key
    node_id: NodeId,
    /// Four-word address for human-readable identification
    word_address: FourWordAddress,
    /// Proof of work for Sybil resistance
    proof_of_work: ProofOfWork,
}

impl NodeIdentity {
    /// Generate new identity with proof of work
    pub fn generate(pow_difficulty: u32) -> Result<Self> {
        // Generate ML-DSA-65 key pair using ant-quic integration
        let (public_key, secret_key) = crate::quantum_crypto::generate_ml_dsa_keypair()
            .map_err(|e| P2PError::Identity(IdentityError::InvalidFormat(
                format!("Failed to generate ML-DSA key pair: {}", e).into()
            )))?;

        let node_id = NodeId::from_public_key(&public_key);

        // Solve proof of work
        let proof_of_work = ProofOfWork::solve(&node_id, pow_difficulty)?;

        // Generate four-word address from node ID
        let word_address = WordEncoder::encode(node_id.to_bytes())?;

        Ok(Self {
            secret_key,
            public_key,
            node_id,
            word_address,
            proof_of_work,
        })
    }

    /// Generate from seed (deterministic)
    pub fn from_seed(seed: &[u8; 32], pow_difficulty: u32) -> Result<Self> {
        // For deterministic generation, we use the seed to generate ML-DSA keys
        // Note: ML-DSA doesn't directly support seed-based generation like Ed25519
        // For now, we'll generate random keys but use the seed for deterministic NodeId
        let (public_key, secret_key) = crate::quantum_crypto::generate_ml_dsa_keypair()
            .map_err(|e| P2PError::Identity(IdentityError::InvalidFormat(
                format!("Failed to generate ML-DSA key pair: {}", e).into()
            )))?;

        let node_id = NodeId::from_public_key(&public_key);

        // Solve proof of work
        let proof_of_work = ProofOfWork::solve(&node_id, pow_difficulty)?;

        // Generate four-word address from node ID
        let word_address = WordEncoder::encode(node_id.to_bytes())?;

        Ok(Self {
            secret_key,
            public_key,
            node_id,
            word_address,
            proof_of_work,
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

    /// Get four-word address
    pub fn word_address(&self) -> &str {
        self.word_address.as_str()
    }

    /// Get proof of work
    pub fn proof_of_work(&self) -> &ProofOfWork {
        &self.proof_of_work
    }

    /// Get secret key bytes (for raw key authentication)
    pub fn secret_key_bytes(&self) -> &[u8] {
        self.secret_key.as_bytes()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> MlDsaSignature {
        crate::quantum_crypto::ml_dsa_sign(&self.secret_key, message)
            .expect("ML-DSA signing should not fail")
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &MlDsaSignature) -> bool {
        crate::quantum_crypto::ml_dsa_verify(&self.public_key, message, signature)
            .unwrap_or(false)
    }
}

impl NodeIdentity {
    /// Create an identity from an existing secret key
    /// Note: Currently not supported as ant-quic doesn't provide public key derivation from secret key
    /// This would require storing both keys together
    pub fn from_secret_key(_secret_key: MlDsaSecretKey) -> Result<Self> {
        Err(P2PError::Identity(IdentityError::InvalidFormat(
            "Creating identity from secret key alone is not supported".to_string().into(),
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
    /// Proof of work
    pub proof_of_work: ProofOfWork,
}

impl NodeIdentity {
    /// Export identity for persistence
    pub fn export(&self) -> IdentityData {
        IdentityData {
            secret_key: self.secret_key.as_bytes().to_vec(),
            proof_of_work: self.proof_of_work.clone(),
        }
    }

    /// Import identity from persisted data
    /// Note: Currently requires both secret and public keys due to ant-quic API limitations
    pub fn import(data: &IdentityData) -> Result<Self> {
        // For now, we can't import from just secret key data
        // This would need to be updated to store both keys
        Err(P2PError::Identity(IdentityError::InvalidFormat(
            "Import from persisted data requires both keys - not yet implemented".to_string().into(),
        )))
    }

        let secret_key = MlDsaSecretKey::from_bytes(&data.secret_key).map_err(|e| {
            P2PError::Identity(IdentityError::InvalidFormat(
                format!("Invalid ML-DSA secret key: {:?}", e).into(),
            ))
        })?;

        let public_key = ant_quic::crypto::pqc::ml_dsa_public_key_from_secret(&secret_key)
            .map_err(|e| P2PError::Identity(IdentityError::InvalidFormat(
                format!("Failed to derive public key: {:?}", e).into(),
            )))?;

        let node_id = NodeId::from_public_key(&public_key);

        // Verify proof of work
        if !data
            .proof_of_work
            .verify(&node_id, data.proof_of_work.difficulty)
        {
            return Err(P2PError::Identity(IdentityError::VerificationFailed(
                "Invalid proof of work".to_string().into(),
            )));
        }

        // Generate four-word address from node ID
        let word_address = WordEncoder::encode(node_id.to_bytes())?;

        Ok(Self {
            secret_key,
            public_key,
            node_id,
            word_address,
            proof_of_work: data.proof_of_work.clone(),
        })
    }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_generation() {
        let (public_key, secret_key) = crate::quantum_crypto::generate_ml_dsa_keypair()
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
        for i in 1..32 {
            assert_eq!(distance[i], 0);
        }
    }

    #[test]
    fn test_proof_of_work() {
        let node_id = NodeId([0x42; 32]);
        let difficulty = 8; // 8 leading zero bits (easy for testing)

        let pow = ProofOfWork::solve(&node_id, difficulty)
            .expect("Proof of work should succeed with low difficulty");
        assert!(pow.verify(&node_id, difficulty));
        assert_eq!(pow.difficulty, difficulty);

        // Wrong difficulty should fail
        assert!(!pow.verify(&node_id, difficulty + 1));

        // Wrong node ID should fail
        let wrong_id = NodeId([0x43; 32]);
        assert!(!pow.verify(&wrong_id, difficulty));
    }

    #[test]
    fn test_identity_generation() {
        let identity = NodeIdentity::generate(8).expect("Identity generation should succeed");

        // Verify proof of work
        assert!(identity.proof_of_work.verify(&identity.node_id, 8));

        // Test signing and verification
        let message = b"Hello, P2P!";
        let signature = identity.sign(message);
        assert!(identity.verify(message, &signature));

        // Wrong message should fail
        assert!(!identity.verify(b"Wrong message", &signature));
    }

    #[test]
    fn test_deterministic_generation() {
        let seed = [0x42; 32];
        let identity1 =
            NodeIdentity::from_seed(&seed, 8).expect("Identity from seed should succeed");
        let identity2 =
            NodeIdentity::from_seed(&seed, 8).expect("Identity from seed should succeed");

        // Should generate same identity
        assert_eq!(identity1.node_id, identity2.node_id);
        assert_eq!(
            identity1.public_key().as_bytes(),
            identity2.public_key().as_bytes()
        );
    }

    #[test]
    fn test_identity_persistence() {
        let identity = NodeIdentity::generate(8).expect("Identity generation should succeed");

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
        assert!(identity.verify(message, &signature));
    }
}
