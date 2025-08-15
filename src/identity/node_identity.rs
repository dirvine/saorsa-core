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
//! - Ed25519 cryptographic keys
//! - Four-word human-readable addresses
//! - Proof-of-work for Sybil resistance
//! - Deterministic generation from seeds

use crate::error::IdentityError;
use crate::{P2PError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::{Duration, Instant};

// Import our four-word implementation
use super::four_words::{FourWordAddress, WordEncoder};

/// Node ID derived from public key (256-bit)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Create from verifying key
    pub fn from_public_key(public_key: &VerifyingKey) -> Self {
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
        for i in 0..32 {
            distance[i] = self.0[i] ^ other.0[i];
        }
        distance
    }

    /// Create from public key bytes
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(P2PError::Identity(IdentityError::InvalidFormat(
                "Invalid public key length".to_string().into(),
            )));
        }

        // Create a VerifyingKey from bytes and then derive NodeId
        let verifying_key = VerifyingKey::from_bytes(bytes.try_into().map_err(|_| {
            IdentityError::InvalidFormat(
                "Invalid byte array length for public key"
                    .to_string()
                    .into(),
            )
        })?)
        .map_err(|e| IdentityError::InvalidFormat(format!("Invalid public key: {}", e).into()))?;

        Ok(NodeId::from_public_key(&verifying_key))
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
    /// Ed25519 signing key (private)
    signing_key: SigningKey,
    /// Ed25519 verifying key (public)
    verification_key: VerifyingKey,
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
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verification_key = signing_key.verifying_key();
        let node_id = NodeId::from_public_key(&verification_key);

        // Solve proof of work
        let proof_of_work = ProofOfWork::solve(&node_id, pow_difficulty)?;

        // Generate four-word address from node ID
        let word_address = WordEncoder::encode(node_id.to_bytes())?;

        Ok(Self {
            signing_key,
            verification_key,
            node_id,
            word_address,
            proof_of_work,
        })
    }

    /// Generate from seed (deterministic)
    pub fn from_seed(seed: &[u8; 32], pow_difficulty: u32) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(seed);
        let verification_key = signing_key.verifying_key();
        let node_id = NodeId::from_public_key(&verification_key);

        // Solve proof of work
        let proof_of_work = ProofOfWork::solve(&node_id, pow_difficulty)?;

        // Generate four-word address from node ID
        let word_address = WordEncoder::encode(node_id.to_bytes())?;

        Ok(Self {
            signing_key,
            verification_key,
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
    pub fn public_key(&self) -> &VerifyingKey {
        &self.verification_key
    }

    /// Get four-word address
    pub fn word_address(&self) -> &str {
        self.word_address.as_str()
    }

    /// Get proof of work
    pub fn proof_of_work(&self) -> &ProofOfWork {
        &self.proof_of_work
    }

    /// Get signing key bytes (for raw key authentication)
    pub fn signing_key_bytes(&self) -> &[u8; 32] {
        self.signing_key.as_bytes()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.verification_key.verify(message, signature).is_ok()
    }
}

/// Serializable identity data for persistence
#[derive(Serialize, Deserialize)]
pub struct IdentityData {
    /// Private key bytes
    pub private_key: Vec<u8>,
    /// Proof of work
    pub proof_of_work: ProofOfWork,
}

impl NodeIdentity {
    /// Export identity for persistence
    pub fn export(&self) -> IdentityData {
        IdentityData {
            private_key: self.signing_key.to_bytes().to_vec(),
            proof_of_work: self.proof_of_work.clone(),
        }
    }

    /// Import identity from persisted data
    pub fn import(data: &IdentityData) -> Result<Self> {
        let signing_key =
            SigningKey::from_bytes(data.private_key.as_slice().try_into().map_err(|_| {
                P2PError::Identity(IdentityError::InvalidFormat(
                    "Invalid private key length".to_string().into(),
                ))
            })?);
        let verification_key = signing_key.verifying_key();
        let node_id = NodeId::from_public_key(&verification_key);

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
            signing_key,
            verification_key,
            node_id,
            word_address,
            proof_of_work: data.proof_of_work.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_generation() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verification_key = signing_key.verifying_key();
        let node_id = NodeId::from_public_key(&verification_key);

        // Should be 32 bytes
        assert_eq!(node_id.to_bytes().len(), 32);

        // Should be deterministic
        let node_id2 = NodeId::from_public_key(&verification_key);
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
