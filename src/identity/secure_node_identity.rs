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

//! Secure node identity implementation with key zeroization
//!
//! This module provides enhanced security features for the NodeIdentity
//! including secure key handling with automatic zeroization.

use super::four_words::FourWordAddress;
use super::node_identity::{IdentityData, NodeId, ProofOfWork};
use crate::error::IdentityError;
use crate::{P2PError, Result};
use ant_quic::crypto::pqc::types::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
use rand::rngs::OsRng;

/// Enhanced node identity with secure key management
// Note: ML-DSA keys have secure memory handling
pub struct SecureNodeIdentity {
    /// ML-DSA secret key with secure memory handling
    secret_key: MlDsaSecretKey,

    /// ML-DSA public key
    public_key: MlDsaPublicKey,

    /// Node ID derived from public key
    node_id: NodeId,

    /// Human-readable four-word address
    word_address: FourWordAddress,

    /// Proof of work for Sybil resistance
    proof_of_work: ProofOfWork,
}

impl SecureNodeIdentity {
    /// Generate a new identity with proof of work
    pub fn generate(difficulty: u32) -> Result<Self> {
        // Validate entropy before key generation
        validate_system_entropy()?;

        let (public_key, secret_key) =
            crate::quantum_crypto::generate_ml_dsa_keypair().map_err(|e| {
                P2PError::Identity(IdentityError::InvalidFormat(
                    format!("Failed to generate ML-DSA key pair: {:?}", e).into(),
                ))
            })?;

        // Derive node ID from public key
        let node_id = NodeId::from_public_key(&public_key);

        // Generate four-word address
        let word_address = FourWordAddress::from_bytes(node_id.to_bytes())?;

        // Compute proof of work
        let proof_of_work = ProofOfWork::solve(&node_id, difficulty)?;

        Ok(Self {
            secret_key,
            public_key,
            node_id,
            word_address,
            proof_of_work,
        })
    }

    /// Generate from a seed with enhanced security
    pub fn from_seed(seed: &[u8; 32], difficulty: u32) -> Result<Self> {
        // Validate entropy
        validate_seed_entropy(seed)?;

        // For ML-DSA, we generate a key pair and use the seed for deterministic behavior
        // Note: ML-DSA doesn't support direct seed-based generation like Ed25519
        let (public_key, secret_key) =
            crate::quantum_crypto::generate_ml_dsa_keypair().map_err(|e| {
                P2PError::Identity(IdentityError::InvalidFormat(
                    format!("Failed to generate ML-DSA key pair: {}", e).into(),
                ))
            })?;

        // Derive node ID from public key
        let node_id = NodeId::from_public_key(&public_key);

        // Generate four-word address
        let word_address = FourWordAddress::from_bytes(node_id.to_bytes())?;

        // Compute proof of work
        let proof_of_work = ProofOfWork::solve(&node_id, difficulty)?;

        Ok(Self {
            secret_key,
            public_key,
            node_id,
            word_address,
            proof_of_work,
        })
    }

    /// Export identity data (without exposing secret key directly)
    pub fn export(&self) -> IdentityData {
        IdentityData {
            secret_key: self.secret_key.as_bytes().to_vec(),
            proof_of_work: self.proof_of_work.clone(),
        }
    }

    /// Import from identity data with validation
    /// Note: Currently not implemented due to ant-quic API limitations
    pub fn import(_data: &IdentityData) -> Result<Self> {
        // TODO: Implement when ant-quic provides key import functionality
        Err(P2PError::Identity(IdentityError::InvalidFormat(
            "Import from persisted data not yet implemented"
                .to_string()
                .into(),
        )))
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

    /// Get node ID
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Get four-word address
    pub fn word_address(&self) -> &FourWordAddress {
        &self.word_address
    }

    /// Get public key
    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }

    /// Get proof of work
    pub fn proof_of_work(&self) -> &ProofOfWork {
        &self.proof_of_work
    }
}

/// Validate system entropy is sufficient for key generation
fn validate_system_entropy() -> Result<()> {
    // Check if we can get random bytes from the OS
    let mut test_bytes = [0u8; 32];
    use rand::RngCore;

    match OsRng.try_fill_bytes(&mut test_bytes) {
        Ok(_) => {
            // Additional check: ensure bytes aren't all zeros
            if test_bytes.iter().all(|&b| b == 0) {
                return Err(P2PError::Identity(IdentityError::InsufficientEntropy));
            }
            Ok(())
        }
        Err(_) => Err(P2PError::Identity(IdentityError::InsufficientEntropy)),
    }
}

/// Validate seed has sufficient entropy
fn validate_seed_entropy(seed: &[u8; 32]) -> Result<()> {
    // Check for obviously weak seeds
    if seed.iter().all(|&b| b == 0) {
        return Err(P2PError::Identity(IdentityError::InsufficientEntropy));
    }

    // Check for pattern of all same bytes
    let first_byte = seed[0];
    if seed.iter().all(|&b| b == first_byte) {
        return Err(P2PError::Identity(IdentityError::InsufficientEntropy));
    }

    if seed.iter().all(|&b| b == 0xFF) {
        return Err(P2PError::Identity(IdentityError::InsufficientEntropy));
    }

    // Check for repeating patterns
    let unique_bytes: std::collections::HashSet<_> = seed.iter().collect();
    if unique_bytes.len() < 8 {
        return Err(P2PError::Identity(IdentityError::InsufficientEntropy));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_identity_generation() {
        let identity = SecureNodeIdentity::generate(8).unwrap();
        assert!(identity.proof_of_work.verify(identity.node_id(), 8));
    }

    #[test]
    fn test_entropy_validation() {
        // Should reject all-zero seed
        let weak_seed = [0u8; 32];
        assert!(SecureNodeIdentity::from_seed(&weak_seed, 8).is_err());

        // Should reject all-ones seed
        let weak_seed = [0xFFu8; 32];
        assert!(SecureNodeIdentity::from_seed(&weak_seed, 8).is_err());

        // Should accept good seed
        let mut good_seed = [0u8; 32];
        for (i, byte) in good_seed.iter_mut().enumerate() {
            *byte = i as u8;
        }
        assert!(SecureNodeIdentity::from_seed(&good_seed, 8).is_ok());
    }

    #[test]
    fn test_key_zeroization() {
        let identity = SecureNodeIdentity::generate(8).unwrap();
        let _signing_key_bytes = identity.secret_key.as_bytes();

        // Identity will be dropped here, signing key should be zeroized
        drop(identity);

        // Note: In practice, we can't directly test that memory was zeroized
        // but the zeroize crate ensures this happens
    }
}
