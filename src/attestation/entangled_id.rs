// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Entangled Identity implementation.
//!
//! An Entangled Identity binds a node's cryptographic identity to:
//! - Its public key (ML-DSA-65)
//! - The hash of its executing binary
//! - A unique nonce
//!
//! The derivation formula is:
//! ```text
//! N_ID = BLAKE3(PK || binary_hash || nonce)
//! ```

use crate::identity::node_identity::NodeId;
use crate::quantum_crypto::ant_quic_integration::MlDsaPublicKey;
use serde::{Deserialize, Serialize};
use std::fmt;

/// An Entangled Identity that binds a node's ID to its software.
///
/// This structure represents a node identity that is cryptographically
/// entangled with the binary it is running, preventing identity spoofing
/// while running modified software.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntangledId {
    /// The derived 32-byte identity: BLAKE3(PK || binary_hash || nonce)
    id: [u8; 32],

    /// The hash of the binary this identity is bound to
    binary_hash: [u8; 32],

    /// The nonce used in derivation
    nonce: u64,
}

impl EntangledId {
    /// Derive an entangled identity from its components.
    ///
    /// The derivation formula is:
    /// ```text
    /// N_ID = BLAKE3(PK || binary_hash || nonce)
    /// ```
    ///
    /// # Arguments
    ///
    /// * `public_key` - The ML-DSA-65 public key
    /// * `binary_hash` - The BLAKE3 hash of the binary
    /// * `nonce` - A unique nonce (e.g., timestamp or random)
    ///
    /// # Returns
    ///
    /// A new `EntangledId` with the derived identity.
    #[must_use]
    pub fn derive(public_key: &MlDsaPublicKey, binary_hash: &[u8; 32], nonce: u64) -> Self {
        let id = Self::compute_id(public_key, binary_hash, nonce);
        Self {
            id,
            binary_hash: *binary_hash,
            nonce,
        }
    }

    /// Compute the entangled ID from components.
    fn compute_id(public_key: &MlDsaPublicKey, binary_hash: &[u8; 32], nonce: u64) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();

        // Prepend public key bytes
        hasher.update(public_key.as_bytes());

        // Append binary hash
        hasher.update(binary_hash);

        // Append nonce as little-endian bytes
        hasher.update(&nonce.to_le_bytes());

        *hasher.finalize().as_bytes()
    }

    /// Verify that this entangled ID matches the given public key.
    ///
    /// This re-derives the ID from the public key and the stored binary hash/nonce,
    /// then compares with the stored ID.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The ML-DSA-65 public key to verify against
    ///
    /// # Returns
    ///
    /// `true` if the ID was derived from this public key and the stored binary hash/nonce.
    #[must_use]
    pub fn verify(&self, public_key: &MlDsaPublicKey) -> bool {
        let expected = Self::compute_id(public_key, &self.binary_hash, self.nonce);
        self.id == expected
    }

    /// Verify that this entangled ID matches the given public key and binary hash.
    ///
    /// This is a stricter verification that also checks the binary hash matches.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The ML-DSA-65 public key to verify against
    /// * `binary_hash` - The expected binary hash
    ///
    /// # Returns
    ///
    /// `true` if the ID was derived from this public key, this binary hash, and the stored nonce.
    #[must_use]
    pub fn verify_with_binary(&self, public_key: &MlDsaPublicKey, binary_hash: &[u8; 32]) -> bool {
        // First check that the binary hash matches what we stored
        if &self.binary_hash != binary_hash {
            return false;
        }

        // Then verify the full derivation
        self.verify(public_key)
    }

    /// Get the raw 32-byte identity.
    #[must_use]
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Get the binary hash this identity is bound to.
    #[must_use]
    pub fn binary_hash(&self) -> &[u8; 32] {
        &self.binary_hash
    }

    /// Get the nonce used in derivation.
    #[must_use]
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Convert to a `NodeId` for use in DHT routing.
    ///
    /// The `NodeId` is simply the entangled ID bytes.
    #[must_use]
    pub fn to_node_id(&self) -> NodeId {
        NodeId::from_bytes(self.id)
    }

    /// Calculate XOR distance to another entangled ID.
    ///
    /// This is used for Kademlia routing.
    #[must_use]
    pub fn xor_distance(&self, other: &EntangledId) -> [u8; 32] {
        let mut distance = [0u8; 32];
        for (i, out) in distance.iter_mut().enumerate() {
            *out = self.id[i] ^ other.id[i];
        }
        distance
    }

    /// Create from raw bytes (for deserialization/testing).
    ///
    /// # Warning
    ///
    /// This bypasses the derivation process and should only be used
    /// for deserialization or testing purposes.
    #[must_use]
    pub fn from_raw(id: [u8; 32], binary_hash: [u8; 32], nonce: u64) -> Self {
        Self {
            id,
            binary_hash,
            nonce,
        }
    }
}

impl fmt::Display for EntangledId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display first 8 bytes as hex for brevity
        write!(f, "{}", hex::encode(&self.id[..8]))
    }
}

impl fmt::Debug for EntangledId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntangledId")
            .field("id", &hex::encode(&self.id[..8]))
            .field("binary_hash", &hex::encode(&self.binary_hash[..8]))
            .field("nonce", &self.nonce)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quantum_crypto::generate_ml_dsa_keypair;

    #[test]
    fn test_derive_deterministic() {
        let (pk, _) = generate_ml_dsa_keypair().unwrap();
        let binary_hash = [0x42u8; 32];
        let nonce = 12345u64;

        let id1 = EntangledId::derive(&pk, &binary_hash, nonce);
        let id2 = EntangledId::derive(&pk, &binary_hash, nonce);

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_different_keys_different_ids() {
        let (pk1, _) = generate_ml_dsa_keypair().unwrap();
        let (pk2, _) = generate_ml_dsa_keypair().unwrap();
        let binary_hash = [0x42u8; 32];
        let nonce = 12345u64;

        let id1 = EntangledId::derive(&pk1, &binary_hash, nonce);
        let id2 = EntangledId::derive(&pk2, &binary_hash, nonce);

        assert_ne!(id1.id(), id2.id());
    }

    #[test]
    fn test_different_binaries_different_ids() {
        let (pk, _) = generate_ml_dsa_keypair().unwrap();
        let binary_hash1 = [0x42u8; 32];
        let binary_hash2 = [0x43u8; 32];
        let nonce = 12345u64;

        let id1 = EntangledId::derive(&pk, &binary_hash1, nonce);
        let id2 = EntangledId::derive(&pk, &binary_hash2, nonce);

        assert_ne!(id1.id(), id2.id());
    }

    #[test]
    fn test_verification() {
        let (pk, _) = generate_ml_dsa_keypair().unwrap();
        let binary_hash = [0x42u8; 32];
        let nonce = 12345u64;

        let id = EntangledId::derive(&pk, &binary_hash, nonce);

        assert!(id.verify(&pk));
    }

    #[test]
    fn test_verification_wrong_key() {
        let (pk1, _) = generate_ml_dsa_keypair().unwrap();
        let (pk2, _) = generate_ml_dsa_keypair().unwrap();
        let binary_hash = [0x42u8; 32];
        let nonce = 12345u64;

        let id = EntangledId::derive(&pk1, &binary_hash, nonce);

        assert!(!id.verify(&pk2));
    }

    #[test]
    fn test_xor_distance_self() {
        let (pk, _) = generate_ml_dsa_keypair().unwrap();
        let id = EntangledId::derive(&pk, &[0u8; 32], 0);

        let distance = id.xor_distance(&id);
        assert_eq!(distance, [0u8; 32]);
    }

    #[test]
    fn test_to_node_id() {
        let (pk, _) = generate_ml_dsa_keypair().unwrap();
        let id = EntangledId::derive(&pk, &[0u8; 32], 0);
        let node_id = id.to_node_id();

        assert_eq!(node_id.to_bytes(), id.id());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let (pk, _) = generate_ml_dsa_keypair().unwrap();
        let id = EntangledId::derive(&pk, &[0x42u8; 32], 12345);

        let json = serde_json::to_string(&id).unwrap();
        let restored: EntangledId = serde_json::from_str(&json).unwrap();

        assert_eq!(id, restored);
    }
}
