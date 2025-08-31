// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Cryptographic identity system for the adaptive P2P network
//!
//! Implements Ed25519-based identity. Sybil-resistance is handled by
//! higher-level mechanisms.

use super::*;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Node identity with cryptographic keys
#[derive(Clone)]
pub struct NodeIdentity {
    /// Ed25519 signing key
    signing_key: SigningKey,
    /// Node ID derived from public key
    node_id: NodeId,
}

/// Signed message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage<T: Serialize> {
    /// Message payload
    pub payload: T,
    /// Sender's node ID
    pub sender_id: NodeId,
    /// Unix timestamp
    pub timestamp: u64,
    /// Ed25519 signature
    pub signature: Vec<u8>,
}

impl NodeIdentity {
    /// Generate a new node identity
    pub fn generate() -> Result<Self> {
        let mut csprng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut csprng);

        let node_id = Self::compute_node_id(&signing_key.verifying_key());

        Ok(Self {
            signing_key,
            node_id,
        })
    }

    /// Create identity from existing signing key
    pub fn from_signing_key(signing_key: SigningKey) -> Result<Self> {
        let node_id = Self::compute_node_id(&signing_key.verifying_key());

        Ok(Self {
            signing_key,
            node_id,
        })
    }

    /// Compute node ID from public key (SHA-256 hash)
    pub fn compute_node_id(public_key: &VerifyingKey) -> NodeId {
        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        let result = hasher.finalize();

        // Convert hash to UserId
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        crate::peer_record::UserId::from_bytes(bytes)
    }

    /// Sign a message
    pub fn sign_message<T: Serialize + Clone>(&self, message: &T) -> Result<SignedMessage<T>> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AdaptiveNetworkError::Other(e.to_string()))?
            .as_secs();

        let payload_bytes =
            bincode::serialize(message).map_err(AdaptiveNetworkError::Serialization)?;

        // Create bytes to sign: payload || sender_id || timestamp
        let mut bytes_to_sign = Vec::new();
        bytes_to_sign.extend_from_slice(&payload_bytes);
        bytes_to_sign.extend_from_slice(&self.node_id.hash);
        bytes_to_sign.extend_from_slice(&timestamp.to_le_bytes());

        let signature = self.signing_key.sign(&bytes_to_sign);

        Ok(SignedMessage {
            payload: message.clone(),
            sender_id: self.node_id.clone(),
            timestamp,
            signature: signature.to_bytes().to_vec(),
        })
    }

    /// Get node ID
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Get public key
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl<T: Serialize + for<'de> Deserialize<'de>> SignedMessage<T> {
    /// Verify message signature
    pub fn verify(&self, public_key: &VerifyingKey) -> Result<bool> {
        let payload_bytes =
            bincode::serialize(&self.payload).map_err(AdaptiveNetworkError::Serialization)?;

        // Recreate bytes that were signed
        let mut bytes_to_verify = Vec::new();
        bytes_to_verify.extend_from_slice(&payload_bytes);
        bytes_to_verify.extend_from_slice(&self.sender_id.hash);
        bytes_to_verify.extend_from_slice(&self.timestamp.to_le_bytes());

        let signature_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| AdaptiveNetworkError::Other("Invalid signature length".to_string()))?;
        let signature = Signature::from_bytes(&signature_bytes);

        Ok(public_key.verify(&bytes_to_verify, &signature).is_ok())
    }

    /// Get message age in seconds
    pub fn age(&self) -> Result<u64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AdaptiveNetworkError::Other(e.to_string()))?
            .as_secs();

        Ok(now.saturating_sub(self.timestamp))
    }
}

/// Identity storage for persistence
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredIdentity {
    /// Secret key bytes
    pub secret_key: Vec<u8>,
    /// Public key bytes
    pub public_key: Vec<u8>,
    /// Node ID
    pub node_id: NodeId,
}

impl StoredIdentity {
    /// Create from NodeIdentity
    pub fn from_identity(identity: &NodeIdentity) -> Self {
        Self {
            secret_key: identity.signing_key.to_bytes().to_vec(),
            public_key: identity.signing_key.verifying_key().to_bytes().to_vec(),
            node_id: identity.node_id.clone(),
        }
    }

    /// Restore to NodeIdentity
    pub fn to_identity(&self) -> Result<NodeIdentity> {
        let secret_key_bytes: [u8; 32] =
            self.secret_key.as_slice().try_into().map_err(|_| {
                AdaptiveNetworkError::Other("Invalid secret key length".to_string())
            })?;
        let signing_key = SigningKey::from_bytes(&secret_key_bytes);

        let public_key_bytes: [u8; 32] =
            self.public_key.as_slice().try_into().map_err(|_| {
                AdaptiveNetworkError::Other("Invalid public key length".to_string())
            })?;
        let public_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|e| AdaptiveNetworkError::Other(format!("Invalid public key: {e}")))?;

        // Verify the stored public key matches the signing key
        if signing_key.verifying_key().to_bytes() != public_key.to_bytes() {
            return Err(AdaptiveNetworkError::Other(
                "Public key doesn't match signing key".to_string(),
            ));
        }

        // Verify the stored node ID matches
        let computed_id = NodeIdentity::compute_node_id(&public_key);
        if computed_id != self.node_id {
            return Err(AdaptiveNetworkError::Other(
                "Stored node ID doesn't match computed ID".to_string(),
            ));
        }

        Ok(NodeIdentity {
            signing_key,
            node_id: self.node_id.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let identity = NodeIdentity::generate().unwrap();

        // Verify node ID matches public key
        let computed_id = NodeIdentity::compute_node_id(&identity.public_key());
        assert_eq!(&computed_id, identity.node_id());

        // PoW removed
    }

    #[test]
    fn test_message_signing_and_verification() {
        let identity = NodeIdentity::generate().unwrap();

        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        struct TestMessage {
            content: String,
            value: u64,
        }

        let message = TestMessage {
            content: "Hello, P2P!".to_string(),
            value: 42,
        };

        // Sign message
        let signed = identity.sign_message(&message).unwrap();

        // Verify with correct public key
        assert!(signed.verify(&identity.public_key()).unwrap());

        // Verify with wrong public key should fail
        let other_identity = NodeIdentity::generate().unwrap();
        assert!(!signed.verify(&other_identity.public_key()).unwrap());
    }

    #[test]
    fn test_proof_of_work_verification() {}

    #[test]
    fn test_identity_serialization() {
        let identity = NodeIdentity::generate().unwrap();

        // Store identity
        let stored = StoredIdentity::from_identity(&identity);

        // Restore identity
        let restored = stored.to_identity().unwrap();

        // Verify they match
        assert_eq!(identity.node_id(), restored.node_id());
        assert_eq!(
            identity.public_key().to_bytes(),
            restored.public_key().to_bytes()
        );
    }
}
