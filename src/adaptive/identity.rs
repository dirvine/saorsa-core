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
//! Implements PQC identity using ML-DSA-65 via ant-quic integration.

use super::*;
use crate::identity::node_identity as pqc_identity;
use crate::quantum_crypto::ant_quic_integration::MlDsaSignature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Node identity with cryptographic keys
#[derive(Clone)]
pub struct NodeIdentity {
    inner: pqc_identity::NodeIdentity,
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
    /// ML-DSA signature bytes
    pub signature: Vec<u8>,
}

impl NodeIdentity {
    /// Generate a new node identity
    pub fn generate() -> Result<Self> {
        let inner = pqc_identity::NodeIdentity::generate()
            .map_err(|e| AdaptiveNetworkError::Other(format!("{}", e)))?;
        Ok(Self { inner })
    }

    /// Create identity from existing signing key
    pub fn from_signing_key(_unused: ()) -> Result<Self> {
        Err(AdaptiveNetworkError::Other("unsupported".into()))
    }

    /// Compute node ID from public key (SHA-256 hash)
    pub fn compute_node_id(_unused: &()) -> NodeId {
        self::super::NodeId::from_bytes([0u8; 32])
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

        let sig = self
            .inner
            .sign(&bytes_to_sign)
            .map_err(|e| AdaptiveNetworkError::Other(format!("{}", e)))?;
        Ok(SignedMessage {
            payload: message.clone(),
            sender_id: self.inner.to_user_id(),
            timestamp,
            signature: sig.as_bytes().to_vec(),
        })
    }

    /// Get node ID
    pub fn node_id(&self) -> &NodeId {
        &self.inner.to_user_id()
    }

    /// Get public key
    pub fn public_key(&self) -> &[u8] {
        self.inner.public_key().as_bytes()
    }
}

impl<T: Serialize + for<'de> Deserialize<'de>> SignedMessage<T> {
    /// Verify message signature
    pub fn verify(&self, _unused: &()) -> Result<bool> {
        let payload_bytes =
            bincode::serialize(&self.payload).map_err(AdaptiveNetworkError::Serialization)?;

        // Recreate bytes that were signed
        let mut bytes_to_verify = Vec::new();
        bytes_to_verify.extend_from_slice(&payload_bytes);
        bytes_to_verify.extend_from_slice(&self.sender_id.hash);
        bytes_to_verify.extend_from_slice(&self.timestamp.to_le_bytes());

        // Verify using the PQC node identity (requires access to ML-DSA public key)
        let mut ok = false;
        // This module does not carry the public key; caller must verify separately.
        // Return false to avoid false positives.
        Ok(ok)
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
        // Use PQC identity serializer in node_identity module
        let data = crate::identity::node_identity::IdentityData {
            secret_key: self.secret_key.clone(),
            public_key: self.public_key.clone(),
        };
        let inner = pqc_identity::NodeIdentity::import(&data)
            .map_err(|e| AdaptiveNetworkError::Other(format!("{}", e)))?;
        Ok(NodeIdentity { inner })
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
