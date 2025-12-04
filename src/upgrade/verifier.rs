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

//! Signature verification for updates using ML-DSA-65.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

use super::config::PinnedKey;
use super::error::UpgradeError;

/// Signature verifier for update artifacts.
pub struct SignatureVerifier {
    /// Pinned signing keys indexed by key_id.
    keys: HashMap<String, PinnedKey>,
}

impl SignatureVerifier {
    /// Create a new verifier with the given pinned keys.
    #[must_use]
    pub fn new(keys: Vec<PinnedKey>) -> Self {
        let keys = keys
            .into_iter()
            .map(|k| (k.key_id.clone(), k))
            .collect();

        Self { keys }
    }

    /// Add a pinned key.
    pub fn add_key(&mut self, key: PinnedKey) {
        self.keys.insert(key.key_id.clone(), key);
    }

    /// Get a key by ID.
    #[must_use]
    pub fn get_key(&self, key_id: &str) -> Option<&PinnedKey> {
        self.keys.get(key_id)
    }

    /// Verify a signature against a message using ML-DSA-65.
    ///
    /// # Arguments
    ///
    /// * `key_id` - ID of the signing key
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify (base64 encoded)
    pub fn verify_signature(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &str,
    ) -> Result<bool, UpgradeError> {
        // Get the signing key
        let key = self
            .keys
            .get(key_id)
            .ok_or_else(|| UpgradeError::NoValidKey(key_id.to_string().into()))?;

        // Check key validity
        if !key.is_valid() {
            return Err(UpgradeError::NoValidKey(
                format!("key {} has expired or is not yet valid", key_id).into(),
            ));
        }

        // Decode the public key from base64
        let public_key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &key.public_key,
        )
        .map_err(|e| UpgradeError::SignatureVerification(format!("invalid public key encoding: {}", e).into()))?;

        // Decode signature from base64
        let signature_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            signature,
        )
        .map_err(|e| UpgradeError::SignatureVerification(format!("invalid signature encoding: {}", e).into()))?;

        // Use the quantum_crypto module for ML-DSA verification
        let public_key =
            crate::quantum_crypto::ant_quic_integration::MlDsaPublicKey::from_bytes(&public_key_bytes)
                .map_err(|e| UpgradeError::SignatureVerification(format!("invalid public key: {:?}", e).into()))?;

        let sig =
            crate::quantum_crypto::ant_quic_integration::MlDsaSignature::from_bytes(&signature_bytes)
                .map_err(|e| UpgradeError::SignatureVerification(format!("invalid signature: {:?}", e).into()))?;

        crate::quantum_crypto::ml_dsa_verify(&public_key, message, &sig)
            .map_err(|e| UpgradeError::SignatureVerification(format!("verification error: {:?}", e).into()))
    }

    /// Verify a file's checksum and signature.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file
    /// * `expected_sha256` - Expected SHA-256 hash (hex encoded)
    /// * `key_id` - ID of the signing key
    /// * `signature` - The signature to verify (base64 encoded)
    pub async fn verify_file(
        &self,
        path: &Path,
        expected_sha256: &str,
        key_id: &str,
        signature: &str,
    ) -> Result<(), UpgradeError> {
        // Read the file
        let contents = tokio::fs::read(path)
            .await
            .map_err(|e| UpgradeError::io(format!("failed to read file: {}", e)))?;

        // Verify checksum first (fast)
        self.verify_checksum(&contents, expected_sha256)?;

        // Then verify signature (slower)
        let verified = self.verify_signature(key_id, &contents, signature)?;

        if verified {
            Ok(())
        } else {
            Err(UpgradeError::SignatureVerification(
                "signature verification failed".into(),
            ))
        }
    }

    /// Verify a checksum.
    pub fn verify_checksum(&self, data: &[u8], expected_sha256: &str) -> Result<(), UpgradeError> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let actual = hex::encode(hash);

        if actual == expected_sha256.to_lowercase() {
            Ok(())
        } else {
            Err(UpgradeError::ChecksumMismatch {
                expected: expected_sha256.to_string(),
                actual,
            })
        }
    }

    /// Calculate SHA-256 checksum of data.
    #[must_use]
    pub fn calculate_checksum(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Calculate SHA-256 checksum of a file.
    pub async fn calculate_file_checksum(path: &Path) -> Result<String, UpgradeError> {
        let contents = tokio::fs::read(path)
            .await
            .map_err(|e| UpgradeError::io(format!("failed to read file: {}", e)))?;

        Ok(Self::calculate_checksum(&contents))
    }
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_creation() {
        let keys = vec![PinnedKey::new("key-001", "base64-encoded-key")];

        let verifier = SignatureVerifier::new(keys);
        assert!(verifier.get_key("key-001").is_some());
        assert!(verifier.get_key("key-002").is_none());
    }

    #[test]
    fn test_add_key() {
        let mut verifier = SignatureVerifier::default();
        assert!(verifier.get_key("key-001").is_none());

        verifier.add_key(PinnedKey::new("key-001", "test"));
        assert!(verifier.get_key("key-001").is_some());
    }

    #[test]
    fn test_checksum_verification() {
        let verifier = SignatureVerifier::default();
        let data = b"Hello, World!";

        let checksum = SignatureVerifier::calculate_checksum(data);
        assert!(verifier.verify_checksum(data, &checksum).is_ok());

        // Wrong checksum should fail
        assert!(verifier.verify_checksum(data, "wrong").is_err());
    }

    #[test]
    fn test_checksum_calculation() {
        let data = b"Hello, World!";
        let checksum = SignatureVerifier::calculate_checksum(data);

        // SHA-256 of "Hello, World!" is known
        assert_eq!(
            checksum,
            "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        );
    }

    #[test]
    fn test_verify_signature_no_key() {
        let verifier = SignatureVerifier::default();

        let result = verifier.verify_signature("nonexistent", b"message", "signature");
        assert!(result.is_err());

        if let Err(UpgradeError::NoValidKey(key_id)) = result {
            assert_eq!(key_id.as_ref(), "nonexistent");
        } else {
            panic!("Expected NoValidKey error");
        }
    }
}
