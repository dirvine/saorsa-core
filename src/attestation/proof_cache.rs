// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Attestation proof caching.
//!
//! Proofs are generated **once per binary version** and cached to disk.
//! This makes CPU-only proving practical since the 10-60 minute generation
//! time only occurs when the binary changes.
//!
//! ## Cache Structure
//!
//! ```text
//! ~/.saorsa/
//! └── attestation/
//!     ├── proof.bin          # Serialized AttestationProof
//!     └── metadata.json      # Binary hash, timestamp, version
//! ```
//!
//! ## Cache Invalidation
//!
//! The cache is invalidated when:
//! - Binary hash changes (software update)
//! - Public key changes (identity regeneration)
//! - Cache file is corrupted or missing

use super::{AttestationError, prover::AttestationProof};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Metadata about a cached proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofCacheMetadata {
    /// BLAKE3 hash of the binary this proof is for.
    pub binary_hash: [u8; 32],

    /// BLAKE3 hash of the public key this proof is for.
    pub public_key_hash: [u8; 32],

    /// Unix timestamp when the proof was generated.
    pub generated_at: u64,

    /// Version of the cache format.
    pub cache_version: u32,

    /// EntangledId this proof proves.
    pub entangled_id: [u8; 32],
}

/// Current cache format version.
const CACHE_VERSION: u32 = 1;

/// Proof cache manager.
///
/// Handles loading, saving, and validating cached attestation proofs.
#[derive(Debug)]
pub struct ProofCache {
    /// Directory where cache files are stored.
    cache_dir: PathBuf,
}

impl ProofCache {
    /// Create a new proof cache at the default location.
    ///
    /// Default: `~/.saorsa/attestation/`
    pub fn default_location() -> Result<Self, AttestationError> {
        let home = dirs::home_dir().ok_or_else(|| {
            AttestationError::CryptoError("Could not determine home directory".to_string())
        })?;

        let cache_dir = home.join(".saorsa").join("attestation");
        Self::new(cache_dir)
    }

    /// Create a new proof cache at a custom location.
    pub fn new(cache_dir: PathBuf) -> Result<Self, AttestationError> {
        // Create directory if it doesn't exist
        if !cache_dir.exists() {
            std::fs::create_dir_all(&cache_dir).map_err(|e| {
                AttestationError::SerializationError(format!(
                    "Failed to create cache directory: {e}"
                ))
            })?;
        }

        Ok(Self { cache_dir })
    }

    /// Path to the proof file.
    fn proof_path(&self) -> PathBuf {
        self.cache_dir.join("proof.bin")
    }

    /// Path to the metadata file.
    fn metadata_path(&self) -> PathBuf {
        self.cache_dir.join("metadata.json")
    }

    /// Check if a valid cached proof exists for the given binary and key.
    ///
    /// Returns `true` if:
    /// - Cache files exist
    /// - Metadata matches current binary hash and public key hash
    /// - Cache version is compatible
    #[must_use]
    pub fn is_valid(&self, binary_hash: &[u8; 32], public_key_hash: &[u8; 32]) -> bool {
        match self.load_metadata() {
            Ok(metadata) => {
                metadata.binary_hash == *binary_hash
                    && metadata.public_key_hash == *public_key_hash
                    && metadata.cache_version == CACHE_VERSION
            }
            Err(_) => false,
        }
    }

    /// Load cached proof if valid.
    ///
    /// # Arguments
    ///
    /// * `binary_hash` - Expected binary hash
    /// * `public_key_hash` - Expected public key hash
    ///
    /// # Returns
    ///
    /// - `Ok(Some(proof))` if valid cache exists
    /// - `Ok(None)` if cache is invalid or missing
    /// - `Err` if cache exists but is corrupted
    pub fn load(
        &self,
        binary_hash: &[u8; 32],
        public_key_hash: &[u8; 32],
    ) -> Result<Option<AttestationProof>, AttestationError> {
        // Check if cache is valid
        if !self.is_valid(binary_hash, public_key_hash) {
            return Ok(None);
        }

        // Load proof
        let proof_bytes = std::fs::read(self.proof_path()).map_err(|e| {
            AttestationError::SerializationError(format!("Failed to read proof cache: {e}"))
        })?;

        let proof: AttestationProof = serde_json::from_slice(&proof_bytes).map_err(|e| {
            AttestationError::SerializationError(format!("Failed to deserialize proof: {e}"))
        })?;

        Ok(Some(proof))
    }

    /// Save a proof to the cache.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to cache
    /// * `public_key_hash` - Hash of the public key
    pub fn save(
        &self,
        proof: &AttestationProof,
        public_key_hash: &[u8; 32],
    ) -> Result<(), AttestationError> {
        // Create metadata
        let metadata = ProofCacheMetadata {
            binary_hash: proof.public_inputs.binary_hash,
            public_key_hash: *public_key_hash,
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            cache_version: CACHE_VERSION,
            entangled_id: proof.public_inputs.entangled_id,
        };

        // Serialize and save proof
        let proof_bytes = serde_json::to_vec(proof).map_err(|e| {
            AttestationError::SerializationError(format!("Failed to serialize proof: {e}"))
        })?;

        std::fs::write(self.proof_path(), proof_bytes).map_err(|e| {
            AttestationError::SerializationError(format!("Failed to write proof cache: {e}"))
        })?;

        // Save metadata
        let metadata_bytes = serde_json::to_vec_pretty(&metadata).map_err(|e| {
            AttestationError::SerializationError(format!("Failed to serialize metadata: {e}"))
        })?;

        std::fs::write(self.metadata_path(), metadata_bytes).map_err(|e| {
            AttestationError::SerializationError(format!("Failed to write metadata: {e}"))
        })?;

        tracing::info!(
            binary_hash = hex::encode(&metadata.binary_hash[..8]),
            entangled_id = hex::encode(&metadata.entangled_id[..8]),
            "Attestation proof cached"
        );

        Ok(())
    }

    /// Load metadata only.
    fn load_metadata(&self) -> Result<ProofCacheMetadata, AttestationError> {
        let metadata_bytes = std::fs::read(self.metadata_path()).map_err(|e| {
            AttestationError::SerializationError(format!("Failed to read metadata: {e}"))
        })?;

        serde_json::from_slice(&metadata_bytes).map_err(|e| {
            AttestationError::SerializationError(format!("Failed to deserialize metadata: {e}"))
        })
    }

    /// Invalidate the cache (delete cached files).
    pub fn invalidate(&self) -> Result<(), AttestationError> {
        let proof_path = self.proof_path();
        let metadata_path = self.metadata_path();

        if proof_path.exists() {
            std::fs::remove_file(&proof_path).map_err(|e| {
                AttestationError::SerializationError(format!("Failed to remove proof: {e}"))
            })?;
        }

        if metadata_path.exists() {
            std::fs::remove_file(&metadata_path).map_err(|e| {
                AttestationError::SerializationError(format!("Failed to remove metadata: {e}"))
            })?;
        }

        tracing::info!("Attestation proof cache invalidated");
        Ok(())
    }

    /// Get the cache directory path.
    #[must_use]
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{AttestationProofPublicInputs, ProofType};
    use tempfile::TempDir;

    fn create_test_proof() -> AttestationProof {
        AttestationProof {
            proof_bytes: vec![1, 2, 3, 4],
            public_inputs: AttestationProofPublicInputs {
                entangled_id: [0x42u8; 32],
                binary_hash: [0x11u8; 32],
                public_key_hash: [0x22u8; 32],
                proof_timestamp: 1700000000,
            },
            vkey_hash: [0x33u8; 32],
            proof_type: ProofType::Mock,
        }
    }

    #[test]
    fn test_cache_save_and_load() {
        let temp_dir = TempDir::new().expect("tempdir");
        let cache = ProofCache::new(temp_dir.path().to_path_buf()).expect("cache");

        let proof = create_test_proof();
        let binary_hash = proof.public_inputs.binary_hash;
        let pk_hash = proof.public_inputs.public_key_hash;

        // Save
        cache.save(&proof, &pk_hash).expect("save");

        // Load
        let loaded = cache.load(&binary_hash, &pk_hash).expect("load");
        assert!(loaded.is_some());

        let loaded_proof = loaded.unwrap();
        assert_eq!(
            loaded_proof.public_inputs.entangled_id,
            proof.public_inputs.entangled_id
        );
    }

    #[test]
    fn test_cache_invalid_binary_hash() {
        let temp_dir = TempDir::new().expect("tempdir");
        let cache = ProofCache::new(temp_dir.path().to_path_buf()).expect("cache");

        let proof = create_test_proof();
        let pk_hash = proof.public_inputs.public_key_hash;

        // Save with one binary hash
        cache.save(&proof, &pk_hash).expect("save");

        // Try to load with different binary hash
        let different_hash = [0xFFu8; 32];
        let loaded = cache.load(&different_hash, &pk_hash).expect("load");
        assert!(loaded.is_none());
    }

    #[test]
    fn test_cache_invalid_key_hash() {
        let temp_dir = TempDir::new().expect("tempdir");
        let cache = ProofCache::new(temp_dir.path().to_path_buf()).expect("cache");

        let proof = create_test_proof();
        let binary_hash = proof.public_inputs.binary_hash;
        let pk_hash = proof.public_inputs.public_key_hash;

        // Save
        cache.save(&proof, &pk_hash).expect("save");

        // Try to load with different key hash
        let different_key = [0xEEu8; 32];
        let loaded = cache.load(&binary_hash, &different_key).expect("load");
        assert!(loaded.is_none());
    }

    #[test]
    fn test_cache_invalidate() {
        let temp_dir = TempDir::new().expect("tempdir");
        let cache = ProofCache::new(temp_dir.path().to_path_buf()).expect("cache");

        let proof = create_test_proof();
        let binary_hash = proof.public_inputs.binary_hash;
        let pk_hash = proof.public_inputs.public_key_hash;

        // Save and verify exists
        cache.save(&proof, &pk_hash).expect("save");
        assert!(cache.is_valid(&binary_hash, &pk_hash));

        // Invalidate
        cache.invalidate().expect("invalidate");
        assert!(!cache.is_valid(&binary_hash, &pk_hash));
    }

    #[test]
    fn test_cache_missing_returns_none() {
        let temp_dir = TempDir::new().expect("tempdir");
        let cache = ProofCache::new(temp_dir.path().to_path_buf()).expect("cache");

        let loaded = cache.load(&[0u8; 32], &[0u8; 32]).expect("load");
        assert!(loaded.is_none());
    }
}
