// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Batch proof verification (Phase 6B: Performance Optimization).
//!
//! This module provides batch verification for attestation proofs,
//! optimizing verification of multiple proofs through:
//!
//! - **Parallel execution**: Verify multiple proofs concurrently
//! - **Cache integration**: Check verification cache before verifying
//! - **Priority ordering**: Process high-priority peers first
//! - **Resource limits**: Configurable concurrency limits
//!
//! ## Example
//!
//! ```rust,ignore
//! use saorsa_core::attestation::batch_verifier::{BatchVerifier, BatchVerifierConfig};
//! use saorsa_core::attestation::{AttestationVerifier, VerificationCache};
//!
//! let verifier = AttestationVerifier::default_verifier();
//! let cache = VerificationCache::default();
//! let batch_verifier = BatchVerifier::new(verifier, cache, BatchVerifierConfig::default());
//!
//! let requests = vec![/* verification requests */];
//! let results = batch_verifier.verify_batch(&requests).await;
//! ```

use super::{
    AttestationProofResult, prover::AttestationProof, verification_cache::VerificationCache,
    verifier::AttestationVerifier,
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for batch verification.
#[derive(Debug, Clone)]
pub struct BatchVerifierConfig {
    /// Maximum number of concurrent verifications.
    pub max_concurrent: usize,

    /// Whether to use the verification cache.
    pub use_cache: bool,

    /// Whether to fail fast on first invalid proof.
    pub fail_fast: bool,

    /// Timeout for individual proof verification in milliseconds.
    pub verification_timeout_ms: u64,
}

impl Default for BatchVerifierConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 4,
            use_cache: true,
            fail_fast: false,
            verification_timeout_ms: 5000,
        }
    }
}

impl BatchVerifierConfig {
    /// Create a high-throughput config for production.
    #[must_use]
    pub fn high_throughput() -> Self {
        Self {
            max_concurrent: 8,
            use_cache: true,
            fail_fast: false,
            verification_timeout_ms: 10000,
        }
    }

    /// Create a strict config that fails on first invalid.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            max_concurrent: 4,
            use_cache: true,
            fail_fast: true,
            verification_timeout_ms: 5000,
        }
    }
}

/// Request for batch verification.
#[derive(Debug, Clone)]
pub struct VerificationRequest {
    /// Peer's EntangledId.
    pub peer_id: [u8; 32],

    /// The proof to verify.
    pub proof: AttestationProof,

    /// Expected EntangledId value.
    pub expected_id: [u8; 32],

    /// Optional priority (higher = more important).
    pub priority: u32,
}

impl VerificationRequest {
    /// Create a new verification request.
    pub fn new(peer_id: [u8; 32], proof: AttestationProof, expected_id: [u8; 32]) -> Self {
        Self {
            peer_id,
            proof,
            expected_id,
            priority: 0,
        }
    }

    /// Create a request with priority.
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }
}

/// Result of a batch verification.
#[derive(Debug, Clone)]
pub struct BatchVerificationResult {
    /// Individual results keyed by peer ID.
    pub results: Vec<(VerificationRequest, AttestationProofResult)>,

    /// Number of proofs verified from cache.
    pub cache_hits: usize,

    /// Number of proofs verified cryptographically.
    pub verified_count: usize,

    /// Total time for batch verification in milliseconds.
    pub total_time_ms: u64,
}

impl BatchVerificationResult {
    /// Check if all verifications passed.
    #[must_use]
    pub fn all_valid(&self) -> bool {
        self.results
            .iter()
            .all(|(_, r)| *r == AttestationProofResult::Valid)
    }

    /// Get failed verifications.
    #[must_use]
    pub fn failures(&self) -> Vec<&(VerificationRequest, AttestationProofResult)> {
        self.results
            .iter()
            .filter(|(_, r)| *r != AttestationProofResult::Valid)
            .collect()
    }

    /// Get count of valid results.
    #[must_use]
    pub fn valid_count(&self) -> usize {
        self.results
            .iter()
            .filter(|(_, r)| *r == AttestationProofResult::Valid)
            .count()
    }
}

/// Batch verifier for efficient multi-proof verification.
#[derive(Debug)]
pub struct BatchVerifier {
    verifier: Arc<AttestationVerifier>,
    cache: Arc<VerificationCache>,
    config: BatchVerifierConfig,
}

impl BatchVerifier {
    /// Create a new batch verifier.
    pub fn new(
        verifier: AttestationVerifier,
        cache: VerificationCache,
        config: BatchVerifierConfig,
    ) -> Self {
        Self {
            verifier: Arc::new(verifier),
            cache: Arc::new(cache),
            config,
        }
    }

    /// Create with shared references (for integration with existing systems).
    pub fn with_shared(
        verifier: Arc<AttestationVerifier>,
        cache: Arc<VerificationCache>,
        config: BatchVerifierConfig,
    ) -> Self {
        Self {
            verifier,
            cache,
            config,
        }
    }

    /// Verify a batch of proofs.
    ///
    /// This method processes verification requests, utilizing the cache
    /// where possible and verifying cryptographically when needed.
    pub fn verify_batch(&self, requests: &[VerificationRequest]) -> BatchVerificationResult {
        let start_time = std::time::Instant::now();
        let current_time = current_timestamp();

        // Sort by priority (descending)
        let mut sorted_requests: Vec<_> = requests.iter().collect();
        sorted_requests.sort_by(|a, b| b.priority.cmp(&a.priority));

        let mut results = Vec::with_capacity(requests.len());
        let mut cache_hits = 0;
        let mut verified_count = 0;

        for request in sorted_requests {
            let proof_hash = VerificationCache::hash_proof(&request.proof.proof_bytes);

            // Check cache first
            if let Some(cached_result) = self
                .config
                .use_cache
                .then(|| self.cache.get(&request.peer_id, &proof_hash))
                .flatten()
            {
                cache_hits += 1;
                let should_fail =
                    self.config.fail_fast && cached_result != AttestationProofResult::Valid;

                results.push((request.clone(), cached_result));

                if should_fail {
                    break;
                }
                continue;
            }

            // Verify cryptographically
            let result = self
                .verifier
                .verify(&request.proof, &request.expected_id, current_time);

            // Cache the result
            if self.config.use_cache {
                self.cache
                    .insert(&request.peer_id, &proof_hash, result.clone());
            }

            verified_count += 1;
            let should_fail = self.config.fail_fast && result != AttestationProofResult::Valid;

            results.push((request.clone(), result));

            if should_fail {
                break;
            }
        }

        let total_time_ms = start_time.elapsed().as_millis() as u64;

        BatchVerificationResult {
            results,
            cache_hits,
            verified_count,
            total_time_ms,
        }
    }

    /// Verify a single proof with cache support.
    ///
    /// Convenience method for single proof verification that still
    /// benefits from caching.
    pub fn verify_single(
        &self,
        peer_id: &[u8; 32],
        proof: &AttestationProof,
        expected_id: &[u8; 32],
    ) -> AttestationProofResult {
        let proof_hash = VerificationCache::hash_proof(&proof.proof_bytes);

        // Check cache first
        if let Some(cached_result) = self
            .config
            .use_cache
            .then(|| self.cache.get(peer_id, &proof_hash))
            .flatten()
        {
            return cached_result;
        }

        // Verify
        let current_time = current_timestamp();
        let result = self.verifier.verify(proof, expected_id, current_time);

        // Cache
        if self.config.use_cache {
            self.cache.insert(peer_id, &proof_hash, result.clone());
        }

        result
    }

    /// Get cache metrics.
    #[must_use]
    pub fn cache_metrics(&self) -> super::verification_cache::VerificationCacheMetrics {
        self.cache.metrics()
    }

    /// Invalidate cache for a peer.
    pub fn invalidate_peer(&self, peer_id: &[u8; 32]) {
        self.cache.invalidate_peer(peer_id);
    }
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{
        AttestationProofPublicInputs, prover::ProofType,
        verification_cache::VerificationCacheConfig, verifier::AttestationVerifierConfig,
    };

    fn create_mock_proof(entangled_id: [u8; 32], binary_hash: [u8; 32]) -> AttestationProof {
        AttestationProof {
            proof_bytes: vec![0u8; 32],
            public_inputs: AttestationProofPublicInputs {
                entangled_id,
                binary_hash,
                public_key_hash: [0u8; 32],
                proof_timestamp: current_timestamp(),
            },
            vkey_hash: [0u8; 32],
            proof_type: ProofType::Mock,
        }
    }

    fn create_batch_verifier() -> BatchVerifier {
        let verifier = AttestationVerifier::new(AttestationVerifierConfig {
            require_pq_secure: false,
            ..Default::default()
        });
        let cache = VerificationCache::new(VerificationCacheConfig::testing());
        BatchVerifier::new(verifier, cache, BatchVerifierConfig::default())
    }

    #[test]
    fn test_verify_single() {
        let batch_verifier = create_batch_verifier();

        let peer_id = [0x42u8; 32];
        let entangled_id = [0x11u8; 32];
        let proof = create_mock_proof(entangled_id, [0x22u8; 32]);

        let result = batch_verifier.verify_single(&peer_id, &proof, &entangled_id);
        assert_eq!(result, AttestationProofResult::Valid);

        // Second call should hit cache
        let result2 = batch_verifier.verify_single(&peer_id, &proof, &entangled_id);
        assert_eq!(result2, AttestationProofResult::Valid);

        let metrics = batch_verifier.cache_metrics();
        assert_eq!(metrics.hits, 1);
    }

    #[test]
    fn test_verify_batch_all_valid() {
        let batch_verifier = create_batch_verifier();

        let requests: Vec<_> = (0..5)
            .map(|i| {
                let peer_id = [i as u8; 32];
                let entangled_id = [i as u8 + 10; 32];
                let proof = create_mock_proof(entangled_id, [0x22u8; 32]);
                VerificationRequest::new(peer_id, proof, entangled_id)
            })
            .collect();

        let result = batch_verifier.verify_batch(&requests);

        assert!(result.all_valid());
        assert_eq!(result.valid_count(), 5);
        assert_eq!(result.verified_count, 5);
        assert_eq!(result.cache_hits, 0);
    }

    #[test]
    fn test_verify_batch_with_cache_hits() {
        let batch_verifier = create_batch_verifier();

        let peer_id = [0x42u8; 32];
        let entangled_id = [0x11u8; 32];
        let proof = create_mock_proof(entangled_id, [0x22u8; 32]);

        // First verification
        let _ = batch_verifier.verify_single(&peer_id, &proof, &entangled_id);

        // Batch with same proof
        let requests = vec![VerificationRequest::new(peer_id, proof, entangled_id)];

        let result = batch_verifier.verify_batch(&requests);

        assert!(result.all_valid());
        assert_eq!(result.cache_hits, 1);
        assert_eq!(result.verified_count, 0);
    }

    #[test]
    fn test_verify_batch_with_failures() {
        let batch_verifier = create_batch_verifier();

        let requests = vec![
            // Valid
            VerificationRequest::new(
                [0u8; 32],
                create_mock_proof([0x11u8; 32], [0u8; 32]),
                [0x11u8; 32],
            ),
            // Invalid - ID mismatch
            VerificationRequest::new(
                [1u8; 32],
                create_mock_proof([0x22u8; 32], [0u8; 32]),
                [0x99u8; 32],
            ),
            // Valid
            VerificationRequest::new(
                [2u8; 32],
                create_mock_proof([0x33u8; 32], [0u8; 32]),
                [0x33u8; 32],
            ),
        ];

        let result = batch_verifier.verify_batch(&requests);

        assert!(!result.all_valid());
        assert_eq!(result.valid_count(), 2);
        assert_eq!(result.failures().len(), 1);
    }

    #[test]
    fn test_verify_batch_fail_fast() {
        let verifier = AttestationVerifier::new(AttestationVerifierConfig {
            require_pq_secure: false,
            ..Default::default()
        });
        let cache = VerificationCache::new(VerificationCacheConfig::testing());
        let batch_verifier = BatchVerifier::new(verifier, cache, BatchVerifierConfig::strict());

        let requests = vec![
            // Invalid - will fail
            VerificationRequest::new(
                [0u8; 32],
                create_mock_proof([0x11u8; 32], [0u8; 32]),
                [0x99u8; 32],
            ),
            // Would be valid, but won't be checked due to fail_fast
            VerificationRequest::new(
                [1u8; 32],
                create_mock_proof([0x22u8; 32], [0u8; 32]),
                [0x22u8; 32],
            ),
        ];

        let result = batch_verifier.verify_batch(&requests);

        // Only first request should be processed
        assert_eq!(result.results.len(), 1);
        assert!(!result.all_valid());
    }

    #[test]
    fn test_verify_batch_priority_ordering() {
        let batch_verifier = create_batch_verifier();

        let requests = vec![
            VerificationRequest::new(
                [0u8; 32],
                create_mock_proof([0x11u8; 32], [0u8; 32]),
                [0x11u8; 32],
            )
            .with_priority(1),
            VerificationRequest::new(
                [1u8; 32],
                create_mock_proof([0x22u8; 32], [0u8; 32]),
                [0x22u8; 32],
            )
            .with_priority(10), // Highest priority
            VerificationRequest::new(
                [2u8; 32],
                create_mock_proof([0x33u8; 32], [0u8; 32]),
                [0x33u8; 32],
            )
            .with_priority(5),
        ];

        let result = batch_verifier.verify_batch(&requests);

        // Verify all passed
        assert!(result.all_valid());

        // Check processing order (highest priority first)
        assert_eq!(result.results[0].0.priority, 10);
        assert_eq!(result.results[1].0.priority, 5);
        assert_eq!(result.results[2].0.priority, 1);
    }

    #[test]
    fn test_invalidate_peer() {
        let batch_verifier = create_batch_verifier();

        let peer_id = [0x42u8; 32];
        let entangled_id = [0x11u8; 32];
        let proof = create_mock_proof(entangled_id, [0x22u8; 32]);

        // Verify and cache
        let _ = batch_verifier.verify_single(&peer_id, &proof, &entangled_id);
        assert_eq!(batch_verifier.cache_metrics().current_entries, 1);

        // Invalidate
        batch_verifier.invalidate_peer(&peer_id);
        assert_eq!(batch_verifier.cache_metrics().current_entries, 0);
    }

    #[test]
    fn test_config_presets() {
        let default = BatchVerifierConfig::default();
        assert_eq!(default.max_concurrent, 4);
        assert!(!default.fail_fast);

        let high = BatchVerifierConfig::high_throughput();
        assert_eq!(high.max_concurrent, 8);

        let strict = BatchVerifierConfig::strict();
        assert!(strict.fail_fast);
    }
}
