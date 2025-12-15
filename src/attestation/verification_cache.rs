// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! In-memory verification result cache (Phase 6B: Performance Optimization).
//!
//! This module provides caching for attestation proof verification results
//! to avoid redundant cryptographic verification operations.
//!
//! ## Features
//!
//! - **LRU eviction**: Automatically evicts least-recently-used entries
//! - **TTL expiration**: Cached results expire after configurable time
//! - **Thread-safe**: Uses `RwLock` for concurrent access
//! - **Metrics**: Tracks hit rate for monitoring
//!
//! ## Cache Key
//!
//! Verification results are keyed by:
//! - Peer's EntangledId (32 bytes)
//! - Proof hash (32 bytes) - BLAKE3 of proof bytes
//!
//! ## Example
//!
//! ```rust,ignore
//! use saorsa_core::attestation::verification_cache::{VerificationCache, VerificationCacheConfig};
//!
//! let cache = VerificationCache::new(VerificationCacheConfig::default());
//!
//! // Check cache before verifying
//! if let Some(result) = cache.get(&peer_id, &proof_hash) {
//!     return result;
//! }
//!
//! // Verify and cache result
//! let result = verifier.verify(&proof, &expected_id, current_time);
//! cache.insert(&peer_id, &proof_hash, result.clone());
//! ```

use super::AttestationProofResult;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Configuration for the verification cache.
#[derive(Debug, Clone)]
pub struct VerificationCacheConfig {
    /// Maximum number of entries in the cache.
    pub max_entries: usize,

    /// Time-to-live for cached entries.
    pub ttl: Duration,

    /// Whether to track detailed metrics.
    pub enable_metrics: bool,
}

impl Default for VerificationCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            ttl: Duration::from_secs(300), // 5 minutes
            enable_metrics: true,
        }
    }
}

impl VerificationCacheConfig {
    /// Create a high-performance config for production.
    #[must_use]
    pub fn production() -> Self {
        Self {
            max_entries: 50_000,
            ttl: Duration::from_secs(600), // 10 minutes
            enable_metrics: true,
        }
    }

    /// Create a minimal config for testing.
    #[must_use]
    pub fn testing() -> Self {
        Self {
            max_entries: 100,
            ttl: Duration::from_secs(60), // 1 minute
            enable_metrics: true,
        }
    }
}

/// Cache key combining peer ID and proof hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CacheKey {
    peer_id: [u8; 32],
    proof_hash: [u8; 32],
}

impl CacheKey {
    fn new(peer_id: &[u8; 32], proof_hash: &[u8; 32]) -> Self {
        Self {
            peer_id: *peer_id,
            proof_hash: *proof_hash,
        }
    }
}

/// Cached verification entry.
#[derive(Debug, Clone)]
struct CacheEntry {
    result: AttestationProofResult,
    inserted_at: Instant,
    last_accessed: Instant,
}

impl CacheEntry {
    fn new(result: AttestationProofResult) -> Self {
        let now = Instant::now();
        Self {
            result,
            inserted_at: now,
            last_accessed: now,
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.inserted_at.elapsed() > ttl
    }

    fn touch(&mut self) {
        self.last_accessed = Instant::now();
    }
}

/// Cache metrics for monitoring.
#[derive(Debug, Clone, Default)]
pub struct VerificationCacheMetrics {
    /// Total cache hits.
    pub hits: u64,

    /// Total cache misses.
    pub misses: u64,

    /// Total insertions.
    pub insertions: u64,

    /// Total evictions (LRU or TTL).
    pub evictions: u64,

    /// Current entry count.
    pub current_entries: usize,
}

impl VerificationCacheMetrics {
    /// Calculate hit rate as a percentage.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

/// Thread-safe in-memory cache for verification results.
#[derive(Debug)]
pub struct VerificationCache {
    entries: RwLock<HashMap<CacheKey, CacheEntry>>,
    config: VerificationCacheConfig,
    metrics: RwLock<VerificationCacheMetrics>,
}

impl VerificationCache {
    /// Create a new verification cache with the given configuration.
    #[must_use]
    pub fn new(config: VerificationCacheConfig) -> Self {
        Self {
            entries: RwLock::new(HashMap::with_capacity(config.max_entries)),
            config,
            metrics: RwLock::new(VerificationCacheMetrics::default()),
        }
    }

    /// Record a cache hit in metrics.
    fn record_hit(&self) {
        if !self.config.enable_metrics {
            return;
        }
        if let Ok(mut metrics) = self.metrics.write() {
            metrics.hits += 1;
        }
    }

    /// Record a cache miss in metrics.
    fn record_miss(&self) {
        if !self.config.enable_metrics {
            return;
        }
        if let Ok(mut metrics) = self.metrics.write() {
            metrics.misses += 1;
        }
    }

    /// Record an insertion in metrics.
    fn record_insertion(&self, current_entries: usize) {
        if !self.config.enable_metrics {
            return;
        }
        if let Ok(mut metrics) = self.metrics.write() {
            metrics.insertions += 1;
            metrics.current_entries = current_entries;
        }
    }

    /// Record evictions in metrics.
    fn record_evictions(&self, count: usize, current_entries: usize) {
        if !self.config.enable_metrics || count == 0 {
            return;
        }
        if let Ok(mut metrics) = self.metrics.write() {
            metrics.evictions += count as u64;
            metrics.current_entries = current_entries;
        }
    }

    /// Update current entry count in metrics.
    fn update_entry_count(&self, current_entries: usize) {
        if !self.config.enable_metrics {
            return;
        }
        if let Ok(mut metrics) = self.metrics.write() {
            metrics.current_entries = current_entries;
        }
    }

    /// Get a cached verification result.
    ///
    /// Returns `Some(result)` if found and not expired, `None` otherwise.
    /// Note: This always uses a write lock to update LRU access times.
    pub fn get(&self, peer_id: &[u8; 32], proof_hash: &[u8; 32]) -> Option<AttestationProofResult> {
        let key = CacheKey::new(peer_id, proof_hash);

        let Ok(mut entries) = self.entries.write() else {
            self.record_miss();
            return None;
        };

        let Some(entry) = entries.get_mut(&key) else {
            // Release lock before recording miss to avoid potential deadlock
            drop(entries);
            self.record_miss();
            return None;
        };

        if entry.is_expired(self.config.ttl) {
            // Entry expired, remove it
            entries.remove(&key);
            let len = entries.len();
            drop(entries);
            self.record_evictions(1, len);
            self.record_miss();
            return None;
        }

        // Update LRU access time
        entry.touch();
        let result = entry.result.clone();
        drop(entries);
        self.record_hit();
        Some(result)
    }

    /// Insert a verification result into the cache.
    pub fn insert(
        &self,
        peer_id: &[u8; 32],
        proof_hash: &[u8; 32],
        result: AttestationProofResult,
    ) {
        let key = CacheKey::new(peer_id, proof_hash);
        let entry = CacheEntry::new(result);

        let Ok(mut entries) = self.entries.write() else {
            return;
        };

        // Check if we need to evict entries
        if entries.len() >= self.config.max_entries {
            self.evict_lru(&mut entries);
        }

        entries.insert(key, entry);
        self.record_insertion(entries.len());
    }

    /// Evict least-recently-used entries to make room.
    fn evict_lru(&self, entries: &mut HashMap<CacheKey, CacheEntry>) {
        // First, remove all expired entries
        let ttl = self.config.ttl;
        let expired_keys: Vec<_> = entries
            .iter()
            .filter(|(_, e)| e.is_expired(ttl))
            .map(|(k, _)| *k)
            .collect();

        let expired_count = expired_keys.len();
        for key in expired_keys {
            entries.remove(&key);
        }

        // If still over capacity, remove oldest accessed entries
        let target_size = self.config.max_entries * 90 / 100; // Evict to 90% capacity
        if entries.len() > target_size {
            let mut sorted: Vec<_> = entries.iter().collect();
            sorted.sort_by_key(|(_, e)| e.last_accessed);

            let to_remove = entries.len() - target_size;
            let keys_to_remove: Vec<_> = sorted.iter().take(to_remove).map(|(k, _)| **k).collect();

            for key in &keys_to_remove {
                entries.remove(key);
            }

            self.record_evictions(expired_count + keys_to_remove.len(), entries.len());
        } else {
            self.record_evictions(expired_count, entries.len());
        }
    }

    /// Remove a specific entry from the cache.
    ///
    /// Useful when a peer's attestation becomes invalid.
    pub fn invalidate(&self, peer_id: &[u8; 32], proof_hash: &[u8; 32]) {
        let key = CacheKey::new(peer_id, proof_hash);
        if let Ok(mut entries) = self.entries.write() {
            entries.remove(&key);
            self.update_entry_count(entries.len());
        }
    }

    /// Remove all entries for a specific peer.
    ///
    /// Useful when a peer is blacklisted or disconnected.
    pub fn invalidate_peer(&self, peer_id: &[u8; 32]) {
        if let Ok(mut entries) = self.entries.write() {
            let keys_to_remove: Vec<_> = entries
                .keys()
                .filter(|k| k.peer_id == *peer_id)
                .copied()
                .collect();

            let count = keys_to_remove.len();
            for key in keys_to_remove {
                entries.remove(&key);
            }

            self.record_evictions(count, entries.len());
        }
    }

    /// Clear all cached entries.
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            let count = entries.len();
            entries.clear();
            self.record_evictions(count, 0);
        }
    }

    /// Get current cache metrics.
    #[must_use]
    pub fn metrics(&self) -> VerificationCacheMetrics {
        self.metrics.read().map(|m| m.clone()).unwrap_or_default()
    }

    /// Get current entry count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().map(|e| e.len()).unwrap_or(0)
    }

    /// Check if cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Compute proof hash from proof bytes.
    ///
    /// Use this to generate the `proof_hash` parameter.
    #[must_use]
    pub fn hash_proof(proof_bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(proof_bytes).as_bytes()
    }
}

impl Default for VerificationCache {
    fn default() -> Self {
        Self::new(VerificationCacheConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_insert_and_get() {
        let cache = VerificationCache::new(VerificationCacheConfig::testing());
        let peer_id = [0x42u8; 32];
        let proof_hash = [0x11u8; 32];

        // Should be empty initially
        assert!(cache.get(&peer_id, &proof_hash).is_none());

        // Insert
        cache.insert(&peer_id, &proof_hash, AttestationProofResult::Valid);

        // Should find it
        let result = cache.get(&peer_id, &proof_hash);
        assert_eq!(result, Some(AttestationProofResult::Valid));
    }

    #[test]
    fn test_cache_different_keys() {
        let cache = VerificationCache::new(VerificationCacheConfig::testing());
        let peer_id1 = [0x42u8; 32];
        let peer_id2 = [0x43u8; 32];
        let proof_hash = [0x11u8; 32];

        cache.insert(&peer_id1, &proof_hash, AttestationProofResult::Valid);
        cache.insert(&peer_id2, &proof_hash, AttestationProofResult::IdMismatch);

        assert_eq!(
            cache.get(&peer_id1, &proof_hash),
            Some(AttestationProofResult::Valid)
        );
        assert_eq!(
            cache.get(&peer_id2, &proof_hash),
            Some(AttestationProofResult::IdMismatch)
        );
    }

    #[test]
    fn test_cache_invalidate() {
        let cache = VerificationCache::new(VerificationCacheConfig::testing());
        let peer_id = [0x42u8; 32];
        let proof_hash = [0x11u8; 32];

        cache.insert(&peer_id, &proof_hash, AttestationProofResult::Valid);
        assert!(cache.get(&peer_id, &proof_hash).is_some());

        cache.invalidate(&peer_id, &proof_hash);
        assert!(cache.get(&peer_id, &proof_hash).is_none());
    }

    #[test]
    fn test_cache_invalidate_peer() {
        let cache = VerificationCache::new(VerificationCacheConfig::testing());
        let peer_id = [0x42u8; 32];
        let proof_hash1 = [0x11u8; 32];
        let proof_hash2 = [0x22u8; 32];

        cache.insert(&peer_id, &proof_hash1, AttestationProofResult::Valid);
        cache.insert(&peer_id, &proof_hash2, AttestationProofResult::Valid);
        assert_eq!(cache.len(), 2);

        cache.invalidate_peer(&peer_id);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_ttl_expiration() {
        let config = VerificationCacheConfig {
            max_entries: 100,
            ttl: Duration::from_millis(50), // Very short TTL for testing
            enable_metrics: true,
        };
        let cache = VerificationCache::new(config);
        let peer_id = [0x42u8; 32];
        let proof_hash = [0x11u8; 32];

        cache.insert(&peer_id, &proof_hash, AttestationProofResult::Valid);
        assert!(cache.get(&peer_id, &proof_hash).is_some());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(60));

        // Should be expired now
        assert!(cache.get(&peer_id, &proof_hash).is_none());
    }

    #[test]
    fn test_cache_lru_eviction() {
        let config = VerificationCacheConfig {
            max_entries: 3,
            ttl: Duration::from_secs(300),
            enable_metrics: true,
        };
        let cache = VerificationCache::new(config);

        // Fill cache
        for i in 0..3 {
            let peer_id = [i as u8; 32];
            cache.insert(&peer_id, &[0u8; 32], AttestationProofResult::Valid);
        }
        assert_eq!(cache.len(), 3);

        // Access first entry to make it recently used
        let _ = cache.get(&[0u8; 32], &[0u8; 32]);

        // Add one more entry - should trigger eviction
        let new_peer = [10u8; 32];
        cache.insert(&new_peer, &[0u8; 32], AttestationProofResult::Valid);

        // First entry should still be there (recently accessed)
        assert!(cache.get(&[0u8; 32], &[0u8; 32]).is_some());
        // New entry should be there
        assert!(cache.get(&new_peer, &[0u8; 32]).is_some());
    }

    #[test]
    fn test_cache_metrics() {
        let cache = VerificationCache::new(VerificationCacheConfig::testing());
        let peer_id = [0x42u8; 32];
        let proof_hash = [0x11u8; 32];

        // Miss
        let _ = cache.get(&peer_id, &proof_hash);

        // Insert
        cache.insert(&peer_id, &proof_hash, AttestationProofResult::Valid);

        // Hit
        let _ = cache.get(&peer_id, &proof_hash);
        let _ = cache.get(&peer_id, &proof_hash);

        let metrics = cache.metrics();
        assert_eq!(metrics.hits, 2);
        assert_eq!(metrics.misses, 1);
        assert_eq!(metrics.insertions, 1);
        assert!(metrics.hit_rate() > 60.0); // ~66.7%
    }

    #[test]
    fn test_cache_clear() {
        let cache = VerificationCache::new(VerificationCacheConfig::testing());

        for i in 0..5 {
            let peer_id = [i as u8; 32];
            cache.insert(&peer_id, &[0u8; 32], AttestationProofResult::Valid);
        }
        assert_eq!(cache.len(), 5);

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_hash_proof() {
        let proof_bytes = vec![1, 2, 3, 4, 5];
        let hash = VerificationCache::hash_proof(&proof_bytes);

        // Same input should produce same hash
        let hash2 = VerificationCache::hash_proof(&proof_bytes);
        assert_eq!(hash, hash2);

        // Different input should produce different hash
        let hash3 = VerificationCache::hash_proof(&[6, 7, 8]);
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_production_config() {
        let config = VerificationCacheConfig::production();
        assert_eq!(config.max_entries, 50_000);
        assert_eq!(config.ttl, Duration::from_secs(600));
        assert!(config.enable_metrics);
    }
}
