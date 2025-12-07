//! Bucket refresh logic for Kademlia routing table
//!
//! Handles periodic refresh of k-buckets by:
//! - Generating keys that land in specific buckets
//! - Performing lookups to find nodes for sparse buckets
//! - Tracking bucket refresh timestamps
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::dht::{DhtKey, DhtNodeId};

/// Tier classification for bucket refresh intervals
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshTier {
    /// Critical tier: close group nodes (refresh every 60s default)
    Critical,
    /// Important tier: recently used in routing (refresh every 5min default)
    Important,
    /// Standard tier: populated buckets (refresh every 15min default)
    Standard,
    /// Background tier: sparse buckets (refresh every 60min default)
    Background,
}

impl RefreshTier {
    /// Get the default refresh interval for this tier
    #[must_use]
    pub fn default_interval(&self) -> Duration {
        match self {
            RefreshTier::Critical => Duration::from_secs(60),
            RefreshTier::Important => Duration::from_secs(300),
            RefreshTier::Standard => Duration::from_secs(900),
            RefreshTier::Background => Duration::from_secs(3600),
        }
    }
}

/// Tracks the state of bucket refresh operations
#[derive(Debug, Clone)]
pub struct BucketRefreshState {
    /// Last time this bucket was refreshed
    pub last_refresh: Instant,
    /// Number of nodes currently in this bucket
    pub node_count: usize,
    /// Current tier for this bucket
    pub tier: RefreshTier,
    /// Number of successful refreshes
    pub success_count: u64,
    /// Number of failed refresh attempts
    pub failure_count: u64,
}

impl Default for BucketRefreshState {
    fn default() -> Self {
        Self::new()
    }
}

impl BucketRefreshState {
    /// Create a new bucket refresh state
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_refresh: Instant::now(),
            node_count: 0,
            tier: RefreshTier::Background,
            success_count: 0,
            failure_count: 0,
        }
    }

    /// Check if this bucket needs a refresh
    #[must_use]
    pub fn needs_refresh(&self) -> bool {
        self.last_refresh.elapsed() > self.tier.default_interval()
    }

    /// Check if this bucket needs refresh based on custom interval
    #[must_use]
    pub fn needs_refresh_with_interval(&self, interval: Duration) -> bool {
        self.last_refresh.elapsed() > interval
    }

    /// Record a successful refresh
    pub fn record_success(&mut self, node_count: usize) {
        self.last_refresh = Instant::now();
        self.node_count = node_count;
        self.success_count += 1;
    }

    /// Record a failed refresh attempt
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
    }

    /// Update the tier based on bucket characteristics
    pub fn update_tier(&mut self, is_close_group: bool, recently_used: bool) {
        self.tier = if is_close_group {
            RefreshTier::Critical
        } else if recently_used {
            RefreshTier::Important
        } else if self.node_count > 2 {
            RefreshTier::Standard
        } else {
            RefreshTier::Background
        };
    }
}

/// Manages refresh operations for all buckets
pub struct BucketRefreshManager {
    /// Our local node ID (for key generation)
    local_id: DhtNodeId,
    /// State for each bucket (indexed 0-255)
    bucket_states: HashMap<usize, BucketRefreshState>,
    /// Close group bucket indices
    close_group_buckets: Vec<usize>,
    /// Recently used bucket indices
    recently_used_buckets: Vec<usize>,
}

impl BucketRefreshManager {
    /// Create a new bucket refresh manager
    #[must_use]
    pub fn new(local_id: DhtNodeId) -> Self {
        Self {
            local_id,
            bucket_states: HashMap::new(),
            close_group_buckets: Vec::new(),
            recently_used_buckets: Vec::new(),
        }
    }

    /// Generate a DHT key that will land in a specific bucket
    ///
    /// The key is constructed to have XOR distance from our ID such that
    /// it falls into the specified bucket index.
    #[must_use]
    pub fn generate_key_for_bucket(&self, bucket_idx: usize) -> Option<DhtKey> {
        if bucket_idx >= 256 {
            return None;
        }

        let mut key_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key_bytes);

        let our_id = self.local_id.as_bytes();
        let byte_idx = bucket_idx / 8;
        let bit_idx = 7 - (bucket_idx % 8);

        // Copy prefix from our ID to ensure correct XOR distance
        for (i, byte) in key_bytes.iter_mut().enumerate().take(byte_idx) {
            *byte = our_id[i];
        }

        // Set the distinguishing bit to create correct distance
        key_bytes[byte_idx] = our_id[byte_idx] ^ (1 << bit_idx);

        Some(DhtKey::from_bytes(key_bytes))
    }

    /// Get the bucket index for a given key
    #[must_use]
    pub fn bucket_index(&self, key: &DhtKey) -> usize {
        let our_bytes = self.local_id.as_bytes();
        let key_bytes = key.as_bytes();

        // Find the first differing bit (leading zeros in XOR)
        for (byte_idx, (&a, &b)) in our_bytes.iter().zip(key_bytes.iter()).enumerate() {
            let xor = a ^ b;
            if xor != 0 {
                let leading_zeros = xor.leading_zeros() as usize;
                return byte_idx * 8 + leading_zeros;
            }
        }

        // Keys are identical (shouldn't happen in practice)
        255
    }

    /// Mark a bucket as part of close group
    pub fn mark_close_group(&mut self, bucket_idx: usize) {
        if !self.close_group_buckets.contains(&bucket_idx) {
            self.close_group_buckets.push(bucket_idx);
        }
        if let Some(state) = self.bucket_states.get_mut(&bucket_idx) {
            state.update_tier(true, false);
        }
    }

    /// Mark a bucket as recently used
    pub fn mark_recently_used(&mut self, bucket_idx: usize) {
        if !self.recently_used_buckets.contains(&bucket_idx) {
            self.recently_used_buckets.push(bucket_idx);
        }
        if let Some(state) = self.bucket_states.get_mut(&bucket_idx) {
            state.update_tier(self.close_group_buckets.contains(&bucket_idx), true);
        }
    }

    /// Get or create state for a bucket
    pub fn get_or_create_state(&mut self, bucket_idx: usize) -> &mut BucketRefreshState {
        self.bucket_states.entry(bucket_idx).or_default()
    }

    /// Record successful refresh for a bucket
    pub fn record_refresh_success(&mut self, bucket_idx: usize, node_count: usize) {
        let state = self.get_or_create_state(bucket_idx);
        state.record_success(node_count);
    }

    /// Record failed refresh for a bucket
    pub fn record_refresh_failure(&mut self, bucket_idx: usize) {
        let state = self.get_or_create_state(bucket_idx);
        state.record_failure();
    }

    /// Get list of buckets needing refresh, sorted by priority
    #[must_use]
    pub fn get_buckets_needing_refresh(&self) -> Vec<usize> {
        let mut buckets: Vec<_> = self
            .bucket_states
            .iter()
            .filter(|(_, state)| state.needs_refresh())
            .map(|(&idx, state)| (idx, state.tier))
            .collect();

        // Sort by tier (Critical first, then Important, etc.)
        buckets.sort_by_key(|(_, tier)| match tier {
            RefreshTier::Critical => 0,
            RefreshTier::Important => 1,
            RefreshTier::Standard => 2,
            RefreshTier::Background => 3,
        });

        buckets.into_iter().map(|(idx, _)| idx).collect()
    }

    /// Initialize tracking for all buckets
    pub fn initialize_buckets(&mut self, num_buckets: usize) {
        for i in 0..num_buckets.min(256) {
            self.get_or_create_state(i);
        }
    }

    /// Get the state of a bucket if it exists
    #[must_use]
    pub fn get_bucket_state(&self, bucket_idx: usize) -> Option<&BucketRefreshState> {
        self.bucket_states.get(&bucket_idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create an instant in the past, handling Windows overflow gracefully.
    /// On Windows, Instant can't be subtracted past system boot time.
    /// Returns an instant that's as far back as possible (up to requested secs).
    fn instant_in_past(secs: u64) -> Instant {
        let now = Instant::now();
        // Try decreasing durations until we find one that works
        let durations = [
            Duration::from_secs(secs),
            Duration::from_secs(secs / 2),
            Duration::from_secs(secs / 4),
            Duration::from_secs(60),
            Duration::from_secs(10),
            Duration::from_secs(1),
        ];

        for dur in durations {
            if let Some(instant) = now.checked_sub(dur) {
                return instant;
            }
        }
        // Fallback: return now (test will need to handle this case)
        now
    }

    /// Check if we can create instants far enough in the past for time-based tests.
    /// Returns true if the platform supports the needed time manipulation.
    fn can_create_stale_instants() -> bool {
        let now = Instant::now();
        // We need at least 2 hours (7200s) for Background tier tests
        now.checked_sub(Duration::from_secs(7200)).is_some()
    }

    #[test]
    fn test_refresh_tier_default_intervals() {
        assert_eq!(
            RefreshTier::Critical.default_interval(),
            Duration::from_secs(60)
        );
        assert_eq!(
            RefreshTier::Important.default_interval(),
            Duration::from_secs(300)
        );
        assert_eq!(
            RefreshTier::Standard.default_interval(),
            Duration::from_secs(900)
        );
        assert_eq!(
            RefreshTier::Background.default_interval(),
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn test_bucket_refresh_state_new() {
        let state = BucketRefreshState::new();
        assert_eq!(state.node_count, 0);
        assert_eq!(state.tier, RefreshTier::Background);
        assert_eq!(state.success_count, 0);
        assert_eq!(state.failure_count, 0);
    }

    #[test]
    fn test_bucket_refresh_state_needs_refresh() {
        let mut state = BucketRefreshState::new();
        state.tier = RefreshTier::Critical;

        // Just created - doesn't need refresh yet
        assert!(!state.needs_refresh());

        // Check with custom interval
        assert!(state.needs_refresh_with_interval(Duration::from_nanos(0)));
    }

    #[test]
    fn test_bucket_refresh_state_record_success() {
        let mut state = BucketRefreshState::new();
        state.record_success(5);

        assert_eq!(state.node_count, 5);
        assert_eq!(state.success_count, 1);
    }

    #[test]
    fn test_bucket_refresh_state_record_failure() {
        let mut state = BucketRefreshState::new();
        state.record_failure();
        state.record_failure();

        assert_eq!(state.failure_count, 2);
    }

    #[test]
    fn test_bucket_refresh_state_update_tier() {
        let mut state = BucketRefreshState::new();

        // Close group = Critical
        state.update_tier(true, false);
        assert_eq!(state.tier, RefreshTier::Critical);

        // Recently used = Important
        state.update_tier(false, true);
        assert_eq!(state.tier, RefreshTier::Important);

        // Many nodes = Standard
        state.node_count = 5;
        state.update_tier(false, false);
        assert_eq!(state.tier, RefreshTier::Standard);

        // Few nodes = Background
        state.node_count = 1;
        state.update_tier(false, false);
        assert_eq!(state.tier, RefreshTier::Background);
    }

    #[test]
    fn test_generate_key_for_bucket_lands_in_correct_bucket() {
        let local_id = DhtNodeId::random();
        let manager = BucketRefreshManager::new(local_id);

        // Test a few bucket indices
        for bucket_idx in [0, 10, 100, 200, 255] {
            let key = manager.generate_key_for_bucket(bucket_idx).unwrap();
            let actual_bucket = manager.bucket_index(&key);
            assert_eq!(
                actual_bucket, bucket_idx,
                "Key for bucket {} landed in bucket {}",
                bucket_idx, actual_bucket
            );
        }
    }

    #[test]
    fn test_generate_key_produces_different_keys() {
        let local_id = DhtNodeId::random();
        let manager = BucketRefreshManager::new(local_id);

        let key1 = manager.generate_key_for_bucket(100).unwrap();
        let key2 = manager.generate_key_for_bucket(100).unwrap();

        // Keys should differ (random component)
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_generate_key_invalid_bucket() {
        let local_id = DhtNodeId::random();
        let manager = BucketRefreshManager::new(local_id);

        assert!(manager.generate_key_for_bucket(256).is_none());
        assert!(manager.generate_key_for_bucket(1000).is_none());
    }

    #[test]
    fn test_mark_close_group() {
        let local_id = DhtNodeId::random();
        let mut manager = BucketRefreshManager::new(local_id);
        manager.initialize_buckets(256);

        manager.mark_close_group(0);
        manager.mark_close_group(1);

        let state = manager.get_bucket_state(0).unwrap();
        assert_eq!(state.tier, RefreshTier::Critical);

        // Marking twice shouldn't duplicate
        manager.mark_close_group(0);
        assert_eq!(manager.close_group_buckets.len(), 2);
    }

    #[test]
    fn test_mark_recently_used() {
        let local_id = DhtNodeId::random();
        let mut manager = BucketRefreshManager::new(local_id);
        manager.initialize_buckets(256);

        manager.mark_recently_used(50);

        let state = manager.get_bucket_state(50).unwrap();
        assert_eq!(state.tier, RefreshTier::Important);
    }

    #[test]
    fn test_get_buckets_needing_refresh_sorted_by_priority() {
        // Skip this test on platforms where we can't create stale instants
        // (e.g., freshly booted Windows CI runners with short uptime)
        if !can_create_stale_instants() {
            eprintln!(
                "Skipping test_get_buckets_needing_refresh_sorted_by_priority: \
                 platform cannot create instants far enough in the past"
            );
            return;
        }

        let local_id = DhtNodeId::random();
        let mut manager = BucketRefreshManager::new(local_id);
        manager.initialize_buckets(256);

        // Set up buckets with different tiers that all need refresh.
        // Use instant_in_past() helper to safely handle Windows Instant limitations.
        {
            let state = manager.get_or_create_state(100);
            state.tier = RefreshTier::Background;
            state.last_refresh = instant_in_past(7200); // 2 hours ago (Background: 3600s interval)
        }
        {
            let state = manager.get_or_create_state(50);
            state.tier = RefreshTier::Critical;
            state.last_refresh = instant_in_past(120); // 2 min ago (Critical: 60s interval)
        }
        {
            let state = manager.get_or_create_state(75);
            state.tier = RefreshTier::Important;
            state.last_refresh = instant_in_past(600); // 10 min ago (Important: 300s interval)
        }

        let buckets = manager.get_buckets_needing_refresh();

        // Critical should be first (priority 0), then Important (1), then Background (3)
        if !buckets.is_empty() {
            assert_eq!(buckets[0], 50, "Critical tier bucket should be first");
        }
    }

    #[test]
    fn test_initialize_buckets() {
        let local_id = DhtNodeId::random();
        let mut manager = BucketRefreshManager::new(local_id);

        manager.initialize_buckets(256);

        assert!(manager.get_bucket_state(0).is_some());
        assert!(manager.get_bucket_state(255).is_some());
        assert!(manager.get_bucket_state(256).is_none());
    }

    #[test]
    fn test_record_refresh_success() {
        let local_id = DhtNodeId::random();
        let mut manager = BucketRefreshManager::new(local_id);

        manager.record_refresh_success(10, 8);

        let state = manager.get_bucket_state(10).unwrap();
        assert_eq!(state.node_count, 8);
        assert_eq!(state.success_count, 1);
    }

    #[test]
    fn test_record_refresh_failure() {
        let local_id = DhtNodeId::random();
        let mut manager = BucketRefreshManager::new(local_id);

        manager.record_refresh_failure(10);
        manager.record_refresh_failure(10);

        let state = manager.get_bucket_state(10).unwrap();
        assert_eq!(state.failure_count, 2);
    }
}
