// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Attestation blacklist for temporary bans (Phase 6: Hard Enforcement).
//!
//! This module provides a time-based blacklist for peers who fail attestation
//! verification. It implements exponential backoff for repeated failures to
//! prevent abuse while allowing legitimate nodes to recover.
//!
//! ## Features
//!
//! - Exponential backoff for repeated failures
//! - Automatic expiration of blacklist entries
//! - Configurable ban durations
//! - Thread-safe access via interior mutability
//!
//! ## Example
//!
//! ```rust,ignore
//! use saorsa_core::attestation::blacklist::{AttestationBlacklist, BlacklistConfig};
//!
//! let mut blacklist = AttestationBlacklist::new(BlacklistConfig::default());
//!
//! // Record a failure - peer gets blacklisted
//! let peer_id = [0x42u8; 32];
//! blacklist.record_failure(&peer_id, "Identity mismatch");
//!
//! // Check if peer is blacklisted
//! if let Some(entry) = blacklist.is_blacklisted(&peer_id) {
//!     println!("Peer blacklisted until {}", entry.expires_at);
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for the attestation blacklist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistConfig {
    /// Initial ban duration in seconds for first failure.
    pub initial_ban_duration_secs: u64,

    /// Maximum ban duration in seconds (cap for exponential backoff).
    pub max_ban_duration_secs: u64,

    /// Multiplier for exponential backoff (e.g., 2.0 doubles each time).
    pub ban_multiplier: f64,

    /// Maximum number of failed attempts before extended ban.
    pub max_failed_attempts: u32,

    /// Duration in seconds after which failure count resets if no new failures.
    pub failure_reset_secs: u64,
}

impl Default for BlacklistConfig {
    fn default() -> Self {
        Self {
            initial_ban_duration_secs: 60, // 1 minute initial ban
            max_ban_duration_secs: 3600,   // 1 hour max ban
            ban_multiplier: 2.0,           // Double each time
            max_failed_attempts: 5,        // Extended ban after 5 failures
            failure_reset_secs: 86400,     // Reset after 24 hours clean
        }
    }
}

impl BlacklistConfig {
    /// Create a strict configuration for production.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            initial_ban_duration_secs: 300, // 5 minute initial ban
            max_ban_duration_secs: 86400,   // 24 hour max ban
            ban_multiplier: 3.0,            // Triple each time
            max_failed_attempts: 3,         // Extended ban after 3 failures
            failure_reset_secs: 604800,     // Reset after 7 days clean
        }
    }

    /// Create a lenient configuration for development.
    #[must_use]
    pub fn lenient() -> Self {
        Self {
            initial_ban_duration_secs: 10, // 10 second initial ban
            max_ban_duration_secs: 300,    // 5 minute max ban
            ban_multiplier: 1.5,           // 1.5x each time
            max_failed_attempts: 10,       // Extended ban after 10 failures
            failure_reset_secs: 3600,      // Reset after 1 hour clean
        }
    }
}

/// Entry in the blacklist tracking a peer's ban status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistEntry {
    /// Unix timestamp when the ban expires.
    pub expires_at: u64,

    /// Number of failed attempts (for exponential backoff).
    pub failure_count: u32,

    /// Unix timestamp of last failure.
    pub last_failure_at: u64,

    /// Reason for the most recent ban.
    pub reason: String,

    /// History of failure reasons (limited to last 5).
    pub failure_history: Vec<FailureRecord>,
}

/// Record of a single failure event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureRecord {
    /// Unix timestamp of the failure.
    pub timestamp: u64,

    /// Reason for the failure.
    pub reason: String,
}

impl BlacklistEntry {
    /// Check if this entry has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        current_timestamp() >= self.expires_at
    }

    /// Get remaining ban time in seconds.
    #[must_use]
    pub fn remaining_secs(&self) -> u64 {
        let now = current_timestamp();
        self.expires_at.saturating_sub(now)
    }
}

/// Attestation blacklist for tracking and managing temporary bans.
#[derive(Debug)]
pub struct AttestationBlacklist {
    /// Blacklist entries keyed by peer EntangledId.
    entries: HashMap<[u8; 32], BlacklistEntry>,

    /// Configuration for ban durations.
    config: BlacklistConfig,
}

impl AttestationBlacklist {
    /// Create a new blacklist with the given configuration.
    #[must_use]
    pub fn new(config: BlacklistConfig) -> Self {
        Self {
            entries: HashMap::new(),
            config,
        }
    }

    /// Check if a peer is currently blacklisted.
    ///
    /// Returns the blacklist entry if the peer is banned and the ban hasn't expired.
    /// Returns None if the peer is not banned or the ban has expired.
    #[must_use]
    pub fn is_blacklisted(&self, peer_id: &[u8; 32]) -> Option<&BlacklistEntry> {
        self.entries
            .get(peer_id)
            .filter(|entry| !entry.is_expired())
    }

    /// Record a failure for a peer, potentially blacklisting them.
    ///
    /// Returns the new blacklist entry.
    pub fn record_failure(&mut self, peer_id: &[u8; 32], reason: &str) -> &BlacklistEntry {
        let now = current_timestamp();

        // Copy config values upfront to avoid borrow issues
        let failure_reset_secs = self.config.failure_reset_secs;
        let initial_ban_duration = self.config.initial_ban_duration_secs;
        let ban_multiplier = self.config.ban_multiplier;
        let max_ban_duration = self.config.max_ban_duration_secs;

        // Use entry API - handles both insert and update cases
        let entry = self
            .entries
            .entry(*peer_id)
            .or_insert_with(|| BlacklistEntry {
                expires_at: 0,
                failure_count: 0,
                last_failure_at: 0,
                reason: String::new(),
                failure_history: Vec::new(),
            });

        // Check if failure count should be reset (clean period elapsed)
        if entry.last_failure_at > 0
            && now.saturating_sub(entry.last_failure_at) > failure_reset_secs
        {
            entry.failure_count = 0;
            entry.failure_history.clear();
        }

        // Increment failure count
        entry.failure_count += 1;
        entry.last_failure_at = now;
        entry.reason = reason.to_string();

        // Add to history (keep last 5)
        entry.failure_history.push(FailureRecord {
            timestamp: now,
            reason: reason.to_string(),
        });
        if entry.failure_history.len() > 5 {
            entry.failure_history.remove(0);
        }

        // Calculate ban duration with exponential backoff (inline to avoid borrow issues)
        let ban_duration = calculate_ban_duration(
            entry.failure_count,
            initial_ban_duration,
            ban_multiplier,
            max_ban_duration,
        );
        entry.expires_at = now + ban_duration;

        tracing::warn!(
            peer_id = %hex::encode(&peer_id[..8]),
            failure_count = entry.failure_count,
            ban_duration_secs = ban_duration,
            reason = %reason,
            "Peer blacklisted due to attestation failure"
        );

        // Return immutable reference - entry was just modified so it must exist
        // SAFETY: We just modified the entry above, so it definitely exists
        #[allow(clippy::unwrap_used)]
        self.entries.get(peer_id).unwrap()
    }

    /// Remove expired entries from the blacklist.
    ///
    /// Returns the number of entries removed.
    pub fn cleanup_expired(&mut self) -> usize {
        let initial_len = self.entries.len();
        self.entries.retain(|_, entry| !entry.is_expired());
        initial_len - self.entries.len()
    }

    /// Manually unban a peer.
    ///
    /// Returns true if the peer was blacklisted, false otherwise.
    pub fn unban(&mut self, peer_id: &[u8; 32]) -> bool {
        self.entries.remove(peer_id).is_some()
    }

    /// Get the number of currently active bans.
    #[must_use]
    pub fn active_ban_count(&self) -> usize {
        self.entries.values().filter(|e| !e.is_expired()).count()
    }

    /// Get all currently blacklisted peer IDs.
    #[must_use]
    pub fn blacklisted_peers(&self) -> Vec<[u8; 32]> {
        self.entries
            .iter()
            .filter(|(_, entry)| !entry.is_expired())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get statistics about the blacklist.
    #[must_use]
    pub fn stats(&self) -> BlacklistStats {
        let now = current_timestamp();
        let active = self.entries.values().filter(|e| !e.is_expired()).count();
        let expired = self.entries.len() - active;

        let total_failures: u32 = self.entries.values().map(|e| e.failure_count).sum();

        let max_failures = self
            .entries
            .values()
            .map(|e| e.failure_count)
            .max()
            .unwrap_or(0);

        let longest_remaining = self
            .entries
            .values()
            .filter(|e| !e.is_expired())
            .map(|e| e.expires_at.saturating_sub(now))
            .max()
            .unwrap_or(0);

        BlacklistStats {
            active_bans: active,
            expired_entries: expired,
            total_failures,
            max_failures_single_peer: max_failures,
            longest_remaining_ban_secs: longest_remaining,
        }
    }
}

/// Statistics about the blacklist state.
#[derive(Debug, Clone, Default)]
pub struct BlacklistStats {
    /// Number of currently active bans.
    pub active_bans: usize,

    /// Number of expired entries not yet cleaned up.
    pub expired_entries: usize,

    /// Total failure count across all peers.
    pub total_failures: u32,

    /// Maximum failures for a single peer.
    pub max_failures_single_peer: u32,

    /// Longest remaining ban duration in seconds.
    pub longest_remaining_ban_secs: u64,
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Calculate ban duration with exponential backoff.
///
/// # Arguments
/// * `failure_count` - Number of failures for this peer
/// * `initial_duration` - Base ban duration in seconds
/// * `multiplier` - Exponential backoff multiplier
/// * `max_duration` - Maximum ban duration cap
fn calculate_ban_duration(
    failure_count: u32,
    initial_duration: u64,
    multiplier: f64,
    max_duration: u64,
) -> u64 {
    let base = initial_duration as f64;
    let exponent = failure_count.saturating_sub(1) as f64;
    let duration = base * multiplier.powf(exponent);
    let duration = duration.min(max_duration as f64);
    duration as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BlacklistConfig::default();
        assert_eq!(config.initial_ban_duration_secs, 60);
        assert_eq!(config.max_ban_duration_secs, 3600);
        assert_eq!(config.ban_multiplier, 2.0);
    }

    #[test]
    fn test_record_failure() {
        let mut blacklist = AttestationBlacklist::new(BlacklistConfig::default());
        let peer_id = [0x42u8; 32];

        // First failure
        let entry = blacklist.record_failure(&peer_id, "Test failure");
        assert_eq!(entry.failure_count, 1);
        assert!(!entry.is_expired());
        assert!(blacklist.is_blacklisted(&peer_id).is_some());
    }

    #[test]
    fn test_exponential_backoff() {
        let mut blacklist = AttestationBlacklist::new(BlacklistConfig::default());
        let peer_id = [0x42u8; 32];

        // Calculate expected durations
        // failure 1: 60s
        // failure 2: 60 * 2^1 = 120s
        // failure 3: 60 * 2^2 = 240s
        let durations = [60, 120, 240];

        for (i, expected) in durations.iter().enumerate() {
            let entry = blacklist.record_failure(&peer_id, "Test");
            let actual_duration = entry.expires_at - entry.last_failure_at;
            assert_eq!(
                actual_duration,
                *expected,
                "Failure {} expected {}s, got {}s",
                i + 1,
                expected,
                actual_duration
            );
        }
    }

    #[test]
    fn test_max_ban_duration() {
        let config = BlacklistConfig {
            initial_ban_duration_secs: 100,
            max_ban_duration_secs: 500,
            ban_multiplier: 10.0,
            ..Default::default()
        };
        let mut blacklist = AttestationBlacklist::new(config);
        let peer_id = [0x42u8; 32];

        // After several failures, duration should cap at max
        for _ in 0..10 {
            blacklist.record_failure(&peer_id, "Test");
        }

        let entry = blacklist.is_blacklisted(&peer_id).unwrap();
        let duration = entry.expires_at - entry.last_failure_at;
        assert_eq!(duration, 500); // Should be capped at max
    }

    #[test]
    fn test_unban() {
        let mut blacklist = AttestationBlacklist::new(BlacklistConfig::default());
        let peer_id = [0x42u8; 32];

        blacklist.record_failure(&peer_id, "Test");
        assert!(blacklist.is_blacklisted(&peer_id).is_some());

        assert!(blacklist.unban(&peer_id));
        assert!(blacklist.is_blacklisted(&peer_id).is_none());

        // Unban non-existent peer returns false
        assert!(!blacklist.unban(&peer_id));
    }

    #[test]
    fn test_not_blacklisted() {
        let blacklist = AttestationBlacklist::new(BlacklistConfig::default());
        let peer_id = [0x42u8; 32];

        assert!(blacklist.is_blacklisted(&peer_id).is_none());
    }

    #[test]
    fn test_stats() {
        let mut blacklist = AttestationBlacklist::new(BlacklistConfig::default());

        let stats = blacklist.stats();
        assert_eq!(stats.active_bans, 0);
        assert_eq!(stats.total_failures, 0);

        let peer1 = [0x01u8; 32];
        let peer2 = [0x02u8; 32];

        blacklist.record_failure(&peer1, "Test 1");
        blacklist.record_failure(&peer1, "Test 2");
        blacklist.record_failure(&peer2, "Test 3");

        let stats = blacklist.stats();
        assert_eq!(stats.active_bans, 2);
        assert_eq!(stats.total_failures, 3);
        assert_eq!(stats.max_failures_single_peer, 2);
    }

    #[test]
    fn test_failure_history() {
        let mut blacklist = AttestationBlacklist::new(BlacklistConfig::default());
        let peer_id = [0x42u8; 32];

        for i in 0..7 {
            blacklist.record_failure(&peer_id, &format!("Failure {}", i));
        }

        let entry = blacklist.is_blacklisted(&peer_id).unwrap();
        assert_eq!(entry.failure_history.len(), 5); // Max 5 entries
        assert!(entry.failure_history[0].reason.contains("2")); // Oldest kept is failure 2
        assert!(entry.failure_history[4].reason.contains("6")); // Newest is failure 6
    }
}
