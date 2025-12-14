// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Sunset timestamp management for binary version expiry.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// A sunset timestamp representing when a binary version expires.
///
/// After the sunset timestamp, nodes running this binary version
/// may be rejected (depending on enforcement mode and grace period).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SunsetTimestamp {
    /// Unix timestamp (seconds since epoch) when this version sunsets.
    timestamp: u64,
}

impl SunsetTimestamp {
    /// Create a new sunset timestamp.
    #[must_use]
    pub fn new(timestamp: u64) -> Self {
        Self { timestamp }
    }

    /// Create a sunset timestamp for N days from now.
    #[must_use]
    pub fn days_from_now(days: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let seconds_per_day = 86400u64;
        Self {
            timestamp: now + (u64::from(days) * seconds_per_day),
        }
    }

    /// Get the raw timestamp value.
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Check if this sunset timestamp has passed.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now > self.timestamp
    }

    /// Check if within the grace period after expiry.
    ///
    /// Returns true if:
    /// - Not expired yet, OR
    /// - Expired but within `grace_days` of the sunset timestamp
    #[must_use]
    pub fn is_within_grace_period(&self, grace_days: u32) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now <= self.timestamp {
            // Not expired yet
            return true;
        }

        let seconds_per_day = 86400u64;
        let grace_seconds = u64::from(grace_days) * seconds_per_day;
        let grace_deadline = self.timestamp.saturating_add(grace_seconds);

        now <= grace_deadline
    }

    /// Get the number of days until sunset (or 0 if already passed).
    #[must_use]
    pub fn days_until_sunset(&self) -> u32 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now >= self.timestamp {
            return 0;
        }

        let seconds_remaining = self.timestamp - now;
        let seconds_per_day = 86400u64;
        (seconds_remaining / seconds_per_day) as u32
    }

    /// Get the number of days since sunset (or 0 if not yet passed).
    #[must_use]
    pub fn days_since_sunset(&self) -> u32 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now <= self.timestamp {
            return 0;
        }

        let seconds_elapsed = now - self.timestamp;
        let seconds_per_day = 86400u64;
        (seconds_elapsed / seconds_per_day) as u32
    }
}

impl Default for SunsetTimestamp {
    fn default() -> Self {
        // Default to 90 days from now
        Self::days_from_now(90)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sunset_not_expired() {
        let sunset = SunsetTimestamp::days_from_now(30);
        assert!(!sunset.is_expired());
        assert!(sunset.days_until_sunset() > 0);
        assert_eq!(sunset.days_since_sunset(), 0);
    }

    #[test]
    fn test_sunset_expired() {
        // Create a timestamp 1 day in the past
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sunset = SunsetTimestamp::new(now - 86400);
        assert!(sunset.is_expired());
        assert_eq!(sunset.days_until_sunset(), 0);
        assert!(sunset.days_since_sunset() >= 1);
    }

    #[test]
    fn test_grace_period() {
        // Create a timestamp 1 hour in the past
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sunset = SunsetTimestamp::new(now - 3600);

        // Expired
        assert!(sunset.is_expired());
        // But within 1 day grace period
        assert!(sunset.is_within_grace_period(1));
        // Not within 0 day grace period
        assert!(!sunset.is_within_grace_period(0));
    }

    #[test]
    fn test_beyond_grace_period() {
        // Create a timestamp 7 days in the past
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sunset = SunsetTimestamp::new(now - (7 * 86400));

        assert!(sunset.is_expired());
        assert!(!sunset.is_within_grace_period(1));
        assert!(sunset.is_within_grace_period(10));
    }

    #[test]
    fn test_days_calculation() {
        let sunset = SunsetTimestamp::days_from_now(30);
        // Should be approximately 30 days (allowing for test execution time)
        let days = sunset.days_until_sunset();
        assert!((29..=30).contains(&days));
    }
}
