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

//! Network rejection handling for identity restart system.
//!
//! This module provides structured rejection reasons and information that enables
//! nodes to understand why they were rejected from joining the DHT network and
//! make intelligent decisions about identity regeneration.
//!
//! # Rejection Reasons
//!
//! Nodes can be rejected for various reasons:
//! - **Keyspace Saturation**: The XOR region is too crowded
//! - **Diversity Limits**: Subnet (/64, /48, /32) or ASN limits exceeded
//! - **Close Group Full**: The target close group is at capacity
//! - **Node ID Collision**: The generated ID conflicts with an existing node
//!
//! # Example
//!
//! ```ignore
//! use saorsa_core::identity::rejection::{RejectionInfo, RejectionReason};
//!
//! let rejection = RejectionInfo::new(RejectionReason::KeyspaceSaturation)
//!     .with_regeneration_recommended(true)
//!     .with_retry_after(60);
//!
//! if rejection.regeneration_recommended {
//!     // Trigger identity regeneration
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Reason why a node was rejected from joining the network.
///
/// These reason codes are wire-format stable and represented as a single byte
/// for efficient network transmission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum RejectionReason {
    /// XOR keyspace region is oversaturated with nodes.
    /// Regenerating identity may help by placing node in less crowded region.
    KeyspaceSaturation = 0x01,

    /// Too many nodes from the same /64 IPv6 subnet.
    /// This is a diversity constraint - regeneration won't help unless IP changes.
    Subnet64Limit = 0x02,

    /// Too many nodes from the same /48 IPv6 subnet.
    /// This is a diversity constraint - regeneration won't help unless IP changes.
    Subnet48Limit = 0x03,

    /// Too many nodes from the same /32 IPv4 subnet.
    /// This is a diversity constraint - regeneration won't help unless IP changes.
    Subnet32Limit = 0x04,

    /// Too many nodes from the same Autonomous System Number (ASN).
    /// This is a diversity constraint - regeneration won't help.
    AsnLimit = 0x05,

    /// Too many nodes from the same geographic region.
    /// This is a diversity constraint - regeneration won't help.
    RegionLimit = 0x06,

    /// The target close group (K=8) is full.
    /// Regenerating to target a different keyspace region may help.
    CloseGroupFull = 0x07,

    /// The generated NodeId collides with an existing node.
    /// Regenerating identity will resolve this (extremely rare).
    NodeIdCollision = 0x08,

    /// Join rate limit exceeded - too many join attempts.
    /// Should wait before retrying, regeneration not needed.
    RateLimited = 0x09,

    /// Node has been blocklisted.
    /// Regeneration will not help - the underlying cause must be addressed.
    Blocklisted = 0x0B,

    /// Generic rejection for unspecified reasons.
    /// May or may not benefit from regeneration.
    Other = 0xFF,

    /// Rejected due to GeoIP policy (e.g., hosting provider, VPN, or restricted region).
    /// Regeneration won't help unless IP changes.
    GeoIpPolicy = 0x0C,
}

impl RejectionReason {
    /// Returns whether identity regeneration could potentially resolve this rejection.
    ///
    /// Some rejections (like diversity limits based on IP/ASN) cannot be resolved
    /// by regenerating identity since the constraints are based on network properties
    /// that remain constant.
    #[must_use]
    pub fn regeneration_may_help(&self) -> bool {
        matches!(
            self,
            Self::KeyspaceSaturation | Self::CloseGroupFull | Self::NodeIdCollision | Self::Other
        )
    }

    /// Returns whether this is a diversity-based constraint.
    ///
    /// Diversity constraints are based on network properties (IP, ASN, region)
    /// that cannot be changed by regenerating identity.
    #[must_use]
    pub fn is_diversity_constraint(&self) -> bool {
        matches!(
            self,
            Self::Subnet64Limit
                | Self::Subnet48Limit
                | Self::Subnet32Limit
                | Self::AsnLimit
                | Self::RegionLimit
        )
    }

    /// Returns whether this rejection should block further regeneration attempts.
    #[must_use]
    pub fn is_blocking(&self) -> bool {
        matches!(
            self,
            Self::Blocklisted
                | Self::Subnet64Limit
                | Self::Subnet48Limit
                | Self::Subnet32Limit
                | Self::AsnLimit
                | Self::GeoIpPolicy
        )
    }

    /// Convert from wire format byte.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Self::KeyspaceSaturation,
            0x02 => Self::Subnet64Limit,
            0x03 => Self::Subnet48Limit,
            0x04 => Self::Subnet32Limit,
            0x05 => Self::AsnLimit,
            0x06 => Self::RegionLimit,
            0x07 => Self::CloseGroupFull,
            0x08 => Self::NodeIdCollision,
            0x09 => Self::RateLimited,
            0x0B => Self::Blocklisted,
            0x0C => Self::GeoIpPolicy,
            _ => Self::Other,
        }
    }

    /// Convert to wire format byte.
    #[must_use]
    pub fn to_byte(&self) -> u8 {
        *self as u8
    }
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyspaceSaturation => write!(f, "keyspace region is oversaturated"),
            Self::Subnet64Limit => write!(f, "too many nodes from /64 subnet"),
            Self::Subnet48Limit => write!(f, "too many nodes from /48 subnet"),
            Self::Subnet32Limit => write!(f, "too many nodes from /32 subnet"),
            Self::AsnLimit => write!(f, "too many nodes from ASN"),
            Self::RegionLimit => write!(f, "too many nodes from geographic region"),
            Self::CloseGroupFull => write!(f, "close group at capacity"),
            Self::NodeIdCollision => write!(f, "node ID collision"),
            Self::RateLimited => write!(f, "join rate limit exceeded"),
            Self::Blocklisted => write!(f, "node is blocklisted"),
            Self::GeoIpPolicy => write!(f, "rejected by GeoIP policy"),
            Self::Other => write!(f, "unspecified rejection"),
        }
    }
}

/// Information about keyspace saturation levels.
///
/// This provides detail about how saturated different regions of the
/// XOR keyspace are, helping the node target less crowded areas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaturationInfo {
    /// Current region's saturation level (0.0 to 1.0).
    /// 1.0 means completely full.
    pub current_saturation: f64,

    /// Average saturation across all regions.
    pub average_saturation: f64,

    /// Least saturated regions (XOR prefix bits).
    /// These are suggested targets for regeneration.
    pub sparse_regions: Vec<KeyspaceRegion>,

    /// Number of nodes in the current close group vicinity.
    pub local_node_count: u32,

    /// Maximum nodes allowed in region before rejection.
    pub region_capacity: u32,
}

impl SaturationInfo {
    /// Create new saturation info.
    #[must_use]
    pub fn new(current: f64, average: f64) -> Self {
        Self {
            current_saturation: current.clamp(0.0, 1.0),
            average_saturation: average.clamp(0.0, 1.0),
            sparse_regions: Vec::new(),
            local_node_count: 0,
            region_capacity: 0,
        }
    }

    /// Add a sparse region suggestion.
    pub fn add_sparse_region(&mut self, region: KeyspaceRegion) {
        self.sparse_regions.push(region);
    }

    /// Set local node count.
    pub fn with_local_count(mut self, count: u32, capacity: u32) -> Self {
        self.local_node_count = count;
        self.region_capacity = capacity;
        self
    }
}

/// A region in the XOR keyspace identified by prefix bits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyspaceRegion {
    /// The prefix bits that identify this region.
    /// Stored as big-endian bytes.
    pub prefix: Vec<u8>,

    /// Number of significant bits in the prefix.
    pub prefix_len: u8,

    /// Saturation level of this region (0.0 to 1.0).
    pub saturation: f64,

    /// Estimated node count in this region.
    pub estimated_nodes: u32,
}

impl KeyspaceRegion {
    /// Create a new keyspace region.
    #[must_use]
    pub fn new(prefix: Vec<u8>, prefix_len: u8, saturation: f64) -> Self {
        Self {
            prefix,
            prefix_len,
            saturation: saturation.clamp(0.0, 1.0),
            estimated_nodes: 0,
        }
    }

    /// Set estimated node count.
    pub fn with_estimated_nodes(mut self, count: u32) -> Self {
        self.estimated_nodes = count;
        self
    }

    /// Check if a NodeId falls within this region.
    #[must_use]
    pub fn contains(&self, node_id: &super::NodeId) -> bool {
        let node_bytes = node_id.to_bytes();
        let full_bytes = self.prefix_len as usize / 8;
        let remaining_bits = self.prefix_len as usize % 8;

        // Check full bytes using zip to iterate both slices together
        let prefix_slice = &self.prefix[..full_bytes.min(self.prefix.len())];
        let node_slice = &node_bytes[..full_bytes.min(node_bytes.len())];
        for (p, n) in prefix_slice.iter().zip(node_slice.iter()) {
            if p != n {
                return false;
            }
        }

        // Check remaining bits
        if remaining_bits > 0 && full_bytes < self.prefix.len() && full_bytes < node_bytes.len() {
            let mask = 0xFF << (8 - remaining_bits);
            if (self.prefix[full_bytes] & mask) != (node_bytes[full_bytes] & mask) {
                return false;
            }
        }

        true
    }
}

/// Suggested target region for identity regeneration.
///
/// When a node is rejected, the network may suggest alternative regions
/// where the node would be more likely to be accepted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetRegion {
    /// The suggested keyspace region.
    pub region: KeyspaceRegion,

    /// How strongly this region is recommended (0.0 to 1.0).
    /// Higher values indicate better fit.
    pub confidence: f64,

    /// Human-readable reason for this suggestion.
    pub reason: String,
}

impl TargetRegion {
    /// Create a new target region suggestion.
    #[must_use]
    pub fn new(region: KeyspaceRegion, confidence: f64, reason: impl Into<String>) -> Self {
        Self {
            region,
            confidence: confidence.clamp(0.0, 1.0),
            reason: reason.into(),
        }
    }
}

/// Complete rejection information returned by the network.
///
/// This structure contains all information needed for a node to understand
/// why it was rejected and make an informed decision about regeneration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectionInfo {
    /// The primary reason for rejection.
    pub reason: RejectionReason,

    /// Unix timestamp when rejection occurred.
    pub timestamp: u64,

    /// Detailed saturation information (if available).
    pub saturation_info: Option<SaturationInfo>,

    /// Suggested target region for regeneration (if available).
    pub suggested_target: Option<TargetRegion>,

    /// Recommended wait time before retrying (seconds).
    pub retry_after_secs: u32,

    /// Whether the network recommends identity regeneration.
    pub regeneration_recommended: bool,

    /// Additional context message.
    pub message: Option<String>,

    /// ID of the rejecting node (for debugging).
    pub rejecting_node: Option<String>,
}

impl RejectionInfo {
    /// Create new rejection info with the given reason.
    #[must_use]
    pub fn new(reason: RejectionReason) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            reason,
            timestamp,
            saturation_info: None,
            suggested_target: None,
            retry_after_secs: 0,
            regeneration_recommended: reason.regeneration_may_help(),
            message: None,
            rejecting_node: None,
        }
    }

    /// Set saturation information.
    #[must_use]
    pub fn with_saturation_info(mut self, info: SaturationInfo) -> Self {
        self.saturation_info = Some(info);
        self
    }

    /// Set suggested target region.
    #[must_use]
    pub fn with_suggested_target(mut self, target: TargetRegion) -> Self {
        self.suggested_target = Some(target);
        self
    }

    /// Set retry delay.
    #[must_use]
    pub fn with_retry_after(mut self, secs: u32) -> Self {
        self.retry_after_secs = secs;
        self
    }

    /// Override regeneration recommendation.
    #[must_use]
    pub fn with_regeneration_recommended(mut self, recommended: bool) -> Self {
        self.regeneration_recommended = recommended;
        self
    }

    /// Set additional context message.
    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Set rejecting node ID.
    #[must_use]
    pub fn with_rejecting_node(mut self, node_id: impl Into<String>) -> Self {
        self.rejecting_node = Some(node_id.into());
        self
    }

    /// Check if this rejection should trigger regeneration.
    ///
    /// Returns true if regeneration is recommended AND the reason
    /// indicates regeneration could help.
    #[must_use]
    pub fn should_regenerate(&self) -> bool {
        self.regeneration_recommended && self.reason.regeneration_may_help()
    }

    /// Check if this rejection should block further attempts.
    #[must_use]
    pub fn is_blocking(&self) -> bool {
        self.reason.is_blocking()
    }

    /// Get the suggested wait duration before retry.
    #[must_use]
    pub fn retry_delay(&self) -> std::time::Duration {
        std::time::Duration::from_secs(u64::from(self.retry_after_secs))
    }
}

impl fmt::Display for RejectionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rejected: {}", self.reason)?;
        if let Some(msg) = &self.message {
            write!(f, " ({})", msg)?;
        }
        if self.regeneration_recommended {
            write!(f, " [regeneration recommended]")?;
        }
        if self.retry_after_secs > 0 {
            write!(f, " [retry after {}s]", self.retry_after_secs)?;
        }
        Ok(())
    }
}

/// History of rejections for a node, used to inform regeneration decisions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RejectionHistory {
    /// List of past rejections with timestamps.
    rejections: Vec<RejectionInfo>,

    /// Maximum number of rejections to keep.
    max_entries: usize,
}

impl RejectionHistory {
    /// Create a new rejection history with default capacity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rejections: Vec::new(),
            max_entries: 100,
        }
    }

    /// Create with custom capacity.
    #[must_use]
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            rejections: Vec::with_capacity(max_entries.min(1000)),
            max_entries: max_entries.min(1000),
        }
    }

    /// Record a new rejection.
    pub fn record(&mut self, info: RejectionInfo) {
        self.rejections.push(info);

        // Trim old entries if over capacity
        if self.rejections.len() > self.max_entries {
            let excess = self.rejections.len() - self.max_entries;
            self.rejections.drain(0..excess);
        }
    }

    /// Get all rejections.
    #[must_use]
    pub fn all(&self) -> &[RejectionInfo] {
        &self.rejections
    }

    /// Get recent rejections within the given duration.
    #[must_use]
    pub fn recent(&self, duration: std::time::Duration) -> Vec<&RejectionInfo> {
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs().saturating_sub(duration.as_secs()))
            .unwrap_or(0);

        self.rejections
            .iter()
            .filter(|r| r.timestamp >= cutoff)
            .collect()
    }

    /// Count rejections by reason.
    #[must_use]
    pub fn count_by_reason(&self, reason: RejectionReason) -> usize {
        self.rejections
            .iter()
            .filter(|r| r.reason == reason)
            .count()
    }

    /// Check if there are too many recent rejections (potential loop detection).
    #[must_use]
    pub fn is_in_rejection_loop(&self, threshold: usize, window: std::time::Duration) -> bool {
        self.recent(window).len() >= threshold
    }

    /// Get the most common rejection reason.
    #[must_use]
    pub fn most_common_reason(&self) -> Option<RejectionReason> {
        use std::collections::HashMap;

        let mut counts: HashMap<RejectionReason, usize> = HashMap::new();
        for rejection in &self.rejections {
            *counts.entry(rejection.reason).or_insert(0) += 1;
        }

        counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(reason, _)| reason)
    }

    /// Clear all rejection history.
    pub fn clear(&mut self) {
        self.rejections.clear();
    }

    /// Get number of recorded rejections.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rejections.len()
    }

    /// Check if history is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rejections.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejection_reason_regeneration_help() {
        assert!(RejectionReason::KeyspaceSaturation.regeneration_may_help());
        assert!(RejectionReason::CloseGroupFull.regeneration_may_help());
        assert!(RejectionReason::NodeIdCollision.regeneration_may_help());

        assert!(!RejectionReason::Subnet64Limit.regeneration_may_help());
        assert!(!RejectionReason::AsnLimit.regeneration_may_help());
        assert!(!RejectionReason::Blocklisted.regeneration_may_help());
    }

    #[test]
    fn test_rejection_reason_byte_conversion() {
        for reason in [
            RejectionReason::KeyspaceSaturation,
            RejectionReason::Subnet64Limit,
            RejectionReason::CloseGroupFull,
            RejectionReason::Blocklisted,
        ] {
            let byte = reason.to_byte();
            let recovered = RejectionReason::from_byte(byte);
            assert_eq!(reason, recovered);
        }

        // Unknown bytes should become Other
        assert_eq!(RejectionReason::from_byte(0xFE), RejectionReason::Other);
    }

    #[test]
    fn test_rejection_info_builder() {
        let info = RejectionInfo::new(RejectionReason::KeyspaceSaturation)
            .with_retry_after(60)
            .with_regeneration_recommended(true)
            .with_message("Test rejection");

        assert_eq!(info.reason, RejectionReason::KeyspaceSaturation);
        assert_eq!(info.retry_after_secs, 60);
        assert!(info.regeneration_recommended);
        assert_eq!(info.message, Some("Test rejection".to_string()));
    }

    #[test]
    fn test_rejection_info_should_regenerate() {
        let info1 = RejectionInfo::new(RejectionReason::KeyspaceSaturation)
            .with_regeneration_recommended(true);
        assert!(info1.should_regenerate());

        let info2 =
            RejectionInfo::new(RejectionReason::Subnet64Limit).with_regeneration_recommended(true);
        // Subnet limit can't be helped by regeneration
        assert!(!info2.should_regenerate());

        let info3 = RejectionInfo::new(RejectionReason::KeyspaceSaturation)
            .with_regeneration_recommended(false);
        assert!(!info3.should_regenerate());
    }

    #[test]
    fn test_saturation_info() {
        let mut saturation = SaturationInfo::new(0.85, 0.60);
        saturation.add_sparse_region(KeyspaceRegion::new(vec![0x00], 4, 0.20));

        assert!((saturation.current_saturation - 0.85).abs() < f64::EPSILON);
        assert!((saturation.average_saturation - 0.60).abs() < f64::EPSILON);
        assert_eq!(saturation.sparse_regions.len(), 1);
    }

    #[test]
    fn test_keyspace_region_contains() {
        // Region with prefix 0x80 (first bit = 1) and 1 bit length
        let region = KeyspaceRegion::new(vec![0x80], 1, 0.5);

        // NodeId starting with 1... should be in region
        let in_region = super::super::NodeId([0xFF; 32]);
        assert!(region.contains(&in_region));

        // NodeId starting with 0... should NOT be in region
        let not_in_region = super::super::NodeId([0x00; 32]);
        assert!(!region.contains(&not_in_region));
    }

    #[test]
    fn test_rejection_history() {
        let mut history = RejectionHistory::with_capacity(10);

        for _ in 0..5 {
            history.record(RejectionInfo::new(RejectionReason::KeyspaceSaturation));
        }
        for _ in 0..3 {
            history.record(RejectionInfo::new(RejectionReason::CloseGroupFull));
        }

        assert_eq!(history.len(), 8);
        assert_eq!(
            history.count_by_reason(RejectionReason::KeyspaceSaturation),
            5
        );
        assert_eq!(history.count_by_reason(RejectionReason::CloseGroupFull), 3);
        assert_eq!(
            history.most_common_reason(),
            Some(RejectionReason::KeyspaceSaturation)
        );
    }

    #[test]
    fn test_rejection_history_capacity() {
        let mut history = RejectionHistory::with_capacity(5);

        for _ in 0..10 {
            history.record(RejectionInfo::new(RejectionReason::KeyspaceSaturation));
        }

        // Should only keep 5 entries
        assert_eq!(history.len(), 5);
    }

    #[test]
    fn test_rejection_loop_detection() {
        let mut history = RejectionHistory::new();

        for _ in 0..5 {
            history.record(RejectionInfo::new(RejectionReason::KeyspaceSaturation));
        }

        // 5 rejections within any window should trigger loop detection at threshold 5
        assert!(history.is_in_rejection_loop(5, std::time::Duration::from_secs(3600)));
        assert!(!history.is_in_rejection_loop(10, std::time::Duration::from_secs(3600)));
    }
}
