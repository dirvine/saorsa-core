// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com

//! Storage types for replication-based storage

use crate::fwid::Key;
use crate::types::presence::DeviceId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Handle to stored data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageHandle {
    /// Unique identifier for the stored data
    pub id: Key,
    /// Size of original data
    pub size: u64,
    /// Storage strategy used
    pub strategy: StorageStrategy,
    /// Shard distribution across devices
    pub shard_map: ShardMap,
    /// Encryption key (sealed)
    pub sealed_key: Option<Vec<u8>>,
}

/// Maximum number of replicas the storage layer targets.
pub const MAX_REPLICATION_TARGET: usize = 8;

/// Storage strategy based on group size
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageStrategy {
    /// Full replication for multi-device or group storage
    FullReplication {
        /// Number of replicas targeted
        replicas: usize,
    },
    /// Direct storage without redundancy (single user)
    Direct,
}

impl StorageStrategy {
    /// Create strategy based on group size
    pub fn from_group_size(size: usize) -> Self {
        match size {
            0 | 1 => Self::Direct,
            _ => {
                let replicas = size.clamp(2, MAX_REPLICATION_TARGET);
                Self::FullReplication { replicas }
            }
        }
    }
}

/// Mapping of shards to devices
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardMap {
    /// Device ID -> list of shard indices
    pub device_shards: HashMap<DeviceId, Vec<u32>>,
    /// Total number of shards
    pub total_shards: u32,
}

impl ShardMap {
    /// Create empty shard map
    pub fn new() -> Self {
        Self {
            device_shards: HashMap::new(),
            total_shards: 0,
        }
    }

    /// Add shard assignment to a device
    pub fn assign_shard(&mut self, device: DeviceId, shard_index: u32) {
        self.device_shards
            .entry(device)
            .or_default()
            .push(shard_index);

        if shard_index >= self.total_shards {
            self.total_shards = shard_index + 1;
        }
    }

    /// Get shards for a specific device
    pub fn device_shards(&self, device: &DeviceId) -> Option<&Vec<u32>> {
        self.device_shards.get(device)
    }

    /// Get all devices storing shards
    pub fn devices(&self) -> Vec<DeviceId> {
        self.device_shards.keys().copied().collect()
    }
}

impl Default for ShardMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Shard assignment for a device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardAssignment {
    /// Container ID this shard belongs to
    pub container_id: Key,
    /// Indices of shards assigned to this device
    pub shard_indices: Vec<u32>,
    /// Role of these shards
    pub role: ShardRole,
}

/// Role of a shard on a device
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShardRole {
    /// Primary storage location
    Primary,
    /// Backup/replica
    Backup,
    /// Cache for performance
    Cache,
}
