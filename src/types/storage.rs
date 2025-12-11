// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com

//! Storage types with saorsa-seal and saorsa-fec integration

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

/// Parameters for saorsa-seal encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealParameters {
    /// Algorithm identifier
    pub algorithm: String,
    /// Nonce for encryption
    pub nonce: Vec<u8>,
    /// Additional authenticated data
    pub aad: Option<Vec<u8>>,
}

impl Default for SealParameters {
    fn default() -> Self {
        Self {
            algorithm: "ChaCha20-Poly1305".to_string(),
            nonce: vec![0u8; 12], // Will be generated properly
            aad: None,
        }
    }
}

/// Parameters for saorsa-fec encoding
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FecParameters {
    /// Number of data shards (k)
    pub data_shards: u16,
    /// Number of parity shards (m)
    pub parity_shards: u16,
    /// Size of each shard in bytes
    pub shard_size: u32,
}

impl FecParameters {
    /// Create new FEC parameters
    pub fn new(data_shards: u16, parity_shards: u16, shard_size: u32) -> Self {
        Self {
            data_shards,
            parity_shards,
            shard_size,
        }
    }

    /// Get total number of shards
    pub fn total_shards(&self) -> u16 {
        self.data_shards + self.parity_shards
    }

    /// Calculate redundancy ratio
    pub fn redundancy_ratio(&self) -> f32 {
        self.parity_shards as f32 / self.data_shards as f32
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

/// Plan for distributing shards across devices
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardDistributionPlan {
    /// FEC parameters used
    pub fec_params: FecParameters,
    /// Assignments per device
    pub assignments: HashMap<DeviceId, Vec<ShardAssignment>>,
    /// Preferred devices for primary storage
    pub primary_devices: Vec<DeviceId>,
    /// Backup devices
    pub backup_devices: Vec<DeviceId>,
}
