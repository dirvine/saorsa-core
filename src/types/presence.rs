// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com

//! Presence and device management types

use crate::fwid::Key;
// use crate::quantum_crypto::{MlDsaPublicKey, MlDsaSignature};
use serde::{Deserialize, Serialize};

/// Unique device identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 32]);

impl DeviceId {
    /// Generate a new random device ID
    pub fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut id = [0u8; 32];
        rng.fill(&mut id);
        Self(id)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Type of device in the network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    /// User-facing device with active interaction
    Active,
    /// Headless storage node (no user interaction)
    Headless,
    /// Mobile device with limited capabilities
    Mobile,
}

/// Network endpoint for device connectivity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    /// Protocol (e.g., "quic", "tcp")
    pub protocol: String,
    /// Address (IP:port or domain:port)
    pub address: String,
}

/// Device registered in the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// Unique device identifier
    pub id: DeviceId,
    /// Type of device
    pub device_type: DeviceType,
    /// Storage capacity in GB
    pub storage_gb: u64,
    /// Network endpoint
    pub endpoint: Endpoint,
    /// Capabilities of this device
    pub capabilities: DeviceCapabilities,
}

/// Device capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCapabilities {
    /// Available storage in bytes
    pub storage_bytes: u64,
    /// Network bandwidth in Mbps
    pub bandwidth_mbps: u32,
    /// Number of CPU cores
    pub cpu_cores: u8,
    /// Whether device is always online
    pub always_online: bool,
    /// Supports FEC operations
    pub supports_fec: bool,
    /// Supports seal operations
    pub supports_seal: bool,
}

impl Default for DeviceCapabilities {
    fn default() -> Self {
        Self {
            storage_bytes: 10 * 1024 * 1024 * 1024, // 10GB default
            bandwidth_mbps: 100,
            cpu_cores: 4,
            always_online: false,
            supports_fec: true,
            supports_seal: true,
        }
    }
}

/// User presence in the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Presence {
    /// User's identity key (hash of four words)
    pub identity: Key,
    /// All registered devices
    pub devices: Vec<Device>,
    /// Currently active device
    pub active_device: Option<DeviceId>,
    /// Unix timestamp
    pub timestamp: u64,
    /// Signature over the presence data
    pub signature: Vec<u8>,
}

impl Presence {
    /// Check if presence has any headless nodes
    pub fn has_headless_nodes(&self) -> bool {
        self.devices
            .iter()
            .any(|d| d.device_type == DeviceType::Headless)
    }

    /// Get total storage capacity across all devices
    pub fn total_storage_gb(&self) -> u64 {
        self.devices.iter().map(|d| d.storage_gb).sum()
    }

    /// Get all headless devices
    pub fn headless_devices(&self) -> Vec<&Device> {
        self.devices
            .iter()
            .filter(|d| d.device_type == DeviceType::Headless)
            .collect()
    }

    /// Get the active device if set
    pub fn active_device(&self) -> Option<&Device> {
        self.active_device
            .and_then(|id| self.devices.iter().find(|d| d.id == id))
    }
}

/// Receipt for presence registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceReceipt {
    /// Identity key
    pub identity: Key,
    /// Timestamp of registration
    pub timestamp: u64,
    /// DHT nodes storing the presence
    pub storing_nodes: Vec<Key>,
}
