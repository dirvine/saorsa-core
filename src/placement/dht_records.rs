// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! DHT record types for the placement system with compact serialization
//!
//! This module implements the core DHT record types used in the placement system:
//! - NODE_AD: Node advertisements with capabilities and network information
//! - GROUP_BEACON: Group formation and policy information  
//! - DATA_POINTER: Content identifier to placement ticket mapping
//! - REGISTER_POINTER: Name resolution for versioned content
//!
//! All records support:
//! - Compact binary serialization (≤512 bytes)
//! - TTL management (60 minutes)
//! - Proof of Work validation (≈18 bits for high-churn keys)
//! - Cryptographic signatures where needed

use crate::error::{P2PError, P2pResult};
use serde::{Deserialize, Serialize};
// use std::collections::HashMap; // Unused import - commented out
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// External dependencies for cryptography
use blake3;

/// Serializable wrapper for blake3::Hash
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SerializableHash([u8; 32]);

impl From<blake3::Hash> for SerializableHash {
    fn from(hash: blake3::Hash) -> Self {
        Self(*hash.as_bytes())
    }
}

impl From<SerializableHash> for blake3::Hash {
    fn from(hash: SerializableHash) -> Self {
        blake3::Hash::from(hash.0)
    }
}

impl SerializableHash {
    /// Get the bytes of the hash
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for SerializableHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for SerializableHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for SerializableHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SerializableHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Invalid hash length"));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

// Type alias for convenience
pub type Hash = SerializableHash;



/// Maximum payload size for DHT records (512 bytes)
pub const MAX_RECORD_SIZE: usize = 512;

/// Default TTL for DHT records (60 minutes)
pub const DEFAULT_TTL: Duration = Duration::from_secs(3600);

/// Minimum proof of work bits for high-churn keys
pub const MIN_POW_BITS: u8 = 18;

/// Node identifier for compatibility with existing saorsa-core
pub use crate::adaptive::NodeId;

/// Group identifier for placement groups
pub type GroupId = SerializableHash;

/// Placement ticket identifier
pub type PlacementTicketId = SerializableHash;

/// Content identifier for data chunks
pub type ContentId = SerializableHash;

/// Name identifier for register pointers
pub type NameId = SerializableHash;

/// Node capabilities information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCapabilities {
    /// Total disk space in bytes
    pub disk_total: u64,
    /// Free disk space in bytes
    pub disk_free: u64,
    /// Donor percentage (0-100)
    pub donor_pct: u8,
}

impl NodeCapabilities {
    /// Create new node capabilities with validation
    pub fn new(disk_total: u64, disk_free: u64, donor_pct: u8) -> P2pResult<Self> {
        if donor_pct > 100 {
            return Err(P2PError::InvalidInput(
                "Donor percentage must be 0-100".to_string(),
            ));
        }
        if disk_free > disk_total {
            return Err(P2PError::InvalidInput(
                "Free disk cannot exceed total disk".to_string(),
            ));
        }

        Ok(Self {
            disk_total,
            disk_free,
            donor_pct,
        })
    }

    /// Get disk usage percentage
    pub fn disk_usage_pct(&self) -> u8 {
        if self.disk_total == 0 {
            return 0;
        }
        let used = self.disk_total.saturating_sub(self.disk_free);
        ((used * 100) / self.disk_total).min(100) as u8
    }

    /// Check if node has sufficient free space
    pub fn has_free_space(&self, required_bytes: u64) -> bool {
        self.disk_free >= required_bytes
    }
}

/// NAT type classification
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NatType {
    /// No NAT (public IP)
    None = 0,
    /// Full cone NAT
    FullCone = 1,
    /// Restricted cone NAT
    RestrictedCone = 2,
    /// Port restricted cone NAT
    PortRestricted = 3,
    /// Symmetric NAT
    Symmetric = 4,
    /// Unknown NAT type
    Unknown = 255,
}

impl Default for NatType {
    fn default() -> Self {
        NatType::Unknown
    }
}

/// Operating system signature for node fingerprinting
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OsSignature {
    /// OS family (e.g., "linux", "windows", "macos")
    pub family: String,
    /// Architecture (e.g., "x86_64", "aarch64")
    pub arch: String,
    /// Version hash (first 8 bytes of OS version hash)
    pub version_hash: [u8; 8],
}

impl OsSignature {
    /// Create OS signature from system information
    pub fn new(family: String, arch: String, version: &str) -> Self {
        let version_hash = blake3::hash(version.as_bytes());
        let mut hash_bytes = [0u8; 8];
        hash_bytes.copy_from_slice(&version_hash.as_bytes()[..8]);

        Self {
            family,
            arch,
            version_hash: hash_bytes,
        }
    }

    /// Get current system OS signature
    pub fn current() -> Self {
        let family = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();
        let version = std::env::var("OS_VERSION").unwrap_or_else(|_| "unknown".to_string());

        Self::new(family, arch, &version)
    }
}

/// Placement policy for groups
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlacementPolicy {
    /// FEC parameters
    pub fec: FecParams,
    /// Delta parameter for repair triggers
    pub delta: u16,
    /// Scope of the placement policy
    pub scope: PolicyScope,
    /// Audit percentage (0-100)
    pub audit_pct: u8,
}

impl Default for PlacementPolicy {
    fn default() -> Self {
        Self {
            fec: FecParams::default(),
            delta: 4,
            scope: PolicyScope::Global,
            audit_pct: 2, // 2% audit rate
        }
    }
}

/// FEC parameters
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FecParams {
    /// Number of data chunks
    pub data: u16,
    /// Number of parity chunks
    pub parity: u16,
}

impl Default for FecParams {
    fn default() -> Self {
        Self {
            data: 8,
            parity: 4,
        }
    }
}

/// Policy scope enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyScope {
    /// Global policy
    Global,
    /// Regional policy
    Regional(String),
    /// Group-specific policy
    Group(GroupId),
}

/// Node advertisement record for DHT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAd {
    /// Node identifier
    pub node_id: NodeId,
    /// Network addresses
    pub addrs: Vec<SocketAddr>,
    /// Node capabilities
    pub caps: NodeCapabilities,
    /// NAT type
    pub nat_type: NatType,
    /// Autonomous System Number
    pub asn: u32,
    /// Operating system signature
    pub os_sig: OsSignature,
    /// Timestamp (seconds since UNIX epoch)
    pub ts: u64,
    /// Trust score hash (first 16 bytes)
    pub trust_hash: [u8; 16],
    /// Churn prediction hash (first 16 bytes)
    pub churn_hash: [u8; 16],
    /// Digital signature of the record (placeholder for actual signature)
    pub signature: Option<Vec<u8>>,
}

impl NodeAd {
    /// Create a new node advertisement
    pub fn new(
        node_id: NodeId,
        addrs: Vec<SocketAddr>,
        caps: NodeCapabilities,
        nat_type: NatType,
        asn: u32,
        os_sig: OsSignature,
        trust_hash: [u8; 16],
        churn_hash: [u8; 16],
    ) -> P2pResult<Self> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| P2PError::TimeError)?
            .as_secs();

        if addrs.is_empty() {
            return Err(P2PError::InvalidInput(
                "Node must have at least one address".to_string(),
            ));
        }

        if addrs.len() > 8 {
            return Err(P2PError::InvalidInput(
                "Node cannot have more than 8 addresses".to_string(),
            ));
        }

        Ok(Self {
            node_id,
            addrs,
            caps,
            nat_type,
            asn,
            os_sig,
            ts,
            trust_hash,
            churn_hash,
            signature: None,
        })
    }

    /// Check if the advertisement is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Valid for 60 minutes
        now.saturating_sub(self.ts) < DEFAULT_TTL.as_secs()
    }

    /// Get TTL remaining in seconds
    pub fn ttl_remaining(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        DEFAULT_TTL
            .as_secs()
            .saturating_sub(now.saturating_sub(self.ts))
    }
}

/// Group beacon record for DHT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupBeacon {
    /// Group identifier
    pub group_id: GroupId,
    /// Placement policy for the group
    pub policy: PlacementPolicy,
    /// Merkle root of group members
    pub member_root: SerializableHash,
    /// Guardian nodes (subset of members with special permissions)
    pub guardians: Vec<NodeId>,
    /// Timestamp (seconds since UNIX epoch)
    pub ts: u64,
    /// Digital signature of the beacon (placeholder for actual signature)
    pub signature: Option<Vec<u8>>,
}

impl GroupBeacon {
    /// Create a new group beacon
    pub fn new(
        group_id: GroupId,
        policy: PlacementPolicy,
        member_root: SerializableHash,
        guardians: Vec<NodeId>,
    ) -> P2pResult<Self> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| P2PError::TimeError)?
            .as_secs();

        if guardians.len() > 16 {
            return Err(P2PError::InvalidInput(
                "Too many guardians (max 16)".to_string(),
            ));
        }

        Ok(Self {
            group_id,
            policy,
            member_root,
            guardians,
            ts,
            signature: None,
        })
    }

    /// Check if the beacon is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Valid for 60 minutes
        now.saturating_sub(self.ts) < DEFAULT_TTL.as_secs()
    }
}

/// Data pointer record for DHT (maps content to placement tickets)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPointer {
    /// Content identifier (hash of the data)
    pub cid: ContentId,
    /// List of placement ticket IDs that store this content
    pub placement_ticket_ids: Vec<PlacementTicketId>,
    /// Timestamp (seconds since UNIX epoch)
    pub ts: u64,
}

impl DataPointer {
    /// Create a new data pointer
    pub fn new(cid: ContentId, placement_ticket_ids: Vec<PlacementTicketId>) -> P2pResult<Self> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| P2PError::TimeError)?
            .as_secs();

        if placement_ticket_ids.is_empty() {
            return Err(P2PError::InvalidInput(
                "Data pointer must have at least one placement ticket".to_string(),
            ));
        }

        if placement_ticket_ids.len() > 32 {
            return Err(P2PError::InvalidInput(
                "Too many placement tickets (max 32)".to_string(),
            ));
        }

        Ok(Self {
            cid,
            placement_ticket_ids,
            ts,
        })
    }

    /// Check if the pointer is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Valid for 60 minutes
        now.saturating_sub(self.ts) < DEFAULT_TTL.as_secs()
    }

    /// Add a placement ticket ID
    pub fn add_placement_ticket(&mut self, ticket_id: PlacementTicketId) -> P2pResult<()> {
        if self.placement_ticket_ids.len() >= 32 {
            return Err(P2PError::InvalidInput(
                "Cannot add more placement tickets (max 32)".to_string(),
            ));
        }

        if !self.placement_ticket_ids.contains(&ticket_id) {
            self.placement_ticket_ids.push(ticket_id);
        }

        Ok(())
    }

    /// Remove a placement ticket ID
    pub fn remove_placement_ticket(&mut self, ticket_id: &PlacementTicketId) {
        self.placement_ticket_ids.retain(|id| id != ticket_id);
    }
}

/// Register pointer record for DHT (name resolution)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPointer {
    /// Name identifier
    pub name_id: NameId,
    /// Root reference (content hash of the named resource)
    pub root_ref: ContentId,
    /// Version number (monotonically increasing)
    pub version: u64,
    /// Timestamp (seconds since UNIX epoch)
    pub ts: u64,
    /// Digital signature of the pointer (placeholder for actual signature)
    pub signature: Option<Vec<u8>>,
}

impl RegisterPointer {
    /// Create a new register pointer
    pub fn new(name_id: NameId, root_ref: ContentId, version: u64) -> P2pResult<Self> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| P2PError::TimeError)?
            .as_secs();

        Ok(Self {
            name_id,
            root_ref,
            version,
            ts,
            signature: None,
        })
    }

    /// Check if the pointer is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Valid for 60 minutes
        now.saturating_sub(self.ts) < DEFAULT_TTL.as_secs()
    }

    /// Update to a new version
    pub fn update_version(&mut self, root_ref: ContentId, version: u64) -> P2pResult<()> {
        if version <= self.version {
            return Err(P2PError::InvalidInput(
                "Version must be higher than current".to_string(),
            ));
        }

        self.root_ref = root_ref;
        self.version = version;
        self.ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| P2PError::TimeError)?
            .as_secs();

        // Clear signature as content has changed
        self.signature = None;

        Ok(())
    }
}

/// DHT record envelope with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtRecord {
    /// Record key (used for DHT routing)
    pub key: Hash,
    /// Record data
    pub data: DhtRecordData,
    /// Proof of work nonce (for high-churn keys)
    pub pow_nonce: Option<u64>,
    /// Time to live in seconds
    pub ttl: u64,
}

/// Union of all DHT record types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtRecordData {
    /// Node advertisement
    NodeAd(NodeAd),
    /// Group beacon
    GroupBeacon(GroupBeacon),
    /// Data pointer
    DataPointer(DataPointer),
    /// Register pointer
    RegisterPointer(RegisterPointer),
}

impl DhtRecord {
    /// Create a new DHT record
    pub fn new(key: Hash, data: DhtRecordData, ttl: Option<Duration>) -> Self {
        let ttl_secs = ttl.unwrap_or(DEFAULT_TTL).as_secs();

        Self {
            key,
            data,
            pow_nonce: None,
            ttl: ttl_secs,
        }
    }

    /// Serialize the record to bytes
    pub fn serialize(&self) -> P2pResult<Vec<u8>> {
        let bytes = bincode::serialize(self)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;

        if bytes.len() > MAX_RECORD_SIZE {
            return Err(P2PError::RecordTooLarge(bytes.len()));
        }

        Ok(bytes)
    }

    /// Deserialize the record from bytes
    pub fn deserialize(bytes: &[u8]) -> P2pResult<Self> {
        if bytes.len() > MAX_RECORD_SIZE {
            return Err(P2PError::RecordTooLarge(bytes.len()));
        }

        bincode::deserialize(bytes)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))
    }

    /// Check if the record is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Check TTL and record-specific validity
        let record_valid = match &self.data {
            DhtRecordData::NodeAd(ad) => ad.is_valid(),
            DhtRecordData::GroupBeacon(beacon) => beacon.is_valid(),
            DhtRecordData::DataPointer(pointer) => pointer.is_valid(),
            DhtRecordData::RegisterPointer(pointer) => pointer.is_valid(),
        };

        let creation_time = match &self.data {
            DhtRecordData::NodeAd(ad) => ad.ts,
            DhtRecordData::GroupBeacon(beacon) => beacon.ts,
            DhtRecordData::DataPointer(pointer) => pointer.ts,
            DhtRecordData::RegisterPointer(pointer) => pointer.ts,
        };

        let ttl_valid = now.saturating_sub(creation_time) < self.ttl;

        record_valid && ttl_valid
    }

    /// Compute proof of work for high-churn keys
    pub fn compute_pow(&mut self, target_bits: u8) -> P2pResult<()> {
        if target_bits == 0 {
            self.pow_nonce = None;
            return Ok(());
        }

        let target_difficulty = if target_bits >= 64 {
            0
        } else {
            u64::MAX >> target_bits
        };

        for nonce in 0..u64::MAX {
            self.pow_nonce = Some(nonce);

            let hash = self.compute_pow_hash()?;
            let hash_value = u64::from_be_bytes(
                hash.as_bytes()[..8]
                    .try_into()
                    .map_err(|_| P2PError::Internal("Hash conversion failed".into()))?,
            );

            if hash_value < target_difficulty {
                return Ok(());
            }

            // Prevent infinite loops
            if nonce % 1_000_000 == 0 {
                return Err(P2PError::ProofOfWorkFailed);
            }
        }

        Err(P2PError::ProofOfWorkFailed)
    }

    /// Verify proof of work
    pub fn verify_pow(&self, target_bits: u8) -> P2pResult<bool> {
        if target_bits == 0 {
            return Ok(self.pow_nonce.is_none());
        }

        let _nonce = self
            .pow_nonce
            .ok_or_else(|| P2PError::InvalidInput("No proof of work nonce".to_string()))?;

        let target_difficulty = if target_bits >= 64 {
            0
        } else {
            u64::MAX >> target_bits
        };

        let hash = self.compute_pow_hash()?;
        let hash_value = u64::from_be_bytes(
            hash.as_bytes()[..8]
                .try_into()
                .map_err(|_| P2PError::Internal("Hash conversion failed".into()))?,
        );

        Ok(hash_value < target_difficulty)
    }

    /// Compute hash for proof of work
    fn compute_pow_hash(&self) -> P2pResult<Hash> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.key.as_bytes());

        // Serialize record data without PoW nonce for consistent hashing
        let mut record_copy = self.clone();
        let original_nonce = record_copy.pow_nonce;
        record_copy.pow_nonce = None;

        let data_bytes = bincode::serialize(&record_copy.data)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;
        hasher.update(&data_bytes);

        if let Some(nonce) = original_nonce {
            hasher.update(&nonce.to_be_bytes());
        }

        Ok(hasher.finalize().into())
    }

    /// Get the size of the serialized record
    pub fn size(&self) -> P2pResult<usize> {
        let bytes = self.serialize()?;
        Ok(bytes.len())
    }

    /// Get record type as string
    pub fn record_type(&self) -> &'static str {
        match &self.data {
            DhtRecordData::NodeAd(_) => "NODE_AD",
            DhtRecordData::GroupBeacon(_) => "GROUP_BEACON",
            DhtRecordData::DataPointer(_) => "DATA_POINTER",
            DhtRecordData::RegisterPointer(_) => "REGISTER_POINTER",
        }
    }
}

/// Builder for creating DHT records
pub struct DhtRecordBuilder {
    key: Option<Hash>,
    ttl: Option<Duration>,
    pow_bits: Option<u8>,
}

impl DhtRecordBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            key: None,
            ttl: None,
            pow_bits: None,
        }
    }

    /// Set the record key
    pub fn key(mut self, key: Hash) -> Self {
        self.key = Some(key);
        self
    }

    /// Set the TTL
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set proof of work difficulty
    pub fn pow_bits(mut self, bits: u8) -> Self {
        self.pow_bits = Some(bits);
        self
    }

    /// Build a DHT record with node advertisement data
    pub fn build_node_ad(self, node_ad: NodeAd) -> P2pResult<DhtRecord> {
        let key = self
            .key
            .ok_or_else(|| P2PError::InvalidInput("Key is required".to_string()))?;

        let mut record = DhtRecord::new(key, DhtRecordData::NodeAd(node_ad), self.ttl);

        if let Some(bits) = self.pow_bits {
            record.compute_pow(bits)?;
        }

        Ok(record)
    }

    /// Build a DHT record with group beacon data
    pub fn build_group_beacon(self, group_beacon: GroupBeacon) -> P2pResult<DhtRecord> {
        let key = self
            .key
            .ok_or_else(|| P2PError::InvalidInput("Key is required".to_string()))?;

        let mut record = DhtRecord::new(key, DhtRecordData::GroupBeacon(group_beacon), self.ttl);

        if let Some(bits) = self.pow_bits {
            record.compute_pow(bits)?;
        }

        Ok(record)
    }

    /// Build a DHT record with data pointer data
    pub fn build_data_pointer(self, data_pointer: DataPointer) -> P2pResult<DhtRecord> {
        let key = self
            .key
            .ok_or_else(|| P2PError::InvalidInput("Key is required".to_string()))?;

        let mut record = DhtRecord::new(key, DhtRecordData::DataPointer(data_pointer), self.ttl);

        if let Some(bits) = self.pow_bits {
            record.compute_pow(bits)?;
        }

        Ok(record)
    }

    /// Build a DHT record with register pointer data
    pub fn build_register_pointer(self, register_pointer: RegisterPointer) -> P2pResult<DhtRecord> {
        let key = self
            .key
            .ok_or_else(|| P2PError::InvalidInput("Key is required".to_string()))?;

        let mut record = DhtRecord::new(
            key,
            DhtRecordData::RegisterPointer(register_pointer),
            self.ttl,
        );

        if let Some(bits) = self.pow_bits {
            record.compute_pow(bits)?;
        }

        Ok(record)
    }
}

impl Default for DhtRecordBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn test_node_capabilities_creation() {
        let caps = NodeCapabilities::new(1000, 500, 50).unwrap();
        assert_eq!(caps.disk_total, 1000);
        assert_eq!(caps.disk_free, 500);
        assert_eq!(caps.donor_pct, 50);
        assert_eq!(caps.disk_usage_pct(), 50);
        assert!(caps.has_free_space(400));
        assert!(!caps.has_free_space(600));
    }

    #[test]
    fn test_node_capabilities_validation() {
        // Invalid donor percentage
        assert!(NodeCapabilities::new(1000, 500, 101).is_err());

        // Free disk exceeds total
        assert!(NodeCapabilities::new(1000, 1500, 50).is_err());
    }

    #[test]
    fn test_os_signature() {
        let os_sig = OsSignature::new("linux".to_string(), "x86_64".to_string(), "5.4.0");
        assert_eq!(os_sig.family, "linux");
        assert_eq!(os_sig.arch, "x86_64");
        assert_eq!(os_sig.version_hash.len(), 8);
    }

    #[test]
    fn test_node_ad_creation() {
        let node_id = NodeId::from([1u8; 32]);
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
        let caps = NodeCapabilities::new(1000, 500, 50).unwrap();
        let os_sig = OsSignature::current();

        let node_ad = NodeAd::new(
            node_id,
            vec![addr],
            caps,
            NatType::None,
            12345,
            os_sig,
            [1u8; 16],
            [2u8; 16],
        )
        .unwrap();

        assert_eq!(node_ad.node_id, node_id);
        assert_eq!(node_ad.addrs.len(), 1);
        assert!(node_ad.is_valid());
    }

    #[test]
    fn test_node_ad_validation() {
        let node_id = NodeId::from([1u8; 32]);
        let caps = NodeCapabilities::new(1000, 500, 50).unwrap();
        let os_sig = OsSignature::current();

        // No addresses
        assert!(NodeAd::new(
            node_id,
            vec![],
            caps.clone(),
            NatType::None,
            12345,
            os_sig.clone(),
            [1u8; 16],
            [2u8; 16],
        )
        .is_err());

        // Too many addresses
        let many_addrs: Vec<SocketAddr> = (0..10)
            .map(|i| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080 + i)))
            .collect();

        assert!(NodeAd::new(
            node_id,
            many_addrs,
            caps,
            NatType::None,
            12345,
            os_sig,
            [1u8; 16],
            [2u8; 16],
        )
        .is_err());
    }

    #[test]
    fn test_group_beacon_creation() {
        let group_id = SerializableHash([3u8; 32]);
        let policy = PlacementPolicy::default();
        let member_root = SerializableHash::from(blake3::hash(b"members"));
        let guardians = vec![NodeId::from([4u8; 32]), NodeId::from([5u8; 32])];

        let beacon = GroupBeacon::new(group_id, policy, member_root, guardians).unwrap();
        assert_eq!(beacon.group_id, group_id);
        assert_eq!(beacon.guardians.len(), 2);
        assert!(beacon.is_valid());
    }

    #[test]
    fn test_data_pointer_creation() {
        let cid = blake3::hash(b"test content");
        let ticket_ids = vec![
            PlacementTicketId::from_bytes([6u8; 32]),
            PlacementTicketId::from_bytes([7u8; 32]),
        ];

        let pointer = DataPointer::new(cid, ticket_ids).unwrap();
        assert_eq!(pointer.cid, cid);
        assert_eq!(pointer.placement_ticket_ids.len(), 2);
        assert!(pointer.is_valid());
    }

    #[test]
    fn test_data_pointer_operations() {
        let cid = blake3::hash(b"test content");
        let ticket_id1 = PlacementTicketId::from_bytes([6u8; 32]);
        let ticket_id2 = PlacementTicketId::from_bytes([7u8; 32]);

        let mut pointer = DataPointer::new(cid, vec![ticket_id1]).unwrap();

        // Add ticket
        pointer.add_placement_ticket(ticket_id2).unwrap();
        assert_eq!(pointer.placement_ticket_ids.len(), 2);

        // Remove ticket
        pointer.remove_placement_ticket(&ticket_id1);
        assert_eq!(pointer.placement_ticket_ids.len(), 1);
        assert!(!pointer.placement_ticket_ids.contains(&ticket_id1));
    }

    #[test]
    fn test_register_pointer_creation() {
        let name_id = blake3::hash(b"test name");
        let root_ref = blake3::hash(b"content");

        let pointer = RegisterPointer::new(name_id, root_ref, 1).unwrap();
        assert_eq!(pointer.name_id, name_id);
        assert_eq!(pointer.root_ref, root_ref);
        assert_eq!(pointer.version, 1);
        assert!(pointer.is_valid());
    }

    #[test]
    fn test_register_pointer_version_update() {
        let name_id = blake3::hash(b"test name");
        let root_ref1 = blake3::hash(b"content v1");
        let root_ref2 = blake3::hash(b"content v2");

        let mut pointer = RegisterPointer::new(name_id, root_ref1, 1).unwrap();

        // Update to higher version
        pointer.update_version(root_ref2, 2).unwrap();
        assert_eq!(pointer.version, 2);
        assert_eq!(pointer.root_ref, root_ref2);

        // Cannot downgrade version
        assert!(pointer.update_version(root_ref1, 1).is_err());
    }

    #[test]
    fn test_dht_record_serialization() {
        let node_id = NodeId::from([1u8; 32]);
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
        let caps = NodeCapabilities::new(1000, 500, 50).unwrap();
        let os_sig = OsSignature::current();

        let node_ad = NodeAd::new(
            node_id,
            vec![addr],
            caps,
            NatType::None,
            12345,
            os_sig,
            [1u8; 16],
            [2u8; 16],
        )
        .unwrap();

        let key = blake3::hash(b"test key");
        let record = DhtRecord::new(key, DhtRecordData::NodeAd(node_ad), None);

        // Serialize
        let bytes = record.serialize().unwrap();
        assert!(bytes.len() <= MAX_RECORD_SIZE);

        // Deserialize
        let deserialized = DhtRecord::deserialize(&bytes).unwrap();
        assert_eq!(deserialized.key, record.key);
        assert!(matches!(deserialized.data, DhtRecordData::NodeAd(_)));
    }

    #[test]
    fn test_dht_record_proof_of_work() {
        let key = blake3::hash(b"test key");
        let cid = blake3::hash(b"test content");
        let ticket_ids = vec![PlacementTicketId::from_bytes([6u8; 32])];
        let pointer = DataPointer::new(cid, ticket_ids).unwrap();

        let mut record = DhtRecord::new(key, DhtRecordData::DataPointer(pointer), None);

        // Compute PoW with low difficulty for testing
        record.compute_pow(8).unwrap();
        assert!(record.pow_nonce.is_some());

        // Verify PoW
        assert!(record.verify_pow(8).unwrap());

        // Wrong difficulty should fail
        assert!(!record.verify_pow(16).unwrap());
    }

    #[test]
    fn test_dht_record_builder() {
        let key = blake3::hash(b"test key");
        let cid = blake3::hash(b"test content");
        let ticket_ids = vec![PlacementTicketId::from_bytes([6u8; 32])];
        let pointer = DataPointer::new(cid, ticket_ids).unwrap();

        let record = DhtRecordBuilder::new()
            .key(key)
            .ttl(Duration::from_secs(1800))
            .pow_bits(8)
            .build_data_pointer(pointer)
            .unwrap();

        assert_eq!(record.key, key);
        assert_eq!(record.ttl, 1800);
        assert!(record.pow_nonce.is_some());
        assert!(record.verify_pow(8).unwrap());
    }

    #[test]
    fn test_record_size_limit() {
        // Create a record that would exceed size limit
        let node_id = NodeId::from([1u8; 32]);
        let many_addrs: Vec<SocketAddr> = (0..100)
            .map(|i| {
                SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(127, 0, 0, 1),
                    8080 + (i % 65535) as u16,
                ))
            })
            .collect();

        // This should fail during NodeAd creation due to address limit
        let caps = NodeCapabilities::new(1000, 500, 50).unwrap();
        let os_sig = OsSignature::current();

        let result = NodeAd::new(
            node_id,
            many_addrs,
            caps,
            NatType::None,
            12345,
            os_sig,
            [1u8; 16],
            [2u8; 16],
        );

        assert!(result.is_err());
    }
}