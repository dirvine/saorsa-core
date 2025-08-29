//! Trust-weighted DHT trait definition
//!
//! Defines the interface for DHT operations with trust bias and capacity signaling.

use crate::identity::node_identity::NodeId;
use anyhow::Result;
use bytes::Bytes;
use std::time::Duration;

/// DHT key type (256-bit)
pub type Key = [u8; 32];

/// Peer identifier
pub type PeerId = NodeId;

/// Contact information for routing
#[derive(Debug, Clone)]
pub struct Contact {
    pub peer: PeerId,
    pub address: String,
}

/// PUT operation policy
#[derive(Debug, Clone)]
pub struct PutPolicy {
    pub ttl: Option<Duration>,
    pub quorum: usize,
}

/// PUT operation receipt
#[derive(Debug, Clone)]
pub struct PutReceipt {
    pub key: Key,
    pub providers: Vec<PeerId>,
    pub proof: Vec<u8>,
}

/// DHT trait for trust-weighted operations
#[async_trait::async_trait]
pub trait Dht {
    /// Store a value with the given policy
    async fn put(&self, key: Key, value: Bytes, policy: PutPolicy) -> Result<PutReceipt>;

    /// Retrieve a value with quorum requirement
    async fn get(&self, key: Key, quorum: usize) -> Result<Bytes>;

    /// Find nodes closest to the target
    async fn find_node(&self, target: PeerId) -> Result<Vec<Contact>>;

    /// Advertise that this node provides the given key
    async fn provide(&self, key: Key) -> Result<()>;
}

/// Interaction outcome for trust recording
#[derive(Debug, Clone, Copy)]
pub enum Outcome {
    Ok,
    Timeout,
    BadData,
    Refused,
}

/// Record an interaction outcome for trust computation
pub async fn record_interaction(_peer: PeerId, _outcome: Outcome) {
    // Global trust recording - would need access to DHT instance
    // This is a placeholder for the global function
}

/// Run EigenTrust computation epoch
pub async fn eigen_trust_epoch() {
    // Global EigenTrust computation - would need access to DHT instance
    // This is a placeholder for the global function
}
