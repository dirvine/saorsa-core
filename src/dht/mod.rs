//! Distributed Hash Table implementations
//!
//! This module provides various DHT implementations including:
//! - Trust-weighted Kademlia DHT with EigenTrust integration
//! - Core DHT engine with replication and fault tolerance
//! - Geographic routing and content addressing
//! - Capacity signaling and telemetry

pub mod capacity_signaling;
pub mod core_engine;
pub mod telemetry;
pub mod trust_weighted_dht;
pub mod trust_weighted_kademlia;

// Re-export the main DHT trait and types
pub use trust_weighted_dht::{
    Contact, Dht, Key, Outcome, PutPolicy, PutReceipt, eigen_trust_epoch, record_interaction,
};

// Re-export PeerId from trust_weighted_dht
pub use trust_weighted_dht::PeerId;

// Re-export the trust-weighted implementation
pub use trust_weighted_kademlia::TrustWeightedKademlia;

// Re-export capacity signaling
pub use capacity_signaling::{CapacityGossip, CapacityHistogram, CapacityManager, CapacityStats};

// Re-export telemetry
pub use telemetry::{DhtTelemetry, OperationStats, OperationType, TelemetryStats};

// Re-export replication grace period types
pub use replication_grace_period::{
    EndpointRegistration, FailedNodeInfo, NodeFailureReason, ReplicationError,
    ReplicationGracePeriodConfig,
};

// Re-export node failure tracker
pub use node_failure_tracker::{DefaultNodeFailureTracker, DhtClient, NodeFailureTracker};

// Re-export existing DHT components
pub use core_engine::{DhtCoreEngine, DhtKey, NodeCapacity, NodeId as DhtNodeId, NodeInfo};

// Legacy type aliases for backward compatibility
pub type DHT = DhtCoreEngine;
pub type DHTNode = NodeInfo;
pub type SerializableDHTNode = NodeInfo;

// Re-export types from trust_weighted_dht
pub use trust_weighted_dht::Key as DHT_Key;

// Import additional types for compatibility
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// DHT configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTConfig {
    /// Replication parameter (k) - number of nodes to store each record
    pub replication_factor: usize,
    /// Maximum nodes per k-bucket
    pub bucket_size: usize,
    /// Concurrency parameter for parallel lookups
    pub alpha: usize,
    /// Record expiration time
    pub record_ttl: Duration,
    /// Refresh interval for buckets
    pub bucket_refresh_interval: Duration,
    /// Republish interval for stored records
    pub republish_interval: Duration,
    /// Maximum distance for considering nodes "close"
    pub max_distance: u8,
}

impl Default for DHTConfig {
    fn default() -> Self {
        Self {
            replication_factor: 8,
            bucket_size: 20,
            alpha: 3,
            record_ttl: Duration::from_secs(3600),
            bucket_refresh_interval: Duration::from_secs(3600),
            republish_interval: Duration::from_secs(3600),
            max_distance: 160,
        }
    }
}

/// DHT record containing key-value data with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    /// Record key
    pub key: Key,
    /// Record value
    pub value: Vec<u8>,
    /// Publisher peer ID
    pub publisher: PeerId,
    /// Record creation time
    pub created_at: std::time::SystemTime,
    /// Record expiration time
    pub expires_at: std::time::SystemTime,
    /// Signature for verification (optional)
    pub signature: Option<Vec<u8>>,
}

impl Record {
    /// Create a new record
    pub fn new(key: Key, value: Vec<u8>, publisher: PeerId) -> Self {
        let now = std::time::SystemTime::now();
        Self {
            key,
            value,
            publisher,
            created_at: now,
            expires_at: now + std::time::Duration::from_secs(3600), // 1 hour default TTL
            signature: None,
        }
    }

    /// Check if the record has expired
    pub fn is_expired(&self) -> bool {
        std::time::SystemTime::now() > self.expires_at
    }
}

// Re-export other DHT modules
pub mod client;
pub mod content_addressing;
pub mod enhanced_storage;
pub mod geographic_network_integration;
pub mod geographic_routing;
pub mod geographic_routing_table;
pub mod latency_aware_selection;
pub mod network_integration;
pub mod node_failure_tracker;
pub mod optimized_storage;
pub mod reed_solomon;
pub mod replication_grace_period;
pub mod rsps_integration;
pub mod skademlia;
pub mod witness;
pub mod witness_client;
pub mod witness_protocol;
pub mod witness_selection;
pub mod witness_signer;

/// IPv6-based DHT identity for security parity
pub mod ipv6_identity;

/// IPv4-based DHT identity for security parity
pub mod ipv4_identity;

/// Cross-network replication for IPv4/IPv6 dual-stack redundancy
pub mod cross_network_replication;

/// Node age verification for anti-Sybil protection
pub mod node_age_verifier;

/// Witness collusion detection for Byzantine-robust consensus
pub mod collusion_detector;

/// Sybil attack detection for DHT protection
pub mod sybil_detector;

/// Authenticated sibling broadcast for eclipse attack prevention
pub mod authenticated_sibling_broadcast;

/// Routing table maintenance and node validation
pub mod routing_maintenance;

/// Comprehensive metrics for security, DHT health, trust, and placement
pub mod metrics;

// Re-export routing maintenance types for convenience
pub use routing_maintenance::{
    BucketRefreshManager, DataChallenge, EvictionManager, EvictionReason, MaintenanceConfig,
    MaintenanceScheduler, MaintenanceTask, NodeLivenessState, NodeValidationResult, RefreshTier,
    ValidationFailure, WitnessSelectionCriteria, compute_attested_hash,
};

// Re-export security coordinator types
pub use routing_maintenance::{
    CloseGroupEviction, CloseGroupEvictionTracker, EvictionRecord, SecurityCoordinator,
    SecurityCoordinatorConfig,
};

// Re-export close group validator types
pub use routing_maintenance::close_group_validator::{
    AttackIndicators, CloseGroupFailure, CloseGroupHistory, CloseGroupResponse,
    CloseGroupValidationResult, CloseGroupValidator, CloseGroupValidatorConfig,
};

// Re-export collusion detector types for witness validation
pub use collusion_detector::{
    CollusionDetector, CollusionDetectorConfig, CollusionEvidence, CollusionGroup, VotingPattern,
    VotingRecord,
};

// Re-export sybil detector types for DHT protection
pub use sybil_detector::{
    BehaviorProfile, JoinRecord, SybilDetector, SybilDetectorConfig, SybilEvidence, SybilGroup,
};

// Re-export authenticated sibling broadcast types
pub use authenticated_sibling_broadcast::{
    AuthenticatedSiblingBroadcast, BroadcastValidationFailure, BroadcastValidationResult,
    MembershipProof, MembershipProofType, SiblingBroadcastBuilder, SiblingBroadcastConfig,
    SiblingBroadcastValidator, SignedSiblingEntry,
};

// Re-export comprehensive metrics types for security, DHT health, trust, and placement
pub use metrics::{
    DhtHealthMetrics, DhtMetricsAggregator, DhtMetricsCollector, MetricsSummary, PlacementMetrics,
    PlacementMetricsCollector, SecurityMetrics, SecurityMetricsCollector, TrustMetrics,
    TrustMetricsCollector,
};
