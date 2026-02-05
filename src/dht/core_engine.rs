//! Enhanced DHT Core Engine with Kademlia routing and intelligent data distribution
//!
//! Provides the main DHT functionality with k=8 replication, load balancing, and fault tolerance.

#[cfg(feature = "adaptive-ml")]
use crate::adaptive::EigenTrustEngine;
use crate::dht::geographic_routing::GeographicRegion;
use crate::dht::metrics::SecurityMetricsCollector;
use crate::dht::network_integration::{DhtMessage, DhtResponse};
use crate::dht::routing_maintenance::close_group_validator::{
    CloseGroupEnforcementMode, CloseGroupFailure, CloseGroupValidator, CloseGroupValidatorConfig,
};
use crate::dht::routing_maintenance::{
    BucketRefreshManager, EvictionManager, EvictionReason, MaintenanceConfig,
};
#[cfg(feature = "adaptive-ml")]
use crate::dht::trust_peer_selector::{TrustAwarePeerSelector, TrustSelectionConfig};
use crate::network::NetworkSender;
use crate::security::{IPDiversityConfig, IPDiversityEnforcer};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{RwLock, oneshot};
use uuid::Uuid;

/// DHT key type (256-bit)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DhtKey([u8; 32]);

impl DhtKey {
    pub fn new(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Self(*hash.as_bytes())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Generate a random DhtKey (useful for testing and key generation)
    #[must_use]
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        Self(bytes)
    }

    /// XOR distance metric for Kademlia
    pub fn distance(&self, other: &DhtKey) -> [u8; 32] {
        let mut result = [0u8; 32];
        for (i, out) in result.iter_mut().enumerate() {
            *out = self.0[i] ^ other.0[i];
        }
        result
    }
}

/// Node identifier in the DHT
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(DhtKey);

impl NodeId {
    pub fn random() -> Self {
        let random_bytes: [u8; 32] = rand::random();
        Self(DhtKey::from_bytes(random_bytes))
    }

    pub fn from_key(key: DhtKey) -> Self {
        Self(key)
    }

    /// Backwards-compat helper for tests expecting from_bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(DhtKey::from_bytes(bytes))
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

/// Node information for routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: NodeId,
    pub address: String,
    pub last_seen: SystemTime,
    pub capacity: NodeCapacity,
}

/// Node capacity metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapacity {
    pub storage_available: u64,
    pub bandwidth_available: u64,
    pub reliability_score: f64,
}

impl Default for NodeCapacity {
    fn default() -> Self {
        Self {
            storage_available: 1_000_000_000, // 1GB
            bandwidth_available: 10_000_000,  // 10MB/s
            reliability_score: 1.0,
        }
    }
}

/// K-bucket for Kademlia routing
struct KBucket {
    nodes: Vec<NodeInfo>,
    max_size: usize,
}

impl KBucket {
    fn new(max_size: usize) -> Self {
        Self {
            nodes: Vec::new(),
            max_size,
        }
    }

    fn add_node(&mut self, node: NodeInfo) -> Result<()> {
        if self.nodes.len() < self.max_size {
            self.nodes.push(node);
            Ok(())
        } else {
            Err(anyhow!(
                "K-bucket at capacity ({}/{})",
                self.nodes.len(),
                self.max_size
            ))
        }
    }

    fn remove_node(&mut self, node_id: &NodeId) {
        self.nodes.retain(|n| &n.id != node_id);
    }

    fn get_nodes(&self) -> &[NodeInfo] {
        &self.nodes
    }
}

/// Kademlia routing table
pub struct KademliaRoutingTable {
    buckets: Vec<KBucket>,
    node_id: NodeId,
    _k_value: usize,
}

impl KademliaRoutingTable {
    fn new(node_id: NodeId, k_value: usize) -> Self {
        let mut buckets = Vec::new();
        for _ in 0..256 {
            buckets.push(KBucket::new(k_value));
        }

        Self {
            buckets,
            node_id,
            _k_value: k_value,
        }
    }

    fn add_node(&mut self, node: NodeInfo) -> Result<()> {
        let bucket_index = self.get_bucket_index(&node.id);
        self.buckets[bucket_index].add_node(node)
    }

    fn remove_node(&mut self, node_id: &NodeId) {
        let bucket_index = self.get_bucket_index(node_id);
        self.buckets[bucket_index].remove_node(node_id);
    }

    fn find_closest_nodes(&self, key: &DhtKey, count: usize) -> Vec<NodeInfo> {
        // Optimization: Start from the bucket closest to the key and work outwards
        // This avoids collecting all nodes from all 256 buckets when we only need a few
        let target_bucket = self.get_bucket_index_for_key(key);

        let mut candidates: Vec<(NodeInfo, [u8; 32])> = Vec::with_capacity(count * 2);

        // Collect from target bucket first, then expand outwards
        for offset in 0..256 {
            // Check bucket above target (or at target when offset == 0)
            let bucket_above = target_bucket.saturating_add(offset).min(255);
            for node in self.buckets[bucket_above].get_nodes() {
                let distance = node.id.0.distance(key);
                candidates.push((node.clone(), distance));
            }

            // Check bucket below target (skip when offset == 0 to avoid duplicate)
            if offset > 0 {
                let bucket_below = target_bucket.saturating_sub(offset);
                // Only check if it's a different bucket (saturating_sub may equal target_bucket)
                if bucket_below != bucket_above {
                    for node in self.buckets[bucket_below].get_nodes() {
                        let distance = node.id.0.distance(key);
                        candidates.push((node.clone(), distance));
                    }
                }
            }

            // Early exit: if we have enough candidates, we can stop expanding
            if candidates.len() >= count * 2 {
                break;
            }
        }

        // Sort by distance
        candidates.sort_by(|a, b| a.1.cmp(&b.1));

        // Return top `count` nodes
        candidates
            .into_iter()
            .take(count)
            .map(|(node, _)| node)
            .collect()
    }

    fn get_bucket_index_for_key(&self, key: &DhtKey) -> usize {
        let distance = self.node_id.0.distance(key);

        // Find first bit that differs
        for i in 0..256 {
            let byte_index = i / 8;
            let bit_index = 7 - (i % 8);

            if (distance[byte_index] >> bit_index) & 1 == 1 {
                return i;
            }
        }

        255 // Same key as node
    }

    fn get_bucket_index(&self, node_id: &NodeId) -> usize {
        let distance = self.node_id.0.distance(&node_id.0);

        // Find first bit that differs
        for i in 0..256 {
            let byte_index = i / 8;
            let bit_index = 7 - (i % 8);

            if (distance[byte_index] >> bit_index) & 1 == 1 {
                return i;
            }
        }

        255 // Same node
    }
}

/// Consistency level for operations
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ConsistencyLevel {
    One,    // At least 1 replica
    Quorum, // Majority of replicas
    All,    // All replicas
}

/// Load metrics for a node
#[derive(Debug, Clone)]
pub struct LoadMetric {
    pub storage_used_percent: f64,
    pub bandwidth_used_percent: f64,
    pub request_rate: f64,
}

/// Store receipt for DHT operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreReceipt {
    pub key: DhtKey,
    pub stored_at: Vec<NodeId>,
    pub timestamp: SystemTime,
    pub success: bool,
}

impl StoreReceipt {
    pub fn is_successful(&self) -> bool {
        self.success
    }
}

/// Data store for local storage
struct DataStore {
    data: HashMap<DhtKey, Vec<u8>>,
    metadata: HashMap<DhtKey, DataMetadata>,
}

#[derive(Debug, Clone)]
struct DataMetadata {
    _size: usize,
    _stored_at: SystemTime,
    access_count: u64,
    last_accessed: SystemTime,
}

impl DataStore {
    fn new() -> Self {
        Self {
            data: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    fn put(&mut self, key: DhtKey, value: Vec<u8>) {
        let metadata = DataMetadata {
            _size: value.len(),
            _stored_at: SystemTime::now(),
            access_count: 0,
            last_accessed: SystemTime::now(),
        };

        self.data.insert(key.clone(), value);
        self.metadata.insert(key, metadata);
    }

    fn get(&mut self, key: &DhtKey) -> Option<Vec<u8>> {
        if let Some(metadata) = self.metadata.get_mut(key) {
            metadata.access_count += 1;
            metadata.last_accessed = SystemTime::now();
        }

        self.data.get(key).cloned()
    }

    fn _remove(&mut self, key: &DhtKey) -> Option<Vec<u8>> {
        self.metadata.remove(key);
        self.data.remove(key)
    }
}

/// Replication manager for maintaining data redundancy
struct ReplicationManager {
    _replication_factor: usize,
    _consistency_level: ConsistencyLevel,
    _pending_repairs: Vec<DhtKey>,
}

impl ReplicationManager {
    fn new(replication_factor: usize) -> Self {
        Self {
            _replication_factor: replication_factor,
            _consistency_level: ConsistencyLevel::Quorum,
            _pending_repairs: Vec::new(),
        }
    }

    fn _required_replicas(&self) -> usize {
        match self._consistency_level {
            ConsistencyLevel::One => 1,
            // Quorum requires strict majority for Byzantine fault tolerance: floor(n/2) + 1
            // For K=8, this gives 5 (tolerates 3 failures). This is intentionally stricter
            // than simple majority (div_ceil which gives 4) to ensure BFT guarantees.
            ConsistencyLevel::Quorum => (self._replication_factor / 2) + 1,
            ConsistencyLevel::All => self._replication_factor,
        }
    }

    fn _schedule_repair(&mut self, key: DhtKey) {
        if !self._pending_repairs.contains(&key) {
            self._pending_repairs.push(key);
        }
    }
}

/// Load balancer for intelligent data distribution
struct LoadBalancer {
    node_loads: HashMap<NodeId, LoadMetric>,
    _rebalance_threshold: f64,
}

impl LoadBalancer {
    fn new() -> Self {
        Self {
            node_loads: HashMap::new(),
            _rebalance_threshold: 0.8,
        }
    }

    fn _update_load(&mut self, node_id: NodeId, load: LoadMetric) {
        self.node_loads.insert(node_id, load);
    }

    fn select_least_loaded(&self, candidates: &[NodeInfo], count: usize) -> Vec<NodeId> {
        // Filter NaN values during collection to avoid intermediate allocations with invalid data
        let mut sorted: Vec<_> = candidates
            .iter()
            .filter_map(|node| {
                let load = self
                    .node_loads
                    .get(&node.id)
                    .map(|l| l.storage_used_percent)
                    .unwrap_or(0.0);
                // Filter NaN during collection rather than after
                if load.is_nan() {
                    None
                } else {
                    Some((node.id.clone(), load))
                }
            })
            .collect();

        // Use total_cmp for safe float comparison
        sorted.sort_by(|a, b| a.1.total_cmp(&b.1));

        sorted.into_iter().take(count).map(|(id, _)| id).collect()
    }

    fn _should_rebalance(&self) -> bool {
        self.node_loads
            .values()
            .any(|load| load.storage_used_percent > self._rebalance_threshold)
    }
}

/// Geographic diversity enforcer for routing table
/// Limits the number of nodes from any single region to prevent geographic concentration attacks
struct GeographicDiversityEnforcer {
    region_counts: HashMap<GeographicRegion, usize>,
    max_per_region: usize,
}

impl GeographicDiversityEnforcer {
    fn new(max_per_region: usize) -> Self {
        Self {
            region_counts: HashMap::new(),
            max_per_region,
        }
    }

    fn can_accept(&self, region: GeographicRegion) -> bool {
        let count = self.region_counts.get(&region).copied().unwrap_or(0);
        count < self.max_per_region
    }

    fn add(&mut self, region: GeographicRegion) {
        *self.region_counts.entry(region).or_insert(0) += 1;
    }

    fn _remove(&mut self, region: GeographicRegion) {
        if let Some(count) = self.region_counts.get_mut(&region) {
            *count = count.saturating_sub(1);
        }
    }
}

/// DHT query timeout duration
const DHT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Alpha parameter from Kademlia - max parallel queries
const MAX_PARALLEL_QUERIES: usize = 3;

/// K parameter - replication factor
const K: usize = 8;

/// Maximum value size for DHT store operations (1 MB)
/// Prevents memory exhaustion from malicious oversized values
const MAX_DHT_VALUE_SIZE: usize = 1024 * 1024;

/// Maximum node count for FindNode requests
/// Prevents amplification attacks by limiting response size
const MAX_FIND_NODE_COUNT: usize = 20;

/// DHT request wrapper with request ID for correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtRequestWrapper {
    /// Unique request ID for response correlation
    pub id: String,
    /// The underlying DHT message
    pub message: DhtMessage,
}

/// DHT response wrapper with request ID for correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtResponseWrapper {
    /// Request ID this response corresponds to
    pub id: String,
    /// The underlying DHT response
    pub response: DhtResponse,
}

/// Main DHT Core Engine
pub struct DhtCoreEngine {
    node_id: NodeId,
    routing_table: Arc<RwLock<KademliaRoutingTable>>,
    data_store: Arc<RwLock<DataStore>>,
    replication_manager: Arc<RwLock<ReplicationManager>>,
    load_balancer: Arc<RwLock<LoadBalancer>>,

    // Security Components
    security_metrics: Arc<SecurityMetricsCollector>,
    bucket_refresh_manager: Arc<RwLock<BucketRefreshManager>>,
    close_group_validator: Arc<RwLock<CloseGroupValidator>>,
    ip_diversity_enforcer: Arc<RwLock<IPDiversityEnforcer>>,
    eviction_manager: Arc<RwLock<EvictionManager>>,
    geographic_diversity_enforcer: Arc<RwLock<GeographicDiversityEnforcer>>,

    // Network query components
    /// Transport handle for sending messages to remote peers
    transport: Option<Arc<dyn NetworkSender>>,
    /// Pending requests waiting for responses (request_id -> response sender)
    pending_requests: Arc<RwLock<HashMap<String, oneshot::Sender<DhtResponse>>>>,

    // Trust-weighted peer selection (requires adaptive-ml feature)
    #[cfg(feature = "adaptive-ml")]
    /// Optional trust-aware peer selector for combining distance with trust scores
    trust_peer_selector: Option<TrustAwarePeerSelector<EigenTrustEngine>>,
}

impl DhtCoreEngine {
    /// Create new DHT engine with specified node ID
    pub fn new(node_id: NodeId) -> Result<Self> {
        Self::new_with_validation_mode(node_id, CloseGroupEnforcementMode::Strict)
    }

    /// Create new DHT engine for testing (permissive validation)
    #[cfg(test)]
    pub fn new_for_tests(node_id: NodeId) -> Result<Self> {
        Self::new_with_validation_mode(node_id, CloseGroupEnforcementMode::LogOnly)
    }

    /// Create new DHT engine with specified validation mode
    fn new_with_validation_mode(
        node_id: NodeId,
        enforcement_mode: CloseGroupEnforcementMode,
    ) -> Result<Self> {
        // Initialize security components
        let security_metrics = Arc::new(SecurityMetricsCollector::new());
        let validator_config =
            CloseGroupValidatorConfig::default().with_enforcement_mode(enforcement_mode);
        let close_group_validator = Arc::new(RwLock::new(CloseGroupValidator::new(
            validator_config.clone(),
        )));

        let mut bucket_refresh_manager = BucketRefreshManager::new_with_validation(
            node_id.clone(),
            CloseGroupValidatorConfig::default(),
        );
        // Link validator to refresh manager
        bucket_refresh_manager.set_validator(close_group_validator.clone());
        let bucket_refresh_manager = Arc::new(RwLock::new(bucket_refresh_manager));

        let ip_diversity_enforcer = Arc::new(RwLock::new(IPDiversityEnforcer::new(
            IPDiversityConfig::default(),
        )));

        let eviction_manager = Arc::new(RwLock::new(EvictionManager::new(
            MaintenanceConfig::default(),
        )));

        // Geographic diversity: limit to 50 nodes per region (matches GeographicRoutingConfig default)
        let geographic_diversity_enforcer =
            Arc::new(RwLock::new(GeographicDiversityEnforcer::new(50)));

        Ok(Self {
            node_id: node_id.clone(),
            routing_table: Arc::new(RwLock::new(KademliaRoutingTable::new(node_id, K))),
            data_store: Arc::new(RwLock::new(DataStore::new())),
            replication_manager: Arc::new(RwLock::new(ReplicationManager::new(K))),
            load_balancer: Arc::new(RwLock::new(LoadBalancer::new())),
            security_metrics,
            bucket_refresh_manager,
            close_group_validator,
            ip_diversity_enforcer,
            eviction_manager,
            geographic_diversity_enforcer,
            transport: None,
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "adaptive-ml")]
            trust_peer_selector: None,
        })
    }

    /// Set the transport handle for network operations
    ///
    /// Once set, `retrieve()` will query remote peers when a key is not found locally.
    pub fn set_transport(&mut self, transport: Arc<dyn NetworkSender>) {
        self.transport = Some(transport);
    }

    /// Check if network operations are available
    #[must_use]
    pub fn has_transport(&self) -> bool {
        self.transport.is_some()
    }

    /// Get this node's ID
    #[must_use]
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // ===== Trust-weighted peer selection methods (requires adaptive-ml feature) =====

    #[cfg(feature = "adaptive-ml")]
    /// Enable trust-weighted peer selection
    ///
    /// When enabled, peer selection for DHT operations will combine XOR distance
    /// with EigenTrust scores to prefer higher-trust nodes.
    ///
    /// # Arguments
    /// * `trust_engine` - The EigenTrust engine providing trust scores
    /// * `config` - Configuration for trust selection behavior
    pub fn enable_trust_selection(
        &mut self,
        trust_engine: Arc<EigenTrustEngine>,
        config: TrustSelectionConfig,
    ) {
        self.trust_peer_selector = Some(TrustAwarePeerSelector::new(trust_engine, config));
        tracing::info!("DHT trust-weighted peer selection enabled");
    }

    #[cfg(feature = "adaptive-ml")]
    /// Enable trust-weighted peer selection with separate configs for queries and storage
    ///
    /// Storage operations use stricter trust requirements since data persistence
    /// depends on node reliability.
    pub fn enable_trust_selection_with_storage_config(
        &mut self,
        trust_engine: Arc<EigenTrustEngine>,
        query_config: TrustSelectionConfig,
        storage_config: TrustSelectionConfig,
    ) {
        self.trust_peer_selector = Some(TrustAwarePeerSelector::with_storage_config(
            trust_engine,
            query_config,
            storage_config,
        ));
        tracing::info!("DHT trust-weighted peer selection enabled with separate storage config");
    }

    #[cfg(feature = "adaptive-ml")]
    /// Disable trust-weighted peer selection
    ///
    /// Falls back to pure distance-based selection.
    pub fn disable_trust_selection(&mut self) {
        self.trust_peer_selector = None;
        tracing::info!("DHT trust-weighted peer selection disabled");
    }

    #[cfg(feature = "adaptive-ml")]
    /// Check if trust-weighted peer selection is enabled
    #[must_use]
    pub fn has_trust_selection(&self) -> bool {
        self.trust_peer_selector.is_some()
    }

    #[cfg(feature = "adaptive-ml")]
    /// Select peers for a query operation, considering trust if enabled
    ///
    /// If trust selection is enabled, combines XOR distance with trust scores.
    /// Otherwise, returns closest nodes by XOR distance only.
    async fn select_query_peers(&self, key: &DhtKey, count: usize) -> Vec<NodeInfo> {
        let routing = self.routing_table.read().await;
        // Get 2x candidates to allow trust-based filtering
        let candidates = routing.find_closest_nodes(key, count * 2);
        drop(routing);

        if let Some(ref selector) = self.trust_peer_selector {
            selector.select_peers(key, &candidates, count)
        } else {
            // Fallback: take closest by distance
            candidates.into_iter().take(count).collect()
        }
    }

    #[cfg(feature = "adaptive-ml")]
    /// Select peers for a storage operation, considering trust if enabled
    ///
    /// Storage operations use stricter trust requirements when trust selection
    /// is enabled, as data persistence depends on node reliability.
    async fn select_storage_peers(&self, key: &DhtKey, count: usize) -> Vec<NodeInfo> {
        let routing = self.routing_table.read().await;
        // Get 3x candidates for storage to allow stricter trust filtering
        let candidates = routing.find_closest_nodes(key, count * 3);
        drop(routing);

        if let Some(ref selector) = self.trust_peer_selector {
            selector.select_storage_peers(key, &candidates, count)
        } else {
            // Fallback: take closest by distance
            candidates.into_iter().take(count).collect()
        }
    }

    // ===== Fallback methods when adaptive-ml feature is disabled =====

    #[cfg(not(feature = "adaptive-ml"))]
    /// Check if trust-weighted peer selection is enabled (always false without adaptive-ml feature)
    #[must_use]
    pub fn has_trust_selection(&self) -> bool {
        false
    }

    #[cfg(not(feature = "adaptive-ml"))]
    /// Select peers for a query operation (distance-only when adaptive-ml is disabled)
    async fn select_query_peers(&self, key: &DhtKey, count: usize) -> Vec<NodeInfo> {
        let routing = self.routing_table.read().await;
        let candidates = routing.find_closest_nodes(key, count);
        drop(routing);
        candidates
    }

    #[cfg(not(feature = "adaptive-ml"))]
    /// Select peers for a storage operation (distance-only when adaptive-ml is disabled)
    async fn select_storage_peers(&self, key: &DhtKey, count: usize) -> Vec<NodeInfo> {
        let routing = self.routing_table.read().await;
        let candidates = routing.find_closest_nodes(key, count);
        drop(routing);
        candidates
    }

    /// Start background maintenance tasks for security and health
    pub fn start_maintenance_tasks(&self) {
        let refresh_manager = self.bucket_refresh_manager.clone();
        let eviction_manager = self.eviction_manager.clone();
        let close_group_validator = self.close_group_validator.clone();
        let security_metrics = self.security_metrics.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;

                // 1. Run Bucket Refresh Logic with Validation Integration
                {
                    let mut mgr = refresh_manager.write().await;

                    // Check for attack mode escalation based on validation failures
                    if mgr.should_trigger_attack_mode() {
                        if let Some(validator) = mgr.validator() {
                            validator.write().await.escalate_to_bft();
                            tracing::warn!(
                                "Escalating to BFT mode due to validation failures (rate: {:.2}%)",
                                mgr.overall_validation_rate() * 100.0
                            );
                        }
                    } else if let Some(validator) = mgr.validator() {
                        // De-escalate if validation rate recovers above 85%
                        if mgr.overall_validation_rate() > 0.85 {
                            validator.write().await.deescalate_from_bft();
                        }
                    }

                    // Get buckets needing refresh
                    let buckets = mgr.get_buckets_needing_refresh();
                    if !buckets.is_empty() {
                        // Get buckets that also need validation
                        let validation_buckets = mgr.get_buckets_needing_validation();
                        let mut total_validated = 0usize;
                        let mut total_evicted = 0usize;

                        for bucket in buckets {
                            // Record refresh (in a real impl, trigger network lookups first)
                            mgr.record_refresh_success(bucket, 0);

                            // Perform trust-based validation during refresh
                            if validation_buckets.contains(&bucket) {
                                // Get nodes that need validation from the refresh manager
                                let nodes_to_validate = mgr.get_nodes_in_bucket(bucket);

                                // Validate each node using trust-based validation
                                let validator = close_group_validator.read().await;
                                let mut evict_list = Vec::new();

                                for node_id in &nodes_to_validate {
                                    // Query trust score from eviction manager's trust cache
                                    // This cache is populated by EigenTrust updates via update_trust_score()
                                    let trust_score = {
                                        let evict_mgr = eviction_manager.read().await;
                                        evict_mgr.get_trust_score(node_id)
                                    };

                                    let (is_valid, failure_reason) =
                                        validator.validate_trust_only(node_id, trust_score);

                                    if !is_valid && let Some(reason) = failure_reason {
                                        tracing::info!(
                                            node_id = ?node_id,
                                            bucket = bucket,
                                            reason = ?reason,
                                            "Node failed validation during refresh"
                                        );
                                        evict_list.push((
                                            node_id.clone(),
                                            EvictionReason::CloseGroupRejection,
                                        ));
                                    }
                                }
                                drop(validator);

                                total_validated += nodes_to_validate.len();

                                // Queue evictions
                                if !evict_list.is_empty() {
                                    let mut evict_mgr = eviction_manager.write().await;
                                    for (node_id, reason) in evict_list {
                                        evict_mgr.record_eviction(&node_id, reason);
                                        total_evicted += 1;
                                    }
                                }

                                // Record validation metrics
                                let nodes_count = nodes_to_validate.len();
                                mgr.record_validation_result(bucket, nodes_count, 0);

                                tracing::debug!(
                                    bucket = bucket,
                                    nodes_validated = nodes_count,
                                    "Bucket validation completed during refresh"
                                );
                            }
                        }

                        // Update security metrics
                        if total_validated > 0 || total_evicted > 0 {
                            security_metrics
                                .record_validation_during_refresh(total_validated, total_evicted);
                            tracing::info!(
                                total_validated = total_validated,
                                total_evicted = total_evicted,
                                "Refresh validation cycle completed"
                            );
                        }
                    }
                }

                // 2. Active Eviction Enforcement
                {
                    let mut eviction_mgr = eviction_manager.write().await;
                    let candidates = eviction_mgr.get_eviction_candidates();
                    for (node_id, reason) in candidates {
                        tracing::warn!("Evicting node {} for reason: {:?}", node_id, reason);
                        // Remove from eviction tracking (routing table removal
                        // would be triggered by the caller or a separate mechanism)
                        eviction_mgr.remove_node(&node_id);
                    }
                }

                // 4. Update Metrics
                // (Example: update churn rate)
                // metrics.update_churn(...)
            }
        });
    }

    /// Get the security metrics collector
    pub fn security_metrics(&self) -> Arc<SecurityMetricsCollector> {
        self.security_metrics.clone()
    }

    /// Store data in the DHT
    ///
    /// When trust-weighted selection is enabled, storage targets are selected
    /// by combining XOR distance with trust scores, using stricter requirements
    /// than query operations since data persistence depends on node reliability.
    ///
    /// # Errors
    /// Returns an error if the value exceeds `MAX_DHT_VALUE_SIZE` (1 MB).
    pub async fn store(&mut self, key: &DhtKey, value: Vec<u8>) -> Result<StoreReceipt> {
        // Security: Reject oversized values to prevent memory exhaustion
        if value.len() > MAX_DHT_VALUE_SIZE {
            return Err(anyhow::anyhow!(
                "Value too large: {} bytes (max: {} bytes)",
                value.len(),
                MAX_DHT_VALUE_SIZE
            ));
        }

        // Find nodes to store at using trust-aware selection if enabled
        let target_nodes = self.select_storage_peers(key, K).await;

        // Select nodes based on load (secondary filter)
        let load_balancer = self.load_balancer.read().await;
        let selected_nodes = load_balancer.select_least_loaded(&target_nodes, K);

        tracing::debug!(
            key = ?hex::encode(key.as_bytes()),
            num_targets = selected_nodes.len(),
            trust_selection = self.has_trust_selection(),
            "Selected storage targets"
        );

        // Store locally if we're one of the selected nodes or if no nodes are available (test/single-node mode)
        if selected_nodes.contains(&self.node_id) || selected_nodes.is_empty() {
            let mut store = self.data_store.write().await;
            // Avoid unnecessary clone of value: key is cloned for ownership, value is consumed by this branch
            store.put(key.clone(), value);
            // Return early since we've consumed value
            return Ok(StoreReceipt {
                key: key.clone(),
                stored_at: selected_nodes,
                timestamp: SystemTime::now(),
                success: true,
            });
        }

        Ok(StoreReceipt {
            key: key.clone(),
            stored_at: selected_nodes,
            timestamp: SystemTime::now(),
            success: true,
        })
    }

    /// Retrieve data from the DHT
    ///
    /// First checks local storage. If not found locally and a transport is configured,
    /// queries the K closest nodes in parallel and returns the first successful response.
    pub async fn retrieve(&self, key: &DhtKey) -> Result<Option<Vec<u8>>> {
        // Step 1: Check local store first
        {
            let mut store = self.data_store.write().await;
            if let Some(value) = store.get(key) {
                tracing::debug!(key = ?hex::encode(key.as_bytes()), "Key found in local store");
                return Ok(Some(value));
            }
        }

        // Step 2: Get transport or return None if not available
        let transport = match &self.transport {
            Some(t) => Arc::clone(t),
            None => {
                tracing::debug!("No transport available for network query");
                return Ok(None);
            }
        };

        // Step 3: Select peers using trust-aware selection if enabled
        let closest_nodes = self.select_query_peers(key, K).await;

        if closest_nodes.is_empty() {
            tracing::debug!("No nodes in routing table to query");
            return Ok(None);
        }

        tracing::debug!(
            key = ?hex::encode(key.as_bytes()),
            num_nodes = closest_nodes.len().min(MAX_PARALLEL_QUERIES),
            trust_selection = self.has_trust_selection(),
            "Querying nodes for key"
        );

        // Step 4: Query nodes in parallel (up to alpha at a time)
        let nodes_to_query: Vec<_> = closest_nodes
            .into_iter()
            .take(MAX_PARALLEL_QUERIES)
            .collect();

        let query_futures: Vec<_> = nodes_to_query
            .iter()
            .map(|node| self.query_node_for_key(Arc::clone(&transport), node, key))
            .collect();

        // Step 5: Wait for responses with timeout
        let results =
            tokio::time::timeout(DHT_QUERY_TIMEOUT, futures::future::join_all(query_futures)).await;

        match results {
            Ok(responses) => {
                // Return first successful response
                for response in responses {
                    if let Ok(Some(value)) = response {
                        tracing::debug!(key = ?hex::encode(key.as_bytes()), "Key found on remote node");
                        return Ok(Some(value));
                    }
                }
                tracing::debug!(key = ?hex::encode(key.as_bytes()), "Key not found on any queried node");
                Ok(None)
            }
            Err(_timeout) => {
                tracing::warn!(key = ?hex::encode(key.as_bytes()), "DHT query timed out");
                Ok(None)
            }
        }
    }

    /// Query a single node for a key value
    async fn query_node_for_key(
        &self,
        transport: Arc<dyn NetworkSender>,
        node: &NodeInfo,
        key: &DhtKey,
    ) -> Result<Option<Vec<u8>>> {
        // Generate unique request ID
        let request_id = Uuid::new_v4().to_string();

        // Create response channel
        let (tx, rx) = oneshot::channel();

        // Register pending request
        {
            let mut pending = self.pending_requests.write().await;
            pending.insert(request_id.clone(), tx);
        }

        // Create the DHT message
        let message = DhtMessage::Retrieve {
            key: key.clone(),
            consistency: ConsistencyLevel::One,
        };

        // Wrap with request ID
        let wrapped_request = DhtRequestWrapper {
            id: request_id.clone(),
            message,
        };

        // Serialize the request using postcard
        let request_bytes = match postcard::to_stdvec(&wrapped_request) {
            Ok(bytes) => bytes,
            Err(e) => {
                // Clean up pending request
                let mut pending = self.pending_requests.write().await;
                pending.remove(&request_id);
                return Err(anyhow!(
                    "Failed to serialize DHT request for key {}: {e}",
                    hex::encode(key.as_bytes())
                ));
            }
        };

        // Convert node ID to peer ID string
        let peer_id = node.id.to_string();

        // Send request via transport
        if let Err(e) = transport
            .send_message(&peer_id, "/dht/1.0.0", request_bytes)
            .await
        {
            // Clean up pending request
            let mut pending = self.pending_requests.write().await;
            pending.remove(&request_id);
            tracing::debug!(peer_id = %peer_id, error = %e, "Failed to send DHT request");
            return Err(anyhow!("Failed to send DHT request to peer {peer_id}: {e}"));
        }

        // Wait for response with timeout
        match tokio::time::timeout(DHT_QUERY_TIMEOUT, rx).await {
            Ok(Ok(response)) => {
                // Clean up happens automatically when channel completes
                match response {
                    DhtResponse::RetrieveReply { value } => Ok(value),
                    DhtResponse::Error { message, .. } => {
                        tracing::debug!(peer_id = %peer_id, error = %message, "DHT error response");
                        Ok(None)
                    }
                    _ => {
                        tracing::debug!(peer_id = %peer_id, "Unexpected DHT response type");
                        Ok(None)
                    }
                }
            }
            Ok(Err(_recv_error)) => {
                // Channel closed without response
                tracing::debug!(peer_id = %peer_id, "Response channel closed");
                Ok(None)
            }
            Err(_timeout) => {
                // Timeout - clean up pending request
                let mut pending = self.pending_requests.write().await;
                pending.remove(&request_id);
                tracing::debug!(peer_id = %peer_id, "DHT request timed out");
                Ok(None)
            }
        }
    }

    /// Handle an incoming DHT response from the network
    ///
    /// This method should be called by the transport layer when a DHT response
    /// message is received. It routes the response to the waiting caller.
    pub async fn handle_response(&self, response_wrapper: DhtResponseWrapper) {
        let mut pending = self.pending_requests.write().await;
        if let Some(tx) = pending.remove(&response_wrapper.id) {
            // Send response - log if receiver dropped (timeout or cancelled request)
            if tx.send(response_wrapper.response).is_err() {
                tracing::debug!(
                    request_id = %response_wrapper.id,
                    "Response receiver dropped (request likely timed out)"
                );
            }
        } else {
            tracing::trace!(
                request_id = %response_wrapper.id,
                "Received response for unknown or timed-out request"
            );
        }
    }

    /// Handle an incoming DHT request from the network
    ///
    /// Processes the request and returns a response wrapper ready to be sent back.
    pub async fn handle_request(&self, request_wrapper: DhtRequestWrapper) -> DhtResponseWrapper {
        let response = match request_wrapper.message {
            DhtMessage::Retrieve { ref key, .. } => match self.data_store.write().await.get(key) {
                Some(value) => DhtResponse::RetrieveReply { value: Some(value) },
                None => DhtResponse::RetrieveReply { value: None },
            },
            DhtMessage::Store {
                ref key, ref value, ..
            } => {
                // Security: Reject oversized values to prevent memory exhaustion
                if value.len() > MAX_DHT_VALUE_SIZE {
                    return DhtResponseWrapper {
                        id: request_wrapper.id,
                        response: DhtResponse::Error {
                            code: crate::dht::network_integration::ErrorCode::InvalidMessage,
                            message: format!(
                                "Value too large: {} bytes (max: {} bytes)",
                                value.len(),
                                MAX_DHT_VALUE_SIZE
                            ),
                            retry_after: None,
                        },
                    };
                }
                self.data_store
                    .write()
                    .await
                    .put(key.clone(), value.clone());
                DhtResponse::StoreAck {
                    replicas: vec![self.node_id.clone()],
                }
            }
            DhtMessage::FindNode { ref target, count } => {
                // Security: Cap count to prevent amplification attacks
                let capped_count = count.min(MAX_FIND_NODE_COUNT);
                let routing = self.routing_table.read().await;
                let nodes = routing.find_closest_nodes(target, capped_count);
                DhtResponse::FindNodeReply {
                    nodes,
                    distances: Vec::new(),
                }
            }
            DhtMessage::FindValue { ref key } => {
                let value = self.data_store.write().await.get(key);
                if value.is_some() {
                    DhtResponse::FindValueReply {
                        value,
                        nodes: Vec::new(),
                    }
                } else {
                    let routing = self.routing_table.read().await;
                    let nodes = routing.find_closest_nodes(key, K);
                    DhtResponse::FindValueReply { value: None, nodes }
                }
            }
            DhtMessage::Ping {
                timestamp,
                sender_info,
            } => DhtResponse::Pong {
                timestamp,
                node_info: sender_info,
            },
            _ => DhtResponse::Error {
                code: crate::dht::network_integration::ErrorCode::InvalidMessage,
                message: "Unsupported message type".to_string(),
                retry_after: None,
            },
        };

        DhtResponseWrapper {
            id: request_wrapper.id,
            response,
        }
    }

    /// Find nodes closest to a key
    pub async fn find_nodes(&self, key: &DhtKey, count: usize) -> Result<Vec<NodeInfo>> {
        let routing = self.routing_table.read().await;
        Ok(routing.find_closest_nodes(key, count))
    }

    /// Join the DHT network
    pub async fn join_network(&mut self, bootstrap_nodes: Vec<NodeInfo>) -> Result<()> {
        let mut routing = self.routing_table.write().await;

        for node in bootstrap_nodes {
            routing.add_node(node)?;
        }

        Ok(())
    }

    /// Leave the DHT network gracefully
    pub async fn leave_network(&mut self) -> Result<()> {
        // Transfer data to other nodes before leaving
        // In a real implementation, would redistribute stored data

        let mut store = self.data_store.write().await;
        store.data.clear();
        store.metadata.clear();

        Ok(())
    }

    /// Handle node failure
    pub async fn handle_node_failure(&mut self, failed_node: NodeId) -> Result<()> {
        // Remove from routing table
        let mut routing = self.routing_table.write().await;
        routing.remove_node(&failed_node);

        // Schedule repairs for affected data
        let _replication = self.replication_manager.write().await;
        // In real implementation, would identify affected keys and schedule repairs

        Ok(())
    }

    /// Evict a node from the routing table with a specific reason.
    ///
    /// This is called when a node fails security validation or is detected
    /// as malicious through Sybil/collusion detection.
    pub async fn evict_node(&self, node_id: &NodeId, reason: EvictionReason) -> Result<()> {
        // 1. Remove from routing table
        {
            let mut routing = self.routing_table.write().await;
            routing.remove_node(node_id);
        }

        // 2. Update security metrics based on eviction reason
        let reason_str = match &reason {
            EvictionReason::ConsecutiveFailures(_) => "consecutive_failures",
            EvictionReason::LowTrust(_) => "low_trust",
            EvictionReason::CloseGroupRejection => "close_group_rejection",
            EvictionReason::Stale => "stale",
        };
        self.security_metrics.record_eviction(reason_str).await;

        // 3. Log eviction for data integrity tracking
        // Note: Data health tracking handled elsewhere
        // Evicted nodes will be removed from routing table, which affects future lookups

        tracing::info!(
            node_id = %node_id,
            reason = ?reason,
            "Node evicted from DHT"
        );

        Ok(())
    }

    /// Evict a node due to close group validation failure.
    ///
    /// This is a specialized eviction for security-related failures.
    pub async fn evict_node_for_security(
        &self,
        node_id: &NodeId,
        failure_reason: CloseGroupFailure,
    ) -> Result<()> {
        let eviction_reason = match failure_reason {
            CloseGroupFailure::NotInCloseGroup => EvictionReason::CloseGroupRejection,
            CloseGroupFailure::EvictedFromCloseGroup => EvictionReason::CloseGroupRejection,
            CloseGroupFailure::InsufficientConfirmation => EvictionReason::CloseGroupRejection,
            CloseGroupFailure::LowTrustScore => {
                EvictionReason::LowTrust("Security validation failed".to_string())
            }
            CloseGroupFailure::InsufficientGeographicDiversity => {
                EvictionReason::LowTrust("Geographic diversity violation".to_string())
            }
            CloseGroupFailure::SuspectedCollusion => {
                EvictionReason::LowTrust("Suspected collusion".to_string())
            }
            CloseGroupFailure::AttackModeTriggered => {
                EvictionReason::LowTrust("Attack mode triggered".to_string())
            }
        };

        self.evict_node(node_id, eviction_reason).await
    }

    /// Get eviction candidates from the refresh manager.
    ///
    /// Returns nodes that should be evicted based on validation failures.
    pub async fn get_eviction_candidates(&self) -> Vec<(NodeId, CloseGroupFailure)> {
        self.bucket_refresh_manager
            .read()
            .await
            .get_nodes_for_eviction()
            .await
    }

    /// Check if the system is currently in attack mode.
    #[must_use]
    pub async fn is_attack_mode(&self) -> bool {
        self.bucket_refresh_manager
            .read()
            .await
            .is_attack_mode()
            .await
    }

    /// Get the bucket refresh manager for external access
    pub fn bucket_refresh_manager(&self) -> Arc<RwLock<BucketRefreshManager>> {
        self.bucket_refresh_manager.clone()
    }

    /// Get the close group validator for external access
    pub fn close_group_validator(&self) -> Arc<RwLock<CloseGroupValidator>> {
        self.close_group_validator.clone()
    }

    /// Add a node to the DHT with security checks
    pub async fn add_node(&mut self, node: NodeInfo) -> Result<()> {
        // 1. Security Check: Close Group Validator
        {
            // Active validation query
            let validator = self.close_group_validator.read().await;
            if !validator.validate(&node.id) {
                tracing::warn!("Node failed close group validation: {:?}", node.id);
                return Err(anyhow::anyhow!("Node failed close group validation"));
            }
        }

        // 2. Security Check: IP Diversity (both IPv4 and IPv6)
        {
            // Parse IP address from node.address string
            // address comes as "ip:port" or just "ip"
            let ip_addr: Option<IpAddr> = if let Ok(socket) = node.address.parse::<SocketAddr>() {
                Some(socket.ip())
            } else {
                node.address.parse::<IpAddr>().ok()
            };

            if let Some(ip) = ip_addr {
                let mut enforcer = self.ip_diversity_enforcer.write().await;
                match enforcer.analyze_unified(ip) {
                    Ok(analysis) => {
                        if !enforcer.can_accept_unified(&analysis) {
                            tracing::warn!("Node rejected due to IP diversity limits: {:?}", ip);
                            return Err(anyhow::anyhow!(
                                "IP diversity limits exceeded for address {ip}"
                            ));
                        }
                        // Record valid node - propagate error as this is a critical security operation
                        enforcer.add_unified(&analysis).map_err(|e| {
                            tracing::error!(
                                "Failed to record node IP for diversity tracking: {:?}",
                                e
                            );
                            anyhow::anyhow!("IP diversity tracking failed: {e:?}")
                        })?;
                    }
                    Err(e) => {
                        tracing::debug!("Could not analyze IP {:?}: {:?}", ip, e);
                        // Continue without IP diversity check if analysis fails
                    }
                }
            }
        }

        // 3. Security Check: Geographic Diversity
        {
            // Parse IP address from node.address string (reuse parsed IP from above)
            let ip_addr: Option<IpAddr> = if let Ok(socket) = node.address.parse::<SocketAddr>() {
                Some(socket.ip())
            } else {
                node.address.parse::<IpAddr>().ok()
            };

            if let Some(ip) = ip_addr {
                let region = GeographicRegion::from_ip(ip);
                let mut enforcer = self.geographic_diversity_enforcer.write().await;
                if !enforcer.can_accept(region) {
                    tracing::warn!(
                        "Node rejected due to geographic diversity limits: {:?} in region {:?}",
                        ip,
                        region
                    );
                    return Err(anyhow::anyhow!(
                        "Geographic diversity limits exceeded for region {region:?} (IP: {ip})"
                    ));
                }
                enforcer.add(region);
            }
        }

        // 4. Add to routing table
        let mut routing = self.routing_table.write().await;
        routing.add_node(node)?;

        // 5. Update Metrics
        // (Placeholder: Add metric for new node joining if available)

        Ok(())
    }
}

// Manual Debug implementation to avoid cascade of Debug requirements
impl std::fmt::Debug for DhtCoreEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhtCoreEngine")
            .field("node_id", &self.node_id)
            .field("routing_table", &"Arc<RwLock<KademliaRoutingTable>>")
            .field("data_store", &"Arc<RwLock<DataStore>>")
            .field("replication_manager", &"Arc<RwLock<ReplicationManager>>")
            .field("load_balancer", &"Arc<RwLock<LoadBalancer>>")
            .field("security_metrics", &"Arc<SecurityMetricsCollector>")
            .field(
                "bucket_refresh_manager",
                &"Arc<RwLock<BucketRefreshManager>>",
            )
            .field("close_group_validator", &"Arc<RwLock<CloseGroupValidator>>")
            .field("ip_diversity_enforcer", &"Arc<RwLock<IPDiversityEnforcer>>")
            .field("eviction_manager", &"Arc<RwLock<EvictionManager>>")
            .field(
                "geographic_diversity_enforcer",
                &"Arc<RwLock<GeographicDiversityEnforcer>>",
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_store_retrieve() -> Result<()> {
        let mut dht = DhtCoreEngine::new(NodeId::from_bytes([42u8; 32]))?;
        let key = DhtKey::new(b"test_key");
        let value = b"test_value".to_vec();

        let receipt = dht.store(&key, value.clone()).await?;
        assert!(receipt.is_successful());

        let retrieved = dht.retrieve(&key).await?;
        assert_eq!(retrieved, Some(value));

        Ok(())
    }

    #[tokio::test]
    async fn test_xor_distance() {
        let key1 = DhtKey::from_bytes([0u8; 32]);
        let key2 = DhtKey::from_bytes([255u8; 32]);

        let distance = key1.distance(&key2);
        assert_eq!(distance, [255u8; 32]);
    }
}
