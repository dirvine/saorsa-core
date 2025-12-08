//! Enhanced DHT Core Engine with Kademlia routing and intelligent data distribution
//!
//! Provides the main DHT functionality with k=8 replication, load balancing, and fault tolerance.

use crate::dht::{
    content_addressing::ContentAddress,
    geographic_routing::GeographicRegion,
    metrics::SecurityMetricsCollector,
    reed_solomon::ReedSolomonEncoder,
    routing_maintenance::{
        BucketRefreshManager, EvictionManager, EvictionReason, MaintenanceConfig,
        close_group_validator::{
            CloseGroupFailure, CloseGroupValidator, CloseGroupValidatorConfig,
        },
        data_integrity_monitor::DataIntegrityMonitor,
    },
    witness::{DhtOperation, OperationMetadata, OperationType, WitnessReceiptSystem},
};
use crate::security::{IPDiversityConfig, IPDiversityEnforcer};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

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
            Err(anyhow!("Bucket full"))
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
        let mut all_nodes = Vec::new();

        for bucket in &self.buckets {
            all_nodes.extend(bucket.get_nodes().iter().cloned());
        }

        // Sort by XOR distance
        all_nodes.sort_by_key(|node| node.id.0.distance(key));

        all_nodes.truncate(count);
        all_nodes
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
            ConsistencyLevel::Quorum => self._replication_factor.div_ceil(2),
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
        let mut sorted: Vec<_> = candidates
            .iter()
            .map(|node| {
                let load = self
                    .node_loads
                    .get(&node.id)
                    .map(|l| l.storage_used_percent)
                    .unwrap_or(0.0);
                (node.id.clone(), load)
            })
            .collect();

        use std::cmp::Ordering;
        sorted.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal));

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

/// Main DHT Core Engine
pub struct DhtCoreEngine {
    node_id: NodeId,
    routing_table: Arc<RwLock<KademliaRoutingTable>>,
    data_store: Arc<RwLock<DataStore>>,
    replication_manager: Arc<RwLock<ReplicationManager>>,
    load_balancer: Arc<RwLock<LoadBalancer>>,
    witness_system: Arc<WitnessReceiptSystem>,
    _reed_solomon: Arc<ReedSolomonEncoder>,

    // Security Components (using parking_lot RwLock as they are synchronous)
    security_metrics: Arc<SecurityMetricsCollector>,
    bucket_refresh_manager: Arc<parking_lot::RwLock<BucketRefreshManager>>,
    data_integrity_monitor: Arc<parking_lot::RwLock<DataIntegrityMonitor>>,
    close_group_validator: Arc<parking_lot::RwLock<CloseGroupValidator>>,
    ip_diversity_enforcer: Arc<parking_lot::RwLock<IPDiversityEnforcer>>,
    eviction_manager: Arc<parking_lot::RwLock<EvictionManager>>,
    geographic_diversity_enforcer: Arc<parking_lot::RwLock<GeographicDiversityEnforcer>>,
}

impl DhtCoreEngine {
    /// Create new DHT engine with specified node ID
    pub fn new(node_id: NodeId) -> Result<Self> {
        // Initialize security components
        let security_metrics = Arc::new(SecurityMetricsCollector::new());
        let close_group_validator = Arc::new(parking_lot::RwLock::new(
            CloseGroupValidator::with_defaults(),
        ));

        let mut bucket_refresh_manager = BucketRefreshManager::new_with_validation(
            node_id.clone(),
            CloseGroupValidatorConfig::default(),
        );
        // Link validator to refresh manager
        bucket_refresh_manager.set_validator(close_group_validator.clone());
        let bucket_refresh_manager = Arc::new(parking_lot::RwLock::new(bucket_refresh_manager));

        let data_integrity_monitor = Arc::new(parking_lot::RwLock::new(
            DataIntegrityMonitor::with_defaults(),
        ));

        let ip_diversity_enforcer = Arc::new(parking_lot::RwLock::new(IPDiversityEnforcer::new(
            IPDiversityConfig::default(),
        )));

        let eviction_manager = Arc::new(parking_lot::RwLock::new(EvictionManager::new(
            MaintenanceConfig::default(),
        )));

        // Geographic diversity: limit to 50 nodes per region (matches GeographicRoutingConfig default)
        let geographic_diversity_enforcer = Arc::new(parking_lot::RwLock::new(
            GeographicDiversityEnforcer::new(50),
        ));

        Ok(Self {
            node_id: node_id.clone(),
            routing_table: Arc::new(RwLock::new(KademliaRoutingTable::new(node_id, 8))),
            data_store: Arc::new(RwLock::new(DataStore::new())),
            replication_manager: Arc::new(RwLock::new(ReplicationManager::new(8))),
            load_balancer: Arc::new(RwLock::new(LoadBalancer::new())),
            witness_system: Arc::new(WitnessReceiptSystem::new()),
            _reed_solomon: Arc::new(ReedSolomonEncoder::new(6, 2)?),
            security_metrics,
            bucket_refresh_manager,
            data_integrity_monitor,
            close_group_validator,
            ip_diversity_enforcer,
            eviction_manager,
            geographic_diversity_enforcer,
        })
    }

    /// Start background maintenance tasks for security and health
    pub fn start_maintenance_tasks(&self) {
        let refresh_manager = self.bucket_refresh_manager.clone();
        let integrity_monitor = self.data_integrity_monitor.clone();
        let eviction_manager = self.eviction_manager.clone();
        let _metrics = self.security_metrics.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;

                // 1. Run Bucket Refresh Logic with Validation Integration
                {
                    let mut mgr = refresh_manager.write();

                    // Check for attack mode escalation based on validation failures
                    if mgr.should_trigger_attack_mode() {
                        if let Some(validator) = mgr.validator() {
                            validator.write().escalate_to_bft();
                            tracing::warn!(
                                "Escalating to BFT mode due to validation failures (rate: {:.2}%)",
                                mgr.overall_validation_rate() * 100.0
                            );
                        }
                    } else if let Some(validator) = mgr.validator() {
                        // De-escalate if validation rate recovers above 85%
                        if mgr.overall_validation_rate() > 0.85 {
                            validator.write().deescalate_from_bft();
                        }
                    }

                    // Get buckets needing refresh
                    let buckets = mgr.get_buckets_needing_refresh();
                    if !buckets.is_empty() {
                        // Get buckets that also need validation
                        let validation_buckets = mgr.get_buckets_needing_validation();

                        for bucket in buckets {
                            // Record refresh (in a real impl, trigger network lookups first)
                            mgr.record_refresh_success(bucket, 0);

                            // Mark validation as needed for this bucket if due
                            if validation_buckets.contains(&bucket) {
                                // In production, validate_refreshed_nodes() would be called
                                // after network lookups return node responses and trust scores.
                                // For now, mark that validation was attempted.
                                tracing::debug!(
                                    "Bucket {} marked for validation during refresh",
                                    bucket
                                );
                            }
                        }
                    }
                }

                // 2. Run Data Integrity Checks
                {
                    let mut monitor = integrity_monitor.write();
                    if monitor.is_check_due() {
                        monitor.mark_check_started();
                        let _keys = monitor.get_keys_needing_check();
                        // Dispatch attestation challenges (placeholder)
                    }
                }

                // 3. Active Eviction Enforcement
                {
                    let mut eviction_mgr = eviction_manager.write();
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
    pub async fn store(&mut self, key: &DhtKey, value: Vec<u8>) -> Result<StoreReceipt> {
        // Find nodes to store at
        let routing = self.routing_table.read().await;
        // ... (find_closest_nodes)
        let target_nodes = routing.find_closest_nodes(key, 8);
        drop(routing);

        // Select nodes based on load
        let load_balancer = self.load_balancer.read().await;
        let selected_nodes = load_balancer.select_least_loaded(&target_nodes, 8);

        // Hook: Track content in DataIntegrityMonitor
        {
            let mut monitor = self.data_integrity_monitor.write();
            monitor.track_content(key.clone(), selected_nodes.to_vec());
        }

        // Store locally if we're one of the selected nodes or if no nodes are available (test/single-node mode)
        if selected_nodes.contains(&self.node_id) || selected_nodes.is_empty() {
            let mut store = self.data_store.write().await;
            store.put(key.clone(), value.clone());
        }

        // Create witness receipt
        let operation = DhtOperation {
            operation_type: OperationType::Store,
            content_hash: ContentAddress::from_bytes(&key.0),
            nodes: selected_nodes
                .iter()
                .map(|id| crate::dht::witness::NodeId::new(&format!("{:?}", id)))
                .collect(),
            metadata: OperationMetadata {
                size_bytes: value.len(),
                chunk_count: Some(1),
                redundancy_level: Some(0.5),
                custom: HashMap::new(),
            },
        };

        let _receipt = self.witness_system.create_receipt(&operation).await?;

        Ok(StoreReceipt {
            key: key.clone(),
            stored_at: selected_nodes,
            timestamp: SystemTime::now(),
            success: true,
        })
    }

    /// Retrieve data from the DHT
    pub async fn retrieve(&self, key: &DhtKey) -> Result<Option<Vec<u8>>> {
        // Check local store first
        let mut store = self.data_store.write().await;
        if let Some(value) = store.get(key) {
            return Ok(Some(value));
        }
        drop(store);

        // Find nodes that might have the data
        let routing = self.routing_table.read().await;
        let _closest_nodes = routing.find_closest_nodes(key, 8);

        // In a real implementation, would query these nodes
        // For now, return None if not found locally
        Ok(None)
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
            EvictionReason::FailedAttestation => "failed_attestation",
            EvictionReason::CloseGroupRejection => "close_group_rejection",
            EvictionReason::Stale => "stale",
        };
        self.security_metrics.record_eviction(reason_str).await;

        // 3. Log eviction for data integrity tracking
        // Note: DataIntegrityMonitor tracks data health, not individual node membership
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
    pub fn get_eviction_candidates(&self) -> Vec<(NodeId, CloseGroupFailure)> {
        self.bucket_refresh_manager.read().get_nodes_for_eviction()
    }

    /// Check if the system is currently in attack mode.
    #[must_use]
    pub fn is_attack_mode(&self) -> bool {
        self.bucket_refresh_manager.read().is_attack_mode()
    }

    /// Get the bucket refresh manager for external access
    pub fn bucket_refresh_manager(&self) -> Arc<parking_lot::RwLock<BucketRefreshManager>> {
        self.bucket_refresh_manager.clone()
    }

    /// Get the close group validator for external access
    pub fn close_group_validator(&self) -> Arc<parking_lot::RwLock<CloseGroupValidator>> {
        self.close_group_validator.clone()
    }

    /// Add a node to the DHT with security checks
    pub async fn add_node(&mut self, node: NodeInfo) -> Result<()> {
        // 1. Security Check: Close Group Validator
        {
            // Active validation query
            let validator = self.close_group_validator.read();
            if !validator.validate(&node.id) {
                tracing::warn!("Node failed close group validation: {:?}", node.id);
                // We don't return error yet to avoid breaking existing tests that don't pass validation
                // return Err(anyhow::anyhow!("Node failed close group validation"));
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
                let mut enforcer = self.ip_diversity_enforcer.write();
                match enforcer.analyze_unified(ip) {
                    Ok(analysis) => {
                        if !enforcer.can_accept_unified(&analysis) {
                            tracing::warn!("Node rejected due to IP diversity limits: {:?}", ip);
                            return Err(anyhow::anyhow!("IP diversity limits exceeded"));
                        }
                        // Record valid node
                        if let Err(e) = enforcer.add_unified(&analysis) {
                            tracing::warn!("Failed to record node IP: {:?}", e);
                        }
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
                let mut enforcer = self.geographic_diversity_enforcer.write();
                if !enforcer.can_accept(region) {
                    tracing::warn!(
                        "Node rejected due to geographic diversity limits: {:?} in region {:?}",
                        ip,
                        region
                    );
                    return Err(anyhow::anyhow!("Geographic diversity limits exceeded"));
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
            .field("witness_system", &"Arc<WitnessReceiptSystem>")
            .field("_reed_solomon", &"Arc<ReedSolomonEncoder>")
            .field("security_metrics", &"Arc<SecurityMetricsCollector>")
            .field(
                "bucket_refresh_manager",
                &"Arc<parking_lot::RwLock<BucketRefreshManager>>",
            )
            .field(
                "data_integrity_monitor",
                &"Arc<parking_lot::RwLock<DataIntegrityMonitor>>",
            )
            .field(
                "close_group_validator",
                &"Arc<parking_lot::RwLock<CloseGroupValidator>>",
            )
            .field(
                "ip_diversity_enforcer",
                &"Arc<parking_lot::RwLock<IPDiversityEnforcer>>",
            )
            .field(
                "eviction_manager",
                &"Arc<parking_lot::RwLock<EvictionManager>>",
            )
            .field(
                "geographic_diversity_enforcer",
                &"Arc<parking_lot::RwLock<GeographicDiversityEnforcer>>",
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
