// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com

//! Cross-Network Replication for IPv4/IPv6 Dual-Stack Networks
//!
//! This module ensures data redundancy across both IPv4 and IPv6 networks.
//! It addresses the scenario where the network operates on both IP versions,
//! and we need to ensure data availability even if one IP family becomes
//! temporarily unreachable.
//!
//! ## Design Goals
//!
//! 1. **Network Diversity**: Ensure replicas exist on both IPv4 and IPv6 nodes
//! 2. **Fault Tolerance**: Survive partial network splits between IP families
//! 3. **Anti-Sybil**: Leverage both address families for security verification
//! 4. **Minimal Overhead**: Smart replica placement to avoid excessive duplication

use crate::dht::Key;
use crate::peer_record::UserId as NodeId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use parking_lot::RwLock;
use tracing::debug;

/// IP address family
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpFamily {
    IPv4,
    IPv6,
}

impl IpFamily {
    /// Get the opposite family
    pub fn opposite(&self) -> Self {
        match self {
            IpFamily::IPv4 => IpFamily::IPv6,
            IpFamily::IPv6 => IpFamily::IPv4,
        }
    }
}

/// Configuration for cross-network replication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossNetworkReplicationConfig {
    /// Minimum replicas required per IP family
    pub min_replicas_per_family: usize,
    /// Target replicas per IP family (best effort)
    pub target_replicas_per_family: usize,
    /// Total replication factor
    pub total_replication_factor: usize,
    /// Enable cross-network replication
    pub enabled: bool,
    /// Prefer dual-stack nodes (both IPv4 and IPv6)
    pub prefer_dual_stack: bool,
    /// Maximum replication lag allowed between families
    pub max_replication_lag: Duration,
    /// Rebalance interval
    pub rebalance_interval: Duration,
}

impl Default for CrossNetworkReplicationConfig {
    fn default() -> Self {
        Self {
            min_replicas_per_family: 2,
            target_replicas_per_family: 4,
            total_replication_factor: 8,
            enabled: true,
            prefer_dual_stack: true,
            max_replication_lag: Duration::from_secs(60),
            rebalance_interval: Duration::from_secs(300),
        }
    }
}

/// Information about a node's network capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeNetworkInfo {
    /// Node ID
    pub node_id: NodeId,
    /// IPv4 addresses (if any)
    pub ipv4_addresses: Vec<Ipv4Addr>,
    /// IPv6 addresses (if any)
    pub ipv6_addresses: Vec<Ipv6Addr>,
    /// Last seen timestamp
    pub last_seen: SystemTime,
    /// Node trust score
    pub trust_score: f64,
}

impl NodeNetworkInfo {
    /// Check if node supports IPv4
    pub fn supports_ipv4(&self) -> bool {
        !self.ipv4_addresses.is_empty()
    }

    /// Check if node supports IPv6
    pub fn supports_ipv6(&self) -> bool {
        !self.ipv6_addresses.is_empty()
    }

    /// Check if node is dual-stack (supports both)
    pub fn is_dual_stack(&self) -> bool {
        self.supports_ipv4() && self.supports_ipv6()
    }

    /// Get supported IP families
    pub fn supported_families(&self) -> Vec<IpFamily> {
        let mut families = Vec::new();
        if self.supports_ipv4() {
            families.push(IpFamily::IPv4);
        }
        if self.supports_ipv6() {
            families.push(IpFamily::IPv6);
        }
        families
    }
}

/// Record replication status across networks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordReplicationStatus {
    /// Record key
    pub key: Key,
    /// Nodes holding replicas by IP family
    pub replicas_by_family: HashMap<IpFamily, Vec<NodeId>>,
    /// Last replication check
    pub last_checked: SystemTime,
    /// Whether replication is healthy
    pub is_healthy: bool,
    /// Missing replicas per family
    pub missing_replicas: HashMap<IpFamily, usize>,
}

impl RecordReplicationStatus {
    /// Create new status for a key
    pub fn new(key: Key) -> Self {
        Self {
            key,
            replicas_by_family: HashMap::new(),
            last_checked: SystemTime::now(),
            is_healthy: false,
            missing_replicas: HashMap::new(),
        }
    }

    /// Get replica count for a family
    pub fn replica_count(&self, family: IpFamily) -> usize {
        self.replicas_by_family
            .get(&family)
            .map(|nodes| nodes.len())
            .unwrap_or(0)
    }

    /// Get total replica count
    pub fn total_replicas(&self) -> usize {
        self.replicas_by_family.values().map(|v| v.len()).sum()
    }
}

/// Cross-network replication manager
#[derive(Debug)]
pub struct CrossNetworkReplicator {
    /// Configuration
    config: CrossNetworkReplicationConfig,
    /// Known nodes by their network info
    nodes: Arc<RwLock<HashMap<NodeId, NodeNetworkInfo>>>,
    /// Record replication status
    record_status: Arc<RwLock<HashMap<Key, RecordReplicationStatus>>>,
    /// Nodes by IP family
    nodes_by_family: Arc<RwLock<HashMap<IpFamily, HashSet<NodeId>>>>,
    /// Dual-stack nodes
    dual_stack_nodes: Arc<RwLock<HashSet<NodeId>>>,
}

impl CrossNetworkReplicator {
    /// Create a new cross-network replicator
    pub fn new(config: CrossNetworkReplicationConfig) -> Self {
        Self {
            config,
            nodes: Arc::new(RwLock::new(HashMap::new())),
            record_status: Arc::new(RwLock::new(HashMap::new())),
            nodes_by_family: Arc::new(RwLock::new(HashMap::new())),
            dual_stack_nodes: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Register a node with its network capabilities
    pub fn register_node(&self, info: NodeNetworkInfo) {
        let node_id = info.node_id.clone();

        // Update node info
        self.nodes.write().insert(node_id.clone(), info.clone());

        // Update family indexes
        let mut by_family = self.nodes_by_family.write();
        if info.supports_ipv4() {
            by_family
                .entry(IpFamily::IPv4)
                .or_default()
                .insert(node_id.clone());
        }
        if info.supports_ipv6() {
            by_family
                .entry(IpFamily::IPv6)
                .or_default()
                .insert(node_id.clone());
        }

        // Update dual-stack index
        if info.is_dual_stack() {
            self.dual_stack_nodes.write().insert(node_id.clone());
            debug!("Registered dual-stack node: {:?}", node_id);
        }
    }

    /// Remove a node from tracking
    pub fn remove_node(&self, node_id: &NodeId) {
        self.nodes.write().remove(node_id);

        let mut by_family = self.nodes_by_family.write();
        for nodes in by_family.values_mut() {
            nodes.remove(node_id);
        }

        self.dual_stack_nodes.write().remove(node_id);
    }

    /// Select replica nodes for a record ensuring cross-network diversity
    pub fn select_replica_nodes(
        &self,
        key: &Key,
        exclude: &[NodeId],
    ) -> ReplicaSelection {
        let nodes = self.nodes.read();
        let by_family = self.nodes_by_family.read();
        let dual_stack = self.dual_stack_nodes.read();

        let excluded: HashSet<_> = exclude.iter().collect();

        let mut selection = ReplicaSelection::new(*key);

        // First, try to get dual-stack nodes (they count for both families)
        if self.config.prefer_dual_stack {
            let mut ds_candidates: Vec<_> = dual_stack
                .iter()
                .filter(|n| !excluded.contains(n))
                .filter_map(|n| nodes.get(n).map(|info| (n.clone(), info.trust_score)))
                .collect();

            // Sort by trust score descending
            ds_candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

            for (node_id, _) in ds_candidates.iter().take(self.config.min_replicas_per_family) {
                selection.add_node(node_id.clone(), vec![IpFamily::IPv4, IpFamily::IPv6]);
            }
        }

        // Then fill in per-family quotas
        for family in [IpFamily::IPv4, IpFamily::IPv6] {
            let current = selection.count_by_family(family);
            let needed = self.config.min_replicas_per_family.saturating_sub(current);

            if needed > 0 && let Some(family_nodes) = by_family.get(&family) {
                let mut candidates: Vec<_> = family_nodes
                    .iter()
                    .filter(|n| !excluded.contains(n))
                    .filter(|n| !selection.contains(n))
                    .filter_map(|n| nodes.get(n).map(|info| (n.clone(), info.trust_score)))
                    .collect();

                candidates.sort_by(|a, b| {
                    b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
                });

                for (node_id, _) in candidates.iter().take(needed) {
                    selection.add_node(node_id.clone(), vec![family]);
                }
            }
        }

        // Fill up to target replication factor
        let remaining = self.config.total_replication_factor.saturating_sub(selection.total());
        if remaining > 0 {
            let all_candidates: Vec<_> = nodes
                .iter()
                .filter(|(n, _)| !excluded.contains(n))
                .filter(|(n, _)| !selection.contains(n))
                .map(|(n, info)| (n.clone(), info.trust_score, info.supported_families()))
                .collect();

            let mut sorted: Vec<_> = all_candidates;
            sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

            for (node_id, _, families) in sorted.iter().take(remaining) {
                selection.add_node(node_id.clone(), families.clone());
            }
        }

        selection
    }

    /// Check if a record has healthy replication
    pub fn check_replication_health(&self, key: &Key, current_replicas: &[(NodeId, IpFamily)]) -> RecordReplicationStatus {
        let mut status = RecordReplicationStatus::new(*key);

        // Count replicas by family
        for (node_id, family) in current_replicas {
            status.replicas_by_family
                .entry(*family)
                .or_default()
                .push(node_id.clone());
        }

        // Calculate missing replicas
        for family in [IpFamily::IPv4, IpFamily::IPv6] {
            let current = status.replica_count(family);
            if current < self.config.min_replicas_per_family {
                let missing = self.config.min_replicas_per_family - current;
                status.missing_replicas.insert(family, missing);
            }
        }

        // Determine health
        status.is_healthy = status.missing_replicas.is_empty()
            && status.total_replicas() >= self.config.total_replication_factor / 2;

        status.last_checked = SystemTime::now();

        // Update cached status
        self.record_status.write().insert(*key, status.clone());

        status
    }

    /// Get nodes that need to receive replicas for a record
    pub fn get_repair_targets(&self, status: &RecordReplicationStatus) -> Vec<(NodeId, IpFamily)> {
        let mut targets = Vec::new();

        for (family, missing_count) in &status.missing_replicas {
            let selection = self.select_replica_nodes(&status.key, &[]);

            for node_id in selection.nodes_for_family(*family).iter().take(*missing_count) {
                targets.push((node_id.clone(), *family));
            }
        }

        targets
    }

    /// Get network diversity statistics
    pub fn get_diversity_stats(&self) -> NetworkDiversityStats {
        let by_family = self.nodes_by_family.read();
        let dual_stack = self.dual_stack_nodes.read();
        let record_status = self.record_status.read();

        let ipv4_only = by_family
            .get(&IpFamily::IPv4)
            .map(|s| s.len())
            .unwrap_or(0)
            .saturating_sub(dual_stack.len());

        let ipv6_only = by_family
            .get(&IpFamily::IPv6)
            .map(|s| s.len())
            .unwrap_or(0)
            .saturating_sub(dual_stack.len());

        let healthy_records = record_status.values().filter(|s| s.is_healthy).count();
        let total_records = record_status.len();

        NetworkDiversityStats {
            ipv4_only_nodes: ipv4_only,
            ipv6_only_nodes: ipv6_only,
            dual_stack_nodes: dual_stack.len(),
            total_nodes: self.nodes.read().len(),
            healthy_records,
            total_records,
            replication_health_ratio: if total_records > 0 {
                healthy_records as f64 / total_records as f64
            } else {
                1.0
            },
        }
    }

    /// Get configuration
    pub fn config(&self) -> &CrossNetworkReplicationConfig {
        &self.config
    }
}

/// Result of replica node selection
#[derive(Debug, Clone)]
pub struct ReplicaSelection {
    /// Key being replicated
    pub key: Key,
    /// Selected nodes with their IP family contributions
    pub nodes: HashMap<NodeId, Vec<IpFamily>>,
}

impl ReplicaSelection {
    /// Create new selection
    pub fn new(key: Key) -> Self {
        Self {
            key,
            nodes: HashMap::new(),
        }
    }

    /// Add a node to the selection
    pub fn add_node(&mut self, node_id: NodeId, families: Vec<IpFamily>) {
        self.nodes.insert(node_id, families);
    }

    /// Check if node is in selection
    pub fn contains(&self, node_id: &NodeId) -> bool {
        self.nodes.contains_key(node_id)
    }

    /// Count nodes contributing to a family
    pub fn count_by_family(&self, family: IpFamily) -> usize {
        self.nodes
            .values()
            .filter(|families| families.contains(&family))
            .count()
    }

    /// Get nodes for a specific family
    pub fn nodes_for_family(&self, family: IpFamily) -> Vec<NodeId> {
        self.nodes
            .iter()
            .filter(|(_, families)| families.contains(&family))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Total selected nodes
    pub fn total(&self) -> usize {
        self.nodes.len()
    }
}

/// Network diversity statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDiversityStats {
    /// Nodes with only IPv4
    pub ipv4_only_nodes: usize,
    /// Nodes with only IPv6
    pub ipv6_only_nodes: usize,
    /// Dual-stack nodes
    pub dual_stack_nodes: usize,
    /// Total nodes
    pub total_nodes: usize,
    /// Records with healthy replication
    pub healthy_records: usize,
    /// Total records tracked
    pub total_records: usize,
    /// Ratio of healthy records
    pub replication_health_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_node(id: &str, ipv4: bool, ipv6: bool, trust: f64) -> NodeNetworkInfo {
        NodeNetworkInfo {
            node_id: NodeId {
                hash: {
                    let mut h = [0u8; 32];
                    h[..id.len().min(32)].copy_from_slice(id.as_bytes());
                    h
                },
            },
            ipv4_addresses: if ipv4 {
                vec![Ipv4Addr::new(192, 168, 1, 1)]
            } else {
                vec![]
            },
            ipv6_addresses: if ipv6 {
                vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)]
            } else {
                vec![]
            },
            last_seen: SystemTime::now(),
            trust_score: trust,
        }
    }

    #[test]
    fn test_node_network_info() {
        let dual = create_test_node("dual", true, true, 0.9);
        assert!(dual.is_dual_stack());
        assert!(dual.supports_ipv4());
        assert!(dual.supports_ipv6());

        let ipv4_only = create_test_node("v4", true, false, 0.8);
        assert!(!ipv4_only.is_dual_stack());
        assert!(ipv4_only.supports_ipv4());
        assert!(!ipv4_only.supports_ipv6());

        let ipv6_only = create_test_node("v6", false, true, 0.7);
        assert!(!ipv6_only.is_dual_stack());
        assert!(!ipv6_only.supports_ipv4());
        assert!(ipv6_only.supports_ipv6());
    }

    #[test]
    fn test_cross_network_replicator_creation() {
        let config = CrossNetworkReplicationConfig::default();
        let replicator = CrossNetworkReplicator::new(config.clone());

        assert_eq!(replicator.config().min_replicas_per_family, 2);
        assert_eq!(replicator.config().total_replication_factor, 8);
    }

    #[test]
    fn test_register_nodes() {
        let replicator = CrossNetworkReplicator::new(CrossNetworkReplicationConfig::default());

        // Register different types of nodes
        replicator.register_node(create_test_node("dual1", true, true, 0.9));
        replicator.register_node(create_test_node("dual2", true, true, 0.8));
        replicator.register_node(create_test_node("v4_only", true, false, 0.7));
        replicator.register_node(create_test_node("v6_only", false, true, 0.6));

        let stats = replicator.get_diversity_stats();
        assert_eq!(stats.total_nodes, 4);
        assert_eq!(stats.dual_stack_nodes, 2);
        assert_eq!(stats.ipv4_only_nodes, 1);
        assert_eq!(stats.ipv6_only_nodes, 1);
    }

    #[test]
    fn test_replica_selection() {
        let replicator = CrossNetworkReplicator::new(CrossNetworkReplicationConfig {
            min_replicas_per_family: 2,
            target_replicas_per_family: 3,
            total_replication_factor: 6,
            ..Default::default()
        });

        // Register nodes
        for i in 0..3 {
            replicator.register_node(create_test_node(&format!("dual{}", i), true, true, 0.9 - i as f64 * 0.1));
        }
        for i in 0..2 {
            replicator.register_node(create_test_node(&format!("v4_{}", i), true, false, 0.6 - i as f64 * 0.1));
        }
        for i in 0..2 {
            replicator.register_node(create_test_node(&format!("v6_{}", i), false, true, 0.5 - i as f64 * 0.1));
        }

        let key = [1u8; 32];
        let selection = replicator.select_replica_nodes(&key, &[]);

        // Should have enough replicas for both families
        assert!(selection.count_by_family(IpFamily::IPv4) >= 2);
        assert!(selection.count_by_family(IpFamily::IPv6) >= 2);
    }

    #[test]
    fn test_replication_health_check() {
        let replicator = CrossNetworkReplicator::new(CrossNetworkReplicationConfig::default());

        let key = [2u8; 32];
        let node1 = NodeId { hash: [1u8; 32] };
        let node2 = NodeId { hash: [2u8; 32] };
        let node3 = NodeId { hash: [3u8; 32] };
        let node4 = NodeId { hash: [4u8; 32] };

        // Good replication - 2 per family
        let replicas = vec![
            (node1.clone(), IpFamily::IPv4),
            (node2.clone(), IpFamily::IPv4),
            (node3.clone(), IpFamily::IPv6),
            (node4.clone(), IpFamily::IPv6),
        ];

        let status = replicator.check_replication_health(&key, &replicas);
        assert!(status.is_healthy);
        assert!(status.missing_replicas.is_empty());

        // Poor replication - missing IPv6
        let poor_replicas = vec![
            (node1.clone(), IpFamily::IPv4),
            (node2.clone(), IpFamily::IPv4),
        ];

        let poor_status = replicator.check_replication_health(&key, &poor_replicas);
        assert!(!poor_status.is_healthy);
        assert!(poor_status.missing_replicas.contains_key(&IpFamily::IPv6));
    }

    #[test]
    fn test_ip_family_opposite() {
        assert_eq!(IpFamily::IPv4.opposite(), IpFamily::IPv6);
        assert_eq!(IpFamily::IPv6.opposite(), IpFamily::IPv4);
    }

    #[test]
    fn test_record_replication_status() {
        let key = [3u8; 32];
        let mut status = RecordReplicationStatus::new(key);

        assert_eq!(status.replica_count(IpFamily::IPv4), 0);
        assert_eq!(status.total_replicas(), 0);

        status.replicas_by_family.insert(
            IpFamily::IPv4,
            vec![NodeId { hash: [1u8; 32] }, NodeId { hash: [2u8; 32] }],
        );
        status.replicas_by_family.insert(
            IpFamily::IPv6,
            vec![NodeId { hash: [3u8; 32] }],
        );

        assert_eq!(status.replica_count(IpFamily::IPv4), 2);
        assert_eq!(status.replica_count(IpFamily::IPv6), 1);
        assert_eq!(status.total_replicas(), 3);
    }

    #[test]
    fn test_remove_node() {
        let replicator = CrossNetworkReplicator::new(CrossNetworkReplicationConfig::default());

        let node = create_test_node("test", true, true, 0.9);
        let node_id = node.node_id.clone();

        replicator.register_node(node);
        assert_eq!(replicator.get_diversity_stats().total_nodes, 1);

        replicator.remove_node(&node_id);
        assert_eq!(replicator.get_diversity_stats().total_nodes, 0);
    }

    #[test]
    fn test_replica_selection_with_exclusions() {
        let replicator = CrossNetworkReplicator::new(CrossNetworkReplicationConfig::default());

        // Register 5 dual-stack nodes
        for i in 0..5 {
            replicator.register_node(create_test_node(&format!("node{}", i), true, true, 0.9 - i as f64 * 0.1));
        }

        // Exclude first two nodes
        let excluded: Vec<NodeId> = (0..2)
            .map(|i| {
                let name = format!("node{}", i);
                NodeId {
                    hash: {
                        let mut h = [0u8; 32];
                        h[..name.len().min(32)].copy_from_slice(name.as_bytes());
                        h
                    },
                }
            })
            .collect();

        let key = [4u8; 32];
        let selection = replicator.select_replica_nodes(&key, &excluded);

        // Excluded nodes should not be in selection
        for node_id in &excluded {
            assert!(!selection.contains(node_id));
        }
    }

    #[test]
    fn test_diversity_stats() {
        let replicator = CrossNetworkReplicator::new(CrossNetworkReplicationConfig::default());

        let stats = replicator.get_diversity_stats();
        assert_eq!(stats.total_nodes, 0);
        assert_eq!(stats.replication_health_ratio, 1.0); // No records = healthy

        // Add some nodes
        replicator.register_node(create_test_node("n1", true, true, 0.9));
        replicator.register_node(create_test_node("n2", true, false, 0.8));
        replicator.register_node(create_test_node("n3", false, true, 0.7));

        let stats = replicator.get_diversity_stats();
        assert_eq!(stats.total_nodes, 3);
        assert_eq!(stats.dual_stack_nodes, 1);
        assert_eq!(stats.ipv4_only_nodes, 1);
        assert_eq!(stats.ipv6_only_nodes, 1);
    }
}
