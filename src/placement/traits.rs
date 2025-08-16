// Copyright (c) 2025 Saorsa Labs Limited
//
// This file is part of the Saorsa P2P network.
//
// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

//! Trait definitions for the placement system
//!
//! Defines pluggable interfaces for placement strategies, network topology,
//! performance estimation, and constraint validation.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::adaptive::{trust::EigenTrustEngine, NodeId, performance::PerformanceMonitor};
use crate::placement::{
    GeographicLocation, NetworkRegion, PlacementDecision, PlacementResult,
};

/// Core trait for placement strategies
#[async_trait]
pub trait PlacementStrategy: Send + Sync + std::fmt::Debug {
    /// Select optimal nodes for placement
    async fn select_nodes(
        &mut self,
        candidates: &HashSet<NodeId>,
        replication_factor: u8,
        trust_system: &EigenTrustEngine,
        performance_monitor: &PerformanceMonitor,
        node_metadata: &HashMap<NodeId, (GeographicLocation, u32, NetworkRegion)>,
    ) -> PlacementResult<PlacementDecision>;

    /// Get strategy name
    fn name(&self) -> &str;

    /// Check if strategy supports constraints
    fn supports_constraints(&self) -> bool;
}

/// Network topology interface for geographic and structural information
#[async_trait]
pub trait NetworkTopology: Send + Sync {
    /// Get geographic location of a node
    async fn get_location(&self, node_id: &NodeId) -> Option<GeographicLocation>;

    /// Get network region of a node
    async fn get_region(&self, node_id: &NodeId) -> Option<NetworkRegion>;

    /// Get ASN (Autonomous System Number) of a node
    async fn get_asn(&self, node_id: &NodeId) -> Option<u32>;

    /// Calculate network distance between two nodes
    async fn network_distance(&self, node_a: &NodeId, node_b: &NodeId) -> Option<Duration>;

    /// Check if two nodes are in the same network segment
    async fn same_network_segment(&self, node_a: &NodeId, node_b: &NodeId) -> bool;
}

/// Performance estimation interface
#[async_trait]
pub trait PerformanceEstimator: Send + Sync {
    /// Get node performance metrics
    async fn get_metrics(&self, node_id: &NodeId) -> Option<NodePerformanceMetrics>;

    /// Predict node availability for the next period
    async fn predict_availability(&self, node_id: &NodeId, period: Duration) -> f64;

    /// Get node capacity utilization
    async fn get_capacity_utilization(&self, node_id: &NodeId) -> f64;

    /// Estimate operation latency for a node
    async fn estimate_latency(&self, node_id: &NodeId) -> Duration;
}

/// Constraint validation interface
#[async_trait]
pub trait PlacementConstraint: Send + Sync {
    /// Check if a node satisfies this constraint
    async fn validate_node(&self, node_id: &NodeId) -> bool;

    /// Check if a set of nodes satisfies this constraint
    async fn validate_selection(&self, nodes: &[NodeId]) -> bool;

    /// Get constraint name for debugging
    fn name(&self) -> &str;

    /// Get constraint severity (higher = more important)
    fn severity(&self) -> u8;
}

/// Final placement validation interface
#[async_trait]
pub trait PlacementValidator: Send + Sync {
    /// Validate a complete placement decision
    async fn validate(&self, decision: &PlacementDecision) -> PlacementResult<()>;

    /// Get validator name
    fn name(&self) -> &str;
}

/// Comprehensive node performance metrics
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodePerformanceMetrics {
    /// Node availability (0.0 - 1.0)
    pub availability: f64,
    /// Average latency in milliseconds
    pub latency_ms: f64,
    /// Bandwidth capacity in bytes per second
    pub bandwidth_bps: u64,
    /// Storage capacity in bytes
    pub storage_capacity: u64,
    /// Current storage utilization (0.0 - 1.0)
    pub storage_utilization: f64,
    /// CPU utilization (0.0 - 1.0)
    pub cpu_utilization: f64,
    /// Memory utilization (0.0 - 1.0)
    pub memory_utilization: f64,
    /// Network reliability score (0.0 - 1.0)
    pub network_reliability: f64,
    /// Churn rate (disconnections per hour)
    pub churn_rate: f64,
    /// Age of the node in hours
    pub node_age_hours: f64,
}

impl NodePerformanceMetrics {
    /// Create new metrics with validation
    pub fn new(
        availability: f64,
        latency_ms: f64,
        bandwidth_bps: u64,
        storage_capacity: u64,
        storage_utilization: f64,
        cpu_utilization: f64,
        memory_utilization: f64,
        network_reliability: f64,
        churn_rate: f64,
        node_age_hours: f64,
    ) -> PlacementResult<Self> {
        // Validate percentage values
        for (name, value) in [
            ("availability", availability),
            ("storage_utilization", storage_utilization),
            ("cpu_utilization", cpu_utilization),
            ("memory_utilization", memory_utilization),
            ("network_reliability", network_reliability),
        ] {
            if !(0.0..=1.0).contains(&value) {
                return Err(crate::placement::PlacementError::InvalidMetrics {
                    field: name.to_string(),
                    value,
                    reason: "Must be between 0.0 and 1.0".to_string(),
                });
            }
        }

        // Validate non-negative values
        if latency_ms < 0.0 {
            return Err(crate::placement::PlacementError::InvalidMetrics {
                field: "latency_ms".to_string(),
                value: latency_ms,
                reason: "Must be non-negative".to_string(),
            });
        }

        if churn_rate < 0.0 {
            return Err(crate::placement::PlacementError::InvalidMetrics {
                field: "churn_rate".to_string(),
                value: churn_rate,
                reason: "Must be non-negative".to_string(),
            });
        }

        if node_age_hours < 0.0 {
            return Err(crate::placement::PlacementError::InvalidMetrics {
                field: "node_age_hours".to_string(),
                value: node_age_hours,
                reason: "Must be non-negative".to_string(),
            });
        }

        Ok(Self {
            availability,
            latency_ms,
            bandwidth_bps,
            storage_capacity,
            storage_utilization,
            cpu_utilization,
            memory_utilization,
            network_reliability,
            churn_rate,
            node_age_hours,
        })
    }

    /// Calculate overall performance score (0.0 - 1.0)
    pub fn overall_score(&self) -> f64 {
        let weights = [
            (self.availability, 0.3),
            (1.0 - self.latency_ms / 1000.0, 0.2), // Invert latency
            (1.0 - self.storage_utilization, 0.1),
            (1.0 - self.cpu_utilization, 0.1),
            (1.0 - self.memory_utilization, 0.1),
            (self.network_reliability, 0.1),
            ((1.0 / (1.0 + self.churn_rate)), 0.1), // Invert churn rate
        ];

        let weighted_sum: f64 = weights.iter().map(|(score, weight)| score * weight).sum();
        weighted_sum.clamp(0.0, 1.0)
    }

    /// Check if node is suitable for storage
    pub fn is_suitable_for_storage(&self) -> bool {
        self.availability >= 0.8
            && self.storage_utilization <= 0.9
            && self.network_reliability >= 0.7
            && self.churn_rate <= 2.0 // Max 2 disconnections per hour
    }

    /// Estimate remaining capacity
    pub fn remaining_capacity(&self) -> u64 {
        ((1.0 - self.storage_utilization) * self.storage_capacity as f64) as u64
    }
}

impl Default for NodePerformanceMetrics {
    fn default() -> Self {
        Self {
            availability: 0.9,
            latency_ms: 50.0,
            bandwidth_bps: 1_000_000, // 1 Mbps
            storage_capacity: 10_000_000_000, // 10 GB
            storage_utilization: 0.5,
            cpu_utilization: 0.3,
            memory_utilization: 0.4,
            network_reliability: 0.8,
            churn_rate: 0.5,
            node_age_hours: 168.0, // 1 week
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_performance_metrics_validation() {
        // Test valid metrics
        let metrics = NodePerformanceMetrics::new(
            0.9, 50.0, 1_000_000, 10_000_000_000, 0.5, 0.3, 0.4, 0.8, 0.5, 168.0,
        );
        assert!(metrics.is_ok());

        // Test invalid availability
        let metrics = NodePerformanceMetrics::new(
            1.5, 50.0, 1_000_000, 10_000_000_000, 0.5, 0.3, 0.4, 0.8, 0.5, 168.0,
        );
        assert!(metrics.is_err());

        // Test negative latency
        let metrics = NodePerformanceMetrics::new(
            0.9, -10.0, 1_000_000, 10_000_000_000, 0.5, 0.3, 0.4, 0.8, 0.5, 168.0,
        );
        assert!(metrics.is_err());
    }

    #[test]
    fn test_overall_score_calculation() {
        let metrics = NodePerformanceMetrics::new(
            1.0, 10.0, 1_000_000, 10_000_000_000, 0.2, 0.1, 0.1, 0.9, 0.1, 168.0,
        ).unwrap();

        let score = metrics.overall_score();
        assert!(score >= 0.0 && score <= 1.0);
        assert!(score > 0.8); // Should be high for good metrics
    }

    #[test]
    fn test_storage_suitability() {
        // Good node
        let good_metrics = NodePerformanceMetrics::new(
            0.95, 20.0, 1_000_000, 10_000_000_000, 0.3, 0.2, 0.2, 0.9, 0.1, 168.0,
        ).unwrap();
        assert!(good_metrics.is_suitable_for_storage());

        // Poor availability
        let poor_availability = NodePerformanceMetrics::new(
            0.5, 20.0, 1_000_000, 10_000_000_000, 0.3, 0.2, 0.2, 0.9, 0.1, 168.0,
        ).unwrap();
        assert!(!poor_availability.is_suitable_for_storage());

        // High storage utilization
        let full_storage = NodePerformanceMetrics::new(
            0.95, 20.0, 1_000_000, 10_000_000_000, 0.95, 0.2, 0.2, 0.9, 0.1, 168.0,
        ).unwrap();
        assert!(!full_storage.is_suitable_for_storage());
    }

    #[test]
    fn test_remaining_capacity_calculation() {
        let metrics = NodePerformanceMetrics::new(
            0.9, 50.0, 1_000_000, 1_000_000_000, 0.3, 0.3, 0.4, 0.8, 0.5, 168.0,
        ).unwrap();

        let remaining = metrics.remaining_capacity();
        assert_eq!(remaining, 700_000_000); // 70% of 1GB
    }
}