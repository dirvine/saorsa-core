// Copyright (c) 2025 Saorsa Labs Limited
//
// This file is part of the Saorsa P2P network.
//
// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

//! Placement Loop & Storage Orchestration System
//!
//! This module implements the core placement system for optimal distribution
//! of erasure-coded shards across the network, integrating EigenTrust reputation,
//! churn prediction, capacity constraints, and diversity rules.
//!
//! ## Core Concepts
//!
//! ### Weighted Selection Algorithm
//!
//! The placement system uses Efraimidis-Spirakis weighted sampling with the formula:
//!
//! ```text
//! w_i = (τ_i^α) * (p_i^β) * (c_i^γ) * d_i
//! ```
//!
//! Where:
//! - `τ_i`: EigenTrust reputation score (0.0-1.0)
//! - `p_i`: Node performance score (0.0-1.0)
//! - `c_i`: Available capacity score (0.0-1.0)
//! - `d_i`: Geographic/network diversity bonus (1.0-2.0)
//! - `α, β, γ`: Configurable weight exponents
//!
//! ### Byzantine Fault Tolerance
//!
//! Implements configurable f-out-of-3f+1 Byzantine fault tolerance:
//! - Tolerates up to f Byzantine (malicious) nodes
//! - Requires minimum 3f+1 nodes for safety
//! - Automatically adjusts replication based on network size
//!
//! ### Geographic Diversity
//!
//! Ensures optimal shard distribution across:
//! - Geographic regions (7 major regions)
//! - Autonomous System Numbers (ASNs)
//! - Network operators and data centers
//!
//! ## Usage Examples
//!
//! ### Basic Placement
//!
//! ```rust,no_run
//! use saorsa_core::placement::{PlacementEngine, PlacementConfig};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = PlacementConfig {
//!     replication_factor: (3, 8).into(),
//!     byzantine_tolerance: 2.into(),
//!     placement_timeout: Duration::from_secs(30),
//!     geographic_diversity: true,
//!     ..Default::default()
//! };
//!
//! let mut engine = PlacementEngine::new(config);
//!
//! // Select optimal nodes for shard placement
//! let decision = engine.select_nodes(
//!     &available_nodes,
//!     8, // replication factor
//!     &trust_system,
//!     &performance_monitor,
//!     &node_metadata,
//! ).await?;
//!
//! println!("Selected {} nodes with {:.2}% reliability",
//!          decision.selected_nodes.len(),
//!          decision.estimated_reliability * 100.0);
//! # Ok(())
//! # }
//! ```
//!
//! ### Advanced Configuration
//!
//! ```rust,no_run
//! use saorsa_core::placement::{
//!     PlacementConfig, OptimizationWeights, PlacementConstraint
//! };
//! use std::time::Duration;
//!
//! let config = PlacementConfig {
//!     weights: OptimizationWeights {
//!         trust_weight: 0.5,      // High trust emphasis
//!         performance_weight: 0.25,
//!         capacity_weight: 0.15,
//!         diversity_bonus: 0.1,
//!     },
//!     constraints: vec![
//!         PlacementConstraint::MinimumTrustScore(0.7),
//!         PlacementConstraint::MaximumLatency(Duration::from_millis(500)),
//!         PlacementConstraint::RequireGeographicDiversity,
//!     ],
//!     ..Default::default()
//! };
//! ```
//!
//! ### Storage Orchestration
//!
//! ```rust,no_run
//! use saorsa_core::placement::PlacementOrchestrator;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let orchestrator = PlacementOrchestrator::new(
//!     config,
//!     dht_engine,
//!     trust_system,
//!     performance_monitor,
//!     churn_predictor,
//! ).await?;
//!
//! // Start audit and repair systems
//! orchestrator.start().await?;
//!
//! // Place data with optimal distribution
//! let decision = orchestrator.place_data(
//!     data,
//!     8, // replication factor
//!     Some(NetworkRegion::Europe),
//! ).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Architecture
//!
//! The placement system consists of several key components:
//!
//! - **PlacementEngine**: Main orchestrator for placement decisions
//! - **WeightedPlacementStrategy**: Implements the weighted selection algorithm
//! - **StorageOrchestrator**: Manages shard storage and retrieval
//! - **AuditSystem**: Continuous monitoring of shard health
//! - **RepairSystem**: Automatic repair with hysteresis control
//! - **DiversityEnforcer**: Geographic and network diversity constraints
//!
//! ## Performance Characteristics
//!
//! - **Selection Speed**: <1 second for 8-node selection from 1000+ candidates
//! - **Memory Usage**: O(n) where n is candidate node count
//! - **Audit Frequency**: Every 5 minutes with concurrent limits
//! - **Repair Latency**: <1 hour detection, immediate repair initiation
//!
//! ## Security Features
//!
//! - EigenTrust integration for reputation-based selection
//! - Byzantine fault tolerance with configurable parameters
//! - Proof-of-work for DHT records (~18 bits difficulty)
//! - Cryptographic verification of all operations
//! - Secure random selection with cryptographic entropy

pub mod algorithms;
pub mod dht_records;
pub mod errors;
pub mod orchestrator;
pub mod traits;
pub mod types;

// Re-export core types for convenience
pub use algorithms::{DiversityEnforcer, WeightedPlacementStrategy, WeightedSampler};
pub use dht_records::{
    DataPointer, DhtRecord, GroupBeacon, NatType, NodeAd, NodeCapabilities, OsSignature,
    RegisterPointer,
};
pub use errors::{PlacementError, PlacementResult};
pub use orchestrator::{AuditSystem, PlacementOrchestrator, RepairSystem, StorageOrchestrator};
pub use traits::{
    NetworkTopology, NodePerformanceMetrics, PerformanceEstimator, PlacementConstraint,
    PlacementStrategy, PlacementValidator,
};
pub use types::{
    ByzantineTolerance, GeographicLocation, NetworkRegion, OptimizationWeights, PlacementConfig,
    PlacementDecision, PlacementMetrics, ReplicationFactor,
};

use std::collections::HashSet;
use std::time::Instant;

use crate::adaptive::{NodeId, performance::PerformanceMonitor, trust::EigenTrustEngine};

/// Main placement engine that orchestrates the entire placement process
#[derive(Debug)]
pub struct PlacementEngine {
    config: PlacementConfig,
    strategy: Box<dyn PlacementStrategy + Send + Sync>,
}

impl PlacementEngine {
    /// Create new placement engine with default weighted strategy
    pub fn new(config: PlacementConfig) -> Self {
        let strategy = Box::new(algorithms::WeightedPlacementStrategy::new(config.clone()));

        Self { config, strategy }
    }

    /// Create placement engine with custom strategy
    pub fn with_strategy(
        config: PlacementConfig,
        strategy: Box<dyn PlacementStrategy + Send + Sync>,
    ) -> Self {
        Self { config, strategy }
    }

    /// Select optimal nodes for shard placement
    pub async fn select_nodes(
        &mut self,
        available_nodes: &HashSet<NodeId>,
        replication_factor: u8,
        trust_system: &EigenTrustEngine,
        performance_monitor: &PerformanceMonitor,
        node_metadata: &std::collections::HashMap<NodeId, (GeographicLocation, u32, NetworkRegion)>,
    ) -> PlacementResult<PlacementDecision> {
        let start_time = Instant::now();

        // Validate inputs
        if available_nodes.is_empty() {
            return Err(PlacementError::InsufficientNodes {
                required: replication_factor as usize,
                available: 0,
            });
        }

        if replication_factor < self.config.replication_factor.min_value() {
            return Err(PlacementError::InvalidReplicationFactor(replication_factor));
        }

        // Apply placement timeout
        let timeout_future = async {
            tokio::time::sleep(self.config.placement_timeout).await;
            Err(PlacementError::PlacementTimeout)
        };

        let placement_future = self.strategy.select_nodes(
            available_nodes,
            replication_factor,
            trust_system,
            performance_monitor,
            node_metadata,
        );

        // Race placement against timeout
        let mut decision = match tokio::select! {
            result = placement_future => result?,
            timeout_result = timeout_future => timeout_result?,
        } {
            result => result,
        };

        // Update timing information
        decision.selection_time = start_time.elapsed();

        // Validate against configuration constraints
        self.validate_decision(&decision)?;

        Ok(decision)
    }

    /// Validate placement decision against configuration constraints
    fn validate_decision(&self, decision: &PlacementDecision) -> PlacementResult<()> {
        // Check minimum nodes
        if decision.selected_nodes.len() < self.config.replication_factor.min_value() as usize {
            return Err(PlacementError::InsufficientNodes {
                required: self.config.replication_factor.min_value() as usize,
                available: decision.selected_nodes.len(),
            });
        }

        // Check Byzantine fault tolerance
        let required_for_byzantine = self.config.byzantine_tolerance.required_nodes();
        if decision.selected_nodes.len() < required_for_byzantine {
            return Err(PlacementError::ByzantineToleranceViolation {
                required: required_for_byzantine,
                available: decision.selected_nodes.len(),
            });
        }

        // Check reliability threshold
        if decision.estimated_reliability < 0.8 {
            return Err(PlacementError::ReliabilityTooLow {
                estimated: decision.estimated_reliability,
                minimum: 0.8,
            });
        }

        Ok(())
    }

    /// Get current configuration
    pub fn config(&self) -> &PlacementConfig {
        &self.config
    }

    /// Update configuration
    pub fn update_config(&mut self, config: PlacementConfig) {
        self.config = config;
    }

    /// Get strategy name
    pub fn strategy_name(&self) -> &str {
        self.strategy.name()
    }
}
