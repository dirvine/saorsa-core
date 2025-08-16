// Copyright (c) 2025 Saorsa Labs Limited
//
// This file is part of the Saorsa P2P network.
//
// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

//! Placement System Example
//!
//! This example demonstrates how to use the Saorsa Core placement system
//! for optimal shard distribution with EigenTrust integration and Byzantine
//! fault tolerance.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use saorsa_core::placement::{
    PlacementEngine, PlacementConfig, PlacementOrchestrator,
    OptimizationWeights, GeographicLocation, NetworkRegion,
    ReplicationFactor, ByzantineTolerance, PlacementConstraint,
};
use saorsa_core::adaptive::{
    NodeId, trust::EigenTrustEngine, performance::PerformanceMonitor,
    learning::ChurnPredictor,
};
use saorsa_core::dht::core_engine::DhtCoreEngine;
use saorsa_core::error::P2pResult;

#[tokio::main]
async fn main() -> P2pResult<()> {
    // Initialize logging
    tracing_subscriber::init();

    println!("🚀 Saorsa Core Placement System Example");
    println!("=========================================");

    // Example 1: Basic placement configuration
    basic_placement_example().await?;
    
    // Example 2: Advanced placement with constraints
    advanced_placement_example().await?;
    
    // Example 3: Full orchestrator with audit and repair
    orchestrator_example().await?;

    println!("\n✅ All placement examples completed successfully!");
    Ok(())
}

/// Basic placement engine usage
async fn basic_placement_example() -> P2pResult<()> {
    println!("\n📋 Example 1: Basic Placement Engine");
    println!("-----------------------------------");

    // Configure basic placement settings
    let config = PlacementConfig {
        replication_factor: ReplicationFactor::range(3, 8),
        byzantine_tolerance: ByzantineTolerance::new(2),
        placement_timeout: Duration::from_secs(30),
        geographic_diversity: true,
        weights: OptimizationWeights::balanced(),
    };

    // Create placement engine
    let mut engine = PlacementEngine::new(config);

    // Mock available nodes
    let available_nodes = create_mock_nodes(20).await?;
    let node_metadata = create_mock_metadata(&available_nodes).await?;

    // Mock trust and performance systems
    let trust_system = create_mock_trust_system().await?;
    let performance_monitor = create_mock_performance_monitor().await?;

    println!("Available nodes: {}", available_nodes.len());
    println!("Replication factor: 8");

    // Perform placement
    let decision = engine.select_nodes(
        &available_nodes,
        8, // replication factor
        &trust_system,
        &performance_monitor,
        &node_metadata,
    ).await?;

    println!("✅ Placement completed!");
    println!("   Selected {} nodes", decision.selected_nodes.len());
    println!("   Estimated reliability: {:.2}%", decision.estimated_reliability * 100.0);
    println!("   Selection time: {:?}", decision.selection_time);
    println!("   Strategy used: {}", decision.strategy_used);

    Ok(())
}

/// Advanced placement with custom constraints
async fn advanced_placement_example() -> P2pResult<()> {
    println!("\n🔧 Example 2: Advanced Placement Configuration");
    println!("----------------------------------------------");

    // Advanced configuration with custom weights and constraints
    let config = PlacementConfig {
        replication_factor: ReplicationFactor::range(5, 12),
        byzantine_tolerance: ByzantineTolerance::new(3),
        placement_timeout: Duration::from_secs(45),
        geographic_diversity: true,
        
        weights: OptimizationWeights {
            trust_weight: 0.5,      // High emphasis on trust
            performance_weight: 0.25,
            capacity_weight: 0.15,
            diversity_bonus: 0.1,
        },
        
        constraints: vec![
            PlacementConstraint::MinimumTrustScore(0.7),
            PlacementConstraint::MaximumLatency(Duration::from_millis(500)),
            PlacementConstraint::RequireGeographicDiversity,
        ],
    };

    println!("Configuration:");
    println!("   Trust weight: {:.1}%", config.weights.trust_weight * 100.0);
    println!("   Performance weight: {:.1}%", config.weights.performance_weight * 100.0);
    println!("   Capacity weight: {:.1}%", config.weights.capacity_weight * 100.0);
    println!("   Diversity bonus: {:.1}%", config.weights.diversity_bonus * 100.0);
    println!("   Constraints: {} active", config.constraints.len());

    let mut engine = PlacementEngine::new(config);

    // Create a larger set of nodes for demonstration
    let available_nodes = create_mock_nodes(50).await?;
    let node_metadata = create_mock_metadata(&available_nodes).await?;

    let trust_system = create_mock_trust_system().await?;
    let performance_monitor = create_mock_performance_monitor().await?;

    // Perform placement with higher replication
    let decision = engine.select_nodes(
        &available_nodes,
        10, // higher replication factor
        &trust_system,
        &performance_monitor,
        &node_metadata,
    ).await?;

    println!("✅ Advanced placement completed!");
    println!("   Selected {} nodes from {} candidates", 
             decision.selected_nodes.len(), available_nodes.len());
    println!("   Estimated reliability: {:.3}%", decision.estimated_reliability * 100.0);

    // Analyze geographic distribution
    let mut region_counts = HashMap::new();
    for node_id in &decision.selected_nodes {
        if let Some((_, _, region)) = node_metadata.get(node_id) {
            *region_counts.entry(*region).or_insert(0) += 1;
        }
    }

    println!("   Geographic distribution:");
    for (region, count) in region_counts {
        println!("     {:?}: {} nodes", region, count);
    }

    Ok(())
}

/// Full orchestrator with audit and repair systems
async fn orchestrator_example() -> P2pResult<()> {
    println!("\n🏗️  Example 3: Full Placement Orchestrator");
    println!("------------------------------------------");

    // Configuration for production-like setup
    let config = PlacementConfig {
        replication_factor: ReplicationFactor::range(4, 10),
        byzantine_tolerance: ByzantineTolerance::new(2),
        placement_timeout: Duration::from_secs(30),
        geographic_diversity: true,
        weights: OptimizationWeights::production(),
    };

    // Mock required systems
    let dht_engine = create_mock_dht_engine().await?;
    let trust_system = create_mock_trust_system().await?;
    let performance_monitor = create_mock_performance_monitor().await?;
    let churn_predictor = create_mock_churn_predictor().await?;

    println!("Creating placement orchestrator...");

    // Create full orchestrator
    let orchestrator = PlacementOrchestrator::new(
        config,
        dht_engine,
        trust_system,
        performance_monitor,
        churn_predictor,
    ).await?;

    println!("Starting audit and repair systems...");

    // Start background systems
    orchestrator.start().await?;

    // Simulate data placement
    let test_data = b"Important data that needs to be stored reliably across the network";
    
    println!("Placing {} bytes of data...", test_data.len());

    let decision = orchestrator.place_data(
        test_data.to_vec(),
        8, // replication factor
        Some(NetworkRegion::NorthAmerica),
    ).await?;

    println!("✅ Data placement completed!");
    println!("   Placed {} shards across {} nodes", 
             decision.shard_count, decision.selected_nodes.len());
    println!("   Target region: North America");

    // Get placement metrics
    let metrics = orchestrator.get_metrics().await;
    println!("   Total placements: {}", metrics.total_placements);
    println!("   Success rate: {:.2}%", metrics.success_rate * 100.0);
    println!("   Average placement time: {:?}", metrics.average_placement_time);

    println!("\n🔍 Audit and repair systems are now running in the background");
    println!("   Audit interval: 5 minutes");
    println!("   Repair threshold: 70% availability");
    println!("   Hysteresis band: 10%");

    Ok(())
}

// Helper functions for creating mock objects

async fn create_mock_nodes(count: usize) -> P2pResult<HashSet<NodeId>> {
    let mut nodes = HashSet::new();
    for i in 0..count {
        let mut node_id = [0u8; 32];
        node_id[0] = (i / 256) as u8;
        node_id[1] = (i % 256) as u8;
        nodes.insert(NodeId::from(node_id));
    }
    Ok(nodes)
}

async fn create_mock_metadata(
    nodes: &HashSet<NodeId>,
) -> P2pResult<HashMap<NodeId, (GeographicLocation, u32, NetworkRegion)>> {
    let mut metadata = HashMap::new();
    
    // Sample coordinates for different regions
    let regions = vec![
        (40.7128, -74.0060, NetworkRegion::NorthAmerica), // New York
        (51.5074, -0.1278, NetworkRegion::Europe),        // London
        (35.6762, 139.6503, NetworkRegion::Asia),         // Tokyo
        (-33.8688, 151.2093, NetworkRegion::Oceania),     // Sydney
        (-23.5505, -46.6333, NetworkRegion::SouthAmerica), // São Paulo
        (30.0444, 31.2357, NetworkRegion::Africa),        // Cairo
    ];
    
    for (i, node_id) in nodes.iter().enumerate() {
        let (lat, lon, region) = regions[i % regions.len()];
        let location = GeographicLocation::new(lat, lon)
            .map_err(|_| saorsa_core::error::P2PError::validation("Invalid coordinates"))?;
        let asn = 12345 + (i as u32 % 1000);
        
        metadata.insert(node_id.clone(), (location, asn, region));
    }
    
    Ok(metadata)
}

async fn create_mock_trust_system() -> P2pResult<EigenTrustEngine> {
    // Mock implementation - in real usage this would be properly initialized
    EigenTrustEngine::new().await
}

async fn create_mock_performance_monitor() -> P2pResult<PerformanceMonitor> {
    // Mock implementation - in real usage this would be properly initialized
    PerformanceMonitor::new().await
}

async fn create_mock_churn_predictor() -> P2pResult<Arc<ChurnPredictor>> {
    // Mock implementation - in real usage this would be properly initialized
    let predictor = ChurnPredictor::new().await?;
    Ok(Arc::new(predictor))
}

async fn create_mock_dht_engine() -> P2pResult<Arc<DhtCoreEngine>> {
    // Mock implementation - in real usage this would be properly initialized
    // For this example, we'll create a minimal mock
    // In practice, this would require proper initialization with storage backend
    unimplemented!("Mock DHT engine - implement based on your DHT setup")
}

impl OptimizationWeights {
    /// Balanced weights for general use
    pub fn balanced() -> Self {
        Self {
            trust_weight: 0.3,
            performance_weight: 0.3,
            capacity_weight: 0.3,
            diversity_bonus: 0.1,
        }
    }
    
    /// Production-optimized weights
    pub fn production() -> Self {
        Self {
            trust_weight: 0.4,
            performance_weight: 0.3,
            capacity_weight: 0.2,
            diversity_bonus: 0.1,
        }
    }
}