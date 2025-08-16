# Placement System Architecture

## Overview

The Saorsa Core Placement System implements intelligent storage orchestration with EigenTrust integration, Byzantine fault tolerance, and automatic shard repair. It provides optimal distribution of erasure-coded data shards across the network while maintaining high availability and security.

## Core Components

### 1. Placement Engine (`src/placement/mod.rs`)

The main orchestrator that coordinates placement decisions:

```rust
use saorsa_core::placement::{PlacementEngine, PlacementConfig};

let config = PlacementConfig {
    replication_factor: (3, 8).into(),
    byzantine_tolerance: 2.into(),
    placement_timeout: Duration::from_secs(30),
    geographic_diversity: true,
    weights: OptimizationWeights::balanced(),
};

let engine = PlacementEngine::new(config);
```

### 2. Weighted Selection Algorithm (`src/placement/algorithms.rs`)

Implements Efraimidis-Spirakis weighted sampling with the formula:

```
w_i = (τ_i^α) * (p_i^β) * (c_i^γ) * d_i
```

Where:
- `τ_i`: EigenTrust reputation score (0.0-1.0)
- `p_i`: Node performance score (0.0-1.0)  
- `c_i`: Available capacity score (0.0-1.0)
- `d_i`: Geographic/network diversity bonus (1.0-2.0)
- `α, β, γ`: Configurable weight exponents

### 3. DHT Record Types (`src/placement/dht_records.rs`)

Efficient record types with ≤512B serialization:

- **NODE_AD**: Node advertisement with capabilities
- **GROUP_BEACON**: Group formation and membership
- **DATA_POINTER**: Content location information
- **REGISTER_POINTER**: Mutable data references

All records include proof-of-work (~18 bits) and TTL (60 minutes).

### 4. Storage Orchestrator (`src/placement/orchestrator.rs`)

Manages the complete placement lifecycle:

```rust
let orchestrator = PlacementOrchestrator::new(
    config,
    dht_engine,
    trust_system,
    performance_monitor,
    churn_predictor,
).await?;

// Start audit and repair systems
orchestrator.start().await?;

// Place data with optimal distribution
let decision = orchestrator.place_data(
    data,
    replication_factor,
    region_preference,
).await?;
```

## Key Features

### Byzantine Fault Tolerance

Configurable f-out-of-3f+1 fault tolerance model:

```rust
let config = PlacementConfig {
    byzantine_tolerance: ByzantineTolerance::new(2), // Tolerate 2 Byzantine nodes
    // Requires minimum 7 nodes (3*2+1)
    ..Default::default()
};
```

### Geographic Diversity

Ensures shards are distributed across different:
- Geographic regions (7 major regions)
- Autonomous System Numbers (ASNs)
- Network operators

```rust
let location = GeographicLocation::new(latitude, longitude)?;
let region = NetworkRegion::from_coordinates(&location);
```

### EigenTrust Integration

Trust scores directly influence placement decisions:

```rust
let weights = OptimizationWeights {
    trust_weight: 0.4,        // 40% weight on EigenTrust scores
    performance_weight: 0.3,   // 30% on performance metrics
    capacity_weight: 0.2,      // 20% on available capacity  
    diversity_bonus: 0.1,      // 10% geographic bonus
};
```

### Audit and Repair System

Continuous monitoring with hysteresis control:

- **Audit Frequency**: Every 5 minutes
- **Concurrent Audits**: Maximum 10 parallel
- **Repair Threshold**: 70% availability
- **Repair Hysteresis**: 10% band to prevent storms
- **Repair Cooldown**: 1 hour between repairs

## Usage Examples

### Basic Placement

```rust
use saorsa_core::placement::*;

// Create placement engine
let mut engine = PlacementEngine::new(PlacementConfig::default());

// Get available nodes (from network discovery)
let available_nodes = get_network_nodes().await?;

// Select optimal nodes for placement
let decision = engine.select_nodes(
    &available_nodes,
    8, // replication factor
    &trust_system,
    &performance_monitor,
    &node_metadata,
).await?;

println!("Selected {} nodes with {:.2}% reliability", 
         decision.selected_nodes.len(),
         decision.estimated_reliability * 100.0);
```

### Advanced Configuration

```rust
let config = PlacementConfig {
    replication_factor: ReplicationFactor::range(5, 12),
    byzantine_tolerance: ByzantineTolerance::new(3),
    placement_timeout: Duration::from_secs(45),
    geographic_diversity: true,
    
    weights: OptimizationWeights {
        trust_weight: 0.5,      // High trust emphasis
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
```

### Custom Placement Strategy

```rust
#[async_trait]
impl PlacementStrategy for CustomStrategy {
    async fn select_nodes(
        &mut self,
        candidates: &HashSet<NodeId>,
        replication_factor: u8,
        trust_system: &EigenTrustEngine,
        performance_monitor: &PerformanceMonitor,
        node_metadata: &HashMap<NodeId, (GeographicLocation, u32, NetworkRegion)>,
    ) -> PlacementResult<PlacementDecision> {
        // Custom placement logic here
        let selected_nodes = self.custom_selection_algorithm(
            candidates,
            replication_factor,
            trust_system,
        ).await?;
        
        Ok(PlacementDecision {
            selected_nodes,
            estimated_reliability: self.calculate_reliability(&selected_nodes),
            selection_time: start_time.elapsed(),
            strategy_used: "Custom".to_string(),
            shard_count: replication_factor as usize,
        })
    }
    
    fn name(&self) -> &str {
        "CustomStrategy"
    }
}
```

## Performance Characteristics

### Placement Performance

- **Selection Speed**: <1 second for 8-node selection from 1000+ candidates
- **Memory Usage**: O(n) where n is candidate node count
- **Network Overhead**: Minimal (uses cached node information)
- **Concurrency**: Fully async with tokio integration

### Storage Performance

- **Shard Distribution**: Parallel placement across selected nodes
- **Audit Frequency**: Configurable (default 5 minutes)
- **Repair Latency**: <1 hour detection, immediate repair initiation
- **Geographic Awareness**: <10ms region lookup via coordinate mapping

## Security Considerations

### Trust Integration

- EigenTrust scores range 0.0-1.0 with decay over time
- Reputation updates based on audit results
- Byzantine node detection through failed audits
- Trust transitivity for new node evaluation

### Proof of Work

DHT records include computational proof-of-work:
- Difficulty: ~18 bits (adjustable)
- Purpose: Rate limiting and spam prevention
- Verification: O(1) constant time
- Storage: 8 bytes per record

### Data Integrity

- Cryptographic verification of all shards
- Witness-based validation for critical operations
- Audit trails for all placement decisions
- Secure random selection with cryptographic entropy

## Error Handling

All placement operations use comprehensive error handling:

```rust
use saorsa_core::placement::{PlacementError, PlacementResult};

match placement_result {
    Ok(decision) => {
        // Handle successful placement
        process_placement_decision(decision).await?;
    }
    Err(PlacementError::InsufficientNodes { required, available }) => {
        // Handle insufficient nodes
        tracing::warn!("Only {} nodes available, need {}", available, required);
        fallback_placement_strategy().await?;
    }
    Err(PlacementError::PlacementTimeout) => {
        // Handle timeout
        retry_with_relaxed_constraints().await?;
    }
    Err(e) => {
        // Handle other errors
        tracing::error!("Placement failed: {}", e);
        return Err(e.into());
    }
}
```

## Testing Strategy

### Unit Tests

- Algorithm correctness verification
- Edge case handling (empty node sets, Byzantine majorities)
- Configuration validation
- Error condition testing

### Integration Tests

- End-to-end placement workflows
- EigenTrust integration validation
- Geographic diversity enforcement
- Performance benchmarking

### Property-Based Testing

Using `proptest` for randomized testing:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn placement_preserves_replication_factor(
        nodes in prop::collection::hash_set(node_id_strategy(), 10..100),
        replication_factor in 3u8..20u8,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            let decision = placement_engine.select_nodes(
                &nodes,
                replication_factor,
                &mock_trust_system,
                &mock_performance_monitor,
                &mock_metadata,
            ).await;
            
            prop_assert!(decision.is_ok());
            let decision = decision.unwrap();
            prop_assert_eq!(decision.selected_nodes.len(), replication_factor as usize);
        });
    }
}
```

## Future Enhancements

### Planned Features

1. **Machine Learning Integration**: Predictive placement based on usage patterns
2. **Dynamic Rebalancing**: Automatic shard migration for optimization
3. **Cost-Based Selection**: Economic incentives in placement decisions
4. **Hierarchical Placement**: Multi-tier storage with hot/cold data classification
5. **Cross-Datacenter Replication**: Global data distribution strategies

### Research Areas

- Quantum-resistant cryptographic integration
- Federated learning for decentralized optimization
- Graph neural networks for network topology analysis
- Zero-knowledge proofs for privacy-preserving audits

## References

- [EigenTrust Algorithm](https://nlp.stanford.edu/pubs/eigentrust.pdf)
- [Efraimidis-Spirakis Weighted Sampling](https://utopia.duth.gr/~pefraimi/research/data/2006EncOfAlg.pdf)
- [Byzantine Fault Tolerance](https://people.eecs.berkeley.edu/~luca/cs174/byzantine.pdf)
- [Reed-Solomon Error Correction](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction)