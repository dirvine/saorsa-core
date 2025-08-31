# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Core Commands
```bash
# Build
cargo build                         # Debug build
cargo build --release               # Release build
cargo build --all-features          # Build with all features

# Tests - MUST ALL PASS before committing
cargo test                          # Run all tests
cargo test --lib                    # Unit tests only
cargo test --test '<test_name>'     # Specific integration test
cargo test test_function_name       # Run specific test by name
cargo test -- --nocapture           # Show println! output
RUST_LOG=debug cargo test           # With debug logging

# Code Quality - MUST PASS before committing
cargo fmt                           # Format code
cargo clippy -- -D warnings -D clippy::unwrap_used -D clippy::expect_used  # Strict linting
cargo audit                         # Security vulnerability check

# Benchmarks
cargo bench                         # Run all benchmarks
cargo bench --bench dht_benchmark  # Run specific benchmark

# Documentation
cargo doc --open                    # Build and open documentation
```

### Adaptive Network Testing Suite
```bash
./scripts/test_adaptive_network.sh  # Run adaptive component tests

# Individual adaptive component tests
cargo test --test adaptive_components_test test_thompson_sampling_basic --release
cargo test --test adaptive_components_test test_multi_armed_bandit_basic --release
cargo test --test adaptive_components_test test_q_learning_cache_basic --release
```

## Critical Code Standards

### NO PANICS IN PRODUCTION CODE - ZERO TOLERANCE
Production code **MUST NOT** contain:
- `.unwrap()` - Use `?` operator or `.ok_or()`
- `.expect()` - Use `.context()` from `anyhow` instead  
- `panic!()` - Return `Result` instead
- `unimplemented!()` or `todo!()` - Complete all implementations
- `println!()` - Use `tracing` for logging

**Exception**: Test code (`#[cfg(test)]`) may use `.unwrap()` and `.expect()` for assertions.

### Error Handling Pattern
```rust
// ✅ CORRECT
let value = some_option.ok_or(P2PError::MissingValue)?;
let result = some_result.context("operation failed")?;

// ❌ WRONG - Will fail CI/CD
let value = some_option.unwrap();
let result = some_result.expect("failed");
```

## Architecture Overview

### Multi-Layer P2P Architecture with ML-Driven Adaptive Routing

The system combines distributed hash table (DHT) storage with machine learning for optimal routing decisions based on network conditions.

#### 1. Transport Layer (`src/transport/`)
- **Primary**: `ant-quic` (0.6+) for QUIC transport with NAT traversal
- **Adapter**: `ant_quic_adapter.rs` provides `P2PNetworkNode` integration
- **Security**: Post-quantum cryptography support via feature flag

#### 2. Adaptive Network Layer (`src/adaptive/`)
Central to the system's intelligence, using ML for dynamic strategy selection:

- **Coordinator** (`coordinator.rs`): Orchestrates all adaptive components
- **Multi-Armed Bandit** (`multi_armed_bandit.rs`): Thompson Sampling for strategy selection
- **Beta Distribution** (`beta_distribution.rs`): Statistical modeling for bandit
- **Routing Strategies**:
  - Kademlia DHT routing
  - Hyperbolic routing for low-latency paths
  - Trust-based routing with EigenTrust++
  - Self-Organizing Maps (SOM) for topology
- **ML Components**:
  - Q-Learning cache optimization
  - Churn prediction for node stability
  - Performance tracking and metrics

#### 3. DHT Layer (`src/dht/`)
Distributed storage with geographic awareness:

- **Core Engine** (`core_engine.rs`): Kademlia-based with K=8 replication
- **Geographic Routing** (`geographic_routing.rs`): Region-aware peer selection
- **Latency-Aware Selection** (`latency_aware_selection.rs`): Smart peer choice
- **Network Integration** (`network_integration.rs`): Protocol handling
- **Witness System** (`witness.rs`): Byzantine fault tolerance
- **Optimizations**: RSPS (Root-Scoped Provider Summaries) via `saorsa-rsps`

#### 4. Identity System (`src/identity/`)
- **Cryptography**: Ed25519 for signatures, X25519 for key exchange
- **Four-Word Addresses**: Human-readable via `four-word-networking` crate
- **Quantum Resistance**: ML-DSA support (feature flag)

#### 5. Storage & Persistence (`src/storage/`)
- SQLite via SQLx for message persistence
- Encrypted DHT storage
- Multi-device synchronization

#### 6. Placement System (`src/placement/`)
Advanced storage orchestration with EigenTrust integration:

- **Placement Engine** (`mod.rs`): Main orchestrator for shard placement
- **Weighted Algorithms** (`algorithms.rs`): Efraimidis-Spirakis sampling with formula `w_i = (τ_i^α) * (p_i^β) * (c_i^γ) * d_i`
- **DHT Records** (`dht_records.rs`): NODE_AD, GROUP_BEACON, DATA_POINTER, REGISTER_POINTER (≤512B)
- **Storage Orchestrator** (`orchestrator.rs`): Audit and repair systems with hysteresis
- **Geographic Diversity** (`types.rs`): Location-aware placement constraints
- **Byzantine Tolerance**: Configurable f-out-of-3f+1 fault tolerance
- **Zero-Panic Code**: Comprehensive error handling with recovery patterns

#### 7. Application Features
- **Chat** (`src/chat/`): Slack-like messaging
- **Discuss** (`src/discuss/`): Forum system
- **Projects** (`src/projects/`): Hierarchical organization

## Key Architectural Patterns

### Network Node Creation
```rust
use saorsa_core::transport::ant_quic_adapter::P2PNetworkNode;

let bind_addr = "127.0.0.1:0".parse()?;
let node = P2PNetworkNode::new(bind_addr).await?;
```

### DHT Operations with Consistency Levels
```rust
use saorsa_core::dht::core_engine::{DhtCoreEngine, ConsistencyLevel};

// Store with quorum consistency
engine.store_with_consistency(
    key,
    value,
    ConsistencyLevel::Quorum,
    Duration::from_secs(3600)
).await?;

// Retrieve with eventual consistency
let data = engine.retrieve_with_consistency(
    key,
    ConsistencyLevel::Eventual
).await?;
```

### Adaptive Strategy Selection
```rust
use saorsa_core::adaptive::coordinator::AdaptiveCoordinator;

// Coordinator automatically selects best strategy
let strategy = coordinator.select_strategy(
    &network_conditions,
    &content_type
).await?;
```

### Four-Word Address Usage
```rust
use saorsa_core::NetworkAddress;

// Parse from four-word format
let addr = NetworkAddress::from_four_words("alpha-beta-gamma-delta")?;

// Convert IP to four-words
let addr = NetworkAddress::from_ipv4("192.168.1.1".parse()?, 9000);
if let Some(words) = addr.four_words() {
    println!("Address: {}", words);
}
```

### Placement System Usage
```rust
use saorsa_core::placement::{
    PlacementEngine, PlacementConfig, PlacementOrchestrator,
    OptimizationWeights, GeographicLocation, NetworkRegion
};

// Configure placement with EigenTrust integration
let config = PlacementConfig {
    replication_factor: (3, 8).into(),
    byzantine_tolerance: 2.into(),
    placement_timeout: Duration::from_secs(30),
    geographic_diversity: true,
    weights: OptimizationWeights {
        trust_weight: 0.4,        // EigenTrust reputation
        performance_weight: 0.3,   // Node performance metrics  
        capacity_weight: 0.2,      // Available storage capacity
        diversity_bonus: 0.1,      // Geographic/network diversity
    },
};

// Create placement orchestrator
let orchestrator = PlacementOrchestrator::new(
    config,
    dht_engine,
    trust_system,
    performance_monitor,
    churn_predictor,
).await?;

// Start audit and repair systems
orchestrator.start().await?;

// Place data with optimal shard distribution
let decision = orchestrator.place_data(
    data,
    8, // replication factor
    Some(NetworkRegion::Europe),
).await?;
```

## External Crate Dependencies

### Saorsa Ecosystem
- `saorsa-rsps` (0.1.0): DHT optimization with provider summaries
- `saorsa-fec`: Forward error correction (prefer over `reed-solomon-erasure`)
- `four-word-networking` (2.3+): Human-readable addresses
- `ant-quic` (0.6+): QUIC transport with NAT traversal

### Feature Flags
```toml
default = ["dht", "ant-quic"]
dht = []                    # Distributed Hash Table
ant-quic = []               # QUIC transport (recommended)
quantum-resistant = []      # Post-quantum cryptography
threshold = []              # Threshold cryptography
metrics = []                # Prometheus metrics
```

## Testing Infrastructure

### Test Organization
- **Unit Tests**: In-module `#[cfg(test)]` blocks
- **Integration Tests**: `tests/` directory (38 test files)
- **Disabled Tests**: Files with `.disabled` extension (API compatibility issues)
- **Property Tests**: Using `proptest` for randomized testing

### Key Integration Tests
```bash
# Core functionality
cargo test --test ant_quic_integration_test      # QUIC transport
cargo test --test dht_core_operations_test        # DHT operations
cargo test --test adaptive_components_test        # Adaptive networking
cargo test --test four_word_integration_test      # Address system

# Security & trust
cargo test --test eigentrust_integration_test     # Trust system
cargo test --test security_comprehensive_test     # Security validation

# Network simulation
cargo test --test full_network_simulation         # End-to-end simulation
cargo test --test gossipsub_integration_test      # Gossip protocol
```

## CI/CD Pipeline

GitHub Actions enforces quality standards on every commit:

1. **Format Check**: `cargo fmt --all -- --check`
2. **Clippy Linting**: `cargo clippy --all-features -- -D warnings`
3. **Security Audit**: `cargo audit`
4. **Test Matrix**: Stable and nightly Rust
5. **Code Coverage**: via `cargo-llvm-cov`
6. **System Dependencies**: Audio/video libraries for WebRTC

## System Dependencies

Required for local development:
```bash
# Ubuntu/Debian
sudo apt-get install -y \
  pkg-config \
  libssl-dev \
  libasound2-dev \
  libpulse-dev \
  libdbus-1-dev \
  portaudio19-dev \
  build-essential
```

## Common Development Workflows

### Adding New Adaptive Strategy
1. Implement in `src/adaptive/`
2. Add to `RoutingStrategy` enum
3. Update multi-armed bandit
4. Add performance metrics
5. Write tests in `tests/adaptive_components_test.rs`

### Adding New Placement Strategy
1. Implement `PlacementStrategy` trait in `src/placement/algorithms.rs`
2. Add strategy to placement engine configuration
3. Ensure geographic diversity compliance
4. Add EigenTrust integration hooks
5. Write comprehensive tests with property-based testing
6. Benchmark placement performance
7. Document algorithm complexity and trade-offs

### DHT Operation with Witnesses
```rust
// Store with witness validation
let witnesses = engine.select_witnesses(&key, 3)?;
let receipt = engine.store_with_witnesses(
    key,
    value,
    &witnesses,
    Duration::from_secs(3600)
).await?;
```

### Network Monitoring
```rust
use saorsa_core::adaptive::performance::PerformanceMonitor;

let monitor = PerformanceMonitor::new();
monitor.record_latency(peer_id, Duration::from_millis(50));
let metrics = monitor.get_metrics(peer_id)?;
```

## Important Implementation Details

### DHT Configuration
- **Replication Factor**: K=8 (8 replicas per key)
- **Consistency Levels**: Eventual, Quorum, All
- **Geographic Awareness**: Regional peer preference
- **Witness System**: Byzantine fault tolerance

### Adaptive Network Behavior
- **Thompson Sampling**: Balances exploration vs exploitation
- **Q-Learning**: Optimizes cache decisions
- **Churn Prediction**: Anticipates node departures
- **Strategy Selection**: Based on network conditions and content type

### Placement System Configuration
- **Weighted Selection Formula**: `w_i = (τ_i^α) * (p_i^β) * (c_i^γ) * d_i`
  - `τ_i`: EigenTrust reputation score (0.0-1.0)
  - `p_i`: Performance score (0.0-1.0)
  - `c_i`: Capacity score (0.0-1.0)
  - `d_i`: Diversity bonus multiplier (1.0-2.0)
- **Byzantine Tolerance**: f-out-of-3f+1 nodes (configurable f)
- **DHT Record Limits**: ≤512 bytes with proof-of-work (~18 bits)
- **Audit Frequency**: 5-minute intervals with concurrent limits
- **Repair Hysteresis**: 10% band to prevent repair storms
- **Geographic Regions**: 7 major regions with ASN diversity

### Performance Optimizations
- **Connection Pooling**: Max 100 connections with LRU eviction
- **Message Batching**: 10ms window, 64KB max batch
- **Caching**: LRU caches throughout with configurable TTL
- **Hashing**: BLAKE3 for speed, SHA2 for compatibility
- **Placement Decisions**: <1s for 8-node selection
- **Shard Repair**: Lazy repair with 1-hour cooldown

## Licensing

Dual-licensed:
- **AGPL-3.0**: For open source use
- **Commercial**: Contact saorsalabs@gmail.com

All files must include the copyright header with dual-licensing notice.
