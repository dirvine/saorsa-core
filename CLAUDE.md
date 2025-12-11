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

# Local CI Pipeline (safe, read-only checks)
./scripts/local_ci.sh               # Run full CI pipeline locally
./scripts/check_no_panic_unwrap.sh  # Check for forbidden patterns
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

### New Clean API (v0.3.16+)

The codebase provides a simplified multi-device API for decentralized identity, presence, and storage:

#### Identity and Presence Registration
```rust
use saorsa_core::{register_identity, register_presence, MlDsaKeyPair, Device, DeviceType, DeviceId, Endpoint};

// One-time identity registration
let words = ["welfare", "absurd", "king", "ridge"];
let keypair = MlDsaKeyPair::generate()?;
let handle = register_identity(words, &keypair).await?;

// Register devices (multi-device support)
let device = Device {
    id: DeviceId::generate(),
    device_type: DeviceType::Active,  // or Headless for storage nodes
    storage_gb: 100,
    endpoint: Endpoint {
        protocol: "quic".to_string(),
        address: "192.168.1.100:9000".to_string(),
    },
    capabilities: Default::default(),
};

let device_id = device.id;
register_presence(&handle, vec![device], device_id).await?;
```

#### Storage with Automatic Strategy Selection
```rust
use saorsa_core::{store_data, store_dyad, store_with_fec, get_data};

// Single user - Direct storage
let data = b"Private data".to_vec();
let storage_handle = store_data(&handle, data, 1).await?;

// Two users - Full replication  
let storage_handle = store_dyad(&handle1, handle2.key(), data).await?;

// Group - Automatic replication based on size (capped at 8 replicas)
let storage_handle = store_data(&handle, data, 10).await?; // Replicates to 8 peers

// Custom replication target (legacy API name)
let storage_handle = store_with_fec(&handle, data, 8, 4).await?;

// Retrieve (automatic decryption/reconstruction)
let retrieved = get_data(&storage_handle).await?;
```

Storage strategies are automatically selected based on group size:
- **1 user**: Direct storage (single active device)
- **2+ users**: Full replication across `min(group_size, 8)` devices (headless-first)
- **Custom**: `store_with_fec` interprets `data_shards + parity_shards` as the desired replica count (legacy name retained for compatibility)

### Multi-Layer P2P Architecture

The system combines distributed hash table (DHT) storage with machine learning for optimal routing:

#### 1. Transport Layer (`src/transport/`)
- **Primary**: `ant-quic` (0.8+) for QUIC transport with NAT traversal
- **Security**: Post-quantum cryptography (ML-DSA-65, ML-KEM-768)

#### 2. Adaptive Network Layer (`src/adaptive/`)
Central to the system's intelligence, using ML for dynamic strategy selection:
- **Multi-Armed Bandit**: Thompson Sampling for strategy selection
- **Routing Strategies**: Kademlia DHT, Hyperbolic routing, Trust-based routing
- **ML Components**: Q-Learning cache optimization, Churn prediction

#### 3. DHT Layer (`src/dht/`)
Distributed storage with geographic awareness:
- **Core Engine**: Kademlia-based with K=8 replication
- **Geographic Routing**: Region-aware peer selection
- **Witness System**: Byzantine fault tolerance
- **Optimizations**: RSPS (Root-Scoped Provider Summaries) via `saorsa-rsps`

#### 4. Identity System (`src/identity/`)
- **Cryptography**: ML-DSA-65 for post-quantum signatures
- **Four-Word Addresses**: Human-readable via `four-word-networking` crate
- **No PoW**: Pure cryptographic identity without proof-of-work

#### 5. Placement System (`src/placement/`)
Advanced storage orchestration with EigenTrust integration:
- **Weighted Selection Formula**: `w_i = (τ_i^α) * (p_i^β) * (c_i^γ) * d_i`
- **Byzantine Tolerance**: Configurable f-out-of-3f+1 fault tolerance
- **DHT Records**: NODE_AD, GROUP_BEACON, DATA_POINTER (≤512B)

## External Crate Dependencies

### Saorsa Ecosystem
- `saorsa-rsps` (0.1.0): DHT optimization with provider summaries
- `saorsa-fec`: Forward error correction
- `saorsa-seal`: Encryption library
- `four-word-networking` (2.3+): Human-readable addresses
- `ant-quic` (0.8+): QUIC transport with NAT traversal

### Feature Flags
```toml
default = ["metrics"]
metrics = ["dep:prometheus", "ant-quic/prometheus"]  # Prometheus monitoring
```

## Testing Infrastructure

### Test Organization
- **Unit Tests**: In-module `#[cfg(test)]` blocks
- **Integration Tests**: `tests/` directory
- **Property Tests**: Using `proptest` for randomized testing

### Key Integration Tests
```bash
# New API Tests (v0.3.16+)
cargo test --test api_implementation_tests       # Clean API implementation
cargo test --test storage_tests                  # Storage strategies & replication

# Core functionality  
cargo test --test ant_quic_integration_test      # QUIC transport
cargo test --test dht_core_operations_test        # DHT operations
cargo test --test adaptive_components_test        # Adaptive networking

# Security & trust
cargo test --test eigentrust_integration_test     # Trust system
cargo test --test security_comprehensive_test     # Security validation
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

## Important Implementation Details

### DHT Configuration
- **Replication Factor**: K=8 (8 replicas per key)
- **Consistency Levels**: Eventual, Quorum, All
- **Geographic Awareness**: Regional peer preference
- **Witness System**: Byzantine fault tolerance

### Placement System Configuration
- **Weighted Selection Formula**: `w_i = (τ_i^α) * (p_i^β) * (c_i^γ) * d_i`
  - `τ_i`: EigenTrust reputation score (0.0-1.0)
  - `p_i`: Performance score (0.0-1.0)
  - `c_i`: Capacity score (0.0-1.0)
  - `d_i`: Diversity bonus multiplier (1.0-2.0)
- **Byzantine Tolerance**: f-out-of-3f+1 nodes (configurable f)
- **DHT Record Limits**: ≤512 bytes
- **Audit Frequency**: 5-minute intervals with concurrent limits

### Performance Optimizations
- **Connection Pooling**: Max 100 connections with LRU eviction
- **Message Batching**: 10ms window, 64KB max batch
- **Caching**: LRU caches throughout with configurable TTL
- **Hashing**: BLAKE3 for speed, SHA2 for compatibility

## Licensing

Dual-licensed:
- **AGPL-3.0**: For open source use
- **Commercial**: Contact saorsalabs@gmail.com

All files must include the copyright header with dual-licensing notice.
