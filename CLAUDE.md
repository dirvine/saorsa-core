# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Core Development Commands
```bash
# Build
cargo build                        # Debug build
cargo build --release              # Release build
cargo build --all-features         # Build with all features

# Tests - MUST ALL PASS before committing
cargo test                         # Run all tests
cargo test --lib                   # Unit tests only
cargo test --test '*'              # All integration tests
cargo test --test adaptive_components_test  # Specific integration test
cargo test test_name               # Run specific test by name
cargo test --features "proptest"   # Property-based tests
cargo test -- --nocapture          # Show println! output
RUST_LOG=debug cargo test          # With debug logging

# Code Quality - MUST PASS before committing
cargo fmt                          # Format code
cargo clippy -- -D warnings -D clippy::unwrap_used -D clippy::expect_used  # Strict linting
cargo audit                        # Security vulnerability check

# Benchmarks
cargo bench                        # Run all benchmarks
cargo bench --bench dht_benchmark # Run specific benchmark

# Documentation
cargo doc --open                   # Build and open documentation
```

### Adaptive Network Testing
```bash
./scripts/test_adaptive_network.sh  # Run adaptive component tests suite
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
let value = some_option.ok_or(Error::MissingValue)?;
let result = some_result.context("operation failed")?;

// ❌ WRONG - Will fail CI/CD
let value = some_option.unwrap();
let result = some_result.expect("failed");
```

## Architecture Overview

### Core Layer Structure

The codebase follows a multi-layer P2P architecture with machine learning-driven adaptive routing:

1. **Transport Layer** (`src/transport/`)
   - Uses `ant-quic` (NOT quinn) for QUIC transport with NAT traversal
   - `ant_quic_adapter.rs` provides `P2PNetworkNode` integration
   - Post-quantum cryptography support

2. **Adaptive Network Layer** (`src/adaptive/`)
   - **Coordinator** (`coordinator.rs`): Central orchestration for adaptive components
   - **Multi-Armed Bandit** (`multi_armed_bandit.rs`): Thompson Sampling for strategy selection
   - **Routing Strategies**:
     - Kademlia DHT (`routing.rs`)
     - Hyperbolic routing (`hyperbolic.rs`, `hyperbolic_enhanced.rs`)
     - Trust-based with EigenTrust++ (`trust.rs`)
     - Self-Organizing Maps (`som.rs`)
   - **Machine Learning Components**:
     - Q-Learning cache optimization (`q_learning_cache.rs`)
     - Churn prediction (`churn_prediction.rs`)
     - Beta distribution for bandit (`beta_distribution.rs`)

3. **DHT Layer** (`src/dht/`)
   - Kademlia-based with K=8 replication factor
   - `core_engine.rs` - Main DHT implementation
   - Geographic routing extensions
   - Content-addressed storage with BLAKE3
   - Reed-Solomon encoding (prefer `saorsa-fec` crate)

4. **Identity System** (`src/identity/`)
   - Ed25519 cryptographic identities
   - Four-word human-readable addresses (`four_words.rs`, `four_words_extensions.rs`)
   - Enhanced identity with ML-DSA quantum resistance

5. **Storage Layer** (`src/storage/`)
   - SQLite persistence via SQLx
   - DHT-based encrypted storage
   - Multi-device synchronization

6. **Application Features**
   - Chat system (`src/chat/`) - Slack-like messaging
   - Discuss system (`src/discuss/`) - Discourse-like forums
   - Projects (`src/projects/`) - Hierarchical organization
   - MCP server (`src/mcp/`) - Model Context Protocol for AI integration

7. **Bootstrap** (`src/bootstrap/`)
   - Network discovery and initialization

### Key Architectural Decisions

1. **ant-quic over quinn**: Uses `ant-quic` for QUIC transport. Remove any quinn references.

2. **Adaptive Routing**: ML-driven strategy selection based on:
   - Network conditions (stable, high-churn, adversarial)
   - Content type (small messages, large files, real-time streams)
   - Latency requirements

3. **Four-Word Addressing**: Human-readable addresses using `four-word-networking` crate.

4. **Dual Licensing**: AGPL-3.0 for open source, commercial license available.

## External Crate Dependencies

### Saorsa Ecosystem Crates
- `saorsa-rsps` (0.1.0) - Root-Scoped Provider Summaries for DHT optimization
- `saorsa-fec` - Forward error correction (preferred over `reed-solomon-erasure`)
- `four-word-networking` (2.3+) - Human-readable network addresses
- `ant-quic` (0.6+) - QUIC transport with NAT traversal

### Feature Flags
```toml
default = ["dht", "mcp", "ant-quic"]
dht = []                    # Distributed Hash Table
mcp = []                    # Model Context Protocol
four-word addresses are always enabled via dependency
ant-quic = []              # QUIC transport
quantum-resistant = []      # Post-quantum cryptography
threshold = []             # Threshold cryptography
cli = []                   # CLI tools
metrics = []               # Prometheus metrics
commercial = []            # Commercial license features
agpl-compliance = []       # AGPL compliance notices
```

## Testing Strategy

### Test Categories
1. **Unit Tests**: In-module `#[cfg(test)]` blocks
2. **Integration Tests**: `tests/` directory
3. **Property-Based Tests**: Using `proptest` and `quickcheck`
4. **Benchmarks**: `benches/` directory using Criterion

### Running Specific Test Types
```bash
# Unit tests only
cargo test --lib

# Specific integration test file
cargo test --test ant_quic_integration_test
cargo test --test eigentrust_integration_test
cargo test --test gossipsub_integration_test

# Specific test function
cargo test --test adaptive_components_test test_thompson_sampling_basic

# With output
cargo test -- --nocapture
RUST_LOG=debug cargo test
```

## Common Development Patterns

### Adding New Adaptive Strategy
1. Implement strategy in `src/adaptive/`
2. Add to `RoutingStrategy` enum in `routing.rs`
3. Update multi-armed bandit in `multi_armed_bandit.rs`
4. Add performance metrics in `performance.rs`
5. Write integration tests in `tests/adaptive_components_test.rs`

### Network Node Creation
```rust
use saorsa_core::transport::ant_quic_adapter::P2PNetworkNode;

let bind_addr = "127.0.0.1:0".parse()?;
let node = P2PNetworkNode::new(bind_addr).await?;
```

### DHT Operations
```rust
use saorsa_core::Network;

// Store data
network.store(key, value.to_vec()).await?;

// Retrieve data
if let Some(data) = network.retrieve(key).await? {
    // Process data
}
```

### Four-Word Address Usage
```rust
use saorsa_core::NetworkAddress;

// Create from IP
let addr = NetworkAddress::from_ipv4("192.168.1.1".parse()?, 9000);

// Get four-word representation
if let Some(words) = addr.four_words() {
    println!("Address: {}", words);
}

// Parse from four-word format
let addr = NetworkAddress::from_four_words("alpha-beta-gamma-delta")?;
```

## CI/CD Pipeline

GitHub Actions workflow (`.github/workflows/rust.yml`) enforces:
1. **Formatting**: `cargo fmt --all -- --check`
2. **Linting**: `cargo clippy --all-features -- -D warnings`
3. **Tests**: All tests must pass on stable and nightly
4. **Security**: `cargo audit` for vulnerability scanning
5. **Coverage**: Code coverage via `cargo-llvm-cov`
6. **Benchmarks**: Run on main branch pushes

## System Dependencies

For local development, install:
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

## Important Files and Modules

### Documentation
- `docs/NETWORK_ARCHITECTURE.md` - Complete system architecture
- `docs/CODE_QUALITY_STANDARDS.md` - Quality enforcement details

### Core Implementation
- `src/network.rs` - Main P2P network implementation
- `src/adaptive/coordinator.rs` - Central coordination for adaptive networking
- `src/transport/ant_quic_adapter.rs` - QUIC transport integration
- `src/dht/core_engine.rs` - DHT engine implementation
- `src/identity/four_words.rs` - Four-word addressing system

### Configuration
- `.github/workflows/rust.yml` - CI/CD pipeline configuration
- `Cargo.toml` - Dependencies and feature flags

## WebRTC and Media Support

The codebase includes full WebRTC stack for voice/video:
- WebRTC components in dependencies
- Media processing with `image`, `blurhash`, `symphonia`
- Audio playback with `rodio`

## Database and Persistence

Uses SQLx with SQLite for message persistence:
- Async database operations
- Migration support
- UUID and chrono integration

## Performance Optimization

- Parking lot for faster mutexes
- LRU caching throughout
- BLAKE3 for fast hashing
- Criterion for benchmarking