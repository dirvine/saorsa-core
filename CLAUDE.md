# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Standard Development Commands
```bash
# Build the project
cargo build
cargo build --release

# Run tests
cargo test                          # Run all tests
cargo test --test '*'              # Run all integration tests
cargo test test_name               # Run specific test
cargo test --features "proptest"   # Run property-based tests

# Code quality checks (MUST pass before committing)
cargo fmt                          # Format code
cargo clippy -- -D warnings -D clippy::unwrap_used -D clippy::expect_used  # Strict linting
cargo audit                        # Security vulnerability check

# Benchmarks
cargo bench                        # Run all benchmarks
cargo bench --bench dht_benchmark # Run specific benchmark

# Documentation
cargo doc --open                   # Build and open documentation
```

### Git Hooks Setup
```bash
./setup-git-hooks.sh              # Enable pre-commit quality checks
```

## Critical Code Standards

### NO PANICS IN PRODUCTION CODE
Production code **MUST NOT** contain:
- `.unwrap()` - Use `?` operator or proper error handling
- `.expect()` - Use `.context()` from `anyhow` instead  
- `panic!()` - Return errors instead
- `unimplemented!()` or `todo!()` - Complete all implementations

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
   - Post-quantum cryptography support built-in

2. **Adaptive Network Layer** (`src/adaptive/`)
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
   - Geographic routing extensions
   - Content-addressed storage with BLAKE3
   - Reed-Solomon encoding (should use `saorsa-fec` crate)

4. **Identity System** (`src/identity/`)
   - Ed25519 cryptographic identities
   - Four-word human-readable addresses
   - Enhanced identity with ML-DSA quantum resistance

5. **Storage Layer** (`src/storage/`)
   - DHT-based encrypted storage
   - Multi-device synchronization
   - Note: Full entity storage with markdown web publishing is in separate crates

6. **Application Features**
   - Chat system (`src/chat/`) - Slack-like messaging
   - Discuss system (`src/discuss/`) - Discourse-like forums
   - Projects (`src/projects/`) - Hierarchical organization
   - MCP server (`src/mcp/`) - Model Context Protocol for AI integration

### Key Architectural Decisions

1. **ant-quic over quinn**: The codebase uses `ant-quic` for QUIC transport, NOT quinn. All quinn references should be removed.

2. **Adaptive Routing**: The system doesn't commit to a single routing algorithm but uses ML to select the best strategy based on:
   - Network conditions (stable, high-churn, adversarial)
   - Content type (small messages, large files, real-time streams)
   - Latency requirements

3. **Four-Word Addressing**: Human-readable addresses using `four-word-networking` crate for better UX.

4. **Dual Licensing**: AGPL-3.0 for open source, commercial license available.

## External Crate Dependencies

### Saorsa Ecosystem Crates
- `saorsa-rsps` (0.1.0) - Root-Scoped Provider Summaries for DHT
- `saorsa-fec` - Forward error correction (Reed-Solomon) - preferred over `reed-solomon-erasure`
- `four-word-networking` (2.3+) - Human-readable network addresses
- `ant-quic` (0.6+) - QUIC transport with NAT traversal

### Feature Flags
```toml
default = ["dht", "mcp", "ant-quic", "four-word-addresses"]
dht = []                    # Distributed Hash Table
mcp = []                    # Model Context Protocol
four-word-addresses = []    # Human-readable addresses
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
cargo test --lib                   # Unit tests only
cargo test --test ant_quic_integration_test  # Specific integration test
cargo test -- --nocapture         # Show println! output
RUST_LOG=debug cargo test         # With debug logging
```

## Common Development Patterns

### Adding New Adaptive Strategy
1. Implement strategy in `src/adaptive/`
2. Add to `RoutingStrategy` enum in `routing.rs`
3. Update multi-armed bandit in `multi_armed_bandit.rs`
4. Add performance metrics in `performance.rs`
5. Write integration tests

### Network Node Creation
```rust
use saorsa_core::transport::ant_quic_adapter::P2PNetworkNode;

let bind_addr = "127.0.0.1:0".parse()?;
let node = P2PNetworkNode::new(bind_addr).await?;
```

### DHT Operations
```rust
// Store data
network.store(key, value.to_vec()).await?;

// Retrieve data
if let Some(data) = network.retrieve(key).await? {
    // Process data
}
```

## CI/CD Pipeline

GitHub Actions workflow (`.github/workflows/rust.yml`) enforces:
1. Formatting with `cargo fmt`
2. Clippy with strict panic prevention
3. All tests must pass
4. Security audit via `cargo audit`
5. Runs on both stable and nightly Rust

## Important Files

- `docs/NETWORK_ARCHITECTURE.md` - Complete system architecture
- `docs/CODE_QUALITY_STANDARDS.md` - Quality enforcement details
- `src/adaptive/coordinator.rs` - Central coordination for adaptive networking
- `src/network.rs` - Main P2P network implementation
- `src/transport/ant_quic_adapter.rs` - QUIC transport integration