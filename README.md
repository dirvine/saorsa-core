# Saorsa Core

[![CI](https://github.com/dirvine/saorsa-core-foundation/actions/workflows/rust.yml/badge.svg)](https://github.com/dirvine/saorsa-core-foundation/actions/workflows/rust.yml)
[![Crates.io](https://img.shields.io/crates/v/saorsa-core.svg)](https://crates.io/crates/saorsa-core)
[![Documentation](https://docs.rs/saorsa-core/badge.svg)](https://docs.rs/saorsa-core)

Core P2P networking library for Saorsa platform with DHT, QUIC transport, dual-stack endpoints (IPv6+IPv4), and four-word endpoint encoding.

## Documentation

- **API Reference**: see [docs/API.md](docs/API.md) - Comprehensive API documentation with examples
- **Architecture Decision Records**: see [docs/adr/](docs/adr/) - Design decisions and rationale
- **Security Model**: see [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) - Network security and anti-Sybil protections
- **Auto-Upgrade System**: see [docs/AUTO_UPGRADE.md](docs/AUTO_UPGRADE.md) - Cross-platform binary updates
- Architecture overview: see [ARCHITECTURE.md](ARCHITECTURE.md)
- Contributor guide: see [AGENTS.md](AGENTS.md)

## Architecture Decision Records (ADRs)

Key design decisions are documented in [docs/adr/](docs/adr/):

| ADR | Title | Description |
|-----|-------|-------------|
| [ADR-001](docs/adr/ADR-001-multi-layer-architecture.md) | Multi-Layer P2P Architecture | Layered design separating transport, DHT, identity, and application concerns |
| [ADR-002](docs/adr/ADR-002-delegated-transport.md) | Delegated Transport | Using ant-quic for QUIC transport, NAT traversal, and bootstrap cache |
| [ADR-003](docs/adr/ADR-003-pure-post-quantum-crypto.md) | Pure Post-Quantum Cryptography | ML-DSA-65 and ML-KEM-768 without classical fallbacks |
| [ADR-004](docs/adr/ADR-004-four-word-addresses.md) | Four-Word Addresses | Human-readable addressing via word encoding |
| [ADR-006](docs/adr/ADR-006-eigentrust-reputation.md) | EigenTrust Reputation | Iterative trust computation for Sybil resistance |
| [ADR-007](docs/adr/ADR-007-adaptive-networking.md) | Adaptive Networking | Machine learning for dynamic routing optimization |
| [ADR-008](docs/adr/ADR-008-bootstrap-delegation.md) | Bootstrap Cache Delegation | Delegating bootstrap to ant-quic with Sybil protection |
| [ADR-009](docs/adr/ADR-009-sybil-protection.md) | Sybil Protection | Multi-layered defense against identity attacks |
| [ADR-011](docs/adr/ADR-011-geographic-placement.md) | Geographic Placement | Region-aware storage for regulatory compliance |
| [ADR-012](docs/adr/ADR-012-identity-without-pow.md) | Identity without PoW | Pure cryptographic identity using ML-DSA |

## Features

- **P2P NAT Traversal**: True peer-to-peer connectivity with automatic NAT traversal (ant-quic 0.10.0+)
- **DHT (Distributed Hash Table)**: Peer phonebook and routing with adaptive scoring and geographic awareness
- **Placement System**: Intelligent shard placement with EigenTrust integration
- **QUIC Transport**: High-performance networking with ant-quic
- **Four-Word Endpoints**: Human‑readable network endpoints via `four-word-networking` (IPv4+port encodes to 4 words; decoding returns both IP and port; IPv6 word count decided by the crate).
- **Post-Quantum Cryptography**: Future-ready cryptographic algorithms
- **Geographic Routing**: Location-aware networking
- **Identity Management**: Post-quantum ML-DSA-65 signatures (NIST Level 3). No PoW; identities hold only required keys (no embedded word address).
- **Auto-Upgrade System**: Cross-platform binary updates with ML-DSA-65 signatures, rollback support, and configurable policies
- **Persistence**: Database-backed internal state (telemetry, caches, coordination)
- **Monitoring**: Prometheus metrics integration

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
saorsa-core = "0.5.0"
```

### Basic P2P Node

```rust
use saorsa_core::{NodeConfig, P2PNode};
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create and start a P2P node
    let config = NodeConfig::default();
    let node = P2PNode::new(config).await?;
    node.run().await?;
    
    Ok(())
}
```

### P2P NAT Traversal

saorsa-core includes full NAT traversal support in the transport and network layers, enabling direct peer-to-peer connections. User-facing messaging examples live in saorsa-node, while this crate provides the transport and DHT primitives.

### Data Replication (saorsa-node)

saorsa-core does **not** replicate application data. saorsa-node:
- Stores chunks locally and tracks replica sets.
- Selects target peers using saorsa-core’s adaptive routing outputs.
- Replicates via `send_message` and reports success/failure back to EigenTrust.
- Reacts to churn events from `DhtNetworkManager::subscribe_events()` and re‑replicates.

Minimal wiring helper:
```rust
use saorsa_core::adaptive::ReplicaPlanner;
use saorsa_core::DhtNetworkEvent;

let planner = ReplicaPlanner::new(adaptive_dht, dht_manager);
let mut events = planner.subscribe_churn();
tokio::spawn(async move {
    while let Ok(DhtNetworkEvent::PeerDisconnected { peer_id }) = events.recv().await {
        // re-replicate any data that had replicas on peer_id
    }
});
```

### Four-Word Endpoints

- Endpoints are encoded/decoded using the `four-word-networking` crate's adaptive API.
- IPv4+port → 4 words; decoding returns both IP and port. IPv6 → word count is crate‑defined.
- Four‑words are reserved strictly for network endpoints.

## Architecture

### Core Components

1. **Network Layer**: QUIC-based P2P networking with automatic NAT traversal (ant-quic 0.10.0+)
2. **DHT**: S/Kademlia-based peer phonebook with adaptive routing and geographic awareness
3. **Placement System**: Intelligent shard placement with weighted selection algorithms
4. **Identity**: Post‑quantum cryptographic identities with ML‑DSA‑65 signatures (no PoW; no embedded four‑word address)
5. **Application Storage**: Implemented in saorsa-node; saorsa-core tracks trust signals
6. **Geographic Routing**: Location-aware message routing


### Cryptographic Architecture

Saorsa Core implements a pure post-quantum cryptographic approach for maximum security:

- **Post‑quantum signatures**: ML‑DSA‑65 (FIPS 204) for quantum‑resistant digital signatures (~128‑bit quantum security)
- **PQC Encryption**: saorsa-pqc primitives for key encapsulation and signatures
- **Key Exchange**: ML-KEM-768 (FIPS 203) for quantum-resistant key encapsulation (~128-bit quantum security)
- **Hashing**: BLAKE3 for fast, secure content addressing
- **Transport Security**: QUIC with TLS 1.3 and PQC cipher suites
- **No Legacy Support**: Pure PQC implementation with no classical cryptographic fallbacks

### Recent Changes

- Removed all Proof‑of‑Work (PoW) usage (identity, adaptive, placement/DHT, error types, CLI).
- Adopted `four-word-networking` adaptive API; four‑words reserved for endpoints only.
- Implemented dual‑stack listeners (IPv6 + IPv4) and Happy Eyeballs dialing.

### Data Flow

```
Application
    ↓
Network API
    ↓
Placement Engine → DHT + Geographic Routing
    ↓              ↓
    ↓         Audit & Repair
    ↓              ↓
QUIC Transport (ant-quic)
    ↓
Internet
```

### Placement System

Saorsa Core includes an advanced placement system for optimal distribution of erasure-coded shards across the network:

```rust
use saorsa_core::placement::{
    PlacementEngine, PlacementConfig, GeographicLocation, NetworkRegion
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure placement system
    let config = PlacementConfig {
        replication_factor: (3, 8).into(), // Min 3, target 8 replicas
        byzantine_tolerance: 2.into(),      // Tolerate up to 2 Byzantine nodes
        placement_timeout: Duration::from_secs(30),
        geographic_diversity: true,
        weights: OptimizationWeights {
            trust_weight: 0.4,        // EigenTrust reputation
            performance_weight: 0.3,   // Node performance metrics
            capacity_weight: 0.2,      // Available storage capacity
            diversity_bonus: 0.1,      // Geographic/network diversity
        },
    };
    
    // Create placement engine
    let mut engine = PlacementEngine::new(config);
    
    // Place data with optimal shard distribution
    let data = b"important data to store";
    let decision = placement_orchestrator.place_data(
        data.to_vec(),
        8, // replication factor
        Some(NetworkRegion::NorthAmerica),
    ).await?;
    
    println!("Placed {} shards across {} nodes", 
             decision.shard_count, 
             decision.selected_nodes.len());
    
    Ok(())
}
```

#### Key Features

- **EigenTrust Integration**: Uses reputation scores for node selection
- **Weighted Selection**: Balances trust, performance, capacity, and diversity
- **Byzantine Fault Tolerance**: Configurable f-out-of-3f+1 security model
- **Geographic Diversity**: Ensures shards are distributed across regions
- **Continuous Monitoring**: Audit system with automatic repair
- **DHT Record Types**: Efficient ≤512B records with cryptographic validation
- **Hysteresis Control**: Prevents repair storms with smart cooldown

## Configuration

```rust
use saorsa_core::NetworkConfig;

let config = NetworkConfig {
    listen_port: 9000,
    bootstrap_nodes: vec![
        "bootstrap1.example.com:9000".parse()?,
        "bootstrap2.example.com:9000".parse()?,
    ],
    enable_four_word_addresses: true,
    dht_replication: 20,
    storage_capacity: 1024 * 1024 * 1024, // 1GB
    ..Default::default()
};
```

## Feature Flags

- `default` - Metrics and Prometheus integration
- `metrics` - Prometheus metrics and monitoring
- `mocks` - Test/dummy helpers for development (off by default)
- `h2_greedy` - Hyperbolic greedy routing helpers in API
- `test-utils` - Test utilities including mock DHT for integration tests

Note: DHT, ant-quic QUIC transport, and post-quantum cryptography are always enabled. Four-word networking is a core feature.

## Performance

Saorsa Core is designed for high performance:

- **Concurrent Operations**: Tokio-based async runtime
- **Memory Efficiency**: Zero-copy operations where possible
- **Network Optimization**: QUIC with congestion control
- **Caching**: Multi-level caching with Q-learning optimization

### Benchmarks

Run benchmarks with:

```bash
cargo bench
```

Key benchmarks:
- DHT operations: ~10,000 ops/sec
- Storage throughput: ~100 MB/sec
- Geographic routing: <10ms latency
- Placement decisions: <1s for 8-node selection
- Shard repair: Automatic with <1h detection
- Cryptographic operations: Hardware-accelerated

## Security

Saorsa Core implements defense-in-depth security designed for adversarial decentralized environments.

**For complete security documentation, see [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).**

### Cryptographic Foundation

- **Post-Quantum Signatures**: ML-DSA-65 (FIPS 204) for quantum-resistant digital signatures (~128-bit quantum security)
- **Key Exchange**: ML-KEM-768 (FIPS 203) for quantum-resistant key encapsulation
- **Symmetric Encryption**: Provided by upper layers; saorsa-core focuses on PQC key exchange and signatures
- **Hashing**: BLAKE3 for fast, secure content addressing
- **Pure PQC**: No classical cryptographic fallbacks - quantum-resistant from the ground up

### Network Protection

| Protection | Implementation |
|------------|----------------|
| **Node Monitoring** | Automatic eviction after 3 consecutive failures |
| **Reputation System** | EigenTrust++ with multi-factor trust scoring |
| **Sybil Resistance** | IP diversity limits (/64: 1, /48: 3, /32: 10, ASN: 20) |
| **Geographic Diversity** | Regional diversity in routing and placement |
| **Routing Validation** | Close-group validation and security coordinator checks |

### Anti-Centralization

The network enforces geographic and infrastructure diversity to prevent centralization:

```
┌───────────────────────────────────────────────────┐
│           Geographic Diversity Distribution        │
├───────────────────────────────────────────────────┤
│  Region A      Region B      Region C      ...    │
│  (max 2)       (max 2)       (max 2)              │
│     │             │             │                 │
│     └─────────────┼─────────────┘                 │
│                   ▼                               │
│    Selection prefers 3+ regions                   │
│    (prevents regional collusion)                  │
└───────────────────────────────────────────────────┘
```

- **ASN Diversity**: Max 20 nodes per autonomous system
- **Hosting Provider Limits**: Stricter limits (halved) for known VPS/cloud providers
- **Eclipse Detection**: Continuous routing table diversity monitoring

## Persistence

Persistence lives in `src/persistence/` with pluggable backends and configuration-driven
storage policies. See `src/persistence/SPECIFICATION.md` for current settings.

## Geographic Features

Location-aware networking:

- Geographic distance calculations
- Location-based routing
- Regional content distribution
- Privacy-preserving location services

## Development

### Building

```bash
# Standard build
cargo build --release

# With all features
cargo build --all-features

# Feature-specific build
cargo build --features "dht,quantum-resistant"
```

### Testing

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test '*'

# Property-based tests
cargo test --features "proptest"
```

### Linting

```bash
cargo clippy --all-features -- -D warnings
cargo fmt --all
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Code Style

- Follow Rust 2024 idioms
- Use `cargo fmt` for formatting
- Ensure `cargo clippy` passes
- Add documentation for public APIs
- Include tests for all new features

## License

This project is dual-licensed:

- **AGPL-3.0**: Open source license for open source projects
- **Commercial**: Commercial license for proprietary projects

For commercial licensing, contact: david@saorsalabs.com

## Dependencies

### Core Dependencies
- `tokio` - Async runtime
- `futures` - Future utilities
- `serde` - Serialization
- `anyhow` - Error handling
- `tracing` - Logging

### Networking
- `ant-quic` (0.10.0+) - QUIC transport with P2P NAT traversal
- `four-word-networking` - Human-readable addresses

### Cryptography
- `saorsa-pqc` - Post-quantum cryptography (ML-DSA, ML-KEM)
- `blake3` - Hashing
- `rand` - Random number generation

### Storage & Database
- `rusqlite` - Database operations
- `lru` - LRU caching

See `Cargo.toml` for complete dependency list.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Support

- **Issues**: [GitHub Issues](https://github.com/dirvine/saorsa-core-foundation/issues)
- **Discussions**: [GitHub Discussions](https://github.com/dirvine/saorsa-core-foundation/discussions)
- **Email**: david@saorsalabs.com

---

**Saorsa Labs Limited** - Building the decentralized future
