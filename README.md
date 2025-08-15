# Saorsa Core

[![CI](https://github.com/dirvine/saorsa-core-foundation/actions/workflows/rust.yml/badge.svg)](https://github.com/dirvine/saorsa-core-foundation/actions/workflows/rust.yml)
[![Crates.io](https://img.shields.io/crates/v/saorsa-core.svg)](https://crates.io/crates/saorsa-core)
[![Documentation](https://docs.rs/saorsa-core/badge.svg)](https://docs.rs/saorsa-core)

Core P2P networking library for Saorsa platform with DHT, QUIC transport, four-word addresses, and MCP integration.

## Features

- **DHT (Distributed Hash Table)**: Advanced DHT implementation with RSPS (Root-Scoped Provider Summaries)
- **QUIC Transport**: High-performance networking with ant-quic
- **Four-Word Addresses**: Human-readable network addresses
- **MCP Integration**: Model Context Protocol support
- **Post-Quantum Cryptography**: Future-ready cryptographic algorithms
- **WebRTC Support**: Voice and video calling capabilities
- **Media Processing**: Image and audio processing with blurhash and symphonia
- **Geographic Routing**: Location-aware networking
- **Identity Management**: Ed25519-based identity system
- **Secure Storage**: Database persistence with SQLx
- **Monitoring**: Prometheus metrics integration

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
saorsa-core = "0.2.6"
```

### Basic DHT Node

```rust
use saorsa_core::{Network, NetworkConfig, NodeId};
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new network node
    let config = NetworkConfig::default();
    let mut network = Network::new(config).await?;
    
    // Start the network
    network.start().await?;
    
    // Store some data
    let key = b"example-key";
    let value = b"example-value";
    network.store(key, value.to_vec()).await?;
    
    // Retrieve the data
    if let Some(retrieved) = network.retrieve(key).await? {
        println!("Retrieved: {:?}", retrieved);
    }
    
    Ok(())
}
```

### Four-Word Addresses

```rust
use saorsa_core::NetworkAddress;

// Create from IP:port
let addr = NetworkAddress::from_ipv4("192.168.1.1".parse()?, 9000);

// Get four-word representation
if let Some(words) = addr.four_words() {
    println!("Address: {}", words);
}

// Parse from four-word format
let addr = NetworkAddress::from_four_words("alpha-beta-gamma-delta")?;
```

### MCP Server

```rust
use saorsa_core::mcp::{McpServer, McpConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = McpConfig::default();
    let server = McpServer::new(config).await?;
    
    // Start MCP server
    server.start().await?;
    
    Ok(())
}
```

## Architecture

### Core Components

1. **Network Layer**: QUIC-based P2P networking with NAT traversal
2. **DHT**: Kademlia-based DHT with RSPS optimization
3. **Identity**: Ed25519 cryptographic identities with four-word addresses
4. **Storage**: Local and distributed content storage
5. **Geographic Routing**: Location-aware message routing
6. **MCP Integration**: Model Context Protocol for AI/LLM integration

### Data Flow

```
Application
    ↓
Network API
    ↓
DHT + Geographic Routing
    ↓
QUIC Transport (ant-quic)
    ↓
Internet
```

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
    enable_mcp: true,
    dht_replication: 20,
    storage_capacity: 1024 * 1024 * 1024, // 1GB
    ..Default::default()
};
```

## Feature Flags

- `default` - DHT, MCP, ant-quic (four-word addresses always enabled)
- `dht` - DHT functionality
- `mcp` - MCP server support
- `ant-quic` - QUIC transport
- `quantum-resistant` - Post-quantum cryptography
- `threshold` - Threshold cryptography
- `cli` - CLI utilities
- `metrics` - Prometheus metrics
- `commercial` - Commercial license features

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
- Cryptographic operations: Hardware-accelerated

## Security

- **Ed25519 Signatures**: All operations cryptographically signed
- **BLAKE3 Hashing**: Fast and secure content addressing
- **QUIC Encryption**: Transport-level encryption
- **Post-Quantum Ready**: ML-KEM and ML-DSA support
- **Secure Memory**: Platform-specific memory protection

## WebRTC Integration

Full WebRTC stack for real-time communication:

```rust
use saorsa_core::webrtc::{WebRtcManager, CallConfig};

let webrtc = WebRtcManager::new().await?;
let call = webrtc.create_call(peer_id, CallConfig::voice_only()).await?;
```

## Media Processing

Built-in media processing capabilities:

- **Images**: JPEG, PNG, WebP, GIF support with blurhash
- **Audio**: Full codec support via symphonia
- **Streaming**: Real-time media streaming over WebRTC

## Database Integration

SQLite-based persistence with migrations:

```rust
use saorsa_core::storage::Database;

let db = Database::open("./data/node.db").await?;
db.store_message(&message).await?;
```

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
cargo build --features "dht,mcp,quantum-resistant"
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

For commercial licensing, contact: saorsalabs@gmail.com

## Dependencies

### Core Dependencies
- `tokio` - Async runtime
- `futures` - Future utilities
- `serde` - Serialization
- `anyhow` - Error handling
- `tracing` - Logging

### Networking
- `ant-quic` - QUIC transport
- `four-word-networking` - Human-readable addresses
- `rustls` - TLS support

### Cryptography
- `ed25519-dalek` - Digital signatures
- `blake3` - Hashing
- `rand` - Random number generation
- `x25519-dalek` - Key exchange
- `aes-gcm` - Symmetric encryption

### Storage & Database
- `sqlx` - Database operations
- `lru` - LRU caching
- `reed-solomon-erasure` - Error correction

### Media & WebRTC
- `webrtc` - WebRTC implementation
- `image` - Image processing
- `symphonia` - Audio codecs
- `rodio` - Audio playback

See `Cargo.toml` for complete dependency list.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Support

- **Issues**: [GitHub Issues](https://github.com/dirvine/saorsa-core-foundation/issues)
- **Discussions**: [GitHub Discussions](https://github.com/dirvine/saorsa-core-foundation/discussions)
- **Email**: saorsalabs@gmail.com

---

**Saorsa Labs Limited** - Building the decentralized future