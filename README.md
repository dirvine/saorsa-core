# Saorsa Core

[![CI](https://github.com/dirvine/saorsa-core-foundation/actions/workflows/rust.yml/badge.svg)](https://github.com/dirvine/saorsa-core-foundation/actions/workflows/rust.yml)
[![Crates.io](https://img.shields.io/crates/v/saorsa-core.svg)](https://crates.io/crates/saorsa-core)
[![Documentation](https://docs.rs/saorsa-core/badge.svg)](https://docs.rs/saorsa-core)

Core P2P networking library for Saorsa platform with DHT, QUIC transport, dual-stack endpoints (IPv6+IPv4), and four-word endpoint encoding.

## Guides

- Contributor guide: see [AGENTS.md](AGENTS.md)
- Architecture overview: see [ARCHITECTURE.md](ARCHITECTURE.md)

## Features

- **DHT (Distributed Hash Table)**: Advanced DHT implementation with RSPS (Root-Scoped Provider Summaries)
- **Placement System**: Intelligent shard placement with EigenTrust integration and Byzantine fault tolerance
- **QUIC Transport**: High-performance networking with ant-quic
- **Four-Word Endpoints**: Human‑readable network endpoints via `four-word-networking` (IPv4 encodes to 4 words; IPv6 word count decided by the crate); decode requires an explicit port (no defaults).
- **Post-Quantum Cryptography**: Future-ready cryptographic algorithms
- **WebRTC over QUIC**: Advanced WebRTC-QUIC bridge for real-time media streaming with adaptive quality
- **Media Processing**: Image and audio processing with blurhash and symphonia
- **Geographic Routing**: Location-aware networking
- **Identity Management**: Post-quantum ML-DSA-65 signatures (NIST Level 3). No PoW; identities hold only required keys (no embedded word address).
- **Secure Storage**: Database persistence with deadpool-sqlite + rusqlite
- **Monitoring**: Prometheus metrics integration

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
saorsa-core = "0.3.4"
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

### Four-Word Endpoints

- Endpoints are encoded/decoded using the `four-word-networking` crate’s adaptive API.
- IPv4 → 4 words; IPv6 → word count is crate‑defined; decoding requires a port (no implicit defaults).
- Four‑words are reserved strictly for network endpoints; user identities in messaging are separate handles.

## Architecture

### Core Components

1. **Network Layer**: QUIC-based P2P networking with NAT traversal
2. **DHT**: Kademlia-based DHT with RSPS optimization
3. **Placement System**: Intelligent shard placement with weighted selection algorithms
4. **Identity**: Post‑quantum cryptographic identities with ML‑DSA‑65 signatures (no PoW; no embedded four‑word address)
5. **Storage**: Local and distributed content storage with audit and repair
6. **Geographic Routing**: Location-aware message routing


### Cryptographic Architecture

Saorsa Core implements a pure post-quantum cryptographic approach for maximum security:

- **Post‑quantum signatures**: ML‑DSA‑65 (FIPS 204) for quantum‑resistant digital signatures (~128‑bit quantum security)
- **PQC Encryption**: ChaCha20-Poly1305 with quantum-resistant key derivation
- **Key Exchange**: ML-KEM-768 (FIPS 203) for quantum-resistant key encapsulation (~128-bit quantum security)
- **Hashing**: BLAKE3 for fast, secure content addressing
- **Transport Security**: QUIC with TLS 1.3 and PQC cipher suites
- **No Legacy Support**: Pure PQC implementation with no classical cryptographic fallbacks

### Recent Changes

- Removed all Proof‑of‑Work (PoW) usage (identity, adaptive, placement/DHT, error types, CLI).
- Adopted `four-word-networking` adaptive API; four‑words reserved for endpoints only.
- Implemented dual‑stack listeners (IPv6 + IPv4) and Happy Eyeballs dialing.
- Introduced `UserHandle` for messaging identities; migrated mentions, presence, participants, search, reactions, and read/delivered receipts to use it.

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
- **DHT Record Types**: Efficient ≤512B records with proof-of-work
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

- `default` - DHT, ant-quic (four-word addresses always enabled)
- `dht` - DHT functionality
- `ant-quic` - QUIC transport
- `quantum-resistant` - Post-quantum cryptography (ML-DSA, ML-KEM)
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
- Placement decisions: <1s for 8-node selection
- Shard repair: Automatic with <1h detection
- Cryptographic operations: Hardware-accelerated

## Security

- **Post-Quantum Signatures**: ML-DSA-65 (FIPS 204) for quantum-resistant digital signatures (~128-bit quantum security)
- **PQC Encryption**: ChaCha20-Poly1305 with quantum-resistant key derivation
- **Key Exchange**: ML-KEM-768 (FIPS 203) for quantum-resistant key encapsulation (~128-bit quantum security)
- **BLAKE3 Hashing**: Fast and secure content addressing
- **QUIC Encryption**: Transport-level encryption with PQC support
- **Pure PQC**: No classical cryptographic algorithms - quantum-resistant from the ground up
- **Secure Memory**: Platform-specific memory protection

## WebRTC over QUIC Integration

Saorsa Core provides a unique **WebRTC-over-QUIC bridge** that combines the real-time capabilities of WebRTC with the performance and reliability of QUIC transport. This allows for high-quality media streaming with improved NAT traversal and congestion control.

### Key Features

- **Seamless Integration**: Bridge WebRTC media streams over ant-quic transport
- **Adaptive Quality**: Automatic bandwidth and quality adaptation based on network conditions
- **Multiple Stream Types**: Support for audio, video, screen sharing, and data channels
- **QoS Management**: Intelligent Quality of Service with stream prioritization
- **Jitter Buffering**: Built-in jitter buffers for smooth media playback
- **Performance Monitoring**: Real-time statistics and performance metrics

### Basic WebRTC-QUIC Bridge Setup

```rust
use saorsa_core::messaging::{
    WebRtcQuicBridge, QuicMediaStreamManager, StreamConfig, StreamType, QosParameters
};
use saorsa_core::transport::ant_quic_adapter::P2PNetworkNode;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create network node
    let node = Arc::new(P2PNetworkNode::new("127.0.0.1:0".parse()?).await?);
    
    // Create WebRTC-QUIC bridge
    let bridge = WebRtcQuicBridge::new(node).await?;
    
    // Create stream manager for bandwidth management
    let manager = QuicMediaStreamManager::new(2000); // 2 Mbps
    manager.start_background_tasks().await?;
    
    // Connect to peer
    let peer_addr = "192.168.1.100:9000".parse()?;
    let peer_id = bridge.connect_peer(peer_addr).await?;
    
    // Configure audio stream
    let audio_config = StreamConfig {
        stream_type: StreamType::Audio,
        codec: "opus".to_string(),
        bitrate_kbps: 64,
        sample_rate: Some(48000),
        resolution: None,
    };
    bridge.add_stream(peer_id, StreamType::Audio, audio_config).await?;
    
    // Configure video stream
    let video_config = StreamConfig {
        stream_type: StreamType::Video,
        codec: "h264".to_string(),
        bitrate_kbps: 1000,
        sample_rate: None,
        resolution: Some((1280, 720)),
    };
    bridge.add_stream(peer_id, StreamType::Video, video_config).await?;
    
    // Set QoS parameters
    manager.set_qos_params(StreamType::Audio, QosParameters::audio()).await;
    manager.set_qos_params(StreamType::Video, QosParameters::video()).await;
    
    // Start receiving packets
    let mut receiver = bridge.start_receiving().await?;
    
    // Handle incoming packets
    tokio::spawn(async move {
        while let Some((peer_id, packet)) = receiver.recv().await {
            println!("Received {} packet from {}", packet.stream_type, peer_id);
            // Process packet...
        }
    });
    
    Ok(())
}
```

### Media Streaming Example

```rust
use saorsa_core::messaging::RtpPacket;

// Create and send RTP packets
async fn send_media_packets(
    bridge: &WebRtcQuicBridge,
    peer_id: PeerId,
) -> Result<()> {
    // Audio packet (Opus codec)
    let audio_packet = RtpPacket::new(
        96,                    // Payload type (Opus)
        1001,                  // Sequence number
        48000,                 // Timestamp (48kHz sample rate)
        0x12345678,            // SSRC identifier
        vec![0xAA; 160],       // Opus frame data (20ms @ 48kHz)
        StreamType::Audio,
    );
    bridge.send_rtp_packet(peer_id, audio_packet).await?;
    
    // Video packet (H.264 codec)
    let video_packet = RtpPacket::new(
        97,                    // Payload type (H.264)
        2001,                  // Sequence number
        90000,                 // Timestamp (90kHz for video)
        0x87654321,            // SSRC identifier
        vec![0xBB; 1200],      // H.264 NAL unit
        StreamType::Video,
    );
    bridge.send_rtp_packet(peer_id, video_packet).await?;
    
    Ok(())
}
```

### Quality of Service (QoS) Configuration

```rust
use saorsa_core::messaging::QosParameters;

// Configure QoS for different stream types
let audio_qos = QosParameters {
    priority: 3,           // Highest priority
    max_latency_ms: 20,    // Low latency for real-time audio
    max_jitter_ms: 5,      // Minimal jitter tolerance
    target_bitrate_kbps: 64,
    max_bitrate_kbps: 128,
    min_bitrate_kbps: 32,
    loss_threshold: 1.0,   // 1% packet loss threshold
};

let video_qos = QosParameters {
    priority: 2,           // Medium priority
    max_latency_ms: 100,   // Higher latency tolerance
    max_jitter_ms: 20,     // More jitter tolerance
    target_bitrate_kbps: 1000,
    max_bitrate_kbps: 2000,
    min_bitrate_kbps: 200,
    loss_threshold: 3.0,   // 3% packet loss threshold
};

manager.set_qos_params(StreamType::Audio, audio_qos).await;
manager.set_qos_params(StreamType::Video, video_qos).await;
```

### Bandwidth Adaptation

```rust
// Check for bandwidth adaptation recommendations
if let Some(adjustment) = manager.check_bandwidth_adaptation().await {
    match adjustment {
        BandwidthAdjustment::Increase { current, recommended } => {
            println!("Increase bandwidth: {} -> {} kbps", current, recommended);
            // Adjust encoder settings...
        }
        BandwidthAdjustment::Decrease { current, recommended } => {
            println!("Decrease bandwidth: {} -> {} kbps", current, recommended);
            // Reduce quality or bitrate...
        }
    }
}

// Check transmission capacity
let can_send_hd = manager.can_transmit(1500).await; // 1.5KB HD frame
if !can_send_hd {
    // Switch to lower resolution or quality
}
```

### Performance Monitoring

```rust
// Get peer statistics
if let Some(stats) = bridge.get_peer_stats(peer_id).await {
    println!("Packets sent: {}", stats.packets_sent);
    println!("Packets received: {}", stats.packets_received);
    println!("Bytes transferred: {}", stats.bytes_sent);
    println!("Active streams: {}", stats.streams.len());
}

// Get stream-specific statistics
let stream_stats = manager.get_all_stats().await;
for ((peer_id, stream_type), stats) in stream_stats {
    println!("{:?} stream to {}:", stream_type, peer_id);
    println!("  RTT: {}ms", stats.rtt_ms);
    println!("  Loss: {:.2}%", stats.loss_percentage());
    println!("  Throughput: {} kbps", stats.effective_bitrate_kbps());
}
```

### Advanced Features

#### Multi-Stream Management
```rust
// Configure multiple streams for comprehensive communication
bridge.add_stream(peer_id, StreamType::Audio, audio_config).await?;
bridge.add_stream(peer_id, StreamType::Video, video_config).await?;
bridge.add_stream(peer_id, StreamType::ScreenShare, screen_config).await?;
bridge.add_stream(peer_id, StreamType::Data, data_config).await?;
```

#### Custom Bridge Configuration
```rust
use saorsa_core::messaging::BridgeConfig;

let config = BridgeConfig {
    jitter_buffer_size: 100,                    // 100 packets max
    jitter_buffer_delay: Duration::from_millis(50), // 50ms buffer
    peer_timeout: Duration::from_secs(30),      // 30s peer timeout
    cleanup_interval: Duration::from_secs(5),   // Cleanup every 5s
    max_packet_size: 1500,                      // MTU consideration
    enable_adaptive_jitter: true,               // Adaptive jitter buffering
};

let bridge = WebRtcQuicBridge::new_with_config(node, config).await?;
```

#### Error Handling and Reconnection
```rust
// Robust error handling
match bridge.send_rtp_packet(peer_id, packet).await {
    Ok(_) => {
        // Packet sent successfully
    }
    Err(e) => {
        eprintln!("Failed to send packet: {}", e);
        
        // Attempt reconnection if peer disconnected
        if e.to_string().contains("not connected") {
            match bridge.connect_peer(peer_addr).await {
                Ok(new_peer_id) => {
                    // Reconfigure streams for new connection
                    configure_streams(&bridge, new_peer_id).await?;
                }
                Err(reconnect_err) => {
                    eprintln!("Reconnection failed: {}", reconnect_err);
                }
            }
        }
    }
}
```

### Use Cases

1. **Voice Calls**: Low-latency audio streaming with Opus codec
2. **Video Conferencing**: Adaptive video quality with H.264/VP8 codecs  
3. **Screen Sharing**: High-quality desktop streaming
4. **File Transfer**: Reliable data channel communication
5. **Gaming**: Real-time game state synchronization
6. **IoT Streaming**: Sensor data and telemetry transmission

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
- `saorsa-pqc` - Post-quantum cryptography (ML-DSA, ML-KEM, ChaCha20-Poly1305)
- `blake3` - Hashing
- `rand` - Random number generation

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
