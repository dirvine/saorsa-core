# Saorsa Core Specification Modules

## Overview

This document provides comprehensive documentation for the five core modules implementing the Saorsa specification. These modules provide a minimal, composable foundation for building Saorsa-based applications.

## Module Architecture

```
saorsa-core/
├── fwid/           # Four-word identifier system
├── auth/           # Pluggable authentication adapters
├── events/         # Async event bus for pub/sub
├── telemetry/      # Metrics and health monitoring
└── api.rs          # High-level public API
```

## 1. FWID Module - Four-Word Identifiers

### Purpose
Provides human-readable four-word addresses for network entities, using BLAKE3 hashing for deterministic key generation.

### Key Components

#### Types
- `Word` - A single word in the four-word address
- `FourWordsV1` - Four-word identifier container
- `Key` - 32-byte BLAKE3 hash representation

#### Core Functions

```rust
// Validate four-word combination
pub fn fw_check(words: [Word; 4]) -> bool

// Convert four words to DHT key
pub fn fw_to_key(words: [Word; 4]) -> Result<Key>

// Compute key from arbitrary data
pub fn compute_key(data: &[u8]) -> Key
```

### Usage Examples

```rust
use saorsa_core::fwid::{fw_check, fw_to_key, Word};

// Create four-word address
let words: [Word; 4] = [
    "alpha".to_string(),
    "beta".to_string(),
    "gamma".to_string(),
    "delta".to_string(),
];

// Validate words
if fw_check(words.clone()) {
    // Convert to DHT key
    let key = fw_to_key(words)?;
    println!("Key: {:?}", key);
}
```

## 2. Auth Module - Authentication System

### Purpose
Provides pluggable authentication mechanisms for multi-writer records in the DHT.

### Key Components

#### Core Trait
```rust
#[async_trait]
pub trait WriteAuth: Send + Sync + Debug {
    async fn verify(&self, record: &[u8], sigs: &[Sig]) -> Result<bool>;
    fn auth_type(&self) -> &str;
}
```

#### Authentication Adapters

1. **SingleWriteAuth** - Single public key authentication
2. **DelegatedWriteAuth** - Multiple authorized writers
3. **MlsWriteAuth** - MLS proof-based authentication (placeholder)
4. **ThresholdWriteAuth** - t-of-n threshold signatures
5. **CompositeWriteAuth** - Combine multiple auth methods

### Usage Examples

```rust
use saorsa_core::auth::{SingleWriteAuth, PubKey, Sig};

// Create single-writer auth
let pub_key = PubKey::new(vec![1, 2, 3]);
let auth = SingleWriteAuth::new(pub_key);

// Verify signature
let record = b"data to sign";
let sig = Sig::new(vec![4, 5, 6]);
let is_valid = auth.verify(record, &[sig]).await?;

// Composite authentication
use saorsa_core::auth::CompositeWriteAuth;

let auth1 = Box::new(SingleWriteAuth::new(key1));
let auth2 = Box::new(ThresholdWriteAuth::new(2, 3, keys)?);
let composite = CompositeWriteAuth::all(vec![auth1, auth2]);
```

## 3. Events Module - Async Event Bus

### Purpose
Provides pub/sub infrastructure for topology changes, DHT updates, and forward events.

### Key Components

#### Event Types
- `TopologyEvent` - Network topology changes
- `ForwardEvent` - Device forward updates
- DHT watch events (raw bytes)

#### Subscription Management
```rust
pub struct Subscription<T> {
    rx: broadcast::Receiver<T>,
}
```

### Usage Examples

```rust
use saorsa_core::events::{subscribe_topology, device_subscribe, dht_watch};
use saorsa_core::fwid::Key;

// Subscribe to topology changes
let mut topology_sub = subscribe_topology().await;
tokio::spawn(async move {
    while let Ok(event) = topology_sub.recv().await {
        println!("Topology changed: {:?}", event);
    }
});

// Watch DHT key for changes
let key = Key::new([1u8; 32]);
let mut dht_sub = dht_watch(key).await;
tokio::spawn(async move {
    while let Ok(data) = dht_sub.recv().await {
        println!("DHT key updated: {} bytes", data.len());
    }
});

// Subscribe to device forwards
let identity_key = Key::new([2u8; 32]);
let mut device_sub = device_subscribe(identity_key).await;
```

## 4. Telemetry Module - Metrics & Health

### Purpose
Provides observability through metrics collection, health monitoring, and performance tracking.

### Key Components

#### Core Metrics
```rust
pub struct Metrics {
    pub lookups_p95_ms: u64,  // Lookup latency P95
    pub hop_p95: u8,          // Hop count P95
    pub timeout_rate: f32,    // Timeout rate (0.0-1.0)
}
```

#### Stream Classes (QoS)
- `Control` - Highest priority
- `Mls` - Message Layer Security
- `File` - File transfers
- `Media` - Media streaming

### Usage Examples

```rust
use saorsa_core::telemetry::{telemetry, record_lookup, StreamClass};
use std::time::Duration;

// Record lookup operation
record_lookup(Duration::from_millis(50), 3).await;

// Record stream metrics
let collector = telemetry();
collector.record_stream_bandwidth(
    StreamClass::Media,
    1_000_000, // 1 Mbps
).await;

// Get current metrics
let metrics = collector.get_metrics().await;
println!("P95 latency: {}ms", metrics.lookups_p95_ms);

// Health monitoring
use saorsa_core::telemetry::HealthMonitor;
let monitor = HealthMonitor::new(collector);
let status = monitor.get_status().await;
if status.healthy {
    println!("System healthy, uptime: {:?}", status.uptime);
}
```

## 5. API Module - Public Interface

### Purpose
Provides high-level API matching the Saorsa specification for identity, DHT, routing, and transport operations.

### Key Data Types

#### Identity System
```rust
pub struct IdentityPacketV1 {
    pub v: u8,
    pub w: [u16; 4],          // Four words
    pub pk: Vec<u8>,          // ML-DSA public key
    pub sig: Vec<u8>,         // Signature
    pub addrs: HashMap<String, Option<String>>,
    pub website_root: Option<Key>,
    pub device_set_root: Key,
}

pub struct DeviceSetV1 {
    pub v: u8,
    pub crdt: String,         // CRDT for multi-writer
    pub forwards: Vec<Forward>,
}
```

#### Storage System
```rust
pub struct ContainerManifestV1 {
    pub v: u8,
    pub object: Key,
    pub fec: FecParams,       // Forward error correction
    pub assets: Vec<Key>,
    pub sealed_meta: Option<Key>,
}
```

### Core API Functions

```rust
// Identity operations
pub async fn identity_claim(
    words: [Word; 4],
    pubkey: PubKey,
    sig: Sig
) -> Result<()>

pub async fn identity_fetch(key: Key) -> Result<IdentityPacketV1>

// DHT operations
pub async fn dht_put(
    key: Key,
    bytes: Bytes,
    policy: &PutPolicy
) -> Result<PutReceipt>

pub async fn dht_get(key: Key, quorum: usize) -> Result<Bytes>

pub async fn dht_watch(key: Key) -> Subscription<Bytes>

// Routing & trust
pub async fn record_interaction(
    peer: Vec<u8>,
    outcome: Outcome
) -> Result<()>

pub async fn eigen_trust_epoch() -> Result<()>

// Transport (QUIC)
pub async fn quic_connect(ep: &Endpoint) -> Result<Conn>

pub async fn quic_open(
    conn: &Conn,
    class: StreamClass
) -> Result<Stream>
```

### Usage Examples

```rust
use saorsa_core::api::*;
use saorsa_core::auth::{SingleWriteAuth, PubKey, Sig};
use saorsa_core::fwid::{Key, Word};
use bytes::Bytes;

// Claim an identity
let words: [Word; 4] = ["alpha", "beta", "gamma", "delta"]
    .map(|s| s.to_string());
let pubkey = PubKey::new(vec![1, 2, 3]);
let sig = Sig::new(vec![4, 5, 6]);
identity_claim(words, pubkey, sig).await?;

// Store in DHT with policy
let key = Key::new([1u8; 32]);
let data = Bytes::from("hello world");
let policy = PutPolicy {
    quorum: 5,
    ttl: Some(Duration::from_secs(3600)),
    auth: Box::new(SingleWriteAuth::new(pubkey)),
};
let receipt = dht_put(key, data, &policy).await?;

// Watch for changes
let mut subscription = dht_watch(key).await;
tokio::spawn(async move {
    while let Ok(data) = subscription.recv().await {
        println!("Data updated: {} bytes", data.len());
    }
});
```

## Integration Patterns

### Complete Identity Flow
```rust
use saorsa_core::{api::*, auth::*, fwid::*, events::*};

async fn setup_identity() -> Result<()> {
    // 1. Generate four words
    let words: [Word; 4] = generate_four_words();
    
    // 2. Create identity key
    let identity_key = fw_to_key(words.clone())?;
    
    // 3. Setup authentication
    let (pubkey, privkey) = generate_keypair();
    let sig = sign_with_key(&privkey, &identity_key.as_bytes())?;
    
    // 4. Claim identity
    identity_claim(words, pubkey, sig).await?;
    
    // 5. Setup device forward
    let forward = Forward {
        proto: "quic".to_string(),
        addr: "192.168.1.100:9000".to_string(),
        exp: future_timestamp(),
    };
    device_publish_forward(identity_key, forward).await?;
    
    // 6. Subscribe to updates
    let sub = device_subscribe(identity_key).await;
    monitor_forwards(sub).await;
    
    Ok(())
}
```

### DHT with Authentication
```rust
async fn secure_dht_operations() -> Result<()> {
    // Setup threshold authentication (2-of-3)
    let keys = vec![
        PubKey::new(key1_bytes),
        PubKey::new(key2_bytes),
        PubKey::new(key3_bytes),
    ];
    let auth = ThresholdWriteAuth::new(2, 3, keys)?;
    
    // Store with threshold auth
    let policy = PutPolicy {
        quorum: 5,
        ttl: Some(Duration::from_secs(86400)),
        auth: Box::new(auth),
    };
    
    let key = compute_key(b"my-data-key");
    let data = Bytes::from("sensitive data");
    let receipt = dht_put(key, data, &policy).await?;
    
    // Verify storage
    assert!(receipt.storing_nodes.len() >= policy.quorum);
    
    Ok(())
}
```

### Telemetry-Driven Routing
```rust
async fn adaptive_routing() -> Result<()> {
    let collector = telemetry();
    
    // Record interactions
    for peer in peers {
        let start = Instant::now();
        let result = interact_with_peer(&peer).await;
        
        match result {
            Ok(data) => {
                let latency = start.elapsed();
                collector.record_lookup(latency, hops).await;
                record_interaction(peer.id, Outcome::Ok).await?;
            }
            Err(_) => {
                collector.record_timeout();
                record_interaction(peer.id, Outcome::Timeout).await?;
            }
        }
    }
    
    // Run trust computation
    eigen_trust_epoch().await?;
    
    // Get updated metrics
    let metrics = collector.get_metrics().await;
    if metrics.timeout_rate > 0.1 {
        warn!("High timeout rate: {:.2}%", metrics.timeout_rate * 100.0);
    }
    
    Ok(())
}
```

## Testing

### Unit Tests
Each module includes comprehensive unit tests:

```bash
# Run all module tests
cargo test --lib

# Test specific module
cargo test --lib fwid
cargo test --lib auth
cargo test --lib events
cargo test --lib telemetry
cargo test --lib api
```

### Integration Tests
```bash
# Run comprehensive integration test
cargo test --test spec_integration_test
```

### Property-Based Testing
The modules use property-based testing for robustness:

```rust
#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    
    proptest! {
        #[test]
        fn test_key_deterministic(data: Vec<u8>) {
            let key1 = compute_key(&data);
            let key2 = compute_key(&data);
            assert_eq!(key1, key2);
        }
    }
}
```

## Performance Considerations

### Telemetry Collection
- Samples are bounded (1000 for lookups, 100 for streams)
- Percentile calculations are O(n log n) but on bounded data
- Atomic counters for lock-free increments

### Event Bus
- Broadcast channels with configurable capacity
- Non-blocking sends (except initial subscription)
- Automatic cleanup of disconnected receivers

### Authentication
- Async verification for non-blocking I/O
- Composite auth short-circuits on first failure (any mode)
- Threshold auth validates minimum signatures only

## Security Notes

1. **Authentication**: All placeholder implementations need real crypto
2. **Key Generation**: BLAKE3 provides cryptographic hashing
3. **Signatures**: Integration points for ML-DSA (post-quantum)
4. **Trust**: EigenTrust integration for reputation management
5. **Transport**: QUIC provides encryption and authentication

## Future Enhancements

### Planned Improvements
1. Complete MLS integration for group operations
2. Threshold signature implementation via saorsa-seal
3. Post-quantum signature verification
4. CRDT implementation for DeviceSetV1
5. FEC integration with saorsa-fec

### Extension Points
- Custom authentication adapters (implement WriteAuth)
- Additional stream classes for QoS
- Custom event types in event bus
- Pluggable metrics collectors
- Alternative DHT implementations

## API Stability

The API is designed for stability with these guarantees:

1. **Semantic Versioning**: Breaking changes increment major version
2. **Trait Stability**: WriteAuth trait is stable
3. **Event Types**: New events are additive only
4. **Metrics**: New metrics are additive only
5. **Function Signatures**: Stable after 1.0 release

## Migration Guide

### From Previous Implementation
```rust
// Old: Direct DHT access
let value = dht.get(key).await?;

// New: API with consistency
let value = dht_get(key, 5).await?; // quorum of 5

// Old: No authentication
dht.put(key, value).await?;

// New: With authentication
let policy = PutPolicy {
    quorum: 5,
    ttl: Some(Duration::from_secs(3600)),
    auth: Box::new(SingleWriteAuth::new(pubkey)),
};
dht_put(key, value, &policy).await?;
```

## Troubleshooting

### Common Issues

1. **"Invalid four-words" error**
   - Ensure words are exactly 4
   - Check word validation passes

2. **"No topology subscribers" warning**
   - Subscribe before publishing events
   - Check event bus is initialized

3. **Percentile calculations returning 0**
   - Ensure samples are recorded
   - Check collector isn't reset

4. **Authentication always passes**
   - Current implementations are placeholders
   - Integrate real crypto libraries

## Resources

- [Saorsa Specification](./SPEC.md)
- [API Documentation](https://docs.rs/saorsa-core)
- [Examples](./examples/)
- [Integration Tests](./tests/spec_integration_test.rs)