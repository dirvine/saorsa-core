# Saorsa Core API Reference

This document provides a comprehensive guide to the saorsa-core public API.

## Table of Contents

- [Identity Management](#identity-management)
- [Storage Operations](#storage-operations)
- [DHT Operations](#dht-operations)
- [Network & Transport](#network--transport)
- [Cryptography](#cryptography)
- [Trust & Reputation](#trust--reputation)
- [Bootstrap & Discovery](#bootstrap--discovery)
- [Configuration](#configuration)

---

## Identity Management

### Register Identity

Create a new identity bound to an ML-DSA-65 keypair.

```rust
use saorsa_core::{register_identity, MlDsaKeyPair};

// Generate a new keypair
let keypair = MlDsaKeyPair::generate()?;

// Register with four-word address
let words = ["welfare", "absurd", "king", "ridge"];
let handle = register_identity(words, &keypair).await?;
```

### Register Headless Device

Register a storage-only device (always-on node).

```rust
use saorsa_core::{register_headless, Device, DeviceType, DeviceId, Endpoint};

let device = Device {
    id: DeviceId::generate(),
    device_type: DeviceType::Headless,
    storage_gb: 500,
    endpoint: Endpoint {
        protocol: "quic".to_string(),
        address: "192.168.1.100:9000".to_string(),
    },
    capabilities: Default::default(),
};

let handle = register_headless(&keypair, device).await?;
```

### Register Presence

Announce devices and set active device.

```rust
use saorsa_core::{register_presence, set_active_device};

// Register devices with identity
register_presence(&handle, vec![device1, device2], active_device_id).await?;

// Change active device
set_active_device(&handle, new_device_id).await?;
```

### Fetch Identity

Retrieve identity by four-word address.

```rust
use saorsa_core::identity_fetch;

let identity = identity_fetch(&["welfare", "absurd", "king", "ridge"]).await?;
println!("Public key: {:?}", identity.public_key);
```

### Four-Word Addresses

Human-readable addresses for network endpoints.

```rust
use saorsa_core::bootstrap::{WordEncoder, FourWordAddress};

let encoder = WordEncoder::new();

// Encode socket address to four words
let addr: SocketAddr = "192.168.1.100:9000".parse()?;
let four_words = encoder.encode_socket_addr(&addr)?;
println!("Address: {}", four_words.0);  // e.g., "welfare-absurd-king-ridge"

// Decode back to socket address
let decoded = encoder.decode_to_socket_addr(&four_words)?;
assert_eq!(addr, decoded);
```

---

## Storage Operations

### Store Data (Automatic Strategy)

Store data with automatic replication strategy based on group size.

```rust
use saorsa_core::store_data;

// Single user: direct storage
let data = b"My private data".to_vec();
let handle = store_data(&identity_handle, data, 1).await?;

// Group: automatic replication (capped at 8 replicas)
let handle = store_data(&identity_handle, data, 10).await?;
```

### Store Dyad (Two-User Replication)

Full replication between two users.

```rust
use saorsa_core::store_dyad;

let data = b"Shared between two users".to_vec();
let handle = store_dyad(&handle1, handle2.key(), data).await?;
```

### Store with Custom Replication

Explicit control over replica count.

```rust
use saorsa_core::store_with_fec;

// Store with 8 data shards + 4 parity shards (interpreted as 12 replicas)
let handle = store_with_fec(&handle, data, 8, 4).await?;
```

### Retrieve Data

Automatic decryption and reconstruction.

```rust
use saorsa_core::get_data;

let retrieved = get_data(&storage_handle).await?;
println!("Data: {:?}", retrieved);
```

---

## DHT Operations

### DHT Network Manager

High-level DHT operations with network integration.

```rust
use saorsa_core::{DhtNetworkManager, DhtNetworkConfig, Key, Record};

// Create manager
let config = DhtNetworkConfig::default();
let manager = DhtNetworkManager::new(config).await?;

// Store record
let key = Key::from_bytes(b"my-key");
let record = Record::new(b"my-value".to_vec());
manager.store(key.clone(), record).await?;

// Retrieve record
if let Some(record) = manager.get(&key).await? {
    println!("Value: {:?}", record.value);
}

// Find closest peers
let peers = manager.get_closest_peers(&key, 8).await;
```

### Low-Level DHT

Direct DHT operations.

```rust
use saorsa_core::dht::{Key, Record, DhtConfig};

// Create key from bytes
let key = Key::from_bytes(b"content-hash");

// Create record with TTL
let record = Record {
    key: key.clone(),
    value: data,
    publisher: Some(peer_id),
    expires: Some(SystemTime::now() + Duration::from_secs(3600)),
};
```

### DHT Subscriptions

Watch for changes to DHT keys.

```rust
use saorsa_core::dht_watch;

let mut subscription = dht_watch(&key).await?;

while let Some(event) = subscription.recv().await {
    match event {
        DhtEvent::ValueChanged(new_value) => println!("Updated: {:?}", new_value),
        DhtEvent::Expired => println!("Key expired"),
    }
}
```

---

## Network & Transport

### P2P Node

Create and run a P2P node.

```rust
use saorsa_core::{P2PNode, NodeConfig, NodeBuilder};

// Using builder pattern
let node = P2PNode::builder()
    .listen_on("0.0.0.0:9000".parse()?)
    .with_bootstrap_nodes(vec![
        "192.168.1.1:9000".parse()?,
    ])
    .build()
    .await?;

// Start the node
node.run().await?;
```

### Network Configuration

Configure network behavior.

```rust
use saorsa_core::messaging::{NetworkConfig, PortConfig, IpMode, NatTraversalMode};

// Default: OS-assigned port, IPv4-only, P2P NAT traversal
let config = NetworkConfig::default();

// Explicit port
let config = NetworkConfig::with_port(9000);

// Port range with fallback
let config = NetworkConfig::with_port_range(9000, 9010);

// Advanced NAT configuration
let config = NetworkConfig::advanced_nat(
    20,     // concurrency_limit
    15,     // max_candidates
    true,   // enable_symmetric_nat
    true,   // enable_relay_fallback
    true,   // prefer_rfc_nat_traversal
);
```

### Connection Events

Subscribe to connection events.

```rust
use saorsa_core::{subscribe_topology, TopologyEvent};

let mut subscription = subscribe_topology().await?;

while let Some(event) = subscription.recv().await {
    match event {
        TopologyEvent::PeerConnected(peer_id) => {
            println!("Connected: {}", peer_id);
        }
        TopologyEvent::PeerDisconnected(peer_id) => {
            println!("Disconnected: {}", peer_id);
        }
    }
}
```

### Messaging Service

High-level messaging with rich features.

```rust
use saorsa_core::messaging::{MessagingService, NetworkConfig};

let service = MessagingService::new_with_config(
    four_word_address,
    dht_client,
    NetworkConfig::default(),
).await?;

// Get listen addresses
let addrs = service.listen_addrs().await;

// Connect to peer
service.connect_peer(&peer_addr).await?;

// Send message
service.send_message(&peer_id, message).await?;
```

---

## Cryptography

### Post-Quantum Key Generation

Generate ML-DSA-65 and ML-KEM-768 key pairs.

```rust
use saorsa_core::{MlDsa65, MlKem768, MlDsaOperations, MlKemOperations};

// Signature keypair (ML-DSA-65)
let (signing_pk, signing_sk) = MlDsa65::generate_keypair()?;

// Key exchange keypair (ML-KEM-768)
let (kem_pk, kem_sk) = MlKem768::generate_keypair()?;
```

### Digital Signatures

Sign and verify with ML-DSA-65.

```rust
use saorsa_core::{MlDsa65, MlDsaOperations};

// Sign message
let message = b"Hello, quantum-safe world!";
let signature = MlDsa65::sign(&signing_sk, message)?;

// Verify signature
let valid = MlDsa65::verify(&signing_pk, message, &signature)?;
assert!(valid);
```

### Key Encapsulation

Establish shared secrets with ML-KEM-768.

```rust
use saorsa_core::{MlKem768, MlKemOperations};

// Sender encapsulates
let (ciphertext, shared_secret_sender) = MlKem768::encapsulate(&recipient_pk)?;

// Recipient decapsulates
let shared_secret_recipient = MlKem768::decapsulate(&recipient_sk, &ciphertext)?;

// Both have the same shared secret
assert_eq!(shared_secret_sender, shared_secret_recipient);
```

### Symmetric Encryption

Encrypt data with ChaCha20-Poly1305.

```rust
use saorsa_core::{ChaCha20Poly1305Cipher, SymmetricKey};

// Create cipher with key
let key = SymmetricKey::generate();
let cipher = ChaCha20Poly1305Cipher::new(&key);

// Encrypt
let plaintext = b"Secret message";
let encrypted = cipher.encrypt(plaintext)?;

// Decrypt
let decrypted = cipher.decrypt(&encrypted)?;
assert_eq!(plaintext, &decrypted[..]);
```

### Secure Memory

Protect sensitive data in memory.

```rust
use saorsa_core::{SecureVec, SecureString, secure_vec_with_capacity};

// Secure vector (zeroed on drop)
let mut secret_key = secure_vec_with_capacity(32);
secret_key.extend_from_slice(&key_bytes);

// Secure string
let password = SecureString::from("my-secret-password");

// Memory is automatically zeroed when dropped
```

---

## Trust & Reputation

### EigenTrust Scores

Query reputation scores for peers.

```rust
use saorsa_core::security::ReputationManager;

let reputation = ReputationManager::new(config);

// Get trust score (0.0 - 1.0)
let score = reputation.get_score(&peer_id);

// Record successful interaction
reputation.record_success(&peer_id);

// Record failed interaction
reputation.record_failure(&peer_id);
```

### Node Age Verification

Check node age for privilege levels.

```rust
use saorsa_core::{NodeAgeVerifier, NodeAgeConfig, OperationType};

let verifier = NodeAgeVerifier::new(NodeAgeConfig::default());

// Check if node can perform operation
let result = verifier.verify_operation(&peer_id, OperationType::Witness)?;

match result {
    AgeVerificationResult::Allowed => println!("Operation permitted"),
    AgeVerificationResult::TooYoung { required_age } => {
        println!("Node must wait {} more seconds", required_age.as_secs());
    }
}
```

### IP Diversity Enforcement

Ensure geographic diversity.

```rust
use saorsa_core::{IPDiversityEnforcer, IPDiversityConfig};

let config = IPDiversityConfig {
    max_per_slash8: 0.25,   // Max 25% from any /8 subnet
    max_per_slash16: 0.10,  // Max 10% from any /16 subnet
    min_distinct_slash16: 5, // At least 5 distinct /16 subnets
};

let enforcer = IPDiversityEnforcer::new(config);

// Check if IP can be added
if enforcer.check_diversity(ip_addr) {
    // IP meets diversity requirements
}
```

---

## Bootstrap & Discovery

### Bootstrap Manager

Manage peer discovery cache.

```rust
use saorsa_core::{BootstrapManager, CacheConfig};
use std::path::PathBuf;

// Create with default config
let manager = BootstrapManager::new(PathBuf::from("~/.cache/saorsa")).await?;

// Add contact (with Sybil protection)
manager.add_contact("192.168.1.100:9000".parse()?).await?;

// Get bootstrap contacts
let contacts = manager.get_contacts(10).await;

// Record connection result
manager.record_connection_result(addr, true, Some(Duration::from_millis(50))).await;
```

### Bootstrap Configuration

Configure cache behavior.

```rust
use saorsa_core::bootstrap::CacheConfig;

let config = CacheConfig {
    cache_dir: PathBuf::from("~/.cache/saorsa"),
    max_contacts: 30_000,
    merge_interval: Duration::from_secs(60),
    cleanup_interval: Duration::from_secs(300),
    quality_update_interval: Duration::from_secs(60),
    stale_threshold: Duration::from_secs(86400),
    ..Default::default()
};
```

---

## Configuration

### Production Configuration

Configure for production deployment.

```rust
use saorsa_core::{ProductionConfig, Config};

let config = ProductionConfig {
    max_connections: 1000,
    max_memory_mb: 512,
    enable_metrics: true,
    metrics_port: 9090,
    ..Default::default()
};
```

### Health Monitoring

Enable health endpoints.

```rust
use saorsa_core::{HealthManager, HealthServer, PrometheusExporter};

// Create health manager
let health = HealthManager::new();

// Start health server
let server = HealthServer::new(health.clone());
server.start("0.0.0.0:8080").await?;

// Export Prometheus metrics
let exporter = PrometheusExporter::new(health);
let metrics = exporter.export()?;
```

### Rate Limiting

Configure join rate limits.

```rust
use saorsa_core::{JoinRateLimiter, JoinRateLimiterConfig};

let config = JoinRateLimiterConfig {
    per_ip_per_minute: 5,
    per_subnet24_per_minute: 20,
    per_subnet16_per_hour: 100,
    ..Default::default()
};

let limiter = JoinRateLimiter::new(config);

// Check rate limit
match limiter.check_rate(ip_addr) {
    Ok(()) => println!("Rate OK"),
    Err(e) => println!("Rate limited: {}", e),
}
```

---

## Error Handling

All operations return `Result<T, P2PError>`:

```rust
use saorsa_core::{P2PError, Result};

fn example() -> Result<()> {
    let data = get_data(&handle).await.map_err(|e| {
        match e {
            P2PError::NotFound => println!("Data not found"),
            P2PError::Timeout(_) => println!("Operation timed out"),
            P2PError::Network(e) => println!("Network error: {}", e),
            _ => println!("Other error: {}", e),
        }
        e
    })?;
    Ok(())
}
```

---

## Feature Flags

Enable optional features in `Cargo.toml`:

```toml
[dependencies]
saorsa-core = { version = "0.10", features = ["metrics"] }
```

| Feature | Description |
|---------|-------------|
| `metrics` | Prometheus metrics integration |

---

## Thread Safety

Most types are `Send + Sync` and can be shared across threads:

```rust
use std::sync::Arc;
use tokio::spawn;

let manager = Arc::new(DhtNetworkManager::new(config).await?);

let manager_clone = manager.clone();
spawn(async move {
    manager_clone.store(key, record).await?;
});
```

---

## Version Compatibility

| saorsa-core | ant-quic | Rust | Features |
|-------------|----------|------|----------|
| 0.10.x | 0.21.x | 1.78+ | Event-driven recv, PQC-only transport |
| 0.4.x–0.9.x | 0.14.x | 1.75+ | Unified config, PQC integration |
| 0.3.x | 0.10.x | 1.70+ | NAT traversal |

---

## See Also

- [Architecture Decision Records](./adr/) - Design decisions
- [Security Model](./SECURITY_MODEL.md) - Security architecture
- [Auto-Upgrade System](./AUTO_UPGRADE.md) - Binary updates
