# Saorsa-Core Messaging & P2P Integration Specification

**Date**: 2025-10-02
**Status**: SPECIFICATION
**Priority**: CRITICAL - Blocking P2P messaging functionality
**Target**: saorsa-core v0.5.3+

## Executive Summary

**Problem**: saorsa-core 0.5.2 has two independent network stacks - the P2P layer (`saorsa_core::network`) and the Messaging layer (`saorsa_core::messaging`). When applications establish P2P connections and then attempt to send messages, the MessagingService creates NEW connections instead of reusing existing P2P connections, causing message delivery failures.

**Root Cause**: The `MessagingTransport` in `src/messaging/transport.rs` has its own internal `NetworkService` instance that operates independently from the P2P `NetworkService` exposed through the public API.

**Solution**: Modify MessagingService to accept an existing NetworkService instance and reuse P2P connections for message delivery.

**Impact**: Enables seamless P2P messaging without duplicate network stacks, reduces connection overhead, and provides a unified network layer for all saorsa-core operations.

---

## Current Architecture (v0.5.2)

### Network Stack Separation

```
┌─────────────────────────────────────────┐
│     Application (communitas-core)       │
└─────────────┬───────────────┬───────────┘
              │               │
    ┌─────────▼──────┐   ┌───▼──────────┐
    │   P2P Layer    │   │ Messaging    │
    │  Network API   │   │  Service     │
    └─────────┬──────┘   └───┬──────────┘
              │               │
    ┌─────────▼──────┐   ┌───▼──────────┐
    │ NetworkService │   │ Network      │
    │  (instance 1)  │   │ Service      │
    │                │   │ (instance 2) │
    └─────────┬──────┘   └───┬──────────┘
              │               │
    ┌─────────▼───────────────▼──────────┐
    │         ant-quic QUIC Layer         │
    └─────────────────────────────────────┘
```

**Problem Flow**:
1. App calls `network.connect_peer("127.0.0.1:9000")` → Creates connection in NetworkService (instance 1)
2. App calls `messaging.send_message(recipient, data)` → MessagingTransport uses NetworkService (instance 2)
3. Instance 2 tries to create NEW connection → Fails because peer PeerIds don't match
4. Error: "send_to_peer failed on both stacks"

### Current Implementation Issues

#### File: `src/messaging/transport.rs` (Lines ~50-100)

```rust
pub struct MessagingTransport {
    network: Arc<NetworkService>,  // ← Separate instance!
    dht_client: DhtClient,
    retry_config: RetryConfig,
    // ...
}

impl MessagingTransport {
    pub fn new(config: NetworkConfig, dht_client: DhtClient) -> Result<Self> {
        // Creates its OWN NetworkService - not reusing existing P2P connections!
        let network = Arc::new(NetworkService::new(config)?);

        Ok(Self {
            network,
            dht_client,
            retry_config: RetryConfig::default(),
        })
    }

    async fn try_direct_delivery(
        &self,
        recipient: &FourWordAddress,
        message: &EncryptedMessage,
    ) -> Result<DeliveryStatus> {
        // Resolves peer address from DHT
        let peer_info = self.resolve_peer_address(recipient).await?;

        // Tries to connect using ITS OWN network instance
        for addr in &peer_info.addresses {
            if let Ok(peer_id) = self.network.connect_peer(addr).await {
                // ← This creates a NEW connection, not reusing existing P2P!
                // ...
            }
        }
    }
}
```

#### File: `src/messaging/mod.rs` (Lines ~100-150)

```rust
pub struct MessagingService {
    transport: Arc<MessagingTransport>,
    encryption: Arc<MessageEncryption>,
    local_address: FourWordAddress,
}

impl MessagingService {
    pub fn new(
        address: FourWordAddress,
        dht_client: DhtClient,
    ) -> Result<Self> {
        // Creates MessagingTransport with ITS OWN network
        let transport = Arc::new(MessagingTransport::new(
            NetworkConfig::default(),
            dht_client.clone(),
        )?);

        // ...
    }
}
```

---

## Proposed Architecture (v0.5.3+)

### Unified Network Stack

```
┌─────────────────────────────────────────┐
│     Application (communitas-core)       │
└─────────────┬───────────────────────────┘
              │
    ┌─────────▼──────────────────────┐
    │   Unified Network Layer        │
    │   (Shared NetworkService)      │
    └─────────┬──────────┬───────────┘
              │          │
    ┌─────────▼──────┐   ┌▼──────────┐
    │   P2P API      │   │ Messaging │
    │                │   │ Service   │
    └────────────────┘   └───────────┘
              │          │
    ┌─────────▼──────────▼───────────┐
    │    ant-quic QUIC Layer         │
    └────────────────────────────────┘
```

**Benefit**: Single NetworkService instance shared by both P2P and Messaging layers. Connections established via P2P API are automatically available for message delivery.

### New API Design

#### 1. Accept External NetworkService in MessagingTransport

**File**: `src/messaging/transport.rs`

```rust
pub struct MessagingTransport {
    network: Arc<NetworkService>,
    dht_client: DhtClient,
    retry_config: RetryConfig,
    owns_network: bool,  // NEW: Track ownership for cleanup
}

impl MessagingTransport {
    /// Create transport with a new internal NetworkService (backward compatible)
    pub fn new(config: NetworkConfig, dht_client: DhtClient) -> Result<Self> {
        let network = Arc::new(NetworkService::new(config)?);

        Ok(Self {
            network,
            dht_client,
            retry_config: RetryConfig::default(),
            owns_network: true,  // We created it, we manage it
        })
    }

    /// NEW: Create transport using an existing NetworkService (shared instance)
    pub fn with_network_service(
        network: Arc<NetworkService>,
        dht_client: DhtClient,
    ) -> Result<Self> {
        Ok(Self {
            network,
            dht_client,
            retry_config: RetryConfig::default(),
            owns_network: false,  // Caller manages lifecycle
        })
    }

    async fn try_direct_delivery(
        &self,
        recipient: &FourWordAddress,
        message: &EncryptedMessage,
    ) -> Result<DeliveryStatus> {
        let peer_info = self.resolve_peer_address(recipient).await?;

        // NEW: Check if we already have an active connection to any of these addresses
        for addr in &peer_info.addresses {
            // First, check existing connections by address
            if let Some(peer_id) = self.network.get_peer_id_by_address(addr).await {
                // Reuse existing connection!
                if let Ok(()) = self.network
                    .send_message(&peer_id, "messaging", data.clone())
                    .await
                {
                    return Ok(DeliveryStatus::Delivered(Utc::now()));
                }
            }

            // Fallback: Try to establish new connection if none exists
            if let Ok(peer_id) = self.network.connect_peer(addr).await {
                if let Ok(()) = self.network
                    .send_message(&peer_id, "messaging", data.clone())
                    .await
                {
                    return Ok(DeliveryStatus::Delivered(Utc::now()));
                }
            }
        }

        Err(anyhow::anyhow!("All endpoints failed for {recipient}"))
    }
}
```

#### 2. Update MessagingService Constructor

**File**: `src/messaging/mod.rs`

```rust
pub struct MessagingService {
    transport: Arc<MessagingTransport>,
    encryption: Arc<MessageEncryption>,
    local_address: FourWordAddress,
}

impl MessagingService {
    /// Create with new internal network (backward compatible)
    pub fn new(
        address: FourWordAddress,
        dht_client: DhtClient,
    ) -> Result<Self> {
        let transport = Arc::new(MessagingTransport::new(
            NetworkConfig::default(),
            dht_client.clone(),
        )?);

        let encryption = Arc::new(MessageEncryption::new(
            address.clone(),
            dht_client,
        )?);

        Ok(Self {
            transport,
            encryption,
            local_address: address,
        })
    }

    /// NEW: Create with custom network config (backward compatible)
    pub fn new_with_config(
        address: FourWordAddress,
        dht_client: DhtClient,
        config: NetworkConfig,
    ) -> Result<Self> {
        let transport = Arc::new(MessagingTransport::new(
            config,
            dht_client.clone(),
        )?);

        let encryption = Arc::new(MessageEncryption::new(
            address.clone(),
            dht_client,
        )?);

        Ok(Self {
            transport,
            encryption,
            local_address: address,
        })
    }

    /// NEW: Create using existing NetworkService (shared instance)
    pub fn with_network_service(
        address: FourWordAddress,
        network: Arc<NetworkService>,
        dht_client: DhtClient,
    ) -> Result<Self> {
        let transport = Arc::new(MessagingTransport::with_network_service(
            network,
            dht_client.clone(),
        )?);

        let encryption = Arc::new(MessageEncryption::new(
            address.clone(),
            dht_client,
        )?);

        Ok(Self {
            transport,
            encryption,
            local_address: address,
        })
    }
}
```

#### 3. Add Connection Lookup to NetworkService

**File**: `src/network/mod.rs`

```rust
impl NetworkService {
    /// NEW: Get PeerId for an already-connected peer by socket address
    pub async fn get_peer_id_by_address(&self, addr: &str) -> Option<PeerId> {
        // Parse socket address
        let socket_addr: SocketAddr = addr.parse().ok()?;

        // Look up in active connections
        let connections = self.active_connections.read().await;

        // Search for matching connection by remote address
        for (peer_id, conn_info) in connections.iter() {
            if conn_info.remote_address() == socket_addr {
                return Some(peer_id.clone());
            }
        }

        None
    }

    /// NEW: Get all active connection addresses (for debugging)
    pub async fn list_active_connections(&self) -> Vec<(PeerId, SocketAddr)> {
        let connections = self.active_connections.read().await;
        connections
            .iter()
            .map(|(peer_id, conn_info)| {
                (peer_id.clone(), conn_info.remote_address())
            })
            .collect()
    }
}
```

---

## Integration Pattern (communitas-core)

### Before (Current - Broken)

```rust
// Create CoreContext
let ctx = CoreContext::initialize(
    four_words,
    display_name,
    device_name,
    DeviceType::Desktop,
).await?;

// Manually establish P2P connection using network address
let network_addr = encode_socket_to_four_words("127.0.0.1:9000");
ctx.connect_to_peer(&network_addr).await?;  // ← Connection in P2P layer

// Try to send message using identity address
ctx.send_channel_message(&channel_id, "Hello").await?;  // ← Tries to use Messaging layer
// ERROR: "send_to_peer failed on both stacks" - layers don't share connections!
```

### After (Fixed - Working)

```rust
// Create CoreContext with shared network
let ctx = CoreContext::initialize(
    four_words,
    display_name,
    device_name,
    DeviceType::Desktop,
).await?;

// Manually establish P2P connection (optional - for immediate connectivity)
let network_addr = encode_socket_to_four_words("127.0.0.1:9000");
ctx.connect_to_peer(&network_addr).await?;  // ← Connection in shared NetworkService

// Publish PeerInfo to DHT (maps identity → network address)
ctx.publish_peer_info_to_dht().await?;

// Send message using identity address
ctx.send_channel_message(&channel_id, "Hello").await?;
// ✅ MessagingTransport looks up identity in DHT → gets "127.0.0.1:9000"
// ✅ Calls get_peer_id_by_address("127.0.0.1:9000") → finds existing connection
// ✅ Reuses existing P2P connection for message delivery
```

---

## Implementation Plan

### Phase 1: Core Changes (saorsa-core)

#### Step 1.1: Add Connection Lookup to NetworkService
**File**: `src/network/mod.rs`

**Changes**:
- Add `get_peer_id_by_address()` method
- Add `list_active_connections()` method for debugging
- Ensure thread-safe access to connection map

**Tests**:
```rust
#[tokio::test]
async fn test_connection_lookup_by_address() {
    let service = NetworkService::new(NetworkConfig::default()).unwrap();

    // Connect to peer
    let peer_id = service.connect_peer("127.0.0.1:9000").await.unwrap();

    // Look up by address
    let found_id = service.get_peer_id_by_address("127.0.0.1:9000").await;
    assert_eq!(found_id, Some(peer_id));

    // Non-existent address returns None
    let not_found = service.get_peer_id_by_address("127.0.0.1:9999").await;
    assert_eq!(not_found, None);
}
```

#### Step 1.2: Update MessagingTransport Constructor
**File**: `src/messaging/transport.rs`

**Changes**:
- Add `owns_network` field to track ownership
- Add `with_network_service()` constructor
- Keep existing `new()` for backward compatibility

**Tests**:
```rust
#[tokio::test]
async fn test_transport_with_shared_network() {
    let network = Arc::new(NetworkService::new(NetworkConfig::default()).unwrap());
    let dht = DhtClient::new().unwrap();

    // Create transport using shared network
    let transport = MessagingTransport::with_network_service(
        network.clone(),
        dht,
    ).unwrap();

    assert!(!transport.owns_network);

    // Verify same network instance
    assert!(Arc::ptr_eq(&transport.network, &network));
}
```

#### Step 1.3: Update Message Delivery Logic
**File**: `src/messaging/transport.rs:try_direct_delivery()`

**Changes**:
- Check existing connections BEFORE attempting new connections
- Use `get_peer_id_by_address()` to find reusable connections
- Fallback to new connection if no existing match
- Add logging for connection reuse

**Tests**:
```rust
#[tokio::test]
async fn test_reuse_existing_p2p_connection() {
    let network = Arc::new(NetworkService::new(NetworkConfig::default()).unwrap());
    let dht = DhtClient::new().unwrap();

    // Establish P2P connection
    let peer_id = network.connect_peer("127.0.0.1:9000").await.unwrap();

    // Publish PeerInfo to DHT
    let peer_info = PeerInfo {
        addresses: vec!["127.0.0.1:9000".to_string()],
        public_key: vec![],
        capabilities: vec!["messaging".to_string()],
        last_seen: Utc::now(),
    };
    dht.put(
        "peer:test-identity".to_string(),
        serde_json::to_vec(&peer_info).unwrap(),
    ).await.unwrap();

    // Create transport with shared network
    let transport = MessagingTransport::with_network_service(network, dht).unwrap();

    // Send message using identity address
    let message = EncryptedMessage::new(/* ... */);
    let status = transport.try_direct_delivery(
        &FourWordAddress::from_str("test-identity").unwrap(),
        &message,
    ).await.unwrap();

    // Should have reused existing connection without creating new one
    assert!(matches!(status, DeliveryStatus::Delivered(_)));
}
```

#### Step 1.4: Update MessagingService API
**File**: `src/messaging/mod.rs`

**Changes**:
- Add `with_network_service()` constructor
- Maintain backward compatibility with existing constructors
- Update documentation with usage examples

**Tests**:
```rust
#[tokio::test]
async fn test_messaging_service_with_shared_network() {
    let network = Arc::new(NetworkService::new(NetworkConfig::default()).unwrap());
    let dht = DhtClient::new().unwrap();
    let address = FourWordAddress::from_str("test-user").unwrap();

    // Create messaging service with shared network
    let messaging = MessagingService::with_network_service(
        address,
        network.clone(),
        dht,
    ).unwrap();

    // Verify integration works end-to-end
    // (Full integration test in Phase 2)
}
```

### Phase 2: Integration Testing (communitas-core)

#### Step 2.1: Update CoreContext Integration
**File**: `communitas-core/src/core_context.rs`

**Changes**:
```rust
pub async fn initialize_with_shared_dht(
    four_words: String,
    display_name: String,
    device_name: String,
    device_type: DeviceType,
    dht_client: DhtClient,
) -> Result<Self, String> {
    // Create shared NetworkService
    let network_config = NetworkConfig::default();
    let network_service = Arc::new(
        saorsa_core::network::NetworkService::new(network_config)
            .map_err(|e| format!("Failed to create network service: {}", e))?
    );

    // Create MessagingService using shared network
    let messaging = saorsa_core::messaging::MessagingService::with_network_service(
        FourWordAddress::from_str(&four_words)
            .map_err(|e| format!("Invalid four-word address: {}", e))?,
        network_service.clone(),
        dht_client.clone(),
    ).map_err(|e| format!("Failed to create messaging service: {}", e))?;

    // Store both network and messaging
    let context = Self {
        network: Some(network_service),
        messaging: Arc::new(messaging),
        // ... rest of initialization
    };

    // Auto-register PeerInfo in DHT
    context.publish_peer_info_to_dht().await?;

    Ok(context)
}
```

#### Step 2.2: Update P2P Messaging Test
**File**: `communitas-core/tests/p2p_messaging.rs`

**Changes**:
- Remove manual `connect_to_peer` calls (let MessagingService handle it via DHT)
- OR keep them to test connection reuse
- Verify messages successfully delivered

**Expected Behavior**:
```rust
#[tokio::test]
async fn test_two_instances_send_message() -> anyhow::Result<()> {
    // Initialize both instances with shared DHT
    let ctx1 = CoreContext::initialize_with_shared_dht(/* ... */).await?;
    let ctx2 = CoreContext::initialize_with_shared_dht(/* ... */).await?;

    // PeerInfo auto-registered during initialization

    // Mark peers online for KEM
    ctx1.mark_peer_online(&four_words_2).await?;
    ctx2.mark_peer_online(&four_words_1).await?;

    // Create channel and add member
    let channel_id = ctx1.chat.create_channel(/* ... */).await?;
    ctx1.add_channel_member(&channel_id, four_words_2.clone(), /* ... */).await?;

    // Send message - should work via DHT-resolved connection
    let msg_id = ctx1.send_channel_message(&channel_id, "Hello!").await?;

    // Verify receipt
    sleep(Duration::from_secs(3)).await;
    let messages = ctx2.get_channel_messages(&channel_id, 10).await?;

    let received = messages.iter().find(|m| m.id.0.to_string() == msg_id).unwrap();
    assert_eq!(received.content, MessageContent::Text("Hello!".to_string()));

    // ✅ Test passes!
    Ok(())
}
```

### Phase 3: Documentation & Migration

#### Step 3.1: Update API Documentation
**Files**:
- `saorsa-core/README.md`
- `saorsa-core/docs/messaging.md`
- `saorsa-core/CHANGELOG.md`

**Content**:
```markdown
## v0.5.3 - Network Stack Unification

### New Features
- `MessagingService::with_network_service()` - Share NetworkService between P2P and Messaging layers
- `MessagingTransport::with_network_service()` - Low-level API for shared transport
- `NetworkService::get_peer_id_by_address()` - Look up existing connections by address
- `NetworkService::list_active_connections()` - Debug helper for connection management

### Improvements
- MessagingService now reuses existing P2P connections instead of creating duplicates
- Reduced memory footprint by eliminating duplicate network stacks
- Faster message delivery by avoiding redundant connection establishment
- Better connection management with unified lifecycle

### Migration Guide

**Before (v0.5.2)**:
```rust
let messaging = MessagingService::new(address, dht_client)?;
// MessagingService creates its own NetworkService internally
```

**After (v0.5.3)** - Recommended for P2P applications:
```rust
// Create shared network
let network = Arc::new(NetworkService::new(NetworkConfig::default())?);

// Use same network for both P2P and Messaging
let messaging = MessagingService::with_network_service(address, network.clone(), dht_client)?;

// Now P2P connections are automatically used for message delivery!
```

**Backward Compatibility**: Existing code continues to work unchanged. The new API is opt-in.
```

#### Step 3.2: Add Usage Examples
**File**: `saorsa-core/examples/p2p_messaging.rs`

```rust
//! Example: P2P Messaging with Shared Network
//!
//! Demonstrates how to establish P2P connections and send messages
//! using a shared NetworkService instance.

use saorsa_core::{
    network::{NetworkService, NetworkConfig},
    messaging::{MessagingService, DhtClient},
    identity::FourWordAddress,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize DHT client
    let dht = DhtClient::new()?;

    // Create shared network service
    let network = Arc::new(NetworkService::new(NetworkConfig::default())?);

    // Create messaging service using shared network
    let messaging = MessagingService::with_network_service(
        FourWordAddress::from_str("alice-test-user-one")?,
        network.clone(),
        dht.clone(),
    )?;

    // Establish P2P connection
    let peer_id = network.connect_peer("127.0.0.1:9000").await?;
    println!("✅ Connected to peer: {}", peer_id);

    // Send message - automatically reuses the connection we just established!
    let recipient = FourWordAddress::from_str("bob-test-user-two")?;
    messaging.send_message(
        vec![recipient],
        "Hello from Alice!".as_bytes(),
        None,  // No channel
        Default::default(),
    ).await?;

    println!("✅ Message sent!");

    Ok(())
}
```

---

## Testing Strategy

### Unit Tests (saorsa-core)

1. **NetworkService Connection Lookup**
   - `test_get_peer_id_by_address_existing`
   - `test_get_peer_id_by_address_not_found`
   - `test_list_active_connections`

2. **MessagingTransport Shared Network**
   - `test_transport_with_network_service`
   - `test_transport_ownership_flag`
   - `test_transport_reuses_connections`

3. **MessagingService Integration**
   - `test_messaging_with_shared_network`
   - `test_backward_compatibility`

### Integration Tests (communitas-core)

1. **P2P Messaging End-to-End**
   - `test_two_instances_send_message`
   - `test_channel_messaging_with_multiple_members`
   - `test_message_delivery_with_offline_peers`

2. **Connection Reuse**
   - `test_manual_p2p_then_messaging`
   - `test_messaging_without_manual_p2p`
   - `test_connection_count_single_stack`

### Performance Tests

1. **Memory Usage**
   - Before: 2 NetworkService instances = ~50MB baseline
   - After: 1 NetworkService instance = ~25MB baseline
   - Target: 50% reduction

2. **Connection Time**
   - Before: Always establish new connection = ~200ms
   - After: Reuse existing = <1ms
   - Target: 99% reduction when connection exists

3. **Message Latency**
   - Before: Connection + Send = ~250ms
   - After: Send only = ~50ms
   - Target: 80% improvement

---

## Backward Compatibility

### Compatibility Matrix

| Use Case | v0.5.2 API | v0.5.3 API | Breaking? |
|----------|------------|------------|-----------|
| Basic messaging (single stack) | `MessagingService::new()` | Same | ❌ No |
| Custom config | `MessagingService::new_with_config()` | Same | ❌ No |
| Shared network (NEW) | N/A | `MessagingService::with_network_service()` | ✅ New feature |
| P2P + Messaging | Broken (duplicate stacks) | Fixed (shared stack) | ✅ Fixes bug |

### Migration Path

**No breaking changes**. Existing code works unchanged. New API is opt-in for applications that want to share NetworkService between P2P and Messaging layers.

**Recommended**: All applications using both P2P and Messaging should migrate to shared NetworkService for better performance and reliability.

---

## Risk Assessment

### Low Risk
- ✅ Backward compatible (new API is additive)
- ✅ Well-defined interfaces (no internal API changes)
- ✅ Comprehensive test coverage

### Medium Risk
- ⚠️ Connection lifecycle management (who closes what)
- ⚠️ Thread safety of shared NetworkService
- ⚠️ Error handling when connection lookup fails

### Mitigation Strategies

1. **Ownership Tracking**: `owns_network` flag ensures proper cleanup
2. **Arc Safety**: NetworkService already thread-safe via Arc + RwLock
3. **Graceful Fallback**: If connection lookup fails, establish new connection
4. **Extensive Testing**: Unit + integration + performance tests

---

## Success Criteria

### Must Have ✅
- [ ] `test_two_instances_send_message` passes consistently
- [ ] Backward compatibility maintained (all existing tests pass)
- [ ] Connection reuse measurable (metrics show single stack)
- [ ] Documentation complete with migration guide

### Should Have 🎯
- [ ] Memory usage reduced by 40%+
- [ ] Message latency improved when connection exists
- [ ] Example code demonstrates best practices

### Nice to Have 💡
- [ ] Connection pool metrics exposed
- [ ] Debug tools for connection visualization
- [ ] Performance benchmarks in CI

---

## Timeline

### Week 1: Core Implementation
- **Days 1-2**: NetworkService connection lookup API
- **Days 3-4**: MessagingTransport shared network support
- **Day 5**: MessagingService public API

### Week 2: Testing & Integration
- **Days 1-2**: Unit tests for all new APIs
- **Days 3-4**: Integration testing in communitas-core
- **Day 5**: Performance testing and optimization

### Week 3: Documentation & Release
- **Days 1-2**: API documentation and examples
- **Days 3-4**: Migration guide and changelog
- **Day 5**: Release v0.5.3

---

## Open Questions

1. **Q**: Should we expose connection metrics (count, bandwidth, etc.)?
   **A**: Yes, add to Phase 3 as debugging tools

2. **Q**: What happens if NetworkService is dropped while MessagingService still active?
   **A**: Arc reference counting prevents this - NetworkService lives as long as any holder

3. **Q**: Should we add connection pooling/limits?
   **A**: Future enhancement - current spec focuses on reuse, not limiting

4. **Q**: How to handle DHT lookup failures (peer not found)?
   **A**: Existing error handling sufficient - return error to caller

---

## References

### Related Issues
- communitas-core: "Transport error: send_to_peer failed on both stacks"
- P2P_INTEGRATION_COMPLETE.md: Expected test to pass but didn't

### Documentation
- saorsa-core API docs: https://docs.rs/saorsa-core
- ant-quic NAT traversal: v0.10.0 P2P support
- communitas-core architecture: CLAUDE.md

### Test Cases
- `communitas-core/tests/p2p_messaging.rs:test_two_instances_send_message`
- Current status: FAILING (connection not reused)
- Expected: PASSING after implementation

---

## Appendix A: Detailed Code Diffs

### src/network/mod.rs

```diff
impl NetworkService {
+   /// Look up PeerId for an active connection by socket address
+   ///
+   /// Returns `Some(PeerId)` if a connection exists to the given address,
+   /// `None` if no matching connection found.
+   ///
+   /// # Example
+   /// ```
+   /// let peer_id = network.connect_peer("127.0.0.1:9000").await?;
+   /// let found = network.get_peer_id_by_address("127.0.0.1:9000").await;
+   /// assert_eq!(found, Some(peer_id));
+   /// ```
+   pub async fn get_peer_id_by_address(&self, addr: &str) -> Option<PeerId> {
+       let socket_addr: SocketAddr = addr.parse().ok()?;
+       let connections = self.active_connections.read().await;
+
+       for (peer_id, conn_info) in connections.iter() {
+           if conn_info.remote_address() == socket_addr {
+               return Some(peer_id.clone());
+           }
+       }
+
+       None
+   }
+
+   /// List all active connections (for debugging)
+   pub async fn list_active_connections(&self) -> Vec<(PeerId, SocketAddr)> {
+       let connections = self.active_connections.read().await;
+       connections
+           .iter()
+           .map(|(id, info)| (id.clone(), info.remote_address()))
+           .collect()
+   }
}
```

### src/messaging/transport.rs

```diff
pub struct MessagingTransport {
    network: Arc<NetworkService>,
    dht_client: DhtClient,
    retry_config: RetryConfig,
+   owns_network: bool,
}

impl MessagingTransport {
    pub fn new(config: NetworkConfig, dht_client: DhtClient) -> Result<Self> {
        let network = Arc::new(NetworkService::new(config)?);

        Ok(Self {
            network,
            dht_client,
            retry_config: RetryConfig::default(),
+           owns_network: true,
        })
    }

+   /// Create transport using an existing NetworkService
+   ///
+   /// This allows sharing a NetworkService between P2P and Messaging layers,
+   /// enabling connection reuse and reducing overhead.
+   ///
+   /// # Example
+   /// ```
+   /// let network = Arc::new(NetworkService::new(config)?);
+   /// let transport = MessagingTransport::with_network_service(network, dht)?;
+   /// ```
+   pub fn with_network_service(
+       network: Arc<NetworkService>,
+       dht_client: DhtClient,
+   ) -> Result<Self> {
+       Ok(Self {
+           network,
+           dht_client,
+           retry_config: RetryConfig::default(),
+           owns_network: false,
+       })
+   }

    async fn try_direct_delivery(
        &self,
        recipient: &FourWordAddress,
        message: &EncryptedMessage,
    ) -> Result<DeliveryStatus> {
        let peer_info = self.resolve_peer_address(recipient).await?;

+       // Try to reuse existing connections first
        for addr in &peer_info.addresses {
+           // Check if we already have a connection to this address
+           if let Some(peer_id) = self.network.get_peer_id_by_address(addr).await {
+               tracing::debug!("Reusing existing connection to {} (peer: {})", addr, peer_id);
+
+               if let Ok(()) = self.network
+                   .send_message(&peer_id, "messaging", data.clone())
+                   .await
+               {
+                   return Ok(DeliveryStatus::Delivered(Utc::now()));
+               }
+
+               tracing::warn!("Failed to send via existing connection, will try new");
+           }
+
+           // Fallback: establish new connection
            if let Ok(peer_id) = self.network.connect_peer(addr).await {
+               tracing::debug!("Established new connection to {}", addr);
                if let Err(e) = self.network
                    .send_message(&peer_id, "messaging", data.clone())
                    .await
                {
                    warn!("Failed sending to {} via {}: {}", recipient, addr, e);
                    continue;
                }
                return Ok(DeliveryStatus::Delivered(Utc::now()));
            }
        }

        Err(anyhow::anyhow!("All endpoints failed for {recipient}"))
    }
}
```

### src/messaging/mod.rs

```diff
impl MessagingService {
    pub fn new(
        address: FourWordAddress,
        dht_client: DhtClient,
    ) -> Result<Self> {
        let transport = Arc::new(MessagingTransport::new(
            NetworkConfig::default(),
            dht_client.clone(),
        )?);

        let encryption = Arc::new(MessageEncryption::new(
            address.clone(),
            dht_client,
        )?);

        Ok(Self {
            transport,
            encryption,
            local_address: address,
        })
    }

    pub fn new_with_config(
        address: FourWordAddress,
        dht_client: DhtClient,
        config: NetworkConfig,
    ) -> Result<Self> {
        let transport = Arc::new(MessagingTransport::new(
            config,
            dht_client.clone(),
        )?);

        let encryption = Arc::new(MessageEncryption::new(
            address.clone(),
            dht_client,
        )?);

        Ok(Self {
            transport,
            encryption,
            local_address: address,
        })
    }

+   /// Create messaging service using an existing NetworkService
+   ///
+   /// This enables sharing a single NetworkService between P2P and Messaging
+   /// layers, allowing message delivery to reuse existing P2P connections.
+   ///
+   /// # Benefits
+   /// - Reduced memory footprint (single network stack)
+   /// - Faster message delivery (reuses connections)
+   /// - Unified connection lifecycle management
+   ///
+   /// # Example
+   /// ```
+   /// // Create shared network
+   /// let network = Arc::new(NetworkService::new(config)?);
+   ///
+   /// // Establish P2P connection
+   /// network.connect_peer("127.0.0.1:9000").await?;
+   ///
+   /// // Create messaging with shared network
+   /// let messaging = MessagingService::with_network_service(
+   ///     address,
+   ///     network.clone(),
+   ///     dht,
+   /// )?;
+   ///
+   /// // Send message - reuses the P2P connection!
+   /// messaging.send_message(recipients, data, None, opts).await?;
+   /// ```
+   pub fn with_network_service(
+       address: FourWordAddress,
+       network: Arc<NetworkService>,
+       dht_client: DhtClient,
+   ) -> Result<Self> {
+       let transport = Arc::new(MessagingTransport::with_network_service(
+           network,
+           dht_client.clone(),
+       )?);
+
+       let encryption = Arc::new(MessageEncryption::new(
+           address.clone(),
+           dht_client,
+       )?);
+
+       Ok(Self {
+           transport,
+           encryption,
+           local_address: address,
+       })
+   }
}
```

---

## Conclusion

This specification provides a complete blueprint for unifying saorsa-core's network stacks, enabling MessagingService to reuse existing P2P connections. The changes are:

- **Backward compatible**: Existing code continues to work
- **Well-scoped**: Clear interfaces and minimal changes
- **Testable**: Comprehensive test strategy included
- **Documented**: Full API docs and migration guide

Implementation of this spec will resolve the "send_to_peer failed on both stacks" error and enable seamless P2P messaging in communitas-core.

**Next Steps**: Submit this spec to saorsa-core maintainers for review and implementation in v0.5.3.
