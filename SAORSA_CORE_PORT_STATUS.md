# Port Configuration Implementation Status

**Date**: 2025-10-01
**Version**: saorsa-core 0.3.28
**Related**: SAORSA_CORE_PORT_SPECIFICATION.md

## Summary

Port configuration support has been partially implemented in saorsa-core. The NetworkConfig types are defined and ready for use, but full functionality requires updates to the ant-quic dependency.

## What's Implemented (v0.3.28)

### ✅ NetworkConfig Types
- `NetworkConfig` struct with port, IP mode, and retry behavior
- `PortConfig` enum: OsAssigned, Explicit, Range
- `IpMode` enum: DualStack, DualStackSeparate, IPv4Only, IPv6Only
- `RetryBehavior` enum: FailFast, FallbackToOsAssigned, TryNext
- `NetworkConfigError` error types with helpful messages

**Location**: `src/messaging/network_config.rs`

### ✅ Port Discovery
- `MessagingService::listen_addrs()` - Get all bound addresses
- `MessagingService::peer_count()` - Get connected peer count
- `MessagingService::connected_peers()` - Get list of peer IDs
- `MessagingService::is_running()` - Check if P2P node is active

**Location**: `src/messaging/service.rs` (lines 436-458)

### ✅ P2P Networking Methods
- `connect_peer(address)` - Connect to peer via network address
- `disconnect_peer(peer_id)` - Disconnect from specific peer

## What's NOT Yet Implemented

### ❌ MessagingService::new_with_config()
**Reason**: Requires ant-quic API changes to support port configuration

The current P2PNode initialization in ant-quic hardcodes port 9000 and doesn't expose configuration options for:
- OS-assigned ports (port 0)
- Custom port selection
- Port range selection
- Dual-stack separate ports

### ❌ Actual Port Configuration
**Reason**: ant-quic limitation

The `NetworkConfig` types are defined but cannot be used until ant-quic supports:
```rust
// This will work once ant-quic is updated:
let config = NetworkConfig {
    port: PortConfig::OsAssigned,  // Currently ignored
    ip_mode: IpMode::IPv4Only,     // Currently ignored
    ..Default::default()
};
let service = MessagingService::new_with_config(addr, dht, config).await?;
```

## Current Workaround

For now, all instances use the default ant-quic behavior (port 9000, dual-stack if available). To run multiple instances:

1. Use separate machines
2. Use Docker containers with port mapping
3. Use network namespaces
4. Wait for Phase 2 implementation

## Phase 2: ant-quic Integration

### Required Changes in ant-quic

1. **Make port configurable in NAT traversal API**
   - Currently hardcoded to 9000
   - Needs to accept port parameter or PortConfig

2. **Add port discovery after binding**
   - Return actual bound port when using port 0
   - Expose via public API

3. **Fix dual-stack binding conflicts**
   - Handle IPv4/IPv6 port conflicts gracefully
   - Support separate ports for each stack

4. **Add EndpointConfig**
   ```rust
   pub struct EndpointConfig {
       pub port: u16,
       pub ip_version: IpVersion,
       pub socket_opts: SocketOptions,
   }
   ```

### Implementation Plan

1. **Contact ant-quic maintainers**
   - Discuss port configuration requirements
   - Propose API changes
   - Coordinate timeline

2. **Create ant-quic PR** (estimated 1-2 weeks)
   - Implement EndpointConfig
   - Add port configuration support
   - Fix dual-stack issues
   - Add tests

3. **Update saorsa-core** (estimated 1 week)
   - Implement `new_with_config()`
   - Wire NetworkConfig to ant-quic EndpointConfig
   - Add integration tests
   - Update documentation

4. **Release**
   - ant-quic 0.9.0 with port configuration
   - saorsa-core 0.4.0 with full NetworkConfig support

## Testing Current Implementation

Even without full port configuration, you can test the networking methods:

```rust
use saorsa_core::messaging::MessagingService;

// Create service (uses default port 9000)
let service = MessagingService::new(address, dht_client).await?;

// Get listen addresses
let addrs = service.listen_addrs().await;
println!("Listening on: {:?}", addrs);

// Get peer count
let count = service.peer_count().await;
println!("Connected peers: {}", count);

// Connect to peer
let peer_addr = "192.168.1.100:9000";
service.connect_peer(peer_addr).await?;
```

## Benefits of Current Implementation

Even though full port configuration isn't available yet:

1. **API is Ready**: NetworkConfig types are defined and documented
2. **Port Discovery Works**: Can query actual bound addresses
3. **P2P Networking Works**: Can connect/disconnect peers
4. **No Breaking Changes**: Existing code continues to work
5. **Easy Migration**: When ant-quic is updated, just use `new_with_config()`

## Timeline

### Completed (2025-10-01)
- ✅ NetworkConfig types designed and implemented
- ✅ Port discovery methods added to MessagingService
- ✅ P2P networking methods exposed
- ✅ Documentation written
- ✅ Published as saorsa-core 0.3.28

### Next Steps (Phase 2 - TBD)
- Contact ant-quic maintainers
- Create ant-quic PR for port configuration
- Implement `new_with_config()` in saorsa-core
- Release saorsa-core 0.4.0

## References

- Specification: `SAORSA_CORE_PORT_SPECIFICATION.md`
- Issue: `SAORSA_CORE_PORT_ISSUE.md`
- NetworkConfig implementation: `src/messaging/network_config.rs`
- ant-quic: https://docs.rs/ant-quic/0.8.17

## Contact

For questions or to help with Phase 2 implementation:
- Email: saorsalabs@gmail.com
- GitHub: https://github.com/dirvine/saorsa-core-foundation

---

**Note**: This is a phased implementation approach. The groundwork is complete, and full functionality will be available once ant-quic adds port configuration support.
