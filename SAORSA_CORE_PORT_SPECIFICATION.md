# Saorsa-Core Port Configuration Specification

**Version**: 1.0
**Date**: 2025-10-01
**Status**: Proposed
**Related Issue**: SAORSA_CORE_PORT_ISSUE.md

## Executive Summary

This specification defines the requirements for making port configuration flexible in saorsa-core's MessagingService and ant-quic networking layer. The primary goals are to:

1. Enable OS-assigned random ports (port 0)
2. Support multiple instances on the same machine
3. Fix dual-stack IPv4/IPv6 port binding conflicts
4. Maintain backward compatibility where possible

## 1. Current Problems

### 1.1 Hardcoded Port 9000
- **Location**: ant-quic NAT traversal API
- **Impact**: Cannot run multiple instances on same machine
- **Severity**: CRITICAL - blocks testing and multi-instance deployments

### 1.2 Dual-Stack Binding Conflict
- **Issue**: Both IPv4 and IPv6 stacks attempt to bind to port 9000
- **Result**: "Address already in use (os error 48)"
- **Impact**: Even SINGLE instance initialization fails
- **Severity**: CRITICAL - blocks all P2P functionality

### 1.3 No Port Discovery Mechanism
- **Issue**: No way to query actual bound port after initialization
- **Impact**: Cannot connect peers when using OS-assigned ports
- **Severity**: HIGH - required for port 0 support

## 2. Requirements

### 2.1 Functional Requirements

#### FR1: Configurable Port Selection
- MUST support explicit port specification (e.g., 9000, 12345)
- MUST support port 0 (OS-assigned random port)
- MUST support port ranges for automatic selection
- SHOULD validate port numbers (1-65535 range)

#### FR2: Port Discovery
- MUST provide method to query actual bound port after initialization
- MUST return both IPv4 and IPv6 bound addresses (if dual-stack)
- MUST include port in returned NetworkAddress

#### FR3: Dual-Stack Networking
- MUST fix IPv4/IPv6 port conflict
- SHOULD support three modes:
  - `DualStack`: Both IPv4 and IPv6 on same port
  - `IPv4Only`: IPv4 only
  - `IPv6Only`: IPv6 only
- MUST allow different ports for IPv4 vs IPv6 if needed

#### FR4: Backward Compatibility
- SHOULD maintain existing API for default behavior
- SHOULD default to port 0 (OS-assigned) for new code
- MAY deprecate hardcoded port 9000 behavior

### 2.2 Non-Functional Requirements

#### NFR1: Performance
- Port configuration MUST NOT add >10ms to initialization time
- Port discovery MUST NOT require network calls

#### NFR2: Security
- MUST validate all port inputs to prevent injection
- MUST fail safely if requested port unavailable
- SHOULD log port binding attempts for audit

#### NFR3: Reliability
- MUST handle port conflicts gracefully
- MUST provide clear error messages for binding failures
- SHOULD retry with OS-assigned port if explicit port fails (configurable)

## 3. Proposed API Design

### 3.1 NetworkConfig Structure

```rust
/// Configuration for network port binding
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Port configuration for networking
    pub port: PortConfig,

    /// IP stack configuration
    pub ip_mode: IpMode,

    /// Retry behavior on port conflicts
    pub retry_behavior: RetryBehavior,
}

/// Port configuration options
#[derive(Debug, Clone)]
pub enum PortConfig {
    /// Let OS assign random available port
    OsAssigned,

    /// Use specific port
    Explicit(u16),

    /// Try ports in range, use first available
    Range(u16, u16),
}

/// IP stack mode configuration
#[derive(Debug, Clone)]
pub enum IpMode {
    /// Both IPv4 and IPv6 on same port (if supported)
    DualStack,

    /// IPv4 and IPv6 on different ports
    DualStackSeparate { ipv4_port: PortConfig, ipv6_port: PortConfig },

    /// IPv4 only
    IPv4Only,

    /// IPv6 only
    IPv6Only,
}

/// Retry behavior on port conflicts
#[derive(Debug, Clone)]
pub enum RetryBehavior {
    /// Fail immediately if port unavailable
    FailFast,

    /// Fall back to OS-assigned port
    FallbackToOsAssigned,

    /// Try next port in range
    TryNext,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            port: PortConfig::OsAssigned,
            ip_mode: IpMode::IPv4Only,  // Avoid dual-stack conflicts by default
            retry_behavior: RetryBehavior::FailFast,
        }
    }
}
```

### 3.2 MessagingService API Changes

```rust
impl MessagingService {
    /// Create new MessagingService with default configuration
    ///
    /// Uses OS-assigned port and IPv4-only mode by default
    pub async fn new(
        address: FourWordAddress,
        dht_client: DhtClient,
    ) -> Result<Self, MessagingError> {
        Self::new_with_config(address, dht_client, NetworkConfig::default()).await
    }

    /// Create new MessagingService with custom network configuration
    pub async fn new_with_config(
        address: FourWordAddress,
        dht_client: DhtClient,
        config: NetworkConfig,
    ) -> Result<Self, MessagingError> {
        // Implementation
    }

    /// Get the actual bound local addresses
    ///
    /// Returns Vec because dual-stack may have multiple addresses
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        // Implementation
    }

    /// Get primary local address (IPv4 preferred)
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addrs().first().copied()
    }

    /// Get local address as four-word encoded string
    pub fn local_four_words(&self) -> Option<String> {
        self.local_addr().and_then(|addr| {
            // Encode using four-word-networking
        })
    }
}
```

### 3.3 Ant-Quic Changes

```rust
// In ant-quic crate

/// Configuration for QUIC endpoint binding
pub struct EndpointConfig {
    /// Port to bind to (0 = OS assigned)
    pub port: u16,

    /// IP version to use
    pub ip_version: IpVersion,

    /// Socket options
    pub socket_opts: SocketOptions,
}

pub enum IpVersion {
    V4,
    V6,
    DualStack,
}

impl Endpoint {
    /// Create endpoint with configuration
    pub fn new_with_config(config: EndpointConfig) -> Result<Self> {
        // Implementation
    }

    /// Get actual bound socket address
    pub fn local_addr(&self) -> SocketAddr {
        // Implementation
    }
}
```

## 4. Migration Path

### 4.1 Phase 1: Add New APIs (v0.4.0)
- Add `NetworkConfig` and related types
- Add `new_with_config()` method
- Add `local_addrs()` and `local_addr()` methods
- Keep existing `new()` behavior unchanged
- Add deprecation warnings to old API

### 4.2 Phase 2: Change Defaults (v0.5.0)
- Change default port from 9000 to 0 (OS-assigned)
- Change default IP mode to IPv4Only
- Update documentation and examples

### 4.3 Phase 3: Remove Old API (v1.0.0)
- Remove deprecated methods
- Make `config` parameter mandatory

## 5. Implementation Guide

### 5.1 Files to Modify

#### In saorsa-core:
- `src/messaging/service.rs` - Add NetworkConfig support
- `src/messaging/mod.rs` - Export new types
- `src/network/mod.rs` - Update network initialization

#### In ant-quic:
- `src/endpoint.rs` - Make port configurable
- `src/nat_traversal_api.rs` - Remove hardcoded port 9000
- `src/socket.rs` - Add socket address discovery

### 5.2 Testing Requirements

#### Unit Tests:
```rust
#[tokio::test]
async fn test_os_assigned_port() {
    let config = NetworkConfig::default();
    let service = MessagingService::new_with_config(addr, dht, config).await?;

    let bound_addr = service.local_addr().expect("Should have address");
    assert_ne!(bound_addr.port(), 0, "Should have actual port assigned");
}

#[tokio::test]
async fn test_explicit_port() {
    let config = NetworkConfig {
        port: PortConfig::Explicit(12345),
        ..Default::default()
    };
    let service = MessagingService::new_with_config(addr, dht, config).await?;

    assert_eq!(service.local_addr().unwrap().port(), 12345);
}

#[tokio::test]
async fn test_multiple_instances() {
    let config1 = NetworkConfig::default();  // OS-assigned
    let config2 = NetworkConfig::default();  // OS-assigned

    let service1 = MessagingService::new_with_config(addr1, dht1, config1).await?;
    let service2 = MessagingService::new_with_config(addr2, dht2, config2).await?;

    // Both should succeed with different ports
    assert_ne!(
        service1.local_addr().unwrap().port(),
        service2.local_addr().unwrap().port()
    );
}

#[tokio::test]
async fn test_port_conflict_handling() {
    let port = 12345;
    let config1 = NetworkConfig {
        port: PortConfig::Explicit(port),
        ..Default::default()
    };

    let _service1 = MessagingService::new_with_config(addr1, dht1, config1.clone()).await?;

    // Second instance with same port should fail
    let result = MessagingService::new_with_config(addr2, dht2, config1).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_ipv4_only_mode() {
    let config = NetworkConfig {
        ip_mode: IpMode::IPv4Only,
        ..Default::default()
    };

    let service = MessagingService::new_with_config(addr, dht, config).await?;

    let addrs = service.local_addrs();
    assert!(addrs.iter().all(|a| a.is_ipv4()));
}
```

#### Integration Tests:
- Two instances on same machine with OS-assigned ports
- Port range selection with fallback
- Dual-stack mode verification
- Cross-instance connectivity

## 6. Usage Examples

### 6.1 Basic Usage (Default)
```rust
use saorsa_core::messaging::MessagingService;

// Uses OS-assigned port, IPv4-only
let service = MessagingService::new(address, dht_client).await?;

// Get actual bound address
let bound_addr = service.local_addr()
    .ok_or("No local address")?;

println!("Listening on: {}", bound_addr);

// Get four-word encoded address for sharing
let four_words = service.local_four_words()
    .ok_or("No four-word address")?;

println!("Connect to: {}", four_words);
```

### 6.2 Explicit Port
```rust
use saorsa_core::messaging::{MessagingService, NetworkConfig, PortConfig};

let config = NetworkConfig {
    port: PortConfig::Explicit(9000),
    ..Default::default()
};

let service = MessagingService::new_with_config(address, dht_client, config).await?;
```

### 6.3 Port Range with Fallback
```rust
let config = NetworkConfig {
    port: PortConfig::Range(9000, 9010),
    retry_behavior: RetryBehavior::TryNext,
    ..Default::default()
};

let service = MessagingService::new_with_config(address, dht_client, config).await?;
println!("Bound to port: {}", service.local_addr().unwrap().port());
```

### 6.4 Dual-Stack (Fixed)
```rust
let config = NetworkConfig {
    port: PortConfig::OsAssigned,
    ip_mode: IpMode::DualStackSeparate {
        ipv4_port: PortConfig::OsAssigned,
        ipv6_port: PortConfig::OsAssigned,
    },
    ..Default::default()
};

let service = MessagingService::new_with_config(address, dht_client, config).await?;

// Get all bound addresses (IPv4 and IPv6)
for addr in service.local_addrs() {
    println!("Listening on: {}", addr);
}
```

### 6.5 Multiple Instances (Testing)
```rust
use saorsa_core::messaging::MessagingService;

// Create multiple instances on same machine
let service1 = MessagingService::new(addr1, dht1).await?;
let service2 = MessagingService::new(addr2, dht2).await?;

// Connect them
let peer_addr = service2.local_four_words().unwrap();
service1.connect_to_peer(&peer_addr).await?;
```

## 7. Error Handling

### 7.1 New Error Types
```rust
#[derive(Debug, thiserror::Error)]
pub enum NetworkConfigError {
    #[error("Port {0} is already in use")]
    PortInUse(u16),

    #[error("Invalid port number: {0}")]
    InvalidPort(u16),

    #[error("No available port in range {0}-{1}")]
    NoPortInRange(u16, u16),

    #[error("Dual-stack not supported on this platform")]
    DualStackNotSupported,

    #[error("Failed to bind socket: {0}")]
    BindFailed(String),
}
```

### 7.2 Error Messages
Clear, actionable error messages:
- "Port 9000 is already in use. Try using PortConfig::OsAssigned to let the OS choose."
- "Cannot bind to port 80: Permission denied. Use port 1024 or higher."
- "IPv6 not available on this system. Use IpMode::IPv4Only."

## 8. Documentation Requirements

### 8.1 API Documentation
- All public types must have doc comments
- Include examples for common use cases
- Document default behavior clearly
- Add migration guide from old API

### 8.2 User Guide Updates
- Update getting-started examples
- Add section on network configuration
- Document multi-instance deployment
- Add troubleshooting guide

### 8.3 Example Updates
- Update all examples to use new API
- Show both simple and advanced configurations
- Include multi-instance example
- Add testing examples

## 9. Success Criteria

### 9.1 Functional
- ✅ Can run multiple instances on same machine
- ✅ OS-assigned ports work correctly
- ✅ Port discovery returns correct addresses
- ✅ Dual-stack conflicts resolved
- ✅ Backward compatibility maintained (v0.4.x)

### 9.2 Quality
- ✅ 100% unit test coverage on new code
- ✅ Integration tests pass with multiple instances
- ✅ No performance regression (>1% overhead)
- ✅ Zero clippy warnings
- ✅ Complete API documentation

### 9.3 User Experience
- ✅ Simple default works out-of-box
- ✅ Clear error messages for failures
- ✅ Easy migration path documented
- ✅ Examples cover common scenarios

## 10. Timeline

### Phase 1: Core Implementation (1-2 weeks)
- Implement NetworkConfig types
- Add new_with_config() method
- Implement port discovery
- Basic unit tests

### Phase 2: Ant-Quic Integration (1 week)
- Update ant-quic for configurable ports
- Fix dual-stack binding
- Integration testing

### Phase 3: Documentation & Examples (1 week)
- Update API documentation
- Create migration guide
- Update all examples
- Write user guide

### Phase 4: Testing & Stabilization (1 week)
- Comprehensive testing
- Performance validation
- Bug fixes
- Beta release

## 11. Open Questions

1. **Backward Compatibility**: Should v0.4.0 maintain exact backward compatibility, or can we change defaults with clear warnings?
   - **Recommendation**: Maintain compatibility in v0.4.x, change defaults in v0.5.0

2. **Dual-Stack Default**: Should dual-stack be the default when supported?
   - **Recommendation**: No, use IPv4-only by default to avoid platform-specific issues

3. **Port Range**: What's a reasonable default port range for automatic selection?
   - **Recommendation**: Don't use ranges by default, only OS-assigned or explicit

4. **Retry Logic**: Should port conflicts automatically retry with OS-assigned?
   - **Recommendation**: No by default, make it opt-in behavior

## 12. References

- Issue: `SAORSA_CORE_PORT_ISSUE.md`
- ant-quic: https://docs.rs/ant-quic/0.8.17
- four-word-networking: https://docs.rs/four-word-networking/2.6
- RFC 6335: Internet Assigned Numbers Authority (IANA) Procedures

## 13. Approval

This specification requires approval from:
- [ ] Saorsa-core maintainers
- [ ] Communitas-core team
- [ ] Security review
- [ ] API design review

---

**Questions or feedback?** Contact the Communitas development team.
