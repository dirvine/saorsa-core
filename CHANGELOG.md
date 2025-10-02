# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.7] - 2025-10-02

### Fixed
- **Wildcard Address Normalization for Local Connections** 🌐
  - ant-quic correctly rejects wildcard addresses (`0.0.0.0`, `[::]`) as invalid remote addresses
  - Added `normalize_wildcard_to_loopback()` to convert wildcard bind addresses to loopback addresses
  - IPv6 `[::]:port` → `::1:port` (IPv6 loopback)
  - IPv4 `0.0.0.0:port` → `127.0.0.1:port` (IPv4 loopback)
  - Resolves "invalid remote address" errors when connecting to nodes bound to wildcard addresses

### Added
- **Address Normalization Infrastructure** 🛠️
  - `normalize_wildcard_to_loopback()` - Transparently converts wildcard to loopback addresses
  - Comprehensive unit tests for IPv4 and IPv6 address normalization
  - Logging of address normalization for debugging

### Changed
- **P2PNode Connection Logic** 📡
  - `connect_peer()` now normalizes addresses before passing to ant-quic
  - Supports both IPv4 and IPv6 loopback connections
  - Non-wildcard addresses pass through unchanged

### Technical Details
- Fixes confusion between BIND addresses (for listening) and CONNECT addresses (for connecting)
- Wildcard addresses (`0.0.0.0`, `[::]`) are only valid for binding, not connecting
- Maintains zero breaking changes - purely internal improvement
- All unit tests passing including new address normalization tests

### Implementation
- Modified `src/network.rs`: Added `normalize_wildcard_to_loopback()` function (lines 508-537)
- Modified `src/network.rs`: Integrated normalization in `connect_peer()` (lines 1352-1360)
- Added unit tests in `src/network.rs` (lines 3180-3221)

## [0.5.6] - 2025-10-02

### Fixed
- **Full Connection Lifecycle Tracking** 🔄
  - Replaced automatic reconnection with comprehensive connection lifecycle tracking
  - P2PNode now synchronizes with ant-quic connection events (ConnectionEstablished/ConnectionLost)
  - Added `active_connections` HashSet tracking actual connection state
  - Keepalive task prevents 30-second idle timeout with 15-second heartbeats
  - Resolves root cause of "send_to_peer failed on both stacks" errors

### Added
- **Connection Lifecycle Infrastructure** 🛠️
  - `P2PNode::is_connection_active()` - Validate connection state via active_connections
  - `P2PNode::keepalive_task()` - Background task sending heartbeats every 15 seconds
  - Connection event subscription to ant-quic lifecycle events
  - Proper shutdown coordination with AtomicBool flags

### Changed
- **Simplified Message Delivery** 📡
  - Removed reconnection logic from `MessageTransport::try_direct_delivery()`
  - `send_message()` now validates connection state before sending
  - Automatic cleanup of stale peer entries when connection inactive
  - Cleaner separation of concerns between transport and network layers

### Removed
- **Temporary Documentation** 📝
  - Removed `P2P_MESSAGING_STATUS_2025-10-02_FINAL.md`
  - Removed `SAORSA_CORE_PORT_SPECIFICATION.md`
  - Removed `SAORSA_CORE_PORT_STATUS.md`

### Technical Details
- Implements full connection lifecycle tracking (Option 1 from status doc)
- Keepalive prevents ant-quic's 30-second max_idle_timeout
- active_connections synchronized with ant-quic connection events
- Maintains zero breaking changes - purely internal reliability improvement
- All 669 unit tests passing with zero failures
- Integration tests prove infrastructure is in place

### Implementation
- Modified `src/network.rs`: Added lifecycle tracking, keepalive task, connection validation
- Modified `src/messaging/transport.rs`: Simplified to rely on P2PNode validation
- Added `tests/connection_lifecycle_proof_test.rs`: Proves fix is in place

## [0.5.5] - 2025-10-02

### Fixed
- **Connection State Synchronization** 🔄
  - Fixed critical issue where P2PNode peers map didn't track when ant-quic connections closed
  - Added automatic reconnection logic in `MessageTransport::try_direct_delivery()`
  - Connections now properly cleaned up when detected as closed
  - Resolves "send_to_peer failed on both stacks" errors

### Added
- **Connection Management Methods** 🛠️
  - `P2PNode::remove_peer()` - Remove stale peer entries from peers map
  - `P2PNode::is_peer_connected()` - Check if peer exists in peers map
  - `MessageTransport::is_connection_error()` - Detect connection closure errors
  - 3 comprehensive unit tests for new connection management functionality

### Changed
- **Enhanced Message Delivery** 📡
  - `try_direct_delivery()` now detects connection errors and automatically attempts reconnection
  - Stale peer entries removed from P2PNode when connection errors detected
  - Improved error logging to distinguish connection closures from other failures
  - Single retry attempt per address before moving to next endpoint

### Technical Details
- Addresses root cause identified in P2P_MESSAGING_STATUS_2025-10-02_FINAL.md
- Connection state gap between P2PNode layer and ant-quic connection layer now bridged
- Error patterns detected: "closed", "connection", "send_to_peer failed", "peer not found"
- Maintains zero breaking changes - purely internal reliability improvement
- All 669 unit tests passing with zero failures
- Zero clippy warnings

### Implementation
- Modified `src/network.rs`: Added `remove_peer()` and `is_peer_connected()` methods
- Modified `src/messaging/transport.rs`: Added reconnection logic to `try_direct_delivery()`
- Added comprehensive test coverage for connection management lifecycle

## [0.5.4] - 2025-10-02

### Removed
- **Documentation Cleanup** 📝
  - Removed temporary specification documents (SAORSA_MESSAGING_P2P_INTEGRATION_SPEC.md)
  - Removed temporary implementation notes (KEY_EXCHANGE_IMPLEMENTATION.md)
  - Cleaned up project root documentation

## [0.5.3] - 2025-10-02

### Added
- **Connection Reuse for P2P Messaging** 🔄
  - Added `P2PNode::get_peer_id_by_address()` method for connection lookup
  - Added `P2PNode::list_active_connections()` method for connection enumeration
  - 6 comprehensive unit tests for connection lookup functionality

### Changed
- **Optimized MessageTransport Delivery** 📡
  - Refactored `MessageTransport::try_direct_delivery()` to check for existing P2P connections before creating new ones
  - Eliminated redundant connection establishment when peer is already connected
  - Simplified delivery logic by removing duplicate code paths
  - Improved logging to distinguish between "reusing existing connection" vs "establishing new connection"
  - Removed unused `ConnectionPool::get_connection()` method (dead code cleanup)

### Performance
- Reduced connection overhead by reusing active P2P connections
- Eliminated unnecessary Happy Eyeballs dual-stack connection attempts for already-connected peers
- Faster message delivery for repeated communications with the same peer

### Technical Details
- Zero breaking changes - purely internal optimization
- MessageTransport already used shared `Arc<P2PNode>` - no architectural changes needed
- Connection lookup uses socket address comparison for accurate matching
- All 666 unit tests passing with zero failures

### Implementation
- Modified `src/network.rs`: Added connection lookup methods to P2PNode
- Modified `src/messaging/transport.rs`: Updated try_direct_delivery() to check existing connections
- Added comprehensive test coverage for new functionality

## [0.5.2] - 2025-10-02

### Added
- **Public API Export** 🔓
  - Exported `PeerInfo` type from public API
  - Exported `ConnectionStatus` enum (dependency of PeerInfo)
  - Makes `P2PNode::peer_info()` method actually usable by library consumers

### Changed
- Updated public exports in `src/lib.rs` to include network peer types
- Enhanced API usability for network monitoring and debugging

### Technical Details
- Zero breaking changes - purely additive API enhancement
- Enables users to inspect peer connection state, addresses, and protocols
- `PeerInfo` contains: peer_id, addresses, connection timestamps, status, protocols, heartbeat_count
- `ConnectionStatus` enum: Connecting, Connected, Disconnecting, Disconnected, Failed(String)

## [0.5.1] - 2025-10-02

### Fixed
- **PQC Key Exchange Now Functional** 🔐
  - Fixed critical bug where `KeyExchange.initiate_exchange()` created but never transmitted messages
  - Added dedicated `"key_exchange"` P2P protocol topic
  - Implemented `send_key_exchange_message()` in MessageTransport
  - Added bidirectional key exchange response handling
  - Integrated automatic session establishment with 5-second timeout
  - Added session key polling with exponential backoff

### Added
- `MessageTransport::send_key_exchange_message()` - Send key exchange over P2P network
- `MessageTransport::subscribe_key_exchange()` - Subscribe to incoming key exchange messages
- `MessagingService::wait_for_session_key()` - Wait for session establishment with timeout
- Automatic key exchange responder in `subscribe_messages()` task
- Comprehensive integration tests in `tests/key_exchange_integration_test.rs`
- Detailed implementation documentation in `KEY_EXCHANGE_IMPLEMENTATION.md`

### Changed
- Enhanced `MessagingService::send_message()` to automatically initiate key exchange
- Updated message receiving loop to handle both encrypted messages and key exchange protocol
- Improved error messages for key exchange failures (timeout, no peer key, etc.)

### Technical Details
- ML-KEM-768 encapsulation/decapsulation over P2P QUIC transport
- HKDF-SHA256 session key derivation
- ChaCha20-Poly1305 symmetric encryption with established keys
- 24-hour session key TTL with automatic caching

### Documentation
- Complete message flow diagrams
- Security considerations and future enhancements
- Performance characteristics and overhead analysis

## [0.5.0] - 2025-10-01

### Added
- **P2P NAT Traversal Support** 🎉
  - Added `NatTraversalMode` enum with `ClientOnly` and `P2PNode` variants
  - Integrated ant-quic 0.10.0's NAT traversal capabilities
  - `P2PNetworkNode::from_network_config()` for NAT-aware network creation
  - Full P2P messaging support between MessagingService instances
  - NAT configuration logging in MessagingService
  - Comprehensive P2P integration tests (6 new tests)

### Changed
- **Breaking Change**: Updated to ant-quic 0.10.0
  - New endpoint role system (Client, Server, Bootstrap)
  - Improved NAT traversal with symmetric ServerSupport
  - Bootstrap role for P2P nodes without external infrastructure
- Added `nat_traversal: Option<NatTraversalMode>` field to `NetworkConfig`
- Default NetworkConfig now includes P2P NAT traversal (concurrency limit: 10)
- Updated `P2PNetworkNode` to use `EndpointRole::Bootstrap` for compatibility

### Dependencies
- Updated `ant-quic` from 0.9.0 to 0.10.0

### Documentation
- Updated CHANGELOG with v0.5.0 release notes
- Added NAT traversal configuration examples
- Documented endpoint role behavior

### Testing
- All 666 unit tests passing
- 6 new P2P NAT integration tests passing
- Zero compilation errors, zero warnings

## [0.4.0] - 2025-10-01

### Added
- **Port Configuration Support** 🎉
  - `MessagingService::new_with_config()` for custom port configuration
  - OS-assigned port support (port 0) enabling multiple instances on same machine
  - Explicit port configuration via `PortConfig::Explicit(port)`
  - Port range support via `PortConfig::Range(start, end)` (uses start of range)
  - Full IPv4/IPv6 support with `IpMode` enum (IPv4Only, IPv6Only, DualStack, DualStackSeparate)
  - Comprehensive integration tests for port configuration scenarios

### Changed
- **Breaking Change**: `MessagingService::new()` now uses OS-assigned ports by default (was hardcoded)
  - Old behavior: Always attempted to bind to a fixed port
  - New behavior: Uses port 0 (OS-assigned) by default for maximum compatibility
  - Migration: Existing code continues to work, but will get different ports
  - To use explicit port: Use `new_with_config()` with `PortConfig::Explicit(port)`
- Updated to ant-quic 0.9.0 with post-quantum cryptography enhancements
- Refactored `MessagingService::new()` to delegate to `new_with_config()` with default NetworkConfig

### Dependencies
- Updated `ant-quic` from 0.8.17 to 0.9.0

### Documentation
- Added comprehensive port configuration guide in SAORSA_CORE_PORT_STATUS.md
- Updated SAORSA_CORE_PORT_SPECIFICATION.md with implementation details
- Added usage examples for all port configuration modes

### Testing
- All 677 unit tests passing
- Added 2 integration tests for port configuration
- Zero compilation errors, zero warnings

## [0.3.28] - 2025-09-30

### Added
- NetworkConfig types for future port configuration (NetworkConfig, PortConfig, IpMode, RetryBehavior)
- Port discovery methods: `listen_addrs()`, `peer_count()`, `connected_peers()`, `is_running()`
- P2P networking methods: `connect_peer()`, `disconnect_peer()`

### Documentation
- Initial port configuration specification
- Port configuration issue tracking document

## [0.3.24] - Previous Release

### Fixed
- Network connectivity issues with listen_addrs() method
- Documentation inconsistencies
- Strong typing improvements

[0.4.0]: https://github.com/dirvine/saorsa-core-foundation/compare/v0.3.28...v0.4.0
[0.3.28]: https://github.com/dirvine/saorsa-core-foundation/compare/v0.3.24...v0.3.28
[0.3.24]: https://github.com/dirvine/saorsa-core-foundation/releases/tag/v0.3.24
