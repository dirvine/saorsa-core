# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
