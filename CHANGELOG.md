# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
