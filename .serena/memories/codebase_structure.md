# Saorsa Core - Codebase Structure

## Root Directory
```
/
├── src/                    # Source code
├── tests/                  # Integration tests (38 files)
├── benches/               # Benchmarks
├── examples/              # Usage examples
├── scripts/               # Build/test scripts
├── docs/                  # Documentation
├── fuzz/                  # Fuzz testing
├── Cargo.toml            # Package configuration
├── README.md             # Project documentation
├── CLAUDE.md             # Development guidelines
└── .clippy.toml          # Linting configuration
```

## Source Code Structure (`src/`)

### Core Modules
- `lib.rs` - Main library entry point with exports
- `error.rs` - Error types and handling
- `config.rs` - Configuration management
- `utils.rs` - Utility functions

### Networking & Transport
- `transport/` - QUIC transport layer (ant-quic integration)
- `network.rs` - Network abstraction layer
- `address.rs` - Four-word addressing system
- `dht/` - Distributed Hash Table implementation
- `dht_network_manager.rs` - DHT network coordination

### Security & Identity
- `quantum_crypto/` - Post-quantum cryptography (ML-DSA, ML-KEM)
- `identity/` - Ed25519 identity management
- `identity_manager/` - Identity coordination
- `security.rs` - Security utilities
- `threshold/` - Threshold cryptography
- `crypto_verify.rs` - Cryptographic verification
- `encrypted_key_storage.rs` - Secure key storage
- `secure_memory.rs` - Memory protection

### Data & Storage
- `storage/` - Database persistence (SQLx/SQLite)
- `persistent_state.rs` - State persistence
- `placement/` - Intelligent shard placement

### Adaptive Features
- `adaptive/` - ML-driven networking (Thompson Sampling, Q-Learning)
- `geographic_enhanced_network.rs` - Location-aware routing

### Applications
- `chat/` - Messaging functionality
- `messaging/` - Message handling
- `discuss/` - Forum system
- `projects/` - Project management
- `mcp/` - Model Context Protocol integration

### System Components
- `bootstrap/` - Network bootstrapping
- `health/` - Health monitoring
- `validation.rs` - Input validation
- `production.rs` - Production utilities
- `peer_record.rs` - Peer information
- `monotonic_counter.rs` - Counter utilities
- `key_derivation.rs` - Key derivation functions

## Test Structure (`tests/`)
- Integration tests organized by feature
- Some tests disabled (`.disabled` extension) due to API compatibility
- Property-based tests with `proptest`
- Adaptive network test suite
- Security and performance tests

## Key Files to Note
- Many `.backup` and `.bak*` files indicate active development
- `CLAUDE.md` contains critical development guidelines
- `.clippy.toml` enforces strict code quality
- Test script: `scripts/test_adaptive_network.sh`