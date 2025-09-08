# Agent Guidelines for Saorsa Core

## New Multi-Device API (v0.3.16+)

### Core API Functions
```rust
// Identity Registration (one-time per user)
use saorsa_core::{register_identity, MlDsaKeyPair};

let words = ["welfare", "absurd", "king", "ridge"];  // Valid four-word address
let keypair = MlDsaKeyPair::generate()?;
let handle = register_identity(words, &keypair).await?;

// Device Registration (multi-device presence)
use saorsa_core::{register_presence, Device, DeviceType, DeviceId, Endpoint};

let devices = vec![
    Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,      // User's active machine
        storage_gb: 100,
        endpoint: Endpoint { 
            protocol: "quic".to_string(),
            address: "192.168.1.100:9000".to_string(),
        },
        capabilities: Default::default(),
    },
    Device {
        id: DeviceId::generate(), 
        device_type: DeviceType::Headless,    // Storage-only node
        storage_gb: 1000,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "10.0.0.1:9001".to_string(),
        },
        capabilities: Default::default(),
    }
];

let active_device_id = devices[0].id;
let receipt = register_presence(&handle, devices, active_device_id).await?;

// Data Storage with Automatic Strategy Selection
use saorsa_core::{store_data, store_dyad, store_with_fec, get_data};

// Single user (Direct storage)
let data = b"My private data".to_vec();
let storage_handle = store_data(&handle, data, 1).await?;

// Two users (Full replication) 
let storage_handle = store_dyad(&handle1, handle2.key(), data).await?;

// Group storage (FEC encoding)
let storage_handle = store_data(&handle, data, 8).await?;  // 8-person group

// Custom FEC parameters
let storage_handle = store_with_fec(&handle, data, 8, 4).await?;  // 8 data, 4 parity

// Retrieve data
let retrieved = get_data(&storage_handle).await?;
```

### Storage Strategy Selection
- **1 user**: Direct storage on user's devices
- **2 users**: Full replication across both users' devices  
- **3-5 users**: FEC with (3,2) encoding
- **6-10 users**: FEC with (4,3) encoding
- **11-20 users**: FEC with (6,4) encoding
- **20+ users**: FEC with (8,5) encoding

## Build/Test Commands
- **Build**: `cargo build --all-features` (release: `cargo build --release`)
- **Test All**: `cargo test --all-features` (doc tests: `cargo test --doc`)
- **Single Test**: `cargo test test_function_name` or `cargo test --test integration_test_name`
- **Lint**: `cargo clippy --all-features -- -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used`
- **Format**: `cargo fmt --all -- --check` (apply: `cargo fmt --all`)
- **Local CI**: `./scripts/local_ci.sh` (runs fmt, clippy, build, tests safely)

## Code Style Guidelines

### Error Handling (ZERO PANICS in production)
- **NEVER use**: `.unwrap()`, `.expect()`, `panic!()` in library/production code
- **Use instead**: `?` operator, `.ok_or()`, `.context()` from `anyhow`
- **Tests OK**: `.unwrap()`/`.expect()` allowed in `#[cfg(test)]` blocks
- **Error types**: `P2PError` enum with structured variants, `thiserror` for derives

### Imports & Dependencies
- **Core async**: `tokio`, `futures`, `async-trait`
- **Serialization**: `serde` with derive features
- **Error handling**: `anyhow`, `thiserror`
- **Logging**: `tracing` (never `println!` in production)
- **Crypto**: `saorsa-pqc` (primary), `ant-quic` (QUIC transport)

### Naming Conventions
- **Modules**: `snake_case` (e.g., `dht`, `transport`, `adaptive`)
- **Types/Traits**: `PascalCase` (e.g., `P2PNode`, `AdaptiveNetworkNode`)
- **Functions**: `snake_case` (e.g., `connect_to_peer`, `store_data`)
- **Constants**: `SCREAMING_SNAKE_CASE`
- **Fields**: `snake_case` (e.g., `content_hash`, `node_id`)

### Formatting & Structure
- **Rust 2024 edition** with `rustfmt` (4 spaces, standard rules)
- **Clippy config**: `.clippy.toml` allows unwrap/expect in tests
- **Documentation**: All public items must be documented
- **Copyright**: Include AGPL-3.0 header on all files

### Architecture Patterns
- **Async traits**: Use `#[async_trait]` for async trait methods
- **Result types**: `Result<T, P2PError>` or `Result<T>` with custom error types
- **Zero-copy**: Use `Cow<'static, str>` for error messages
- **Structured logging**: JSON-based error reporting with `tracing`

### Security & Performance
- **Post-quantum crypto**: Use `saorsa-pqc` types exclusively
- **Memory safety**: Zeroize sensitive data, secure memory pools
- **No secrets in code**: Never commit keys or credentials
- **Performance**: O(n log n) or better, minimize allocations

## Cursor Rules Integration
- **No unwrap/expect/panic** in production (CI enforces)
- **Proper error context** with `.context()` or `?` operator
- **Tracing logging** instead of `println!`
- **Zero-panic guarantee** for library code