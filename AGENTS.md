# Agent Guidelines for Saorsa Core

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