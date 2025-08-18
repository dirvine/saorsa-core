# Saorsa Core - Code Standards and Conventions

## CRITICAL: Zero Panic Policy
**ZERO TOLERANCE** for panics in production code:

### BANNED in Production Code
- `.unwrap()` - Use `?` operator or `.ok_or()` instead
- `.expect()` - Use `.context()` from `anyhow` instead  
- `panic!()` - Return `Result` instead
- `unimplemented!()` or `todo!()` - Complete all implementations
- `println!()` - Use `tracing` for logging

### EXCEPTION
Test code (`#[cfg(test)]`) may use `.unwrap()` and `.expect()` for assertions.

## Error Handling Pattern
```rust
// ✅ CORRECT
let value = some_option.ok_or(P2PError::MissingValue)?;
let result = some_result.context("operation failed")?;

// ❌ WRONG - Will fail CI/CD
let value = some_option.unwrap();
let result = some_result.expect("failed");
```

## Code Style
- **Rust 2024 Edition**
- **Clippy configuration** in `.clippy.toml`:
  - Allow unwrap/expect/panic only in tests
  - Cognitive complexity threshold: 30
  - Too many arguments threshold: 10
  - Type complexity threshold: 250

## Naming Conventions
- **Modules**: snake_case (e.g., `quantum_crypto`, `dht_network`)
- **Structs/Enums**: PascalCase (e.g., `NetworkConfig`, `PqcMode`)
- **Functions/Variables**: snake_case (e.g., `generate_keypair`, `public_key`)
- **Constants**: SCREAMING_SNAKE_CASE (e.g., `VERSION`, `DEFAULT_PORT`)

## Documentation
- All public APIs must have doc comments
- Include examples in doc comments
- Use `///` for public items
- Use `//!` for module-level documentation

## Async/Concurrency
- Use Tokio 1.35 as async runtime
- Prefer async/await over manual futures
- Use channels for inter-task communication
- Avoid blocking operations in async contexts

## Testing
- Unit tests in-module with `#[cfg(test)]`
- Integration tests in `tests/` directory
- Property-based testing with `proptest`
- Some tests disabled with `.disabled` extension due to API compatibility

## Security
- Never expose secrets or credentials
- Use secure random number generation
- Validate all inputs
- Sanitize user data
- Follow OWASP guidelines

## Features/Dependencies
- Default features: `["metrics"]`
- Optional Prometheus integration
- All PQC features enabled by default (not feature-gated)
- Prefer ant-quic over other QUIC implementations