# Saorsa Core - Essential Commands

## Build Commands
```bash
# Debug build
cargo build

# Release build  
cargo build --release

# Build with all features
cargo build --all-features
```

## Testing Commands
```bash
# Run all tests (MUST PASS before committing)
cargo test

# Run unit tests only
cargo test --lib

# Run specific integration test
cargo test --test '<test_name>'

# Run specific test function
cargo test test_function_name

# Show println! output
cargo test -- --nocapture

# Run tests with debug logging
RUST_LOG=debug cargo test

# Run adaptive network test suite
./scripts/test_adaptive_network.sh

# Individual adaptive component tests
cargo test --test adaptive_components_test test_thompson_sampling_basic --release
cargo test --test adaptive_components_test test_multi_armed_bandit_basic --release
cargo test --test adaptive_components_test test_q_learning_cache_basic --release
```

## Code Quality Commands (MUST PASS before committing)
```bash
# Format code
cargo fmt

# Strict linting (zero tolerance for unwrap/expect in production)
cargo clippy -- -D warnings -D clippy::unwrap_used -D clippy::expect_used

# Security vulnerability check
cargo audit
```

## Documentation
```bash
# Build and open documentation
cargo doc --open
```

## Benchmarking
```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench --bench dht_benchmark
```

## Publishing
```bash
# Publish to crates.io (after version bump in Cargo.toml)
cargo publish
```

## System Commands (Darwin/macOS)
```bash
# List files
ls -la

# Change directory
cd <path>

# Search for patterns in files
grep -r "pattern" src/

# Find files
find . -name "*.rs" -type f

# Git operations
git status
git add .
git commit -m "message"
git push
```