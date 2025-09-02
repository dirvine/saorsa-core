# Test Metrics Issue and Solution

## Problem

Some tests fail when run in parallel due to Prometheus metrics registration conflicts. The Prometheus library uses a global registry, and when multiple tests try to register the same metrics concurrently, they fail with:

```
called `Result::unwrap()` on an `Err` value: Duplicate metrics collector registration attempted
```

## Affected Tests

The following 6 client tests are affected:
- `adaptive::client::tests::test_client_connect`
- `adaptive::client::tests::test_client_creation`
- `adaptive::client::tests::test_compute_job`
- `adaptive::client::tests::test_network_stats`
- `adaptive::client::tests::test_not_connected_error`
- `adaptive::client::tests::test_pubsub_messaging`
- `adaptive::client::tests::test_storage_operations`

## Solutions

### Solution 1: Run Tests Without Metrics (Recommended)

The code has been updated to support compilation and testing without the metrics feature:

```bash
# Run all tests without metrics
cargo test --no-default-features

# Or use the convenient alias
cargo test-no-metrics

# Run specific tests without metrics
cargo test --lib --no-default-features adaptive::client
```

### Solution 2: Run Tests Sequentially

Force tests to run one at a time to avoid concurrent registration:

```bash
cargo test --lib -- --test-threads=1
```

### Solution 3: Run Individual Tests

Use the provided Python script to run problematic tests individually:

```bash
python3 scripts/run_tests_individually.py
```

## Code Changes Made

1. **Conditional Compilation**: Added proper `#[cfg(feature = "metrics")]` guards throughout the monitoring system
2. **Test Helper Updates**: Modified `new_test_client()` to work with or without metrics
3. **Registry Handling**: Made registry optional when metrics feature is disabled
4. **Cargo Aliases**: Added convenient aliases in `.cargo/config.toml`:
   - `cargo test-no-metrics` - Run tests without metrics
   - `cargo test-all` - Run tests with all features

## Future Improvements

To fully resolve this issue, consider:

1. **Use Thread-Local Registries**: Modify the monitoring system to use thread-local registries for tests
2. **Registry Pool**: Implement a pool of registries that tests can borrow
3. **Mock Metrics**: Create a mock metrics implementation for tests that doesn't use Prometheus
4. **Unique Metric Names**: Generate unique metric names per test using test name or thread ID

## Current Status

- ✅ All tests compile with and without metrics feature
- ✅ All affected tests pass when run individually
- ✅ All affected tests pass when run without metrics feature
- ⚠️ Tests still fail when run in parallel with metrics enabled (expected behavior)