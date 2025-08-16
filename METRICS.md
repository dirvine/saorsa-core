# Metrics Configuration

This document describes how metrics are configured in saorsa-core and its dependencies.

## Current Configuration

### Saorsa-Core Metrics

The `metrics` feature is enabled by default and provides:
- Prometheus metrics collection
- Performance monitoring for adaptive algorithms
- Network statistics tracking
- DHT operation metrics

### Ant-QUIC Metrics Integration

Ant-quic v0.8.0 supports prometheus metrics via the `prometheus` feature flag, which is automatically enabled when saorsa-core's metrics feature is active.

**Current Configuration (Cargo.toml):**
```toml
[features]
default = ["metrics"]
metrics = ["dep:prometheus", "ant-quic/prometheus"]
```

## Available Metrics

When the metrics feature is enabled, the following metrics are available:

### DHT Metrics
- `dht_operations_total` - Total DHT operations performed
- `dht_latency_seconds` - DHT operation latency distribution
- `dht_peer_count` - Number of connected DHT peers
- `dht_storage_size_bytes` - Amount of data stored in DHT

### Adaptive Algorithm Metrics
- `adaptive_strategy_selections_total` - Strategy selection counts
- `multi_armed_bandit_rewards` - Bandit algorithm reward distribution
- `q_learning_cache_hits_total` - Q-learning cache performance
- `routing_decision_latency_seconds` - Time to make routing decisions

### Network Metrics
- `network_connections_active` - Currently active connections
- `network_messages_sent_total` - Total messages sent
- `network_messages_received_total` - Total messages received
- `network_bandwidth_bytes_total` - Network bandwidth usage

### Performance Metrics
- `placement_algorithm_duration_seconds` - Time for placement decisions
- `trust_calculation_duration_seconds` - EigenTrust computation time
- `consensus_rounds_total` - Byzantine consensus rounds

## Accessing Metrics

### Prometheus Endpoint

When metrics are enabled, they are available at:
```
http://localhost:9090/metrics
```

### Programmatic Access

```rust
use saorsa_core::metrics::MetricsCollector;

let collector = MetricsCollector::new();
let metrics = collector.gather().await?;
```

## Configuration

### Enabling Metrics

```toml
# Enable metrics (default)
saorsa-core = { version = "0.3", features = ["metrics"] }

# Disable metrics
saorsa-core = { version = "0.3", default-features = false }
```

### Environment Variables

- `SAORSA_METRICS_ENABLED` - Override feature flag at runtime
- `SAORSA_METRICS_PORT` - Custom metrics endpoint port (default: 9090)
- `SAORSA_METRICS_HOST` - Custom metrics endpoint host (default: localhost)

### Custom Metrics

```rust
use saorsa_core::metrics::register_custom_metric;

// Register a custom counter
let custom_counter = register_custom_metric(
    "my_custom_operations_total",
    "Total custom operations performed"
)?;

// Increment the counter
custom_counter.inc();
```

## Ant-QUIC Metrics

With ant-quic v0.8.0, the following QUIC-level metrics are now available:

- QUIC connection metrics
- Transport-layer performance data
- NAT traversal success rates
- Packet loss and retransmission statistics
- Connection establishment times
- Bandwidth utilization

These metrics are automatically enabled when saorsa-core is compiled with the `metrics` feature.

## Troubleshooting

### Metrics Not Available

1. Verify metrics feature is enabled: `cargo check --features metrics`
2. Check that Prometheus endpoint is accessible
3. Ensure no firewall is blocking the metrics port

### Performance Impact

- Metrics collection has minimal performance overhead (<1%)
- Consider disabling in production if every microsecond matters
- Metrics are collected asynchronously to avoid blocking operations

### Missing Ant-QUIC Metrics

Ant-QUIC metrics are now supported in v0.8.0. If metrics are missing:
1. Verify ant-quic v0.8.0 is being used: `cargo tree | grep ant-quic`
2. Ensure metrics feature is enabled: `cargo check --features metrics`
3. Check that prometheus feature is active in ant-quic