# Trust Signals API Reference

## Overview

saorsa-core provides an EigenTrust-based reputation system for tracking node reliability.
Consumers (like saorsa-node) **MUST** report data operation outcomes to maintain accurate
trust scores across the network.

The trust system enables:
- **Sybil resistance**: Malicious nodes are downscored automatically
- **Quality routing**: High-trust nodes are preferred for data operations
- **Self-healing**: The network learns from failures and adapts

## Feature Requirement

The trust API requires the `adaptive-ml` feature to be enabled:

```toml
[dependencies]
saorsa-core = { version = "0.11.0", features = ["adaptive-ml"] }
```

## Quick Start

```rust
use saorsa_core::P2PNode;

// After successful data retrieval from a peer:
node.report_peer_success(&peer_id).await?;

// After failed data retrieval:
node.report_peer_failure(&peer_id).await?;

// Check peer trust before operations:
let trust = node.peer_trust(&peer_id);
if trust < 0.3 {
    tracing::warn!("Low trust peer: {peer_id}");
}
```

## P2PNode Trust Methods

### `report_peer_success(peer_id)`

Report a successful interaction with a peer. Call this after:
- Successful chunk retrieval
- Successful chunk storage verification
- Valid response to any request

```rust
pub async fn report_peer_success(&self, peer_id: &str) -> Result<()>
```

**Parameters:**
- `peer_id`: The peer ID string of the node that performed well

**Returns:** `Result<()>` - Always succeeds (trust updates are best-effort)

**Example:**
```rust
match fetch_chunk_from(&peer_id, &chunk_address).await {
    Ok(chunk) if chunk.verify() => {
        node.report_peer_success(&peer_id).await?;
        Ok(chunk)
    }
    Ok(_) => {
        // Corrupted data
        node.report_peer_failure(&peer_id).await?;
        Err(DataError::CorruptedData)
    }
    Err(e) => {
        node.report_peer_failure(&peer_id).await?;
        Err(e)
    }
}
```

### `report_peer_failure(peer_id)`

Report a failed interaction with a peer. Call this after:
- Request timeout
- Connection refused
- Invalid/corrupted data received
- Storage verification failure

```rust
pub async fn report_peer_failure(&self, peer_id: &str) -> Result<()>
```

**Parameters:**
- `peer_id`: The peer ID string of the node that failed

**Returns:** `Result<()>` - Always succeeds (trust updates are best-effort)

**Example:**
```rust
match tokio::time::timeout(
    Duration::from_secs(30),
    send_request(&peer_id, request)
).await {
    Ok(Ok(response)) => {
        node.report_peer_success(&peer_id).await?;
        Ok(response)
    }
    Ok(Err(_)) | Err(_) => {
        // Request failed or timed out
        node.report_peer_failure(&peer_id).await?;
        Err(NetworkError::RequestFailed)
    }
}
```

### `peer_trust(peer_id)`

Get the current trust score for a peer.

```rust
pub fn peer_trust(&self, peer_id: &str) -> f64
```

**Parameters:**
- `peer_id`: The peer ID string to query

**Returns:** Trust score between 0.0 (untrusted) and 1.0 (fully trusted)
- Unknown peers return 0.0
- If trust engine is not initialized, returns 0.5 (neutral)

**Example:**
```rust
// Sort providers by trust before fetching
let mut providers: Vec<_> = find_providers(&chunk_address).await?;
providers.sort_by(|a, b| {
    node.peer_trust(b)
        .partial_cmp(&node.peer_trust(a))
        .unwrap_or(std::cmp::Ordering::Equal)
});

// Skip very low trust peers
for provider in providers {
    if node.peer_trust(&provider) < 0.1 {
        tracing::debug!("Skipping low-trust provider: {provider}");
        continue;
    }
    // Try this provider...
}
```

### `trust_engine()`

Get direct access to the EigenTrust engine for advanced operations.

```rust
pub fn trust_engine(&self) -> Option<Arc<EigenTrustEngine>>
```

**Returns:** `Option<Arc<EigenTrustEngine>>` - The underlying trust engine

**Example:**
```rust
use saorsa_core::NodeStatisticsUpdate;

if let Some(engine) = node.trust_engine() {
    // Report bandwidth contribution
    engine
        .update_node_stats(&node_id, NodeStatisticsUpdate::BandwidthContributed(bytes))
        .await;

    // Get global trust scores
    let all_scores = engine.compute_global_trust().await;

    // Check specific node statistics
    let trust = engine.get_trust_async(&node_id).await;
}
```

## Direct EigenTrust Engine API

For advanced use cases, you can work directly with the `EigenTrustEngine`:

### `update_node_stats(node_id, update)`

Update statistics for a specific node.

```rust
pub async fn update_node_stats(&self, node_id: &NodeId, stats_update: NodeStatisticsUpdate)
```

**Parameters:**
- `node_id`: The NodeId of the peer
- `stats_update`: The type of update (see below)

### `NodeStatisticsUpdate` Enum

```rust
pub enum NodeStatisticsUpdate {
    /// Node has been online for the specified seconds
    Uptime(u64),

    /// Node responded correctly to a request
    CorrectResponse,

    /// Node failed to respond or returned invalid data
    FailedResponse,

    /// Node contributed storage capacity (bytes)
    StorageContributed(u64),

    /// Node contributed bandwidth (bytes transferred)
    BandwidthContributed(u64),

    /// Node contributed compute resources
    ComputeContributed(u64),
}
```

### `update_local_trust(from, to, success)`

Record a direct interaction between two nodes.

```rust
pub async fn update_local_trust(&self, from: &NodeId, to: &NodeId, success: bool)
```

### `compute_global_trust()`

Manually trigger global trust computation. Usually not needed as background task handles this.

```rust
pub async fn compute_global_trust(&self) -> HashMap<NodeId, f64>
```

### `get_trust(node_id)` / `get_trust_async(node_id)`

Get trust score for a node. The synchronous version uses cached values.

```rust
// Synchronous (uses cache)
pub fn get_trust(&self, node_id: &NodeId) -> f64

// Async (reads from cache)
pub async fn get_trust_async(&self, node_id: &NodeId) -> f64
```

## When to Report Trust Signals

| Event | Method | Rationale |
|-------|--------|-----------|
| Chunk retrieved successfully | `report_peer_success` | Node served data correctly |
| Chunk hash mismatch | `report_peer_failure` | Node served corrupted data |
| Request timeout | `report_peer_failure` | Node unresponsive |
| Connection refused | `report_peer_failure` | Node not serving |
| Storage verified | `report_peer_success` | Node maintains data |
| Storage missing | `report_peer_failure` | Node lost data |
| Large transfer complete | `BandwidthContributed(bytes)` | Track bandwidth contribution |
| Storage quota used | `StorageContributed(bytes)` | Track storage contribution |

## Trust Score Impact

The EigenTrust algorithm uses these signals to compute global trust:

- **CorrectResponse**: Increases local trust by ~0.1 (EMA smoothing)
- **FailedResponse**: Decreases local trust by ~0.1 (EMA smoothing)
- **Time decay**: Trust decays by 0.99 per epoch if no interactions
- **Global computation**: PageRank-style iteration every 5 minutes
- **Pre-trusted nodes**: Bootstrap nodes start with 0.9 trust

Nodes start with trust 0.0 unless pre-trusted in config.

## Error Handling

Trust updates are **best-effort** - errors should be logged but not propagated:

```rust
// Recommended error handling pattern
if let Err(e) = node.report_peer_success(&peer_id).await {
    tracing::warn!("Failed to update trust for {peer_id}: {e}");
}

// Or simply ignore (these methods never fail in practice)
let _ = node.report_peer_success(&peer_id).await;
```

## Configuration

The EigenTrust engine is automatically configured with sensible defaults:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `update_interval` | 5 minutes | How often to recompute global trust |
| `alpha` | 0.4 | Teleportation parameter for Sybil resistance |
| `decay_rate` | 0.99 | Trust decay per epoch |
| `max_iterations` | 50 | Maximum PageRank iterations |
| `epsilon` | 0.0001 | Convergence threshold |

Pre-trusted nodes are automatically derived from the bootstrap peers in `NodeConfig`.

## Thread Safety

All trust methods are thread-safe and can be called concurrently:
- `report_peer_success` / `report_peer_failure` - async, uses internal locking
- `peer_trust` - synchronous, reads from cache
- `trust_engine` - returns `Arc<EigenTrustEngine>`

## Related Documentation

- [Integration Example: saorsa-node](examples/saorsa-node-trust-integration.md) - Complete integration guide
- [ADR-006: EigenTrust Reputation](adr/ADR-006-eigentrust-reputation.md) - Architecture decision record
- [SECURITY_MODEL.md](SECURITY_MODEL.md) - Overall security architecture
