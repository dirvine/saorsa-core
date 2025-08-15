# Adaptive Network Module API Analysis

## Summary

I have analyzed the actual implementations in the `src/adaptive/` directory and identified significant differences between what the test files were attempting to use versus the real API methods that exist. This document provides a comprehensive mapping of the actual APIs.

## Key Findings

### 1. **ThompsonSampling** (`src/adaptive/learning.rs`)

**Actual Constructor:**
```rust
ThompsonSampling::new() -> Self
```

**Actual Methods:**
```rust
// Strategy selection for different content types
select_strategy(&self, content_type: ContentType) -> Result<StrategyChoice>

// Update with outcome feedback 
update(&self, content_type: ContentType, strategy: StrategyChoice, success: bool, latency_ms: u64) -> Result<()>

// Get routing metrics
get_metrics(&self) -> RoutingMetrics

// Get confidence interval for strategy performance
get_confidence_interval(&self, content_type: ContentType, strategy: StrategyChoice) -> (f64, f64)
```

**What tests were incorrectly trying to use:**
- `new(10)` - doesn't take parameters
- `select_arm()` - doesn't exist, use `select_strategy()`
- `update(arm, success)` - wrong signature
- `get_top_k_arms(3)` - doesn't exist

### 2. **MultiArmedBandit** (`src/adaptive/multi_armed_bandit.rs`)

**Actual Constructor:**
```rust
MultiArmedBandit::new(config: MABConfig) -> Result<Self>
```

**Actual Methods:**
```rust
// Route selection with strategy choices
select_route(&self, destination: &NodeId, content_type: ContentType, available_strategies: &[StrategyChoice]) -> Result<RouteDecision>

// Update route performance
update_route(&self, route_id: &RouteId, content_type: ContentType, outcome: &Outcome) -> Result<()>

// Get performance metrics
get_metrics(&self) -> MABMetrics

// Get detailed statistics
get_all_statistics(&self) -> HashMap<(RouteId, ContentType), RouteStatistics>

// Persist state to disk
persist(&self) -> Result<()>
```

**What tests were incorrectly trying to use:**
- `new(10, 0.1)` - takes `MABConfig` struct
- `select_arm()` - doesn't exist, use `select_route()`
- `update(arm, reward)` - wrong signature, use `update_route()`
- `get_best_arm()` - doesn't exist

### 3. **SecurityManager** (`src/adaptive/security.rs`)

**Actual Constructor:**
```rust
SecurityManager::new(config: SecurityConfig, identity: NodeIdentity) -> Self
```

**Actual Methods:**
```rust
// Validate node join requests
validate_node_join(&self, node: &NodeDescriptor) -> Result<(), SecurityError>

// Check rate limiting
check_rate_limit(&self, node_id: &NodeId, ip: Option<IpAddr>) -> Result<(), SecurityError>

// Eclipse attack detection
detect_eclipse_attack(&self, routing_table: &[NodeId]) -> Result<(), SecurityError>

// Message integrity verification
verify_message_integrity(&self, message: &[u8], hash: &[u8], signature: Option<&[u8]>) -> Result<(), SecurityError>

// Blacklist management
blacklist_node(&self, node_id: NodeId, reason: BlacklistReason)

// Get security metrics
get_metrics(&self) -> SecurityMetrics
```

**What tests were incorrectly trying to use:**
- `new(Default::default())` - needs both config AND identity
- `log_event(event_type)` - doesn't exist, events are logged internally
- `assess_threat_level()` - doesn't exist
- `get_active_mitigations()` - doesn't exist

### 4. **ReplicationManager** (`src/adaptive/replication.rs`)

**Actual Constructor:**
```rust
ReplicationManager::new(
    config: ReplicationConfig,
    trust_provider: Arc<dyn TrustProvider>,
    churn_predictor: Arc<ChurnPredictor>,
    router: Arc<AdaptiveRouter>,
) -> Self
```

**Actual Methods:**
```rust
// Calculate adaptive replication factor
calculate_replication_factor(&self, content_hash: &ContentHash) -> u32

// Replicate content with metadata
replicate_content(&self, content_hash: &ContentHash, content: &[u8], metadata: ContentMetadata) -> Result<ReplicaInfo>

// Maintain existing replications
maintain_replications(&self) -> Result<()>

// Handle node departures
handle_node_departure(&self, departed_node: &NodeId) -> Result<()>

// Get replication statistics
get_stats(&self) -> ReplicationStats
```

**What tests were incorrectly trying to use:**
- `new(3)` - needs complex dependency injection
- `add_data(key, importance)` - doesn't exist
- `handle_node_failure(id)` - wrong method name
- `get_replication_factor(key)` - wrong signature

### 5. **AdaptiveStrategy/Eviction** (`src/adaptive/eviction.rs`)

**Actual API - Uses trait `EvictionStrategy`:**
```rust
// Available concrete implementations
LRUStrategy::new() -> Self
LFUStrategy::new() -> Self  
FIFOStrategy::new() -> Self

// Trait methods
select_victim(&self, cache_state: &CacheState, access_info: &HashMap<ContentHash, AccessInfo>) -> Option<ContentHash>
on_access(&mut self, content_hash: &ContentHash)
on_insert(&mut self, content_hash: &ContentHash)
name(&self) -> &str
```

**What tests were incorrectly trying to use:**
- `AdaptiveStrategy::new(50)` - doesn't exist, use specific strategies
- `add(key, value, access_count)` - doesn't exist
- `access(key)` - wrong signature
- `contains(key)` - doesn't exist
- `get_evicted_count()` - doesn't exist

### 6. **QLearnCacheManager** (`src/adaptive/learning.rs`)

**Actual Constructor:**
```rust
QLearnCacheManager::new(capacity: usize) -> Self
```

**Actual Methods:**
```rust
// Cache operations
insert(&self, hash: ContentHash, data: Vec<u8>) -> bool
get(&self, hash: &ContentHash) -> Option<Vec<u8>>

// Q-learning decisions
decide_action(&self, content_hash: &ContentHash) -> CacheAction
execute_action(&self, hash: &ContentHash, action: CacheAction, data: Option<Vec<u8>>) -> Result<()>
decide_caching(&self, hash: ContentHash, data: Vec<u8>, content_type: ContentType) -> Result<()>

// Statistics
get_stats_async(&self) -> CacheStats
```

### 7. **ChurnPredictor** (`src/adaptive/learning.rs`)

**Actual Methods:**
```rust
// Record node events
record_node_event(&self, node_id: &NodeId, event: NodeEvent) -> Result<()>

// Update node behavior patterns
update_node_behavior(&self, node_id: &NodeId, features: NodeFeatures) -> Result<()>

// Predict churn probability
predict(&self, node_id: &NodeId) -> ChurnPrediction

// Replication recommendations
should_replicate(&self, node_id: &NodeId) -> bool
```

## Type Definitions

### Important Type Aliases
```rust
// In src/adaptive/mod.rs
pub type NodeId = crate::peer_record::UserId;
pub type ContentHash = [u8; 32];

// In src/identity/node_identity.rs  
pub struct NodeId(pub [u8; 32]);

// In src/adaptive/learning.rs
pub enum ContentType { DHTLookup, DataRetrieval, ComputeRequest, RealtimeMessage }
pub enum StrategyChoice { Kademlia, Hyperbolic, TrustPath, SOMRegion }
```

### Key Structs
```rust
pub struct NodeFeatures {
    pub online_duration: f64,
    pub avg_response_time: f64,
    pub resource_contribution: f64,
    pub message_frequency: f64,
    pub time_of_day: f64,
    pub day_of_week: f64,
    pub historical_reliability: f64,
    pub recent_disconnections: f64,
    pub avg_session_length: f64,
    pub connection_stability: f64,
}

pub struct Outcome {
    pub success: bool,
    pub latency_ms: u64,
    pub hops: usize,
}

pub struct ChurnPrediction {
    pub probability_1h: f64,
    pub probability_6h: f64,
    pub probability_24h: f64,
    pub confidence: f64,
}
```

## Fixed Test File

I have created a corrected test file at `/Users/davidirvine/Desktop/Devel/projects/saorsa-core/tests/adaptive_components_corrected_test.rs` that:

1. **Uses the real API methods** - All method calls match the actual implementations
2. **Proper error handling** - Uses `Result` types correctly
3. **Realistic test scenarios** - Tests actual use cases the components were designed for
4. **Comprehensive coverage** - Tests all major components and their interactions
5. **Async/await support** - Properly handles async methods
6. **Dependency injection** - Creates required dependencies correctly

## Key Differences from Original Tests

### Constructor Patterns
- **Original**: Simple constructors like `new(capacity)`
- **Real**: Complex dependency injection, configuration structs

### Method Names
- **Original**: Generic names like `select_arm()`, `add_data()`
- **Real**: Domain-specific names like `select_strategy()`, `replicate_content()`

### Return Types
- **Original**: Simple types like `usize`, `bool`
- **Real**: Rich result types like `Result<RouteDecision>`, `ChurnPrediction`

### Async Patterns
- **Original**: Mostly synchronous
- **Real**: Extensive use of async/await

### Error Handling
- **Original**: Panics and unwraps
- **Real**: Proper `Result<T, E>` error handling

## Recommendations

1. **Use the corrected test file** as a reference for proper API usage
2. **Update any existing code** that uses the incorrect API patterns
3. **Refer to the actual source files** in `src/adaptive/` for the most up-to-date APIs
4. **Follow the dependency injection patterns** shown in the working tests
5. **Use proper error handling** throughout the codebase

The corrected test file demonstrates production-ready usage patterns and should serve as a guide for integrating these adaptive network components into the larger system.