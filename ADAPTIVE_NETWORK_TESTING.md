# Adaptive Network Components Testing Guide

## Overview

The Saorsa Core adaptive network implements multiple machine learning and optimization techniques to create a self-improving P2P network. This guide explains how to test each component.

## Components and Their Purposes

### 1. Thompson Sampling (`adaptive::learning::ThompsonSampling`)
- **Purpose**: Optimal routing strategy selection based on content type
- **Key Methods**:
  - `new()` - Create instance (no parameters)
  - `select_strategy(content_type)` - Choose routing strategy
  - `update(strategy, content_type, success, latency)` - Update with feedback

### 2. Multi-Armed Bandit (`adaptive::multi_armed_bandit::MultiArmedBandit`)
- **Purpose**: Balance exploration vs exploitation in route selection
- **Key Methods**:
  - `new(MABConfig)` - Create with configuration
  - `select_route()` - Choose route with epsilon-greedy
  - `update_route(route_id, reward)` - Update route quality

### 3. Q-Learning Cache (`adaptive::q_learning_cache`)
- **Purpose**: Intelligent cache management using reinforcement learning
- **Features**:
  - Learns optimal caching policies
  - Adapts to access patterns
  - Minimizes cache misses

### 4. LSTM Churn Prediction (`adaptive::churn_prediction`)
- **Purpose**: Predict node departure probability
- **Features**:
  - Uses node behavior patterns
  - Enables proactive replication
  - Reduces data loss from churn

### 5. Adaptive Eviction (`adaptive::eviction::AdaptiveStrategy`)
- **Purpose**: Smart cache eviction beyond simple LRU
- **Features**:
  - Considers access frequency and recency
  - Adapts to workload patterns
  - Maintains hot data in cache

### 6. Replication Manager (`adaptive::replication::ReplicationManager`)
- **Purpose**: Dynamic replication based on data importance
- **Features**:
  - Critical data gets higher replication
  - Adapts to node failures
  - Balances storage overhead

### 7. Adaptive GossipSub (`adaptive::gossip::AdaptiveGossipSub`)
- **Purpose**: Efficient message propagation
- **Features**:
  - Adjusts fanout based on network size
  - Minimizes redundant messages
  - Ensures reliable delivery

### 8. Security Manager (`adaptive::security::SecurityManager`)
- **Purpose**: Threat detection and mitigation
- **Features**:
  - Monitors suspicious patterns
  - Rate limiting
  - Automatic threat response

## Testing Approach

### Unit Tests
Each component has unit tests in its module:
```bash
cargo test --lib adaptive::learning
cargo test --lib adaptive::multi_armed_bandit
cargo test --lib adaptive::q_learning_cache
```

### Integration Tests
Full system integration tests are in:
- `tests/adaptive_network_integration_test.rs`
- `tests/adaptive_components_test.rs`

### Performance Benchmarks
Run benchmarks to measure adaptive component performance:
```bash
cargo bench --bench adaptive_network_bench
cargo bench --bench multi_armed_bandit_bench
cargo bench --bench q_learning_cache_bench
```

### Live Monitoring
Use the monitoring example to see adaptive components in action:
```bash
cargo run --example adaptive_network_monitor
```

## Running a Test Network

### Basic Setup
```rust
use saorsa_core::{
    adaptive::coordinator::NetworkCoordinator,
    config::Config,
    P2PNode, NodeConfig,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Create config with adaptive features enabled
    let mut config = Config::default();
    config.network.enable_adaptive_routing = true;
    config.network.enable_thompson_sampling = true;
    config.network.enable_mab_routing = true;
    config.network.enable_q_learning = true;
    config.network.enable_lstm_churn = true;
    
    // Create and start node
    let node = P2PNode::builder()
        .with_config(config)
        .build()
        .await?;
    
    node.run().await?;
    Ok(())
}
```

### Testing Individual Components

#### Thompson Sampling Test
```rust
let thompson = ThompsonSampling::new();

// Test routing decisions
let strategy = thompson.select_strategy(ContentType::Video).await?;
println!("Selected strategy: {:?}", strategy);

// Provide feedback
thompson.update(strategy, ContentType::Video, true, 100).await;
```

#### Multi-Armed Bandit Test
```rust
let config = MABConfig {
    epsilon: 0.1,
    decay: 0.995,
    min_epsilon: 0.01,
};
let mab = MultiArmedBandit::new(config).await?;

// Select route
let route = mab.select_route().await?;

// Update with reward
mab.update_route(route, 0.8).await;
```

#### Churn Prediction Test
```rust
let predictor = ChurnPrediction::new();

let features = vec![
    online_duration / 24.0,  // Normalized
    avg_response_time / 1000.0,
    message_frequency / 100.0,
    connection_stability,
];

let churn_prob = predictor.predict_churn(&features);
println!("Churn probability: {:.2}%", churn_prob * 100.0);
```

## Verification Checklist

### Component Functionality
- [ ] Thompson Sampling selects appropriate strategies
- [ ] MAB balances exploration vs exploitation
- [ ] Q-Learning cache improves hit rate over time
- [ ] LSTM accurately predicts churn
- [ ] Eviction strategy keeps hot data
- [ ] Replication maintains data availability
- [ ] Gossip ensures message delivery
- [ ] Security detects threats

### Performance Metrics
- [ ] Routing latency decreases over time
- [ ] Cache hit rate improves with learning
- [ ] Churn prediction accuracy > 70%
- [ ] Message delivery rate > 95%
- [ ] Threat detection rate > 90%

### System Integration
- [ ] All components work together
- [ ] No performance degradation
- [ ] Graceful degradation under stress
- [ ] Recovery from failures

## Monitoring Metrics

### Key Performance Indicators
1. **Routing Performance**
   - Average latency
   - Success rate
   - Route stability

2. **Cache Performance**
   - Hit rate
   - Eviction rate
   - Memory usage

3. **Network Health**
   - Active nodes
   - Churn rate
   - Message delivery rate

4. **Security Status**
   - Threat level
   - Blocked connections
   - Suspicious events

## Troubleshooting

### Common Issues

1. **Low Thompson Sampling Performance**
   - Check if enough samples collected
   - Verify decay factor settings
   - Ensure diverse content types

2. **Poor Cache Hit Rate**
   - Verify Q-learning parameters
   - Check cache size adequacy
   - Monitor access patterns

3. **High Churn Rate**
   - Review LSTM predictions
   - Check network stability
   - Verify replication factor

4. **Security False Positives**
   - Adjust threat thresholds
   - Review detection patterns
   - Check rate limit settings

## Advanced Testing

### Stress Testing
```bash
# Run with many nodes
cargo test --release --test stress_test_adaptive -- --nodes 100

# Simulate high churn
cargo test --release --test churn_simulation -- --churn-rate 0.3

# Test under attack
cargo test --release --test security_stress -- --attack-rate 0.1
```

### Performance Profiling
```bash
# CPU profiling
cargo build --release
perf record --call-graph=dwarf ./target/release/examples/adaptive_network_monitor
perf report

# Memory profiling
valgrind --tool=massif ./target/release/examples/adaptive_network_monitor
ms_print massif.out.*
```

## Conclusion

The adaptive network components work together to create a self-improving P2P system. Regular testing ensures:
- Components function correctly
- Performance improves over time
- System remains stable under stress
- Security threats are detected and mitigated

For detailed implementation, see the source code in `src/adaptive/` directory.