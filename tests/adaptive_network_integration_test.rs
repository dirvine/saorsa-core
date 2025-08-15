//! Comprehensive integration tests for the adaptive network components
//! Tests all adaptive features including Thompson Sampling, MAB routing,
//! Q-Learning cache, LSTM churn prediction, and more.

use saorsa_core::{
    adaptive::{
        churn_prediction::{ChurnPredictor, LstmChurnPredictor},
        coordinator::AdaptiveCoordinator,
        eviction::AdaptiveStrategy,
        gossip::AdaptiveGossipSub,
        learning::ThompsonSampling,
        multi_armed_bandit::MultiArmedBandit,
        q_learning_cache::{QLearningCache, QLearningConfig},
        replication::ReplicationManager,
        routing::AdaptiveRouter,
        security::SecurityMonitor,
    },
    config::Config,
    dht::{DHTConfig, DHTNode, Key},
    identity::Identity,
    network::{Network, NetworkConfig, P2PNetworkNode},
    transport::TransportConfig,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex, RwLock},
    time::{sleep, timeout},
};

/// Test configuration for adaptive network testing
struct TestConfig {
    num_nodes: usize,
    test_duration: Duration,
    enable_thompson_sampling: bool,
    enable_mab_routing: bool,
    enable_q_learning: bool,
    enable_lstm_churn: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            num_nodes: 10,
            test_duration: Duration::from_secs(30),
            enable_thompson_sampling: true,
            enable_mab_routing: true,
            enable_q_learning: true,
            enable_lstm_churn: true,
        }
    }
}

/// Helper struct to manage test network nodes
struct TestNetwork {
    nodes: Vec<Arc<Network>>,
    coordinators: Vec<Arc<AdaptiveCoordinator>>,
}

impl TestNetwork {
    async fn new(config: TestConfig) -> anyhow::Result<Self> {
        let mut nodes = Vec::new();
        let mut coordinators = Vec::new();

        for i in 0..config.num_nodes {
            let port = 50000 + i as u16;
            let addr: SocketAddr = format!("127.0.0.1:{}", port).parse()?;
            
            let mut network_config = NetworkConfig::default();
            network_config.listen_address = addr;
            network_config.enable_adaptive_routing = true;
            network_config.enable_thompson_sampling = config.enable_thompson_sampling;
            network_config.enable_mab_routing = config.enable_mab_routing;
            network_config.enable_q_learning = config.enable_q_learning;
            network_config.enable_lstm_churn = config.enable_lstm_churn;

            let identity = Identity::generate();
            let network = Arc::new(Network::new(network_config, identity).await?);
            
            let coordinator = Arc::new(AdaptiveCoordinator::new(
                network.clone(),
                Default::default(),
            ));

            nodes.push(network);
            coordinators.push(coordinator);
        }

        // Bootstrap nodes - connect them in a ring topology initially
        for i in 0..config.num_nodes {
            let next = (i + 1) % config.num_nodes;
            let next_addr = nodes[next].local_addr();
            nodes[i].connect_to_peer(next_addr).await?;
        }

        Ok(Self { nodes, coordinators })
    }

    async fn start_all(&self) -> anyhow::Result<()> {
        for coordinator in &self.coordinators {
            coordinator.start().await?;
        }
        Ok(())
    }

    async fn stop_all(&self) -> anyhow::Result<()> {
        for coordinator in &self.coordinators {
            coordinator.stop().await?;
        }
        Ok(())
    }
}

#[tokio::test]
async fn test_thompson_sampling_adaptation() -> anyhow::Result<()> {
    let config = TestConfig {
        num_nodes: 5,
        enable_thompson_sampling: true,
        ..Default::default()
    };

    let network = TestNetwork::new(config).await?;
    network.start_all().await?;

    // Create Thompson Sampling instance
    let mut thompson = ThompsonSampling::new(10); // 10 arms for 10 possible routes

    // Simulate route selection and feedback
    for _ in 0..100 {
        let selected_arm = thompson.select_arm();
        
        // Simulate success/failure based on arm quality
        let success = rand::random::<f64>() < 0.5 + (selected_arm as f64 * 0.05);
        thompson.update(selected_arm, success);
    }

    // Verify that Thompson Sampling is learning
    let best_arms = thompson.get_top_k_arms(3);
    assert!(!best_arms.is_empty(), "Thompson Sampling should identify best arms");

    // Check success rates
    let stats = thompson.get_statistics();
    println!("Thompson Sampling Statistics: {:?}", stats);
    
    network.stop_all().await?;
    Ok(())
}

#[tokio::test]
async fn test_multi_armed_bandit_routing() -> anyhow::Result<()> {
    let config = TestConfig {
        num_nodes: 8,
        enable_mab_routing: true,
        ..Default::default()
    };

    let network = TestNetwork::new(config).await?;
    network.start_all().await?;

    // Create MAB router
    let mut mab = MultiArmedBandit::new(8, 0.1); // epsilon = 0.1

    // Simulate routing decisions
    let mut route_successes = HashMap::new();
    let mut route_attempts = HashMap::new();

    for _ in 0..200 {
        let selected_route = mab.select_arm();
        
        // Simulate routing success based on route quality
        let success = rand::random::<f64>() < 0.4 + (selected_route as f64 * 0.1);
        
        *route_attempts.entry(selected_route).or_insert(0) += 1;
        if success {
            *route_successes.entry(selected_route).or_insert(0) += 1;
            mab.update(selected_route, 1.0);
        } else {
            mab.update(selected_route, 0.0);
        }
    }

    // Verify MAB is learning optimal routes
    let best_route = mab.get_best_arm();
    let success_rate = route_successes.get(&best_route).unwrap_or(&0) as f64
        / route_attempts.get(&best_route).unwrap_or(&1) as f64;
    
    println!("Best route: {}, Success rate: {:.2}%", best_route, success_rate * 100.0);
    assert!(success_rate > 0.5, "MAB should identify high-quality routes");

    network.stop_all().await?;
    Ok(())
}

#[tokio::test]
async fn test_q_learning_cache_optimization() -> anyhow::Result<()> {
    let config = TestConfig {
        num_nodes: 6,
        enable_q_learning: true,
        ..Default::default()
    };

    let network = TestNetwork::new(config).await?;
    network.start_all().await?;

    // Create Q-Learning cache
    let q_config = QLearningConfig {
        cache_size: 100,
        learning_rate: 0.1,
        discount_factor: 0.9,
        exploration_rate: 0.1,
        min_exploration_rate: 0.01,
        exploration_decay: 0.995,
    };
    
    let mut q_cache = QLearningCache::new(q_config);

    // Simulate cache operations
    let keys: Vec<Key> = (0..50).map(|i| {
        let mut key = [0u8; 32];
        key[0] = i as u8;
        Key::from(key)
    }).collect();

    // Access patterns with locality
    for epoch in 0..10 {
        for i in 0..30 {
            let key_idx = if rand::random::<f64>() < 0.7 {
                // 70% of accesses to hot keys (first 10)
                rand::random::<usize>() % 10
            } else {
                // 30% to cold keys
                10 + rand::random::<usize>() % 40
            };
            
            let key = &keys[key_idx];
            let hit = q_cache.get(key).is_some();
            
            if !hit {
                q_cache.put(key.clone(), vec![epoch as u8; 100]);
            }
            
            // Simulate reward based on hit/miss
            let reward = if hit { 1.0 } else { -0.1 };
            q_cache.update_q_values(key, reward);
        }
    }

    // Check cache performance
    let stats = q_cache.get_statistics();
    println!("Q-Learning Cache Stats: Hit rate: {:.2}%", stats.hit_rate * 100.0);
    assert!(stats.hit_rate > 0.5, "Q-Learning should optimize cache hit rate");

    network.stop_all().await?;
    Ok(())
}

#[tokio::test]
async fn test_lstm_churn_prediction() -> anyhow::Result<()> {
    let config = TestConfig {
        num_nodes: 10,
        enable_lstm_churn: true,
        ..Default::default()
    };

    let network = TestNetwork::new(config).await?;
    network.start_all().await?;

    // Create LSTM churn predictor
    let mut predictor = LstmChurnPredictor::new(10, 32, 0.001);

    // Generate synthetic node behavior data
    let mut node_features = Vec::new();
    for i in 0..100 {
        let online_duration = (i as f64 * 0.5 + rand::random::<f64>() * 10.0).max(0.0);
        let response_time = (100.0 + rand::random::<f64>() * 50.0).max(0.0);
        let message_freq = (5.0 + rand::random::<f64>() * 20.0).max(0.0);
        
        node_features.push(vec![
            online_duration / 24.0,  // Normalize to days
            response_time / 1000.0,   // Normalize to seconds
            message_freq / 100.0,     // Normalize
            rand::random::<f64>(),    // Random feature
        ]);
    }

    // Train the LSTM
    for epoch in 0..5 {
        for features in &node_features {
            // Simulate churn label (1 if likely to churn)
            let will_churn = features[0] < 0.3 || features[1] > 0.15;
            predictor.train(features, will_churn);
        }
    }

    // Test predictions
    let test_features = vec![0.1, 0.2, 0.5, 0.3]; // High churn risk profile
    let churn_prob = predictor.predict(&test_features);
    
    println!("LSTM Churn Prediction: {:.2}% probability", churn_prob * 100.0);
    assert!(churn_prob > 0.0 && churn_prob < 1.0, "LSTM should produce valid probabilities");

    network.stop_all().await?;
    Ok(())
}

#[tokio::test]
async fn test_adaptive_eviction_strategies() -> anyhow::Result<()> {
    let config = TestConfig {
        num_nodes: 7,
        ..Default::default()
    };

    let network = TestNetwork::new(config).await?;
    network.start_all().await?;

    // Create adaptive eviction strategy
    let mut eviction = AdaptiveStrategy::new(100); // Cache size 100

    // Add items with different access patterns
    for i in 0..150 {
        let key = format!("key_{}", i);
        let value = vec![i as u8; 100];
        let access_count = if i < 20 {
            10 + rand::random::<u32>() % 50  // Hot items
        } else {
            rand::random::<u32>() % 5  // Cold items
        };
        
        eviction.add(key.clone(), value, access_count);
        
        // Simulate some accesses
        if rand::random::<f64>() < 0.3 {
            eviction.access(&key);
        }
    }

    // Check eviction decisions
    let evicted_count = eviction.get_evicted_count();
    println!("Adaptive Eviction: {} items evicted", evicted_count);
    assert!(evicted_count > 0, "Should evict items when cache is full");

    // Verify hot items are retained
    for i in 0..20 {
        let key = format!("key_{}", i);
        assert!(eviction.contains(&key), "Hot items should be retained");
    }

    network.stop_all().await?;
    Ok(())
}

#[tokio::test]
async fn test_adaptive_replication() -> anyhow::Result<()> {
    let config = TestConfig {
        num_nodes: 8,
        ..Default::default()
    };

    let network = TestNetwork::new(config).await?;
    network.start_all().await?;

    // Create replication manager
    let mut replication = ReplicationManager::new(3); // Target replication factor 3

    // Add data items with different importance levels
    for i in 0..50 {
        let key = Key::from([i as u8; 32]);
        let importance = if i < 10 { 
            1.0  // Critical data
        } else if i < 30 {
            0.5  // Important data
        } else {
            0.1  // Regular data
        };
        
        replication.add_data(key, importance);
    }

    // Simulate node failures
    for _ in 0..3 {
        replication.handle_node_failure(rand::random::<usize>() % 8);
    }

    // Check replication levels
    let critical_replicas = replication.get_replication_factor(&Key::from([0u8; 32]));
    println!("Critical data replicas: {}", critical_replicas);
    assert!(critical_replicas >= 2, "Critical data should maintain high replication");

    network.stop_all().await?;
    Ok(())
}

#[tokio::test]
async fn test_adaptive_gossip_protocol() -> anyhow::Result<()> {
    let config = TestConfig {
        num_nodes: 12,
        ..Default::default()
    };

    let network = TestNetwork::new(config).await?;
    network.start_all().await?;

    // Create adaptive gossip instance
    let gossip = AdaptiveGossipSub::new(Default::default());
    
    // Subscribe nodes to topics
    let topics = vec!["topic_a", "topic_b", "topic_c"];
    for topic in &topics {
        gossip.subscribe(topic).await?;
    }

    // Simulate message propagation
    let start = Instant::now();
    let message = b"test_message".to_vec();
    
    gossip.publish("topic_a", message.clone()).await?;
    
    // Wait for propagation
    sleep(Duration::from_millis(500)).await;
    
    // Check message delivery
    let delivered = gossip.get_delivered_count("topic_a").await;
    let propagation_time = start.elapsed();
    
    println!("Gossip propagation: {} nodes in {:?}", delivered, propagation_time);
    assert!(delivered > config.num_nodes / 2, "Message should reach majority of nodes");

    network.stop_all().await?;
    Ok(())
}

#[tokio::test]
async fn test_security_monitoring() -> anyhow::Result<()> {
    let config = TestConfig {
        num_nodes: 6,
        ..Default::default()
    };

    let network = TestNetwork::new(config).await?;
    network.start_all().await?;

    // Create security monitor
    let monitor = SecurityMonitor::new();

    // Simulate various network events
    for i in 0..100 {
        let event_type = match i % 5 {
            0 => "connection_attempt",
            1 => "data_request",
            2 => "route_query",
            3 => "suspicious_pattern",
            _ => "normal_traffic",
        };
        
        monitor.record_event(event_type, HashMap::new()).await;
    }

    // Simulate potential attack
    for _ in 0..20 {
        monitor.record_event("suspicious_pattern", HashMap::new()).await;
    }

    // Check threat detection
    let threat_level = monitor.get_threat_level().await;
    println!("Security threat level: {:?}", threat_level);
    assert!(threat_level > 0.5, "Should detect suspicious activity");

    // Verify mitigation triggered
    let mitigations = monitor.get_active_mitigations().await;
    assert!(!mitigations.is_empty(), "Should trigger mitigations for threats");

    network.stop_all().await?;
    Ok(())
}

#[tokio::test]
async fn test_full_adaptive_network_simulation() -> anyhow::Result<()> {
    println!("Starting comprehensive adaptive network simulation...");
    
    let config = TestConfig {
        num_nodes: 20,
        test_duration: Duration::from_secs(60),
        enable_thompson_sampling: true,
        enable_mab_routing: true,
        enable_q_learning: true,
        enable_lstm_churn: true,
    };

    let network = TestNetwork::new(config.clone()).await?;
    network.start_all().await?;

    // Create all adaptive components
    let thompson = Arc::new(Mutex::new(ThompsonSampling::new(20)));
    let mab = Arc::new(Mutex::new(MultiArmedBandit::new(20, 0.1)));
    let q_cache = Arc::new(Mutex::new(QLearningCache::new(Default::default())));
    let lstm = Arc::new(Mutex::new(LstmChurnPredictor::new(10, 32, 0.001)));
    let eviction = Arc::new(Mutex::new(AdaptiveStrategy::new(1000)));
    let replication = Arc::new(Mutex::new(ReplicationManager::new(3)));
    let gossip = Arc::new(AdaptiveGossipSub::new(Default::default()));
    let security = Arc::new(SecurityMonitor::new());

    // Metrics tracking
    let metrics = Arc::new(RwLock::new(SimulationMetrics::default()));

    // Spawn monitoring tasks
    let mut handles = Vec::new();

    // Thompson Sampling monitoring
    let thompson_clone = thompson.clone();
    let metrics_clone = metrics.clone();
    handles.push(tokio::spawn(async move {
        for _ in 0..100 {
            sleep(Duration::from_millis(500)).await;
            let mut ts = thompson_clone.lock().await;
            let arm = ts.select_arm();
            let success = rand::random::<bool>();
            ts.update(arm, success);
            
            let mut m = metrics_clone.write().await;
            m.thompson_selections += 1;
            if success {
                m.thompson_successes += 1;
            }
        }
    }));

    // MAB routing monitoring
    let mab_clone = mab.clone();
    let metrics_clone = metrics.clone();
    handles.push(tokio::spawn(async move {
        for _ in 0..100 {
            sleep(Duration::from_millis(500)).await;
            let mut mab = mab_clone.lock().await;
            let route = mab.select_arm();
            let reward = rand::random::<f64>();
            mab.update(route, reward);
            
            let mut m = metrics_clone.write().await;
            m.mab_selections += 1;
            m.mab_total_reward += reward;
        }
    }));

    // Q-Learning cache monitoring
    let q_cache_clone = q_cache.clone();
    let metrics_clone = metrics.clone();
    handles.push(tokio::spawn(async move {
        for _ in 0..100 {
            sleep(Duration::from_millis(500)).await;
            let mut cache = q_cache_clone.lock().await;
            let key = Key::from([rand::random::<u8>(); 32]);
            let hit = cache.get(&key).is_some();
            
            if !hit {
                cache.put(key.clone(), vec![0u8; 100]);
            }
            
            let mut m = metrics_clone.write().await;
            m.cache_accesses += 1;
            if hit {
                m.cache_hits += 1;
            }
        }
    }));

    // Wait for test duration
    println!("Running simulation for {:?}...", config.test_duration);
    tokio::time::timeout(config.test_duration, async {
        for handle in handles {
            let _ = handle.await;
        }
    }).await.ok();

    // Collect and display metrics
    let final_metrics = metrics.read().await;
    println!("\n=== Simulation Results ===");
    println!("Thompson Sampling:");
    println!("  Selections: {}", final_metrics.thompson_selections);
    println!("  Success Rate: {:.2}%", 
        (final_metrics.thompson_successes as f64 / final_metrics.thompson_selections.max(1) as f64) * 100.0);
    
    println!("\nMulti-Armed Bandit:");
    println!("  Selections: {}", final_metrics.mab_selections);
    println!("  Average Reward: {:.3}", 
        final_metrics.mab_total_reward / final_metrics.mab_selections.max(1) as f64);
    
    println!("\nQ-Learning Cache:");
    println!("  Accesses: {}", final_metrics.cache_accesses);
    println!("  Hit Rate: {:.2}%", 
        (final_metrics.cache_hits as f64 / final_metrics.cache_accesses.max(1) as f64) * 100.0);

    // Verify all components are functioning
    assert!(final_metrics.thompson_selections > 0, "Thompson Sampling should be active");
    assert!(final_metrics.mab_selections > 0, "MAB routing should be active");
    assert!(final_metrics.cache_accesses > 0, "Q-Learning cache should be active");

    network.stop_all().await?;
    println!("\nSimulation completed successfully!");
    Ok(())
}

/// Metrics for tracking simulation performance
#[derive(Default, Debug)]
struct SimulationMetrics {
    thompson_selections: usize,
    thompson_successes: usize,
    mab_selections: usize,
    mab_total_reward: f64,
    cache_accesses: usize,
    cache_hits: usize,
    messages_sent: usize,
    messages_delivered: usize,
    nodes_churned: usize,
    threats_detected: usize,
}

#[tokio::test]
async fn test_adaptive_network_resilience() -> anyhow::Result<()> {
    println!("Testing adaptive network resilience under stress...");
    
    let config = TestConfig {
        num_nodes: 15,
        test_duration: Duration::from_secs(30),
        ..Default::default()
    };

    let network = TestNetwork::new(config.clone()).await?;
    network.start_all().await?;

    // Simulate node failures
    println!("Simulating node failures...");
    for i in 0..5 {
        sleep(Duration::from_secs(3)).await;
        let node_idx = rand::random::<usize>() % network.nodes.len();
        println!("  Failing node {}", node_idx);
        // Simulate failure by disconnecting
        network.nodes[node_idx].disconnect_all().await?;
    }

    // Check network recovery
    sleep(Duration::from_secs(5)).await;
    
    // Count connected nodes
    let mut connected_count = 0;
    for node in &network.nodes {
        if node.peer_count().await > 0 {
            connected_count += 1;
        }
    }

    println!("Connected nodes after failures: {}/{}", connected_count, config.num_nodes);
    assert!(connected_count > config.num_nodes / 2, "Network should maintain connectivity");

    network.stop_all().await?;
    Ok(())
}

#[tokio::test]
async fn test_adaptive_performance_optimization() -> anyhow::Result<()> {
    println!("Testing adaptive performance optimization...");
    
    let config = TestConfig {
        num_nodes: 10,
        ..Default::default()
    };

    let network = TestNetwork::new(config).await?;
    network.start_all().await?;

    // Measure baseline performance
    let mut baseline_latencies = Vec::new();
    for _ in 0..20 {
        let start = Instant::now();
        // Simulate a request
        let key = Key::from([rand::random::<u8>(); 32]);
        network.nodes[0].dht_get(&key).await?;
        baseline_latencies.push(start.elapsed());
    }

    let baseline_avg = baseline_latencies.iter()
        .map(|d| d.as_millis())
        .sum::<u128>() as f64 / baseline_latencies.len() as f64;

    println!("Baseline average latency: {:.2}ms", baseline_avg);

    // Let adaptive mechanisms optimize
    sleep(Duration::from_secs(10)).await;

    // Measure optimized performance
    let mut optimized_latencies = Vec::new();
    for _ in 0..20 {
        let start = Instant::now();
        let key = Key::from([rand::random::<u8>(); 32]);
        network.nodes[0].dht_get(&key).await?;
        optimized_latencies.push(start.elapsed());
    }

    let optimized_avg = optimized_latencies.iter()
        .map(|d| d.as_millis())
        .sum::<u128>() as f64 / optimized_latencies.len() as f64;

    println!("Optimized average latency: {:.2}ms", optimized_avg);
    println!("Improvement: {:.2}%", ((baseline_avg - optimized_avg) / baseline_avg) * 100.0);

    // Adaptive mechanisms should improve or maintain performance
    assert!(optimized_avg <= baseline_avg * 1.1, "Performance should not degrade significantly");

    network.stop_all().await?;
    Ok(())
}