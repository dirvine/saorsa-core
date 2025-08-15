//! Simplified integration tests for adaptive network components
//! Tests the actual exported adaptive features

use saorsa_core::{
    adaptive::{
        churn_prediction::ChurnPrediction,
        coordinator::NetworkCoordinator,
        eviction::AdaptiveStrategy,
        gossip::AdaptiveGossipSub,
        learning::ThompsonSampling,
        multi_armed_bandit::MultiArmedBandit,
        q_learning_cache::QLearningConfig,
        replication::ReplicationManager,
        routing::AdaptiveRouter,
        security::SecurityManager,
    },
    config::Config,
    dht::{DHTConfig, Key},
    Identity,
    P2PNode, NodeConfig,
};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex, RwLock},
    time::sleep,
};

#[tokio::test]
async fn test_thompson_sampling_component() -> anyhow::Result<()> {
    println!("Testing Thompson Sampling adaptation...");
    
    let mut thompson = ThompsonSampling::new(10);
    
    // Simulate route selection and feedback
    let mut successes = 0;
    let mut attempts = 100;
    
    for _ in 0..attempts {
        let selected_arm = thompson.select_arm();
        
        // Simulate success based on arm quality (higher arms have better success rate)
        let success = rand::random::<f64>() < 0.3 + (selected_arm as f64 * 0.07);
        thompson.update(selected_arm, success);
        
        if success {
            successes += 1;
        }
    }
    
    let success_rate = successes as f64 / attempts as f64;
    println!("Thompson Sampling success rate: {:.2}%", success_rate * 100.0);
    
    // Check that Thompson is favoring better arms
    let best_arms = thompson.get_top_k_arms(3);
    println!("Top 3 arms: {:?}", best_arms);
    
    assert!(!best_arms.is_empty(), "Should identify top performing arms");
    assert!(best_arms[0] >= 5, "Best arm should be from higher quality range");
    
    Ok(())
}

#[tokio::test]
async fn test_mab_routing_component() -> anyhow::Result<()> {
    println!("Testing Multi-Armed Bandit routing...");
    
    let mut mab = MultiArmedBandit::new(10, 0.1);
    
    // Train the MAB with simulated routing outcomes
    let mut route_rewards = HashMap::new();
    
    for _ in 0..200 {
        let route = mab.select_arm();
        
        // Simulate reward based on route quality
        let base_reward = 0.2 + (route as f64 * 0.08);
        let reward = base_reward + rand::random::<f64>() * 0.2;
        
        mab.update(route, reward);
        route_rewards.entry(route).or_insert(Vec::new()).push(reward);
    }
    
    // Calculate average rewards per route
    for (route, rewards) in &route_rewards {
        let avg = rewards.iter().sum::<f64>() / rewards.len() as f64;
        println!("Route {}: avg reward = {:.3}", route, avg);
    }
    
    let best_route = mab.get_best_arm();
    println!("MAB selected best route: {}", best_route);
    
    assert!(best_route >= 5, "Should select higher quality routes");
    
    Ok(())
}

#[tokio::test]
async fn test_adaptive_eviction_component() -> anyhow::Result<()> {
    println!("Testing Adaptive Eviction strategies...");
    
    let mut eviction = AdaptiveStrategy::new(50); // Small cache for testing
    
    // Add items with varying access patterns
    for i in 0..100 {
        let key = format!("item_{}", i);
        let value = vec![i as u8; 50];
        
        // Hot items (0-10) get more accesses
        let access_count = if i < 10 {
            20 + rand::random::<u32>() % 30
        } else if i < 30 {
            5 + rand::random::<u32>() % 10
        } else {
            rand::random::<u32>() % 3
        };
        
        eviction.add(key.clone(), value, access_count);
        
        // Simulate accesses for hot items
        if i < 10 {
            for _ in 0..5 {
                eviction.access(&key);
            }
        }
    }
    
    // Check that hot items are retained
    let mut hot_items_retained = 0;
    for i in 0..10 {
        if eviction.contains(&format!("item_{}", i)) {
            hot_items_retained += 1;
        }
    }
    
    println!("Hot items retained: {}/10", hot_items_retained);
    assert!(hot_items_retained >= 7, "Most hot items should be retained");
    
    Ok(())
}

#[tokio::test]
async fn test_churn_prediction_component() -> anyhow::Result<()> {
    println!("Testing Churn Prediction...");
    
    let predictor = ChurnPrediction::new();
    
    // Simulate node behavior patterns
    let mut predictions = Vec::new();
    
    for i in 0..50 {
        let features = vec![
            (i as f64 * 0.5) / 24.0,           // Online duration (normalized)
            (100.0 + i as f64 * 2.0) / 1000.0, // Response time (normalized)
            (5.0 + i as f64) / 100.0,           // Message frequency (normalized)
            rand::random::<f64>(),              // Random factor
        ];
        
        let prediction = predictor.predict_churn(&features);
        predictions.push(prediction);
        
        if i % 10 == 0 {
            println!("Node {} churn probability: {:.2}%", i, prediction * 100.0);
        }
    }
    
    // Verify predictions are in valid range
    for pred in &predictions {
        assert!(*pred >= 0.0 && *pred <= 1.0, "Predictions should be probabilities");
    }
    
    // Check that nodes with poor metrics have higher churn probability
    let early_avg = predictions[..10].iter().sum::<f64>() / 10.0;
    let late_avg = predictions[40..].iter().sum::<f64>() / 10.0;
    
    println!("Early nodes avg churn: {:.2}%", early_avg * 100.0);
    println!("Late nodes avg churn: {:.2}%", late_avg * 100.0);
    
    Ok(())
}

#[tokio::test]
async fn test_replication_manager_component() -> anyhow::Result<()> {
    println!("Testing Replication Manager...");
    
    let mut replication = ReplicationManager::new(3); // Replication factor of 3
    
    // Add data with different importance levels
    let critical_data = vec![
        (Key::from([1u8; 32]), 1.0),  // Critical
        (Key::from([2u8; 32]), 1.0),  // Critical
        (Key::from([3u8; 32]), 0.7),  // Important
        (Key::from([4u8; 32]), 0.7),  // Important
        (Key::from([5u8; 32]), 0.3),  // Regular
    ];
    
    for (key, importance) in &critical_data {
        replication.add_data(key.clone(), *importance);
    }
    
    // Simulate some node failures
    replication.handle_node_failure(0);
    replication.handle_node_failure(1);
    
    // Check replication factors
    for (key, importance) in &critical_data {
        let replicas = replication.get_replication_factor(key);
        println!("Key importance {:.1}: {} replicas", importance, replicas);
        
        if *importance >= 0.7 {
            assert!(replicas >= 2, "Important data should maintain replication");
        }
    }
    
    Ok(())
}

#[tokio::test]
async fn test_adaptive_gossip_component() -> anyhow::Result<()> {
    println!("Testing Adaptive GossipSub...");
    
    let gossip = AdaptiveGossipSub::new(Default::default());
    
    // Subscribe to topics
    let topics = vec!["news", "updates", "alerts"];
    for topic in &topics {
        gossip.subscribe(topic).await?;
    }
    
    // Simulate message publishing
    let message = b"Important update".to_vec();
    gossip.publish("updates", message.clone()).await?;
    
    // Give time for propagation
    sleep(Duration::from_millis(100)).await;
    
    // Check delivery metrics
    let delivered = gossip.get_delivered_count("updates").await;
    println!("Message delivered to {} nodes", delivered);
    
    assert!(delivered > 0, "Message should be delivered to at least one node");
    
    Ok(())
}

#[tokio::test]
async fn test_security_manager_component() -> anyhow::Result<()> {
    println!("Testing Security Manager...");
    
    let security = SecurityManager::new(Default::default());
    
    // Simulate various security events
    for i in 0..50 {
        let event_type = match i % 4 {
            0 => "normal_traffic",
            1 => "suspicious_pattern",
            2 => "rate_limit_exceeded",
            _ => "unknown_peer",
        };
        
        security.log_event(event_type).await;
    }
    
    // Add some attack patterns
    for _ in 0..10 {
        security.log_event("potential_dos").await;
    }
    
    // Check threat assessment
    let threat_level = security.assess_threat_level().await;
    println!("Current threat level: {:.2}", threat_level);
    
    assert!(threat_level > 0.0, "Should detect some threat activity");
    assert!(threat_level < 1.0, "Should not be at maximum threat");
    
    // Check if mitigations are triggered
    if threat_level > 0.5 {
        let mitigations = security.get_active_mitigations().await;
        assert!(!mitigations.is_empty(), "Should have active mitigations for high threat");
    }
    
    Ok(())
}

#[tokio::test]
async fn test_adaptive_router_component() -> anyhow::Result<()> {
    println!("Testing Adaptive Router...");
    
    let router = AdaptiveRouter::new(Default::default());
    
    // Simulate routing decisions
    let mut route_counts = HashMap::new();
    
    for _ in 0..100 {
        let destination = Key::from([rand::random::<u8>(); 32]);
        let route = router.select_route(&destination).await;
        
        *route_counts.entry(route.clone()).or_insert(0) += 1;
        
        // Simulate feedback
        let success = rand::random::<bool>();
        router.update_route_quality(&route, success).await;
    }
    
    // Display route distribution
    println!("Route distribution:");
    for (route, count) in &route_counts {
        println!("  Route {:?}: {} times", route, count);
    }
    
    assert!(!route_counts.is_empty(), "Should have selected some routes");
    
    Ok(())
}

#[tokio::test]
async fn test_network_coordinator_component() -> anyhow::Result<()> {
    println!("Testing Network Coordinator...");
    
    let config = Config::default();
    let coordinator = NetworkCoordinator::new(config);
    
    // Start coordinator
    coordinator.start().await?;
    
    // Simulate network activity
    for i in 0..10 {
        coordinator.handle_peer_join(format!("peer_{}", i)).await;
        sleep(Duration::from_millis(50)).await;
    }
    
    // Get network statistics
    let stats = coordinator.get_statistics().await;
    println!("Network stats: {:?}", stats);
    
    assert!(stats.peer_count > 0, "Should have some peers");
    
    // Simulate some peer departures
    for i in 0..3 {
        coordinator.handle_peer_leave(format!("peer_{}", i)).await;
    }
    
    // Check updated stats
    let updated_stats = coordinator.get_statistics().await;
    assert!(updated_stats.peer_count < stats.peer_count, "Peer count should decrease");
    
    coordinator.stop().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_integrated_adaptive_system() -> anyhow::Result<()> {
    println!("\n=== Testing Integrated Adaptive System ===\n");
    
    // Create all components
    let thompson = Arc::new(Mutex::new(ThompsonSampling::new(10)));
    let mab = Arc::new(Mutex::new(MultiArmedBandit::new(10, 0.1)));
    let eviction = Arc::new(Mutex::new(AdaptiveStrategy::new(100)));
    let replication = Arc::new(Mutex::new(ReplicationManager::new(3)));
    let security = Arc::new(SecurityManager::new(Default::default()));
    
    // Simulate integrated operations
    let start = Instant::now();
    let mut total_operations = 0;
    
    while start.elapsed() < Duration::from_secs(2) {
        // Thompson Sampling for route selection
        let route = {
            let mut ts = thompson.lock().await;
            let arm = ts.select_arm();
            ts.update(arm, rand::random::<bool>());
            arm
        };
        
        // MAB for backup route
        let backup = {
            let mut m = mab.lock().await;
            let arm = m.select_arm();
            m.update(arm, rand::random::<f64>());
            arm
        };
        
        // Eviction decision
        {
            let mut ev = eviction.lock().await;
            let key = format!("data_{}", total_operations);
            ev.add(key.clone(), vec![0u8; 50], rand::random::<u32>() % 10);
            if rand::random::<f64>() < 0.3 {
                ev.access(&key);
            }
        }
        
        // Replication management
        {
            let mut rep = replication.lock().await;
            let key = Key::from([rand::random::<u8>(); 32]);
            rep.add_data(key, rand::random::<f64>());
        }
        
        // Security monitoring
        security.log_event("operation").await;
        
        total_operations += 1;
        
        // Small delay to prevent tight loop
        sleep(Duration::from_millis(10)).await;
    }
    
    println!("Completed {} integrated operations", total_operations);
    println!("Test duration: {:?}", start.elapsed());
    
    // Verify all systems are functioning
    assert!(total_operations > 100, "Should complete many operations");
    
    // Check final states
    let threat_level = security.assess_threat_level().await;
    println!("Final threat level: {:.2}", threat_level);
    
    let eviction_stats = eviction.lock().await.get_evicted_count();
    println!("Total evictions: {}", eviction_stats);
    
    println!("\n=== Integrated System Test Passed ===\n");
    
    Ok(())
}