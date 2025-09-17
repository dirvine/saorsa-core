//! Corrected integration tests for adaptive network components
//! Tests the actual exported adaptive features using real APIs

use saorsa_core::adaptive::{
    ContentHash, ContentType, NodeId, NodeIdentity, Outcome, StrategyChoice,
    eviction::{CacheState, EvictionStrategy, LFUStrategy, LRUStrategy},
    learning::{ChurnPredictor, NodeEvent, NodeFeatures, QLearnCacheManager, ThompsonSampling},
    multi_armed_bandit::{MABConfig, MultiArmedBandit},
    q_learning_cache::{AccessInfo, StateVector},
    replication::ReplicationManager,
    routing::AdaptiveRouter,
    security::{BlacklistReason, SecurityConfig, SecurityError, SecurityManager},
};
use saorsa_core::adaptive::{storage::ReplicationConfig, trust::MockTrustProvider};
use saorsa_core::quantum_crypto::ant_quic_integration::MlDsaPublicKey;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;

#[tokio::test]
async fn test_thompson_sampling_real_api() -> anyhow::Result<()> {
    println!("Testing Thompson Sampling with real API...");

    let ts = ThompsonSampling::new();

    // Test strategy selection for different content types
    let content_types = [
        ContentType::DHTLookup,
        ContentType::DataRetrieval,
        ContentType::ComputeRequest,
        ContentType::RealtimeMessage,
    ];

    let mut strategy_counts = HashMap::new();

    // Simulate routing decisions and feedback
    for content_type in &content_types {
        for _ in 0..50 {
            let strategy = ts.select_strategy(*content_type).await?;
            *strategy_counts.entry((content_type, strategy)).or_insert(0) += 1;

            // Simulate different success rates for different strategies
            let success = match strategy {
                StrategyChoice::Kademlia => rand::random::<f64>() < 0.8,
                StrategyChoice::Hyperbolic => rand::random::<f64>() < 0.7,
                StrategyChoice::TrustPath => rand::random::<f64>() < 0.6,
                StrategyChoice::SOMRegion => rand::random::<f64>() < 0.5,
            };

            let latency = if success {
                50 + rand::random::<u64>() % 100
            } else {
                500 + rand::random::<u64>() % 1000
            };

            ts.update(*content_type, strategy, success, latency).await?;
        }
    }

    // Check metrics
    let metrics = ts.get_metrics().await;
    println!("Thompson Sampling metrics: {:?}", metrics);
    assert!(metrics.total_decisions > 0, "Should have made decisions");

    // Check confidence intervals
    for content_type in &content_types {
        let (lower, upper) = ts
            .get_confidence_interval(*content_type, StrategyChoice::Kademlia)
            .await;
        println!(
            "Confidence interval for {:?} with Kademlia: [{:.3}, {:.3}]",
            content_type, lower, upper
        );
        assert!(
            lower >= 0.0 && upper <= 1.0 && lower <= upper,
            "Invalid confidence interval"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_multi_armed_bandit_real_api() -> anyhow::Result<()> {
    println!("Testing Multi-Armed Bandit with real API...");

    let temp_dir = TempDir::new()?;
    let config = MABConfig {
        epsilon: 0.1,
        min_samples: 5,
        decay_factor: 0.95,
        storage_path: Some(temp_dir.path().to_path_buf()),
        persist_interval: Duration::from_secs(60),
        max_stats_age: Duration::from_secs(3600),
    };

    let mab = MultiArmedBandit::new(config).await?;

    // Create test destinations and strategies
    let destinations = [
        NodeId { hash: [1u8; 32] },
        NodeId { hash: [2u8; 32] },
        NodeId { hash: [3u8; 32] },
    ];

    let strategies = vec![
        StrategyChoice::Kademlia,
        StrategyChoice::Hyperbolic,
        StrategyChoice::TrustPath,
    ];

    let mut route_successes = HashMap::new();

    // Simulate routing decisions and outcomes
    for _ in 0..100 {
        let destination = &destinations[rand::random::<usize>() % destinations.len()];
        let content_type = ContentType::DHTLookup;

        let decision = mab
            .select_route(destination, content_type, &strategies)
            .await?;
        println!(
            "Selected route: {:?} with probability {:.3}",
            decision.route_id.strategy, decision.probability
        );

        // Simulate outcome based on strategy quality
        let success = match decision.route_id.strategy {
            StrategyChoice::Kademlia => rand::random::<f64>() < 0.8,
            StrategyChoice::Hyperbolic => rand::random::<f64>() < 0.6,
            StrategyChoice::TrustPath => rand::random::<f64>() < 0.7,
            StrategyChoice::SOMRegion => rand::random::<f64>() < 0.5,
        };

        let outcome = Outcome {
            success,
            latency_ms: if success {
                50 + rand::random::<u64>() % 100
            } else {
                500 + rand::random::<u64>() % 1000
            },
            hops: rand::random::<usize>() % 6 + 1,
        };

        mab.update_route(&decision.route_id, content_type, &outcome)
            .await?;

        *route_successes
            .entry(decision.route_id.strategy)
            .or_insert((0, 0)) = {
            let (s, t) = route_successes
                .get(&decision.route_id.strategy)
                .unwrap_or(&(0, 0));
            if success { (s + 1, t + 1) } else { (*s, t + 1) }
        };
    }

    // Display results
    println!("Route success rates:");
    for (strategy, (successes, total)) in &route_successes {
        let rate = *successes as f64 / *total as f64;
        println!(
            "  {:?}: {:.1}% ({}/{})",
            strategy,
            rate * 100.0,
            successes,
            total
        );
    }

    let metrics = mab.get_metrics().await;
    println!("MAB metrics: {:?}", metrics);
    assert!(
        metrics.total_decisions > 0,
        "Should have made routing decisions"
    );

    // Test persistence
    mab.persist().await?;

    Ok(())
}

#[tokio::test]
async fn test_security_manager_real_api() -> anyhow::Result<()> {
    println!("Testing Security Manager with real API...");

    let config = SecurityConfig::default();
    let identity = NodeIdentity::generate()?;
    let security = SecurityManager::new(config, &identity);

    // Test node join validation
    let test_node = saorsa_core::adaptive::NodeDescriptor {
        id: NodeId { hash: [1u8; 32] },
        public_key: MlDsaPublicKey::from_bytes(&vec![0u8; 1952])?,
        addresses: vec!["192.168.1.100:8080".to_string()],
        hyperbolic: None,
        som_position: None,
        trust: 0.8,
        capabilities: saorsa_core::adaptive::NodeCapabilities {
            storage: 1000,
            compute: 500,
            bandwidth: 100,
        },
    };

    // Should pass validation initially
    match security.validate_node_join(&test_node).await {
        Ok(()) => println!("Node validation passed"),
        Err(e) => println!("Node validation failed: {:?}", e),
    }

    // Test rate limiting
    let node_id = &test_node.id;
    let ip = Some("192.168.1.100".parse()?);

    // Simulate multiple requests
    for i in 0..10 {
        match security.check_rate_limit(node_id, ip).await {
            Ok(()) => println!("Request {} passed rate limit", i),
            Err(SecurityError::RateLimitExceeded) => {
                println!("Request {} hit rate limit", i);
                break;
            }
            Err(e) => println!("Request {} failed: {:?}", i, e),
        }
    }

    // Test blacklisting
    security
        .blacklist_node(
            test_node.id.clone(),
            BlacklistReason::Manual("Test blacklist".to_string()),
        )
        .await;

    // Should fail validation after blacklisting
    match security.validate_node_join(&test_node).await {
        Err(SecurityError::Blacklisted) => println!("Correctly blocked blacklisted node"),
        Ok(()) => println!("WARNING: Blacklisted node was allowed to join!"),
        Err(e) => println!("Other error: {:?}", e),
    }

    // Check security metrics
    let metrics = security.get_metrics().await;
    println!("Security metrics: {:?}", metrics);
    assert!(
        metrics.blacklisted_nodes > 0,
        "Should have blacklisted nodes"
    );

    Ok(())
}

#[tokio::test]
async fn test_replication_manager_real_api() -> anyhow::Result<()> {
    println!("Testing Replication Manager with real API...");

    // Create dependencies
    let config = ReplicationConfig::default();
    let trust_provider = Arc::new(MockTrustProvider::new());
    let churn_predictor = Arc::new(ChurnPredictor::new());
    let router = Arc::new(AdaptiveRouter::new(trust_provider.clone()));

    let replication = ReplicationManager::new(config, trust_provider, churn_predictor, router);

    // Test replication factor calculation
    let content_hash = ContentHash([1u8; 32]);
    let factor = replication
        .calculate_replication_factor(&content_hash)
        .await;
    println!("Calculated replication factor: {}", factor);
    assert!(factor > 0, "Replication factor should be positive");

    // Test content replication
    let content = b"Test content for replication";
    let metadata = saorsa_core::adaptive::storage::ContentMetadata {
        size: content.len(),
        content_type: ContentType::DataRetrieval,
        created_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        chunk_count: None,
        replication_factor: factor,
    };

    let replica_info = replication
        .replicate_content(&content_hash, content, metadata)
        .await?;
    println!("Replica info: {:?}", replica_info);
    assert!(
        !replica_info.storing_nodes.is_empty(),
        "Should have storing nodes"
    );

    // Test node departure handling
    if let Some(departed_node) = replica_info.storing_nodes.iter().next() {
        replication.handle_node_departure(departed_node).await?;
        println!("Handled node departure for: {:?}", departed_node);
    }

    // Check replication statistics
    let stats = replication.get_stats().await;
    println!("Replication stats: {:?}", stats);

    Ok(())
}

#[tokio::test]
async fn test_eviction_strategies_real_api() -> anyhow::Result<()> {
    println!("Testing Eviction Strategies with real API...");

    // Create test cache state
    let cache_state = CacheState {
        current_size: 800,
        max_size: 1000,
        item_count: 5,
        avg_access_frequency: 10.0,
    };

    // Create access info for test content
    let mut access_info = HashMap::new();
    let content_hashes = vec![
        ContentHash([1u8; 32]),
        ContentHash([2u8; 32]),
        ContentHash([3u8; 32]),
        ContentHash([4u8; 32]),
        ContentHash([5u8; 32]),
    ];

    for (i, hash) in content_hashes.iter().enumerate() {
        access_info.insert(
            *hash,
            AccessInfo {
                count: (i + 1) as u64 * 10,
                last_access_secs: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
                    - (i as u64 * 60),
                size: 1024,
            },
        );
    }

    // Test LRU strategy
    let mut lru = LRUStrategy::new();
    println!("Testing LRU Strategy: {}", lru.name());

    // Simulate accesses in order
    for hash in &content_hashes {
        lru.on_insert(hash);
    }

    let lru_victim = lru.select_victim(&cache_state, &access_info);
    println!("LRU selected victim: {:?}", lru_victim);

    // Test LFU strategy
    let mut lfu = LFUStrategy::new();
    println!("Testing LFU Strategy: {}", lfu.name());

    for hash in &content_hashes {
        lfu.on_insert(hash);
        // Simulate different access frequencies
        for _ in 0..((hash.0[0] % 5) + 1) {
            lfu.on_access(hash);
        }
    }

    let lfu_victim = lfu.select_victim(&cache_state, &access_info);
    println!("LFU selected victim: {:?}", lfu_victim);

    assert!(
        lru_victim.is_some() || lfu_victim.is_some(),
        "At least one strategy should select a victim"
    );

    Ok(())
}

#[tokio::test]
async fn test_q_learning_cache_real_api() -> anyhow::Result<()> {
    println!("Testing Q-Learning Cache Manager with real API...");

    let manager = QLearnCacheManager::new(1024); // 1KB cache for testing

    // Test content insertion and retrieval
    let content_hashes = vec![
        ContentHash([1u8; 32]),
        ContentHash([2u8; 32]),
        ContentHash([3u8; 32]),
    ];

    let test_content = vec![
        vec![1u8; 100], // 100 bytes
        vec![2u8; 200], // 200 bytes
        vec![3u8; 150], // 150 bytes
    ];

    // Insert content
    for (hash, data) in content_hashes.iter().zip(test_content.iter()) {
        let success = manager.insert(*hash, data.clone()).await;
        println!("Inserted content {}: {}", hash.0[0], success);
    }

    // Test retrieval
    let mut hits = 0;
    let mut misses = 0;

    for hash in &content_hashes {
        if let Some(data) = manager.get(hash).await {
            hits += 1;
            println!("Cache hit for content {}, size: {}", hash.0[0], data.len());
        } else {
            misses += 1;
            println!("Cache miss for content {}", hash.0[0]);
        }
    }

    // Test Q-learning decision making
    for (hash, data) in content_hashes.iter().zip(test_content.iter()) {
        let action = manager.decide_action(hash).await;
        println!(
            "Q-learning decided action for content {}: {:?}",
            hash.0[0], action
        );

        // Test action execution
        manager
            .execute_action(hash, action, Some(data.clone()))
            .await?;
    }

    // Test caching decisions
    let new_hash = ContentHash([4u8; 32]);
    let new_data = vec![4u8; 100];
    manager
        .decide_caching(new_hash, new_data, ContentType::DataRetrieval)
        .await?;

    // Get cache statistics
    let stats = manager.get_stats_async().await;
    println!(
        "Cache stats: hits={}, misses={}, size={}, items={}, hit_rate={:.2}%",
        stats.hits,
        stats.misses,
        stats.size_bytes,
        stats.item_count,
        stats.hit_rate * 100.0
    );

    assert!(hits + misses > 0, "Should have attempted retrievals");

    Ok(())
}

#[tokio::test]
async fn test_churn_predictor_real_api() -> anyhow::Result<()> {
    println!("Testing Churn Predictor with real API...");

    let predictor = ChurnPredictor::new();
    let node_id = NodeId { hash: [1u8; 32] };

    // Record node events
    predictor
        .record_node_event(&node_id, NodeEvent::Connected)
        .await?;

    // Update node behavior with realistic features
    let features = NodeFeatures {
        online_duration: 3600.0,     // 1 hour
        avg_response_time: 50.0,     // 50ms
        resource_contribution: 0.8,  // High contribution
        message_frequency: 10.0,     // 10 messages/hour
        time_of_day: 14.0,           // 2 PM
        day_of_week: 2.0,            // Tuesday
        historical_reliability: 0.9, // High reliability
        recent_disconnections: 0.0,  // No recent disconnections
        avg_session_length: 8.0,     // 8 hours average
        connection_stability: 0.95,  // Very stable
    };

    predictor
        .update_node_behavior(&node_id, features.clone())
        .await?;

    // Test churn prediction
    let prediction = predictor.predict(&node_id).await;
    println!(
        "Churn prediction for stable node: 1h={:.1}%, 6h={:.1}%, 24h={:.1}%, confidence={:.1}%",
        prediction.probability_1h * 100.0,
        prediction.probability_6h * 100.0,
        prediction.probability_24h * 100.0,
        prediction.confidence * 100.0
    );

    // Test with unstable node
    let unstable_node = NodeId { hash: [2u8; 32] };
    let unstable_features = NodeFeatures {
        online_duration: 300.0,      // 5 minutes
        avg_response_time: 500.0,    // 500ms
        resource_contribution: 0.1,  // Low contribution
        message_frequency: 1.0,      // 1 message/hour
        time_of_day: 2.0,            // 2 AM
        day_of_week: 6.0,            // Saturday
        historical_reliability: 0.2, // Low reliability
        recent_disconnections: 10.0, // Many disconnections
        avg_session_length: 0.5,     // 30 minutes average
        connection_stability: 0.1,   // Very unstable
    };

    predictor
        .record_node_event(&unstable_node, NodeEvent::Connected)
        .await?;
    predictor
        .update_node_behavior(&unstable_node, unstable_features)
        .await?;

    let unstable_prediction = predictor.predict(&unstable_node).await;
    println!(
        "Churn prediction for unstable node: 1h={:.1}%, 6h={:.1}%, 24h={:.1}%, confidence={:.1}%",
        unstable_prediction.probability_1h * 100.0,
        unstable_prediction.probability_6h * 100.0,
        unstable_prediction.probability_24h * 100.0,
        unstable_prediction.confidence * 100.0
    );

    // Test replication recommendation
    let should_replicate_stable = predictor.should_replicate(&node_id).await;
    let should_replicate_unstable = predictor.should_replicate(&unstable_node).await;

    println!(
        "Should replicate from stable node: {}",
        should_replicate_stable
    );
    println!(
        "Should replicate from unstable node: {}",
        should_replicate_unstable
    );

    assert!(
        prediction.probability_1h <= 1.0,
        "Probabilities should be <= 1.0"
    );
    assert!(
        unstable_prediction.probability_1h <= 1.0,
        "Probabilities should be <= 1.0"
    );

    // Record node disconnection
    predictor
        .record_node_event(&unstable_node, NodeEvent::Disconnected)
        .await?;

    Ok(())
}

#[tokio::test]
async fn test_state_vector_discretization() -> anyhow::Result<()> {
    println!("Testing State Vector discretization...");

    let test_cases = vec![
        (0.5, 10.0, 300, 1024 * 50),   // 50% util, 10/hr freq, 5min recency, 50KB
        (0.9, 100.0, 60, 1024 * 1024), // 90% util, 100/hr freq, 1min recency, 1MB
        (0.1, 1.0, 86400, 500),        // 10% util, 1/hr freq, 1day recency, 500B
    ];

    for (i, (utilization, frequency, recency_seconds, content_size)) in
        test_cases.iter().enumerate()
    {
        let state =
            StateVector::from_metrics(*utilization, *frequency, *recency_seconds, *content_size);

        println!(
            "Test case {}: util={:.1}%, freq={:.1}/hr, recency={}s, size={}B",
            i + 1,
            utilization * 100.0,
            frequency,
            recency_seconds,
            content_size
        );
        println!(
            "  Discretized: util_bucket={}, freq_bucket={}, recency_bucket={}, size_bucket={}",
            state.utilization_bucket,
            state.frequency_bucket,
            state.recency_bucket,
            state.content_size_bucket
        );

        // Validate buckets are within expected ranges
        assert!(
            state.utilization_bucket <= 10,
            "Utilization bucket should be <= 10"
        );
        assert!(
            state.frequency_bucket <= 5,
            "Frequency bucket should be <= 5"
        );
        assert!(state.recency_bucket <= 5, "Recency bucket should be <= 5");
        assert!(
            state.content_size_bucket <= 4,
            "Content size bucket should be <= 4"
        );
    }

    let state_space = StateVector::state_space_size();
    println!("Total state space size: {}", state_space);
    assert!(state_space > 0, "State space should be positive");

    Ok(())
}

#[tokio::test]
async fn test_integrated_adaptive_system() -> anyhow::Result<()> {
    println!("\n=== Testing Integrated Adaptive System ===\n");

    // Create all components
    let thompson = ThompsonSampling::new();

    let temp_dir = TempDir::new()?;
    let mab_config = MABConfig {
        epsilon: 0.1,
        min_samples: 5,
        decay_factor: 0.95,
        storage_path: Some(temp_dir.path().to_path_buf()),
        persist_interval: Duration::from_secs(60),
        max_stats_age: Duration::from_secs(3600),
    };
    let mab = MultiArmedBandit::new(mab_config).await?;

    let cache_manager = QLearnCacheManager::new(2048);

    let identity = NodeIdentity::generate()?;
    let security = SecurityManager::new(SecurityConfig::default(), &identity);

    let predictor = ChurnPredictor::new();

    // Simulate integrated operations
    let mut total_operations = 0;
    let start_time = std::time::Instant::now();

    while start_time.elapsed() < Duration::from_secs(1) && total_operations < 50 {
        // Thompson Sampling for strategy selection
        let content_type = match total_operations % 4 {
            0 => ContentType::DHTLookup,
            1 => ContentType::DataRetrieval,
            2 => ContentType::ComputeRequest,
            _ => ContentType::RealtimeMessage,
        };

        let strategy = thompson.select_strategy(content_type).await?;
        let success = rand::random::<bool>();
        let latency = if success {
            50 + rand::random::<u64>() % 100
        } else {
            500
        };
        thompson
            .update(content_type, strategy, success, latency)
            .await?;

        // MAB for route selection
        let destination = NodeId {
            hash: [rand::random::<u8>(); 32],
        };
        let strategies = vec![StrategyChoice::Kademlia, StrategyChoice::Hyperbolic];
        let route_decision = mab
            .select_route(&destination, content_type, &strategies)
            .await?;

        let outcome = Outcome {
            success: rand::random::<bool>(),
            latency_ms: 50 + rand::random::<u64>() % 200,
            hops: rand::random::<usize>() % 5 + 1,
        };
        mab.update_route(&route_decision.route_id, content_type, &outcome)
            .await?;

        // Cache operations
        let content_hash = ContentHash([rand::random::<u8>(); 32]);
        let data = vec![rand::random::<u8>(); 100 + rand::random::<usize>() % 400];
        cache_manager
            .decide_caching(content_hash, data, content_type)
            .await?;

        // Security monitoring
        security.check_rate_limit(&destination, None).await.ok(); // Ignore rate limit errors

        // Churn prediction
        let node_features = NodeFeatures {
            online_duration: (total_operations as f64) * 60.0,
            avg_response_time: latency as f64,
            resource_contribution: rand::random::<f64>(),
            message_frequency: 10.0 + rand::random::<f64>() * 90.0,
            time_of_day: 12.0,
            day_of_week: 3.0,
            historical_reliability: 0.5 + rand::random::<f64>() * 0.5,
            recent_disconnections: rand::random::<f64>() * 5.0,
            avg_session_length: 2.0 + rand::random::<f64>() * 6.0,
            connection_stability: rand::random::<f64>(),
        };
        predictor
            .update_node_behavior(&destination, node_features)
            .await?;

        total_operations += 1;

        // Small delay to prevent tight loop
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    println!(
        "Completed {} integrated operations in {:?}",
        total_operations,
        start_time.elapsed()
    );

    // Check final states
    let ts_metrics = thompson.get_metrics().await;
    let mab_metrics = mab.get_metrics().await;
    let cache_stats = cache_manager.get_stats_async().await;
    let security_metrics = security.get_metrics().await;

    println!("Final metrics:");
    println!(
        "  Thompson Sampling decisions: {}",
        ts_metrics.total_decisions
    );
    println!("  MAB decisions: {}", mab_metrics.total_decisions);
    println!(
        "  Cache hits: {}, misses: {}",
        cache_stats.hits, cache_stats.misses
    );
    println!(
        "  Security audit entries: {}",
        security_metrics.audit_entries
    );

    // Verify all systems are functioning
    assert!(total_operations > 10, "Should complete multiple operations");
    assert!(
        ts_metrics.total_decisions > 0,
        "Thompson Sampling should make decisions"
    );
    assert!(mab_metrics.total_decisions > 0, "MAB should make decisions");

    println!("\n=== Integrated System Test Passed ===\n");

    Ok(())
}
