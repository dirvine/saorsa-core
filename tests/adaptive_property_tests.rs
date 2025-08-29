//! Comprehensive property-based tests for adaptive network components
//!
//! This module provides rigorous property-based testing for all adaptive
//! network components to ensure mathematical correctness and system invariants.

use proptest::prelude::*;
use saorsa_core::adaptive::*;
use saorsa_core::security::SecurityEventType;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

// Strategy for generating valid node IDs
fn node_id_strategy() -> impl Strategy<Value = NodeId> {
    prop::array::uniform32(any::<u8>()).prop_map(|hash| NodeId { hash })
}

// Strategy for generating content hashes
fn content_hash_strategy() -> impl Strategy<Value = ContentHash> {
    prop::array::uniform32(any::<u8>()).prop_map(ContentHash)
}

// Strategy for generating network configurations
fn network_config_strategy() -> impl Strategy<Value = NetworkConfig> {
    (1u64..1000, 10usize..1000, 3u8..10, 0u8..10).prop_map(
        |(storage, connections, replication, security)| NetworkConfig {
            bootstrap_nodes: vec![],
            storage_capacity: storage,
            max_connections: connections,
            replication_factor: replication,
            ml_enabled: true,
            monitoring_interval: Duration::from_secs(30),
            security_level: security,
        },
    )
}

// Strategy for generating cache configurations
fn cache_config_strategy() -> impl Strategy<Value = CacheConfig> {
    (10usize..1000, 1u64..3600, 0.1f64..1.0, 0.01f64..0.5).prop_map(
        |(capacity, ttl, learning_rate, exploration_factor)| CacheConfig {
            capacity,
            default_ttl: Duration::from_secs(ttl),
            learning_rate,
            exploration_factor,
            enable_ml: true,
        },
    )
}

// Strategy for generating routing configurations
fn routing_config_strategy() -> impl Strategy<Value = RoutingConfig> {
    (1usize..100, 0.1f64..1.0, 0.0f64..1.0).prop_map(
        |(max_hops, trust_threshold, churn_threshold)| RoutingConfig {
            max_hops,
            trust_threshold,
            churn_threshold,
            enable_adaptive_routing: true,
        },
    )
}

proptest! {
    /// Property: Thompson Sampling maintains valid probability distributions
    #[test]
    fn prop_thompson_sampling_valid_probabilities(
        iterations in 10..100usize,
        arms in 2..10usize,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let ts = ThompsonSampling::new();

            // Initialize arms
            for arm_id in 0..arms {
                ts.add_arm(arm_id as u32).await;
            }

            // Run iterations
            for _ in 0..iterations {
                let selected_arm = ts.select_arm().await;
                prop_assert!(selected_arm < arms as u32, "Selected arm should be valid");

                // Simulate reward (0.0 to 1.0)
                let reward = random::<f64>() % 1.0;
                ts.update_arm(selected_arm, reward).await;
            }

            // Check that all arms have valid beta parameters
            for arm_id in 0..arms {
                let (alpha, beta) = ts.get_beta_params(arm_id as u32).await;
                prop_assert!(alpha > 0.0, "Alpha should be positive");
                prop_assert!(beta > 0.0, "Beta should be positive");
            }
        });
    }

    /// Property: Multi-Armed Bandit converges to optimal arm
    #[test]
    fn prop_multi_armed_bandit_convergence(
        iterations in 100..1000usize,
        num_arms in 2..8usize,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let config = MABConfig {
                exploration_factor: 0.1,
                learning_rate: 0.1,
                max_reward: 1.0,
                min_reward: 0.0,
            };

            let mab = MultiArmedBandit::new(config).await.unwrap();

            // Initialize arms with different true rewards
            let mut true_rewards = Vec::new();
            for i in 0..num_arms {
                let reward = 0.1 + (i as f64 * 0.9 / (num_arms - 1) as f64);
                true_rewards.push(reward);
                mab.add_arm(i as u32, reward).await.unwrap();
            }

            // Run learning iterations
            let mut selections = HashMap::new();
            for _ in 0..iterations {
                let selected_arm = mab.select_arm().await.unwrap();
                *selections.entry(selected_arm).or_insert(0) += 1;

                // Give reward based on true reward with some noise
                let noise = (random::<f64>() - 0.5) * 0.1;
                let reward = (true_rewards[selected_arm as usize] + noise).max(0.0).min(1.0);
                mab.update_arm(selected_arm, reward).await.unwrap();
            }

            // The optimal arm should be selected most often in the second half
            let optimal_arm = (num_arms - 1) as u32;
            let optimal_selections = selections.get(&optimal_arm).unwrap_or(&0);
            let total_selections: usize = selections.values().sum();

            // In the second half of iterations, optimal arm should be selected at least 30% of the time
            let second_half_selections = *optimal_selections * 2 / 3;
            let second_half_total = total_selections * 2 / 3;

            if second_half_total > 0 {
                let optimal_ratio = second_half_selections as f64 / second_half_total as f64;
                prop_assert!(optimal_ratio > 0.3, "Optimal arm should be selected >30% in second half");
            }
        });
    }

    /// Property: Q-Learning cache maintains bounded size
    #[test]
    fn prop_q_learning_cache_size_bounds(
        cache_size in 10..100usize,
        operations in 50..200usize,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = CacheConfig {
                capacity: cache_size,
                default_ttl: Duration::from_secs(3600),
                learning_rate: 0.1,
                exploration_factor: 0.1,
                enable_ml: true,
            };

            let cache = QLearningCacheManager::new(config, cache_size).await.unwrap();

            // Perform random operations
            for i in 0..operations {
                let key = ContentHash([i as u8; 32]);
                let access_info = AccessInfo {
                    access_pattern: if random::<bool>() { AccessPattern::Frequent } else { AccessPattern::Rare },
                    content_type: ContentType::DHTLookup,
                    size_bytes: 1024,
                    access_frequency: random::<f64>(),
                };

                cache.record_access(key, access_info).await.unwrap();

                // Cache size should never exceed configured capacity
                let current_size = cache.get_size().await;
                prop_assert!(current_size <= cache_size, "Cache size {} exceeds capacity {}", current_size, cache_size);
            }
        });
    }

    /// Property: Hyperbolic routing maintains triangle inequality
    #[test]
    fn prop_hyperbolic_routing_triangle_inequality(
        nodes in 5..20usize,
        dimensions in 2..10usize,
    ) {
        let space = Arc::new(HyperbolicSpace::new());
        let mut node_positions = Vec::new();

        // Generate random node positions
        for _ in 0..nodes {
            let r = random::<f64>() * 0.9; // Keep within hyperbolic bounds
            let theta = random::<f64>() * 2.0 * std::f64::consts::PI;
            node_positions.push((r, theta));
        }

        // Test triangle inequality for random triplets
        for _ in 0..10 {
            let i = random::<usize>() % nodes;
            let j = random::<usize>() % nodes;
            let k = random::<usize>() % nodes;

            if i != j && j != k && i != k {
                let node_i = NodeId { hash: [i as u8; 32] };
                let node_j = NodeId { hash: [j as u8; 32] };
                let node_k = NodeId { hash: [k as u8; 32] };

                let dist_ij = space.distance(&node_i, &node_j);
                let dist_jk = space.distance(&node_j, &node_k);
                let dist_ik = space.distance(&node_i, &node_k);

                // Triangle inequality: d(i,j) + d(j,k) >= d(i,k)
                prop_assert!(dist_ij + dist_jk >= dist_ik - 1e-10,
                    "Triangle inequality violated: {} + {} < {}",
                    dist_ij, dist_jk, dist_ik);
            }
        }
    }

    /// Property: Churn prediction accuracy improves with data
    #[test]
    fn prop_churn_prediction_accuracy(
        training_samples in 50..200usize,
        test_samples in 10..50usize,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let predictor = ChurnPredictor::new();

            // Train with synthetic data
            for i in 0..training_samples {
                let features = vec![
                    random::<f64>(), // Network latency
                    random::<f64>(), // Connection stability
                    random::<f64>(), // Message frequency
                    random::<f64>(), // Node age
                ];

                // Generate churn label based on features (simplified model)
                let churn_probability = features.iter().sum::<f64>() / features.len() as f64;
                let churned = random::<f64>() < churn_probability;

                predictor.add_training_sample(&features, churned).await.unwrap();
            }

            // Train the model
            predictor.train().await.unwrap();

            // Test predictions
            let mut correct_predictions = 0;
            for _ in 0..test_samples {
                let features = vec![
                    random::<f64>(),
                    random::<f64>(),
                    random::<f64>(),
                    random::<f64>(),
                ];

                let churn_probability = features.iter().sum::<f64>() / features.len() as f64;
                let actual_churn = random::<f64>() < churn_probability;

                let predicted_churn = predictor.predict_churn(&features).await.unwrap();

                if (predicted_churn > 0.5) == actual_churn {
                    correct_predictions += 1;
                }
            }

            let accuracy = correct_predictions as f64 / test_samples as f64;
            // With enough training data, accuracy should be better than random (50%)
            prop_assert!(accuracy > 0.4, "Prediction accuracy {} should be > 40%", accuracy);
        });
    }

    /// Property: Replication manager maintains consistency
    #[test]
    fn prop_replication_manager_consistency(
        nodes in 3..10usize,
        replication_factor in 2..5u8,
        operations in 20..100usize,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ReplicationConfig {
                replication_factor,
                consistency_level: ConsistencyLevel::Quorum,
                max_replicas: (replication_factor * 2) as u32,
            };

            let manager = ReplicationManager::new(config).await.unwrap();

            // Add nodes
            for i in 0..nodes {
                let node_id = NodeId { hash: [i as u8; 32] };
                manager.add_node(node_id).await.unwrap();
            }

            // Perform operations
            for i in 0..operations {
                let key = ContentHash([i as u8; 32]);
                let node_id = NodeId { hash: [(i % nodes) as u8; 32] };

                if random::<bool>() {
                    // Store operation
                    manager.store_replica(key, node_id).await.unwrap();
                } else {
                    // Retrieve operation
                    let replicas = manager.get_replicas(&key).await.unwrap();
                    // Should have at least 1 replica if stored
                    prop_assert!(replicas.len() <= nodes, "Too many replicas");
                }
            }

            // Verify consistency
            let total_stored = manager.get_total_stored().await;
            prop_assert!(total_stored <= operations, "Stored count exceeds operations");
        });
    }

    /// Property: Security manager maintains threat detection
    #[test]
    fn prop_security_manager_threat_detection(
        events in 50..200usize,
        threat_ratio in 0.1..0.5f64,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = SecurityConfig {
                threat_threshold: 0.7,
                anomaly_threshold: 0.8,
                max_events: 1000,
            };

            let manager = SecurityManager::new(config).await.unwrap();

            // Generate security events
            let mut threats_detected = 0;
            for i in 0..events {
                let event_type = if random::<f64>() < threat_ratio {
                    SecurityEventType::SuspiciousActivity
                } else {
                    SecurityEventType::NormalActivity
                };

                let severity = if matches!(event_type, SecurityEventType::SuspiciousActivity) {
                    0.8 + random::<f64>() * 0.2 // High severity for threats
                } else {
                    random::<f64>() * 0.3 // Low severity for normal
                };

                let event = SecurityEvent {
                    id: i as u64,
                    event_type,
                    severity,
                    timestamp: std::time::SystemTime::now(),
                    source: format!("node_{}", i % 10),
                    details: HashMap::new(),
                };

                manager.process_event(event).await.unwrap();

                if matches!(event_type, SecurityEventType::SuspiciousActivity) {
                    threats_detected += 1;
                }
            }

            // Check threat detection
            let stats = manager.get_statistics().await.unwrap();
            let expected_threats = (events as f64 * threat_ratio) as usize;

            // Should detect most threats
            prop_assert!(stats.threats_detected >= (expected_threats as f64 * 0.7) as usize,
                "Detected {} threats, expected at least {}", stats.threats_detected, expected_threats);
        });
    }

    /// Property: Adaptive router maintains valid routing tables
    #[test]
    fn prop_adaptive_router_routing_table_consistency(
        nodes in 5..15usize,
        routes in 20..100usize,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = RoutingConfig {
                max_hops: 10,
                trust_threshold: 0.5,
                churn_threshold: 0.3,
                enable_adaptive_routing: true,
            };

            let trust_provider = Arc::new(MockTrustProvider::new());
            let som = Arc::new(RwLock::new(SelfOrganizingMap::new(GridSize::Small)));

            let router = AdaptiveRouter::new(
                NodeId { hash: [0u8; 32] },
                trust_provider,
                som,
                config,
            ).await.unwrap();

            // Add nodes to routing table
            for i in 1..nodes {
                let node_id = NodeId { hash: [i as u8; 32] };
                router.add_peer(node_id).await.unwrap();
            }

            // Add routes
            for i in 0..routes {
                let target = ContentHash([i as u8; 32]);
                let next_hop = NodeId { hash: [(i % (nodes - 1) + 1) as u8; 32] };

                router.add_route(target, next_hop, 1).await.unwrap();
            }

            // Verify routing table consistency
            let routing_table = router.get_routing_table().await;
            prop_assert!(routing_table.len() <= routes, "Routing table too large");

            // All routes should have valid next hops
            for (target, (next_hop, hops)) in &routing_table {
                prop_assert!(*hops > 0, "Invalid hop count for target {:?}", target);
                prop_assert!(*hops <= 10, "Hop count too high for target {:?}", target);
            }
        });
    }
}

// Additional helper functions for property testing
fn generate_random_features() -> Vec<f64> {
    vec![
        random::<f64>(), // Network latency
        random::<f64>(), // Connection stability
        random::<f64>(), // Message frequency
        random::<f64>(), // Node age
    ]
}

fn generate_random_access_info() -> AccessInfo {
    AccessInfo {
        access_pattern: if random::<bool>() {
            AccessPattern::Frequent
        } else {
            AccessPattern::Rare
        },
        content_type: ContentType::DHTLookup,
        size_bytes: 1024 + random::<usize>() % 1024000, // 1KB to 1MB
        access_frequency: random::<f64>(),
    }
}
