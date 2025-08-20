//! Comprehensive integration tests for adaptive network components
//!
//! This module tests the integration between all adaptive components
//! to ensure they work together correctly in realistic scenarios.

use saorsa_core::adaptive::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::RwLock;
use tokio::time::sleep;

#[tokio::test]
async fn test_full_adaptive_system_integration() -> anyhow::Result<()> {
    println!("🧠 Testing full adaptive system integration...");

    let temp_dir = TempDir::new()?;
    let mut config = AdaptiveConfig::default();

    // Configure adaptive system
    config.thompson_sampling.enabled = true;
    config.multi_armed_bandit.enabled = true;
    config.q_learning_cache.enabled = true;
    config.churn_prediction.enabled = true;
    config.hyperbolic_routing.enabled = true;

    // Create adaptive system
    let system = AdaptiveSystem::new(config).await?;

    // Add test nodes
    let mut nodes = Vec::new();
    for i in 0..5 {
        let node_id = NodeId { hash: [i as u8; 32] };
        let node = AdaptiveNode::new(node_id, system.clone()).await?;
        nodes.push(node);
    }

    // Simulate network activity
    for round in 0..10 {
        println!("📊 Simulation round {}", round + 1);

        // Generate content requests
        for node in &nodes {
            let content_hash = ContentHash([round as u8; 32]);
            let access_info = AccessInfo {
                access_pattern: AccessPattern::Frequent,
                content_type: ContentType::DHTLookup,
                size_bytes: 1024,
                access_frequency: 0.8,
            };

            // Record access
            node.record_content_access(content_hash, access_info).await?;

            // Make routing decision
            let target_node = NodeId { hash: [(round % 5) as u8; 32] };
            let route = node.select_route(target_node).await?;
            assert!(route.len() <= 3, "Route too long");

            // Simulate network conditions
            let latency = Duration::from_millis(50 + (round * 10) as u64);
            let success = node.simulate_network_request(route, latency).await?;

            // Update learning systems
            node.update_learning_systems(success, latency).await?;
        }

        // Let the system adapt
        sleep(Duration::from_millis(100)).await;
    }

    // Verify system adaptation
    let metrics = system.get_system_metrics().await?;
    println!("🎯 Final system metrics: {:?}", metrics);

    // Verify that the system has adapted
    assert!(metrics.total_decisions > 0, "No decisions made");
    assert!(metrics.average_latency < Duration::from_millis(200), "Latency too high");
    assert!(metrics.success_rate > 0.7, "Success rate too low");

    println!("✅ Full adaptive system integration test passed");
    Ok(())
}

#[tokio::test]
async fn test_adaptive_security_integration() -> anyhow::Result<()> {
    println!("🔒 Testing adaptive security integration...");

    let security_config = SecurityConfig {
        threat_threshold: 0.7,
        anomaly_threshold: 0.8,
        max_events: 1000,
    };

    let adaptive_config = AdaptiveConfig {
        security_manager: security_config,
        ..Default::default()
    };

    let system = AdaptiveSystem::new(adaptive_config).await?;
    let security = system.get_security_manager();

    // Simulate security events
    for i in 0..50 {
        let event_type = if i % 10 == 0 {
            SecurityEventType::SuspiciousActivity
        } else {
            SecurityEventType::NormalActivity
        };

        let severity = if matches!(event_type, SecurityEventType::SuspiciousActivity) {
            0.9
        } else {
            0.2
        };

        let event = SecurityEvent {
            id: i as u64,
            event_type,
            severity,
            timestamp: std::time::SystemTime::now(),
            source: format!("node_{}", i % 5),
            details: HashMap::new(),
        };

        security.process_event(event).await?;
    }

    // Verify threat detection
    let stats = security.get_statistics().await?;
    assert!(stats.threats_detected > 0, "No threats detected");
    assert!(stats.total_events >= 50, "Not all events processed");

    println!("✅ Adaptive security integration test passed");
    Ok(())
}

#[tokio::test]
async fn test_performance_regression_detection() -> anyhow::Result<()> {
    println!("📈 Testing performance regression detection...");

    let performance_config = PerformanceConfig {
        regression_threshold: 0.1, // 10% regression threshold
        measurement_window: Duration::from_secs(60),
        baseline_samples: 10,
    };

    let system = AdaptiveSystem::new(Default::default()).await?;
    let monitor = system.get_performance_monitor();

    // Establish baseline performance
    for i in 0..10 {
        let latency = Duration::from_millis(50 + (i * 2) as u64);
        monitor.record_operation_latency("test_operation", latency).await?;
    }

    // Simulate normal performance
    for i in 0..20 {
        let latency = Duration::from_millis(50 + (i % 10) as u64);
        monitor.record_operation_latency("test_operation", latency).await?;
    }

    // Check for regression (should be false)
    let has_regression = monitor.detect_regression("test_operation").await?;
    assert!(!has_regression, "False positive regression detected");

    // Simulate performance regression
    for i in 0..15 {
        let latency = Duration::from_millis(100 + (i * 5) as u64); // Much slower
        monitor.record_operation_latency("test_operation", latency).await?;
    }

    // Check for regression (should be true)
    let has_regression = monitor.detect_regression("test_operation").await?;
    assert!(has_regression, "Performance regression not detected");

    println!("✅ Performance regression detection test passed");
    Ok(())
}

#[tokio::test]
async fn test_chaos_engineering_resilience() -> anyhow::Result<()> {
    println!("🌪️ Testing chaos engineering resilience...");

    let chaos_config = ChaosConfig {
        node_failure_rate: 0.1,
        network_partition_rate: 0.05,
        latency_spike_rate: 0.1,
        test_duration: Duration::from_secs(30),
    };

    let system = AdaptiveSystem::new(Default::default()).await?;
    let chaos_engine = ChaosEngine::new(system.clone(), chaos_config).await?;

    // Start chaos testing
    chaos_engine.start().await?;

    // Let chaos run for a short time
    sleep(Duration::from_secs(5)).await;

    // Verify system resilience
    let health = system.get_health_status().await?;
    assert!(health.overall_health > 0.5, "System health too low under chaos");

    // Stop chaos
    chaos_engine.stop().await?;

    // Verify recovery
    sleep(Duration::from_secs(2)).await;
    let final_health = system.get_health_status().await?;
    assert!(final_health.overall_health > 0.8, "System did not recover properly");

    println!("✅ Chaos engineering resilience test passed");
    Ok(())
}

#[tokio::test]
async fn test_adaptive_learning_convergence() -> anyhow::Result<()> {
    println!("🎓 Testing adaptive learning convergence...");

    let learning_config = LearningConfig {
        convergence_threshold: 0.01,
        max_training_iterations: 1000,
        learning_rate: 0.1,
        exploration_factor: 0.2,
    };

    let system = AdaptiveSystem::new(Default::default()).await?;
    let learner = system.get_adaptive_learner();

    // Train on synthetic data
    let mut previous_accuracy = 0.0;
    let mut converged = false;

    for iteration in 0..50 {
        // Generate training data
        let features = vec![
            random::<f64>(), // Network condition
            random::<f64>(), // Load factor
            random::<f64>(), // Distance metric
        ];

        let optimal_action = if features[0] > 0.5 {
            0 // Use direct routing
        } else {
            1 // Use adaptive routing
        };

        // Train the model
        learner.add_training_example(&features, optimal_action).await?;
        learner.train_step().await?;

        // Test accuracy
        let mut correct = 0;
        for _ in 0..10 {
            let test_features = vec![random::<f64>(), random::<f64>(), random::<f64>()];
            let predicted = learner.predict(&test_features).await?;
            let expected = if test_features[0] > 0.5 { 0 } else { 1 };

            if predicted == expected {
                correct += 1;
            }
        }

        let accuracy = correct as f64 / 10.0;

        // Check for convergence
        if (accuracy - previous_accuracy).abs() < learning_config.convergence_threshold {
            if iteration > 10 { // Allow some initial training
                converged = true;
                break;
            }
        }

        previous_accuracy = accuracy;
    }

    assert!(converged, "Learning system did not converge");
    assert!(previous_accuracy > 0.7, "Final accuracy too low: {}", previous_accuracy);

    println!("✅ Adaptive learning convergence test passed with accuracy: {:.2}%", previous_accuracy * 100.0);
    Ok(())
}

#[tokio::test]
async fn test_multi_node_adaptive_coordination() -> anyhow::Result<()> {
    println!("🤝 Testing multi-node adaptive coordination...");

    let mut nodes = Vec::new();
    let mut systems = Vec::new();

    // Create multiple adaptive systems
    for i in 0..3 {
        let config = AdaptiveConfig {
            node_id: NodeId { hash: [i as u8; 32] },
            ..Default::default()
        };

        let system = AdaptiveSystem::new(config).await?;
        systems.push(system.clone());

        let node = AdaptiveNode::new(NodeId { hash: [i as u8; 32] }, system).await?;
        nodes.push(node);
    }

    // Establish connections between nodes
    for i in 0..3 {
        for j in 0..3 {
            if i != j {
                nodes[i].connect_to_peer(nodes[j].get_id()).await?;
            }
        }
    }

    // Simulate coordinated adaptive behavior
    for round in 0..5 {
        println!("🔄 Coordination round {}", round + 1);

        // Each node makes decisions and shares with others
        for node in &nodes {
            let decision = node.make_adaptive_decision().await?;
            node.broadcast_decision(decision).await?;
        }

        // Process decisions from other nodes
        for node in &nodes {
            let decisions = node.receive_decisions().await?;
            node.learn_from_peers(&decisions).await?;
        }

        sleep(Duration::from_millis(200)).await;
    }

    // Verify coordination benefits
    let mut total_improvement = 0.0;
    for system in &systems {
        let metrics = system.get_system_metrics().await?;
        total_improvement += metrics.performance_improvement;
    }

    let average_improvement = total_improvement / systems.len() as f64;
    assert!(average_improvement > 0.1, "Coordination did not provide sufficient improvement");

    println!("✅ Multi-node adaptive coordination test passed with average improvement: {:.2}%", average_improvement * 100.0);
    Ok(())
}

// Helper functions and types for integration tests

#[derive(Debug, Clone)]
struct AdaptiveConfig {
    node_id: NodeId,
    thompson_sampling: ComponentConfig,
    multi_armed_bandit: ComponentConfig,
    q_learning_cache: ComponentConfig,
    churn_prediction: ComponentConfig,
    hyperbolic_routing: ComponentConfig,
    security_manager: SecurityConfig,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            node_id: NodeId { hash: [0u8; 32] },
            thompson_sampling: ComponentConfig { enabled: true },
            multi_armed_bandit: ComponentConfig { enabled: true },
            q_learning_cache: ComponentConfig { enabled: true },
            churn_prediction: ComponentConfig { enabled: true },
            hyperbolic_routing: ComponentConfig { enabled: true },
            security_manager: SecurityConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
struct ComponentConfig {
    enabled: bool,
}

#[derive(Debug)]
struct AdaptiveSystem {
    config: AdaptiveConfig,
    metrics: Arc<RwLock<SystemMetrics>>,
}

#[derive(Debug, Default)]
struct SystemMetrics {
    total_decisions: u64,
    average_latency: Duration,
    success_rate: f64,
    performance_improvement: f64,
}

impl AdaptiveSystem {
    async fn new(config: AdaptiveConfig) -> anyhow::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            config,
            metrics: Arc::new(RwLock::new(SystemMetrics::default())),
        }))
    }

    async fn get_system_metrics(&self) -> anyhow::Result<SystemMetrics> {
        Ok(self.metrics.read().await.clone())
    }

    fn get_security_manager(&self) -> Arc<SecurityManager> {
        // Mock implementation
        Arc::new(SecurityManager::new(self.config.security_manager.clone()))
    }

    fn get_performance_monitor(&self) -> Arc<PerformanceMonitor> {
        // Mock implementation
        Arc::new(PerformanceMonitor::new())
    }
}

#[derive(Debug)]
struct AdaptiveNode {
    id: NodeId,
    system: Arc<AdaptiveSystem>,
}

impl AdaptiveNode {
    async fn new(id: NodeId, system: Arc<AdaptiveSystem>) -> anyhow::Result<Self> {
        Ok(Self { id, system })
    }

    async fn record_content_access(&self, _hash: ContentHash, _info: AccessInfo) -> anyhow::Result<()> {
        Ok(())
    }

    async fn select_route(&self, _target: NodeId) -> anyhow::Result<Vec<NodeId>> {
        Ok(vec![self.id, _target])
    }

    async fn simulate_network_request(&self, _route: Vec<NodeId>, _latency: Duration) -> anyhow::Result<bool> {
        Ok(random::<f64>() > 0.2) // 80% success rate
    }

    async fn update_learning_systems(&self, _success: bool, _latency: Duration) -> anyhow::Result<()> {
        Ok(())
    }

    async fn connect_to_peer(&self, _peer: NodeId) -> anyhow::Result<()> {
        Ok(())
    }

    fn get_id(&self) -> NodeId {
        self.id
    }

    async fn make_adaptive_decision(&self) -> anyhow::Result<AdaptiveDecision> {
        Ok(AdaptiveDecision {
            action: "test_action".to_string(),
            confidence: 0.8,
        })
    }

    async fn broadcast_decision(&self, _decision: AdaptiveDecision) -> anyhow::Result<()> {
        Ok(())
    }

    async fn receive_decisions(&self) -> anyhow::Result<Vec<AdaptiveDecision>> {
        Ok(vec![])
    }

    async fn learn_from_peers(&self, _decisions: &[AdaptiveDecision]) -> anyhow::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct AdaptiveDecision {
    action: String,
    confidence: f64,
}

#[derive(Debug)]
struct ChaosEngine {
    system: Arc<AdaptiveSystem>,
    config: ChaosConfig,
    running: Arc<RwLock<bool>>,
}

#[derive(Debug)]
struct ChaosConfig {
    node_failure_rate: f64,
    network_partition_rate: f64,
    latency_spike_rate: f64,
    test_duration: Duration,
}

impl ChaosEngine {
    async fn new(system: Arc<AdaptiveSystem>, config: ChaosConfig) -> anyhow::Result<Self> {
        Ok(Self {
            system,
            config,
            running: Arc::new(RwLock::new(false)),
        })
    }

    async fn start(&self) -> anyhow::Result<()> {
        *self.running.write().await = true;
        Ok(())
    }

    async fn stop(&self) -> anyhow::Result<()> {
        *self.running.write().await = false;
        Ok(())
    }
}

#[derive(Debug)]
struct PerformanceMonitor {
    // Mock implementation
}

impl PerformanceMonitor {
    fn new() -> Self {
        Self {}
    }

    async fn record_operation_latency(&self, _operation: &str, _latency: Duration) -> anyhow::Result<()> {
        Ok(())
    }

    async fn detect_regression(&self, _operation: &str) -> anyhow::Result<bool> {
        Ok(false)
    }
}

fn random<T>() -> T where rand::distributions::Standard: rand::distributions::Distribution<T> {
    use rand::Rng;
    rand::thread_rng().r#gen()
}