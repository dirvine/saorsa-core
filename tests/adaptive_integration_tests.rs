//! Adaptive integration tests aligned with current APIs
use saorsa_core::adaptive::*;
use saorsa_core::adaptive::q_learning_cache::{ActionType, StateVector};
use std::sync::Arc;

#[tokio::test]
async fn test_q_learning_manager_updates_q_values() -> anyhow::Result<()> {
    let mut cfg = QLearningConfig::default();
    cfg.learning_rate = 0.5;
    cfg.discount_factor = 0.9;
    cfg.epsilon = 0.0;
    cfg.buffer_size = 128;
    cfg.batch_size = 8;

    let manager = QLearningCacheManager::new(cfg, 10 * 1024 * 1024);

    let s1 = StateVector::from_metrics(0.2, 2.0, 30, 2048);
    let s2 = StateVector::from_metrics(0.3, 4.0, 10, 4096);

    let before = manager.get_q_value(&s1, ActionType::Cache).await;
    assert_eq!(before, 0.0);

    manager
        .update_q_value(&s1, ActionType::Cache, 1.0, &s2, false)
        .await?;

    let after = manager.get_q_value(&s1, ActionType::Cache).await;
    assert!(after > before);
    Ok(())
}

#[tokio::test]
async fn test_security_manager_validate_join() -> anyhow::Result<()> {
    let identity = saorsa_core::identity::NodeIdentity::generate()?;
    let sm = SecurityManager::new(SecurityConfig::default(), &identity);

    let desc = NodeDescriptor {
        id: identity.to_user_id(),
        public_key: identity.public_key().clone(),
        addresses: vec!["127.0.0.1:0".to_string()],
        hyperbolic: None,
        som_position: None,
        trust: 0.5,
        capabilities: NodeCapabilities {
            storage: 1,
            compute: 1,
            bandwidth: 1,
        },
    };

    sm.validate_node_join(&desc).await?;
    sm.check_rate_limit(&desc.id, None).await?;
    Ok(())
}

#[tokio::test]
async fn test_adaptive_router_routes_with_registered_strategy() -> anyhow::Result<()> {
    let trust = Arc::new(MockTrustProvider::new());
    let hyper = Arc::new(HyperbolicSpace::new());
    let som = Arc::new(SelfOrganizingMap::new(SomConfig {
        initial_learning_rate: 0.3,
        initial_radius: 5.0,
        iterations: 100,
        grid_size: GridSize::Fixed(4, 4),
    }));
    let router = AdaptiveRouter::new(trust, hyper, som);

    struct DirectStrategy;
    #[async_trait::async_trait]
    impl RoutingStrategy for DirectStrategy {
        async fn find_path(&self, target: &NodeId) -> Result<Vec<NodeId>> {
            Ok(vec![target.clone()])
        }
        fn route_score(&self, _from: &NodeId, _to: &NodeId) -> f64 { 1.0 }
        fn update_metrics(&mut self, _path: &[NodeId], _success: bool) {}
    }

    router
        .register_strategy(StrategyChoice::Kademlia, Box::new(DirectStrategy))
        .await;

    let target = NodeId::from_bytes([1u8; 32]);
    let path = router.route(&target, ContentType::DHTLookup).await?;
    assert_eq!(path.len(), 1);
    assert_eq!(path[0], target);
    Ok(())
}

