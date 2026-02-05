use crate::dht::core_engine::{DhtCoreEngine, NodeCapacity, NodeId, NodeInfo};
use std::time::SystemTime;

#[tokio::test]
async fn test_ip_diversity_enforcement_ipv6() -> anyhow::Result<()> {
    // 1. Initialize Engine
    let mut engine = DhtCoreEngine::new_for_tests(NodeId::random())?;

    // 2. Create Node 1 (IPv6)
    let node1 = NodeInfo {
        id: NodeId::random(),
        address: "2001:db8::1".to_string(), // /64 subnet 2001:db8::
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };

    // 3. Create Node 2 (Same /64 subnet)
    let node2 = NodeInfo {
        id: NodeId::random(),
        address: "2001:db8::2".to_string(), // Same /64
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };

    // 4. Add Node 1 - Should Succeed
    engine.add_node(node1).await?;

    // 5. Add Node 2 - Should Fail (Default limit is 1 per /64)
    let result = engine.add_node(node2).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("IP diversity limits exceeded"),
        "Error should indicate IP diversity limits"
    );

    Ok(())
}

#[tokio::test]
async fn test_ip_diversity_enforcement_ipv4() -> anyhow::Result<()> {
    // Verify IPv4 addresses are now checked (security fix - IPv4 no longer bypasses)
    let mut engine = DhtCoreEngine::new_for_tests(NodeId::random())?;

    // First node should succeed
    let node1 = NodeInfo {
        id: NodeId::random(),
        address: "192.168.1.1".to_string(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node1).await?;

    // Second node on same IP should fail (default limit is 1 per IP for small networks)
    let node2 = NodeInfo {
        id: NodeId::random(),
        address: "192.168.1.1".to_string(), // Same IP
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    let result = engine.add_node(node2).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("IP diversity limits exceeded"),
        "Error should indicate IP diversity limits"
    );

    Ok(())
}

#[tokio::test]
async fn test_ipv4_subnet_24_limit() -> anyhow::Result<()> {
    // Test /24 subnet limit (default: 3x per-IP limit)
    let mut engine = DhtCoreEngine::new_for_tests(NodeId::random())?;

    // Add nodes on different IPs but same /24 subnet
    let node1 = NodeInfo {
        id: NodeId::random(),
        address: "192.168.1.1".to_string(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node1).await?;

    let node2 = NodeInfo {
        id: NodeId::random(),
        address: "192.168.1.2".to_string(), // Different IP, same /24
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node2).await?;

    let node3 = NodeInfo {
        id: NodeId::random(),
        address: "192.168.1.3".to_string(), // Different IP, same /24
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node3).await?;

    // Fourth node should fail (default /24 limit is 3)
    let node4 = NodeInfo {
        id: NodeId::random(),
        address: "192.168.1.4".to_string(), // Different IP, same /24
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    let result = engine.add_node(node4).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("IP diversity limits exceeded"),
        "Error should indicate IP diversity limits"
    );

    Ok(())
}

#[tokio::test]
async fn test_mixed_ipv4_ipv6_enforcement() -> anyhow::Result<()> {
    // Test that both IPv4 and IPv6 are enforced in the same engine
    let mut engine = DhtCoreEngine::new_for_tests(NodeId::random())?;

    // Add IPv4 node
    let node_v4 = NodeInfo {
        id: NodeId::random(),
        address: "192.168.1.1".to_string(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node_v4).await?;

    // Add IPv6 node (should succeed - different address family)
    let node_v6 = NodeInfo {
        id: NodeId::random(),
        address: "2001:db8::1".to_string(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node_v6).await?;

    // Second IPv4 on same IP should fail
    let node_v4_2 = NodeInfo {
        id: NodeId::random(),
        address: "192.168.1.1".to_string(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    let result_v4 = engine.add_node(node_v4_2).await;
    assert!(result_v4.is_err());

    // Second IPv6 on same /64 should also fail
    let node_v6_2 = NodeInfo {
        id: NodeId::random(),
        address: "2001:db8::2".to_string(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    let result_v6 = engine.add_node(node_v6_2).await;
    assert!(result_v6.is_err());

    Ok(())
}

#[tokio::test]
async fn test_geographic_diversity_allows_different_regions() -> anyhow::Result<()> {
    // Test that nodes from different geographic regions can be added
    // This verifies the geographic diversity enforcement doesn't block legitimate diversity
    let mut engine = DhtCoreEngine::new_for_tests(NodeId::random())?;

    // Add node from North America (192.x.x.x range)
    let node_na = NodeInfo {
        id: NodeId::random(),
        address: "192.168.1.1".to_string(), // NorthAmerica
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node_na).await?;

    // Add node from Europe (127-159 range)
    let node_eu = NodeInfo {
        id: NodeId::random(),
        address: "130.45.10.1".to_string(), // Europe
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node_eu).await?;

    // Add node from Asia Pacific (160-191 range)
    let node_ap = NodeInfo {
        id: NodeId::random(),
        address: "170.20.30.1".to_string(), // AsiaPacific
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node_ap).await?;

    // Add node from South America (224-239 range)
    let node_sa = NodeInfo {
        id: NodeId::random(),
        address: "225.1.1.1".to_string(), // SouthAmerica
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node_sa).await?;

    // All different regions should succeed
    Ok(())
}

#[tokio::test]
async fn test_geographic_diversity_counts_region_nodes() -> anyhow::Result<()> {
    // Test that multiple nodes from the same region are tracked correctly
    // We use different /24 subnets to avoid IP diversity rejection
    let mut engine = DhtCoreEngine::new_for_tests(NodeId::random())?;

    // Add 3 nodes from Europe (different /24 subnets to avoid IP diversity limits)
    let node1 = NodeInfo {
        id: NodeId::random(),
        address: "130.10.1.1".to_string(), // Europe
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node1).await?;

    let node2 = NodeInfo {
        id: NodeId::random(),
        address: "130.20.1.1".to_string(), // Europe, different /24
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node2).await?;

    let node3 = NodeInfo {
        id: NodeId::random(),
        address: "131.30.1.1".to_string(), // Europe, different /16
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node3).await?;

    // All should succeed since geographic limit is 50 and we're only adding 3
    Ok(())
}
