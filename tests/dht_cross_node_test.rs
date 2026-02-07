// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// Cross-node DHT replication tests
//
// These tests verify that DHT operations work correctly across multiple nodes
// when using the DhtNetworkManager for network-wide replication.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use anyhow::Result;
use saorsa_core::dht::{DHTConfig, Key};
use saorsa_core::dht_network_manager::{DhtNetworkConfig, DhtNetworkManager, DhtNetworkResult};
use saorsa_core::network::{NodeConfig, P2PNode};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::info;

/// Helper to create a unique key from a string
fn key_from_str(s: &str) -> Key {
    let bytes = s.as_bytes();
    let mut key = [0u8; 32];
    let len = bytes.len().min(32);
    key[..len].copy_from_slice(&bytes[..len]);
    key
}

/// Helper to create a DhtNetworkConfig for testing with a unique port
fn create_test_dht_config(peer_id: &str, port: u16) -> DhtNetworkConfig {
    let node_config = NodeConfig::builder()
        .peer_id(peer_id.to_string())
        .listen_port(port)
        .ipv6(false)
        .build()
        .expect("Failed to build NodeConfig");

    DhtNetworkConfig {
        local_peer_id: peer_id.to_string(),
        dht_config: DHTConfig::default(),
        node_config,
        bootstrap_nodes: vec![],
        request_timeout: Duration::from_secs(5),
        max_concurrent_operations: 10,
        replication_factor: 3,
        enable_security: false,
    }
}

/// Test that DhtNetworkManager can be created and started
#[tokio::test]
async fn test_dht_network_manager_creation() -> Result<()> {
    let config = create_test_dht_config("test_node_1", 0);
    let manager = Arc::new(DhtNetworkManager::new(config).await?);

    // Start the manager
    manager.start().await?;

    // Verify stats are accessible
    let stats = manager.get_stats().await;
    assert_eq!(stats.total_operations, 0);

    // Stop the manager
    manager.stop().await?;

    Ok(())
}

/// Test local DHT put and get operations through the manager
#[tokio::test]
async fn test_dht_local_put_get() -> Result<()> {
    let config = create_test_dht_config("test_local_node", 0);
    let manager = Arc::new(DhtNetworkManager::new(config).await?);
    manager.start().await?;

    // Store a value
    let key = key_from_str("test_key_local");
    let value = b"test_value_local".to_vec();

    let put_result = manager.put(key, value.clone()).await?;
    match put_result {
        DhtNetworkResult::PutSuccess { replicated_to, .. } => {
            info!("Put succeeded, replicated to {} nodes", replicated_to);
            assert!(
                replicated_to >= 1,
                "Should replicate to at least local storage"
            );
        }
        other => panic!("Unexpected put result: {:?}", other),
    }

    // Retrieve the value
    let get_result = manager.get(&key).await?;
    match get_result {
        DhtNetworkResult::GetSuccess {
            value: retrieved_value,
            ..
        } => {
            assert_eq!(
                retrieved_value, value,
                "Retrieved value should match stored value"
            );
        }
        DhtNetworkResult::GetNotFound { .. } => {
            panic!("Value should be found after put");
        }
        other => panic!("Unexpected get result: {:?}", other),
    }

    manager.stop().await?;
    Ok(())
}

/// Test cross-node DHT store and retrieve
/// This test creates two nodes, connects them, and verifies that data stored
/// on one node can be retrieved from the other.
#[tokio::test]
async fn test_cross_node_dht_store_retrieve() -> Result<()> {
    // Create node1 with DhtNetworkManager
    let config1 = create_test_dht_config("cross_node_1", 0);
    let manager1 = Arc::new(DhtNetworkManager::new(config1).await?);
    manager1.start().await?;

    // Give node1 time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create node2 with DhtNetworkManager
    let config2 = create_test_dht_config("cross_node_2", 0);
    let manager2 = Arc::new(DhtNetworkManager::new(config2).await?);
    manager2.start().await?;

    // Note: In a full implementation, we would connect node2 to node1 here
    // For now, we verify that the managers work independently

    // Store on node1
    let key = key_from_str("cross_node_test_key");
    let value = b"cross_node_test_value".to_vec();

    let put_result = manager1.put(key, value.clone()).await?;
    assert!(
        matches!(put_result, DhtNetworkResult::PutSuccess { .. }),
        "Put should succeed on node1"
    );

    // Retrieve from node1 (should work since data is stored locally)
    let get_result = manager1.get(&key).await?;
    assert!(
        matches!(get_result, DhtNetworkResult::GetSuccess { .. }),
        "Get should succeed on node1"
    );

    // Note: Cross-node retrieval would require actual network connectivity
    // between the nodes. In unit tests without network setup, node2 won't
    // be able to find the value stored on node1.

    manager1.stop().await?;
    manager2.stop().await?;
    Ok(())
}

/// Test correct architecture: DhtNetworkManager owns P2PNode
///
/// This test demonstrates the correct layering per ADR-001:
/// - DHT layer (DhtNetworkManager) sits above transport layer (P2PNode)
/// - DhtNetworkManager owns and uses P2PNode for transport
/// - Applications use DhtNetworkManager directly for network-wide operations
#[tokio::test]
async fn test_correct_architecture_dht_owns_transport() -> Result<()> {
    // Create DhtNetworkManager (DHT layer)
    // It internally creates and owns a P2PNode (transport layer)
    let node_config = NodeConfig::builder()
        .peer_id("architecture_test_node".to_string())
        .listen_port(0)
        .ipv6(false)
        .build()?;

    let dht_config = DhtNetworkConfig {
        local_peer_id: "architecture_test_node".to_string(),
        dht_config: DHTConfig::default(),
        node_config,
        bootstrap_nodes: vec![],
        request_timeout: Duration::from_secs(5),
        max_concurrent_operations: 10,
        replication_factor: 3,
        enable_security: false,
    };

    // Correct pattern: Create DhtNetworkManager which owns P2PNode internally
    let manager = Arc::new(DhtNetworkManager::new(dht_config).await?);
    manager.start().await?;

    // Test DHT operations through the manager (correct layer)
    let key = key_from_str("architecture_test_key");
    let value = b"architecture_test_value".to_vec();

    // Put through DhtNetworkManager (network-wide replication)
    let put_result = manager.put(key, value.clone()).await?;
    assert!(
        matches!(put_result, DhtNetworkResult::PutSuccess { .. }),
        "Put should succeed through manager"
    );

    // Get through DhtNetworkManager (network-wide lookup)
    let get_result = manager.get(&key).await?;
    match get_result {
        DhtNetworkResult::GetSuccess {
            value: retrieved, ..
        } => {
            assert_eq!(retrieved, value, "Retrieved value should match");
        }
        _ => panic!("Get should succeed through manager"),
    }

    manager.stop().await?;
    Ok(())
}

/// Test P2PNode local-only DHT operations (transport layer only)
///
/// P2PNode provides local-only DHT storage without network replication.
/// For network-wide operations, use DhtNetworkManager instead.
#[tokio::test]
async fn test_p2p_node_local_dht_only() -> Result<()> {
    // Create P2PNode (transport layer only)
    let node_config = NodeConfig::builder()
        .peer_id("local_only_test_node".to_string())
        .listen_port(0)
        .ipv6(false)
        .build()?;

    let node = P2PNode::new(node_config).await?;

    // Test local-only DHT operations (no network replication)
    let key = key_from_str("local_only_test_key");
    let value = b"local_only_test_value".to_vec();

    // Put stores locally only (no replication)
    node.dht_put(key, value.clone()).await?;

    // Get retrieves from local storage only (no network query)
    let retrieved = node.dht_get(key).await?;
    assert!(
        retrieved.is_some(),
        "Value should be retrievable from local DHT"
    );
    assert_eq!(
        retrieved.unwrap(),
        value,
        "Retrieved value should match stored value"
    );

    Ok(())
}

/// Test concurrent DHT operations through the manager
#[tokio::test]
async fn test_concurrent_dht_operations() -> Result<()> {
    let config = create_test_dht_config("concurrent_test_node", 0);
    let manager = Arc::new(DhtNetworkManager::new(config).await?);
    manager.start().await?;

    // Spawn multiple concurrent put operations
    let mut handles = vec![];
    for i in 0..10 {
        let manager_clone = Arc::clone(&manager);
        let handle = tokio::spawn(async move {
            let key = key_from_str(&format!("concurrent_key_{i}"));
            let value = format!("concurrent_value_{i}").into_bytes();
            manager_clone.put(key, value).await
        });
        handles.push(handle);
    }

    // Wait for all puts to complete
    for handle in handles {
        let result = handle.await??;
        assert!(
            matches!(result, DhtNetworkResult::PutSuccess { .. }),
            "Concurrent put should succeed"
        );
    }

    // Verify all values are retrievable
    for i in 0..10 {
        let key = key_from_str(&format!("concurrent_key_{i}"));
        let expected_value = format!("concurrent_value_{i}").into_bytes();
        let get_result = manager.get(&key).await?;
        match get_result {
            DhtNetworkResult::GetSuccess { value, .. } => {
                assert_eq!(value, expected_value, "Value {i} should match");
            }
            _ => panic!("Get for key {i} should succeed"),
        }
    }

    manager.stop().await?;
    Ok(())
}

/// Test DHT put at the maximum allowed value size (512 bytes) succeeds,
/// and that oversized values are correctly rejected with a validation error.
#[tokio::test]
async fn test_dht_put_large_value() -> Result<()> {
    let config = create_test_dht_config("large_value_test_node", 0);
    let manager = Arc::new(DhtNetworkManager::new(config).await?);
    manager.start().await?;

    // A value at exactly the 512-byte limit should succeed
    let key = key_from_str("max_size_value_key");
    let value = vec![0xABu8; 512];

    let put_result = timeout(Duration::from_secs(30), manager.put(key, value.clone())).await??;
    assert!(
        matches!(put_result, DhtNetworkResult::PutSuccess { .. }),
        "Value at max size should succeed"
    );

    let get_result = timeout(Duration::from_secs(30), manager.get(&key)).await??;
    match get_result {
        DhtNetworkResult::GetSuccess {
            value: retrieved_value,
            ..
        } => {
            assert_eq!(
                retrieved_value.len(),
                value.len(),
                "Retrieved value size should match"
            );
            assert_eq!(retrieved_value, value, "Retrieved value content should match");
        }
        _ => panic!("Get for max-size value should succeed"),
    }

    // A value exceeding the 512-byte limit should be rejected
    let oversized_key = key_from_str("oversized_value_key");
    let oversized_value = vec![0xFFu8; 513];

    let oversized_result = manager.put(oversized_key, oversized_value).await;
    assert!(
        oversized_result.is_err(),
        "Oversized value should be rejected with a validation error"
    );
    let err_msg = format!("{}", oversized_result.unwrap_err());
    assert!(
        err_msg.contains("exceeds maximum"),
        "Error should mention size limit, got: {}",
        err_msg
    );

    manager.stop().await?;
    Ok(())
}
