// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// Single-node DHT operation tests
//
// These tests validate PUT/GET correctness, concurrent operations, and stress
// behavior on an isolated node (no peers). Parallel replication across multiple
// nodes is covered in dht_replication_e2e_test.rs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use anyhow::Result;
use saorsa_core::dht::{DHTConfig, Key};
use saorsa_core::dht_network_manager::{DhtNetworkConfig, DhtNetworkManager, DhtNetworkResult};
use saorsa_core::network::NodeConfig;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Helper to create a unique key from a string
fn key_from_str(s: &str) -> Key {
    let bytes = s.as_bytes();
    let mut key = [0u8; 32];
    let len = bytes.len().min(32);
    key[..len].copy_from_slice(&bytes[..len]);
    key
}

/// Helper to create a DhtNetworkConfig for testing
fn create_test_dht_config(peer_id: &str, port: u16, replication_factor: usize) -> DhtNetworkConfig {
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
        request_timeout: Duration::from_secs(10),
        max_concurrent_operations: 50,
        replication_factor,
        enable_security: false,
    }
}

/// Verify single-node PUT stores locally and GET retrieves it.
/// With no peers, replicated_to must be exactly 1 (local only).
#[tokio::test]
async fn test_single_node_put_get_roundtrip() -> Result<()> {
    let config = create_test_dht_config("put_get_roundtrip_node", 0, 8);
    let manager = Arc::new(DhtNetworkManager::new(config).await?);
    manager.start().await?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let key = key_from_str("roundtrip_test_key");
    let value = b"roundtrip_test_value".to_vec();

    let put_result = manager.put(key, value.clone()).await?;
    match put_result {
        DhtNetworkResult::PutSuccess { replicated_to, .. } => {
            // No peers connected, so replication is local-only
            assert_eq!(
                replicated_to, 1,
                "Isolated node should replicate to exactly 1 (local), got {}",
                replicated_to
            );
        }
        other => panic!("Expected PutSuccess, got: {:?}", other),
    }

    let get_result = manager.get(&key).await?;
    match get_result {
        DhtNetworkResult::GetSuccess {
            value: retrieved, ..
        } => {
            assert_eq!(
                retrieved, value,
                "Retrieved value should match stored value"
            );
        }
        other => panic!("Expected GetSuccess, got: {:?}", other),
    }

    manager.stop().await?;
    Ok(())
}

/// Verify GET returns GetNotFound for keys that were never stored.
#[tokio::test]
async fn test_get_missing_key_returns_not_found() -> Result<()> {
    let config = create_test_dht_config("missing_key_node", 0, 8);
    let manager = Arc::new(DhtNetworkManager::new(config).await?);
    manager.start().await?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let key = key_from_str("nonexistent_key");
    let get_result = manager.get(&key).await?;

    assert!(
        matches!(get_result, DhtNetworkResult::GetNotFound { .. }),
        "GET for missing key should return GetNotFound, got: {:?}",
        get_result
    );

    manager.stop().await?;
    Ok(())
}

/// Verify 20 concurrent PUT operations all succeed and are retrievable.
#[tokio::test]
async fn test_concurrent_puts() -> Result<()> {
    let config = create_test_dht_config("concurrent_puts_node", 0, 8);
    let manager = Arc::new(DhtNetworkManager::new(config).await?);
    manager.start().await?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut handles = vec![];
    for i in 0..20 {
        let mgr = Arc::clone(&manager);
        let handle = tokio::spawn(async move {
            let key = key_from_str(&format!("concurrent_key_{}", i));
            let value = format!("concurrent_value_{}", i).into_bytes();
            mgr.put(key, value).await
        });
        handles.push(handle);
    }

    let mut success_count = 0;
    for handle in handles {
        match handle.await? {
            Ok(DhtNetworkResult::PutSuccess { replicated_to, .. }) => {
                assert_eq!(replicated_to, 1, "Isolated node: replicated_to should be 1");
                success_count += 1;
            }
            Ok(other) => warn!("Unexpected result: {:?}", other),
            Err(e) => warn!("PUT failed: {}", e),
        }
    }

    assert_eq!(success_count, 20, "All 20 PUTs should succeed");

    // Verify all values retrievable
    for i in 0..20 {
        let key = key_from_str(&format!("concurrent_key_{}", i));
        let expected = format!("concurrent_value_{}", i).into_bytes();

        let get_result = manager.get(&key).await?;
        match get_result {
            DhtNetworkResult::GetSuccess { value, .. } => {
                assert_eq!(value, expected, "Value {} should match", i);
            }
            other => panic!("GET for key {} should succeed, got: {:?}", i, other),
        }
    }

    manager.stop().await?;
    Ok(())
}

/// Verify replication count is exactly 1 on isolated node with K=5.
#[tokio::test]
async fn test_replication_count_isolated_node() -> Result<()> {
    let config = create_test_dht_config("replication_count_node", 0, 5);
    let manager = Arc::new(DhtNetworkManager::new(config).await?);
    manager.start().await?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let key = key_from_str("replication_count_key");
    let value = b"replication_count_value".to_vec();

    let put_result = manager.put(key, value).await?;
    match put_result {
        DhtNetworkResult::PutSuccess {
            replicated_to,
            key: result_key,
        } => {
            assert_eq!(result_key, key, "Returned key should match");
            assert_eq!(
                replicated_to, 1,
                "Isolated node with K=5 should still replicate to exactly 1 (local)"
            );
        }
        other => panic!("Expected PutSuccess, got: {:?}", other),
    }

    manager.stop().await?;
    Ok(())
}

/// Stress test: 50 values of varying sizes (up to 512 bytes), all stored and retrieved.
#[tokio::test]
async fn test_stress_50_values() -> Result<()> {
    let config = create_test_dht_config("stress_node", 0, 8);
    let manager = Arc::new(DhtNetworkManager::new(config).await?);
    manager.start().await?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // MAX_VALUE_SIZE is 512 bytes; vary sizes from 10 to 512
    for i in 0..50 {
        let key = key_from_str(&format!("stress_key_{}", i));
        let value_size = 10 + (i % 50) * 10; // 10..500 bytes
        let value_size = value_size.min(512);
        let value = vec![i as u8; value_size];

        match manager.put(key, value).await {
            Ok(DhtNetworkResult::PutSuccess { .. }) => {}
            Ok(other) => panic!("PUT {} unexpected result: {:?}", i, other),
            Err(e) => panic!("PUT {} failed: {}", i, e),
        }
    }

    info!("All 50 PUTs succeeded, verifying retrieval");

    for i in 0..50 {
        let key = key_from_str(&format!("stress_key_{}", i));
        let expected_size = (10 + (i % 50) * 10).min(512);

        match manager.get(&key).await {
            Ok(DhtNetworkResult::GetSuccess { value, .. }) => {
                assert_eq!(value.len(), expected_size, "Value {} size mismatch", i);
                assert_eq!(value[0], i as u8, "Value {} content mismatch", i);
            }
            Ok(other) => panic!("GET {} unexpected result: {:?}", i, other),
            Err(e) => panic!("GET {} failed: {}", i, e),
        }
    }

    manager.stop().await?;
    Ok(())
}
