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
use saorsa_core::transport_handle::{TransportConfig, TransportHandle};
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

/// Helper to create a TransportHandle and DhtNetworkConfig for testing
async fn create_test_dht_config(
    peer_id: &str,
    port: u16,
    replication_factor: usize,
) -> Result<(Arc<TransportHandle>, DhtNetworkConfig)> {
    let node_config = NodeConfig::builder()
        .peer_id(peer_id.to_string())
        .listen_port(port)
        .ipv6(false)
        .build()
        .expect("Failed to build NodeConfig");

    let transport = Arc::new(
        TransportHandle::new(TransportConfig {
            peer_id: peer_id.to_string(),
            listen_addr: node_config.listen_addr,
            enable_ipv6: node_config.enable_ipv6,
            connection_timeout: node_config.connection_timeout,
            stale_peer_threshold: node_config.stale_peer_threshold,
            max_connections: node_config.max_connections,
            production_config: node_config.production_config.clone(),
            event_channel_capacity: saorsa_core::DEFAULT_EVENT_CHANNEL_CAPACITY,
        })
        .await?,
    );

    let config = DhtNetworkConfig {
        local_peer_id: peer_id.to_string(),
        dht_config: DHTConfig::default(),
        node_config,
        request_timeout: Duration::from_secs(10),
        max_concurrent_operations: 50,
        replication_factor,
        enable_security: false,
    };

    Ok((transport, config))
}

/// Verify single-node PUT stores locally and GET retrieves it.
/// With no peers, replicated_to must be exactly 1 (local only).
#[tokio::test]
async fn test_single_node_put_get_roundtrip() -> Result<()> {
    let (transport, config) = create_test_dht_config("put_get_roundtrip_node", 0, 8).await?;
    transport.start_network_listeners().await?;
    let manager = Arc::new(DhtNetworkManager::new(transport, None, config).await?);
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
    let (transport, config) = create_test_dht_config("missing_key_node", 0, 8).await?;
    transport.start_network_listeners().await?;
    let manager = Arc::new(DhtNetworkManager::new(transport, None, config).await?);
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
    let (transport, config) = create_test_dht_config("concurrent_puts_node", 0, 8).await?;
    transport.start_network_listeners().await?;
    let manager = Arc::new(DhtNetworkManager::new(transport, None, config).await?);
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
    let (transport, config) = create_test_dht_config("replication_count_node", 0, 5).await?;
    transport.start_network_listeners().await?;
    let manager = Arc::new(DhtNetworkManager::new(transport, None, config).await?);
    manager.start().await?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let key = key_from_str("replication_count_key");
    let value = b"replication_count_value".to_vec();

    let put_result = manager.put(key, value).await?;
    match put_result {
        DhtNetworkResult::PutSuccess {
            replicated_to,
            key: result_key,
            ..
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

/// Stress test: 50 values of varying sizes (10–500 bytes), all stored and retrieved.
/// Values stay within the 512-byte DHT value size limit.
#[tokio::test]
async fn test_stress_50_values() -> Result<()> {
    let (transport, config) = create_test_dht_config("stress_node", 0, 8).await?;
    transport.start_network_listeners().await?;
    let manager = Arc::new(DhtNetworkManager::new(transport, None, config).await?);
    manager.start().await?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    for i in 0..50 {
        let key = key_from_str(&format!("stress_key_{}", i));
        // Vary sizes from 10 to 500 bytes (within 512-byte limit)
        let value_size = 10 + (i % 10) * 50;
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
        let expected_size = 10 + (i % 10) * 50;

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
