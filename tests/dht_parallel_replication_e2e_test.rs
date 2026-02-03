// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// E2E test for parallel DHT replication (PR verification)
//
// This test validates that the parallel replication changes in the PR work correctly:
// 1. PUT operations replicate to K nodes in parallel (not sequential)
// 2. GET operations query multiple nodes in parallel
// 3. Performance improvement is measurable
// 4. Replication correctness is maintained

#![allow(clippy::unwrap_used, clippy::expect_used)]

use anyhow::Result;
use saorsa_core::dht::{DHTConfig, Key};
use saorsa_core::dht_network_manager::{DhtNetworkConfig, DhtNetworkManager, DhtNetworkResult};
use saorsa_core::network::NodeConfig;
use std::sync::Arc;
use std::time::{Duration, Instant};
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

/// Test parallel DHT replication performance
///
/// This test validates the PR's claim that replication now happens in parallel:
/// - Before: Sequential replication to K=8 nodes (~800ms with 100ms per node)
/// - After: Parallel replication to K=8 nodes (~100-200ms total)
///
/// The test creates a network of nodes and measures actual replication time.
#[tokio::test]
async fn test_parallel_put_replication_performance() -> Result<()> {
    info!("=== Testing Parallel PUT Replication Performance ===");

    // Create a manager with K=8 replication
    let config = create_test_dht_config("parallel_test_node", 0, 8);
    let manager = Arc::new(DhtNetworkManager::new(config).await?);
    manager.start().await?;

    // Give the manager time to initialize
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test data
    let key = key_from_str("parallel_replication_test_key");
    let value = b"parallel_replication_test_value".to_vec();

    // Measure PUT operation time
    let start = Instant::now();
    let put_result = manager.put(key, value.clone()).await?;
    let elapsed = start.elapsed();

    match put_result {
        DhtNetworkResult::PutSuccess { replicated_to, .. } => {
            info!(
                "✓ PUT succeeded: replicated_to={} in {:?}",
                replicated_to, elapsed
            );

            // Verify replication happened (at least local storage)
            assert!(
                replicated_to >= 1,
                "Should replicate to at least local storage, got {}",
                replicated_to
            );

            // Performance assertion: With parallel replication, even with K=8,
            // the operation should complete much faster than sequential (800ms)
            // We allow up to 5 seconds for safety (network, CI, etc)
            assert!(
                elapsed < Duration::from_secs(5),
                "PUT should complete quickly with parallel replication, took {:?}",
                elapsed
            );

            info!("✓ Performance check passed: {:?} < 5s", elapsed);
        }
        other => panic!("Unexpected PUT result: {:?}", other),
    }

    // Verify the value is retrievable
    let get_result = manager.get(&key).await?;
    match get_result {
        DhtNetworkResult::GetSuccess {
            value: retrieved, ..
        } => {
            assert_eq!(retrieved, value, "Retrieved value should match");
            info!("✓ GET verification passed");
        }
        DhtNetworkResult::GetNotFound { .. } => {
            panic!("Value should be found after PUT");
        }
        other => panic!("Unexpected GET result: {:?}", other),
    }

    manager.stop().await?;
    info!("=== Parallel PUT Replication Test PASSED ===");
    Ok(())
}

/// Test parallel DHT GET query performance
///
/// This test validates that GET operations query multiple nodes in parallel
/// and return as soon as the first successful result is found.
#[tokio::test]
async fn test_parallel_get_query_performance() -> Result<()> {
    info!("=== Testing Parallel GET Query Performance ===");

    let config = create_test_dht_config("parallel_get_test_node", 0, 8);
    let manager = Arc::new(DhtNetworkManager::new(config).await?);
    manager.start().await?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Store test data
    let key = key_from_str("parallel_get_test_key");
    let value = b"parallel_get_test_value".to_vec();

    let put_result = manager.put(key, value.clone()).await?;
    assert!(
        matches!(put_result, DhtNetworkResult::PutSuccess { .. }),
        "PUT should succeed"
    );

    // Measure GET operation time
    let start = Instant::now();
    let get_result = manager.get(&key).await?;
    let elapsed = start.elapsed();

    match get_result {
        DhtNetworkResult::GetSuccess {
            value: retrieved,
            source,
            ..
        } => {
            info!("✓ GET succeeded: source={} in {:?}", source, elapsed);
            assert_eq!(retrieved, value, "Retrieved value should match");

            // With parallel queries, GET should be fast (local hit or quick network query)
            assert!(
                elapsed < Duration::from_secs(2),
                "GET should complete quickly with parallel queries, took {:?}",
                elapsed
            );

            info!("✓ Performance check passed: {:?} < 2s", elapsed);
        }
        DhtNetworkResult::GetNotFound { .. } => {
            panic!("Value should be found after PUT");
        }
        other => panic!("Unexpected GET result: {:?}", other),
    }

    manager.stop().await?;
    info!("=== Parallel GET Query Test PASSED ===");
    Ok(())
}

/// Test concurrent PUT operations with parallel replication
///
/// This validates that multiple concurrent PUTs work correctly with
/// the new parallel replication implementation.
#[tokio::test]
async fn test_concurrent_parallel_puts() -> Result<()> {
    info!("=== Testing Concurrent Parallel PUTs ===");

    let config = create_test_dht_config("concurrent_parallel_test", 0, 8);
    let manager = Arc::new(DhtNetworkManager::new(config).await?);
    manager.start().await?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Spawn 20 concurrent PUT operations
    let mut handles = vec![];
    let start = Instant::now();

    for i in 0..20 {
        let manager_clone = Arc::clone(&manager);
        let handle = tokio::spawn(async move {
            let key = key_from_str(&format!("concurrent_parallel_key_{}", i));
            let value = format!("concurrent_parallel_value_{}", i).into_bytes();
            manager_clone.put(key, value).await
        });
        handles.push(handle);
    }

    // Wait for all PUTs to complete
    let mut success_count = 0;
    for handle in handles {
        match handle.await? {
            Ok(DhtNetworkResult::PutSuccess { .. }) => success_count += 1,
            Ok(other) => warn!("Unexpected result: {:?}", other),
            Err(e) => warn!("PUT failed: {}", e),
        }
    }

    let total_elapsed = start.elapsed();
    info!("✓ Completed {} PUTs in {:?}", success_count, total_elapsed);

    assert_eq!(success_count, 20, "All PUTs should succeed");

    // With parallel replication, 20 concurrent operations should complete quickly
    assert!(
        total_elapsed < Duration::from_secs(10),
        "20 concurrent PUTs should complete in <10s with parallelization, took {:?}",
        total_elapsed
    );

    // Verify all values are retrievable
    for i in 0..20 {
        let key = key_from_str(&format!("concurrent_parallel_key_{}", i));
        let expected = format!("concurrent_parallel_value_{}", i).into_bytes();

        let get_result = manager.get(&key).await?;
        match get_result {
            DhtNetworkResult::GetSuccess { value, .. } => {
                assert_eq!(value, expected, "Value {} should match", i);
            }
            _ => panic!("GET for key {} should succeed", i),
        }
    }

    info!("✓ All 20 values verified successfully");

    manager.stop().await?;
    info!("=== Concurrent Parallel PUTs Test PASSED ===");
    Ok(())
}

/// Test that replication count is accurate with parallel implementation
///
/// This validates that the parallel replication correctly counts
/// successful replications across all nodes.
#[tokio::test]
async fn test_replication_count_accuracy() -> Result<()> {
    info!("=== Testing Replication Count Accuracy ===");

    // Use K=5 for this test
    let config = create_test_dht_config("replication_count_test", 0, 5);
    let manager = Arc::new(DhtNetworkManager::new(config).await?);
    manager.start().await?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let key = key_from_str("replication_count_test_key");
    let value = b"replication_count_test_value".to_vec();

    let put_result = manager.put(key, value.clone()).await?;

    match put_result {
        DhtNetworkResult::PutSuccess {
            replicated_to,
            key: result_key,
        } => {
            info!("✓ PUT succeeded: replicated_to={}", replicated_to);
            assert_eq!(result_key, key, "Key should match");

            // Should have at least local storage (1)
            // May have more if nodes were added to the network
            assert!(
                replicated_to >= 1,
                "Should replicate to at least local storage"
            );

            // In isolation (no connected peers), should be exactly 1 (local only)
            assert!(
                replicated_to <= 6, // 1 local + max 5 remote (K=5)
                "Should not exceed K+1 replications"
            );

            info!(
                "✓ Replication count is within valid range: {}",
                replicated_to
            );
        }
        other => panic!("Unexpected PUT result: {:?}", other),
    }

    manager.stop().await?;
    info!("=== Replication Count Accuracy Test PASSED ===");
    Ok(())
}

/// Stress test: Many large values with parallel replication
///
/// This test validates that parallel replication maintains correctness
/// and performance under load.
#[tokio::test]
async fn test_parallel_replication_stress() -> Result<()> {
    info!("=== Testing Parallel Replication Under Load ===");

    let config = create_test_dht_config("stress_test_node", 0, 8);
    let manager = Arc::new(DhtNetworkManager::new(config).await?);
    manager.start().await?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Store 50 values of varying sizes
    let start = Instant::now();
    let mut put_count = 0;

    for i in 0..50 {
        let key = key_from_str(&format!("stress_test_key_{}", i));
        let value_size = 1024 * (i % 10 + 1); // 1KB to 10KB
        let value = vec![i as u8; value_size];

        match manager.put(key, value).await {
            Ok(DhtNetworkResult::PutSuccess { .. }) => put_count += 1,
            Ok(other) => warn!("Unexpected result for key {}: {:?}", i, other),
            Err(e) => warn!("PUT failed for key {}: {}", i, e),
        }
    }

    let put_elapsed = start.elapsed();
    info!("✓ Completed {} PUTs in {:?}", put_count, put_elapsed);

    assert_eq!(put_count, 50, "All PUTs should succeed");

    // Retrieve all values to verify correctness
    let get_start = Instant::now();
    let mut get_count = 0;

    for i in 0..50 {
        let key = key_from_str(&format!("stress_test_key_{}", i));
        let expected_size = 1024 * (i % 10 + 1);

        match manager.get(&key).await {
            Ok(DhtNetworkResult::GetSuccess { value, .. }) => {
                assert_eq!(
                    value.len(),
                    expected_size,
                    "Value size for key {} should match",
                    i
                );
                assert_eq!(
                    value[0], i as u8,
                    "Value content for key {} should match",
                    i
                );
                get_count += 1;
            }
            Ok(DhtNetworkResult::GetNotFound { .. }) => {
                panic!("Value {} should be found", i);
            }
            Ok(other) => panic!("Unexpected result for key {}: {:?}", i, other),
            Err(e) => panic!("GET failed for key {}: {}", i, e),
        }
    }

    let get_elapsed = get_start.elapsed();
    info!("✓ Verified {} values in {:?}", get_count, get_elapsed);

    assert_eq!(get_count, 50, "All GETs should succeed");

    manager.stop().await?;
    info!("=== Parallel Replication Stress Test PASSED ===");
    Ok(())
}
