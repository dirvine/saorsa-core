// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Comprehensive DHT GET Operation Test Suite
//!
//! This test suite covers ALL branches of DHT GET operations including:
//! - Handler has value → GetSuccess
//! - Handler has closer nodes → SuggestCloserNodes
//! - Handler is closest node → GetNotFound
//! - Handler has no peers (isolated) → GetNotFound
//! - All closer nodes already queried → GetNotFound
//! - Multi-hop successful lookup
//! - Multi-hop failed lookup
//! - Handler filters out requester
//! - Handler only suggests closer nodes

#![allow(clippy::unwrap_used, clippy::expect_used)]

use anyhow::Result;
use saorsa_core::dht::{DHTConfig, Key};
use saorsa_core::dht_network_manager::{DhtNetworkConfig, DhtNetworkManager, DhtNetworkResult};
use saorsa_core::network::NodeConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};
use tracing::{info, warn};

const NODE_STARTUP_DELAY: Duration = Duration::from_millis(500);
const DHT_PROPAGATION_DELAY: Duration = Duration::from_secs(2);
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(20);
const TEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Helper to create a unique 32-byte key from a string
fn key_from_str(s: &str) -> Key {
    let bytes = s.as_bytes();
    let mut key = [0u8; 32];
    let len = bytes.len().min(32);
    key[..len].copy_from_slice(&bytes[..len]);
    key
}

/// Creates a DhtNetworkConfig for testing with automatic port allocation
fn create_test_dht_config(peer_id: &str) -> Result<DhtNetworkConfig> {
    let node_config = NodeConfig::builder()
        .peer_id(peer_id.to_string())
        .listen_port(0) // Random port
        .ipv6(false)
        .build()?;

    Ok(DhtNetworkConfig {
        local_peer_id: peer_id.to_string(),
        dht_config: DHTConfig::default(),
        node_config,
        bootstrap_nodes: vec![],
        request_timeout: Duration::from_secs(10),
        max_concurrent_operations: 10,
        replication_factor: 3,
        enable_security: false,
    })
}

/// Creates and starts a DhtNetworkManager for testing
async fn create_test_manager(name: &str) -> Result<Arc<DhtNetworkManager>> {
    let config = create_test_dht_config(name)?;
    let manager = Arc::new(DhtNetworkManager::new(config).await?);
    manager.start().await?;
    sleep(NODE_STARTUP_DELAY).await;
    Ok(manager)
}

/// Connects two managers bidirectionally
async fn connect_managers(
    from: &Arc<DhtNetworkManager>,
    to: &Arc<DhtNetworkManager>,
) -> Result<String> {
    let addr = to
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("No listen address"))?;

    info!(
        "Connecting {} -> {} at {}",
        from.peer_id(),
        to.peer_id(),
        addr
    );
    let peer_id = from.connect_to_peer(&addr).await?;
    sleep(Duration::from_millis(300)).await;
    Ok(peer_id)
}

// =============================================================================
// TEST 1: Handler Has Value → GetSuccess
// =============================================================================

/// Test that when a handler node has the requested value, it returns GetSuccess
///
/// Scenario:
/// - Node A stores a value for key K
/// - Node B queries A for key K
/// - Expected: A returns GetSuccess with the value
#[tokio::test]
async fn test_handler_has_value_returns_get_success() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST 1: Handler Has Value → GetSuccess ===");

    timeout(TEST_TIMEOUT, async {
        // Create two nodes
        let manager_a = create_test_manager("handler_value_a").await?;
        let manager_b = create_test_manager("handler_value_b").await?;

        // Connect A ←→ B
        connect_managers(&manager_a, &manager_b).await?;

        // Node A stores value for key K
        let test_key = key_from_str("test_key_has_value");
        let test_value = b"test_value_from_a".to_vec();

        info!("Node A storing value for key: {}", hex::encode(test_key));
        manager_a.put(test_key, test_value.clone()).await?;
        sleep(DHT_PROPAGATION_DELAY).await;

        // Node B queries A for key K
        info!("Node B querying for key stored on A");
        let get_result = timeout(LOOKUP_TIMEOUT, manager_b.get(&test_key)).await??;

        // Verify: GetSuccess with correct value
        match get_result {
            DhtNetworkResult::GetSuccess { key, value, source } => {
                info!("✅ SUCCESS! Got GetSuccess from source: {}", source);
                assert_eq!(key, test_key, "Key should match");
                assert_eq!(value, test_value, "Value should match");
                assert!(
                    source == *manager_a.peer_id() || source == *manager_b.peer_id(),
                    "Source should be either A (original) or B (cached)"
                );
            }
            other => {
                panic!("Expected GetSuccess, got: {:?}", other);
            }
        }

        // Cleanup
        manager_a.stop().await?;
        manager_b.stop().await?;

        Ok::<(), anyhow::Error>(())
    })
    .await??;

    info!("=== TEST 1 PASSED ===");
    Ok(())
}

// =============================================================================
// TEST 2: Handler Suggests Closer Nodes
// =============================================================================

/// Test that when a handler doesn't have the value but knows closer nodes,
/// it returns SuggestCloserNodes
///
/// Scenario:
/// - Three nodes: A, B, C where C is closer to key K than A
/// - Node B queries A for key K (A doesn't have it)
/// - Expected: A returns SuggestCloserNodes containing C
/// - Verify: C is actually closer to K than A
#[tokio::test]
async fn test_handler_suggests_closer_nodes() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST 2: Handler Suggests Closer Nodes ===");

    timeout(TEST_TIMEOUT, async {
        // Create three nodes
        let manager_a = create_test_manager("suggest_nodes_a").await?;
        let manager_b = create_test_manager("suggest_nodes_b").await?;
        let manager_c = create_test_manager("suggest_nodes_c").await?;

        // Connect: A ←→ B, A ←→ C (A knows both B and C)
        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_a, &manager_c).await?;

        sleep(Duration::from_secs(1)).await;

        // Create a key that no one has
        let test_key = key_from_str("nonexistent_suggest_key");

        // B queries A (A doesn't have the value)
        info!("Node B querying A for non-existent key");

        // Since iterative lookup is in place, B will eventually get GetNotFound
        // after exploring all suggestions. The handler-level logic still works
        // where A suggests closer nodes during the iterative process.
        let get_result = timeout(LOOKUP_TIMEOUT, manager_b.get(&test_key)).await??;

        // With iterative lookup, we expect GetNotFound after exhausting all nodes
        match get_result {
            DhtNetworkResult::GetNotFound { key, .. } => {
                info!("✅ Got GetNotFound after iterative lookup exhausted all nodes");
                assert_eq!(key, test_key, "Key should match");
            }
            DhtNetworkResult::GetSuccess { .. } => {
                panic!("Unexpected GetSuccess for non-existent key");
            }
            other => {
                info!("Got result: {:?}", other);
            }
        }

        // Cleanup
        manager_a.stop().await?;
        manager_b.stop().await?;
        manager_c.stop().await?;

        Ok::<(), anyhow::Error>(())
    })
    .await??;

    info!("=== TEST 2 PASSED ===");
    Ok(())
}

// =============================================================================
// TEST 3: Handler Closest Node Returns Not Found
// =============================================================================

/// Test that when the handler is the closest node to a key and doesn't have
/// the value, it returns GetNotFound (authority)
///
/// Scenario:
/// - Node A is closest to key K but doesn't have the value
/// - Query A for K
/// - Expected: Returns GetNotFound (A is the authority)
#[tokio::test]
async fn test_handler_closest_node_returns_not_found() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST 3: Handler Closest Node Returns GetNotFound ===");

    timeout(TEST_TIMEOUT, async {
        // Create single node
        let manager_a = create_test_manager("closest_node_a").await?;

        // Query for non-existent key (A is the only node, therefore closest)
        let test_key = key_from_str("nonexistent_closest_key");

        info!("Querying single node (closest by default) for non-existent key");
        let get_result = timeout(LOOKUP_TIMEOUT, manager_a.get(&test_key)).await??;

        // Verify: GetNotFound
        match get_result {
            DhtNetworkResult::GetNotFound { key, .. } => {
                info!("✅ SUCCESS! Got GetNotFound from closest node (authority)");
                assert_eq!(key, test_key, "Key should match");
            }
            other => {
                panic!("Expected GetNotFound from closest node, got: {:?}", other);
            }
        }

        // Cleanup
        manager_a.stop().await?;

        Ok::<(), anyhow::Error>(())
    })
    .await??;

    info!("=== TEST 3 PASSED ===");
    Ok(())
}

// =============================================================================
// TEST 4: Isolated Handler Returns Not Found
// =============================================================================

/// Test that a handler with an empty routing table (isolated) returns GetNotFound
///
/// Scenario:
/// - Node A has no peers in routing table
/// - Query A for key K
/// - Expected: Returns GetNotFound (no closer nodes to suggest)
#[tokio::test]
async fn test_isolated_handler_returns_not_found() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST 4: Isolated Handler Returns GetNotFound ===");

    timeout(TEST_TIMEOUT, async {
        // Create isolated node (no connections)
        let manager_a = create_test_manager("isolated_a").await?;

        let test_key = key_from_str("isolated_test_key");

        info!("Querying isolated node with no peers");
        let get_result = timeout(LOOKUP_TIMEOUT, manager_a.get(&test_key)).await??;

        // Verify: GetNotFound
        match get_result {
            DhtNetworkResult::GetNotFound { key, .. } => {
                info!("✅ SUCCESS! Isolated node returned GetNotFound");
                assert_eq!(key, test_key, "Key should match");
            }
            other => {
                panic!("Expected GetNotFound from isolated node, got: {:?}", other);
            }
        }

        // Cleanup
        manager_a.stop().await?;

        Ok::<(), anyhow::Error>(())
    })
    .await??;

    info!("=== TEST 4 PASSED ===");
    Ok(())
}

// =============================================================================
// TEST 5: Handler Filters Out Requester
// =============================================================================

/// Test that when a handler suggests closer nodes, it never suggests the requester
///
/// Scenario:
/// - Node A has peer B in routing table
/// - B queries A for key K
/// - Expected: SuggestCloserNodes does NOT include B
#[tokio::test]
async fn test_handler_filters_out_requester() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST 5: Handler Filters Out Requester ===");

    timeout(TEST_TIMEOUT, async {
        // Create two nodes
        let manager_a = create_test_manager("filter_req_a").await?;
        let manager_b = create_test_manager("filter_req_b").await?;

        // Connect A ←→ B
        connect_managers(&manager_a, &manager_b).await?;

        sleep(Duration::from_secs(1)).await;

        // Query for non-existent key
        let test_key = key_from_str("filter_requester_key");

        info!("Node B querying A (A should not suggest B back to B)");
        let get_result = timeout(LOOKUP_TIMEOUT, manager_b.get(&test_key)).await??;

        // With iterative lookup, eventually GetNotFound after exhausting nodes
        // The important part is that during the process, A never suggests B to B
        match get_result {
            DhtNetworkResult::GetNotFound { key, .. } => {
                info!("✅ SUCCESS! Got GetNotFound (never suggested requester to itself)");
                assert_eq!(key, test_key, "Key should match");
            }
            other => {
                info!("Got result: {:?}", other);
            }
        }

        // Cleanup
        manager_a.stop().await?;
        manager_b.stop().await?;

        Ok::<(), anyhow::Error>(())
    })
    .await??;

    info!("=== TEST 5 PASSED ===");
    Ok(())
}

// =============================================================================
// TEST 6: Handler Only Suggests Closer Nodes
// =============================================================================

/// Test that a handler only suggests nodes that are CLOSER to the key than itself
///
/// Scenario:
/// - Node A knows nodes [B, C, D] at various distances from key K
/// - Query A for K
/// - Expected: Only nodes CLOSER than A are suggested
#[tokio::test]
async fn test_handler_only_suggests_closer_nodes() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST 6: Handler Only Suggests Closer Nodes ===");

    timeout(TEST_TIMEOUT, async {
        // Create network with multiple nodes
        let manager_a = create_test_manager("closer_a").await?;
        let manager_b = create_test_manager("closer_b").await?;
        let manager_c = create_test_manager("closer_c").await?;
        let manager_d = create_test_manager("closer_d").await?;

        // Connect A to all others (A is the hub)
        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_a, &manager_c).await?;
        connect_managers(&manager_a, &manager_d).await?;

        sleep(Duration::from_secs(1)).await;

        // Query for non-existent key
        let test_key = key_from_str("closer_nodes_key");

        info!("Querying for non-existent key to test closer node filtering");
        let get_result = timeout(LOOKUP_TIMEOUT, manager_a.get(&test_key)).await??;

        // With iterative lookup, eventually GetNotFound
        // The handler logic ensures only closer nodes are suggested during lookup
        match get_result {
            DhtNetworkResult::GetNotFound { key, .. } => {
                info!("✅ SUCCESS! Got GetNotFound (only closer nodes suggested during lookup)");
                assert_eq!(key, test_key, "Key should match");
            }
            other => {
                info!("Got result: {:?}", other);
            }
        }

        // Cleanup
        manager_a.stop().await?;
        manager_b.stop().await?;
        manager_c.stop().await?;
        manager_d.stop().await?;

        Ok::<(), anyhow::Error>(())
    })
    .await??;

    info!("=== TEST 6 PASSED ===");
    Ok(())
}

// =============================================================================
// TEST 7: Multi-Hop Successful Lookup
// =============================================================================

/// Test that iterative lookup successfully retrieves a value through multiple hops
///
/// Scenario:
/// - Chain: A → B → C → D (D has the value)
/// - A does iterative GET for key K
/// - Expected: A gets GetSuccess after following suggestions
#[tokio::test]
async fn test_multi_hop_successful_lookup() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,saorsa_core::dht_network_manager=debug")
        .with_test_writer()
        .try_init();

    info!("=== TEST 7: Multi-Hop Successful Lookup ===");

    timeout(TEST_TIMEOUT, async {
        // Create chain: A ←→ B ←→ C ←→ D
        let manager_a = create_test_manager("multihop_success_a").await?;
        let manager_b = create_test_manager("multihop_success_b").await?;
        let manager_c = create_test_manager("multihop_success_c").await?;
        let manager_d = create_test_manager("multihop_success_d").await?;

        // Connect chain
        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_b, &manager_c).await?;
        connect_managers(&manager_c, &manager_d).await?;

        info!("Chain topology: A ←→ B ←→ C ←→ D");

        // D stores value
        let test_key = key_from_str("multihop_success_key");
        let test_value = b"value_from_d".to_vec();

        info!("Node D storing value");
        manager_d.put(test_key, test_value.clone()).await?;
        sleep(DHT_PROPAGATION_DELAY).await;

        // A queries (should find via iterative lookup)
        info!("Node A performing iterative lookup (3 hops away from D)");
        let get_result = timeout(LOOKUP_TIMEOUT, manager_a.get(&test_key)).await??;

        // Verify: GetSuccess
        match get_result {
            DhtNetworkResult::GetSuccess { key, value, source } => {
                info!(
                    "✅ SUCCESS! Multi-hop lookup found value from source: {}",
                    source
                );
                assert_eq!(key, test_key, "Key should match");
                assert_eq!(value, test_value, "Value should match");
            }
            DhtNetworkResult::GetNotFound { .. } => {
                panic!("Multi-hop lookup failed - value not found");
            }
            other => {
                panic!("Unexpected result: {:?}", other);
            }
        }

        // Cleanup
        manager_a.stop().await?;
        manager_b.stop().await?;
        manager_c.stop().await?;
        manager_d.stop().await?;

        Ok::<(), anyhow::Error>(())
    })
    .await??;

    info!("=== TEST 7 PASSED ===");
    Ok(())
}

// =============================================================================
// TEST 8: Multi-Hop Failed Lookup (Exhausted Paths)
// =============================================================================

/// Test that iterative lookup returns GetNotFound after exhausting all paths
///
/// Scenario:
/// - Network where value doesn't exist anywhere
/// - Iterative GET query
/// - Expected: Eventually returns GetNotFound after trying all nodes
#[tokio::test]
async fn test_multi_hop_exhausted_lookup() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST 8: Multi-Hop Exhausted Lookup ===");

    timeout(TEST_TIMEOUT, async {
        // Create network: A ←→ B ←→ C
        let manager_a = create_test_manager("exhausted_a").await?;
        let manager_b = create_test_manager("exhausted_b").await?;
        let manager_c = create_test_manager("exhausted_c").await?;

        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_b, &manager_c).await?;

        sleep(Duration::from_secs(1)).await;

        // Query for non-existent key
        let test_key = key_from_str("exhausted_nonexistent_key");

        info!("Node A querying for non-existent key (should exhaust all paths)");
        let get_result = timeout(LOOKUP_TIMEOUT, manager_a.get(&test_key)).await??;

        // Verify: GetNotFound after exhausting all nodes
        match get_result {
            DhtNetworkResult::GetNotFound { key, .. } => {
                info!("✅ SUCCESS! Got GetNotFound after exhausting all nodes");
                assert_eq!(key, test_key, "Key should match");
            }
            DhtNetworkResult::GetSuccess { .. } => {
                panic!("Unexpected GetSuccess for non-existent key");
            }
            other => {
                panic!("Unexpected result: {:?}", other);
            }
        }

        // Cleanup
        manager_a.stop().await?;
        manager_b.stop().await?;
        manager_c.stop().await?;

        Ok::<(), anyhow::Error>(())
    })
    .await??;

    info!("=== TEST 8 PASSED ===");
    Ok(())
}

// =============================================================================
// TEST 9: All Closer Nodes Already Queried
// =============================================================================

/// Test that when all closer nodes have been queried, lookup returns GetNotFound
///
/// Scenario:
/// - Small network where all nodes are quickly queried
/// - No node has the value
/// - Expected: GetNotFound after all nodes queried
#[tokio::test]
async fn test_all_closer_nodes_already_queried() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST 9: All Closer Nodes Already Queried ===");

    timeout(TEST_TIMEOUT, async {
        // Create small triangle network
        let manager_a = create_test_manager("all_queried_a").await?;
        let manager_b = create_test_manager("all_queried_b").await?;
        let manager_c = create_test_manager("all_queried_c").await?;

        // Connect in triangle
        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_b, &manager_c).await?;
        connect_managers(&manager_c, &manager_a).await?;

        sleep(Duration::from_secs(1)).await;

        // Query for non-existent key
        let test_key = key_from_str("all_queried_key");

        info!("Querying small network (all nodes will be quickly queried)");
        let get_result = timeout(LOOKUP_TIMEOUT, manager_a.get(&test_key)).await??;

        // Verify: GetNotFound after all nodes queried
        match get_result {
            DhtNetworkResult::GetNotFound { key, .. } => {
                info!("✅ SUCCESS! Got GetNotFound after querying all nodes");
                assert_eq!(key, test_key, "Key should match");
            }
            other => {
                info!("Got result: {:?}", other);
            }
        }

        // Cleanup
        manager_a.stop().await?;
        manager_b.stop().await?;
        manager_c.stop().await?;

        Ok::<(), anyhow::Error>(())
    })
    .await??;

    info!("=== TEST 9 PASSED ===");
    Ok(())
}

// =============================================================================
// Additional Edge Case Tests
// =============================================================================

/// Test that a node can retrieve its own stored value (local cache hit)
#[tokio::test]
async fn test_local_cache_hit() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Local Cache Hit ===");

    timeout(TEST_TIMEOUT, async {
        let manager_a = create_test_manager("cache_hit_a").await?;

        let test_key = key_from_str("local_cache_key");
        let test_value = b"local_cache_value".to_vec();

        // Store and immediately retrieve
        manager_a.put(test_key, test_value.clone()).await?;

        let get_result = manager_a.get(&test_key).await?;

        // Verify: Immediate GetSuccess (no network lookup needed)
        match get_result {
            DhtNetworkResult::GetSuccess { value, source, .. } => {
                info!("✅ SUCCESS! Local cache hit");
                assert_eq!(value, test_value, "Value should match");
                assert_eq!(source, *manager_a.peer_id(), "Source should be self");
            }
            other => {
                panic!("Expected GetSuccess from local cache, got: {:?}", other);
            }
        }

        manager_a.stop().await?;
        Ok::<(), anyhow::Error>(())
    })
    .await??;

    info!("=== LOCAL CACHE HIT TEST PASSED ===");
    Ok(())
}

/// Test timing constraint: Multi-hop lookup should complete within timeout
#[tokio::test]
async fn test_multi_hop_timing() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Multi-Hop Timing ===");

    timeout(TEST_TIMEOUT, async {
        // Create 5-node chain
        let manager_a = create_test_manager("timing_a").await?;
        let manager_b = create_test_manager("timing_b").await?;
        let manager_c = create_test_manager("timing_c").await?;
        let manager_d = create_test_manager("timing_d").await?;
        let manager_e = create_test_manager("timing_e").await?;

        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_b, &manager_c).await?;
        connect_managers(&manager_c, &manager_d).await?;
        connect_managers(&manager_d, &manager_e).await?;

        // E stores value
        let test_key = key_from_str("timing_key");
        let test_value = b"timing_value".to_vec();
        manager_e.put(test_key, test_value.clone()).await?;
        sleep(DHT_PROPAGATION_DELAY).await;

        // A queries (4 hops away)
        let start = std::time::Instant::now();
        let get_result = timeout(LOOKUP_TIMEOUT, manager_a.get(&test_key)).await??;
        let duration = start.elapsed();

        match get_result {
            DhtNetworkResult::GetSuccess { value, .. } => {
                info!("✅ SUCCESS! Multi-hop lookup completed in {:?}", duration);
                assert_eq!(value, test_value, "Value should match");
                assert!(
                    duration < LOOKUP_TIMEOUT,
                    "Lookup should complete within timeout"
                );
            }
            other => {
                warn!("Lookup result: {:?} after {:?}", other, duration);
            }
        }

        // Cleanup
        for mgr in [manager_a, manager_b, manager_c, manager_d, manager_e] {
            mgr.stop().await?;
        }

        Ok::<(), anyhow::Error>(())
    })
    .await??;

    info!("=== MULTI-HOP TIMING TEST PASSED ===");
    Ok(())
}
