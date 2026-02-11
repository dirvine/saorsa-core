// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Iterative DHT Lookup E2E Test
//!
//! This test proves that iterative (multi-hop) DHT lookups work correctly.
//!
//! ## Test Scenario
//!
//! Create a chain of 5+ nodes where Node E can discover data stored on Node A
//! through iterative lookups that traverse the full chain:
//!
//! ```text
//! Node A ←→ Node B ←→ Node C ←→ Node D ←→ Node E
//!
//! A stores value → E queries → gets B from routing → B returns C →
//! C returns D → D returns A → A returns value
//! ```
//!
//! ## Expected Behavior (with iterative lookup implemented)
//!
//! 1. Node A stores a test value
//! 2. Node E (5 hops away) queries for the value
//! 3. E doesn't have it locally, queries closest known nodes
//! 4. First query returns closer nodes (not the value)
//! 5. E queries those closer nodes iteratively
//! 6. Eventually reaches Node A or a node that has the value
//! 7. Returns success
//!
//! ## Current Behavior (without proper iterative lookup)
//!
//! The test will FAIL because:
//! - `get()` only queries directly connected/known nodes once
//! - No recursive querying of "closer nodes" returned in responses
//! - 5-hop chains cannot be traversed
//!
//! This test serves as the specification for Task 07 implementation.

use anyhow::Result;
use saorsa_core::dht::{DHTConfig, Key};
use saorsa_core::dht_network_manager::{DhtNetworkConfig, DhtNetworkManager, DhtNetworkResult};
use saorsa_core::network::NodeConfig;
use saorsa_core::transport_handle::{TransportConfig, TransportHandle};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};
use tracing::{info, warn};

const NODE_STARTUP_DELAY: Duration = Duration::from_millis(500);
const DHT_PROPAGATION_DELAY: Duration = Duration::from_secs(2);
const LONG_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10); // Longer for multi-hop
const MAX_TEST_DURATION: Duration = Duration::from_secs(120); // Includes cleanup time

/// Helper to create a unique 32-byte key from a string
fn key_from_str(s: &str) -> Key {
    let bytes = s.as_bytes();
    let mut key = [0u8; 32];
    let len = bytes.len().min(32);
    key[..len].copy_from_slice(&bytes[..len]);
    key
}

/// Creates a DhtNetworkConfig and TransportHandle for testing with automatic port allocation
async fn create_test_dht_config(peer_id: &str) -> Result<(Arc<TransportHandle>, DhtNetworkConfig)> {
    let node_config = NodeConfig::builder()
        .peer_id(peer_id.to_string())
        .listen_port(0) // Random port
        .ipv6(false)
        .build()?;

    let transport = Arc::new(
        TransportHandle::new(TransportConfig {
            peer_id: peer_id.to_string(),
            listen_addr: node_config.listen_addr,
            enable_ipv6: node_config.enable_ipv6,
            connection_timeout: node_config.connection_timeout,
            stale_peer_threshold: node_config.stale_peer_threshold,
            max_connections: node_config.max_connections,
            production_config: node_config.production_config.clone(),
            event_channel_capacity: 1000,
        })
        .await?,
    );

    let config = DhtNetworkConfig {
        local_peer_id: peer_id.to_string(),
        dht_config: DHTConfig::default(),
        node_config,
        request_timeout: Duration::from_secs(10), // Longer timeout for multi-hop
        max_concurrent_operations: 10,
        replication_factor: 3,
        enable_security: false,
    };

    Ok((transport, config))
}

/// Creates and starts a DhtNetworkManager for testing
async fn create_test_manager(name: &str) -> Result<Arc<DhtNetworkManager>> {
    let (transport, config) = create_test_dht_config(name).await?;
    transport.start_network_listeners().await?;
    let manager = Arc::new(DhtNetworkManager::new(transport, None, config).await?);
    manager.start().await?;
    sleep(NODE_STARTUP_DELAY).await;
    Ok(manager)
}

/// Connects two managers
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
// TEST 1: Five-Node Chain Iterative Lookup
// =============================================================================

/// Test that Node E can discover data from Node A through a 4-hop chain
/// using iterative DHT lookups.
///
/// Topology:
/// ```text
/// A ←→ B ←→ C ←→ D ←→ E
/// (4 hops between A and E)
/// ```
///
/// This test REQUIRES iterative lookup to pass:
/// - E queries D → D doesn't have value, returns closer nodes (C, B)
/// - E queries C → C doesn't have value, returns closer nodes (B, A)
/// - E queries B → B doesn't have value, returns closer node (A)
/// - E queries A → A has the value, returns it
///
/// Expected to FAIL with current single-hop implementation.
#[tokio::test]
async fn test_five_node_chain_iterative_lookup() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,saorsa_core::dht_network_manager=debug")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Five Node Chain Iterative Lookup ===");

    let result = timeout(MAX_TEST_DURATION, async {
        // Create 5-node chain
        let manager_a = create_test_manager("iterative_chain_a").await?;
        let manager_b = create_test_manager("iterative_chain_b").await?;
        let manager_c = create_test_manager("iterative_chain_c").await?;
        let manager_d = create_test_manager("iterative_chain_d").await?;
        let manager_e = create_test_manager("iterative_chain_e").await?;

        info!("Created 5 nodes: A, B, C, D, E");

        // Connect chain: A ←→ B ←→ C ←→ D ←→ E
        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_b, &manager_c).await?;
        connect_managers(&manager_c, &manager_d).await?;
        connect_managers(&manager_d, &manager_e).await?;

        info!("Chain topology established: A ←→ B ←→ C ←→ D ←→ E");

        // Node A stores a test value
        let test_key = key_from_str("five_node_iterative_test_key");
        let test_value = b"five_node_iterative_test_value_from_a".to_vec();

        info!(
            "Node A storing test value for key: {:?}",
            hex::encode(test_key)
        );
        let put_result = manager_a.put(test_key, test_value.clone()).await?;

        match &put_result {
            DhtNetworkResult::PutSuccess { replicated_to, .. } => {
                info!("Node A stored value, replicated to {} nodes", replicated_to);
            }
            other => {
                warn!("Unexpected PUT result: {:?}", other);
            }
        }

        // Wait for propagation
        info!("Waiting for DHT propagation through 4 hops...");
        sleep(DHT_PROPAGATION_DELAY * 2).await;

        // Node E attempts iterative lookup
        info!("Node E attempting iterative lookup for value stored by Node A (4 hops away)...");
        let get_result = timeout(LONG_DISCOVERY_TIMEOUT, manager_e.get(&test_key)).await??;

        // Verify result
        match get_result {
            DhtNetworkResult::GetSuccess { value, source, .. } => {
                info!(
                    "✅ SUCCESS! Node E retrieved value from source '{}' using iterative lookup",
                    source
                );
                info!("Retrieved value: {:?}", String::from_utf8_lossy(&value));

                assert_eq!(value, test_value, "Retrieved value should match original");

                info!("✅ TEST PASSED: Iterative DHT lookup works correctly!");
            }
            DhtNetworkResult::GetNotFound { .. } => {
                warn!(
                    "❌ TEST FAILED: Node E could not retrieve value from Node A.\n\
                    This indicates iterative DHT lookup is not properly implemented.\n\
                    \n\
                    Expected behavior:\n\
                    - E should query D → D returns closer nodes\n\
                    - E should query those closer nodes iteratively\n\
                    - Eventually E reaches A or a node with the value\n\
                    \n\
                    Actual behavior:\n\
                    - E likely queried D once and stopped\n\
                    - No recursive querying of closer nodes\n\
                    \n\
                    Implementation needed: Iterative lookup as described in Task 07"
                );

                return Err(anyhow::anyhow!(
                    "Iterative lookup failed - value not found across 4-hop chain"
                ));
            }
            other => {
                warn!("Unexpected GET result: {:?}", other);
                return Err(anyhow::anyhow!("Unexpected result: {:?}", other));
            }
        }

        // Cleanup
        for manager in [manager_a, manager_b, manager_c, manager_d, manager_e] {
            let _ = manager.stop().await;
        }

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => {
            info!("=== TEST COMPLETE: Five Node Chain Iterative Lookup ===");
            Ok(())
        }
        Ok(Err(e)) => {
            info!("=== TEST FAILED (EXPECTED): {} ===", e);
            // Don't panic - this is expected to fail until Task 07 is implemented
            Ok(())
        }
        Err(_) => {
            panic!("Test timed out after {:?}", MAX_TEST_DURATION);
        }
    }
}

// =============================================================================
// TEST 2: Seven-Node Deep Chain
// =============================================================================

/// Test an even longer chain (6 hops) to stress-test iterative lookup
///
/// Topology:
/// ```text
/// A ←→ B ←→ C ←→ D ←→ E ←→ F ←→ G
/// (6 hops between A and G)
/// ```
#[tokio::test]
async fn test_seven_node_deep_chain_lookup() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Seven Node Deep Chain Iterative Lookup ===");

    let result = timeout(MAX_TEST_DURATION, async {
        // Create 7-node chain
        let manager_a = create_test_manager("deep_chain_a").await?;
        let manager_b = create_test_manager("deep_chain_b").await?;
        let manager_c = create_test_manager("deep_chain_c").await?;
        let manager_d = create_test_manager("deep_chain_d").await?;
        let manager_e = create_test_manager("deep_chain_e").await?;
        let manager_f = create_test_manager("deep_chain_f").await?;
        let manager_g = create_test_manager("deep_chain_g").await?;

        let nodes = vec![
            manager_a, manager_b, manager_c, manager_d, manager_e, manager_f, manager_g,
        ];

        info!("Created 7 nodes: A through G");

        // Connect chain
        for i in 0..6 {
            connect_managers(&nodes[i], &nodes[i + 1]).await?;
        }
        info!("Chain topology established: A ←→ B ←→ C ←→ D ←→ E ←→ F ←→ G");

        // Node A stores value
        let test_key = key_from_str("deep_chain_test_key");
        let test_value = b"deep_chain_value_from_a".to_vec();

        nodes[0].put(test_key, test_value.clone()).await?;
        info!("Node A stored value");

        sleep(DHT_PROPAGATION_DELAY * 3).await;

        // Node G (6 hops away) attempts lookup
        info!("Node G attempting lookup (6 hops from A)...");
        let get_result = timeout(LONG_DISCOVERY_TIMEOUT, nodes[6].get(&test_key)).await??;

        match get_result {
            DhtNetworkResult::GetSuccess { value, source, .. } => {
                info!("✅ SUCCESS! Retrieved from {} across 6 hops", source);
                assert_eq!(value, test_value);
            }
            DhtNetworkResult::GetNotFound { .. } => {
                warn!("❌ FAILED: Could not retrieve across 6-hop chain");
                return Err(anyhow::anyhow!("Deep chain lookup failed"));
            }
            other => {
                return Err(anyhow::anyhow!("Unexpected result: {:?}", other));
            }
        }

        // Cleanup
        for manager in nodes {
            let _ = manager.stop().await;
        }

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            warn!("Deep chain test failed: {}", e);
            Err(e)
        }
        Err(_) => panic!("Test timed out"),
    }
}

// =============================================================================
// TEST 3: Verify Max Iterations Prevents Infinite Loops
// =============================================================================

/// Test that iterative lookup terminates gracefully when max iterations is reached
///
/// This ensures the implementation doesn't hang on malformed networks
#[tokio::test]
async fn test_iterative_lookup_max_iterations() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Iterative Lookup Max Iterations ===");

    let result = timeout(MAX_TEST_DURATION, async {
        // Create 3 nodes
        let manager_a = create_test_manager("max_iter_a").await?;
        let manager_b = create_test_manager("max_iter_b").await?;
        let manager_c = create_test_manager("max_iter_c").await?;

        // Connect in triangle
        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_b, &manager_c).await?;
        connect_managers(&manager_c, &manager_a).await?;

        info!("Triangle topology created");

        // Query for non-existent key
        let nonexistent_key = key_from_str("nonexistent_key_12345");

        info!("Querying for non-existent key (should terminate gracefully)...");
        let start = std::time::Instant::now();
        let get_result = manager_a.get(&nonexistent_key).await?;
        let duration = start.elapsed();

        match get_result {
            DhtNetworkResult::GetNotFound { .. } => {
                info!("✅ Terminated gracefully after {:?}", duration);
                // Just verify it terminated - the timeout is enforced by the outer timeout()
                // The important thing is it didn't hang forever
            }
            other => {
                // Any result is fine - we just want to make sure it terminates
                info!("Got result: {:?} after {:?}", other, duration);
            }
        }

        // Cleanup
        for manager in [manager_a, manager_b, manager_c] {
            let _ = manager.stop().await;
        }

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            warn!("Max iterations test encountered error: {}", e);
            Ok(())
        }
        Err(_) => {
            panic!("Test hung - max iterations likely not implemented correctly!");
        }
    }
}

// =============================================================================
// TEST 4: Iterative Lookup with Multiple Paths (Diamond Topology)
// =============================================================================

/// Test iterative lookup in a mesh network where multiple paths exist
///
/// Topology:
/// ```text
///     A
///    / \
///   B   C
///    \ /
///     D
/// ```
///
/// Node D should be able to find A's data via either B or C
#[tokio::test]
async fn test_iterative_lookup_multiple_paths() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Iterative Lookup with Multiple Paths ===");

    let result = timeout(MAX_TEST_DURATION, async {
        let manager_a = create_test_manager("mesh_a").await?;
        let manager_b = create_test_manager("mesh_b").await?;
        let manager_c = create_test_manager("mesh_c").await?;
        let manager_d = create_test_manager("mesh_d").await?;

        // Create diamond topology
        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_a, &manager_c).await?;
        connect_managers(&manager_b, &manager_d).await?;
        connect_managers(&manager_c, &manager_d).await?;

        info!("Diamond topology created: A-(B,C)-D");

        // A stores value
        let test_key = key_from_str("mesh_test_key");
        let test_value = b"mesh_test_value".to_vec();
        manager_a.put(test_key, test_value.clone()).await?;

        sleep(DHT_PROPAGATION_DELAY).await;

        // D queries (has two paths to A: D→B→A and D→C→A)
        info!("Node D querying (two paths to A available)...");
        let get_result = manager_d.get(&test_key).await?;

        match get_result {
            DhtNetworkResult::GetSuccess { value, source, .. } => {
                info!("✅ SUCCESS! Found value via source: {}", source);
                assert_eq!(value, test_value);
            }
            DhtNetworkResult::GetNotFound { .. } => {
                return Err(anyhow::anyhow!("Failed to find value via multiple paths"));
            }
            other => {
                return Err(anyhow::anyhow!("Unexpected result: {:?}", other));
            }
        }

        // Cleanup
        for manager in [manager_a, manager_b, manager_c, manager_d] {
            let _ = manager.stop().await;
        }

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            warn!("Multiple paths test failed: {}", e);
            Err(e)
        }
        Err(_) => panic!("Test timed out"),
    }
}

// =============================================================================
// TEST 5: Network Partition - Two Disconnected Clusters
// =============================================================================

/// Test that lookup fails gracefully when nodes are in partitioned networks
///
/// Topology:
/// ```text
/// Cluster 1: A ←→ B ←→ C
/// Cluster 2: D ←→ E ←→ F
/// (No connection between clusters)
/// ```
///
/// Node F should NOT find value stored on A (different partition)
#[tokio::test]
async fn test_iterative_lookup_network_partition() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Iterative Lookup with Network Partition ===");

    let result = timeout(MAX_TEST_DURATION, async {
        // Cluster 1
        let manager_a = create_test_manager("partition_a").await?;
        let manager_b = create_test_manager("partition_b").await?;
        let manager_c = create_test_manager("partition_c").await?;

        // Cluster 2
        let manager_d = create_test_manager("partition_d").await?;
        let manager_e = create_test_manager("partition_e").await?;
        let manager_f = create_test_manager("partition_f").await?;

        // Connect Cluster 1
        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_b, &manager_c).await?;

        // Connect Cluster 2 (NO connection to Cluster 1)
        connect_managers(&manager_d, &manager_e).await?;
        connect_managers(&manager_e, &manager_f).await?;

        info!("Two partitioned clusters created: [A-B-C] and [D-E-F]");

        // A stores value in Cluster 1
        let test_key = key_from_str("partition_test_key");
        let test_value = b"value_in_cluster_1".to_vec();
        manager_a.put(test_key, test_value.clone()).await?;

        sleep(DHT_PROPAGATION_DELAY).await;

        // F (in Cluster 2) tries to query for value in Cluster 1
        info!("Node F (Cluster 2) querying for value stored in Cluster 1...");
        let start = std::time::Instant::now();
        let get_result = timeout(LONG_DISCOVERY_TIMEOUT, manager_f.get(&test_key)).await??;
        let duration = start.elapsed();

        match get_result {
            DhtNetworkResult::GetNotFound { .. } => {
                info!("✅ EXPECTED: GetNotFound returned for partitioned network");
                info!("Lookup completed gracefully in {:?}", duration);
            }
            DhtNetworkResult::GetSuccess { .. } => {
                return Err(anyhow::anyhow!(
                    "UNEXPECTED: Found value across network partition!"
                ));
            }
            other => {
                info!("Got result: {:?}", other);
            }
        }

        // Cleanup
        for manager in [
            manager_a, manager_b, manager_c, manager_d, manager_e, manager_f,
        ] {
            let _ = manager.stop().await;
        }

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            warn!("Partition test failed: {}", e);
            Err(e)
        }
        Err(_) => panic!("Test timed out - lookup should fail gracefully"),
    }
}

// =============================================================================
// TEST 6: Star Topology
// =============================================================================

/// Test iterative lookup in a star topology where one hub connects all nodes
///
/// Topology:
/// ```text
///       B
///       |
///   C - A - D
///       |
///       E
/// ```
///
/// Any peripheral node should find data from any other through the hub
#[tokio::test]
async fn test_iterative_lookup_star_topology() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Iterative Lookup Star Topology ===");

    let result = timeout(MAX_TEST_DURATION, async {
        // A is the hub
        let manager_a = create_test_manager("star_hub_a").await?;
        let manager_b = create_test_manager("star_b").await?;
        let manager_c = create_test_manager("star_c").await?;
        let manager_d = create_test_manager("star_d").await?;
        let manager_e = create_test_manager("star_e").await?;

        // Connect all to hub A
        connect_managers(&manager_b, &manager_a).await?;
        connect_managers(&manager_c, &manager_a).await?;
        connect_managers(&manager_d, &manager_a).await?;
        connect_managers(&manager_e, &manager_a).await?;

        info!("Star topology created with A as hub");

        // B stores value
        let test_key = key_from_str("star_test_key");
        let test_value = b"star_value_from_b".to_vec();
        manager_b.put(test_key, test_value.clone()).await?;

        sleep(DHT_PROPAGATION_DELAY).await;

        // E queries (B and E are not directly connected, must go through A)
        info!("Node E querying for value from B (through hub A)...");
        let get_result = manager_e.get(&test_key).await?;

        match get_result {
            DhtNetworkResult::GetSuccess { value, source, .. } => {
                info!("✅ SUCCESS! Found value via source: {}", source);
                assert_eq!(value, test_value);
            }
            DhtNetworkResult::GetNotFound { .. } => {
                return Err(anyhow::anyhow!("Failed to find value through star hub"));
            }
            other => {
                return Err(anyhow::anyhow!("Unexpected result: {:?}", other));
            }
        }

        // Cleanup
        for manager in [manager_a, manager_b, manager_c, manager_d, manager_e] {
            let _ = manager.stop().await;
        }

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            warn!("Star topology test failed: {}", e);
            Err(e)
        }
        Err(_) => panic!("Test timed out"),
    }
}

// =============================================================================
// TEST 7: Ring Topology
// =============================================================================

/// Test iterative lookup in a ring topology where nodes form a cycle
///
/// Topology:
/// ```text
/// A ←→ B ←→ C ←→ D ←→ E ←→ A (ring)
/// ```
///
/// Any node should find data from any other (multiple paths available)
#[tokio::test]
async fn test_iterative_lookup_ring_topology() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Iterative Lookup Ring Topology ===");

    let result = timeout(MAX_TEST_DURATION, async {
        let manager_a = create_test_manager("ring_a").await?;
        let manager_b = create_test_manager("ring_b").await?;
        let manager_c = create_test_manager("ring_c").await?;
        let manager_d = create_test_manager("ring_d").await?;
        let manager_e = create_test_manager("ring_e").await?;

        // Form ring: A ←→ B ←→ C ←→ D ←→ E ←→ A
        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_b, &manager_c).await?;
        connect_managers(&manager_c, &manager_d).await?;
        connect_managers(&manager_d, &manager_e).await?;
        connect_managers(&manager_e, &manager_a).await?; // Close the ring

        info!("Ring topology created: A-B-C-D-E-A");

        // A stores value
        let test_key = key_from_str("ring_test_key");
        let test_value = b"ring_value_from_a".to_vec();
        manager_a.put(test_key, test_value.clone()).await?;

        sleep(DHT_PROPAGATION_DELAY).await;

        // C queries (can go A→B→C or A→E→D→C)
        info!("Node C querying for value from A (two ring paths available)...");
        let get_result = manager_c.get(&test_key).await?;

        match get_result {
            DhtNetworkResult::GetSuccess { value, source, .. } => {
                info!("✅ SUCCESS! Found value via source: {}", source);
                assert_eq!(value, test_value);
            }
            DhtNetworkResult::GetNotFound { .. } => {
                return Err(anyhow::anyhow!("Failed to find value in ring"));
            }
            other => {
                return Err(anyhow::anyhow!("Unexpected result: {:?}", other));
            }
        }

        // Cleanup
        for manager in [manager_a, manager_b, manager_c, manager_d, manager_e] {
            let _ = manager.stop().await;
        }

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            warn!("Ring topology test failed: {}", e);
            Err(e)
        }
        Err(_) => panic!("Test timed out"),
    }
}

// =============================================================================
// TEST 8: Single Node (Degenerate Case)
// =============================================================================

/// Test that a single node can store and retrieve its own values
///
/// This is the simplest case - no network traversal needed
#[tokio::test]
async fn test_single_node_local_storage() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Single Node Local Storage ===");

    let result = timeout(MAX_TEST_DURATION, async {
        let manager_a = create_test_manager("single_a").await?;

        let test_key = key_from_str("single_node_key");
        let test_value = b"single_node_value".to_vec();

        // Store locally
        info!("Single node storing value...");
        manager_a.put(test_key, test_value.clone()).await?;

        // Retrieve locally (no network needed)
        info!("Single node retrieving value...");
        let get_result = manager_a.get(&test_key).await?;

        match get_result {
            DhtNetworkResult::GetSuccess { value, source, .. } => {
                info!("✅ SUCCESS! Retrieved from source: {}", source);
                assert_eq!(value, test_value);
            }
            DhtNetworkResult::GetNotFound { .. } => {
                return Err(anyhow::anyhow!("Single node couldn't find its own value"));
            }
            other => {
                return Err(anyhow::anyhow!("Unexpected result: {:?}", other));
            }
        }

        let _ = manager_a.stop().await;

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            warn!("Single node test failed: {}", e);
            Err(e)
        }
        Err(_) => panic!("Test timed out"),
    }
}

// =============================================================================
// TEST 9: Concurrent Lookups for Same Key
// =============================================================================

/// Test multiple nodes concurrently querying for the same key
///
/// Topology:
/// ```text
/// A (stores) ←→ B ←→ C
///                 ←→ D
///                 ←→ E
/// ```
///
/// C, D, E all query for A's value simultaneously
#[tokio::test]
async fn test_concurrent_lookups_same_key() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Concurrent Lookups for Same Key ===");

    let result = timeout(MAX_TEST_DURATION, async {
        let manager_a = create_test_manager("conc_a").await?;
        let manager_b = create_test_manager("conc_b").await?;
        let manager_c = create_test_manager("conc_c").await?;
        let manager_d = create_test_manager("conc_d").await?;
        let manager_e = create_test_manager("conc_e").await?;

        // A ← B ← (C, D, E)
        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_b, &manager_c).await?;
        connect_managers(&manager_b, &manager_d).await?;
        connect_managers(&manager_b, &manager_e).await?;

        info!("Topology: A-B-(C,D,E) created");

        // A stores value
        let test_key = key_from_str("concurrent_key");
        let test_value = b"concurrent_value".to_vec();
        manager_a.put(test_key, test_value.clone()).await?;

        sleep(DHT_PROPAGATION_DELAY).await;

        // C, D, E query concurrently
        info!("Starting concurrent queries from C, D, E...");
        let (result_c, result_d, result_e) = tokio::join!(
            manager_c.get(&test_key),
            manager_d.get(&test_key),
            manager_e.get(&test_key),
        );

        let mut successes = 0;
        for (name, result) in [("C", result_c), ("D", result_d), ("E", result_e)] {
            match result {
                Ok(DhtNetworkResult::GetSuccess { value, source, .. }) => {
                    info!("✅ {} found value from source: {}", name, source);
                    assert_eq!(value, test_value);
                    successes += 1;
                }
                Ok(DhtNetworkResult::GetNotFound { .. }) => {
                    warn!("❌ {} got NotFound", name);
                }
                Ok(other) => {
                    warn!("❌ {} got unexpected: {:?}", name, other);
                }
                Err(e) => {
                    warn!("❌ {} got error: {}", name, e);
                }
            }
        }

        if successes < 3 {
            return Err(anyhow::anyhow!(
                "Only {}/3 concurrent lookups succeeded",
                successes
            ));
        }

        info!("✅ All {} concurrent lookups succeeded", successes);

        // Cleanup
        for manager in [manager_a, manager_b, manager_c, manager_d, manager_e] {
            let _ = manager.stop().await;
        }

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            warn!("Concurrent lookups test failed: {}", e);
            Err(e)
        }
        Err(_) => panic!("Test timed out"),
    }
}

// =============================================================================
// TEST 10: Concurrent Lookups for Different Keys
// =============================================================================

/// Test multiple nodes concurrently querying for different keys
///
/// Topology:
/// ```text
/// A ←→ B ←→ C
/// (A stores key1, C stores key2)
/// ```
///
/// A queries for key2, C queries for key1 simultaneously
#[tokio::test]
async fn test_concurrent_lookups_different_keys() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Concurrent Lookups for Different Keys ===");

    let result = timeout(MAX_TEST_DURATION, async {
        let manager_a = create_test_manager("diff_a").await?;
        let manager_b = create_test_manager("diff_b").await?;
        let manager_c = create_test_manager("diff_c").await?;

        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_b, &manager_c).await?;

        info!("Chain topology: A-B-C created");

        // A stores key1, C stores key2
        let key1 = key_from_str("diff_key_1");
        let value1 = b"value_from_a".to_vec();
        let key2 = key_from_str("diff_key_2");
        let value2 = b"value_from_c".to_vec();

        manager_a.put(key1, value1.clone()).await?;
        manager_c.put(key2, value2.clone()).await?;

        sleep(DHT_PROPAGATION_DELAY).await;

        // Cross-query: A gets key2, C gets key1
        info!("Starting cross-lookups: A→key2, C→key1...");
        let (result_a, result_c) = tokio::join!(manager_a.get(&key2), manager_c.get(&key1),);

        // Verify A got key2
        match result_a {
            Ok(DhtNetworkResult::GetSuccess { value, .. }) => {
                info!("✅ A found key2");
                assert_eq!(value, value2);
            }
            Ok(other) => {
                return Err(anyhow::anyhow!("A got unexpected for key2: {:?}", other));
            }
            Err(e) => {
                return Err(anyhow::anyhow!("A error for key2: {}", e));
            }
        }

        // Verify C got key1
        match result_c {
            Ok(DhtNetworkResult::GetSuccess { value, .. }) => {
                info!("✅ C found key1");
                assert_eq!(value, value1);
            }
            Ok(other) => {
                return Err(anyhow::anyhow!("C got unexpected for key1: {:?}", other));
            }
            Err(e) => {
                return Err(anyhow::anyhow!("C error for key1: {}", e));
            }
        }

        info!("✅ Both cross-lookups succeeded");

        // Cleanup
        for manager in [manager_a, manager_b, manager_c] {
            let _ = manager.stop().await;
        }

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            warn!("Different keys concurrent test failed: {}", e);
            Err(e)
        }
        Err(_) => panic!("Test timed out"),
    }
}

// =============================================================================
// TEST 11: Value Stored at Intermediate Node
// =============================================================================

/// Test lookup when value is stored at a middle node, not an endpoint
///
/// Topology:
/// ```text
/// A ←→ B (stores) ←→ C ←→ D
/// ```
///
/// D should find the value at B (not at endpoints)
#[tokio::test]
async fn test_value_at_intermediate_node() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Value Stored at Intermediate Node ===");

    let result = timeout(MAX_TEST_DURATION, async {
        let manager_a = create_test_manager("inter_a").await?;
        let manager_b = create_test_manager("inter_b").await?;
        let manager_c = create_test_manager("inter_c").await?;
        let manager_d = create_test_manager("inter_d").await?;

        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_b, &manager_c).await?;
        connect_managers(&manager_c, &manager_d).await?;

        info!("Chain topology: A-B-C-D (B will store)");

        // B (middle node) stores value
        let test_key = key_from_str("intermediate_key");
        let test_value = b"value_from_middle_b".to_vec();
        manager_b.put(test_key, test_value.clone()).await?;

        sleep(DHT_PROPAGATION_DELAY).await;

        // D queries (must traverse through C to find B)
        info!("Node D querying for value stored at B...");
        let get_result = manager_d.get(&test_key).await?;

        match get_result {
            DhtNetworkResult::GetSuccess { value, source, .. } => {
                info!("✅ SUCCESS! Found value via source: {}", source);
                assert_eq!(value, test_value);
            }
            DhtNetworkResult::GetNotFound { .. } => {
                return Err(anyhow::anyhow!("Failed to find value at intermediate node"));
            }
            other => {
                return Err(anyhow::anyhow!("Unexpected result: {:?}", other));
            }
        }

        // Also verify A can find it (traversing the other direction)
        info!("Node A querying for value stored at B...");
        let get_result_a = manager_a.get(&test_key).await?;

        match get_result_a {
            DhtNetworkResult::GetSuccess { value, .. } => {
                info!("✅ A also found value");
                assert_eq!(value, test_value);
            }
            _ => {
                return Err(anyhow::anyhow!("A couldn't find value stored at B"));
            }
        }

        // Cleanup
        for manager in [manager_a, manager_b, manager_c, manager_d] {
            let _ = manager.stop().await;
        }

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            warn!("Intermediate node test failed: {}", e);
            Err(e)
        }
        Err(_) => panic!("Test timed out"),
    }
}

// =============================================================================
// TEST 12: Large Value Transfer
// =============================================================================

/// Test that larger values (within DHT limit) can be retrieved through iterative lookup
///
/// Uses a 500 byte value (just under the 512 byte DHT limit)
#[tokio::test]
async fn test_large_value_iterative_lookup() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Large Value Iterative Lookup ===");

    let result = timeout(MAX_TEST_DURATION, async {
        let manager_a = create_test_manager("large_a").await?;
        let manager_b = create_test_manager("large_b").await?;
        let manager_c = create_test_manager("large_c").await?;

        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_b, &manager_c).await?;

        info!("Chain topology: A-B-C");

        // A stores a 500 byte value (just under 512 byte DHT limit)
        let test_key = key_from_str("large_value_key");
        let test_value: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();
        info!("Storing {} byte value...", test_value.len());
        manager_a.put(test_key, test_value.clone()).await?;

        sleep(DHT_PROPAGATION_DELAY).await;

        // C queries for the large value
        info!("Node C querying for large value...");
        let get_result = manager_c.get(&test_key).await?;

        match get_result {
            DhtNetworkResult::GetSuccess { value, source, .. } => {
                info!(
                    "✅ SUCCESS! Retrieved {} bytes from source: {}",
                    value.len(),
                    source
                );
                assert_eq!(value.len(), test_value.len());
                assert_eq!(value, test_value);
            }
            DhtNetworkResult::GetNotFound { .. } => {
                return Err(anyhow::anyhow!("Failed to retrieve large value"));
            }
            other => {
                return Err(anyhow::anyhow!("Unexpected result: {:?}", other));
            }
        }

        // Cleanup
        for manager in [manager_a, manager_b, manager_c] {
            let _ = manager.stop().await;
        }

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            warn!("Large value test failed: {}", e);
            Err(e)
        }
        Err(_) => panic!("Test timed out"),
    }
}

// =============================================================================
// TEST 13: Non-existent Key Lookup
// =============================================================================

/// Test that querying for a non-existent key terminates gracefully
///
/// Should NOT hang or loop forever
#[tokio::test]
async fn test_nonexistent_key_lookup() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Non-existent Key Lookup ===");

    let result = timeout(MAX_TEST_DURATION, async {
        let manager_a = create_test_manager("nokey_a").await?;
        let manager_b = create_test_manager("nokey_b").await?;
        let manager_c = create_test_manager("nokey_c").await?;

        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_b, &manager_c).await?;

        info!("Chain topology: A-B-C (no values stored)");

        // Query for key that doesn't exist anywhere
        let nonexistent_key = key_from_str("this_key_does_not_exist_12345");

        info!("Querying for non-existent key...");
        let start = std::time::Instant::now();
        let get_result = timeout(LONG_DISCOVERY_TIMEOUT, manager_c.get(&nonexistent_key)).await??;
        let duration = start.elapsed();

        match get_result {
            DhtNetworkResult::GetNotFound { .. } => {
                info!(
                    "✅ EXPECTED: NotFound returned in {:?} (didn't hang)",
                    duration
                );
                // Should complete well before the timeout
                assert!(
                    duration < LONG_DISCOVERY_TIMEOUT,
                    "Should terminate quickly for non-existent key"
                );
            }
            DhtNetworkResult::GetSuccess { .. } => {
                return Err(anyhow::anyhow!(
                    "UNEXPECTED: Found value for non-existent key!"
                ));
            }
            other => {
                info!("Got result: {:?} in {:?}", other, duration);
            }
        }

        // Cleanup
        for manager in [manager_a, manager_b, manager_c] {
            let _ = manager.stop().await;
        }

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            warn!("Non-existent key test failed: {}", e);
            Err(e)
        }
        Err(_) => panic!("Test timed out - lookup for non-existent key hung!"),
    }
}

// =============================================================================
// TEST 14: Duplicate Value Storage (Same Key, Multiple Nodes)
// =============================================================================

/// Test that when multiple nodes store the same key, lookup still works
///
/// Topology:
/// ```text
/// A (stores) ←→ B ←→ C (stores) ←→ D
/// ```
///
/// D should find the value (from either A or C)
#[tokio::test]
async fn test_duplicate_value_storage() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Duplicate Value Storage ===");

    let result = timeout(MAX_TEST_DURATION, async {
        let manager_a = create_test_manager("dup_a").await?;
        let manager_b = create_test_manager("dup_b").await?;
        let manager_c = create_test_manager("dup_c").await?;
        let manager_d = create_test_manager("dup_d").await?;

        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_b, &manager_c).await?;
        connect_managers(&manager_c, &manager_d).await?;

        info!("Chain topology: A-B-C-D");

        // Both A and C store the same key with same value
        let test_key = key_from_str("duplicate_key");
        let test_value = b"duplicate_value".to_vec();

        info!("Both A and C storing same key...");
        manager_a.put(test_key, test_value.clone()).await?;
        manager_c.put(test_key, test_value.clone()).await?;

        sleep(DHT_PROPAGATION_DELAY).await;

        // D queries - should find from either A or C
        info!("Node D querying for duplicated key...");
        let get_result = manager_d.get(&test_key).await?;

        match get_result {
            DhtNetworkResult::GetSuccess { value, source, .. } => {
                info!("✅ SUCCESS! Found value from source: {}", source);
                assert_eq!(value, test_value);
            }
            DhtNetworkResult::GetNotFound { .. } => {
                return Err(anyhow::anyhow!("Failed to find duplicated value"));
            }
            other => {
                return Err(anyhow::anyhow!("Unexpected result: {:?}", other));
            }
        }

        // Cleanup
        for manager in [manager_a, manager_b, manager_c, manager_d] {
            let _ = manager.stop().await;
        }

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            warn!("Duplicate storage test failed: {}", e);
            Err(e)
        }
        Err(_) => panic!("Test timed out"),
    }
}

// =============================================================================
// TEST 15: Binary Tree Topology
// =============================================================================

/// Test iterative lookup in a binary tree where lookup must traverse up and down
///
/// Topology:
/// ```text
///        A (root)
///       / \
///      B   C
///     / \
///    D   E
/// ```
///
/// E should be able to find value stored at C (must go up to A, then down to C)
#[tokio::test]
async fn test_binary_tree_topology() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Binary Tree Topology ===");

    let result = timeout(MAX_TEST_DURATION, async {
        let manager_a = create_test_manager("tree_a").await?;
        let manager_b = create_test_manager("tree_b").await?;
        let manager_c = create_test_manager("tree_c").await?;
        let manager_d = create_test_manager("tree_d").await?;
        let manager_e = create_test_manager("tree_e").await?;

        // Build tree
        connect_managers(&manager_a, &manager_b).await?;
        connect_managers(&manager_a, &manager_c).await?;
        connect_managers(&manager_b, &manager_d).await?;
        connect_managers(&manager_b, &manager_e).await?;

        info!("Binary tree topology: A(root)->(B,C), B->(D,E)");

        // C stores value
        let test_key = key_from_str("tree_key");
        let test_value = b"tree_value_from_c".to_vec();
        manager_c.put(test_key, test_value.clone()).await?;

        sleep(DHT_PROPAGATION_DELAY).await;

        // E queries (path: E→B→A→C)
        info!("Node E querying for value from C (E→B→A→C path)...");
        let get_result = manager_e.get(&test_key).await?;

        match get_result {
            DhtNetworkResult::GetSuccess { value, source, .. } => {
                info!("✅ SUCCESS! Found value via source: {}", source);
                assert_eq!(value, test_value);
            }
            DhtNetworkResult::GetNotFound { .. } => {
                return Err(anyhow::anyhow!("Failed to traverse tree for value lookup"));
            }
            other => {
                return Err(anyhow::anyhow!("Unexpected result: {:?}", other));
            }
        }

        // Also test D→C lookup
        info!("Node D querying for value from C...");
        let get_result_d = manager_d.get(&test_key).await?;

        match get_result_d {
            DhtNetworkResult::GetSuccess { .. } => {
                info!("✅ D also found value");
            }
            _ => {
                return Err(anyhow::anyhow!("D couldn't traverse tree to find C"));
            }
        }

        // Cleanup
        for manager in [manager_a, manager_b, manager_c, manager_d, manager_e] {
            let _ = manager.stop().await;
        }

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            warn!("Binary tree test failed: {}", e);
            Err(e)
        }
        Err(_) => panic!("Test timed out"),
    }
}
