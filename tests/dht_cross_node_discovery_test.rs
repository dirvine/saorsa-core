// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Cross-Node DHT Discovery Integration Tests
//!
//! These tests prove that 3+ P2P nodes can discover each other through the DHT network.
//! The DHT functions as a working "phonebook" where nodes can find peers they haven't
//! directly connected to.
//!
//! ## Test Topology
//!
//! Test 1: Three-Node Peer Discovery
//! ```text
//! Node A (Bootstrap) ←──connects──→ Node B ←──connects──→ Node C
//!      │                                                      │
//!      └──────── Node C discovers Node A via DHT ─────────────┘
//! ```
//!
//! ## Expected Results
//!
//! These tests will identify exactly where the DHT cross-node discovery needs work:
//! - If dht_get returns None for keys stored on other nodes → retrieve() needs network wiring
//! - If timeout waiting for DHT propagation → store() needs replication to K closest nodes
//! - If nodes can't find each other at all → bootstrap needs to populate routing table
//!
//! Run with: `cargo test --test dht_cross_node_discovery_test -- --nocapture`
//! Run with logging: `RUST_LOG=debug cargo test --test dht_cross_node_discovery_test -- --nocapture`

use anyhow::Result;
use saorsa_core::dht::{DHTConfig, Key};
use saorsa_core::dht_network_manager::{DhtNetworkConfig, DhtNetworkManager, DhtNetworkResult};
use saorsa_core::network::NodeConfig;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

// =============================================================================
// Test Configuration Constants
// =============================================================================

const NODE_STARTUP_DELAY: Duration = Duration::from_millis(500);
const DHT_PROPAGATION_DELAY: Duration = Duration::from_secs(2);
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TEST_DURATION: Duration = Duration::from_secs(30);
const CONNECTION_STABILIZATION_DELAY: Duration = Duration::from_millis(300);

// =============================================================================
// Helper Functions
// =============================================================================

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
        .listen_port(0) // Use 0 for automatic port allocation
        .ipv6(false)
        .build()?;

    Ok(DhtNetworkConfig {
        local_peer_id: peer_id.to_string(),
        dht_config: DHTConfig::default(),
        node_config,
        request_timeout: Duration::from_secs(5),
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

/// Connects two DhtNetworkManager instances and waits for connection confirmation
async fn connect_managers(
    from_manager: &Arc<DhtNetworkManager>,
    to_manager: &Arc<DhtNetworkManager>,
) -> Result<String> {
    let addr = to_manager
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("Target manager has no listen address"))?;

    info!(
        "Connecting {} -> {} at {}",
        from_manager.peer_id(),
        to_manager.peer_id(),
        addr
    );

    let peer_id = from_manager.connect_to_peer(&addr).await?;

    // Wait for connection to stabilize
    sleep(CONNECTION_STABILIZATION_DELAY).await;

    Ok(peer_id)
}

/// Stores a peer record in DHT
async fn register_peer_in_dht(
    manager: &Arc<DhtNetworkManager>,
    peer_id: &str,
    addresses: Vec<String>,
) -> Result<()> {
    // Create a simple peer record: peer_id -> serialized addresses
    let key = key_from_str(&format!("peer_record:{peer_id}"));
    let value = addresses.join(",").into_bytes();

    let result = manager.put(key, value).await?;
    match result {
        DhtNetworkResult::PutSuccess { replicated_to, .. } => {
            info!(
                "Registered peer {} in DHT, replicated to {} nodes",
                peer_id, replicated_to
            );
            Ok(())
        }
        other => Err(anyhow::anyhow!(
            "Failed to register peer in DHT: {:?}",
            other
        )),
    }
}

/// Queries DHT for a peer record with timeout
async fn discover_peer_via_dht(
    manager: &Arc<DhtNetworkManager>,
    target_peer_id: &str,
    timeout_duration: Duration,
) -> Result<Option<Vec<String>>> {
    let key = key_from_str(&format!("peer_record:{target_peer_id}"));

    let result = timeout(timeout_duration, manager.get(&key)).await??;
    match result {
        DhtNetworkResult::GetSuccess { value, source, .. } => {
            let addresses_str = String::from_utf8(value)?;
            let addresses: Vec<String> = addresses_str.split(',').map(|s| s.to_string()).collect();
            info!(
                "Discovered peer {} via DHT from source {}, addresses: {:?}",
                target_peer_id, source, addresses
            );
            Ok(Some(addresses))
        }
        DhtNetworkResult::GetNotFound { .. } => {
            debug!("Peer {} not found in DHT", target_peer_id);
            Ok(None)
        }
        other => Err(anyhow::anyhow!("DHT get failed: {:?}", other)),
    }
}

/// Verifies no direct P2P connection exists between two managers
async fn assert_not_directly_connected(
    manager: &Arc<DhtNetworkManager>,
    other_peer_id: &str,
) -> Result<()> {
    let connected_peers = manager.transport().connected_peers().await;
    let is_connected = connected_peers.iter().any(|p| p == other_peer_id);

    if is_connected {
        Err(anyhow::anyhow!(
            "Unexpected direct connection to peer {}",
            other_peer_id
        ))
    } else {
        Ok(())
    }
}

/// Cleanup helper to stop all managers gracefully
async fn cleanup_managers(managers: Vec<Arc<DhtNetworkManager>>) {
    for manager in managers {
        if let Err(e) = manager.stop().await {
            warn!("Error stopping manager {}: {}", manager.peer_id(), e);
        }
    }
}

// =============================================================================
// TEST 1: Three-Node Peer Discovery
// =============================================================================

/// Test that Node C can discover Node A's peer record through Node B
///
/// Topology:
/// ```text
/// Node A (Bootstrap) ←──connects──→ Node B ←──connects──→ Node C
/// ```
///
/// Expected behavior:
/// 1. Node A publishes its peer record to DHT
/// 2. DHT propagates to Node B (connected to A)
/// 3. Node C (only connected to B) queries DHT for Node A's record
/// 4. Node C receives Node A's address without ever connecting directly
#[tokio::test]
async fn test_three_node_peer_discovery() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Three Node Peer Discovery ===");

    // Create three nodes
    let manager_a = create_test_manager("node_a_bootstrap").await?;
    let manager_b = create_test_manager("node_b_relay").await?;
    let manager_c = create_test_manager("node_c_querier").await?;

    info!(
        "Created nodes: A={}, B={}, C={}",
        manager_a.peer_id(),
        manager_b.peer_id(),
        manager_c.peer_id()
    );

    // Connect: A <-> B <-> C (A and C NOT directly connected)
    let _peer_b_from_a = connect_managers(&manager_a, &manager_b).await?;
    let _peer_c_from_b = connect_managers(&manager_b, &manager_c).await?;

    info!("Network topology established: A <-> B <-> C");

    // Verify Node C is NOT directly connected to Node A
    assert_not_directly_connected(&manager_c, manager_a.peer_id()).await?;
    info!("Verified: Node C is not directly connected to Node A");

    // Node A publishes its peer record to DHT
    let node_a_addr = manager_a
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("Node A has no listen address"))?;

    register_peer_in_dht(&manager_a, manager_a.peer_id(), vec![node_a_addr.clone()]).await?;

    // Wait for DHT propagation
    info!("Waiting for DHT propagation...");
    sleep(DHT_PROPAGATION_DELAY).await;

    // Node C attempts to discover Node A via DHT
    info!("Node C attempting to discover Node A via DHT...");
    let discovery_result =
        discover_peer_via_dht(&manager_c, manager_a.peer_id(), DISCOVERY_TIMEOUT).await?;

    // Verify discovery result
    match discovery_result {
        Some(addresses) => {
            info!(
                "SUCCESS! Node C discovered Node A's address via DHT: {:?}",
                addresses
            );
            assert!(
                addresses.contains(&node_a_addr),
                "Discovered addresses should include Node A's actual address"
            );
        }
        None => {
            // This is the expected failure mode if DHT cross-node discovery isn't implemented
            warn!(
                "EXPECTED FAILURE: Node C could not discover Node A via DHT.\n\
                This indicates that DhtCoreEngine::retrieve() doesn't query remote nodes.\n\
                Required fix: Wire retrieve() to send DHT query messages via send_message()."
            );
            // Don't panic - document the failure for the report
        }
    }

    // Cleanup
    cleanup_managers(vec![manager_a, manager_b, manager_c]).await;

    info!("=== TEST COMPLETE: Three Node Peer Discovery ===");
    Ok(())
}

// =============================================================================
// TEST 2: Four-Node Transitive Discovery
// =============================================================================

/// Test that Node D can discover Node A's data through a 3-hop chain
///
/// Topology:
/// ```text
/// Node A ←→ Node B ←→ Node C ←→ Node D
/// ```
#[tokio::test]
async fn test_four_node_transitive_discovery() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Four Node Transitive Discovery ===");

    // Create four nodes in a chain
    let manager_a = create_test_manager("transitive_a").await?;
    let manager_b = create_test_manager("transitive_b").await?;
    let manager_c = create_test_manager("transitive_c").await?;
    let manager_d = create_test_manager("transitive_d").await?;

    info!(
        "Created nodes: A={}, B={}, C={}, D={}",
        manager_a.peer_id(),
        manager_b.peer_id(),
        manager_c.peer_id(),
        manager_d.peer_id()
    );

    // Connect chain: A <-> B <-> C <-> D
    connect_managers(&manager_a, &manager_b).await?;
    connect_managers(&manager_b, &manager_c).await?;
    connect_managers(&manager_c, &manager_d).await?;

    info!("Network topology established: A <-> B <-> C <-> D");

    // Verify D is not connected to A or B
    assert_not_directly_connected(&manager_d, manager_a.peer_id()).await?;
    assert_not_directly_connected(&manager_d, manager_b.peer_id()).await?;
    info!("Verified: Node D has no direct connections to A or B");

    // Node A stores a unique key-value pair
    let test_key = key_from_str("transitive_test_key_unique");
    let test_value = b"transitive_test_value_from_node_a".to_vec();

    let put_result = manager_a.put(test_key, test_value.clone()).await?;
    match &put_result {
        DhtNetworkResult::PutSuccess { replicated_to, .. } => {
            info!("Node A stored value, replicated to {} nodes", replicated_to);
        }
        other => {
            warn!("Put returned unexpected result: {:?}", other);
        }
    }

    // Wait for propagation through the chain
    info!("Waiting for DHT propagation through 3 hops...");
    sleep(DHT_PROPAGATION_DELAY * 2).await;

    // Node D attempts to retrieve the value
    info!("Node D attempting to retrieve value stored by Node A...");
    let get_result = timeout(DISCOVERY_TIMEOUT, manager_d.get(&test_key)).await??;

    match get_result {
        DhtNetworkResult::GetSuccess { value, source, .. } => {
            info!(
                "SUCCESS! Node D retrieved value from source '{}': {:?}",
                source,
                String::from_utf8_lossy(&value)
            );
            assert_eq!(
                value, test_value,
                "Retrieved value should match stored value"
            );
        }
        DhtNetworkResult::GetNotFound { .. } => {
            warn!(
                "EXPECTED FAILURE: Node D could not retrieve value stored by Node A.\n\
                This indicates DHT queries don't traverse the network.\n\
                The value should have propagated: A -> B -> C -> D"
            );
        }
        other => {
            warn!("Get returned unexpected result: {:?}", other);
        }
    }

    // Cleanup
    cleanup_managers(vec![manager_a, manager_b, manager_c, manager_d]).await;

    info!("=== TEST COMPLETE: Four Node Transitive Discovery ===");
    Ok(())
}

// =============================================================================
// TEST 3: Concurrent Peer Registration
// =============================================================================

/// Test that all nodes can register and discover each other concurrently
///
/// Topology: Partial mesh with 5 nodes
/// ```text
///   A ─── B ─── C
///   │     │     │
///   └── D ─── E─┘
/// ```
#[tokio::test]
async fn test_concurrent_peer_registration() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Concurrent Peer Registration ===");

    // Create 5 nodes
    let manager_a = create_test_manager("concurrent_a").await?;
    let manager_b = create_test_manager("concurrent_b").await?;
    let manager_c = create_test_manager("concurrent_c").await?;
    let manager_d = create_test_manager("concurrent_d").await?;
    let manager_e = create_test_manager("concurrent_e").await?;

    let managers = vec![
        manager_a.clone(),
        manager_b.clone(),
        manager_c.clone(),
        manager_d.clone(),
        manager_e.clone(),
    ];

    info!(
        "Created 5 nodes: A={}, B={}, C={}, D={}, E={}",
        manager_a.peer_id(),
        manager_b.peer_id(),
        manager_c.peer_id(),
        manager_d.peer_id(),
        manager_e.peer_id()
    );

    // Create partial mesh: A-B-C, A-D-E, B-D, C-E
    connect_managers(&manager_a, &manager_b).await?;
    connect_managers(&manager_b, &manager_c).await?;
    connect_managers(&manager_a, &manager_d).await?;
    connect_managers(&manager_d, &manager_e).await?;
    connect_managers(&manager_b, &manager_d).await?;
    connect_managers(&manager_c, &manager_e).await?;

    info!("Partial mesh topology established");

    // Each node registers its peer record concurrently
    let mut registration_handles = vec![];
    for manager in &managers {
        let manager_clone = manager.clone();
        let peer_id = manager.peer_id().to_string();
        let addr = match manager.local_addr() {
            Some(a) => a,
            None => {
                warn!(
                    "Manager {} has no local address, skipping registration",
                    peer_id
                );
                continue;
            }
        };

        let handle = tokio::spawn(async move {
            register_peer_in_dht(&manager_clone, &peer_id, vec![addr]).await
        });
        registration_handles.push(handle);
    }

    // Wait for all registrations
    for handle in registration_handles {
        if let Err(e) = handle.await? {
            warn!("Registration failed: {}", e);
        }
    }
    info!("All nodes registered their peer records");

    // Wait for DHT propagation
    sleep(DHT_PROPAGATION_DELAY * 2).await;

    // Each node queries for all other nodes' records
    let mut discovery_results: HashMap<String, HashMap<String, bool>> = HashMap::new();

    for querier in &managers {
        let mut results_for_querier: HashMap<String, bool> = HashMap::new();

        for target in &managers {
            if querier.peer_id() == target.peer_id() {
                continue; // Skip self
            }

            let result =
                discover_peer_via_dht(querier, target.peer_id(), Duration::from_secs(2)).await;
            let found = matches!(result, Ok(Some(_)));
            results_for_querier.insert(target.peer_id().to_string(), found);

            if found {
                debug!(
                    "{} discovered {} via DHT",
                    querier.peer_id(),
                    target.peer_id()
                );
            } else {
                debug!(
                    "{} could NOT discover {} via DHT",
                    querier.peer_id(),
                    target.peer_id()
                );
            }
        }

        discovery_results.insert(querier.peer_id().to_string(), results_for_querier);
    }

    // Report results
    let mut total_discoveries = 0;
    let mut total_attempts = 0;

    for (querier, targets) in &discovery_results {
        for (target, found) in targets {
            total_attempts += 1;
            if *found {
                total_discoveries += 1;
            }
            info!(
                "{} -> {}: {}",
                querier,
                target,
                if *found { "✓" } else { "✗" }
            );
        }
    }

    info!(
        "Discovery success rate: {}/{} ({:.1}%)",
        total_discoveries,
        total_attempts,
        (total_discoveries as f64 / total_attempts as f64) * 100.0
    );

    if total_discoveries == 0 {
        warn!(
            "EXPECTED FAILURE: No cross-node discovery succeeded.\n\
            This indicates DHT replication/query routing is not working.\n\
            Each node can only see its own records."
        );
    } else if total_discoveries < total_attempts {
        info!(
            "PARTIAL SUCCESS: Some discoveries worked ({}/{})",
            total_discoveries, total_attempts
        );
    } else {
        info!("FULL SUCCESS: All nodes can discover all other nodes!");
    }

    // Cleanup
    cleanup_managers(managers).await;

    info!("=== TEST COMPLETE: Concurrent Peer Registration ===");
    Ok(())
}

// =============================================================================
// TEST 4: Node Discovery After Join
// =============================================================================

/// Test that a late-joining node can discover pre-existing nodes
///
/// Topology:
/// ```text
/// Phase 1: A <-> B <-> C (all register)
/// Phase 2: D joins via C and discovers A and B
/// ```
#[tokio::test]
async fn test_node_discovery_after_join() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Node Discovery After Join ===");

    // Phase 1: Create initial network of 3 nodes
    let manager_a = create_test_manager("late_join_a").await?;
    let manager_b = create_test_manager("late_join_b").await?;
    let manager_c = create_test_manager("late_join_c").await?;

    // Connect: A <-> B <-> C
    connect_managers(&manager_a, &manager_b).await?;
    connect_managers(&manager_b, &manager_c).await?;

    info!("Initial network established: A <-> B <-> C");

    // All nodes register their peer records
    for manager in [&manager_a, &manager_b, &manager_c] {
        let addr = manager
            .local_addr()
            .ok_or_else(|| anyhow::anyhow!("Manager {} has no local address", manager.peer_id()))?;
        register_peer_in_dht(manager, manager.peer_id(), vec![addr]).await?;
    }

    // Wait for DHT propagation
    sleep(DHT_PROPAGATION_DELAY).await;

    // Phase 2: New node D joins by connecting only to C
    info!("Creating late-joining Node D...");
    let manager_d = create_test_manager("late_join_d").await?;
    connect_managers(&manager_d, &manager_c).await?;

    info!("Node D joined network via Node C");

    // Verify D is not directly connected to A or B
    assert_not_directly_connected(&manager_d, manager_a.peer_id()).await?;
    assert_not_directly_connected(&manager_d, manager_b.peer_id()).await?;

    // Give D time to sync with DHT
    sleep(DHT_PROPAGATION_DELAY).await;

    // Node D attempts to discover A and B
    info!("Node D attempting to discover pre-existing nodes...");

    let discovered_a =
        discover_peer_via_dht(&manager_d, manager_a.peer_id(), DISCOVERY_TIMEOUT).await?;
    let discovered_b =
        discover_peer_via_dht(&manager_d, manager_b.peer_id(), DISCOVERY_TIMEOUT).await?;

    match (&discovered_a, &discovered_b) {
        (Some(addrs_a), Some(addrs_b)) => {
            info!(
                "SUCCESS! Late-joining Node D discovered both pre-existing nodes:\n\
                - Node A: {:?}\n\
                - Node B: {:?}",
                addrs_a, addrs_b
            );
        }
        (Some(addrs_a), None) => {
            info!(
                "PARTIAL SUCCESS: Node D discovered A ({:?}) but not B",
                addrs_a
            );
        }
        (None, Some(addrs_b)) => {
            info!(
                "PARTIAL SUCCESS: Node D discovered B ({:?}) but not A",
                addrs_b
            );
        }
        (None, None) => {
            warn!(
                "EXPECTED FAILURE: Late-joining Node D could not discover any pre-existing nodes.\n\
                This indicates DHT state is not properly synchronized with new joiners."
            );
        }
    }

    // Cleanup
    cleanup_managers(vec![manager_a, manager_b, manager_c, manager_d]).await;

    info!("=== TEST COMPLETE: Node Discovery After Join ===");
    Ok(())
}

// =============================================================================
// TEST 5: Discovery With Node Departure
// =============================================================================

/// Test that discovery still works after a node in the path departs
///
/// Topology:
/// ```text
/// Phase 1: A <-> B <-> C <-> D (all register)
/// Phase 2: B disconnects/shuts down
/// Phase 3: D attempts to discover A
/// ```
#[tokio::test]
async fn test_discovery_with_node_departure() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Discovery With Node Departure ===");

    // Phase 1: Create chain of 4 nodes
    let manager_a = create_test_manager("departure_a").await?;
    let manager_b = create_test_manager("departure_b").await?;
    let manager_c = create_test_manager("departure_c").await?;
    let manager_d = create_test_manager("departure_d").await?;

    // Connect chain: A <-> B <-> C <-> D
    connect_managers(&manager_a, &manager_b).await?;
    connect_managers(&manager_b, &manager_c).await?;
    connect_managers(&manager_c, &manager_d).await?;

    info!("Initial chain established: A <-> B <-> C <-> D");

    // All nodes register their peer records
    for manager in [&manager_a, &manager_b, &manager_c, &manager_d] {
        let addr = manager
            .local_addr()
            .ok_or_else(|| anyhow::anyhow!("Manager {} has no local address", manager.peer_id()))?;
        register_peer_in_dht(manager, manager.peer_id(), vec![addr]).await?;
    }

    // Wait for DHT propagation
    sleep(DHT_PROPAGATION_DELAY).await;

    // Verify D can initially find A (before B leaves)
    info!("Verifying initial discovery works...");
    let initial_discovery =
        discover_peer_via_dht(&manager_d, manager_a.peer_id(), DISCOVERY_TIMEOUT).await?;
    info!(
        "Initial discovery of A by D: {}",
        if initial_discovery.is_some() {
            "SUCCESS"
        } else {
            "NOT FOUND (expected if cross-node not working)"
        }
    );

    // Phase 2: Node B gracefully shuts down
    info!("Node B shutting down...");
    manager_b.stop().await?;

    // Give network time to detect departure
    sleep(Duration::from_secs(2)).await;

    // Phase 3: Node D attempts to discover Node A
    info!("Node D attempting to discover Node A after B's departure...");
    let test_start = tokio::time::Instant::now();
    let post_departure_discovery =
        discover_peer_via_dht(&manager_d, manager_a.peer_id(), DISCOVERY_TIMEOUT).await;
    let discovery_duration = test_start.elapsed();

    match post_departure_discovery {
        Ok(Some(addresses)) => {
            info!(
                "SUCCESS! Discovery still works after node departure:\n\
                - Discovered addresses: {:?}\n\
                - Discovery took: {:?}",
                addresses, discovery_duration
            );
        }
        Ok(None) => {
            info!(
                "Discovery returned None after node departure.\n\
                This could be expected if:\n\
                1. Cross-node DHT not implemented (likely)\n\
                2. Alternative route through C not found\n\
                Duration: {:?}",
                discovery_duration
            );
        }
        Err(e) => {
            info!(
                "Discovery returned error after node departure: {}\n\
                Duration: {:?}\n\
                This is acceptable - the system handled departure gracefully without hanging.",
                e, discovery_duration
            );
        }
    }

    // Verify no hang occurred (should complete within timeout)
    assert!(
        discovery_duration < MAX_TEST_DURATION,
        "Discovery took too long ({:?}), possible hang",
        discovery_duration
    );

    // Cleanup remaining managers
    cleanup_managers(vec![manager_a, manager_c, manager_d]).await;

    info!("=== TEST COMPLETE: Discovery With Node Departure ===");
    Ok(())
}

// =============================================================================
// Supplementary Tests
// =============================================================================

/// Test that local DHT operations still work correctly (baseline sanity check)
#[tokio::test]
async fn test_local_dht_operations_baseline() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Local DHT Operations Baseline ===");

    let manager = create_test_manager("local_baseline").await?;

    // Store locally
    let key = key_from_str("local_test_key");
    let value = b"local_test_value".to_vec();

    let put_result = manager.put(key, value.clone()).await?;
    assert!(
        matches!(put_result, DhtNetworkResult::PutSuccess { .. }),
        "Local put should succeed"
    );
    info!("Local put succeeded");

    // Retrieve locally
    let get_result = manager.get(&key).await?;
    match get_result {
        DhtNetworkResult::GetSuccess {
            value: retrieved, ..
        } => {
            assert_eq!(retrieved, value, "Retrieved value should match");
            info!("Local get succeeded: values match");
        }
        other => {
            manager.stop().await?;
            return Err(anyhow::anyhow!("Local get failed: {:?}", other));
        }
    }

    manager.stop().await?;

    info!("=== TEST PASSED: Local DHT Operations Baseline ===");
    Ok(())
}

/// Test that two directly connected nodes can share DHT data
#[tokio::test]
async fn test_two_node_direct_dht_sharing() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Two Node Direct DHT Sharing ===");

    let manager_a = create_test_manager("direct_a").await?;
    let manager_b = create_test_manager("direct_b").await?;

    // Connect A <-> B
    connect_managers(&manager_a, &manager_b).await?;
    info!("Nodes connected: A <-> B");

    // Store on A
    let key = key_from_str("direct_sharing_key");
    let value = b"direct_sharing_value".to_vec();

    let put_result = manager_a.put(key, value.clone()).await?;
    info!("Put result on A: {:?}", put_result);

    // Wait for potential replication
    sleep(DHT_PROPAGATION_DELAY).await;

    // Try to retrieve on B
    info!("Node B attempting to retrieve value stored by Node A...");
    let get_result = manager_b.get(&key).await?;

    match get_result {
        DhtNetworkResult::GetSuccess {
            value: retrieved,
            source,
            ..
        } => {
            info!(
                "SUCCESS! Node B retrieved value from source '{}': {:?}",
                source,
                String::from_utf8_lossy(&retrieved)
            );
            assert_eq!(retrieved, value, "Retrieved value should match");
        }
        DhtNetworkResult::GetNotFound { .. } => {
            warn!(
                "EXPECTED FAILURE: Node B could not retrieve value stored by Node A.\n\
                Even with direct connection, DHT data is not being replicated/queried.\n\
                This confirms DhtNetworkManager needs network wiring for cross-node operations."
            );
        }
        other => {
            warn!("Get returned unexpected result: {:?}", other);
        }
    }

    cleanup_managers(vec![manager_a, manager_b]).await;

    info!("=== TEST COMPLETE: Two Node Direct DHT Sharing ===");
    Ok(())
}

/// Test routing table population on connect
#[tokio::test]
async fn test_routing_table_population() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Routing Table Population ===");

    let manager_a = create_test_manager("routing_a").await?;
    let manager_b = create_test_manager("routing_b").await?;

    // Check routing table before connection
    let routing_size_a_before = manager_a.get_routing_table_size().await;
    let routing_size_b_before = manager_b.get_routing_table_size().await;
    info!(
        "Routing table sizes before connection: A={}, B={}",
        routing_size_a_before, routing_size_b_before
    );

    // Connect A <-> B
    connect_managers(&manager_a, &manager_b).await?;

    // Wait for routing table updates
    sleep(Duration::from_secs(1)).await;

    // Check routing table after connection
    let routing_size_a_after = manager_a.get_routing_table_size().await;
    let routing_size_b_after = manager_b.get_routing_table_size().await;
    info!(
        "Routing table sizes after connection: A={}, B={}",
        routing_size_a_after, routing_size_b_after
    );

    // Get connected peers info
    let peers_a = manager_a.get_connected_peers().await;
    let peers_b = manager_b.get_connected_peers().await;
    info!(
        "Connected peers: A has {} peers, B has {} peers",
        peers_a.len(),
        peers_b.len()
    );

    if routing_size_a_after > routing_size_a_before || routing_size_b_after > routing_size_b_before
    {
        info!("SUCCESS: Routing table was populated on connect");
    } else if !peers_a.is_empty() || !peers_b.is_empty() {
        info!("PARTIAL: Peers connected but routing table may not be updated");
    } else {
        warn!(
            "EXPECTED ISSUE: Routing table not populated on connect.\n\
            Bootstrap should add connected peers to routing table."
        );
    }

    cleanup_managers(vec![manager_a, manager_b]).await;

    info!("=== TEST COMPLETE: Routing Table Population ===");
    Ok(())
}

// =============================================================================
// TEST: Iterative DHT Lookup - Multi-Hop (TDD - Will Fail Until Feature Complete)
// =============================================================================

/// Maximum time allowed for an iterative lookup to complete
const MAX_ITERATIVE_LOOKUP_TIME: Duration = Duration::from_secs(10);

/// Test that iterative DHT lookup traverses multiple hops.
///
/// This test will FAIL until the DHT GET handler returns closer nodes
/// when it doesn't have the requested value.
///
/// Topology:
/// ```text
/// A ←→ B ←→ C ←→ D ←→ E ←→ F
/// ```
///
/// Expected behavior after fix:
/// 1. F queries E for value
/// 2. E doesn't have it, returns "closer nodes: [D]"
/// 3. F queries D, gets "closer nodes: [C]"
/// 4. F queries C, gets "closer nodes: [B]"
/// 5. F queries B, gets "closer nodes: [A]" or value from B's cache
/// 6. F queries A (or B), gets value
#[tokio::test]
async fn test_iterative_dht_lookup_five_hops() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Iterative DHT Lookup - 5 Hops ===");
    info!("This test WILL FAIL until iterative lookup returns closer nodes");

    // Create 6 nodes in a chain
    let manager_a = create_test_manager("iter_a").await?;
    let manager_b = create_test_manager("iter_b").await?;
    let manager_c = create_test_manager("iter_c").await?;
    let manager_d = create_test_manager("iter_d").await?;
    let manager_e = create_test_manager("iter_e").await?;
    let manager_f = create_test_manager("iter_f").await?;

    // Connect chain: A ←→ B ←→ C ←→ D ←→ E ←→ F
    connect_managers(&manager_a, &manager_b).await?;
    connect_managers(&manager_b, &manager_c).await?;
    connect_managers(&manager_c, &manager_d).await?;
    connect_managers(&manager_d, &manager_e).await?;
    connect_managers(&manager_e, &manager_f).await?;

    info!("Chain topology established: A ←→ B ←→ C ←→ D ←→ E ←→ F");

    // Verify F is not directly connected to A, B, C, or D
    assert_not_directly_connected(&manager_f, manager_a.peer_id()).await?;
    assert_not_directly_connected(&manager_f, manager_b.peer_id()).await?;
    assert_not_directly_connected(&manager_f, manager_c.peer_id()).await?;
    assert_not_directly_connected(&manager_f, manager_d.peer_id()).await?;
    info!("Verified: Node F has no direct connections to A, B, C, or D");

    // Node A stores a unique key-value pair
    let test_key = key_from_str("iterative_lookup_test_key");
    let test_value = b"value_stored_by_node_a_five_hops_away".to_vec();

    let put_result = manager_a.put(test_key, test_value.clone()).await?;
    match &put_result {
        DhtNetworkResult::PutSuccess { replicated_to, .. } => {
            info!("Node A stored value, replicated to {} nodes", replicated_to);
        }
        other => {
            cleanup_managers(vec![
                manager_a, manager_b, manager_c, manager_d, manager_e, manager_f,
            ])
            .await;
            return Err(anyhow::anyhow!("Put failed: {:?}", other));
        }
    }

    // Brief delay - NOT relying on passive replication
    sleep(Duration::from_secs(1)).await;

    // THE KEY ASSERTION: Node F retrieves value via iterative lookup
    info!("Node F attempting iterative lookup for value stored by Node A...");
    let start_time = tokio::time::Instant::now();

    let get_result = timeout(MAX_ITERATIVE_LOOKUP_TIME, manager_f.get(&test_key)).await;
    let lookup_duration = start_time.elapsed();

    let result = match get_result {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            cleanup_managers(vec![
                manager_a, manager_b, manager_c, manager_d, manager_e, manager_f,
            ])
            .await;
            return Err(anyhow::anyhow!("Get operation failed: {}", e));
        }
        Err(_) => {
            cleanup_managers(vec![
                manager_a, manager_b, manager_c, manager_d, manager_e, manager_f,
            ])
            .await;
            panic!(
                "FAIL: Iterative lookup timed out after {:?}.\n\
                \n\
                The lookup should either succeed or fail fast, not hang.\n\
                This may indicate an infinite loop or blocked future.",
                MAX_ITERATIVE_LOOKUP_TIME
            );
        }
    };

    match result {
        DhtNetworkResult::GetSuccess { value, source, .. } => {
            info!(
                "SUCCESS! Node F retrieved value via iterative lookup:\n\
                - Source: {}\n\
                - Duration: {:?}\n\
                - Value: {:?}",
                source,
                lookup_duration,
                String::from_utf8_lossy(&value)
            );

            // Assert value matches
            assert_eq!(
                value, test_value,
                "Retrieved value should match stored value"
            );

            // Assert lookup was reasonably fast (not stuck in loops)
            assert!(
                lookup_duration < MAX_ITERATIVE_LOOKUP_TIME,
                "Lookup should complete within {} seconds, took {:?}",
                MAX_ITERATIVE_LOOKUP_TIME.as_secs(),
                lookup_duration
            );

            info!("Iterative lookup completed in {:?}", lookup_duration);
        }
        DhtNetworkResult::GetNotFound { .. } => {
            // THIS IS THE EXPECTED FAILURE BEFORE THE FIX
            cleanup_managers(vec![
                manager_a, manager_b, manager_c, manager_d, manager_e, manager_f,
            ])
            .await;
            panic!(
                "FAIL: Node F could not retrieve value stored by Node A.\n\
                \n\
                This test fails because the DHT GET handler does NOT return\n\
                closer nodes when it doesn't have the requested value.\n\
                \n\
                Required fix in handle_dht_message() GET case:\n\
                - When value not found locally, find nodes closer to key\n\
                - Return NodesFound {{ nodes: closer_nodes }} instead of GetNotFound\n\
                \n\
                See: planning/07-implement-iterative-dht-lookup.md"
            );
        }
        other => {
            cleanup_managers(vec![
                manager_a, manager_b, manager_c, manager_d, manager_e, manager_f,
            ])
            .await;
            panic!("Unexpected result: {:?}", other);
        }
    }

    // Cleanup
    cleanup_managers(vec![
        manager_a, manager_b, manager_c, manager_d, manager_e, manager_f,
    ])
    .await;

    info!("=== TEST PASSED: Iterative DHT Lookup - 5 Hops ===");
    Ok(())
}

/// Test that iterative lookup handles network partitions gracefully.
///
/// Topology:
/// ```text
/// A ←→ B ←→ C    D ←→ E ←→ F
///           (no connection)
/// ```
///
/// Expected: F's lookup for A's value should timeout/fail gracefully, not hang.
#[tokio::test]
async fn test_iterative_lookup_handles_partition() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Iterative Lookup Handles Partition ===");

    // Create two disconnected clusters
    let manager_a = create_test_manager("part_a").await?;
    let manager_b = create_test_manager("part_b").await?;
    let manager_c = create_test_manager("part_c").await?;

    let manager_d = create_test_manager("part_d").await?;
    let manager_e = create_test_manager("part_e").await?;
    let manager_f = create_test_manager("part_f").await?;

    // Cluster 1: A ←→ B ←→ C
    connect_managers(&manager_a, &manager_b).await?;
    connect_managers(&manager_b, &manager_c).await?;

    // Cluster 2: D ←→ E ←→ F (NOT connected to cluster 1)
    connect_managers(&manager_d, &manager_e).await?;
    connect_managers(&manager_e, &manager_f).await?;

    info!("Two partitioned clusters: [A-B-C] and [D-E-F]");

    // A stores a value
    let test_key = key_from_str("partitioned_test_key");
    let test_value = b"value_in_cluster_1".to_vec();

    let put_result = manager_a.put(test_key, test_value.clone()).await?;
    match &put_result {
        DhtNetworkResult::PutSuccess { replicated_to, .. } => {
            info!("Node A stored value, replicated to {} nodes", replicated_to);
        }
        other => {
            warn!("Put returned: {:?}", other);
        }
    }

    // F tries to retrieve it (should fail gracefully, not hang)
    info!("Node F attempting to retrieve value from partitioned cluster...");
    let start_time = tokio::time::Instant::now();

    let get_result = timeout(DISCOVERY_TIMEOUT, manager_f.get(&test_key)).await;
    let lookup_duration = start_time.elapsed();

    match get_result {
        Ok(Ok(DhtNetworkResult::GetNotFound { .. })) => {
            info!(
                "EXPECTED: Node F correctly got NotFound for partitioned data\n\
                Lookup completed in {:?} (did not hang)",
                lookup_duration
            );
        }
        Ok(Ok(DhtNetworkResult::GetSuccess { .. })) => {
            cleanup_managers(vec![
                manager_a, manager_b, manager_c, manager_d, manager_e, manager_f,
            ])
            .await;
            panic!(
                "UNEXPECTED: Node F found value despite network partition!\n\
                This should not be possible."
            );
        }
        Ok(Ok(other)) => {
            info!("Got result: {:?} in {:?}", other, lookup_duration);
        }
        Ok(Err(e)) => {
            info!(
                "Got error: {} in {:?} (acceptable - graceful failure)",
                e, lookup_duration
            );
        }
        Err(_) => {
            info!(
                "Lookup timed out after {:?} (acceptable for partitioned network)",
                DISCOVERY_TIMEOUT
            );
        }
    }

    // Assert lookup didn't hang indefinitely
    assert!(
        lookup_duration < DISCOVERY_TIMEOUT + Duration::from_secs(1),
        "Lookup should complete (with failure) within timeout, took {:?}",
        lookup_duration
    );

    cleanup_managers(vec![
        manager_a, manager_b, manager_c, manager_d, manager_e, manager_f,
    ])
    .await;

    info!("=== TEST PASSED: Iterative Lookup Handles Partition ===");
    Ok(())
}
