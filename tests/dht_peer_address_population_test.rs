// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! DHT Peer Address Population Test
//!
//! This test verifies that the DHT manager correctly populates peer addresses
//! from the P2P layer when nodes connect and communicate.
//!
//! ## Problem Statement
//!
//! The DHT layer needs to know the network addresses of peers for routing and
//! replication. These addresses should be automatically populated from the P2P
//! connection layer, but we need to verify this happens correctly.
//!
//! ## Test Coverage
//!
//! 1. **Direct Connection Address Propagation**: Verifies that when two nodes
//!    connect directly, both nodes populate each other's addresses in their
//!    DHT peer info.
//!
//! 2. **Find Closest Nodes Returns Addresses**: Verifies that when querying
//!    for closest nodes, the returned nodes have non-empty address fields.
//!
//! 3. **Address Consistency Between Layers**: Verifies that addresses stored
//!    in the DHT layer match the addresses from the P2P layer.
//!
//! ## Expected Initial Behavior
//!
//! These tests are expected to FAIL initially because address population from
//! the P2P layer may not be fully implemented. The failures will show:
//! - Empty address lists in DHT peer info
//! - Missing addresses in find_closest_nodes results
//! - Mismatches between P2P and DHT address information
//!
//! This test serves as both verification and specification for proper address
//! population implementation.

use anyhow::Result;
use saorsa_core::dht::{DHTConfig, Key};
use saorsa_core::dht_network_manager::{DhtNetworkConfig, DhtNetworkManager};
use saorsa_core::network::NodeConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info, warn};

const NODE_STARTUP_DELAY: Duration = Duration::from_millis(500);
const ADDRESS_PROPAGATION_DELAY: Duration = Duration::from_millis(500);

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

// =============================================================================
// TEST 1: Direct Connection Address Propagation
// =============================================================================

/// Test that when two nodes connect, both populate each other's addresses
/// in their DHT peer info.
///
/// ## Topology
/// ```text
/// Node A ←→ Node B
/// ```
///
/// ## Expected Behavior
/// - After connection, Node A's get_connected_peers() should show Node B with addresses
/// - After connection, Node B's get_connected_peers() should show Node A with addresses
/// - Addresses should be valid network addresses (not empty strings)
///
/// ## Current Expected Result
/// FAIL - addresses will likely be empty because address population is not implemented
#[tokio::test]
async fn test_direct_connection_address_propagation() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug,saorsa_core::dht_network_manager=trace")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Direct Connection Address Propagation ===");

    // Create two nodes
    let manager_a = create_test_manager("address_test_a").await?;
    let manager_b = create_test_manager("address_test_b").await?;

    info!("Created nodes A and B");

    // Get Node B's listen address
    let addr_b = manager_b
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("Node B has no listen address"))?;

    // Node A connects to Node B
    info!("Node A connecting to Node B at {}", addr_b);
    let peer_id_b = manager_a.connect_to_peer(&addr_b).await?;
    info!("Node A connected to Node B (peer_id: {})", peer_id_b);

    // Wait for address propagation
    info!(
        "Waiting {} ms for address propagation...",
        ADDRESS_PROPAGATION_DELAY.as_millis()
    );
    sleep(ADDRESS_PROPAGATION_DELAY).await;

    // Check Node A's view of Node B
    info!("Checking Node A's view of connected peers...");
    let peers_from_a = manager_a.get_connected_peers().await;
    info!("Node A sees {} connected peers", peers_from_a.len());

    let peer_b_in_a = peers_from_a.iter().find(|p| p.peer_id == peer_id_b);

    match peer_b_in_a {
        Some(peer_info) => {
            info!(
                "Node A sees peer B with {} addresses",
                peer_info.addresses.len()
            );
            for (i, addr) in peer_info.addresses.iter().enumerate() {
                info!("  Address {}: {}", i, addr);
            }

            if peer_info.addresses.is_empty() {
                warn!(
                    "❌ TEST FAILED: Node A sees peer B but has ZERO addresses.\n\
                    \n\
                    Expected behavior:\n\
                    - When Node A connects to Node B, the DHT layer should populate peer B's addresses\n\
                    - Addresses should come from the P2P layer's PeerInfo\n\
                    \n\
                    Actual behavior:\n\
                    - peer_info.addresses is empty\n\
                    \n\
                    Implementation needed:\n\
                    - Populate addresses from P2P layer when peers connect\n\
                    - Update addresses in DHT peer info on connection events"
                );
                return Err(anyhow::anyhow!(
                    "Address propagation failed: Node A has no addresses for Node B"
                ));
            }

            info!("✅ Node A successfully populated addresses for Node B");
        }
        None => {
            warn!("❌ Node A does not see peer B in connected peers at all!");
            return Err(anyhow::anyhow!("Node B not in Node A's connected peers"));
        }
    }

    // Check Node B's view of Node A
    info!("Checking Node B's view of connected peers...");
    let peers_from_b = manager_b.get_connected_peers().await;
    info!("Node B sees {} connected peers", peers_from_b.len());

    // Get Node A's transport peer ID (cryptographic ID used on the wire)
    let transport_peer_id_a = manager_a
        .transport_peer_id()
        .ok_or_else(|| anyhow::anyhow!("Node A has no transport peer ID"))?;
    info!(
        "Looking for Node A's transport_peer_id: {}",
        transport_peer_id_a
    );

    let peer_a_in_b = peers_from_b
        .iter()
        .find(|p| p.peer_id == transport_peer_id_a);

    match peer_a_in_b {
        Some(peer_info) => {
            info!(
                "Node B sees peer A with {} addresses",
                peer_info.addresses.len()
            );
            for (i, addr) in peer_info.addresses.iter().enumerate() {
                info!("  Address {}: {}", i, addr);
            }

            if peer_info.addresses.is_empty() {
                warn!(
                    "❌ TEST FAILED: Node B sees peer A but has ZERO addresses.\n\
                    This indicates address population is not working correctly."
                );
                return Err(anyhow::anyhow!(
                    "Address propagation failed: Node B has no addresses for Node A"
                ));
            }

            info!("✅ Node B successfully populated addresses for Node A");
        }
        None => {
            warn!("❌ Node B does not see peer A in connected peers at all!");
            return Err(anyhow::anyhow!("Node A not in Node B's connected peers"));
        }
    }

    // Cleanup
    let _ = manager_a.stop().await;
    let _ = manager_b.stop().await;

    info!("✅ TEST PASSED: Both nodes correctly populated peer addresses!");
    Ok(())
}

// =============================================================================
// TEST 2: Find Closest Nodes Returns Addresses
// =============================================================================

/// Test that find_closest_nodes returns nodes with populated address fields.
///
/// ## Topology
/// ```text
/// Node A ←→ Node B ←→ Node C
/// (Chain topology)
/// ```
///
/// ## Expected Behavior
/// - When Node B calls find_closest_nodes(), the returned nodes should have addresses
/// - Addresses should be usable for making connections
///
/// ## Current Expected Result
/// FAIL - returned nodes may have empty address fields
#[tokio::test]
async fn test_find_closest_nodes_returns_addresses() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug,saorsa_core::dht_network_manager=trace")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Find Closest Nodes Returns Addresses ===");

    // Create three nodes
    let manager_a = create_test_manager("find_nodes_a").await?;
    let manager_b = create_test_manager("find_nodes_b").await?;
    let manager_c = create_test_manager("find_nodes_c").await?;

    info!("Created nodes A, B, and C");

    // Connect in chain: A ←→ B ←→ C
    let addr_b = manager_b
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("Node B has no listen address"))?;
    let addr_c = manager_c
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("Node C has no listen address"))?;

    info!("Connecting A → B");
    let _peer_id_b = manager_a.connect_to_peer(&addr_b).await?;

    info!("Connecting B → C");
    let _peer_id_c = manager_b.connect_to_peer(&addr_c).await?;

    // Wait for network stabilization
    info!(
        "Waiting {} ms for network stabilization...",
        ADDRESS_PROPAGATION_DELAY.as_millis()
    );
    sleep(ADDRESS_PROPAGATION_DELAY).await;

    // Node B calls find_closest_nodes for a test key
    let test_key = key_from_str("test_find_nodes_key");
    info!(
        "Node B finding closest nodes to key: {}",
        hex::encode(test_key)
    );

    let closest_nodes = manager_b.find_closest_nodes_local(&test_key, 5).await;

    info!("find_closest_nodes returned {} nodes", closest_nodes.len());

    if closest_nodes.is_empty() {
        warn!("❌ TEST FAILED: find_closest_nodes returned ZERO nodes");
        return Err(anyhow::anyhow!("No nodes returned from find_closest_nodes"));
    }

    // Check each returned node for addresses
    let mut nodes_with_addresses = 0;
    let mut nodes_without_addresses = 0;

    for (i, node) in closest_nodes.iter().enumerate() {
        debug!("Node {}: peer_id={}", i, node.peer_id);
        debug!("  address: '{}'", node.address);
        debug!("  reliability: {}", node.reliability);

        if node.address.is_empty() {
            warn!("  ⚠️  Node {} has EMPTY address field", i);
            nodes_without_addresses += 1;
        } else {
            debug!("  ✅ Node {} has address: {}", i, node.address);
            nodes_with_addresses += 1;
        }
    }

    info!(
        "Address population results: {} with addresses, {} without",
        nodes_with_addresses, nodes_without_addresses
    );

    if nodes_without_addresses > 0 {
        warn!(
            "❌ TEST FAILED: {}/{} nodes returned by find_closest_nodes have NO addresses.\n\
            \n\
            Expected behavior:\n\
            - find_closest_nodes should return nodes with populated address fields\n\
            - These addresses should be usable for connecting to the nodes\n\
            \n\
            Actual behavior:\n\
            - {} nodes have empty address fields\n\
            \n\
            Implementation needed:\n\
            - Ensure DHTNode.address is populated from peer connection info\n\
            - Address should be the socket address or multiaddr of the peer",
            nodes_without_addresses,
            closest_nodes.len(),
            nodes_without_addresses
        );
        return Err(anyhow::anyhow!(
            "{} nodes missing addresses",
            nodes_without_addresses
        ));
    }

    // Cleanup
    let _ = manager_a.stop().await;
    let _ = manager_b.stop().await;
    let _ = manager_c.stop().await;

    info!("✅ TEST PASSED: All returned nodes have populated addresses!");
    Ok(())
}

// =============================================================================
// TEST 3: Address Consistency Between P2P and DHT Layers
// =============================================================================

/// Test that addresses in DHT peer info match addresses from the P2P layer.
///
/// ## Topology
/// ```text
/// Node A ←→ Node B
/// ```
///
/// ## Expected Behavior
/// - When Node A connects to Node B:
///   - P2P layer stores peer info with addresses
///   - DHT layer should have matching addresses
/// - Addresses should be consistent between both layers
///
/// ## Current Expected Result
/// FAIL - addresses may differ or be missing in DHT layer
#[tokio::test]
async fn test_address_consistency_with_p2p_layer() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug,saorsa_core::dht_network_manager=trace")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Address Consistency Between P2P and DHT Layers ===");

    // Create two nodes
    let manager_a = create_test_manager("consistency_a").await?;
    let manager_b = create_test_manager("consistency_b").await?;

    info!("Created nodes A and B");

    // Node A connects to Node B
    let addr_b = manager_b
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("Node B has no listen address"))?;

    info!("Node A connecting to Node B at {}", addr_b);
    let peer_id_b = manager_a.connect_to_peer(&addr_b).await?;
    info!("Connection established, peer_id_b: {}", peer_id_b);

    // Wait for address propagation
    info!(
        "Waiting {} ms for address propagation...",
        ADDRESS_PROPAGATION_DELAY.as_millis()
    );
    sleep(ADDRESS_PROPAGATION_DELAY).await;

    // Query P2P layer for peer B's info
    info!("Querying P2P layer for peer B's info...");
    let p2p_peer_info = manager_a.transport().peer_info(&peer_id_b).await;

    let p2p_addresses = match p2p_peer_info {
        Some(info) => {
            info!(
                "P2P layer has {} addresses for peer B",
                info.addresses.len()
            );
            for (i, addr) in info.addresses.iter().enumerate() {
                info!("  P2P Address {}: {}", i, addr);
            }
            info.addresses
        }
        None => {
            warn!("❌ P2P layer has NO peer info for peer B!");
            return Err(anyhow::anyhow!("P2P layer missing peer info"));
        }
    };

    // Query DHT layer for peer B's info
    info!("Querying DHT layer for peer B's info...");
    let dht_peers = manager_a.get_connected_peers().await;
    let dht_peer_info = dht_peers.iter().find(|p| p.peer_id == peer_id_b);

    let dht_addresses = match dht_peer_info {
        Some(info) => {
            info!(
                "DHT layer has {} addresses for peer B",
                info.addresses.len()
            );
            for (i, addr) in info.addresses.iter().enumerate() {
                info!("  DHT Address {}: {}", i, addr);
            }
            info.addresses.clone()
        }
        None => {
            warn!("❌ DHT layer has NO peer info for peer B!");
            return Err(anyhow::anyhow!("DHT layer missing peer info"));
        }
    };

    // Compare address counts
    if p2p_addresses.len() != dht_addresses.len() {
        warn!(
            "❌ TEST FAILED: Address count mismatch!\n\
            P2P layer has {} addresses\n\
            DHT layer has {} addresses",
            p2p_addresses.len(),
            dht_addresses.len()
        );
        return Err(anyhow::anyhow!(
            "Address count mismatch: P2P={} vs DHT={}",
            p2p_addresses.len(),
            dht_addresses.len()
        ));
    }

    // Check if addresses are consistent (convert both to strings for comparison)
    let p2p_addr_strings: Vec<String> = p2p_addresses.clone();
    let dht_addr_strings: Vec<String> = dht_addresses.iter().map(|ma| ma.to_string()).collect();

    info!("Comparing addresses for consistency...");
    let mut mismatches = 0;

    for (i, p2p_addr) in p2p_addr_strings.iter().enumerate() {
        if let Some(dht_addr) = dht_addr_strings.get(i) {
            // Check if addresses match (exact or contain each other)
            let match_found =
                p2p_addr == dht_addr || p2p_addr.contains(dht_addr) || dht_addr.contains(p2p_addr);

            if !match_found {
                warn!(
                    "  Address mismatch at index {}:\n    P2P: {}\n    DHT: {}",
                    i, p2p_addr, dht_addr
                );
                mismatches += 1;
            } else {
                debug!("  ✅ Address {} matches: {}", i, p2p_addr);
            }
        }
    }

    if mismatches > 0 {
        warn!(
            "❌ TEST FAILED: Found {} address mismatches between P2P and DHT layers.\n\
            \n\
            Expected behavior:\n\
            - DHT layer should store the same addresses as P2P layer\n\
            - Addresses should be synchronized when peers connect\n\
            \n\
            Actual behavior:\n\
            - {} addresses differ between layers\n\
            \n\
            Implementation needed:\n\
            - Properly propagate addresses from P2P PeerInfo to DHT DhtPeerInfo\n\
            - Ensure address format is consistent",
            mismatches, mismatches
        );
        return Err(anyhow::anyhow!("{} address mismatches", mismatches));
    }

    // Cleanup
    let _ = manager_a.stop().await;
    let _ = manager_b.stop().await;

    info!("✅ TEST PASSED: Addresses are consistent between P2P and DHT layers!");
    Ok(())
}
