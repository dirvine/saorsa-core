// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// DHT Replication Diagnostic Test
//
// This test diagnoses cross-node replication issues by:
// 1. Creating a 5-node network
// 2. Bootstrapping all nodes to node 0
// 3. Storing data on node 0
// 4. Attempting retrieval from nodes 1-4
// 5. Checking local storage on all nodes to verify replication
//
// The test includes detailed logging to help identify where replication fails.

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
    let hash = blake3::hash(s.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    key
}

/// Create a DhtNetworkConfig and TransportHandle for testing
async fn create_node_config(peer_id: &str) -> (Arc<TransportHandle>, DhtNetworkConfig) {
    let node_config = NodeConfig::builder()
        .peer_id(peer_id.to_string())
        .listen_port(0) // Ephemeral port
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
            event_channel_capacity: 1000,
        })
        .await
        .expect("Failed to create TransportHandle"),
    );

    let config = DhtNetworkConfig {
        local_peer_id: peer_id.to_string(),
        dht_config: DHTConfig::default(),
        node_config,
        request_timeout: Duration::from_secs(10),
        max_concurrent_operations: 50,
        replication_factor: 8,
        enable_security: false,
    };

    (transport, config)
}

#[tokio::test]
async fn test_cross_node_replication_diagnostic() -> Result<()> {
    const NODE_COUNT: usize = 5;

    info!("=== DHT REPLICATION DIAGNOSTIC TEST ===");
    info!("Creating {} node network...", NODE_COUNT);

    // Step 1: Create all nodes
    let mut transports = Vec::new();
    let mut nodes = Vec::new();
    for i in 0..NODE_COUNT {
        let peer_id = format!("diagnostic_node_{i}");
        let (transport, config) = create_node_config(&peer_id).await;
        transport.start_network_listeners().await?;
        let manager = Arc::new(DhtNetworkManager::new(transport.clone(), None, config).await?);
        transports.push(transport);
        nodes.push(manager);
    }

    // Step 2: Start all nodes
    info!("\nStarting all nodes...");
    for (i, node) in nodes.iter().enumerate() {
        node.start().await?;
        let addr = node.local_addr().unwrap_or_else(|| "unknown".to_string());
        info!("  Node {} started at {}", i, addr);
    }

    // Step 3: Bootstrap all nodes to node 0 (hub topology)
    info!("\nBootstrapping all nodes to node 0 (hub)...");
    let hub_node = nodes
        .first()
        .ok_or_else(|| anyhow::anyhow!("No nodes created"))?;
    let hub_addr = hub_node
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("Hub node has no address"))?;
    info!("  Hub address: {}", hub_addr);

    for (i, node) in nodes.iter().enumerate().skip(1) {
        match node.connect_to_peer(&hub_addr).await {
            Ok(peer_id) => {
                info!("  Node {} connected to hub (peer: {})", i, peer_id);
            }
            Err(e) => {
                warn!("  Node {} FAILED to connect to hub: {}", i, e);
            }
        }
    }

    // Step 4: Wait for network to stabilize
    info!("\nWaiting for network to stabilize...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 5: Store data on node 0
    let key = key_from_str("diagnostic_test_key");
    let value = b"diagnostic_test_value_12345".to_vec();

    info!("\nStoring data on node 0...");
    info!("  Key: {}", hex::encode(key));
    info!("  Value: {} bytes", value.len());

    let hub_node_ref = nodes
        .first()
        .ok_or_else(|| anyhow::anyhow!("No nodes available for PUT"))?;
    let put_result = hub_node_ref.put(key, value.clone()).await?;
    match &put_result {
        DhtNetworkResult::PutSuccess { replicated_to, .. } => {
            info!(
                "  PUT succeeded, reported replication to {} nodes",
                replicated_to
            );
        }
        other => {
            warn!("  PUT returned unexpected result: {:?}", other);
        }
    }

    // Step 6: Wait for replication to complete
    info!("\nWaiting for replication to complete...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Step 7: Check LOCAL storage on all nodes
    info!("\n=== VERIFICATION: Checking LOCAL storage on each node ===");
    let mut nodes_with_data = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        let has_data = node.has_key_locally(&key).await;
        if has_data {
            info!("  Node {}: HAS DATA locally", i);
            nodes_with_data.push(i);

            // Verify the value is correct
            match node.get_local(&key).await {
                Ok(Some(stored_value)) => {
                    if stored_value == value {
                        info!("  Node {}: Value verified correct", i);
                    } else {
                        warn!("  Node {}: Value CORRUPTED!", i);
                    }
                }
                Ok(None) => {
                    warn!(
                        "  Node {}: has_key returned true but get_local returned None!",
                        i
                    );
                }
                Err(e) => {
                    warn!("  Node {}: get_local failed: {}", i, e);
                }
            }
        } else {
            warn!("  Node {}: NO DATA locally", i);
        }
    }

    // Step 8: Try network retrieval from each node
    info!("\n=== VERIFICATION: Trying network GET from each node ===");
    let mut successful_retrievals = 0;
    for (i, node) in nodes.iter().enumerate() {
        match node.get(&key).await {
            Ok(DhtNetworkResult::GetSuccess {
                value: retrieved, ..
            }) => {
                if retrieved == value {
                    info!("  Node {}: GET SUCCESS (value verified)", i);
                    successful_retrievals += 1;
                } else {
                    warn!("  Node {}: GET returned WRONG VALUE", i);
                }
            }
            Ok(DhtNetworkResult::GetNotFound { .. }) => {
                warn!("  Node {}: GET returned NotFound", i);
            }
            Ok(other) => {
                warn!("  Node {}: Unexpected result: {:?}", i, other);
            }
            Err(e) => {
                warn!("  Node {}: GET failed: {}", i, e);
            }
        }
    }

    // Step 9: Summary
    info!("\n=== DIAGNOSTIC SUMMARY ===");
    info!(
        "Nodes with data in LOCAL storage: {} out of {}",
        nodes_with_data.len(),
        NODE_COUNT
    );
    info!(
        "Successful network GET retrievals: {} out of {}",
        successful_retrievals, NODE_COUNT
    );
    info!("Nodes with local data: {:?}", nodes_with_data);

    // Step 10: Assertions
    assert!(
        nodes_with_data.contains(&0),
        "CRITICAL: Node 0 (originator) does not have the data!"
    );

    assert!(
        nodes_with_data.len() >= 3,
        "REPLICATION FAILED: Data only found on {} nodes, expected at least 3",
        nodes_with_data.len()
    );

    assert!(
        successful_retrievals >= 3,
        "RETRIEVAL FAILED: Only {} successful retrievals, expected at least 3",
        successful_retrievals
    );

    // Cleanup
    info!("\nCleaning up...");
    for node in &nodes {
        let _ = node.stop().await;
    }

    info!("\n=== TEST PASSED ===");
    Ok(())
}
