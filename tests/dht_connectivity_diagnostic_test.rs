// Copyright 2024 Saorsa Labs Limited
//
// Diagnostic test to identify DHT connectivity issues
// This test runs step-by-step with timeouts to pinpoint where things fail.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use anyhow::Result;
use saorsa_core::dht::DHTConfig;
use saorsa_core::dht_network_manager::{DhtNetworkConfig, DhtNetworkManager, DhtNetworkResult};
use saorsa_core::network::NodeConfig;
use saorsa_core::transport_handle::{TransportConfig, TransportHandle};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

async fn create_node_with_transport(
    peer_id: &str,
) -> saorsa_core::Result<(Arc<TransportHandle>, DhtNetworkConfig)> {
    let node_config = NodeConfig::builder()
        .peer_id(peer_id.to_string())
        .listen_port(0)
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
        .await?,
    );

    let config = DhtNetworkConfig {
        local_peer_id: peer_id.to_string(),
        dht_config: DHTConfig::default(),
        node_config,
        request_timeout: Duration::from_secs(5),
        max_concurrent_operations: 10,
        replication_factor: 3,
        enable_security: false,
    };

    Ok((transport, config))
}

fn key_from_str(s: &str) -> [u8; 32] {
    let hash = blake3::hash(s.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    key
}

/// Step 1: Can we create a single DhtNetworkManager?
#[tokio::test]
async fn step1_create_single_manager() -> Result<()> {
    println!("STEP 1: Creating single DhtNetworkManager...");

    let result = timeout(Duration::from_secs(10), async {
        let (transport, config) = create_node_with_transport("diag_node_1").await?;
        transport.start_network_listeners().await?;
        DhtNetworkManager::new(transport, None, config).await
    })
    .await;

    match result {
        Ok(Ok(manager)) => {
            println!("  ✓ Manager created successfully");
            println!("  Local addr: {:?}", manager.local_addr());
            println!("  Peer ID: {}", manager.peer_id());
            Ok(())
        }
        Ok(Err(e)) => {
            println!("  ✗ Manager creation failed: {}", e);
            Err(e.into())
        }
        Err(_) => {
            println!("  ✗ Manager creation timed out after 10s");
            Err(anyhow::anyhow!("Timeout"))
        }
    }
}

/// Step 2: Can we start a manager?
#[tokio::test]
async fn step2_start_manager() -> Result<()> {
    println!("STEP 2: Starting DhtNetworkManager...");

    let manager = Arc::new(
        timeout(Duration::from_secs(10), async {
            let (transport, config) = create_node_with_transport("diag_node_2").await?;
            transport.start_network_listeners().await?;
            DhtNetworkManager::new(transport, None, config).await
        })
        .await??,
    );
    println!("  Manager created");

    let start_result = timeout(Duration::from_secs(10), manager.start()).await;

    match start_result {
        Ok(Ok(())) => {
            println!("  ✓ Manager started successfully");
            println!("  Local addr after start: {:?}", manager.local_addr());
            let _ = manager.stop().await;
            Ok(())
        }
        Ok(Err(e)) => {
            println!("  ✗ Manager start failed: {}", e);
            Err(e.into())
        }
        Err(_) => {
            println!("  ✗ Manager start timed out after 10s");
            Err(anyhow::anyhow!("Timeout"))
        }
    }
}

/// Step 3: Can we create and start two managers?
#[tokio::test]
async fn step3_two_managers() -> Result<()> {
    println!("STEP 3: Creating two managers...");

    let manager1 = Arc::new(
        timeout(Duration::from_secs(10), async {
            let (transport, config) = create_node_with_transport("diag_node_3a").await?;
            transport.start_network_listeners().await?;
            DhtNetworkManager::new(transport, None, config).await
        })
        .await??,
    );
    println!("  Manager 1 created");

    let manager2 = Arc::new(
        timeout(Duration::from_secs(10), async {
            let (transport, config) = create_node_with_transport("diag_node_3b").await?;
            transport.start_network_listeners().await?;
            DhtNetworkManager::new(transport, None, config).await
        })
        .await??,
    );
    println!("  Manager 2 created");

    timeout(Duration::from_secs(10), manager1.start()).await??;
    println!("  Manager 1 started at {:?}", manager1.local_addr());

    timeout(Duration::from_secs(10), manager2.start()).await??;
    println!("  Manager 2 started at {:?}", manager2.local_addr());

    println!("  ✓ Both managers started");

    let _ = manager1.stop().await;
    let _ = manager2.stop().await;
    Ok(())
}

/// Step 4: Can two managers connect?
#[tokio::test]
async fn step4_connect_managers() -> Result<()> {
    println!("STEP 4: Connecting two managers...");

    let manager1 = Arc::new(
        timeout(Duration::from_secs(10), async {
            let (transport, config) = create_node_with_transport("diag_node_4a").await?;
            transport.start_network_listeners().await?;
            DhtNetworkManager::new(transport, None, config).await
        })
        .await??,
    );
    let manager2 = Arc::new(
        timeout(Duration::from_secs(10), async {
            let (transport, config) = create_node_with_transport("diag_node_4b").await?;
            transport.start_network_listeners().await?;
            DhtNetworkManager::new(transport, None, config).await
        })
        .await??,
    );

    timeout(Duration::from_secs(10), manager1.start()).await??;
    timeout(Duration::from_secs(10), manager2.start()).await??;

    let addr1 = manager1
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("No addr for manager1"))?;
    println!("  Manager 1 listening at: {}", addr1);
    println!("  Attempting connection from manager2 -> manager1...");

    let connect_result = timeout(Duration::from_secs(15), manager2.connect_to_peer(&addr1)).await;

    match connect_result {
        Ok(Ok(peer_id)) => {
            println!("  ✓ Connected! Peer ID: {}", peer_id);
        }
        Ok(Err(e)) => {
            println!("  ✗ Connection failed: {}", e);
            // Don't fail the test - continue to see what we can learn
        }
        Err(_) => {
            println!("  ✗ Connection timed out after 15s");
        }
    }

    // Check connected peers
    tokio::time::sleep(Duration::from_millis(500)).await;
    let peers1 = manager1.get_connected_peers().await;
    let peers2 = manager2.get_connected_peers().await;
    println!("  Manager 1 connected peers: {}", peers1.len());
    println!("  Manager 2 connected peers: {}", peers2.len());

    let _ = manager1.stop().await;
    let _ = manager2.stop().await;
    Ok(())
}

/// Step 5: Local put/get (no network needed)
#[tokio::test]
async fn step5_local_put_get() -> Result<()> {
    println!("STEP 5: Local put/get (single node)...");

    let manager = Arc::new(
        timeout(Duration::from_secs(10), async {
            let (transport, config) = create_node_with_transport("diag_node_5").await?;
            transport.start_network_listeners().await?;
            DhtNetworkManager::new(transport, None, config).await
        })
        .await??,
    );
    timeout(Duration::from_secs(10), manager.start()).await??;

    let key = key_from_str("diagnostic_test_key");
    let value = b"diagnostic_test_value".to_vec();

    println!("  Storing key locally...");
    let put_result = timeout(Duration::from_secs(10), manager.put(key, value.clone())).await;

    match &put_result {
        Ok(Ok(DhtNetworkResult::PutSuccess { replicated_to, .. })) => {
            println!("  ✓ Put succeeded, replicated to {} nodes", replicated_to);
        }
        Ok(Ok(other)) => println!("  ? Put returned: {:?}", other),
        Ok(Err(e)) => println!("  ✗ Put failed: {}", e),
        Err(_) => println!("  ✗ Put timed out"),
    }

    println!("  Checking local storage...");
    let has_local = manager.has_key_locally(&key).await;
    println!("  Has key locally: {}", has_local);

    if has_local {
        let local_value = manager.get_local(&key).await;
        if let Ok(Some(v)) = local_value {
            if v == value {
                println!("  ✓ Local value matches!");
            } else {
                println!("  ✗ Local value mismatch!");
            }
        }
    }

    let _ = manager.stop().await;
    Ok(())
}

/// Step 6: Cross-node replication test
#[tokio::test]
async fn step6_cross_node_replication() -> Result<()> {
    println!("STEP 6: Cross-node replication test...");

    // Create and start two managers
    let manager1 = Arc::new(
        timeout(Duration::from_secs(10), async {
            let (transport, config) = create_node_with_transport("diag_node_6a").await?;
            transport.start_network_listeners().await?;
            DhtNetworkManager::new(transport, None, config).await
        })
        .await??,
    );
    let manager2 = Arc::new(
        timeout(Duration::from_secs(10), async {
            let (transport, config) = create_node_with_transport("diag_node_6b").await?;
            transport.start_network_listeners().await?;
            DhtNetworkManager::new(transport, None, config).await
        })
        .await??,
    );

    timeout(Duration::from_secs(10), manager1.start()).await??;
    timeout(Duration::from_secs(10), manager2.start()).await??;
    println!("  Both managers started");

    // Connect them
    let addr1 = manager1
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("No addr"))?;
    println!("  Connecting manager2 -> manager1 at {}", addr1);

    let connect_result = timeout(Duration::from_secs(15), manager2.connect_to_peer(&addr1)).await;
    match &connect_result {
        Ok(Ok(peer_id)) => println!("  ✓ Connected: {}", peer_id),
        Ok(Err(e)) => println!("  ✗ Connect error: {}", e),
        Err(_) => println!("  ✗ Connect timeout"),
    }
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Check connected peers before put (these are DHT peers, not just network connections)
    let peers1 = manager1.get_connected_peers().await;
    let peers2 = manager2.get_connected_peers().await;
    println!("  Manager1 DHT peers: {}", peers1.len());
    for p in &peers1 {
        println!("    - {} (connected: {})", p.peer_id, p.is_connected);
    }
    println!("  Manager2 DHT peers: {}", peers2.len());
    for p in &peers2 {
        println!("    - {} (connected: {})", p.peer_id, p.is_connected);
    }

    // Store on manager1
    let key = key_from_str("cross_node_test_key");
    let value = b"cross_node_test_value".to_vec();

    println!("  Storing on manager1 (timeout 30s)...");
    let put_result = timeout(Duration::from_secs(30), manager1.put(key, value.clone())).await;

    match &put_result {
        Ok(Ok(DhtNetworkResult::PutSuccess { replicated_to, .. })) => {
            println!("  ✓ Put succeeded, replicated to {} nodes", replicated_to);
        }
        Ok(Ok(other)) => {
            println!("  ? Put returned unexpected: {:?}", other);
        }
        Ok(Err(e)) => {
            println!("  ✗ Put failed with error: {}", e);
        }
        Err(_) => {
            println!("  ✗ Put TIMED OUT after 30s!");
            println!("    This means put() is blocking on network operations");
        }
    }

    // Wait for potential replication
    println!("  Waiting for replication...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Check local storage on BOTH nodes
    let has_on_1 = manager1.has_key_locally(&key).await;
    let has_on_2 = manager2.has_key_locally(&key).await;

    println!("\n  === REPLICATION RESULTS ===");
    println!("  Manager 1 has key locally: {}", has_on_1);
    println!("  Manager 2 has key locally: {}", has_on_2);

    if has_on_1 && has_on_2 {
        println!("  ✓✓ REPLICATION WORKS! Data exists on both nodes.");
    } else if has_on_1 && !has_on_2 {
        println!("  ⚠ Data only on originating node - replication may not be working");
    } else if !has_on_1 && !has_on_2 {
        println!("  ✗ Data not even stored locally - put() likely timed out");
    } else {
        println!("  ✗ Unexpected state");
    }

    let _ = manager1.stop().await;
    let _ = manager2.stop().await;
    Ok(())
}
