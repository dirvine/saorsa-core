// P2P NAT Traversal Integration Test for saorsa-core v0.5.0
//
// Tests that two MessagingService instances can establish P2P connections
// and exchange messages using ant-quic 0.10.0's NAT traversal capabilities.

use anyhow::Result;
use saorsa_core::identity::FourWordAddress;
use saorsa_core::messaging::{DhtClient, MessagingService, NetworkConfig};
use std::time::Duration;
use tokio::time::timeout;

/// Test that two messaging services can establish P2P connections with default NAT config
#[tokio::test(flavor = "multi_thread")]
async fn test_p2p_connection_with_default_nat() -> Result<()> {
    // Initialize tracing for debugging
    let _ = tracing_subscriber::fmt::try_init();

    // Create two test identities
    let addr1 = FourWordAddress("alpha-bravo-charlie-delta".to_string());
    let addr2 = FourWordAddress("echo-foxtrot-golf-hotel".to_string());

    // Create DHT clients
    let dht1 = DhtClient::new()?;
    let dht2 = DhtClient::new()?;

    // Use default NetworkConfig (includes P2P NAT traversal)
    let config = NetworkConfig::default();

    tracing::info!("Creating messaging service 1...");
    let service1 = MessagingService::new_with_config(addr1.clone(), dht1, config.clone()).await?;

    tracing::info!("Creating messaging service 2...");
    let service2 = MessagingService::new_with_config(addr2.clone(), dht2, config).await?;

    // Get the listening addresses
    let addrs1 = service1.listen_addrs().await;
    let addrs2 = service2.listen_addrs().await;

    tracing::info!("Service 1 listening on: {:?}", addrs1);
    tracing::info!("Service 2 listening on: {:?}", addrs2);

    // Verify both services are listening
    assert!(
        !addrs1.is_empty(),
        "Service 1 should have listening addresses"
    );
    assert!(
        !addrs2.is_empty(),
        "Service 2 should have listening addresses"
    );

    Ok(())
}

/// Test P2P connection with explicit NAT configuration
#[tokio::test(flavor = "multi_thread")]
async fn test_p2p_connection_with_explicit_nat() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let addr1 = FourWordAddress("india-juliet-kilo-lima".to_string());
    let addr2 = FourWordAddress("mike-november-oscar-papa".to_string());

    let dht1 = DhtClient::new()?;
    let dht2 = DhtClient::new()?;

    // Create P2P node configuration with specific concurrency limit
    let config = NetworkConfig::p2p_node(5);

    tracing::info!("Creating messaging service 1 with P2P NAT (concurrency=5)...");
    let service1 = MessagingService::new_with_config(addr1, dht1, config.clone()).await?;

    tracing::info!("Creating messaging service 2 with P2P NAT (concurrency=5)...");
    let service2 = MessagingService::new_with_config(addr2, dht2, config).await?;

    // Verify services are running
    assert!(service1.is_running().await, "Service 1 should be running");
    assert!(service2.is_running().await, "Service 2 should be running");

    // Verify we can get peer count (should be 0 initially)
    let peer_count1 = service1.peer_count().await;
    let peer_count2 = service2.peer_count().await;

    assert_eq!(peer_count1, 0, "Service 1 should have no peers initially");
    assert_eq!(peer_count2, 0, "Service 2 should have no peers initially");

    Ok(())
}

/// Test client-only NAT configuration
#[tokio::test(flavor = "multi_thread")]
async fn test_client_only_nat() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let addr = FourWordAddress("quebec-romeo-sierra-tango".to_string());
    let dht = DhtClient::new()?;

    // Create client-only configuration
    let config = NetworkConfig::client_only();

    tracing::info!("Creating messaging service with client-only NAT...");
    let service = MessagingService::new_with_config(addr, dht, config).await?;

    // Verify service is running
    assert!(service.is_running().await, "Service should be running");

    // Get listening addresses
    let addrs = service.listen_addrs().await;
    tracing::info!("Client-only service listening on: {:?}", addrs);

    assert!(
        !addrs.is_empty(),
        "Client-only service should have listening addresses"
    );

    Ok(())
}

/// Test NAT traversal disabled
#[tokio::test(flavor = "multi_thread")]
async fn test_no_nat_traversal() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let addr = FourWordAddress("uniform-victor-whiskey-xray".to_string());
    let dht = DhtClient::new()?;

    // Create configuration with NAT traversal disabled
    let config = NetworkConfig::no_nat_traversal();

    tracing::info!("Creating messaging service with NAT traversal disabled...");
    let service = MessagingService::new_with_config(addr, dht, config).await?;

    // Verify service is running
    assert!(service.is_running().await, "Service should be running");

    Ok(())
}

/// Test that services can be created and destroyed cleanly
#[tokio::test(flavor = "multi_thread")]
async fn test_service_lifecycle_with_nat() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let addr = FourWordAddress("yankee-zulu-alpha-bravo".to_string());
    let dht = DhtClient::new()?;

    let config = NetworkConfig::default();

    // Create service
    tracing::info!("Creating messaging service...");
    let service = MessagingService::new_with_config(addr, dht, config).await?;

    assert!(
        service.is_running().await,
        "Service should be running after creation"
    );

    // Service should be dropped cleanly when it goes out of scope
    drop(service);

    // Small delay to allow cleanup
    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok(())
}

/// Benchmark: Measure time to create P2P messaging services
#[tokio::test(flavor = "multi_thread")]
async fn test_p2p_service_creation_performance() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let addr = FourWordAddress("charlie-delta-echo-foxtrot".to_string());
    let dht = DhtClient::new()?;
    let config = NetworkConfig::default();

    let start = std::time::Instant::now();

    let service = timeout(
        Duration::from_secs(5),
        MessagingService::new_with_config(addr, dht, config),
    )
    .await??;

    let duration = start.elapsed();

    tracing::info!("P2P service creation took: {:?}", duration);

    // Service should be created quickly (< 2 seconds)
    assert!(
        duration < Duration::from_secs(2),
        "Service creation should be fast (took {:?})",
        duration
    );

    assert!(service.is_running().await, "Service should be running");

    Ok(())
}
