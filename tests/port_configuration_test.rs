//! Integration tests for port configuration functionality
//! Tests the new NetworkConfig integration with ant-quic 0.9.0

use anyhow::Result;
use saorsa_core::identity::FourWordAddress;
use saorsa_core::messaging::DhtClient;
use saorsa_core::messaging::{IpMode, MessagingService, NetworkConfig, PortConfig, RetryBehavior};

#[tokio::test]
async fn test_os_assigned_port() -> Result<()> {
    // Create DHT client
    let dht_client = DhtClient::new()?;

    // Create identity
    let address = FourWordAddress("test-peer-one-alpha".to_string());

    // Use default config (OS-assigned port, IPv4-only)
    let service = MessagingService::new(address, dht_client).await?;

    // Get actual bound addresses
    let addrs = service.listen_addrs().await;
    assert!(!addrs.is_empty(), "Should have at least one bound address");

    // OS-assigned port should not be 0 after binding
    let port = addrs[0].port();
    assert_ne!(port, 0, "OS-assigned port should have actual value");
    assert!(port >= 1024, "Should be non-privileged port");

    Ok(())
}

#[tokio::test]
async fn test_multiple_instances_different_ports() -> Result<()> {
    // Create two instances with OS-assigned ports
    let dht1 = DhtClient::new()?;
    let dht2 = DhtClient::new()?;

    let addr1 = FourWordAddress("test-peer-two-alpha".to_string());
    let addr2 = FourWordAddress("test-peer-two-beta".to_string());

    let service1 = MessagingService::new(addr1, dht1).await?;
    let service2 = MessagingService::new(addr2, dht2).await?;

    // Get ports
    let port1 = service1.listen_addrs().await[0].port();
    let port2 = service2.listen_addrs().await[0].port();

    // Should have different ports
    assert_ne!(
        port1, port2,
        "Multiple instances should get different ports"
    );

    Ok(())
}

#[tokio::test]
#[ignore] // Ignore by default as this requires new_with_config() implementation
async fn test_explicit_port_configuration() -> Result<()> {
    let dht_client = DhtClient::new()?;
    let address = FourWordAddress("test-peer-three-alpha".to_string());

    // Use explicit port
    let config = NetworkConfig {
        port: PortConfig::Explicit(12345),
        ip_mode: IpMode::IPv4Only,
        retry_behavior: RetryBehavior::FailFast,
        nat_traversal: None,
    };

    let service = MessagingService::new_with_config(address, dht_client, config).await?;

    // Verify port
    let port = service.listen_addrs().await[0].port();
    assert_eq!(port, 12345, "Should bind to explicit port");

    Ok(())
}

#[tokio::test]
#[ignore] // Ignore by default as this requires new_with_config() implementation
async fn test_port_range_configuration() -> Result<()> {
    let dht_client = DhtClient::new()?;
    let address = FourWordAddress("test-peer-four-alpha".to_string());

    // Use port range
    let config = NetworkConfig {
        port: PortConfig::Range(20000, 20010),
        ip_mode: IpMode::IPv4Only,
        retry_behavior: RetryBehavior::TryNext,
        nat_traversal: None,
    };

    let service = MessagingService::new_with_config(address, dht_client, config).await?;

    // Verify port is in range
    let port = service.listen_addrs().await[0].port();
    assert!(
        (20000..=20010).contains(&port),
        "Port should be in specified range"
    );

    Ok(())
}

#[tokio::test]
#[ignore] // Ignore by default as this requires new_with_config() implementation
async fn test_ipv4_only_mode() -> Result<()> {
    let dht_client = DhtClient::new()?;
    let address = FourWordAddress("test-peer-five-alpha".to_string());

    let config = NetworkConfig {
        port: PortConfig::OsAssigned,
        ip_mode: IpMode::IPv4Only,
        retry_behavior: RetryBehavior::FailFast,
        nat_traversal: None,
    };

    let service = MessagingService::new_with_config(address, dht_client, config).await?;

    // All addresses should be IPv4
    for addr in service.listen_addrs().await {
        assert!(addr.is_ipv4(), "All addresses should be IPv4");
    }

    Ok(())
}

#[tokio::test]
#[ignore] // Ignore by default as this requires new_with_config() implementation
async fn test_port_conflict_handling() -> Result<()> {
    let dht1 = DhtClient::new()?;
    let dht2 = DhtClient::new()?;

    let addr1 = FourWordAddress("test-peer-six-alpha".to_string());
    let addr2 = FourWordAddress("test-peer-six-beta".to_string());

    let port = 12346;
    let config = NetworkConfig {
        port: PortConfig::Explicit(port),
        ip_mode: IpMode::IPv4Only,
        retry_behavior: RetryBehavior::FailFast,
        nat_traversal: None,
    };

    // First instance should succeed
    let _service1 = MessagingService::new_with_config(addr1, dht1, config.clone()).await?;

    // Second instance should fail with FailFast
    let result = MessagingService::new_with_config(addr2, dht2, config).await;
    assert!(
        result.is_err(),
        "Second instance should fail on port conflict"
    );

    Ok(())
}

#[tokio::test]
#[ignore] // Ignore by default as this requires new_with_config() implementation
async fn test_port_conflict_fallback() -> Result<()> {
    let dht1 = DhtClient::new()?;
    let dht2 = DhtClient::new()?;

    let addr1 = FourWordAddress("test-peer-seven-alpha".to_string());
    let addr2 = FourWordAddress("test-peer-seven-beta".to_string());

    let port = 12347;
    let config1 = NetworkConfig {
        port: PortConfig::Explicit(port),
        ip_mode: IpMode::IPv4Only,
        retry_behavior: RetryBehavior::FailFast,
        nat_traversal: None,
    };

    let config2 = NetworkConfig {
        port: PortConfig::Explicit(port),
        ip_mode: IpMode::IPv4Only,
        retry_behavior: RetryBehavior::FallbackToOsAssigned,
        nat_traversal: None,
    };

    // First instance uses explicit port
    let service1 = MessagingService::new_with_config(addr1, dht1, config1).await?;
    let port1 = service1.listen_addrs().await[0].port();

    // Second instance should fall back to OS-assigned
    let service2 = MessagingService::new_with_config(addr2, dht2, config2).await?;
    let port2 = service2.listen_addrs().await[0].port();

    assert_eq!(port1, port, "First instance should use explicit port");
    assert_ne!(
        port2, port,
        "Second instance should fall back to different port"
    );

    Ok(())
}
