// Copyright 2024 Saorsa Labs Limited
// Tests for presence and device management

use anyhow::Result;
use saorsa_core::types::{
    Device, DeviceCapabilities, DeviceId, DeviceType, Endpoint, MlDsaKeyPair, Presence,
};
use saorsa_core::{
    get_presence, register_headless, register_identity, register_presence, set_active_device,
};

#[tokio::test]
async fn test_single_device_presence() -> Result<()> {
    // Test registering presence with single device
    let words = ["welfare", "absurd", "kingdom", "ridge"];
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;
    
    let device = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 100,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.100:9000".to_string(),
        },
        capabilities: DeviceCapabilities::default(),
    };
    
    let receipt = register_presence(&handle, vec![device.clone()], device.id).await?;
    
    assert_eq!(receipt.identity, handle.key());
    assert!(!receipt.storing_nodes.is_empty());
    
    Ok(())
}

#[tokio::test]
async fn test_multi_device_presence() -> Result<()> {
    // Test registering presence with multiple devices
    let words = ["regime", "abstract", "aaron", "ancient"];
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;
    
    let active_device = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 50,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.100:9000".to_string(),
        },
        capabilities: DeviceCapabilities::default(),
    };
    
    let headless_device = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Headless,
        storage_gb: 1000,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.101:9001".to_string(),
        },
        capabilities: DeviceCapabilities {
            storage_bytes: 1_000_000_000_000, // 1TB
            always_online: true,
            ..Default::default()
        },
    };
    
    let mobile_device = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Mobile,
        storage_gb: 10,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "10.0.0.5:9002".to_string(),
        },
        capabilities: DeviceCapabilities {
            storage_bytes: 10_000_000_000, // 10GB
            bandwidth_mbps: 50,
            cpu_cores: 2,
            always_online: false,
            ..Default::default()
        },
    };
    
    let devices = vec![active_device.clone(), headless_device, mobile_device];
    let receipt = register_presence(&handle, devices.clone(), active_device.id).await?;
    
    assert_eq!(receipt.identity, handle.key());
    
    // Fetch and verify presence
    let presence = get_presence(handle.key()).await?;
    assert_eq!(presence.devices.len(), 3);
    assert_eq!(presence.active_device, Some(active_device.id));
    assert!(presence.has_headless_nodes());
    assert_eq!(presence.total_storage_gb(), 1060); // 50 + 1000 + 10
    
    Ok(())
}

#[tokio::test]
async fn test_headless_node_registration() -> Result<()> {
    // Test registering headless storage nodes
    let words = ["court", "absurd", "aaron", "picture"];
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;
    
    // Register initial presence with active device
    let active_device = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 50,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.100:9000".to_string(),
        },
        capabilities: DeviceCapabilities::default(),
    };
    
    register_presence(&handle, vec![active_device.clone()], active_device.id).await?;
    
    // Add headless node
    let headless_id = register_headless(
        &handle,
        2000, // 2TB
        Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.200:9100".to_string(),
        },
    )
    .await?;
    
    // Verify headless node was added
    let presence = get_presence(handle.key()).await?;
    assert_eq!(presence.devices.len(), 2);
    
    let headless = presence.headless_devices();
    assert_eq!(headless.len(), 1);
    assert_eq!(headless[0].id, headless_id);
    assert_eq!(headless[0].storage_gb, 2000);
    
    Ok(())
}

#[tokio::test]
async fn test_active_device_switching() -> Result<()> {
    // Test switching active device
    let words = ["welfare", "absurd", "kinshasa", "ridge"];
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;
    
    let device1 = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 50,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.100:9000".to_string(),
        },
        capabilities: DeviceCapabilities::default(),
    };
    
    let device2 = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 100,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.101:9001".to_string(),
        },
        capabilities: DeviceCapabilities::default(),
    };
    
    // Register with device1 active
    register_presence(&handle, vec![device1.clone(), device2.clone()], device1.id).await?;
    
    let presence1 = get_presence(handle.key()).await?;
    assert_eq!(presence1.active_device, Some(device1.id));
    
    // Switch to device2
    set_active_device(&handle, device2.id).await?;
    
    let presence2 = get_presence(handle.key()).await?;
    assert_eq!(presence2.active_device, Some(device2.id));
    
    Ok(())
}

#[tokio::test]
async fn test_device_capabilities() -> Result<()> {
    // Test device capability tracking
    let words = ["huge", "yours", "zurich", "picture"];
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;
    
    let high_perf_device = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Headless,
        storage_gb: 5000,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "10.0.0.100:9000".to_string(),
        },
        capabilities: DeviceCapabilities {
            storage_bytes: 5_000_000_000_000, // 5TB
            bandwidth_mbps: 1000,              // 1Gbps
            cpu_cores: 16,
            always_online: true,
            supports_fec: true,
            supports_seal: true,
        },
    };
    
    let low_perf_device = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Mobile,
        storage_gb: 5,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "10.0.0.101:9001".to_string(),
        },
        capabilities: DeviceCapabilities {
            storage_bytes: 5_000_000_000, // 5GB
            bandwidth_mbps: 10,
            cpu_cores: 2,
            always_online: false,
            supports_fec: false, // Mobile can't do FEC
            supports_seal: true,
        },
    };
    
    register_presence(
        &handle,
        vec![high_perf_device.clone(), low_perf_device.clone()],
        high_perf_device.id,
    )
    .await?;
    
    let presence = get_presence(handle.key()).await?;
    
    // Find devices that support FEC
    let fec_capable: Vec<_> = presence
        .devices
        .iter()
        .filter(|d| d.capabilities.supports_fec)
        .collect();
    assert_eq!(fec_capable.len(), 1);
    assert_eq!(fec_capable[0].id, high_perf_device.id);
    
    // Find always-online devices
    let always_online: Vec<_> = presence
        .devices
        .iter()
        .filter(|d| d.capabilities.always_online)
        .collect();
    assert_eq!(always_online.len(), 1);
    
    Ok(())
}

#[tokio::test]
async fn test_presence_signature_verification() -> Result<()> {
    // Test that presence packets are properly signed
    let words = ["thrive", "scott", "liechtenstein", "ridge"];
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;
    
    let device = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 100,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.100:9000".to_string(),
        },
        capabilities: DeviceCapabilities::default(),
    };
    
    register_presence(&handle, vec![device.clone()], device.id).await?;
    
    let presence = get_presence(handle.key()).await?;
    
    // Signature should be present and non-empty
    assert!(!presence.signature.is_empty());
    
    // TODO: Verify signature with identity's public key
    // This would require exposing the canonical presence bytes function
    
    Ok(())
}

#[tokio::test]
async fn test_presence_update() -> Result<()> {
    // Test updating presence (adding/removing devices)
    let words = ["addition", "almaty", "kite", "almaty"];
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;
    
    let device1 = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 50,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.100:9000".to_string(),
        },
        capabilities: DeviceCapabilities::default(),
    };
    
    // Initial presence with one device
    register_presence(&handle, vec![device1.clone()], device1.id).await?;
    
    let presence1 = get_presence(handle.key()).await?;
    assert_eq!(presence1.devices.len(), 1);
    
    // Update with additional device
    let device2 = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Headless,
        storage_gb: 500,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.101:9001".to_string(),
        },
        capabilities: DeviceCapabilities {
            always_online: true,
            ..Default::default()
        },
    };
    
    register_presence(&handle, vec![device1.clone(), device2], device1.id).await?;
    
    let presence2 = get_presence(handle.key()).await?;
    assert_eq!(presence2.devices.len(), 2);
    assert_eq!(presence2.total_storage_gb(), 550);
    
    Ok(())
}

#[tokio::test]
async fn test_presence_timestamp() -> Result<()> {
    // Test that presence includes proper timestamps
    let words = ["bless", "abstract", "assess", "abstract"];
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;
    
    let device = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 100,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.100:9000".to_string(),
        },
        capabilities: DeviceCapabilities::default(),
    };
    
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    
    let device_id = device.id;
    register_presence(&handle, vec![device], device_id).await?;
    
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    
    let presence = get_presence(handle.key()).await?;
    
    assert!(presence.timestamp >= before);
    assert!(presence.timestamp <= after);
    
    Ok(())
}