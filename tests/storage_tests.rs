// Copyright 2024 Saorsa Labs Limited
// Tests for storage API with saorsa-seal and saorsa-fec

use anyhow::Result;
use saorsa_core::types::{Device, DeviceId, DeviceType, Endpoint, MlDsaKeyPair, StorageStrategy};
use saorsa_core::{
    get_data, register_identity, register_presence, store_data, store_dyad, store_with_fec,
};

#[tokio::test]
async fn test_store_and_retrieve_single_user() -> Result<()> {
    // Test basic store/retrieve for single user (no FEC)
    let words = ["welfare", "absurd", "king", "ridge"];
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;
    
    // Register device
    let device = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 100,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.100:9000".to_string(),
        },
        capabilities: Default::default(),
    };
    let device_id = device.id;
    register_presence(&handle, vec![device], device_id).await?;
    
    // Store data
    let data = b"Hello, Saorsa Network!".to_vec();
    let storage_handle = store_data(&handle, data.clone(), 1).await?;
    
    // Verify storage strategy (should be Direct for single user)
    assert!(matches!(storage_handle.strategy, StorageStrategy::Direct));
    
    // Retrieve data
    let retrieved = get_data(&storage_handle).await?;
    assert_eq!(retrieved, data);
    
    Ok(())
}

#[tokio::test]
async fn test_store_dyad_optimization() -> Result<()> {
    // Test optimized storage for 2-person groups (no FEC, just replication)
    let words1 = ["huge", "yours", "zurich", "picture"];
    let words2 = ["thrive", "scott", "liechtenstein", "ridge"];
    let keypair1 = MlDsaKeyPair::generate()?;
    let keypair2 = MlDsaKeyPair::generate()?;
    
    let handle1 = register_identity(words1, &keypair1).await?;
    let handle2 = register_identity(words2, &keypair2).await?;
    
    // Register devices for both users
    let device1 = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 100,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.100:9000".to_string(),
        },
        capabilities: Default::default(),
    };
    
    let device2 = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 100,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.101:9001".to_string(),
        },
        capabilities: Default::default(),
    };
    
    let device1_id = device1.id;
    let device2_id = device2.id;
    register_presence(&handle1, vec![device1], device1_id).await?;
    register_presence(&handle2, vec![device2], device2_id).await?;
    
    // Store data using dyad optimization
    let data = b"Private message between two users".to_vec();
    let storage_handle = store_dyad(&handle1, handle2.key(), data.clone()).await?;
    
    // Verify storage strategy (should be FullReplication)
    assert!(matches!(
        storage_handle.strategy,
        StorageStrategy::FullReplication { replicas: 2 }
    ));
    
    // Both users should be able to retrieve
    let retrieved = get_data(&storage_handle).await?;
    assert_eq!(retrieved, data);
    
    Ok(())
}

#[tokio::test]
async fn test_store_with_fec_small_group() -> Result<()> {
    // Test FEC storage for small group (3-5 members)
    let words = ["regime", "abstract", "a", "ancient"];
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;
    
    // Register multiple devices to distribute shards
    let mut devices = vec![];
    for i in 0..3 {
        devices.push(Device {
            id: DeviceId::generate(),
            device_type: if i == 0 {
                DeviceType::Active
            } else {
                DeviceType::Headless
            },
            storage_gb: 100,
            endpoint: Endpoint {
                protocol: "quic".to_string(),
                address: format!("192.168.1.{}:900{}", 100 + i, i),
            },
            capabilities: Default::default(),
        });
    }
    
    register_presence(&handle, devices.clone(), devices[0].id).await?;
    
    // Store data with FEC for group size 4
    let data = vec![42u8; 10000]; // 10KB of data
    let storage_handle = store_data(&handle, data.clone(), 4).await?;
    
    // Verify FEC strategy
    match &storage_handle.strategy {
        StorageStrategy::FecEncoded {
            data_shards,
            parity_shards,
            ..
        } => {
            assert_eq!(*data_shards, 3);
            assert_eq!(*parity_shards, 2);
        }
        _ => panic!("Expected FEC encoding for group size 4"),
    }
    
    // Verify shard distribution across devices
    assert_eq!(storage_handle.shard_map.devices().len(), 3);
    
    // Retrieve and verify
    let retrieved = get_data(&storage_handle).await?;
    assert_eq!(retrieved, data);
    
    Ok(())
}

#[tokio::test]
async fn test_store_with_custom_fec_params() -> Result<()> {
    // Test custom FEC parameters
    let words = ["component", "abuja", "a", "kenneth"];
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;
    
    // Register headless nodes for storage
    let mut devices = vec![];
    for i in 0..5 {
        devices.push(Device {
            id: DeviceId::generate(),
            device_type: if i == 0 {
                DeviceType::Active
            } else {
                DeviceType::Headless
            },
            storage_gb: 500,
            endpoint: Endpoint {
                protocol: "quic".to_string(),
                address: format!("10.0.0.{}:9000", i),
            },
            capabilities: Default::default(),
        });
    }
    
    register_presence(&handle, devices.clone(), devices[0].id).await?;
    
    // Store with custom FEC (8 data, 4 parity)
    let data = vec![0xABu8; 100000]; // 100KB
    let storage_handle = store_with_fec(&handle, data.clone(), 8, 4).await?;
    
    // Verify custom parameters
    match &storage_handle.strategy {
        StorageStrategy::FecEncoded {
            data_shards,
            parity_shards,
            ..
        } => {
            assert_eq!(*data_shards, 8);
            assert_eq!(*parity_shards, 4);
        }
        _ => panic!("Expected FEC encoding with custom params"),
    }
    
    // Retrieve and verify
    let retrieved = get_data(&storage_handle).await?;
    assert_eq!(retrieved, data);
    
    Ok(())
}

#[tokio::test]
async fn test_fec_recovery_with_missing_shards() -> Result<()> {
    // Test that data can be recovered even with missing shards
    let words = ["court", "absurd", "a", "picture"];
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;
    
    // Register enough devices for FEC
    let mut devices = vec![];
    for i in 0..6 {
        devices.push(Device {
            id: DeviceId::generate(),
            device_type: DeviceType::Headless,
            storage_gb: 200,
            endpoint: Endpoint {
                protocol: "quic".to_string(),
                address: format!("10.0.1.{}:9000", i),
            },
            capabilities: Default::default(),
        });
    }
    
    register_presence(&handle, devices.clone(), devices[0].id).await?;
    
    // Store with FEC (4 data, 2 parity = can lose 2 shards)
    let data = b"Important data that must survive failures".to_vec();
    let storage_handle = store_with_fec(&handle, data.clone(), 4, 2).await?;
    
    // TODO: Simulate losing 2 shards (would require lower-level API)
    // For now, just verify we can retrieve
    let retrieved = get_data(&storage_handle).await?;
    assert_eq!(retrieved, data);
    
    Ok(())
}

#[tokio::test]
async fn test_seal_encryption() -> Result<()> {
    // Test that data is properly sealed (encrypted)
    let words = ["regime", "abstract", "abandon", "ancient"];
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
        capabilities: Default::default(),
    };
    let device_id = device.id;
    register_presence(&handle, vec![device], device_id).await?;
    
    // Store sensitive data
    let sensitive_data = b"Secret information that must be encrypted".to_vec();
    let storage_handle = store_data(&handle, sensitive_data.clone(), 1).await?;
    
    // Verify sealed_key is present (encryption was applied)
    assert!(storage_handle.sealed_key.is_some());
    assert!(!storage_handle.sealed_key.as_ref().unwrap().is_empty());
    
    // Retrieve should decrypt automatically
    let retrieved = get_data(&storage_handle).await?;
    assert_eq!(retrieved, sensitive_data);
    
    Ok(())
}

#[tokio::test]
async fn test_large_file_storage() -> Result<()> {
    // Test storing larger files with FEC
    let words = ["court", "absurd", "abandon", "picture"];
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;
    
    // Register high-capacity headless nodes
    let mut devices = vec![];
    for i in 0..4 {
        devices.push(Device {
            id: DeviceId::generate(),
            device_type: DeviceType::Headless,
            storage_gb: 1000, // 1TB each
            endpoint: Endpoint {
                protocol: "quic".to_string(),
                address: format!("10.0.2.{}:9000", i),
            },
            capabilities: saorsa_core::types::DeviceCapabilities {
                storage_bytes: 1_000_000_000_000,
                always_online: true,
                supports_fec: true,
                supports_seal: true,
                ..Default::default()
            },
        });
    }
    
    register_presence(&handle, devices.clone(), devices[0].id).await?;
    
    // Store 1MB file
    let large_data = vec![0xFFu8; 1_000_000];
    let storage_handle = store_with_fec(&handle, large_data.clone(), 6, 3).await?;
    
    // Verify sharding
    assert!(storage_handle.shard_map.total_shards > 0);
    assert_eq!(storage_handle.size, 1_000_000);
    
    // Retrieve and verify (first and last bytes)
    let retrieved = get_data(&storage_handle).await?;
    assert_eq!(retrieved.len(), large_data.len());
    assert_eq!(retrieved[0], 0xFF);
    assert_eq!(retrieved[999_999], 0xFF);
    
    Ok(())
}

#[tokio::test]
async fn test_shard_distribution_preference() -> Result<()> {
    // Test that shards prefer headless nodes over active devices
    let words = ["welfare", "absurd", "kiribati", "ridge"];
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
        capabilities: Default::default(),
    };
    
    let headless1 = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Headless,
        storage_gb: 500,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "10.0.0.1:9001".to_string(),
        },
        capabilities: saorsa_core::types::DeviceCapabilities {
            always_online: true,
            ..Default::default()
        },
    };
    
    let headless2 = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Headless,
        storage_gb: 500,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "10.0.0.2:9002".to_string(),
        },
        capabilities: saorsa_core::types::DeviceCapabilities {
            always_online: true,
            ..Default::default()
        },
    };
    
    register_presence(
        &handle,
        vec![active_device.clone(), headless1.clone(), headless2.clone()],
        active_device.id,
    )
    .await?;
    
    // Store data with FEC
    let data = vec![123u8; 50000];
    let storage_handle = store_with_fec(&handle, data, 4, 2).await?;
    
    // Verify most shards went to headless nodes
    let headless1_shards = storage_handle
        .shard_map
        .device_shards(&headless1.id)
        .map(|s| s.len())
        .unwrap_or(0);
    let headless2_shards = storage_handle
        .shard_map
        .device_shards(&headless2.id)
        .map(|s| s.len())
        .unwrap_or(0);
    let active_shards = storage_handle
        .shard_map
        .device_shards(&active_device.id)
        .map(|s| s.len())
        .unwrap_or(0);
    
    // Headless nodes should have more shards than active device
    assert!(headless1_shards + headless2_shards > active_shards);
    
    Ok(())
}

#[tokio::test]
async fn test_group_size_strategy_selection() -> Result<()> {
    // Test automatic strategy selection based on group size
    let words = ["regime", "ancient", "ok", "ancient"];
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;
    
    // Register device
    let device = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 100,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.100:9000".to_string(),
        },
        capabilities: Default::default(),
    };
    let device_id = device.id;
    register_presence(&handle, vec![device], device_id).await?;
    
    let data = b"Test data".to_vec();
    
    // Test different group sizes
    let test_cases = vec![
        (1, StorageStrategy::Direct),
        (
            2,
            StorageStrategy::FullReplication { replicas: 2 },
        ),
        (
            4,
            StorageStrategy::FecEncoded {
                data_shards: 3,
                parity_shards: 2,
                shard_size: 65536,
            },
        ),
        (
            8,
            StorageStrategy::FecEncoded {
                data_shards: 4,
                parity_shards: 3,
                shard_size: 65536,
            },
        ),
        (
            15,
            StorageStrategy::FecEncoded {
                data_shards: 6,
                parity_shards: 4,
                shard_size: 131072,
            },
        ),
    ];
    
    for (group_size, expected_strategy) in test_cases {
        let storage_handle = store_data(&handle, data.clone(), group_size).await?;
        
        match (&storage_handle.strategy, &expected_strategy) {
            (StorageStrategy::Direct, StorageStrategy::Direct) => {}
            (
                StorageStrategy::FullReplication { replicas: r1 },
                StorageStrategy::FullReplication { replicas: r2 },
            ) => assert_eq!(r1, r2),
            (
                StorageStrategy::FecEncoded {
                    data_shards: d1,
                    parity_shards: p1,
                    ..
                },
                StorageStrategy::FecEncoded {
                    data_shards: d2,
                    parity_shards: p2,
                    ..
                },
            ) => {
                assert_eq!(d1, d2);
                assert_eq!(p1, p2);
            }
            _ => panic!(
                "Strategy mismatch for group size {}: got {:?}, expected {:?}",
                group_size, storage_handle.strategy, expected_strategy
            ),
        }
    }
    
    Ok(())
}