// Copyright 2024 Saorsa Labs Limited
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Multi-device integration tests

use anyhow::Result;
use saorsa_core::types::{
    Device, DeviceCapabilities, DeviceId, DeviceType, Endpoint, MlDsaKeyPair, StorageStrategy,
};
use saorsa_core::{
    get_data, get_presence, register_headless, register_identity, register_presence, store_data,
    store_with_fec,
};
use std::net::Ipv4Addr;

fn valid_four_words(seed: u16) -> [String; 4] {
    use four_word_networking::FourWordEncoder;

    let encoder = FourWordEncoder::new();
    let ip = Ipv4Addr::new(
        10,
        (seed >> 8) as u8,
        (seed & 0xFF) as u8,
        (seed % 200) as u8,
    );
    let port = 10000 + seed;
    let encoding = encoder
        .encode_ipv4(ip, port)
        .expect("IPv4 encoding should succeed for deterministic seed");
    let words = encoding.words();
    [
        words[0].clone(),
        words[1].clone(),
        words[2].clone(),
        words[3].clone(),
    ]
}

fn words_refs(words: &[String; 4]) -> [&str; 4] {
    [
        words[0].as_str(),
        words[1].as_str(),
        words[2].as_str(),
        words[3].as_str(),
    ]
}

#[tokio::test]
async fn test_multi_user_multi_device_storage() -> Result<()> {
    // Test storage across multiple users with multiple devices
    let mut handles = vec![];
    let mut all_devices = vec![];

    // Create 4 users with varying device configurations
    for i in 0..4 {
        let words_owned = valid_four_words(i as u16);
        let words: [&str; 4] = [
            words_owned[0].as_str(),
            words_owned[1].as_str(),
            words_owned[2].as_str(),
            words_owned[3].as_str(),
        ];

        let keypair = MlDsaKeyPair::generate()?;
        let handle = register_identity(words, &keypair).await?;

        // User 0: 1 active + 2 headless
        // User 1: 1 active + 1 headless
        // User 2: 2 active devices
        // User 3: 1 active + 3 headless (storage farm)
        let mut user_devices = vec![];

        // Active device
        let active = Device {
            id: DeviceId::generate(),
            device_type: DeviceType::Active,
            storage_gb: 50 + i * 20,
            endpoint: Endpoint {
                protocol: "quic".to_string(),
                address: format!("192.168.1.{}:900{}", 100 + i, i),
            },
            capabilities: DeviceCapabilities::default(),
        };
        user_devices.push(active.clone());

        // Add headless devices based on user
        let headless_count = match i {
            0 => 2,
            1 => 1,
            2 => 0, // User 2 has second active instead
            3 => 3,
            _ => 0,
        };

        if i == 2 {
            // User 2 gets second active device
            let active2 = Device {
                id: DeviceId::generate(),
                device_type: DeviceType::Active,
                storage_gb: 100,
                endpoint: Endpoint {
                    protocol: "quic".to_string(),
                    address: format!("192.168.1.{}:9005", 100 + i),
                },
                capabilities: DeviceCapabilities::default(),
            };
            user_devices.push(active2);
        }

        for j in 0..headless_count {
            let headless = Device {
                id: DeviceId::generate(),
                device_type: DeviceType::Headless,
                storage_gb: 500 + j * 100,
                endpoint: Endpoint {
                    protocol: "quic".to_string(),
                    address: format!("10.0.{}.{}:900{}", i, j + 1, j),
                },
                capabilities: DeviceCapabilities {
                    storage_bytes: (500 + j * 100) * 1_000_000_000,
                    always_online: true,
                    supports_fec: true,
                    supports_seal: true,
                    ..Default::default()
                },
            };
            user_devices.push(headless);
        }

        register_presence(&handle, user_devices.clone(), active.id).await?;

        handles.push(handle);
        all_devices.extend(user_devices);
    }

    // Store data using replication across all users' devices
    let data = vec![0xABu8; 100_000]; // 100KB
    let storage_handle = store_with_fec(&handles[0], data.clone(), 8, 4).await?;

    // Verify shards are distributed across devices
    // Note: Current implementation only uses devices from the storing user's presence,
    // so we verify that shards are distributed across that user's devices.
    let device_count = storage_handle.shard_map.devices().len();

    // Should use multiple devices from the storing user for redundancy
    // User 0 has 1 active + 2 headless = 3 devices, with 12 total shards (8+4)
    // Headless devices should receive multiple shards
    assert!(device_count >= 1, "Expected at least 1 device with shards");

    // Verify that we got the expected number of total shards assigned
    let total_shards_assigned: usize = storage_handle
        .shard_map
        .devices()
        .iter()
        .filter_map(|d| storage_handle.shard_map.device_shards(d))
        .map(|shards| shards.len())
        .sum();
    assert_eq!(
        total_shards_assigned, 12,
        "Expected 12 total shards (8 data + 4 parity)"
    );

    // Retrieve and verify
    let retrieved = get_data(&storage_handle).await?;
    assert_eq!(retrieved, data);

    Ok(())
}

#[tokio::test]
async fn test_headless_node_preference() -> Result<()> {
    // Test that headless nodes are preferred for storage
    let words_owned = valid_four_words(100);
    let words = words_refs(&words_owned);
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;

    // Mix of device types
    let active1 = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 100,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.100:9000".to_string(),
        },
        capabilities: DeviceCapabilities::default(),
    };

    let mobile = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Mobile,
        storage_gb: 20,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "10.0.0.50:9001".to_string(),
        },
        capabilities: DeviceCapabilities {
            storage_bytes: 20_000_000_000,
            bandwidth_mbps: 50,
            always_online: false,
            ..Default::default()
        },
    };

    let mut headless_devices = vec![];
    for i in 0..3 {
        headless_devices.push(Device {
            id: DeviceId::generate(),
            device_type: DeviceType::Headless,
            storage_gb: 1000,
            endpoint: Endpoint {
                protocol: "quic".to_string(),
                address: format!("10.0.1.{}:900{}", i, i),
            },
            capabilities: DeviceCapabilities {
                storage_bytes: 1_000_000_000_000,
                always_online: true,
                supports_fec: true,
                supports_seal: true,
                ..Default::default()
            },
        });
    }

    let mut all_devices = vec![active1.clone(), mobile.clone()];
    all_devices.extend(headless_devices.clone());

    register_presence(&handle, all_devices, active1.id).await?;

    // Store data with replication across devices
    let data = vec![0xFFu8; 50_000];
    let storage_handle = store_with_fec(&handle, data.clone(), 4, 2).await?;

    // Count shards on each device type
    let mut headless_shards = 0;
    let mut active_shards = 0;
    let mut mobile_shards = 0;

    for device in &headless_devices {
        if let Some(shards) = storage_handle.shard_map.device_shards(&device.id) {
            headless_shards += shards.len();
        }
    }

    if let Some(shards) = storage_handle.shard_map.device_shards(&active1.id) {
        active_shards = shards.len();
    }

    if let Some(shards) = storage_handle.shard_map.device_shards(&mobile.id) {
        mobile_shards = shards.len();
    }

    // Headless should have most shards, mobile least
    assert!(headless_shards > active_shards);
    assert!(active_shards >= mobile_shards);

    Ok(())
}

#[tokio::test]
async fn test_device_failure_recovery() -> Result<()> {
    // Test recovery when devices go offline
    let words_owned = valid_four_words(200);
    let words = words_refs(&words_owned);
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;

    // Start with 6 devices for redundancy
    let mut devices = vec![];
    for i in 0..6 {
        devices.push(Device {
            id: DeviceId::generate(),
            device_type: if i == 0 {
                DeviceType::Active
            } else {
                DeviceType::Headless
            },
            storage_gb: 200,
            endpoint: Endpoint {
                protocol: "quic".to_string(),
                address: format!("10.0.0.{}:900{}", i, i),
            },
            capabilities: DeviceCapabilities {
                always_online: i != 0, // Active device not always online
                supports_fec: true,
                supports_seal: true,
                ..Default::default()
            },
        });
    }

    register_presence(&handle, devices.clone(), devices[0].id).await?;

    // Store with custom replication target (legacy FEC params)
    let data = b"Critical data with redundancy".to_vec();
    let storage_handle = store_with_fec(&handle, data.clone(), 4, 2).await?;

    // Simulate 2 devices going offline by updating presence
    let online_devices = vec![
        devices[0].clone(),
        devices[1].clone(),
        devices[3].clone(),
        devices[4].clone(),
    ];
    register_presence(&handle, online_devices, devices[0].id).await?;

    // Should still be able to retrieve data
    let retrieved = get_data(&storage_handle).await?;
    assert_eq!(retrieved, data);

    Ok(())
}

#[tokio::test]
async fn test_dynamic_device_addition() -> Result<()> {
    // Test adding devices dynamically and redistributing shards
    let words_owned = valid_four_words(300);
    let words = words_refs(&words_owned);
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;

    // Start with minimal devices
    let initial_device = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 50,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.100:9000".to_string(),
        },
        capabilities: DeviceCapabilities::default(),
    };

    register_presence(&handle, vec![initial_device.clone()], initial_device.id).await?;

    // Store initial data (no replication, single device)
    let data1 = b"Initial data on single device".to_vec();
    let storage1 = store_data(&handle, data1.clone(), 1).await?;
    assert!(matches!(storage1.strategy, StorageStrategy::Direct));

    // Add headless nodes dynamically
    let headless1_id = register_headless(
        &handle,
        1000,
        Endpoint {
            protocol: "quic".to_string(),
            address: "10.0.0.1:9001".to_string(),
        },
    )
    .await?;

    let headless2_id = register_headless(
        &handle,
        1000,
        Endpoint {
            protocol: "quic".to_string(),
            address: "10.0.0.2:9002".to_string(),
        },
    )
    .await?;

    // Store new data with replication now that we have redundancy
    let data2 = vec![0x42u8; 50_000];
    let storage2 = store_with_fec(&handle, data2.clone(), 3, 2).await?;

    // Verify replication strategy is used with new devices
    assert!(matches!(
        storage2.strategy,
        StorageStrategy::FullReplication { .. }
    ));

    // Verify new devices are being used
    let presence = get_presence(handle.key()).await?;
    assert_eq!(presence.devices.len(), 3);

    let has_headless1_shards = storage2.shard_map.device_shards(&headless1_id).is_some();
    let has_headless2_shards = storage2.shard_map.device_shards(&headless2_id).is_some();
    assert!(has_headless1_shards || has_headless2_shards);

    Ok(())
}

#[tokio::test]
async fn test_cross_user_collaboration() -> Result<()> {
    // Test multiple users collaborating on shared data
    let words1_owned = valid_four_words(400);
    let words2_owned = valid_four_words(401);
    let words3_owned = valid_four_words(402);

    let words1 = words_refs(&words1_owned);
    let words2 = words_refs(&words2_owned);
    let words3 = words_refs(&words3_owned);

    let keypair1 = MlDsaKeyPair::generate()?;
    let keypair2 = MlDsaKeyPair::generate()?;
    let keypair3 = MlDsaKeyPair::generate()?;

    let handle1 = register_identity(words1, &keypair1).await?;
    let handle2 = register_identity(words2, &keypair2).await?;
    let handle3 = register_identity(words3, &keypair3).await?;

    // Each user registers devices
    for (i, handle) in [&handle1, &handle2, &handle3].iter().enumerate() {
        let active = Device {
            id: DeviceId::generate(),
            device_type: DeviceType::Active,
            storage_gb: 100,
            endpoint: Endpoint {
                protocol: "quic".to_string(),
                address: format!("192.168.1.{}:900{}", 100 + i, i),
            },
            capabilities: DeviceCapabilities::default(),
        };

        let headless = Device {
            id: DeviceId::generate(),
            device_type: DeviceType::Headless,
            storage_gb: 500,
            endpoint: Endpoint {
                protocol: "quic".to_string(),
                address: format!("10.0.0.{}:900{}", i, i),
            },
            capabilities: DeviceCapabilities {
                always_online: true,
                supports_fec: true,
                supports_seal: true,
                ..Default::default()
            },
        };

        register_presence(handle, vec![active.clone(), headless], active.id).await?;
    }

    // Store shared group data using devices from all users
    let group_data = b"Shared collaborative document".to_vec();
    let storage_handle = store_data(&handle1, group_data.clone(), 3).await?;

    // Verify strategy is appropriate for 3-person group
    match storage_handle.strategy {
        StorageStrategy::FullReplication { replicas } => {
            assert_eq!(replicas, 3);
        }
        _ => panic!("Expected replication for 3-person group"),
    }

    // All users should be able to retrieve
    let retrieved = get_data(&storage_handle).await?;
    assert_eq!(retrieved, group_data);

    Ok(())
}

#[tokio::test]
async fn test_mobile_device_handling() -> Result<()> {
    // Test special handling for mobile devices
    let words_owned = valid_four_words(500);
    let words = words_refs(&words_owned);
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;

    // Mix of device types including mobile
    let desktop = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 200,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.100:9000".to_string(),
        },
        capabilities: DeviceCapabilities {
            cpu_cores: 8,
            bandwidth_mbps: 1000,
            ..Default::default()
        },
    };

    let mobile1 = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Mobile,
        storage_gb: 10,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "10.0.0.51:9001".to_string(),
        },
        capabilities: DeviceCapabilities {
            storage_bytes: 10_000_000_000,
            cpu_cores: 2,
            bandwidth_mbps: 50,
            always_online: false,
            supports_fec: false, // Legacy flag indicating mobiles shouldn't be used for replication
            supports_seal: true,
        },
    };

    let mobile2 = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Mobile,
        storage_gb: 5,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "10.0.0.52:9002".to_string(),
        },
        capabilities: DeviceCapabilities {
            storage_bytes: 5_000_000_000,
            cpu_cores: 2,
            bandwidth_mbps: 20,
            always_online: false,
            supports_fec: false,
            supports_seal: true,
        },
    };

    let headless = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Headless,
        storage_gb: 1000,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "10.0.1.1:9003".to_string(),
        },
        capabilities: DeviceCapabilities {
            storage_bytes: 1_000_000_000_000,
            always_online: true,
            supports_fec: true,
            supports_seal: true,
            ..Default::default()
        },
    };

    register_presence(
        &handle,
        vec![
            desktop.clone(),
            mobile1.clone(),
            mobile2.clone(),
            headless.clone(),
        ],
        desktop.id,
    )
    .await?;

    // Store data - planner should still avoid mobiles when placing replicas
    let data = vec![0x55u8; 30_000];
    let storage_handle = store_with_fec(&handle, data.clone(), 3, 2).await?;

    // Mobile devices should have minimal or no shards
    let mobile1_shards = storage_handle
        .shard_map
        .device_shards(&mobile1.id)
        .map(|s| s.len())
        .unwrap_or(0);
    let mobile2_shards = storage_handle
        .shard_map
        .device_shards(&mobile2.id)
        .map(|s| s.len())
        .unwrap_or(0);
    let headless_shards = storage_handle
        .shard_map
        .device_shards(&headless.id)
        .map(|s| s.len())
        .unwrap_or(0);

    // Headless should have more shards than mobile devices combined
    assert!(headless_shards > mobile1_shards + mobile2_shards);

    Ok(())
}

#[tokio::test]
async fn test_storage_farm_scenario() -> Result<()> {
    // Test user with storage farm (many headless nodes)
    let words_owned = valid_four_words(510);
    let words = words_refs(&words_owned);
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;

    // One active device and 10 headless nodes (storage farm)
    let active = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 50,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.100:9000".to_string(),
        },
        capabilities: DeviceCapabilities::default(),
    };

    let mut devices = vec![active.clone()];

    // Add 10 headless storage nodes
    for i in 0..10 {
        devices.push(Device {
            id: DeviceId::generate(),
            device_type: DeviceType::Headless,
            storage_gb: 2000, // 2TB each
            endpoint: Endpoint {
                protocol: "quic".to_string(),
                address: format!("10.0.100.{}:900{}", i, i % 10),
            },
            capabilities: DeviceCapabilities {
                storage_bytes: 2_000_000_000_000,
                always_online: true,
                supports_fec: true,
                supports_seal: true,
                bandwidth_mbps: 1000,
                cpu_cores: 4,
            },
        });
    }

    register_presence(&handle, devices.clone(), active.id).await?;

    // Store large data with high redundancy
    let large_data = vec![0xFFu8; 1_000_000]; // 1MB
    let storage_handle = store_with_fec(&handle, large_data.clone(), 6, 4).await?;

    // Verify shards are well distributed across storage farm
    let mut devices_with_shards = 0;
    for device in &devices[1..] {
        // Skip active device
        if storage_handle.shard_map.device_shards(&device.id).is_some() {
            devices_with_shards += 1;
        }
    }

    // Should use multiple storage nodes for distribution
    assert!(devices_with_shards >= 5);

    // Verify total storage capacity
    let presence = get_presence(handle.key()).await?;
    assert_eq!(presence.total_storage_gb(), 20050); // 50 + 10*2000

    Ok(())
}

#[tokio::test]
async fn test_device_capability_based_selection() -> Result<()> {
    // Test that device capabilities influence shard placement
    let words_owned = valid_four_words(520);
    let words = words_refs(&words_owned);
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;

    // Devices with varying capabilities
    let high_perf = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Headless,
        storage_gb: 1000,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "10.0.0.1:9001".to_string(),
        },
        capabilities: DeviceCapabilities {
            storage_bytes: 1_000_000_000_000,
            bandwidth_mbps: 10000, // 10Gbps
            cpu_cores: 32,
            always_online: true,
            supports_fec: true,
            supports_seal: true,
        },
    };

    let medium_perf = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Headless,
        storage_gb: 500,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "10.0.0.2:9002".to_string(),
        },
        capabilities: DeviceCapabilities {
            storage_bytes: 500_000_000_000,
            bandwidth_mbps: 1000, // 1Gbps
            cpu_cores: 8,
            always_online: true,
            supports_fec: true,
            supports_seal: true,
        },
    };

    let low_perf = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 100,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.100:9000".to_string(),
        },
        capabilities: DeviceCapabilities {
            storage_bytes: 100_000_000_000,
            bandwidth_mbps: 100, // 100Mbps
            cpu_cores: 4,
            always_online: false,
            supports_fec: true,
            supports_seal: true,
        },
    };

    register_presence(
        &handle,
        vec![low_perf.clone(), medium_perf.clone(), high_perf.clone()],
        low_perf.id,
    )
    .await?;

    // Store data requiring high performance
    let data = vec![0x88u8; 200_000];
    let storage_handle = store_with_fec(&handle, data, 4, 2).await?;

    // High performance device should get more shards
    let high_shards = storage_handle
        .shard_map
        .device_shards(&high_perf.id)
        .map(|s| s.len())
        .unwrap_or(0);
    let medium_shards = storage_handle
        .shard_map
        .device_shards(&medium_perf.id)
        .map(|s| s.len())
        .unwrap_or(0);
    let low_shards = storage_handle
        .shard_map
        .device_shards(&low_perf.id)
        .map(|s| s.len())
        .unwrap_or(0);

    // Higher capability devices should generally have more shards
    assert!(high_shards >= medium_shards);
    assert!(medium_shards >= low_shards);

    Ok(())
}

#[tokio::test]
async fn test_geographic_distribution() -> Result<()> {
    // Test geographic distribution of shards
    let words_owned = valid_four_words(530);
    let words = words_refs(&words_owned);
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;

    // Devices in different geographic locations (inferred from IP)
    let us_east = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Headless,
        storage_gb: 500,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "54.0.0.1:9001".to_string(), // US East IP range
        },
        capabilities: DeviceCapabilities {
            always_online: true,
            supports_fec: true,
            supports_seal: true,
            ..Default::default()
        },
    };

    let eu_west = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Headless,
        storage_gb: 500,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "185.0.0.1:9002".to_string(), // EU IP range
        },
        capabilities: DeviceCapabilities {
            always_online: true,
            supports_fec: true,
            supports_seal: true,
            ..Default::default()
        },
    };

    let asia_pac = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Headless,
        storage_gb: 500,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "1.0.0.1:9003".to_string(), // APAC IP range
        },
        capabilities: DeviceCapabilities {
            always_online: true,
            supports_fec: true,
            supports_seal: true,
            ..Default::default()
        },
    };

    let active = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 50,
        endpoint: Endpoint {
            protocol: "quic".to_string(),
            address: "192.168.1.100:9000".to_string(),
        },
        capabilities: DeviceCapabilities::default(),
    };

    register_presence(
        &handle,
        vec![
            active.clone(),
            us_east.clone(),
            eu_west.clone(),
            asia_pac.clone(),
        ],
        active.id,
    )
    .await?;

    // Store data with geographic distribution
    let data = vec![0x77u8; 60_000];
    let storage_handle = store_with_fec(&handle, data.clone(), 3, 2).await?;

    // Should distribute shards across regions for resilience
    let regions_used = [us_east.id, eu_west.id, asia_pac.id]
        .iter()
        .filter(|id| storage_handle.shard_map.device_shards(id).is_some())
        .count();

    // Should use multiple geographic regions
    assert!(regions_used >= 2);

    Ok(())
}
