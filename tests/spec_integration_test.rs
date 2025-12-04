// Copyright 2024 Saorsa Labs Limited
//
// Integration tests for the saorsa-core spec implementation

#![cfg(feature = "test-utils")]

use anyhow::Result;
use bytes::Bytes;
use saorsa_core::api::{GroupIdentityPacketV1, IdentityPacketV1, MemberRef};
use saorsa_core::auth::{
    CompositeWriteAuth, DelegatedWriteAuth, MlsWriteAuth, PubKey, Sig, SingleWriteAuth,
    ThresholdWriteAuth, WriteAuth,
};
use saorsa_core::dht::{Outcome, PutPolicy, eigen_trust_epoch, record_interaction};
use saorsa_core::events::{self, EventBus, TopologyEvent, global_bus, subscribe_topology};
use saorsa_core::fwid::{FourWordsV1, Key, compute_key, fw_check, fw_to_key};
use saorsa_core::identity::node_identity::NodeId;
use saorsa_core::mock_dht::mock_ops;
use saorsa_core::telemetry::{record_lookup, telemetry};
use saorsa_core::types::storage::StorageStrategy;
use saorsa_core::types::{
    Device, DeviceId, Endpoint, Forward, Identity, IdentityHandle, MlDsaKeyPair,
    presence::DeviceType,
};
use saorsa_core::virtual_disk::{ContainerManifestV1, FecParams};
use saorsa_core::{
    get_data, get_identity, get_presence, register_identity, register_presence, store_data,
    store_dyad, store_with_fec,
};
use std::time::Duration;

/// Test the complete four-word identifier system
#[tokio::test]
async fn test_fwid_complete_flow() -> Result<()> {
    // Test word validation
    let valid_words = [
        "hello".to_string(),
        "world".to_string(),
        "test".to_string(),
        "data".to_string(),
    ];

    assert!(fw_check(valid_words.clone()));

    // Test key generation is deterministic
    let key1 = fw_to_key(valid_words.clone())?;
    let key2 = fw_to_key(valid_words.clone())?;
    assert_eq!(key1, key2);

    // Test FourWordsV1 structure (indices-based constructor)
    let fw = FourWordsV1::new([1, 2, 3, 4]);
    let indices = fw.indices();
    assert_eq!(indices.len(), 4);

    // Test key serialization
    let hex = key1.to_hex();
    assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars

    let recovered = Key::from_hex(&hex)?;
    assert_eq!(key1, recovered);

    // Test compute_key function
    let context_key = compute_key("test-context", b"test-content");
    assert_ne!(context_key, key1); // Should be different

    Ok(())
}

/// Test all authentication methods
#[tokio::test]
async fn test_auth_comprehensive() -> Result<()> {
    let record = b"test record data";

    // Test SingleWriteAuth
    let pub_key = PubKey::new(vec![1, 2, 3, 4, 5]);
    let single_auth = SingleWriteAuth::new(pub_key.clone());
    let sig = Sig::new(vec![10, 11, 12]);

    assert!(
        single_auth
            .verify(record, std::slice::from_ref(&sig))
            .await?
    );
    assert_eq!(single_auth.auth_type(), "single");

    // Empty signatures should fail
    assert!(!single_auth.verify(record, &[]).await?);

    // Test DelegatedWriteAuth
    let key1 = PubKey::new(vec![1]);
    let key2 = PubKey::new(vec![2]);
    let key3 = PubKey::new(vec![3]);

    let mut delegated = DelegatedWriteAuth::new(vec![key1.clone(), key2.clone()]);
    delegated.add_key(key3.clone());
    delegated.add_key(key3.clone()); // Duplicate should not be added twice

    assert!(delegated.verify(record, std::slice::from_ref(&sig)).await?);
    assert_eq!(delegated.auth_type(), "delegated");

    // Test MlsWriteAuth
    let mls_auth = MlsWriteAuth::new(vec![1, 2, 3], 42);
    assert!(mls_auth.verify(record, std::slice::from_ref(&sig)).await?);
    assert_eq!(mls_auth.auth_type(), "mls");

    // Test ThresholdWriteAuth
    let threshold_keys = vec![
        PubKey::new(vec![10]),
        PubKey::new(vec![20]),
        PubKey::new(vec![30]),
        PubKey::new(vec![40]),
    ];

    let threshold = ThresholdWriteAuth::new(2, 4, threshold_keys)?;

    // Should pass with 2 signatures (threshold)
    let sigs = vec![Sig::new(vec![1]), Sig::new(vec![2])];
    assert!(threshold.verify(record, &sigs).await?);

    // Should fail with 1 signature (below threshold)
    assert!(!threshold.verify(record, std::slice::from_ref(&sig)).await?);

    assert_eq!(threshold.auth_type(), "threshold");

    // Test invalid threshold creation
    let result = ThresholdWriteAuth::new(5, 3, vec![PubKey::new(vec![1])]);
    assert!(result.is_err()); // threshold > total

    // Test CompositeWriteAuth (all mode)
    let auth1: Box<dyn WriteAuth> = Box::new(SingleWriteAuth::new(pub_key.clone()));
    let auth2: Box<dyn WriteAuth> = Box::new(SingleWriteAuth::new(pub_key.clone()));

    let composite_all = CompositeWriteAuth::all(vec![auth1, auth2]);
    assert!(
        composite_all
            .verify(record, std::slice::from_ref(&sig))
            .await?
    );
    assert_eq!(composite_all.auth_type(), "composite_all");

    // Test CompositeWriteAuth (any mode)
    let auth3: Box<dyn WriteAuth> = Box::new(SingleWriteAuth::new(pub_key));
    let auth4: Box<dyn WriteAuth> = Box::new(MlsWriteAuth::new(vec![5], 10));

    let composite_any = CompositeWriteAuth::any(vec![auth3, auth4]);
    assert!(composite_any.verify(record, &[sig]).await?);
    assert_eq!(composite_any.auth_type(), "composite_any");

    Ok(())
}

/// Test the event bus publish/subscribe system
#[tokio::test]
async fn test_events_pubsub_system() -> Result<()> {
    // Create a new event bus (not using global for isolation)
    let bus = EventBus::new();

    // Test topology events
    let mut topology_sub = bus.subscribe_topology();

    let join_event = TopologyEvent::PeerJoined {
        peer_id: vec![1, 2, 3],
        address: "192.168.1.100:8080".to_string(),
    };

    bus.publish_topology(join_event.clone()).await?;

    let received = topology_sub.recv().await?;
    match received {
        TopologyEvent::PeerJoined { peer_id, address } => {
            assert_eq!(peer_id, vec![1, 2, 3]);
            assert_eq!(address, "192.168.1.100:8080");
        }
        _ => panic!("Wrong event type"),
    }

    // Test multiple event types
    let leave_event = TopologyEvent::PeerLeft {
        peer_id: vec![1, 2, 3],
        reason: "timeout".to_string(),
    };

    let partition_event = TopologyEvent::PartitionDetected {
        partition_id: 123,
        affected_peers: vec![vec![4, 5], vec![6, 7]],
    };

    bus.publish_topology(leave_event).await?;
    bus.publish_topology(partition_event).await?;

    // Should receive in order
    let event2 = topology_sub.recv().await?;
    assert!(matches!(event2, TopologyEvent::PeerLeft { .. }));

    let event3 = topology_sub.recv().await?;
    assert!(matches!(event3, TopologyEvent::PartitionDetected { .. }));

    // Test DHT watch events
    let key1 = Key::new([1u8; 32]);
    let key2 = Key::new([2u8; 32]);

    let mut dht_sub1 = bus.subscribe_dht_key(key1.clone()).await;
    let mut dht_sub2 = bus.subscribe_dht_key(key2.clone()).await;

    let value1 = vec![10, 20, 30];
    let value2 = vec![40, 50, 60];

    bus.publish_dht_update(key1.clone(), bytes::Bytes::from(value1.clone()))
        .await?;
    bus.publish_dht_update(key2.clone(), bytes::Bytes::from(value2.clone()))
        .await?;

    assert_eq!(dht_sub1.recv().await?, bytes::Bytes::from(value1));
    assert_eq!(dht_sub2.recv().await?, bytes::Bytes::from(value2));

    // Test forward events
    let identity_key = Key::new([99u8; 32]);
    let mut forward_sub = bus.subscribe_forwards(identity_key.clone()).await;

    let forward = Forward {
        proto: "quic".into(),
        addr: "example.com:9000".into(),
        exp: 1234567890,
    };

    bus.publish_forward_for(identity_key.clone(), forward.clone())
        .await?;

    let received_forward = forward_sub.recv().await?;
    assert_eq!(received_forward.proto, "quic");
    assert_eq!(received_forward.exp, 1234567890);

    // Test cleanup
    drop(dht_sub1);
    drop(dht_sub2);
    drop(forward_sub);

    bus.cleanup_expired().await;

    // After cleanup, publishing should not panic
    bus.publish_dht_update(key1, bytes::Bytes::from(vec![70, 80, 90]))
        .await?;

    Ok(())
}

/// Test the global topology bus delivers events
#[tokio::test]
async fn test_global_topology_bus() -> Result<()> {
    let mut sub = subscribe_topology();

    let event = TopologyEvent::RoutingTableUpdated {
        added: vec![vec![1, 2]],
        removed: vec![vec![3, 4]],
    };

    global_bus().publish_topology(event).await?;

    let received = sub.recv().await?;
    assert!(matches!(
        received,
        TopologyEvent::RoutingTableUpdated { .. }
    ));

    Ok(())
}
/// Test API module functions
#[tokio::test]
async fn test_api_functions() -> Result<()> {
    // Register a new identity and fetch it back through the API
    let words = ["hello", "world", "test", "data"];
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words, &keypair).await?;

    let identity = get_identity(handle.key()).await?;
    let expected_words: [String; 4] = words.map(|w| w.to_string());
    assert_eq!(identity.words, expected_words);

    // Register multi-device presence
    let devices = vec![
        Device {
            id: DeviceId::generate(),
            device_type: DeviceType::Active,
            storage_gb: 128,
            endpoint: Endpoint {
                protocol: "quic".into(),
                address: "127.0.0.1:9000".into(),
            },
            capabilities: Default::default(),
        },
        Device {
            id: DeviceId::generate(),
            device_type: DeviceType::Headless,
            storage_gb: 512,
            endpoint: Endpoint {
                protocol: "quic".into(),
                address: "10.0.0.2:9000".into(),
            },
            capabilities: Default::default(),
        },
    ];

    let active_device = devices[0].id;
    let receipt = register_presence(&handle, devices.clone(), active_device).await?;
    assert_eq!(receipt.identity, handle.key());

    let presence = get_presence(handle.key()).await?;
    assert_eq!(presence.devices.len(), devices.len());
    assert_eq!(presence.active_device, Some(active_device));

    // Exercise storage helpers
    let direct_data = b"direct data".to_vec();
    let direct_handle = store_data(&handle, direct_data.clone(), 1).await?;
    let roundtrip_direct = get_data(&direct_handle).await?;
    assert_eq!(roundtrip_direct, direct_data);

    let dyad_data = b"dyad data".to_vec();
    let dyad_handle = store_dyad(&handle, handle.key(), dyad_data.clone()).await?;
    let roundtrip_dyad = get_data(&dyad_handle).await?;
    assert_eq!(roundtrip_dyad, dyad_data);

    let fec_data = b"fec data".to_vec();
    let fec_handle = store_with_fec(&handle, fec_data.clone(), 2, 1).await?;
    match fec_handle.strategy {
        StorageStrategy::FecEncoded {
            data_shards,
            parity_shards,
            ..
        } => {
            assert_eq!(data_shards, 2);
            assert_eq!(parity_shards, 1);
        }
        other => panic!("unexpected storage strategy: {:?}", other),
    }

    let roundtrip_fec = get_data(&fec_handle).await?;
    assert_eq!(roundtrip_fec, fec_data);

    Ok(())
}

/// Test data structure serialization
#[tokio::test]
async fn test_data_structures() -> Result<()> {
    use serde_json;

    // Test IdentityPacketV1 (align with current API)
    let identity = IdentityPacketV1 {
        v: 1,
        words: ["a".into(), "b".into(), "c".into(), "d".into()],
        id: Key::new([9u8; 32]),
        pk: vec![1, 2, 3],
        sig: Some(vec![4, 5, 6]),
        device_set_root: compute_key("device-set", &[1, 2, 3]),
    };

    let json = serde_json::to_string(&identity)?;
    let recovered: IdentityPacketV1 = serde_json::from_str(&json)?;
    assert_eq!(recovered.v, 1);
    assert_eq!(recovered.words.len(), 4);
    assert_eq!(recovered.sig.as_ref().unwrap(), &[4, 5, 6]);

    // Test GroupIdentityPacketV1
    let group_packet = GroupIdentityPacketV1 {
        v: 1,
        words: [
            "alpha".into(),
            "beta".into(),
            "gamma".into(),
            "delta".into(),
        ],
        id: Key::new([20u8; 32]),
        group_pk: vec![7, 7, 7],
        group_sig: vec![8, 8, 8],
        members: vec![
            MemberRef {
                member_id: Key::new([21u8; 32]),
                member_pk: vec![1, 1, 1],
            },
            MemberRef {
                member_id: Key::new([22u8; 32]),
                member_pk: vec![2, 2, 2],
            },
        ],
        membership_root: Key::new([23u8; 32]),
        created_at: 1_700_000_000,
        mls_ciphersuite: Some(0x0a0a),
    };

    let json = serde_json::to_string(&group_packet)?;
    let recovered: GroupIdentityPacketV1 = serde_json::from_str(&json)?;
    assert_eq!(recovered.members.len(), 2);
    assert_eq!(recovered.membership_root, Key::new([23u8; 32]));

    // Test ContainerManifestV1
    let manifest = ContainerManifestV1 {
        v: 1,
        object: Key::new([40u8; 32]),
        fec: Some(FecParams {
            k: 8,
            m: 4,
            shard_size: 65536,
        }),
        assets: vec![Key::new([41u8; 32]), Key::new([42u8; 32])],
        sealed_meta: None,
    };

    let json = serde_json::to_string(&manifest)?;
    let recovered: ContainerManifestV1 = serde_json::from_str(&json)?;
    assert_eq!(recovered.fec.unwrap().k, 8);
    assert_eq!(recovered.assets.len(), 2);

    Ok(())
}

/// Integration test combining multiple modules
#[tokio::test]
async fn test_multi_module_integration() -> Result<()> {
    // Synthesize an identity handle without touching the persistent DHT
    let keypair = MlDsaKeyPair::generate()?;
    let identity = Identity {
        words: [
            "orchid".into(),
            "ember".into(),
            "lunar".into(),
            "pilot".into(),
        ],
        key: Key::new([42u8; 32]),
        public_key: keypair.public_key.clone(),
    };
    let handle = IdentityHandle::new(identity, keypair);
    let identity_key = handle.key();

    // Subscribe to forward announcements
    let mut device_sub = events::device_subscribe(identity_key.clone()).await;
    let forward = Forward {
        proto: "quic".into(),
        addr: "orchid.example.com:9000".into(),
        exp: 1_700_000_000,
    };

    global_bus()
        .publish_forward_for(identity_key.clone(), forward.clone())
        .await?;

    let forward_event = device_sub.recv().await?;
    assert_eq!(forward_event.addr, forward.addr);

    // Record telemetry for the operation and verify metrics aggregation
    record_lookup(Duration::from_millis(25), 3).await;

    // Store data in the mock DHT and read it back
    let dht_key = compute_key("orchid-data", identity_key.as_bytes());
    let payload = Bytes::from_static(b"orchid payload");
    let policy = PutPolicy {
        ttl: Some(Duration::from_secs(600)),
        quorum: 2,
    };
    mock_ops::dht_put(dht_key.clone(), payload.clone(), &policy).await?;
    let stored = mock_ops::dht_get(dht_key.clone(), 1).await?;
    assert_eq!(stored, payload);

    // Watch for updates on the DHT key via the event bus
    let mut dht_sub = events::dht_watch(dht_key.clone()).await;
    let update_payload = Bytes::from_static(b"updated payload");
    global_bus()
        .publish_dht_update(dht_key.clone(), update_payload.clone())
        .await?;
    let update = dht_sub.recv().await?;
    assert_eq!(update, update_payload);

    // Telemetry snapshot should include the lookup metrics
    let metrics = telemetry().get_metrics().await;
    assert!(metrics.lookups_p95_ms >= 25);

    // Simulate topology changes and verify delivery
    let mut topology_sub = subscribe_topology();
    global_bus()
        .publish_topology(TopologyEvent::PeerJoined {
            peer_id: identity_key.as_bytes().to_vec(),
            address: forward_event.addr.clone(),
        })
        .await?;
    assert!(matches!(
        topology_sub.recv().await?,
        TopologyEvent::PeerJoined { .. }
    ));

    // Trust recording stubs should be callable without panicking
    record_interaction(NodeId([5u8; 32]), Outcome::Ok).await;
    eigen_trust_epoch().await;

    Ok(())
}

/// Test error conditions and edge cases
#[tokio::test]
async fn test_error_conditions() -> Result<()> {
    // Test invalid hex key
    let result = Key::from_hex("invalid");
    assert!(result.is_err());

    // Test key with wrong length
    let result = Key::from_hex("abcd");
    assert!(result.is_err());

    // Test threshold auth with invalid parameters
    let result = ThresholdWriteAuth::new(5, 3, vec![PubKey::new(vec![1])]);
    assert!(result.is_err());

    let result = ThresholdWriteAuth::new(2, 3, vec![PubKey::new(vec![1]), PubKey::new(vec![2])]);
    assert!(result.is_err()); // Not enough keys

    // Test subscription error handling
    let bus = EventBus::new();
    let mut sub = bus.subscribe_topology();
    drop(bus); // Drop the bus

    // Should get an error when trying to receive
    let result = sub.recv().await;
    assert!(result.is_err());

    // register_presence should fail when active device is missing
    let keypair = MlDsaKeyPair::generate()?;
    let identity = Identity {
        words: [
            "ember".into(),
            "signal".into(),
            "polar".into(),
            "haze".into(),
        ],
        key: Key::new([99u8; 32]),
        public_key: keypair.public_key.clone(),
    };
    let handle = IdentityHandle::new(identity, keypair);
    let device = Device {
        id: DeviceId::generate(),
        device_type: DeviceType::Active,
        storage_gb: 64,
        endpoint: Endpoint {
            protocol: "quic".into(),
            address: "127.0.0.1:4000".into(),
        },
        capabilities: Default::default(),
    };

    let invalid_active = DeviceId::generate();
    let result = register_presence(&handle, vec![device], invalid_active).await;
    assert!(result.is_err());

    Ok(())
}
