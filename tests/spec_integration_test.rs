// Copyright 2024 Saorsa Labs Limited
//
// Integration tests for the saorsa-core spec implementation

use anyhow::Result;
use saorsa_core::{
    api::*,
    auth::*,
    events::*,
    fwid::*,
    telemetry::*,
};
use saorsa_core::events;
use std::sync::Arc;
use std::time::Duration;
use bytes::Bytes;

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
    
    // Test FourWordsV1 structure
    let fw = FourWordsV1::from_words(valid_words)?;
    let indices = fw.indices();
    assert_eq!(indices.len(), 4);
    
    // Test to_words (even though it's placeholder)
    let _ = fw.to_words()?;
    
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
    
    assert!(single_auth.verify(record, &[sig.clone()]).await?);
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
    
    assert!(delegated.verify(record, &[sig.clone()]).await?);
    assert_eq!(delegated.auth_type(), "delegated");
    
    // Test MlsWriteAuth
    let mls_auth = MlsWriteAuth::new(vec![1, 2, 3], 42);
    assert!(mls_auth.verify(record, &[sig.clone()]).await?);
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
    assert!(!threshold.verify(record, &[sig.clone()]).await?);
    
    assert_eq!(threshold.auth_type(), "threshold");
    
    // Test invalid threshold creation
    let result = ThresholdWriteAuth::new(5, 3, vec![PubKey::new(vec![1])]);
    assert!(result.is_err()); // threshold > total
    
    // Test CompositeWriteAuth (all mode)
    let auth1: Box<dyn WriteAuth> = Box::new(SingleWriteAuth::new(pub_key.clone()));
    let auth2: Box<dyn WriteAuth> = Box::new(SingleWriteAuth::new(pub_key.clone()));
    
    let composite_all = CompositeWriteAuth::all(vec![auth1, auth2]);
    assert!(composite_all.verify(record, &[sig.clone()]).await?);
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
    
    bus.publish_dht_update(key1.clone(), bytes::Bytes::from(value1.clone())).await?;
    bus.publish_dht_update(key2.clone(), bytes::Bytes::from(value2.clone())).await?;
    
    assert_eq!(dht_sub1.recv().await?, bytes::Bytes::from(value1));
    assert_eq!(dht_sub2.recv().await?, bytes::Bytes::from(value2));
    
    // Test forward events
    let identity_key = Key::new([99u8; 32]);
    let mut forward_sub = bus.subscribe_forwards(identity_key.clone()).await;
    
    let forward_event = ForwardEvent {
        identity_key: identity_key.clone(),
        protocol: "quic".to_string(),
        address: "example.com:9000".to_string(),
        expiry: 1234567890,
    };
    
    bus.publish_forward(forward_event.clone()).await?;
    
    let received_forward = forward_sub.recv().await?;
    assert_eq!(received_forward.protocol, "quic");
    assert_eq!(received_forward.expiry, 1234567890);
    
    // Test cleanup
    drop(dht_sub1);
    drop(dht_sub2);
    drop(forward_sub);
    
    bus.cleanup_expired().await;
    
    // After cleanup, publishing should not panic
    bus.publish_dht_update(key1, bytes::Bytes::from(vec![70, 80, 90])).await?;
    
    Ok(())
}

/// Test telemetry collection and metrics
#[tokio::test]
async fn test_telemetry_comprehensive() -> Result<()> {
    let collector = TelemetryCollector::new();
    
    // Record various lookup operations
    for i in 0..10 {
        let latency = Duration::from_millis(10 * (i + 1));
        let hops = (i % 5 + 1) as u8;
        collector.record_lookup(latency, hops).await;
    }
    
    // Record some timeouts
    for _ in 0..3 {
        collector.record_timeout();
    }
    
    // Record DHT operations
    for _ in 0..5 {
        collector.record_dht_put();
    }
    for _ in 0..8 {
        collector.record_dht_get();
    }
    
    // Record auth failures
    for _ in 0..2 {
        collector.record_auth_failure();
    }
    
    // Record stream metrics - need more samples for percentile calculation
    collector.record_stream_bandwidth(StreamClass::Media, 1_000_000).await;
    collector.record_stream_bandwidth(StreamClass::Media, 1_500_000).await;
    collector.record_stream_bandwidth(StreamClass::Media, 2_000_000).await;
    collector.record_stream_bandwidth(StreamClass::Media, 2_500_000).await;
    collector.record_stream_bandwidth(StreamClass::Media, 3_000_000).await;
    collector.record_stream_bandwidth(StreamClass::Control, 50_000).await;
    
    collector.record_stream_rtt(StreamClass::Media, Duration::from_millis(20)).await;
    collector.record_stream_rtt(StreamClass::Media, Duration::from_millis(30)).await;
    collector.record_stream_rtt(StreamClass::Control, Duration::from_millis(5)).await;
    
    // Get and verify metrics
    let metrics = collector.get_metrics().await;
    assert!(metrics.lookups_p95_ms > 0);
    assert!(metrics.hop_p95 > 0);
    assert!(metrics.timeout_rate > 0.0);
    assert!(metrics.timeout_rate < 0.5); // Should be ~23% (3/13)
    
    // Get and verify counters
    let counters = collector.get_counters();
    assert_eq!(counters.dht_puts, 5);
    assert_eq!(counters.dht_gets, 8);
    assert_eq!(counters.auth_failures, 2);
    
    // Get stream metrics
    let media_metrics = collector.get_stream_metrics(StreamClass::Media).await.unwrap();
    assert!(media_metrics.bandwidth_p50 > 0);
    assert!(media_metrics.bandwidth_p95 > media_metrics.bandwidth_p50);
    assert!(media_metrics.rtt_p50_ms > 0);
    
    let control_metrics = collector.get_stream_metrics(StreamClass::Control).await.unwrap();
    assert_eq!(control_metrics.bandwidth_p50, 50_000);
    assert_eq!(control_metrics.rtt_p50_ms, 5);
    
    // Test health monitor - create a new collector for fresh stats
    let collector_for_health = Arc::new(TelemetryCollector::new());
    // Record some healthy operations (low latency, few timeouts)
    for i in 0..10 {
        collector_for_health.record_lookup(Duration::from_millis(10 + i), 3).await;
    }
    // Only 1 timeout out of 11 operations = ~9% timeout rate (< 10% threshold)
    collector_for_health.record_timeout();
    
    let health_monitor = HealthMonitor::new(collector_for_health.clone());
    let status = health_monitor.get_status().await;
    
    assert!(status.healthy); // Should be healthy with these metrics
    assert!(status.uptime.as_secs() < 1); // Just started
    
    // Check original collector's counters
    assert_eq!(counters.dht_puts, 5);
    
    // Test reset
    let collector2 = TelemetryCollector::new();
    collector2.record_lookup(Duration::from_secs(1), 5).await;
    collector2.reset().await;
    
    let metrics2 = collector2.get_metrics().await;
    assert_eq!(metrics2.lookups_p95_ms, 0);
    assert_eq!(metrics2.timeout_rate, 0.0);
    
    Ok(())
}

/// Test the global instances work correctly
#[tokio::test]
async fn test_global_instances() -> Result<()> {
    // Test global telemetry
    record_lookup(Duration::from_millis(50), 3).await;
    record_timeout();
    
    let global_telemetry = telemetry();
    let metrics = global_telemetry.get_metrics().await;
    assert!(metrics.lookups_p95_ms > 0 || metrics.timeout_rate > 0.0);
    
    // Test global event bus
    let mut sub = subscribe_topology();
    
    let event = TopologyEvent::RoutingTableUpdated {
        added: vec![vec![1, 2]],
        removed: vec![vec![3, 4]],
    };
    
    global_bus().publish_topology(event).await?;
    
    let received = sub.recv().await?;
    assert!(matches!(received, TopologyEvent::RoutingTableUpdated { .. }));
    
    // Test DHT watch helper
    let key = Key::new([42u8; 32]);
    let mut dht_sub = events::dht_watch(key.clone()).await;
    
    global_bus().publish_dht_update(key, bytes::Bytes::from(vec![100, 200])).await?;
    assert_eq!(dht_sub.recv().await?, bytes::Bytes::from(vec![100, 200]));
    
    // Test device subscribe helper
    let identity_key = Key::new([88u8; 32]);
    let mut device_sub = events::device_subscribe(identity_key.clone()).await;
    
    let forward = ForwardEvent {
        identity_key,
        protocol: "tcp".to_string(),
        address: "localhost:3000".to_string(),
        expiry: 9999999999,
    };
    
    global_bus().publish_forward(forward.clone()).await?;
    
    let received = device_sub.recv().await?;
    assert_eq!(received.protocol, "tcp");
    
    Ok(())
}

/// Test API module functions
#[tokio::test]
async fn test_api_functions() -> Result<()> {
    // Test identity claim - using same words that pass in fwid test
    let words = ["hello".to_string(), "world".to_string(), "test".to_string(), "data".to_string()];
    let pubkey = PubKey::new(vec![1, 2, 3]);
    let sig = Sig::new(vec![4, 5, 6]);
    
    identity_claim(words.clone(), pubkey, sig).await?;
    
    // Test identity fetch
    let key = Key::new([7u8; 32]);
    let packet = identity_fetch(key.clone()).await?;
    assert_eq!(packet.v, 1);
    assert_eq!(packet.device_set_root, key);
    
    // Test device forward publishing
    let forward = Forward {
        proto: "quic".to_string(),
        addr: "192.168.1.1:9000".to_string(),
        exp: 1234567890,
    };
    
    device_publish_forward(key.clone(), forward).await?;
    
    // Test DHT operations
    let dht_key = Key::new([8u8; 32]);
    let data = Bytes::from("test data");
    let policy = PutPolicy {
        quorum: 3,
        ttl: Some(Duration::from_secs(3600)),
        auth: Box::new(SingleWriteAuth::new(PubKey::new(vec![9]))),
    };
    
    let receipt = dht_put(dht_key.clone(), data, &policy).await?;
    assert_eq!(receipt.key, dht_key);
    assert!(receipt.timestamp > 0);
    
    let _retrieved = dht_get(dht_key.clone(), 3).await?;
    
    // Test routing functions
    let peer = vec![10, 11, 12];
    record_interaction(peer.clone(), Outcome::Ok).await?;
    record_interaction(peer.clone(), Outcome::Timeout).await?;
    
    eigen_trust_epoch().await?;
    
    let next_hop = route_next_hop(vec![13, 14, 15]);
    assert!(next_hop.is_none()); // Placeholder returns None
    
    // Test transport functions
    let endpoint = Endpoint {
        address: "example.com:9000".to_string(),
    };
    
    let conn = quic_connect(&endpoint).await?;
    assert_eq!(conn.peer, vec![0u8; 0]);
    
    let stream = quic_open(&conn, StreamClass::Control).await?;
    assert_eq!(stream.class, StreamClass::Control);
    
    // Test storage control
    let object_id = [15u8; 32];
    let shards = place_shards(object_id, 8);
    assert_eq!(shards.len(), 0); // Placeholder returns empty
    
    provider_advertise_space(1000000, 2000000);
    
    let repair_plan = repair_request(object_id);
    assert_eq!(repair_plan.object_id, object_id);
    assert_eq!(repair_plan.missing_shards.len(), 0);
    
    Ok(())
}

/// Test data structure serialization
#[tokio::test]
async fn test_data_structures() -> Result<()> {
    use serde_json;
    
    // Test IdentityPacketV1
    let identity = IdentityPacketV1 {
        v: 1,
        w: [100, 200, 300, 400],
        pk: vec![1, 2, 3],
        sig: vec![4, 5, 6],
        addrs: [("btc".to_string(), Some("bc1q...".to_string()))].into_iter().collect(),
        website_root: Some(Key::new([10u8; 32])),
        device_set_root: Key::new([11u8; 32]),
    };
    
    let json = serde_json::to_string(&identity)?;
    let recovered: IdentityPacketV1 = serde_json::from_str(&json)?;
    assert_eq!(recovered.v, 1);
    assert_eq!(recovered.w, [100, 200, 300, 400]);
    
    // Test DeviceSetV1
    let device_set = DeviceSetV1 {
        v: 1,
        crdt: "or-set".to_string(),
        forwards: vec![
            Forward {
                proto: "quic".to_string(),
                addr: "192.168.1.1:9000".to_string(),
                exp: 1234567890,
            },
        ],
    };
    
    let json = serde_json::to_string(&device_set)?;
    let recovered: DeviceSetV1 = serde_json::from_str(&json)?;
    assert_eq!(recovered.crdt, "or-set");
    assert_eq!(recovered.forwards.len(), 1);
    
    // Test GroupPacketV1
    let group = GroupPacketV1 {
        v: 1,
        group_id: vec![20, 21, 22],
        epoch: 42,
        membership: Key::new([30u8; 32]),
        forwards_root: Key::new([31u8; 32]),
        container_root: Key::new([32u8; 32]),
    };
    
    let json = serde_json::to_string(&group)?;
    let recovered: GroupPacketV1 = serde_json::from_str(&json)?;
    assert_eq!(recovered.epoch, 42);
    
    // Test ContainerManifestV1
    let manifest = ContainerManifestV1 {
        v: 1,
        object: Key::new([40u8; 32]),
        fec: FecParams {
            k: 8,
            m: 4,
            shard_size: 65536,
        },
        assets: vec![Key::new([41u8; 32]), Key::new([42u8; 32])],
        sealed_meta: None,
    };
    
    let json = serde_json::to_string(&manifest)?;
    let recovered: ContainerManifestV1 = serde_json::from_str(&json)?;
    assert_eq!(recovered.fec.k, 8);
    assert_eq!(recovered.fec.m, 4);
    assert_eq!(recovered.assets.len(), 2);
    
    Ok(())
}

/// Integration test combining multiple modules
#[tokio::test]
async fn test_multi_module_integration() -> Result<()> {
    // Create an identity with valid four words (same as fwid test)
    let words = ["hello".to_string(), "world".to_string(), "test".to_string(), "data".to_string()];
    let identity_key = fw_to_key(words.clone())?;
    
    // Set up authentication
    let alice_pubkey = PubKey::new(vec![1, 2, 3]);
    let auth = SingleWriteAuth::new(alice_pubkey.clone());
    
    // Subscribe to events for this identity
    let mut device_sub = events::device_subscribe(identity_key.clone()).await;
    
    // Publish a forward
    let forward = Forward {
        proto: "quic".to_string(),
        addr: "alice.example.com:9000".to_string(),
        exp: chrono::Utc::now().timestamp() as u64 + 3600,
    };
    
    device_publish_forward(identity_key.clone(), forward.clone()).await?;
    
    // Receive the event
    let event = device_sub.recv().await?;
    assert_eq!(event.identity_key, identity_key);
    assert_eq!(event.protocol, "quic");
    
    // Record telemetry for the operation
    record_lookup(Duration::from_millis(25), 3).await;
    
    // Store data in DHT with authentication
    let dht_key = compute_key("alice-data", identity_key.as_bytes());
    let data = Bytes::from("Alice's encrypted data");
    let policy = PutPolicy {
        quorum: 3,
        ttl: Some(Duration::from_secs(7200)),
        auth: Box::new(auth),
    };
    
    let _receipt = dht_put(dht_key.clone(), data.clone(), &policy).await?;
    
    // Watch for DHT updates
    let mut dht_sub = events::dht_watch(dht_key.clone()).await;
    
    // Publish an update
    global_bus().publish_dht_update(dht_key.clone(), bytes::Bytes::from("Updated data")).await?;
    
    let update = dht_sub.recv().await?;
    assert_eq!(update.as_ref(), b"Updated data");
    
    // Check telemetry
    let metrics = telemetry().get_metrics().await;
    assert!(metrics.lookups_p95_ms > 0);
    
    // Subscribe to topology events before publishing
    let mut topology_sub = subscribe_topology();
    
    // Simulate topology change
    global_bus().publish_topology(TopologyEvent::PeerJoined {
        peer_id: alice_pubkey.as_bytes().to_vec(),
        address: event.address.clone(),
    }).await?;
    
    // Verify we receive the event
    let topology_event = topology_sub.recv().await?;
    assert!(matches!(topology_event, TopologyEvent::PeerJoined { .. }));
    
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
    
    Ok(())
}