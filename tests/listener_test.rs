// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Integration tests for the unified message listener system.

use async_trait::async_trait;
use bytes::Bytes;
use saorsa_core::listener::{
    IncomingMessage, MessageSource, Protocol, ProtocolBuilder, UnifiedListener,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::time::{Duration, timeout};

/// Test basic listener creation and subscription
#[tokio::test]
async fn test_listener_creation_and_subscription() {
    let listener = UnifiedListener::new();
    assert_eq!(listener.subscriber_count(), 0);

    let _rx1 = listener.subscribe();
    assert_eq!(listener.subscriber_count(), 1);

    let _rx2 = listener.subscribe();
    assert_eq!(listener.subscriber_count(), 2);
}

/// Test message injection and reception
#[tokio::test]
async fn test_message_injection() {
    let listener = UnifiedListener::new();
    let mut rx = listener.subscribe();

    // Inject a network message
    let msg = IncomingMessage::network(
        "peer123".to_string(),
        "chat/v1".to_string(),
        vec![1, 2, 3, 4],
    );
    listener.inject_message(msg).unwrap();

    // Receive and verify
    let received = timeout(Duration::from_millis(100), rx.recv())
        .await
        .expect("timeout")
        .expect("recv error");

    assert_eq!(received.peer_id, "peer123");
    assert_eq!(received.data(), &[1, 2, 3, 4]);
    assert!(matches!(
        received.source,
        MessageSource::Network { topic } if topic == "chat/v1"
    ));
}

/// Test message injector handle
#[tokio::test]
async fn test_message_injector() {
    let listener = UnifiedListener::new();
    let mut rx = listener.subscribe();
    let injector = listener.message_injector();

    // Inject via the injector handle
    injector
        .inject_network("peer1".to_string(), "test".to_string(), vec![42])
        .unwrap();

    let received = rx.try_recv().unwrap();
    assert_eq!(received.peer_id, "peer1");
    assert_eq!(received.data(), &[42]);
}

/// Test multiple subscribers receive the same message
#[tokio::test]
async fn test_broadcast_to_multiple_subscribers() {
    let listener = UnifiedListener::new();
    let mut rx1 = listener.subscribe();
    let mut rx2 = listener.subscribe();
    let mut rx3 = listener.subscribe();

    listener
        .inject_message(IncomingMessage::transport(
            "peer1".to_string(),
            vec![1, 2, 3],
        ))
        .unwrap();

    let msg1 = rx1.try_recv().unwrap();
    let msg2 = rx2.try_recv().unwrap();
    let msg3 = rx3.try_recv().unwrap();

    // All subscribers should receive the same message content
    assert_eq!(msg1.id, msg2.id);
    assert_eq!(msg2.id, msg3.id);
    assert_eq!(msg1.peer_id, "peer1");
    assert_eq!(msg2.peer_id, "peer1");
    assert_eq!(msg3.peer_id, "peer1");
}

/// Test protocol registration and listing
#[tokio::test]
async fn test_protocol_registration() {
    let listener = UnifiedListener::new();

    // Register a protocol
    let protocol = ProtocolBuilder::new("myapp/v1")
        .handler(|_peer, _data| async { Ok(None) })
        .build()
        .unwrap();

    listener.register_protocol(protocol).await.unwrap();

    // Verify it's listed
    let protocols = listener.registered_protocols().await;
    assert!(protocols.contains(&"myapp/v1".to_string()));

    // Register another
    let protocol2 = ProtocolBuilder::new("myapp/v2")
        .handler(|_peer, _data| async { Ok(None) })
        .build()
        .unwrap();

    listener.register_protocol(protocol2).await.unwrap();

    let protocols = listener.registered_protocols().await;
    assert_eq!(protocols.len(), 2);
}

/// Test duplicate protocol registration fails
#[tokio::test]
async fn test_duplicate_protocol_registration() {
    let listener = UnifiedListener::new();

    let protocol1 = ProtocolBuilder::new("myapp/v1")
        .handler(|_peer, _data| async { Ok(None) })
        .build()
        .unwrap();

    let protocol2 = ProtocolBuilder::new("myapp/v1")
        .handler(|_peer, _data| async { Ok(None) })
        .build()
        .unwrap();

    listener.register_protocol(protocol1).await.unwrap();

    // Second registration with same ID should fail
    let result = listener.register_protocol(protocol2).await;
    assert!(result.is_err());
}

/// Test protocol unregistration
#[tokio::test]
async fn test_protocol_unregistration() {
    let listener = UnifiedListener::new();

    let protocol = ProtocolBuilder::new("myapp/v1")
        .handler(|_peer, _data| async { Ok(None) })
        .build()
        .unwrap();

    listener.register_protocol(protocol).await.unwrap();
    assert!(
        listener
            .registered_protocols()
            .await
            .contains(&"myapp/v1".to_string())
    );

    listener.unregister_protocol("myapp/v1").await.unwrap();
    assert!(
        !listener
            .registered_protocols()
            .await
            .contains(&"myapp/v1".to_string())
    );

    // Unregistering non-existent protocol should fail
    let result = listener.unregister_protocol("nonexistent").await;
    assert!(result.is_err());
}

/// Test custom protocol implementation via trait
#[tokio::test]
async fn test_custom_protocol_trait() {
    struct EchoProtocol {
        call_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Protocol for EchoProtocol {
        fn protocol_id(&self) -> &str {
            "echo/v1"
        }

        fn stream_type(&self) -> Option<u8> {
            Some(42)
        }

        async fn handle(&self, _peer_id: &str, data: Bytes) -> anyhow::Result<Option<Bytes>> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(Some(data))
        }
    }

    let call_count = Arc::new(AtomicUsize::new(0));
    let protocol = EchoProtocol {
        call_count: call_count.clone(),
    };

    assert_eq!(protocol.protocol_id(), "echo/v1");
    assert_eq!(protocol.stream_type(), Some(42));

    let result = protocol
        .handle("peer1", Bytes::from_static(b"hello"))
        .await
        .unwrap();
    assert_eq!(result, Some(Bytes::from_static(b"hello")));
    assert_eq!(call_count.load(Ordering::SeqCst), 1);
}

/// Test ProtocolBuilder with stream type
#[tokio::test]
async fn test_protocol_builder_with_stream_type() {
    let protocol = ProtocolBuilder::new("dht/v1")
        .stream_type(100)
        .handler(|_peer, data| async move {
            let mut response = b"prefix:".to_vec();
            response.extend_from_slice(&data);
            Ok(Some(Bytes::from(response)))
        })
        .build()
        .unwrap();

    assert_eq!(protocol.protocol_id(), "dht/v1");
    assert_eq!(protocol.stream_type(), Some(100));

    let response = protocol
        .handle("peer1", Bytes::from_static(b"test"))
        .await
        .unwrap();
    assert_eq!(response, Some(Bytes::from_static(b"prefix:test")));
}

/// Test different message source types
#[tokio::test]
async fn test_message_source_types() {
    let listener = UnifiedListener::new();
    let mut rx = listener.subscribe();

    // Network message
    listener
        .inject_message(IncomingMessage::network(
            "peer1".to_string(),
            "topic1".to_string(),
            vec![1],
        ))
        .unwrap();

    let msg = rx.try_recv().unwrap();
    assert!(matches!(msg.source, MessageSource::Network { topic } if topic == "topic1"));

    // Transport message
    listener
        .inject_message(IncomingMessage::transport("peer2".to_string(), vec![2]))
        .unwrap();

    let msg = rx.try_recv().unwrap();
    assert!(matches!(msg.source, MessageSource::Transport));

    // DHT message
    listener
        .inject_message(IncomingMessage::dht("peer3".to_string(), 42, vec![3]))
        .unwrap();

    let msg = rx.try_recv().unwrap();
    assert!(matches!(msg.source, MessageSource::Dht { stream_type: 42 }));

    // Custom message
    listener
        .inject_message(IncomingMessage::custom(
            "peer4".to_string(),
            "myproto/v1".to_string(),
            vec![4],
        ))
        .unwrap();

    let msg = rx.try_recv().unwrap();
    assert!(matches!(
        msg.source,
        MessageSource::Custom { protocol_id } if protocol_id == "myproto/v1"
    ));
}

/// Test message ID uniqueness
#[tokio::test]
async fn test_message_id_uniqueness() {
    let listener = UnifiedListener::new();
    let mut rx = listener.subscribe();

    // Inject multiple messages
    for i in 0..100 {
        listener
            .inject_message(IncomingMessage::transport(
                format!("peer{}", i),
                vec![i as u8],
            ))
            .unwrap();
    }

    // Collect all IDs
    let mut ids = Vec::new();
    for _ in 0..100 {
        let msg = rx.try_recv().unwrap();
        ids.push(msg.id);
    }

    // Verify all IDs are unique
    let mut sorted_ids = ids.clone();
    sorted_ids.sort();
    sorted_ids.dedup();
    assert_eq!(ids.len(), sorted_ids.len());
}

/// Test listener capacity configuration
#[tokio::test]
async fn test_custom_capacity() {
    let listener = UnifiedListener::with_capacity(100);
    let mut rx = listener.subscribe();

    // Should work with smaller capacity
    for i in 0..50 {
        listener
            .inject_message(IncomingMessage::transport(
                format!("peer{}", i),
                vec![i as u8],
            ))
            .unwrap();
    }

    // Drain the messages
    for _ in 0..50 {
        let _ = rx.try_recv().unwrap();
    }
}

/// Test message serialization round-trip
#[tokio::test]
async fn test_message_serialization() {
    let original = IncomingMessage::custom(
        "peer123".to_string(),
        "proto/v1".to_string(),
        vec![1, 2, 3, 4, 5],
    );

    // Serialize to JSON
    let json = serde_json::to_string(&original).unwrap();

    // Deserialize back
    let deserialized: IncomingMessage = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.peer_id, original.peer_id);
    assert_eq!(deserialized.data(), original.data());
    assert!(matches!(
        deserialized.source,
        MessageSource::Custom { protocol_id } if protocol_id == "proto/v1"
    ));
}

/// Test listener shutdown
#[tokio::test]
async fn test_listener_shutdown() {
    let listener = UnifiedListener::new();
    let _rx = listener.subscribe();

    assert_eq!(listener.subscriber_count(), 1);

    // Shutdown should be graceful
    listener.shutdown();

    // Can still check subscriber count after shutdown
    assert_eq!(listener.subscriber_count(), 1);
}

/// Test default listener implementation
#[tokio::test]
async fn test_default_implementation() {
    let listener1 = UnifiedListener::new();
    let listener2 = UnifiedListener::default();

    // Both should work identically
    let mut rx1 = listener1.subscribe();
    let mut rx2 = listener2.subscribe();

    listener1
        .inject_message(IncomingMessage::transport("peer1".to_string(), vec![1]))
        .unwrap();
    listener2
        .inject_message(IncomingMessage::transport("peer1".to_string(), vec![1]))
        .unwrap();

    let _ = rx1.try_recv().unwrap();
    let _ = rx2.try_recv().unwrap();
}
