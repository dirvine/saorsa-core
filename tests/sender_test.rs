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

//! Integration tests for the UnifiedSender system.

use saorsa_core::sender::{
    DeliveryEvent, DeliveryTracking, EncodedPayload, EncodingType, MessageDestination,
    MessageEncoder, RetryPolicy, SenderBuilder, UnifiedSender,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TestMessage {
    id: u64,
    content: String,
    timestamp: u64,
}

#[tokio::test]
async fn test_sender_creation_and_defaults() {
    let sender = UnifiedSender::new();

    // Should start without any transports registered
    assert!(!sender.has_p2p().await);
    assert!(!sender.has_gossip().await);

    // Should have no pending messages
    assert_eq!(sender.pending_count().await, 0);
}

#[tokio::test]
async fn test_builder_creates_empty_sender() {
    let sender = SenderBuilder::new().build().await.unwrap();

    assert!(!sender.has_p2p().await);
    assert!(!sender.has_gossip().await);
}

#[tokio::test]
async fn test_message_encoder_bincode() {
    let msg = TestMessage {
        id: 42,
        content: "Hello, World!".to_string(),
        timestamp: 1234567890,
    };

    let payload = MessageEncoder::bincode(&msg).unwrap();
    assert_eq!(payload.encoding, EncodingType::Bincode);
    assert!(!payload.is_empty());

    // Verify round-trip
    let decoded: TestMessage = bincode::deserialize(payload.as_bytes()).unwrap();
    assert_eq!(decoded, msg);
}

#[tokio::test]
async fn test_message_encoder_json() {
    let msg = TestMessage {
        id: 42,
        content: "Hello, JSON!".to_string(),
        timestamp: 1234567890,
    };

    let payload = MessageEncoder::json(&msg).unwrap();
    assert_eq!(payload.encoding, EncodingType::Json);
    assert!(!payload.is_empty());

    // Verify round-trip
    let decoded: TestMessage = serde_json::from_slice(payload.as_bytes()).unwrap();
    assert_eq!(decoded, msg);

    // Verify it's valid JSON
    let json_str = std::str::from_utf8(payload.as_bytes()).unwrap();
    assert!(json_str.contains("Hello, JSON!"));
}

#[tokio::test]
async fn test_message_encoder_raw() {
    let data = b"raw binary data";
    let payload = MessageEncoder::raw(data.to_vec());

    assert_eq!(payload.encoding, EncodingType::Raw);
    assert_eq!(payload.as_bytes(), data);
}

#[tokio::test]
async fn test_message_destination_variants() {
    // Network unicast
    let network = MessageDestination::network("peer123", "chat");
    assert!(network.is_unicast());
    assert!(!network.is_broadcast());
    assert!(!network.is_gossip());
    assert_eq!(network.topic(), "chat");

    // Broadcast
    let broadcast = MessageDestination::broadcast("announcements");
    assert!(!broadcast.is_unicast());
    assert!(broadcast.is_broadcast());
    assert!(!broadcast.is_gossip());
    assert_eq!(broadcast.topic(), "announcements");

    // Gossip
    let gossip = MessageDestination::gossip("events");
    assert!(!gossip.is_unicast());
    assert!(!gossip.is_broadcast());
    assert!(gossip.is_gossip());
    assert_eq!(gossip.topic(), "events");
}

#[tokio::test]
async fn test_delivery_tracking_defaults() {
    let tracking = DeliveryTracking::default();

    assert!(tracking.require_ack);
    assert_eq!(tracking.timeout, Duration::from_secs(30));
    assert_eq!(tracking.retry_policy.max_retries, 3);
}

#[tokio::test]
async fn test_delivery_tracking_fire_and_forget() {
    let tracking = DeliveryTracking::fire_and_forget();

    assert!(!tracking.require_ack);
    assert_eq!(tracking.retry_policy.max_retries, 0);
}

#[tokio::test]
async fn test_retry_policy_delay_calculation() {
    let policy = RetryPolicy {
        max_retries: 5,
        initial_delay: Duration::from_millis(100),
        backoff_multiplier: 2.0,
        max_delay: Duration::from_secs(10),
    };

    // First attempt uses initial delay
    assert_eq!(policy.delay_for_attempt(0), Duration::from_millis(100));

    // Subsequent attempts use exponential backoff
    assert_eq!(policy.delay_for_attempt(1), Duration::from_millis(200));
    assert_eq!(policy.delay_for_attempt(2), Duration::from_millis(400));
    assert_eq!(policy.delay_for_attempt(3), Duration::from_millis(800));
    assert_eq!(policy.delay_for_attempt(4), Duration::from_millis(1600));

    // Should cap at max_delay
    let delay = policy.delay_for_attempt(20);
    assert!(delay <= Duration::from_secs(10));
}

#[tokio::test]
async fn test_delivery_event_subscription() {
    let sender = UnifiedSender::new();

    // Can subscribe to events
    let mut rx1 = sender.subscribe_delivery();
    let mut rx2 = sender.subscribe_delivery();

    // Multiple subscriptions work
    assert!(rx1.try_recv().is_err()); // Empty
    assert!(rx2.try_recv().is_err()); // Empty
}

#[tokio::test]
async fn test_send_without_transport_emits_error() {
    let sender = UnifiedSender::new();
    let payload = EncodedPayload::raw(vec![1, 2, 3]);

    // Network send without P2P should fail
    let result = sender
        .send(MessageDestination::network("peer1", "test"), payload.clone())
        .await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("P2P node not registered"));

    // Broadcast without P2P should fail
    let result = sender.broadcast("test", payload.clone()).await;
    assert!(result.is_err());

    // Gossip without GossipSub should fail
    let result = sender.gossip("test", payload).await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("GossipSub not registered"));
}

#[tokio::test]
async fn test_encoded_payload_from_impls() {
    // From Vec<u8>
    let from_vec: EncodedPayload = vec![1, 2, 3, 4].into();
    assert_eq!(from_vec.as_bytes(), &[1, 2, 3, 4]);
    assert_eq!(from_vec.encoding, EncodingType::Raw);

    // From Bytes
    let bytes = bytes::Bytes::from(vec![5, 6, 7]);
    let from_bytes: EncodedPayload = bytes.into();
    assert_eq!(from_bytes.as_bytes(), &[5, 6, 7]);

    // From slice
    let slice: &[u8] = &[8, 9, 10];
    let from_slice: EncodedPayload = slice.into();
    assert_eq!(from_slice.as_bytes(), &[8, 9, 10]);
}

#[tokio::test]
async fn test_encoded_payload_accessors() {
    let payload = EncodedPayload::raw(vec![1, 2, 3, 4, 5]);

    assert_eq!(payload.len(), 5);
    assert!(!payload.is_empty());
    assert_eq!(payload.as_bytes(), &[1, 2, 3, 4, 5]);

    let bytes = payload.into_bytes();
    assert_eq!(&bytes[..], &[1, 2, 3, 4, 5]);

    // Empty payload
    let empty = EncodedPayload::raw(vec![]);
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
}

#[tokio::test]
async fn test_delivery_event_accessors() {
    use saorsa_core::sender::MessageId;

    let msg_id = MessageId::from(42);

    // Sent event
    let sent = DeliveryEvent::Sent {
        message_id: msg_id,
        destination: MessageDestination::gossip("test"),
        attempt: 0,
        sent_at: chrono::Utc::now(),
    };
    assert_eq!(sent.message_id(), msg_id);
    assert!(!sent.is_success());
    assert!(!sent.is_terminal_failure());

    // Delivered event
    let delivered = DeliveryEvent::Delivered {
        message_id: msg_id,
        destination: MessageDestination::gossip("test"),
        attempts: 1,
        delivered_at: chrono::Utc::now(),
        rtt: Duration::from_millis(50),
    };
    assert!(delivered.is_success());
    assert!(!delivered.is_terminal_failure());

    // Failed event
    let failed = DeliveryEvent::Failed {
        message_id: msg_id,
        destination: MessageDestination::gossip("test"),
        attempts: 3,
        error: "Connection refused".into(),
        failed_at: chrono::Utc::now(),
    };
    assert!(!failed.is_success());
    assert!(failed.is_terminal_failure());

    // TimedOut event
    let timed_out = DeliveryEvent::TimedOut {
        message_id: msg_id,
        destination: MessageDestination::gossip("test"),
        attempts: 2,
        timed_out_at: chrono::Utc::now(),
    };
    assert!(!timed_out.is_success());
    assert!(timed_out.is_terminal_failure());

    // Retrying event
    let retrying = DeliveryEvent::Retrying {
        message_id: msg_id,
        destination: MessageDestination::gossip("test"),
        attempt: 1,
        reason: "Network error".into(),
        retry_at: chrono::Utc::now(),
    };
    assert!(!retrying.is_success());
    assert!(!retrying.is_terminal_failure());
}

#[tokio::test]
async fn test_sender_shutdown() {
    let sender = UnifiedSender::new();
    sender.shutdown();
    // Should not panic or hang
}

#[tokio::test]
async fn test_message_destination_equality() {
    let d1 = MessageDestination::network("peer1", "topic1");
    let d2 = MessageDestination::network("peer1", "topic1");
    let d3 = MessageDestination::network("peer2", "topic1");
    let d4 = MessageDestination::network("peer1", "topic2");

    assert_eq!(d1, d2);
    assert_ne!(d1, d3);
    assert_ne!(d1, d4);

    let b1 = MessageDestination::broadcast("topic1");
    let b2 = MessageDestination::broadcast("topic1");
    let b3 = MessageDestination::broadcast("topic2");

    assert_eq!(b1, b2);
    assert_ne!(b1, b3);

    let g1 = MessageDestination::gossip("topic1");
    let g2 = MessageDestination::gossip("topic1");

    assert_eq!(g1, g2);

    // Different variants are not equal
    assert_ne!(d1, b1);
    assert_ne!(b1, g1);
}

#[tokio::test]
async fn test_custom_encoder() {
    let payload = MessageEncoder::custom(|buf| {
        buf.extend_from_slice(b"HEADER:");
        buf.extend_from_slice(&42u32.to_le_bytes());
        Ok(())
    })
    .unwrap();

    assert_eq!(payload.encoding, EncodingType::Custom);
    assert!(payload.as_bytes().starts_with(b"HEADER:"));
}

#[tokio::test]
async fn test_payload_serialization() {
    let payload = EncodedPayload::new(vec![1, 2, 3, 4], EncodingType::Bincode);

    // Serialize to JSON
    let json = serde_json::to_string(&payload).unwrap();

    // Deserialize back
    let deserialized: EncodedPayload = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.as_bytes(), payload.as_bytes());
    assert_eq!(deserialized.encoding, payload.encoding);
}

#[tokio::test]
async fn test_destination_serialization() {
    let destinations = vec![
        MessageDestination::network("peer1", "chat"),
        MessageDestination::broadcast("announcements"),
        MessageDestination::gossip("events"),
    ];

    for dest in destinations {
        let json = serde_json::to_string(&dest).unwrap();
        let deserialized: MessageDestination = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, dest);
    }
}

#[tokio::test]
async fn test_delivery_event_serialization() {
    use saorsa_core::sender::MessageId;

    let event = DeliveryEvent::Delivered {
        message_id: MessageId::from(123),
        destination: MessageDestination::gossip("test"),
        attempts: 2,
        delivered_at: chrono::Utc::now(),
        rtt: Duration::from_millis(75),
    };

    let json = serde_json::to_string(&event).unwrap();
    let deserialized: DeliveryEvent = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.message_id(), event.message_id());
}
