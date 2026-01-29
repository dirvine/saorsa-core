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

//! Core types for the unified message sender system.
//!
//! The main types are:
//! - [`MessageDestination`]: Where to send a message (P2P unicast, broadcast, or GossipSub)
//! - [`EncodedPayload`]: Encoded message bytes ready to send
//! - [`DeliveryTracking`]: Configuration for delivery confirmation and retries
//! - [`DeliveryEvent`]: Events emitted during message delivery lifecycle

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// =============================================================================
// Default Configuration Constants
// =============================================================================

/// Default maximum number of retry attempts before giving up
const DEFAULT_MAX_RETRIES: u32 = 3;

/// Default initial delay before first retry attempt (milliseconds)
const DEFAULT_INITIAL_RETRY_DELAY_MS: u64 = 100;

/// Default multiplier for exponential backoff between retries
const DEFAULT_BACKOFF_MULTIPLIER: f64 = 2.0;

/// Default maximum delay between retry attempts (seconds)
const DEFAULT_MAX_RETRY_DELAY_SECS: u64 = 30;

/// Default timeout for delivery confirmation (seconds)
const DEFAULT_DELIVERY_TIMEOUT_SECS: u64 = 30;

/// Fire-and-forget mode timeout (seconds) - shorter since we don't track
const FIRE_AND_FORGET_TIMEOUT_SECS: u64 = 5;

/// Counter for generating unique message IDs
static MESSAGE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique message ID
pub(crate) fn next_message_id() -> MessageId {
    MessageId(MESSAGE_COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// Unique identifier for tracking outgoing messages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub u64);

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "msg-{}", self.0)
    }
}

impl From<u64> for MessageId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

/// Destination for outgoing messages
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageDestination {
    /// Send to a specific peer via P2P network
    Network {
        /// Peer ID to send to
        peer_id: String,
        /// Topic/protocol for routing
        topic: String,
    },
    /// Broadcast to all connected peers via P2P network
    Broadcast {
        /// Topic/protocol for the broadcast
        topic: String,
    },
    /// Publish via GossipSub to topic subscribers
    Gossip {
        /// GossipSub topic to publish on
        topic: String,
    },
}

impl MessageDestination {
    /// Create a network destination for unicast to a specific peer
    pub fn network(peer_id: impl Into<String>, topic: impl Into<String>) -> Self {
        Self::Network {
            peer_id: peer_id.into(),
            topic: topic.into(),
        }
    }

    /// Create a broadcast destination for all connected peers
    pub fn broadcast(topic: impl Into<String>) -> Self {
        Self::Broadcast {
            topic: topic.into(),
        }
    }

    /// Create a gossip destination for pub/sub delivery
    pub fn gossip(topic: impl Into<String>) -> Self {
        Self::Gossip {
            topic: topic.into(),
        }
    }

    /// Get the topic associated with this destination
    pub fn topic(&self) -> &str {
        match self {
            Self::Network { topic, .. } => topic,
            Self::Broadcast { topic } => topic,
            Self::Gossip { topic } => topic,
        }
    }

    /// Check if this is a unicast destination
    pub fn is_unicast(&self) -> bool {
        matches!(self, Self::Network { .. })
    }

    /// Check if this is a broadcast destination
    pub fn is_broadcast(&self) -> bool {
        matches!(self, Self::Broadcast { .. })
    }

    /// Check if this is a gossip destination
    pub fn is_gossip(&self) -> bool {
        matches!(self, Self::Gossip { .. })
    }
}

/// Type of encoding used for the payload
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum EncodingType {
    /// Bincode binary format (compact, fast, Rust-native)
    #[default]
    Bincode,
    /// JSON text format (interoperable)
    Json,
    /// Raw bytes (no encoding)
    Raw,
    /// Custom encoding (user-defined)
    Custom,
}

/// Encoded message payload ready for transmission
///
/// Wraps the raw bytes with metadata about the encoding used.
/// Created via [`MessageEncoder`](crate::sender::MessageEncoder) methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodedPayload {
    /// The encoded bytes
    #[serde(with = "bytes_serde")]
    pub data: Bytes,
    /// Type of encoding used
    pub encoding: EncodingType,
}

impl EncodedPayload {
    /// Create a new encoded payload
    pub fn new(data: impl Into<Bytes>, encoding: EncodingType) -> Self {
        Self {
            data: data.into(),
            encoding,
        }
    }

    /// Create a raw payload from bytes
    pub fn raw(data: impl Into<Bytes>) -> Self {
        Self::new(data, EncodingType::Raw)
    }

    /// Get the length of the payload in bytes
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the payload is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get a reference to the underlying bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consume and return the underlying Bytes
    pub fn into_bytes(self) -> Bytes {
        self.data
    }
}

impl From<Vec<u8>> for EncodedPayload {
    fn from(data: Vec<u8>) -> Self {
        Self::raw(data)
    }
}

impl From<Bytes> for EncodedPayload {
    fn from(data: Bytes) -> Self {
        Self::raw(data)
    }
}

impl From<&[u8]> for EncodedPayload {
    fn from(data: &[u8]) -> Self {
        Self::raw(data.to_vec())
    }
}

/// Policy for retrying failed message deliveries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial delay before first retry
    pub initial_delay: Duration,
    /// Multiplier for exponential backoff
    pub backoff_multiplier: f64,
    /// Maximum delay between retries
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_MAX_RETRIES,
            initial_delay: Duration::from_millis(DEFAULT_INITIAL_RETRY_DELAY_MS),
            backoff_multiplier: DEFAULT_BACKOFF_MULTIPLIER,
            max_delay: Duration::from_secs(DEFAULT_MAX_RETRY_DELAY_SECS),
        }
    }
}

impl RetryPolicy {
    /// Create a policy with no retries
    pub fn none() -> Self {
        Self {
            max_retries: 0,
            ..Default::default()
        }
    }

    /// Create a policy with the specified number of retries
    pub fn with_max_retries(max_retries: u32) -> Self {
        Self {
            max_retries,
            ..Default::default()
        }
    }

    /// Calculate delay for a given attempt number (0-indexed)
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return self.initial_delay;
        }

        let delay_ms = self.initial_delay.as_millis() as f64
            * self.backoff_multiplier.powi(attempt as i32);
        let delay = Duration::from_millis(delay_ms as u64);

        std::cmp::min(delay, self.max_delay)
    }
}

/// Configuration for delivery tracking and acknowledgments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryTracking {
    /// Whether to require acknowledgment from the recipient
    pub require_ack: bool,
    /// Overall timeout for delivery (including retries)
    pub timeout: Duration,
    /// Policy for retrying failed deliveries
    pub retry_policy: RetryPolicy,
}

impl Default for DeliveryTracking {
    fn default() -> Self {
        Self {
            require_ack: true,
            timeout: Duration::from_secs(DEFAULT_DELIVERY_TIMEOUT_SECS),
            retry_policy: RetryPolicy::default(),
        }
    }
}

impl DeliveryTracking {
    /// Create tracking config for fire-and-forget delivery (no tracking)
    pub fn fire_and_forget() -> Self {
        Self {
            require_ack: false,
            timeout: Duration::from_secs(FIRE_AND_FORGET_TIMEOUT_SECS),
            retry_policy: RetryPolicy::none(),
        }
    }

    /// Create tracking config with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            timeout,
            ..Default::default()
        }
    }

    /// Create tracking config with custom retry policy
    pub fn with_retry_policy(retry_policy: RetryPolicy) -> Self {
        Self {
            retry_policy,
            ..Default::default()
        }
    }
}

/// Events emitted during message delivery lifecycle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeliveryEvent {
    /// Message was sent (initial send or retry)
    Sent {
        /// Message identifier
        message_id: MessageId,
        /// Destination the message was sent to
        destination: MessageDestination,
        /// Which attempt this was (0 = first send)
        attempt: u32,
        /// When the message was sent
        sent_at: DateTime<Utc>,
    },
    /// Message was acknowledged/delivered
    Delivered {
        /// Message identifier
        message_id: MessageId,
        /// Destination that acknowledged
        destination: MessageDestination,
        /// How many attempts it took
        attempts: u32,
        /// When delivery was confirmed
        delivered_at: DateTime<Utc>,
        /// Round-trip time from last send
        rtt: Duration,
    },
    /// Attempting a retry after failure
    Retrying {
        /// Message identifier
        message_id: MessageId,
        /// Destination being retried
        destination: MessageDestination,
        /// Which retry attempt (1 = first retry)
        attempt: u32,
        /// Reason for retry
        reason: String,
        /// When retry is scheduled
        retry_at: DateTime<Utc>,
    },
    /// Message delivery failed permanently
    Failed {
        /// Message identifier
        message_id: MessageId,
        /// Destination that failed
        destination: MessageDestination,
        /// How many attempts were made
        attempts: u32,
        /// Error description
        error: String,
        /// When failure was determined
        failed_at: DateTime<Utc>,
    },
    /// Message delivery timed out
    TimedOut {
        /// Message identifier
        message_id: MessageId,
        /// Destination that timed out
        destination: MessageDestination,
        /// How many attempts were made
        attempts: u32,
        /// When timeout occurred
        timed_out_at: DateTime<Utc>,
    },
}

impl DeliveryEvent {
    /// Get the message ID associated with this event
    pub fn message_id(&self) -> MessageId {
        match self {
            Self::Sent { message_id, .. } => *message_id,
            Self::Delivered { message_id, .. } => *message_id,
            Self::Retrying { message_id, .. } => *message_id,
            Self::Failed { message_id, .. } => *message_id,
            Self::TimedOut { message_id, .. } => *message_id,
        }
    }

    /// Check if this event indicates successful delivery
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Delivered { .. })
    }

    /// Check if this event indicates final failure
    pub fn is_terminal_failure(&self) -> bool {
        matches!(self, Self::Failed { .. } | Self::TimedOut { .. })
    }
}

/// Serde support for Bytes type
mod bytes_serde {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_ref().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<u8>::deserialize(deserializer)?;
        Ok(Bytes::from(vec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_id_uniqueness() {
        let id1 = next_message_id();
        let id2 = next_message_id();
        assert_ne!(id1, id2);
        assert!(id2.0 > id1.0);
    }

    #[test]
    fn test_message_destination_constructors() {
        let network = MessageDestination::network("peer123", "chat");
        assert!(network.is_unicast());
        assert_eq!(network.topic(), "chat");

        let broadcast = MessageDestination::broadcast("announcements");
        assert!(broadcast.is_broadcast());
        assert_eq!(broadcast.topic(), "announcements");

        let gossip = MessageDestination::gossip("events");
        assert!(gossip.is_gossip());
        assert_eq!(gossip.topic(), "events");
    }

    #[test]
    fn test_encoded_payload_creation() {
        let payload = EncodedPayload::raw(vec![1, 2, 3, 4]);
        assert_eq!(payload.len(), 4);
        assert!(!payload.is_empty());
        assert_eq!(payload.encoding, EncodingType::Raw);
    }

    #[test]
    fn test_encoded_payload_from_impls() {
        let from_vec: EncodedPayload = vec![1, 2, 3].into();
        assert_eq!(from_vec.as_bytes(), &[1, 2, 3]);

        let from_bytes: EncodedPayload = Bytes::from(vec![4, 5, 6]).into();
        assert_eq!(from_bytes.as_bytes(), &[4, 5, 6]);

        let slice: &[u8] = &[7, 8, 9];
        let from_slice: EncodedPayload = slice.into();
        assert_eq!(from_slice.as_bytes(), &[7, 8, 9]);
    }

    #[test]
    fn test_retry_policy_delay_calculation() {
        let policy = RetryPolicy {
            max_retries: 5,
            initial_delay: Duration::from_millis(100),
            backoff_multiplier: 2.0,
            max_delay: Duration::from_secs(10),
        };

        assert_eq!(policy.delay_for_attempt(0), Duration::from_millis(100));
        assert_eq!(policy.delay_for_attempt(1), Duration::from_millis(200));
        assert_eq!(policy.delay_for_attempt(2), Duration::from_millis(400));
        assert_eq!(policy.delay_for_attempt(3), Duration::from_millis(800));

        // Should cap at max_delay
        let long_delay = policy.delay_for_attempt(10);
        assert!(long_delay <= policy.max_delay);
    }

    #[test]
    fn test_delivery_tracking_defaults() {
        let tracking = DeliveryTracking::default();
        assert!(tracking.require_ack);
        assert_eq!(tracking.timeout, Duration::from_secs(DEFAULT_DELIVERY_TIMEOUT_SECS));
        assert_eq!(tracking.retry_policy.max_retries, DEFAULT_MAX_RETRIES);
    }

    #[test]
    fn test_delivery_tracking_fire_and_forget() {
        let tracking = DeliveryTracking::fire_and_forget();
        assert!(!tracking.require_ack);
        assert_eq!(tracking.retry_policy.max_retries, 0);
    }

    #[test]
    fn test_delivery_event_accessors() {
        let event = DeliveryEvent::Sent {
            message_id: MessageId(42),
            destination: MessageDestination::gossip("test"),
            attempt: 0,
            sent_at: Utc::now(),
        };

        assert_eq!(event.message_id(), MessageId(42));
        assert!(!event.is_success());
        assert!(!event.is_terminal_failure());

        let delivered = DeliveryEvent::Delivered {
            message_id: MessageId(42),
            destination: MessageDestination::gossip("test"),
            attempts: 1,
            delivered_at: Utc::now(),
            rtt: Duration::from_millis(50),
        };

        assert!(delivered.is_success());

        let failed = DeliveryEvent::Failed {
            message_id: MessageId(42),
            destination: MessageDestination::gossip("test"),
            attempts: 3,
            error: "Connection refused".into(),
            failed_at: Utc::now(),
        };

        assert!(failed.is_terminal_failure());
    }

    #[test]
    fn test_payload_serialization() {
        let payload = EncodedPayload::new(vec![1, 2, 3, 4], EncodingType::Bincode);
        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: EncodedPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.as_bytes(), payload.as_bytes());
        assert_eq!(deserialized.encoding, payload.encoding);
    }
}
