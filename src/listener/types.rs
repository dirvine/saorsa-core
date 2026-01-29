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

//! Core types for the unified message listener system.
//!
//! The main types are:
//! - [`RawMessage`]: The core payload that consumers decode using their own protocols
//! - [`IncomingMessage`]: Wraps a `RawMessage` with source metadata (who sent it, from where)
//! - [`MessageSource`]: Identifies which layer the message came from

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Counter for generating unique message IDs
static MESSAGE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique message ID
fn next_message_id() -> u64 {
    MESSAGE_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// DHT stream type for query operations (GET, FIND_NODE, FIND_VALUE)
pub const DHT_STREAM_QUERY: u8 = 0x10;
/// DHT stream type for store operations (PUT, STORE)
pub const DHT_STREAM_STORE: u8 = 0x11;
/// DHT stream type for witness requests (BFT)
pub const DHT_STREAM_WITNESS: u8 = 0x12;
/// DHT stream type for replication traffic
pub const DHT_STREAM_REPLICATION: u8 = 0x13;

/// Source of an incoming message
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageSource {
    /// Message from the P2P network layer (topic-based pub/sub)
    Network {
        /// Topic/channel the message was received on
        topic: String,
    },
    /// Message from the transport layer (direct connection)
    Transport,
    /// Message from the DHT layer
    Dht {
        /// Stream type identifier. Use `DHT_STREAM_*` constants to match:
        /// - `DHT_STREAM_QUERY` (0x10): GET, FIND_NODE, FIND_VALUE
        /// - `DHT_STREAM_STORE` (0x11): PUT, STORE
        /// - `DHT_STREAM_WITNESS` (0x12): Witness requests for BFT
        /// - `DHT_STREAM_REPLICATION` (0x13): Background replication
        stream_type: u8,
    },
    /// Custom protocol message
    Custom {
        /// Protocol identifier (e.g., "myapp/chat/v1")
        protocol_id: String,
    },
}

// ============================================================================
// RawMessage - The core payload type
// ============================================================================

/// Raw message payload that consumers can decode using their own protocols.
///
/// This is the core message type that wraps the raw bytes received from the network.
/// Consumers should use the decode methods to convert the bytes into their
/// application-specific message types.
///
/// # Example
///
/// ```ignore
/// use saorsa_core::listener::RawMessage;
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct ChatMessage {
///     from: String,
///     content: String,
/// }
///
/// let raw = RawMessage::new(bytes);
///
/// // Decode using bincode
/// let chat: ChatMessage = raw.decode_bincode()?;
///
/// // Or decode using JSON
/// let chat: ChatMessage = raw.decode_json()?;
///
/// // Or use a custom decoder
/// let chat = raw.decode_with(|bytes| my_custom_decode(bytes))?;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawMessage {
    /// The raw bytes of the message payload
    #[serde(with = "bytes_serde")]
    data: Bytes,
}

impl RawMessage {
    /// Create a new raw message from bytes
    pub fn new(data: impl Into<Bytes>) -> Self {
        Self { data: data.into() }
    }

    /// Get the raw bytes of the message
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the underlying Bytes handle (zero-copy)
    pub fn bytes(&self) -> &Bytes {
        &self.data
    }

    /// Consume and return the underlying Bytes
    pub fn into_bytes(self) -> Bytes {
        self.data
    }

    /// Get the length of the message in bytes
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the message is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Decode the message using bincode.
    ///
    /// This is the recommended format for Rust-to-Rust communication
    /// as it's compact and fast.
    pub fn decode_bincode<T: DeserializeOwned>(&self) -> Result<T, bincode::Error> {
        bincode::deserialize(&self.data)
    }

    /// Decode the message using JSON.
    ///
    /// Use this for interoperability with non-Rust clients or
    /// for human-readable message formats.
    pub fn decode_json<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.data)
    }

    /// Decode using a custom decoder function.
    ///
    /// Use this when you need a custom deserialization format or
    /// want to use a different serialization library.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let result = raw.decode_with(|bytes| {
    ///     protobuf::Message::parse_from_bytes(bytes)
    /// })?;
    /// ```
    pub fn decode_with<T, E, F>(&self, decoder: F) -> Result<T, E>
    where
        F: FnOnce(&[u8]) -> Result<T, E>,
    {
        decoder(&self.data)
    }
}

impl From<Vec<u8>> for RawMessage {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<Bytes> for RawMessage {
    fn from(data: Bytes) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for RawMessage {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

impl AsRef<[u8]> for RawMessage {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

// ============================================================================
// IncomingMessage - Wrapper with source metadata
// ============================================================================

/// A unified incoming message from any network layer.
///
/// This wraps a [`RawMessage`] with metadata about the sender and source.
/// The consumer can access the raw payload via the `message` field and
/// decode it using their own protocol.
///
/// # Example
///
/// ```ignore
/// use saorsa_core::listener::{subscribe_all, MessageSource};
///
/// let mut rx = subscribe_all();
/// while let Ok(incoming) = rx.recv().await {
///     println!("From: {}", incoming.peer_id);
///     println!("Source: {:?}", incoming.source);
///
///     // Decode the raw message using your protocol
///     let chat_msg: MyChatMessage = incoming.message.decode_bincode()?;
///     println!("Content: {}", chat_msg.content);
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingMessage {
    /// Unique message identifier (monotonically increasing)
    pub id: u64,
    /// Peer ID of the sender (hex-encoded for DHT/Gossip, or string for P2P)
    pub peer_id: String,
    /// Source layer and routing information
    pub source: MessageSource,
    /// Timestamp when the message was received
    pub received_at: DateTime<Utc>,
    /// The raw message payload - decode this using your protocol
    pub message: RawMessage,
}

impl IncomingMessage {
    /// Create a new incoming message
    pub fn new(peer_id: String, data: impl Into<Bytes>, source: MessageSource) -> Self {
        Self {
            id: next_message_id(),
            peer_id,
            source,
            received_at: Utc::now(),
            message: RawMessage::new(data),
        }
    }

    /// Create a network message (from P2P pub/sub)
    pub fn network(peer_id: String, topic: String, data: impl Into<Bytes>) -> Self {
        Self::new(peer_id, data, MessageSource::Network { topic })
    }

    /// Create a transport message (from direct connection)
    pub fn transport(peer_id: String, data: impl Into<Bytes>) -> Self {
        Self::new(peer_id, data, MessageSource::Transport)
    }

    /// Create a DHT message
    pub fn dht(peer_id: String, stream_type: u8, data: impl Into<Bytes>) -> Self {
        Self::new(peer_id, data, MessageSource::Dht { stream_type })
    }

    /// Create a custom protocol message
    pub fn custom(peer_id: String, protocol_id: String, data: impl Into<Bytes>) -> Self {
        Self::new(peer_id, data, MessageSource::Custom { protocol_id })
    }

    // ========================================================================
    // Convenience accessors (delegate to RawMessage)
    // ========================================================================

    /// Get the raw bytes of the message (shorthand for `self.message.as_bytes()`)
    pub fn data(&self) -> &[u8] {
        self.message.as_bytes()
    }

    /// Decode the message using bincode (shorthand for `self.message.decode_bincode()`)
    pub fn decode_bincode<T: DeserializeOwned>(&self) -> Result<T, bincode::Error> {
        self.message.decode_bincode()
    }

    /// Decode the message using JSON (shorthand for `self.message.decode_json()`)
    pub fn decode_json<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        self.message.decode_json()
    }

    /// Decode using a custom decoder (shorthand for `self.message.decode_with()`)
    pub fn decode_with<T, E, F>(&self, decoder: F) -> Result<T, E>
    where
        F: FnOnce(&[u8]) -> Result<T, E>,
    {
        self.message.decode_with(decoder)
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
    fn test_raw_message_creation() {
        let raw = RawMessage::new(vec![1, 2, 3, 4]);
        assert_eq!(raw.as_bytes(), &[1, 2, 3, 4]);
        assert_eq!(raw.len(), 4);
        assert!(!raw.is_empty());
    }

    #[test]
    fn test_raw_message_from_impls() {
        let from_vec: RawMessage = vec![1, 2, 3].into();
        assert_eq!(from_vec.as_bytes(), &[1, 2, 3]);

        let from_bytes: RawMessage = Bytes::from(vec![4, 5, 6]).into();
        assert_eq!(from_bytes.as_bytes(), &[4, 5, 6]);

        let slice: &[u8] = &[7, 8, 9];
        let from_slice: RawMessage = slice.into();
        assert_eq!(from_slice.as_bytes(), &[7, 8, 9]);
    }

    #[test]
    fn test_raw_message_decode_bincode() {
        let original = "hello world".to_string();
        let encoded = bincode::serialize(&original).unwrap();
        let raw = RawMessage::new(encoded);

        let decoded: String = raw.decode_bincode().unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_raw_message_decode_json() {
        let json = r#"{"name":"test","value":42}"#;
        let raw = RawMessage::new(json.as_bytes().to_vec());

        #[derive(Deserialize, PartialEq, Debug)]
        struct TestStruct {
            name: String,
            value: u32,
        }

        let decoded: TestStruct = raw.decode_json().unwrap();
        assert_eq!(decoded.name, "test");
        assert_eq!(decoded.value, 42);
    }

    #[test]
    fn test_raw_message_decode_with_custom() {
        let raw = RawMessage::new(b"Hi".to_vec());

        let decoded = raw
            .decode_with(|bytes| -> Result<String, std::string::FromUtf8Error> {
                String::from_utf8(bytes.to_vec())
            })
            .unwrap();

        assert_eq!(decoded, "Hi");
    }

    #[test]
    fn test_incoming_message_creation() {
        let msg =
            IncomingMessage::network("peer1".to_string(), "chat".to_string(), vec![1, 2, 3, 4]);

        assert_eq!(msg.peer_id, "peer1");
        assert_eq!(msg.data(), &[1, 2, 3, 4]);
        assert_eq!(msg.message.as_bytes(), &[1, 2, 3, 4]);
        assert!(matches!(msg.source, MessageSource::Network { topic } if topic == "chat"));
    }

    #[test]
    fn test_message_source_variants() {
        let network = MessageSource::Network {
            topic: "test".to_string(),
        };
        let transport = MessageSource::Transport;
        let dht = MessageSource::Dht { stream_type: 42 };
        let custom = MessageSource::Custom {
            protocol_id: "myapp/v1".to_string(),
        };

        assert!(matches!(network, MessageSource::Network { .. }));
        assert!(matches!(transport, MessageSource::Transport));
        assert!(matches!(dht, MessageSource::Dht { stream_type: 42 }));
        assert!(matches!(custom, MessageSource::Custom { .. }));
    }

    #[test]
    fn test_message_id_uniqueness() {
        let msg1 = IncomingMessage::transport("peer1".to_string(), vec![1]);
        let msg2 = IncomingMessage::transport("peer2".to_string(), vec![2]);

        assert_ne!(msg1.id, msg2.id);
    }

    #[test]
    fn test_message_serialization() {
        let msg =
            IncomingMessage::custom("peer1".to_string(), "proto/v1".to_string(), vec![1, 2, 3]);

        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: IncomingMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.peer_id, msg.peer_id);
        assert_eq!(deserialized.data(), msg.data());
    }

    #[test]
    fn test_incoming_message_convenience_decode() {
        // Test that decode methods work directly on IncomingMessage
        let original = vec![1u32, 2, 3, 4, 5];
        let encoded = bincode::serialize(&original).unwrap();
        let msg = IncomingMessage::transport("peer1".to_string(), encoded);

        let decoded: Vec<u32> = msg.decode_bincode().unwrap();
        assert_eq!(decoded, original);
    }
}
