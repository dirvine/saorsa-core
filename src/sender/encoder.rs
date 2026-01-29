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

//! Message encoding utilities for the sender system.
//!
//! Provides static methods for encoding messages in various formats before sending.
//! This is symmetric to the [`RawMessage`](crate::listener::RawMessage) decode methods.

use super::types::{EncodedPayload, EncodingType};
use anyhow::Result;
use bytes::Bytes;
use serde::Serialize;

/// Message encoder with static methods for various encoding formats.
///
/// This struct provides encoding methods that are symmetric to the
/// [`RawMessage`](crate::listener::RawMessage) decode methods in the listener module.
///
/// # Example
///
/// ```ignore
/// use saorsa_core::sender::MessageEncoder;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct ChatMessage {
///     from: String,
///     content: String,
/// }
///
/// let msg = ChatMessage {
///     from: "alice".into(),
///     content: "Hello!".into(),
/// };
///
/// // Encode using bincode (recommended for Rust-to-Rust)
/// let payload = MessageEncoder::bincode(&msg)?;
///
/// // Or encode using JSON (for interoperability)
/// let payload = MessageEncoder::json(&msg)?;
///
/// // Or use raw bytes
/// let payload = MessageEncoder::raw(b"raw bytes");
/// ```
pub struct MessageEncoder;

impl MessageEncoder {
    /// Encode a value using bincode.
    ///
    /// This is the recommended format for Rust-to-Rust communication
    /// as it's compact and fast.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn bincode<T: Serialize>(value: &T) -> Result<EncodedPayload> {
        let data = bincode::serialize(value)?;
        Ok(EncodedPayload::new(data, EncodingType::Bincode))
    }

    /// Encode a value using JSON.
    ///
    /// Use this for interoperability with non-Rust clients or
    /// for human-readable message formats.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn json<T: Serialize>(value: &T) -> Result<EncodedPayload> {
        let data = serde_json::to_vec(value)?;
        Ok(EncodedPayload::new(data, EncodingType::Json))
    }

    /// Create a payload from raw bytes (no encoding).
    ///
    /// Use this when you have pre-encoded data or want to send
    /// arbitrary bytes without any additional encoding.
    pub fn raw(data: impl Into<Bytes>) -> EncodedPayload {
        EncodedPayload::new(data, EncodingType::Raw)
    }

    /// Create a payload using a custom encoding function.
    ///
    /// Use this when you need a custom serialization format or
    /// want to use a different serialization library.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let payload = MessageEncoder::custom(|buf| {
    ///     // Custom encoding logic
    ///     buf.extend_from_slice(&my_data);
    ///     Ok(())
    /// })?;
    /// ```
    pub fn custom<F>(encoder: F) -> Result<EncodedPayload>
    where
        F: FnOnce(&mut Vec<u8>) -> Result<()>,
    {
        let mut buf = Vec::new();
        encoder(&mut buf)?;
        Ok(EncodedPayload::new(buf, EncodingType::Custom))
    }

    /// Encode a value using a provided encoder function.
    ///
    /// This allows using any serialization library while still
    /// tracking the encoding type.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let payload = MessageEncoder::with_encoder(&my_message, |msg| {
    ///     // Use protobuf, msgpack, or any other format
    ///     prost::Message::encode(msg)
    /// })?;
    /// ```
    pub fn with_encoder<T, F, E>(value: &T, encoder: F) -> Result<EncodedPayload>
    where
        F: FnOnce(&T) -> std::result::Result<Vec<u8>, E>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let data = encoder(value)?;
        Ok(EncodedPayload::new(data, EncodingType::Custom))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestMessage {
        name: String,
        value: u32,
    }

    #[test]
    fn test_bincode_encoding() {
        let msg = TestMessage {
            name: "test".into(),
            value: 42,
        };

        let payload = MessageEncoder::bincode(&msg).unwrap();
        assert_eq!(payload.encoding, EncodingType::Bincode);
        assert!(!payload.is_empty());

        // Verify we can decode it back
        let decoded: TestMessage = bincode::deserialize(payload.as_bytes()).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_json_encoding() {
        let msg = TestMessage {
            name: "test".into(),
            value: 42,
        };

        let payload = MessageEncoder::json(&msg).unwrap();
        assert_eq!(payload.encoding, EncodingType::Json);
        assert!(!payload.is_empty());

        // Verify we can decode it back
        let decoded: TestMessage = serde_json::from_slice(payload.as_bytes()).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_raw_encoding() {
        let data = b"hello world";
        let payload = MessageEncoder::raw(data.to_vec());

        assert_eq!(payload.encoding, EncodingType::Raw);
        assert_eq!(payload.as_bytes(), data);
    }

    #[test]
    fn test_raw_from_bytes() {
        let bytes = Bytes::from_static(b"test bytes");
        let payload = MessageEncoder::raw(bytes.clone());

        assert_eq!(payload.encoding, EncodingType::Raw);
        assert_eq!(payload.as_bytes(), bytes.as_ref());
    }

    #[test]
    fn test_custom_encoding() {
        let payload = MessageEncoder::custom(|buf| {
            buf.extend_from_slice(b"custom:");
            buf.extend_from_slice(&42u32.to_le_bytes());
            Ok(())
        })
        .unwrap();

        assert_eq!(payload.encoding, EncodingType::Custom);
        assert!(payload.as_bytes().starts_with(b"custom:"));
    }

    #[test]
    fn test_with_encoder() {
        let msg = TestMessage {
            name: "encoded".into(),
            value: 100,
        };

        let payload =
            MessageEncoder::with_encoder(&msg, |m| {
                bincode::serialize(m).map_err(std::io::Error::other)
            })
                .unwrap();

        assert_eq!(payload.encoding, EncodingType::Custom);

        let decoded: TestMessage = bincode::deserialize(payload.as_bytes()).unwrap();
        assert_eq!(decoded, msg);
    }
}
