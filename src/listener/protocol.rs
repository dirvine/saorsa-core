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

//! Protocol trait for consumer-defined message handlers.

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// A consumer-defined protocol for handling messages
///
/// Implement this trait to define custom message handling logic for your application.
///
/// # Example
///
/// ```ignore
/// use saorsa_core::listener::{Protocol, IncomingMessage};
/// use bytes::Bytes;
/// use async_trait::async_trait;
/// use anyhow::Result;
///
/// struct ChatProtocol;
///
/// #[async_trait]
/// impl Protocol for ChatProtocol {
///     fn protocol_id(&self) -> &str {
///         "myapp/chat/v1"
///     }
///
///     fn stream_type(&self) -> Option<u8> {
///         None  // Use topic-based routing
///     }
///
///     async fn handle(&self, peer_id: &str, data: Bytes) -> Result<Option<Bytes>> {
///         println!("Chat from {}: {:?}", peer_id, data);
///         Ok(None)  // No response
///     }
/// }
/// ```
#[async_trait]
pub trait Protocol: Send + Sync + 'static {
    /// Returns the unique identifier for this protocol
    ///
    /// Convention: use format "app/protocol/version" (e.g., "myapp/chat/v1")
    fn protocol_id(&self) -> &str;

    /// Returns the DHT stream type for this protocol, if using stream-type routing
    ///
    /// Return `None` to use topic-based routing instead.
    fn stream_type(&self) -> Option<u8> {
        None
    }

    /// Handle an incoming message
    ///
    /// # Arguments
    /// * `peer_id` - The ID of the peer that sent the message
    /// * `data` - The raw message data
    ///
    /// # Returns
    /// * `Ok(Some(response))` - Send a response back to the peer
    /// * `Ok(None)` - No response needed
    /// * `Err(e)` - An error occurred while processing
    async fn handle(&self, peer_id: &str, data: Bytes) -> Result<Option<Bytes>>;
}

/// Type alias for protocol handler functions
type ProtocolHandlerFn = Arc<
    dyn Fn(&str, Bytes) -> Pin<Box<dyn Future<Output = Result<Option<Bytes>>> + Send + 'static>>
        + Send
        + Sync
        + 'static,
>;

/// Builder for creating simple protocols from closures
///
/// Use this when you don't need a full struct implementation.
///
/// # Example
///
/// ```ignore
/// use saorsa_core::listener::ProtocolBuilder;
///
/// let echo_protocol = ProtocolBuilder::new("myapp/echo/v1")
///     .handler(|_peer_id, data| async move {
///         Ok(Some(data))  // Echo back the message
///     })
///     .build();
/// ```
pub struct ProtocolBuilder {
    protocol_id: String,
    stream_type: Option<u8>,
    handler: Option<ProtocolHandlerFn>,
}

impl ProtocolBuilder {
    /// Create a new protocol builder with the given protocol ID
    pub fn new(protocol_id: impl Into<String>) -> Self {
        Self {
            protocol_id: protocol_id.into(),
            stream_type: None,
            handler: None,
        }
    }

    /// Set the stream type for DHT stream-type routing
    pub fn stream_type(mut self, stream_type: u8) -> Self {
        self.stream_type = Some(stream_type);
        self
    }

    /// Set the handler function
    pub fn handler<F, Fut>(mut self, handler: F) -> Self
    where
        F: Fn(&str, Bytes) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<Bytes>>> + Send + 'static,
    {
        let handler = Arc::new(move |peer_id: &str, data: Bytes| {
            let fut = handler(peer_id, data);
            Box::pin(fut) as Pin<Box<dyn Future<Output = Result<Option<Bytes>>> + Send + 'static>>
        });
        self.handler = Some(handler);
        self
    }

    /// Build the protocol
    ///
    /// # Errors
    /// Returns an error if no handler was set
    pub fn build(self) -> Result<ClosureProtocol> {
        let handler = self
            .handler
            .ok_or_else(|| anyhow::anyhow!("handler must be set before building"))?;
        Ok(ClosureProtocol {
            protocol_id: self.protocol_id,
            stream_type: self.stream_type,
            handler,
        })
    }
}

/// A protocol implementation backed by a closure
pub struct ClosureProtocol {
    protocol_id: String,
    stream_type: Option<u8>,
    handler: ProtocolHandlerFn,
}

#[async_trait]
impl Protocol for ClosureProtocol {
    fn protocol_id(&self) -> &str {
        &self.protocol_id
    }

    fn stream_type(&self) -> Option<u8> {
        self.stream_type
    }

    async fn handle(&self, peer_id: &str, data: Bytes) -> Result<Option<Bytes>> {
        (self.handler)(peer_id, data).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestProtocol;

    #[async_trait]
    impl Protocol for TestProtocol {
        fn protocol_id(&self) -> &str {
            "test/v1"
        }

        async fn handle(&self, peer_id: &str, data: Bytes) -> Result<Option<Bytes>> {
            // Echo with peer_id prefix
            let mut response = peer_id.as_bytes().to_vec();
            response.push(b':');
            response.extend_from_slice(&data);
            Ok(Some(Bytes::from(response)))
        }
    }

    #[tokio::test]
    async fn test_protocol_trait() {
        let protocol = TestProtocol;

        assert_eq!(protocol.protocol_id(), "test/v1");
        assert_eq!(protocol.stream_type(), None);

        let response = protocol
            .handle("peer1", Bytes::from_static(b"hello"))
            .await
            .unwrap();

        assert_eq!(response, Some(Bytes::from_static(b"peer1:hello")));
    }

    #[tokio::test]
    async fn test_protocol_builder() {
        let protocol = ProtocolBuilder::new("echo/v1")
            .stream_type(42)
            .handler(|_peer_id, data| async move { Ok(Some(data)) })
            .build()
            .unwrap();

        assert_eq!(protocol.protocol_id(), "echo/v1");
        assert_eq!(protocol.stream_type(), Some(42));

        let response = protocol
            .handle("peer1", Bytes::from_static(b"test"))
            .await
            .unwrap();

        assert_eq!(response, Some(Bytes::from_static(b"test")));
    }

    #[tokio::test]
    async fn test_no_response_protocol() {
        let protocol = ProtocolBuilder::new("sink/v1")
            .handler(|_peer_id, _data| async move { Ok(None) })
            .build()
            .unwrap();

        let response = protocol
            .handle("peer1", Bytes::from_static(b"ignored"))
            .await
            .unwrap();

        assert_eq!(response, None);
    }
}
