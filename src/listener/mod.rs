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

//! Unified message listener system for Saorsa Core.
//!
//! This module provides a single interface for receiving messages from all
//! network layers and allows consumers to define custom protocol handlers.
//!
//! # Overview
//!
//! The listener system aggregates messages from:
//! - **P2P Network**: Topic-based publish/subscribe messages
//! - **Transport**: Direct peer-to-peer connections
//! - **DHT**: Distributed hash table operations
//! - **Custom Protocols**: User-defined message handlers
//!
//! # Quick Start
//!
//! ```ignore
//! use saorsa_core::listener::{subscribe_all, MessageSource};
//! use serde::Deserialize;
//!
//! #[derive(Deserialize)]
//! struct ChatMessage {
//!     from: String,
//!     content: String,
//! }
//!
//! // Components auto-register when created, so just subscribe
//! let mut rx = subscribe_all();
//!
//! while let Ok(msg) = rx.recv().await {
//!     match &msg.source {
//!         MessageSource::Network { topic } if topic == "chat" => {
//!             // Decode the raw message using your protocol
//!             let chat: ChatMessage = msg.decode_bincode()?;
//!             println!("{}: {}", chat.from, chat.content);
//!         }
//!         MessageSource::Dht { stream_type } => {
//!             println!("DHT message (type {}): {} bytes", stream_type, msg.message.len());
//!         }
//!         _ => {}
//!     }
//! }
//! ```
//!
//! # Custom Protocols
//!
//! Define your own message handlers by implementing the [`Protocol`] trait:
//!
//! ```ignore
//! use saorsa_core::listener::{Protocol, ProtocolBuilder};
//! use bytes::Bytes;
//! use async_trait::async_trait;
//!
//! // Using the trait directly
//! struct ChatProtocol;
//!
//! #[async_trait]
//! impl Protocol for ChatProtocol {
//!     fn protocol_id(&self) -> &str { "myapp/chat/v1" }
//!
//!     async fn handle(&self, peer: &str, data: Bytes) -> anyhow::Result<Option<Bytes>> {
//!         println!("Chat from {}: {:?}", peer, data);
//!         Ok(None)
//!     }
//! }
//!
//! // Using the builder for simple cases
//! let echo = ProtocolBuilder::new("myapp/echo/v1")
//!     .handler(|_peer, data| async move { Ok(Some(data)) })
//!     .build();
//!
//! listener.register_protocol(ChatProtocol).await?;
//! listener.register_protocol(echo).await?;
//! ```
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
//! │  P2P Node   │  │  Transport  │  │     DHT     │
//! └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
//!        │                │                │
//!        └────────────────┼────────────────┘
//!                         │
//!                         ▼
//!               ┌─────────────────┐
//!               │ UnifiedListener │
//!               │                 │
//!               │  ┌───────────┐  │
//!               │  │ Protocols │  │
//!               │  └───────────┘  │
//!               └────────┬────────┘
//!                        │
//!           ┌────────────┼────────────┐
//!           │            │            │
//!           ▼            ▼            ▼
//!     Subscriber 1  Subscriber 2  Subscriber N
//! ```

mod protocol;
mod types;
mod unified;

// Re-export public types
pub use protocol::{ClosureProtocol, Protocol, ProtocolBuilder};
pub use types::{
    IncomingMessage, MessageSource, RawMessage,
    // DHT stream type constants
    DHT_STREAM_QUERY, DHT_STREAM_REPLICATION, DHT_STREAM_STORE, DHT_STREAM_WITNESS,
};
pub use unified::{ListenerBuilder, MessageInjector, UnifiedListener};

// Global listener functions
pub use unified::{
    global_injector, global_listener, register_dht, register_gossip, register_p2p, subscribe_all,
};

// Re-export event types from connected layers for convenience
pub use crate::adaptive::gossip::{GossipEvent, GossipEventSender, GossipMessage};
pub use crate::transport::dht_handler::DhtStreamEvent;
