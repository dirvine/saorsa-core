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

//! Unified message sender system for Saorsa Core.
//!
//! This module provides a single interface for sending messages through all
//! network layers, symmetric to the [`listener`](crate::listener) module.
//!
//! # Overview
//!
//! The sender system provides a unified interface for sending messages via:
//! - **P2P Network**: Unicast to specific peers or broadcast to all connected
//! - **GossipSub**: Publish/subscribe message delivery
//!
//! # Quick Start
//!
//! ```ignore
//! use saorsa_core::sender::{global_sender, MessageDestination, MessageEncoder};
//! use serde::Serialize;
//!
//! #[derive(Serialize)]
//! struct ChatMessage {
//!     from: String,
//!     content: String,
//! }
//!
//! // Create and encode a message
//! let msg = ChatMessage {
//!     from: "alice".into(),
//!     content: "Hello!".into(),
//! };
//! let payload = MessageEncoder::bincode(&msg)?;
//!
//! // Send to a specific peer
//! global_sender().send(
//!     MessageDestination::Network { peer_id: peer.into(), topic: "chat".into() },
//!     payload.clone(),
//! ).await?;
//!
//! // Or broadcast to all connected peers
//! global_sender().broadcast("announcements", payload.clone()).await?;
//!
//! // Or publish via GossipSub
//! global_sender().gossip("events", payload).await?;
//! ```
//!
//! # Delivery Tracking
//!
//! For reliable delivery with retries:
//!
//! ```ignore
//! use saorsa_core::sender::{global_sender, MessageDestination, MessageEncoder, DeliveryTracking};
//! use std::time::Duration;
//!
//! let payload = MessageEncoder::json(&my_data)?;
//! let tracking = DeliveryTracking {
//!     require_ack: true,
//!     timeout: Duration::from_secs(30),
//!     retry_policy: RetryPolicy::with_max_retries(3),
//! };
//!
//! let msg_id = global_sender().send_tracked(
//!     MessageDestination::Network { peer_id: peer.into(), topic: "important".into() },
//!     payload,
//!     tracking,
//! ).await?;
//!
//! // Monitor delivery events
//! let mut events = global_sender().subscribe_delivery();
//! while let Ok(event) = events.recv().await {
//!     match event {
//!         DeliveryEvent::Delivered { message_id, .. } if message_id == msg_id => {
//!             println!("Message delivered!");
//!             break;
//!         }
//!         DeliveryEvent::Failed { message_id, error, .. } if message_id == msg_id => {
//!             println!("Delivery failed: {}", error);
//!             break;
//!         }
//!         _ => {}
//!     }
//! }
//! ```
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      Application                             │
//! └────────────────────────┬────────────────────────────────────┘
//!                          │
//!                          ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    UnifiedSender                             │
//! │                                                              │
//! │  send() ────► MessageDestination ────► Transport Selection   │
//! │                                                              │
//! │  ┌─────────────────┬───────────────────┬─────────────────┐  │
//! │  │  MessageEncoder │  DeliveryTracking │  RetryManager   │  │
//! │  │  (bincode/json) │  (ack/timeout)    │  (background)   │  │
//! │  └─────────────────┴───────────────────┴─────────────────┘  │
//! └────────────────────────┬────────────────────────────────────┘
//!                          │
//!           ┌──────────────┼──────────────┐
//!           │              │              │
//!           ▼              ▼              ▼
//!      ┌─────────┐   ┌─────────┐   ┌─────────────┐
//!      │   P2P   │   │   P2P   │   │  GossipSub  │
//!      │ Unicast │   │Broadcast│   │   Publish   │
//!      └─────────┘   └─────────┘   └─────────────┘
//! ```

mod encoder;
mod retry;
mod types;
mod unified;

// Re-export public types
pub use encoder::MessageEncoder;
pub use types::{
    DeliveryEvent, DeliveryTracking, EncodedPayload, EncodingType, MessageDestination, MessageId,
    RetryPolicy,
};
pub use unified::{SenderBuilder, UnifiedSender};

// Global sender functions
pub use unified::{
    broadcast_message, global_sender, gossip_message, send_message, sender_register_gossip,
    sender_register_p2p,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all expected types are exported
        let _ = MessageDestination::gossip("test");
        let _ = EncodedPayload::raw(vec![1, 2, 3]);
        let _ = DeliveryTracking::default();
        let _ = RetryPolicy::default();
        let _ = EncodingType::Bincode;
    }

    #[test]
    fn test_encoder_exports() {
        let payload = MessageEncoder::raw(b"test".to_vec());
        assert_eq!(payload.encoding, EncodingType::Raw);
    }
}
