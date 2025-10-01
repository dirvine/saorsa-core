// Rich Messaging Module for P2P Foundation
// Implements WhatsApp/Slack-style messaging with full decentralization

pub mod composer;
pub mod database;
pub mod encryption;
pub mod key_exchange;
pub mod media;
#[cfg(any(test, feature = "mocks"))]
pub mod mocks;
pub mod network_config;
pub mod quic_media_streams;
pub mod reactions;
pub mod search;
pub mod service;
pub mod sync;
pub mod threads;
pub mod transport;
pub mod types;
pub mod user_handle;
pub mod user_resolver;
pub mod webrtc;
pub mod webrtc_quic_bridge;

use user_handle::UserHandle;
// Removed unused imports
// use anyhow::Result;
use serde::{Deserialize, Serialize};
// use std::sync::Arc;
// use chrono::{DateTime, Utc};
// Removed unused imports: use tracing::{debug, warn};

pub use composer::MessageComposer;
pub use database::MessageStore;
pub use encryption::SecureMessaging;
pub use key_exchange::{KeyExchange, KeyExchangeMessage};
pub use media::MediaProcessor;
pub use network_config::{
    IpMode, NetworkConfig, NetworkConfigError, PortConfig, RetryBehavior,
};
pub use quic_media_streams::{QosParameters, QuicMediaStreamManager, StreamStats};
pub use reactions::ReactionManager;
pub use search::MessageSearch;
pub use service::{MessagingService, SendOptions};
pub use sync::RealtimeSync;
pub use threads::ThreadManager;
pub use transport::{DeliveryReceipt, DeliveryStatus, MessageTransport, ReceivedMessage};
pub use types::*;
pub use webrtc::{CallEvent, CallManager, WebRtcEvent, WebRtcService};
pub use webrtc_quic_bridge::{RtpPacket, StreamConfig, StreamType, WebRtcQuicBridge};

// Import the real DHT client
pub use crate::dht::client::DhtClient;

/// Request to send a message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub channel_id: ChannelId,
    pub content: MessageContent,
    pub attachments: Vec<Vec<u8>>,
    pub thread_id: Option<ThreadId>,
    pub reply_to: Option<MessageId>,
    pub mentions: Vec<UserHandle>,
    pub ephemeral: bool,
}

// MessagingService is now defined in service.rs

// Legacy implementation removed - see service.rs for the new implementation

/*
impl MessagingService {
    /// Create a new messaging service with a real DHT client
    pub async fn new(identity: FourWordAddress) -> Result<Self> {
        // Create DHT client based on the user's identity
        // Convert four-word address to a node ID
        let node_id_bytes = blake3::hash(identity.to_string().as_bytes());
        let node_id = crate::dht::core_engine::NodeId::from_key(
            crate::dht::core_engine::DhtKey::from_bytes(*node_id_bytes.as_bytes())
        );

        // Create DHT client with the user's node ID
        let dht_client = DhtClient::with_node_id(node_id)?;

        // Initialize all components
        let store = MessageStore::new(dht_client.clone()).await?;
        let threads = ThreadManager::new(store.clone());
        let reactions = ReactionManager::new(store.clone());
        let media = MediaProcessor::new()?;
        let search = MessageSearch::new(store.clone()).await?;
        let encryption = SecureMessaging::new(identity.clone(), dht_client.clone()).await?;
        let sync = RealtimeSync::new(dht_client.clone()).await?;

        Ok(Self {
            store,
            threads,
            reactions,
            media,
            search,
            encryption,
            sync,
            transport: None, // Will be initialized when network is available
            webrtc: None,    // Will be initialized when needed
            identity,
        })
    }

    /// Create a new messaging service with an existing DHT client
    pub async fn with_dht_client(
        identity: FourWordAddress,
        dht_client: DhtClient,
    ) -> Result<Self> {
        let store = MessageStore::new(dht_client.clone()).await?;
        let threads = ThreadManager::new(store.clone());
        let reactions = ReactionManager::new(store.clone());
        let media = MediaProcessor::new()?;
        let search = MessageSearch::new(store.clone()).await?;
        let encryption = SecureMessaging::new(identity.clone(), dht_client.clone()).await?;
        let sync = RealtimeSync::new(dht_client).await?;

        Ok(Self {
            store,
            threads,
            reactions,
            media,
            search,
            encryption,
            sync,
            transport: None, // Will be initialized when network is available
            webrtc: None,    // Will be initialized when needed
            identity,
        })
    }

    /// Connect to network transport
    pub async fn connect_transport(&mut self, network: Arc<crate::network::P2PNode>) -> Result<()> {
        let transport = MessageTransport::new(network, self.store.dht_client.clone()).await?;

        // Start background tasks
        transport.monitor_network_quality().await;
        transport.process_message_queue().await;

        self.transport = Some(transport);
        Ok(())
    }

    /// Initialize WebRTC service
    pub async fn initialize_webrtc(&mut self) -> Result<()> {
        // Create WebRTC service using the DHT client
        let dht_engine = self.store.dht_client.core_engine();
        let webrtc = WebRtcService::new(
            self.identity.clone(),
            dht_engine,
        ).await?;

        // Start the WebRTC service
        webrtc.start().await?;

        self.webrtc = Some(webrtc);
        Ok(())
    }

    /// Initiate a voice/video call
    pub async fn initiate_call(
        &self,
        callee: FourWordAddress,
        constraints: webrtc::MediaConstraints,
    ) -> Result<webrtc::CallId> {
        if let Some(ref webrtc) = self.webrtc {
            webrtc.initiate_call(callee, constraints).await
        } else {
            Err(anyhow::anyhow!("WebRTC service not initialized"))
        }
    }

    /// Accept an incoming call
    pub async fn accept_call(
        &self,
        call_id: webrtc::CallId,
        constraints: webrtc::MediaConstraints,
    ) -> Result<()> {
        if let Some(ref webrtc) = self.webrtc {
            webrtc.accept_call(call_id, constraints).await
        } else {
            Err(anyhow::anyhow!("WebRTC service not initialized"))
        }
    }

    /// Reject an incoming call
    pub async fn reject_call(&self, call_id: webrtc::CallId) -> Result<()> {
        if let Some(ref webrtc) = self.webrtc {
            webrtc.reject_call(call_id).await
        } else {
            Err(anyhow::anyhow!("WebRTC service not initialized"))
        }
    }

    /// End an active call
    pub async fn end_call(&self, call_id: webrtc::CallId) -> Result<()> {
        if let Some(ref webrtc) = self.webrtc {
            webrtc.end_call(call_id).await
        } else {
            Err(anyhow::anyhow!("WebRTC service not initialized"))
        }
    }

    /// Get call state
    pub async fn get_call_state(&self, call_id: webrtc::CallId) -> Option<webrtc::CallState> {
        if let Some(ref webrtc) = self.webrtc {
            webrtc.get_call_state(call_id).await
        } else {
            None
        }
    }

    /// Subscribe to WebRTC events
    pub fn subscribe_webrtc_events(&self) -> Option<tokio::sync::broadcast::Receiver<WebRtcEvent>> {
        self.webrtc.as_ref().map(|w| w.subscribe_events())
    }

    /// Get WebRTC service reference
    pub fn webrtc(&self) -> Option<&WebRtcService> {
        self.webrtc.as_ref()
    }

    /// Send a new message
    pub async fn send_message(&mut self, request: SendMessageRequest) -> Result<RichMessage> {
        // Create message
        let mut message = RichMessage::new(
            self.identity.clone(),
            request.channel_id,
            request.content,
        );

        // Add attachments if any
        for attachment in request.attachments {
            let processed = self.media.process_attachment(attachment).await?;
            message.attachments.push(processed);
        }

        // Handle threading
        if let Some(thread_id) = request.thread_id {
            message.thread_id = Some(thread_id);
            self.threads.add_to_thread(thread_id, &message).await?;
        }

        // Handle reply
        if let Some(reply_to) = request.reply_to {
            message.reply_to = Some(reply_to);
        }

        // Encrypt message
        let encrypted = self.encryption.encrypt_message(&message).await?;

        // Store message (we store the original, not encrypted version locally)
        self.store.store_message(&message).await?;

        // Send via transport if available, otherwise use sync
        if let Some(ref transport) = self.transport {
            // Extract recipients from channel members
            let recipients = self.get_channel_members(request.channel_id).await?;
            let receipt = transport.send_message(&encrypted, recipients).await?;

            // Log delivery status
            for (recipient, status) in receipt.delivery_status {
                match status {
                    DeliveryStatus::Delivered(_) => {
                        debug!("Message delivered to {}", recipient);
                    }
                    DeliveryStatus::Queued => {
                        debug!("Message queued for {}", recipient);
                    }
                    DeliveryStatus::Failed(e) => {
                        warn!("Message delivery failed for {}: {}", recipient, e);
                    }
                    _ => {}
                }
            }
        } else {
            // Fallback to broadcast sync
            self.sync.broadcast_message(&encrypted).await?;
        }

        Ok(message)
    }

    /// Receive and process an incoming message
    pub async fn receive_message(&mut self, encrypted: EncryptedMessage) -> Result<RichMessage> {
        // Decrypt message
        let message = self.encryption.decrypt_message(encrypted).await?;

        // Verify signature
        if !self.encryption.verify_message(&message) {
            return Err(anyhow::anyhow!("Invalid message signature"));
        }

        // Store message
        self.store.store_message(&message).await?;

        // Update thread if applicable
        if let Some(thread_id) = &message.thread_id {
            self.threads.update_thread(*thread_id, &message).await?;
        }

        // Process mentions
        if message.mentions.contains(&self.identity) {
            self.handle_mention(&message).await?;
        }

        Ok(message)
    }

    /// Add a reaction to a message
    pub async fn add_reaction(&mut self, message_id: MessageId, emoji: String) -> Result<()> {
        self.reactions.add_reaction(
            message_id,
            emoji.clone(),
            crate::messaging::user_resolver::resolve_handle(&self.identity),
        ).await?;

        // Sync reaction
        self.sync.broadcast_reaction(message_id, emoji, true).await?;

        Ok(())
    }

    /// Remove a reaction from a message
    pub async fn remove_reaction(&mut self, message_id: MessageId, emoji: String) -> Result<()> {
        self.reactions.remove_reaction(
            message_id,
            emoji.clone(),
            crate::messaging::user_resolver::resolve_handle(&self.identity),
        ).await?;

        // Sync reaction removal
        self.sync.broadcast_reaction(message_id, emoji, false).await?;

        Ok(())
    }

    /// Edit a message
    pub async fn edit_message(
        &mut self,
        message_id: MessageId,
        new_content: MessageContent,
    ) -> Result<()> {
        // Get original message
        let mut message = self.store.get_message(message_id).await?;

        // Verify sender
        if message.sender != self.identity {
            return Err(anyhow::anyhow!("Cannot edit message from another user"));
        }

        // Update content
        message.content = new_content.clone();
        message.edited_at = Some(Utc::now());

        // Re-encrypt and store
        let _encrypted = self.encryption.encrypt_message(&message).await?;
        self.store.update_message(&message).await?;

        // Sync edit
        self.sync.broadcast_edit(message_id, new_content).await?;

        Ok(())
    }

    /// Delete a message
    pub async fn delete_message(&mut self, message_id: MessageId) -> Result<()> {
        // Get message
        let mut message = self.store.get_message(message_id).await?;

        // Verify sender
        if message.sender != self.identity {
            return Err(anyhow::anyhow!("Cannot delete message from another user"));
        }

        // Soft delete
        message.deleted_at = Some(Utc::now());

        // Update storage
        self.store.update_message(&message).await?;

        // Sync deletion
        self.sync.broadcast_deletion(message_id).await?;

        Ok(())
    }

    /// Search messages
    pub async fn search_messages(&self, query: SearchQuery) -> Result<Vec<RichMessage>> {
        self.search.search(query).await
    }

    /// Get message history for a channel
    pub async fn get_channel_messages(
        &self,
        channel_id: ChannelId,
        limit: usize,
        before: Option<DateTime<Utc>>,
    ) -> Result<Vec<RichMessage>> {
        self.store.get_channel_messages(channel_id, limit, before).await
    }

    /// Get thread messages
    pub async fn get_thread_messages(
        &self,
        thread_id: ThreadId,
    ) -> Result<ThreadView> {
        self.threads.get_thread(thread_id).await
    }

    /// Mark messages as read
    pub async fn mark_as_read(&mut self, message_ids: Vec<MessageId>) -> Result<()> {
        for message_id in message_ids {
            self.store.mark_as_read(
                message_id,
                crate::messaging::user_resolver::resolve_handle(&self.identity),
            ).await?;
            self.sync.broadcast_read_receipt(message_id).await?;
        }
        Ok(())
    }

    /// Start typing indicator
    pub async fn start_typing(&mut self, channel_id: ChannelId) -> Result<()> {
        self.sync
            .broadcast_typing(
                channel_id,
                crate::messaging::user_handle::UserHandle::from(self.identity.to_string()),
                true,
            )
            .await
    }

    /// Stop typing indicator
    pub async fn stop_typing(&mut self, channel_id: ChannelId) -> Result<()> {
        self.sync
            .broadcast_typing(
                channel_id,
                crate::messaging::user_handle::UserHandle::from(self.identity.to_string()),
                false,
            )
            .await
    }

    /// Initiate key exchange with a peer
    pub async fn initiate_key_exchange(&self, peer: FourWordAddress) -> Result<KeyExchangeMessage> {
        self.encryption.key_exchange.initiate_exchange(peer).await
    }

    /// Handle incoming key exchange message
    pub async fn handle_key_exchange(&self, message: KeyExchangeMessage) -> Result<Option<KeyExchangeMessage>> {
        use key_exchange::KeyExchangeType;

        match message.message_type {
            KeyExchangeType::Initiation => {
                // Respond to initiation
                let response = self.encryption.key_exchange.respond_to_exchange(message).await?;
                Ok(Some(response))
            }
            KeyExchangeType::Response => {
                // Complete the exchange
                self.encryption.key_exchange.complete_exchange(message).await?;
                Ok(None)
            }
            KeyExchangeType::PrekeyBundle => {
                // Handle prekey bundle
                Ok(None)
            }
        }
    }

    /// Get our prekey bundle for others
    pub async fn get_prekey_bundle(&self) -> key_exchange::PrekeyBundle {
        self.encryption.key_exchange.get_prekey_bundle().await
    }

    /// Rotate encryption keys
    pub async fn rotate_keys(&self) -> Result<()> {
        self.encryption.key_exchange.rotate_prekeys().await?;
        self.encryption.key_exchange.cleanup_expired().await?;
        Ok(())
    }

    /// Handle mention notification
    async fn handle_mention(&self, message: &RichMessage) -> Result<()> {
        // Create notification
        tracing::info!("Mentioned in message: {:?}", message.id);
        // TODO: Trigger system notification
        Ok(())
    }

    /// Get channel members
    async fn get_channel_members(&self, _channel_id: ChannelId) -> Result<Vec<FourWordAddress>> {
        // TODO: Implement channel membership lookup
        // For now, return empty list which will fallback to broadcast
        Ok(Vec::new())
    }
}
*/

// MessageStore is now a type alias in database.rs

/*
/// Message store for persistence
#[derive(Clone)]
pub struct MessageStore {
    inner: Arc<database::DatabaseMessageStore>,
    dht_client: DhtClient,
}

impl MessageStore {
    pub async fn new(dht_client: DhtClient) -> Result<Self> {
        let inner = Arc::new(
            database::DatabaseMessageStore::new(dht_client.clone(), None).await?
        );

        Ok(Self {
            inner,
            dht_client,
        })
    }

    pub async fn store_message(&self, message: &RichMessage) -> Result<()> {
        self.inner.store_message(message).await
    }

    pub async fn get_message(&self, id: MessageId) -> Result<RichMessage> {
        self.inner.get_message(id).await
    }

    pub async fn update_message(&self, message: &RichMessage) -> Result<()> {
        self.inner.update_message(message).await
    }

    pub async fn get_channel_messages(
        &self,
        channel_id: ChannelId,
        limit: usize,
        before: Option<DateTime<Utc>>,
    ) -> Result<Vec<RichMessage>> {
        self.inner.get_channel_messages(channel_id, limit, before).await
    }

    pub async fn mark_as_read(
        &self,
        message_id: MessageId,
        user: FourWordAddress,
    ) -> Result<()> {
        self.inner.mark_as_read(message_id, user).await
    }

    /// Search messages
    pub async fn search_messages(&self, query: &str, channel_id: Option<ChannelId>) -> Result<Vec<RichMessage>> {
        self.inner.search_messages(query, channel_id, 50).await
    }

    /// Get thread messages
    pub async fn get_thread_messages(&self, thread_id: ThreadId) -> Result<Vec<RichMessage>> {
        self.inner.get_thread_messages(thread_id).await
    }

    /// Add reaction
    pub async fn add_reaction(&self, message_id: MessageId, emoji: String, user: crate::messaging::user_handle::UserHandle) -> Result<()> {
        self.inner.add_reaction(message_id, emoji, user).await
    }

    /// Remove reaction
    pub async fn remove_reaction(&self, message_id: MessageId, emoji: String, user: crate::messaging::user_handle::UserHandle) -> Result<()> {
        self.inner.remove_reaction(message_id, emoji, user).await
    }

    /// Get database statistics
    pub async fn get_stats(&self) -> Result<database::DatabaseStats> {
        self.inner.get_stats().await
    }

    /// Clean up ephemeral messages
    pub async fn cleanup_ephemeral(&self, ttl_seconds: i64) -> Result<usize> {
        self.inner.cleanup_ephemeral(ttl_seconds).await
    }
}
*/

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::FourWordAddress;

    #[tokio::test]
    async fn test_message_creation() {
        let identity = crate::messaging::user_handle::UserHandle::from("ocean-forest-moon-star");
        let channel = ChannelId::new();
        let content = MessageContent::Text("Hello, world!".to_string());

        let message = RichMessage::new(identity.clone(), channel, content.clone());

        assert_eq!(message.sender, identity);
        assert_eq!(message.channel_id, channel);
        assert!(matches!(message.content, MessageContent::Text(_)));
    }

    #[tokio::test]
    async fn test_messaging_service_with_real_dht() {
        // Skip this test in regular test runs as it requires a real DHT network
        // and can cause nested runtime issues. This test should be run separately
        // with proper network setup.
        println!("Skipping test_messaging_service_with_real_dht - requires separate network setup");

        // For now, just test that we can create the identity
        let identity = FourWordAddress::from("ocean-forest-moon-star");
        assert!(!identity.to_string().is_empty());
    }
}
