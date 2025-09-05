// High-level messaging service API
use super::transport::{DeliveryReceipt, DeliveryStatus, ReceivedMessage};
use super::types::*;
use super::{DhtClient, KeyExchange, MessageStore, MessageTransport};
use crate::identity::FourWordAddress;
use crate::messaging::user_handle::UserHandle;
use anyhow::Result;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tracing::{info, warn};

/// Resolve channel members to their FourWordAddress recipients
/// This maps channel member user_ids to their FourWordAddress representation
pub async fn channel_recipients(_channel_id: &ChannelId) -> Result<Vec<FourWordAddress>> {
    // Load channel metadata from storage/database
    // Note: This is a placeholder implementation that should be connected to
    // the actual channel storage system (e.g., ChatManager)

    // For now, we'll return an empty list. In production, this would:
    // 1. Load channel from storage
    // 2. Get member list
    // 3. Map each member's user_id to their FourWordAddress
    // 4. Return the list of addresses

    // Example production implementation:
    // let channel = chat_manager.get_channel(channel_id).await?;
    // let mut recipients = Vec::new();
    // for member_id in channel.members {
    //     if let Ok(addr) = FourWordAddress::from_user_id(&member_id) {
    //         recipients.push(addr);
    //     }
    // }
    // Ok(recipients)

    // TODO: Integrate with actual channel storage
    Ok(Vec::new())
}

/// High-level messaging service that coordinates all messaging components
pub struct MessagingService {
    /// Local user identity
    identity: FourWordAddress,
    /// Message store for persistence
    store: MessageStore,
    /// Transport layer for network communication
    transport: Arc<MessageTransport>,
    /// Key exchange for E2E encryption
    key_exchange: Arc<KeyExchange>,
    /// DHT client for distributed storage
    _dht_client: DhtClient,
    /// Message event broadcaster
    event_tx: broadcast::Sender<ReceivedMessage>,
    /// Online users tracking
    online_users: Arc<RwLock<HashMap<FourWordAddress, chrono::DateTime<Utc>>>>,
}

/// Options for sending messages
#[derive(Debug, Clone, Default)]
pub struct SendOptions {
    pub ephemeral: bool,
    pub expiry_seconds: Option<u64>,
    pub reply_to: Option<MessageId>,
    pub thread_id: Option<ThreadId>,
    pub attachments: Vec<Attachment>,
}

impl MessagingService {
    /// Create a new messaging service
    pub async fn new(identity: FourWordAddress, dht_client: DhtClient) -> Result<Self> {
        // Initialize components
        let store = MessageStore::new(dht_client.clone(), None).await?;

        // Create mock network for testing
        #[cfg(test)]
        let network = Arc::new(crate::network::P2PNode::new_for_tests()?);

        #[cfg(not(test))]
        let network = {
            // Use a real P2P node with defaults for production wiring
            let config = crate::network::NodeConfig::new()?;
            let node = crate::network::P2PNode::new(config).await?;
            Arc::new(node)
        };
        let transport = Arc::new(MessageTransport::new(network, dht_client.clone()).await?);
        let key_exchange = Arc::new(KeyExchange::new(identity.clone(), dht_client.clone()).await?);

        let (event_tx, _) = broadcast::channel(1000);

        Ok(Self {
            identity,
            store,
            transport,
            key_exchange,
            _dht_client: dht_client,
            event_tx,
            online_users: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Send a message to recipients
    pub async fn send_message(
        &self,
        recipients: Vec<FourWordAddress>,
        content: MessageContent,
        channel_id: ChannelId,
        options: SendOptions,
    ) -> Result<(MessageId, DeliveryReceipt)> {
        // Create rich message
        let mut message = RichMessage::new(
            UserHandle::from(self.identity.to_string()),
            channel_id,
            content,
        );

        // Apply options
        message.ephemeral = options.ephemeral;
        if let Some(seconds) = options.expiry_seconds {
            message.expires_at = Some(Utc::now() + Duration::seconds(seconds as i64));
        }
        message.reply_to = options.reply_to;
        message.thread_id = options.thread_id;
        message.attachments = options.attachments;

        // Store locally first
        self.store.store_message(&message).await?;

        // Encrypt for each recipient
        let mut delivery_results = Vec::new();

        for recipient in &recipients {
            // Get or establish encryption key
            let encryption_key = match self.key_exchange.get_session_key(recipient).await {
                Ok(key) => key,
                Err(e) => {
                    // Attempt to initiate PQC key exchange; if unavailable, error out
                    let _ = self.key_exchange.initiate_exchange(recipient.clone()).await;
                    return Err(anyhow::anyhow!(
                        "No session key established for {}: {}",
                        recipient,
                        e
                    ));
                }
            };

            // Encrypt message
            let encrypted = self
                .encrypt_message_with_key(&message, &encryption_key)
                .await?;

            // Send via transport
            match self
                .transport
                .send_message(&encrypted, vec![recipient.clone()])
                .await
            {
                Ok(_receipt) => {
                    delivery_results.push((recipient.clone(), DeliveryStatus::Queued));
                }
                Err(e) => {
                    warn!("Failed to send to {}: {}", recipient, e);
                    delivery_results
                        .push((recipient.clone(), DeliveryStatus::Failed(e.to_string())));
                }
            }
        }

        // Create delivery receipt
        let receipt = DeliveryReceipt {
            message_id: message.id,
            timestamp: Utc::now(),
            delivery_status: delivery_results,
        };

        info!(
            "Sent message {} to {} recipients",
            message.id,
            recipients.len()
        );

        Ok((message.id, receipt))
    }

    /// Send a message to a channel
    pub async fn send_message_to_channel(
        &self,
        channel_id: ChannelId,
        content: MessageContent,
        options: SendOptions,
    ) -> Result<(MessageId, DeliveryReceipt)> {
        // Resolve recipients from channel members
        let recipients = channel_recipients(&channel_id).await?;

        if recipients.is_empty() {
            return Err(anyhow::anyhow!(
                "No recipients found for channel {}",
                channel_id
            ));
        }

        // Call existing send_message with resolved recipients
        self.send_message(recipients, content, channel_id, options)
            .await
    }

    /// Subscribe to incoming messages
    pub async fn subscribe_messages(
        &self,
        channel_filter: Option<ChannelId>,
    ) -> broadcast::Receiver<ReceivedMessage> {
        let rx = self.event_tx.subscribe();

        // Start message receiver if not already running
        let transport = self.transport.clone();
        let event_tx = self.event_tx.clone();
        let key_exchange = self.key_exchange.clone();
        let store = self.store.clone();

        tokio::spawn(async move {
            let mut receiver = transport.receive_messages().await;

            while let Ok(received) = receiver.recv().await {
                // Decrypt message
                if let Ok(decrypted) =
                    Self::decrypt_received_message(&received.message, &key_exchange).await
                {
                    // Store in database
                    let _ = store.store_message(&decrypted).await;

                    // Apply channel filter if specified
                    if let Some(filter) = channel_filter
                        && decrypted.channel_id != filter
                    {
                        continue;
                    }

                    // Broadcast to subscribers
                    let _ = event_tx.send(ReceivedMessage {
                        message: received.message,
                        received_at: received.received_at,
                    });
                }
            }
        });

        rx
    }

    /// Get message delivery status
    pub async fn get_message_status(&self, message_id: MessageId) -> Result<DeliveryStatus> {
        // Check local confirmations first
        // In production, this would query the transport layer's confirmation tracking

        // For now, check if message exists in store
        if let Ok(_msg) = self.store.get_message(message_id).await {
            // Check if delivered (simplified logic)
            let online = self.online_users.read().await;
            if !online.is_empty() {
                Ok(DeliveryStatus::Delivered(Utc::now()))
            } else {
                Ok(DeliveryStatus::Queued)
            }
        } else {
            Ok(DeliveryStatus::Failed("Message not found".to_string()))
        }
    }

    /// Retrieve a message by ID
    pub async fn get_message(&self, message_id: MessageId) -> Result<RichMessage> {
        self.store.get_message(message_id).await
    }

    /// Mark a user as online
    pub async fn mark_user_online(&self, user: FourWordAddress) -> Result<()> {
        let mut online = self.online_users.write().await;
        online.insert(user, Utc::now());
        Ok(())
    }

    /// Mark message as delivered
    pub async fn mark_delivered(
        &self,
        message_id: MessageId,
        recipient: FourWordAddress,
    ) -> Result<()> {
        // Update delivery status in store
        if let Ok(mut msg) = self.store.get_message(message_id).await {
            msg.delivered_to.insert(
                crate::messaging::user_resolver::resolve_handle(&recipient),
                Utc::now(),
            );
            self.store.update_message(&msg).await?;
        }
        Ok(())
    }

    /// Process queued messages
    pub async fn process_message_queue(&self) -> Result<()> {
        // Trigger transport layer queue processing
        self.transport.process_message_queue().await;
        Ok(())
    }

    /// Encrypt a message for a recipient
    pub async fn encrypt_message(
        &self,
        recipient: FourWordAddress,
        channel_id: ChannelId,
        content: MessageContent,
    ) -> Result<EncryptedMessage> {
        let message = RichMessage::new(
            UserHandle::from(self.identity.to_string()),
            channel_id,
            content,
        );

        // Get encryption key
        let key = self
            .key_exchange
            .get_session_key(&recipient)
            .await
            .unwrap_or_else(|_| vec![0u8; 32]); // Placeholder

        self.encrypt_message_with_key(&message, &key).await
    }

    /// Decrypt a message
    pub async fn decrypt_message(&self, encrypted: EncryptedMessage) -> Result<RichMessage> {
        Self::decrypt_received_message(&encrypted, &self.key_exchange).await
    }

    // Helper: Encrypt message with key
    async fn encrypt_message_with_key(
        &self,
        message: &RichMessage,
        key: &[u8],
    ) -> Result<EncryptedMessage> {
        use saorsa_pqc::{ChaCha20Poly1305Cipher, SymmetricKey};

        let plaintext = serde_json::to_vec(message)?;
        let mut k = [0u8; 32];
        if key.len() != 32 {
            return Err(anyhow::anyhow!("Invalid session key length"));
        }
        k.copy_from_slice(&key[..32]);
        let sk = SymmetricKey::from_bytes(k);
        let cipher = ChaCha20Poly1305Cipher::new(&sk);
        let (ciphertext, nonce) = cipher
            .encrypt(&plaintext, None)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        Ok(EncryptedMessage {
            id: message.id,
            channel_id: message.channel_id,
            sender: self.identity.clone(),
            ciphertext,
            nonce: nonce.to_vec(),
            key_id: format!("key_{}", self.identity),
        })
    }

    // Helper: Decrypt received message
    async fn decrypt_received_message(
        encrypted: &EncryptedMessage,
        key_exchange: &Arc<KeyExchange>,
    ) -> Result<RichMessage> {
        use saorsa_pqc::{ChaCha20Poly1305Cipher, SymmetricKey};

        // Get decryption key
        let key = key_exchange
            .get_session_key(&encrypted.sender)
            .await
            .map_err(|e| anyhow::anyhow!("No session key for {}: {}", encrypted.sender, e))?;
        if key.len() != 32 {
            return Err(anyhow::anyhow!("Invalid session key length"));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&key[..32]);
        let sk = SymmetricKey::from_bytes(k);
        let cipher = ChaCha20Poly1305Cipher::new(&sk);
        // Convert Vec<u8> nonce back to [u8; 12] array
        if encrypted.nonce.len() != 12 {
            return Err(anyhow::anyhow!(
                "Invalid nonce length: expected 12, got {}",
                encrypted.nonce.len()
            ));
        }
        let mut nonce_array = [0u8; 12];
        nonce_array.copy_from_slice(&encrypted.nonce);

        let plaintext = cipher
            .decrypt(&encrypted.ciphertext, &nonce_array, None)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        // Deserialize
        let message: RichMessage = serde_json::from_slice(&plaintext)?;

        Ok(message)
    }

    // Test helpers
    #[cfg(test)]
    pub fn create_test_message(
        &self,
        sender: UserHandle,
        channel_id: ChannelId,
        content: MessageContent,
    ) -> RichMessage {
        RichMessage::new(sender, channel_id, content)
    }

    #[cfg(test)]
    pub async fn inject_test_message(&self, message: RichMessage) -> Result<()> {
        self.store.store_message(&message).await?;

        // Create encrypted version for event
        let encrypted = EncryptedMessage {
            id: message.id,
            channel_id: message.channel_id,
            sender: self.identity.clone(),
            ciphertext: vec![],
            nonce: vec![],
            key_id: "test".to_string(),
        };

        let _ = self.event_tx.send(ReceivedMessage {
            message: encrypted,
            received_at: Utc::now(),
        });

        Ok(())
    }
}

// Use mock implementations from mocks module
// These are now properly implemented in mocks.rs
