// High-level messaging service API
use super::transport::{DeliveryReceipt, DeliveryStatus, ReceivedMessage};
use super::types::*;
use super::{DhtClient, KeyExchange, MessageStore, MessageTransport};
use crate::control::ControlMessageHandler;
use crate::identity::FourWordAddress;
use crate::identity::restart::RestartManager;
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
    /// Create a new messaging service with default configuration
    ///
    /// Uses OS-assigned port (port 0) by default to avoid port conflicts.
    /// This is the recommended way to create a MessagingService for most use cases.
    ///
    /// # Example
    /// ```no_run
    /// # use saorsa_core::messaging::{MessagingService, DhtClient};
    /// # use saorsa_core::identity::FourWordAddress;
    /// # async fn example() -> anyhow::Result<()> {
    /// let dht = DhtClient::new()?;
    /// let address = FourWordAddress("test-user-one-alpha".to_string());
    /// let service = MessagingService::new(address, dht).await?;
    ///
    /// // Get actual bound port
    /// let addrs = service.listen_addrs().await;
    /// println!("Listening on: {:?}", addrs);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(identity: FourWordAddress, dht_client: DhtClient) -> Result<Self> {
        // Use default NetworkConfig (OS-assigned port, IPv4-only)
        Self::new_with_config(identity, dht_client, super::NetworkConfig::default()).await
    }

    /// Create a new messaging service with custom network configuration
    ///
    /// This allows fine-grained control over port binding, IP mode, and retry behavior.
    ///
    /// # Arguments
    /// * `identity` - Four-word address for this node
    /// * `dht_client` - DHT client for distributed operations
    /// * `config` - Network configuration (port, IP mode, retry behavior)
    ///
    /// # Example with OS-Assigned Port
    /// ```no_run
    /// # use saorsa_core::messaging::{MessagingService, DhtClient, NetworkConfig};
    /// # use saorsa_core::identity::FourWordAddress;
    /// # async fn example() -> anyhow::Result<()> {
    /// let dht = DhtClient::new()?;
    /// let address = FourWordAddress("test-user-one-alpha".to_string());
    ///
    /// // Use default config (OS-assigned port)
    /// let config = NetworkConfig::default();
    /// let service = MessagingService::new_with_config(address, dht, config).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Example with Explicit Port
    /// ```rust,ignore
    /// use saorsa_core::messaging::{MessagingService, DhtClient, NetworkConfig, PortConfig, IpMode, RetryBehavior};
    /// use saorsa_core::identity::FourWordAddress;
    ///
    /// async fn example() -> anyhow::Result<()> {
    ///     let dht = DhtClient::new()?;
    ///     let address = FourWordAddress("test-user-two-alpha".to_string());
    ///
    ///     // Use explicit port with NAT traversal
    ///     let config = NetworkConfig {
    ///         port: PortConfig::Explicit(12345),
    ///         ip_mode: IpMode::IPv4Only,
    ///         retry_behavior: RetryBehavior::FailFast,
    ///         nat_traversal: None,
    ///     };
    ///     let service = MessagingService::new_with_config(address, dht, config).await?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Note
    /// Currently, only `PortConfig::OsAssigned` and `PortConfig::Explicit` are fully supported.
    /// Full configuration support (port ranges, dual-stack separate ports) requires ant-quic 0.10.0.
    pub async fn new_with_config(
        identity: FourWordAddress,
        dht_client: DhtClient,
        config: super::NetworkConfig,
    ) -> Result<Self> {
        // Log NAT traversal configuration
        match &config.nat_traversal {
            Some(super::NatTraversalMode::P2PNode { concurrency_limit }) => {
                info!(
                    "Initializing MessagingService with P2P NAT traversal (concurrency limit: {})",
                    concurrency_limit
                );
            }
            Some(super::NatTraversalMode::ClientOnly) => {
                info!("Initializing MessagingService with client-only NAT traversal");
            }
            Some(super::NatTraversalMode::Advanced {
                concurrency_limit,
                max_candidates,
                enable_symmetric_nat,
                ..
            }) => {
                info!(
                    "Initializing MessagingService with advanced NAT traversal (concurrency: {}, max_candidates: {}, symmetric_nat: {})",
                    concurrency_limit, max_candidates, enable_symmetric_nat
                );
            }
            None => {
                warn!("Initializing MessagingService with NAT traversal disabled");
            }
        }

        // Initialize components
        let store = MessageStore::new(dht_client.clone(), None).await?;

        // Create mock network for testing
        #[cfg(test)]
        let network = Arc::new(crate::network::P2PNode::new_for_tests()?);

        #[cfg(not(test))]
        let network = {
            // Convert NetworkConfig to NodeConfig
            let mut node_config = crate::network::NodeConfig::new()?;

            // Apply port configuration
            match &config.port {
                super::PortConfig::OsAssigned => {
                    // Use port 0 for OS-assigned
                    let bind_addr = std::net::SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        0, // Port 0 = OS-assigned
                    );
                    node_config.listen_addr = bind_addr;
                    node_config.listen_addrs = vec![bind_addr];
                }
                super::PortConfig::Explicit(port) => {
                    // Use explicit port
                    let bind_addr = match &config.ip_mode {
                        super::IpMode::IPv6Only => std::net::SocketAddr::new(
                            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                            *port,
                        ),
                        _ => std::net::SocketAddr::new(
                            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                            *port,
                        ),
                    };
                    node_config.listen_addr = bind_addr;
                    node_config.listen_addrs = vec![bind_addr];
                }
                super::PortConfig::Range(start, _end) => {
                    // For now, use the start of the range
                    // Full range support requires ant-quic 0.10.0
                    warn!(
                        "Port range configuration not fully supported yet, using port {}",
                        start
                    );
                    let bind_addr = std::net::SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        *start,
                    );
                    node_config.listen_addr = bind_addr;
                    node_config.listen_addrs = vec![bind_addr];
                }
            }

            // Apply IP mode configuration
            match &config.ip_mode {
                super::IpMode::IPv4Only => {
                    node_config.enable_ipv6 = false;
                }
                super::IpMode::IPv6Only => {
                    node_config.enable_ipv6 = true;
                    // Only include IPv6 address
                    let port = node_config.listen_addr.port();
                    node_config.listen_addrs = vec![std::net::SocketAddr::new(
                        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                        port,
                    )];
                }
                super::IpMode::DualStack => {
                    node_config.enable_ipv6 = true;
                    // Add both IPv4 and IPv6
                    let port = node_config.listen_addr.port();
                    node_config.listen_addrs = vec![
                        std::net::SocketAddr::new(
                            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                            port,
                        ),
                        std::net::SocketAddr::new(
                            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                            port,
                        ),
                    ];
                }
                super::IpMode::DualStackSeparate {
                    ipv4_port,
                    ipv6_port,
                } => {
                    // Separate ports for IPv4 and IPv6
                    node_config.enable_ipv6 = true;

                    let ipv4_port_num = match ipv4_port {
                        super::PortConfig::OsAssigned => 0,
                        super::PortConfig::Explicit(p) => *p,
                        super::PortConfig::Range(start, _) => *start,
                    };

                    let ipv6_port_num = match ipv6_port {
                        super::PortConfig::OsAssigned => 0,
                        super::PortConfig::Explicit(p) => *p,
                        super::PortConfig::Range(start, _) => *start,
                    };

                    node_config.listen_addrs = vec![
                        std::net::SocketAddr::new(
                            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                            ipv4_port_num,
                        ),
                        std::net::SocketAddr::new(
                            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                            ipv6_port_num,
                        ),
                    ];

                    // Set primary listen_addr to IPv4
                    node_config.listen_addr = node_config.listen_addrs[0];
                }
            }

            let node = crate::network::P2PNode::new(node_config).await?;
            node.start().await?;
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

    /// Enable restart management for this service
    ///
    /// This integrates the RestartManager to handle network rejections and identity regeneration.
    pub async fn enable_restart_management(&self, restart_manager: Arc<RestartManager>) {
        let handler = Arc::new(ControlMessageHandler::new(restart_manager));
        let events = self.transport.network().subscribe_events();
        handler.start(events).await;
        info!("Restart management enabled for MessagingService");
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
                Err(_) => {
                    // Initiate PQC key exchange
                    info!("No session key for {}, initiating key exchange", recipient);
                    let kex_msg = self
                        .key_exchange
                        .initiate_exchange(recipient.clone())
                        .await?;

                    // Send the key exchange message
                    self.transport
                        .send_key_exchange_message(recipient, kex_msg)
                        .await?;

                    // Wait for session establishment with timeout
                    let wait_result = tokio::time::timeout(
                        tokio::time::Duration::from_secs(5),
                        self.wait_for_session_key(recipient),
                    )
                    .await;

                    match wait_result {
                        Ok(Ok(key)) => {
                            info!("Key exchange completed for {}", recipient);
                            key
                        }
                        Ok(Err(e)) => {
                            return Err(anyhow::anyhow!(
                                "Key exchange failed for {}: {}",
                                recipient,
                                e
                            ));
                        }
                        Err(_) => {
                            return Err(anyhow::anyhow!("Key exchange timeout for {}", recipient));
                        }
                    }
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

        // Spawn message receiver task
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

        // Spawn key exchange handler task
        let transport_kex = self.transport.clone();
        let key_exchange_kex = self.key_exchange.clone();
        tokio::spawn(async move {
            let mut kex_receiver = transport_kex.subscribe_key_exchange();

            while let Ok(kex_msg) = kex_receiver.recv().await {
                use super::key_exchange::KeyExchangeType;

                match kex_msg.message_type {
                    KeyExchangeType::Initiation => {
                        // Received key exchange initiation - respond
                        info!("Received key exchange initiation from {}", kex_msg.sender);
                        match key_exchange_kex.respond_to_exchange(kex_msg).await {
                            Ok(response) => {
                                // Send response back
                                let recipient = response.recipient.clone();
                                if let Err(e) = transport_kex
                                    .send_key_exchange_message(&recipient, response)
                                    .await
                                {
                                    warn!(
                                        "Failed to send key exchange response to {}: {}",
                                        recipient, e
                                    );
                                }
                            }
                            Err(e) => {
                                warn!("Failed to respond to key exchange: {}", e);
                            }
                        }
                    }
                    KeyExchangeType::Response => {
                        // Received key exchange response - complete
                        info!("Received key exchange response from {}", kex_msg.sender);
                        if let Err(e) = key_exchange_kex.complete_exchange(kex_msg).await {
                            warn!("Failed to complete key exchange: {}", e);
                        }
                    }
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

    /// Get messages for a channel with pagination
    ///
    /// # Arguments
    /// * `channel_id` - The channel to retrieve messages from
    /// * `limit` - Maximum number of messages to return
    /// * `before` - Optional timestamp to get messages before (for pagination)
    ///
    /// # Returns
    /// Vector of messages ordered by creation time (newest first)
    pub async fn get_channel_messages(
        &self,
        channel_id: ChannelId,
        limit: usize,
        before: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<RichMessage>> {
        self.store
            .get_channel_messages(channel_id, limit, before)
            .await
    }

    /// Get all messages in a thread
    ///
    /// # Arguments
    /// * `thread_id` - The thread to retrieve messages from
    ///
    /// # Returns
    /// Vector of all messages in the thread
    pub async fn get_thread_messages(&self, thread_id: ThreadId) -> Result<Vec<RichMessage>> {
        self.store.get_thread_messages(thread_id).await
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

    // ===== P2P Networking Methods =====

    /// Get the local network address(es) this node is listening on
    pub async fn listen_addrs(&self) -> Vec<std::net::SocketAddr> {
        self.transport.listen_addrs().await
    }

    /// Get the list of currently connected peer IDs
    pub async fn connected_peers(&self) -> Vec<String> {
        self.transport
            .connected_peers()
            .await
            .into_iter()
            .map(|peer_id| peer_id.to_string())
            .collect()
    }

    /// Get the count of currently connected peers
    pub async fn peer_count(&self) -> usize {
        self.transport.peer_count().await
    }

    /// Check if the P2P node is running
    pub async fn is_running(&self) -> bool {
        // If we have a transport, we're running
        // The transport is created during initialization and stays active
        true
    }

    /// Connect to a peer via their network address
    ///
    /// # Arguments
    /// * `address` - Network address in format "ip:port" or "[ipv6]:port"
    ///
    /// # Returns
    /// The peer ID of the connected peer
    pub async fn connect_peer(&self, address: &str) -> Result<String> {
        let peer_id = self.transport.connect_peer(address).await?;
        Ok(peer_id.to_string())
    }

    /// Disconnect from a specific peer
    ///
    /// # Arguments
    /// * `peer_id` - The peer ID to disconnect from
    pub async fn disconnect_peer(&self, peer_id: &str) -> Result<()> {
        // Parse peer ID from string
        let peer_id_parsed = peer_id
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid peer ID: {}", e))?;
        self.transport.disconnect_peer(&peer_id_parsed).await
    }

    /// Wait for a session key to be established with a peer
    ///
    /// Polls the key exchange system for up to the specified duration.
    /// This is called after initiating key exchange to wait for the response.
    async fn wait_for_session_key(&self, peer: &FourWordAddress) -> Result<Vec<u8>> {
        // Poll with exponential backoff
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100));
        let max_attempts = 50; // 5 seconds total (100ms * 50)

        for _ in 0..max_attempts {
            interval.tick().await;

            if let Ok(key) = self.key_exchange.get_session_key(peer).await {
                return Ok(key);
            }
        }

        Err(anyhow::anyhow!(
            "Session key not established within timeout"
        ))
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
