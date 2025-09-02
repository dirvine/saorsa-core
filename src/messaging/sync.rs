// Real-time message synchronization

use super::DhtClient;
use super::types::*;
use super::user_handle::UserHandle;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};

/// Real-time sync service for messaging
pub struct RealtimeSync {
    /// DHT client for distributed sync
    _dht_client: DhtClient,
    /// Event broadcaster
    event_tx: broadcast::Sender<SyncEvent>,
    /// Active subscriptions
    subscriptions: Arc<RwLock<HashMap<ChannelId, Subscription>>>,
    /// Presence tracker
    presence: Arc<RwLock<HashMap<UserHandle, UserPresence>>>,
    /// Typing indicators
    typing: Arc<RwLock<HashMap<ChannelId, Vec<TypingUser>>>>,
}

impl RealtimeSync {
    /// Create new sync service
    pub async fn new(dht_client: DhtClient) -> Result<Self> {
        let (event_tx, _) = broadcast::channel(1000);

        Ok(Self {
            _dht_client: dht_client,
            event_tx,
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            presence: Arc::new(RwLock::new(HashMap::new())),
            typing: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Subscribe to channel updates
    pub async fn subscribe_channel(&self, channel_id: ChannelId) -> broadcast::Receiver<SyncEvent> {
        let mut subs = self.subscriptions.write().await;

        subs.insert(
            channel_id,
            Subscription {
                _channel_id: channel_id,
                _subscribed_at: Utc::now(),
                _last_sync: Utc::now(),
            },
        );

        self.event_tx.subscribe()
    }

    /// Unsubscribe from channel
    pub async fn unsubscribe_channel(&self, channel_id: ChannelId) -> Result<()> {
        let mut subs = self.subscriptions.write().await;
        subs.remove(&channel_id);
        Ok(())
    }

    /// Broadcast new message
    pub async fn broadcast_message(&self, message: &EncryptedMessage) -> Result<()> {
        let event = SyncEvent::NewMessage {
            message: message.clone(),
            timestamp: Utc::now(),
        };

        // Broadcast locally
        let _ = self.event_tx.send(event.clone());

        // Sync to DHT
        self.sync_to_dht(message.channel_id, event).await?;

        Ok(())
    }

    /// Broadcast message edit
    pub async fn broadcast_edit(
        &self,
        message_id: MessageId,
        new_content: MessageContent,
    ) -> Result<()> {
        let event = SyncEvent::MessageEdited {
            message_id,
            new_content,
            edited_at: Utc::now(),
        };

        let _ = self.event_tx.send(event.clone());
        // Sync to network

        Ok(())
    }

    /// Broadcast message deletion
    pub async fn broadcast_deletion(&self, message_id: MessageId) -> Result<()> {
        let event = SyncEvent::MessageDeleted {
            message_id,
            deleted_at: Utc::now(),
        };

        let _ = self.event_tx.send(event);
        Ok(())
    }

    /// Broadcast reaction change
    pub async fn broadcast_reaction(
        &self,
        message_id: MessageId,
        emoji: String,
        added: bool,
    ) -> Result<()> {
        let event = if added {
            SyncEvent::ReactionAdded {
                message_id,
                emoji,
                timestamp: Utc::now(),
            }
        } else {
            SyncEvent::ReactionRemoved {
                message_id,
                emoji,
                timestamp: Utc::now(),
            }
        };

        let _ = self.event_tx.send(event);
        Ok(())
    }

    /// Broadcast typing indicator
    pub async fn broadcast_typing(
        &self,
        channel_id: ChannelId,
        user: UserHandle,
        is_typing: bool,
    ) -> Result<()> {
        let mut typing = self.typing.write().await;
        let channel_typing = typing.entry(channel_id).or_insert_with(Vec::new);

        if is_typing {
            // Add to typing list
            let handle = user.clone();
            if !channel_typing.iter().any(|t| t.user == user) {
                channel_typing.push(TypingUser {
                    user: handle,
                    started_at: Utc::now(),
                });
            }
        } else {
            // Remove from typing list
            channel_typing.retain(|t| t.user != user);
        }

        // Broadcast event
        let event = SyncEvent::TypingIndicator {
            channel_id,
            user,
            is_typing,
            timestamp: Utc::now(),
        };

        let _ = self.event_tx.send(event);
        Ok(())
    }

    /// Broadcast read receipt
    pub async fn broadcast_read_receipt(&self, message_id: MessageId) -> Result<()> {
        let event = SyncEvent::ReadReceipt {
            message_id,
            timestamp: Utc::now(),
        };

        let _ = self.event_tx.send(event);
        Ok(())
    }

    /// Update user presence
    pub async fn update_presence(&self, user: UserHandle, status: PresenceStatus) -> Result<()> {
        let mut presence = self.presence.write().await;
        presence.insert(
            user.clone(),
            UserPresence {
                identity: user.clone(),
                status: status.clone(),
                custom_status: None,
                last_seen: Some(Utc::now()),
                typing_in: Vec::new(),
                device: DeviceType::Desktop,
            },
        );

        // Broadcast presence update
        let event = SyncEvent::PresenceUpdate {
            user,
            status,
            timestamp: Utc::now(),
        };

        let _ = self.event_tx.send(event);
        Ok(())
    }

    /// Get current presence for users
    pub async fn get_presence(&self, users: Vec<UserHandle>) -> HashMap<UserHandle, UserPresence> {
        let presence = self.presence.read().await;

        users
            .into_iter()
            .filter_map(|handle| presence.get(&handle).map(|p| (handle, p.clone())))
            .collect()
    }

    /// Sync channel state
    pub async fn sync_channel(&self, channel_id: ChannelId) -> Result<ChannelSyncState> {
        // Fetch latest state from DHT
        let _key = format!("channel:sync:{}", channel_id.0);

        // In production, fetch from DHT
        let state = ChannelSyncState {
            channel_id,
            last_message_id: None,
            last_sync: Utc::now(),
            unread_count: 0,
            mention_count: 0,
        };

        Ok(state)
    }

    /// Handle incoming sync events
    pub async fn handle_sync_event(&self, event: SyncEvent) -> Result<()> {
        // Process event based on type
        match &event {
            SyncEvent::NewMessage { .. } => {
                log::debug!("New message received");
            }
            SyncEvent::TypingIndicator {
                channel_id,
                user,
                is_typing,
                ..
            } => {
                let mut typing = self.typing.write().await;
                let channel_typing = typing.entry(*channel_id).or_insert_with(Vec::new);

                if *is_typing {
                    if !channel_typing.iter().any(|t| t.user == *user) {
                        channel_typing.push(TypingUser {
                            user: user.clone(),
                            started_at: Utc::now(),
                        });
                    }
                } else {
                    channel_typing.retain(|t| t.user != *user);
                }
            }
            _ => {}
        }

        // Broadcast to local subscribers
        let _ = self.event_tx.send(event);

        Ok(())
    }

    /// Clean up stale typing indicators
    pub async fn cleanup_typing(&self) {
        let mut typing = self.typing.write().await;
        let timeout = Utc::now() - chrono::Duration::seconds(10);

        for channel_typing in typing.values_mut() {
            channel_typing.retain(|t| t.started_at > timeout);
        }
    }

    /// Sync to DHT network
    async fn sync_to_dht(&self, channel_id: ChannelId, event: SyncEvent) -> Result<()> {
        let _key = format!("channel:events:{}", channel_id.0);
        let _value = serde_json::to_vec(&event)?;

        // In production, publish to DHT
        // self.dht_client.publish(key, value).await?;

        Ok(())
    }
}

/// Sync event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncEvent {
    NewMessage {
        message: EncryptedMessage,
        timestamp: DateTime<Utc>,
    },
    MessageEdited {
        message_id: MessageId,
        new_content: MessageContent,
        edited_at: DateTime<Utc>,
    },
    MessageDeleted {
        message_id: MessageId,
        deleted_at: DateTime<Utc>,
    },
    ReactionAdded {
        message_id: MessageId,
        emoji: String,
        timestamp: DateTime<Utc>,
    },
    ReactionRemoved {
        message_id: MessageId,
        emoji: String,
        timestamp: DateTime<Utc>,
    },
    TypingIndicator {
        channel_id: ChannelId,
        user: UserHandle,
        is_typing: bool,
        timestamp: DateTime<Utc>,
    },
    ReadReceipt {
        message_id: MessageId,
        timestamp: DateTime<Utc>,
    },
    PresenceUpdate {
        user: UserHandle,
        status: PresenceStatus,
        timestamp: DateTime<Utc>,
    },
}

/// Channel subscription
#[derive(Debug, Clone)]
struct Subscription {
    _channel_id: ChannelId,
    _subscribed_at: DateTime<Utc>,
    _last_sync: DateTime<Utc>,
}

/// Typing user
#[derive(Debug, Clone)]
struct TypingUser {
    user: UserHandle,
    started_at: DateTime<Utc>,
}

/// Channel sync state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSyncState {
    pub channel_id: ChannelId,
    pub last_message_id: Option<MessageId>,
    pub last_sync: DateTime<Utc>,
    pub unread_count: u32,
    pub mention_count: u32,
}

/// Sync conflict resolution
#[derive(Debug, Clone)]
pub enum ConflictResolution {
    /// Use local version
    UseLocal,
    /// Use remote version
    UseRemote,
    /// Merge both versions
    Merge,
    /// Create new version
    Fork,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sync_creation() {
        let dht = super::DhtClient::new_mock();
        let sync = RealtimeSync::new(dht).await.unwrap();

        let channel = ChannelId::new();
        let mut rx = sync.subscribe_channel(channel).await;

        // Should be able to receive events
        assert!(rx.try_recv().is_err()); // No events yet
    }

    #[tokio::test]
    async fn test_typing_indicators() {
        let dht = super::DhtClient::new_mock();
        let sync = RealtimeSync::new(dht).await.unwrap();

        let channel = ChannelId::new();

        // Start typing
        sync.broadcast_typing(channel, UserHandle::from("alice"), true)
            .await
            .unwrap();

        let typing = sync.typing.read().await;
        assert!(typing.get(&channel).is_some());
    }

    #[tokio::test]
    async fn test_presence_update() {
        let dht = super::DhtClient::new_mock();
        let sync = RealtimeSync::new(dht).await.unwrap();

        sync.update_presence(UserHandle::from("alice"), PresenceStatus::Online)
            .await
            .unwrap();

        let user = UserHandle::from("alice");
        let presence = sync.get_presence(vec![user.clone()]).await;

        assert!(presence.contains_key(&user));
    }
}
