// Thread management for Slack-style message threading

use super::MessageStore;
use super::types::*;
use crate::identity::FourWordAddress;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Manages message threads
pub struct ThreadManager {
    _store: MessageStore,
    /// Cache of active threads
    thread_cache: Arc<RwLock<HashMap<ThreadId, ThreadView>>>,
    /// User's thread subscriptions
    subscriptions: Arc<RwLock<HashSet<ThreadId>>>,
}

impl ThreadManager {
    /// Create a new thread manager
    pub fn new(store: MessageStore) -> Self {
        Self {
            _store: store,
            thread_cache: Arc::new(RwLock::new(HashMap::new())),
            subscriptions: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Create a new thread from a message
    pub async fn create_thread(&self, parent_message: &RichMessage) -> Result<ThreadId> {
        let thread_id = ThreadId::new();

        // Create thread view
        let thread_view = ThreadView {
            parent_message: parent_message.clone(),
            replies: Vec::new(),
            participants: vec![parent_message.sender.clone()],
            is_following: true,
            unread_count: 0,
            last_activity: parent_message.created_at,
        };

        // Cache the thread
        let mut cache = self.thread_cache.write().await;
        cache.insert(thread_id, thread_view);

        // Subscribe to thread
        let mut subs = self.subscriptions.write().await;
        subs.insert(thread_id);

        Ok(thread_id)
    }

    /// Add a message to a thread
    pub async fn add_to_thread(&self, thread_id: ThreadId, message: &RichMessage) -> Result<()> {
        let mut cache = self.thread_cache.write().await;

        if let Some(thread) = cache.get_mut(&thread_id) {
            // Add reply
            thread.replies.push(message.clone());

            // Update participants
            if !thread.participants.contains(&message.sender) {
                thread.participants.push(message.sender.clone());
            }

            // Update last activity
            thread.last_activity = message.created_at;

            // Update parent message thread count
            // In production, this would update the parent message in storage
        } else {
            // Thread not in cache, fetch from storage
            let thread = self.fetch_thread(thread_id).await?;
            cache.insert(thread_id, thread);
        }

        Ok(())
    }

    /// Update thread metadata
    pub async fn update_thread(&self, thread_id: ThreadId, message: &RichMessage) -> Result<()> {
        self.add_to_thread(thread_id, message).await
    }

    /// Get a thread by ID
    pub async fn get_thread(&self, thread_id: ThreadId) -> Result<ThreadView> {
        // Check cache first
        let cache = self.thread_cache.read().await;
        if let Some(thread) = cache.get(&thread_id) {
            return Ok(thread.clone());
        }
        drop(cache);

        // Fetch from storage
        let thread = self.fetch_thread(thread_id).await?;

        // Update cache
        let mut cache = self.thread_cache.write().await;
        cache.insert(thread_id, thread.clone());

        Ok(thread)
    }

    /// Get all threads for a channel
    pub async fn get_channel_threads(&self, channel_id: ChannelId) -> Result<Vec<ThreadSummary>> {
        // In production, this would query storage for all threads in a channel
        let cache = self.thread_cache.read().await;
        let threads: Vec<ThreadSummary> = cache
            .values()
            .filter(|t| t.parent_message.channel_id == channel_id)
            .map(ThreadSummary::from)
            .collect();

        Ok(threads)
    }

    /// Mark thread as read
    pub async fn mark_thread_read(&self, thread_id: ThreadId) -> Result<()> {
        let mut cache = self.thread_cache.write().await;
        if let Some(thread) = cache.get_mut(&thread_id) {
            thread.unread_count = 0;
        }
        Ok(())
    }

    /// Follow/unfollow a thread
    pub async fn set_following(&self, thread_id: ThreadId, following: bool) -> Result<()> {
        let mut subs = self.subscriptions.write().await;

        if following {
            subs.insert(thread_id);
        } else {
            subs.remove(&thread_id);
        }

        // Update thread view
        let mut cache = self.thread_cache.write().await;
        if let Some(thread) = cache.get_mut(&thread_id) {
            thread.is_following = following;
        }

        Ok(())
    }

    /// Get user's followed threads
    pub async fn get_followed_threads(&self) -> Result<Vec<ThreadId>> {
        let subs = self.subscriptions.read().await;
        Ok(subs.iter().copied().collect())
    }

    /// Resolve/close a thread
    pub async fn resolve_thread(&self, thread_id: ThreadId) -> Result<()> {
        // Mark thread as resolved
        // In production, this would update storage
        log::info!("Thread {:?} resolved", thread_id);
        Ok(())
    }

    /// Fetch thread from storage
    async fn fetch_thread(&self, _thread_id: ThreadId) -> Result<ThreadView> {
        // In production, this would query the DHT/database
        // For now, return a mock thread
        Ok(ThreadView {
            parent_message: RichMessage::new(
                FourWordAddress::from("system-thread-mock-user"),
                ChannelId::new(),
                MessageContent::Text("Mock thread parent".to_string()),
            ),
            replies: Vec::new(),
            participants: Vec::new(),
            is_following: false,
            unread_count: 0,
            last_activity: Utc::now(),
        })
    }
}

/// Thread summary for list views
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadSummary {
    pub thread_id: ThreadId,
    pub parent_preview: String,
    pub reply_count: u32,
    pub participant_count: u32,
    pub last_activity: DateTime<Utc>,
    pub unread_count: u32,
    pub is_following: bool,
}

impl From<&ThreadView> for ThreadSummary {
    fn from(thread: &ThreadView) -> Self {
        let parent_preview = match &thread.parent_message.content {
            MessageContent::Text(text) => text.chars().take(100).collect(),
            MessageContent::RichText(rich) => rich.raw.chars().take(100).collect(),
            _ => "[Media]".to_string(),
        };

        Self {
            thread_id: thread.parent_message.thread_id.unwrap_or_default(),
            parent_preview,
            reply_count: thread.replies.len() as u32,
            participant_count: thread.participants.len() as u32,
            last_activity: thread.last_activity,
            unread_count: thread.unread_count,
            is_following: thread.is_following,
        }
    }
}

/// Thread notification preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadNotificationPrefs {
    /// Notify on all replies
    pub all_replies: bool,
    /// Only notify when mentioned
    pub mentions_only: bool,
    /// Mute thread completely
    pub muted: bool,
    /// Custom notification sound
    pub custom_sound: Option<String>,
}

impl Default for ThreadNotificationPrefs {
    fn default() -> Self {
        Self {
            all_replies: true,
            mentions_only: false,
            muted: false,
            custom_sound: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_thread_creation() {
        #[allow(unused)]
        let store = super::super::database::DatabaseMessageStore::new(
            super::super::DhtClient::new_mock(),
            None,
        )
        .await
        .unwrap();
        let manager = ThreadManager::new(store);

        let parent = RichMessage::new(
            FourWordAddress::from("alice-bob-charlie-david"),
            ChannelId::new(),
            MessageContent::Text("Start a thread".to_string()),
        );

        let thread_id = manager.create_thread(&parent).await.unwrap();
        let thread = manager.get_thread(thread_id).await.unwrap();

        assert_eq!(thread.parent_message.id, parent.id);
        assert_eq!(thread.replies.len(), 0);
        assert_eq!(thread.participants.len(), 1);
        assert!(thread.is_following);
    }

    #[tokio::test]
    async fn test_thread_replies() {
        #[allow(unused)]
        let store = super::super::database::DatabaseMessageStore::new(
            super::super::DhtClient::new_mock(),
            None,
        )
        .await
        .unwrap();
        let manager = ThreadManager::new(store);

        let parent = RichMessage::new(
            FourWordAddress::from("alice-bob-charlie-david"),
            ChannelId::new(),
            MessageContent::Text("Start a thread".to_string()),
        );

        let thread_id = manager.create_thread(&parent).await.unwrap();

        let reply = RichMessage::new(
            FourWordAddress::from("eve-frank-grace-henry"),
            parent.channel_id,
            MessageContent::Text("Reply to thread".to_string()),
        );

        manager.add_to_thread(thread_id, &reply).await.unwrap();

        let thread = manager.get_thread(thread_id).await.unwrap();
        assert_eq!(thread.replies.len(), 1);
        assert_eq!(thread.participants.len(), 2);
    }
}
