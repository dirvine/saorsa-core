// Emoji reactions system for messages

use super::MessageStore;
use super::types::*;
use crate::identity::FourWordAddress;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Manages message reactions
pub struct ReactionManager {
    store: MessageStore,
    /// Cache of reactions by message ID
    reaction_cache: Arc<RwLock<HashMap<MessageId, MessageReactions>>>,
    /// Popular emojis for quick access
    popular_emojis: Arc<RwLock<Vec<String>>>,
}

impl ReactionManager {
    /// Create a new reaction manager
    pub fn new(store: MessageStore) -> Self {
        let popular = vec![
            "👍", "❤️", "😂", "😮", "😢", "🔥", "🎉", "👀", "🚀", "💯", "✅", "🙏", "🤔", "👏",
            "😍", "🤝",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        Self {
            store,
            reaction_cache: Arc::new(RwLock::new(HashMap::new())),
            popular_emojis: Arc::new(RwLock::new(popular)),
        }
    }

    /// Add a reaction to a message
    pub async fn add_reaction(
        &self,
        message_id: MessageId,
        emoji: String,
        user: FourWordAddress,
    ) -> Result<()> {
        // Validate emoji
        if !self.is_valid_emoji(&emoji) {
            return Err(anyhow::anyhow!("Invalid emoji"));
        }

        // Use database store directly
        self.store
            .add_reaction(message_id, emoji.clone(), user.clone())
            .await?;

        // Update cache
        let mut cache = self.reaction_cache.write().await;
        let reactions = cache
            .entry(message_id)
            .or_insert_with(|| MessageReactions::new(message_id));
        reactions.add_reaction(emoji.clone(), user.clone());

        // Update popular emojis
        self.update_popular_emoji(&emoji).await;

        Ok(())
    }

    /// Remove a reaction from a message
    pub async fn remove_reaction(
        &self,
        message_id: MessageId,
        emoji: String,
        user: FourWordAddress,
    ) -> Result<()> {
        // Use database store directly
        self.store
            .remove_reaction(message_id, emoji.clone(), user.clone())
            .await?;

        // Update cache
        let mut cache = self.reaction_cache.write().await;
        if let Some(reactions) = cache.get_mut(&message_id) {
            reactions.remove_reaction(&emoji, &user);
        }

        Ok(())
    }

    /// Get all reactions for a message
    pub async fn get_reactions(&self, message_id: MessageId) -> Result<MessageReactions> {
        // Check cache first
        let cache = self.reaction_cache.read().await;
        if let Some(reactions) = cache.get(&message_id) {
            return Ok(reactions.clone());
        }
        drop(cache);

        // Fetch from storage
        let reactions = self.fetch_reactions(message_id).await?;

        // Update cache
        let mut cache = self.reaction_cache.write().await;
        cache.insert(message_id, reactions.clone());

        Ok(reactions)
    }

    /// Get reaction count for a message
    pub async fn get_reaction_count(&self, message_id: MessageId) -> Result<ReactionCount> {
        let reactions = self.get_reactions(message_id).await?;
        Ok(reactions.get_count())
    }

    /// Check if a user has reacted with a specific emoji
    pub async fn has_user_reacted(
        &self,
        message_id: MessageId,
        emoji: &str,
        user: &FourWordAddress,
    ) -> Result<bool> {
        let reactions = self.get_reactions(message_id).await?;
        Ok(reactions.has_user_reacted(emoji, user))
    }

    /// Get popular emojis for quick reaction picker
    pub async fn get_popular_emojis(&self) -> Vec<String> {
        let popular = self.popular_emojis.read().await;
        popular.clone()
    }

    /// Get custom emoji packs
    pub async fn get_custom_emojis(&self) -> Result<Vec<EmojiPack>> {
        // In production, fetch from organization/user settings
        Ok(vec![EmojiPack {
            id: "default".to_string(),
            name: "Default Pack".to_string(),
            emojis: vec![CustomEmoji {
                shortcode: ":thumbsup:".to_string(),
                url: "".to_string(),
                animated: false,
            }],
        }])
    }

    /// Toggle reaction (add if not present, remove if present)
    pub async fn toggle_reaction(
        &self,
        message_id: MessageId,
        emoji: String,
        user: FourWordAddress,
    ) -> Result<bool> {
        let has_reacted = self.has_user_reacted(message_id, &emoji, &user).await?;

        if has_reacted {
            self.remove_reaction(message_id, emoji, user).await?;
            Ok(false)
        } else {
            self.add_reaction(message_id, emoji, user).await?;
            Ok(true)
        }
    }

    /// Validate emoji
    fn is_valid_emoji(&self, emoji: &str) -> bool {
        // Check if it's a valid Unicode emoji or custom emoji shortcode
        emoji.chars().count() > 0 && emoji.chars().count() <= 10
    }

    /// Update popular emoji list based on usage
    async fn update_popular_emoji(&self, emoji: &str) {
        let mut popular = self.popular_emojis.write().await;

        // Remove if exists and add to front
        popular.retain(|e| e != emoji);
        popular.insert(0, emoji.to_string());

        // Keep only top 16
        popular.truncate(16);
    }

    /// Persist reactions to storage
    async fn _persist_reactions(
        &self,
        message_id: MessageId,
        reactions: &MessageReactions,
    ) -> Result<()> {
        // In production, save to DHT/database
        let _key = format!("reactions:{}", message_id.0);
        let _value = serde_json::to_vec(reactions)?;
        // self.store.dht_client.put(key, value).await?;
        Ok(())
    }

    /// Fetch reactions from storage
    async fn fetch_reactions(&self, message_id: MessageId) -> Result<MessageReactions> {
        // In production, fetch from DHT/database
        Ok(MessageReactions::new(message_id))
    }
}

/// Reactions for a single message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageReactions {
    pub message_id: MessageId,
    /// Map of emoji to users who reacted
    pub reactions: HashMap<String, Vec<FourWordAddress>>,
    /// Total reaction count
    pub total_count: u32,
}

impl MessageReactions {
    /// Create new empty reactions
    pub fn new(message_id: MessageId) -> Self {
        Self {
            message_id,
            reactions: HashMap::new(),
            total_count: 0,
        }
    }

    /// Add a reaction
    pub fn add_reaction(&mut self, emoji: String, user: FourWordAddress) {
        let users = self.reactions.entry(emoji).or_default();
        if !users.contains(&user) {
            users.push(user);
            self.total_count += 1;
        }
    }

    /// Remove a reaction
    pub fn remove_reaction(&mut self, emoji: &str, user: &FourWordAddress) {
        if let Some(users) = self.reactions.get_mut(emoji) {
            if let Some(pos) = users.iter().position(|u| u == user) {
                users.remove(pos);
                self.total_count = self.total_count.saturating_sub(1);

                // Remove emoji if no users left
                if users.is_empty() {
                    self.reactions.remove(emoji);
                }
            }
        }
    }

    /// Check if user has reacted with emoji
    pub fn has_user_reacted(&self, emoji: &str, user: &FourWordAddress) -> bool {
        self.reactions
            .get(emoji)
            .map(|users| users.contains(user))
            .unwrap_or(false)
    }

    /// Get reaction count summary
    pub fn get_count(&self) -> ReactionCount {
        let by_emoji: HashMap<String, u32> = self
            .reactions
            .iter()
            .map(|(emoji, users)| (emoji.clone(), users.len() as u32))
            .collect();

        ReactionCount {
            total: self.total_count,
            by_emoji,
        }
    }
}

/// Reaction count summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionCount {
    pub total: u32,
    pub by_emoji: HashMap<String, u32>,
}

/// Custom emoji pack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmojiPack {
    pub id: String,
    pub name: String,
    pub emojis: Vec<CustomEmoji>,
}

/// Custom emoji definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomEmoji {
    pub shortcode: String,
    pub url: String,
    pub animated: bool,
}

/// Reaction event for real-time updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionEvent {
    pub message_id: MessageId,
    pub emoji: String,
    pub user: FourWordAddress,
    pub action: ReactionAction,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Reaction action type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReactionAction {
    Added,
    Removed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_reaction() {
        #[allow(unused)]
        let store = super::super::database::DatabaseMessageStore::new(
            super::super::DhtClient::new_mock(),
            None,
        )
        .await
        .unwrap();
        let manager = ReactionManager::new(store);

        let message_id = MessageId::new();
        let user = FourWordAddress::from("alice-bob-charlie-david");

        manager
            .add_reaction(message_id, "👍".to_string(), user.clone())
            .await
            .unwrap();

        let reactions = manager.get_reactions(message_id).await.unwrap();
        assert!(reactions.has_user_reacted("👍", &user));
        assert_eq!(reactions.total_count, 1);
    }

    #[tokio::test]
    async fn test_toggle_reaction() {
        #[allow(unused)]
        let store = super::super::database::DatabaseMessageStore::new(
            super::super::DhtClient::new_mock(),
            None,
        )
        .await
        .unwrap();
        let manager = ReactionManager::new(store);

        let message_id = MessageId::new();
        let user = FourWordAddress::from("alice-bob-charlie-david");
        let emoji = "❤️".to_string();

        // First toggle - add
        let added = manager
            .toggle_reaction(message_id, emoji.clone(), user.clone())
            .await
            .unwrap();
        assert!(added);

        // Second toggle - remove
        let added = manager
            .toggle_reaction(message_id, emoji.clone(), user.clone())
            .await
            .unwrap();
        assert!(!added);

        let reactions = manager.get_reactions(message_id).await.unwrap();
        assert!(!reactions.has_user_reacted("❤️", &user));
    }

    #[tokio::test]
    async fn test_multiple_reactions() {
        #[allow(unused)]
        let store = super::super::database::DatabaseMessageStore::new(
            super::super::DhtClient::new_mock(),
            None,
        )
        .await
        .unwrap();
        let manager = ReactionManager::new(store);

        let message_id = MessageId::new();
        let user1 = FourWordAddress::from("alice-bob-charlie-david");
        let user2 = FourWordAddress::from("eve-frank-grace-henry");

        manager
            .add_reaction(message_id, "👍".to_string(), user1.clone())
            .await
            .unwrap();
        manager
            .add_reaction(message_id, "👍".to_string(), user2.clone())
            .await
            .unwrap();
        manager
            .add_reaction(message_id, "❤️".to_string(), user1.clone())
            .await
            .unwrap();

        let count = manager.get_reaction_count(message_id).await.unwrap();
        assert_eq!(count.total, 3);
        assert_eq!(count.by_emoji.get("👍"), Some(&2));
        assert_eq!(count.by_emoji.get("❤️"), Some(&1));
    }
}
