// Message search and filtering capabilities

use super::MessageStore;
use super::types::*;
use super::user_handle::UserHandle;
use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Message search engine with advanced filtering
pub struct MessageSearch {
    store: MessageStore,
    /// Search index cache
    search_index: Arc<RwLock<SearchIndex>>,
    /// Recent searches for quick access
    recent_searches: Arc<RwLock<Vec<SearchQuery>>>,
}

impl MessageSearch {
    /// Create new search engine
    pub async fn new(store: MessageStore) -> Result<Self> {
        let search_index = SearchIndex::new();

        Ok(Self {
            store,
            search_index: Arc::new(RwLock::new(search_index)),
            recent_searches: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Search messages with query
    pub async fn search(&self, query: SearchQuery) -> Result<Vec<RichMessage>> {
        // Add to recent searches
        self.add_to_recent(query.clone()).await;

        // Build search filters
        let filters = self.build_filters(&query);

        // Search in index first
        let message_ids = self.search_index(&query, &filters).await?;

        // Fetch full messages
        let mut messages = Vec::new();
        for id in message_ids {
            if let Ok(msg) = self.store.get_message(id).await
                && self.matches_query(&msg, &query, &filters)
            {
                messages.push(msg);
            }
        }

        // Sort by relevance and date
        messages.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        // Apply limit
        messages.truncate(query.limit);

        Ok(messages)
    }

    /// Quick search with just text
    pub async fn quick_search(&self, text: String, limit: usize) -> Result<Vec<RichMessage>> {
        let query = SearchQuery {
            text: Some(text),
            from: None,
            in_channels: None,
            has_attachments: None,
            has_reactions: None,
            is_thread: None,
            date_range: None,
            limit,
        };

        self.search(query).await
    }

    /// Search within a specific channel
    pub async fn search_channel(
        &self,
        channel_id: ChannelId,
        text: Option<String>,
        limit: usize,
    ) -> Result<Vec<RichMessage>> {
        let query = SearchQuery {
            text,
            from: None,
            in_channels: Some(vec![channel_id]),
            has_attachments: None,
            has_reactions: None,
            is_thread: None,
            date_range: None,
            limit,
        };

        self.search(query).await
    }

    /// Search messages from specific users
    pub async fn search_from_users(
        &self,
        users: Vec<UserHandle>,
        text: Option<String>,
        limit: usize,
    ) -> Result<Vec<RichMessage>> {
        let query = SearchQuery {
            text,
            from: Some(users),
            in_channels: None,
            has_attachments: None,
            has_reactions: None,
            is_thread: None,
            date_range: None,
            limit,
        };

        self.search(query).await
    }

    /// Search for messages with attachments
    pub async fn search_attachments(
        &self,
        mime_type: Option<String>,
        limit: usize,
    ) -> Result<Vec<RichMessage>> {
        let query = SearchQuery {
            text: mime_type,
            from: None,
            in_channels: None,
            has_attachments: Some(true),
            has_reactions: None,
            is_thread: None,
            date_range: None,
            limit,
        };

        self.search(query).await
    }

    /// Advanced search with regex
    pub async fn regex_search(&self, pattern: &str, limit: usize) -> Result<Vec<RichMessage>> {
        let regex = Regex::new(pattern)?;

        // Search with pattern
        let query = SearchQuery {
            text: Some(pattern.to_string()),
            from: None,
            in_channels: None,
            has_attachments: None,
            has_reactions: None,
            is_thread: None,
            date_range: None,
            limit: limit * 2, // Get more for regex filtering
        };

        let mut messages = self.search(query).await?;

        // Filter with regex
        messages.retain(|msg| match &msg.content {
            MessageContent::Text(text) => regex.is_match(text),
            MessageContent::RichText(rich) => regex.is_match(&rich.raw),
            _ => false,
        });

        messages.truncate(limit);
        Ok(messages)
    }

    /// Get search suggestions based on partial input
    pub async fn get_suggestions(&self, partial: &str) -> Result<Vec<SearchSuggestion>> {
        let mut suggestions = Vec::new();

        // Suggest recent searches
        let recent = self.recent_searches.read().await;
        for query in recent.iter() {
            if let Some(text) = &query.text
                && text.starts_with(partial)
            {
                suggestions.push(SearchSuggestion {
                    text: text.clone(),
                    category: SuggestionCategory::Recent,
                    icon: "🕐".to_string(),
                });
            }
        }

        // Suggest users (from index)
        let index = self.search_index.read().await;
        for user in &index.known_users {
            let user_str = user.to_string();
            if user_str.contains(partial) {
                suggestions.push(SearchSuggestion {
                    text: format!("from:{}", user_str),
                    category: SuggestionCategory::User,
                    icon: "👤".to_string(),
                });
            }
        }

        // Suggest channels
        for channel in &index.known_channels {
            suggestions.push(SearchSuggestion {
                text: format!("in:channel-{}", channel.0),
                category: SuggestionCategory::Channel,
                icon: "#".to_string(),
            });
        }

        // Common search operators
        if "has:".starts_with(partial) {
            suggestions.push(SearchSuggestion {
                text: "has:attachment".to_string(),
                category: SuggestionCategory::Filter,
                icon: "📎".to_string(),
            });
            suggestions.push(SearchSuggestion {
                text: "has:reaction".to_string(),
                category: SuggestionCategory::Filter,
                icon: "😊".to_string(),
            });
        }

        Ok(suggestions)
    }

    /// Get recent searches
    pub async fn get_recent_searches(&self) -> Vec<SearchQuery> {
        let recent = self.recent_searches.read().await;
        recent.clone()
    }

    /// Clear search history
    pub async fn clear_history(&self) -> Result<()> {
        let mut recent = self.recent_searches.write().await;
        recent.clear();
        Ok(())
    }

    /// Update search index with new message
    pub async fn index_message(&self, message: &RichMessage) -> Result<()> {
        let mut index = self.search_index.write().await;
        index.add_message(message);
        Ok(())
    }

    /// Build search filters from query
    fn build_filters(&self, query: &SearchQuery) -> SearchFilters {
        SearchFilters {
            text_tokens: query
                .text
                .as_ref()
                .map(|t| t.split_whitespace().map(|s| s.to_lowercase()).collect())
                .unwrap_or_default(),
            from_users: query.from.clone().unwrap_or_default(),
            channels: query.in_channels.clone().unwrap_or_default(),
            has_attachments: query.has_attachments,
            has_reactions: query.has_reactions,
            is_thread: query.is_thread,
            date_range: query.date_range.clone(),
        }
    }

    /// Search in index
    async fn search_index(
        &self,
        query: &SearchQuery,
        _filters: &SearchFilters,
    ) -> Result<Vec<MessageId>> {
        let index = self.search_index.read().await;

        let mut results = Vec::new();

        // Text search in index
        if let Some(text) = &query.text
            && let Some(msg_ids) = index.text_index.get(&text.to_lowercase())
        {
            results.extend(msg_ids.iter().copied());
        }

        // If no text query, get all messages for filtering
        if results.is_empty() && query.text.is_none() {
            // In production, this would query from storage with filters
            // For now, return empty
        }

        Ok(results)
    }

    /// Check if message matches query
    fn matches_query(
        &self,
        message: &RichMessage,
        _query: &SearchQuery,
        filters: &SearchFilters,
    ) -> bool {
        // Check text match
        if !filters.text_tokens.is_empty() {
            let content_text = match &message.content {
                MessageContent::Text(t) => t.clone(),
                MessageContent::RichText(r) => r.raw.clone(),
                _ => String::new(),
            };

            let content_lower = content_text.to_lowercase();
            if !filters
                .text_tokens
                .iter()
                .all(|token| content_lower.contains(token))
            {
                return false;
            }
        }

        // Check sender
        if !filters.from_users.is_empty()
            && !filters.from_users.contains(&message.sender)
        {
            return false;
        }

        // Check channel
        if !filters.channels.is_empty() && !filters.channels.contains(&message.channel_id) {
            return false;
        }

        // Check attachments
        if let Some(has_attach) = filters.has_attachments
            && has_attach == message.attachments.is_empty()
        {
            return false;
        }

        // Check reactions
        if let Some(has_react) = filters.has_reactions
            && has_react == message.reactions.is_empty()
        {
            return false;
        }

        // Check thread
        if let Some(is_thread) = filters.is_thread
            && is_thread != message.thread_id.is_some()
        {
            return false;
        }

        // Check date range
        if let Some(range) = &filters.date_range
            && (message.created_at < range.start || message.created_at > range.end)
        {
            return false;
        }

        true
    }

    /// Add to recent searches
    async fn add_to_recent(&self, query: SearchQuery) {
        let mut recent = self.recent_searches.write().await;

        // Remove duplicates
        recent.retain(|q| q.text != query.text);

        // Add to front
        recent.insert(0, query);

        // Keep only last 10
        recent.truncate(10);
    }
}

/// Search index for fast lookups
struct SearchIndex {
    /// Text to message IDs mapping
    text_index: HashMap<String, HashSet<MessageId>>,
    /// Known users for suggestions
    known_users: HashSet<UserHandle>,
    /// Known channels for suggestions
    known_channels: HashSet<ChannelId>,
}

impl SearchIndex {
    fn new() -> Self {
        Self {
            text_index: HashMap::new(),
            known_users: HashSet::new(),
            known_channels: HashSet::new(),
        }
    }

    fn add_message(&mut self, message: &RichMessage) {
        // Index text content
        let text = match &message.content {
            MessageContent::Text(t) => t.clone(),
            MessageContent::RichText(r) => r.raw.clone(),
            _ => String::new(),
        };

        // Tokenize and index
        for word in text.split_whitespace() {
            let token = word.to_lowercase();
            self.text_index.entry(token).or_default().insert(message.id);
        }

        // Track users and channels
        self.known_users.insert(message.sender.clone());
        self.known_channels.insert(message.channel_id);
    }
}

/// Search filters
struct SearchFilters {
    text_tokens: Vec<String>,
    from_users: Vec<UserHandle>,
    channels: Vec<ChannelId>,
    has_attachments: Option<bool>,
    has_reactions: Option<bool>,
    is_thread: Option<bool>,
    date_range: Option<DateRange>,
}

/// Search suggestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchSuggestion {
    pub text: String,
    pub category: SuggestionCategory,
    pub icon: String,
}

/// Suggestion category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SuggestionCategory {
    Recent,
    User,
    Channel,
    Filter,
    Command,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_search_creation() {
        #[allow(unused)]
        let store = super::super::database::DatabaseMessageStore::new(
            super::super::DhtClient::new_mock(),
            None,
        )
        .await
        .unwrap();
        let search = MessageSearch::new(store).await.unwrap();

        let recent = search.get_recent_searches().await;
        assert_eq!(recent.len(), 0);
    }

    #[tokio::test]
    async fn test_quick_search() {
        #[allow(unused)]
        let store = super::super::database::DatabaseMessageStore::new(
            super::super::DhtClient::new_mock(),
            None,
        )
        .await
        .unwrap();
        let search = MessageSearch::new(store).await.unwrap();

        let results = search.quick_search("test".to_string(), 10).await.unwrap();
        assert_eq!(results.len(), 0); // No messages indexed yet
    }

    #[tokio::test]
    async fn test_search_suggestions() {
        #[allow(unused)]
        let store = super::super::database::DatabaseMessageStore::new(
            super::super::DhtClient::new_mock(),
            None,
        )
        .await
        .unwrap();
        let search = MessageSearch::new(store).await.unwrap();

        let suggestions = search.get_suggestions("has").await.unwrap();
        assert!(suggestions.iter().any(|s| s.text == "has:attachment"));
        assert!(suggestions.iter().any(|s| s.text == "has:reaction"));
    }
}
