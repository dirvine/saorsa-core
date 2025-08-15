// Message composer with rich text editing capabilities

use super::types::*;
use super::SendMessageRequest;
use crate::identity::FourWordAddress;
use anyhow::Result;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Message composer for creating rich messages
pub struct MessageComposer {
    /// Draft messages by channel
    drafts: HashMap<ChannelId, DraftMessage>,
    /// Mention suggestions
    mention_cache: Vec<FourWordAddress>,
    /// Emoji shortcuts
    emoji_shortcuts: HashMap<String, String>,
}

impl Default for MessageComposer {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageComposer {
    /// Create new message composer
    pub fn new() -> Self {
        let mut emoji_shortcuts = HashMap::new();
        emoji_shortcuts.insert(":)".to_string(), "😊".to_string());
        emoji_shortcuts.insert(":D".to_string(), "😃".to_string());
        emoji_shortcuts.insert(":((".to_string(), "😢".to_string());
        emoji_shortcuts.insert("<3".to_string(), "❤️".to_string());
        emoji_shortcuts.insert(":fire:".to_string(), "🔥".to_string());
        emoji_shortcuts.insert(":rocket:".to_string(), "🚀".to_string());
        emoji_shortcuts.insert(":+1:".to_string(), "👍".to_string());
        emoji_shortcuts.insert(":-1:".to_string(), "👎".to_string());
        
        Self {
            drafts: HashMap::new(),
            mention_cache: Vec::new(),
            emoji_shortcuts,
        }
    }
    
    /// Start composing a message
    pub fn start_draft(&mut self, channel_id: ChannelId) -> &mut DraftMessage {
        self.drafts.entry(channel_id).or_insert_with(|| {
            DraftMessage::new(channel_id)
        })
    }
    
    /// Get current draft
    pub fn get_draft(&self, channel_id: ChannelId) -> Option<&DraftMessage> {
        self.drafts.get(&channel_id)
    }
    
    /// Update draft text
    pub fn update_draft(&mut self, channel_id: ChannelId, text: String) {
        let draft = self.start_draft(channel_id);
        draft.text = text;
        draft.update_formatted();
    }
    
    /// Add mention to draft
    pub fn add_mention(&mut self, channel_id: ChannelId, user: FourWordAddress) {
        let draft = self.start_draft(channel_id);
        draft.mentions.push(user.clone());
        
        // Add to text
        let mention_text = format!("@{} ", user);
        draft.text.push_str(&mention_text);
        draft.update_formatted();
    }
    
    /// Add attachment to draft
    pub fn add_attachment(&mut self, channel_id: ChannelId, attachment: DraftAttachment) {
        let draft = self.start_draft(channel_id);
        draft.attachments.push(attachment);
    }
    
    /// Remove attachment from draft
    pub fn remove_attachment(&mut self, channel_id: ChannelId, index: usize) {
        if let Some(draft) = self.drafts.get_mut(&channel_id)
            && index < draft.attachments.len() {
                draft.attachments.remove(index);
            }
    }
    
    /// Set reply target
    pub fn set_reply_to(&mut self, channel_id: ChannelId, message_id: MessageId) {
        let draft = self.start_draft(channel_id);
        draft.reply_to = Some(message_id);
    }
    
    /// Set thread target
    pub fn set_thread(&mut self, channel_id: ChannelId, thread_id: ThreadId) {
        let draft = self.start_draft(channel_id);
        draft.thread_id = Some(thread_id);
    }
    
    /// Clear draft
    pub fn clear_draft(&mut self, channel_id: ChannelId) {
        self.drafts.remove(&channel_id);
    }
    
    /// Get mention suggestions
    pub fn get_mention_suggestions(&self, partial: &str) -> Vec<FourWordAddress> {
        self.mention_cache
            .iter()
            .filter(|user| {
                user.to_string().to_lowercase().contains(&partial.to_lowercase())
            })
            .cloned()
            .collect()
    }
    
    /// Update mention cache
    pub fn update_mention_cache(&mut self, users: Vec<FourWordAddress>) {
        self.mention_cache = users;
    }
    
    /// Apply text formatting
    pub fn apply_formatting(&mut self, channel_id: ChannelId, format: TextFormat) {
        let draft = self.start_draft(channel_id);
        
        match format {
            TextFormat::Bold => {
                draft.text = format!("**{}**", draft.text);
            }
            TextFormat::Italic => {
                draft.text = format!("*{}*", draft.text);
            }
            TextFormat::Code => {
                draft.text = format!("`{}`", draft.text);
            }
            TextFormat::Strike => {
                draft.text = format!("~~{}~~", draft.text);
            }
            TextFormat::Quote => {
                draft.text = format!("> {}", draft.text);
            }
            TextFormat::CodeBlock(lang) => {
                draft.text = format!("```{}\n{}\n```", lang, draft.text);
            }
        }
        
        draft.update_formatted();
    }
    
    /// Insert emoji
    pub fn insert_emoji(&mut self, channel_id: ChannelId, emoji: String) {
        let draft = self.start_draft(channel_id);
        draft.text.push_str(&emoji);
        draft.update_formatted();
    }
    
    /// Convert emoji shortcuts
    pub fn process_shortcuts(&mut self, channel_id: ChannelId) {
        // Clone the shortcuts to avoid borrow conflicts
        let shortcuts = self.emoji_shortcuts.clone();
        
        let draft = self.start_draft(channel_id);
        
        for (shortcut, emoji) in &shortcuts {
            draft.text = draft.text.replace(shortcut, emoji);
        }
        
        draft.update_formatted();
    }
    
    /// Validate draft before sending
    pub fn validate_draft(&self, channel_id: ChannelId) -> Result<()> {
        let draft = self.drafts.get(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("No draft found"))?;
        
        // Check if empty
        if draft.text.trim().is_empty() && draft.attachments.is_empty() {
            return Err(anyhow::anyhow!("Cannot send empty message"));
        }
        
        // Check message length
        if draft.text.len() > 10000 {
            return Err(anyhow::anyhow!("Message too long (max 10000 characters)"));
        }
        
        // Check attachment size
        let total_size: usize = draft.attachments.iter()
            .map(|a| a.size)
            .sum();
        
        if total_size > 100 * 1024 * 1024 {
            return Err(anyhow::anyhow!("Total attachment size exceeds 100MB"));
        }
        
        Ok(())
    }
    
    /// Build message from draft
    pub fn build_message(
        &self,
        channel_id: ChannelId,
        _sender: FourWordAddress,
    ) -> Result<SendMessageRequest> {
        let draft = self.drafts.get(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("No draft found"))?;
        
        // Create message content
        let content = if draft.formatted_text.is_some() {
            MessageContent::RichText(MarkdownContent {
                raw: draft.text.clone(),
                formatted: draft.formatted_text.clone().unwrap_or_default(),
                mentions: draft.mentions.clone(),
                links: draft.extract_links(),
            })
        } else {
            MessageContent::Text(draft.text.clone())
        };
        
        // Convert attachments
        let attachments = draft.attachments.iter()
            .map(|a| a.data.clone())
            .collect();
        
        Ok(SendMessageRequest {
            channel_id,
            content,
            attachments,
            thread_id: draft.thread_id,
            reply_to: draft.reply_to,
            mentions: draft.mentions.clone(),
            ephemeral: draft.ephemeral,
        })
    }
}

/// Draft message being composed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DraftMessage {
    pub channel_id: ChannelId,
    pub text: String,
    pub formatted_text: Option<String>,
    pub mentions: Vec<FourWordAddress>,
    pub attachments: Vec<DraftAttachment>,
    pub reply_to: Option<MessageId>,
    pub thread_id: Option<ThreadId>,
    pub ephemeral: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl DraftMessage {
    /// Create new draft
    fn new(channel_id: ChannelId) -> Self {
        let now = chrono::Utc::now();
        Self {
            channel_id,
            text: String::new(),
            formatted_text: None,
            mentions: Vec::new(),
            attachments: Vec::new(),
            reply_to: None,
            thread_id: None,
            ephemeral: false,
            created_at: now,
            updated_at: now,
        }
    }
    
    /// Update formatted text from raw text
    fn update_formatted(&mut self) {
        // Simple markdown detection
        if self.text.contains("**") || self.text.contains("*") || 
           self.text.contains("`") || self.text.contains("~~") {
            self.formatted_text = Some(self.text.clone());
        }
        
        self.updated_at = chrono::Utc::now();
    }
    
    /// Extract links from text
    fn extract_links(&self) -> Vec<String> {
        let url_regex = match regex::Regex::new(r"https?://[^\s<]+[^<.,:;'!\?\s]") {
            Ok(re) => re,
            Err(_) => regex::Regex::new(r"https?://.+").unwrap_or_else(|_| regex::Regex::new(r"https?://.*").unwrap()),
        };
        
        url_regex.find_iter(&self.text)
            .map(|m| m.as_str().to_string())
            .collect()
    }
}

/// Draft attachment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DraftAttachment {
    pub filename: String,
    pub mime_type: String,
    pub size: usize,
    pub data: Vec<u8>,
    pub thumbnail: Option<Vec<u8>>,
}

/// Text formatting options
#[derive(Debug, Clone)]
pub enum TextFormat {
    Bold,
    Italic,
    Code,
    Strike,
    Quote,
    CodeBlock(String),
}

/// Autocomplete suggestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutocompleteSuggestion {
    pub text: String,
    pub icon: String,
    pub description: String,
    pub action: AutocompleteAction,
}

/// Autocomplete action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AutocompleteAction {
    InsertMention(FourWordAddress),
    InsertEmoji(String),
    InsertCommand(String),
    InsertChannel(ChannelId),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_draft_creation() {
        let mut composer = MessageComposer::new();
        let channel = ChannelId::new();
        
        composer.update_draft(channel, "Hello world".to_string());
        
        let draft = composer.get_draft(channel).unwrap();
        assert_eq!(draft.text, "Hello world");
    }
    
    #[test]
    fn test_mention_addition() {
        let mut composer = MessageComposer::new();
        let channel = ChannelId::new();
        let user = FourWordAddress::from("alice-bob-charlie-david");
        
        composer.add_mention(channel, user.clone());
        
        let draft = composer.get_draft(channel).unwrap();
        assert!(draft.mentions.contains(&user));
        assert!(draft.text.contains("@alice-bob-charlie-david"));
    }
    
    #[test]
    fn test_emoji_shortcuts() {
        let mut composer = MessageComposer::new();
        let channel = ChannelId::new();
        
        composer.update_draft(channel, "Hello :) :fire:".to_string());
        composer.process_shortcuts(channel);
        
        let draft = composer.get_draft(channel).unwrap();
        assert!(draft.text.contains("😊"));
        assert!(draft.text.contains("🔥"));
    }
    
    #[test]
    fn test_draft_validation() {
        let mut composer = MessageComposer::new();
        let channel = ChannelId::new();
        
        // Empty draft should fail
        let result = composer.validate_draft(channel);
        assert!(result.is_err());
        
        // Valid draft should pass
        composer.update_draft(channel, "Valid message".to_string());
        let result = composer.validate_draft(channel);
        assert!(result.is_ok());
    }
}