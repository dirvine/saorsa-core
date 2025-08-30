// Message type definitions for rich messaging

use crate::messaging::user_handle::UserHandle;
use crate::identity::FourWordAddress;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Unique message identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub Uuid);

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Thread identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThreadId(pub Uuid);

impl Default for ThreadId {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreadId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for ThreadId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Channel/conversation identifier  
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelId(pub Uuid);

impl Default for ChannelId {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Device identifier for multi-device support
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub String);

/// Rich message with all modern messaging features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichMessage {
    /// Unique message ID
    pub id: MessageId,

    /// Thread ID if part of a thread
    pub thread_id: Option<ThreadId>,

    /// Channel/conversation ID
    pub channel_id: ChannelId,

    /// Sender's messaging handle (not a network endpoint)
    pub sender: UserHandle,

    /// Sender's device
    pub sender_device: DeviceId,

    /// Message content
    pub content: MessageContent,

    /// File attachments
    pub attachments: Vec<Attachment>,

    /// User mentions
    pub mentions: Vec<UserHandle>,

    /// Reply to another message
    pub reply_to: Option<MessageId>,

    /// Number of thread replies
    pub thread_count: u32,

    /// Last thread reply time
    pub last_thread_reply: Option<DateTime<Utc>>,

    /// Reactions grouped by emoji
    pub reactions: HashMap<String, Vec<UserHandle>>,

    /// Read receipts
    pub read_by: HashMap<UserHandle, DateTime<Utc>>,

    /// Delivery receipts
    pub delivered_to: HashMap<UserHandle, DateTime<Utc>>,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Edit timestamp
    pub edited_at: Option<DateTime<Utc>>,

    /// Deletion timestamp (soft delete)
    pub deleted_at: Option<DateTime<Utc>>,

    /// Message expiration for ephemeral messages
    pub expires_at: Option<DateTime<Utc>>,

    /// Whether this is an ephemeral message
    pub ephemeral: bool,

    /// Encryption method used
    pub encryption: EncryptionMethod,

    /// Message signature for verification
    pub signature: MessageSignature,
}

impl RichMessage {
    /// Create a new message
    pub fn new(sender: UserHandle, channel_id: ChannelId, content: MessageContent) -> Self {
        Self {
            id: MessageId::new(),
            thread_id: None,
            channel_id,
            sender,
            sender_device: DeviceId("primary".to_string()),
            content,
            attachments: Vec::new(),
            mentions: Vec::new(),
            reply_to: None,
            thread_count: 0,
            last_thread_reply: None,
            reactions: HashMap::new(),
            read_by: HashMap::new(),
            delivered_to: HashMap::new(),
            created_at: Utc::now(),
            edited_at: None,
            deleted_at: None,
            expires_at: None,
            ephemeral: false,
            encryption: EncryptionMethod::E2E,
            signature: MessageSignature::default(),
        }
    }

    /// Check if message is deleted
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Check if message is edited
    pub fn is_edited(&self) -> bool {
        self.edited_at.is_some()
    }

    /// Check if message has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }
}

/// Message content types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    /// Plain text message
    Text(String),

    /// Rich text with markdown formatting
    RichText(MarkdownContent),

    /// Code block with syntax highlighting
    Code(CodeBlock),

    /// Voice message
    Voice(VoiceMessage),

    /// Video message
    Video(VideoMessage),

    /// Location sharing
    Location(GeoLocation),

    /// Poll/survey
    Poll(PollMessage),

    /// System message (join, leave, etc.)
    System(SystemMessage),

    /// Sticker
    Sticker(Sticker),

    /// GIF
    Gif(GifMessage),
}

/// Markdown formatted content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkdownContent {
    pub raw: String,
    pub formatted: String,
    pub mentions: Vec<UserHandle>,
    pub links: Vec<String>,
}

/// Code block with syntax highlighting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeBlock {
    pub language: String,
    pub code: String,
    pub filename: Option<String>,
    pub line_numbers: bool,
}

/// Voice message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceMessage {
    pub duration_seconds: u32,
    pub waveform: Vec<u8>,
    pub transcription: Option<String>,
    pub mime_type: String,
    pub data: Vec<u8>,
}

/// Video message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoMessage {
    pub duration_seconds: u32,
    pub thumbnail: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub mime_type: String,
    pub data: Vec<u8>,
}

/// Geographic location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy_meters: Option<f32>,
    pub address: Option<String>,
    pub place_name: Option<String>,
}

/// Poll message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollMessage {
    pub question: String,
    pub options: Vec<PollOption>,
    pub allows_multiple: bool,
    pub anonymous: bool,
    pub closes_at: Option<DateTime<Utc>>,
}

/// Poll option
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollOption {
    pub id: String,
    pub text: String,
    pub votes: Vec<UserHandle>,
}

/// System message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemMessage {
    UserJoined(FourWordAddress),
    UserLeft(FourWordAddress),
    ChannelCreated,
    ChannelRenamed(String),
    UserInvited(FourWordAddress, FourWordAddress), // inviter, invitee
    CallStarted(FourWordAddress),
    CallEnded { duration_seconds: u32 },
    MessagePinned(MessageId),
}

/// Sticker message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sticker {
    pub pack_id: String,
    pub sticker_id: String,
    pub emoji: String,
    pub animated: bool,
    pub data: Vec<u8>,
}

/// GIF message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GifMessage {
    pub url: String,
    pub thumbnail: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub caption: Option<String>,
}

/// File attachment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub id: String,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub thumbnail: Option<Vec<u8>>,
    pub dht_hash: String,
    pub encryption_key: Option<Vec<u8>>,
    pub metadata: std::collections::HashMap<String, String>,
}

/// Encryption methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionMethod {
    /// End-to-end encryption
    E2E,
    /// Transport layer security only
    TLS,
    /// No encryption (not recommended)
    None,
}

/// Message signature for verification
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MessageSignature {
    pub algorithm: String,
    pub signature: Vec<u8>,
}

/// Encrypted message wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub id: MessageId,
    pub channel_id: ChannelId,
    pub sender: FourWordAddress,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_id: String,
}

/// Search query for messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    pub text: Option<String>,
    pub from: Option<Vec<UserHandle>>,
    pub in_channels: Option<Vec<ChannelId>>,
    pub has_attachments: Option<bool>,
    pub has_reactions: Option<bool>,
    pub is_thread: Option<bool>,
    pub date_range: Option<DateRange>,
    pub limit: usize,
}

/// Date range for filtering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Thread view with all messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadView {
    pub parent_message: RichMessage,
    pub replies: Vec<RichMessage>,
    pub participants: Vec<UserHandle>,
    pub is_following: bool,
    pub unread_count: u32,
    pub last_activity: DateTime<Utc>,
}

/// User presence information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPresence {
    pub identity: UserHandle,
    pub status: PresenceStatus,
    pub custom_status: Option<CustomStatus>,
    pub last_seen: Option<DateTime<Utc>>,
    pub typing_in: Vec<ChannelId>,
    pub device: DeviceType,
}

/// Presence status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PresenceStatus {
    Online,
    Away,
    Busy,
    Offline,
}

/// Custom user status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomStatus {
    pub emoji: String,
    pub text: String,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Device types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceType {
    Desktop,
    Mobile,
    Web,
    CLI,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_creation() {
        let sender = UserHandle::from("ocean-forest-moon-star");
        let channel = ChannelId::new();
        let content = MessageContent::Text("Hello, world!".to_string());

        let message = RichMessage::new(sender.clone(), channel, content);

        assert_eq!(message.sender, sender);
        assert_eq!(message.channel_id, channel);
        assert!(!message.is_deleted());
        assert!(!message.is_edited());
        assert!(!message.is_expired());
    }

    #[test]
    fn test_message_expiration() {
        let sender = UserHandle::from("ocean-forest-moon-star");
        let channel = ChannelId::new();
        let content = MessageContent::Text("Ephemeral".to_string());

        let mut message = RichMessage::new(sender, channel, content);

        // Set expiration in the past
        message.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(message.is_expired());

        // Set expiration in the future
        message.expires_at = Some(Utc::now() + chrono::Duration::hours(1));
        assert!(!message.is_expired());
    }
}
