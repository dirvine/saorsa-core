// SQLite database for message persistence using sqlx
// Provides local caching and fast retrieval of messages

use super::types::*;
use super::DhtClient;
use crate::identity::FourWordAddress;
use anyhow::{Result, Context};
use chrono::{DateTime, Utc};
use sqlx::{sqlite::{SqlitePool, SqlitePoolOptions}, Row};
use serde_json;
use std::collections::HashMap;
use tracing::{debug, info};
use uuid::Uuid;
use tokio::sync::RwLock;
use std::sync::Arc;

/// Type alias for the message store
pub type MessageStore = DatabaseMessageStore;

/// Database-backed message store with DHT synchronization
#[derive(Clone)]
pub struct DatabaseMessageStore {
    /// SQLite connection pool
    pool: SqlitePool,
    /// DHT client for distributed storage
    dht_client: DhtClient,
    /// Database path
    db_path: String,
    /// In-memory message cache
    messages: Arc<RwLock<HashMap<MessageId, RichMessage>>>,
}

impl DatabaseMessageStore {
    /// Create a new database-backed message store
    pub async fn new(dht_client: DhtClient, db_path: Option<String>) -> Result<Self> {
        let db_path = db_path.unwrap_or_else(|| {
            let data_dir = dirs::data_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("saorsa")
                .join("messages");
            
            std::fs::create_dir_all(&data_dir).ok();
            data_dir.join("messages.db").to_string_lossy().to_string()
        });
        
        info!("Opening message database at: {}", db_path);
        
        // Create database file if it doesn't exist
        if !std::path::Path::new(&db_path).exists() {
            std::fs::File::create(&db_path)?;
        }
        
        // Create connection pool
        let pool_url = format!("sqlite:{}", db_path);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&pool_url)
            .await
            .context("Failed to create database pool")?;
        
        let store = Self {
            pool,
            dht_client,
            db_path: db_path.clone(),
            messages: Arc::new(RwLock::new(HashMap::new())),
        };
        
        // Initialize database schema
        store.initialize_schema().await?;
        
        Ok(store)
    }
    
    /// Initialize database schema
    async fn initialize_schema(&self) -> Result<()> {
        // Configure SQLite for optimal performance
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&self.pool)
            .await?;
        sqlx::query("PRAGMA synchronous = NORMAL")
            .execute(&self.pool)
            .await?;
        
        // Create messages table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                channel_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                content TEXT NOT NULL,
                thread_id TEXT,
                reply_to TEXT,
                created_at INTEGER NOT NULL,
                edited_at INTEGER,
                deleted_at INTEGER,
                ephemeral INTEGER DEFAULT 0,
                signature TEXT
            )"
        )
        .execute(&self.pool)
        .await?;
        
        // Create attachments table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS attachments (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL,
                attachment_type TEXT NOT NULL,
                filename TEXT NOT NULL,
                size INTEGER NOT NULL,
                mime_type TEXT NOT NULL,
                hash BLOB NOT NULL,
                thumbnail BLOB,
                metadata TEXT,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
            )"
        )
        .execute(&self.pool)
        .await?;
        
        // Create reactions table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL,
                emoji TEXT NOT NULL,
                user TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
                UNIQUE(message_id, emoji, user)
            )"
        )
        .execute(&self.pool)
        .await?;
        
        // Create mentions table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS mentions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL,
                user TEXT NOT NULL,
                FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
            )"
        )
        .execute(&self.pool)
        .await?;
        
        // Create read receipts table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS read_receipts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL,
                user TEXT NOT NULL,
                read_at INTEGER NOT NULL,
                FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
                UNIQUE(message_id, user)
            )"
        )
        .execute(&self.pool)
        .await?;
        
        // Create threads table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS threads (
                id TEXT PRIMARY KEY,
                parent_message_id TEXT NOT NULL,
                last_reply_at INTEGER,
                reply_count INTEGER DEFAULT 0,
                participant_count INTEGER DEFAULT 0,
                FOREIGN KEY (parent_message_id) REFERENCES messages(id) ON DELETE CASCADE
            )"
        )
        .execute(&self.pool)
        .await?;
        
        // Create indexes for performance
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id, created_at DESC)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(thread_id, created_at)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_attachments_message ON attachments(message_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_reactions_message ON reactions(message_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_mentions_user ON mentions(user)")
            .execute(&self.pool)
            .await?;
        
        info!("Database schema initialized successfully");
        Ok(())
    }
    
    /// Store a message in the database
    pub async fn store_message(&self, message: &RichMessage) -> Result<()> {
        // Begin transaction
        let mut tx = self.pool.begin().await?;
        
        // Serialize content
        let content_json = serde_json::to_string(&message.content)?;
        
        // Insert main message
        sqlx::query(
            "INSERT OR REPLACE INTO messages (
                id, channel_id, sender, content, thread_id, reply_to,
                created_at, edited_at, deleted_at, ephemeral, signature
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
        )
        .bind(message.id.to_string())
        .bind(message.channel_id.to_string())
        .bind(message.sender.to_string())
        .bind(content_json)
        .bind(message.thread_id.as_ref().map(|id| id.to_string()))
        .bind(message.reply_to.as_ref().map(|id| id.to_string()))
        .bind(message.created_at.timestamp_millis())
        .bind(message.edited_at.as_ref().map(|dt| dt.timestamp_millis()))
        .bind(message.deleted_at.as_ref().map(|dt| dt.timestamp_millis()))
        .bind(message.ephemeral as i32)
        .bind(hex::encode(&message.signature.signature))
        .execute(&mut *tx)
        .await?;
        
        // Insert attachments
        for attachment in &message.attachments {
            let metadata_json = serde_json::to_string(&attachment.metadata)?;
            
            sqlx::query(
                "INSERT OR REPLACE INTO attachments (
                    id, message_id, attachment_type, filename, size,
                    mime_type, hash, thumbnail, metadata, created_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
            )
            .bind(attachment.id.to_string())
            .bind(message.id.to_string())
            .bind(&attachment.mime_type)
            .bind(&attachment.filename)
            .bind(attachment.size_bytes as i64)
            .bind(&attachment.mime_type)
            .bind(&attachment.dht_hash)
            .bind(&attachment.thumbnail)
            .bind(metadata_json)
            .bind(Utc::now().timestamp_millis())
            .execute(&mut *tx)
            .await?;
        }
        
        // Insert mentions
        for mention in &message.mentions {
            sqlx::query(
                "INSERT OR IGNORE INTO mentions (message_id, user) VALUES (?1, ?2)"
            )
            .bind(message.id.to_string())
            .bind(mention.to_string())
            .execute(&mut *tx)
            .await?;
        }
        
        // Commit transaction
        tx.commit().await?;
        
        // Also sync to DHT for distributed storage
        self.sync_to_dht(message).await?;
        
        debug!("Stored message {} in database", message.id);
        Ok(())
    }
    
    /// Update an existing message in the database
    pub async fn update_message(&self, message: &RichMessage) -> Result<()> {
        // Update in memory cache
        let mut cache = self.messages.write().await;
        cache.insert(message.id, message.clone());
        
        // Update in database - for now just re-store
        // In production, this would be a proper UPDATE query
        self.store_message(message).await?;
        Ok(())
    }
    
    /// Retrieve a message from the database
    pub async fn get_message(&self, id: MessageId) -> Result<RichMessage> {
        // Try local database first
        let row = sqlx::query(
            "SELECT id, channel_id, sender, content, thread_id, reply_to,
                    created_at, edited_at, deleted_at, ephemeral, signature
             FROM messages WHERE id = ?1"
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        
        if let Some(row) = row {
            let mut message = self.parse_message_row(row)?;
            
            // Load attachments
            message.attachments = self.load_attachments(id).await?;
            
            // Load mentions
            message.mentions = self.load_mentions(id).await?;
            
            return Ok(message);
        }
        
        // If not found locally, try DHT
        self.get_from_dht(id).await
    }
    
    /// Update a message in the database
    /// Get channel messages with pagination
    pub async fn get_channel_messages(
        &self,
        channel_id: ChannelId,
        limit: usize,
        before: Option<DateTime<Utc>>,
    ) -> Result<Vec<RichMessage>> {
        let before_timestamp = before
            .map(|dt| dt.timestamp_millis())
            .unwrap_or(i64::MAX);
        
        let rows = sqlx::query(
            "SELECT id, channel_id, sender, content, thread_id, reply_to,
                    created_at, edited_at, deleted_at, ephemeral, signature
             FROM messages 
             WHERE channel_id = ?1 AND created_at < ?2 AND deleted_at IS NULL
             ORDER BY created_at DESC
             LIMIT ?3"
        )
        .bind(channel_id.to_string())
        .bind(before_timestamp)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        
        let mut result = Vec::new();
        for row in rows {
            let mut msg = self.parse_message_row(row)?;
            
            // Load attachments and mentions
            msg.attachments = self.load_attachments(msg.id).await?;
            msg.mentions = self.load_mentions(msg.id).await?;
            
            result.push(msg);
        }
        
        Ok(result)
    }
    
    /// Mark message as read
    pub async fn mark_as_read(
        &self,
        message_id: MessageId,
        user: FourWordAddress,
    ) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO read_receipts (message_id, user, read_at)
             VALUES (?1, ?2, ?3)"
        )
        .bind(message_id.to_string())
        .bind(user.to_string())
        .bind(Utc::now().timestamp_millis())
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    /// Search messages using LIKE pattern matching
    pub async fn search_messages(
        &self,
        query: &str,
        channel_id: Option<ChannelId>,
        limit: usize,
    ) -> Result<Vec<RichMessage>> {
        let search_pattern = format!("%{}%", query);
        
        let rows = if let Some(channel) = channel_id {
            sqlx::query(
                "SELECT id, channel_id, sender, content, thread_id, reply_to,
                        created_at, edited_at, deleted_at, ephemeral, signature
                 FROM messages
                 WHERE content LIKE ?1 AND channel_id = ?2 AND deleted_at IS NULL
                 ORDER BY created_at DESC
                 LIMIT ?3"
            )
            .bind(&search_pattern)
            .bind(channel.to_string())
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, channel_id, sender, content, thread_id, reply_to,
                        created_at, edited_at, deleted_at, ephemeral, signature
                 FROM messages
                 WHERE content LIKE ?1 AND deleted_at IS NULL
                 ORDER BY created_at DESC
                 LIMIT ?2"
            )
            .bind(&search_pattern)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await?
        };
        
        let mut result = Vec::new();
        for row in rows {
            let mut msg = self.parse_message_row(row)?;
            msg.attachments = self.load_attachments(msg.id).await?;
            msg.mentions = self.load_mentions(msg.id).await?;
            result.push(msg);
        }
        
        Ok(result)
    }
    
    /// Get thread messages
    pub async fn get_thread_messages(&self, thread_id: ThreadId) -> Result<Vec<RichMessage>> {
        let rows = sqlx::query(
            "SELECT id, channel_id, sender, content, thread_id, reply_to,
                    created_at, edited_at, deleted_at, ephemeral, signature
             FROM messages 
             WHERE thread_id = ?1 AND deleted_at IS NULL
             ORDER BY created_at ASC"
        )
        .bind(thread_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        
        let mut result = Vec::new();
        for row in rows {
            let mut msg = self.parse_message_row(row)?;
            msg.attachments = self.load_attachments(msg.id).await?;
            msg.mentions = self.load_mentions(msg.id).await?;
            result.push(msg);
        }
        
        Ok(result)
    }
    
    /// Add a reaction to a message
    pub async fn add_reaction(
        &self,
        message_id: MessageId,
        emoji: String,
        user: FourWordAddress,
    ) -> Result<()> {
        sqlx::query(
            "INSERT OR IGNORE INTO reactions (message_id, emoji, user, created_at)
             VALUES (?1, ?2, ?3, ?4)"
        )
        .bind(message_id.to_string())
        .bind(emoji)
        .bind(user.to_string())
        .bind(Utc::now().timestamp_millis())
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    /// Remove a reaction from a message
    pub async fn remove_reaction(
        &self,
        message_id: MessageId,
        emoji: String,
        user: FourWordAddress,
    ) -> Result<()> {
        sqlx::query(
            "DELETE FROM reactions WHERE message_id = ?1 AND emoji = ?2 AND user = ?3"
        )
        .bind(message_id.to_string())
        .bind(emoji)
        .bind(user.to_string())
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    /// Get reactions for a message
    pub async fn get_reactions(&self, message_id: MessageId) -> Result<HashMap<String, Vec<FourWordAddress>>> {
        let rows = sqlx::query(
            "SELECT emoji, user FROM reactions WHERE message_id = ?1"
        )
        .bind(message_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        
        let mut result: HashMap<String, Vec<FourWordAddress>> = HashMap::new();
        for row in rows {
            let emoji: String = row.try_get(0)?;
            let user = FourWordAddress::from(row.try_get::<String, _>(1)?);
            result.entry(emoji).or_insert_with(Vec::new).push(user);
        }
        
        Ok(result)
    }
    
    /// Clean up old ephemeral messages
    pub async fn cleanup_ephemeral(&self, ttl_seconds: i64) -> Result<usize> {
        let cutoff = (Utc::now() - chrono::Duration::seconds(ttl_seconds)).timestamp_millis();
        
        let result = sqlx::query(
            "DELETE FROM messages WHERE ephemeral = 1 AND created_at < ?1"
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        
        let deleted = result.rows_affected() as usize;
        
        if deleted > 0 {
            info!("Cleaned up {} ephemeral messages", deleted);
        }
        
        Ok(deleted)
    }
    
    /// Vacuum database to reclaim space
    pub async fn vacuum(&self) -> Result<()> {
        sqlx::query("VACUUM")
            .execute(&self.pool)
            .await?;
        info!("Database vacuumed successfully");
        Ok(())
    }
    
    /// Get database statistics
    pub async fn get_stats(&self) -> Result<DatabaseStats> {
        let message_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM messages WHERE deleted_at IS NULL"
        )
        .fetch_one(&self.pool)
        .await?;
        
        let attachment_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM attachments"
        )
        .fetch_one(&self.pool)
        .await?;
        
        let reaction_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM reactions"
        )
        .fetch_one(&self.pool)
        .await?;
        
        let db_size = std::fs::metadata(&self.db_path)?.len();
        
        Ok(DatabaseStats {
            message_count: message_count as usize,
            attachment_count: attachment_count as usize,
            reaction_count: reaction_count as usize,
            database_size_bytes: db_size,
        })
    }
    
    // Helper methods
    
    fn parse_message_row(&self, row: sqlx::sqlite::SqliteRow) -> Result<RichMessage> {
        let content_json: String = row.try_get(3)?;
        let content: MessageContent = serde_json::from_str(&content_json)?;
        
        Ok(RichMessage {
            id: MessageId(Uuid::parse_str(&row.try_get::<String, _>(0)?)?),
            channel_id: ChannelId(Uuid::parse_str(&row.try_get::<String, _>(1)?)?),
            sender: FourWordAddress::from(row.try_get::<String, _>(2)?),
            sender_device: DeviceId("primary".to_string()),
            content,
            thread_id: row.try_get::<Option<String>, _>(4)?
                .map(|s| ThreadId(Uuid::parse_str(&s).unwrap())),
            reply_to: row.try_get::<Option<String>, _>(5)?
                .map(|s| MessageId(Uuid::parse_str(&s).unwrap())),
            created_at: DateTime::from_timestamp_millis(row.try_get(6)?).unwrap_or_else(Utc::now),
            edited_at: row.try_get::<Option<i64>, _>(7)?
                .and_then(DateTime::from_timestamp_millis),
            deleted_at: row.try_get::<Option<i64>, _>(8)?
                .and_then(DateTime::from_timestamp_millis),
            ephemeral: row.try_get::<i32, _>(9)? != 0,
            signature: row.try_get::<Option<String>, _>(10)?
                .and_then(|s| hex::decode(s).ok())
                .map(|sig| MessageSignature {
                    algorithm: "Ed25519".to_string(),
                    signature: sig,
                })
                .unwrap_or_default(),
            attachments: Vec::new(), // Loaded separately
            mentions: Vec::new(), // Loaded separately
            reactions: HashMap::new(), // Loaded separately
            read_by: HashMap::new(), // Loaded separately
            delivered_to: HashMap::new(), // Loaded separately
            thread_count: 0,
            last_thread_reply: None,
            expires_at: None,
            encryption: EncryptionMethod::E2E,
        })
    }
    
    async fn load_attachments(&self, message_id: MessageId) -> Result<Vec<Attachment>> {
        let rows = sqlx::query(
            "SELECT id, attachment_type, filename, size, mime_type, hash, thumbnail, metadata
             FROM attachments WHERE message_id = ?1"
        )
        .bind(message_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        
        let mut attachments = Vec::new();
        for row in rows {
            let metadata_json: String = row.try_get(7)?;
            let metadata: HashMap<String, String> = serde_json::from_str(&metadata_json)
                .unwrap_or_default();
            
            attachments.push(Attachment {
                id: row.try_get::<String, _>(0)?,
                filename: row.try_get(2)?,
                mime_type: row.try_get(4)?,
                size_bytes: row.try_get::<i64, _>(3)? as u64,
                thumbnail: row.try_get(6)?,
                dht_hash: row.try_get(5)?,
                encryption_key: None,
                metadata,
            });
        }
        
        Ok(attachments)
    }
    
    async fn load_mentions(&self, message_id: MessageId) -> Result<Vec<FourWordAddress>> {
        let rows = sqlx::query(
            "SELECT user FROM mentions WHERE message_id = ?1"
        )
        .bind(message_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        
        let mut mentions = Vec::new();
        for row in rows {
            mentions.push(FourWordAddress::from(row.try_get::<String, _>(0)?));
        }
        
        Ok(mentions)
    }
    
    async fn sync_to_dht(&self, message: &RichMessage) -> Result<()> {
        // Store in DHT for distributed backup
        let key = format!("msg:{}", message.id);
        let value = serde_json::to_vec(message)?;
        
        self.dht_client.put(key, value).await?;
        
        // Also store in channel index
        let channel_key = format!("channel:{}:messages", message.channel_id);
        let mut messages = self.dht_client.get(channel_key.clone()).await?
            .and_then(|data| serde_json::from_slice::<Vec<String>>(&data).ok())
            .unwrap_or_default();
        
        if !messages.contains(&message.id.to_string()) {
            messages.push(message.id.to_string());
            let value = serde_json::to_vec(&messages)?;
            self.dht_client.put(channel_key, value).await?;
        }
        
        Ok(())
    }
    
    async fn get_from_dht(&self, id: MessageId) -> Result<RichMessage> {
        let key = format!("msg:{}", id);
        
        if let Some(data) = self.dht_client.get(key).await? {
            let message: RichMessage = serde_json::from_slice(&data)?;
            
            // Cache in local database
            self.store_message(&message).await?;
            
            return Ok(message);
        }
        
        Err(anyhow::anyhow!("Message not found in database or DHT"))
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub message_count: usize,
    pub attachment_count: usize,
    pub reaction_count: usize,
    pub database_size_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_database_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db").to_string_lossy().to_string();
        
        let dht = DhtClient::new_mock();
        let store = DatabaseMessageStore::new(dht, Some(db_path)).await;
        
        assert!(store.is_ok());
    }
    
    #[tokio::test]
    async fn test_message_storage_and_retrieval() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db").to_string_lossy().to_string();
        
        let dht = DhtClient::new_mock();
        let store = DatabaseMessageStore::new(dht, Some(db_path)).await.unwrap();
        
        // Create test message
        let message = RichMessage::new(
            FourWordAddress::from("test-user-here"),
            ChannelId::new(),
            MessageContent::Text("Test message".to_string()),
        );
        
        // Store message
        store.store_message(&message).await.unwrap();
        
        // Retrieve message
        let retrieved = store.get_message(message.id).await.unwrap();
        
        assert_eq!(retrieved.id, message.id);
        assert_eq!(retrieved.sender, message.sender);
        assert!(matches!(retrieved.content, MessageContent::Text(_)));
    }
    
    #[tokio::test]
    async fn test_channel_message_retrieval() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db").to_string_lossy().to_string();
        
        let dht = DhtClient::new_mock();
        let store = DatabaseMessageStore::new(dht, Some(db_path)).await.unwrap();
        
        let channel_id = ChannelId::new();
        let sender = FourWordAddress::from("test-user");
        
        // Store multiple messages
        for i in 0..10 {
            let message = RichMessage::new(
                sender.clone(),
                channel_id,
                MessageContent::Text(format!("Message {}", i)),
            );
            store.store_message(&message).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
        
        // Retrieve messages
        let messages = store.get_channel_messages(channel_id, 5, None).await.unwrap();
        
        assert_eq!(messages.len(), 5);
        // Messages should be in reverse chronological order
        assert!(messages[0].created_at > messages[1].created_at);
    }
    
    #[tokio::test]
    async fn test_reactions() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db").to_string_lossy().to_string();
        
        let dht = DhtClient::new_mock();
        let store = DatabaseMessageStore::new(dht, Some(db_path)).await.unwrap();
        
        let message = RichMessage::new(
            FourWordAddress::from("test-user"),
            ChannelId::new(),
            MessageContent::Text("React to this".to_string()),
        );
        
        store.store_message(&message).await.unwrap();
        
        // Add reactions
        let user1 = FourWordAddress::from("user-one");
        let user2 = FourWordAddress::from("user-two");
        
        store.add_reaction(message.id, "👍".to_string(), user1.clone()).await.unwrap();
        store.add_reaction(message.id, "👍".to_string(), user2.clone()).await.unwrap();
        store.add_reaction(message.id, "❤️".to_string(), user1.clone()).await.unwrap();
        
        // Get reactions
        let reactions = store.get_reactions(message.id).await.unwrap();
        
        assert_eq!(reactions.len(), 2);
        assert_eq!(reactions.get("👍").unwrap().len(), 2);
        assert_eq!(reactions.get("❤️").unwrap().len(), 1);
        
        // Remove reaction
        store.remove_reaction(message.id, "👍".to_string(), user1).await.unwrap();
        
        let reactions = store.get_reactions(message.id).await.unwrap();
        assert_eq!(reactions.get("👍").unwrap().len(), 1);
    }
    
    #[tokio::test]
    async fn test_ephemeral_cleanup() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db").to_string_lossy().to_string();
        
        let dht = DhtClient::new_mock();
        let store = DatabaseMessageStore::new(dht, Some(db_path)).await.unwrap();
        
        // Create ephemeral message
        let mut message = RichMessage::new(
            FourWordAddress::from("test-user"),
            ChannelId::new(),
            MessageContent::Text("Ephemeral".to_string()),
        );
        message.ephemeral = true;
        
        store.store_message(&message).await.unwrap();
        
        // Should exist initially
        assert!(store.get_message(message.id).await.is_ok());
        
        // Clean up with 0 TTL (should delete all ephemeral messages)
        let deleted = store.cleanup_ephemeral(0).await.unwrap();
        assert_eq!(deleted, 1);
        
        // Should be gone now
        assert!(store.get_message(message.id).await.is_err());
    }
}