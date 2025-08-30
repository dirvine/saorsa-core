// Message database implementation using deadpool-sqlite + rusqlite
// Replaced sqlx to resolve RSA security vulnerability RUSTSEC-2023-0071

use crate::messaging::types::*;
use crate::messaging::user_handle::UserHandle;
use anyhow::Result;
use chrono::{DateTime, TimeZone, Utc};
use deadpool_sqlite::{Config, Pool, Runtime};
use rusqlite::params;
use serde_json;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, info};
use uuid::Uuid;

pub use crate::dht::client::DhtClient;

/// Message store using deadpool-sqlite for connection pooling
#[derive(Clone)]
pub struct DatabaseMessageStore {
    pool: Pool,
    #[allow(dead_code)] // TODO: Integrate DHT client functionality
    dht_client: DhtClient,
}

impl DatabaseMessageStore {
    /// Create a new database message store
    pub async fn new(dht_client: DhtClient, db_path: Option<PathBuf>) -> Result<Self> {
        let db_path = db_path.unwrap_or_else(|| {
            let mut path = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
            path.push("saorsa");
            std::fs::create_dir_all(&path).unwrap_or(());
            path.push("messages.db");
            path
        });

        info!("Initializing message database at: {:?}", db_path);

        // Create deadpool-sqlite configuration
        let cfg = Config::new(db_path);
        let pool = cfg.create_pool(Runtime::Tokio1)?;

        let store = Self { pool, dht_client };

        // Initialize database schema
        store.init_schema().await?;

        Ok(store)
    }

    /// Initialize the database schema with all required tables
    async fn init_schema(&self) -> Result<()> {
        let conn = self.pool.get().await?;

        let result = conn.interact(|conn| -> Result<(), rusqlite::Error> {
            // Configure SQLite for optimal performance
            conn.execute("PRAGMA journal_mode = WAL", [])?;
            conn.execute("PRAGMA synchronous = NORMAL", [])?;
            conn.execute("PRAGMA cache_size = -64000", [])?; // 64MB cache
            conn.execute("PRAGMA foreign_keys = ON", [])?;
            conn.execute("PRAGMA temp_store = MEMORY", [])?;
            conn.execute("PRAGMA mmap_size = 268435456", [])?; // 256MB mmap

            // Messages table
            conn.execute(
                "CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY NOT NULL,
                    channel_id TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    content TEXT NOT NULL,
                    thread_id TEXT,
                    reply_to TEXT,
                    created_at INTEGER NOT NULL,
                    edited_at INTEGER,
                    deleted_at INTEGER,
                    ephemeral INTEGER DEFAULT 0,
                    signature TEXT NOT NULL DEFAULT ''
                )",
                [],
            )?;

            // Attachments table
            conn.execute(
                "CREATE TABLE IF NOT EXISTS attachments (
                    id TEXT PRIMARY KEY NOT NULL,
                    message_id TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    dht_hash TEXT NOT NULL,
                    thumbnail BLOB,
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
                )",
                [],
            )?;

            // Reactions table
            conn.execute(
                "CREATE TABLE IF NOT EXISTS reactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id TEXT NOT NULL,
                    emoji TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
                    UNIQUE(message_id, emoji, user_id)
                )",
                [],
            )?;

            // Mentions table
            conn.execute(
                "CREATE TABLE IF NOT EXISTS mentions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id TEXT NOT NULL,
                    user TEXT NOT NULL,
                    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
                )",
                [],
            )?;

            // Read receipts table
            conn.execute(
                "CREATE TABLE IF NOT EXISTS read_receipts (
                    message_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    read_at INTEGER NOT NULL,
                    PRIMARY KEY (message_id, user_id),
                    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
                )",
                [],
            )?;

            // Create indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id, created_at DESC)", [])?;
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(thread_id, created_at)", [])?;
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender)", [])?;
            conn.execute("CREATE INDEX IF NOT EXISTS idx_attachments_message ON attachments(message_id)", [])?;
            conn.execute("CREATE INDEX IF NOT EXISTS idx_reactions_message ON reactions(message_id)", [])?;
            conn.execute("CREATE INDEX IF NOT EXISTS idx_mentions_user ON mentions(user)", [])?;

            Ok(())
        }).await;

        match result {
            Ok(Ok(())) => {
                info!("Database schema initialized successfully");
                Ok(())
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("Database schema creation failed: {}", e)),
            Err(e) => Err(anyhow::anyhow!(
                "Failed to execute schema initialization: {}",
                e
            )),
        }
    }

    /// Store a message in the database
    pub async fn store_message(&self, message: &RichMessage) -> Result<()> {
        let conn = self.pool.get().await?;

        // Serialize content
        let content_json = serde_json::to_string(&message.content)?;
        let message_clone = message.clone();

        let result = conn
            .interact(move |conn| -> Result<(), rusqlite::Error> {
                let tx = conn.transaction()?;

                // Insert main message
                tx.execute(
                    "INSERT OR REPLACE INTO messages (
                    id, channel_id, sender, content, thread_id, reply_to,
                    created_at, edited_at, deleted_at, ephemeral, signature
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    params![
                        message_clone.id.to_string(),
                        message_clone.channel_id.to_string(),
                        message_clone.sender.to_string(),
                        content_json,
                        message_clone.thread_id.as_ref().map(|id| id.to_string()),
                        message_clone.reply_to.as_ref().map(|id| id.to_string()),
                        message_clone.created_at.timestamp_millis(),
                        message_clone
                            .edited_at
                            .as_ref()
                            .map(|dt| dt.timestamp_millis()),
                        message_clone
                            .deleted_at
                            .as_ref()
                            .map(|dt| dt.timestamp_millis()),
                        message_clone.ephemeral as i32,
                        hex::encode(&message_clone.signature.signature)
                    ],
                )?;

                // Insert attachments
                for attachment in &message_clone.attachments {
                    let metadata_json =
                        serde_json::to_string(&attachment.metadata).unwrap_or_default();

                    tx.execute(
                        "INSERT OR REPLACE INTO attachments (
                        id, message_id, filename, mime_type, size_bytes,
                        dht_hash, thumbnail, metadata
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        params![
                            attachment.id,
                            message_clone.id.to_string(),
                            attachment.filename,
                            attachment.mime_type,
                            attachment.size_bytes,
                            attachment.dht_hash,
                            attachment.thumbnail.as_ref(),
                            metadata_json
                        ],
                    )?;
                }

                // Insert mentions
                for mention in &message_clone.mentions {
                    tx.execute(
                        "INSERT OR IGNORE INTO mentions (message_id, user) VALUES (?1, ?2)",
                        params![message_clone.id.to_string(), mention.to_string()],
                    )?;
                }

                // Insert reactions
                for (emoji, users) in &message_clone.reactions {
                    for user in users {
                        tx.execute(
                        "INSERT OR IGNORE INTO reactions (message_id, emoji, user_id, created_at) 
                         VALUES (?1, ?2, ?3, ?4)",
                        params![
                            message_clone.id.to_string(),
                            emoji,
                            user.to_string(),
                            chrono::Utc::now().timestamp_millis()
                        ],
                    )?;
                    }
                }

                tx.commit()?;
                Ok(())
            })
            .await;

        match result {
            Ok(Ok(())) => {
                debug!("Message stored successfully: {}", message.id);
                Ok(())
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("Failed to store message: {}", e)),
            Err(e) => Err(anyhow::anyhow!("Database interaction failed: {}", e)),
        }
    }

    /// Retrieve a message by ID
    pub async fn get_message(&self, id: MessageId) -> Result<RichMessage> {
        let conn = self.pool.get().await?;
        let message_id = id.to_string();

        let result = conn
            .interact(move |conn| -> Result<RichMessage, rusqlite::Error> {
                let mut stmt = conn.prepare(
                    "SELECT id, channel_id, sender, content, thread_id, reply_to,
                        created_at, edited_at, deleted_at, ephemeral, signature
                 FROM messages WHERE id = ?1",
                )?;

                let row = stmt.query_row(params![message_id], |row| {
                    let content_json: String = row.get("content")?;
                    let content: MessageContent =
                        serde_json::from_str(&content_json).map_err(|_| {
                            rusqlite::Error::InvalidColumnType(
                                0,
                                "content".to_string(),
                                rusqlite::types::Type::Text,
                            )
                        })?;

                    let created_at = Utc
                        .timestamp_millis_opt(row.get("created_at")?)
                        .single()
                        .ok_or(rusqlite::Error::InvalidColumnType(
                            0,
                            "created_at".to_string(),
                            rusqlite::types::Type::Integer,
                        ))?;

                    let edited_at: Option<i64> = row.get("edited_at")?;
                    let edited_at = edited_at.and_then(|ts| Utc.timestamp_millis_opt(ts).single());

                    let deleted_at: Option<i64> = row.get("deleted_at")?;
                    let deleted_at =
                        deleted_at.and_then(|ts| Utc.timestamp_millis_opt(ts).single());

                    let thread_id: Option<String> = row.get("thread_id")?;
                    let thread_id = thread_id.and_then(|s| Uuid::parse_str(&s).ok().map(ThreadId));

                    let reply_to: Option<String> = row.get("reply_to")?;
                    let reply_to = reply_to.and_then(|s| Uuid::parse_str(&s).ok().map(MessageId));

                    let signature_hex: String = row.get("signature")?;
                    let signature_bytes = hex::decode(&signature_hex).unwrap_or_default();

                    Ok(RichMessage {
                        id: MessageId(Uuid::parse_str(&row.get::<_, String>("id")?).map_err(
                            |_| {
                                rusqlite::Error::InvalidColumnType(
                                    0,
                                    "id".to_string(),
                                    rusqlite::types::Type::Text,
                                )
                            },
                        )?),
                        channel_id: ChannelId(
                            Uuid::parse_str(&row.get::<_, String>("channel_id")?).map_err(
                                |_| {
                                    rusqlite::Error::InvalidColumnType(
                                        0,
                                        "channel_id".to_string(),
                                        rusqlite::types::Type::Text,
                                    )
                                },
                            )?,
                        ),
                        sender: UserHandle::from(row.get::<_, String>("sender")?),
                        content,
                        thread_id,
                        reply_to,
                        created_at,
                        edited_at,
                        deleted_at,
                        ephemeral: row.get::<_, i32>("ephemeral")? != 0,
                        attachments: Vec::new(),   // Filled below
                        mentions: Vec::new(),      // Filled below
                        reactions: HashMap::new(), // Filled below
                        read_by: HashMap::new(),
                        delivered_to: HashMap::new(),
                        expires_at: None,
                        thread_count: 0,
                        last_thread_reply: None,
                        sender_device: crate::messaging::types::DeviceId("primary".to_string()),
                        encryption: EncryptionMethod::E2E,
                        signature: MessageSignature {
                            algorithm: "ed25519".to_string(),
                            signature: signature_bytes,
                        },
                    })
                })?;

                Ok(row)
            })
            .await;

        match result {
            Ok(Ok(mut message)) => {
                // Load attachments, mentions, and reactions
                message.attachments = self.get_attachments(message.id).await?;
                message.mentions = self.get_mentions(message.id).await?;
                message.reactions = self.get_reactions(message.id).await?;
                Ok(message)
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("Failed to retrieve message: {}", e)),
            Err(e) => Err(anyhow::anyhow!("Database interaction failed: {}", e)),
        }
    }

    /// Get attachments for a message
    async fn get_attachments(&self, message_id: MessageId) -> Result<Vec<Attachment>> {
        let conn = self.pool.get().await?;
        let msg_id = message_id.to_string();

        let result = conn
            .interact(move |conn| -> Result<Vec<Attachment>, rusqlite::Error> {
                let mut stmt = conn.prepare(
                    "SELECT id, filename, mime_type, size_bytes, dht_hash, thumbnail, metadata
                 FROM attachments WHERE message_id = ?1",
                )?;

                let rows = stmt.query_map(params![msg_id], |row| {
                    let metadata_json: String = row.get("metadata")?;
                    let metadata: HashMap<String, String> =
                        serde_json::from_str(&metadata_json).unwrap_or_default();

                    let thumbnail: Option<Vec<u8>> = row.get("thumbnail")?;

                    Ok(Attachment {
                        id: row.get("id")?,
                        filename: row.get("filename")?,
                        mime_type: row.get("mime_type")?,
                        size_bytes: row.get("size_bytes")?,
                        dht_hash: row.get("dht_hash")?,
                        thumbnail,
                        metadata,
                        encryption_key: None, // Not stored in DB for security
                    })
                })?;

                let mut attachments = Vec::new();
                for row in rows {
                    attachments.push(row?);
                }
                Ok(attachments)
            })
            .await;

        match result {
            Ok(Ok(attachments)) => Ok(attachments),
            Ok(Err(e)) => Err(anyhow::anyhow!("Failed to get attachments: {}", e)),
            Err(e) => Err(anyhow::anyhow!("Database interaction failed: {}", e)),
        }
    }

    /// Get mentions for a message
    async fn get_mentions(&self, message_id: MessageId) -> Result<Vec<crate::messaging::user_handle::UserHandle>> {
        let conn = self.pool.get().await?;
        let msg_id = message_id.to_string();

        let result = conn
            .interact(move |conn| -> Result<Vec<String>, rusqlite::Error> {
                let mut stmt = conn.prepare("SELECT user FROM mentions WHERE message_id = ?1")?;
                let rows = stmt.query_map(params![msg_id], |row| row.get::<_, String>("user"))?;

                let mut mentions = Vec::new();
                for row in rows {
                    mentions.push(row?);
                }
                Ok(mentions)
            })
            .await;

        match result {
            Ok(Ok(user_strings)) => Ok(
                user_strings
                    .into_iter()
                    .map(crate::messaging::user_handle::UserHandle::from)
                    .collect(),
            ),
            Ok(Err(e)) => Err(anyhow::anyhow!("Failed to get mentions: {}", e)),
            Err(e) => Err(anyhow::anyhow!("Database interaction failed: {}", e)),
        }
    }

    /// Get reactions for a message
    async fn get_reactions(
        &self,
        message_id: MessageId,
    ) -> Result<HashMap<String, Vec<crate::messaging::user_handle::UserHandle>>> {
        let conn = self.pool.get().await?;
        let msg_id = message_id.to_string();

        let result = conn
            .interact(
                move |conn| -> Result<HashMap<String, Vec<String>>, rusqlite::Error> {
                    let mut stmt = conn.prepare(
                "SELECT emoji, user_id FROM reactions WHERE message_id = ?1 ORDER BY created_at"
            )?;
                    let rows = stmt.query_map(params![msg_id], |row| {
                        Ok((
                            row.get::<_, String>("emoji")?,
                            row.get::<_, String>("user_id")?,
                        ))
                    })?;

                    let mut reactions: HashMap<String, Vec<String>> = HashMap::new();
                    for row in rows {
                        let (emoji, user_id) = row?;
                        reactions.entry(emoji).or_default().push(user_id);
                    }
                    Ok(reactions)
                },
            )
            .await;

        match result {
            Ok(Ok(reaction_strings)) => Ok(
                reaction_strings
                    .into_iter()
                    .map(|(emoji, users)| {
                        let handles = users
                            .into_iter()
                            .map(crate::messaging::user_handle::UserHandle::from)
                            .collect();
                        (emoji, handles)
                    })
                    .collect(),
            ),
            Ok(Err(e)) => Err(anyhow::anyhow!("Failed to get reactions: {}", e)),
            Err(e) => Err(anyhow::anyhow!("Database interaction failed: {}", e)),
        }
    }

    /// Update an existing message
    pub async fn update_message(&self, message: &RichMessage) -> Result<()> {
        // For simplicity, delete and re-insert the message
        // In production, you might want to do selective updates
        self.store_message(message).await
    }

    /// Get messages for a channel
    pub async fn get_channel_messages(
        &self,
        channel_id: ChannelId,
        limit: usize,
        before: Option<DateTime<Utc>>,
    ) -> Result<Vec<RichMessage>> {
        let conn = self.pool.get().await?;
        let chan_id = channel_id.to_string();
        let before_ts = before.map(|dt| dt.timestamp_millis()).unwrap_or(i64::MAX);

        let result = conn
            .interact(move |conn| -> Result<Vec<MessageId>, rusqlite::Error> {
                let mut stmt = conn.prepare(
                    "SELECT id FROM messages 
                 WHERE channel_id = ?1 AND created_at < ?2 AND deleted_at IS NULL
                 ORDER BY created_at DESC LIMIT ?3",
                )?;

                let rows = stmt.query_map(params![chan_id, before_ts, limit as i64], |row| {
                    let id_str: String = row.get("id")?;
                    Uuid::parse_str(&id_str).map(MessageId).map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            0,
                            "id".to_string(),
                            rusqlite::types::Type::Text,
                        )
                    })
                })?;

                let mut message_ids = Vec::new();
                for row in rows {
                    message_ids.push(row?);
                }
                Ok(message_ids)
            })
            .await;

        match result {
            Ok(Ok(message_ids)) => {
                let mut messages = Vec::new();
                for id in message_ids {
                    if let Ok(msg) = self.get_message(id).await {
                        messages.push(msg);
                    }
                }
                Ok(messages)
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("Failed to get channel messages: {}", e)),
            Err(e) => Err(anyhow::anyhow!("Database interaction failed: {}", e)),
        }
    }

    /// Mark a message as read
    pub async fn mark_as_read(&self, message_id: MessageId, user: crate::messaging::user_handle::UserHandle) -> Result<()> {
        let conn = self.pool.get().await?;
        let msg_id = message_id.to_string();
        let user_str = user.as_str().to_string();

        let result = conn
            .interact(move |conn| -> Result<(), rusqlite::Error> {
                conn.execute(
                    "INSERT OR REPLACE INTO read_receipts (message_id, user_id, read_at) 
                 VALUES (?1, ?2, ?3)",
                    params![msg_id, user_str, chrono::Utc::now().timestamp_millis()],
                )?;
                Ok(())
            })
            .await;

        match result {
            Ok(Ok(())) => {
                debug!("Message {} marked as read by {}", message_id, user);
                Ok(())
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("Failed to mark message as read: {}", e)),
            Err(e) => Err(anyhow::anyhow!("Database interaction failed: {}", e)),
        }
    }

    /// Search messages by content
    pub async fn search_messages(
        &self,
        query: &str,
        channel_id: Option<ChannelId>,
        limit: usize,
    ) -> Result<Vec<RichMessage>> {
        let conn = self.pool.get().await?;
        let search_query = format!("%{}%", query);
        let chan_filter = channel_id.map(|id| id.to_string());

        let result = conn
            .interact(move |conn| -> Result<Vec<MessageId>, rusqlite::Error> {
                let (sql, params): (String, Vec<Box<dyn rusqlite::ToSql + Send>>) =
                    if let Some(channel) = chan_filter {
                        (
                            "SELECT id FROM messages 
                     WHERE content LIKE ?1 AND channel_id = ?2 AND deleted_at IS NULL
                     ORDER BY created_at DESC LIMIT ?3"
                                .to_string(),
                            vec![
                                Box::new(search_query),
                                Box::new(channel),
                                Box::new(limit as i64),
                            ],
                        )
                    } else {
                        (
                            "SELECT id FROM messages 
                     WHERE content LIKE ?1 AND deleted_at IS NULL
                     ORDER BY created_at DESC LIMIT ?2"
                                .to_string(),
                            vec![Box::new(search_query), Box::new(limit as i64)],
                        )
                    };

                let mut stmt = conn.prepare(&sql)?;
                let param_refs: Vec<&dyn rusqlite::ToSql> = params
                    .iter()
                    .map(|p| p.as_ref() as &dyn rusqlite::ToSql)
                    .collect();

                let rows = stmt.query_map(param_refs.as_slice(), |row| {
                    let id_str: String = row.get("id")?;
                    Uuid::parse_str(&id_str).map(MessageId).map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            0,
                            "id".to_string(),
                            rusqlite::types::Type::Text,
                        )
                    })
                })?;

                let mut message_ids = Vec::new();
                for row in rows {
                    message_ids.push(row?);
                }
                Ok(message_ids)
            })
            .await;

        match result {
            Ok(Ok(message_ids)) => {
                let mut messages = Vec::new();
                for id in message_ids {
                    if let Ok(msg) = self.get_message(id).await {
                        messages.push(msg);
                    }
                }
                Ok(messages)
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("Failed to search messages: {}", e)),
            Err(e) => Err(anyhow::anyhow!("Database interaction failed: {}", e)),
        }
    }

    /// Add a reaction to a message
    pub async fn add_reaction(
        &self,
        message_id: MessageId,
        emoji: String,
        user: crate::messaging::user_handle::UserHandle,
    ) -> Result<()> {
        let conn = self.pool.get().await?;
        let msg_id = message_id.to_string();
        let user_str = user.as_str().to_string();
        let emoji_clone = emoji.clone();

        let result = conn
            .interact(move |conn| -> Result<(), rusqlite::Error> {
                conn.execute(
                    "INSERT OR IGNORE INTO reactions (message_id, emoji, user_id, created_at) 
                 VALUES (?1, ?2, ?3, ?4)",
                    params![
                        msg_id,
                        emoji_clone,
                        user_str,
                        chrono::Utc::now().timestamp_millis()
                    ],
                )?;
                Ok(())
            })
            .await;

        match result {
            Ok(Ok(())) => {
                debug!(
                    "Reaction {} added to message {} by {}",
                    emoji, message_id, user
                );
                Ok(())
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("Failed to add reaction: {}", e)),
            Err(e) => Err(anyhow::anyhow!("Database interaction failed: {}", e)),
        }
    }

    /// Remove a reaction from a message
    pub async fn remove_reaction(
        &self,
        message_id: MessageId,
        emoji: String,
        user: crate::messaging::user_handle::UserHandle,
    ) -> Result<()> {
        let conn = self.pool.get().await?;
        let msg_id = message_id.to_string();
        let user_str = user.as_str().to_string();
        let emoji_clone = emoji.clone();

        let result = conn
            .interact(move |conn| -> Result<(), rusqlite::Error> {
                conn.execute(
                    "DELETE FROM reactions 
                 WHERE message_id = ?1 AND emoji = ?2 AND user_id = ?3",
                    params![msg_id, emoji_clone, user_str],
                )?;
                Ok(())
            })
            .await;

        match result {
            Ok(Ok(())) => {
                debug!(
                    "Reaction {} removed from message {} by {}",
                    emoji, message_id, user
                );
                Ok(())
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("Failed to remove reaction: {}", e)),
            Err(e) => Err(anyhow::anyhow!("Database interaction failed: {}", e)),
        }
    }

    /// Get thread messages
    pub async fn get_thread_messages(&self, thread_id: ThreadId) -> Result<Vec<RichMessage>> {
        let conn = self.pool.get().await?;
        let thread_str = thread_id.to_string();

        let result = conn
            .interact(move |conn| -> Result<Vec<MessageId>, rusqlite::Error> {
                let mut stmt = conn.prepare(
                    "SELECT id FROM messages 
                 WHERE thread_id = ?1 AND deleted_at IS NULL
                 ORDER BY created_at ASC",
                )?;

                let rows = stmt.query_map(params![thread_str], |row| {
                    let id_str: String = row.get("id")?;
                    Uuid::parse_str(&id_str).map(MessageId).map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            0,
                            "id".to_string(),
                            rusqlite::types::Type::Text,
                        )
                    })
                })?;

                let mut message_ids = Vec::new();
                for row in rows {
                    message_ids.push(row?);
                }
                Ok(message_ids)
            })
            .await;

        match result {
            Ok(Ok(message_ids)) => {
                let mut messages = Vec::new();
                for id in message_ids {
                    if let Ok(msg) = self.get_message(id).await {
                        messages.push(msg);
                    }
                }
                Ok(messages)
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("Failed to get thread messages: {}", e)),
            Err(e) => Err(anyhow::anyhow!("Database interaction failed: {}", e)),
        }
    }

    /// Get database statistics
    pub async fn get_stats(&self) -> Result<DatabaseStats> {
        let conn = self.pool.get().await?;

        let result = conn
            .interact(|conn| -> Result<DatabaseStats, rusqlite::Error> {
                let mut total_messages: i64 = 0;
                let mut total_attachments: i64 = 0;
                let mut total_reactions: i64 = 0;
                conn.query_row("SELECT COUNT(*) FROM messages", [], |row| {
                    total_messages = row.get(0)?;
                    Ok(())
                })?;

                conn.query_row("SELECT COUNT(*) FROM attachments", [], |row| {
                    total_attachments = row.get(0)?;
                    Ok(())
                })?;

                conn.query_row("SELECT COUNT(*) FROM reactions", [], |row| {
                    total_reactions = row.get(0)?;
                    Ok(())
                })?;

                // Get database page count and page size to calculate size
                let page_count: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0))?;
                let page_size: i64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
                let db_size = page_count * page_size;

                Ok(DatabaseStats {
                    total_messages: total_messages as u64,
                    total_attachments: total_attachments as u64,
                    total_reactions: total_reactions as u64,
                    database_size_bytes: db_size as u64,
                })
            })
            .await;

        match result {
            Ok(Ok(stats)) => Ok(stats),
            Ok(Err(e)) => Err(anyhow::anyhow!("Failed to get database stats: {}", e)),
            Err(e) => Err(anyhow::anyhow!("Database interaction failed: {}", e)),
        }
    }

    /// Clean up ephemeral messages
    pub async fn cleanup_ephemeral(&self, ttl_seconds: i64) -> Result<usize> {
        let conn = self.pool.get().await?;
        let cutoff_time = chrono::Utc::now().timestamp_millis() - (ttl_seconds * 1000);

        let result = conn
            .interact(move |conn| -> Result<usize, rusqlite::Error> {
                let changes = conn.execute(
                    "DELETE FROM messages 
                 WHERE ephemeral = 1 AND created_at < ?1",
                    params![cutoff_time],
                )?;
                Ok(changes)
            })
            .await;

        match result {
            Ok(Ok(count)) => {
                info!("Cleaned up {} ephemeral messages", count);
                Ok(count)
            }
            Ok(Err(e)) => Err(anyhow::anyhow!(
                "Failed to cleanup ephemeral messages: {}",
                e
            )),
            Err(e) => Err(anyhow::anyhow!("Database interaction failed: {}", e)),
        }
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub total_messages: u64,
    pub total_attachments: u64,
    pub total_reactions: u64,
    pub database_size_bytes: u64,
}

// Type alias for compatibility
pub type MessageStore = DatabaseMessageStore;
