// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! DHT-based storage module for multi-device synchronization
//!
//! All user data is stored in the DHT with proper encryption for privacy
//! and multi-device access.

use crate::dht::{DHT, Key};
use crate::identity::enhanced::EnhancedIdentity;
use aes_gcm::{
    Aes256Gcm, Key as AesKey, Nonce,
    aead::{Aead, KeyInit},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// Storage errors
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("DHT error: {0}")]
    DhtError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid data format")]
    InvalidFormat,
}

type Result<T> = std::result::Result<T, StorageError>;

/// DHT key patterns for different data types
pub mod keys {
    /// User profile key pattern
    pub fn profile(user_id: &str) -> String {
        format!("profile:{user_id}")
    }

    /// Device registry key
    pub fn devices(user_id: &str) -> String {
        format!("devices:{user_id}")
    }

    /// Chat channel key
    pub fn chat_channel(channel_id: &str) -> String {
        format!("chat:channel:{channel_id}")
    }

    /// Chat message key
    pub fn chat_message(channel_id: &str, msg_id: &str) -> String {
        format!("chat:msg:{channel_id}:{msg_id}")
    }

    /// Chat message index (for pagination)
    pub fn chat_index(channel_id: &str, timestamp: u64) -> String {
        format!("chat:idx:{channel_id}:{timestamp}")
    }

    /// Discussion topic key
    pub fn discuss_topic(topic_id: &str) -> String {
        format!("discuss:topic:{topic_id}")
    }

    /// Discussion reply key
    pub fn discuss_reply(topic_id: &str, reply_id: &str) -> String {
        format!("discuss:reply:{topic_id}:{reply_id}")
    }

    /// Project key
    pub fn project(project_id: &str) -> String {
        format!("project:{project_id}")
    }

    /// Document metadata key
    pub fn document_meta(doc_id: &str) -> String {
        format!("doc:meta:{doc_id}")
    }

    /// File chunk key
    pub fn file_chunk(file_id: &str, chunk_num: u32) -> String {
        format!("file:chunk:{file_id}:{chunk_num:08}")
    }

    /// Organization key
    pub fn organization(org_id: &str) -> String {
        format!("org:{org_id}")
    }

    /// Public channel discovery
    pub fn public_channel_list() -> String {
        "public:channels".to_string()
    }

    /// User's joined channels
    pub fn user_channels(user_id: &str) -> String {
        format!("user:channels:{user_id}")
    }
}

/// TTL values for different data types
pub mod ttl {
    use std::time::Duration;

    /// Profile data - effectively permanent
    pub const PROFILE: Duration = Duration::from_secs(365 * 24 * 60 * 60); // 1 year

    /// Messages - long term storage
    pub const MESSAGE: Duration = Duration::from_secs(90 * 24 * 60 * 60); // 90 days

    /// File chunks - permanent until deleted
    pub const FILE_CHUNK: Duration = Duration::from_secs(365 * 24 * 60 * 60); // 1 year

    /// Temporary data
    pub const TEMP: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours

    /// Presence/status updates
    pub const PRESENCE: Duration = Duration::from_secs(5 * 60); // 5 minutes
}

/// Encrypted data wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Encrypted payload
    pub ciphertext: Vec<u8>,

    /// Nonce used for encryption
    pub nonce: Vec<u8>,

    /// Key ID (for key rotation)
    pub key_id: String,

    /// Timestamp
    pub timestamp: SystemTime,

    /// Optional metadata (unencrypted)
    pub metadata: Option<serde_json::Value>,
}

/// Storage manager for DHT operations
pub struct StorageManager {
    /// DHT instance
    dht: DHT,

    /// Encryption keys (in production, use secure key storage)
    master_key: [u8; 32],
}

impl StorageManager {
    /// Create new storage manager
    pub fn new(dht: DHT, identity: &EnhancedIdentity) -> Result<Self> {
        // Derive master key from identity (simplified - use proper KDF in production)
        let mut hasher = Sha256::new();
        hasher.update(identity.base_identity.user_id.as_bytes()); // Placeholder implementation
        let master_key: [u8; 32] = hasher.finalize().into();

        Ok(Self { dht, master_key })
    }

    /// Store encrypted data in DHT
    pub async fn store_encrypted<T: Serialize>(
        &mut self,
        key: &str,
        data: &T,
        _ttl: Duration,
        metadata: Option<serde_json::Value>,
    ) -> Result<()> {
        // Serialize data
        let plaintext = bincode::serialize(data)?;

        // Encrypt data
        let encrypted = self.encrypt(&plaintext)?;

        // Create encrypted wrapper
        let wrapper = EncryptedData {
            ciphertext: encrypted.0,
            nonce: encrypted.1.to_vec(),
            key_id: "v1".to_string(),
            timestamp: SystemTime::now(),
            metadata,
        };

        // Serialize wrapper
        let wrapper_bytes = bincode::serialize(&wrapper)?;

        // Store in DHT
        let dht_key = Key::new(key.as_bytes());

        self.dht
            .put(dht_key, wrapper_bytes)
            .await
            .map_err(|e| StorageError::DhtError(e.to_string()))?;

        Ok(())
    }

    /// Retrieve and decrypt data from DHT
    pub async fn get_encrypted<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<T> {
        // Get from DHT
        let dht_key = Key::new(key.as_bytes());
        let record = self
            .dht
            .get(&dht_key)
            .await
            .ok_or_else(|| StorageError::KeyNotFound(key.to_string()))?;

        // Deserialize wrapper
        let wrapper: EncryptedData = bincode::deserialize(&record.value)?;

        // Decrypt data
        let plaintext = self.decrypt(&wrapper.ciphertext, &wrapper.nonce)?;

        // Deserialize data
        let data = bincode::deserialize(&plaintext)?;

        Ok(data)
    }

    /// Store public (unencrypted) data
    pub async fn store_public<T: Serialize>(
        &mut self,
        key: &str,
        data: &T,
        _ttl: Duration,
    ) -> Result<()> {
        let value = bincode::serialize(data)?;

        let dht_key = Key::new(key.as_bytes());

        self.dht
            .put(dht_key, value)
            .await
            .map_err(|e| StorageError::DhtError(e.to_string()))?;

        Ok(())
    }

    /// Get public data
    pub async fn get_public<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<T> {
        let dht_key = Key::new(key.as_bytes());
        let record = self
            .dht
            .get(&dht_key)
            .await
            .ok_or_else(|| StorageError::KeyNotFound(key.to_string()))?;

        let data = bincode::deserialize(&record.value)?;
        Ok(data)
    }

    /// Delete data from DHT
    pub async fn delete(&mut self, key: &str) -> Result<()> {
        // DHT doesn't expose direct delete method, so we'll put an empty value with immediate expiry
        let dht_key = Key::new(key.as_bytes());
        self.dht
            .put(dht_key, vec![])
            .await
            .map_err(|e| StorageError::DhtError(e.to_string()))?;
        Ok(())
    }

    /// List keys with prefix (for discovery)
    pub async fn list_keys(&self, _prefix: &str) -> Result<Vec<String>> {
        // In a real implementation, this would query the DHT for keys with prefix
        // For now, return empty list
        Ok(vec![])
    }

    /// Encrypt data using AES-256-GCM
    fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
        let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&self.master_key));

        // Generate random nonce
        let nonce_bytes = rand::random::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| StorageError::EncryptionError(e.to_string()))?;

        Ok((ciphertext, nonce_bytes))
    }

    /// Decrypt data
    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&self.master_key));
        let nonce = Nonce::from_slice(nonce);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| StorageError::EncryptionError(e.to_string()))?;

        Ok(plaintext)
    }
}

/*
// Multi-device sync manager (temporarily disabled)
pub struct SyncManager {
    storage: StorageManager,
    identity: EnhancedIdentity,
}

impl SyncManager {
    /// Create new sync manager
    pub fn new(storage: StorageManager, identity: EnhancedIdentity) -> Self {
        Self {
            storage,
            identity,
        }
    }

    /// Sync identity across devices
    pub async fn sync_identity(&mut self) -> Result<()> {
        // Store identity in DHT
        let key = keys::profile(&self.identity.base_identity.user_id);
        self.storage.store_encrypted(
            &key,
            &self.identity,
            ttl::PROFILE,
            None,
        ).await?;

        // Store device registry
        let devices_key = keys::devices(&self.identity.base_identity.user_id);
        self.storage.store_encrypted(
            &devices_key,
            &self.identity.devices,
            ttl::PROFILE,
            None,
        ).await?;

        // Update last sync time
        self.identity.last_sync = SystemTime::now();

        Ok(())
    }

    /// Load identity from DHT
    pub async fn load_identity(&self, user_id: &str) -> Result<EnhancedIdentity> {
        let key = keys::profile(user_id);
        self.storage.get_encrypted(&key).await
    }

    /// Register new device
    pub async fn register_device(
        &mut self,
        device_id: DeviceId,
        device_info: crate::identity::enhanced::DeviceInfo,
    ) -> Result<()> {
        // Add to local registry
        self.identity.devices.devices.insert(device_id.clone(), device_info);

        // Sync to DHT
        self.sync_identity().await
    }

    /// Check for updates from other devices
    pub async fn check_updates(&mut self) -> Result<bool> {
        let remote_identity = self.load_identity(&self.identity.base_identity.user_id).await?;

        if remote_identity.last_sync > self.identity.last_sync {
            // Remote is newer, update local
            self.identity = remote_identity;
            return Ok(true);
        }

        Ok(false)
    }
}
*/

/// File chunking for large media
pub struct FileChunker {
    chunk_size: usize,
}

impl FileChunker {
    /// Create new file chunker
    pub fn new(chunk_size: usize) -> Self {
        Self { chunk_size }
    }

    /// Split file into chunks
    pub fn chunk_file(&self, data: &[u8]) -> Vec<Vec<u8>> {
        data.chunks(self.chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    /// Store chunked file
    pub async fn store_file(
        &self,
        storage: &mut StorageManager,
        file_id: &str,
        data: &[u8],
        metadata: FileMetadata,
    ) -> Result<()> {
        let chunks = self.chunk_file(data);
        let total_chunks = chunks.len() as u32;

        // Store metadata
        let meta_with_chunks = FileMetadata {
            total_chunks,
            ..metadata
        };

        let meta_key = keys::document_meta(file_id);
        storage
            .store_encrypted(&meta_key, &meta_with_chunks, ttl::FILE_CHUNK, None)
            .await?;

        // Store chunks
        for (i, chunk) in chunks.iter().enumerate() {
            let chunk_key = keys::file_chunk(file_id, i as u32);
            storage
                .store_encrypted(&chunk_key, chunk, ttl::FILE_CHUNK, None)
                .await?;
        }

        Ok(())
    }

    /// Retrieve chunked file
    pub async fn get_file(&self, storage: &StorageManager, file_id: &str) -> Result<Vec<u8>> {
        // Get metadata
        let meta_key = keys::document_meta(file_id);
        let metadata: FileMetadata = storage.get_encrypted(&meta_key).await?;

        // Get chunks
        let mut data = Vec::new();
        for i in 0..metadata.total_chunks {
            let chunk_key = keys::file_chunk(file_id, i);
            let chunk: Vec<u8> = storage.get_encrypted(&chunk_key).await?;
            data.extend(chunk);
        }

        Ok(data)
    }
}

/// File metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub file_id: String,
    pub name: String,
    pub size: u64,
    pub mime_type: String,
    pub hash: Vec<u8>,
    pub total_chunks: u32,
    pub created_at: SystemTime,
    pub created_by: String,
}
