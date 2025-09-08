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

//! Virtual Disk API implementation for encrypted file storage

// TODO: Update to use new clean API
// use crate::api::{ContainerManifestV1, FecParams, container_manifest_put};

// Temporary stubs
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContainerManifestV1 {
    pub v: u8,
    pub object: Key,
    pub fec: Option<FecParams>,
    pub assets: Vec<Key>,
    pub sealed_meta: Option<Key>,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FecParams {
    pub k: usize,
    pub m: usize,
    pub shard_size: usize,
}
#[allow(dead_code)]
async fn container_manifest_put(_: &ContainerManifestV1, _: &FecParams, _: &PutPolicy) -> Result<Key> {
    unimplemented!("Virtual disk not yet migrated")
}
#[allow(dead_code)]
async fn container_manifest_fetch(_: &[u8]) -> Result<ContainerManifestV1> {
    unimplemented!("Virtual disk not yet migrated")
}

use crate::dht::PutPolicy;
use crate::fwid::Key;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Disk type for virtual disk instances
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiskType {
    /// Private encrypted disk for user data
    Private,
    /// Public disk for website/content hosting
    Public,
    /// Shared disk with access control
    Shared,
}

/// Configuration for virtual disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskConfig {
    /// Maximum disk size in bytes
    pub max_size: u64,
    /// Encryption enabled
    pub encrypted: bool,
    /// FEC parameters for redundancy
    pub fec: FecParams,
    /// Auto-sync interval in seconds
    pub auto_sync_interval: Option<u64>,
}

impl Default for DiskConfig {
    fn default() -> Self {
        Self {
            max_size: 1_073_741_824, // 1GB default
            encrypted: true,
            fec: FecParams {
                k: 4,              // 4 data shards
                m: 2,              // 2 parity shards
                shard_size: 65536, // 64KB shards
            },
            auto_sync_interval: Some(300), // 5 minutes
        }
    }
}

/// Handle to an active virtual disk
#[derive(Debug, Clone)]
pub struct DiskHandle {
    /// Entity ID owning this disk
    pub entity_id: Key,
    /// Disk type
    pub disk_type: DiskType,
    /// Disk configuration
    pub config: DiskConfig,
    /// Root manifest key
    pub root_manifest: Key,
    /// Internal state
    state: Arc<RwLock<DiskState>>,
}

/// Internal disk state
#[derive(Debug)]
struct DiskState {
    /// File system tree
    files: HashMap<PathBuf, FileEntry>,
    /// Total used space
    used_space: u64,
    /// Last sync time
    last_sync: DateTime<Utc>,
    /// Dirty flag for pending changes
    dirty: bool,
}

/// File entry in virtual disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// File path
    pub path: PathBuf,
    /// File size in bytes
    pub size: u64,
    /// Content hash
    pub content_hash: Key,
    /// File metadata
    pub metadata: FileMetadata,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Modification time
    pub modified_at: DateTime<Utc>,
    /// Is directory
    pub is_directory: bool,
}

/// File metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    /// MIME type
    pub mime_type: Option<String>,
    /// Custom attributes
    pub attributes: HashMap<String, String>,
    /// Permissions (Unix-style)
    pub permissions: u32,
}

impl Default for FileMetadata {
    fn default() -> Self {
        Self {
            mime_type: None,
            attributes: HashMap::new(),
            permissions: 0o644,
        }
    }
}

/// Write receipt for disk operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteReceipt {
    /// Written file path
    pub path: PathBuf,
    /// Content hash
    pub content_hash: Key,
    /// Bytes written
    pub bytes_written: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Sync status for disk synchronization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    /// Files synced
    pub files_synced: usize,
    /// Bytes synced
    pub bytes_synced: u64,
    /// Sync timestamp
    pub timestamp: DateTime<Utc>,
    /// Any errors encountered
    pub errors: Vec<String>,
}

/// Asset for website publishing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    /// Asset path (relative)
    pub path: String,
    /// Asset content
    pub content: Vec<u8>,
    /// MIME type
    pub mime_type: String,
}

/// Publish receipt for website publishing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishReceipt {
    /// Entity ID
    pub entity_id: Key,
    /// Website root key
    pub website_root: Key,
    /// Manifest key
    pub manifest_key: Key,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Create a new virtual disk
pub async fn disk_create(
    entity_id: Key,
    disk_type: DiskType,
    config: DiskConfig,
) -> Result<DiskHandle> {
    // Generate root manifest key
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(entity_id.as_bytes());
    hash_input.push(disk_type as u8);
    let root_manifest = Key::from(*blake3::hash(&hash_input).as_bytes());

    // Initialize disk state
    let state = Arc::new(RwLock::new(DiskState {
        files: HashMap::new(),
        used_space: 0,
        last_sync: Utc::now(),
        dirty: false,
    }));

    // Create initial manifest
    let manifest = ContainerManifestV1 {
        v: 1,
        object: root_manifest.clone(),
        fec: Some(config.fec.clone()),
        assets: Vec::new(),
        sealed_meta: if config.encrypted {
            Some(Key::from([0u8; 32])) // Placeholder for sealed metadata
        } else {
            None
        },
    };

    // Store manifest in DHT
    #[cfg(any(test, feature = "test-utils"))]
    {
        use crate::mock_dht::mock_ops;
        mock_ops::container_manifest_put(
            &manifest,
            &PutPolicy {
                quorum: 3,
                ttl: None,
                // auth: Box::new(crate::auth::DelegatedWriteAuth::new(vec![])),
            },
        )
        .await?;
    }

    #[cfg(not(any(test, feature = "test-utils")))]
    {
        let fec_params = manifest.fec.as_ref().unwrap_or(&config.fec);
        container_manifest_put(
            &manifest,
            fec_params,
            &PutPolicy {
                quorum: 3,
                ttl: None,
                // auth: Box::new(crate::auth::DelegatedWriteAuth::new(vec![])),
            },
        )
        .await?;
    }

    Ok(DiskHandle {
        entity_id,
        disk_type,
        config,
        root_manifest,
        state,
    })
}

/// Mount an existing virtual disk
pub async fn disk_mount(entity_id: Key, disk_type: DiskType) -> Result<DiskHandle> {
    // Derive root manifest key
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(entity_id.as_bytes());
    hash_input.push(disk_type as u8);
    let root_manifest = Key::from(*blake3::hash(&hash_input).as_bytes());

    // Fetch manifest from DHT
    #[cfg(any(test, feature = "test-utils"))]
    let _manifest =
        crate::mock_dht::mock_ops::container_manifest_fetch(root_manifest.as_bytes()).await?;

    #[cfg(not(any(test, feature = "test-utils")))]
    let _manifest = container_manifest_fetch(root_manifest.as_bytes()).await?;

    // Load disk state from manifest
    // TODO: Deserialize file tree from manifest assets
    let state = Arc::new(RwLock::new(DiskState {
        files: HashMap::new(),
        used_space: 0,
        last_sync: Utc::now(),
        dirty: false,
    }));

    Ok(DiskHandle {
        entity_id,
        disk_type,
        config: DiskConfig::default(),
        root_manifest,
        state,
    })
}

/// Write a file to the virtual disk
pub async fn disk_write(
    handle: &DiskHandle,
    path: &str,
    content: &[u8],
    metadata: FileMetadata,
) -> Result<WriteReceipt> {
    let path_buf = PathBuf::from(path);

    // Check disk space
    let mut state = handle.state.write().await;
    if state.used_space + content.len() as u64 > handle.config.max_size {
        anyhow::bail!("Disk space exceeded");
    }

    // Hash content
    let content_hash = Key::from(*blake3::hash(content).as_bytes());

    // Apply FEC encoding / encryption (handled in build-specific branches below)
    // TODO: Use saorsa-fec for forward error correction

    // Store in DHT
    #[cfg(any(test, feature = "test-utils"))]
    {
        // Encrypt if needed
        let stored_content = if handle.config.encrypted {
            // TODO: Use saorsa-seal for encryption
            content.to_vec()
        } else {
            content.to_vec()
        };
        let pol = PutPolicy {
            quorum: 3,
            ttl: None,
            // auth: Box::new(crate::auth::DelegatedWriteAuth::new(vec![])),
        };
        crate::mock_dht::mock_ops::dht_put(
            content_hash.clone(),
            bytes::Bytes::from(stored_content),
            &pol,
        )
        .await?;
    }

    #[cfg(not(any(test, feature = "test-utils")))]
    {
        let _pol = PutPolicy {
            quorum: 3,
            ttl: None,
            // auth: Box::new(crate::auth::DelegatedWriteAuth::new(vec![])),
        };
        // TODO: Update to use new clean API
        // crate::api::dht_put(
        //     content_hash.clone(),
        //     bytes::Bytes::from(stored_content),
        //     &pol,
        // )
        // .await?;
    }

    // Update file tree
    let now = Utc::now();
    let entry = FileEntry {
        path: path_buf.clone(),
        size: content.len() as u64,
        content_hash: content_hash.clone(),
        metadata,
        created_at: state
            .files
            .get(&path_buf)
            .map(|e| e.created_at)
            .unwrap_or(now),
        modified_at: now,
        is_directory: false,
    };

    // Update state
    if let Some(old_entry) = state.files.insert(path_buf.clone(), entry) {
        state.used_space -= old_entry.size;
    }
    state.used_space += content.len() as u64;
    state.dirty = true;

    Ok(WriteReceipt {
        path: path_buf,
        content_hash,
        bytes_written: content.len() as u64,
        timestamp: now,
    })
}

/// Read a file from the virtual disk
pub async fn disk_read(handle: &DiskHandle, path: &str) -> Result<Vec<u8>> {
    let path_buf = PathBuf::from(path);

    // Find file in tree
    let state = handle.state.read().await;
    let entry = state
        .files
        .get(&path_buf)
        .ok_or_else(|| anyhow::anyhow!("File not found: {}", path))?;

    if entry.is_directory {
        anyhow::bail!("Path is a directory: {}", path);
    }

    // Fetch from DHT
    #[cfg(any(test, feature = "test-utils"))]
    let content = crate::mock_dht::mock_ops::dht_get(entry.content_hash.clone(), 1).await?;

    #[cfg(not(any(test, feature = "test-utils")))]
    // TODO: Update to use new clean API
    // let content = crate::api::dht_get(entry.content_hash.clone(), 1).await?;
    let content = bytes::Bytes::from(vec![]);

    // Decrypt if needed
    let decrypted = if handle.config.encrypted {
        // TODO: Use saorsa-seal for decryption
        content.to_vec()
    } else {
        content.to_vec()
    };

    Ok(decrypted)
}

/// List files in a directory
pub async fn disk_list(handle: &DiskHandle, path: &str, recursive: bool) -> Result<Vec<FileEntry>> {
    let search_path = if path == "." {
        PathBuf::new() // Use empty path for current directory
    } else {
        PathBuf::from(path)
    };
    let state = handle.state.read().await;

    let mut results = Vec::new();

    for (file_path, entry) in &state.files {
        // Check if file is in the requested directory
        if recursive {
            // Include if path is ancestor or if we're listing from root
            if search_path.as_os_str().is_empty() || file_path.starts_with(&search_path) {
                results.push(entry.clone());
            }
        } else {
            // Include only direct children
            if let Some(parent) = file_path.parent() {
                if parent == search_path {
                    results.push(entry.clone());
                }
            } else if search_path.as_os_str().is_empty() {
                // File has no parent (is in root), and we're searching root
                results.push(entry.clone());
            }
        }
    }

    // Sort by path
    results.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(results)
}

/// Delete a file from the virtual disk
pub async fn disk_delete(handle: &DiskHandle, path: &str) -> Result<()> {
    let path_buf = PathBuf::from(path);

    let mut state = handle.state.write().await;

    // Remove file from tree
    if let Some(entry) = state.files.remove(&path_buf) {
        state.used_space -= entry.size;
        state.dirty = true;
        Ok(())
    } else {
        Err(anyhow::anyhow!("File not found: {}", path))
    }
}

/// Synchronize disk state to DHT
pub async fn disk_sync(handle: &DiskHandle) -> Result<SyncStatus> {
    let mut state = handle.state.write().await;

    if !state.dirty {
        return Ok(SyncStatus {
            files_synced: 0,
            bytes_synced: 0,
            timestamp: Utc::now(),
            errors: Vec::new(),
        });
    }

    // Serialize file tree
    let file_list: Vec<FileEntry> = state.files.values().cloned().collect();
    let tree_bytes = serde_cbor::to_vec(&file_list)?;
    let tree_hash = Key::from(*blake3::hash(&tree_bytes).as_bytes());

    // Store tree in DHT
    #[cfg(any(test, feature = "test-utils"))]
    {
        let pol = PutPolicy {
            quorum: 3,
            ttl: None,
            // auth: Box::new(crate::auth::DelegatedWriteAuth::new(vec![])),
        };
        crate::mock_dht::mock_ops::dht_put(tree_hash.clone(), bytes::Bytes::from(tree_bytes), &pol)
            .await?;

        // Update manifest
        let manifest = ContainerManifestV1 {
            v: 1,
            object: handle.root_manifest.clone(),
            fec: Some(handle.config.fec.clone()),
            assets: vec![tree_hash],
            sealed_meta: if handle.config.encrypted {
                Some(Key::from([0u8; 32])) // Placeholder
            } else {
                None
            },
        };

        crate::mock_dht::mock_ops::container_manifest_put(&manifest, &pol).await?;
    }

    #[cfg(not(any(test, feature = "test-utils")))]
    {
        let pol = PutPolicy {
            quorum: 3,
            ttl: None,
            // auth: Box::new(crate::auth::DelegatedWriteAuth::new(vec![])),
        };
        // TODO: Update to use new clean API
        // crate::api::dht_put(tree_hash.clone(), bytes::Bytes::from(tree_bytes), &pol).await?;

        // Update manifest
        let manifest = ContainerManifestV1 {
            v: 1,
            object: handle.root_manifest.clone(),
            fec: Some(handle.config.fec.clone()),
            assets: vec![tree_hash],
            sealed_meta: if handle.config.encrypted {
                Some(Key::from([0u8; 32])) // Placeholder
            } else {
                None
            },
        };

        let fec_params = manifest.fec.as_ref().unwrap_or(&handle.config.fec);
        container_manifest_put(&manifest, fec_params, &pol).await?;
    }

    // Update state
    state.dirty = false;
    state.last_sync = Utc::now();

    Ok(SyncStatus {
        files_synced: state.files.len(),
        bytes_synced: state.used_space,
        timestamp: state.last_sync,
        errors: Vec::new(),
    })
}

/// Set the home page for a website
pub async fn website_set_home(
    handle: &DiskHandle,
    markdown_content: &str,
    assets: Vec<Asset>,
) -> Result<()> {
    // Write home.md
    disk_write(
        handle,
        "home.md",
        markdown_content.as_bytes(),
        FileMetadata {
            mime_type: Some("text/markdown".to_string()),
            ..Default::default()
        },
    )
    .await?;

    // Write assets
    for asset in assets {
        disk_write(
            handle,
            &asset.path,
            &asset.content,
            FileMetadata {
                mime_type: Some(asset.mime_type),
                ..Default::default()
            },
        )
        .await?;
    }

    // Sync to ensure persistence
    disk_sync(handle).await?;

    Ok(())
}

/// Publish a website from a disk
pub async fn website_publish(entity_id: Key, website_root: Key) -> Result<PublishReceipt> {
    // Create public disk if not exists
    let handle = match disk_mount(entity_id.clone(), DiskType::Public).await {
        Ok(h) => h,
        Err(_) => disk_create(entity_id.clone(), DiskType::Public, DiskConfig::default()).await?,
    };

    // Sync disk to ensure latest state
    disk_sync(&handle).await?;

    // Optionally update identity with website root
    // Note: This requires the caller to have signing material
    // identity_set_website_root(entity_id.clone(), website_root.clone(), sig).await?;

    Ok(PublishReceipt {
        entity_id,
        website_root,
        manifest_key: handle.root_manifest,
        timestamp: Utc::now(),
    })
}
