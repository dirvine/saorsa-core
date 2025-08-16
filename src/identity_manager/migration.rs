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

//! # Identity Data Migration Tool
//!
//! This module provides utilities for migrating existing plaintext identity
//! data to the new encrypted format.

#![allow(missing_docs)]

use crate::error::StorageError;
use crate::identity_manager::{Identity, IdentityManager, SecurityLevel};
use crate::secure_memory::SecureString;
use crate::{P2PError, Result};
use serde_json;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{error, info};

/// Migration status for tracking progress
#[derive(Debug, Clone)]
pub struct MigrationStatus {
    pub total_identities: usize,
    pub migrated: usize,
    pub failed: usize,
    pub skipped: usize,
}

/// Migrate plaintext identity files to encrypted format
pub struct IdentityMigrator {
    source_path: PathBuf,
    target_path: PathBuf,
    backup_path: PathBuf,
}

impl IdentityMigrator {
    /// Create a new migrator
    pub fn new<P: AsRef<Path>>(source_path: P, target_path: P, backup_path: P) -> Result<Self> {
        Ok(Self {
            source_path: source_path.as_ref().to_path_buf(),
            target_path: target_path.as_ref().to_path_buf(),
            backup_path: backup_path.as_ref().to_path_buf(),
        })
    }

    /// Perform the migration
    pub async fn migrate(
        &self,
        storage_password: &SecureString,
        device_password: &SecureString,
    ) -> Result<MigrationStatus> {
        info!("Starting identity migration from {:?}", self.source_path);

        // Create backup directory
        fs::create_dir_all(&self.backup_path).map_err(|e| {
            P2PError::Storage(StorageError::Database(
                format!("Failed to create backup directory: {}", e).into(),
            ))
        })?;

        // Create target directory
        fs::create_dir_all(&self.target_path).map_err(|e| {
            P2PError::Storage(StorageError::Database(
                format!("Failed to create target directory: {}", e).into(),
            ))
        })?;

        // Initialize new identity manager
        let manager = IdentityManager::new(&self.target_path, SecurityLevel::High).await?;
        manager.initialize(storage_password).await?;

        let mut status = MigrationStatus {
            total_identities: 0,
            migrated: 0,
            failed: 0,
            skipped: 0,
        };

        // Find all identity files
        let entries = fs::read_dir(&self.source_path).map_err(|e| {
            P2PError::Storage(StorageError::Database(
                format!("Failed to read source directory: {}", e).into(),
            ))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                P2PError::Storage(StorageError::Database(
                    format!("Failed to read directory entry: {}", e).into(),
                ))
            })?;

            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                status.total_identities += 1;

                match self
                    .migrate_identity_file(&path, &manager, storage_password, device_password)
                    .await
                {
                    Ok(true) => {
                        status.migrated += 1;
                        info!("Migrated identity from {:?}", path);
                    }
                    Ok(false) => {
                        status.skipped += 1;
                        info!("Skipped identity from {:?} (already encrypted)", path);
                    }
                    Err(e) => {
                        status.failed += 1;
                        error!("Failed to migrate identity from {:?}: {}", path, e);
                    }
                }
            }
        }

        info!("Migration completed: {:?}", status);
        Ok(status)
    }

    /// Migrate a single identity file
    async fn migrate_identity_file(
        &self,
        path: &Path,
        manager: &IdentityManager,
        storage_password: &SecureString,
        device_password: &SecureString,
    ) -> Result<bool> {
        // Backup the original file
        let file_name = path.file_name().ok_or_else(|| {
            P2PError::Storage(StorageError::Database(
                "Invalid file path: no filename".into(),
            ))
        })?;
        let backup_path = self.backup_path.join(file_name);
        fs::copy(path, &backup_path).map_err(|e| {
            P2PError::Storage(StorageError::Database(
                format!("Failed to backup file: {}", e).into(),
            ))
        })?;

        // Read the identity file
        let data = fs::read_to_string(path).map_err(|e| {
            P2PError::Storage(StorageError::Database(
                format!("Failed to read identity file: {}", e).into(),
            ))
        })?;

        // Check if it's already encrypted (contains encrypted_identity field)
        if data.contains("encrypted_identity") {
            return Ok(false); // Already migrated
        }

        // Parse as plaintext identity
        let identity: Identity = serde_json::from_str(&data)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;

        // Save using the encrypted manager
        manager.save_identity(&identity, storage_password).await?;

        // Create sync package for backup
        let sync_package = manager
            .create_sync_package(&identity.id, storage_password, device_password)
            .await?;

        // Save sync package as additional backup
        let sync_backup_path = self.backup_path.join(format!("{}_sync.enc", identity.id));
        let sync_data = serde_json::to_vec(&sync_package)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;
        fs::write(&sync_backup_path, sync_data).map_err(|e| {
            P2PError::Storage(StorageError::Database(
                format!("Failed to write sync backup: {}", e).into(),
            ))
        })?;

        Ok(true)
    }

    /// Verify migration by comparing counts
    pub async fn verify_migration(&self) -> Result<bool> {
        let source_count = self.count_identity_files(&self.source_path)?;
        let target_count = self.count_identity_files(&self.target_path)?;
        let backup_count = self.count_identity_files(&self.backup_path)?;

        info!(
            "Verification - Source: {}, Target: {}, Backup: {}",
            source_count, target_count, backup_count
        );

        Ok(source_count == target_count && source_count == backup_count / 2) // /2 because we create both .json and .enc backups
    }

    /// Count identity files in a directory
    fn count_identity_files(&self, path: &Path) -> Result<usize> {
        let mut count = 0;

        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    count += 1;
                }
            }
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_record::UserId;
    use std::collections::HashMap;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_migration_tool() {
        // Create temporary directories
        let source_dir = TempDir::new().unwrap();
        let target_dir = TempDir::new().unwrap();
        let backup_dir = TempDir::new().unwrap();

        // Create a plaintext identity file
        let identity = Identity {
            id: UserId::from_bytes([1u8; 32]),
            four_word_address: "test.word.address.here".to_string(),
            state: crate::identity_manager::IdentityState::Active,
            display_name: Some("Test User".to_string()),
            avatar_url: None,
            bio: Some("Test bio".to_string()),
            metadata: HashMap::new(),
            key_version: 1,
            created_at: 1000,
            updated_at: 1000,
            expires_at: 2000,
            previous_keys: vec![],
            revocation_cert: None,
        };

        let identity_path = source_dir.path().join(format!("{}.json", identity.id));
        let identity_data = serde_json::to_string_pretty(&identity).unwrap();
        fs::write(&identity_path, identity_data).unwrap();

        // Create migrator
        let migrator =
            IdentityMigrator::new(source_dir.path(), target_dir.path(), backup_dir.path()).unwrap();

        // Perform migration
        let storage_password = SecureString::from_plain_str("test_storage").unwrap();
        let device_password = SecureString::from_plain_str("test_device").unwrap();

        let status = migrator
            .migrate(&storage_password, &device_password)
            .await
            .unwrap();

        assert_eq!(status.total_identities, 1);
        assert_eq!(status.migrated, 1);
        assert_eq!(status.failed, 0);
        assert_eq!(status.skipped, 0);

        // Verify migration
        assert!(migrator.verify_migration().await.unwrap());

        // Check that backup was created
        let backup_path = backup_dir.path().join(format!("{}.json", identity.id));
        assert!(backup_path.exists());

        // Check that sync package backup was created
        let sync_backup_path = backup_dir.path().join(format!("{}_sync.enc", identity.id));
        assert!(sync_backup_path.exists());
    }
}
