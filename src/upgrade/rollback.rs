// Copyright (c) 2025 Saorsa Labs Limited

// This file is part of the Saorsa P2P network.

// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Copyright 2024 P2P Foundation
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rollback and backup management for updates.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::error::UpgradeError;
use super::manifest::Platform;

/// Metadata about a backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    /// Version that was backed up.
    pub version: String,

    /// When the backup was created (Unix timestamp).
    pub created_at: u64,

    /// Path to the backup binary (relative to backup dir).
    pub backup_filename: String,

    /// Original path of the binary.
    pub original_path: String,

    /// Platform identifier.
    pub platform: String,

    /// SHA-256 checksum of the backup.
    pub checksum: String,

    /// Size in bytes.
    pub size: u64,
}

impl BackupMetadata {
    /// Get the age of this backup.
    #[must_use]
    pub fn age(&self) -> Duration {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Duration::from_secs(now.saturating_sub(self.created_at))
    }
}

/// Manager for backup and rollback operations.
pub struct RollbackManager {
    /// Directory for storing backups.
    backup_dir: PathBuf,

    /// Maximum age for backups before cleanup.
    max_backup_age: Duration,

    /// Maximum number of backups to retain.
    max_backups: usize,
}

impl RollbackManager {
    /// Create a new rollback manager.
    #[must_use]
    pub fn new(backup_dir: PathBuf) -> Self {
        Self {
            backup_dir,
            max_backup_age: Duration::from_secs(30 * 24 * 3600), // 30 days
            max_backups: 5,
        }
    }

    /// Set maximum backup age.
    #[must_use]
    pub fn with_max_age(mut self, age: Duration) -> Self {
        self.max_backup_age = age;
        self
    }

    /// Set maximum number of backups.
    #[must_use]
    pub fn with_max_backups(mut self, count: usize) -> Self {
        self.max_backups = count;
        self
    }

    /// Get the backup directory.
    #[must_use]
    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }

    /// Ensure the backup directory exists.
    pub async fn ensure_backup_dir(&self) -> Result<(), UpgradeError> {
        tokio::fs::create_dir_all(&self.backup_dir)
            .await
            .map_err(|e| UpgradeError::io(format!("failed to create backup directory: {}", e)))
    }

    /// Get the metadata file path.
    fn metadata_path(&self) -> PathBuf {
        self.backup_dir.join("backups.json")
    }

    /// Load all backup metadata.
    pub async fn load_metadata(&self) -> Result<Vec<BackupMetadata>, UpgradeError> {
        let path = self.metadata_path();
        if !path.exists() {
            return Ok(Vec::new());
        }

        let json = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| UpgradeError::io(format!("failed to read backup metadata: {}", e)))?;

        let backups: Vec<BackupMetadata> = serde_json::from_str(&json)
            .map_err(|e| UpgradeError::io(format!("failed to parse backup metadata: {}", e)))?;

        Ok(backups)
    }

    /// Save backup metadata.
    async fn save_metadata(&self, backups: &[BackupMetadata]) -> Result<(), UpgradeError> {
        let json = serde_json::to_string_pretty(backups)
            .map_err(|e| UpgradeError::io(format!("failed to serialize backup metadata: {}", e)))?;

        tokio::fs::write(self.metadata_path(), json)
            .await
            .map_err(|e| UpgradeError::io(format!("failed to write backup metadata: {}", e)))
    }

    /// Create a backup of a binary.
    pub async fn create_backup(
        &self,
        binary_path: &Path,
        version: &str,
        platform: Platform,
    ) -> Result<BackupMetadata, UpgradeError> {
        self.ensure_backup_dir().await?;

        // Read the binary
        let contents = tokio::fs::read(binary_path)
            .await
            .map_err(|e| UpgradeError::io(format!("failed to read binary for backup: {}", e)))?;

        // Calculate checksum
        let checksum = super::verifier::SignatureVerifier::calculate_checksum(&contents);

        // Generate backup filename
        let extension = if platform.is_windows() { ".exe" } else { "" };
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let backup_filename = format!(
            "saorsa-{}-{}-{}{}.bak",
            version,
            platform.as_str(),
            timestamp,
            extension
        );

        let backup_path = self.backup_dir.join(&backup_filename);

        // Write the backup
        tokio::fs::write(&backup_path, &contents)
            .await
            .map_err(|e| UpgradeError::io(format!("failed to write backup: {}", e)))?;

        let metadata = BackupMetadata {
            version: version.to_string(),
            created_at: timestamp,
            backup_filename,
            original_path: binary_path.to_string_lossy().to_string(),
            platform: platform.as_str().to_string(),
            checksum,
            size: contents.len() as u64,
        };

        // Update metadata file
        let mut backups = self.load_metadata().await.unwrap_or_default();
        backups.push(metadata.clone());
        self.save_metadata(&backups).await?;

        // Cleanup old backups
        self.cleanup_old_backups().await?;

        Ok(metadata)
    }

    /// Get the most recent backup.
    pub async fn get_latest_backup(&self) -> Result<Option<BackupMetadata>, UpgradeError> {
        let backups = self.load_metadata().await?;
        Ok(backups.into_iter().max_by_key(|b| b.created_at))
    }

    /// Get backup for a specific version.
    pub async fn get_backup_for_version(
        &self,
        version: &str,
    ) -> Result<Option<BackupMetadata>, UpgradeError> {
        let backups = self.load_metadata().await?;
        Ok(backups.into_iter().find(|b| b.version == version))
    }

    /// Check if rollback is available.
    pub async fn can_rollback(&self) -> bool {
        if let Ok(Some(backup)) = self.get_latest_backup().await {
            let backup_path = self.backup_dir.join(&backup.backup_filename);
            backup_path.exists()
        } else {
            false
        }
    }

    /// Perform a rollback to the previous version.
    pub async fn rollback(&self) -> Result<BackupMetadata, UpgradeError> {
        let backup = self
            .get_latest_backup()
            .await?
            .ok_or_else(|| UpgradeError::NoRollback("no backup available".into()))?;

        let backup_path = self.backup_dir.join(&backup.backup_filename);

        if !backup_path.exists() {
            return Err(UpgradeError::NoRollback("backup file not found".into()));
        }

        // Verify backup integrity
        let contents = tokio::fs::read(&backup_path)
            .await
            .map_err(|e| UpgradeError::io(format!("failed to read backup: {}", e)))?;

        let actual_checksum = super::verifier::SignatureVerifier::calculate_checksum(&contents);

        if actual_checksum != backup.checksum {
            return Err(UpgradeError::Rollback(
                format!(
                    "backup corrupted: checksum mismatch (expected {}, got {})",
                    backup.checksum, actual_checksum
                )
                .into(),
            ));
        }

        // Restore to original path
        let original_path = PathBuf::from(&backup.original_path);

        // Create parent directory if needed
        if let Some(parent) = original_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| UpgradeError::io(format!("failed to create directory: {}", e)))?;
        }

        // Write the restored binary
        tokio::fs::write(&original_path, &contents)
            .await
            .map_err(|e| {
                UpgradeError::Rollback(format!("failed to restore binary: {}", e).into())
            })?;

        // Set executable permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            tokio::fs::set_permissions(&original_path, perms)
                .await
                .map_err(|e| UpgradeError::io(format!("failed to set permissions: {}", e)))?;
        }

        Ok(backup)
    }

    /// Rollback to a specific version.
    pub async fn rollback_to_version(&self, version: &str) -> Result<BackupMetadata, UpgradeError> {
        let backup = self.get_backup_for_version(version).await?.ok_or_else(|| {
            UpgradeError::NoRollback(format!("no backup for version {}", version).into())
        })?;

        let backup_path = self.backup_dir.join(&backup.backup_filename);

        if !backup_path.exists() {
            return Err(UpgradeError::NoRollback("backup file not found".into()));
        }

        // Read and verify
        let contents = tokio::fs::read(&backup_path)
            .await
            .map_err(|e| UpgradeError::io(format!("failed to read backup: {}", e)))?;

        let actual_checksum = super::verifier::SignatureVerifier::calculate_checksum(&contents);

        if actual_checksum != backup.checksum {
            return Err(UpgradeError::Rollback("backup corrupted".into()));
        }

        // Restore
        let original_path = PathBuf::from(&backup.original_path);
        tokio::fs::write(&original_path, &contents)
            .await
            .map_err(|e| {
                UpgradeError::Rollback(format!("failed to restore binary: {}", e).into())
            })?;

        // Set executable permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            tokio::fs::set_permissions(&original_path, perms)
                .await
                .map_err(|e| UpgradeError::io(format!("failed to set permissions: {}", e)))?;
        }

        Ok(backup)
    }

    /// List all available backups.
    pub async fn list_backups(&self) -> Result<Vec<BackupMetadata>, UpgradeError> {
        let mut backups = self.load_metadata().await?;
        backups.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(backups)
    }

    /// Clean up old backups based on age and count limits.
    pub async fn cleanup_old_backups(&self) -> Result<usize, UpgradeError> {
        let mut backups = self.load_metadata().await?;
        let original_count = backups.len();

        // Sort by creation time (newest first)
        backups.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        // Filter out old backups
        let mut to_remove = Vec::new();
        let mut to_keep = Vec::new();

        for (i, backup) in backups.into_iter().enumerate() {
            let too_old = backup.age() > self.max_backup_age;
            let exceeds_limit = i >= self.max_backups;

            if too_old || exceeds_limit {
                to_remove.push(backup);
            } else {
                to_keep.push(backup);
            }
        }

        // Delete removed backup files
        for backup in &to_remove {
            let path = self.backup_dir.join(&backup.backup_filename);
            let _ = tokio::fs::remove_file(&path).await;
        }

        // Save updated metadata
        self.save_metadata(&to_keep).await?;

        Ok(original_count - to_keep.len())
    }

    /// Delete a specific backup.
    pub async fn delete_backup(&self, version: &str) -> Result<bool, UpgradeError> {
        let mut backups = self.load_metadata().await?;

        if let Some(pos) = backups.iter().position(|b| b.version == version) {
            let backup = backups.remove(pos);

            // Delete the file
            let path = self.backup_dir.join(&backup.backup_filename);
            let _ = tokio::fs::remove_file(&path).await;

            // Save updated metadata
            self.save_metadata(&backups).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Clean up all backups.
    pub async fn cleanup_all(&self) -> Result<(), UpgradeError> {
        if self.backup_dir.exists() {
            tokio::fs::remove_dir_all(&self.backup_dir)
                .await
                .map_err(|e| UpgradeError::io(format!("failed to cleanup backups: {}", e)))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_backup_metadata_age() {
        let metadata = BackupMetadata {
            version: "1.0.0".to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() - 3600) // 1 hour ago
                .unwrap_or(0),
            backup_filename: "test.bak".to_string(),
            original_path: "/usr/bin/saorsa".to_string(),
            platform: "linux-x64".to_string(),
            checksum: "abc123".to_string(),
            size: 1000,
        };

        let age = metadata.age();
        // Should be approximately 1 hour (3600 seconds)
        assert!(age.as_secs() >= 3590 && age.as_secs() <= 3610);
    }

    #[test]
    fn test_rollback_manager_creation() {
        let manager = RollbackManager::new(PathBuf::from("/backup"))
            .with_max_age(Duration::from_secs(7 * 24 * 3600))
            .with_max_backups(3);

        assert_eq!(manager.max_backup_age, Duration::from_secs(7 * 24 * 3600));
        assert_eq!(manager.max_backups, 3);
    }

    #[tokio::test]
    async fn test_backup_and_rollback() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");
        let manager = RollbackManager::new(backup_dir);

        // Create a test binary
        let binary_path = temp_dir.path().join("test-binary");
        tokio::fs::write(&binary_path, b"binary content")
            .await
            .unwrap();

        // Create backup
        let backup = manager
            .create_backup(&binary_path, "1.0.0", Platform::LinuxX64)
            .await
            .unwrap();

        assert_eq!(backup.version, "1.0.0");
        assert_eq!(backup.size, 14);

        // Should be able to rollback now
        assert!(manager.can_rollback().await);

        // List backups
        let backups = manager.list_backups().await.unwrap();
        assert_eq!(backups.len(), 1);

        // Delete the original binary
        tokio::fs::remove_file(&binary_path).await.unwrap();

        // Rollback
        let restored = manager.rollback().await.unwrap();
        assert_eq!(restored.version, "1.0.0");

        // Binary should exist again
        assert!(binary_path.exists());

        let contents = tokio::fs::read(&binary_path).await.unwrap();
        assert_eq!(contents, b"binary content");
    }

    #[tokio::test]
    async fn test_multiple_backups() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");
        let manager = RollbackManager::new(backup_dir).with_max_backups(3);

        let binary_path = temp_dir.path().join("test-binary");

        // Create multiple backups
        for i in 1..=5 {
            let version = format!("1.0.{}", i);
            let content = format!("version {}", i);
            tokio::fs::write(&binary_path, content.as_bytes())
                .await
                .unwrap();

            manager
                .create_backup(&binary_path, &version, Platform::LinuxX64)
                .await
                .unwrap();
        }

        // Should only keep 3 most recent
        let backups = manager.list_backups().await.unwrap();
        assert!(backups.len() <= 3);
    }

    #[tokio::test]
    async fn test_delete_backup() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");
        let manager = RollbackManager::new(backup_dir);

        let binary_path = temp_dir.path().join("test-binary");
        tokio::fs::write(&binary_path, b"test").await.unwrap();

        manager
            .create_backup(&binary_path, "1.0.0", Platform::LinuxX64)
            .await
            .unwrap();

        assert!(manager.can_rollback().await);

        let deleted = manager.delete_backup("1.0.0").await.unwrap();
        assert!(deleted);

        assert!(!manager.can_rollback().await);
    }
}
