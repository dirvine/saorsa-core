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

//! Staged update management for downloaded binaries.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::error::UpgradeError;
use super::manifest::Platform;

/// A staged update ready for application.
#[derive(Debug, Clone)]
pub struct StagedUpdate {
    /// Version of the staged update.
    pub version: String,

    /// Path to the staged binary.
    pub binary_path: PathBuf,

    /// Target platform.
    pub platform: Platform,

    /// SHA-256 checksum of the binary.
    pub checksum: String,

    /// Size in bytes.
    pub size: u64,

    /// When this update was staged (Unix timestamp).
    pub staged_at: u64,

    /// Whether this is a critical security update.
    pub is_critical: bool,

    /// Release notes for this update.
    pub release_notes: String,
}

impl StagedUpdate {
    /// Create a new staged update.
    #[must_use]
    pub fn new(
        version: impl Into<String>,
        binary_path: PathBuf,
        platform: Platform,
        checksum: impl Into<String>,
        size: u64,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            version: version.into(),
            binary_path,
            platform,
            checksum: checksum.into(),
            size,
            staged_at: now,
            is_critical: false,
            release_notes: String::new(),
        }
    }

    /// Set critical flag.
    #[must_use]
    pub fn with_critical(mut self, critical: bool) -> Self {
        self.is_critical = critical;
        self
    }

    /// Set release notes.
    #[must_use]
    pub fn with_release_notes(mut self, notes: impl Into<String>) -> Self {
        self.release_notes = notes.into();
        self
    }

    /// Check if the staged binary exists.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.binary_path.exists()
    }

    /// Verify the staged binary checksum.
    pub async fn verify(&self) -> Result<bool, UpgradeError> {
        use super::verifier::SignatureVerifier;

        let checksum = SignatureVerifier::calculate_file_checksum(&self.binary_path).await?;
        Ok(checksum == self.checksum)
    }

    /// Get the age of this staged update.
    #[must_use]
    pub fn age(&self) -> std::time::Duration {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        std::time::Duration::from_secs(now.saturating_sub(self.staged_at))
    }

    /// Clean up the staged update (delete binary).
    pub async fn cleanup(&self) -> Result<(), UpgradeError> {
        if self.binary_path.exists() {
            tokio::fs::remove_file(&self.binary_path)
                .await
                .map_err(|e| UpgradeError::io(format!("failed to cleanup staged update: {}", e)))?;
        }
        Ok(())
    }
}

/// Metadata for persisting staged update information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedUpdateMetadata {
    /// Version of the staged update.
    pub version: String,

    /// Relative path to the binary within staging directory.
    pub binary_filename: String,

    /// Target platform string.
    pub platform: String,

    /// SHA-256 checksum.
    pub checksum: String,

    /// Size in bytes.
    pub size: u64,

    /// When staged (Unix timestamp).
    pub staged_at: u64,

    /// Critical update flag.
    pub is_critical: bool,

    /// Release notes.
    pub release_notes: String,
}

impl StagedUpdateMetadata {
    /// Create metadata from a staged update.
    #[must_use]
    pub fn from_staged(staged: &StagedUpdate) -> Self {
        let binary_filename = staged
            .binary_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(String::from)
            .unwrap_or_else(|| "binary".to_string());

        Self {
            version: staged.version.clone(),
            binary_filename,
            platform: staged.platform.as_str().to_string(),
            checksum: staged.checksum.clone(),
            size: staged.size,
            staged_at: staged.staged_at,
            is_critical: staged.is_critical,
            release_notes: staged.release_notes.clone(),
        }
    }

    /// Convert back to staged update with base path.
    pub fn to_staged(&self, staging_dir: &Path) -> Option<StagedUpdate> {
        let platform = match self.platform.as_str() {
            "windows-x64" => Platform::WindowsX64,
            "windows-arm64" => Platform::WindowsArm64,
            "macos-x64" => Platform::MacOsX64,
            "macos-arm64" => Platform::MacOsArm64,
            "linux-x64" => Platform::LinuxX64,
            "linux-arm64" => Platform::LinuxArm64,
            _ => return None,
        };

        Some(StagedUpdate {
            version: self.version.clone(),
            binary_path: staging_dir.join(&self.binary_filename),
            platform,
            checksum: self.checksum.clone(),
            size: self.size,
            staged_at: self.staged_at,
            is_critical: self.is_critical,
            release_notes: self.release_notes.clone(),
        })
    }
}

/// Manager for staged updates in the staging directory.
pub struct StagedUpdateManager {
    /// Path to the staging directory.
    staging_dir: PathBuf,

    /// Maximum age for staged updates before cleanup.
    max_age: std::time::Duration,
}

impl StagedUpdateManager {
    /// Create a new staged update manager.
    #[must_use]
    pub fn new(staging_dir: PathBuf) -> Self {
        Self {
            staging_dir,
            max_age: std::time::Duration::from_secs(7 * 24 * 3600), // 7 days
        }
    }

    /// Set maximum age for staged updates.
    #[must_use]
    pub fn with_max_age(mut self, max_age: std::time::Duration) -> Self {
        self.max_age = max_age;
        self
    }

    /// Get the staging directory.
    #[must_use]
    pub fn staging_dir(&self) -> &Path {
        &self.staging_dir
    }

    /// Ensure the staging directory exists.
    pub async fn ensure_staging_dir(&self) -> Result<(), UpgradeError> {
        tokio::fs::create_dir_all(&self.staging_dir)
            .await
            .map_err(|e| {
                UpgradeError::staging(format!("failed to create staging directory: {}", e))
            })
    }

    /// Get the path for a new staged binary.
    #[must_use]
    pub fn staged_binary_path(&self, version: &str, platform: Platform) -> PathBuf {
        let extension = if platform.is_windows() { ".exe" } else { "" };
        let filename = format!("saorsa-{}-{}{}", version, platform.as_str(), extension);
        self.staging_dir.join(filename)
    }

    /// Get the metadata file path.
    fn metadata_path(&self) -> PathBuf {
        self.staging_dir.join("staged.json")
    }

    /// Save staged update metadata.
    pub async fn save_metadata(&self, staged: &StagedUpdate) -> Result<(), UpgradeError> {
        let metadata = StagedUpdateMetadata::from_staged(staged);
        let json = serde_json::to_string_pretty(&metadata)
            .map_err(|e| UpgradeError::staging(format!("failed to serialize metadata: {}", e)))?;

        tokio::fs::write(self.metadata_path(), json)
            .await
            .map_err(|e| UpgradeError::staging(format!("failed to write metadata: {}", e)))
    }

    /// Load staged update metadata.
    pub async fn load_metadata(&self) -> Result<Option<StagedUpdate>, UpgradeError> {
        let path = self.metadata_path();
        if !path.exists() {
            return Ok(None);
        }

        let json = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| UpgradeError::staging(format!("failed to read metadata: {}", e)))?;

        let metadata: StagedUpdateMetadata = serde_json::from_str(&json)
            .map_err(|e| UpgradeError::staging(format!("failed to parse metadata: {}", e)))?;

        Ok(metadata.to_staged(&self.staging_dir))
    }

    /// Check if there's a staged update.
    pub async fn has_staged_update(&self) -> bool {
        if let Ok(Some(staged)) = self.load_metadata().await {
            staged.exists()
        } else {
            false
        }
    }

    /// Get the current staged update if any.
    pub async fn get_staged_update(&self) -> Result<Option<StagedUpdate>, UpgradeError> {
        let staged = self.load_metadata().await?;

        if let Some(ref s) = staged
            && !s.exists()
        {
            // Binary is missing, clean up metadata
            self.clear_metadata().await?;
            return Ok(None);
        }

        Ok(staged)
    }

    /// Clear staged update metadata.
    pub async fn clear_metadata(&self) -> Result<(), UpgradeError> {
        let path = self.metadata_path();
        if path.exists() {
            tokio::fs::remove_file(&path)
                .await
                .map_err(|e| UpgradeError::staging(format!("failed to remove metadata: {}", e)))?;
        }
        Ok(())
    }

    /// Clean up old staged updates.
    pub async fn cleanup_old_updates(&self) -> Result<usize, UpgradeError> {
        let mut cleaned = 0;

        // Check metadata
        if let Ok(Some(staged)) = self.load_metadata().await
            && staged.age() > self.max_age
        {
            staged.cleanup().await?;
            self.clear_metadata().await?;
            cleaned += 1;
        }

        // Also clean any orphaned binaries in staging dir
        if let Ok(mut entries) = tokio::fs::read_dir(&self.staging_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();

                // Skip metadata file
                if path.file_name().and_then(|n| n.to_str()) == Some("staged.json") {
                    continue;
                }

                // Check file age and remove if too old
                if let Ok(metadata) = tokio::fs::metadata(&path).await
                    && let Ok(modified) = metadata.modified()
                {
                    let age = modified.elapsed().unwrap_or_default();
                    if age > self.max_age && tokio::fs::remove_file(&path).await.is_ok() {
                        cleaned += 1;
                    }
                }
            }
        }

        Ok(cleaned)
    }

    /// Clean up everything in the staging directory.
    pub async fn cleanup_all(&self) -> Result<(), UpgradeError> {
        if self.staging_dir.exists() {
            tokio::fs::remove_dir_all(&self.staging_dir)
                .await
                .map_err(|e| UpgradeError::staging(format!("failed to cleanup staging: {}", e)))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_staged_update_creation() {
        let staged = StagedUpdate::new(
            "1.0.0",
            PathBuf::from("/tmp/binary"),
            Platform::LinuxX64,
            "abc123",
            1000,
        );

        assert_eq!(staged.version, "1.0.0");
        assert_eq!(staged.checksum, "abc123");
        assert_eq!(staged.size, 1000);
        assert!(!staged.is_critical);
    }

    #[test]
    fn test_staged_update_with_critical() {
        let staged = StagedUpdate::new(
            "1.0.0",
            PathBuf::from("/tmp/binary"),
            Platform::LinuxX64,
            "abc",
            100,
        )
        .with_critical(true)
        .with_release_notes("Security fix");

        assert!(staged.is_critical);
        assert_eq!(staged.release_notes, "Security fix");
    }

    #[test]
    fn test_metadata_conversion() {
        let staged = StagedUpdate::new(
            "2.0.0",
            PathBuf::from("/staging/binary"),
            Platform::MacOsArm64,
            "def456",
            2000,
        )
        .with_critical(true);

        let metadata = StagedUpdateMetadata::from_staged(&staged);
        assert_eq!(metadata.version, "2.0.0");
        assert_eq!(metadata.platform, "macos-arm64");
        assert!(metadata.is_critical);

        let restored = metadata.to_staged(Path::new("/staging"));
        assert!(restored.is_some());

        let restored = restored.unwrap();
        assert_eq!(restored.version, "2.0.0");
        assert_eq!(restored.platform, Platform::MacOsArm64);
    }

    #[test]
    fn test_staged_binary_path() {
        let manager = StagedUpdateManager::new(PathBuf::from("/staging"));

        let windows_path = manager.staged_binary_path("1.0.0", Platform::WindowsX64);
        assert!(windows_path.to_str().unwrap().ends_with(".exe"));

        let linux_path = manager.staged_binary_path("1.0.0", Platform::LinuxX64);
        assert!(!linux_path.to_str().unwrap().ends_with(".exe"));
    }

    #[tokio::test]
    async fn test_staging_manager_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let manager = StagedUpdateManager::new(temp_dir.path().to_path_buf());

        // Ensure directory exists
        manager.ensure_staging_dir().await.unwrap();

        // Initially no staged update
        let staged = manager.load_metadata().await.unwrap();
        assert!(staged.is_none());

        // Create and save a staged update
        let staged = StagedUpdate::new(
            "3.0.0",
            temp_dir.path().join("test-binary"),
            Platform::LinuxX64,
            "checksum123",
            5000,
        );

        manager.save_metadata(&staged).await.unwrap();

        // Load it back
        let loaded = manager.load_metadata().await.unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.version, "3.0.0");
        assert_eq!(loaded.checksum, "checksum123");
    }
}
