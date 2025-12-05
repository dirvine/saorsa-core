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

//! Auto-upgrade system for cross-platform binary updates.
//!
//! This module provides mechanisms for automatic binary updates with:
//! - Version checking against remote manifest
//! - Secure download with ML-DSA-65 signature verification
//! - Platform-specific update application strategies
//! - Rollback support for failed updates
//!
//! # Platform Strategies
//!
//! - **Windows**: Rename-and-restart (can't replace running binary)
//! - **macOS**: Binary replacement with quarantine clearing
//! - **Linux**: Binary replacement with optional systemd restart
//!
//! # Security
//!
//! All updates are signed with ML-DSA-65 (post-quantum) signatures.
//! Signatures must verify before any update is applied.
//!
//! # Example
//!
//! ```ignore
//! use saorsa_core::upgrade::{UpdateManager, UpdateConfig, UpdatePolicy};
//!
//! let config = UpdateConfig::default();
//! let manager = DefaultUpdateManager::new(config).await?;
//!
//! // Check for updates
//! if let Some(update) = manager.check_for_updates().await? {
//!     println!("New version available: {}", update.version);
//!
//!     // Download and verify
//!     let staged = manager.download_update(&update).await?;
//!
//!     // Apply update (platform-specific)
//!     manager.apply_update(staged).await?;
//! }
//! ```

pub mod applier;
pub mod config;
pub mod downloader;
pub mod error;
pub mod manifest;
pub mod rollback;
pub mod staged;
pub mod verifier;

use async_trait::async_trait;

pub use applier::{ApplierConfig, ApplyResult, UpdateApplier, create_applier};
pub use config::{PinnedKey, ReleaseChannel, UpdateConfig, UpdateConfigBuilder, UpdatePolicy};
pub use downloader::{DownloadProgress, Downloader, DownloaderConfig};
pub use error::UpgradeError;
pub use manifest::{Platform, PlatformBinary, Release, UpdateManifest};
pub use rollback::{BackupMetadata, RollbackManager};
pub use staged::{StagedUpdate, StagedUpdateManager, StagedUpdateMetadata};
pub use verifier::SignatureVerifier;

use crate::Result;

/// Information about an available update.
#[derive(Debug, Clone)]
pub struct UpdateInfo {
    /// Version string (semver).
    pub version: String,

    /// Release channel.
    pub channel: ReleaseChannel,

    /// Whether this is a critical security update.
    pub is_critical: bool,

    /// Release notes.
    pub release_notes: String,

    /// Binary information for the current platform.
    pub binary: PlatformBinary,

    /// URL to the full manifest.
    pub manifest_url: String,
}

impl UpdateInfo {
    /// Check if this update should be applied automatically based on policy.
    #[must_use]
    pub fn should_auto_apply(&self, policy: UpdatePolicy) -> bool {
        match policy {
            UpdatePolicy::Silent => true,
            UpdatePolicy::DownloadAndNotify => false,
            UpdatePolicy::NotifyOnly => false,
            UpdatePolicy::Manual => false,
            UpdatePolicy::CriticalOnly => self.is_critical,
        }
    }
}

/// Core trait for update management.
///
/// Implementations handle the full update lifecycle:
/// checking, downloading, verifying, and applying updates.
#[async_trait]
pub trait UpdateManager: Send + Sync {
    /// Check if an update is available.
    ///
    /// Fetches the manifest and compares versions.
    async fn check_for_updates(&self) -> Result<Option<UpdateInfo>>;

    /// Download an update to the staging area.
    ///
    /// The downloaded binary is verified before being staged.
    async fn download_update(&self, update: &UpdateInfo) -> Result<StagedUpdate>;

    /// Apply a staged update.
    ///
    /// This uses platform-specific logic:
    /// - Windows: Rename current binary, move new binary, spawn new process
    /// - macOS/Linux: Replace binary, optionally restart service
    async fn apply_update(&self, staged: StagedUpdate) -> Result<()>;

    /// Get current configuration.
    fn config(&self) -> &UpdateConfig;

    /// Update configuration.
    fn set_config(&mut self, config: UpdateConfig);

    /// Get the current running version.
    fn current_version(&self) -> &str;

    /// Rollback to the previous version.
    ///
    /// Only works if a backup exists.
    async fn rollback(&self) -> Result<()>;

    /// Check if a rollback is available.
    fn can_rollback(&self) -> bool;
}

/// Event emitted by the upgrade system.
#[derive(Debug, Clone)]
pub enum UpgradeEvent {
    /// Checking for updates.
    Checking,

    /// Update check completed.
    CheckComplete {
        /// Whether an update is available.
        available: bool,
        /// Version if available.
        version: Option<String>,
    },

    /// Download started.
    DownloadStarted {
        /// Version being downloaded.
        version: String,
        /// Total size in bytes.
        total_bytes: u64,
    },

    /// Download progress.
    DownloadProgress {
        /// Bytes downloaded so far.
        downloaded: u64,
        /// Total bytes.
        total: u64,
        /// Download speed in bytes/second.
        speed_bps: u64,
    },

    /// Download completed.
    DownloadComplete {
        /// Version downloaded.
        version: String,
    },

    /// Verification started.
    VerificationStarted,

    /// Verification completed.
    VerificationComplete {
        /// Whether verification succeeded.
        success: bool,
    },

    /// Update being applied.
    Applying {
        /// Version being applied.
        version: String,
    },

    /// Update applied successfully.
    Applied {
        /// New version.
        version: String,
        /// Whether restart is required.
        restart_required: bool,
    },

    /// Rollback initiated.
    RollingBack {
        /// Version rolling back to.
        to_version: String,
    },

    /// Rollback completed.
    RolledBack {
        /// Version after rollback.
        version: String,
    },

    /// Error occurred.
    Error {
        /// Error message.
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_info_should_auto_apply() {
        let update = UpdateInfo {
            version: "1.0.0".to_string(),
            channel: ReleaseChannel::Stable,
            is_critical: false,
            release_notes: "Test release".to_string(),
            binary: PlatformBinary {
                url: "https://example.com/binary".to_string(),
                sha256: "abc123".to_string(),
                signature: "sig123".to_string(),
                size: 1000,
            },
            manifest_url: "https://example.com/manifest".to_string(),
        };

        assert!(update.should_auto_apply(UpdatePolicy::Silent));
        assert!(!update.should_auto_apply(UpdatePolicy::Manual));
        assert!(!update.should_auto_apply(UpdatePolicy::CriticalOnly));

        let critical_update = UpdateInfo {
            is_critical: true,
            ..update.clone()
        };
        assert!(critical_update.should_auto_apply(UpdatePolicy::CriticalOnly));
    }
}
