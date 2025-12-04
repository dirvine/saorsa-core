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

//! Windows-specific update applier using rename-and-restart strategy.
//!
//! Windows cannot replace a running executable, so we:
//! 1. Rename current.exe -> current.exe.old
//! 2. Copy new binary -> current.exe
//! 3. Spawn new process with --post-update flag
//! 4. Exit current process
//!
//! The new process cleans up .old files on startup.

use async_trait::async_trait;
use std::path::{Path, PathBuf};

use super::{ApplierConfig, ApplyResult, UpdateApplier};
use crate::upgrade::error::UpgradeError;
use crate::upgrade::manifest::Platform;
use crate::upgrade::rollback::RollbackManager;
use crate::upgrade::staged::StagedUpdate;

/// Windows update applier using rename-and-restart strategy.
pub struct WindowsApplier {
    /// Suffix for old binary files.
    old_suffix: String,
}

impl WindowsApplier {
    /// Create a new Windows applier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            old_suffix: ".old".to_string(),
        }
    }

    /// Get the path for the old binary.
    fn old_binary_path(&self, binary_path: &Path) -> PathBuf {
        let mut path = binary_path.to_path_buf().into_os_string();
        path.push(&self.old_suffix);
        PathBuf::from(path)
    }

    /// Clean up old binary files from previous updates.
    pub async fn cleanup_old_binaries(&self, binary_path: &Path) -> Result<(), UpgradeError> {
        let old_path = self.old_binary_path(binary_path);

        if old_path.exists() {
            // Try to delete, but don't fail if we can't
            // (might still be locked by previous process)
            let _ = tokio::fs::remove_file(&old_path).await;
        }

        Ok(())
    }
}

impl Default for WindowsApplier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UpdateApplier for WindowsApplier {
    async fn apply(
        &self,
        staged: &StagedUpdate,
        config: &ApplierConfig,
        rollback_manager: &RollbackManager,
    ) -> Result<ApplyResult, UpgradeError> {
        // Validate the staged update
        self.validate_staged(staged).await?;

        let current = &config.current_binary;
        let old_binary = self.old_binary_path(current);

        // Create backup if configured
        if config.create_backup {
            // Get current version from binary name or use "unknown"
            let current_version = current
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|s| s.split('-').nth(1))
                .unwrap_or("unknown");

            rollback_manager
                .create_backup(current, current_version, staged.platform)
                .await?;
        }

        // Clean up any previous .old files
        self.cleanup_old_binaries(current).await?;

        // Step 1: Rename current binary to .old
        if current.exists() {
            tokio::fs::rename(current, &old_binary)
                .await
                .map_err(|e| UpgradeError::Apply(format!("failed to rename current binary: {}", e).into()))?;
        }

        // Step 2: Copy new binary to current location
        tokio::fs::copy(&staged.binary_path, current)
            .await
            .map_err(|e| {
                // Try to restore old binary on failure
                let _ = std::fs::rename(&old_binary, current);
                UpgradeError::Apply(format!("failed to copy new binary: {}", e).into())
            })?;

        // Build restart command
        let restart_command = if config.auto_restart {
            let mut cmd = current.to_string_lossy().to_string();
            for arg in &config.restart_args {
                cmd.push(' ');
                cmd.push_str(arg);
            }
            Some(cmd)
        } else {
            None
        };

        Ok(ApplyResult {
            restart_required: true,
            restart_command,
            new_binary_path: current.clone(),
            version: staged.version.clone(),
        })
    }

    fn platform(&self) -> Platform {
        #[cfg(target_arch = "aarch64")]
        return Platform::WindowsArm64;

        #[cfg(not(target_arch = "aarch64"))]
        Platform::WindowsX64
    }

    fn is_applicable(&self) -> bool {
        cfg!(target_os = "windows")
    }

    async fn trigger_restart(&self, config: &ApplierConfig) -> Result<(), UpgradeError> {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const DETACHED_PROCESS: u32 = 0x00000008;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;

            let mut cmd = std::process::Command::new(&config.current_binary);
            cmd.args(&config.restart_args);
            cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);

            cmd.spawn()
                .map_err(|e| UpgradeError::Apply(format!("failed to spawn new process: {}", e).into()))?;

            // Exit current process
            std::process::exit(0);
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = config;
            Err(UpgradeError::platform("Windows restart not available on this platform"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_applier_creation() {
        let applier = WindowsApplier::new();
        assert_eq!(applier.old_suffix, ".old");
    }

    #[test]
    fn test_old_binary_path() {
        let applier = WindowsApplier::new();
        let binary = PathBuf::from("C:\\Program Files\\Saorsa\\saorsa.exe");
        let old = applier.old_binary_path(&binary);

        assert_eq!(
            old,
            PathBuf::from("C:\\Program Files\\Saorsa\\saorsa.exe.old")
        );
    }

    #[test]
    fn test_platform() {
        let applier = WindowsApplier::new();
        let platform = applier.platform();

        assert!(matches!(
            platform,
            Platform::WindowsX64 | Platform::WindowsArm64
        ));
    }

    #[test]
    fn test_is_applicable() {
        let applier = WindowsApplier::new();
        let applicable = applier.is_applicable();

        #[cfg(target_os = "windows")]
        assert!(applicable);

        #[cfg(not(target_os = "windows"))]
        assert!(!applicable);
    }
}
