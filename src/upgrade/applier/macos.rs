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

//! macOS-specific update applier.
//!
//! macOS can replace a running binary directly, but downloaded files
//! have a quarantine attribute that needs to be cleared.
//!
//! Strategy:
//! 1. Create backup of current binary
//! 2. Clear quarantine attribute from new binary
//! 3. Replace current binary with new one
//! 4. Set executable permissions
//! 5. Optionally restart

use async_trait::async_trait;
use std::path::PathBuf;

use super::{ApplierConfig, ApplyResult, UpdateApplier};
use crate::upgrade::error::UpgradeError;
use crate::upgrade::manifest::Platform;
use crate::upgrade::rollback::RollbackManager;
use crate::upgrade::staged::StagedUpdate;

/// macOS update applier with quarantine clearing.
pub struct MacOsApplier {
    /// Whether to clear quarantine attributes.
    clear_quarantine: bool,

    /// Whether to sign with ad-hoc signature.
    adhoc_sign: bool,
}

impl MacOsApplier {
    /// Create a new macOS applier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            clear_quarantine: true,
            adhoc_sign: false,
        }
    }

    /// Disable quarantine clearing.
    #[must_use]
    pub fn without_quarantine_clear(mut self) -> Self {
        self.clear_quarantine = false;
        self
    }

    /// Enable ad-hoc code signing.
    #[must_use]
    pub fn with_adhoc_sign(mut self) -> Self {
        self.adhoc_sign = true;
        self
    }

    /// Clear the quarantine extended attribute from a file.
    async fn clear_quarantine_attr(&self, path: &PathBuf) -> Result<(), UpgradeError> {
        #[cfg(target_os = "macos")]
        {
            let status = tokio::process::Command::new("xattr")
                .args(["-d", "com.apple.quarantine"])
                .arg(path)
                .status()
                .await
                .map_err(|e| UpgradeError::platform(format!("failed to run xattr: {}", e)))?;

            // xattr returns error if attribute doesn't exist, which is fine
            if !status.success() && status.code() != Some(1) {
                return Err(UpgradeError::platform("failed to clear quarantine attribute"));
            }
        }

        #[cfg(not(target_os = "macos"))]
        let _ = path;

        Ok(())
    }

    /// Sign the binary with an ad-hoc signature.
    async fn adhoc_sign_binary(&self, path: &PathBuf) -> Result<(), UpgradeError> {
        #[cfg(target_os = "macos")]
        {
            let status = tokio::process::Command::new("codesign")
                .args(["--force", "--sign", "-"])
                .arg(path)
                .status()
                .await
                .map_err(|e| UpgradeError::platform(format!("failed to run codesign: {}", e)))?;

            if !status.success() {
                return Err(UpgradeError::platform("ad-hoc signing failed"));
            }
        }

        #[cfg(not(target_os = "macos"))]
        let _ = path;

        Ok(())
    }

    /// Set executable permissions on the binary.
    async fn set_executable(&self, path: &PathBuf) -> Result<(), UpgradeError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            tokio::fs::set_permissions(path, perms)
                .await
                .map_err(|e| UpgradeError::platform(format!("failed to set permissions: {}", e)))?;
        }

        #[cfg(not(unix))]
        let _ = path;

        Ok(())
    }
}

impl Default for MacOsApplier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UpdateApplier for MacOsApplier {
    async fn apply(
        &self,
        staged: &StagedUpdate,
        config: &ApplierConfig,
        rollback_manager: &RollbackManager,
    ) -> Result<ApplyResult, UpgradeError> {
        // Validate the staged update
        self.validate_staged(staged).await?;

        let current = &config.current_binary;

        // Create backup if configured
        if config.create_backup {
            let current_version = current
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|s| s.split('-').nth(1))
                .unwrap_or("unknown");

            rollback_manager
                .create_backup(current, current_version, staged.platform)
                .await?;
        }

        // Clear quarantine attribute from downloaded binary
        if self.clear_quarantine {
            self.clear_quarantine_attr(&staged.binary_path).await?;
        }

        // Copy new binary to current location
        tokio::fs::copy(&staged.binary_path, current)
            .await
            .map_err(|e| UpgradeError::Apply(format!("failed to copy new binary: {}", e).into()))?;

        // Set executable permissions
        self.set_executable(current).await?;

        // Ad-hoc sign if configured
        if self.adhoc_sign {
            self.adhoc_sign_binary(current).await?;
        }

        Ok(ApplyResult {
            restart_required: true,
            restart_command: None,
            new_binary_path: current.clone(),
            version: staged.version.clone(),
        })
    }

    fn platform(&self) -> Platform {
        #[cfg(target_arch = "aarch64")]
        return Platform::MacOsArm64;

        #[cfg(not(target_arch = "aarch64"))]
        Platform::MacOsX64
    }

    fn is_applicable(&self) -> bool {
        cfg!(target_os = "macos")
    }

    async fn trigger_restart(&self, config: &ApplierConfig) -> Result<(), UpgradeError> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;

            let mut cmd = std::process::Command::new(&config.current_binary);
            cmd.args(&config.restart_args);

            // exec() replaces the current process
            let err = cmd.exec();

            // If we get here, exec failed
            return Err(UpgradeError::Apply(format!("exec failed: {}", err).into()));
        }

        #[cfg(not(unix))]
        {
            let _ = config;
            Err(UpgradeError::platform("Unix restart not available on this platform"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_applier_creation() {
        let applier = MacOsApplier::new();
        assert!(applier.clear_quarantine);
        assert!(!applier.adhoc_sign);
    }

    #[test]
    fn test_macos_applier_config() {
        let applier = MacOsApplier::new()
            .without_quarantine_clear()
            .with_adhoc_sign();

        assert!(!applier.clear_quarantine);
        assert!(applier.adhoc_sign);
    }

    #[test]
    fn test_platform() {
        let applier = MacOsApplier::new();
        let platform = applier.platform();

        assert!(matches!(platform, Platform::MacOsX64 | Platform::MacOsArm64));
    }

    #[test]
    fn test_is_applicable() {
        let applier = MacOsApplier::new();
        let applicable = applier.is_applicable();

        #[cfg(target_os = "macos")]
        assert!(applicable);

        #[cfg(not(target_os = "macos"))]
        assert!(!applicable);
    }
}
