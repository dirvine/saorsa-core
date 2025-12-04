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

//! Platform-specific update applier implementations.
//!
//! Each platform has different requirements for replacing a running binary:
//!
//! - **Windows**: Cannot replace a running executable. Uses rename-and-restart strategy.
//! - **macOS**: Can replace binary but needs quarantine attribute clearing.
//! - **Linux**: Direct binary replacement with optional systemd restart.

mod linux;
mod macos;
mod windows;

pub use linux::LinuxApplier;
pub use macos::MacOsApplier;
pub use windows::WindowsApplier;

use async_trait::async_trait;
use std::path::PathBuf;

use super::error::UpgradeError;
use super::manifest::Platform;
use super::rollback::RollbackManager;
use super::staged::StagedUpdate;

/// Result of applying an update.
#[derive(Debug, Clone)]
pub struct ApplyResult {
    /// Whether the process needs to restart.
    pub restart_required: bool,

    /// Command to run after restart (for Windows).
    pub restart_command: Option<String>,

    /// Path to the new binary.
    pub new_binary_path: PathBuf,

    /// Version that was applied.
    pub version: String,
}

/// Configuration for the update applier.
#[derive(Debug, Clone)]
pub struct ApplierConfig {
    /// Path to the current binary being updated.
    pub current_binary: PathBuf,

    /// Whether to create a backup before applying.
    pub create_backup: bool,

    /// Whether to automatically restart after applying.
    pub auto_restart: bool,

    /// Arguments to pass to the new binary on restart.
    pub restart_args: Vec<String>,
}

impl ApplierConfig {
    /// Create a new applier configuration.
    #[must_use]
    pub fn new(current_binary: PathBuf) -> Self {
        Self {
            current_binary,
            create_backup: true,
            auto_restart: false,
            restart_args: vec!["--post-update".to_string()],
        }
    }

    /// Disable backup creation.
    #[must_use]
    pub fn without_backup(mut self) -> Self {
        self.create_backup = false;
        self
    }

    /// Enable auto-restart.
    #[must_use]
    pub fn with_auto_restart(mut self) -> Self {
        self.auto_restart = true;
        self
    }

    /// Set restart arguments.
    #[must_use]
    pub fn with_restart_args(mut self, args: Vec<String>) -> Self {
        self.restart_args = args;
        self
    }
}

/// Trait for platform-specific update application.
#[async_trait]
pub trait UpdateApplier: Send + Sync {
    /// Apply a staged update.
    ///
    /// This method handles:
    /// 1. Creating a backup of the current binary (if configured)
    /// 2. Replacing/renaming the current binary
    /// 3. Moving the new binary into place
    /// 4. Setting appropriate permissions
    /// 5. Optionally triggering a restart
    async fn apply(
        &self,
        staged: &StagedUpdate,
        config: &ApplierConfig,
        rollback_manager: &RollbackManager,
    ) -> Result<ApplyResult, UpgradeError>;

    /// Get the platform this applier is for.
    fn platform(&self) -> Platform;

    /// Check if this applier can handle the current platform.
    fn is_applicable(&self) -> bool;

    /// Validate that the staged update is ready to apply.
    async fn validate_staged(&self, staged: &StagedUpdate) -> Result<(), UpgradeError> {
        // Check binary exists
        if !staged.exists() {
            return Err(UpgradeError::Apply(
                "staged binary does not exist".into(),
            ));
        }

        // Verify checksum
        if !staged.verify().await? {
            return Err(UpgradeError::Apply(
                "staged binary checksum mismatch".into(),
            ));
        }

        Ok(())
    }

    /// Trigger a restart of the current process.
    async fn trigger_restart(&self, config: &ApplierConfig) -> Result<(), UpgradeError>;
}

/// Create an applier for the current platform.
#[must_use]
pub fn create_applier() -> Box<dyn UpdateApplier> {
    let platform = Platform::current();

    match platform {
        Platform::WindowsX64 | Platform::WindowsArm64 => {
            Box::new(WindowsApplier::new())
        }
        Platform::MacOsX64 | Platform::MacOsArm64 => {
            Box::new(MacOsApplier::new())
        }
        Platform::LinuxX64 | Platform::LinuxArm64 => {
            Box::new(LinuxApplier::new())
        }
    }
}

/// Get the path to the current executable.
pub fn current_exe() -> Result<PathBuf, UpgradeError> {
    std::env::current_exe().map_err(|e| UpgradeError::platform(format!("failed to get current exe: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_applier_config() {
        let config = ApplierConfig::new(PathBuf::from("/usr/bin/saorsa"))
            .without_backup()
            .with_auto_restart()
            .with_restart_args(vec!["--daemon".to_string()]);

        assert!(!config.create_backup);
        assert!(config.auto_restart);
        assert_eq!(config.restart_args, vec!["--daemon"]);
    }

    #[test]
    fn test_create_applier() {
        let applier = create_applier();
        assert!(applier.is_applicable());
    }
}
