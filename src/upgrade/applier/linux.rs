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

//! Linux-specific update applier.
//!
//! Linux can replace a running binary directly.
//!
//! Strategy:
//! 1. Create backup of current binary
//! 2. Replace current binary with new one
//! 3. Set executable permissions
//! 4. Optionally restart via exec() or systemd

use async_trait::async_trait;
use std::path::PathBuf;

use super::{ApplierConfig, ApplyResult, UpdateApplier};
use crate::upgrade::error::UpgradeError;
use crate::upgrade::manifest::Platform;
use crate::upgrade::rollback::RollbackManager;
use crate::upgrade::staged::StagedUpdate;

/// Linux update applier with optional systemd integration.
pub struct LinuxApplier {
    /// Optional systemd service name for restart.
    systemd_service: Option<String>,

    /// Whether to use exec() for restart.
    use_exec: bool,
}

impl LinuxApplier {
    /// Create a new Linux applier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            systemd_service: None,
            use_exec: true,
        }
    }

    /// Set systemd service for restart.
    #[must_use]
    pub fn with_systemd_service(mut self, service: impl Into<String>) -> Self {
        self.systemd_service = Some(service.into());
        self.use_exec = false;
        self
    }

    /// Disable exec-based restart.
    #[must_use]
    pub fn without_exec(mut self) -> Self {
        self.use_exec = false;
        self
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

    /// Restart via systemctl.
    async fn restart_systemd(&self, service: &str) -> Result<(), UpgradeError> {
        #[cfg(target_os = "linux")]
        {
            let status = tokio::process::Command::new("systemctl")
                .args(["restart", service])
                .status()
                .await
                .map_err(|e| UpgradeError::platform(format!("failed to run systemctl: {}", e)))?;

            if !status.success() {
                return Err(UpgradeError::platform(format!(
                    "systemctl restart {} failed",
                    service
                )));
            }
        }

        #[cfg(not(target_os = "linux"))]
        let _ = service;

        Ok(())
    }

    /// Check if we're running under systemd.
    #[cfg(target_os = "linux")]
    fn is_systemd_service(&self) -> bool {
        // Check for systemd-specific environment variables
        std::env::var("INVOCATION_ID").is_ok() || std::env::var("NOTIFY_SOCKET").is_ok()
    }

    /// Get the systemd service name if running as a service.
    #[cfg(target_os = "linux")]
    async fn detect_systemd_service(&self) -> Option<String> {
        if !self.is_systemd_service() {
            return None;
        }

        // Try to get the service name from the unit file
        let output = tokio::process::Command::new("systemctl")
            .args([
                "--user",
                "show",
                "--property=Id",
                "--value",
                "saorsa.service",
            ])
            .output()
            .await
            .ok()?;

        if output.status.success() {
            let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }

        // Fallback to checking system-wide services
        let output = tokio::process::Command::new("systemctl")
            .args(["show", "--property=Id", "--value", "saorsa.service"])
            .output()
            .await
            .ok()?;

        if output.status.success() {
            let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }

        None
    }
}

impl Default for LinuxApplier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UpdateApplier for LinuxApplier {
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

        // Create parent directory if needed
        if let Some(parent) = current.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| UpgradeError::io(format!("failed to create directory: {}", e)))?;
        }

        // Copy new binary to current location
        tokio::fs::copy(&staged.binary_path, current)
            .await
            .map_err(|e| UpgradeError::Apply(format!("failed to copy new binary: {}", e).into()))?;

        // Set executable permissions
        self.set_executable(current).await?;

        Ok(ApplyResult {
            restart_required: true,
            restart_command: None,
            new_binary_path: current.clone(),
            version: staged.version.clone(),
        })
    }

    fn platform(&self) -> Platform {
        #[cfg(target_arch = "aarch64")]
        return Platform::LinuxArm64;

        #[cfg(not(target_arch = "aarch64"))]
        Platform::LinuxX64
    }

    fn is_applicable(&self) -> bool {
        cfg!(target_os = "linux")
    }

    async fn trigger_restart(&self, config: &ApplierConfig) -> Result<(), UpgradeError> {
        // Check for systemd service first
        if let Some(ref service) = self.systemd_service {
            return self.restart_systemd(service).await;
        }

        // Auto-detect systemd if running as a service
        #[cfg(target_os = "linux")]
        if let Some(service) = self.detect_systemd_service().await {
            return self.restart_systemd(&service).await;
        }

        // Use exec() for direct restart
        if self.use_exec {
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
        }

        #[cfg(not(unix))]
        let _ = config;

        Err(UpgradeError::platform(
            "no restart method available (exec disabled, not a systemd service)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_applier_creation() {
        let applier = LinuxApplier::new();
        assert!(applier.systemd_service.is_none());
        assert!(applier.use_exec);
    }

    #[test]
    fn test_linux_applier_with_systemd() {
        let applier = LinuxApplier::new().with_systemd_service("saorsa");

        assert_eq!(applier.systemd_service, Some("saorsa".to_string()));
        assert!(!applier.use_exec);
    }

    #[test]
    fn test_linux_applier_without_exec() {
        let applier = LinuxApplier::new().without_exec();
        assert!(!applier.use_exec);
    }

    #[test]
    fn test_platform() {
        let applier = LinuxApplier::new();
        let platform = applier.platform();

        assert!(matches!(
            platform,
            Platform::LinuxX64 | Platform::LinuxArm64
        ));
    }

    #[test]
    fn test_is_applicable() {
        let applier = LinuxApplier::new();
        let applicable = applier.is_applicable();

        #[cfg(target_os = "linux")]
        assert!(applicable);

        #[cfg(not(target_os = "linux"))]
        assert!(!applicable);
    }
}
