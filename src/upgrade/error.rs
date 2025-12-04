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

//! Error types for the upgrade system.

use std::borrow::Cow;
use thiserror::Error;

/// Errors that can occur during upgrade operations.
#[derive(Debug, Error)]
pub enum UpgradeError {
    /// Failed to fetch the update manifest.
    #[error("failed to fetch manifest: {0}")]
    ManifestFetch(Cow<'static, str>),

    /// Failed to parse the update manifest.
    #[error("failed to parse manifest: {0}")]
    ManifestParse(Cow<'static, str>),

    /// Manifest signature verification failed.
    #[error("manifest signature invalid: {0}")]
    ManifestSignature(Cow<'static, str>),

    /// No update available for the current platform.
    #[error("no update available for platform: {0}")]
    PlatformNotSupported(Cow<'static, str>),

    /// Download failed.
    #[error("download failed: {0}")]
    Download(Cow<'static, str>),

    /// Download size exceeded maximum.
    #[error("download size {actual} exceeds maximum {max}")]
    DownloadTooLarge { actual: u64, max: u64 },

    /// Checksum verification failed.
    #[error("checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch {
        expected: String,
        actual: String,
    },

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerification(Cow<'static, str>),

    /// No valid signing key found.
    #[error("no valid signing key found for key_id: {0}")]
    NoValidKey(Cow<'static, str>),

    /// Failed to stage the update.
    #[error("failed to stage update: {0}")]
    Staging(Cow<'static, str>),

    /// Failed to apply the update.
    #[error("failed to apply update: {0}")]
    Apply(Cow<'static, str>),

    /// Failed to rollback.
    #[error("rollback failed: {0}")]
    Rollback(Cow<'static, str>),

    /// No rollback available.
    #[error("no rollback available: {0}")]
    NoRollback(Cow<'static, str>),

    /// IO error during update.
    #[error("IO error: {0}")]
    Io(Cow<'static, str>),

    /// Version parsing error.
    #[error("version parse error: {0}")]
    VersionParse(Cow<'static, str>),

    /// Current version is already latest.
    #[error("already at latest version: {0}")]
    AlreadyLatest(Cow<'static, str>),

    /// Update was cancelled.
    #[error("update cancelled: {0}")]
    Cancelled(Cow<'static, str>),

    /// Permission denied.
    #[error("permission denied: {0}")]
    PermissionDenied(Cow<'static, str>),

    /// Platform-specific error.
    #[error("platform error: {0}")]
    Platform(Cow<'static, str>),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(Cow<'static, str>),
}

impl UpgradeError {
    /// Create a manifest fetch error.
    pub fn manifest_fetch(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::ManifestFetch(msg.into())
    }

    /// Create a manifest parse error.
    pub fn manifest_parse(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::ManifestParse(msg.into())
    }

    /// Create a download error.
    pub fn download(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::Download(msg.into())
    }

    /// Create an apply error.
    pub fn apply(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::Apply(msg.into())
    }

    /// Create a staging error.
    pub fn staging(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::Staging(msg.into())
    }

    /// Create an IO error.
    pub fn io(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::Io(msg.into())
    }

    /// Create a platform error.
    pub fn platform(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::Platform(msg.into())
    }

    /// Check if this error is recoverable (can retry).
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::ManifestFetch(_) | Self::Download(_) | Self::Io(_)
        )
    }

    /// Check if this error is a security issue.
    #[must_use]
    pub fn is_security_issue(&self) -> bool {
        matches!(
            self,
            Self::ManifestSignature(_)
                | Self::ChecksumMismatch { .. }
                | Self::SignatureVerification(_)
                | Self::NoValidKey(_)
        )
    }
}

impl From<std::io::Error> for UpgradeError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = UpgradeError::manifest_fetch("connection refused");
        assert_eq!(
            err.to_string(),
            "failed to fetch manifest: connection refused"
        );
    }

    #[test]
    fn test_checksum_mismatch() {
        let err = UpgradeError::ChecksumMismatch {
            expected: "abc123".to_string(),
            actual: "def456".to_string(),
        };
        assert!(err.to_string().contains("abc123"));
        assert!(err.to_string().contains("def456"));
    }

    #[test]
    fn test_is_recoverable() {
        assert!(UpgradeError::download("timeout").is_recoverable());
        assert!(UpgradeError::manifest_fetch("error").is_recoverable());
        assert!(!UpgradeError::SignatureVerification("invalid".into()).is_recoverable());
    }

    #[test]
    fn test_is_security_issue() {
        assert!(UpgradeError::SignatureVerification("invalid".into()).is_security_issue());
        assert!(UpgradeError::ChecksumMismatch {
            expected: "a".to_string(),
            actual: "b".to_string()
        }
        .is_security_issue());
        assert!(!UpgradeError::download("timeout").is_security_issue());
    }
}
