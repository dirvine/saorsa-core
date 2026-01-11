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

//! Configuration for the auto-upgrade system.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Update policy controlling when updates are applied.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UpdatePolicy {
    /// Automatically download and apply updates (DEFAULT).
    #[default]
    Silent,

    /// Download updates but notify user before applying.
    DownloadAndNotify,

    /// Only notify about available updates, don't download.
    NotifyOnly,

    /// Never automatically update - manual only.
    Manual,

    /// Only force updates for critical security patches.
    CriticalOnly,
}

impl UpdatePolicy {
    /// Returns whether this policy allows automatic downloads.
    #[must_use]
    pub fn allows_auto_download(&self) -> bool {
        matches!(self, Self::Silent | Self::DownloadAndNotify)
    }

    /// Returns whether this policy allows automatic application.
    #[must_use]
    pub fn allows_auto_apply(&self) -> bool {
        matches!(self, Self::Silent)
    }
}

/// Release channel for updates.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReleaseChannel {
    /// Stable releases - thoroughly tested.
    #[default]
    Stable,

    /// Beta releases - feature complete but still testing.
    Beta,

    /// Nightly releases - latest development builds.
    Nightly,
}

impl ReleaseChannel {
    /// Convert to string identifier.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Nightly => "nightly",
        }
    }

    /// Parse from string name.
    #[must_use]
    pub fn parse_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "stable" => Some(Self::Stable),
            "beta" => Some(Self::Beta),
            "nightly" => Some(Self::Nightly),
            _ => None,
        }
    }
}

/// A pinned signing key for update verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedKey {
    /// Key identifier.
    pub key_id: String,

    /// ML-DSA-65 public key bytes (base64 encoded).
    pub public_key: String,

    /// When this key becomes valid (Unix timestamp).
    pub valid_from: u64,

    /// When this key expires (Unix timestamp, 0 = no expiry).
    pub valid_until: u64,
}

impl PinnedKey {
    /// Create a new pinned key.
    #[must_use]
    pub fn new(key_id: impl Into<String>, public_key: impl Into<String>) -> Self {
        Self {
            key_id: key_id.into(),
            public_key: public_key.into(),
            valid_from: 0,
            valid_until: 0,
        }
    }

    /// Check if this key is currently valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        now >= self.valid_from && (self.valid_until == 0 || now < self.valid_until)
    }
}

/// Configuration for the update system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    /// URL to the update manifest.
    pub manifest_url: String,

    /// How often to check for updates.
    pub check_interval: Duration,

    /// Update policy.
    pub policy: UpdatePolicy,

    /// Release channel to follow.
    pub channel: ReleaseChannel,

    /// Directory for staging downloaded updates.
    pub staging_dir: PathBuf,

    /// Directory for backup of current binary.
    pub backup_dir: PathBuf,

    /// Pinned signing keys for verification.
    pub signing_keys: Vec<PinnedKey>,

    /// Maximum download size in bytes (default: 500MB).
    pub max_download_size: u64,

    /// Connection timeout for downloads.
    pub download_timeout: Duration,

    /// Whether to verify signatures (should always be true in production).
    pub verify_signatures: bool,

    /// Number of retry attempts for downloads.
    pub max_retries: u32,

    /// Delay between retries.
    pub retry_delay: Duration,

    /// User-Agent header for HTTP requests.
    pub user_agent: String,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        let staging_dir = dirs::cache_dir()
            .map(|d| d.join("saorsa").join("updates"))
            .unwrap_or_else(|| PathBuf::from("updates"));

        let backup_dir = dirs::data_local_dir()
            .map(|d| d.join("saorsa").join("backup"))
            .unwrap_or_else(|| PathBuf::from("backup"));

        Self {
            manifest_url: "https://releases.saorsa.io/manifest.json".to_string(),
            check_interval: Duration::from_secs(6 * 3600), // 6 hours
            policy: UpdatePolicy::default(),
            channel: ReleaseChannel::default(),
            staging_dir,
            backup_dir,
            signing_keys: Vec::new(),
            max_download_size: 500 * 1024 * 1024,       // 500 MB
            download_timeout: Duration::from_secs(300), // 5 minutes
            verify_signatures: true,
            max_retries: 3,
            retry_delay: Duration::from_secs(5),
            user_agent: format!("saorsa-core/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

impl UpdateConfig {
    /// Create a new config with the given manifest URL.
    #[must_use]
    pub fn with_manifest_url(mut self, url: impl Into<String>) -> Self {
        self.manifest_url = url.into();
        self
    }

    /// Set the update policy.
    #[must_use]
    pub fn with_policy(mut self, policy: UpdatePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Set the release channel.
    #[must_use]
    pub fn with_channel(mut self, channel: ReleaseChannel) -> Self {
        self.channel = channel;
        self
    }

    /// Set the check interval.
    #[must_use]
    pub fn with_check_interval(mut self, interval: Duration) -> Self {
        self.check_interval = interval;
        self
    }

    /// Add a pinned signing key.
    #[must_use]
    pub fn with_signing_key(mut self, key: PinnedKey) -> Self {
        self.signing_keys.push(key);
        self
    }

    /// Set the staging directory.
    #[must_use]
    pub fn with_staging_dir(mut self, dir: PathBuf) -> Self {
        self.staging_dir = dir;
        self
    }

    /// Set the backup directory.
    #[must_use]
    pub fn with_backup_dir(mut self, dir: PathBuf) -> Self {
        self.backup_dir = dir;
        self
    }

    /// Disable signature verification (DANGEROUS - only for testing).
    #[must_use]
    pub fn without_signature_verification(mut self) -> Self {
        self.verify_signatures = false;
        self
    }
}

/// Builder for UpdateConfig.
pub struct UpdateConfigBuilder {
    config: UpdateConfig,
}

impl UpdateConfigBuilder {
    /// Create a new builder with default config.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: UpdateConfig::default(),
        }
    }

    /// Set manifest URL.
    #[must_use]
    pub fn manifest_url(mut self, url: impl Into<String>) -> Self {
        self.config.manifest_url = url.into();
        self
    }

    /// Set update policy.
    #[must_use]
    pub fn policy(mut self, policy: UpdatePolicy) -> Self {
        self.config.policy = policy;
        self
    }

    /// Set release channel.
    #[must_use]
    pub fn channel(mut self, channel: ReleaseChannel) -> Self {
        self.config.channel = channel;
        self
    }

    /// Set check interval.
    #[must_use]
    pub fn check_interval(mut self, interval: Duration) -> Self {
        self.config.check_interval = interval;
        self
    }

    /// Add signing key.
    #[must_use]
    pub fn signing_key(mut self, key: PinnedKey) -> Self {
        self.config.signing_keys.push(key);
        self
    }

    /// Set staging directory.
    #[must_use]
    pub fn staging_dir(mut self, dir: PathBuf) -> Self {
        self.config.staging_dir = dir;
        self
    }

    /// Build the config.
    #[must_use]
    pub fn build(self) -> UpdateConfig {
        self.config
    }
}

impl Default for UpdateConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_policy_default() {
        assert_eq!(UpdatePolicy::default(), UpdatePolicy::Silent);
    }

    #[test]
    fn test_update_policy_auto_download() {
        assert!(UpdatePolicy::Silent.allows_auto_download());
        assert!(UpdatePolicy::DownloadAndNotify.allows_auto_download());
        assert!(!UpdatePolicy::NotifyOnly.allows_auto_download());
        assert!(!UpdatePolicy::Manual.allows_auto_download());
        assert!(!UpdatePolicy::CriticalOnly.allows_auto_download());
    }

    #[test]
    fn test_release_channel_as_str() {
        assert_eq!(ReleaseChannel::Stable.as_str(), "stable");
        assert_eq!(ReleaseChannel::Beta.as_str(), "beta");
        assert_eq!(ReleaseChannel::Nightly.as_str(), "nightly");
    }

    #[test]
    fn test_release_channel_parse_name() {
        assert_eq!(
            ReleaseChannel::parse_name("stable"),
            Some(ReleaseChannel::Stable)
        );
        assert_eq!(
            ReleaseChannel::parse_name("BETA"),
            Some(ReleaseChannel::Beta)
        );
        assert_eq!(ReleaseChannel::parse_name("invalid"), None);
    }

    #[test]
    fn test_pinned_key_validity() {
        let key = PinnedKey::new("test-key", "public-key-data");
        assert!(key.is_valid()); // No time bounds = always valid

        let future_key = PinnedKey {
            key_id: "future".to_string(),
            public_key: "key".to_string(),
            valid_from: u64::MAX,
            valid_until: 0,
        };
        assert!(!future_key.is_valid());
    }

    #[test]
    fn test_config_builder() {
        let config = UpdateConfigBuilder::new()
            .manifest_url("https://test.com/manifest")
            .policy(UpdatePolicy::Manual)
            .channel(ReleaseChannel::Beta)
            .check_interval(Duration::from_secs(3600))
            .build();

        assert_eq!(config.manifest_url, "https://test.com/manifest");
        assert_eq!(config.policy, UpdatePolicy::Manual);
        assert_eq!(config.channel, ReleaseChannel::Beta);
        assert_eq!(config.check_interval, Duration::from_secs(3600));
    }

    #[test]
    fn test_config_with_methods() {
        let config = UpdateConfig::default()
            .with_manifest_url("https://test.com")
            .with_policy(UpdatePolicy::CriticalOnly)
            .with_channel(ReleaseChannel::Nightly);

        assert_eq!(config.manifest_url, "https://test.com");
        assert_eq!(config.policy, UpdatePolicy::CriticalOnly);
        assert_eq!(config.channel, ReleaseChannel::Nightly);
    }
}
