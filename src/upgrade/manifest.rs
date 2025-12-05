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

//! Update manifest parsing and types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::config::ReleaseChannel;
use super::error::UpgradeError;

/// The update manifest containing all release information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    /// Manifest format version.
    pub manifest_version: u8,

    /// When the manifest was generated (Unix timestamp).
    pub generated_at: u64,

    /// ML-DSA-65 signature of the manifest (base64).
    pub signature: String,

    /// ID of the key used to sign this manifest.
    pub signing_key_id: String,

    /// URL to fetch the next signing key (for rotation).
    #[serde(default)]
    pub next_signing_key_url: Option<String>,

    /// Available releases.
    pub releases: Vec<Release>,
}

impl UpdateManifest {
    /// Current manifest format version.
    pub const CURRENT_VERSION: u8 = 1;

    /// Parse manifest from JSON.
    pub fn from_json(json: &str) -> Result<Self, UpgradeError> {
        serde_json::from_str(json).map_err(|e| UpgradeError::manifest_parse(e.to_string()))
    }

    /// Serialize manifest to JSON.
    pub fn to_json(&self) -> Result<String, UpgradeError> {
        serde_json::to_string_pretty(self).map_err(|e| UpgradeError::manifest_parse(e.to_string()))
    }

    /// Get the canonical bytes for signature verification.
    ///
    /// This returns the manifest JSON without the signature field.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, UpgradeError> {
        // Create a copy without signature for verification
        let mut manifest_for_signing = self.clone();
        manifest_for_signing.signature = String::new();

        let json = serde_json::to_string(&manifest_for_signing)
            .map_err(|e| UpgradeError::manifest_parse(e.to_string()))?;

        Ok(json.into_bytes())
    }

    /// Find the latest release for a given channel.
    #[must_use]
    pub fn latest_for_channel(&self, channel: ReleaseChannel) -> Option<&Release> {
        self.releases
            .iter()
            .filter(|r| r.channel == channel)
            .max_by(|a, b| a.version.cmp(&b.version))
    }

    /// Find a specific release by version.
    #[must_use]
    pub fn find_release(&self, version: &str) -> Option<&Release> {
        self.releases.iter().find(|r| r.version == version)
    }

    /// Get all releases for a channel, sorted by version descending.
    #[must_use]
    pub fn releases_for_channel(&self, channel: ReleaseChannel) -> Vec<&Release> {
        let mut releases: Vec<_> = self
            .releases
            .iter()
            .filter(|r| r.channel == channel)
            .collect();
        releases.sort_by(|a, b| b.version.cmp(&a.version));
        releases
    }
}

/// A single release entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    /// Semantic version string.
    pub version: String,

    /// Release channel.
    pub channel: ReleaseChannel,

    /// Whether this is a critical security update.
    pub is_critical: bool,

    /// Release notes (markdown).
    pub release_notes: String,

    /// Minimum version required to upgrade from (optional).
    #[serde(default)]
    pub minimum_from_version: Option<String>,

    /// When this release was published (Unix timestamp).
    pub published_at: u64,

    /// Platform-specific binaries.
    pub binaries: HashMap<Platform, PlatformBinary>,
}

impl Release {
    /// Check if an upgrade from `current_version` is supported.
    #[must_use]
    pub fn supports_upgrade_from(&self, current_version: &str) -> bool {
        match &self.minimum_from_version {
            Some(min) => current_version >= min.as_str(),
            None => true,
        }
    }

    /// Get the binary for the current platform.
    #[must_use]
    pub fn binary_for_current_platform(&self) -> Option<&PlatformBinary> {
        let platform = Platform::current();
        self.binaries.get(&platform)
    }

    /// Check if this release supports the current platform.
    #[must_use]
    pub fn supports_current_platform(&self) -> bool {
        let platform = Platform::current();
        self.binaries.contains_key(&platform)
    }
}

/// Target platform identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// Windows x86_64.
    #[serde(rename = "windows-x64")]
    WindowsX64,

    /// Windows ARM64.
    #[serde(rename = "windows-arm64")]
    WindowsArm64,

    /// macOS x86_64 (Intel).
    #[serde(rename = "macos-x64")]
    MacOsX64,

    /// macOS ARM64 (Apple Silicon).
    #[serde(rename = "macos-arm64")]
    MacOsArm64,

    /// Linux x86_64.
    #[serde(rename = "linux-x64")]
    LinuxX64,

    /// Linux ARM64.
    #[serde(rename = "linux-arm64")]
    LinuxArm64,
}

impl Platform {
    /// Get the current platform.
    #[must_use]
    pub fn current() -> Self {
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        return Self::WindowsX64;

        #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
        return Self::WindowsArm64;

        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        return Self::MacOsX64;

        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        return Self::MacOsArm64;

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        return Self::LinuxX64;

        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        return Self::LinuxArm64;

        // Fallback for other platforms (compilation will still succeed)
        #[cfg(not(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "windows", target_arch = "aarch64"),
            all(target_os = "macos", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "aarch64"),
        )))]
        return Self::LinuxX64; // Default fallback
    }

    /// Get the string identifier for this platform.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WindowsX64 => "windows-x64",
            Self::WindowsArm64 => "windows-arm64",
            Self::MacOsX64 => "macos-x64",
            Self::MacOsArm64 => "macos-arm64",
            Self::LinuxX64 => "linux-x64",
            Self::LinuxArm64 => "linux-arm64",
        }
    }

    /// Check if this is a Windows platform.
    #[must_use]
    pub fn is_windows(&self) -> bool {
        matches!(self, Self::WindowsX64 | Self::WindowsArm64)
    }

    /// Check if this is a macOS platform.
    #[must_use]
    pub fn is_macos(&self) -> bool {
        matches!(self, Self::MacOsX64 | Self::MacOsArm64)
    }

    /// Check if this is a Linux platform.
    #[must_use]
    pub fn is_linux(&self) -> bool {
        matches!(self, Self::LinuxX64 | Self::LinuxArm64)
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Platform-specific binary information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformBinary {
    /// Download URL for the binary.
    pub url: String,

    /// SHA-256 hash of the binary (hex encoded).
    pub sha256: String,

    /// ML-DSA-65 signature of the binary (base64).
    pub signature: String,

    /// Size in bytes.
    pub size: u64,
}

impl PlatformBinary {
    /// Create a new platform binary entry.
    #[must_use]
    pub fn new(
        url: impl Into<String>,
        sha256: impl Into<String>,
        signature: impl Into<String>,
        size: u64,
    ) -> Self {
        Self {
            url: url.into(),
            sha256: sha256.into(),
            signature: signature.into(),
            size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest_json() -> &'static str {
        r#"{
            "manifest_version": 1,
            "generated_at": 1700000000,
            "signature": "test-signature",
            "signing_key_id": "key-001",
            "releases": [
                {
                    "version": "1.0.0",
                    "channel": "stable",
                    "is_critical": false,
                    "release_notes": "Initial release",
                    "published_at": 1700000000,
                    "binaries": {
                        "linux-x64": {
                            "url": "https://example.com/binary-linux-x64",
                            "sha256": "abc123",
                            "signature": "sig123",
                            "size": 10000
                        }
                    }
                }
            ]
        }"#
    }

    #[test]
    fn test_manifest_parse() {
        let manifest = UpdateManifest::from_json(sample_manifest_json()).unwrap();

        assert_eq!(manifest.manifest_version, 1);
        assert_eq!(manifest.signing_key_id, "key-001");
        assert_eq!(manifest.releases.len(), 1);
    }

    #[test]
    fn test_manifest_to_json() {
        let manifest = UpdateManifest::from_json(sample_manifest_json()).unwrap();
        let json = manifest.to_json().unwrap();

        // Should be valid JSON
        let reparsed = UpdateManifest::from_json(&json).unwrap();
        assert_eq!(reparsed.manifest_version, manifest.manifest_version);
    }

    #[test]
    fn test_latest_for_channel() {
        let manifest = UpdateManifest::from_json(sample_manifest_json()).unwrap();

        let latest = manifest.latest_for_channel(ReleaseChannel::Stable);
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().version, "1.0.0");

        let beta = manifest.latest_for_channel(ReleaseChannel::Beta);
        assert!(beta.is_none());
    }

    #[test]
    fn test_platform_current() {
        // This just verifies it doesn't panic
        let _platform = Platform::current();
    }

    #[test]
    fn test_platform_checks() {
        assert!(Platform::WindowsX64.is_windows());
        assert!(Platform::WindowsArm64.is_windows());
        assert!(!Platform::LinuxX64.is_windows());

        assert!(Platform::MacOsX64.is_macos());
        assert!(Platform::MacOsArm64.is_macos());
        assert!(!Platform::LinuxX64.is_macos());

        assert!(Platform::LinuxX64.is_linux());
        assert!(Platform::LinuxArm64.is_linux());
        assert!(!Platform::WindowsX64.is_linux());
    }

    #[test]
    fn test_release_supports_upgrade() {
        let release = Release {
            version: "2.0.0".to_string(),
            channel: ReleaseChannel::Stable,
            is_critical: false,
            release_notes: "Test".to_string(),
            minimum_from_version: Some("1.5.0".to_string()),
            published_at: 1700000000,
            binaries: HashMap::new(),
        };

        assert!(release.supports_upgrade_from("1.5.0"));
        assert!(release.supports_upgrade_from("1.6.0"));
        assert!(!release.supports_upgrade_from("1.4.0"));
    }

    #[test]
    fn test_platform_binary() {
        let binary = PlatformBinary::new("https://example.com/binary", "abc123", "sig456", 1000);

        assert_eq!(binary.url, "https://example.com/binary");
        assert_eq!(binary.sha256, "abc123");
        assert_eq!(binary.signature, "sig456");
        assert_eq!(binary.size, 1000);
    }
}
