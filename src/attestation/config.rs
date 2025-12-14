// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Attestation configuration types.

use serde::{Deserialize, Serialize};

/// Enforcement mode for attestation verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EnforcementMode {
    /// Attestation is completely disabled.
    #[default]
    Off,
    /// Soft enforcement: log warnings but don't reject invalid attestations.
    Soft,
    /// Hard enforcement: reject nodes with invalid attestations.
    Hard,
}

/// Configuration for the attestation system.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AttestationConfig {
    /// Whether attestation is enabled.
    pub enabled: bool,

    /// Enforcement mode for attestation verification.
    pub enforcement_mode: EnforcementMode,

    /// List of allowed binary hashes (empty = allow all for permissive mode).
    pub allowed_binary_hashes: Vec<[u8; 32]>,

    /// Grace period in days after sunset before hard rejection.
    pub sunset_grace_days: u32,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            enforcement_mode: EnforcementMode::Off,
            allowed_binary_hashes: Vec::new(),
            sunset_grace_days: 30,
        }
    }
}

impl AttestationConfig {
    /// Create a new attestation config with the given enforcement mode.
    #[must_use]
    pub fn new(enforcement_mode: EnforcementMode) -> Self {
        Self {
            enabled: enforcement_mode != EnforcementMode::Off,
            enforcement_mode,
            ..Default::default()
        }
    }

    /// Check if hard enforcement is enabled.
    #[must_use]
    pub fn is_hard_enforcement(&self) -> bool {
        self.enabled && self.enforcement_mode == EnforcementMode::Hard
    }

    /// Check if soft enforcement is enabled.
    #[must_use]
    pub fn is_soft_enforcement(&self) -> bool {
        self.enabled && self.enforcement_mode == EnforcementMode::Soft
    }

    /// Check if a binary hash is allowed.
    ///
    /// If the allowed list is empty, all binaries are allowed (permissive mode).
    #[must_use]
    pub fn is_binary_allowed(&self, binary_hash: &[u8; 32]) -> bool {
        // Empty list = allow all (permissive mode for testing/development)
        if self.allowed_binary_hashes.is_empty() {
            return true;
        }
        self.allowed_binary_hashes.contains(binary_hash)
    }

    /// Add a binary hash to the allowed list.
    pub fn allow_binary(&mut self, binary_hash: [u8; 32]) {
        if !self.allowed_binary_hashes.contains(&binary_hash) {
            self.allowed_binary_hashes.push(binary_hash);
        }
    }

    /// Remove a binary hash from the allowed list.
    pub fn disallow_binary(&mut self, binary_hash: &[u8; 32]) {
        self.allowed_binary_hashes.retain(|h| h != binary_hash);
    }

    /// Create a development configuration with all binaries allowed.
    #[must_use]
    pub fn development() -> Self {
        Self {
            enabled: true,
            enforcement_mode: EnforcementMode::Soft,
            allowed_binary_hashes: Vec::new(), // Allow all
            sunset_grace_days: 365,            // Long grace period for development
        }
    }

    /// Create a production configuration with strict enforcement.
    #[must_use]
    pub fn production(allowed_hashes: Vec<[u8; 32]>) -> Self {
        Self {
            enabled: true,
            enforcement_mode: EnforcementMode::Hard,
            allowed_binary_hashes: allowed_hashes,
            sunset_grace_days: 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AttestationConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.enforcement_mode, EnforcementMode::Off);
        assert!(config.allowed_binary_hashes.is_empty());
        assert_eq!(config.sunset_grace_days, 30);
    }

    #[test]
    fn test_enforcement_modes() {
        let config = AttestationConfig::new(EnforcementMode::Soft);
        assert!(config.enabled);
        assert!(config.is_soft_enforcement());
        assert!(!config.is_hard_enforcement());

        let config = AttestationConfig::new(EnforcementMode::Hard);
        assert!(config.enabled);
        assert!(config.is_hard_enforcement());
        assert!(!config.is_soft_enforcement());

        let config = AttestationConfig::new(EnforcementMode::Off);
        assert!(!config.enabled);
        assert!(!config.is_hard_enforcement());
        assert!(!config.is_soft_enforcement());
    }

    #[test]
    fn test_binary_allowlist() {
        let mut config = AttestationConfig::default();
        let hash1 = [0x42u8; 32];
        let hash2 = [0x43u8; 32];

        // Empty list allows all
        assert!(config.is_binary_allowed(&hash1));
        assert!(config.is_binary_allowed(&hash2));

        // Add specific hash
        config.allow_binary(hash1);
        assert!(config.is_binary_allowed(&hash1));
        assert!(!config.is_binary_allowed(&hash2));

        // Remove hash
        config.disallow_binary(&hash1);
        assert!(config.is_binary_allowed(&hash1)); // Back to permissive
    }

    #[test]
    fn test_development_config() {
        let config = AttestationConfig::development();
        assert!(config.enabled);
        assert!(config.is_soft_enforcement());
        assert!(config.allowed_binary_hashes.is_empty());
    }

    #[test]
    fn test_production_config() {
        let hash = [0x42u8; 32];
        let config = AttestationConfig::production(vec![hash]);
        assert!(config.enabled);
        assert!(config.is_hard_enforcement());
        assert!(config.is_binary_allowed(&hash));
        assert!(!config.is_binary_allowed(&[0x43u8; 32]));
    }
}
