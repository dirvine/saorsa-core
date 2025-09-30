// Shared simple types used across modules
// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

use serde::{Deserialize, Serialize};

/// Forward entry (transport endpoint advertisement)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Forward {
    pub proto: String,
    pub addr: String,
    pub exp: u64,
}

// New clean types modules
pub mod identity;
pub mod presence;
pub mod storage;

// Re-export main types
pub use identity::{Identity, IdentityHandle, MlDsaKeyPair};
pub use presence::{
    Device, DeviceCapabilities, DeviceId, DeviceType, Endpoint, Presence, PresenceReceipt,
};
pub use storage::{
    FecParameters, SealParameters, ShardAssignment, ShardDistributionPlan, ShardMap, ShardRole,
    StorageHandle, StorageStrategy,
};

/// Example strong typing implementations (future replacements for string-based IDs)
///
/// This demonstrates how `pub type PeerId = String` should eventually
/// be replaced with validated newtypes for better type safety.
pub mod validated_ids {
    use serde::{Deserialize, Serialize};

    /// Example of a properly typed peer ID (not yet used in main codebase)
    #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
    pub struct ValidatedPeerId(String);

    impl ValidatedPeerId {
        /// Create a new ValidatedPeerId from a string, validating the format
        pub fn new(id: impl Into<String>) -> Result<Self, ValidationError> {
            let id = id.into();
            if id.is_empty() {
                return Err(ValidationError::Empty);
            }
            if id.len() > 256 {
                return Err(ValidationError::TooLong(id.len()));
            }
            // Basic validation - could be enhanced with cryptographic checks
            if !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(ValidationError::InvalidCharacters);
            }
            Ok(Self(id))
        }

        /// Get the inner string representation
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    impl std::fmt::Display for ValidatedPeerId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    /// Validation errors for strongly-typed IDs
    #[derive(Debug, Clone, thiserror::Error)]
    pub enum ValidationError {
        #[error("ID cannot be empty")]
        Empty,
        #[error("ID too long: {0} characters (max 256)")]
        TooLong(usize),
        #[error("ID contains invalid characters (only alphanumeric, -, _ allowed)")]
        InvalidCharacters,
    }
}
