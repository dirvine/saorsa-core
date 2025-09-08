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
