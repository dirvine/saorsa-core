// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Identity management module
//!
//! Provides identity creation, management, and encryption with quantum-resistant capabilities.
//!
//! # Identity Restart System
//!
//! The identity restart system enables nodes to detect when their identity doesn't
//! "fit" a DHT close group and automatically regenerate with a new identity.
//!
//! Key components:
//! - [`rejection`]: Network rejection reasons and information
//! - [`fitness`]: Proactive fitness monitoring
//! - [`regeneration`]: Regeneration trigger with loop prevention
//! - [`targeting`]: Targeted identity generation
//! - [`restart`]: Main orchestrator with state persistence

pub mod cli;
pub mod encryption;
pub mod enhanced;
pub mod fitness;
pub mod four_words;
pub mod manager;
pub mod node_identity;
pub mod regeneration;
pub mod rejection;
pub mod restart;
pub mod secure_node_identity;
pub mod targeting;

#[cfg(test)]
mod four_words_error_tests;

pub use enhanced::*;
pub use four_words::{FourWordAddress, WordEncoder};
pub use manager::{IdentityManager, UserIdentity};
pub use node_identity::{IdentityData, NodeId, NodeIdentity};
pub use secure_node_identity::SecureNodeIdentity;

// Identity restart system exports
pub use fitness::{FitnessConfig, FitnessMetrics, FitnessMonitor, FitnessVerdict};
pub use regeneration::{
    BlockReason, RegenerationConfig, RegenerationDecision, RegenerationReason, RegenerationTrigger,
    RegenerationUrgency,
};
pub use rejection::{
    KeyspaceRegion, RejectionHistory, RejectionInfo, RejectionReason, TargetRegion,
};
pub use restart::{
    IdentitySystemEvent, PersistentState, RestartConfig, RestartManager, RestartManagerStatus,
};
pub use targeting::{IdentityTargeter, TargetingConfig, TargetingStats};
