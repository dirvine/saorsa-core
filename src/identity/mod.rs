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

//! Cryptographic Identity Module
//!
//! Provides cryptographic node identity for the P2P network using post-quantum
//! ML-DSA signatures. This module handles peer identity (NodeIdentity), NOT
//! user-facing identity management (which was removed).
//!
//! # Core Types
//!
//! - `NodeIdentity`: Cryptographic identity with ML-DSA keypair
//! - `NodeId`: 32-byte hash of public key (PeerId)
//! - `FourWordAddress`: Human-readable address for bootstrap
//!
//! # Identity Restart System
//!
//! Enables nodes to detect when their identity doesn't "fit" a DHT close group
//! and automatically regenerate with a new identity.

pub mod cli;
pub mod encryption;
pub mod fitness;
pub mod four_words;
pub mod node_identity;
pub mod regeneration;
pub mod rejection;
pub mod restart;
pub mod secure_node_identity;
pub mod targeting;

#[cfg(test)]
mod four_words_error_tests;

pub use four_words::{FourWordAddress, WordEncoder};
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
