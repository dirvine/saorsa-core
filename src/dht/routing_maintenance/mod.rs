//! Routing table maintenance and node validation
//!
//! This module provides:
//! - Periodic routing table refresh with liveness checking
//! - Ill-behaving node removal from routing table
//! - Node validity verification via close group consensus
//! - Data attestation using nonce-prepended hash challenges
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

pub mod attestation;
pub mod config;
pub mod eviction;
pub mod liveness;
pub mod refresh;
pub mod scheduler;
pub mod validator;

// Re-export main types
pub use attestation::{ChallengeResponse, DataChallenge, compute_attested_hash};
pub use config::MaintenanceConfig;
pub use eviction::{EvictionManager, EvictionReason};
pub use liveness::NodeLivenessState;
pub use refresh::{BucketRefreshManager, BucketRefreshState, RefreshTier};
pub use scheduler::{MaintenanceScheduler, MaintenanceTask, ScheduledTask, TaskStats};
pub use validator::{
    NodeValidationResult, ValidationFailure, WitnessResponse, WitnessSelectionCriteria,
};
