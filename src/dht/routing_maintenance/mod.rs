//! Routing table maintenance and node validation
//!
//! This module provides:
//! - Periodic routing table refresh with liveness checking
//! - Ill-behaving node removal from routing table
//! - Node validity verification via close group consensus
//! - Close group validation with hybrid trust/BFT approach
//! - Data attestation using nonce-prepended hash challenges
//! - Security coordination integrating Sybil/collusion detection
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

pub mod attestation;
pub mod close_group_validator;
pub mod config;
pub mod data_integrity_monitor;
pub mod eviction;
pub mod liveness;
pub mod refresh;
pub mod scheduler;
pub mod security_coordinator;
pub mod validator;

// Re-export main types
pub use attestation::{ChallengeResponse, DataChallenge, compute_attested_hash};
pub use close_group_validator::{
    AttackIndicators, CloseGroupFailure, CloseGroupHistory, CloseGroupResponse,
    CloseGroupValidationResult, CloseGroupValidator, CloseGroupValidatorConfig,
};
pub use config::MaintenanceConfig;
pub use eviction::{EvictionManager, EvictionReason};
pub use liveness::NodeLivenessState;
pub use refresh::{BucketRefreshManager, BucketRefreshState, RefreshTier};
pub use scheduler::{MaintenanceScheduler, MaintenanceTask, ScheduledTask, TaskStats};
pub use validator::{
    NodeValidationResult, ValidationFailure, WitnessResponse, WitnessSelectionCriteria,
};
pub use security_coordinator::{
    CloseGroupEviction, CloseGroupEvictionTracker, EvictionRecord, SecurityCoordinator,
    SecurityCoordinatorConfig,
};
pub use data_integrity_monitor::{
    AttestationResult, DataHealthScore, DataHealthStatus, DataIntegrityConfig,
    DataIntegrityMetrics, DataIntegrityMonitor, NodeAttestationHistory, RepairRecommendation,
};
