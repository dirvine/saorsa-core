//! Node validity verification via close group consensus
//!
//! Validates that nodes are still considered valid by their close group.
//! Uses BFT thresholds to tolerate Byzantine faults.
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use std::time::SystemTime;

use crate::dht::DhtNodeId;

use super::config::MaintenanceConfig;

/// Reasons why validation might fail
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationFailure {
    /// Node is not known by witnesses
    UnknownNode,
    /// Node has been marked as malicious
    MarkedMalicious,
    /// Node is unreachable
    Unreachable,
    /// Insufficient witnesses available
    InsufficientWitnesses,
    /// Node's close group rejected it
    CloseGroupRejection,
}

/// Result of validating a node via its close group
#[derive(Debug, Clone)]
pub struct NodeValidationResult {
    /// The node that was validated
    pub node_id: DhtNodeId,
    /// Number of witnesses confirming validity
    pub confirming_witnesses: usize,
    /// Number of witnesses denying validity
    pub denying_witnesses: usize,
    /// Total witnesses queried
    pub total_witnesses: usize,
    /// When validation was performed
    pub validated_at: SystemTime,
    /// Any failure reasons reported by witnesses
    pub failure_reasons: Vec<ValidationFailure>,
}

impl Default for NodeValidationResult {
    fn default() -> Self {
        Self {
            node_id: DhtNodeId::random(),
            confirming_witnesses: 0,
            denying_witnesses: 0,
            total_witnesses: 0,
            validated_at: SystemTime::now(),
            failure_reasons: Vec::new(),
        }
    }
}

impl NodeValidationResult {
    /// Create a new validation result
    #[must_use]
    pub fn new(node_id: DhtNodeId) -> Self {
        Self {
            node_id,
            confirming_witnesses: 0,
            denying_witnesses: 0,
            total_witnesses: 0,
            validated_at: SystemTime::now(),
            failure_reasons: Vec::new(),
        }
    }

    /// Check if the node is valid based on simple majority
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.total_witnesses > 0 && self.confirming_witnesses > self.total_witnesses / 2
    }

    /// Check if the node is valid based on BFT threshold
    ///
    /// For f Byzantine faults, we need at least 2f+1 confirmations
    #[must_use]
    pub fn is_valid_bft(&self, config: &MaintenanceConfig) -> bool {
        self.confirming_witnesses >= config.required_confirmations()
    }

    /// Check if we have enough witnesses for a valid result
    #[must_use]
    pub fn has_sufficient_witnesses(&self, config: &MaintenanceConfig) -> bool {
        self.total_witnesses >= config.minimum_witnesses()
    }

    /// Record a confirming witness
    pub fn record_confirmation(&mut self) {
        self.confirming_witnesses += 1;
        self.total_witnesses += 1;
    }

    /// Record a denying witness with reason
    pub fn record_denial(&mut self, reason: ValidationFailure) {
        self.denying_witnesses += 1;
        self.total_witnesses += 1;
        if !self.failure_reasons.contains(&reason) {
            self.failure_reasons.push(reason);
        }
    }

    /// Record a witness that couldn't respond (neutral)
    pub fn record_no_response(&mut self) {
        self.total_witnesses += 1;
        // Neither confirming nor denying - could be network issues
    }

    /// Get the confirmation ratio (0.0 - 1.0)
    #[must_use]
    pub fn confirmation_ratio(&self) -> f64 {
        if self.total_witnesses == 0 {
            0.0
        } else {
            self.confirming_witnesses as f64 / self.total_witnesses as f64
        }
    }
}

/// A witness response for node validation
#[derive(Debug, Clone)]
pub struct WitnessResponse {
    /// The witness who responded
    pub witness_id: DhtNodeId,
    /// Whether the witness confirms the node is valid
    pub confirms_valid: bool,
    /// Reason if denying validity
    pub failure_reason: Option<ValidationFailure>,
    /// When the response was received
    pub response_time: SystemTime,
}

impl WitnessResponse {
    /// Create a confirming response
    #[must_use]
    pub fn confirming(witness_id: DhtNodeId) -> Self {
        Self {
            witness_id,
            confirms_valid: true,
            failure_reason: None,
            response_time: SystemTime::now(),
        }
    }

    /// Create a denying response
    #[must_use]
    pub fn denying(witness_id: DhtNodeId, reason: ValidationFailure) -> Self {
        Self {
            witness_id,
            confirms_valid: false,
            failure_reason: Some(reason),
            response_time: SystemTime::now(),
        }
    }
}

/// Criteria for selecting validation witnesses
#[derive(Debug, Clone)]
pub struct WitnessSelectionCriteria {
    /// Minimum number of witnesses needed
    pub min_witnesses: usize,
    /// Maximum number of witnesses to query
    pub max_witnesses: usize,
    /// Whether to require geographic diversity
    pub require_geographic_diversity: bool,
    /// Minimum trust score for a witness
    pub min_trust_score: f64,
    /// Whether to exclude nodes sharing subnet with target
    pub exclude_same_subnet: bool,
}

impl Default for WitnessSelectionCriteria {
    fn default() -> Self {
        Self {
            min_witnesses: 5,
            max_witnesses: 10,
            require_geographic_diversity: true,
            min_trust_score: 0.3,
            exclude_same_subnet: true,
        }
    }
}

impl WitnessSelectionCriteria {
    /// Create criteria from maintenance config
    #[must_use]
    pub fn from_config(config: &MaintenanceConfig) -> Self {
        Self {
            min_witnesses: config.minimum_witnesses(),
            max_witnesses: config.minimum_witnesses() + 3,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_requires_majority() {
        let mut result = NodeValidationResult {
            confirming_witnesses: 2,
            total_witnesses: 5,
            ..Default::default()
        };
        assert!(!result.is_valid()); // 2/5 < majority

        result.confirming_witnesses = 3;
        assert!(result.is_valid()); // 3/5 >= majority
    }

    #[test]
    fn test_bft_threshold_calculation() {
        // For f=2 Byzantine faults, need 2f+1 = 5 confirmations
        let config = MaintenanceConfig {
            bft_fault_tolerance: 2,
            ..Default::default()
        };
        assert_eq!(config.required_confirmations(), 5);

        // For f=1, need 3 confirmations
        let config_f1 = MaintenanceConfig {
            bft_fault_tolerance: 1,
            ..Default::default()
        };
        assert_eq!(config_f1.required_confirmations(), 3);
    }

    #[test]
    fn test_validation_with_bft_threshold() {
        let config = MaintenanceConfig {
            bft_fault_tolerance: 2,
            ..Default::default()
        };

        let mut result = NodeValidationResult::default();

        // 4 confirmations - not enough for f=2 (needs 5)
        for _ in 0..4 {
            result.record_confirmation();
        }
        assert!(!result.is_valid_bft(&config));

        // 5 confirmations - exactly enough
        result.record_confirmation();
        assert!(result.is_valid_bft(&config));
    }

    #[test]
    fn test_sufficient_witnesses() {
        let config = MaintenanceConfig {
            bft_fault_tolerance: 2,
            ..Default::default()
        };

        let mut result = NodeValidationResult::default();

        // Need 3f+1 = 7 witnesses for f=2
        for _ in 0..6 {
            result.record_confirmation();
        }
        assert!(!result.has_sufficient_witnesses(&config));

        result.record_confirmation();
        assert!(result.has_sufficient_witnesses(&config));
    }

    #[test]
    fn test_record_confirmation() {
        let mut result = NodeValidationResult::new(DhtNodeId::random());

        result.record_confirmation();
        assert_eq!(result.confirming_witnesses, 1);
        assert_eq!(result.total_witnesses, 1);

        result.record_confirmation();
        assert_eq!(result.confirming_witnesses, 2);
        assert_eq!(result.total_witnesses, 2);
    }

    #[test]
    fn test_record_denial() {
        let mut result = NodeValidationResult::new(DhtNodeId::random());

        result.record_denial(ValidationFailure::UnknownNode);
        assert_eq!(result.denying_witnesses, 1);
        assert_eq!(result.total_witnesses, 1);
        assert_eq!(result.failure_reasons.len(), 1);

        // Same reason shouldn't duplicate
        result.record_denial(ValidationFailure::UnknownNode);
        assert_eq!(result.failure_reasons.len(), 1);

        // Different reason should add
        result.record_denial(ValidationFailure::Unreachable);
        assert_eq!(result.failure_reasons.len(), 2);
    }

    #[test]
    fn test_record_no_response() {
        let mut result = NodeValidationResult::new(DhtNodeId::random());

        result.record_no_response();
        assert_eq!(result.confirming_witnesses, 0);
        assert_eq!(result.denying_witnesses, 0);
        assert_eq!(result.total_witnesses, 1);
    }

    #[test]
    fn test_confirmation_ratio() {
        let mut result = NodeValidationResult::new(DhtNodeId::random());

        // No witnesses yet
        assert!((result.confirmation_ratio() - 0.0).abs() < f64::EPSILON);

        // 3 out of 4 confirm
        result.record_confirmation();
        result.record_confirmation();
        result.record_confirmation();
        result.record_denial(ValidationFailure::UnknownNode);

        assert!((result.confirmation_ratio() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn test_witness_response_confirming() {
        let witness_id = DhtNodeId::random();
        let response = WitnessResponse::confirming(witness_id.clone());

        assert!(response.confirms_valid);
        assert!(response.failure_reason.is_none());
        assert_eq!(response.witness_id, witness_id);
    }

    #[test]
    fn test_witness_response_denying() {
        let witness_id = DhtNodeId::random();
        let response =
            WitnessResponse::denying(witness_id.clone(), ValidationFailure::MarkedMalicious);

        assert!(!response.confirms_valid);
        assert_eq!(
            response.failure_reason,
            Some(ValidationFailure::MarkedMalicious)
        );
    }

    #[test]
    fn test_witness_selection_criteria_from_config() {
        let config = MaintenanceConfig {
            bft_fault_tolerance: 2,
            ..Default::default()
        };

        let criteria = WitnessSelectionCriteria::from_config(&config);

        // For f=2, min witnesses should be 3f+1 = 7
        assert_eq!(criteria.min_witnesses, 7);
        assert_eq!(criteria.max_witnesses, 10);
    }

    #[test]
    fn test_validation_failure_reasons_distinct() {
        let mut result = NodeValidationResult::new(DhtNodeId::random());

        result.record_denial(ValidationFailure::UnknownNode);
        result.record_denial(ValidationFailure::Unreachable);
        result.record_denial(ValidationFailure::MarkedMalicious);

        assert_eq!(result.failure_reasons.len(), 3);
        assert!(
            result
                .failure_reasons
                .contains(&ValidationFailure::UnknownNode)
        );
        assert!(
            result
                .failure_reasons
                .contains(&ValidationFailure::Unreachable)
        );
        assert!(
            result
                .failure_reasons
                .contains(&ValidationFailure::MarkedMalicious)
        );
    }

    #[test]
    fn test_is_valid_with_no_witnesses() {
        let result = NodeValidationResult::new(DhtNodeId::random());
        assert!(!result.is_valid()); // No witnesses = not valid
    }
}
