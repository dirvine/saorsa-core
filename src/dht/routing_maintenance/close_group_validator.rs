//! Close group validation during routing table refresh
//!
//! Validates that nodes are still considered valid members of their close groups.
//! Uses hybrid validation: trust-weighted normally, BFT consensus when attacks detected.
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use parking_lot::RwLock;

use crate::dht::DhtNodeId;

use super::config::MaintenanceConfig;
use super::validator::{NodeValidationResult, ValidationFailure};

/// Reasons why close group validation might fail
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseGroupFailure {
    /// Node is not in any peer's close group
    NotInCloseGroup,
    /// Node was evicted from close group
    EvictedFromCloseGroup,
    /// Insufficient peers confirmed membership
    InsufficientConfirmation,
    /// Node's trust score too low
    LowTrustScore,
    /// Geographic diversity requirement not met
    InsufficientGeographicDiversity,
    /// Witness responses showed signs of collusion
    SuspectedCollusion,
    /// Attack mode escalation triggered
    AttackModeTriggered,
}

/// Enforcement mode for close group validation
///
/// Controls whether validation failures result in node rejection or just logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CloseGroupEnforcementMode {
    /// Log-only mode - log validation failures but allow unknown nodes
    /// Use during initial deployment or for monitoring
    LogOnly,
    /// Strict mode - reject nodes that fail validation (default)
    /// Use in production for full security
    #[default]
    Strict,
}

impl CloseGroupEnforcementMode {
    /// Check if this mode is strict (rejects invalid nodes)
    #[must_use]
    pub fn is_strict(&self) -> bool {
        matches!(self, Self::Strict)
    }

    /// Check if this mode is log-only (allows all nodes, just logs issues)
    #[must_use]
    pub fn is_log_only(&self) -> bool {
        matches!(self, Self::LogOnly)
    }
}

/// Result of close group validation
#[derive(Debug, Clone)]
pub struct CloseGroupValidationResult {
    /// The node that was validated
    pub node_id: DhtNodeId,
    /// Whether the node is valid
    pub is_valid: bool,
    /// Weighted confirmation ratio (0.0 - 1.0)
    pub confirmation_ratio: f64,
    /// Trust-weighted confirmation score
    pub weighted_confirmation: f64,
    /// Number of unique regions that confirmed
    pub confirming_regions: usize,
    /// Any failure reasons
    pub failure_reasons: Vec<CloseGroupFailure>,
    /// Whether BFT consensus was used
    pub used_bft_consensus: bool,
    /// Time taken for validation
    pub validation_duration: Duration,
    /// Timestamp of validation
    pub validated_at: SystemTime,
}

impl CloseGroupValidationResult {
    /// Create a new validation result
    #[must_use]
    pub fn new(node_id: DhtNodeId) -> Self {
        Self {
            node_id,
            is_valid: false,
            confirmation_ratio: 0.0,
            weighted_confirmation: 0.0,
            confirming_regions: 0,
            failure_reasons: Vec::new(),
            used_bft_consensus: false,
            validation_duration: Duration::ZERO,
            validated_at: SystemTime::now(),
        }
    }

    /// Check if validation passed with sufficient confidence
    #[must_use]
    pub fn is_confident(&self) -> bool {
        self.is_valid && self.weighted_confirmation >= 0.7
    }

    /// Add a failure reason
    pub fn add_failure(&mut self, reason: CloseGroupFailure) {
        if !self.failure_reasons.contains(&reason) {
            self.failure_reasons.push(reason);
        }
    }
}

/// Attack indicator state for escalation decisions
#[derive(Debug, Clone)]
pub struct AttackIndicators {
    /// Eclipse attack risk score (0.0 - 1.0)
    pub eclipse_risk: f64,
    /// Sybil attack risk score (0.0 - 1.0)
    pub sybil_risk: f64,
    /// Routing manipulation detected
    pub routing_manipulation: bool,
    /// Recent churn rate (percentage of table changed in 5 minutes)
    pub churn_rate: f64,
    /// Number of validation failures in last hour
    pub recent_failures: u64,
    /// Time of last attack indicator update
    pub last_updated: Instant,
}

impl Default for AttackIndicators {
    fn default() -> Self {
        Self {
            eclipse_risk: 0.0,
            sybil_risk: 0.0,
            routing_manipulation: false,
            churn_rate: 0.0,
            recent_failures: 0,
            last_updated: Instant::now(),
        }
    }
}

impl AttackIndicators {
    /// Check if any attack indicator suggests we should escalate to BFT
    #[must_use]
    pub fn should_escalate_to_bft(&self) -> bool {
        self.eclipse_risk > 0.5
            || self.sybil_risk > 0.5
            || self.routing_manipulation
            || self.churn_rate > 0.3 // > 30% churn in 5 minutes
            || self.recent_failures > 10
    }

    /// Get the highest risk score
    #[must_use]
    pub fn max_risk(&self) -> f64 {
        self.eclipse_risk.max(self.sybil_risk).max(self.churn_rate)
    }
}

/// Peer's response about close group membership
#[derive(Debug, Clone)]
pub struct CloseGroupResponse {
    /// The peer who responded
    pub peer_id: DhtNodeId,
    /// Whether the peer confirms the node is in their close group
    pub confirms_membership: bool,
    /// The peer's trust score (if available)
    pub peer_trust_score: Option<f64>,
    /// The peer's geographic region (if known)
    pub peer_region: Option<String>,
    /// Response latency
    pub response_latency: Duration,
    /// When the response was received
    pub received_at: Instant,
}

/// Historical close group membership for change detection
#[derive(Debug, Clone)]
pub struct CloseGroupHistory {
    /// Node ID
    pub node_id: DhtNodeId,
    /// Previous close group members
    pub previous_members: HashSet<DhtNodeId>,
    /// Current close group members
    pub current_members: HashSet<DhtNodeId>,
    /// When the previous snapshot was taken
    pub previous_snapshot_at: Instant,
    /// When the current snapshot was taken
    pub current_snapshot_at: Instant,
}

impl CloseGroupHistory {
    /// Create a new history entry
    #[must_use]
    pub fn new(node_id: DhtNodeId, members: HashSet<DhtNodeId>) -> Self {
        let now = Instant::now();
        Self {
            node_id,
            previous_members: HashSet::new(),
            current_members: members,
            previous_snapshot_at: now,
            current_snapshot_at: now,
        }
    }

    /// Update with new membership
    pub fn update(&mut self, new_members: HashSet<DhtNodeId>) {
        self.previous_members = std::mem::take(&mut self.current_members);
        self.previous_snapshot_at = self.current_snapshot_at;
        self.current_members = new_members;
        self.current_snapshot_at = Instant::now();
    }

    /// Get nodes that were removed since last snapshot
    #[must_use]
    pub fn removed_nodes(&self) -> HashSet<DhtNodeId> {
        self.previous_members
            .difference(&self.current_members)
            .cloned()
            .collect()
    }

    /// Get nodes that were added since last snapshot
    #[must_use]
    pub fn added_nodes(&self) -> HashSet<DhtNodeId> {
        self.current_members
            .difference(&self.previous_members)
            .cloned()
            .collect()
    }

    /// Calculate churn rate (0.0 - 1.0)
    #[must_use]
    pub fn churn_rate(&self) -> f64 {
        if self.previous_members.is_empty() {
            return 0.0;
        }
        let removed = self.removed_nodes().len();
        let added = self.added_nodes().len();
        let changes = removed + added;
        let total = self.previous_members.len().max(1);
        (changes as f64 / total as f64).min(1.0)
    }
}

/// Configuration for close group validation
#[derive(Debug, Clone)]
pub struct CloseGroupValidatorConfig {
    /// Minimum peers to query for validation
    pub min_peers_to_query: usize,
    /// Maximum peers to query for validation
    pub max_peers_to_query: usize,
    /// Trust-weighted confirmation threshold (normal mode)
    pub trust_weighted_threshold: f64,
    /// BFT confirmation threshold (attack mode)
    pub bft_threshold: f64,
    /// Minimum trust score for a witness
    pub min_witness_trust: f64,
    /// Minimum geographic regions for diversity
    pub min_regions: usize,
    /// Query timeout
    pub query_timeout: Duration,
    /// Enable automatic BFT escalation
    pub auto_escalate: bool,
    /// Enforcement mode (Strict or LogOnly)
    pub enforcement_mode: CloseGroupEnforcementMode,
}

impl Default for CloseGroupValidatorConfig {
    fn default() -> Self {
        Self {
            min_peers_to_query: 5,
            max_peers_to_query: 10,
            trust_weighted_threshold: 0.7,
            bft_threshold: 0.71, // 5/7 for f=2
            min_witness_trust: 0.3,
            min_regions: 3,
            query_timeout: Duration::from_secs(5),
            auto_escalate: true,
            enforcement_mode: CloseGroupEnforcementMode::default(),
        }
    }
}

impl CloseGroupValidatorConfig {
    /// Create config with strict enforcement (default)
    #[must_use]
    pub fn strict() -> Self {
        Self::default()
    }

    /// Create config with log-only enforcement (for monitoring without rejection)
    #[must_use]
    pub fn log_only() -> Self {
        Self {
            enforcement_mode: CloseGroupEnforcementMode::LogOnly,
            ..Default::default()
        }
    }

    /// Set the enforcement mode
    #[must_use]
    pub fn with_enforcement_mode(mut self, mode: CloseGroupEnforcementMode) -> Self {
        self.enforcement_mode = mode;
        self
    }

    /// Create config from maintenance config
    #[must_use]
    pub fn from_maintenance_config(config: &MaintenanceConfig) -> Self {
        Self {
            min_peers_to_query: config.minimum_witnesses(),
            max_peers_to_query: config.minimum_witnesses() + 3,
            bft_threshold: config.required_confirmations() as f64
                / config.minimum_witnesses() as f64,
            ..Default::default()
        }
    }
}

/// Close group validator with hybrid validation
///
/// Uses trust-weighted validation normally, escalates to BFT consensus
/// when attack indicators are detected.
pub struct CloseGroupValidator {
    /// Configuration
    config: CloseGroupValidatorConfig,
    /// Whether attack mode is active (use BFT instead of trust-weighted)
    attack_mode: AtomicBool,
    /// Current attack indicators
    attack_indicators: Arc<RwLock<AttackIndicators>>,
    /// Close group history for change detection
    close_group_history: Arc<RwLock<HashMap<DhtNodeId, CloseGroupHistory>>>,
    /// Cache of recent validation results
    validation_cache: Arc<RwLock<HashMap<DhtNodeId, CloseGroupValidationResult>>>,
    /// Cache TTL
    cache_ttl: Duration,
}

impl CloseGroupValidator {
    /// Create a new close group validator
    #[must_use]
    pub fn new(config: CloseGroupValidatorConfig) -> Self {
        Self {
            config,
            attack_mode: AtomicBool::new(false),
            attack_indicators: Arc::new(RwLock::new(AttackIndicators::default())),
            close_group_history: Arc::new(RwLock::new(HashMap::new())),
            validation_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(60),
        }
    }

    /// Create with default configuration
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(CloseGroupValidatorConfig::default())
    }

    /// Check if attack mode is currently active
    #[must_use]
    pub fn is_attack_mode(&self) -> bool {
        self.attack_mode.load(Ordering::Relaxed)
    }

    /// Manually set attack mode
    pub fn set_attack_mode(&self, enabled: bool) {
        self.attack_mode.store(enabled, Ordering::Relaxed);
    }

    /// Update attack indicators and check for escalation
    pub fn update_attack_indicators(&self, indicators: AttackIndicators) {
        let should_escalate = indicators.should_escalate_to_bft();

        {
            let mut current = self.attack_indicators.write();
            *current = indicators;
        }

        if self.config.auto_escalate && should_escalate {
            self.escalate_to_bft();
        }
    }

    /// Get current attack indicators
    #[must_use]
    pub fn get_attack_indicators(&self) -> AttackIndicators {
        self.attack_indicators.read().clone()
    }

    /// Escalate to BFT consensus mode
    pub fn escalate_to_bft(&self) {
        self.attack_mode.store(true, Ordering::SeqCst);
    }

    /// De-escalate from BFT mode (when attack indicators clear)
    pub fn deescalate_from_bft(&self) {
        let indicators = self.attack_indicators.read();
        if !indicators.should_escalate_to_bft() {
            self.attack_mode.store(false, Ordering::SeqCst);
        }
    }

    /// Check if a node is valid based on cached validation results
    ///
    /// Behavior depends on enforcement mode:
    /// - Strict: Unknown nodes are rejected (return false)
    /// - LogOnly: Unknown nodes are allowed (return true) with warning logged
    pub fn validate(&self, node_id: &DhtNodeId) -> bool {
        if let Some(result) = self.get_cached_result(node_id) {
            if !result.is_valid && self.config.enforcement_mode.is_log_only() {
                tracing::warn!(
                    node_id = ?node_id,
                    "Close group validation failed but allowed (LogOnly mode)"
                );
                return true;
            }
            return result.is_valid;
        }

        // Node not in cache - behavior depends on enforcement mode
        match self.config.enforcement_mode {
            CloseGroupEnforcementMode::Strict => {
                // Strict mode: unknown nodes are rejected
                tracing::debug!(
                    node_id = ?node_id,
                    "Unknown node rejected (Strict mode)"
                );
                false
            }
            CloseGroupEnforcementMode::LogOnly => {
                // LogOnly mode: allow unknown nodes
                tracing::debug!(
                    node_id = ?node_id,
                    "Unknown node allowed (LogOnly mode)"
                );
                true
            }
        }
    }

    /// Get the current enforcement mode
    #[must_use]
    pub fn enforcement_mode(&self) -> CloseGroupEnforcementMode {
        self.config.enforcement_mode
    }

    /// Validate close group membership with hybrid approach
    ///
    /// Uses trust-weighted validation normally, BFT consensus when attack mode is active.
    pub fn validate_membership(
        &self,
        node_id: &DhtNodeId,
        responses: &[CloseGroupResponse],
        node_trust_score: Option<f64>,
    ) -> CloseGroupValidationResult {
        let start = Instant::now();
        let mut result = CloseGroupValidationResult::new(node_id.clone());

        // Check if we have enough responses
        if responses.len() < self.config.min_peers_to_query {
            result.add_failure(CloseGroupFailure::InsufficientConfirmation);
            result.validation_duration = start.elapsed();
            return result;
        }

        // Check node's own trust score
        if node_trust_score.is_some_and(|trust| trust < self.config.min_witness_trust) {
            result.add_failure(CloseGroupFailure::LowTrustScore);
            result.validation_duration = start.elapsed();
            return result;
        }

        // Determine validation mode
        let use_bft = self.is_attack_mode();
        result.used_bft_consensus = use_bft;

        if use_bft {
            self.validate_bft(responses, &mut result);
        } else {
            self.validate_trust_weighted(responses, &mut result);
        }

        // Check geographic diversity
        let regions = self.count_confirming_regions(responses);
        result.confirming_regions = regions;
        if regions < self.config.min_regions && result.is_valid {
            // Only fail on diversity if we were otherwise valid
            result.add_failure(CloseGroupFailure::InsufficientGeographicDiversity);
            // In attack mode, diversity failure is hard failure
            if use_bft {
                result.is_valid = false;
            }
        }

        result.validation_duration = start.elapsed();
        result
    }

    /// Trust-weighted validation (normal mode)
    fn validate_trust_weighted(
        &self,
        responses: &[CloseGroupResponse],
        result: &mut CloseGroupValidationResult,
    ) {
        let mut total_weight = 0.0;
        let mut confirming_weight = 0.0;
        let mut confirmations = 0;

        for response in responses {
            let weight = response.peer_trust_score.unwrap_or(0.5);
            total_weight += weight;

            if response.confirms_membership {
                confirming_weight += weight;
                confirmations += 1;
            }
        }

        result.confirmation_ratio = if responses.is_empty() {
            0.0
        } else {
            confirmations as f64 / responses.len() as f64
        };

        result.weighted_confirmation = if total_weight > 0.0 {
            confirming_weight / total_weight
        } else {
            0.0
        };

        result.is_valid = result.weighted_confirmation >= self.config.trust_weighted_threshold;

        if !result.is_valid {
            result.add_failure(CloseGroupFailure::InsufficientConfirmation);
        }
    }

    /// BFT consensus validation (attack mode)
    fn validate_bft(
        &self,
        responses: &[CloseGroupResponse],
        result: &mut CloseGroupValidationResult,
    ) {
        // Filter responses to only include trusted witnesses
        let trusted_responses: Vec<_> = responses
            .iter()
            .filter(|r| r.peer_trust_score.unwrap_or(0.0) >= self.config.min_witness_trust)
            .collect();

        if trusted_responses.len() < self.config.min_peers_to_query {
            result.add_failure(CloseGroupFailure::InsufficientConfirmation);
            result.is_valid = false;
            return;
        }

        let confirmations = trusted_responses
            .iter()
            .filter(|r| r.confirms_membership)
            .count();

        result.confirmation_ratio = confirmations as f64 / trusted_responses.len() as f64;
        result.weighted_confirmation = result.confirmation_ratio; // BFT uses unweighted

        // For f=2 Byzantine faults, need 5/7 (> 2/3) confirmations
        result.is_valid = result.confirmation_ratio >= self.config.bft_threshold;

        if !result.is_valid {
            result.add_failure(CloseGroupFailure::InsufficientConfirmation);
        }

        // Check for collusion indicators in BFT mode
        if self.detect_collusion_indicators(&trusted_responses) {
            result.add_failure(CloseGroupFailure::SuspectedCollusion);
            // Collusion is a hard failure in BFT mode
            result.is_valid = false;
        }
    }

    /// Count unique geographic regions that confirmed membership
    fn count_confirming_regions(&self, responses: &[CloseGroupResponse]) -> usize {
        responses
            .iter()
            .filter(|r| r.confirms_membership)
            .filter_map(|r| r.peer_region.as_ref())
            .collect::<HashSet<_>>()
            .len()
    }

    /// Detect potential collusion indicators
    fn detect_collusion_indicators(&self, responses: &[&CloseGroupResponse]) -> bool {
        if responses.len() < 3 {
            return false;
        }

        // Check for suspiciously similar response times (within 10ms)
        let mut latencies: Vec<_> = responses.iter().map(|r| r.response_latency).collect();
        latencies.sort();

        let mut similar_count = 0;
        for window in latencies.windows(2) {
            if let [a, b] = window {
                let diff = (*a).abs_diff(*b);
                if diff < Duration::from_millis(10) {
                    similar_count += 1;
                }
            }
        }

        // If more than half have suspiciously similar timing
        similar_count > responses.len() / 2
    }

    /// Update close group history for a node
    pub fn update_close_group_history(&self, node_id: DhtNodeId, members: HashSet<DhtNodeId>) {
        let mut history = self.close_group_history.write();
        if let Some(entry) = history.get_mut(&node_id) {
            entry.update(members);
        } else {
            history.insert(node_id.clone(), CloseGroupHistory::new(node_id, members));
        }
    }

    /// Detect nodes that have been removed from close groups
    #[must_use]
    pub fn detect_removed_nodes(&self) -> Vec<(DhtNodeId, HashSet<DhtNodeId>)> {
        let history = self.close_group_history.read();
        history
            .iter()
            .map(|(node_id, hist)| (node_id.clone(), hist.removed_nodes()))
            .filter(|(_, removed)| !removed.is_empty())
            .collect()
    }

    /// Calculate overall churn rate across all tracked close groups
    #[must_use]
    pub fn calculate_overall_churn_rate(&self) -> f64 {
        let history = self.close_group_history.read();
        if history.is_empty() {
            return 0.0;
        }

        let total_churn: f64 = history.values().map(|h| h.churn_rate()).sum();
        total_churn / history.len() as f64
    }

    /// Get cached validation result if still valid
    #[must_use]
    pub fn get_cached_result(&self, node_id: &DhtNodeId) -> Option<CloseGroupValidationResult> {
        let cache = self.validation_cache.read();
        cache.get(node_id).and_then(|result| {
            let age = result.validated_at.elapsed().ok()?;
            if age < self.cache_ttl {
                Some(result.clone())
            } else {
                None
            }
        })
    }

    /// Cache a validation result
    pub fn cache_result(&self, result: CloseGroupValidationResult) {
        let mut cache = self.validation_cache.write();
        cache.insert(result.node_id.clone(), result);
    }

    /// Clear expired cache entries
    pub fn clear_expired_cache(&self) {
        let mut cache = self.validation_cache.write();
        cache.retain(|_, result| {
            result
                .validated_at
                .elapsed()
                .map(|age| age < self.cache_ttl)
                .unwrap_or(false)
        });
    }

    /// Convert to NodeValidationResult for compatibility with existing validator
    #[must_use]
    pub fn to_node_validation_result(
        &self,
        result: &CloseGroupValidationResult,
    ) -> NodeValidationResult {
        let mut node_result = NodeValidationResult::new(result.node_id.clone());

        // Map confirmation ratio to witness counts
        // This is an approximation for compatibility
        let total = self.config.min_peers_to_query;
        let confirming = (result.confirmation_ratio * total as f64).round() as usize;

        for _ in 0..confirming {
            node_result.record_confirmation();
        }

        for _ in confirming..total {
            node_result.record_denial(ValidationFailure::CloseGroupRejection);
        }

        node_result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_response(
        confirms: bool,
        trust: f64,
        region: Option<&str>,
        latency_ms: u64,
    ) -> CloseGroupResponse {
        CloseGroupResponse {
            peer_id: DhtNodeId::random(),
            confirms_membership: confirms,
            peer_trust_score: Some(trust),
            peer_region: region.map(String::from),
            response_latency: Duration::from_millis(latency_ms),
            received_at: Instant::now(),
        }
    }

    #[test]
    fn test_trust_weighted_validation_passes() {
        let validator = CloseGroupValidator::with_defaults();
        let node_id = DhtNodeId::random();

        let responses = vec![
            create_response(true, 0.9, Some("us-east"), 50),
            create_response(true, 0.8, Some("eu-west"), 60),
            create_response(true, 0.7, Some("asia"), 70),
            create_response(true, 0.6, Some("oceania"), 80),
            create_response(false, 0.4, Some("africa"), 90),
        ];

        let result = validator.validate_membership(&node_id, &responses, Some(0.5));

        assert!(result.is_valid);
        assert!(!result.used_bft_consensus);
        assert!(result.weighted_confirmation > 0.7);
        assert_eq!(result.confirming_regions, 4);
    }

    #[test]
    fn test_trust_weighted_validation_fails_low_confirmation() {
        let validator = CloseGroupValidator::with_defaults();
        let node_id = DhtNodeId::random();

        let responses = vec![
            create_response(true, 0.3, Some("us-east"), 50),
            create_response(false, 0.9, Some("eu-west"), 60),
            create_response(false, 0.8, Some("asia"), 70),
            create_response(false, 0.7, Some("oceania"), 80),
            create_response(false, 0.6, Some("africa"), 90),
        ];

        let result = validator.validate_membership(&node_id, &responses, Some(0.5));

        assert!(!result.is_valid);
        assert!(
            result
                .failure_reasons
                .contains(&CloseGroupFailure::InsufficientConfirmation)
        );
    }

    #[test]
    fn test_bft_validation_requires_strict_threshold() {
        let validator = CloseGroupValidator::with_defaults();
        validator.set_attack_mode(true);

        let node_id = DhtNodeId::random();

        // 4/7 confirmations - not enough for BFT (needs 5/7)
        let responses = vec![
            create_response(true, 0.9, Some("us-east"), 50),
            create_response(true, 0.8, Some("eu-west"), 60),
            create_response(true, 0.7, Some("asia"), 70),
            create_response(true, 0.6, Some("oceania"), 80),
            create_response(false, 0.5, Some("africa"), 90),
            create_response(false, 0.4, Some("us-west"), 100),
            create_response(false, 0.35, Some("sa"), 110),
        ];

        let result = validator.validate_membership(&node_id, &responses, Some(0.5));

        assert!(!result.is_valid);
        assert!(result.used_bft_consensus);
    }

    #[test]
    fn test_bft_validation_passes_with_sufficient_confirmations() {
        let validator = CloseGroupValidator::with_defaults();
        validator.set_attack_mode(true);

        let node_id = DhtNodeId::random();

        // 5/7 confirmations - enough for BFT
        let responses = vec![
            create_response(true, 0.9, Some("us-east"), 50),
            create_response(true, 0.8, Some("eu-west"), 60),
            create_response(true, 0.7, Some("asia"), 70),
            create_response(true, 0.6, Some("oceania"), 80),
            create_response(true, 0.5, Some("africa"), 90),
            create_response(false, 0.4, Some("us-west"), 100),
            create_response(false, 0.35, Some("sa"), 110),
        ];

        let result = validator.validate_membership(&node_id, &responses, Some(0.5));

        assert!(result.is_valid);
        assert!(result.used_bft_consensus);
    }

    #[test]
    fn test_insufficient_responses_fails() {
        let validator = CloseGroupValidator::with_defaults();
        let node_id = DhtNodeId::random();

        let responses = vec![
            create_response(true, 0.9, Some("us-east"), 50),
            create_response(true, 0.8, Some("eu-west"), 60),
        ];

        let result = validator.validate_membership(&node_id, &responses, Some(0.5));

        assert!(!result.is_valid);
        assert!(
            result
                .failure_reasons
                .contains(&CloseGroupFailure::InsufficientConfirmation)
        );
    }

    #[test]
    fn test_low_trust_node_fails() {
        let validator = CloseGroupValidator::with_defaults();
        let node_id = DhtNodeId::random();

        let responses = vec![
            create_response(true, 0.9, Some("us-east"), 50),
            create_response(true, 0.8, Some("eu-west"), 60),
            create_response(true, 0.7, Some("asia"), 70),
            create_response(true, 0.6, Some("oceania"), 80),
            create_response(true, 0.5, Some("africa"), 90),
        ];

        // Node's own trust score is too low
        let result = validator.validate_membership(&node_id, &responses, Some(0.1));

        assert!(!result.is_valid);
        assert!(
            result
                .failure_reasons
                .contains(&CloseGroupFailure::LowTrustScore)
        );
    }

    #[test]
    fn test_attack_indicators_escalation() {
        let indicators = AttackIndicators {
            eclipse_risk: 0.6,
            sybil_risk: 0.3,
            routing_manipulation: false,
            churn_rate: 0.1,
            recent_failures: 5,
            last_updated: Instant::now(),
        };

        assert!(indicators.should_escalate_to_bft()); // eclipse_risk > 0.5
    }

    #[test]
    fn test_churn_triggers_escalation() {
        let indicators = AttackIndicators {
            eclipse_risk: 0.2,
            sybil_risk: 0.2,
            routing_manipulation: false,
            churn_rate: 0.35, // > 30%
            recent_failures: 5,
            last_updated: Instant::now(),
        };

        assert!(indicators.should_escalate_to_bft());
    }

    #[test]
    fn test_no_escalation_when_safe() {
        let indicators = AttackIndicators {
            eclipse_risk: 0.2,
            sybil_risk: 0.2,
            routing_manipulation: false,
            churn_rate: 0.1,
            recent_failures: 5,
            last_updated: Instant::now(),
        };

        assert!(!indicators.should_escalate_to_bft());
    }

    #[test]
    fn test_close_group_history_tracking() {
        let validator = CloseGroupValidator::with_defaults();
        let node_id = DhtNodeId::random();

        let initial_members: HashSet<_> = (0..5).map(|_| DhtNodeId::random()).collect();
        validator.update_close_group_history(node_id.clone(), initial_members.clone());

        // Simulate some members changing
        let mut new_members: HashSet<_> = initial_members.iter().take(3).cloned().collect();
        new_members.insert(DhtNodeId::random());
        new_members.insert(DhtNodeId::random());

        validator.update_close_group_history(node_id.clone(), new_members);

        let removed = validator.detect_removed_nodes();
        assert!(!removed.is_empty());

        let churn = validator.calculate_overall_churn_rate();
        assert!(churn > 0.0);
    }

    #[test]
    fn test_collusion_detection() {
        let validator = CloseGroupValidator::with_defaults();

        // Responses with very similar latencies (suspicious)
        let suspicious_responses: Vec<_> = (0..5)
            .map(|i| create_response(true, 0.8, Some("us-east"), 50 + i))
            .collect();

        let suspicious_refs: Vec<_> = suspicious_responses.iter().collect();
        assert!(validator.detect_collusion_indicators(&suspicious_refs));

        // Responses with varied latencies (normal)
        let normal_responses = vec![
            create_response(true, 0.8, Some("us-east"), 50),
            create_response(true, 0.8, Some("eu-west"), 150),
            create_response(true, 0.8, Some("asia"), 280),
            create_response(true, 0.8, Some("oceania"), 90),
            create_response(true, 0.8, Some("africa"), 200),
        ];

        let normal_refs: Vec<_> = normal_responses.iter().collect();
        assert!(!validator.detect_collusion_indicators(&normal_refs));
    }

    #[test]
    fn test_cache_functionality() {
        let validator = CloseGroupValidator::with_defaults();
        let node_id = DhtNodeId::random();

        let mut result = CloseGroupValidationResult::new(node_id.clone());
        result.is_valid = true;
        result.weighted_confirmation = 0.85;

        validator.cache_result(result);

        let cached = validator.get_cached_result(&node_id);
        assert!(cached.is_some());
        assert!(cached.unwrap().is_valid);
    }

    #[test]
    fn test_auto_escalation() {
        let validator = CloseGroupValidator::with_defaults();
        assert!(!validator.is_attack_mode());

        let indicators = AttackIndicators {
            eclipse_risk: 0.7,
            ..Default::default()
        };

        validator.update_attack_indicators(indicators);
        assert!(validator.is_attack_mode());
    }

    #[test]
    fn test_to_node_validation_result_conversion() {
        let validator = CloseGroupValidator::with_defaults();
        let node_id = DhtNodeId::random();

        let mut result = CloseGroupValidationResult::new(node_id);
        result.is_valid = true;
        result.confirmation_ratio = 0.8;

        let node_result = validator.to_node_validation_result(&result);
        assert!(node_result.is_valid());
    }

    #[test]
    fn test_geographic_diversity_warning() {
        let validator = CloseGroupValidator::with_defaults();
        let node_id = DhtNodeId::random();

        // All from same region
        let responses = vec![
            create_response(true, 0.9, Some("us-east"), 50),
            create_response(true, 0.8, Some("us-east"), 60),
            create_response(true, 0.7, Some("us-east"), 70),
            create_response(true, 0.6, Some("us-east"), 80),
            create_response(true, 0.5, Some("us-east"), 90),
        ];

        let result = validator.validate_membership(&node_id, &responses, Some(0.5));

        // Should still be valid in normal mode but with diversity warning
        assert!(result.is_valid);
        assert!(
            result
                .failure_reasons
                .contains(&CloseGroupFailure::InsufficientGeographicDiversity)
        );
        assert_eq!(result.confirming_regions, 1);
    }

    #[test]
    fn test_enforcement_mode_enum() {
        // Test default is Strict
        assert_eq!(
            CloseGroupEnforcementMode::default(),
            CloseGroupEnforcementMode::Strict
        );

        // Test helper methods
        assert!(CloseGroupEnforcementMode::Strict.is_strict());
        assert!(!CloseGroupEnforcementMode::Strict.is_log_only());
        assert!(!CloseGroupEnforcementMode::LogOnly.is_strict());
        assert!(CloseGroupEnforcementMode::LogOnly.is_log_only());
    }

    #[test]
    fn test_config_strict() {
        let config = CloseGroupValidatorConfig::strict();
        assert_eq!(config.enforcement_mode, CloseGroupEnforcementMode::Strict);
    }

    #[test]
    fn test_config_log_only() {
        let config = CloseGroupValidatorConfig::log_only();
        assert_eq!(config.enforcement_mode, CloseGroupEnforcementMode::LogOnly);
    }

    #[test]
    fn test_config_with_enforcement_mode() {
        let config = CloseGroupValidatorConfig::default()
            .with_enforcement_mode(CloseGroupEnforcementMode::LogOnly);
        assert_eq!(config.enforcement_mode, CloseGroupEnforcementMode::LogOnly);
    }

    #[test]
    fn test_strict_mode_rejects_unknown_nodes() {
        let config = CloseGroupValidatorConfig::strict();
        let validator = CloseGroupValidator::new(config);
        let unknown_node = DhtNodeId::random();

        // Unknown nodes should be rejected in strict mode
        assert!(!validator.validate(&unknown_node));
        assert!(validator.enforcement_mode().is_strict());
    }

    #[test]
    fn test_log_only_mode_allows_unknown_nodes() {
        let config = CloseGroupValidatorConfig::log_only();
        let validator = CloseGroupValidator::new(config);
        let unknown_node = DhtNodeId::random();

        // Unknown nodes should be allowed in log-only mode
        assert!(validator.validate(&unknown_node));
        assert!(validator.enforcement_mode().is_log_only());
    }

    #[test]
    fn test_strict_mode_respects_cached_results() {
        let config = CloseGroupValidatorConfig::strict();
        let validator = CloseGroupValidator::new(config);
        let node_id = DhtNodeId::random();

        // Cache a valid result
        let mut valid_result = CloseGroupValidationResult::new(node_id.clone());
        valid_result.is_valid = true;
        validator.cache_result(valid_result);

        // Should return true because cached result is valid
        assert!(validator.validate(&node_id));

        // Cache an invalid result for a different node
        let invalid_node = DhtNodeId::random();
        let mut invalid_result = CloseGroupValidationResult::new(invalid_node.clone());
        invalid_result.is_valid = false;
        validator.cache_result(invalid_result);

        // Should return false because cached result is invalid (strict mode)
        assert!(!validator.validate(&invalid_node));
    }

    #[test]
    fn test_log_only_mode_allows_failed_cached_results() {
        let config = CloseGroupValidatorConfig::log_only();
        let validator = CloseGroupValidator::new(config);
        let node_id = DhtNodeId::random();

        // Cache an invalid result
        let mut invalid_result = CloseGroupValidationResult::new(node_id.clone());
        invalid_result.is_valid = false;
        validator.cache_result(invalid_result);

        // Should return true because log-only mode allows failed nodes
        assert!(validator.validate(&node_id));
    }
}
