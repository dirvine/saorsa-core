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

//! Contact Entry and Quality Scoring
//!
//! Manages peer contact information with comprehensive quality metrics for
//! intelligent bootstrap peer selection.

use crate::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

// Temporary compatibility types for iroh removal
#[allow(dead_code)]
type NodeId = String; // Simplified placeholder
#[allow(dead_code)]
type RelayUrl = String; // Simplified placeholder

/// QUIC-specific contact information for direct connectivity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuicContactInfo {
    /// Direct socket addresses that can be used to reach this peer
    pub direct_addresses: Vec<SocketAddr>,
    /// Quality information about QUIC connections
    pub quic_quality: QuicQualityMetrics,
    /// Last successful QUIC connection timestamp
    pub last_quic_connection: chrono::DateTime<chrono::Utc>,
    /// Connection types that have been successful with this peer
    pub successful_connection_types: Vec<QuicConnectionType>,
}

/// Quality metrics specific to QUIC connections
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuicQualityMetrics {
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Average throughput in Mbps
    pub avg_throughput_mbps: f64,
    /// Connection success rate (0.0 to 1.0)
    pub connection_success_rate: f64,
    /// Average time to establish QUIC connection (milliseconds)
    pub avg_connection_setup_time_ms: f64,
    /// Success rate for different connection types
    pub connection_type_success_rates: HashMap<QuicConnectionType, f64>,
}

/// Types of connections that QUIC can establish
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum QuicConnectionType {
    /// Direct IPv4 connection
    DirectIPv4,
    /// Direct IPv6 connection
    DirectIPv6,
}

/// A contact entry representing a known peer
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContactEntry {
    /// Unique identifier for this peer
    pub peer_id: PeerId,
    /// List of socket addresses where this peer can be reached
    pub addresses: Vec<SocketAddr>,
    /// Timestamp when this peer was last seen online
    pub last_seen: chrono::DateTime<chrono::Utc>,
    /// Quality metrics for connection performance evaluation
    pub quality_metrics: QualityMetrics,
    /// List of capabilities supported by this peer
    pub capabilities: Vec<String>,
    /// Whether this peer's IPv6 identity has been verified
    pub ipv6_identity_verified: bool,
    /// Overall reputation score (0.0 to 1.0)
    pub reputation_score: f64,
    /// Historical connection data for this peer
    pub connection_history: ConnectionHistory,

    // QUIC-specific contact information
    /// QUIC contact data for direct connectivity
    pub quic_contact: Option<QuicContactInfo>,
}

/// Quality metrics for peer evaluation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QualityMetrics {
    /// Connection success rate (0.0 to 1.0)
    pub success_rate: f64,
    /// Average connection latency in milliseconds
    pub avg_latency_ms: f64,
    /// Computed overall quality score (0.0 to 1.0)
    pub quality_score: f64,
    /// Timestamp of the last connection attempt
    pub last_connection_attempt: chrono::DateTime<chrono::Utc>,
    /// Timestamp of the last successful connection
    pub last_successful_connection: chrono::DateTime<chrono::Utc>,
    /// Estimated uptime reliability score (0.0 to 1.0)
    pub uptime_score: f64,
}

/// Connection history tracking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConnectionHistory {
    /// Total number of connection attempts made
    pub total_attempts: u64,
    /// Number of successful connections established
    pub successful_connections: u64,
    /// Number of failed connection attempts
    pub failed_connections: u64,
    /// Total time spent in successful sessions
    pub total_session_time: Duration,
    /// Last 10 latency measurements in milliseconds
    pub recent_latencies: Vec<u64>,
    /// Failure reasons and their occurrence counts
    pub connection_failures: HashMap<String, u64>,
}

impl ContactEntry {
    /// Create a new contact entry
    pub fn new(peer_id: PeerId, addresses: Vec<SocketAddr>) -> Self {
        let now = chrono::Utc::now();

        Self {
            peer_id,
            addresses,
            last_seen: now,
            quality_metrics: QualityMetrics::new(),
            capabilities: Vec::new(),
            ipv6_identity_verified: false,
            reputation_score: 0.5, // Neutral starting score
            connection_history: ConnectionHistory::new(),
            quic_contact: None, // No QUIC contact info initially
        }
    }

    /// Create a new contact entry with QUIC information
    pub fn new_with_quic(
        peer_id: PeerId,
        addresses: Vec<SocketAddr>,
        quic_info: QuicContactInfo,
    ) -> Self {
        let now = chrono::Utc::now();

        Self {
            peer_id,
            addresses,
            last_seen: now,
            quality_metrics: QualityMetrics::new(),
            capabilities: Vec::new(),
            ipv6_identity_verified: false,
            reputation_score: 0.5, // Neutral starting score
            connection_history: ConnectionHistory::new(),
            quic_contact: Some(quic_info),
        }
    }

    /// Update quality metrics based on connection result
    pub fn update_connection_result(
        &mut self,
        success: bool,
        latency_ms: Option<u64>,
        error: Option<String>,
    ) {
        let now = chrono::Utc::now();
        self.last_seen = now;
        self.quality_metrics.last_connection_attempt = now;
        self.connection_history.total_attempts += 1;

        if success {
            self.connection_history.successful_connections += 1;
            self.quality_metrics.last_successful_connection = now;

            if let Some(latency) = latency_ms {
                self.add_latency_measurement(latency);
            }
        } else {
            self.connection_history.failed_connections += 1;

            if let Some(err) = error {
                *self
                    .connection_history
                    .connection_failures
                    .entry(err)
                    .or_insert(0) += 1;
            }
        }

        self.update_success_rate();
        self.update_latency_average();
        self.recalculate_quality_score();
    }

    /// Add a latency measurement
    fn add_latency_measurement(&mut self, latency_ms: u64) {
        self.connection_history.recent_latencies.push(latency_ms);

        // Keep only last 10 measurements
        if self.connection_history.recent_latencies.len() > 10 {
            self.connection_history.recent_latencies.remove(0);
        }
    }

    /// Update success rate
    pub fn update_success_rate(&mut self) {
        if self.connection_history.total_attempts > 0 {
            self.quality_metrics.success_rate = self.connection_history.successful_connections
                as f64
                / self.connection_history.total_attempts as f64;
        }
    }

    /// Update average latency
    fn update_latency_average(&mut self) {
        if !self.connection_history.recent_latencies.is_empty() {
            let sum: u64 = self.connection_history.recent_latencies.iter().sum();
            self.quality_metrics.avg_latency_ms =
                sum as f64 / self.connection_history.recent_latencies.len() as f64;
        }
    }

    /// Recalculate overall quality score
    pub fn recalculate_quality_score(&mut self) {
        let quality_calculator = QualityCalculator::new();
        self.quality_metrics.quality_score = quality_calculator.calculate_quality(self);
    }

    /// Update capabilities
    pub fn update_capabilities(&mut self, capabilities: Vec<String>) {
        self.capabilities = capabilities;
        self.recalculate_quality_score();
    }

    /// Update reputation score
    pub fn update_reputation(&mut self, reputation: f64) {
        self.reputation_score = reputation.clamp(0.0, 1.0);
        self.recalculate_quality_score();
    }

    /// Mark IPv6 identity as verified
    pub fn mark_ipv6_verified(&mut self) {
        self.ipv6_identity_verified = true;
        self.recalculate_quality_score();
    }

    /// Check if contact is considered stale
    pub fn is_stale(&self, max_age: Duration) -> bool {
        let now = chrono::Utc::now();
        let age = now.signed_duration_since(self.last_seen);
        age.to_std().unwrap_or(Duration::MAX) > max_age
    }

    /// Get contact age in seconds
    pub fn age_seconds(&self) -> u64 {
        let now = chrono::Utc::now();
        let age = now.signed_duration_since(self.last_seen);
        age.num_seconds().max(0) as u64
    }

    /// Check if contact has essential capabilities
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.contains(&capability.to_string())
    }

    /// Get a summary string for debugging
    pub fn summary(&self) -> String {
        let quic_info = if let Some(ref quic_contact) = self.quic_contact {
            format!(
                " QUIC: Setup:{:.0}ms",
                quic_contact.quic_quality.avg_connection_setup_time_ms
            )
        } else {
            " QUIC: None".to_string()
        };

        format!(
            "Peer {} (Quality: {:.2}, Success: {:.1}%, Latency: {:.0}ms, Verified: {}{})",
            self.peer_id.to_string().chars().take(8).collect::<String>(),
            self.quality_metrics.quality_score,
            self.quality_metrics.success_rate * 100.0,
            self.quality_metrics.avg_latency_ms,
            self.ipv6_identity_verified,
            quic_info
        )
    }

    /// Update or set QUIC contact information
    pub fn update_quic_contact(&mut self, quic_info: QuicContactInfo) {
        self.quic_contact = Some(quic_info);
        self.recalculate_quality_score(); // QUIC may affect overall quality
    }

    /// Update QUIC connection result
    pub fn update_quic_connection_result(
        &mut self,
        connection_type: QuicConnectionType,
        success: bool,
        setup_time_ms: Option<u64>,
    ) {
        if let Some(ref mut quic_contact) = self.quic_contact {
            let now = chrono::Utc::now();

            if success {
                quic_contact.last_quic_connection = now;

                // Add to successful connection types if not already present
                if !quic_contact
                    .successful_connection_types
                    .contains(&connection_type)
                {
                    quic_contact
                        .successful_connection_types
                        .push(connection_type.clone());
                }

                // Update setup time
                if let Some(setup_time) = setup_time_ms {
                    let current_avg = quic_contact.quic_quality.avg_connection_setup_time_ms;
                    quic_contact.quic_quality.avg_connection_setup_time_ms = if current_avg == 0.0 {
                        setup_time as f64
                    } else {
                        (current_avg + setup_time as f64) / 2.0 // Simple moving average
                    };
                }
            }

            // Update connection type success rates
            let current_rate = quic_contact
                .quic_quality
                .connection_type_success_rates
                .get(&connection_type)
                .copied()
                .unwrap_or(0.0);
            let new_rate = if current_rate == 0.0 {
                if success { 1.0 } else { 0.0 }
            } else {
                (current_rate + if success { 1.0 } else { 0.0 }) / 2.0
            };
            quic_contact
                .quic_quality
                .connection_type_success_rates
                .insert(connection_type.clone(), new_rate);

            self.recalculate_quality_score();
        }
    }

    /// Get QUIC direct addresses if available
    pub fn quic_direct_addresses(&self) -> Option<&Vec<SocketAddr>> {
        self.quic_contact
            .as_ref()
            .map(|contact| &contact.direct_addresses)
    }

    /// Check if peer supports specific QUIC connection type
    pub fn supports_quic_connection_type(&self, connection_type: &QuicConnectionType) -> bool {
        self.quic_contact
            .as_ref()
            .map(|contact| {
                contact
                    .successful_connection_types
                    .contains(connection_type)
            })
            .unwrap_or(false)
    }

    /// Get QUIC quality score (0.0 to 1.0)
    pub fn quic_quality_score(&self) -> f64 {
        if let Some(ref quic_contact) = self.quic_contact {
            let setup_score = if quic_contact.quic_quality.avg_connection_setup_time_ms > 0.0 {
                // Lower setup time = higher score
                (5000.0 / (quic_contact.quic_quality.avg_connection_setup_time_ms + 1000.0))
                    .min(1.0)
            } else {
                0.5 // Neutral if no data
            };
            let type_diversity_score = quic_contact.successful_connection_types.len() as f64 / 2.0; // Up to 2 types (IPv4/IPv6)
            let success_score = quic_contact.quic_quality.connection_success_rate;

            // Weighted average
            (setup_score * 0.4 + type_diversity_score * 0.3 + success_score * 0.3).clamp(0.0, 1.0)
        } else {
            0.0 // No QUIC information
        }
    }
}

impl Default for QualityMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl QualityMetrics {
    /// Create new quality metrics with default values
    pub fn new() -> Self {
        let now = chrono::Utc::now();

        Self {
            success_rate: 0.0,
            avg_latency_ms: 0.0,
            quality_score: 0.0,
            last_connection_attempt: now,
            last_successful_connection: now,
            uptime_score: 0.5, // Neutral starting score
        }
    }

    /// Apply age decay to quality metrics
    pub fn apply_age_decay(&mut self, decay_factor: f64) {
        // Decay quality score over time to favor recent connections
        self.quality_score *= decay_factor;
        self.uptime_score *= decay_factor;
    }
}

impl Default for ConnectionHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionHistory {
    /// Create new connection history
    pub fn new() -> Self {
        Self {
            total_attempts: 0,
            successful_connections: 0,
            failed_connections: 0,
            total_session_time: Duration::from_secs(0),
            recent_latencies: Vec::new(),
            connection_failures: HashMap::new(),
        }
    }

    /// Add session time
    pub fn add_session_time(&mut self, duration: Duration) {
        self.total_session_time = self.total_session_time.saturating_add(duration);
    }

    /// Get failure rate for specific error type
    pub fn get_failure_rate(&self, error_type: &str) -> f64 {
        let failures = self
            .connection_failures
            .get(error_type)
            .copied()
            .unwrap_or(0);
        if self.total_attempts > 0 {
            failures as f64 / self.total_attempts as f64
        } else {
            0.0
        }
    }
}

/// Quality calculator for computing peer scores
pub struct QualityCalculator {
    success_weight: f64,
    latency_weight: f64,
    recency_weight: f64,
    reputation_weight: f64,
    verification_bonus: f64,
    capability_bonus: f64,
}

impl QualityCalculator {
    /// Create new quality calculator with default weights
    pub fn new() -> Self {
        Self {
            success_weight: 0.40,     // 40% - Connection success rate
            latency_weight: 0.30,     // 30% - Network performance
            recency_weight: 0.20,     // 20% - How recently seen
            reputation_weight: 0.10,  // 10% - Reputation score
            verification_bonus: 0.05, // 5% bonus for verified identity
            capability_bonus: 0.02,   // 2% bonus per important capability
        }
    }

    /// Calculate overall quality score for a contact
    pub fn calculate_quality(&self, contact: &ContactEntry) -> f64 {
        let mut score = 0.0;

        // Success rate component (0.0 to 1.0)
        let success_component = contact.quality_metrics.success_rate * self.success_weight;
        score += success_component;

        // Latency component (inverse of latency, normalized)
        let latency_component = if contact.quality_metrics.avg_latency_ms > 0.0 {
            let normalized_latency =
                (1000.0 / (contact.quality_metrics.avg_latency_ms + 100.0)).min(1.0);
            normalized_latency * self.latency_weight
        } else {
            0.0
        };
        score += latency_component;

        // Recency component (exponential decay)
        let age_seconds = contact.age_seconds() as f64;
        let recency_component = (-age_seconds / 86400.0).exp() * self.recency_weight; // 24 hour half-life
        score += recency_component;

        // Reputation component
        let reputation_component = contact.reputation_score * self.reputation_weight;
        score += reputation_component;

        // IPv6 verification bonus
        if contact.ipv6_identity_verified {
            score += self.verification_bonus;
        }

        // Capability bonuses
        let important_capabilities = ["dht", "relay"];
        let capability_count = important_capabilities
            .iter()
            .filter(|&cap| contact.has_capability(cap))
            .count();
        score += capability_count as f64 * self.capability_bonus;

        // QUIC connectivity bonus
        if let Some(ref quic_contact) = contact.quic_contact {
            let quic_score = contact.quic_quality_score();
            // Give 10% bonus for having QUIC + quality-based multiplier
            let quic_bonus = 0.10 * quic_score;
            score += quic_bonus;

            // Bonus for connection type diversity (more ways to connect = better)
            let diversity_bonus =
                (quic_contact.successful_connection_types.len() as f64 / 2.0) * 0.03;
            score += diversity_bonus;
        }

        // Clamp to valid range
        score.clamp(0.0, 1.0)
    }

    /// Calculate quality with custom weights
    pub fn calculate_with_weights(
        &self,
        contact: &ContactEntry,
        success_weight: f64,
        latency_weight: f64,
        recency_weight: f64,
        reputation_weight: f64,
    ) -> f64 {
        let mut calculator = self.clone();
        calculator.success_weight = success_weight;
        calculator.latency_weight = latency_weight;
        calculator.recency_weight = recency_weight;
        calculator.reputation_weight = reputation_weight;

        calculator.calculate_quality(contact)
    }
}

impl Clone for QualityCalculator {
    fn clone(&self) -> Self {
        Self {
            success_weight: self.success_weight,
            latency_weight: self.latency_weight,
            recency_weight: self.recency_weight,
            reputation_weight: self.reputation_weight,
            verification_bonus: self.verification_bonus,
            capability_bonus: self.capability_bonus,
        }
    }
}

impl Default for QualityCalculator {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicContactInfo {
    /// Create new QUIC contact info
    pub fn new(direct_addresses: Vec<std::net::SocketAddr>) -> Self {
        let now = chrono::Utc::now();

        Self {
            direct_addresses,
            quic_quality: QuicQualityMetrics::new(),
            last_quic_connection: now,
            successful_connection_types: Vec::new(),
        }
    }

    /// Update direct addresses
    pub fn update_direct_addresses(&mut self, addresses: Vec<std::net::SocketAddr>) {
        self.direct_addresses = addresses;
    }

    /// Check if this contact has any connectivity options
    pub fn has_connectivity_options(&self) -> bool {
        !self.direct_addresses.is_empty()
    }
}

impl QuicQualityMetrics {
    /// Create new QUIC quality metrics with default values
    pub fn new() -> Self {
        Self {
            avg_response_time_ms: 0.0,
            avg_throughput_mbps: 0.0,
            connection_success_rate: 0.0,
            avg_connection_setup_time_ms: 0.0,
            connection_type_success_rates: HashMap::new(),
        }
    }

    /// Get overall QUIC connectivity score
    pub fn overall_score(&self) -> f64 {
        let speed_score = if self.avg_connection_setup_time_ms > 0.0 {
            (5000.0 / (self.avg_connection_setup_time_ms + 1000.0)).min(1.0)
        } else {
            0.5
        };
        let reliability_score = if !self.connection_type_success_rates.is_empty() {
            self.connection_type_success_rates.values().sum::<f64>()
                / self.connection_type_success_rates.len() as f64
        } else {
            0.0
        };
        let success_score = self.connection_success_rate;

        // Weighted combination
        (speed_score * 0.4 + reliability_score * 0.3 + success_score * 0.3).clamp(0.0, 1.0)
    }
}

impl Default for QuicQualityMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contact_entry_creation() {
        let peer_id = PeerId::from("test-peer");
        let addresses = vec!["127.0.0.1:9000".parse().unwrap()];

        let contact = ContactEntry::new(peer_id.clone(), addresses.clone());

        assert_eq!(contact.peer_id, peer_id);
        assert_eq!(contact.addresses, addresses);
        assert_eq!(contact.quality_metrics.success_rate, 0.0);
        assert!(!contact.ipv6_identity_verified);
    }

    #[test]
    fn test_quality_calculation() {
        let mut contact = ContactEntry::new(
            PeerId::from("test-peer"),
            vec!["127.0.0.1:9000".parse().unwrap()],
        );

        // Simulate successful connections
        contact.update_connection_result(true, Some(50), None);
        contact.update_connection_result(true, Some(60), None);
        contact.update_connection_result(false, None, Some("timeout".to_string()));

        assert!(contact.quality_metrics.success_rate > 0.5);
        assert!(contact.quality_metrics.avg_latency_ms > 0.0);
        assert!(contact.quality_metrics.quality_score > 0.0);
    }

    #[test]
    fn test_capability_bonus() {
        let mut contact = ContactEntry::new(
            PeerId::from("test-peer"),
            vec!["127.0.0.1:9000".parse().unwrap()],
        );

        let initial_score = contact.quality_metrics.quality_score;

        contact.update_capabilities(vec!["dht".to_string()]);

        assert!(contact.quality_metrics.quality_score > initial_score);
    }

    #[test]
    fn test_stale_detection() {
        let mut contact = ContactEntry::new(
            PeerId::from("test-peer"),
            vec!["127.0.0.1:9000".parse().unwrap()],
        );

        // Set last seen to 2 hours ago
        contact.last_seen = chrono::Utc::now() - chrono::Duration::hours(2);

        assert!(contact.is_stale(Duration::from_secs(3600))); // 1 hour threshold
        assert!(!contact.is_stale(Duration::from_secs(10800))); // 3 hour threshold
    }

    #[test]
    fn test_quality_decay() {
        let mut metrics = QualityMetrics::new();
        metrics.quality_score = 0.8;
        metrics.uptime_score = 0.9;

        metrics.apply_age_decay(0.9);

        assert!(metrics.quality_score < 0.8);
        assert!(metrics.uptime_score < 0.9);
    }

    #[test]
    fn test_quic_contact_creation() {
        let addresses = vec!["127.0.0.1:9000".parse().unwrap()];

        let quic_contact = QuicContactInfo::new(addresses.clone());

        assert_eq!(quic_contact.direct_addresses, addresses);
        assert!(quic_contact.has_connectivity_options());
    }

    #[test]
    fn test_contact_with_quic_info() {
        let addresses = vec!["127.0.0.1:9000".parse().unwrap()];
        let quic_info = QuicContactInfo::new(addresses);

        let contact = ContactEntry::new_with_quic(
            PeerId::from("test-peer"),
            vec!["127.0.0.1:9000".parse().unwrap()],
            quic_info,
        );

        assert!(contact.quic_contact.is_some());
        assert!(contact.quic_direct_addresses().is_some());
        assert!(has_connectivity_options(&contact));
    }

    #[test]
    fn test_quic_connection_result_update() {
        let addresses = vec!["127.0.0.1:9000".parse().unwrap()];
        let quic_info = QuicContactInfo::new(addresses);

        let mut contact = ContactEntry::new_with_quic(
            PeerId::from("test-peer"),
            vec!["127.0.0.1:9000".parse().unwrap()],
            quic_info,
        );

        // Simulate successful QUIC connection
        contact.update_quic_connection_result(
            QuicConnectionType::DirectIPv4,
            true,
            Some(250), // 250ms setup time
        );

        assert_eq!(
            contact
                .quic_contact
                .as_ref()
                .unwrap()
                .quic_quality
                .avg_connection_setup_time_ms,
            250.0
        );
        assert!(contact.supports_quic_connection_type(&QuicConnectionType::DirectIPv4));

        let quic_quality = contact.quic_quality_score();
        assert!(quic_quality > 0.0);
    }

    #[test]
    fn test_quic_quality_affects_overall_score() {
        let addresses = vec!["127.0.0.1:9000".parse().unwrap()];
        let quic_info = QuicContactInfo::new(addresses);

        // Contact without QUIC
        let mut contact_no_quic = ContactEntry::new(
            PeerId::from("test-peer-no-quic"),
            vec!["127.0.0.1:9000".parse().unwrap()],
        );
        contact_no_quic.update_connection_result(true, Some(100), None);

        // Contact with QUIC
        let mut contact_with_quic = ContactEntry::new_with_quic(
            PeerId::from("test-peer-with-quic"),
            vec!["127.0.0.1:9000".parse().unwrap()],
            quic_info,
        );
        contact_with_quic.update_connection_result(true, Some(100), None);
        contact_with_quic.update_quic_connection_result(
            QuicConnectionType::DirectIPv4,
            true,
            Some(200),
        );

        // QUIC contact should have higher quality score
        assert!(
            contact_with_quic.quality_metrics.quality_score
                > contact_no_quic.quality_metrics.quality_score
        );
    }

    fn has_connectivity_options(contact: &ContactEntry) -> bool {
        contact
            .quic_contact
            .as_ref()
            .map(|quic| !quic.direct_addresses.is_empty())
            .unwrap_or(false)
    }
}
