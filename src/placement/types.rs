// Copyright (c) 2025 Saorsa Labs Limited
//
// This file is part of the Saorsa P2P network.
//
// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

//! Core data structures for the placement system
//!
//! Defines configuration, decisions, metrics, and geographic types used
//! throughout the placement system.

use std::collections::HashMap;
// use std::net::SocketAddr; // Unused import - commented out
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::adaptive::NodeId;
use crate::placement::PlacementResult;

/// Main configuration for the placement system
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlacementConfig {
    /// Replication factor configuration
    pub replication_factor: ReplicationFactor,
    /// Timeout for placement operations
    pub placement_timeout: Duration,
    /// Byzantine fault tolerance requirements
    pub byzantine_tolerance: ByzantineTolerance,
    /// Optimization weights for different factors
    pub optimization_weights: OptimizationWeights,
}

impl PlacementConfig {
    /// Create new configuration with validation
    pub fn new(
        replication_factor: ReplicationFactor,
        placement_timeout: Duration,
        byzantine_tolerance: ByzantineTolerance,
        optimization_weights: OptimizationWeights,
    ) -> PlacementResult<Self> {
        // Validate timeout
        if placement_timeout.as_secs() == 0 {
            return Err(crate::placement::PlacementError::InvalidConfiguration {
                field: "placement_timeout".to_string(),
                reason: "Timeout must be greater than zero".to_string(),
            });
        }

        // Validate Byzantine tolerance compatibility
        if replication_factor.default_value() < byzantine_tolerance.required_nodes() as u8 {
            return Err(crate::placement::PlacementError::InvalidConfiguration {
                field: "byzantine_tolerance".to_string(),
                reason: format!(
                    "Replication factor {} insufficient for Byzantine tolerance {}",
                    replication_factor.default_value(),
                    byzantine_tolerance.required_nodes()
                ),
            });
        }

        Ok(Self {
            replication_factor,
            placement_timeout,
            byzantine_tolerance,
            optimization_weights,
        })
    }
}

impl Default for PlacementConfig {
    fn default() -> Self {
        Self {
            replication_factor: ReplicationFactor::default(),
            placement_timeout: Duration::from_secs(30),
            byzantine_tolerance: ByzantineTolerance::default(),
            optimization_weights: OptimizationWeights::default(),
        }
    }
}

/// Replication factor configuration with adaptive bounds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationFactor {
    /// Minimum replication factor
    pub min: u8,
    /// Default replication factor
    pub default: u8,
    /// Maximum replication factor
    pub max: u8,
}

impl ReplicationFactor {
    /// Create new replication factor with validation
    pub fn new(min: u8, default: u8, max: u8) -> PlacementResult<Self> {
        if min == 0 {
            return Err(crate::placement::PlacementError::InvalidReplicationFactor(
                min,
            ));
        }

        if default < min || default > max {
            return Err(crate::placement::PlacementError::InvalidConfiguration {
                field: "replication_factor".to_string(),
                reason: format!("Default {} not in range [{}, {}]", default, min, max),
            });
        }

        if min > max {
            return Err(crate::placement::PlacementError::InvalidConfiguration {
                field: "replication_factor".to_string(),
                reason: format!("Min {} greater than max {}", min, max),
            });
        }

        Ok(Self { min, default, max })
    }

    /// Get minimum value
    pub fn min_value(&self) -> u8 {
        self.min
    }

    /// Get default value
    pub fn default_value(&self) -> u8 {
        self.default
    }

    /// Get maximum value
    pub fn max_value(&self) -> u8 {
        self.max
    }

    /// Check if a value is within bounds
    pub fn is_valid(&self, value: u8) -> bool {
        value >= self.min && value <= self.max
    }
}

impl Default for ReplicationFactor {
    fn default() -> Self {
        Self {
            min: 3,
            default: 8,
            max: 16,
        }
    }
}

/// Byzantine fault tolerance configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByzantineTolerance {
    /// No Byzantine fault tolerance
    None,
    /// Tolerate f faults out of 3f+1 nodes
    Classic { f: usize },
    /// Custom threshold
    Custom {
        total_nodes: usize,
        max_faults: usize,
    },
}

impl ByzantineTolerance {
    /// Calculate required number of nodes
    pub fn required_nodes(&self) -> usize {
        match self {
            ByzantineTolerance::None => 1,
            ByzantineTolerance::Classic { f } => 3 * f + 1,
            ByzantineTolerance::Custom { total_nodes, .. } => *total_nodes,
        }
    }

    /// Calculate maximum tolerable faults
    pub fn max_faults(&self) -> usize {
        match self {
            ByzantineTolerance::None => 0,
            ByzantineTolerance::Classic { f } => *f,
            ByzantineTolerance::Custom { max_faults, .. } => *max_faults,
        }
    }

    /// Check if configuration is valid
    pub fn is_valid(&self) -> bool {
        match self {
            ByzantineTolerance::None => true,
            ByzantineTolerance::Classic { f } => *f > 0,
            ByzantineTolerance::Custom {
                total_nodes,
                max_faults,
            } => *max_faults < *total_nodes && *total_nodes >= 2 * max_faults + 1,
        }
    }
}

impl Default for ByzantineTolerance {
    fn default() -> Self {
        ByzantineTolerance::Classic { f: 1 } // Tolerate 1 fault out of 4 nodes
    }
}

/// Optimization weights for placement algorithm
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OptimizationWeights {
    /// Weight for trust scores (α)
    pub trust_weight: f64,
    /// Weight for performance metrics (β)  
    pub performance_weight: f64,
    /// Weight for capacity factors (γ)
    pub capacity_weight: f64,
    /// Weight for diversity factors
    pub diversity_weight: f64,
}

impl OptimizationWeights {
    /// Create new weights with validation
    pub fn new(
        trust_weight: f64,
        performance_weight: f64,
        capacity_weight: f64,
        diversity_weight: f64,
    ) -> PlacementResult<Self> {
        let weights = [
            trust_weight,
            performance_weight,
            capacity_weight,
            diversity_weight,
        ];

        // Check all weights are non-negative
        for (i, &weight) in weights.iter().enumerate() {
            if weight < 0.0 {
                let field_names = [
                    "trust_weight",
                    "performance_weight",
                    "capacity_weight",
                    "diversity_weight",
                ];
                return Err(crate::placement::PlacementError::InvalidConfiguration {
                    field: field_names[i].to_string(),
                    reason: "Weight must be non-negative".to_string(),
                });
            }
        }

        // Check at least one weight is positive
        if weights.iter().all(|&w| w == 0.0) {
            return Err(crate::placement::PlacementError::InvalidConfiguration {
                field: "optimization_weights".to_string(),
                reason: "At least one weight must be positive".to_string(),
            });
        }

        Ok(Self {
            trust_weight,
            performance_weight,
            capacity_weight,
            diversity_weight,
        })
    }

    /// Get normalized weights (sum to 1.0)
    pub fn normalized(&self) -> Self {
        let sum = self.trust_weight
            + self.performance_weight
            + self.capacity_weight
            + self.diversity_weight;

        if sum == 0.0 {
            return Self::default();
        }

        Self {
            trust_weight: self.trust_weight / sum,
            performance_weight: self.performance_weight / sum,
            capacity_weight: self.capacity_weight / sum,
            diversity_weight: self.diversity_weight / sum,
        }
    }
}

impl Default for OptimizationWeights {
    fn default() -> Self {
        Self {
            trust_weight: 1.0,
            performance_weight: 1.0,
            capacity_weight: 1.0,
            diversity_weight: 1.0,
        }
    }
}

/// Result of a placement decision
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlacementDecision {
    /// Selected nodes for placement
    pub selected_nodes: Vec<NodeId>,
    /// Backup nodes for failover
    pub backup_nodes: Vec<NodeId>,
    /// Strategy used for placement
    pub placement_strategy: String,
    /// Diversity score (0.0 - 1.0)
    pub diversity_score: f64,
    /// Estimated reliability (0.0 - 1.0)
    pub estimated_reliability: f64,
    /// Time taken for selection
    pub selection_time: Duration,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl PlacementDecision {
    /// Create new placement decision
    pub fn new(selected_nodes: Vec<NodeId>, placement_strategy: String) -> Self {
        Self {
            selected_nodes,
            backup_nodes: Vec::new(),
            placement_strategy,
            diversity_score: 0.0,
            estimated_reliability: 0.0,
            selection_time: Duration::ZERO,
            metadata: HashMap::new(),
        }
    }

    /// Add backup nodes
    pub fn with_backup_nodes(mut self, backup_nodes: Vec<NodeId>) -> Self {
        self.backup_nodes = backup_nodes;
        self
    }

    /// Set diversity score
    pub fn with_diversity_score(mut self, score: f64) -> Self {
        self.diversity_score = score.clamp(0.0, 1.0);
        self
    }

    /// Set estimated reliability
    pub fn with_estimated_reliability(mut self, reliability: f64) -> Self {
        self.estimated_reliability = reliability.clamp(0.0, 1.0);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Get total number of nodes (primary + backup)
    pub fn total_nodes(&self) -> usize {
        self.selected_nodes.len() + self.backup_nodes.len()
    }

    /// Check if decision meets minimum requirements
    pub fn is_valid(&self, min_nodes: usize) -> bool {
        self.selected_nodes.len() >= min_nodes && !self.selected_nodes.is_empty()
    }
}

/// Geographic location with distance calculations
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GeographicLocation {
    /// Latitude in degrees
    pub latitude: f64,
    /// Longitude in degrees
    pub longitude: f64,
}

impl GeographicLocation {
    /// Create new geographic location with validation
    pub fn new(latitude: f64, longitude: f64) -> PlacementResult<Self> {
        if !(-90.0..=90.0).contains(&latitude) {
            return Err(crate::placement::PlacementError::InvalidConfiguration {
                field: "latitude".to_string(),
                reason: format!("Latitude {} not in range [-90, 90]", latitude),
            });
        }

        if !(-180.0..=180.0).contains(&longitude) {
            return Err(crate::placement::PlacementError::InvalidConfiguration {
                field: "longitude".to_string(),
                reason: format!("Longitude {} not in range [-180, 180]", longitude),
            });
        }

        Ok(Self {
            latitude,
            longitude,
        })
    }

    /// Calculate distance to another location in kilometers using Haversine formula
    pub fn distance_km(&self, other: &GeographicLocation) -> f64 {
        const EARTH_RADIUS_KM: f64 = 6371.0;

        let lat1_rad = self.latitude.to_radians();
        let lat2_rad = other.latitude.to_radians();
        let delta_lat = (other.latitude - self.latitude).to_radians();
        let delta_lon = (other.longitude - self.longitude).to_radians();

        let a = (delta_lat / 2.0).sin().powi(2)
            + lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);

        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

        EARTH_RADIUS_KM * c
    }

    /// Check if location is within a certain distance
    pub fn within_distance(&self, other: &GeographicLocation, max_distance_km: f64) -> bool {
        self.distance_km(other) <= max_distance_km
    }
}

/// Network regions for geographic diversity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkRegion {
    /// North America
    NorthAmerica,
    /// South America
    SouthAmerica,
    /// Europe
    Europe,
    /// Asia Pacific
    AsiaPacific,
    /// Africa
    Africa,
    /// Middle East
    MiddleEast,
    /// Oceania
    Oceania,
    /// Unknown/Other
    Unknown,
}

impl NetworkRegion {
    /// Get region from geographic coordinates
    pub fn from_coordinates(location: &GeographicLocation) -> Self {
        let lat = location.latitude;
        let lon = location.longitude;

        match (lat, lon) {
            // North America
            (lat, lon) if lat >= 15.0 && lat <= 72.0 && lon >= -168.0 && lon <= -52.0 => {
                NetworkRegion::NorthAmerica
            }
            // South America
            (lat, lon) if lat >= -56.0 && lat <= 15.0 && lon >= -82.0 && lon <= -30.0 => {
                NetworkRegion::SouthAmerica
            }
            // Europe
            (lat, lon) if lat >= 35.0 && lat <= 72.0 && lon >= -10.0 && lon <= 40.0 => {
                NetworkRegion::Europe
            }
            // Asia Pacific
            (lat, lon) if lat >= -47.0 && lat <= 77.0 && lon >= 40.0 && lon <= 180.0 => {
                NetworkRegion::AsiaPacific
            }
            // Africa
            (lat, lon) if lat >= -35.0 && lat <= 37.0 && lon >= -20.0 && lon <= 52.0 => {
                NetworkRegion::Africa
            }
            // Middle East
            (lat, lon) if lat >= 12.0 && lat <= 42.0 && lon >= 26.0 && lon <= 75.0 => {
                NetworkRegion::MiddleEast
            }
            // Oceania
            (lat, lon) if lat >= -47.0 && lat <= -9.0 && lon >= 110.0 && lon <= 180.0 => {
                NetworkRegion::Oceania
            }
            _ => NetworkRegion::Unknown,
        }
    }

    /// Get typical timezone offset for the region
    pub fn timezone_offset_hours(&self) -> i8 {
        match self {
            NetworkRegion::NorthAmerica => -6, // Central Time
            NetworkRegion::SouthAmerica => -3, // Brazil Time
            NetworkRegion::Europe => 1,        // CET
            NetworkRegion::AsiaPacific => 8,   // China Time
            NetworkRegion::Africa => 2,        // CAT
            NetworkRegion::MiddleEast => 3,    // Arabia Time
            NetworkRegion::Oceania => 10,      // AEST
            NetworkRegion::Unknown => 0,       // UTC
        }
    }
}

/// Placement metrics for monitoring and optimization
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlacementMetrics {
    /// Total placement requests
    pub total_requests: u64,
    /// Successful placements
    pub successful_placements: u64,
    /// Failed placements
    pub failed_placements: u64,
    /// Average placement time
    pub average_placement_time: Duration,
    /// Average diversity score
    pub average_diversity_score: f64,
    /// Average reliability estimate
    pub average_reliability: f64,
    /// Placement requests by region
    pub requests_by_region: HashMap<NetworkRegion, u64>,
}

impl PlacementMetrics {
    /// Create new empty metrics
    pub fn new() -> Self {
        Self {
            total_requests: 0,
            successful_placements: 0,
            failed_placements: 0,
            average_placement_time: Duration::ZERO,
            average_diversity_score: 0.0,
            average_reliability: 0.0,
            requests_by_region: HashMap::new(),
        }
    }

    /// Calculate success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.successful_placements as f64 / self.total_requests as f64
        }
    }

    /// Calculate failure rate
    pub fn failure_rate(&self) -> f64 {
        1.0 - self.success_rate()
    }

    /// Record a successful placement
    pub fn record_success(&mut self, decision: &PlacementDecision, region: NetworkRegion) {
        self.total_requests += 1;
        self.successful_placements += 1;

        // Update averages
        let n = self.successful_placements as f64;
        self.average_placement_time = Duration::from_nanos(
            ((self.average_placement_time.as_nanos() as f64 * (n - 1.0)
                + decision.selection_time.as_nanos() as f64)
                / n) as u64,
        );
        self.average_diversity_score =
            (self.average_diversity_score * (n - 1.0) + decision.diversity_score) / n;
        self.average_reliability =
            (self.average_reliability * (n - 1.0) + decision.estimated_reliability) / n;

        // Update region counter
        *self.requests_by_region.entry(region).or_insert(0) += 1;
    }

    /// Record a failed placement
    pub fn record_failure(&mut self, region: NetworkRegion) {
        self.total_requests += 1;
        self.failed_placements += 1;
        *self.requests_by_region.entry(region).or_insert(0) += 1;
    }
}

impl Default for PlacementMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replication_factor_validation() {
        // Valid configuration
        let rf = ReplicationFactor::new(3, 8, 16);
        assert!(rf.is_ok());

        // Invalid: min = 0
        let rf = ReplicationFactor::new(0, 8, 16);
        assert!(rf.is_err());

        // Invalid: default < min
        let rf = ReplicationFactor::new(5, 3, 16);
        assert!(rf.is_err());

        // Invalid: min > max
        let rf = ReplicationFactor::new(10, 8, 5);
        assert!(rf.is_err());
    }

    #[test]
    fn test_byzantine_tolerance() {
        let bt = ByzantineTolerance::Classic { f: 2 };
        assert_eq!(bt.required_nodes(), 7); // 3*2+1
        assert_eq!(bt.max_faults(), 2);
        assert!(bt.is_valid());

        let bt_custom = ByzantineTolerance::Custom {
            total_nodes: 10,
            max_faults: 3,
        };
        assert_eq!(bt_custom.required_nodes(), 10);
        assert_eq!(bt_custom.max_faults(), 3);
        assert!(bt_custom.is_valid());

        // Invalid custom configuration
        let bt_invalid = ByzantineTolerance::Custom {
            total_nodes: 5,
            max_faults: 3,
        };
        assert!(!bt_invalid.is_valid());
    }

    #[test]
    fn test_optimization_weights() {
        // Valid weights
        let weights = OptimizationWeights::new(1.0, 2.0, 1.5, 0.5);
        assert!(weights.is_ok());

        // Negative weight
        let weights = OptimizationWeights::new(-1.0, 2.0, 1.5, 0.5);
        assert!(weights.is_err());

        // All zero weights
        let weights = OptimizationWeights::new(0.0, 0.0, 0.0, 0.0);
        assert!(weights.is_err());

        // Test normalization
        let weights = OptimizationWeights::new(2.0, 4.0, 2.0, 2.0).unwrap();
        let normalized = weights.normalized();
        let sum = normalized.trust_weight
            + normalized.performance_weight
            + normalized.capacity_weight
            + normalized.diversity_weight;
        assert!((sum - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_geographic_location() {
        // Valid location
        let loc = GeographicLocation::new(40.7128, -74.0060); // NYC
        assert!(loc.is_ok());

        // Invalid latitude
        let loc = GeographicLocation::new(91.0, -74.0060);
        assert!(loc.is_err());

        // Invalid longitude
        let loc = GeographicLocation::new(40.7128, 181.0);
        assert!(loc.is_err());

        // Distance calculation
        let nyc = GeographicLocation::new(40.7128, -74.0060).unwrap();
        let la = GeographicLocation::new(34.0522, -118.2437).unwrap();
        let distance = nyc.distance_km(&la);
        assert!(distance > 3900.0 && distance < 4000.0); // ~3944 km
    }

    #[test]
    fn test_network_region_from_coordinates() {
        let nyc = GeographicLocation::new(40.7128, -74.0060).unwrap();
        assert_eq!(
            NetworkRegion::from_coordinates(&nyc),
            NetworkRegion::NorthAmerica
        );

        let london = GeographicLocation::new(51.5074, -0.1278).unwrap();
        assert_eq!(
            NetworkRegion::from_coordinates(&london),
            NetworkRegion::Europe
        );

        let tokyo = GeographicLocation::new(35.6762, 139.6503).unwrap();
        assert_eq!(
            NetworkRegion::from_coordinates(&tokyo),
            NetworkRegion::AsiaPacific
        );
    }

    #[test]
    fn test_placement_decision() {
        let nodes = vec![NodeId::from([1u8; 32]), NodeId::from([2u8; 32])];

        let decision = PlacementDecision::new(nodes.clone(), "test_strategy".to_string())
            .with_diversity_score(0.8)
            .with_estimated_reliability(0.95)
            .with_metadata("key".to_string(), "value".to_string());

        assert_eq!(decision.selected_nodes, nodes);
        assert_eq!(decision.diversity_score, 0.8);
        assert_eq!(decision.estimated_reliability, 0.95);
        assert_eq!(decision.metadata.get("key"), Some(&"value".to_string()));
        assert!(decision.is_valid(2));
        assert!(!decision.is_valid(3));
    }

    #[test]
    fn test_placement_metrics() {
        let mut metrics = PlacementMetrics::new();
        assert_eq!(metrics.success_rate(), 0.0);

        let decision = PlacementDecision::new(vec![NodeId::from([1u8; 32])], "test".to_string());

        metrics.record_success(&decision, NetworkRegion::NorthAmerica);
        assert_eq!(metrics.success_rate(), 1.0);
        assert_eq!(metrics.total_requests, 1);
        assert_eq!(metrics.successful_placements, 1);

        metrics.record_failure(NetworkRegion::Europe);
        assert_eq!(metrics.success_rate(), 0.5);
        assert_eq!(metrics.failure_rate(), 0.5);
        assert_eq!(metrics.total_requests, 2);
    }
}
