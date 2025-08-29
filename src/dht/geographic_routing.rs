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

//! Geographic-Aware DHT Routing Core Components
//!
//! Provides region-based routing optimization for improved P2P network performance
//! across different geographic areas with latency and reliability considerations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

/// Geographic regions for DHT routing optimization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GeographicRegion {
    NorthAmerica,
    Europe,
    AsiaPacific,
    SouthAmerica,
    Africa,
    Oceania,
    Unknown,
}

impl GeographicRegion {
    /// Determine geographic region from IP address
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ipv4) => {
                // Basic IP range mapping for major regions
                let octets = ipv4.octets();
                match octets[0] {
                    // North America (simplified ranges)
                    1..=99 => GeographicRegion::NorthAmerica,
                    100..=126 => GeographicRegion::NorthAmerica,
                    // Europe (including DigitalOcean European infrastructure)
                    127..=159 => GeographicRegion::Europe,
                    // Asia Pacific
                    160..=191 => GeographicRegion::AsiaPacific,
                    // More North America
                    192..=223 => GeographicRegion::NorthAmerica,
                    // Rest mapped to regions
                    224..=239 => GeographicRegion::SouthAmerica,
                    240..=247 => GeographicRegion::Africa,
                    248..=251 => GeographicRegion::Oceania,
                    _ => GeographicRegion::Unknown,
                }
            }
            IpAddr::V6(_) => {
                // IPv6 region detection would be more complex
                // For now, default to Unknown and rely on explicit configuration
                GeographicRegion::Unknown
            }
        }
    }

    /// Get region preference score for cross-region routing
    pub fn preference_score(&self, other: &GeographicRegion) -> f64 {
        if self == other {
            1.0 // Same region = highest preference
        } else {
            match (self, other) {
                // Adjacent regions get higher scores
                (GeographicRegion::Europe, GeographicRegion::Africa) => 0.8,
                (GeographicRegion::Africa, GeographicRegion::Europe) => 0.8,
                (GeographicRegion::NorthAmerica, GeographicRegion::SouthAmerica) => 0.7,
                (GeographicRegion::SouthAmerica, GeographicRegion::NorthAmerica) => 0.7,
                (GeographicRegion::Europe, GeographicRegion::AsiaPacific) => 0.6,
                (GeographicRegion::AsiaPacific, GeographicRegion::Europe) => 0.6,
                (GeographicRegion::AsiaPacific, GeographicRegion::Oceania) => 0.9,
                (GeographicRegion::Oceania, GeographicRegion::AsiaPacific) => 0.9,
                // Default cross-region score
                _ => 0.5,
            }
        }
    }

    /// Get expected latency range for this region
    pub fn expected_latency_range(&self) -> (Duration, Duration) {
        match self {
            GeographicRegion::NorthAmerica => {
                (Duration::from_millis(20), Duration::from_millis(100))
            }
            GeographicRegion::Europe => (Duration::from_millis(15), Duration::from_millis(80)),
            GeographicRegion::AsiaPacific => {
                (Duration::from_millis(25), Duration::from_millis(150))
            }
            GeographicRegion::SouthAmerica => {
                (Duration::from_millis(30), Duration::from_millis(120))
            }
            GeographicRegion::Africa => (Duration::from_millis(40), Duration::from_millis(200)),
            GeographicRegion::Oceania => (Duration::from_millis(35), Duration::from_millis(180)),
            GeographicRegion::Unknown => (Duration::from_millis(50), Duration::from_millis(500)),
        }
    }

    /// Get all regions for iteration
    pub fn all_regions() -> Vec<GeographicRegion> {
        vec![
            GeographicRegion::NorthAmerica,
            GeographicRegion::Europe,
            GeographicRegion::AsiaPacific,
            GeographicRegion::SouthAmerica,
            GeographicRegion::Africa,
            GeographicRegion::Oceania,
            GeographicRegion::Unknown,
        ]
    }
}

/// Peer quality metrics for geographic routing decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerQualityMetrics {
    /// Round trip time measurements
    pub rtt_history: Vec<Duration>,
    /// Success rate for requests (0.0 - 1.0)
    pub success_rate: f64,
    /// Last measurement timestamp
    pub last_measured: SystemTime,
    /// Total requests made
    pub total_requests: u64,
    /// Successful requests
    pub successful_requests: u64,
    /// Geographic region of the peer
    pub region: GeographicRegion,
    /// Reliability score (0.0 - 1.0)
    pub reliability_score: f64,
}

impl Default for PeerQualityMetrics {
    fn default() -> Self {
        Self {
            rtt_history: Vec::new(),
            success_rate: 0.0,
            last_measured: SystemTime::now(),
            total_requests: 0,
            successful_requests: 0,
            region: GeographicRegion::Unknown,
            reliability_score: 0.5,
        }
    }
}

impl PeerQualityMetrics {
    /// Create new metrics for a peer in a specific region
    pub fn new(region: GeographicRegion) -> Self {
        Self {
            region,
            ..Default::default()
        }
    }

    /// Record a new RTT measurement
    pub fn record_rtt(&mut self, rtt: Duration) {
        self.rtt_history.push(rtt);

        // Keep only last 10 measurements for efficiency
        if self.rtt_history.len() > 10 {
            self.rtt_history.remove(0);
        }

        self.last_measured = SystemTime::now();
        self.update_reliability_score();
    }

    /// Record a request result (success or failure)
    pub fn record_request(&mut self, success: bool) {
        self.total_requests += 1;
        if success {
            self.successful_requests += 1;
        }

        self.success_rate = self.successful_requests as f64 / self.total_requests as f64;
        self.last_measured = SystemTime::now();
        self.update_reliability_score();
    }

    /// Get average RTT
    pub fn average_rtt(&self) -> Option<Duration> {
        if self.rtt_history.is_empty() {
            None
        } else {
            let total: Duration = self.rtt_history.iter().sum();
            Some(total / self.rtt_history.len() as u32)
        }
    }

    /// Get current reliability score (combines RTT and success rate)
    pub fn get_reliability_score(&self) -> f64 {
        self.reliability_score
    }

    /// Update the reliability score based on current metrics
    fn update_reliability_score(&mut self) {
        let mut score = 0.5; // Base score

        // Factor in success rate (40% weight)
        score += (self.success_rate - 0.5) * 0.4;

        // Factor in RTT performance (30% weight)
        if let Some(avg_rtt) = self.average_rtt() {
            let (min_expected, max_expected) = self.region.expected_latency_range();
            let rtt_score = if avg_rtt <= min_expected {
                1.0 // Excellent RTT
            } else if avg_rtt >= max_expected {
                0.0 // Poor RTT
            } else {
                // Linear interpolation between min and max
                let range = max_expected.as_millis() - min_expected.as_millis();
                let position = avg_rtt.as_millis() - min_expected.as_millis();
                1.0 - (position as f64 / range as f64)
            };
            score += (rtt_score - 0.5) * 0.3;
        }

        // Factor in measurement freshness (30% weight)
        let age = self
            .last_measured
            .elapsed()
            .unwrap_or(Duration::from_secs(0));
        let freshness_score = if age < Duration::from_secs(60) {
            1.0 // Fresh measurements
        } else if age > Duration::from_secs(600) {
            0.0 // Stale measurements
        } else {
            // Decay over 10 minutes
            1.0 - (age.as_secs() as f64 / 600.0)
        };
        score += (freshness_score - 0.5) * 0.3;

        // Clamp to valid range
        self.reliability_score = score.clamp(0.0, 1.0);
    }

    /// Check if metrics are stale and need refresh
    pub fn needs_refresh(&self, max_age: Duration) -> bool {
        self.last_measured
            .elapsed()
            .unwrap_or(Duration::from_secs(0))
            > max_age
    }

    /// Reset metrics (for testing or peer reconnection)
    pub fn reset(&mut self) {
        self.rtt_history.clear();
        self.success_rate = 0.0;
        self.total_requests = 0;
        self.successful_requests = 0;
        self.reliability_score = 0.5;
        self.last_measured = SystemTime::now();
    }
}

/// Regional bucket for storing peers from a specific geographic region
#[derive(Debug, Clone)]
pub struct RegionalBucket {
    /// The region this bucket represents
    pub region: GeographicRegion,
    /// Peers in this region with their quality metrics
    pub peers: HashMap<String, PeerQualityMetrics>,
    /// Maximum peers per bucket
    pub max_peers: usize,
    /// Last maintenance timestamp
    pub last_maintenance: Instant,
}

impl RegionalBucket {
    /// Create a new regional bucket
    pub fn new(region: GeographicRegion, max_peers: usize) -> Self {
        Self {
            region,
            peers: HashMap::new(),
            max_peers,
            last_maintenance: Instant::now(),
        }
    }

    /// Add or update a peer in this bucket
    pub fn add_peer(&mut self, peer_id: String, mut metrics: PeerQualityMetrics) -> bool {
        // Ensure the metrics region matches this bucket
        metrics.region = self.region;

        if self.peers.contains_key(&peer_id) {
            // Update existing peer
            self.peers.insert(peer_id, metrics);
            true
        } else if self.peers.len() < self.max_peers {
            // Add new peer if there's space
            self.peers.insert(peer_id, metrics);
            true
        } else {
            // Bucket is full, check if we should replace a peer
            self.try_replace_peer(peer_id, metrics)
        }
    }

    /// Try to replace a poor-performing peer with a new one
    fn try_replace_peer(&mut self, new_peer_id: String, new_metrics: PeerQualityMetrics) -> bool {
        // Find the peer with the lowest reliability score
        let worst_peer = self
            .peers
            .iter()
            .min_by(|(_, a), (_, b)| {
                a.get_reliability_score()
                    .partial_cmp(&b.get_reliability_score())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(id, metrics)| (id.clone(), metrics.get_reliability_score()));

        if let Some((worst_peer_id, worst_score)) = worst_peer {
            if new_metrics.get_reliability_score() > worst_score {
                self.peers.remove(&worst_peer_id);
                self.peers.insert(new_peer_id, new_metrics);
                return true;
            }
        }

        false
    }

    /// Remove a peer from this bucket
    pub fn remove_peer(&mut self, peer_id: &str) -> bool {
        self.peers.remove(peer_id).is_some()
    }

    /// Get the best peers from this bucket
    pub fn get_best_peers(&self, count: usize) -> Vec<(String, PeerQualityMetrics)> {
        let mut peer_list: Vec<_> = self
            .peers
            .iter()
            .map(|(id, metrics)| (id.clone(), metrics.clone()))
            .collect();

        // Sort by reliability score (descending)
        peer_list.sort_by(|(_, a), (_, b)| {
            b.get_reliability_score()
                .partial_cmp(&a.get_reliability_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        peer_list.into_iter().take(count).collect()
    }

    /// Perform maintenance on this bucket
    pub fn maintenance(&mut self, max_peer_age: Duration) {
        // Remove stale peers
        let stale_peers: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, metrics)| metrics.needs_refresh(max_peer_age))
            .map(|(id, _)| id.clone())
            .collect();

        for peer_id in stale_peers {
            self.peers.remove(&peer_id);
        }

        self.last_maintenance = Instant::now();
    }

    /// Get statistics for this bucket
    pub fn stats(&self) -> RegionalBucketStats {
        let peer_count = self.peers.len();
        let avg_reliability = if peer_count > 0 {
            self.peers
                .values()
                .map(|m| m.get_reliability_score())
                .sum::<f64>()
                / peer_count as f64
        } else {
            0.0
        };

        let avg_rtt = if peer_count > 0 {
            let total_rtt: Duration = self.peers.values().filter_map(|m| m.average_rtt()).sum();
            Some(total_rtt / peer_count as u32)
        } else {
            None
        };

        RegionalBucketStats {
            region: self.region,
            peer_count,
            avg_reliability,
            avg_rtt,
            last_maintenance: SystemTime::now() - self.last_maintenance.elapsed(),
        }
    }
}

/// Statistics for a regional bucket
#[derive(Debug, Clone)]
pub struct RegionalBucketStats {
    pub region: GeographicRegion,
    pub peer_count: usize,
    pub avg_reliability: f64,
    pub avg_rtt: Option<Duration>,
    pub last_maintenance: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_geographic_region_from_ip() {
        // Test DigitalOcean IP (159.89.81.21)
        let digitalocean_ip = IpAddr::V4(Ipv4Addr::new(159, 89, 81, 21));
        assert_eq!(
            GeographicRegion::from_ip(digitalocean_ip),
            GeographicRegion::Europe
        );

        // Test other regions
        let na_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(
            GeographicRegion::from_ip(na_ip),
            GeographicRegion::NorthAmerica
        );
    }

    #[test]
    fn test_peer_quality_metrics() {
        let mut metrics = PeerQualityMetrics::new(GeographicRegion::Europe);

        // Record some measurements
        metrics.record_rtt(Duration::from_millis(50));
        metrics.record_request(true);

        assert!(metrics.get_reliability_score() > 0.5);
        assert_eq!(metrics.average_rtt(), Some(Duration::from_millis(50)));
        assert_eq!(metrics.success_rate, 1.0);
    }

    #[test]
    fn test_regional_bucket() {
        let mut bucket = RegionalBucket::new(GeographicRegion::Europe, 3);

        let metrics1 = PeerQualityMetrics::new(GeographicRegion::Europe);
        let metrics2 = PeerQualityMetrics::new(GeographicRegion::Europe);

        assert!(bucket.add_peer("peer1".to_string(), metrics1));
        assert!(bucket.add_peer("peer2".to_string(), metrics2));
        assert_eq!(bucket.peers.len(), 2);

        let best_peers = bucket.get_best_peers(1);
        assert_eq!(best_peers.len(), 1);
    }
}
