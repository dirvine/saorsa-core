//! Sybil attack detection for DHT protection
//!
//! Detects potential Sybil attacks by analyzing:
//! - Temporal clustering: > 10 nodes from same /48 subnet in 1 hour
//! - ID prefix clustering: > 5 nodes with same 4-byte prefix
//! - Behavioral clustering: Nodes that always respond identically
//! - Resource asymmetry: High bandwidth claims, poor actual performance
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::dht::PeerId;

/// Configuration for Sybil detection
#[derive(Debug, Clone)]
pub struct SybilDetectorConfig {
    /// Maximum nodes from same /48 subnet within window before flagging
    pub subnet_burst_threshold: usize,
    /// Time window for subnet burst detection
    pub subnet_burst_window: Duration,
    /// Maximum nodes with same 4-byte ID prefix before flagging
    pub id_prefix_threshold: usize,
    /// Minimum behavioral similarity to flag as clustering
    pub behavioral_similarity_threshold: f64,
    /// Maximum ratio of claimed to actual performance
    pub resource_asymmetry_threshold: f64,
    /// Maximum age for tracking records
    pub max_record_age: Duration,
    /// Minimum observations before analyzing behavior
    pub min_observations: usize,
}

impl Default for SybilDetectorConfig {
    fn default() -> Self {
        Self {
            subnet_burst_threshold: 10,
            subnet_burst_window: Duration::from_secs(3600), // 1 hour
            id_prefix_threshold: 5,
            behavioral_similarity_threshold: 0.95,
            resource_asymmetry_threshold: 3.0,
            max_record_age: Duration::from_secs(3600 * 24), // 24 hours
            min_observations: 10,
        }
    }
}

/// A record of a peer joining the network
#[derive(Debug, Clone)]
pub struct JoinRecord {
    /// Peer ID
    pub peer_id: PeerId,
    /// IP address (if known)
    pub ip_addr: Option<IpAddr>,
    /// When the peer joined
    pub joined_at: Instant,
}

/// Behavior profile for a peer
#[derive(Debug, Clone, Default)]
pub struct BehaviorProfile {
    /// Recent response latencies
    pub latencies: VecDeque<Duration>,
    /// Recent response sizes
    pub response_sizes: VecDeque<usize>,
    /// Recent vote patterns (as hashes for comparison)
    pub vote_hashes: VecDeque<u64>,
    /// Claimed bandwidth (bytes/sec)
    pub claimed_bandwidth: Option<u64>,
    /// Measured bandwidth (bytes/sec)
    pub measured_bandwidth: Option<u64>,
    /// Claimed storage capacity (bytes)
    pub claimed_storage: Option<u64>,
    /// Number of observations
    pub observation_count: usize,
}

impl BehaviorProfile {
    /// Create a new behavior profile
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a response observation
    pub fn record_response(&mut self, latency: Duration, response_size: usize) {
        const MAX_HISTORY: usize = 100;

        if self.latencies.len() >= MAX_HISTORY {
            self.latencies.pop_front();
        }
        self.latencies.push_back(latency);

        if self.response_sizes.len() >= MAX_HISTORY {
            self.response_sizes.pop_front();
        }
        self.response_sizes.push_back(response_size);

        self.observation_count += 1;
    }

    /// Record a vote hash (for behavioral pattern matching)
    pub fn record_vote(&mut self, vote_hash: u64) {
        const MAX_HISTORY: usize = 100;

        if self.vote_hashes.len() >= MAX_HISTORY {
            self.vote_hashes.pop_front();
        }
        self.vote_hashes.push_back(vote_hash);
    }

    /// Set claimed resources
    pub fn set_claimed_resources(&mut self, bandwidth: u64, storage: u64) {
        self.claimed_bandwidth = Some(bandwidth);
        self.claimed_storage = Some(storage);
    }

    /// Set measured bandwidth
    pub fn set_measured_bandwidth(&mut self, bandwidth: u64) {
        self.measured_bandwidth = Some(bandwidth);
    }

    /// Calculate average latency
    #[must_use]
    pub fn average_latency(&self) -> Option<Duration> {
        if self.latencies.is_empty() {
            return None;
        }
        let sum: Duration = self.latencies.iter().sum();
        Some(sum / self.latencies.len() as u32)
    }

    /// Calculate average response size
    #[must_use]
    pub fn average_response_size(&self) -> Option<usize> {
        if self.response_sizes.is_empty() {
            return None;
        }
        Some(self.response_sizes.iter().sum::<usize>() / self.response_sizes.len())
    }

    /// Check resource asymmetry (claimed vs actual)
    #[must_use]
    pub fn resource_asymmetry(&self) -> Option<f64> {
        match (self.claimed_bandwidth, self.measured_bandwidth) {
            (Some(claimed), Some(measured)) if measured > 0 => {
                Some(claimed as f64 / measured as f64)
            }
            _ => None,
        }
    }
}

/// Types of Sybil evidence
#[derive(Debug, Clone)]
pub enum SybilEvidence {
    /// Many nodes from same subnet in short time
    SubnetBurst {
        /// The subnet prefix
        subnet_prefix: String,
        /// Peers from this subnet
        peers: Vec<PeerId>,
        /// Time window over which they joined
        window: Duration,
    },
    /// Many nodes with similar ID prefixes
    IdPrefixClustering {
        /// The common prefix (4 bytes)
        prefix: [u8; 4],
        /// Peers sharing this prefix
        peers: Vec<PeerId>,
    },
    /// Nodes with suspiciously similar behavior
    BehavioralClustering {
        /// Peers with similar behavior
        peers: Vec<PeerId>,
        /// Similarity score (0.0 - 1.0)
        similarity: f64,
        /// Pattern description
        pattern: String,
    },
    /// Node claims resources it doesn't have
    ResourceAsymmetry {
        /// The peer
        peer: PeerId,
        /// Claimed bandwidth
        claimed: u64,
        /// Measured bandwidth
        measured: u64,
        /// Asymmetry ratio
        ratio: f64,
    },
}

/// A group of suspected Sybil nodes
#[derive(Debug, Clone)]
pub struct SybilGroup {
    /// Members of the suspected Sybil group
    pub members: HashSet<PeerId>,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f64,
    /// Evidence for the Sybil grouping
    pub evidence: Vec<SybilEvidence>,
    /// When the group was detected
    pub detected_at: Instant,
}

impl SybilGroup {
    /// Create a new Sybil group
    #[must_use]
    pub fn new(members: HashSet<PeerId>, evidence: Vec<SybilEvidence>) -> Self {
        let confidence = (evidence.len() as f64 / 5.0).min(1.0);
        Self {
            members,
            confidence,
            evidence,
            detected_at: Instant::now(),
        }
    }

    /// Check if a peer is in this group
    #[must_use]
    pub fn contains(&self, peer_id: &PeerId) -> bool {
        self.members.contains(peer_id)
    }

    /// Add more evidence
    pub fn add_evidence(&mut self, evidence: SybilEvidence) {
        self.evidence.push(evidence);
        self.confidence = (self.evidence.len() as f64 / 5.0).min(1.0);
    }
}

/// Sybil attack detector
pub struct SybilDetector {
    /// Configuration
    config: SybilDetectorConfig,
    /// Recent joins by subnet (/48 for IPv6, /24 for IPv4)
    subnet_joins: HashMap<String, VecDeque<JoinRecord>>,
    /// Peers by ID prefix (first 4 bytes)
    id_prefix_map: HashMap<[u8; 4], HashSet<PeerId>>,
    /// Behavior profiles per peer
    behavior_profiles: HashMap<PeerId, BehaviorProfile>,
    /// Detected Sybil groups
    suspected_groups: Vec<SybilGroup>,
    /// All known peer IDs for tracking
    known_peers: HashSet<PeerId>,
}

impl SybilDetector {
    /// Create a new Sybil detector
    #[must_use]
    pub fn new(config: SybilDetectorConfig) -> Self {
        Self {
            config,
            subnet_joins: HashMap::new(),
            id_prefix_map: HashMap::new(),
            behavior_profiles: HashMap::new(),
            suspected_groups: Vec::new(),
            known_peers: HashSet::new(),
        }
    }

    /// Create with default configuration
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(SybilDetectorConfig::default())
    }

    /// Extract /48 subnet prefix for IPv6 or /24 for IPv4
    fn subnet_prefix(ip: &IpAddr) -> String {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
            }
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                format!("{:x}:{:x}:{:x}::/48", segments[0], segments[1], segments[2])
            }
        }
    }

    /// Extract ID prefix (first 4 bytes)
    fn id_prefix(peer_id: &PeerId) -> [u8; 4] {
        let bytes = &peer_id.0;
        [bytes[0], bytes[1], bytes[2], bytes[3]]
    }

    /// Record a peer joining the network
    pub fn record_join(&mut self, peer_id: PeerId, ip_addr: Option<IpAddr>) {
        let now = Instant::now();
        self.known_peers.insert(peer_id.clone());

        // Track subnet joins
        if let Some(ip) = &ip_addr {
            let prefix = Self::subnet_prefix(ip);
            let joins = self.subnet_joins.entry(prefix).or_default();

            // Clean old records
            while let Some(front) = joins.front() {
                if now.duration_since(front.joined_at) > self.config.subnet_burst_window {
                    joins.pop_front();
                } else {
                    break;
                }
            }

            joins.push_back(JoinRecord {
                peer_id: peer_id.clone(),
                ip_addr,
                joined_at: now,
            });
        }

        // Track ID prefix
        let prefix = Self::id_prefix(&peer_id);
        self.id_prefix_map
            .entry(prefix)
            .or_default()
            .insert(peer_id.clone());

        // Initialize behavior profile
        self.behavior_profiles.entry(peer_id).or_default();
    }

    /// Record a peer leaving the network
    pub fn record_leave(&mut self, peer_id: &PeerId) {
        self.known_peers.remove(peer_id);

        // Remove from ID prefix map
        let prefix = Self::id_prefix(peer_id);
        if let Some(peers) = self.id_prefix_map.get_mut(&prefix) {
            peers.remove(peer_id);
        }
    }

    /// Record a response observation for a peer
    pub fn record_response(&mut self, peer_id: &PeerId, latency: Duration, response_size: usize) {
        if let Some(profile) = self.behavior_profiles.get_mut(peer_id) {
            profile.record_response(latency, response_size);
        }
    }

    /// Record claimed resources for a peer
    pub fn record_claimed_resources(&mut self, peer_id: &PeerId, bandwidth: u64, storage: u64) {
        if let Some(profile) = self.behavior_profiles.get_mut(peer_id) {
            profile.set_claimed_resources(bandwidth, storage);
        }
    }

    /// Record measured bandwidth for a peer
    pub fn record_measured_bandwidth(&mut self, peer_id: &PeerId, bandwidth: u64) {
        if let Some(profile) = self.behavior_profiles.get_mut(peer_id) {
            profile.set_measured_bandwidth(bandwidth);
        }
    }

    /// Check for subnet burst attacks
    pub fn check_subnet_bursts(&self) -> Vec<SybilEvidence> {
        let mut evidence = Vec::new();

        for (subnet, joins) in &self.subnet_joins {
            if joins.len() >= self.config.subnet_burst_threshold {
                let peers: Vec<PeerId> = joins.iter().map(|j| j.peer_id.clone()).collect();

                if let (Some(first), Some(last)) = (joins.front(), joins.back()) {
                    let window = last.joined_at.duration_since(first.joined_at);
                    evidence.push(SybilEvidence::SubnetBurst {
                        subnet_prefix: subnet.clone(),
                        peers,
                        window,
                    });
                }
            }
        }

        evidence
    }

    /// Check for ID prefix clustering
    pub fn check_id_prefix_clustering(&self) -> Vec<SybilEvidence> {
        let mut evidence = Vec::new();

        for (prefix, peers) in &self.id_prefix_map {
            if peers.len() >= self.config.id_prefix_threshold {
                evidence.push(SybilEvidence::IdPrefixClustering {
                    prefix: *prefix,
                    peers: peers.iter().cloned().collect(),
                });
            }
        }

        evidence
    }

    /// Check for behavioral clustering (nodes with similar response patterns)
    pub fn check_behavioral_clustering(&self) -> Vec<SybilEvidence> {
        let mut evidence = Vec::new();
        let peers: Vec<_> = self.behavior_profiles.keys().cloned().collect();

        for i in 0..peers.len() {
            for j in (i + 1)..peers.len() {
                let peer_a = &peers[i];
                let peer_b = &peers[j];

                if let Some(similarity) = self
                    .calculate_behavioral_similarity(peer_a, peer_b)
                    .filter(|&s| s >= self.config.behavioral_similarity_threshold)
                {
                    evidence.push(SybilEvidence::BehavioralClustering {
                        peers: vec![peer_a.clone(), peer_b.clone()],
                        similarity,
                        pattern: "Response pattern similarity".to_string(),
                    });
                }
            }
        }

        evidence
    }

    /// Calculate behavioral similarity between two peers
    fn calculate_behavioral_similarity(&self, peer_a: &PeerId, peer_b: &PeerId) -> Option<f64> {
        let profile_a = self.behavior_profiles.get(peer_a)?;
        let profile_b = self.behavior_profiles.get(peer_b)?;

        // Need minimum observations
        if profile_a.observation_count < self.config.min_observations
            || profile_b.observation_count < self.config.min_observations
        {
            return None;
        }

        let mut similarity_scores = Vec::new();

        // Compare average latencies
        if let (Some(lat_a), Some(lat_b)) = (profile_a.average_latency(), profile_b.average_latency())
        {
            let lat_sim = 1.0
                - (lat_a.as_micros() as f64 - lat_b.as_micros() as f64).abs()
                    / lat_a.as_micros().max(lat_b.as_micros()) as f64;
            similarity_scores.push(lat_sim.max(0.0));
        }

        // Compare average response sizes
        if let (Some(size_a), Some(size_b)) = (
            profile_a.average_response_size(),
            profile_b.average_response_size(),
        ) {
            let size_sim = 1.0
                - (size_a as f64 - size_b as f64).abs() / size_a.max(size_b) as f64;
            similarity_scores.push(size_sim.max(0.0));
        }

        // Compare vote patterns
        if !profile_a.vote_hashes.is_empty() && !profile_b.vote_hashes.is_empty() {
            let matching: usize = profile_a
                .vote_hashes
                .iter()
                .zip(profile_b.vote_hashes.iter())
                .filter(|(a, b)| a == b)
                .count();
            let total = profile_a.vote_hashes.len().min(profile_b.vote_hashes.len());
            if total > 0 {
                similarity_scores.push(matching as f64 / total as f64);
            }
        }

        if similarity_scores.is_empty() {
            return None;
        }

        Some(similarity_scores.iter().sum::<f64>() / similarity_scores.len() as f64)
    }

    /// Check for resource asymmetry
    pub fn check_resource_asymmetry(&self) -> Vec<SybilEvidence> {
        let mut evidence = Vec::new();

        for (peer_id, profile) in &self.behavior_profiles {
            if let Some(ratio) = profile
                .resource_asymmetry()
                .filter(|&r| r > self.config.resource_asymmetry_threshold)
            {
                evidence.push(SybilEvidence::ResourceAsymmetry {
                    peer: peer_id.clone(),
                    claimed: profile.claimed_bandwidth.unwrap_or(0),
                    measured: profile.measured_bandwidth.unwrap_or(0),
                    ratio,
                });
            }
        }

        evidence
    }

    /// Run full Sybil analysis
    pub fn run_analysis(&mut self) {
        let mut all_evidence = Vec::new();

        all_evidence.extend(self.check_subnet_bursts());
        all_evidence.extend(self.check_id_prefix_clustering());
        all_evidence.extend(self.check_behavioral_clustering());
        all_evidence.extend(self.check_resource_asymmetry());

        // Group evidence into Sybil groups
        self.update_sybil_groups(&all_evidence);
    }

    /// Update Sybil groups based on new evidence
    fn update_sybil_groups(&mut self, evidence: &[SybilEvidence]) {
        for ev in evidence {
            let involved_peers: HashSet<PeerId> = match ev {
                SybilEvidence::SubnetBurst { peers, .. } => peers.iter().cloned().collect(),
                SybilEvidence::IdPrefixClustering { peers, .. } => peers.iter().cloned().collect(),
                SybilEvidence::BehavioralClustering { peers, .. } => peers.iter().cloned().collect(),
                SybilEvidence::ResourceAsymmetry { peer, .. } => {
                    [peer.clone()].into_iter().collect()
                }
            };

            // Find existing group that overlaps
            let mut found_group = false;
            for group in &mut self.suspected_groups {
                if group.members.intersection(&involved_peers).count() > 0 {
                    group.members.extend(involved_peers.iter().cloned());
                    group.add_evidence(ev.clone());
                    found_group = true;
                    break;
                }
            }

            // Create new group if no overlap found
            if !found_group && involved_peers.len() >= 2 {
                let group = SybilGroup::new(involved_peers, vec![ev.clone()]);
                self.suspected_groups.push(group);
            }
        }

        // Prune old groups
        self.suspected_groups.retain(|g| {
            g.confidence >= 0.1 && g.detected_at.elapsed() < Duration::from_secs(3600 * 24)
        });
    }

    /// Get suspected Sybil groups
    #[must_use]
    pub fn get_suspected_groups(&self) -> &[SybilGroup] {
        &self.suspected_groups
    }

    /// Check if a peer is suspected of being a Sybil
    #[must_use]
    pub fn is_peer_suspected(&self, peer_id: &PeerId) -> bool {
        self.suspected_groups.iter().any(|g| g.contains(peer_id))
    }

    /// Get Sybil risk score for a peer (0.0 - 1.0)
    #[must_use]
    pub fn sybil_risk_score(&self, peer_id: &PeerId) -> f64 {
        self.suspected_groups
            .iter()
            .filter(|g| g.contains(peer_id))
            .map(|g| g.confidence)
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or(0.0)
    }

    /// Get overall Sybil risk score (0.0 - 1.0)
    #[must_use]
    pub fn overall_risk_score(&self) -> f64 {
        if self.known_peers.is_empty() {
            return 0.0;
        }

        let suspected_count: usize = self.suspected_groups.iter().map(|g| g.members.len()).sum();

        (suspected_count as f64 / self.known_peers.len() as f64).min(1.0)
    }

    /// Get the number of detected Sybil groups
    #[must_use]
    pub fn group_count(&self) -> usize {
        self.suspected_groups.len()
    }

    /// Clear all detected groups
    pub fn clear_groups(&mut self) {
        self.suspected_groups.clear();
    }

    /// Clean up old records
    pub fn cleanup_old_records(&mut self) {
        let cutoff = Instant::now() - self.config.max_record_age;

        // Clean subnet joins
        for joins in self.subnet_joins.values_mut() {
            joins.retain(|j| j.joined_at > cutoff);
        }

        // Remove empty subnet entries
        self.subnet_joins.retain(|_, v| !v.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn random_peer_id() -> PeerId {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill(&mut bytes);
        crate::identity::node_identity::NodeId::from_bytes(bytes)
    }

    fn peer_with_prefix(prefix: [u8; 4]) -> PeerId {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill(&mut bytes);
        bytes[0] = prefix[0];
        bytes[1] = prefix[1];
        bytes[2] = prefix[2];
        bytes[3] = prefix[3];
        crate::identity::node_identity::NodeId::from_bytes(bytes)
    }

    #[test]
    fn test_behavior_profile_response() {
        let mut profile = BehaviorProfile::new();

        profile.record_response(Duration::from_millis(50), 1024);
        profile.record_response(Duration::from_millis(60), 2048);

        assert_eq!(profile.observation_count, 2);
        assert!(profile.average_latency().is_some());
        assert_eq!(profile.average_response_size(), Some(1536));
    }

    #[test]
    fn test_behavior_profile_resource_asymmetry() {
        let mut profile = BehaviorProfile::new();

        profile.set_claimed_resources(100_000_000, 1_000_000_000);
        profile.set_measured_bandwidth(10_000_000);

        let asymmetry = profile.resource_asymmetry();
        assert!(asymmetry.is_some());
        assert!((asymmetry.unwrap() - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_subnet_prefix_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let prefix = SybilDetector::subnet_prefix(&ip);
        assert_eq!(prefix, "192.168.1.0/24");
    }

    #[test]
    fn test_subnet_prefix_ipv6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0, 0, 0, 0, 1));
        let prefix = SybilDetector::subnet_prefix(&ip);
        assert_eq!(prefix, "2001:db8:85a3::/48");
    }

    #[test]
    fn test_record_join() {
        let mut detector = SybilDetector::with_defaults();
        let peer = random_peer_id();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        detector.record_join(peer.clone(), Some(ip));

        assert!(detector.known_peers.contains(&peer));
        assert!(detector.behavior_profiles.contains_key(&peer));
    }

    #[test]
    fn test_subnet_burst_detection() {
        let mut detector = SybilDetector::new(SybilDetectorConfig {
            subnet_burst_threshold: 3,
            ..Default::default()
        });

        // Add multiple peers from same subnet
        for i in 0..5 {
            let peer = random_peer_id();
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100 + i));
            detector.record_join(peer, Some(ip));
        }

        let evidence = detector.check_subnet_bursts();
        assert!(!evidence.is_empty());

        if let SybilEvidence::SubnetBurst { peers, .. } = &evidence[0] {
            assert!(peers.len() >= 3);
        }
    }

    #[test]
    fn test_id_prefix_clustering() {
        let mut detector = SybilDetector::new(SybilDetectorConfig {
            id_prefix_threshold: 3,
            ..Default::default()
        });

        let prefix = [0xAB, 0xCD, 0xEF, 0x12];

        // Add multiple peers with same prefix
        for _ in 0..5 {
            let peer = peer_with_prefix(prefix);
            detector.record_join(peer, None);
        }

        let evidence = detector.check_id_prefix_clustering();
        assert!(!evidence.is_empty());

        if let SybilEvidence::IdPrefixClustering {
            prefix: found_prefix,
            peers,
        } = &evidence[0]
        {
            assert_eq!(*found_prefix, prefix);
            assert!(peers.len() >= 3);
        }
    }

    #[test]
    fn test_resource_asymmetry_detection() {
        let mut detector = SybilDetector::new(SybilDetectorConfig {
            resource_asymmetry_threshold: 2.0,
            ..Default::default()
        });

        let peer = random_peer_id();
        detector.record_join(peer.clone(), None);

        detector.record_claimed_resources(&peer, 1_000_000_000, 1_000_000_000_000);
        detector.record_measured_bandwidth(&peer, 100_000_000);

        let evidence = detector.check_resource_asymmetry();
        assert!(!evidence.is_empty());

        if let SybilEvidence::ResourceAsymmetry { ratio, .. } = &evidence[0] {
            assert!(*ratio >= 2.0);
        }
    }

    #[test]
    fn test_sybil_group_creation() {
        let peer_a = random_peer_id();
        let peer_b = random_peer_id();
        let members: HashSet<_> = [peer_a.clone(), peer_b.clone()].into_iter().collect();

        let evidence = vec![SybilEvidence::IdPrefixClustering {
            prefix: [0xAB, 0xCD, 0xEF, 0x12],
            peers: vec![peer_a.clone(), peer_b.clone()],
        }];

        let group = SybilGroup::new(members, evidence);

        assert!(group.contains(&peer_a));
        assert!(group.contains(&peer_b));
        assert!(group.confidence > 0.0);
    }

    #[test]
    fn test_peer_suspected_check() {
        let mut detector = SybilDetector::with_defaults();
        let peer_a = random_peer_id();
        let peer_b = random_peer_id();
        let peer_c = random_peer_id();

        // Create a suspected group
        let members: HashSet<_> = [peer_a.clone(), peer_b.clone()].into_iter().collect();
        let group = SybilGroup::new(
            members,
            vec![SybilEvidence::IdPrefixClustering {
                prefix: [0xAB, 0xCD, 0xEF, 0x12],
                peers: vec![peer_a.clone(), peer_b.clone()],
            }],
        );
        detector.suspected_groups.push(group);

        assert!(detector.is_peer_suspected(&peer_a));
        assert!(detector.is_peer_suspected(&peer_b));
        assert!(!detector.is_peer_suspected(&peer_c));
    }

    #[test]
    fn test_sybil_risk_score() {
        let mut detector = SybilDetector::with_defaults();
        let peer = random_peer_id();
        let other = random_peer_id();

        let members: HashSet<_> = [peer.clone(), other].into_iter().collect();
        let mut group = SybilGroup::new(members, vec![]);
        group.confidence = 0.8;
        detector.suspected_groups.push(group);

        let risk = detector.sybil_risk_score(&peer);
        assert!((risk - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_run_analysis() {
        let mut detector = SybilDetector::new(SybilDetectorConfig {
            subnet_burst_threshold: 3,
            id_prefix_threshold: 3,
            ..Default::default()
        });

        // Add enough peers for detection
        let prefix = [0xAB, 0xCD, 0xEF, 0x12];
        for i in 0..5 {
            let peer = peer_with_prefix(prefix);
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100 + i));
            detector.record_join(peer, Some(ip));
        }

        detector.run_analysis();

        // Should detect ID prefix clustering
        assert!(!detector.get_suspected_groups().is_empty());
    }

    #[test]
    fn test_overall_risk_score() {
        let mut detector = SybilDetector::with_defaults();

        // Add some normal peers
        for _ in 0..10 {
            detector.record_join(random_peer_id(), None);
        }

        // Initially no Sybil groups
        assert!((detector.overall_risk_score() - 0.0).abs() < f64::EPSILON);

        // Add a Sybil group with 2 members
        let peer_a = random_peer_id();
        let peer_b = random_peer_id();
        detector.known_peers.insert(peer_a.clone());
        detector.known_peers.insert(peer_b.clone());

        let members: HashSet<_> = [peer_a, peer_b].into_iter().collect();
        let group = SybilGroup::new(members, vec![]);
        detector.suspected_groups.push(group);

        // Risk should now be > 0
        assert!(detector.overall_risk_score() > 0.0);
    }

    #[test]
    fn test_record_leave() {
        let mut detector = SybilDetector::with_defaults();
        let peer = random_peer_id();

        detector.record_join(peer.clone(), None);
        assert!(detector.known_peers.contains(&peer));

        detector.record_leave(&peer);
        assert!(!detector.known_peers.contains(&peer));
    }
}
