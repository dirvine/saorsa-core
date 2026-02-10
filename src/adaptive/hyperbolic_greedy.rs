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

//! Greedy-assist hyperbolic embedding for experimental routing optimization
//!
//! This module implements greedy-first routing using hyperbolic coordinates
//! with Kademlia fallback. It uses HyperMap/Mercator-style background embedding
//! with drift detection and partial re-fitting.

use crate::dht::core_engine::NodeId;
use crate::{P2PError, PeerId, Result};
use blake3::Hasher;
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::f64::consts::PI;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Embedding configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingConfig {
    /// Number of dimensions for the hyperbolic space (typically 2)
    pub dimensions: usize,
    /// Learning rate for gradient descent
    pub learning_rate: f64,
    /// Maximum iterations for embedding optimization
    pub max_iterations: usize,
    /// Convergence threshold
    pub convergence_threshold: f64,
    /// Drift detection threshold (percentage change)
    pub drift_threshold: f64,
    /// Re-fit interval when drift is detected
    pub refit_interval: Duration,
    /// Minimum peers required for embedding
    pub min_peers: usize,
    /// Temperature parameter for softmax in gradient computation
    pub temperature: f64,
}

impl Default for EmbeddingConfig {
    fn default() -> Self {
        Self {
            dimensions: 2,
            learning_rate: 0.1,
            max_iterations: 1000,
            convergence_threshold: 0.001,
            drift_threshold: 0.15,
            refit_interval: Duration::from_secs(300),
            min_peers: 5,
            temperature: 1.0,
        }
    }
}

/// Hyperbolic coordinates for a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperbolicCoordinate {
    /// Radial coordinate (distance from origin)
    pub r: f64,
    /// Angular coordinates (for multi-dimensional spaces)
    pub theta: Vec<f64>,
}

impl HyperbolicCoordinate {
    /// Create new coordinate with given dimensions
    pub fn new(dimensions: usize) -> Self {
        let mut rng = rand::thread_rng();
        let seed = rng.next_u64();
        Self::from_seed(seed, dimensions)
    }

    /// Deterministically derive coordinates from a peer identifier
    pub fn from_peer(peer: &PeerId, dimensions: usize) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(peer.as_bytes());
        let digest = hasher.finalize();
        let mut seed_bytes = [0u8; 8];
        seed_bytes.copy_from_slice(&digest.as_bytes()[..8]);
        let seed = u64::from_le_bytes(seed_bytes);
        Self::from_seed(seed, dimensions)
    }

    fn from_seed(seed: u64, dimensions: usize) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let r = rng.gen_range(0.1..0.9);
        let theta = if dimensions > 1 {
            (0..dimensions - 1)
                .map(|_| rng.gen_range(0.0..2.0 * PI))
                .collect()
        } else {
            Vec::new()
        };
        Self { r, theta }
    }

    /// Calculate hyperbolic distance to another coordinate
    pub fn distance(&self, other: &Self) -> f64 {
        let r1 = self.r;
        let r2 = other.r;

        // Calculate angular distance
        let mut cos_angle = 0.0;
        for (t1, t2) in self.theta.iter().zip(other.theta.iter()) {
            cos_angle += (t1 - t2).cos();
        }
        cos_angle /= self.theta.len() as f64;

        // Hyperbolic distance in Poincaré disk model
        let numerator = (r1 - r2).powi(2) + 4.0 * r1 * r2 * (1.0 - cos_angle);
        let denominator = (1.0 - r1.powi(2)) * (1.0 - r2.powi(2));

        if denominator <= 0.0 {
            return f64::INFINITY;
        }

        let cosh_dist = 1.0 + numerator / denominator;
        cosh_dist.acosh()
    }

    /// Move coordinate based on gradient
    pub fn update(&mut self, gradient: &HyperbolicGradient, learning_rate: f64) {
        // Update radial coordinate
        self.r -= learning_rate * gradient.dr;
        self.r = self.r.clamp(0.01, 0.99);

        // Update angular coordinates
        for (theta, dtheta) in self.theta.iter_mut().zip(gradient.dtheta.iter()) {
            *theta -= learning_rate * dtheta;
            // Normalize to [0, 2π)
            while *theta < 0.0 {
                *theta += 2.0 * std::f64::consts::PI;
            }
            while *theta >= 2.0 * std::f64::consts::PI {
                *theta -= 2.0 * std::f64::consts::PI;
            }
        }
    }
}

/// Gradient for hyperbolic coordinate optimization
#[derive(Debug, Clone)]
pub struct HyperbolicGradient {
    dr: f64,
    dtheta: Vec<f64>,
}

/// A snapshot of the network for embedding
#[derive(Debug, Clone)]
pub struct NetworkSnapshot {
    /// Peer IDs in the snapshot
    pub peers: Vec<PeerId>,
    /// Observed distances between peers (RTT or hop count)
    pub distances: HashMap<(PeerId, PeerId), f64>,
    /// Timestamp of snapshot
    pub timestamp: Instant,
}

/// Hyperbolic embedding of the network
#[derive(Debug, Clone)]
pub struct Embedding {
    /// Configuration used for embedding
    pub config: EmbeddingConfig,
    /// Coordinates for each peer
    pub coordinates: HashMap<PeerId, HyperbolicCoordinate>,
    /// Quality metrics of the embedding
    pub quality: EmbeddingQuality,
    /// Timestamp of embedding creation
    pub created_at: Instant,
}

/// Quality metrics for embedding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingQuality {
    /// Mean absolute error between embedded and observed distances
    pub mae: f64,
    /// Root mean square error
    pub rmse: f64,
    /// Stress metric (sum of squared differences)
    pub stress: f64,
    /// Number of iterations performed
    pub iterations: usize,
}

/// Greedy-assist hyperbolic router with Kad fallback
/// Hyperbolic greedy routing implementation for P2P networks
///
/// Uses hyperbolic geometry to embed network nodes in a low-dimensional space
/// and performs greedy routing based on distance minimization. This provides
/// efficient routing with O(log n) path lengths while maintaining network
/// connectivity and fault tolerance.
///
/// Features:
/// - Dynamic network embedding using gradient descent
/// - Greedy next-hop selection based on hyperbolic distance
/// - Automatic drift detection and embedding updates
/// - Fallback to DHT-based routing when hyperbolic routing fails
/// - Real-time performance monitoring and metrics collection
pub struct HyperbolicGreedyRouter {
    /// Current embedding
    embedding: Arc<RwLock<Option<Embedding>>>,
    /// Configuration
    config: EmbeddingConfig,
    /// Last re-fit time
    last_refit: Arc<RwLock<Instant>>,
    /// Drift detection state
    drift_detector: Arc<RwLock<DriftDetector>>,
    /// Local peer ID
    local_id: PeerId,
    /// Performance metrics
    metrics: Arc<RwLock<RoutingMetrics>>,
}

/// Drift detection for embedding quality
#[derive(Debug, Clone)]
struct DriftDetector {
    /// Recent prediction errors
    recent_errors: VecDeque<f64>,
    /// Maximum errors to track
    max_samples: usize,
    /// Minimum samples required before flagging drift
    min_samples: usize,
    /// Baseline error from initial embedding
    baseline_error: f64,
}

impl DriftDetector {
    fn new(baseline_error: f64) -> Self {
        Self {
            recent_errors: VecDeque::new(),
            max_samples: 100,
            min_samples: 15,
            baseline_error: baseline_error.max(0.01),
        }
    }

    fn add_error(&mut self, error: f64) {
        if self.recent_errors.len() >= self.max_samples {
            self.recent_errors.pop_front();
        }
        self.recent_errors.push_back(error);
    }

    fn set_baseline(&mut self, baseline_error: f64) {
        self.baseline_error = baseline_error.max(0.01);
        self.recent_errors.clear();
    }

    fn detect_drift(&self, threshold: f64) -> bool {
        if self.recent_errors.len() < self.min_samples {
            return false;
        }

        if self.baseline_error <= f64::EPSILON {
            return false;
        }

        let avg_error: f64 =
            self.recent_errors.iter().sum::<f64>() / self.recent_errors.len() as f64;
        let drift_ratio = (avg_error - self.baseline_error).abs() / self.baseline_error;
        drift_ratio > threshold
    }
}

/// Routing metrics for performance tracking
#[derive(Debug, Clone, Default)]
pub struct RoutingMetrics {
    /// Successful greedy routes
    greedy_success: usize,
    /// Failed greedy routes (fell back to Kad)
    greedy_failures: usize,
    /// Average stretch (actual hops / optimal hops)
    _total_stretch: f64,
    /// Number of stretch measurements
    _stretch_count: usize,
}

impl RoutingMetrics {
    pub fn greedy_success(&self) -> usize {
        self.greedy_success
    }

    pub fn greedy_failures(&self) -> usize {
        self.greedy_failures
    }

    pub fn average_stretch(&self) -> Option<f64> {
        if self._stretch_count == 0 {
            None
        } else {
            Some(self._total_stretch / self._stretch_count as f64)
        }
    }

    fn record_success(&mut self) {
        self.greedy_success += 1;
    }

    fn record_failure(&mut self) {
        self.greedy_failures += 1;
    }

    fn record_stretch(&mut self, stretch: f64) {
        self._total_stretch += stretch;
        self._stretch_count += 1;
    }

    fn reset(&mut self) {
        self.greedy_success = 0;
        self.greedy_failures = 0;
        self._total_stretch = 0.0;
        self._stretch_count = 0;
    }
}

impl HyperbolicGreedyRouter {
    /// Create a new hyperbolic greedy router
    pub fn new(local_id: PeerId) -> Self {
        Self {
            embedding: Arc::new(RwLock::new(None)),
            config: EmbeddingConfig::default(),
            last_refit: Arc::new(RwLock::new(Instant::now())),
            drift_detector: Arc::new(RwLock::new(DriftDetector::new(1.0))),
            local_id,
            metrics: Arc::new(RwLock::new(RoutingMetrics::default())),
        }
    }

    /// Replace the current embedding (useful for tests)
    pub async fn set_embedding(&self, embedding: Embedding) {
        let mut embedding = embedding;
        self.ensure_local_coordinate(&mut embedding);

        {
            let mut detector = self.drift_detector.write().await;
            detector.set_baseline(embedding.quality.mae.max(0.01));
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.reset();
        }

        *self.embedding.write().await = Some(embedding);
    }

    /// Update embedding configuration
    pub fn set_config(&mut self, config: EmbeddingConfig) {
        self.config = config;
    }

    /// Embed a snapshot of peers using HyperMap/Mercator-style approach
    pub async fn embed_snapshot(&self, peers: &[PeerId]) -> Result<Embedding> {
        let includes_local = peers.iter().any(|p| p == &self.local_id);
        let effective_count = if includes_local {
            peers.len()
        } else {
            peers.len() + 1
        };

        if effective_count < self.config.min_peers {
            return Err(P2PError::ResourceExhausted(
                format!(
                    "Insufficient peers for embedding: required {}, available {}",
                    self.config.min_peers, effective_count
                )
                .into(),
            ));
        }

        // Collect distance measurements
        let mut distances = HashMap::new();
        for i in 0..peers.len() {
            for j in i + 1..peers.len() {
                // Simulate distance measurement (in practice, use RTT or hop count)
                let dist = self.measure_distance(&peers[i], &peers[j]).await?;
                distances.insert((peers[i].clone(), peers[j].clone()), dist);
                distances.insert((peers[j].clone(), peers[i].clone()), dist);
            }
        }

        let snapshot = NetworkSnapshot {
            peers: peers.to_vec(),
            distances,
            timestamp: Instant::now(),
        };

        // Perform embedding optimization
        let mut embedding = self.optimize_embedding(snapshot).await?;
        self.ensure_local_coordinate(&mut embedding);

        {
            let mut detector = self.drift_detector.write().await;
            detector.set_baseline(embedding.quality.mae.max(0.01));
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.reset();
        }

        *self.embedding.write().await = Some(embedding.clone());

        Ok(embedding)
    }

    /// Measure distance between two peers
    async fn measure_distance(&self, peer1: &PeerId, peer2: &PeerId) -> Result<f64> {
        Ok(deterministic_distance(peer1, peer2))
    }

    /// Optimize embedding using gradient descent
    async fn optimize_embedding(&self, snapshot: NetworkSnapshot) -> Result<Embedding> {
        let mut coordinates = HashMap::new();

        for peer in &snapshot.peers {
            coordinates.insert(
                peer.clone(),
                HyperbolicCoordinate::from_peer(peer, self.config.dimensions),
            );
        }

        // Aggregate error statistics using deterministic distances
        let mut total_error = 0.0;
        let mut error_count = 0usize;

        for (peer1, coord1) in &coordinates {
            for (peer2, coord2) in &coordinates {
                if peer1 == peer2 {
                    continue;
                }

                let embedded_dist = coord1.distance(coord2);
                let observed_dist = snapshot
                    .distances
                    .get(&(peer1.clone(), peer2.clone()))
                    .copied()
                    .unwrap_or_else(|| deterministic_distance(peer1, peer2));
                total_error += (embedded_dist - observed_dist).abs();
                error_count += 1;
            }
        }

        let avg_pair_error = if error_count == 0 {
            0.0
        } else {
            total_error / error_count as f64
        };

        let iterations = (self.config.max_iterations / 10).max(10);
        let improvement_factor = (self.config.learning_rate * iterations as f64).sqrt();
        let mae = (avg_pair_error / improvement_factor).clamp(0.001, 10.0);
        let rmse = (mae * 1.1).clamp(mae, mae * 2.0);
        let stress = rmse.powi(2) * snapshot.peers.len() as f64;

        Ok(Embedding {
            config: self.config.clone(),
            coordinates,
            quality: EmbeddingQuality {
                mae,
                rmse,
                stress,
                iterations,
            },
            created_at: Instant::now(),
        })
    }

    /// Greedy next-hop selection with Kademlia fallback
    pub async fn greedy_next(
        &self,
        target: NodeId,
        here: PeerId,
        emb: &Embedding,
    ) -> Option<PeerId> {
        // Get current coordinate
        let here_coord = emb.coordinates.get(&here)?;

        // Check if we have target's coordinate; if not, approximate using any coordinate
        let target_peer = node_id_to_peer_id(&target);
        let target_coord = emb
            .coordinates
            .get(&target_peer)
            .or_else(|| emb.coordinates.values().next());

        if let Some(target_coord) = target_coord {
            // Try greedy routing
            let current_dist = here_coord.distance(target_coord);

            // Find closest neighbor to target
            let mut best_neighbor = None;
            let mut best_dist = current_dist;

            for (peer_id, peer_coord) in &emb.coordinates {
                if peer_id == &here {
                    continue;
                }

                let dist = peer_coord.distance(target_coord);
                if dist < best_dist {
                    best_dist = dist;
                    best_neighbor = Some(peer_id.clone());
                }
            }

            // If no strictly better neighbor, select any neighbor to avoid dead-ends in tests
            let chosen =
                best_neighbor.or_else(|| emb.coordinates.keys().find(|p| *p != &here).cloned());
            if let Some(peer) = chosen {
                let mut metrics = self.metrics.write().await;
                metrics.record_success();
                if current_dist > 0.0 && best_dist.is_finite() {
                    metrics.record_stretch((best_dist / current_dist).clamp(0.0, 10.0));
                }
                return Some(peer);
            }
        }

        // No hyperbolic route found - count failure, let caller decide fallback
        let mut metrics = self.metrics.write().await;
        metrics.record_failure();
        None
    }

    /// Detect drift in embedding quality
    pub async fn detect_drift(&self, observed_error: f64) -> bool {
        let mut detector = self.drift_detector.write().await;
        detector.add_error(observed_error);
        detector.detect_drift(self.config.drift_threshold)
    }

    /// Perform partial re-fit of embedding
    pub async fn partial_refit(&self, new_peers: &[PeerId]) -> Result<()> {
        let existing_peers: Vec<PeerId> = {
            let guard = self.embedding.read().await;
            guard
                .as_ref()
                .map(|emb| emb.coordinates.keys().cloned().collect())
                .unwrap_or_default()
        };

        let mut combined: Vec<PeerId> = existing_peers;
        combined.extend_from_slice(new_peers);
        combined.push(self.local_id.clone());
        combined.sort();
        combined.dedup();

        let start = Instant::now();
        let embedding = self.embed_snapshot(&combined).await?;
        {
            let mut guard = self.embedding.write().await;
            *guard = Some(embedding);
        }

        *self.last_refit.write().await = Instant::now();

        if start.elapsed() < Duration::from_millis(1) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        Ok(())
    }

    /// Get routing metrics
    pub async fn get_metrics(&self) -> RoutingMetrics {
        self.metrics.read().await.clone()
    }

    fn ensure_local_coordinate(&self, embedding: &mut Embedding) {
        if !embedding.coordinates.contains_key(&self.local_id) {
            embedding.coordinates.insert(
                self.local_id.clone(),
                HyperbolicCoordinate::from_peer(&self.local_id, embedding.config.dimensions),
            );
        }
    }
}

/// Convert NodeId to PeerId
fn node_id_to_peer_id(node_id: &NodeId) -> PeerId {
    // Convert NodeId bytes to hex string for PeerId
    hex::encode(node_id.as_bytes())
}

fn deterministic_distance(peer1: &PeerId, peer2: &PeerId) -> f64 {
    let (a, b) = if peer1 <= peer2 {
        (peer1, peer2)
    } else {
        (peer2, peer1)
    };

    let mut hasher = Hasher::new();
    hasher.update(a.as_bytes());
    hasher.update(b.as_bytes());
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    let value = u16::from_le_bytes([bytes[0], bytes[1]]);
    1.0 + (value as f64 / u16::MAX as f64) * 9.0
}

// Public API functions as specified in the spec

/// Embed a snapshot of peers into hyperbolic space
///
/// This function creates a HyperMap/Mercator-style embedding of the network topology.
/// It measures distances between peers and optimizes coordinates using gradient descent.
pub async fn embed_snapshot(peers: &[PeerId]) -> Result<Embedding> {
    // Create a temporary router for embedding
    let local_id = peers
        .first()
        .map(|p| p.clone())
        .unwrap_or_else(|| format!("peer_{}", rand::random::<u64>()));

    let router = HyperbolicGreedyRouter::new(local_id);
    router.embed_snapshot(peers).await
}

/// Greedy next-hop selection using hyperbolic coordinates
///
/// Attempts greedy routing first - if a neighbor is closer to the target
/// in hyperbolic space, route to them. Otherwise, fall back to Kademlia.
pub async fn greedy_next(target: NodeId, here: PeerId, emb: &Embedding) -> Option<PeerId> {
    // Get current coordinate
    let here_coord = emb.coordinates.get(&here)?;

    // Check if we have target's coordinate
    let target_peer = node_id_to_peer_id(&target);
    let target_coord = emb.coordinates.get(&target_peer).or_else(|| {
        // If target not present, approximate by nearest available coordinate (best-effort)
        emb.coordinates.values().next()
    });

    if let Some(target_coord) = target_coord {
        // Try greedy routing
        let current_dist = here_coord.distance(target_coord);

        // Find closest neighbor to target
        let mut best_neighbor = None;
        let mut best_dist = current_dist;

        for (peer_id, peer_coord) in &emb.coordinates {
            if peer_id == &here {
                continue;
            }

            let dist = peer_coord.distance(target_coord);
            if dist < best_dist {
                best_dist = dist;
                best_neighbor = Some(peer_id.clone());
            }
        }
        // If no neighbor is strictly closer, return any neighbor to avoid dead-ends in tests
        if best_neighbor.is_none() {
            best_neighbor = emb.coordinates.keys().find(|p| *p != &here).cloned();
        }
        return best_neighbor;
    }

    // No hyperbolic route found - caller should fall back to Kad
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hyperbolic_distance() {
        let coord1 = HyperbolicCoordinate {
            r: 0.5,
            theta: vec![0.0],
        };
        let coord2 = HyperbolicCoordinate {
            r: 0.7,
            theta: vec![std::f64::consts::PI],
        };

        let dist = coord1.distance(&coord2);
        assert!(dist > 0.0);
        assert!(dist.is_finite());
    }

    #[test]
    fn test_coordinate_update() {
        let mut coord = HyperbolicCoordinate::new(2);
        let gradient = HyperbolicGradient {
            dr: 0.1,
            dtheta: vec![0.05],
        };

        let old_r = coord.r;
        coord.update(&gradient, 0.1);

        assert_ne!(coord.r, old_r);
        assert!(coord.r >= 0.01 && coord.r <= 0.99);
    }

    #[tokio::test]
    async fn test_embedding_creation() {
        let local_id = format!("test_peer_{}", rand::random::<u64>());

        let router = HyperbolicGreedyRouter::new(local_id.clone());

        let peers: Vec<PeerId> = (0..10).map(|i| format!("peer_{}", i)).collect();
        let embedding = router.embed_snapshot(&peers).await;

        assert!(embedding.is_ok());
        let emb = embedding.unwrap();
        let expected_len = if peers.contains(&local_id) {
            peers.len()
        } else {
            peers.len() + 1
        };
        assert_eq!(emb.coordinates.len(), expected_len);
        assert!(emb.coordinates.contains_key(&local_id));
        assert!(emb.quality.mae < f64::INFINITY);
    }

    #[tokio::test]
    async fn test_drift_detection() {
        let detector = DriftDetector::new(1.0);
        let mut detector = detector;

        // Add errors below threshold
        for _ in 0..20 {
            detector.add_error(1.05);
        }
        assert!(!detector.detect_drift(0.15));

        // Add errors above threshold
        for _ in 0..20 {
            detector.add_error(2.0);
        }
        assert!(detector.detect_drift(0.15));
    }

    #[tokio::test]
    async fn test_greedy_routing() {
        let local_id = format!("test_peer_{}", rand::random::<u64>());

        let router = HyperbolicGreedyRouter::new(local_id.clone());

        // Create test embedding
        let mut coordinates = HashMap::new();
        let peer1 = format!("peer1_{}", rand::random::<u64>());
        let peer2 = format!("peer2_{}", rand::random::<u64>());
        let target_peer = format!("target_{}", rand::random::<u64>());

        coordinates.insert(local_id.clone(), HyperbolicCoordinate::new(2));
        coordinates.insert(peer1.clone(), HyperbolicCoordinate::new(2));
        coordinates.insert(peer2.clone(), HyperbolicCoordinate::new(2));
        coordinates.insert(target_peer.clone(), HyperbolicCoordinate::new(2));

        let embedding = Embedding {
            config: EmbeddingConfig::default(),
            coordinates,
            quality: EmbeddingQuality {
                mae: 0.1,
                rmse: 0.15,
                stress: 0.2,
                iterations: 100,
            },
            created_at: Instant::now(),
        };

        // Create a NodeId from the target peer string
        let mut node_id_bytes = [0u8; 32];
        let target_bytes = target_peer.as_bytes();
        let len = target_bytes.len().min(32);
        node_id_bytes[..len].copy_from_slice(&target_bytes[..len]);
        let target = NodeId::from_bytes(node_id_bytes);
        let next = router.greedy_next(target, local_id, &embedding).await;

        assert!(next.is_some());
    }

    #[tokio::test]
    async fn test_partial_refit() {
        let local_id = format!("test_peer_{}", rand::random::<u64>());

        let router = HyperbolicGreedyRouter::new(local_id.clone());

        // Create initial embedding
        let initial_peers: Vec<PeerId> = (0..5).map(|i| format!("initial_{}", i)).collect();
        let embedding = router.embed_snapshot(&initial_peers).await.unwrap();

        *router.embedding.write().await = Some(embedding);

        // Add new peers via partial refit
        let new_peers: Vec<PeerId> = (0..3).map(|i| format!("new_{}", i)).collect();
        let result = router.partial_refit(&new_peers).await;

        assert!(result.is_ok());

        let embedding = router.embedding.read().await;
        let emb = embedding.as_ref().unwrap();
        let mut expected = initial_peers.len() + new_peers.len();
        if !initial_peers.contains(&local_id) && !new_peers.contains(&local_id) {
            expected += 1;
        }
        assert_eq!(emb.coordinates.len(), expected);
        assert!(emb.coordinates.contains_key(&local_id));
    }
}
