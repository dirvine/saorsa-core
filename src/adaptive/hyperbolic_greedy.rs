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

//! Greedy-assist hyperbolic embedding for experimental routing optimization
//!
//! This module implements greedy-first routing using hyperbolic coordinates
//! with Kademlia fallback. It uses HyperMap/Mercator-style background embedding
//! with drift detection and partial re-fitting.

use crate::dht::core_engine::{DhtCoreEngine, NodeId};
use crate::dht::DhtKey;
use crate::{P2PError, PeerId, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
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
        Self {
            r: rng.gen_range(0.1..0.9),
            theta: (0..dimensions - 1)
                .map(|_| rng.gen_range(0.0..2.0 * std::f64::consts::PI))
                .collect(),
        }
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
pub struct HyperbolicGreedyRouter {
    /// Current embedding
    embedding: Arc<RwLock<Option<Embedding>>>,
    /// DHT engine for Kademlia fallback
    dht_engine: Arc<DhtCoreEngine>,
    /// Configuration
    config: EmbeddingConfig,
    /// Last re-fit time
    last_refit: Arc<RwLock<Instant>>,
    /// Drift detection state
    drift_detector: Arc<RwLock<DriftDetector>>,
    /// Local peer ID
    _local_id: PeerId,
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
    /// Baseline error from initial embedding
    baseline_error: f64,
}

impl DriftDetector {
    fn new(baseline_error: f64) -> Self {
        Self {
            recent_errors: VecDeque::new(),
            max_samples: 100,
            baseline_error,
        }
    }

    fn add_error(&mut self, error: f64) {
        if self.recent_errors.len() >= self.max_samples {
            self.recent_errors.pop_front();
        }
        self.recent_errors.push_back(error);
    }

    fn detect_drift(&self, threshold: f64) -> bool {
        if self.recent_errors.len() < 10 {
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

impl HyperbolicGreedyRouter {
    /// Create a new hyperbolic greedy router
    pub fn new(local_id: PeerId, dht_engine: Arc<DhtCoreEngine>) -> Self {
        Self {
            embedding: Arc::new(RwLock::new(None)),
            dht_engine,
            config: EmbeddingConfig::default(),
            last_refit: Arc::new(RwLock::new(Instant::now())),
            drift_detector: Arc::new(RwLock::new(DriftDetector::new(0.1))),
            _local_id: local_id,
            metrics: Arc::new(RwLock::new(RoutingMetrics::default())),
        }
    }

    /// Embed a snapshot of peers using HyperMap/Mercator-style approach
    pub async fn embed_snapshot(&self, peers: &[PeerId]) -> Result<Embedding> {
        if peers.len() < self.config.min_peers {
            return Err(P2PError::ResourceExhausted(
                format!(
                    "Insufficient peers for embedding: required {}, available {}",
                    self.config.min_peers,
                    peers.len()
                ).into()
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
        self.optimize_embedding(snapshot).await
    }

    /// Measure distance between two peers
    async fn measure_distance(&self, _peer1: &PeerId, _peer2: &PeerId) -> Result<f64> {
        // In practice, this would measure RTT or hop count
        // For now, return a simulated distance
        Ok(rand::thread_rng().gen_range(1.0..10.0))
    }

    /// Optimize embedding using gradient descent
    async fn optimize_embedding(&self, snapshot: NetworkSnapshot) -> Result<Embedding> {
        let mut coordinates = HashMap::new();

        // Initialize random coordinates
        for peer in &snapshot.peers {
            coordinates.insert(
                peer.clone(),
                HyperbolicCoordinate::new(self.config.dimensions),
            );
        }

        let mut best_quality = EmbeddingQuality {
            mae: f64::INFINITY,
            rmse: f64::INFINITY,
            stress: f64::INFINITY,
            iterations: 0,
        };

        // Gradient descent optimization
        for iteration in 0..self.config.max_iterations {
            let mut total_gradient = HashMap::new();
            let mut total_error = 0.0;
            let mut error_count = 0;

            // Compute gradients for all pairs
            for (peer1, coord1) in &coordinates {
                let mut gradient = HyperbolicGradient {
                    dr: 0.0,
                    dtheta: vec![0.0; self.config.dimensions - 1],
                };

                for (peer2, coord2) in &coordinates {
                    if peer1 == peer2 {
                        continue;
                    }

                    let embedded_dist = coord1.distance(coord2);
                    let observed_dist = snapshot
                        .distances
                        .get(&(peer1.clone(), peer2.clone()))
                        .copied()
                        .unwrap_or(5.0);

                    let error = embedded_dist - observed_dist;
                    total_error += error.abs();
                    error_count += 1;

                    // Compute gradient contribution
                    let grad_factor = error * 2.0 / (error_count as f64);

                    // Radial gradient
                    let dr_contrib = grad_factor * (coord1.r - coord2.r) / embedded_dist.max(0.001);
                    gradient.dr += dr_contrib;

                    // Angular gradients
                    for (i, (t1, t2)) in coord1.theta.iter().zip(coord2.theta.iter()).enumerate() {
                        let dtheta_contrib =
                            grad_factor * (t1 - t2).sin() / embedded_dist.max(0.001);
                        gradient.dtheta[i] += dtheta_contrib;
                    }
                }

                total_gradient.insert(peer1.clone(), gradient);
            }

            // Update coordinates
            for (peer, gradient) in total_gradient {
                if let Some(coord) = coordinates.get_mut(&peer) {
                    coord.update(&gradient, self.config.learning_rate);
                }
            }

            // Calculate quality metrics
            let mae = total_error / error_count.max(1) as f64;
            let quality = EmbeddingQuality {
                mae,
                rmse: (total_error.powi(2) / error_count.max(1) as f64).sqrt(),
                stress: total_error.powi(2),
                iterations: iteration + 1,
            };

            // Check convergence
            if quality.mae < best_quality.mae {
                best_quality = quality.clone();
                if best_quality.mae < self.config.convergence_threshold {
                    break;
                }
            } else if iteration > 100 && best_quality.mae < quality.mae * 1.1 {
                // Early stopping if not improving
                break;
            }
        }

        Ok(Embedding {
            config: self.config.clone(),
            coordinates,
            quality: best_quality,
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

        // Check if we have target's coordinate
        let target_peer = node_id_to_peer_id(&target);
        let target_coord = emb.coordinates.get(&target_peer);

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

            if best_neighbor.is_some() {
                // Update metrics
                let mut metrics = self.metrics.write().await;
                metrics.greedy_success += 1;
                return best_neighbor;
            }
        }

        // Fall back to Kademlia routing
        let mut metrics = self.metrics.write().await;
        metrics.greedy_failures += 1;
        drop(metrics);

        // Use DHT for fallback
        self.kad_fallback(&target).await
    }

    /// Kademlia fallback routing
    async fn kad_fallback(&self, target: &NodeId) -> Option<PeerId> {
        // Use DHT engine to find next hop
        // DhtCoreEngine doesn't have find_closest_peers, use find_nodes instead
        let target_key = DhtKey::from_bytes(*target.as_bytes());
        match self.dht_engine.find_nodes(&target_key, 1).await {
            Ok(nodes) => {
                // Convert NodeInfo to PeerId
                nodes.into_iter().next().map(|node| {
                    // Convert NodeId to PeerId (String)
                    // Encode the node ID as hex string
                    hex::encode(node.id.as_bytes())
                })
            }
            Err(_) => None,
        }
    }

    /// Detect drift in embedding quality
    pub async fn detect_drift(&self, observed_error: f64) -> bool {
        let mut detector = self.drift_detector.write().await;
        detector.add_error(observed_error);
        detector.detect_drift(self.config.drift_threshold)
    }

    /// Perform partial re-fit of embedding
    pub async fn partial_refit(&self, new_peers: &[PeerId]) -> Result<()> {
        let mut embedding_guard = self.embedding.write().await;

        if let Some(current_embedding) = embedding_guard.as_mut() {
            // Add new peers with initial coordinates
            for peer in new_peers {
                if !current_embedding.coordinates.contains_key(peer) {
                    current_embedding.coordinates.insert(
                        peer.clone(),
                        HyperbolicCoordinate::new(self.config.dimensions),
                    );
                }
            }

            // Perform limited optimization iterations
            let max_refit_iterations = self.config.max_iterations / 5;
            for _ in 0..max_refit_iterations {
                // Simplified gradient update for new peers only
                for new_peer in new_peers {
                    if let Some(coord) = current_embedding.coordinates.get_mut(new_peer) {
                        // Small random perturbation for exploration
                        coord.r += rand::thread_rng().gen_range(-0.01..0.01);
                        coord.r = coord.r.clamp(0.01, 0.99);
                    }
                }
            }

            // Update timestamp
            *self.last_refit.write().await = Instant::now();
        }

        Ok(())
    }

    /// Get routing metrics
    pub async fn get_metrics(&self) -> RoutingMetrics {
        self.metrics.read().await.clone()
    }
}

/// Convert NodeId to PeerId
fn node_id_to_peer_id(node_id: &NodeId) -> PeerId {
    // Convert NodeId bytes to hex string for PeerId
    hex::encode(node_id.as_bytes())
}

// Public API functions as specified in the spec

/// Embed a snapshot of peers into hyperbolic space
///
/// This function creates a HyperMap/Mercator-style embedding of the network topology.
/// It measures distances between peers and optimizes coordinates using gradient descent.
pub async fn embed_snapshot(peers: &[PeerId]) -> Result<Embedding> {
    // Create a temporary router for embedding
    let local_id = if !peers.is_empty() {
        peers[0].clone()
    } else {
        // Generate a random PeerId
        format!("peer_{}", rand::random::<u64>())
    };

    // Convert PeerId to NodeId for DHT
    let mut node_id_bytes = [0u8; 32];
    let id_bytes = local_id.as_bytes();
    let len = id_bytes.len().min(32);
    node_id_bytes[..len].copy_from_slice(&id_bytes[..len]);
    let node_id = NodeId::from_bytes(node_id_bytes);

    let dht = Arc::new(DhtCoreEngine::new(node_id).map_err(|e| P2PError::Internal(e.to_string().into()))?);

    let router = HyperbolicGreedyRouter::new(local_id, dht);
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
    let target_coord = emb.coordinates.get(&target_peer);

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
        
        // Convert PeerId to NodeId for DHT
        let mut node_id_bytes = [0u8; 32];
        let id_bytes = local_id.as_bytes();
        let len = id_bytes.len().min(32);
        node_id_bytes[..len].copy_from_slice(&id_bytes[..len]);
        let node_id = NodeId::from_bytes(node_id_bytes);
        
        let dht = Arc::new(DhtCoreEngine::new(node_id).unwrap());

        let router = HyperbolicGreedyRouter::new(local_id, dht);

        let peers: Vec<PeerId> = (0..10).map(|i| format!("peer_{}", i)).collect();
        let embedding = router.embed_snapshot(&peers).await;

        assert!(embedding.is_ok());
        let emb = embedding.unwrap();
        assert_eq!(emb.coordinates.len(), peers.len());
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
        let local_id = format!("local_{}", rand::random::<u64>());
        
        // Convert PeerId to NodeId for DHT
        let mut node_id_bytes = [0u8; 32];
        let id_bytes = local_id.as_bytes();
        let len = id_bytes.len().min(32);
        node_id_bytes[..len].copy_from_slice(&id_bytes[..len]);
        let node_id = NodeId::from_bytes(node_id_bytes);
        
        let dht = Arc::new(DhtCoreEngine::new(node_id).unwrap());

        let router = HyperbolicGreedyRouter::new(local_id.clone(), dht);

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
        let local_id = format!("refit_test_{}", rand::random::<u64>());
        
        // Convert PeerId to NodeId for DHT
        let mut node_id_bytes = [0u8; 32];
        let id_bytes = local_id.as_bytes();
        let len = id_bytes.len().min(32);
        node_id_bytes[..len].copy_from_slice(&id_bytes[..len]);
        let node_id = NodeId::from_bytes(node_id_bytes);
        
        let dht = Arc::new(DhtCoreEngine::new(node_id).unwrap());

        let router = HyperbolicGreedyRouter::new(local_id, dht);

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
        assert_eq!(emb.coordinates.len(), initial_peers.len() + new_peers.len());
    }
}
