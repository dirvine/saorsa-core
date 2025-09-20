// Copyright 2024 Saorsa Labs Limited
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

//! # Multi-Armed Bandit Routing Optimization
//!
//! This module implements a Multi-Armed Bandit (MAB) system for optimizing
//! route selection in the P2P network using Thompson Sampling.
//!
//! ## Features
//! - Per-route, per-content-type optimization
//! - Automatic exploration vs exploitation balance
//! - Persistent statistics across restarts
//! - Confidence intervals for decision quality
//! - Minimum exploration thresholds

use super::beta_distribution::BetaDistribution;
use super::*;
use crate::error::ConfigError;
use crate::{P2PError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

type LegacyStatsFormat = (HashMap<(RouteId, ContentType), RouteStatistics>, MABMetrics);
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::sync::RwLock;

/// Route identifier for tracking statistics
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RouteId {
    /// Node ID of the destination
    pub node_id: NodeId,
    /// Strategy used for routing
    pub strategy: StrategyChoice,
}

impl RouteId {
    /// Create a new route identifier
    pub fn new(node_id: NodeId, strategy: StrategyChoice) -> Self {
        Self { node_id, strategy }
    }
}

/// Statistics for a specific route and content type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteStatistics {
    /// Beta distribution parameters
    pub alpha: f64,
    pub beta: f64,
    /// Total number of attempts
    pub attempts: u64,
    /// Total successful deliveries
    pub successes: u64,
    /// Average latency in milliseconds
    pub avg_latency_ms: f64,
    /// Last update timestamp
    pub last_updated: u64,
    /// Creation timestamp
    pub created_at: u64,
}

impl Default for RouteStatistics {
    fn default() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            alpha: 1.0, // Uniform prior
            beta: 1.0,  // Uniform prior
            attempts: 0,
            successes: 0,
            avg_latency_ms: 0.0,
            last_updated: now,
            created_at: now,
        }
    }
}

/// Routing decision made by the MAB system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteDecision {
    /// Selected route
    pub route_id: RouteId,
    /// Probability of success (Thompson sample)
    pub probability: f64,
    /// Whether this was exploration (vs exploitation)
    pub exploration: bool,
    /// Confidence interval for success rate
    pub confidence_interval: (f64, f64),
    /// Expected latency
    pub expected_latency_ms: f64,
}

/// Configuration for the Multi-Armed Bandit system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MABConfig {
    /// Minimum exploration probability (epsilon)
    pub epsilon: f64,
    /// Minimum samples before trusting statistics
    pub min_samples: u32,
    /// Decay factor for old observations (per hour)
    pub decay_factor: f64,
    /// Path for persistent storage
    pub storage_path: Option<PathBuf>,
    /// How often to persist statistics
    pub persist_interval: Duration,
    /// Maximum age for statistics before removal
    pub max_stats_age: Duration,
}

impl Default for MABConfig {
    fn default() -> Self {
        Self {
            epsilon: 0.05, // 5% exploration
            min_samples: 10,
            decay_factor: 0.99,
            storage_path: None,
            persist_interval: Duration::from_secs(300), // 5 minutes
            max_stats_age: Duration::from_secs(7 * 24 * 3600), // 7 days
        }
    }
}

/// Multi-Armed Bandit system for routing optimization
pub struct MultiArmedBandit {
    /// Configuration
    config: MABConfig,
    /// Statistics per (route, content type)
    statistics: Arc<RwLock<HashMap<(RouteId, ContentType), RouteStatistics>>>,
    /// Last persistence time
    last_persist: Arc<RwLock<Instant>>,
    /// Performance metrics
    metrics: Arc<RwLock<MABMetrics>>,
}

/// Performance metrics for the MAB system
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MABMetrics {
    /// Total routing decisions made
    pub total_decisions: u64,
    /// Decisions that were exploration
    pub exploration_decisions: u64,
    /// Average success rate across all routes
    pub overall_success_rate: f64,
    /// Number of unique routes tracked
    pub unique_routes: usize,
    /// Last cleanup timestamp
    pub last_cleanup: u64,
}

impl MultiArmedBandit {
    /// Create a new Multi-Armed Bandit instance
    pub async fn new(config: MABConfig) -> Result<Self> {
        let initial_persist = Instant::now() - config.persist_interval;

        let mut mab = Self {
            config,
            statistics: Arc::new(RwLock::new(HashMap::new())),
            last_persist: Arc::new(RwLock::new(initial_persist)),
            metrics: Arc::new(RwLock::new(MABMetrics::default())),
        };

        // Load persisted statistics if available
        if let Some(path) = mab.config.storage_path.clone()
            && let Err(e) = mab.load_statistics(&path).await
        {
            tracing::warn!("Failed to load MAB statistics: {}", e);
        }

        Ok(mab)
    }

    /// Select the best route for a given destination and content type
    pub async fn select_route(
        &self,
        destination: &NodeId,
        content_type: ContentType,
        available_strategies: &[StrategyChoice],
    ) -> Result<RouteDecision> {
        let mut statistics = self.statistics.write().await;
        let mut metrics = self.metrics.write().await;

        metrics.total_decisions += 1;

        // Check if we should explore
        let should_explore = rand::random::<f64>() < self.config.epsilon;

        if should_explore {
            metrics.exploration_decisions += 1;
            // Random exploration
            let strategy =
                available_strategies[rand::random::<usize>() % available_strategies.len()];
            let route_id = RouteId::new(destination.clone(), strategy);

            let stats = statistics
                .entry((route_id.clone(), content_type))
                .or_default();

            let distribution = BetaDistribution::new(stats.alpha, stats.beta).map_err(|e| {
                P2PError::Config(ConfigError::ValidationFailed(
                    format!("Beta distribution error: {}", e).into(),
                ))
            })?;

            return Ok(RouteDecision {
                route_id,
                probability: distribution.mean().clamp(0.0, 1.0), // Clamp to valid probability range
                exploration: true,
                confidence_interval: distribution.confidence_interval(),
                expected_latency_ms: stats.avg_latency_ms,
            });
        }

        // Thompson Sampling for exploitation
        let mut best_route = None;
        let mut best_sample = 0.0;
        let mut best_stats = RouteStatistics::default();

        for strategy in available_strategies {
            let route_id = RouteId::new(destination.clone(), *strategy);
            let key = (route_id.clone(), content_type);

            let stats = statistics.entry(key).or_default();

            // Apply time decay
            self.apply_decay(stats);

            // Sample from Beta distribution
            let distribution = BetaDistribution::new(stats.alpha, stats.beta).map_err(|e| {
                P2PError::Config(ConfigError::ValidationFailed(
                    format!("Beta distribution error: {}", e).into(),
                ))
            })?;

            let mut rng = rand::thread_rng();
            let sample = distribution.sample(&mut rng);

            // Add bonus for under-sampled routes
            let exploration_bonus = if stats.attempts < self.config.min_samples as u64 {
                0.1 * (1.0 - (stats.attempts as f64 / self.config.min_samples as f64))
            } else {
                0.0
            };

            let adjusted_sample = sample + exploration_bonus;

            if adjusted_sample > best_sample || best_route.is_none() {
                best_sample = adjusted_sample;
                best_route = Some(route_id);
                best_stats = stats.clone();
            }
        }

        let route_id = best_route.ok_or_else(|| {
            P2PError::Config(ConfigError::ValidationFailed(
                "No routes available".to_string().into(),
            ))
        })?;

        let distribution =
            BetaDistribution::new(best_stats.alpha, best_stats.beta).map_err(|e| {
                P2PError::Config(ConfigError::ValidationFailed(
                    format!("Beta distribution error: {}", e).into(),
                ))
            })?;

        // Update metrics
        metrics.unique_routes = statistics.len();

        Ok(RouteDecision {
            route_id,
            probability: best_sample.min(1.0), // Clamp to valid probability range
            exploration: false,
            confidence_interval: distribution.confidence_interval(),
            expected_latency_ms: best_stats.avg_latency_ms,
        })
    }

    /// Update statistics based on routing outcome
    pub async fn update_route(
        &self,
        route_id: &RouteId,
        content_type: ContentType,
        outcome: &Outcome,
    ) -> Result<()> {
        let mut statistics = self.statistics.write().await;
        let mut metrics = self.metrics.write().await;

        let key = (route_id.clone(), content_type);
        let stats = statistics.entry(key).or_default();

        // Update Beta parameters
        if outcome.success {
            stats.alpha += 1.0;
            stats.successes += 1;
        } else {
            stats.beta += 1.0;
        }
        stats.attempts += 1;

        // Update latency (exponential moving average)
        let alpha = 0.1; // Learning rate for latency
        stats.avg_latency_ms =
            (1.0 - alpha) * stats.avg_latency_ms + alpha * outcome.latency_ms as f64;

        // Update timestamp
        stats.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Update overall metrics
        let total_successes: u64 = statistics.values().map(|s| s.successes).sum();
        let total_attempts: u64 = statistics.values().map(|s| s.attempts).sum();
        metrics.overall_success_rate = if total_attempts > 0 {
            total_successes as f64 / total_attempts as f64
        } else {
            0.0
        };

        // Check if we should persist
        let last_persist = *self.last_persist.read().await;
        if last_persist.elapsed() > self.config.persist_interval
            && let Some(ref path) = self.config.storage_path
        {
            let statistics_clone = statistics.clone();
            let metrics_clone = metrics.clone();
            let path_clone = path.clone();
            let stats_arc = Arc::clone(&self.statistics);
            let metrics_arc = Arc::clone(&self.metrics);
            let path_deferred = path.clone();
            let interval = self.config.persist_interval;

            // Persist asynchronously
            tokio::spawn(async move {
                if let Err(e) =
                    Self::persist_statistics_static(&path_clone, &statistics_clone, &metrics_clone)
                        .await
                {
                    tracing::error!("Failed to persist MAB statistics: {}", e);
                }
            });

            // Schedule a deferred persistence to capture subsequent updates
            tokio::spawn(async move {
                tokio::time::sleep(interval).await;
                let statistics = stats_arc.read().await.clone();
                let metrics = metrics_arc.read().await.clone();
                if let Err(e) =
                    Self::persist_statistics_static(&path_deferred, &statistics, &metrics).await
                {
                    tracing::error!("Failed to persist deferred MAB statistics: {}", e);
                }
            });

            *self.last_persist.write().await = Instant::now();
        }

        Ok(())
    }

    /// Get confidence interval for a specific route
    pub async fn get_route_confidence(
        &self,
        route_id: &RouteId,
        content_type: ContentType,
    ) -> Result<(f64, f64)> {
        let statistics = self.statistics.read().await;
        let key = (route_id.clone(), content_type);

        if let Some(stats) = statistics.get(&key) {
            let distribution = BetaDistribution::new(stats.alpha, stats.beta).map_err(|e| {
                P2PError::Config(ConfigError::ValidationFailed(
                    format!("Beta distribution error: {}", e).into(),
                ))
            })?;
            Ok(distribution.confidence_interval())
        } else {
            Ok((0.0, 1.0)) // Maximum uncertainty
        }
    }

    /// Get all statistics for monitoring
    pub async fn get_all_statistics(&self) -> HashMap<(RouteId, ContentType), RouteStatistics> {
        self.statistics.read().await.clone()
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> MABMetrics {
        self.metrics.read().await.clone()
    }

    /// Reset statistics for a specific route
    pub async fn reset_route(&self, route_id: &RouteId, content_type: ContentType) {
        let mut statistics = self.statistics.write().await;
        statistics.remove(&(route_id.clone(), content_type));
    }

    /// Apply time decay to statistics
    fn apply_decay(&self, stats: &mut RouteStatistics) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let hours_elapsed = (now - stats.last_updated) as f64 / 3600.0;
        if hours_elapsed > 0.0 {
            let decay = self.config.decay_factor.powf(hours_elapsed);
            stats.alpha = 1.0 + (stats.alpha - 1.0) * decay;
            stats.beta = 1.0 + (stats.beta - 1.0) * decay;
        }
    }

    /// Load statistics from disk
    async fn load_statistics(&mut self, path: &Path) -> Result<()> {
        let stats_path = path.join("mab_statistics.json");
        if !stats_path.exists() {
            return Ok(());
        }

        let data = fs::read_to_string(&stats_path)
            .await
            .map_err(P2PError::Io)?;

        // Try legacy tuple format first
        let parsed_legacy: Result<LegacyStatsFormat> = serde_json::from_str(&data).map_err(|e| {
            P2PError::Storage(crate::error::StorageError::Database(
                format!("Failed to deserialize legacy statistics: {}", e).into(),
            ))
        });

        let (statistics, metrics) = if let Ok((stats, metrics)) = parsed_legacy {
            (stats, metrics)
        } else {
            // New format: {"statistics":[{route_id:{node_id, strategy}, content_type, stats}], "metrics":{...}}
            let v: serde_json::Value = serde_json::from_str(&data).map_err(|e| {
                P2PError::Storage(crate::error::StorageError::Database(
                    format!("Failed to parse statistics JSON: {}", e).into(),
                ))
            })?;

            let metrics: MABMetrics =
                serde_json::from_value(v.get("metrics").cloned().unwrap_or_default())
                    .unwrap_or_default();

            let mut map: HashMap<(RouteId, ContentType), RouteStatistics> = HashMap::new();
            if let Some(arr) = v.get("statistics").and_then(|s| s.as_array()) {
                for item in arr {
                    if let (Some(route_id_v), Some(ct_v), Some(stats_v)) = (
                        item.get("route_id"),
                        item.get("content_type"),
                        item.get("stats"),
                    ) {
                        // Parse route id
                        let node_hex = route_id_v
                            .get("node_id")
                            .and_then(|n| n.as_str())
                            .unwrap_or("");
                        let mut node_bytes = [0u8; 32];
                        if let Ok(b) = hex::decode(node_hex) {
                            let len = b.len().min(32);
                            node_bytes[..len].copy_from_slice(&b[..len]);
                        }
                        let node = crate::peer_record::UserId::from_bytes(node_bytes);
                        let strategy_str = route_id_v
                            .get("strategy")
                            .and_then(|s| s.as_str())
                            .unwrap_or("Kademlia");
                        let strategy = match strategy_str {
                            "Kademlia" => StrategyChoice::Kademlia,
                            "Hyperbolic" => StrategyChoice::Hyperbolic,
                            "TrustPath" => StrategyChoice::TrustPath,
                            "SOMRegion" => StrategyChoice::SOMRegion,
                            _ => StrategyChoice::Kademlia,
                        };
                        let route_id = RouteId {
                            node_id: node,
                            strategy,
                        };

                        // Parse content type
                        let ct_str = ct_v.as_str().unwrap_or("DHTLookup");
                        let ct = match ct_str {
                            "DHTLookup" => ContentType::DHTLookup,
                            "DataRetrieval" => ContentType::DataRetrieval,
                            "ComputeRequest" => ContentType::ComputeRequest,
                            "RealtimeMessage" => ContentType::RealtimeMessage,
                            _ => ContentType::DHTLookup,
                        };

                        // Parse stats
                        if let Ok(st) = serde_json::from_value::<RouteStatistics>(stats_v.clone()) {
                            map.insert((route_id, ct), st);
                        }
                    }
                }
            }
            (map, metrics)
        };

        // Clean up old statistics
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let max_age_secs = self.config.max_stats_age.as_secs();
        let cleaned_stats: HashMap<_, _> = statistics
            .into_iter()
            .filter(|(_, stats)| now.saturating_sub(stats.last_updated) < max_age_secs)
            .collect();

        *self.statistics.write().await = cleaned_stats;
        *self.metrics.write().await = metrics;

        tracing::info!(
            "Loaded {} route statistics from disk",
            self.statistics.read().await.len()
        );
        Ok(())
    }

    /// Persist statistics to disk (static version for spawning)
    async fn persist_statistics_static(
        path: &Path,
        statistics: &HashMap<(RouteId, ContentType), RouteStatistics>,
        metrics: &MABMetrics,
    ) -> Result<()> {
        let stats_path = path.join("mab_statistics.json");

        // Create directory if it doesn't exist
        if let Some(parent) = stats_path.parent() {
            fs::create_dir_all(parent).await.map_err(P2PError::Io)?;
        }

        // New format: serialize with string keys for portability
        let export_stats: Vec<serde_json::Value> = statistics
            .iter()
            .map(|((rid, ct), st)| {
                let node_hex = hex::encode(rid.node_id.as_bytes());
                serde_json::json!({
                    "route_id": {"node_id": node_hex, "strategy": format!("{:?}", rid.strategy)},
                    "content_type": format!("{:?}", ct),
                    "stats": st,
                })
            })
            .collect();

        let export = serde_json::json!({
            "statistics": export_stats,
            "metrics": metrics,
        });

        let data = serde_json::to_string_pretty(&export).map_err(|e| {
            P2PError::Storage(crate::error::StorageError::Database(
                format!("Failed to serialize statistics: {}", e).into(),
            ))
        })?;

        fs::write(&stats_path, data).await.map_err(P2PError::Io)?;

        Ok(())
    }

    /// Manually trigger persistence
    pub async fn persist(&self) -> Result<()> {
        if let Some(ref path) = self.config.storage_path {
            let statistics = self.statistics.read().await.clone();
            let metrics = self.metrics.read().await.clone();
            Self::persist_statistics_static(path, &statistics, &metrics).await?;
            *self.last_persist.write().await = Instant::now();
        }
        Ok(())
    }
}

/// Trait for integrating MAB with routing systems
#[async_trait]
pub trait MABRoutingStrategy: Send + Sync {
    /// Select route using MAB optimization
    async fn select_mab_route(
        &self,
        destination: &NodeId,
        content_type: ContentType,
    ) -> Result<RouteDecision>;

    /// Update MAB with routing outcome
    async fn update_mab_outcome(
        &self,
        route_id: &RouteId,
        content_type: ContentType,
        outcome: &Outcome,
    ) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_mab() -> MultiArmedBandit {
        let config = MABConfig {
            epsilon: 0.1,
            min_samples: 5,
            decay_factor: 0.95,
            storage_path: None,
            persist_interval: Duration::from_secs(60),
            max_stats_age: Duration::from_secs(3600),
        };
        MultiArmedBandit::new(config).await.unwrap()
    }

    #[tokio::test]
    async fn test_mab_creation() {
        let mab = create_test_mab().await;
        let metrics = mab.get_metrics().await;
        assert_eq!(metrics.total_decisions, 0);
        assert_eq!(metrics.exploration_decisions, 0);
    }

    #[tokio::test]
    async fn test_route_selection() {
        let mab = create_test_mab().await;
        let destination = NodeId::from_bytes([1u8; 32]);
        let strategies = vec![
            StrategyChoice::Kademlia,
            StrategyChoice::Hyperbolic,
            StrategyChoice::TrustPath,
        ];

        let decision = mab
            .select_route(&destination, ContentType::DHTLookup, &strategies)
            .await
            .unwrap();

        assert!(decision.probability >= 0.0 && decision.probability <= 1.0);
        assert!(strategies.contains(&decision.route_id.strategy));
    }

    #[tokio::test]
    async fn test_route_update() {
        let mab = create_test_mab().await;
        let route_id = RouteId::new(NodeId::from_bytes([1u8; 32]), StrategyChoice::Kademlia);

        // Update with success
        let outcome = Outcome {
            success: true,
            latency_ms: 50,
            hops: 3,
        };

        mab.update_route(&route_id, ContentType::DHTLookup, &outcome)
            .await
            .unwrap();

        let stats = mab.get_all_statistics().await;
        let key = (route_id.clone(), ContentType::DHTLookup);
        assert!(stats.contains_key(&key));
        assert_eq!(stats[&key].successes, 1);
        assert_eq!(stats[&key].attempts, 1);
    }

    #[tokio::test]
    async fn test_thompson_sampling_convergence() {
        let mab = create_test_mab().await;
        let destination = NodeId::from_bytes([1u8; 32]);
        let strategies = vec![StrategyChoice::Kademlia, StrategyChoice::Hyperbolic];

        // Simulate Kademlia being better (80% success rate)
        for _ in 0..100 {
            let route_id = RouteId::new(destination.clone(), StrategyChoice::Kademlia);
            let success = rand::random::<f64>() < 0.8;
            let outcome = Outcome {
                success,
                latency_ms: 50,
                hops: 3,
            };
            mab.update_route(&route_id, ContentType::DHTLookup, &outcome)
                .await
                .unwrap();
        }

        // Simulate Hyperbolic being worse (30% success rate)
        for _ in 0..100 {
            let route_id = RouteId::new(destination.clone(), StrategyChoice::Hyperbolic);
            let success = rand::random::<f64>() < 0.3;
            let outcome = Outcome {
                success,
                latency_ms: 100,
                hops: 5,
            };
            mab.update_route(&route_id, ContentType::DHTLookup, &outcome)
                .await
                .unwrap();
        }

        // Now check that Kademlia is selected more often
        let mut kademlia_selections = 0;
        for _ in 0..100 {
            let decision = mab
                .select_route(&destination, ContentType::DHTLookup, &strategies)
                .await
                .unwrap();

            if decision.route_id.strategy == StrategyChoice::Kademlia && !decision.exploration {
                kademlia_selections += 1;
            }
        }

        // Should select Kademlia most of the time (accounting for exploration)
        assert!(kademlia_selections > 70);
    }

    #[tokio::test]
    async fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let config = MABConfig {
            epsilon: 0.1,
            min_samples: 5,
            decay_factor: 0.95,
            storage_path: Some(temp_dir.path().to_path_buf()),
            persist_interval: Duration::from_secs(60),
            max_stats_age: Duration::from_secs(3600),
        };

        let mab = MultiArmedBandit::new(config.clone()).await.unwrap();

        // Add some statistics
        let route_id = RouteId::new(NodeId::from_bytes([1u8; 32]), StrategyChoice::Kademlia);
        let outcome = Outcome {
            success: true,
            latency_ms: 50,
            hops: 3,
        };
        mab.update_route(&route_id, ContentType::DHTLookup, &outcome)
            .await
            .unwrap();

        // Manually persist
        mab.persist().await.unwrap();

        // Create new instance and verify it loads the data
        let mab2 = MultiArmedBandit::new(config).await.unwrap();
        let stats = mab2.get_all_statistics().await;
        assert!(!stats.is_empty());
        assert_eq!(stats[&(route_id, ContentType::DHTLookup)].successes, 1);
    }

    #[tokio::test]
    async fn test_confidence_intervals() {
        let mab = create_test_mab().await;
        let route_id = RouteId::new(NodeId::from_bytes([1u8; 32]), StrategyChoice::Kademlia);

        // Initially, confidence interval should be wide (high uncertainty)
        let (lower, upper) = mab
            .get_route_confidence(&route_id, ContentType::DHTLookup)
            .await
            .unwrap();
        assert_eq!((lower, upper), (0.0, 1.0));

        // Add some successes
        for _ in 0..10 {
            let outcome = Outcome {
                success: true,
                latency_ms: 50,
                hops: 3,
            };
            mab.update_route(&route_id, ContentType::DHTLookup, &outcome)
                .await
                .unwrap();
        }

        // Confidence interval should be narrower and higher
        let (lower, upper) = mab
            .get_route_confidence(&route_id, ContentType::DHTLookup)
            .await
            .unwrap();
        assert!(lower > 0.5);
        assert!(upper > lower);
        assert!(upper <= 1.0);
    }
}
