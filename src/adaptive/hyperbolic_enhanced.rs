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

//! Enhanced hyperbolic geometry routing with fixed-point arithmetic and visualization
//!
//! This module implements improvements to the hyperbolic routing layer:
//! - Fixed-point arithmetic for improved precision
//! - Hysteresis in coordinate adjustment to prevent oscillation
//! - Visualization support for debugging
//! - Enhanced distance calculations

use super::*;
use crate::adaptive::hyperbolic::{RoutingStats, angle_difference};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Fixed-point arithmetic precision (number of decimal places)
const FIXED_POINT_SCALE: i64 = 1_000_000; // 6 decimal places

/// Hysteresis parameters for coordinate adjustment
const HYSTERESIS_THRESHOLD: f64 = 0.001;
const HYSTERESIS_DAMPING: f64 = 0.8;

/// Enhanced hyperbolic coordinate with fixed-point support
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EnhancedHyperbolicCoordinate {
    /// Radial coordinate in fixed-point representation
    r_fixed: i64,
    /// Angular coordinate in fixed-point representation
    theta_fixed: i64,
}

impl EnhancedHyperbolicCoordinate {
    /// Create from floating point coordinates
    pub fn from_float(r: f64, theta: f64) -> Self {
        Self {
            r_fixed: (r * FIXED_POINT_SCALE as f64) as i64,
            theta_fixed: (theta * FIXED_POINT_SCALE as f64) as i64,
        }
    }

    /// Get radial coordinate as float
    pub fn r(&self) -> f64 {
        self.r_fixed as f64 / FIXED_POINT_SCALE as f64
    }

    /// Get angular coordinate as float
    pub fn theta(&self) -> f64 {
        self.theta_fixed as f64 / FIXED_POINT_SCALE as f64
    }

    /// Set radial coordinate from float
    pub fn set_r(&mut self, r: f64) {
        self.r_fixed = (r * FIXED_POINT_SCALE as f64) as i64;
    }

    /// Set angular coordinate from float
    pub fn set_theta(&mut self, theta: f64) {
        self.theta_fixed = (theta * FIXED_POINT_SCALE as f64) as i64;
    }
}

/// Enhanced hyperbolic space with visualization support
pub struct EnhancedHyperbolicSpace {
    /// Our node's current coordinate
    my_coordinate: RwLock<EnhancedHyperbolicCoordinate>,

    /// Previous coordinate for hysteresis
    previous_coordinate: RwLock<Option<EnhancedHyperbolicCoordinate>>,

    /// Neighbor coordinates
    neighbor_coordinates: Arc<RwLock<HashMap<NodeId, EnhancedHyperbolicCoordinate>>>,

    /// Coordinate adjustment parameters
    adjustment_params: AdjustmentParameters,

    /// Routing statistics
    _routing_stats: Arc<RwLock<RoutingStats>>,

    /// Visualization data
    visualization_data: Arc<RwLock<VisualizationData>>,
}

/// Parameters for coordinate adjustment with hysteresis
#[derive(Debug, Clone)]
pub struct AdjustmentParameters {
    /// Base adjustment rate
    base_rate: f64,
    /// Current adjustment rate (with hysteresis)
    current_rate: f64,
    /// Minimum adjustment rate
    min_rate: f64,
    /// Maximum adjustment rate
    max_rate: f64,
    /// Hysteresis factor
    hysteresis_factor: f64,
}

impl Default for AdjustmentParameters {
    fn default() -> Self {
        Self {
            base_rate: 0.01,
            current_rate: 0.01,
            min_rate: 0.001,
            max_rate: 0.1,
            hysteresis_factor: HYSTERESIS_DAMPING,
        }
    }
}

/// Data structure for visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualizationData {
    /// Node positions for visualization
    pub nodes: HashMap<NodeId, VisualizationNode>,
    /// Routing paths for visualization
    pub paths: Vec<RoutingPath>,
    /// Network metrics
    pub metrics: NetworkMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualizationNode {
    pub id: NodeId,
    pub coordinate: HyperbolicCoordinate,
    pub label: String,
    pub degree: usize,
    pub trust_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingPath {
    pub source: NodeId,
    pub target: NodeId,
    pub hops: Vec<NodeId>,
    pub success: bool,
    pub total_distance: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub total_nodes: usize,
    pub average_degree: f64,
    pub clustering_coefficient: f64,
    pub average_path_length: f64,
}

impl EnhancedHyperbolicSpace {
    /// Create a new enhanced hyperbolic space instance
    pub fn new() -> Self {
        let initial_r = 0.5;
        let initial_theta = rand::random::<f64>() * 2.0 * std::f64::consts::PI;

        Self {
            my_coordinate: RwLock::new(EnhancedHyperbolicCoordinate::from_float(
                initial_r,
                initial_theta,
            )),
            previous_coordinate: RwLock::new(None),
            neighbor_coordinates: Arc::new(RwLock::new(HashMap::new())),
            adjustment_params: AdjustmentParameters::default(),
            _routing_stats: Arc::new(RwLock::new(RoutingStats::default())),
            visualization_data: Arc::new(RwLock::new(VisualizationData {
                nodes: HashMap::new(),
                paths: Vec::new(),
                metrics: NetworkMetrics {
                    total_nodes: 0,
                    average_degree: 0.0,
                    clustering_coefficient: 0.0,
                    average_path_length: 0.0,
                },
            })),
        }
    }

    /// Calculate hyperbolic distance with improved precision
    pub fn distance_fixed(
        a: &EnhancedHyperbolicCoordinate,
        b: &EnhancedHyperbolicCoordinate,
    ) -> f64 {
        let r1 = a.r();
        let r2 = b.r();
        let theta1 = a.theta();
        let theta2 = b.theta();

        // Use improved distance formula for Poincaré disk
        let cos_angle_diff = (theta1 - theta2).cos();

        // Handle edge cases near the boundary
        if r1 > 0.999 || r2 > 0.999 {
            return f64::INFINITY;
        }

        // Compute distance using more stable formula
        let numerator = (r1 - r2).powi(2) + 4.0 * r1 * r2 * (1.0 - cos_angle_diff);
        let denominator = (1.0 - r1.powi(2)) * (1.0 - r2.powi(2));

        if denominator <= 0.0 {
            return f64::INFINITY;
        }

        let cosh_dist = 1.0 + numerator / denominator;
        cosh_dist.acosh()
    }

    /// Adjust coordinate with hysteresis to prevent oscillation
    pub async fn adjust_coordinate_with_hysteresis(
        &self,
        neighbor_coords: &[(NodeId, EnhancedHyperbolicCoordinate)],
    ) {
        let mut my_coord = self.my_coordinate.write().await;
        let mut prev_coord_guard = self.previous_coordinate.write().await;

        // Calculate target position
        let degree = neighbor_coords.len();
        let target_r = 1.0 - (2.0 / (degree as f64 + 2.0));

        // Calculate angular adjustment with circular mean
        let (sin_sum, cos_sum) =
            neighbor_coords
                .iter()
                .fold((0.0, 0.0), |(sin_acc, cos_acc), (_, coord)| {
                    let theta = coord.theta();
                    (sin_acc + theta.sin(), cos_acc + theta.cos())
                });

        let target_theta = sin_sum.atan2(cos_sum);

        // Apply hysteresis based on previous movement
        let mut params = self.adjustment_params.clone();

        if let Some(prev_coord) = prev_coord_guard.as_ref() {
            let prev_movement = Self::distance_fixed(&my_coord, prev_coord);

            // Adjust rate based on movement magnitude
            if prev_movement < HYSTERESIS_THRESHOLD {
                // Small movement - increase damping
                params.current_rate *= params.hysteresis_factor;
            } else {
                // Large movement - allow faster adjustment
                params.current_rate = params.base_rate;
            }

            // Clamp rate to bounds
            params.current_rate = params.current_rate.clamp(params.min_rate, params.max_rate);
        }

        // Store current position as previous
        *prev_coord_guard = Some(*my_coord);

        // Apply adjustments with hysteresis
        let current_r = my_coord.r();
        let current_theta = my_coord.theta();

        let new_r = current_r + params.current_rate * (target_r - current_r);
        let angle_diff = angle_difference(target_theta, current_theta);
        let new_theta = current_theta + params.current_rate * angle_diff;

        // Update coordinate with bounds checking
        my_coord.set_r(new_r.clamp(0.0, 0.999));

        // Normalize theta to [0, 2π)
        let normalized_theta = if new_theta < 0.0 {
            new_theta + 2.0 * std::f64::consts::PI
        } else if new_theta >= 2.0 * std::f64::consts::PI {
            new_theta - 2.0 * std::f64::consts::PI
        } else {
            new_theta
        };

        my_coord.set_theta(normalized_theta);
    }

    /// Update visualization data
    pub async fn update_visualization(&self) {
        let neighbors = self.neighbor_coordinates.read().await;
        let mut viz_data = self.visualization_data.write().await;

        // Clear old data
        viz_data.nodes.clear();

        // Add our node
        let my_coord = self.my_coordinate.read().await;
        let my_id = generate_local_node_id(); // Placeholder

        viz_data.nodes.insert(
            my_id.clone(),
            VisualizationNode {
                id: my_id.clone(),
                coordinate: HyperbolicCoordinate {
                    r: my_coord.r(),
                    theta: my_coord.theta(),
                },
                label: "Local Node".to_string(),
                degree: neighbors.len(),
                trust_score: 1.0,
            },
        );

        // Add neighbor nodes
        for (node_id, coord) in neighbors.iter() {
            viz_data.nodes.insert(
                node_id.clone(),
                VisualizationNode {
                    id: node_id.clone(),
                    coordinate: HyperbolicCoordinate {
                        r: coord.r(),
                        theta: coord.theta(),
                    },
                    label: format!("Node {:?}", node_id).into(),
                    degree: 0,        // Unknown for neighbors
                    trust_score: 0.5, // Default
                },
            );
        }

        // Update metrics
        viz_data.metrics.total_nodes = viz_data.nodes.len();
        viz_data.metrics.average_degree = neighbors.len() as f64;
    }

    /// Export visualization data as JSON
    pub async fn export_visualization_json(&self) -> Result<String> {
        let viz_data = self.visualization_data.read().await;
        serde_json::to_string_pretty(&*viz_data).map_err(|e| {
            AdaptiveNetworkError::Other(format!("Failed to serialize visualization: {}", e).into())
        })
    }

    /// Export visualization as SVG
    pub async fn export_visualization_svg(&self) -> Result<String> {
        let viz_data = self.visualization_data.read().await;
        let mut svg = String::new();

        // SVG header
        svg.push_str(
            r#"<svg width="800" height="800" xmlns="http://www.w3.org/2000/svg">
            <circle cx="400" cy="400" r="380" fill="none" stroke="black" stroke-width="2"/>
        "#,
        );

        // Draw nodes
        for (_, node) in &viz_data.nodes {
            let (x, y) = polar_to_cartesian(
                node.coordinate.r,
                node.coordinate.theta,
                400.0,
                400.0,
                380.0,
            );
            svg.push_str(&format!(
                r#"<circle cx="{}" cy="{}" r="5" fill="blue" stroke="black" stroke-width="1"/>"#,
                x, y
            ));
        }

        // Draw paths
        for path in &viz_data.paths {
            if let (Some(source), Some(target)) = (
                viz_data.nodes.get(&path.source),
                viz_data.nodes.get(&path.target),
            ) {
                let (x1, y1) = polar_to_cartesian(
                    source.coordinate.r,
                    source.coordinate.theta,
                    400.0,
                    400.0,
                    380.0,
                );
                let (x2, y2) = polar_to_cartesian(
                    target.coordinate.r,
                    target.coordinate.theta,
                    400.0,
                    400.0,
                    380.0,
                );

                let color = if path.success { "green" } else { "red" };
                svg.push_str(&format!(
                    r#"<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="2" opacity="0.5"/>"#,
                    x1, y1, x2, y2, color
                ));
            }
        }

        svg.push_str("</svg>");
        Ok(svg)
    }
}

/// Convert polar coordinates to Cartesian for visualization
fn polar_to_cartesian(r: f64, theta: f64, cx: f64, cy: f64, radius: f64) -> (f64, f64) {
    let x = cx + r * radius * theta.cos();
    let y = cy + r * radius * theta.sin();
    (x, y)
}

/// Generate a placeholder local node ID
fn generate_local_node_id() -> NodeId {
    use rand::RngCore;
    let mut hash = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut hash);
    NodeId::from_bytes(hash)
}

/// Enhanced routing strategy with visualization support
pub struct EnhancedHyperbolicRoutingStrategy {
    /// The enhanced hyperbolic space manager
    space: Arc<EnhancedHyperbolicSpace>,

    /// Local node ID
    local_id: NodeId,

    /// Maximum hops before declaring failure
    max_hops: usize,

    /// Enable visualization recording
    enable_visualization: bool,
}

impl EnhancedHyperbolicRoutingStrategy {
    /// Create a new enhanced routing strategy
    pub fn new(local_id: NodeId, space: Arc<EnhancedHyperbolicSpace>) -> Self {
        Self {
            space,
            local_id,
            max_hops: 10,
            enable_visualization: true,
        }
    }

    /// Find path with visualization support
    async fn find_enhanced_path(&self, target: &NodeId) -> Result<Vec<NodeId>> {
        let target_coord = {
            let neighbors = self.space.neighbor_coordinates.read().await;
            neighbors.get(target).cloned()
        };

        let target_coord = match target_coord {
            Some(coord) => coord,
            None => {
                return Err(AdaptiveNetworkError::Routing(
                    "Target coordinate unknown".to_string(),
                ));
            }
        };

        let mut path = Vec::new();
        let mut visited = std::collections::HashSet::<NodeId>::new();
        visited.insert(self.local_id.clone());

        let mut total_distance = 0.0;
        let _start_time = std::time::Instant::now();

        // Greedy routing with visualization
        for hop in 0..self.max_hops {
            let my_coord = self.space.my_coordinate.read().await;
            let my_distance = EnhancedHyperbolicSpace::distance_fixed(&my_coord, &target_coord);

            let neighbors = self.space.neighbor_coordinates.read().await;
            let next_hop = neighbors
                .iter()
                .filter(|(id, _)| !visited.contains(id))
                .filter(|(_, coord)| {
                    EnhancedHyperbolicSpace::distance_fixed(coord, &target_coord) < my_distance
                })
                .min_by(|(_, a), (_, b)| {
                    let dist_a = EnhancedHyperbolicSpace::distance_fixed(a, &target_coord);
                    let dist_b = EnhancedHyperbolicSpace::distance_fixed(b, &target_coord);
                    dist_a
                        .partial_cmp(&dist_b)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|(id, coord)| (id.clone(), *coord));

            match next_hop {
                Some((next_id, next_coord)) => {
                    if next_id == *target {
                        // Reached target
                        path.push(next_id);
                        total_distance +=
                            EnhancedHyperbolicSpace::distance_fixed(&my_coord, &next_coord);

                        // Record successful path for visualization
                        if self.enable_visualization {
                            let mut viz_data = self.space.visualization_data.write().await;
                            viz_data.paths.push(RoutingPath {
                                source: self.local_id.clone(),
                                target: target.clone(),
                                hops: path.clone(),
                                success: true,
                                total_distance,
                            });
                        }

                        return Ok(path);
                    }

                    path.push(next_id.clone());
                    visited.insert(next_id);
                    total_distance +=
                        EnhancedHyperbolicSpace::distance_fixed(&my_coord, &next_coord);
                }
                None => {
                    // No closer neighbor found
                    if self.enable_visualization {
                        let mut viz_data = self.space.visualization_data.write().await;
                        viz_data.paths.push(RoutingPath {
                            source: self.local_id.clone(),
                            target: target.clone(),
                            hops: path.clone(),
                            success: false,
                            total_distance,
                        });
                    }

                    return Err(AdaptiveNetworkError::Routing(
                        format!("No closer neighbor found after {} hops", hop).into(),
                    ));
                }
            }
        }

        // Max hops exceeded
        Err(AdaptiveNetworkError::Routing(
            "Maximum hop count exceeded".to_string(),
        ))
    }
}

#[async_trait]
impl RoutingStrategy for EnhancedHyperbolicRoutingStrategy {
    async fn find_path(&self, target: &NodeId) -> Result<Vec<NodeId>> {
        self.find_enhanced_path(target).await
    }

    fn route_score(&self, _neighbor: &NodeId, _target: &NodeId) -> f64 {
        0.5
    }

    fn update_metrics(&mut self, _path: &[NodeId], _success: bool) {
        // Metrics are updated in find_enhanced_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_point_conversion() {
        let coord = EnhancedHyperbolicCoordinate::from_float(0.5, std::f64::consts::PI);
        assert!((coord.r() - 0.5).abs() < 1e-6);
        assert!((coord.theta() - std::f64::consts::PI).abs() < 1e-6);
    }

    #[test]
    fn test_enhanced_distance_calculation() {
        let a = EnhancedHyperbolicCoordinate::from_float(0.0, 0.0);
        let b = EnhancedHyperbolicCoordinate::from_float(0.5, std::f64::consts::PI);

        let dist = EnhancedHyperbolicSpace::distance_fixed(&a, &b);
        assert!(dist > 0.0);
        assert!(dist.is_finite());

        // Test boundary behavior
        let boundary = EnhancedHyperbolicCoordinate::from_float(0.9999, 0.0);
        let dist_boundary = EnhancedHyperbolicSpace::distance_fixed(&a, &boundary);
        assert!(dist_boundary > 5.0); // Should be very large near boundary
    }

    #[tokio::test]
    async fn test_hysteresis_adjustment() {
        let space = EnhancedHyperbolicSpace::new();

        // Create test neighbors
        let neighbors = vec![
            (
                generate_local_node_id(),
                EnhancedHyperbolicCoordinate::from_float(0.8, 0.0),
            ),
            (
                generate_local_node_id(),
                EnhancedHyperbolicCoordinate::from_float(0.8, std::f64::consts::PI),
            ),
        ];

        // Perform multiple adjustments
        let mut movements = vec![];
        for _i in 0..10 {
            let coord_before = space.my_coordinate.read().await.clone();
            space.adjust_coordinate_with_hysteresis(&neighbors).await;
            let coord_after = space.my_coordinate.read().await.clone();

            let movement = EnhancedHyperbolicSpace::distance_fixed(&coord_before, &coord_after);
            movements.push(movement);

            // Small delay to simulate time passing
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        // Movements should decrease over time due to hysteresis
        for i in 1..movements.len() {
            assert!(movements[i] <= movements[i - 1] * 1.1); // Allow small increase due to randomness
        }
    }

    #[tokio::test]
    async fn test_visualization_export() {
        let space = Arc::new(EnhancedHyperbolicSpace::new());

        // Add some test nodes
        let mut neighbors = space.neighbor_coordinates.write().await;
        for i in 0..5 {
            let angle = (i as f64) * 2.0 * std::f64::consts::PI / 5.0;
            neighbors.insert(
                generate_local_node_id(),
                EnhancedHyperbolicCoordinate::from_float(0.5, angle),
            );
        }
        drop(neighbors);

        // Update visualization
        space.update_visualization().await;

        // Export as JSON
        let json = space.export_visualization_json().await.unwrap();
        assert!(json.contains("nodes"));
        assert!(json.contains("metrics"));

        // Export as SVG
        let svg = space.export_visualization_svg().await.unwrap();
        assert!(svg.contains("<svg"));
        assert!(svg.contains("<circle"));
    }
}
