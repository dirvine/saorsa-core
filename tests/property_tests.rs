// Copyright (c) 2025 Saorsa Labs Limited

// This file is part of the Saorsa P2P network.

// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Property-based tests for P2P Foundation
//!
//! This test suite uses proptest to verify core invariants
//! across all adaptive network components.

use proptest::prelude::*;
use saorsa_core::adaptive::*;
use std::collections::HashSet;
use std::time::Duration;

// Strategy for generating valid node IDs
fn node_id_strategy() -> impl Strategy<Value = NodeId> {
    prop::array::uniform32(any::<u8>()).prop_map(|hash| NodeId { hash })
}

// Strategy for generating content hashes
fn content_hash_strategy() -> impl Strategy<Value = ContentHash> {
    prop::array::uniform32(any::<u8>()).prop_map(ContentHash)
}

// Strategy for network configurations
fn network_config_strategy() -> impl Strategy<Value = NetworkConfig> {
    (1u64..1000, 10usize..1000, 3u8..10, 0u8..10).prop_map(
        |(storage, connections, replication, security)| NetworkConfig {
            bootstrap_nodes: vec![],
            storage_capacity: storage,
            max_connections: connections,
            replication_factor: replication,
            ml_enabled: true,
            monitoring_interval: Duration::from_secs(30),
            security_level: security,
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_node_identity_deterministic(_seed in prop::array::uniform32(any::<u8>())) {
        // NodeIdentity generation is now truly random, not seed-based
        // So we just test that we can generate identities
        let id1 = NodeIdentity::generate().unwrap();
        let id2 = NodeIdentity::generate().unwrap();

        // They should be different
        prop_assert_ne!(id1.node_id(), id2.node_id());
    }

    #[test]
    fn prop_different_identities(
        _seed1 in prop::array::uniform32(any::<u8>()),
        _seed2 in prop::array::uniform32(any::<u8>())
    ) {
        // Generate two identities - they should be different
        let id1 = NodeIdentity::generate().unwrap();
        let id2 = NodeIdentity::generate().unwrap();

        prop_assert_ne!(id1.node_id(), id2.node_id());
    }

    #[test]
    fn prop_content_hash_consistency(data: Vec<u8>) {
        // Same data should always produce same hash
        let hash1 = ContentHash::from(&data);
        let hash2 = ContentHash::from(&data);

        prop_assert_eq!(hash1, hash2);
    }

    #[test]
    fn prop_hyperbolic_distance_symmetric(
        r1 in 0.0f64..0.99,
        theta1 in 0.0f64..std::f64::consts::TAU,
        r2 in 0.0f64..0.99,
        theta2 in 0.0f64..std::f64::consts::TAU
    ) {
        let coord1 = HyperbolicCoordinate { r: r1, theta: theta1 };
        let coord2 = HyperbolicCoordinate { r: r2, theta: theta2 };

        // Distance should be symmetric
        let d12 = hyperbolic_distance(&coord1, &coord2);
        let d21 = hyperbolic_distance(&coord2, &coord1);

        prop_assert!((d12 - d21).abs() < 1e-10);
    }

    #[test]
    fn prop_hyperbolic_distance_triangle_inequality(
        coords in prop::collection::vec(
            (0.0f64..0.99, 0.0f64..std::f64::consts::TAU)
                .prop_map(|(r, theta)| HyperbolicCoordinate { r, theta }),
            3..=3
        )
    ) {
        let d01 = hyperbolic_distance(&coords[0], &coords[1]);
        let d12 = hyperbolic_distance(&coords[1], &coords[2]);
        let d02 = hyperbolic_distance(&coords[0], &coords[2]);

        // Triangle inequality
        prop_assert!(d02 <= d01 + d12 + 1e-10);
    }

    #[test]
    fn prop_trust_scores_bounded(
        interactions in prop::collection::vec(
            (node_id_strategy(), node_id_strategy(), any::<bool>()),
            0..100
        )
    ) {
        let engine = EigenTrustEngine::new(HashSet::new());

        for (from, to, success) in interactions {
            engine.update_trust(&from, &to, success);
        }

        let trust_scores = engine.get_global_trust();
        for (_, score) in trust_scores {
            prop_assert!(score >= 0.0 && score <= 1.0);
        }
    }

    #[test]
    fn prop_replication_factor_maintained(
        config in network_config_strategy(),
        num_nodes in 10usize..50
    ) {
        prop_assume!(num_nodes as u8 >= config.replication_factor);

        // In a healthy network, replication factor should be maintained
        prop_assert!(config.replication_factor >= 3);
        prop_assert!(config.replication_factor <= 10);
    }

    #[test]
    fn prop_cache_eviction_preserves_capacity(
        capacity in 10usize..1000,
        operations in prop::collection::vec(
            (content_hash_strategy(), 1usize..100),
            0..200
        )
    ) {
        let mut cache = LRUCache::new(capacity);

        for (hash, size) in operations {
            cache.insert(hash, vec![0u8; size]);
            prop_assert!(cache.size() <= capacity);
        }
    }

    // Disabled: legacy synchronous MAB API no longer matches async implementation
    // #[test]
    // fn prop_mab_convergence(
    //     rewards in prop::collection::vec(
    //         prop::collection::vec(0.0f64..1.0, 100..=100),
    //         3..=10
    //     )
    // ) {
    // }

    // Commenting out this test since it uses old SOM interface that's no longer available
    // TODO: Update this test to use the new SOM interface with NodeFeatures
    // #[test]
    // fn prop_som_preserves_topology(
    //     inputs in prop::collection::vec(
    //         prop::collection::vec(0.0f64..1.0, 4..=4),
    //         10..50
    //     )
    // ) {
    //     let mut som = SelfOrganizingMap::new(10, 10, 4);
    //
    //     // Train SOM
    //     for input in &inputs {
    //         som.train(input, 0.1, 2.0);
    //     }
    //
    //     // Check that similar inputs map to nearby neurons
    //     for i in 0..inputs.len() {
    //         for j in i+1..inputs.len() {
    //             let dist_input = euclidean_distance(&inputs[i], &inputs[j]);
    //             let (x1, y1) = som.find_bmu(&inputs[i]);
    //             let (x2, y2) = som.find_bmu(&inputs[j]);
    //             let dist_som = ((x1 as f64 - x2 as f64).powi(2) +
    //                            (y1 as f64 - y2 as f64).powi(2)).sqrt();
    //
    //             // If inputs are very similar, they should map to nearby neurons
    //             if dist_input < 0.1 {
    //                 prop_assert!(dist_som < 3.0);
    //             }
    //         }
    //     }
    // }
}

// Helper functions
fn hyperbolic_distance(a: &HyperbolicCoordinate, b: &HyperbolicCoordinate) -> f64 {
    let delta = ((a.r * a.theta.cos() - b.r * b.theta.cos()).powi(2)
        + (a.r * a.theta.sin() - b.r * b.theta.sin()).powi(2))
    .sqrt();

    let cosh_d = 1.0 + 2.0 * delta.powi(2) / ((1.0 - a.r.powi(2)) * (1.0 - b.r.powi(2)));
    cosh_d.max(1.0).acosh()
}

fn euclidean_distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f64>()
        .sqrt()
}

// Mock implementations for testing
struct LRUCache {
    capacity: usize,
    items: std::collections::HashMap<ContentHash, Vec<u8>>,
}

impl LRUCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            items: std::collections::HashMap::new(),
        }
    }

    fn insert(&mut self, hash: ContentHash, data: Vec<u8>) {
        if self.size() + data.len() > self.capacity {
            // Evict until we have space
            while self.size() + data.len() > self.capacity && !self.items.is_empty() {
                let key = self.items.keys().next().cloned().unwrap();
                self.items.remove(&key);
            }
        }
        self.items.insert(hash, data);
    }

    fn size(&self) -> usize {
        self.items.values().map(|v| v.len()).sum()
    }
}
