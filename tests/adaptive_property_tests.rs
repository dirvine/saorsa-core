//! Property-based tests for adaptive components aligned with current APIs
#![cfg(feature = "adaptive-ml")]

use proptest::prelude::*;
use saorsa_core::adaptive::q_learning_cache::{CacheStatistics, StateVector};
use saorsa_core::adaptive::{HyperbolicCoordinate, HyperbolicSpace};

proptest! {
    #[test]
    fn prop_statevector_bucket_ranges(
        utilization in 0.0f64..1.0,
        frequency in 0.0f64..1000.0,
        recency in 0u64..1_000_000u64,
        size in 0u64..(50u64*1024*1024),
    ) {
        let s = StateVector::from_metrics(utilization, frequency, recency, size);
        prop_assert!(s.utilization_bucket <= 10);
        prop_assert!(s.frequency_bucket <= 5);
        prop_assert!(s.recency_bucket <= 5);
        prop_assert!(s.content_size_bucket <= 4);
    }

    #[test]
    fn prop_cache_hit_rate_is_bounded(hits in 0u64..10_000u64, misses in 0u64..10_000u64) {
        let stats = CacheStatistics {
            hits,
            misses,
            ..Default::default()
        };
        let rate = stats.hit_rate();
        prop_assert!((0.0..=1.0).contains(&rate));
        if hits == 0 && misses == 0 { prop_assert!(rate == 0.0); }
    }

    #[test]
    fn prop_hyperbolic_distance_properties(r in 0.0f64..0.99, theta in 0.0f64..(2.0*std::f64::consts::PI), r2 in 0.0f64..0.99, theta2 in 0.0f64..(2.0*std::f64::consts::PI)) {
        let a = HyperbolicCoordinate { r, theta };
        let b = HyperbolicCoordinate { r: r2, theta: theta2 };
        let d_ab = HyperbolicSpace::distance(&a, &b);
        let d_ba = HyperbolicSpace::distance(&b, &a);
        prop_assert!(d_ab >= 0.0);
        // Symmetry within a small epsilon
        prop_assert!((d_ab - d_ba).abs() < 1e-9);
        // Identity of indiscernibles
        let d_aa = HyperbolicSpace::distance(&a, &a);
        prop_assert!(d_aa.abs() < 1e-9);
    }
}
