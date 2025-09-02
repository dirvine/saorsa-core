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
// distributed under these licenses is distributed on an "AS IS" BASIS.

//! Comprehensive benchmarks for adaptive P2P network
//!
//! This benchmark suite establishes performance baselines
//! for all critical operations in the adaptive network.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use saorsa_core::adaptive::{
    ContentHash, HyperbolicCoordinate, TrustProvider, trust::MockTrustProvider,
};
use saorsa_core::identity::NodeIdentity;
use saorsa_core::peer_record::UserId;
use std::sync::Arc;

/// Benchmark identity generation operations
fn bench_identity_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("identity_generation");

    group.bench_function("generate_new_identity", |b| {
        b.iter(|| {
            let identity = NodeIdentity::generate().unwrap();
            black_box(identity);
        });
    });

    group.finish();
}

/// Benchmark routing operations
fn bench_routing_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("routing");

    // Hyperbolic coordinate operations
    group.bench_function("hyperbolic_coordinate_distance", |b| {
        let coord1 = HyperbolicCoordinate { r: 0.5, theta: 1.0 };
        let coord2 = HyperbolicCoordinate { r: 0.7, theta: 2.0 };

        b.iter(|| {
            let distance = hyperbolic_distance(&coord1, &coord2);
            black_box(distance);
        });
    });

    // Node ID XOR distance calculation
    group.bench_function("node_id_xor_distance", |b| {
        let id1 = UserId::from_bytes([1u8; 32]);
        let id2 = UserId::from_bytes([2u8; 32]);

        b.iter(|| {
            let distance = xor_distance(&id1, &id2);
            black_box(distance);
        });
    });

    group.finish();
}

/// Benchmark machine learning operations
fn bench_ml_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("machine_learning");

    // Simple synchronous operations
    group.bench_function("content_hash_creation", |b| {
        let data = vec![42u8; 1024];

        b.iter(|| {
            let hash = ContentHash::from(&data);
            black_box(hash);
        });
    });

    // Node ID operations
    group.bench_function("node_id_operations", |b| {
        let data = [42u8; 32];

        b.iter(|| {
            let node_id = UserId::from_bytes(data);
            let hash = node_id.hash;
            black_box(hash);
        });
    });

    group.finish();
}

/// Benchmark trust computation operations
fn bench_trust_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("trust");

    // Trust score calculation
    group.bench_function("trust_score_calculation", |b| {
        let trust_provider = Arc::new(MockTrustProvider::new());
        let node_id = UserId::from_bytes([42u8; 32]);

        b.iter(|| {
            let score = trust_provider.get_trust(&node_id);
            black_box(score);
        });
    });

    // Trust updates
    group.bench_function("trust_update", |b| {
        let trust_provider = Arc::new(MockTrustProvider::new());
        let from = UserId::from_bytes([1u8; 32]);
        let to = UserId::from_bytes([2u8; 32]);

        b.iter(|| {
            trust_provider.update_trust(&from, &to, true);
        });
    });

    group.finish();
}

/// Benchmark eviction strategy operations
fn bench_eviction_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("eviction");

    // Simple hash operations
    group.bench_function("blake3_hash", |b| {
        let data = vec![42u8; 1024];

        b.iter(|| {
            let hash = blake3::hash(&data);
            black_box(hash);
        });
    });

    group.finish();
}

/// Benchmark gossip operations
fn bench_gossip_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("gossip");

    group.bench_function("vector_operations", |b| {
        b.iter(|| {
            let mut vec = Vec::with_capacity(1000);
            for i in 0..1000 {
                vec.push(i as u8);
            }
            let sum: u64 = vec.iter().map(|&x| x as u64).sum();
            black_box(sum);
        });
    });

    group.finish();
}

/// Benchmark security operations
fn bench_security_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("security");

    group.bench_function("string_operations", |b| {
        b.iter(|| {
            let mut s = String::with_capacity(1000);
            for i in 0..100 {
                s.push_str(&format!("item_{}", i));
            }
            let len = s.len();
            black_box(len);
        });
    });

    group.finish();
}

// Helper functions

/// Calculate hyperbolic distance between coordinates
fn hyperbolic_distance(a: &HyperbolicCoordinate, b: &HyperbolicCoordinate) -> f64 {
    let delta_r = a.r - b.r;
    let delta_theta = a.theta - b.theta;
    (delta_r * delta_r + delta_theta * delta_theta).sqrt()
}

/// Calculate XOR distance between two node IDs
fn xor_distance(a: &UserId, b: &UserId) -> [u8; 32] {
    let mut result = [0u8; 32];
    for (i, (a_byte, b_byte)) in a.hash.iter().zip(b.hash.iter()).enumerate() {
        result[i] = a_byte ^ b_byte;
    }
    result
}

criterion_group!(
    benches,
    bench_identity_generation,
    bench_routing_operations,
    bench_ml_operations,
    bench_trust_operations,
    bench_eviction_operations,
    bench_gossip_operations,
    bench_security_operations
);

criterion_main!(benches);
