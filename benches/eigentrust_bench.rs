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

//! EigenTrust Performance Benchmarks
//!
//! Benchmarks for EigenTrust++ trust computation and reputation management.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use saorsa_core::adaptive::{TrustProvider, trust::MockTrustProvider};
use saorsa_core::peer_record::UserId;
use std::sync::Arc;

// Type alias for clarity
type NodeId = UserId;

/// Benchmark trust computation operations
fn bench_trust_computation(c: &mut Criterion) {
    let mut group = c.benchmark_group("trust_computation");

    // Benchmark trust score calculation
    group.bench_function("trust_score_calculation", |b| {
        let trust_provider = Arc::new(MockTrustProvider::new());
        let node_id = create_test_node_id([42u8; 32]);

        b.iter(|| {
            let score = trust_provider.get_trust(&node_id);
            black_box(score);
        });
    });

    // Benchmark trust updates
    group.bench_function("trust_update", |b| {
        let trust_provider = Arc::new(MockTrustProvider::new());
        let from = create_test_node_id([1u8; 32]);
        let to = create_test_node_id([2u8; 32]);

        b.iter(|| {
            trust_provider.update_trust(&from, &to, true);
            black_box(());
        });
    });

    group.finish();
}

/// Benchmark trust provider operations
fn bench_trust_provider(c: &mut Criterion) {
    let mut group = c.benchmark_group("trust_provider");

    group.bench_function("provider_creation", |b| {
        b.iter(|| {
            let provider = MockTrustProvider::new();
            black_box(provider);
        });
    });

    group.bench_function("global_trust_retrieval", |b| {
        let trust_provider = Arc::new(MockTrustProvider::new());

        b.iter(|| {
            let global_trust = trust_provider.get_global_trust();
            black_box(global_trust);
        });
    });

    group.finish();
}

/// Create a test NodeId from bytes
fn create_test_node_id(bytes: [u8; 32]) -> NodeId {
    UserId::from_bytes(bytes)
}

criterion_group!(benches, bench_trust_computation, bench_trust_provider);
criterion_main!(benches);
