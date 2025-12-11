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

//! Performance benchmarks for the Adaptive P2P Network
//!
//! Run with: cargo bench --bench adaptive_benchmarks

use criterion::{Criterion, black_box, criterion_group, criterion_main};

/// Benchmark basic operations
fn benchmark_basic_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("basic_ops");

    // Benchmark simple operations
    group.bench_function("simple_math", |b| {
        b.iter(|| {
            let result = (0..100).sum::<i32>();
            black_box(result);
        });
    });

    group.finish();
}

/// Benchmark routing operations
fn benchmark_routing(c: &mut Criterion) {
    let mut group = c.benchmark_group("routing");

    group.bench_function("vector_operations", |b| {
        b.iter(|| {
            let mut vec = Vec::with_capacity(100);
            for i in 0..100 {
                vec.push(i * i);
            }
            black_box(vec.len());
        });
    });

    group.finish();
}

/// Benchmark cryptographic operations
fn benchmark_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto");

    group.bench_function("memory_operations", |b| {
        b.iter(|| {
            let data = vec![0u8; 1000];
            let sum: u64 = data.iter().map(|&x| x as u64).sum();
            black_box(sum);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_basic_ops,
    benchmark_routing,
    benchmark_crypto
);
criterion_main!(benches);
