// Copyright 2024 Saorsa Labs Limited
//
#![allow(clippy::unwrap_used, clippy::expect_used)]
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

//! Security Module Performance Benchmarks
//!
//! Benchmarks for security features including cryptographic operations and peer ID generation.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use saorsa_core::peer_record::UserId;
use std::net::Ipv6Addr;

/// Benchmark cryptographic operations
fn crypto_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("cryptographic_operations");

    // Benchmark hash operations
    group.bench_function("blake3_hash", |b| {
        let data = vec![42u8; 1024];
        b.iter(|| {
            let hash = blake3::hash(black_box(&data));
            black_box(hash);
        });
    });

    // Benchmark peer ID generation
    group.bench_function("peer_id_generation", |b| {
        let data = vec![rand::random::<u8>(); 32];
        b.iter(|| {
            let peer_id = UserId::from_bytes(black_box(data.as_slice().try_into().unwrap()));
            black_box(peer_id);
        });
    });

    // Benchmark peer ID distance calculation
    group.bench_function("peer_id_distance", |b| {
        let id1 = UserId::from_bytes([1u8; 32]);
        let id2 = UserId::from_bytes([2u8; 32]);

        b.iter(|| {
            let distance = xor_distance(&id1, &id2);
            black_box(distance);
        });
    });

    group.finish();
}

/// Benchmark IPv6 operations
fn ipv6_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipv6_operations");

    // Benchmark IPv6 address parsing
    let test_ips = [
        "2001:db8:85a3::8a2e:370:7334",
        "2001:db8:85a3:1234:5678:8a2e:370:7334",
        "fe80::1234:5678:8a2e:370",
        "2001:db8::1",
        "::1",
    ];

    for (i, ip_str) in test_ips.iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("ipv6_parsing", i), ip_str, |b, ip_str| {
            b.iter(|| {
                let addr: Ipv6Addr = black_box(ip_str).parse().unwrap();
                black_box(addr);
            });
        });
    }

    group.finish();
}

/// Calculate XOR distance between two peer IDs
fn xor_distance(a: &UserId, b: &UserId) -> [u8; 32] {
    let mut result = [0u8; 32];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = a.hash[i] ^ b.hash[i];
    }
    result
}

criterion_group!(benches, crypto_benchmarks, ipv6_benchmarks);
criterion_main!(benches);
