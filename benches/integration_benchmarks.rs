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

//! Integration Performance Benchmarks
//!
//! Measures performance of integration test scenarios for regression detection.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use saorsa_core::adaptive::{TrustProvider, trust::MockTrustProvider};
use saorsa_core::dht::{Key, PeerId, Record};
use saorsa_core::identity::{NodeIdentity, node_identity::NodeId};
use saorsa_core::peer_record::UserId;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

/// Benchmark storage performance with DHT operations
fn benchmark_storage_performance(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("storage_performance");
    group.measurement_time(Duration::from_secs(20));

    for data_size in [1024, 10240, 102400].iter() {
        group.bench_with_input(
            BenchmarkId::new("store_retrieve", data_size),
            data_size,
            |b, &data_size| {
                b.iter_custom(|iters| {
                    let start = std::time::Instant::now();
                    for _ in 0..iters {
                        let _ =
                            rt.block_on(async { benchmark_storage_operations(data_size).await });
                    }
                    start.elapsed()
                });
            },
        );
    }

    group.finish();
}

/// Benchmark crypto performance with identity operations
fn benchmark_crypto_performance(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("crypto_performance");

    for message_size in [1024, 10240].iter() {
        group.bench_with_input(
            BenchmarkId::new("encrypt_decrypt", message_size),
            message_size,
            |b, &message_size| {
                b.iter_custom(|iters| {
                    let start = std::time::Instant::now();
                    for _ in 0..iters {
                        let _ = rt.block_on(async {
                            benchmark_encryption_operations(message_size).await
                        });
                    }
                    start.elapsed()
                });
            },
        );
    }

    group.finish();
}

/// Benchmark adaptive network operations
fn benchmark_adaptive_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("adaptive_operations");

    // Benchmark trust operations
    group.bench_function("trust_operations", |b| {
        let trust_provider = Arc::new(MockTrustProvider::new());
        let node_id = UserId::from_bytes([42u8; 32]);

        b.iter(|| {
            let score = trust_provider.get_trust(&node_id);
            trust_provider.update_trust(&node_id, &node_id, true);
            black_box(score);
        });
    });

    group.finish();
}

async fn benchmark_storage_operations(data_size: usize) -> Result<(), Box<dyn std::error::Error>> {
    // Simplified storage benchmark using available DHT functionality
    let peer_id = create_test_peer_id([1u8; 32]);
    let data = vec![0xAB; data_size];

    // Create key from data hash
    let mut key_bytes = [0u8; 32];
    let hash = blake3::hash(&data);
    key_bytes.copy_from_slice(hash.as_bytes());
    let key: Key = key_bytes;

    let record = Record::new(key, data, peer_id);

    // Benchmark key operations
    let key2: Key = [1u8; 32];
    let _distance = xor_distance(&key, &key2);

    // Check record validity
    let _is_expired = record.is_expired();

    Ok(())
}

async fn benchmark_encryption_operations(
    message_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    // Simplified encryption benchmark using available crypto functionality
    let identity = NodeIdentity::generate()?;

    let message = vec![0xCD; message_size];

    // Benchmark signature generation and verification
    let signature = identity.sign(&message)?;
    let is_valid = identity.verify(&message, &signature)?;

    if !is_valid {
        return Err("Signature verification failed".into());
    }

    // Benchmark hash operations (variable is intentionally unused for benchmark)
    let _hash = blake3::hash(&message);

    Ok(())
}

/// Create a test PeerId from bytes
fn create_test_peer_id(bytes: [u8; 32]) -> PeerId {
    NodeId::from_bytes(bytes)
}

/// Calculate XOR distance between two keys
fn xor_distance(a: &Key, b: &Key) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

criterion_group!(
    benches,
    benchmark_storage_performance,
    benchmark_crypto_performance,
    benchmark_adaptive_operations
);
criterion_main!(benches);
