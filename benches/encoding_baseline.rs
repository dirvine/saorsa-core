//! Encoding baseline benchmarks to measure current JSON overhead
//!
//! This benchmark suite measures the triple JSON encoding overhead identified in the codebase:
//! 1. RichMessage → JSON
//! 2. EncryptedMessage → JSON (wrapping RichMessage JSON)
//! 3. Protocol wrapper → JSON (wrapping EncryptedMessage JSON)
//!
//! These benchmarks are measurement code (not production), so .expect() is allowed for setup.

#![allow(clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use saorsa_core::identity::FourWordAddress;
use saorsa_core::messaging::types::{
    ChannelId, EncryptedMessage, MessageContent, MessageId, RichMessage,
};
use saorsa_core::messaging::user_handle::UserHandle;
use serde::{Deserialize, Serialize};

/// Creates a test RichMessage with given text content of specified size
fn create_rich_message(size_kb: usize) -> RichMessage {
    let sender = UserHandle::from("ocean-forest-moon-star");
    let channel = ChannelId::new();

    // Create text content of specified size
    let text = "x".repeat(size_kb * 1024);
    let content = MessageContent::Text(text);

    RichMessage::new(sender, channel, content)
}

/// Creates a test EncryptedMessage with given payload
fn create_encrypted_message(payload: Vec<u8>, size_kb: usize) -> EncryptedMessage {
    let sender = FourWordAddress::parse_str("ocean-forest-moon-star").expect("valid address");

    EncryptedMessage {
        id: MessageId::new(),
        channel_id: ChannelId::new(),
        sender,
        ciphertext: payload,
        nonce: vec![0u8; 12],
        key_id: format!("key_{}", size_kb),
    }
}

/// Protocol wrapper for testing outer encoding (matches network.rs:1645-1669)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProtocolWrapper {
    protocol: String,
    data: Vec<u8>,
    from: String,
    timestamp: u64,
}

fn create_protocol_wrapper(data: Vec<u8>) -> ProtocolWrapper {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_secs();

    ProtocolWrapper {
        protocol: "test".to_string(),
        data,
        from: "test-peer-id".to_string(),
        timestamp,
    }
}

/// Benchmark RichMessage encoding (struct → JSON → struct)
fn bench_rich_message_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("rich_message_encoding");

    for size_kb in [8, 64, 256] {
        // Serialization benchmark
        group.bench_with_input(
            BenchmarkId::new("serialize", size_kb),
            &size_kb,
            |b, &size_kb| {
                let message = create_rich_message(size_kb);

                b.iter(|| {
                    let json = serde_json::to_vec(&message);
                    black_box(json)
                });
            },
        );

        // Deserialization benchmark
        group.bench_with_input(
            BenchmarkId::new("deserialize", size_kb),
            &size_kb,
            |b, &size_kb| {
                let message = create_rich_message(size_kb);
                let json = serde_json::to_vec(&message).expect("serialization should succeed");

                b.iter(|| {
                    let deserialized: Result<RichMessage, _> =
                        serde_json::from_slice(black_box(&json));
                    black_box(deserialized)
                });
            },
        );

        // Round-trip benchmark
        group.bench_with_input(
            BenchmarkId::new("round_trip", size_kb),
            &size_kb,
            |b, &size_kb| {
                b.iter(|| {
                    let message = create_rich_message(size_kb);
                    let json = serde_json::to_vec(&message).expect("serialization should succeed");
                    let deserialized: RichMessage =
                        serde_json::from_slice(&json).expect("deserialization should succeed");
                    black_box(deserialized)
                });
            },
        );

        // Size overhead measurement
        group.bench_with_input(
            BenchmarkId::new("size_overhead", size_kb),
            &size_kb,
            |b, &size_kb| {
                let message = create_rich_message(size_kb);

                b.iter(|| {
                    let json = serde_json::to_vec(&message).expect("serialization should succeed");
                    let input_size = size_kb * 1024;
                    let output_size = json.len();
                    let overhead_ratio = output_size as f64 / input_size as f64;
                    black_box(overhead_ratio)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark EncryptedMessage encoding (second layer - wraps RichMessage JSON)
fn bench_encrypted_message_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypted_message_encoding");

    for size_kb in [8, 64, 256] {
        // Serialization benchmark
        group.bench_with_input(
            BenchmarkId::new("serialize", size_kb),
            &size_kb,
            |b, &size_kb| {
                // Simulate encrypting a RichMessage JSON
                let rich_message = create_rich_message(size_kb);
                let rich_json = serde_json::to_vec(&rich_message).expect("RichMessage serialization");
                let encrypted = create_encrypted_message(rich_json, size_kb);

                b.iter(|| {
                    let json = serde_json::to_vec(&encrypted);
                    black_box(json)
                });
            },
        );

        // Deserialization benchmark
        group.bench_with_input(
            BenchmarkId::new("deserialize", size_kb),
            &size_kb,
            |b, &size_kb| {
                let rich_message = create_rich_message(size_kb);
                let rich_json = serde_json::to_vec(&rich_message).expect("RichMessage serialization");
                let encrypted = create_encrypted_message(rich_json, size_kb);
                let json = serde_json::to_vec(&encrypted).expect("serialization should succeed");

                b.iter(|| {
                    let deserialized: Result<EncryptedMessage, _> =
                        serde_json::from_slice(black_box(&json));
                    black_box(deserialized)
                });
            },
        );

        // Round-trip benchmark
        group.bench_with_input(
            BenchmarkId::new("round_trip", size_kb),
            &size_kb,
            |b, &size_kb| {
                b.iter(|| {
                    let rich_message = create_rich_message(size_kb);
                    let rich_json = serde_json::to_vec(&rich_message).expect("RichMessage serialization");
                    let encrypted = create_encrypted_message(rich_json, size_kb);
                    let json = serde_json::to_vec(&encrypted).expect("serialization should succeed");
                    let deserialized: EncryptedMessage =
                        serde_json::from_slice(&json).expect("deserialization should succeed");
                    black_box(deserialized)
                });
            },
        );

        // Size overhead measurement (comparing to original RichMessage size)
        group.bench_with_input(
            BenchmarkId::new("size_overhead", size_kb),
            &size_kb,
            |b, &size_kb| {
                let rich_message = create_rich_message(size_kb);
                let rich_json = serde_json::to_vec(&rich_message).expect("RichMessage serialization");
                let encrypted = create_encrypted_message(rich_json, size_kb);

                b.iter(|| {
                    let json = serde_json::to_vec(&encrypted).expect("serialization should succeed");
                    let input_size = size_kb * 1024;
                    let output_size = json.len();
                    let overhead_ratio = output_size as f64 / input_size as f64;
                    black_box(overhead_ratio)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark protocol wrapper encoding (third layer - wraps EncryptedMessage JSON)
fn bench_protocol_wrapper_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol_wrapper_encoding");

    for size_kb in [8, 64, 256] {
        // Serialization benchmark
        group.bench_with_input(
            BenchmarkId::new("serialize", size_kb),
            &size_kb,
            |b, &size_kb| {
                // Simulate wrapping an EncryptedMessage JSON
                let rich_message = create_rich_message(size_kb);
                let rich_json = serde_json::to_vec(&rich_message).expect("RichMessage serialization");
                let encrypted = create_encrypted_message(rich_json, size_kb);
                let encrypted_json = serde_json::to_vec(&encrypted).expect("EncryptedMessage serialization");
                let wrapper = create_protocol_wrapper(encrypted_json);

                b.iter(|| {
                    let json = serde_json::to_vec(&wrapper);
                    black_box(json)
                });
            },
        );

        // Deserialization benchmark
        group.bench_with_input(
            BenchmarkId::new("deserialize", size_kb),
            &size_kb,
            |b, &size_kb| {
                let rich_message = create_rich_message(size_kb);
                let rich_json = serde_json::to_vec(&rich_message).expect("RichMessage serialization");
                let encrypted = create_encrypted_message(rich_json, size_kb);
                let encrypted_json = serde_json::to_vec(&encrypted).expect("EncryptedMessage serialization");
                let wrapper = create_protocol_wrapper(encrypted_json);
                let json = serde_json::to_vec(&wrapper).expect("serialization should succeed");

                b.iter(|| {
                    let deserialized: Result<ProtocolWrapper, _> =
                        serde_json::from_slice(black_box(&json));
                    black_box(deserialized)
                });
            },
        );

        // Round-trip benchmark
        group.bench_with_input(
            BenchmarkId::new("round_trip", size_kb),
            &size_kb,
            |b, &size_kb| {
                b.iter(|| {
                    let rich_message = create_rich_message(size_kb);
                    let rich_json = serde_json::to_vec(&rich_message).expect("RichMessage serialization");
                    let encrypted = create_encrypted_message(rich_json, size_kb);
                    let encrypted_json = serde_json::to_vec(&encrypted).expect("EncryptedMessage serialization");
                    let wrapper = create_protocol_wrapper(encrypted_json);
                    let json = serde_json::to_vec(&wrapper).expect("serialization should succeed");
                    let deserialized: ProtocolWrapper =
                        serde_json::from_slice(&json).expect("deserialization should succeed");
                    black_box(deserialized)
                });
            },
        );

        // Size overhead measurement (final size vs original)
        group.bench_with_input(
            BenchmarkId::new("size_overhead", size_kb),
            &size_kb,
            |b, &size_kb| {
                let rich_message = create_rich_message(size_kb);
                let rich_json = serde_json::to_vec(&rich_message).expect("RichMessage serialization");
                let encrypted = create_encrypted_message(rich_json, size_kb);
                let encrypted_json = serde_json::to_vec(&encrypted).expect("EncryptedMessage serialization");
                let wrapper = create_protocol_wrapper(encrypted_json);

                b.iter(|| {
                    let json = serde_json::to_vec(&wrapper).expect("serialization should succeed");
                    let input_size = size_kb * 1024;
                    let output_size = json.len();
                    let overhead_ratio = output_size as f64 / input_size as f64;
                    black_box(overhead_ratio)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_rich_message_encoding,
    bench_encrypted_message_encoding,
    bench_protocol_wrapper_encoding
);
criterion_main!(benches);
