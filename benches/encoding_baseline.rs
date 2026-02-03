//! Encoding baseline benchmarks to measure current JSON overhead
//!
//! This benchmark suite measures the triple JSON encoding overhead identified in the codebase:
//! 1. RichMessage → JSON
//! 2. EncryptedMessage → JSON (wrapping RichMessage JSON)
//! 3. Protocol wrapper → JSON (wrapping EncryptedMessage JSON)
//!
//! These benchmarks are measurement code (not production), so .expect() is allowed for setup.

#![allow(clippy::expect_used)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
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
                // Pre-build fixture outside measurement loop to isolate encoding-only work
                let message = create_rich_message(size_kb);
                b.iter(|| {
                    // Only measure serialization + deserialization, not message creation
                    let json = serde_json::to_vec(black_box(&message))
                        .expect("serialization should succeed");
                    let deserialized: RichMessage = serde_json::from_slice(black_box(&json))
                        .expect("deserialization should succeed");
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
                // Pre-compute size metrics once (not in loop) to capture actual values
                let json = serde_json::to_vec(&message).expect("serialization should succeed");
                let input_size = size_kb * 1024;
                let output_size = json.len();
                let overhead_ratio = output_size as f64 / input_size as f64;

                // Log actual metrics for reporting
                eprintln!(
                    "Layer 1 - RichMessage {} KB: serialized={} bytes, overhead ratio={:.2}x",
                    size_kb, output_size, overhead_ratio
                );

                b.iter(|| {
                    // Just measure serialization performance with pre-built fixture
                    let json = serde_json::to_vec(black_box(&message))
                        .expect("serialization should succeed");
                    black_box(json.len() as f64 / input_size as f64)
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
                let rich_json =
                    serde_json::to_vec(&rich_message).expect("RichMessage serialization");
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
                let rich_json =
                    serde_json::to_vec(&rich_message).expect("RichMessage serialization");
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
                // Pre-build fixture outside measurement loop
                let rich_message = create_rich_message(size_kb);
                let rich_json =
                    serde_json::to_vec(&rich_message).expect("RichMessage serialization");
                let encrypted = create_encrypted_message(rich_json, size_kb);

                b.iter(|| {
                    // Only measure serialization + deserialization of EncryptedMessage
                    let json = serde_json::to_vec(black_box(&encrypted))
                        .expect("serialization should succeed");
                    let deserialized: EncryptedMessage = serde_json::from_slice(black_box(&json))
                        .expect("deserialization should succeed");
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
                let rich_json =
                    serde_json::to_vec(&rich_message).expect("RichMessage serialization");
                let encrypted = create_encrypted_message(rich_json, size_kb);

                // Pre-compute size metrics once
                let json = serde_json::to_vec(&encrypted).expect("serialization should succeed");
                let input_size = size_kb * 1024;
                let output_size = json.len();
                let overhead_ratio = output_size as f64 / input_size as f64;

                // Log actual metrics
                eprintln!(
                    "Layer 2 - EncryptedMessage {} KB: serialized={} bytes, overhead ratio={:.2}x",
                    size_kb, output_size, overhead_ratio
                );

                b.iter(|| {
                    let json = serde_json::to_vec(black_box(&encrypted))
                        .expect("serialization should succeed");
                    let input_size = size_kb * 1024;
                    let output_size = json.len();
                    black_box(output_size as f64 / input_size as f64)
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
                let rich_json =
                    serde_json::to_vec(&rich_message).expect("RichMessage serialization");
                let encrypted = create_encrypted_message(rich_json, size_kb);
                let encrypted_json =
                    serde_json::to_vec(&encrypted).expect("EncryptedMessage serialization");
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
                let rich_json =
                    serde_json::to_vec(&rich_message).expect("RichMessage serialization");
                let encrypted = create_encrypted_message(rich_json, size_kb);
                let encrypted_json =
                    serde_json::to_vec(&encrypted).expect("EncryptedMessage serialization");
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
                // Pre-build fixture outside measurement loop
                let rich_message = create_rich_message(size_kb);
                let rich_json =
                    serde_json::to_vec(&rich_message).expect("RichMessage serialization");
                let encrypted = create_encrypted_message(rich_json, size_kb);
                let encrypted_json =
                    serde_json::to_vec(&encrypted).expect("EncryptedMessage serialization");
                let wrapper = create_protocol_wrapper(encrypted_json);

                b.iter(|| {
                    // Only measure serialization + deserialization of ProtocolWrapper
                    let json = serde_json::to_vec(black_box(&wrapper))
                        .expect("serialization should succeed");
                    let deserialized: ProtocolWrapper = serde_json::from_slice(black_box(&json))
                        .expect("deserialization should succeed");
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
                let rich_json =
                    serde_json::to_vec(&rich_message).expect("RichMessage serialization");
                let encrypted = create_encrypted_message(rich_json, size_kb);
                let encrypted_json =
                    serde_json::to_vec(&encrypted).expect("EncryptedMessage serialization");
                let wrapper = create_protocol_wrapper(encrypted_json);

                // Pre-compute size metrics once
                let json = serde_json::to_vec(&wrapper).expect("serialization should succeed");
                let input_size = size_kb * 1024;
                let output_size = json.len();
                let overhead_ratio = output_size as f64 / input_size as f64;

                // Log actual metrics
                eprintln!(
                    "Layer 3 - ProtocolWrapper {} KB: serialized={} bytes, overhead ratio={:.2}x",
                    size_kb, output_size, overhead_ratio
                );

                b.iter(|| {
                    let json = serde_json::to_vec(black_box(&wrapper))
                        .expect("serialization should succeed");
                    let input_size = size_kb * 1024;
                    let output_size = json.len();
                    black_box(output_size as f64 / input_size as f64)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark bincode vs JSON for RichMessage (Task 7: serialization performance comparison)
fn bench_bincode_vs_json(c: &mut Criterion) {
    let mut group = c.benchmark_group("bincode_vs_json");

    for size_kb in [8, 64, 256] {
        // JSON serialization
        group.bench_with_input(
            BenchmarkId::new("json_serialize", size_kb),
            &size_kb,
            |b, &size_kb| {
                let message = create_rich_message(size_kb);

                b.iter(|| {
                    let json = serde_json::to_vec(&message);
                    black_box(json)
                });
            },
        );

        // Bincode serialization
        group.bench_with_input(
            BenchmarkId::new("bincode_serialize", size_kb),
            &size_kb,
            |b, &size_kb| {
                let message = create_rich_message(size_kb);

                b.iter(|| {
                    let bincode = postcard::to_stdvec(&message);
                    black_box(bincode)
                });
            },
        );

        // JSON deserialization
        group.bench_with_input(
            BenchmarkId::new("json_deserialize", size_kb),
            &size_kb,
            |b, &size_kb| {
                let message = create_rich_message(size_kb);
                let json = serde_json::to_vec(&message).expect("JSON serialization");

                b.iter(|| {
                    let deserialized: Result<RichMessage, _> =
                        serde_json::from_slice(black_box(&json));
                    black_box(deserialized)
                });
            },
        );

        // Bincode deserialization
        group.bench_with_input(
            BenchmarkId::new("bincode_deserialize", size_kb),
            &size_kb,
            |b, &size_kb| {
                let message = create_rich_message(size_kb);
                let bincode = postcard::to_stdvec(&message).expect("bincode serialization");

                b.iter(|| {
                    let deserialized: Result<RichMessage, _> =
                        postcard::from_bytes(black_box(&bincode));
                    black_box(deserialized)
                });
            },
        );

        // Size comparison
        group.bench_with_input(
            BenchmarkId::new("size_comparison", size_kb),
            &size_kb,
            |b, &size_kb| {
                let message = create_rich_message(size_kb);

                // Pre-compute size metrics once
                let json = serde_json::to_vec(&message).expect("JSON serialization");
                let bincode = postcard::to_stdvec(&message).expect("bincode serialization");
                let ratio = bincode.len() as f64 / json.len() as f64;

                // Log actual metrics
                eprintln!(
                    "Bincode vs JSON - {} KB: JSON={} bytes, Bincode={} bytes, ratio={:.2}x",
                    size_kb,
                    json.len(),
                    bincode.len(),
                    ratio
                );

                b.iter(|| {
                    // Measure serialization throughput on pre-built message
                    let json = serde_json::to_vec(black_box(&message)).expect("JSON serialization");
                    let bincode =
                        postcard::to_stdvec(black_box(&message)).expect("bincode serialization");

                    // Return size ratio: bincode / json (expect < 1.0, meaning bincode is smaller)
                    let ratio = bincode.len() as f64 / json.len() as f64;
                    black_box(ratio)
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
    bench_protocol_wrapper_encoding,
    bench_bincode_vs_json
);
criterion_main!(benches);
