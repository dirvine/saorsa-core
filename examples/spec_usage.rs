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
//
// Example usage of the Saorsa Core specification modules

use anyhow::Result;
use bytes::Bytes;
use saorsa_core::api::*;
use saorsa_core::auth::*;
use saorsa_core::events::{self, TopologyEvent, global_bus};
use saorsa_core::fwid::*;
use saorsa_core::telemetry::*;
use saorsa_core::types::Forward;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Saorsa Core Specification Examples ===\n");

    // Example 1: Four-Word Identifiers
    example_fwid()?;

    // Example 2: Authentication System
    example_auth().await?;

    // Example 3: Event Bus
    example_events().await?;

    // Example 4: Telemetry Collection
    example_telemetry().await?;

    // Example 5: Complete API Flow
    example_api_flow().await?;

    println!("\n=== All examples completed successfully ===");
    Ok(())
}

fn example_fwid() -> Result<()> {
    println!("--- Four-Word Identifiers ---");

    // Create four-word address
    let words: [Word; 4] = [
        "quantum".to_string(),
        "nexus".to_string(),
        "cipher".to_string(),
        "vault".to_string(),
    ];

    // Validate words
    if fw_check(words.clone()) {
        println!("✓ Four words are valid");

        // Convert to DHT key
        let key = fw_to_key(words.clone())?;
        println!("✓ Generated key: {} bytes", key.as_bytes().len());

        // Compute key from arbitrary data
        let data_key = compute_key("user", b"data-12345");
        println!("✓ Data key: {} bytes", data_key.as_bytes().len());
    }

    Ok(())
}

async fn example_auth() -> Result<()> {
    println!("\n--- Authentication System ---");

    // Single-writer authentication
    let pub_key = PubKey::new(vec![1, 2, 3, 4, 5]);
    let single_auth = SingleWriteAuth::new(pub_key.clone());

    let record = b"important data";
    let sig = Sig::new(vec![6, 7, 8, 9, 10]);

    let valid = single_auth.verify(record.as_ref(), &[sig.clone()]).await?;
    println!(
        "✓ Single-writer auth: {}",
        if valid { "valid" } else { "invalid" }
    );

    // Delegated authentication
    let key2 = PubKey::new(vec![11, 12, 13]);
    let key3 = PubKey::new(vec![14, 15, 16]);
    let delegated = DelegatedWriteAuth::new(vec![pub_key.clone(), key2, key3]);

    let valid = delegated.verify(record.as_ref(), &[sig.clone()]).await?;
    println!(
        "✓ Delegated auth: {}",
        if valid { "valid" } else { "invalid" }
    );

    // Threshold authentication (2-of-3)
    let keys = vec![
        PubKey::new(vec![20, 21]),
        PubKey::new(vec![22, 23]),
        PubKey::new(vec![24, 25]),
    ];
    let threshold = ThresholdWriteAuth::new(2, 3, keys)?;

    let sigs = vec![Sig::new(vec![30, 31]), Sig::new(vec![32, 33])];
    let valid = threshold.verify(record.as_ref(), &sigs).await?;
    println!(
        "✓ Threshold auth (2-of-3): {}",
        if valid { "valid" } else { "invalid" }
    );

    // Composite authentication (all must pass)
    let auth1 = Box::new(SingleWriteAuth::new(pub_key));
    let auth2 = Box::new(threshold);
    let composite = CompositeWriteAuth::all(vec![auth1, auth2]);

    let valid = composite.verify(record.as_ref(), &[sig]).await?;
    println!(
        "✓ Composite auth (all): {}",
        if valid { "valid" } else { "invalid" }
    );
    println!("  Auth type: {}", composite.auth_type());

    Ok(())
}

async fn example_events() -> Result<()> {
    println!("\n--- Event Bus ---");

    // Subscribe to topology events
    let mut topology_sub = events::subscribe_topology();
    println!("✓ Subscribed to topology events");

    // Publish topology event (in background)
    let bus = global_bus();
    tokio::spawn(async move {
        sleep(Duration::from_millis(100)).await;
        let event = TopologyEvent::PeerJoined {
            peer_id: vec![1, 2, 3],
            address: "192.168.1.100:9000".to_string(),
        };
        let _ = bus.publish_topology(event).await;
    });

    // Receive event
    tokio::select! {
        result = topology_sub.recv() => {
            if let Ok(event) = result {
                println!("✓ Received topology event: {:?}", event);
            } else {
                println!("  (No event received - channel closed)");
            }
        }
        _ = sleep(Duration::from_millis(200)) => {
            println!("  (No event received - timeout)");
        }
    }

    // Watch DHT key
    let key = Key::new([42u8; 32]);
    let mut dht_sub = events::dht_watch(key.clone()).await;
    println!("✓ Watching DHT key");

    // Update DHT key (in background)
    let bus = global_bus();
    tokio::spawn(async move {
        sleep(Duration::from_millis(100)).await;
        let _ = bus
            .publish_dht_update(key, Bytes::from(vec![1, 2, 3, 4]))
            .await;
    });

    // Receive update
    tokio::select! {
        result = dht_sub.recv() => {
            if let Ok(data) = result {
                println!("✓ DHT key updated: {} bytes", data.len());
            } else {
                println!("  (No update received - channel closed)");
            }
        }
        _ = sleep(Duration::from_millis(200)) => {
            println!("  (No update received - timeout)");
        }
    }

    // Device forward subscription
    let identity_key = Key::new([99u8; 32]);
    let mut device_sub = events::device_subscribe(identity_key.clone()).await;
    println!("✓ Subscribed to device forwards");

    // Publish forward (in background)
    let bus = global_bus();
    let identity_key_copy = identity_key.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(100)).await;
        let forward = Forward {
            proto: "quic".into(),
            addr: "192.168.1.100:9000".into(),
            exp: 1234567890,
        };
        let _ = bus.publish_forward_for(identity_key_copy, forward).await;
    });

    // Receive forward
    tokio::select! {
        result = device_sub.recv() => {
            if let Ok(forward) = result {
                println!("✓ Device forward: {} at {}", forward.proto, forward.addr);
            } else {
                println!("  (No forward received - channel closed)");
            }
        }
        _ = sleep(Duration::from_millis(200)) => {
            println!("  (No forward received - timeout)");
        }
    }

    Ok(())
}

async fn example_telemetry() -> Result<()> {
    println!("\n--- Telemetry Collection ---");

    let collector = telemetry();

    // Record some lookup operations
    for i in 1..=10 {
        let latency = Duration::from_millis(10 * i);
        let hops = (i % 5 + 1) as u8;
        collector.record_lookup(latency, hops).await;
    }
    println!("✓ Recorded 10 lookup operations");

    // Record some timeouts
    for _ in 0..2 {
        collector.record_timeout();
    }
    println!("✓ Recorded 2 timeouts");

    // Record DHT operations
    collector.record_dht_put();
    collector.record_dht_put();
    collector.record_dht_get();
    println!("✓ Recorded DHT operations");

    // Record stream metrics
    for i in 1..=5 {
        collector
            .record_stream_bandwidth(StreamClass::Media, 1_000_000 * i)
            .await;
        collector
            .record_stream_rtt(StreamClass::Media, Duration::from_millis(20 + i * 5))
            .await;
    }
    println!("✓ Recorded stream metrics");

    // Get metrics
    let metrics = collector.get_metrics().await;
    println!("\nMetrics Summary:");
    println!("  Lookup P95: {}ms", metrics.lookups_p95_ms);
    println!("  Hop P95: {} hops", metrics.hop_p95);
    println!("  Timeout rate: {:.1}%", metrics.timeout_rate * 100.0);

    // Get counters
    let counters = collector.get_counters();
    println!("\nEvent Counters:");
    println!("  DHT puts: {}", counters.dht_puts);
    println!("  DHT gets: {}", counters.dht_gets);
    println!("  Auth failures: {}", counters.auth_failures);

    // Get stream metrics
    if let Some(stream_metrics) = collector.get_stream_metrics(StreamClass::Media).await {
        println!("\nMedia Stream Metrics:");
        println!("  Bandwidth P50: {} bps", stream_metrics.bandwidth_p50);
        println!("  Bandwidth P95: {} bps", stream_metrics.bandwidth_p95);
        println!("  RTT P50: {}ms", stream_metrics.rtt_p50_ms);
        println!("  RTT P95: {}ms", stream_metrics.rtt_p95_ms);
    }

    // Health monitoring
    let monitor = HealthMonitor::new(collector.clone());
    let status = monitor.get_status().await;
    println!("\nHealth Status:");
    println!("  Healthy: {}", status.healthy);
    println!("  Uptime: {:.1}s", status.uptime.as_secs_f32());

    Ok(())
}

async fn example_api_flow() -> Result<()> {
    println!("\n--- Complete API Flow ---");

    // 1. Create identity
    let words: [Word; 4] = [
        "secure".to_string(),
        "vault".to_string(),
        "crypto".to_string(),
        "node".to_string(),
    ];

    let pubkey = PubKey::new(vec![100, 101, 102]);
    let sig = Sig::new(vec![103, 104, 105]);

    println!("✓ Claiming identity with four words");
    identity_claim(words.clone(), pubkey.clone(), sig.clone()).await?;

    // 2. Get identity key
    let identity_key = fw_to_key(words)?;
    println!("✓ Identity key generated");

    // 3. Publish device forward
    let forward = Forward {
        proto: "quic".to_string(),
        addr: "10.0.0.1:9000".to_string(),
        exp: 1234567890,
    };
    device_publish_forward(identity_key, forward).await?;
    println!("✓ Device forward published");

    // 4. Store data in DHT
    let data_key = compute_key("app", b"my-application-data");
    let data = Bytes::from("Hello, Saorsa Network!");
    let policy = PutPolicy {
        quorum: 3,
        ttl: Some(Duration::from_secs(3600)),
        auth: Box::new(SingleWriteAuth::new(pubkey)),
    };

    let receipt = dht_put(data_key.clone(), data.clone(), &policy).await?;
    println!("✓ Data stored in DHT");
    println!("  Timestamp: {}", receipt.timestamp);
    println!("  Storing nodes: {} nodes", receipt.storing_nodes.len());

    // 5. Retrieve data from DHT
    let retrieved = dht_get(data_key.clone(), 3).await?;
    println!("✓ Data retrieved from DHT: {} bytes", retrieved.len());

    // 6. Watch for changes
    let mut watch_sub = dht_watch(data_key.clone()).await;
    println!("✓ Watching DHT key for changes");

    // Simulate update (in background)
    let bus = global_bus();
    let data_key_copy = data_key.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(100)).await;
        let _ = bus
            .publish_dht_update(data_key_copy, Bytes::from("Updated data!"))
            .await;
    });

    // Receive update
    tokio::select! {
        result = watch_sub.recv() => {
            if let Ok(update) = result {
                println!("✓ Received DHT update: {} bytes", update.len());
            } else {
                println!("  (No update received - channel closed)");
            }
        }
        _ = sleep(Duration::from_millis(200)) => {
            println!("  (No update received - timeout)");
        }
    }

    // 7. Record routing interactions
    let peer_id = vec![200, 201, 202];
    record_interaction(peer_id.clone(), Outcome::Ok).await?;
    println!("✓ Recorded successful interaction");

    record_interaction(peer_id, Outcome::Timeout).await?;
    println!("✓ Recorded timeout interaction");

    // 8. Transport operations (placeholders)
    let endpoint = Endpoint {
        address: "192.168.1.1:9000".to_string(),
    };
    let conn = quic_connect(&endpoint).await?;
    println!("✓ QUIC connection established");

    let stream = quic_open(&conn, StreamClass::Control).await?;
    println!("✓ Control stream opened (id: {})", stream.id);

    // 9. Storage control
    let object_id = [5u8; 32];
    let nodes = place_shards(object_id, 8);
    println!("✓ Shards placed on {} nodes", nodes.len());

    let repair_plan = repair_request(object_id);
    println!("✓ Repair plan created:");
    println!("  Missing shards: {}", repair_plan.missing_shards.len());
    println!("  Repair nodes: {}", repair_plan.repair_nodes.len());

    Ok(())
}
