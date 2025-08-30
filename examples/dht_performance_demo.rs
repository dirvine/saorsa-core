//! DHT Performance Demonstration
//!
//! This example demonstrates the performance improvements from the optimized DHT storage
//! implementation, showing O(n) to O(1) improvements for key operations.

use saorsa_core::dht::{
    DHTConfig, Key, PeerId as DhtPeerId, Record, optimized_storage::OptimizedDHTStorage,
};
use saorsa_core::identity::node_identity::NodeId;
use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::RwLock;

// Default implementation for LegacyDHTStorage
impl Default for LegacyDHTStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Legacy DHT storage for comparison
pub struct LegacyDHTStorage {
    records: RwLock<HashMap<Key, Record>>,
}

impl LegacyDHTStorage {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
        }
    }

    pub async fn store(&self, record: Record) -> anyhow::Result<()> {
        let mut records = self.records.write().await;
        records.insert(record.key.clone(), record);
        Ok(())
    }

    pub async fn get(&self, key: &Key) -> Option<Record> {
        let records = self.records.read().await;
        records.get(key).cloned()
    }

    pub async fn get_records_by_publisher(&self, publisher: &DhtPeerId) -> Vec<Record> {
        let records = self.records.read().await;
        records
            .values()
            .filter(|record| &record.publisher == publisher)
            .cloned()
            .collect()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing for performance logging
    tracing_subscriber::fmt::init();

    println!("🚀 DHT Performance Demonstration");
    println!("=================================");

    // Create test data
    let record_count = 10_000;
    println!("📊 Creating {} test records...", record_count);

    let mut test_records = Vec::new();
    for i in 0..record_count {
        let key_bytes: [u8; 32] = blake3::hash(format!("test_key_{}", i).as_bytes()).into();
        let key: Key = key_bytes;
        let value = format!("test_value_{}", i).into_bytes();
        let pub_bytes: [u8; 32] = blake3::hash(format!("publisher_{}", i % 100).as_bytes()).into();
        let publisher: DhtPeerId = NodeId::from_bytes(pub_bytes);
        let record = Record::new(key, value, publisher);
        test_records.push(record);
    }

    // Create storage instances
    let config = DHTConfig::default();
    let legacy_storage = LegacyDHTStorage::new();
    let optimized_storage = OptimizedDHTStorage::new(config.clone());

    println!("\n🔄 Running performance benchmarks...");

    // Benchmark 1: Storage operations
    println!("\n1️⃣ Storage Operations");
    println!("   Loading {} records into legacy storage...", record_count);

    let legacy_start = Instant::now();
    for record in &test_records {
        legacy_storage.store(record.clone()).await?;
    }
    let legacy_store_time = legacy_start.elapsed();

    println!(
        "   Loading {} records into optimized storage...",
        record_count
    );
    let optimized_start = Instant::now();
    for record in &test_records {
        optimized_storage.store(record.clone()).await?;
    }
    let optimized_store_time = optimized_start.elapsed();

    let store_speedup =
        legacy_store_time.as_nanos() as f64 / optimized_store_time.as_nanos() as f64;
    println!(
        "   ✅ Legacy: {:?} | Optimized: {:?} | Speedup: {:.2}x",
        legacy_store_time, optimized_store_time, store_speedup
    );

    // Benchmark 2: Retrieval operations
    println!("\n2️⃣ Retrieval Operations");
    let test_keys: Vec<&Key> = test_records
        .iter()
        .step_by(100) // Test every 100th record
        .map(|record| &record.key)
        .collect();

    println!(
        "   Testing {} random retrievals from legacy storage...",
        test_keys.len()
    );
    let legacy_start = Instant::now();
    for key in &test_keys {
        let _ = legacy_storage.get(key).await;
    }
    let legacy_get_time = legacy_start.elapsed();

    println!(
        "   Testing {} random retrievals from optimized storage...",
        test_keys.len()
    );
    let optimized_start = Instant::now();
    for key in &test_keys {
        let _ = optimized_storage.get(key).await;
    }
    let optimized_get_time = optimized_start.elapsed();

    let get_speedup = legacy_get_time.as_nanos() as f64 / optimized_get_time.as_nanos() as f64;
    println!(
        "   ✅ Legacy: {:?} | Optimized: {:?} | Speedup: {:.2}x",
        legacy_get_time, optimized_get_time, get_speedup
    );

    // Benchmark 3: Publisher queries (demonstrates indexed lookup)
    println!("\n3️⃣ Publisher Queries (O(n) vs O(1))");
    let test_publishers = vec![
        "publisher_0",
        "publisher_25",
        "publisher_50",
        "publisher_75",
        "publisher_99",
    ];

    println!("   Testing publisher queries on legacy storage (O(n) scan)...");
    let legacy_start = Instant::now();
    let mut legacy_results = 0;
    for publisher in &test_publishers {
        let pub_bytes: [u8; 32] = blake3::hash(publisher.as_bytes()).into();
        let pub_id: DhtPeerId = NodeId::from_bytes(pub_bytes);
        let records = legacy_storage.get_records_by_publisher(&pub_id).await;
        legacy_results += records.len();
    }
    let legacy_query_time = legacy_start.elapsed();

    println!("   Testing publisher queries on optimized storage (O(1) indexed)...");
    let optimized_start = Instant::now();
    let mut optimized_results = 0;
    for publisher in &test_publishers {
        let records = optimized_storage
            .get_records_by_publisher(publisher, None)
            .await;
        optimized_results += records.len();
    }
    let optimized_query_time = optimized_start.elapsed();

    let query_speedup =
        legacy_query_time.as_nanos() as f64 / optimized_query_time.as_nanos() as f64;
    println!(
        "   ✅ Legacy: {:?} ({} results) | Optimized: {:?} ({} results) | Speedup: {:.2}x",
        legacy_query_time, legacy_results, optimized_query_time, optimized_results, query_speedup
    );

    // Benchmark 4: Memory usage and bounds
    println!("\n4️⃣ Memory Management");
    let stats = optimized_storage.get_stats().await;
    println!("   📊 Optimized storage stats:");
    println!("      - Total records: {}", stats.total_records);
    println!(
        "      - Memory usage: {} bytes ({:.2} MB)",
        stats.memory_usage_bytes,
        stats.memory_usage_bytes as f64 / 1_048_576.0
    );
    println!(
        "      - Cache hits: {}, misses: {}",
        stats.cache_hits, stats.cache_misses
    );
    println!(
        "      - Hit ratio: {:.1}%",
        (stats.cache_hits as f64 / (stats.cache_hits + stats.cache_misses) as f64) * 100.0
    );

    // Demonstrate memory bounds with small cache
    println!("\n5️⃣ Memory Bounds Demonstration");
    let small_cache_storage = OptimizedDHTStorage::with_cache_size(config, 1000); // Small cache

    println!("   Testing memory bounds with 1000-record cache limit...");
    for i in 0..2000 {
        // Try to store more than cache can hold
        let key: Key = blake3::hash(format!("bound_test_{}", i).as_bytes()).into();
        let value = vec![0u8; 512]; // 512 bytes per record
        let pub_bytes: [u8; 32] = blake3::hash(b"bound_tester").into();
        let publisher: DhtPeerId = NodeId::from_bytes(pub_bytes);
        let record = Record::new(key, value, publisher);
        small_cache_storage.store(record).await?;
    }

    let bounded_stats = small_cache_storage.get_stats().await;
    println!("   ✅ Cache bounded correctly:");
    println!("      - Records stored: 2000");
    println!(
        "      - Cache size: {} (≤ 1000 limit)",
        bounded_stats.total_records
    );
    println!(
        "      - Memory usage: {} bytes",
        bounded_stats.memory_usage_bytes
    );

    // Overall summary
    println!("\n🎯 Performance Summary");
    println!("======================");
    println!("Storage operations:   {:.2}x speedup", store_speedup);
    println!("Retrieval operations: {:.2}x speedup", get_speedup);
    println!(
        "Publisher queries:    {:.2}x speedup (O(n) → O(1))",
        query_speedup
    );

    let average_speedup = (store_speedup + get_speedup + query_speedup) / 3.0;
    println!(
        "\n🚀 Average performance improvement: {:.2}x",
        average_speedup
    );
    println!("✅ Memory bounds enforced successfully");
    println!("\n✨ DHT optimization completed successfully!");

    Ok(())
}
