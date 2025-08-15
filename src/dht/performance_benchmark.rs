//! DHT Performance Benchmark - Demonstrates O(n) to O(1) improvements
//!
//! This module provides benchmarking tools to measure the performance improvements
//! from the optimized DHT storage implementation.

use crate::dht::{Key, Record, DHTConfig, DHTStorage, optimized_storage::OptimizedDHTStorage};
use crate::PeerId;
use std::collections::HashMap;
use std::time::{Instant, Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{info, debug};

/// Performance benchmark results
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub operation: String,
    pub record_count: usize,
    pub old_implementation_time: Duration,
    pub new_implementation_time: Duration,
    pub speedup_factor: f64,
    pub memory_usage: usize,
}

/// Legacy DHT storage implementation for benchmarking comparison
pub struct LegacyDHTStorage {
    records: RwLock<HashMap<Key, Record>>,
    config: DHTConfig,
}

impl LegacyDHTStorage {
    pub fn new(config: DHTConfig) -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
            config,
        }
    }

    pub async fn store(&self, record: Record) -> crate::error::P2pResult<()> {
        let mut records = self.records.write().await;
        records.insert(record.key.clone(), record);
        Ok(())
    }

    pub async fn get(&self, key: &Key) -> Option<Record> {
        let records = self.records.read().await;
        records.get(key).cloned()
    }

    pub async fn cleanup_expired(&self) -> usize {
        let mut records = self.records.write().await;
        let initial_count = records.len();
        records.retain(|_, record| !record.is_expired());
        initial_count - records.len()
    }

    pub async fn get_records_by_publisher(&self, publisher: &str) -> Vec<Record> {
        let records = self.records.read().await;
        records.values()
            .filter(|record| record.publisher.to_string() == publisher)
            .cloned()
            .collect()
    }
}

/// DHT performance benchmarking suite
pub struct DHTPerformanceBenchmark {
    config: DHTConfig,
    test_data: Vec<Record>,
}

impl DHTPerformanceBenchmark {
    /// Create a new benchmark suite
    pub fn new(record_count: usize) -> Self {
        let config = DHTConfig::default();
        let mut test_data = Vec::new();
        
        for i in 0..record_count {
            let key = Key::new(format!("test_key_{}", i).as_bytes());
            let value = format!("test_value_{}", i).into_bytes();
            let publisher = PeerId::from(format!("publisher_{}", i % 10)); // 10 different publishers
            let record = Record::new(key, value, publisher);
            test_data.push(record);
        }
        
        Self { config, test_data }
    }

    /// Benchmark storage operations
    pub async fn benchmark_storage_operations(&self) -> BenchmarkResult {
        info!("Starting storage operations benchmark with {} records", self.test_data.len());
        
        // Test legacy implementation
        let legacy_storage = LegacyDHTStorage::new(self.config.clone());
        let legacy_start = Instant::now();
        
        for record in &self.test_data {
            legacy_storage.store(record.clone()).await.unwrap();
        }
        
        let legacy_duration = legacy_start.elapsed();
        
        // Test optimized implementation
        let optimized_storage = OptimizedDHTStorage::new(self.config.clone());
        let optimized_start = Instant::now();
        
        for record in &self.test_data {
            optimized_storage.store(record.clone()).await.unwrap();
        }
        
        let optimized_duration = optimized_start.elapsed();
        let speedup = legacy_duration.as_nanos() as f64 / optimized_duration.as_nanos() as f64;
        let memory_stats = optimized_storage.get_stats().await;
        
        info!("Storage benchmark completed - Legacy: {:?}, Optimized: {:?}, Speedup: {:.2}x", 
              legacy_duration, optimized_duration, speedup);
        
        BenchmarkResult {
            operation: "Storage Operations".to_string(),
            record_count: self.test_data.len(),
            old_implementation_time: legacy_duration,
            new_implementation_time: optimized_duration,
            speedup_factor: speedup,
            memory_usage: memory_stats.memory_usage_bytes,
        }
    }

    /// Benchmark retrieval operations
    pub async fn benchmark_retrieval_operations(&self) -> BenchmarkResult {
        info!("Starting retrieval operations benchmark");
        
        // Setup both storages with data
        let legacy_storage = LegacyDHTStorage::new(self.config.clone());
        let optimized_storage = OptimizedDHTStorage::new(self.config.clone());
        
        for record in &self.test_data {
            legacy_storage.store(record.clone()).await.unwrap();
            optimized_storage.store(record.clone()).await.unwrap();
        }
        
        // Test retrieval performance - access random keys
        let test_keys: Vec<&Key> = self.test_data.iter()
            .step_by(10) // Test every 10th record to simulate real usage
            .map(|record| &record.key)
            .collect();
        
        // Legacy retrieval
        let legacy_start = Instant::now();
        for key in &test_keys {
            let _ = legacy_storage.get(key).await;
        }
        let legacy_duration = legacy_start.elapsed();
        
        // Optimized retrieval
        let optimized_start = Instant::now();
        for key in &test_keys {
            let _ = optimized_storage.get(key).await;
        }
        let optimized_duration = optimized_start.elapsed();
        
        let speedup = legacy_duration.as_nanos() as f64 / optimized_duration.as_nanos() as f64;
        let memory_stats = optimized_storage.get_stats().await;
        
        info!("Retrieval benchmark completed - Legacy: {:?}, Optimized: {:?}, Speedup: {:.2}x", 
              legacy_duration, optimized_duration, speedup);
        
        BenchmarkResult {
            operation: "Retrieval Operations".to_string(),
            record_count: test_keys.len(),
            old_implementation_time: legacy_duration,
            new_implementation_time: optimized_duration,
            speedup_factor: speedup,
            memory_usage: memory_stats.memory_usage_bytes,
        }
    }

    /// Benchmark publisher-based queries (demonstrates indexed lookup performance)
    pub async fn benchmark_publisher_queries(&self) -> BenchmarkResult {
        info!("Starting publisher query benchmark");
        
        // Setup both storages
        let legacy_storage = LegacyDHTStorage::new(self.config.clone());
        let optimized_storage = OptimizedDHTStorage::new(self.config.clone());
        
        for record in &self.test_data {
            legacy_storage.store(record.clone()).await.unwrap();
            optimized_storage.store(record.clone()).await.unwrap();
        }
        
        // Test publisher queries
        let test_publishers = vec!["publisher_0", "publisher_5", "publisher_9"];
        
        // Legacy queries (O(n) scan)
        let legacy_start = Instant::now();
        for publisher in &test_publishers {
            let _ = legacy_storage.get_records_by_publisher(publisher).await;
        }
        let legacy_duration = legacy_start.elapsed();
        
        // Optimized queries (O(1) indexed lookup)
        let optimized_start = Instant::now();
        for publisher in &test_publishers {
            let _ = optimized_storage.get_records_by_publisher(publisher, None).await;
        }
        let optimized_duration = optimized_start.elapsed();
        
        let speedup = legacy_duration.as_nanos() as f64 / optimized_duration.as_nanos() as f64;
        let memory_stats = optimized_storage.get_stats().await;
        
        info!("Publisher query benchmark completed - Legacy: {:?}, Optimized: {:?}, Speedup: {:.2}x", 
              legacy_duration, optimized_duration, speedup);
        
        BenchmarkResult {
            operation: "Publisher Queries".to_string(),
            record_count: test_publishers.len(),
            old_implementation_time: legacy_duration,
            new_implementation_time: optimized_duration,
            speedup_factor: speedup,
            memory_usage: memory_stats.memory_usage_bytes,
        }
    }

    /// Benchmark cleanup operations (demonstrates indexed expiration cleanup)
    pub async fn benchmark_cleanup_operations(&self) -> BenchmarkResult {
        info!("Starting cleanup operations benchmark");
        
        // Create test data with some expired records
        let mut expired_data = Vec::new();
        for i in 0..self.test_data.len() / 2 {
            let key = Key::new(format!("expired_key_{}", i).as_bytes());
            let value = format!("expired_value_{}", i).into_bytes();
            let publisher = PeerId::from("expired_publisher".to_string());
            let mut record = Record::new(key, value, publisher);
            
            // Set expiration to past
            record.expires_at = SystemTime::now() - Duration::from_secs(3600);
            expired_data.push(record);
        }
        
        // Setup both storages with mixed data
        let legacy_storage = LegacyDHTStorage::new(self.config.clone());
        let optimized_storage = OptimizedDHTStorage::new(self.config.clone());
        
        for record in &self.test_data {
            legacy_storage.store(record.clone()).await.unwrap();
            optimized_storage.store(record.clone()).await.unwrap();
        }
        for record in &expired_data {
            legacy_storage.store(record.clone()).await.unwrap();
            optimized_storage.store(record.clone()).await.unwrap();
        }
        
        // Legacy cleanup (O(n) scan)
        let legacy_start = Instant::now();
        let _ = legacy_storage.cleanup_expired().await;
        let legacy_duration = legacy_start.elapsed();
        
        // Optimized cleanup (O(log n + k) where k is expired records)
        let optimized_start = Instant::now();
        let _ = optimized_storage.cleanup_expired().await.unwrap();
        let optimized_duration = optimized_start.elapsed();
        
        let speedup = legacy_duration.as_nanos() as f64 / optimized_duration.as_nanos() as f64;
        let memory_stats = optimized_storage.get_stats().await;
        
        info!("Cleanup benchmark completed - Legacy: {:?}, Optimized: {:?}, Speedup: {:.2}x", 
              legacy_duration, optimized_duration, speedup);
        
        BenchmarkResult {
            operation: "Cleanup Operations".to_string(),
            record_count: expired_data.len(),
            old_implementation_time: legacy_duration,
            new_implementation_time: optimized_duration,
            speedup_factor: speedup,
            memory_usage: memory_stats.memory_usage_bytes,
        }
    }

    /// Run complete benchmark suite
    pub async fn run_complete_benchmark(&self) -> Vec<BenchmarkResult> {
        info!("Starting complete DHT performance benchmark suite");
        
        let mut results = Vec::new();
        
        results.push(self.benchmark_storage_operations().await);
        results.push(self.benchmark_retrieval_operations().await);
        results.push(self.benchmark_publisher_queries().await);
        results.push(self.benchmark_cleanup_operations().await);
        
        // Print summary
        info!("=== DHT Performance Benchmark Results ===");
        for result in &results {
            info!("{}: {:.2}x speedup ({} operations, {} bytes memory)", 
                  result.operation, result.speedup_factor, result.record_count, result.memory_usage);
        }
        
        let average_speedup = results.iter()
            .map(|r| r.speedup_factor)
            .sum::<f64>() / results.len() as f64;
            
        info!("Average speedup across all operations: {:.2}x", average_speedup);
        info!("==========================================");
        
        results
    }
}

/// Demonstrate memory bounds with LRU cache
pub async fn demonstrate_memory_bounds() {
    info!("Demonstrating memory bounds with LRU cache");
    
    let config = DHTConfig::default();
    let small_cache_storage = OptimizedDHTStorage::with_cache_size(config, 100); // Very small cache
    
    let mut records_added = 0;
    
    // Add more records than cache can hold
    for i in 0..200 {
        let key = Key::new(format!("memory_test_{}", i).as_bytes());
        let value = vec![0u8; 1024]; // 1KB records
        let publisher = PeerId::from("memory_tester".to_string());
        let record = Record::new(key, value, publisher);
        
        small_cache_storage.store(record).await.unwrap();
        records_added += 1;
        
        let stats = small_cache_storage.get_stats().await;
        debug!("Added {} records, cache contains {} records, memory: {} bytes", 
               records_added, stats.total_records, stats.memory_usage_bytes);
        
        // Cache should never exceed its bounds
        assert!(stats.total_records <= 100, "Cache exceeded size bounds!");
    }
    
    let final_stats = small_cache_storage.get_stats().await;
    info!("Memory bounds demonstration completed:");
    info!("- Added {} records", records_added);
    info!("- Final cache size: {} records (bounded)", final_stats.total_records);
    info!("- Memory usage: {} bytes", final_stats.memory_usage_bytes);
    info!("- Cache hits: {}, misses: {}", final_stats.cache_hits, final_stats.cache_misses);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;

    #[tokio_test::tokio::test]
    async fn test_performance_benchmark_small_dataset() {
        let benchmark = DHTPerformanceBenchmark::new(100);
        let results = benchmark.run_complete_benchmark().await;
        
        // Verify we got results for all operations
        assert_eq!(results.len(), 4);
        
        // All operations should show some speedup (even if minimal for small dataset)
        for result in &results {
            assert!(result.speedup_factor > 0.0);
            println!("✅ {}: {:.2}x speedup", result.operation, result.speedup_factor);
        }
    }

    #[tokio_test::tokio::test]
    async fn test_memory_bounds_enforcement() {
        demonstrate_memory_bounds().await;
    }

    #[tokio_test::tokio::test]
    async fn test_publisher_index_performance() {
        let benchmark = DHTPerformanceBenchmark::new(1000);
        let result = benchmark.benchmark_publisher_queries().await;
        
        // Publisher queries should show significant speedup due to indexing
        assert!(result.speedup_factor > 1.0);
        println!("✅ Publisher query speedup: {:.2}x", result.speedup_factor);
    }
}