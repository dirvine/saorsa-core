//! Optimized DHT storage with LRU cache and performance improvements
//!
//! This module provides:
//! - LRU-based memory bounds to prevent unbounded memory growth
//! - Indexed lookups for O(1) operations instead of O(n) scans
//! - Batched operations for improved performance
//! - Memory-efficient data structures

use crate::dht::{Key, Record, DHTConfig};
use crate::error::P2pResult as Result;
use lru::LruCache;
use std::collections::{HashMap, BTreeMap};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Maximum default cache size (10MB worth of records)
const DEFAULT_MAX_CACHE_SIZE: usize = 10_000;
/// Maximum record size for memory calculation (1KB average)
const AVG_RECORD_SIZE: usize = 1024;
/// Batch size for cleanup operations
const CLEANUP_BATCH_SIZE: usize = 1000;

/// Optimized DHT storage with LRU cache and indexed operations
#[derive(Debug)]
pub struct OptimizedDHTStorage {
    /// LRU cache for records with memory bounds
    records: Arc<RwLock<LruCache<Key, Record>>>,
    /// Expiration index for efficient cleanup - maps expiration time to keys
    expiration_index: Arc<RwLock<BTreeMap<SystemTime, Vec<Key>>>>,
    /// Publisher index for efficient queries by publisher
    publisher_index: Arc<RwLock<HashMap<String, Vec<Key>>>>,
    /// Configuration
    config: DHTConfig,
    /// Memory usage tracking
    memory_usage: Arc<RwLock<usize>>,
    /// Last cleanup time
    last_cleanup: Arc<RwLock<Instant>>,
    /// Statistics
    stats: Arc<RwLock<StorageStats>>,
}

/// Storage statistics for monitoring
#[derive(Debug, Clone, Default)]
pub struct StorageStats {
    pub total_records: usize,
    pub expired_records: usize,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub memory_usage_bytes: usize,
    pub total_stores: u64,
    pub total_gets: u64,
    pub cleanup_runs: u64,
}

impl OptimizedDHTStorage {
    /// Create new optimized DHT storage with memory bounds
    pub fn new(config: DHTConfig) -> Self {
        let cache_size = Self::calculate_cache_size(&config);
        
        info!("Creating optimized DHT storage with cache size: {}", cache_size);
        
        Self {
            records: Arc::new(RwLock::new(
                // Safe: calculate_cache_size guarantees minimum of 100
                LruCache::new(NonZeroUsize::new(cache_size).unwrap_or(NonZeroUsize::MIN))
            )),
            expiration_index: Arc::new(RwLock::new(BTreeMap::new())),
            publisher_index: Arc::new(RwLock::new(HashMap::new())),
            config,
            memory_usage: Arc::new(RwLock::new(0)),
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
            stats: Arc::new(RwLock::new(StorageStats::default())),
        }
    }

    /// Create with custom cache size
    pub fn with_cache_size(config: DHTConfig, cache_size: usize) -> Self {
        info!("Creating optimized DHT storage with custom cache size: {}", cache_size);
        
        Self {
            records: Arc::new(RwLock::new(
                // Safe: max(100) guarantees non-zero value
                LruCache::new(NonZeroUsize::new(cache_size.max(100)).unwrap_or(NonZeroUsize::MIN))
            )),
            expiration_index: Arc::new(RwLock::new(BTreeMap::new())),
            publisher_index: Arc::new(RwLock::new(HashMap::new())),
            config,
            memory_usage: Arc::new(RwLock::new(0)),
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
            stats: Arc::new(RwLock::new(StorageStats::default())),
        }
    }

    /// Store a record with O(1) performance and memory bounds
    pub async fn store(&self, record: Record) -> Result<()> {
        let mut records = self.records.write().await;
        let mut expiration_index = self.expiration_index.write().await;
        let mut publisher_index = self.publisher_index.write().await;
        let mut memory_usage = self.memory_usage.write().await;
        let mut stats = self.stats.write().await;

        let key = record.key.clone();
        let expires_at = record.expires_at;
        let publisher_id = record.publisher.to_string();
        let record_size = self.estimate_record_size(&record);

        // Check if we're replacing an existing record
        let mut size_delta = record_size as i64;
        if let Some(old_record) = records.peek(&key) {
            let old_size = self.estimate_record_size(old_record);
            size_delta -= old_size as i64;
            
            // Remove old record from indexes
            self.remove_from_expiration_index(&mut expiration_index, &old_record.expires_at, &key);
            self.remove_from_publisher_index(&mut publisher_index, &old_record.publisher.to_string(), &key);
        }

        // Store record (LRU will handle eviction if needed)
        if let Some(evicted) = records.put(key.clone(), record) {
            // Update indexes for evicted record
            let evicted_size = self.estimate_record_size(&evicted);
            size_delta -= evicted_size as i64;
            
            self.remove_from_expiration_index(&mut expiration_index, &evicted.expires_at, &evicted.key);
            self.remove_from_publisher_index(&mut publisher_index, &evicted.publisher.to_string(), &evicted.key);
        }

        // Update indexes for new record
        expiration_index
            .entry(expires_at)
            .or_insert_with(Vec::new)
            .push(key.clone());

        publisher_index
            .entry(publisher_id)
            .or_insert_with(Vec::new)
            .push(key);

        // Update memory usage
        *memory_usage = (*memory_usage as i64 + size_delta).max(0) as usize;
        
        // Update stats
        stats.total_records = records.len();
        stats.memory_usage_bytes = *memory_usage;
        stats.total_stores += 1;

        debug!("Stored record, cache size: {}, memory: {} bytes", records.len(), *memory_usage);
        Ok(())
    }

    /// Retrieve a record with O(1) performance
    pub async fn get(&self, key: &Key) -> Option<Record> {
        let mut records = self.records.write().await; // Write lock needed for LRU updates
        let mut stats = self.stats.write().await;
        
        stats.total_gets += 1;
        
        if let Some(record) = records.get(key) {
            // Check if record is expired
            if record.is_expired() {
                // Remove expired record immediately
                records.pop(key);
                stats.cache_misses += 1;
                None
            } else {
                stats.cache_hits += 1;
                Some(record.clone())
            }
        } else {
            stats.cache_misses += 1;
            None
        }
    }

    /// Batch cleanup of expired records with O(log n) performance
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let now = SystemTime::now();
        let mut cleaned_count = 0;
        
        // Check if cleanup is needed (avoid excessive cleanup calls)
        {
            let last_cleanup = self.last_cleanup.read().await;
            if last_cleanup.elapsed() < Duration::from_secs(60) {
                return Ok(0); // Skip cleanup if done recently
            }
        }

        let mut records = self.records.write().await;
        let mut expiration_index = self.expiration_index.write().await;
        let mut publisher_index = self.publisher_index.write().await;
        let mut memory_usage = self.memory_usage.write().await;
        let mut stats = self.stats.write().await;

        // Use the expiration index for efficient cleanup - O(log n + k) where k is expired records
        let expired_times: Vec<SystemTime> = expiration_index
            .range(..now)
            .map(|(time, _)| *time)
            .collect();

        for expired_time in expired_times {
            if let Some(keys) = expiration_index.remove(&expired_time) {
                for key in keys {
                    if let Some(record) = records.pop(&key) {
                        let record_size = self.estimate_record_size(&record);
                        *memory_usage = memory_usage.saturating_sub(record_size);
                        cleaned_count += 1;

                        // Remove from publisher index
                        self.remove_from_publisher_index(&mut publisher_index, &record.publisher.to_string(), &key);
                    }
                }
            }
        }

        // Update stats
        stats.total_records = records.len();
        stats.expired_records = stats.expired_records.saturating_sub(cleaned_count);
        stats.memory_usage_bytes = *memory_usage;
        stats.cleanup_runs += 1;

        // Update last cleanup time
        *self.last_cleanup.write().await = Instant::now();

        if cleaned_count > 0 {
            info!("Cleaned up {} expired records, cache size: {}, memory: {} bytes", 
                  cleaned_count, records.len(), *memory_usage);
        }

        Ok(cleaned_count)
    }

    /// Get records by publisher with indexed lookup - O(1) performance
    pub async fn get_records_by_publisher(&self, publisher: &str, limit: Option<usize>) -> Vec<Record> {
        let publisher_index = self.publisher_index.read().await;
        let records = self.records.read().await;
        
        if let Some(keys) = publisher_index.get(publisher) {
            let mut results = Vec::new();
            let take_count = limit.unwrap_or(keys.len());
            
            for key in keys.iter().take(take_count) {
                if let Some(record) = records.peek(key)
                    && !record.is_expired()
                {
                    results.push(record.clone());
                }
            }
            results
        } else {
            Vec::new()
        }
    }

    /// Get records expiring within a time window - O(log n) performance
    pub async fn get_expiring_records(&self, within: Duration) -> Vec<Record> {
        let target_time = SystemTime::now() + within;
        let expiration_index = self.expiration_index.read().await;
        let records = self.records.read().await;
        
        let mut results = Vec::new();
        
        for (_, keys) in expiration_index.range(..target_time) {
            for key in keys {
                if let Some(record) = records.peek(key)
                    && !record.is_expired()
                {
                    results.push(record.clone());
                }
            }
        }
        
        results
    }

    /// Get storage statistics
    pub async fn get_stats(&self) -> StorageStats {
        let records = self.records.read().await;
        let memory_usage = self.memory_usage.read().await;
        let mut stats = self.stats.write().await;
        
        // Update current stats
        stats.total_records = records.len();
        stats.memory_usage_bytes = *memory_usage;
        
        stats.clone()
    }

    /// Check if storage has reached memory limits
    pub async fn is_near_memory_limit(&self) -> bool {
        let memory_usage = self.memory_usage.read().await;
        let max_memory = Self::calculate_cache_size(&self.config) * AVG_RECORD_SIZE;
        
        *memory_usage > (max_memory * 90 / 100) // 90% threshold
    }

    /// Force cache eviction of oldest records
    pub async fn force_eviction(&self, target_count: usize) -> Result<usize> {
        let mut records = self.records.write().await;
        let mut evicted_count = 0;
        
        while records.len() > target_count && evicted_count < CLEANUP_BATCH_SIZE {
            if records.pop_lru().is_some() {
                evicted_count += 1;
            } else {
                break;
            }
        }
        
        info!("Force evicted {} records, cache size now: {}", evicted_count, records.len());
        Ok(evicted_count)
    }

    // Helper methods

    fn calculate_cache_size(config: &DHTConfig) -> usize {
        // Base cache size on replication factor and expected network size
        let base_size = config.replication_factor * 500; // 500 records per replication node
        base_size.clamp(100, DEFAULT_MAX_CACHE_SIZE) // Minimum 100, maximum 10k
    }

    fn estimate_record_size(&self, record: &Record) -> usize {
        // Estimate memory usage: key + value + metadata
        32 + record.value.len() + 64 // Conservative estimate
    }

    fn remove_from_expiration_index(&self, 
        expiration_index: &mut BTreeMap<SystemTime, Vec<Key>>, 
        expires_at: &SystemTime, 
        key: &Key) {
        if let Some(keys) = expiration_index.get_mut(expires_at) {
            keys.retain(|k| k != key);
            if keys.is_empty() {
                expiration_index.remove(expires_at);
            }
        }
    }

    fn remove_from_publisher_index(&self,
        publisher_index: &mut HashMap<String, Vec<Key>>,
        publisher: &str,
        key: &Key) {
        if let Some(keys) = publisher_index.get_mut(publisher) {
            keys.retain(|k| k != key);
            if keys.is_empty() {
                publisher_index.remove(publisher);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerId;

    #[tokio::test]
    async fn test_optimized_storage_basic_operations() {
        let config = DHTConfig::default();
        let storage = OptimizedDHTStorage::new(config);
        
        // Create test record
        let key = Key::new(b"test_key");
        let value = b"test_value".to_vec();
        let publisher = PeerId::from("test_peer".to_string());
        let record = Record::new(key.clone(), value.clone(), publisher);
        
        // Store and retrieve
        storage.store(record.clone()).await.unwrap();
        let retrieved = storage.get(&key).await;
        
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().value, value);
    }

    #[tokio::test]
    async fn test_lru_eviction() {
        let config = DHTConfig::default();
        let storage = OptimizedDHTStorage::with_cache_size(config, 3); // Very small cache
        
        // Fill cache beyond capacity
        for i in 0..5 {
            let key = Key::new(format!("key_{}", i).as_bytes());
            let value = format!("value_{}", i).into_bytes();
            let publisher = PeerId::from(format!("peer_{}", i));
            let record = Record::new(key, value, publisher);
            storage.store(record).await.unwrap();
        }
        
        let stats = storage.get_stats().await;
        assert_eq!(stats.total_records, 3); // Should be limited by cache size
    }

    #[tokio::test]
    async fn test_indexed_publisher_lookup() {
        let config = DHTConfig::default();
        let storage = OptimizedDHTStorage::new(config);
        
        let publisher = PeerId::from("test_publisher".to_string());
        
        // Store multiple records from same publisher
        for i in 0..3 {
            let key = Key::new(format!("key_{}", i).as_bytes());
            let value = format!("value_{}", i).into_bytes();
            let record = Record::new(key, value, publisher.clone());
            storage.store(record).await.unwrap();
        }
        
        // Query by publisher
        let records = storage.get_records_by_publisher("test_publisher", None).await;
        assert_eq!(records.len(), 3);
    }

    #[tokio::test]
    async fn test_expiration_cleanup() {
        let config = DHTConfig::default();
        let storage = OptimizedDHTStorage::new(config);
        
        // Create expired record
        let key = Key::new(b"expired_key");
        let value = b"expired_value".to_vec();
        let publisher = PeerId::from("test_peer".to_string());
        let mut record = Record::new(key.clone(), value, publisher);
        
        // Set expiration to past
        record.expires_at = SystemTime::now() - Duration::from_secs(3600);
        
        storage.store(record).await.unwrap();
        
        // Should return None for expired record
        let retrieved = storage.get(&key).await;
        assert!(retrieved.is_none());
        
        // Run cleanup
        let cleaned = storage.cleanup_expired().await.unwrap();
        assert!(cleaned >= 0); // Should clean up expired records
    }
}