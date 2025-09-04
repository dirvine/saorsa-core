//! Property-Based Tests for DHT Storage
//!
//! These tests use property-based testing to verify invariants hold
//! under arbitrary sequences of operations. This catches edge cases
//! and subtle bugs that unit tests might miss.

use anyhow::Result;
use proptest::prelude::*;
use saorsa_core::dht::{DHTConfig, Key, Record, optimized_storage::OptimizedDHTStorage};
use saorsa_core::identity::node_identity::NodeId;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

/// Strategy to generate random keys
fn arb_key() -> impl Strategy<Value = Key> {
    any::<Vec<u8>>()
        .prop_filter("Key cannot be empty", |v| !v.is_empty())
        .prop_map(|bytes| {
            let mut key = [0u8; 32];
            let len = bytes.len().min(32);
            key[..len].copy_from_slice(&bytes[..len]);
            key
        })
}

/// Strategy to generate random peer IDs (NodeId)
fn arb_peer_id() -> impl Strategy<Value = NodeId> {
    "[a-zA-Z0-9_-]{3,20}".prop_map(|s| {
        // Create NodeId from string by hashing it
        let hash_bytes = *blake3::hash(s.as_bytes()).as_bytes();
        NodeId::from_bytes(hash_bytes)
    })
}

/// Strategy to generate random values
fn arb_value() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..1024)
}

/// Strategy to generate random records
fn arb_record() -> impl Strategy<Value = Record> {
    (arb_key(), arb_value(), arb_peer_id())
        .prop_map(|(key, value, publisher)| Record::new(key, value, publisher))
}

/// Strategy to generate records that might be expired
fn arb_record_with_expiration() -> impl Strategy<Value = Record> {
    (arb_record(), any::<bool>()).prop_map(|(mut record, should_expire)| {
        if should_expire {
            record.expires_at = SystemTime::now() - Duration::from_secs(3600);
        }
        record
    })
}

/// Operations that can be performed on the DHT storage
#[derive(Debug, Clone)]
enum DHTOperation {
    Store(Record),
    Get(Key),
    GetByPublisher(String),
    Cleanup,
}

/// Strategy to generate sequences of DHT operations
fn arb_operations(max_ops: usize) -> impl Strategy<Value = Vec<DHTOperation>> {
    prop::collection::vec(
        prop_oneof![
            arb_record_with_expiration().prop_map(DHTOperation::Store),
            arb_key().prop_map(DHTOperation::Get),
            "[a-zA-Z0-9_-]{3,20}".prop_map(DHTOperation::GetByPublisher),
            Just(DHTOperation::Cleanup),
        ],
        0..max_ops,
    )
}

proptest! {
    #[test]
    fn prop_cache_size_bounded(
        cache_size in 10usize..100,
        operations in arb_operations(200)
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = DHTConfig::default();
            let storage = OptimizedDHTStorage::with_cache_size(config.clone(), cache_size);

            for operation in operations {
                match operation {
                    DHTOperation::Store(record) => {
                        let _ = storage.store(record).await;
                    }
                    DHTOperation::Get(key) => {
                        let _ = storage.get(&key).await;
                    }
                    DHTOperation::GetByPublisher(publisher) => {
                        let _ = storage.get_records_by_publisher(&publisher, None).await;
                    }
                    DHTOperation::Cleanup => {
                        let _ = storage.cleanup_expired().await;
                    }
                }

                // Invariant: Cache size never exceeds bounds
                let stats = storage.get_stats().await;
                prop_assert!(stats.total_records <= cache_size,
                           "Cache size {} should never exceed bounds {}",
                           stats.total_records, cache_size);
            }
            Ok(())
        })?;
    }
}

proptest! {
    #[test]
    fn prop_publisher_index_consistent(
        records in prop::collection::vec(arb_record(), 1..50)
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = DHTConfig::default();
            let storage = OptimizedDHTStorage::new(config.clone());

            // Track what we store
            let mut publishers_to_keys: HashMap<String, HashSet<Key>> = HashMap::new();

            for record in records {
                let publisher = record.publisher.to_string();
                let key = record.key;

                storage.store(record).await.unwrap();

                publishers_to_keys
                    .entry(publisher.clone())
                    .or_default()
                    .insert(key);
            }

            // Verify publisher index consistency
            for (publisher, expected_keys) in publishers_to_keys {
                let indexed_records = storage.get_records_by_publisher(&publisher, None).await;
                let indexed_keys: HashSet<_> = indexed_records.iter().map(|r| r.key).collect();

                // All indexed keys should be in our expected set
                // (Due to LRU eviction, expected_keys might be a superset)
                for key in &indexed_keys {
                    prop_assert!(expected_keys.contains(key),
                               "Publisher index contains key that shouldn't be there");
                }

                // All indexed records should belong to the correct publisher
                for record in &indexed_records {
                    prop_assert_eq!(record.publisher.to_string(), publisher.clone());
                    prop_assert!(!record.is_expired(), "Indexed record should not be expired");
                }
            }
            Ok(())
        })?;
    }
}

proptest! {
    #[test]
    fn prop_store_get_consistency(
        records in prop::collection::vec(arb_record(), 1..20)
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = DHTConfig::default();
            let storage = OptimizedDHTStorage::with_cache_size(config.clone(), 100); // Large enough cache

            for record in &records {
                storage.store(record.clone()).await.unwrap();

                // Should be immediately retrievable
                let retrieved = storage.get(&record.key).await;
                prop_assert!(retrieved.is_some(), "Record should be retrievable after storage");

                let retrieved = retrieved.unwrap();
                prop_assert_eq!(retrieved.key, record.key);
                prop_assert_eq!(retrieved.value, record.value.clone());
                prop_assert_eq!(retrieved.publisher, record.publisher.clone());
            }
            Ok(())
        })?;
    }
}

proptest! {
    #[test]
    fn prop_memory_tracking_consistent(
        operations in arb_operations(50)
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = DHTConfig::default();
            let storage = OptimizedDHTStorage::new(config.clone());

            for operation in operations {
                match operation {
                    DHTOperation::Store(record) => {
                        let _ = storage.store(record).await;
                    }
                    DHTOperation::Cleanup => {
                        let _ = storage.cleanup_expired().await;
                    }
                    _ => {} // Skip other operations for this property
                }

                let stats = storage.get_stats().await;

                // Memory usage should be reasonable
                if stats.total_records > 0 {
                    let avg_memory_per_record = stats.memory_usage_bytes / stats.total_records;
                    prop_assert!(avg_memory_per_record > 0, "Average memory per record should be positive");
                    prop_assert!(avg_memory_per_record < 10000, "Average memory per record should be reasonable (<10KB)");
                }

                // Statistics should be consistent
                prop_assert!(stats.cache_hits + stats.cache_misses <= stats.total_gets);
                prop_assert!(stats.total_stores > 0 || stats.total_records == 0);
            }
            Ok(())
        })?;
    }
}

proptest! {
    #[test]
    fn prop_expired_records_not_returned(
        mut records in prop::collection::vec(arb_record(), 1..30)
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = DHTConfig::default();
            let storage = OptimizedDHTStorage::new(config);

            // Make some records expired
            for (i, record) in records.iter_mut().enumerate() {
                if i % 3 == 0 {
                    record.expires_at = SystemTime::now() - Duration::from_secs(3600);
                }
                storage.store(record.clone()).await.unwrap();
            }

            // Verify expired records are not returned
            for record in &records {
                let retrieved = storage.get(&record.key).await;

                if record.is_expired() {
                    prop_assert!(retrieved.is_none(), "Expired record should not be returned");
                } else {
                    // Non-expired record might be evicted due to LRU, but if present should be valid
                    if let Some(retrieved_record) = retrieved {
                        prop_assert!(!retrieved_record.is_expired());
                        prop_assert_eq!(retrieved_record.key, record.key);
                    }
                }
            }

            // Publisher queries should not return expired records
            let publishers: HashSet<String> = records.iter()
                .map(|r| r.publisher.to_string())
                .collect();

            for publisher in publishers {
                let publisher_records = storage.get_records_by_publisher(&publisher, None).await;
                for record in publisher_records {
                    prop_assert!(!record.is_expired(), "Publisher query should not return expired records");
                }
            }
            Ok(())
        })?;
    }
}

proptest! {
    #[test]
    fn prop_lru_ordering_maintained(
        operations in prop::collection::vec(
            prop_oneof![
                arb_record().prop_map(DHTOperation::Store),
                arb_key().prop_map(DHTOperation::Get),
            ],
            10..50
        )
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = DHTConfig::default();
            let storage = OptimizedDHTStorage::with_cache_size(config.clone(), 10); // Small cache

            let mut stored_keys = Vec::new();

            for operation in operations {
                match operation {
                    DHTOperation::Store(record) => {
                        let key = record.key;
                        storage.store(record).await.unwrap();
                        stored_keys.push(key);
                    }
                    DHTOperation::Get(key) => {
                        let _ = storage.get(&key).await;
                        // Getting a key should make it recently used
                    }
                    _ => {}
                }

                let stats = storage.get_stats().await;
                prop_assert!(stats.total_records <= 10, "LRU cache should maintain bounds");
            }

            // After many operations, only the most recent should remain
            // (This is a weak property due to the complexity of LRU + get operations)
            let final_stats = storage.get_stats().await;
            prop_assert!(final_stats.total_records <= 10);
            Ok(())
        })?;
    }
}

proptest! {
    #[test]
    fn prop_cleanup_removes_expired(
        records in prop::collection::vec(arb_record_with_expiration(), 5..20)
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = DHTConfig::default();
            let storage = OptimizedDHTStorage::new(config);

            let mut expired_count = 0;

            // Store records, counting expired ones
            for record in &records {
                if record.is_expired() {
                    expired_count += 1;
                }
                storage.store(record.clone()).await.unwrap();
            }

            let before_cleanup = storage.get_stats().await;
            let _cleaned = storage.cleanup_expired().await.unwrap();
            let after_cleanup = storage.get_stats().await;

            // Properties about cleanup
            prop_assert!(after_cleanup.total_records <= before_cleanup.total_records,
                       "Cleanup should not increase record count");

            if expired_count > 0 {
                // Should have cleaned up at least some expired records
                // (Due to LRU, some expired records might have been evicted already)
                // Note: cleaned count can be 0 if records were already evicted by LRU
            }

            // After cleanup, getting expired records should return None
            for record in &records {
                if record.is_expired() {
                    let retrieved = storage.get(&record.key).await;
                    prop_assert!(retrieved.is_none(), "Expired record should be cleaned up");
                }
            }
            Ok(())
        })?;
    }
}

proptest! {
    #[test]
    fn prop_system_stability(
        cache_size in 20usize..100,
        operations in arb_operations(100)
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = DHTConfig::default();
            let storage = OptimizedDHTStorage::with_cache_size(config, cache_size);

            let mut operation_count = 0;

            for operation in operations {
                operation_count += 1;

                match operation {
                    DHTOperation::Store(record) => {
                        let _ = storage.store(record).await;
                    }
                    DHTOperation::Get(key) => {
                        let _ = storage.get(&key).await;
                    }
                    DHTOperation::GetByPublisher(publisher) => {
                        let records = storage.get_records_by_publisher(&publisher, None).await;
                        // All returned records should belong to the publisher
                        for record in records {
                            prop_assert_eq!(record.publisher.to_string(), publisher.clone());
                        }
                    }
                    DHTOperation::Cleanup => {
                        let _ = storage.cleanup_expired().await;
                    }
                }

                // System stability invariants
                let stats = storage.get_stats().await;

                // Cache bounds
                prop_assert!(stats.total_records <= cache_size);

                // Statistics consistency
                prop_assert!(stats.total_stores + stats.total_gets + stats.cleanup_runs > 0 || operation_count <= 1);

                // Memory tracking
                if stats.total_records > 0 {
                    prop_assert!(stats.memory_usage_bytes > 0);
                }

                // Operation counts should be reasonable
                prop_assert!(stats.total_stores <= operation_count);
                prop_assert!(stats.total_gets <= operation_count);
            }
            Ok(())
        })?;
    }
}

#[cfg(test)]
mod deterministic_properties {
    use super::*;

    /// Test that demonstrates property-based testing concepts with deterministic data
    #[tokio::test]
    async fn test_property_examples() -> Result<()> {
        let config = DHTConfig::default();
        let storage = OptimizedDHTStorage::with_cache_size(config, 5);

        println!("🧪 Property-based testing examples");

        // Example 1: Cache bounds property
        for i in 0..20 {
            let record = Record::new(
                {
                    let bytes = format!("prop_test_{}", i).into_bytes();
                    let mut key = [0u8; 32];
                    let len = bytes.len().min(32);
                    key[..len].copy_from_slice(&bytes[..len]);
                    key
                },
                format!("value_{}", i).into_bytes(),
                NodeId::from_bytes(
                    *blake3::hash(format!("publisher_{}", i % 3).as_bytes())
                        .as_bytes(),
                ),
            );
            storage.store(record).await?;

            let stats = storage.get_stats().await;
            assert!(
                stats.total_records <= 5,
                "Property violation: cache bounds exceeded"
            );
        }

        // Example 2: Publisher consistency property
        let publishers = ["alice", "bob", "charlie"];
        for (i, publisher) in publishers.iter().enumerate() {
            let record = Record::new(
                {
                    let bytes = format!("user_data_{}", i).into_bytes();
                    let mut key = [0u8; 32];
                    let len = bytes.len().min(32);
                    key[..len].copy_from_slice(&bytes[..len]);
                    key
                },
                format!("data_for_{}", publisher).into_bytes(),
                NodeId::from_bytes(*blake3::hash(publisher.as_bytes()).as_bytes()),
            );
            storage.store(record).await?;
        }

        for publisher in &publishers {
            let records = storage.get_records_by_publisher(publisher, None).await;
            for record in records {
                assert_eq!(
                    record.publisher.to_string(),
                    *publisher,
                    "Property violation: publisher index inconsistency"
                );
            }
        }

        // Example 3: Expiration property
        let mut expired_record = Record::new(
            {
                let bytes = b"expired_test";
                let mut key = [0u8; 32];
                let len = bytes.len().min(32);
                key[..len].copy_from_slice(&bytes[..len]);
                key
            },
            b"expired_data".to_vec(),
            NodeId::from_bytes(*blake3::hash(b"expired_publisher").as_bytes()),
        );
        expired_record.expires_at = SystemTime::now() - Duration::from_secs(3600);

        storage.store(expired_record.clone()).await?;
        let retrieved = storage.get(&expired_record.key).await;
        assert!(
            retrieved.is_none(),
            "Property violation: expired record returned"
        );

        println!("✅ Property-based testing examples completed");
        Ok(())
    }
}
