//! Comprehensive DHT Core Operations Test Suite
//!
//! This test suite validates the critical DHT operations that form the backbone
//! of the decentralized P2P network. It ensures correctness, performance,
//! memory safety, and concurrent access safety.

use anyhow::Result;

use saorsa_core::dht::{DHTConfig, Record, optimized_storage::OptimizedDHTStorage};
use saorsa_core::identity::node_identity::NodeId;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Barrier;
use tokio::task::JoinHandle;

/// Test helper to create a test record
fn create_test_record(key_suffix: &str, publisher: &str, value: &str) -> Record {
    let key = {
        let bytes = format!("test_key_{}", key_suffix).into_bytes();
        let mut key = [0u8; 32];
        let len = bytes.len().min(32);
        key[..len].copy_from_slice(&bytes[..len]);
        key
    };
    let value = value.as_bytes().to_vec();
    // Create NodeId from publisher string by hashing it
    let publisher_bytes = *blake3::hash(publisher.as_bytes()).as_bytes();
    let publisher = NodeId::from_bytes(publisher_bytes);
    Record::new(key, value, publisher)
}

/// Test helper to create an expired record
fn create_expired_record(key_suffix: &str, publisher: &str, value: &str) -> Record {
    let mut record = create_test_record(key_suffix, publisher, value);
    record.expires_at = SystemTime::now() - Duration::from_secs(3600); // Expired 1 hour ago
    record
}

/// Test helper to create multiple test records
fn create_test_records(count: usize, publisher_count: usize) -> Vec<Record> {
    let mut records = Vec::new();
    for i in 0..count {
        let key_suffix = i.to_string();
        let publisher = format!("publisher_{}", i % publisher_count);
        let value = format!("value_{}", i);
        records.push(create_test_record(&key_suffix, &publisher, &value));
    }
    records
}

#[tokio::test]
async fn test_basic_crud_operations() -> Result<()> {
    let config = DHTConfig::default();
    let storage = OptimizedDHTStorage::new(config);

    // Test store and retrieve
    let record = create_test_record("basic", "test_publisher", "test_value");
    let key = record.key;

    storage.store(record.clone()).await?;

    let retrieved = storage.get(&key).await;
    assert!(
        retrieved.is_some(),
        "Record should be retrievable after storage"
    );

    let retrieved = retrieved.unwrap();
    assert_eq!(
        retrieved.key, record.key,
        "Retrieved key should match stored key"
    );
    assert_eq!(
        retrieved.value, record.value,
        "Retrieved value should match stored value"
    );
    assert_eq!(
        retrieved.publisher, record.publisher,
        "Retrieved publisher should match stored publisher"
    );

    // Test overwrite
    let new_record = create_test_record("basic", "new_publisher", "new_value");
    storage.store(new_record.clone()).await?;

    let retrieved = storage.get(&key).await.unwrap();
    assert_eq!(
        retrieved.publisher, new_record.publisher,
        "Record should be overwritten"
    );
    assert_eq!(
        retrieved.value, new_record.value,
        "Value should be overwritten"
    );

    // Test non-existent key
    let non_existent_key = {
        let bytes = b"non_existent";
        let mut key = [0u8; 32];
        let len = bytes.len().min(32);
        key[..len].copy_from_slice(&bytes[..len]);
        key
    };
    let result = storage.get(&non_existent_key).await;
    assert!(result.is_none(), "Non-existent key should return None");

    println!("✅ Basic CRUD operations test passed");
    Ok(())
}

#[tokio::test]
async fn test_lru_eviction_behavior() -> Result<()> {
    let config = DHTConfig::default();
    let storage = OptimizedDHTStorage::with_cache_size(config, 5); // Very small cache for testing

    let records = create_test_records(10, 1); // More records than cache can hold

    // Store all records
    for record in &records {
        storage.store(record.clone()).await?;
    }

    // Cache should be bounded to 5 records
    let stats = storage.get_stats().await;
    assert_eq!(
        stats.total_records, 5,
        "Cache should be bounded to configured size"
    );

    // The last 5 records should be in cache (LRU evicted the first 5)
    for i in 5..10 {
        let key = &records[i].key;
        let retrieved = storage.get(key).await;
        assert!(
            retrieved.is_some(),
            "Recently added record {} should still be in cache",
            i
        );
    }

    // Access the first few records to make them recently used
    for i in 5..7 {
        let _ = storage.get(&records[i].key).await;
    }

    // Add more records to trigger more eviction
    let new_records = create_test_records(3, 1);
    for record in &new_records {
        storage.store(record.clone()).await?;
    }

    // Recently accessed records should still be there
    for i in 5..7 {
        let retrieved = storage.get(&records[i].key).await;
        assert!(
            retrieved.is_some(),
            "Recently accessed record {} should not be evicted",
            i
        );
    }

    println!("✅ LRU eviction behavior test passed");
    Ok(())
}

#[tokio::test]
async fn test_expired_record_handling() -> Result<()> {
    let config = DHTConfig::default();
    let storage = OptimizedDHTStorage::new(config);

    // Store expired record
    let expired_record = create_expired_record("expired", "test_publisher", "expired_value");
    let expired_key = expired_record.key;

    storage.store(expired_record).await?;

    // Retrieving expired record should return None
    let retrieved = storage.get(&expired_key).await;
    assert!(
        retrieved.is_none(),
        "Expired record should not be retrievable"
    );

    // Store mix of expired and valid records
    let expired_records: Vec<_> = (0..3)
        .map(|i| {
            create_expired_record(
                &format!("exp_{}", i),
                "publisher",
                &format!("exp_val_{}", i),
            )
        })
        .collect();

    let valid_records = create_test_records(3, 1);

    for record in &expired_records {
        storage.store(record.clone()).await?;
    }
    for record in &valid_records {
        storage.store(record.clone()).await?;
    }

    // Run cleanup
    let cleaned_count = storage.cleanup_expired().await?;
    assert!(
        cleaned_count >= 3,
        "Should clean up at least the 3 expired records we added"
    );

    // Valid records should still be accessible
    for record in &valid_records {
        let retrieved = storage.get(&record.key).await;
        assert!(
            retrieved.is_some(),
            "Valid record should still be accessible after cleanup"
        );
    }

    println!("✅ Expired record handling test passed");
    Ok(())
}

#[tokio::test]
async fn test_publisher_index_consistency() -> Result<()> {
    let config = DHTConfig::default();
    let storage = OptimizedDHTStorage::new(config);

    // Store records from multiple publishers
    let publishers = ["alice", "bob", "charlie"];
    let mut expected_counts = HashMap::new();
    let mut publisher_node_ids = HashMap::new();

    for (i, record) in create_test_records(15, 3).into_iter().enumerate() {
        let publisher_name = &publishers[i % 3];
        let mut record = record;
        // Create NodeId from publisher string by hashing it
        let publisher_bytes = *blake3::hash(publisher_name.as_bytes()).as_bytes();
        let node_id = NodeId::from_bytes(publisher_bytes);
        let node_id_str = node_id.to_string();

        // Track the mapping for later queries
        publisher_node_ids.insert(publisher_name.to_string(), node_id_str.clone());
        record.publisher = node_id;

        storage.store(record).await?;
        *expected_counts.entry(node_id_str).or_insert(0) += 1;
    }

    // Test publisher queries
    for (publisher_str, expected_count) in &expected_counts {
        let records = storage.get_records_by_publisher(publisher_str, None).await;
        assert_eq!(
            records.len(),
            *expected_count,
            "Publisher {} should have {} records",
            publisher_str,
            expected_count
        );

        // All returned records should belong to the correct publisher
        for record in &records {
            assert_eq!(
                record.publisher.to_string(),
                *publisher_str,
                "All records should belong to queried publisher"
            );
        }
    }

    // Test publisher query with limit
    let default_string = String::new();
    let alice_node_id = publisher_node_ids.get("alice").unwrap_or(&default_string);
    let limited_records = storage
        .get_records_by_publisher(alice_node_id, Some(2))
        .await;
    assert!(
        limited_records.len() <= 2,
        "Limited query should respect limit"
    );

    // Test query for non-existent publisher
    let empty_records = storage.get_records_by_publisher("nonexistent", None).await;
    assert!(
        empty_records.is_empty(),
        "Non-existent publisher should return empty results"
    );

    println!("✅ Publisher index consistency test passed");
    Ok(())
}

#[tokio::test]
async fn test_memory_bounds_enforcement() -> Result<()> {
    let config = DHTConfig::default();
    let storage = OptimizedDHTStorage::with_cache_size(config, 100); // Small cache

    // Track memory usage throughout the test
    let mut memory_readings = Vec::new();

    // Add records and monitor memory
    for batch in 0..5 {
        // Add a batch of records
        for i in 0..50 {
            let key = format!("memory_test_{}_{}", batch, i);
            let record = create_test_record(&key, "memory_tester", &format!("data_{}", i));
            storage.store(record).await?;
        }

        let stats = storage.get_stats().await;
        memory_readings.push((
            batch * 50 + 50,
            stats.total_records,
            stats.memory_usage_bytes,
        ));

        // Cache should never exceed bounds
        assert!(
            stats.total_records <= 100,
            "Cache size should never exceed bounds: {} <= 100",
            stats.total_records
        );
    }

    // Print memory progression for verification
    println!("Memory progression:");
    for (records_added, cache_size, memory_bytes) in &memory_readings {
        println!(
            "  Added: {}, Cache: {}, Memory: {} bytes",
            records_added, cache_size, memory_bytes
        );
    }

    // Memory should be bounded even with many operations
    let final_stats = storage.get_stats().await;
    assert!(
        final_stats.total_records <= 100,
        "Final cache size should be bounded"
    );

    // Test that memory bounds are maintained under heavy access
    let test_keys: Vec<_> = (0..200)
        .map(|i| {
            let bytes = format!("access_test_{}", i).into_bytes();
            let mut key = [0u8; 32];
            let len = bytes.len().min(32);
            key[..len].copy_from_slice(&bytes[..len]);
            key
        })
        .collect();

    // Heavy access pattern that could cause memory issues
    for _ in 0..10 {
        for key in &test_keys {
            let _ = storage.get(key).await; // Cache miss, but shouldn't grow unbounded
        }
    }

    let stress_stats = storage.get_stats().await;
    assert!(
        stress_stats.total_records <= 100,
        "Memory should stay bounded even under heavy access"
    );

    println!("✅ Memory bounds enforcement test passed");
    Ok(())
}

#[tokio::test]
async fn test_concurrent_access_safety() -> Result<()> {
    let config = DHTConfig::default();
    let storage = Arc::new(OptimizedDHTStorage::new(config));

    let barrier = Arc::new(Barrier::new(10)); // 10 concurrent tasks
    let mut handles = Vec::new();

    // Spawn multiple concurrent tasks
    for task_id in 0..10 {
        let storage_clone = Arc::clone(&storage);
        let barrier_clone = Arc::clone(&barrier);

        let handle: JoinHandle<Result<()>> = tokio::spawn(async move {
            barrier_clone.wait().await; // Synchronize start

            // Each task performs various operations
            for i in 0..100 {
                let key_suffix = format!("{}_{}", task_id, i);
                let record = create_test_record(
                    &key_suffix,
                    &format!("task_{}", task_id),
                    &format!("value_{}", i),
                );

                // Store record
                storage_clone.store(record.clone()).await?;

                // Immediate retrieval
                let retrieved = storage_clone.get(&record.key).await;
                assert!(
                    retrieved.is_some(),
                    "Record should be immediately retrievable"
                );

                // Publisher query - convert to NodeId string representation
                let publisher_str = format!("task_{}", task_id);
                let publisher_bytes = *blake3::hash(publisher_str.as_bytes()).as_bytes();
                let publisher_node_id = NodeId::from_bytes(publisher_bytes);
                let publisher_records = storage_clone
                    .get_records_by_publisher(&publisher_node_id.to_string(), None)
                    .await;
                assert!(
                    !publisher_records.is_empty(),
                    "Publisher should have records"
                );
            }

            Ok(())
        });

        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await??;
    }

    // Verify final state consistency
    let final_stats = storage.get_stats().await;
    println!("Concurrent access test completed:");
    println!("  Final records: {}", final_stats.total_records);
    println!(
        "  Total operations: {}",
        final_stats.total_stores + final_stats.total_gets
    );
    println!(
        "  Cache hits: {}, misses: {}",
        final_stats.cache_hits, final_stats.cache_misses
    );

    // Verify some records from each task exist
    for task_id in 0..10 {
        let publisher_str = format!("task_{}", task_id);
        let publisher_bytes = *blake3::hash(publisher_str.as_bytes()).as_bytes();
        let publisher_node_id = NodeId::from_bytes(publisher_bytes);
        let publisher_records = storage
            .get_records_by_publisher(&publisher_node_id.to_string(), None)
            .await;
        assert!(
            !publisher_records.is_empty(),
            "Each task should have contributed some records"
        );
    }

    println!("✅ Concurrent access safety test passed");
    Ok(())
}

#[tokio::test]
async fn test_index_consistency_invariants() -> Result<()> {
    let config = DHTConfig::default();
    let storage = Arc::new(OptimizedDHTStorage::with_cache_size(config, 50)); // Small cache to trigger evictions

    // Helper function to verify index consistency
    let verify_consistency = |test_name: &'static str, storage: Arc<OptimizedDHTStorage>| async move {
        let stats = storage.get_stats().await;

        // All publisher queries should return valid records
        let all_publishers: HashSet<String> = (0..10)
            .map(|i| format!("consistency_publisher_{}", i))
            .collect();

        let mut total_indexed_records = 0;
        for publisher in &all_publishers {
            let records = storage.get_records_by_publisher(publisher, None).await;
            total_indexed_records += records.len();

            // All returned records should be valid and match the publisher
            for record in &records {
                assert_eq!(
                    record.publisher.to_string(),
                    *publisher,
                    "{}: Publisher index returned record from wrong publisher",
                    test_name
                );
                assert!(
                    !record.is_expired(),
                    "{}: Publisher index should not return expired records",
                    test_name
                );
            }
        }

        println!(
            "{}: Total records: {}, Indexed records: {}",
            test_name, stats.total_records, total_indexed_records
        );
    };

    // Test 1: Initial state
    let records = create_test_records(30, 10);
    for record in &records {
        storage.store(record.clone()).await?;
    }
    verify_consistency("After initial load", storage.clone()).await;

    // Test 2: After triggering evictions
    let more_records = create_test_records(40, 10);
    for record in &more_records {
        storage.store(record.clone()).await?;
    }
    verify_consistency("After triggering evictions", storage.clone()).await;

    // Test 3: After cleanup operations
    let expired_records: Vec<_> = (0..10)
        .map(|i| {
            create_expired_record(
                &format!("expired_{}", i),
                &format!("consistency_publisher_{}", i % 10),
                "expired",
            )
        })
        .collect();

    for record in &expired_records {
        storage.store(record.clone()).await?;
    }

    storage.cleanup_expired().await?;
    verify_consistency("After cleanup", storage.clone()).await;

    // Test 4: After record updates (overwriting existing records)
    let update_records: Vec<_> = (0..10)
        .map(|i| {
            create_test_record(
                &format!("update_{}", i),
                &format!("consistency_publisher_{}", i),
                &format!("updated_value_{}", i),
            )
        })
        .collect();

    for record in &update_records {
        storage.store(record.clone()).await?;
        storage.store(record.clone()).await?; // Store twice to test overwrite
    }
    verify_consistency("After record updates", storage.clone()).await;

    println!("✅ Index consistency invariants test passed");
    Ok(())
}

#[tokio::test]
async fn test_performance_characteristics() -> Result<()> {
    let config = DHTConfig::default();
    let storage = OptimizedDHTStorage::new(config);

    // Load test data
    let record_count = 5000;
    let publisher_count = 50;
    let records = create_test_records(record_count, publisher_count);

    println!(
        "🚀 Performance characteristics test with {} records",
        record_count
    );

    // Measure storage performance
    let storage_start = Instant::now();
    for record in &records {
        storage.store(record.clone()).await?;
    }
    let storage_time = storage_start.elapsed();

    // Measure retrieval performance
    let retrieval_keys: Vec<_> = records.iter().step_by(10).map(|r| &r.key).collect();
    let retrieval_start = Instant::now();
    let mut retrieved_count = 0;
    for key in &retrieval_keys {
        if storage.get(key).await.is_some() {
            retrieved_count += 1;
        }
    }
    let retrieval_time = retrieval_start.elapsed();

    // Measure publisher query performance (this should be O(1))
    // Note: create_test_records uses 5 publishers (publisher_0 through publisher_4)
    let test_publishers: Vec<_> = (0..5)
        .map(|i| {
            let publisher_str = format!("publisher_{}", i);
            let publisher_bytes = *blake3::hash(publisher_str.as_bytes()).as_bytes();
            let publisher_node_id = NodeId::from_bytes(publisher_bytes);
            publisher_node_id.to_string()
        })
        .collect();
    let query_start = Instant::now();
    let mut total_query_results = 0;
    for publisher in &test_publishers {
        let results = storage.get_records_by_publisher(publisher, None).await;
        total_query_results += results.len();
    }
    let query_time = query_start.elapsed();

    // Performance metrics
    let storage_rate = record_count as f64 / storage_time.as_secs_f64();
    let retrieval_rate = retrieved_count as f64 / retrieval_time.as_secs_f64();
    let query_rate = test_publishers.len() as f64 / query_time.as_secs_f64();

    println!("📊 Performance Results:");
    println!(
        "  Storage: {:.0} records/sec ({:?} total)",
        storage_rate, storage_time
    );
    println!(
        "  Retrieval: {:.0} lookups/sec ({:?} total)",
        retrieval_rate, retrieval_time
    );
    println!(
        "  Publisher queries: {:.0} queries/sec ({:?} total)",
        query_rate, query_time
    );
    println!("  Query results: {} records found", total_query_results);

    // Performance assertions (these should be fast with our optimizations)
    assert!(
        storage_rate > 1000.0,
        "Storage should handle >1000 records/sec"
    );
    assert!(
        retrieval_rate > 5000.0,
        "Retrieval should handle >5000 lookups/sec"
    );
    assert!(
        query_rate > 100.0,
        "Publisher queries should handle >100 queries/sec"
    );

    // Memory efficiency check
    let stats = storage.get_stats().await;
    let memory_per_record = stats.memory_usage_bytes as f64 / stats.total_records as f64;
    println!("  Memory efficiency: {:.1} bytes/record", memory_per_record);

    assert!(
        memory_per_record < 2000.0,
        "Memory usage should be reasonable (<2KB/record)"
    );

    println!("✅ Performance characteristics test passed");
    Ok(())
}

#[tokio::test]
async fn test_stress_scenarios() -> Result<()> {
    let config = DHTConfig::default();
    let storage = OptimizedDHTStorage::with_cache_size(config, 1000);

    println!("🔥 Stress testing DHT storage");

    // Stress test 1: Rapid insertions with cache pressure
    println!("  Stress test 1: Rapid insertions");
    for batch in 0..10 {
        let batch_records = create_test_records(500, 20);
        for record in batch_records {
            storage.store(record).await?;
        }

        if batch % 3 == 0 {
            storage.cleanup_expired().await?;
        }
    }

    let stats_after_insertions = storage.get_stats().await;
    assert!(
        stats_after_insertions.total_records <= 1000,
        "Cache bounds should be maintained under stress"
    );

    // Stress test 2: Mixed workload (reads, writes, queries)
    println!("  Stress test 2: Mixed workload");
    let test_publisher_names: Vec<_> = (0..20).map(|i| format!("stress_publisher_{}", i)).collect();
    let test_publishers: Vec<_> = test_publisher_names
        .iter()
        .map(|name| {
            let publisher_bytes = *blake3::hash(name.as_bytes()).as_bytes();
            let publisher_node_id = NodeId::from_bytes(publisher_bytes);
            publisher_node_id.to_string()
        })
        .collect();

    for round in 0..20 {
        // Write phase
        for i in 0..25 {
            let record = create_test_record(
                &format!("stress_{}_{}", round, i),
                &test_publisher_names[i % test_publisher_names.len()],
                &format!("stress_value_{}_{}", round, i),
            );
            storage.store(record).await?;
        }

        // Read phase
        for i in 0..25 {
            let key = {
                let bytes = format!("stress_{}_{}", round, i).into_bytes();
                let mut k = [0u8; 32];
                let len = bytes.len().min(32);
                k[..len].copy_from_slice(&bytes[..len]);
                k
            };
            let _ = storage.get(&key).await;
        }

        // Query phase
        for publisher in test_publishers.iter().take(5) {
            let _ = storage.get_records_by_publisher(publisher, Some(10)).await;
        }
    }

    // Stress test 3: Concurrent heavy access
    println!("  Stress test 3: Concurrent heavy access");
    let storage_arc = Arc::new(storage);
    let mut handles = Vec::new();

    for task_id in 0..5 {
        let storage_clone = Arc::clone(&storage_arc);
        let handle = tokio::spawn(async move {
            for i in 0..200 {
                let record = create_test_record(
                    &format!("concurrent_{}_{}", task_id, i),
                    &format!("task_{}", task_id),
                    &format!("value_{}_{}", task_id, i),
                );
                storage_clone.store(record.clone()).await?;

                // Immediate read back
                let _ = storage_clone.get(&record.key).await;

                // Publisher query every 10 operations
                if i % 10 == 0 {
                    let publisher_str = format!("task_{}", task_id);
                    let publisher_bytes = *blake3::hash(publisher_str.as_bytes()).as_bytes();
                    let publisher_node_id = NodeId::from_bytes(publisher_bytes);
                    let _ = storage_clone
                        .get_records_by_publisher(&publisher_node_id.to_string(), Some(5))
                        .await;
                }
            }
            anyhow::Ok(())
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await??;
    }

    let final_stats = storage_arc.get_stats().await;
    println!("  Final stress test stats:");
    println!("    Records: {}", final_stats.total_records);
    println!("    Memory: {} bytes", final_stats.memory_usage_bytes);
    println!(
        "    Operations: {} stores, {} gets",
        final_stats.total_stores, final_stats.total_gets
    );
    println!(
        "    Hit ratio: {:.1}%",
        (final_stats.cache_hits as f64
            / (final_stats.cache_hits + final_stats.cache_misses) as f64)
            * 100.0
    );

    // System should remain stable after stress testing
    assert!(
        final_stats.total_records <= 1000,
        "Cache bounds maintained through stress"
    );
    assert!(
        final_stats.memory_usage_bytes > 0,
        "Memory tracking should work"
    );

    println!("✅ Stress scenarios test passed");
    Ok(())
}

/// Integration test that validates the complete DHT system
#[tokio::test]
async fn test_dht_system_integration() -> Result<()> {
    let config = DHTConfig::default();
    let storage = OptimizedDHTStorage::new(config);

    println!("🔗 DHT System Integration Test");

    // Simulate realistic P2P network usage patterns
    struct NetworkNode {
        id: String,
    }

    let nodes: Vec<NetworkNode> = (0..20)
        .map(|i| NetworkNode {
            id: format!("node_{}", i),
        })
        .collect();

    // Phase 1: Network bootstrapping - nodes publish their data
    println!("  Phase 1: Network bootstrapping");
    for (node_idx, node) in nodes.iter().enumerate() {
        // Each node publishes some data
        for data_idx in 0..50 {
            let key = format!("{}:data:{}", node.id, data_idx);
            let value = format!("node_{}_data_{}", node_idx, data_idx);
            let record = create_test_record(&key, &node.id, &value);

            storage.store(record).await?;
        }
    }

    let bootstrap_stats = storage.get_stats().await;
    println!(
        "    After bootstrap: {} records",
        bootstrap_stats.total_records
    );

    // Phase 2: Network operation - nodes access each other's data
    println!("  Phase 2: Network operation");
    for access_round in 0..10 {
        // Each node accesses data from random other nodes
        for node_idx in 0..nodes.len() {
            let target_node_idx = (node_idx + access_round + 1) % nodes.len();
            let target_node = &nodes[target_node_idx];

            // Query for the target node's data - convert to NodeId string representation
            let target_publisher_bytes = *blake3::hash(target_node.id.as_bytes()).as_bytes();
            let target_publisher_node_id = NodeId::from_bytes(target_publisher_bytes);
            let target_records = storage
                .get_records_by_publisher(&target_publisher_node_id.to_string(), Some(5))
                .await;

            // Access some specific records
            for (i, record) in target_records.iter().enumerate().take(3) {
                let retrieved = storage.get(&record.key).await;
                assert!(
                    retrieved.is_some(),
                    "Published network data should be accessible"
                );

                if i == 0 {
                    // First access might trigger re-ordering in LRU cache
                    let _ = storage.get(&record.key).await;
                }
            }
        }
    }

    // Phase 3: Network maintenance - cleanup and optimization
    println!("  Phase 3: Network maintenance");

    // Add some expired records to simulate real network conditions
    for i in 0..20 {
        let expired_record = create_expired_record(
            &format!("expired_{}", i),
            &format!("node_{}", i % 5),
            "expired_data",
        );
        storage.store(expired_record).await?;
    }

    let before_cleanup = storage.get_stats().await;
    let cleaned = storage.cleanup_expired().await?;
    let after_cleanup = storage.get_stats().await;

    println!("    Cleanup removed {} expired records", cleaned);
    println!(
        "    Records before: {}, after: {}",
        before_cleanup.total_records, after_cleanup.total_records
    );

    // Phase 4: System validation
    println!("  Phase 4: System validation");

    // Verify data integrity across the network
    let mut total_node_records = 0;
    for node in &nodes {
        // Convert node.id to NodeId string representation
        let node_publisher_bytes = *blake3::hash(node.id.as_bytes()).as_bytes();
        let node_publisher_node_id = NodeId::from_bytes(node_publisher_bytes);
        let node_records = storage
            .get_records_by_publisher(&node_publisher_node_id.to_string(), None)
            .await;
        total_node_records += node_records.len();

        // Each node should have some data
        assert!(
            !node_records.is_empty(),
            "Each network node should have published data"
        );

        // Verify record integrity
        for record in &node_records {
            assert_eq!(
                record.publisher.to_string(),
                node.id,
                "Record publisher should match"
            );
            assert!(!record.is_expired(), "Active records should not be expired");
        }
    }

    println!("    Total node records found: {}", total_node_records);

    // System health check
    let final_stats = storage.get_stats().await;
    let hit_ratio = (final_stats.cache_hits as f64
        / (final_stats.cache_hits + final_stats.cache_misses) as f64)
        * 100.0;

    println!("  System health:");
    println!("    Total records: {}", final_stats.total_records);
    println!("    Memory usage: {} bytes", final_stats.memory_usage_bytes);
    println!("    Cache hit ratio: {:.1}%", hit_ratio);
    println!(
        "    Total operations: {} stores, {} gets",
        final_stats.total_stores, final_stats.total_gets
    );

    // System should be healthy after integration test
    assert!(
        hit_ratio > 50.0,
        "Cache should be effective in realistic usage"
    );
    assert!(final_stats.total_records > 0, "System should contain data");
    assert!(
        final_stats.memory_usage_bytes > 0,
        "Memory tracking should work"
    );

    println!("✅ DHT System Integration test passed");
    Ok(())
}
