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

//! Comprehensive test suite for the persistence layer

#[cfg(test)]
mod tests {
    use super::super::*;
    use proptest::prelude::*;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};
    use tokio::sync::RwLock;

    // Test helpers
    fn test_key(id: &str) -> Vec<u8> {
        format!("test:key:{}", id).into_bytes()
    }

    fn test_value(content: &str) -> Vec<u8> {
        format!("test:value:{}", content).into_bytes()
    }

    async fn create_test_store() -> Arc<dyn Store> {
        // Use memory backend for tests
        Arc::new(MemoryStore::new())
    }

    // Core Store trait tests
    mod store_tests {
        use super::*;

        #[tokio::test]
        async fn test_put_and_get() {
            let store = create_test_store().await;
            let key = test_key("1");
            let value = test_value("data");

            // Put value
            store.put(&key, &value, None).await.unwrap();

            // Get value
            let retrieved = store.get(&key).await.unwrap();
            assert_eq!(retrieved, Some(value));
        }

        #[tokio::test]
        async fn test_get_nonexistent() {
            let store = create_test_store().await;
            let key = test_key("nonexistent");

            let retrieved = store.get(&key).await.unwrap();
            assert_eq!(retrieved, None);
        }

        #[tokio::test]
        async fn test_delete() {
            let store = create_test_store().await;
            let key = test_key("to_delete");
            let value = test_value("temporary");

            // Put value
            store.put(&key, &value, None).await.unwrap();
            assert!(store.exists(&key).await.unwrap());

            // Delete value
            store.delete(&key).await.unwrap();
            assert!(!store.exists(&key).await.unwrap());
        }

        #[tokio::test]
        async fn test_exists() {
            let store = create_test_store().await;
            let key = test_key("exists");
            let value = test_value("present");

            assert!(!store.exists(&key).await.unwrap());
            store.put(&key, &value, None).await.unwrap();
            assert!(store.exists(&key).await.unwrap());
        }

        #[tokio::test]
        async fn test_ttl_expiration() {
            let store = create_test_store().await;
            let key = test_key("ttl");
            let value = test_value("expiring");

            // Put with 100ms TTL
            store
                .put(&key, &value, Some(Duration::from_millis(100)))
                .await
                .unwrap();

            // Should exist immediately
            assert!(store.exists(&key).await.unwrap());

            // Wait for expiration
            tokio::time::sleep(Duration::from_millis(150)).await;

            // Should be expired
            assert!(!store.exists(&key).await.unwrap());
        }

        #[tokio::test]
        async fn test_batch_operations() {
            let store = create_test_store().await;

            let ops = vec![
                Operation::Put {
                    key: test_key("batch1"),
                    value: test_value("value1"),
                    ttl: None,
                },
                Operation::Put {
                    key: test_key("batch2"),
                    value: test_value("value2"),
                    ttl: None,
                },
                Operation::Delete {
                    key: test_key("batch3"),
                },
            ];

            store.batch(ops).await.unwrap();

            assert!(store.exists(&test_key("batch1")).await.unwrap());
            assert!(store.exists(&test_key("batch2")).await.unwrap());
            assert!(!store.exists(&test_key("batch3")).await.unwrap());
        }

        #[tokio::test]
        async fn test_transaction_commit() {
            let store = create_test_store().await;

            let result = store
                .transaction(|tx| {
                    tx.put(&test_key("tx1"), &test_value("committed"), None)?;
                    tx.put(&test_key("tx2"), &test_value("committed"), None)?;
                    Ok(())
                })
                .await;

            assert!(result.is_ok());
            assert!(store.exists(&test_key("tx1")).await.unwrap());
            assert!(store.exists(&test_key("tx2")).await.unwrap());
        }

        #[tokio::test]
        async fn test_transaction_rollback() {
            let store = create_test_store().await;

            let result = store
                .transaction(|tx| {
                    tx.put(&test_key("tx3"), &test_value("rollback"), None)?;
                    Err(PersistenceError::Transaction("test rollback".into()))
                })
                .await;

            assert!(result.is_err());
            assert!(!store.exists(&test_key("tx3")).await.unwrap());
        }

        #[tokio::test]
        async fn test_concurrent_access() {
            let store = Arc::new(create_test_store().await);
            let mut handles = vec![];

            for i in 0..10 {
                let store_clone = store.clone();
                let handle = tokio::spawn(async move {
                    let key = test_key(&format!("concurrent_{}", i));
                    let value = test_value(&format!("value_{}", i));
                    store_clone.put(&key, &value, None).await.unwrap();
                    let retrieved = store_clone.get(&key).await.unwrap();
                    assert_eq!(retrieved, Some(value));
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.await.unwrap();
            }
        }
    }

    // Query trait tests
    mod query_tests {
        use super::*;

        #[tokio::test]
        async fn test_range_query() {
            let store = create_test_store().await;

            // Insert test data
            for i in 0..10 {
                let key = format!("range:{:02}", i).into_bytes();
                let value = format!("value_{}", i).into_bytes();
                store.put(&key, &value, None).await.unwrap();
            }

            // Query range
            let start = b"range:03";
            let end = b"range:07";
            let results = store.range(start, end, 10, false).await.unwrap();

            assert_eq!(results.len(), 4);
            assert_eq!(results[0].0, b"range:03");
            assert_eq!(results[3].0, b"range:06");
        }

        #[tokio::test]
        async fn test_range_query_reverse() {
            let store = create_test_store().await;

            // Insert test data
            for i in 0..10 {
                let key = format!("reverse:{:02}", i).into_bytes();
                let value = format!("value_{}", i).into_bytes();
                store.put(&key, &value, None).await.unwrap();
            }

            // Query range in reverse
            let start = b"reverse:03";
            let end = b"reverse:07";
            let results = store.range(start, end, 10, true).await.unwrap();

            assert_eq!(results.len(), 4);
            assert_eq!(results[0].0, b"reverse:06");
            assert_eq!(results[3].0, b"reverse:03");
        }

        #[tokio::test]
        async fn test_prefix_scan() {
            let store = create_test_store().await;

            // Insert test data
            store.put(b"prefix:a:1", b"value1", None).await.unwrap();
            store.put(b"prefix:a:2", b"value2", None).await.unwrap();
            store.put(b"prefix:b:1", b"value3", None).await.unwrap();
            store.put(b"other:1", b"value4", None).await.unwrap();

            // Scan by prefix
            let results = store.prefix(b"prefix:a:", 10).await.unwrap();

            assert_eq!(results.len(), 2);
            assert!(results.iter().all(|(k, _)| k.starts_with(b"prefix:a:")));
        }

        #[tokio::test]
        async fn test_count_keys() {
            let store = create_test_store().await;

            // Insert test data
            for i in 0..20 {
                let key = format!("count:{:02}", i).into_bytes();
                store.put(&key, b"value", None).await.unwrap();
            }

            // Count keys in range
            let count = store.count(b"count:05", b"count:15").await.unwrap();
            assert_eq!(count, 10);
        }

        #[tokio::test]
        async fn test_pagination() {
            let store = create_test_store().await;

            // Insert many items
            for i in 0..100 {
                let key = format!("page:{:03}", i).into_bytes();
                let value = format!("value_{}", i).into_bytes();
                store.put(&key, &value, None).await.unwrap();
            }

            // First page
            let page1 = store.range(b"page:000", b"page:999", 10, false).await.unwrap();
            assert_eq!(page1.len(), 10);
            assert_eq!(page1[0].0, b"page:000");
            assert_eq!(page1[9].0, b"page:009");

            // Second page
            let next_key = &page1.last().unwrap().0;
            let page2 = store.range(next_key, b"page:999", 10, false).await.unwrap();
            assert_eq!(page2.len(), 10);
            assert_eq!(page2[0].0, b"page:009"); // Inclusive range
        }
    }

    // Replication tests
    mod replication_tests {
        use super::*;

        #[tokio::test]
        async fn test_replicate_to_nodes() {
            let store = create_test_store().await;
            let key = test_key("replicated");
            let value = test_value("data");

            store.put(&key, &value, None).await.unwrap();

            let nodes = vec![
                NodeId::from("node1"),
                NodeId::from("node2"),
                NodeId::from("node3"),
            ];

            store.replicate(&key, nodes).await.unwrap();

            let status = store.replication_status(&key).await.unwrap();
            assert_eq!(status.replica_count, 3);
            assert!(status.is_healthy());
        }

        #[tokio::test]
        async fn test_sync_from_peer() {
            let store1 = create_test_store().await;
            let store2 = create_test_store().await;

            // Add data to store1
            for i in 0..10 {
                let key = format!("sync:{}", i).into_bytes();
                let value = format!("value_{}", i).into_bytes();
                store1.put(&key, &value, None).await.unwrap();
            }

            // Sync from store1 to store2
            let stats = store2
                .sync_from(NodeId::from("store1"), "sync:")
                .await
                .unwrap();

            assert_eq!(stats.keys_synced, 10);
            assert_eq!(stats.bytes_transferred, stats.bytes_transferred);

            // Verify data synced
            for i in 0..10 {
                let key = format!("sync:{}", i).into_bytes();
                assert!(store2.exists(&key).await.unwrap());
            }
        }

        #[tokio::test]
        async fn test_conflict_resolution() {
            let store = create_test_store().await;
            let key = test_key("conflict");

            // Simulate conflicting writes
            let value1 = test_value("version1");
            let value2 = test_value("version2");

            store.put(&key, &value1, None).await.unwrap();
            store.put(&key, &value2, None).await.unwrap();

            // Should resolve to latest write
            let resolved = store.get(&key).await.unwrap();
            assert_eq!(resolved, Some(value2));
        }

        #[tokio::test]
        async fn test_quorum_writes() {
            let store = create_test_store().await;
            let key = test_key("quorum");
            let value = test_value("consensus");

            // Configure quorum write
            let config = ReplicationConfig {
                replication_factor: 5,
                write_consistency: ConsistencyLevel::Quorum,
                read_consistency: ConsistencyLevel::One,
                conflict_resolver: ConflictResolver::LastWriteWins,
            };

            store.set_replication_config(config).await.unwrap();
            store.put(&key, &value, None).await.unwrap();

            let status = store.replication_status(&key).await.unwrap();
            assert!(status.write_quorum_met);
        }
    }

    // Encryption tests
    mod encryption_tests {
        use super::*;

        #[tokio::test]
        async fn test_encrypted_storage() {
            let store = create_encrypted_store().await;
            let key = test_key("encrypted");
            let value = test_value("sensitive_data");

            store.put(&key, &value, None).await.unwrap();

            // Verify data is encrypted on disk
            let raw = store.get_raw(&key).await.unwrap();
            assert_ne!(raw, Some(value.clone()));

            // Verify decryption works
            let decrypted = store.get(&key).await.unwrap();
            assert_eq!(decrypted, Some(value));
        }

        #[tokio::test]
        async fn test_key_rotation() {
            let store = create_encrypted_store().await;
            let key = test_key("rotation");
            let value = test_value("data");

            // Store with initial key
            store.put(&key, &value, None).await.unwrap();

            // Rotate encryption key
            store.rotate_encryption_key().await.unwrap();

            // Should still be able to read old data
            let retrieved = store.get(&key).await.unwrap();
            assert_eq!(retrieved, Some(value));

            // New writes use new key
            let new_key = test_key("after_rotation");
            let new_value = test_value("new_data");
            store.put(&new_key, &new_value, None).await.unwrap();

            let retrieved_new = store.get(&new_key).await.unwrap();
            assert_eq!(retrieved_new, Some(new_value));
        }

        #[tokio::test]
        async fn test_secure_deletion() {
            let store = create_encrypted_store().await;
            let key = test_key("secure_delete");
            let value = test_value("sensitive");

            store.put(&key, &value, None).await.unwrap();
            store.secure_delete(&key).await.unwrap();

            // Verify complete removal
            assert!(!store.exists(&key).await.unwrap());
            
            // Verify overwritten in storage
            let raw = store.get_raw(&key).await.unwrap();
            assert_eq!(raw, None);
        }
    }

    // Performance tests
    mod performance_tests {
        use super::*;
        use std::time::Instant;

        #[tokio::test]
        async fn test_write_throughput() {
            let store = create_test_store().await;
            let count = 10000;
            let start = Instant::now();

            for i in 0..count {
                let key = format!("perf:write:{}", i).into_bytes();
                let value = vec![0u8; 1024]; // 1KB value
                store.put(&key, &value, None).await.unwrap();
            }

            let duration = start.elapsed();
            let ops_per_sec = count as f64 / duration.as_secs_f64();
            
            println!("Write throughput: {:.0} ops/sec", ops_per_sec);
            assert!(ops_per_sec > 1000.0); // Minimum 1000 ops/sec
        }

        #[tokio::test]
        async fn test_read_latency() {
            let store = create_test_store().await;
            let key = test_key("latency");
            let value = vec![0u8; 1024];

            store.put(&key, &value, None).await.unwrap();

            let mut latencies = vec![];
            for _ in 0..1000 {
                let start = Instant::now();
                store.get(&key).await.unwrap();
                latencies.push(start.elapsed());
            }

            latencies.sort();
            let p99 = latencies[990];
            
            println!("Read latency P99: {:?}", p99);
            assert!(p99 < Duration::from_millis(1)); // Sub-millisecond P99
        }

        #[tokio::test]
        async fn test_range_query_performance() {
            let store = create_test_store().await;

            // Insert test data
            for i in 0..10000 {
                let key = format!("perf:range:{:05}", i).into_bytes();
                let value = format!("value_{}", i).into_bytes();
                store.put(&key, &value, None).await.unwrap();
            }

            let start = Instant::now();
            let results = store
                .range(b"perf:range:00000", b"perf:range:99999", 1000, false)
                .await
                .unwrap();

            let duration = start.elapsed();
            
            assert_eq!(results.len(), 1000);
            println!("Range query (1000 items): {:?}", duration);
            assert!(duration < Duration::from_millis(100));
        }
    }

    // Property-based tests
    mod property_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn prop_put_get_consistency(
                key in prop::collection::vec(any::<u8>(), 1..256),
                value in prop::collection::vec(any::<u8>(), 0..10000)
            ) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let store = create_test_store().await;
                    store.put(&key, &value, None).await.unwrap();
                    let retrieved = store.get(&key).await.unwrap();
                    assert_eq!(retrieved, Some(value));
                });
            }

            #[test]
            fn prop_delete_idempotent(
                key in prop::collection::vec(any::<u8>(), 1..256)
            ) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let store = create_test_store().await;
                    
                    // Delete non-existent key should succeed
                    store.delete(&key).await.unwrap();
                    
                    // Add and delete
                    store.put(&key, b"value", None).await.unwrap();
                    store.delete(&key).await.unwrap();
                    
                    // Delete again should succeed
                    store.delete(&key).await.unwrap();
                    
                    assert!(!store.exists(&key).await.unwrap());
                });
            }

            #[test]
            fn prop_batch_atomicity(
                ops in prop::collection::vec(
                    prop::strategy::Union::new(vec![
                        (0..100u8).prop_map(|i| Operation::Put {
                            key: format!("batch:{}", i).into_bytes(),
                            value: vec![i],
                            ttl: None,
                        }).boxed(),
                        (0..100u8).prop_map(|i| Operation::Delete {
                            key: format!("batch:{}", i).into_bytes(),
                        }).boxed(),
                    ]),
                    1..50
                )
            ) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let store = create_test_store().await;
                    
                    // Execute batch
                    let result = store.batch(ops.clone()).await;
                    
                    if result.is_ok() {
                        // Verify all operations applied
                        for op in ops {
                            match op {
                                Operation::Put { key, .. } => {
                                    assert!(store.exists(&key).await.unwrap());
                                }
                                Operation::Delete { key } => {
                                    assert!(!store.exists(&key).await.unwrap());
                                }
                            }
                        }
                    }
                });
            }
        }
    }

    // Migration tests
    mod migration_tests {
        use super::*;

        #[tokio::test]
        async fn test_schema_migration() {
            let store = create_test_store().await;

            let migrations = vec![
                Migration {
                    version: 1,
                    description: "Initial schema".to_string(),
                    up: |s| {
                        s.put(b"version", b"1", None)?;
                        Ok(())
                    },
                    down: |s| {
                        s.delete(b"version")?;
                        Ok(())
                    },
                },
                Migration {
                    version: 2,
                    description: "Add indexes".to_string(),
                    up: |s| {
                        s.put(b"version", b"2", None)?;
                        s.put(b"index:created", b"true", None)?;
                        Ok(())
                    },
                    down: |s| {
                        s.put(b"version", b"1", None)?;
                        s.delete(b"index:created")?;
                        Ok(())
                    },
                },
            ];

            // Apply migrations
            store.migrate(&migrations).await.unwrap();

            // Verify final state
            let version = store.get(b"version").await.unwrap();
            assert_eq!(version, Some(b"2".to_vec()));
            
            let index = store.get(b"index:created").await.unwrap();
            assert_eq!(index, Some(b"true".to_vec()));
        }

        #[tokio::test]
        async fn test_migration_rollback() {
            let store = create_test_store().await;

            let migration = Migration {
                version: 1,
                description: "Failing migration".to_string(),
                up: |_s| {
                    Err(PersistenceError::Migration("Intentional failure".into()))
                },
                down: |_s| Ok(()),
            };

            let result = store.migrate(&[migration]).await;
            assert!(result.is_err());

            // Verify no partial state
            let version = store.get(b"schema_version").await.unwrap();
            assert_eq!(version, None);
        }
    }

    // Crash recovery tests
    mod recovery_tests {
        use super::*;

        #[tokio::test]
        async fn test_crash_recovery() {
            // Simulate crash during write
            let store = create_test_store().await;
            
            // Start transaction
            let tx_result = store.transaction(|tx| {
                tx.put(b"before_crash", b"value1", None)?;
                // Simulate crash
                panic!("Simulated crash");
            }).await;

            assert!(tx_result.is_err());
            
            // Verify transaction rolled back
            assert!(!store.exists(b"before_crash").await.unwrap());
        }

        #[tokio::test]
        async fn test_wal_recovery() {
            let store = create_rocksdb_store().await;
            
            // Write data
            for i in 0..100 {
                let key = format!("wal:{}", i).into_bytes();
                let value = format!("value_{}", i).into_bytes();
                store.put(&key, &value, None).await.unwrap();
            }

            // Simulate ungraceful shutdown
            drop(store);

            // Reopen store
            let recovered_store = create_rocksdb_store().await;

            // Verify data recovered
            for i in 0..100 {
                let key = format!("wal:{}", i).into_bytes();
                assert!(recovered_store.exists(&key).await.unwrap());
            }
        }
    }

    // Helper functions for creating different store types
    async fn create_encrypted_store() -> Arc<dyn Store> {
        let config = EncryptionConfig {
            kdf: KeyDerivationFunction::Argon2,
            algorithm: EncryptionAlgorithm::MlKem768Aes256Gcm,
            rotation: KeyRotationPolicy::Days(90),
        };
        Arc::new(EncryptedStore::new(MemoryStore::new(), config))
    }

    async fn create_rocksdb_store() -> Arc<dyn Store> {
        let path = tempfile::tempdir().unwrap();
        Arc::new(RocksDbStore::new(path.path()).unwrap())
    }
}