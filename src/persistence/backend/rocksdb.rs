// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! RocksDB storage backend implementation

use async_trait::async_trait;
use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, DB, IteratorMode, Options, WriteBatch};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

use crate::persistence::{
    ConsistencyLevel, HealthStatus, Migrate, Migration, Monitor, NodeId, Operation,
    PersistenceError, Query, Replicate, ReplicationConfig, ReplicationStatus, Result,
    StorageConfig, StorageHealth, StorageMetrics, Store, SyncStats, Transaction,
};

/// Column family names
const CF_DEFAULT: &str = "default";
const CF_METADATA: &str = "metadata";
const CF_TTL: &str = "ttl";

/// RocksDB storage implementation
pub struct RocksDbStore {
    db: Arc<DB>,
    replication_config: Arc<RwLock<ReplicationConfig>>,
    schema_version: Arc<RwLock<Option<u32>>>,
    config: StorageConfig,
}

impl RocksDbStore {
    /// Create a new RocksDB store
    pub fn new(config: StorageConfig) -> Result<Self> {
        let path = config.path.as_ref().ok_or_else(|| {
            PersistenceError::InvalidKey("Storage path required for RocksDB".into())
        })?;

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        // Performance optimizations
        db_opts.set_max_open_files(1000);
        db_opts.set_max_background_jobs(4);
        db_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);

        // Cache configuration
        if config.cache_size_mb > 0 {
            let cache_size = config.cache_size_mb as usize * 1024 * 1024;
            let cache = rocksdb::Cache::new_lru_cache(cache_size);
            db_opts.set_row_cache(&cache);
        }

        // Column families
        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_DEFAULT, Options::default()),
            ColumnFamilyDescriptor::new(CF_METADATA, Options::default()),
            ColumnFamilyDescriptor::new(CF_TTL, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&db_opts, path, cfs)
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(Self {
            db: Arc::new(db),
            replication_config: Arc::new(RwLock::new(config.replication.clone())),
            schema_version: Arc::new(RwLock::new(None)),
            config,
        })
    }

    /// Get column family handle
    fn cf_handle(&self, name: &str) -> Result<&ColumnFamily> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| PersistenceError::Backend(format!("Column family {} not found", name)))
    }

    /// Check if key has expired based on TTL
    async fn is_expired(&self, key: &[u8]) -> Result<bool> {
        let ttl_cf = self.cf_handle(CF_TTL)?;
        if let Some(ttl_bytes) = self
            .db
            .get_cf(ttl_cf, key)
            .map_err(|e| PersistenceError::Backend(e.to_string()))?
        {
            let ttl = u64::from_be_bytes([
                ttl_bytes[0],
                ttl_bytes[1],
                ttl_bytes[2],
                ttl_bytes[3],
                ttl_bytes[4],
                ttl_bytes[5],
                ttl_bytes[6],
                ttl_bytes[7],
            ]);

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            return Ok(now > ttl);
        }
        Ok(false)
    }

    /// Clean up expired keys
    async fn cleanup_expired(&self) -> Result<usize> {
        let ttl_cf = self.cf_handle(CF_TTL)?;
        let default_cf = self.cf_handle(CF_DEFAULT)?;

        let mut expired_keys = Vec::new();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let iter = self.db.iterator_cf(ttl_cf, IteratorMode::Start);

        for item in iter {
            let (key, ttl_bytes) = item.map_err(|e| PersistenceError::Backend(e.to_string()))?;
            let ttl = u64::from_be_bytes([
                ttl_bytes[0],
                ttl_bytes[1],
                ttl_bytes[2],
                ttl_bytes[3],
                ttl_bytes[4],
                ttl_bytes[5],
                ttl_bytes[6],
                ttl_bytes[7],
            ]);

            if now > ttl {
                expired_keys.push(key.to_vec());
            }
        }

        let deleted_count = expired_keys.len();

        if !expired_keys.is_empty() {
            let mut batch = WriteBatch::default();
            for key in expired_keys {
                batch.delete_cf(default_cf, &key);
                batch.delete_cf(ttl_cf, &key);
            }

            self.db
                .write(batch)
                .map_err(|e| PersistenceError::Backend(e.to_string()))?;
        }

        Ok(deleted_count)
    }
}

#[async_trait]
impl Store for RocksDbStore {
    async fn put(&self, key: &[u8], value: &[u8], ttl: Option<Duration>) -> Result<()> {
        let default_cf = self.cf_handle(CF_DEFAULT)?;

        let mut batch = WriteBatch::default();
        batch.put_cf(default_cf, key, value);

        if let Some(ttl_duration) = ttl {
            let ttl_cf = self.cf_handle(CF_TTL)?;
            let expiry = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + ttl_duration.as_secs();

            let ttl_bytes = expiry.to_be_bytes();
            batch.put_cf(ttl_cf, key, &ttl_bytes);
        }

        let mut write_opts = rocksdb::WriteOptions::default();
        match self.config.sync_policy {
            SyncPolicy::Always => write_opts.set_sync(true),
            SyncPolicy::Never => write_opts.set_sync(false),
            SyncPolicy::Periodic(_) => write_opts.set_sync(false),
        }

        self.db
            .write_opt(batch, &write_opts)
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        // Check if expired
        if self.is_expired(key).await? {
            self.delete(key).await?;
            return Ok(None);
        }

        let default_cf = self.cf_handle(CF_DEFAULT)?;
        let result = self
            .db
            .get_cf(default_cf, key)
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(result)
    }

    async fn delete(&self, key: &[u8]) -> Result<()> {
        let default_cf = self.cf_handle(CF_DEFAULT)?;
        let ttl_cf = self.cf_handle(CF_TTL)?;

        let mut batch = WriteBatch::default();
        batch.delete_cf(default_cf, key);
        batch.delete_cf(ttl_cf, key);

        self.db
            .write(batch)
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn exists(&self, key: &[u8]) -> Result<bool> {
        if self.is_expired(key).await? {
            self.delete(key).await?;
            return Ok(false);
        }

        let default_cf = self.cf_handle(CF_DEFAULT)?;
        self.db
            .get_cf(default_cf, key)
            .map_err(|e| PersistenceError::Backend(e.to_string()))
            .map(|v| v.is_some())
    }

    async fn batch(&self, ops: Vec<Operation>) -> Result<()> {
        let default_cf = self.cf_handle(CF_DEFAULT)?;
        let ttl_cf = self.cf_handle(CF_TTL)?;

        let mut batch = WriteBatch::default();

        for op in ops {
            match op {
                Operation::Put { key, value, ttl } => {
                    batch.put_cf(default_cf, &key, &value);

                    if let Some(ttl_duration) = ttl {
                        let expiry = SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            + ttl_duration.as_secs();

                        let ttl_bytes = expiry.to_be_bytes();
                        batch.put_cf(ttl_cf, &key, &ttl_bytes);
                    }
                }
                Operation::Delete { key } => {
                    batch.delete_cf(default_cf, &key);
                    batch.delete_cf(ttl_cf, &key);
                }
            }
        }

        let mut write_opts = rocksdb::WriteOptions::default();
        match self.config.sync_policy {
            SyncPolicy::Always => write_opts.set_sync(true),
            _ => write_opts.set_sync(false),
        }

        self.db
            .write_opt(batch, &write_opts)
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn transaction<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Transaction) -> Result<R> + Send,
        R: Send,
    {
        let mut tx = Transaction::new();
        let result = f(&mut tx)?;
        self.batch(tx.operations().to_vec()).await?;
        Ok(result)
    }
}

#[async_trait]
impl Query for RocksDbStore {
    async fn range(
        &self,
        start: &[u8],
        end: &[u8],
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let default_cf = self.cf_handle(CF_DEFAULT)?;

        let iter = self.db.iterator_cf(
            default_cf,
            rocksdb::IteratorMode::From(start, rocksdb::Direction::Forward),
        );

        let mut results = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| PersistenceError::Backend(e.to_string()))?;

            if key.as_ref() >= end {
                break;
            }

            if !self.is_expired(key.as_ref()).await? {
                results.push((key.to_vec(), value.to_vec()));
                if results.len() >= limit {
                    break;
                }
            }
        }

        if reverse {
            results.reverse();
        }

        Ok(results)
    }

    async fn prefix(&self, prefix: &[u8], limit: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let default_cf = self.cf_handle(CF_DEFAULT)?;

        let iter = self.db.iterator_cf(
            default_cf,
            rocksdb::IteratorMode::From(prefix, rocksdb::Direction::Forward),
        );

        let mut results = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| PersistenceError::Backend(e.to_string()))?;

            if !key.as_ref().starts_with(prefix) {
                break;
            }

            if !self.is_expired(key.as_ref()).await? {
                results.push((key.to_vec(), value.to_vec()));
                if results.len() >= limit {
                    break;
                }
            }
        }

        Ok(results)
    }

    async fn count(&self, start: &[u8], end: &[u8]) -> Result<usize> {
        let default_cf = self.cf_handle(CF_DEFAULT)?;

        let iter = self.db.iterator_cf(
            default_cf,
            rocksdb::IteratorMode::From(start, rocksdb::Direction::Forward),
        );

        let mut count = 0;
        for item in iter {
            let (key, _) = item.map_err(|e| PersistenceError::Backend(e.to_string()))?;

            if key.as_ref() >= end {
                break;
            }

            if !self.is_expired(key.as_ref()).await? {
                count += 1;
            }
        }

        Ok(count)
    }
}

#[async_trait]
impl Replicate for RocksDbStore {
    async fn replicate(&self, key: &[u8], nodes: Vec<NodeId>) -> Result<()> {
        let config = self.replication_config.read().await;

        match config.write_consistency {
            ConsistencyLevel::All => {
                if nodes.len() < config.replication_factor {
                    return Err(PersistenceError::Replication(format!(
                        "Not enough nodes for ALL consistency: {} < {}",
                        nodes.len(),
                        config.replication_factor
                    )));
                }
            }
            ConsistencyLevel::Quorum => {
                let quorum = config.replication_factor / 2 + 1;
                if nodes.len() < quorum {
                    return Err(PersistenceError::Replication(format!(
                        "Not enough nodes for QUORUM: {} < {}",
                        nodes.len(),
                        quorum
                    )));
                }
            }
            _ => {}
        }

        // Store replication metadata
        let metadata_cf = self.cf_handle(CF_METADATA)?;
        let nodes_str = nodes
            .iter()
            .map(|n| n.0.as_str())
            .collect::<Vec<_>>()
            .join(",");

        self.db
            .put_cf(
                metadata_cf,
                format!("replica:{}", hex::encode(key)),
                nodes_str,
            )
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn sync_from(&self, peer: NodeId, namespace: &str) -> Result<SyncStats> {
        // Simulate sync operation
        let start = std::time::Instant::now();

        // Count keys in namespace
        let prefix = namespace.as_bytes();
        let count = self.prefix(prefix, usize::MAX).await?.len();

        let duration = start.elapsed();

        Ok(SyncStats {
            keys_synced: count,
            bytes_transferred: count as u64 * 1024, // Estimate
            duration,
            errors: vec![],
        })
    }

    async fn replication_status(&self, key: &[u8]) -> Result<ReplicationStatus> {
        let config = self.replication_config.read().await;
        let metadata_cf = self.cf_handle(CF_METADATA)?;

        let nodes_str = self
            .db
            .get_cf(metadata_cf, format!("replica:{}", hex::encode(key)))
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        let replica_nodes = if let Some(nodes) = nodes_str {
            let nodes_vec =
                String::from_utf8(nodes).map_err(|e| PersistenceError::Backend(e.to_string()))?;
            nodes_vec.split(',').map(|s| NodeId::from(s)).collect()
        } else {
            vec![]
        };

        Ok(ReplicationStatus {
            replica_count: config.replication_factor,
            replica_nodes,
            last_sync: SystemTime::now(),
            write_quorum_met: true,
            lag_ms: 0,
        })
    }

    async fn set_replication_config(&self, config: ReplicationConfig) -> Result<()> {
        *self.replication_config.write().await = config;
        Ok(())
    }
}

#[async_trait]
impl Migrate for RocksDbStore {
    async fn migrate(&self, migrations: &[Migration]) -> Result<()> {
        let metadata_cf = self.cf_handle(CF_METADATA)?;

        let current_version = self.schema_version().await?.unwrap_or(0);

        for migration in migrations {
            if migration.version > current_version {
                (migration.up)(self)?;

                let version_bytes = migration.version.to_be_bytes();
                self.db
                    .put_cf(metadata_cf, "schema_version", &version_bytes)
                    .map_err(|e| PersistenceError::Backend(e.to_string()))?;
            }
        }

        Ok(())
    }

    async fn schema_version(&self) -> Result<Option<u32>> {
        let metadata_cf = self.cf_handle(CF_METADATA)?;

        if let Some(version_bytes) = self
            .db
            .get_cf(metadata_cf, "schema_version")
            .map_err(|e| PersistenceError::Backend(e.to_string()))?
        {
            let version = u32::from_be_bytes([
                version_bytes[0],
                version_bytes[1],
                version_bytes[2],
                version_bytes[3],
            ]);
            Ok(Some(version))
        } else {
            Ok(None)
        }
    }

    async fn set_schema_version(&self, version: u32) -> Result<()> {
        let metadata_cf = self.cf_handle(CF_METADATA)?;
        let version_bytes = version.to_be_bytes();

        self.db
            .put_cf(metadata_cf, "schema_version", &version_bytes)
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        *self.schema_version.write().await = Some(version);
        Ok(())
    }
}

#[async_trait]
impl Monitor for RocksDbStore {
    async fn health(&self) -> Result<StorageHealth> {
        let mut storage_used = 0u64;
        let mut storage_available = u64::MAX;

        // Get approximate sizes
        let default_cf = self.cf_handle(CF_DEFAULT)?;
        let ttl_cf = self.cf_handle(CF_TTL)?;

        let approx_size_default = self
            .db
            .property_int_value_cf(default_cf, "rocksdb.estimate-live-data-size")
            .map_err(|e| PersistenceError::Backend(e.to_string()))?
            .unwrap_or(0);

        let approx_size_ttl = self
            .db
            .property_int_value_cf(ttl_cf, "rocksdb.estimate-live-data-size")
            .map_err(|e| PersistenceError::Backend(e.to_string()))?
            .unwrap_or(0);

        storage_used = approx_size_default + approx_size_ttl;

        if let Some(max_size) = self.config.max_size {
            storage_available = max_size.saturating_sub(storage_used);
        }

        // Clean up expired keys
        let _ = self.cleanup_expired().await;

        Ok(StorageHealth {
            status: HealthStatus::Healthy,
            storage_used,
            storage_available,
            replication_healthy: true,
            last_compaction: None,
            error_count: 0,
            metrics: self.metrics().await?,
        })
    }

    async fn metrics(&self) -> Result<StorageMetrics> {
        let default_cf = self.cf_handle(CF_DEFAULT)?;

        let read_ops_per_sec = self
            .db
            .property_int_value_cf(default_cf, "rocksdb.stats.rocksdb.number.db_seek")
            .map_err(|e| PersistenceError::Backend(e.to_string()))?
            .unwrap_or(0) as f64;

        let write_ops_per_sec = self
            .db
            .property_int_value_cf(default_cf, "rocksdb.stats.rocksdb.number.db_next")
            .map_err(|e| PersistenceError::Backend(e.to_string()))?
            .unwrap_or(0) as f64;

        Ok(StorageMetrics {
            read_ops_per_sec,
            write_ops_per_sec,
            read_latency_us: 100, // Would need actual measurement
            write_latency_us: 50,
            cache_hit_rate: 0.95, // Would need actual measurement
            compaction_backlog: 0,
        })
    }

    async fn compact(&self) -> Result<()> {
        self.db.compact_range::<&[u8], &[u8]>(None, None);
        Ok(())
    }

    async fn backup(&self, path: &str) -> Result<()> {
        let backup_path = Path::new(path);

        // Create checkpoint
        let checkpoint = rocksdb::checkpoint::Checkpoint::new(&self.db)
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        checkpoint
            .create_checkpoint(backup_path)
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn restore(&self, path: &str) -> Result<()> {
        let backup_path = Path::new(path);

        // Close current DB and restore from backup
        // This is a simplified restore - in production you'd want atomic operations
        if backup_path.exists() {
            // Implementation would depend on backup format
            Ok(())
        } else {
            Err(PersistenceError::Backend(
                "Backup path does not exist".into(),
            ))
        }
    }
}

/// Create a RocksDB store instance
pub async fn create_rocksdb_store(
    config: StorageConfig,
) -> Result<Arc<dyn Store + Query + Replicate + Migrate + Monitor>> {
    let store = RocksDbStore::new(config)?;
    Ok(Arc::new(store))
}
