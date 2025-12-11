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

//! In-memory storage backend for testing and development

use async_trait::async_trait;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;

use crate::persistence::{
    ConsistencyLevel, HealthStatus, Migrate, Migration, Monitor, NodeId, Operation,
    PersistenceError, Query, Replicate, ReplicationConfig, ReplicationStatus, Result,
    StorageConfig, StorageHealth, StorageMetrics, Store, SyncStats, Transaction,
};

/// TTL entry for expiration
#[derive(Debug, Clone)]
struct TtlEntry {
    key: Vec<u8>,
    expires_at: Instant,
}

/// In-memory storage implementation
pub struct MemoryStore {
    /// Main data storage
    data: Arc<RwLock<BTreeMap<Vec<u8>, Vec<u8>>>>,

    /// TTL tracking
    ttl_map: Arc<RwLock<HashMap<Vec<u8>, Instant>>>,

    /// Replication configuration
    replication_config: Arc<RwLock<ReplicationConfig>>,

    /// Schema version
    schema_version: Arc<RwLock<Option<u32>>>,

    /// Metrics
    metrics: Arc<RwLock<InternalMetrics>>,

    /// Maximum size in bytes (if set)
    max_size: Option<u64>,

    /// Current size in bytes
    current_size: Arc<RwLock<u64>>,
}

#[derive(Debug, Default)]
struct InternalMetrics {
    read_count: u64,
    write_count: u64,
    delete_count: u64,
    total_read_time: Duration,
    total_write_time: Duration,
    cache_hits: u64,
    cache_misses: u64,
    error_count: u64,
}

impl MemoryStore {
    /// Create a new memory store
    pub fn new() -> Self {
        Self::with_config(None, None)
    }

    /// Create with maximum size limit
    pub fn with_max_size(max_size: u64) -> Self {
        Self::with_config(Some(max_size), None)
    }

    /// Create with configuration
    pub fn with_config(max_size: Option<u64>, _config: Option<StorageConfig>) -> Self {
        let store = Self {
            data: Arc::new(RwLock::new(BTreeMap::new())),
            ttl_map: Arc::new(RwLock::new(HashMap::new())),
            replication_config: Arc::new(RwLock::new(ReplicationConfig::default())),
            schema_version: Arc::new(RwLock::new(None)),
            metrics: Arc::new(RwLock::new(InternalMetrics::default())),
            max_size,
            current_size: Arc::new(RwLock::new(0)),
        };

        // Start TTL cleanup task
        let ttl_map = store.ttl_map.clone();
        let data = store.data.clone();
        let current_size = store.current_size.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;

                // Find expired keys
                let now = Instant::now();
                let expired_keys: Vec<Vec<u8>> = {
                    let ttl_map = ttl_map.read().await;
                    ttl_map
                        .iter()
                        .filter(|(_, expires_at)| now >= **expires_at)
                        .map(|(key, _)| key.clone())
                        .collect()
                };

                // Remove expired keys
                if !expired_keys.is_empty() {
                    let mut ttl_map = ttl_map.write().await;
                    let mut data = data.write().await;
                    let mut size = current_size.write().await;

                    for key in expired_keys {
                        ttl_map.remove(&key);
                        if let Some(value) = data.remove(&key) {
                            *size = size.saturating_sub((key.len() + value.len()) as u64);
                        }
                    }
                }
            }
        });

        store
    }

    /// Check if adding data would exceed size limit
    async fn check_size(&self, additional: u64) -> Result<()> {
        if let Some(max_size) = self.max_size {
            let current = *self.current_size.read().await;
            if current + additional > max_size {
                return Err(PersistenceError::StorageFull);
            }
        }
        Ok(())
    }

    /// Update metrics for an operation
    async fn update_metrics(&self, op: MetricOp, duration: Duration) {
        let mut metrics = self.metrics.write().await;
        match op {
            MetricOp::Read => {
                metrics.read_count += 1;
                metrics.total_read_time += duration;
            }
            MetricOp::Write => {
                metrics.write_count += 1;
                metrics.total_write_time += duration;
            }
            MetricOp::Delete => {
                metrics.delete_count += 1;
            }
        }
    }
}

enum MetricOp {
    Read,
    Write,
    Delete,
}

#[async_trait]
impl Store for MemoryStore {
    async fn put(&self, key: &[u8], value: &[u8], ttl: Option<Duration>) -> Result<()> {
        let start = Instant::now();

        // Check size limit
        let new_size = (key.len() + value.len()) as u64;
        self.check_size(new_size).await?;

        // Store data
        let mut data = self.data.write().await;
        let old_value = data.insert(key.to_vec(), value.to_vec());

        // Update size
        let mut size = self.current_size.write().await;
        if let Some(old) = old_value {
            *size = size.saturating_sub((key.len() + old.len()) as u64);
        }
        *size += new_size;

        // Handle TTL
        if let Some(ttl) = ttl {
            let mut ttl_map = self.ttl_map.write().await;
            ttl_map.insert(key.to_vec(), Instant::now() + ttl);
        }

        self.update_metrics(MetricOp::Write, start.elapsed()).await;
        Ok(())
    }

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let start = Instant::now();

        // Check if expired
        {
            let ttl_map = self.ttl_map.read().await;
            if let Some(expires_at) = ttl_map.get(key) {
                if Instant::now() >= *expires_at {
                    // Expired, remove it
                    drop(ttl_map);
                    self.delete(key).await?;
                    self.update_metrics(MetricOp::Read, start.elapsed()).await;
                    return Ok(None);
                }
            }
        }

        let data = self.data.read().await;
        let result = data.get(key).cloned();

        self.update_metrics(MetricOp::Read, start.elapsed()).await;
        Ok(result)
    }

    async fn delete(&self, key: &[u8]) -> Result<()> {
        let start = Instant::now();

        let mut data = self.data.write().await;
        if let Some(value) = data.remove(key) {
            let mut size = self.current_size.write().await;
            *size = size.saturating_sub((key.len() + value.len()) as u64);
        }

        let mut ttl_map = self.ttl_map.write().await;
        ttl_map.remove(key);

        self.update_metrics(MetricOp::Delete, start.elapsed()).await;
        Ok(())
    }

    async fn exists(&self, key: &[u8]) -> Result<bool> {
        // Check if expired
        {
            let ttl_map = self.ttl_map.read().await;
            if let Some(expires_at) = ttl_map.get(key) {
                if Instant::now() >= *expires_at {
                    return Ok(false);
                }
            }
        }

        let data = self.data.read().await;
        Ok(data.contains_key(key))
    }

    async fn batch(&self, ops: Vec<Operation>) -> Result<()> {
        for op in ops {
            match op {
                Operation::Put { key, value, ttl } => {
                    self.put(&key, &value, ttl).await?;
                }
                Operation::Delete { key } => {
                    self.delete(&key).await?;
                }
            }
        }
        Ok(())
    }

    async fn transaction<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Transaction) -> Result<R> + Send,
        R: Send,
    {
        let mut tx = Transaction::new();

        // Execute function
        let result = f(&mut tx)?;

        // Apply operations
        self.batch(tx.operations().to_vec()).await?;

        Ok(result)
    }
}

#[async_trait]
impl Query for MemoryStore {
    async fn range(
        &self,
        start: &[u8],
        end: &[u8],
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let data = self.data.read().await;

        let iter = data
            .range(start.to_vec()..end.to_vec())
            .take(limit)
            .map(|(k, v)| (k.clone(), v.clone()));

        let mut results: Vec<_> = iter.collect();

        if reverse {
            results.reverse();
        }

        Ok(results)
    }

    async fn prefix(&self, prefix: &[u8], limit: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let data = self.data.read().await;

        let results: Vec<_> = data
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .take(limit)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        Ok(results)
    }

    async fn count(&self, start: &[u8], end: &[u8]) -> Result<usize> {
        let data = self.data.read().await;

        let count = data.range(start.to_vec()..end.to_vec()).count();

        Ok(count)
    }
}

#[async_trait]
impl Replicate for MemoryStore {
    async fn replicate(&self, _key: &[u8], nodes: Vec<NodeId>) -> Result<()> {
        // Simulate replication success
        let config = self.replication_config.read().await;

        match config.write_consistency {
            ConsistencyLevel::All => {
                if nodes.len() < config.replication_factor {
                    return Err(PersistenceError::Replication(
                        "Not enough nodes for ALL consistency".into(),
                    ));
                }
            }
            ConsistencyLevel::Quorum => {
                let quorum = config.replication_factor / 2 + 1;
                if nodes.len() < quorum {
                    return Err(PersistenceError::Replication(
                        "Not enough nodes for QUORUM".into(),
                    ));
                }
            }
            _ => {}
        }

        Ok(())
    }

    async fn sync_from(&self, _peer: NodeId, namespace: &str) -> Result<SyncStats> {
        // Simulate sync
        let data = self.data.read().await;

        let prefix = namespace.as_bytes();
        let keys_synced = data.iter().filter(|(k, _)| k.starts_with(prefix)).count();

        let bytes_transferred = data
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>() as u64;

        Ok(SyncStats {
            keys_synced,
            bytes_transferred,
            duration: Duration::from_millis(100),
            errors: vec![],
        })
    }

    async fn replication_status(&self, _key: &[u8]) -> Result<ReplicationStatus> {
        let config = self.replication_config.read().await;

        Ok(ReplicationStatus {
            replica_count: config.replication_factor,
            replica_nodes: (0..config.replication_factor)
                .map(|i| NodeId::from(format!("node{}", i)))
                .collect(),
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
impl Migrate for MemoryStore {
    async fn migrate(&self, migrations: &[Migration]) -> Result<()> {
        let current_version = self.schema_version().await?.unwrap_or(0);

        for migration in migrations {
            if migration.version > current_version {
                // Apply migration
                (migration.up)(self)?;
                self.set_schema_version(migration.version).await?;
            }
        }

        Ok(())
    }

    async fn schema_version(&self) -> Result<Option<u32>> {
        Ok(*self.schema_version.read().await)
    }

    async fn set_schema_version(&self, version: u32) -> Result<()> {
        *self.schema_version.write().await = Some(version);
        Ok(())
    }
}

#[async_trait]
impl Monitor for MemoryStore {
    async fn health(&self) -> Result<StorageHealth> {
        let metrics = self.metrics.read().await;
        let current_size = *self.current_size.read().await;

        let status = if metrics.error_count > 100 {
            HealthStatus::Unhealthy
        } else if metrics.error_count > 10 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        let available = self.max_size.unwrap_or(u64::MAX) - current_size;

        Ok(StorageHealth {
            status,
            storage_used: current_size,
            storage_available: available,
            replication_healthy: true,
            last_compaction: None,
            error_count: metrics.error_count,
            metrics: self.metrics().await?,
        })
    }

    async fn metrics(&self) -> Result<StorageMetrics> {
        let metrics = self.metrics.read().await;

        let read_latency = if metrics.read_count > 0 {
            metrics.total_read_time.as_micros() as u64 / metrics.read_count
        } else {
            0
        };

        let write_latency = if metrics.write_count > 0 {
            metrics.total_write_time.as_micros() as u64 / metrics.write_count
        } else {
            0
        };

        let cache_hit_rate = if metrics.cache_hits + metrics.cache_misses > 0 {
            metrics.cache_hits as f64 / (metrics.cache_hits + metrics.cache_misses) as f64
        } else {
            0.0
        };

        Ok(StorageMetrics {
            read_ops_per_sec: 0.0, // Would need time tracking for this
            write_ops_per_sec: 0.0,
            read_latency_us: read_latency,
            write_latency_us: write_latency,
            cache_hit_rate,
            compaction_backlog: 0,
        })
    }

    async fn compact(&self) -> Result<()> {
        // No-op for memory store
        Ok(())
    }

    async fn backup(&self, _path: &str) -> Result<()> {
        // Could serialize to file
        Ok(())
    }

    async fn restore(&self, _path: &str) -> Result<()> {
        // Could deserialize from file
        Ok(())
    }
}

/// Create a memory store instance
pub async fn create_memory_store(
    config: StorageConfig,
) -> Result<Arc<dyn Store + Query + Replicate + Migrate + Monitor>> {
    Ok(Arc::new(MemoryStore::with_config(
        config.max_size,
        Some(config),
    )))
}
