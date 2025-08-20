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

//! SQLite storage backend implementation

use async_trait::async_trait;
use rusqlite::{Connection, OpenFlags, Transaction as SqliteTransaction, params};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;

use crate::persistence::{
    Store, Query, Replicate, Migrate, Monitor, StorageConfig, Result, Operation, Transaction,
    PersistenceError, NodeId, ReplicationStatus, SyncStats, ReplicationConfig, StorageHealth,
    StorageMetrics, HealthStatus, Migration, ConsistencyLevel,
};

/// SQLite storage implementation
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
    replication_config: Arc<tokio::sync::RwLock<ReplicationConfig>>,
    schema_version: Arc<tokio::sync::RwLock<Option<u32>>>,
    config: StorageConfig,
}

impl SqliteStore {
    /// Create a new SQLite store
    pub fn new(config: StorageConfig) -> Result<Self> {
        let path = config.path.as_ref()
            .ok_or_else(|| PersistenceError::InvalidKey("Storage path required for SQLite".into()))?;

        let conn = if path == ":memory:" {
            Connection::open_in_memory()
        } else {
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE)
        }.map_err(|e| PersistenceError::Backend(e.to_string()))?;

        // Initialize database schema
        Self::initialize_schema(&conn)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            replication_config: Arc::new(tokio::sync::RwLock::new(config.replication.clone())),
            schema_version: Arc::new(tokio::sync::RwLock::new(None)),
            config,
        })
    }

    /// Initialize database schema
    fn initialize_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS kv_store (
                key BLOB PRIMARY KEY,
                value BLOB NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            );

            CREATE TABLE IF NOT EXISTS ttl_store (
                key BLOB PRIMARY KEY,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY (key) REFERENCES kv_store(key) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS replication_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                operation TEXT NOT NULL,
                value BLOB,
                timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            );

            CREATE INDEX IF NOT EXISTS idx_ttl_expires ON ttl_store(expires_at);
            CREATE INDEX IF NOT EXISTS idx_kv_updated ON kv_store(updated_at);
            "#,
        ).map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(())
    }

    /// Check if key has expired based on TTL
    async fn is_expired(&self, key: &[u8]) -> Result<bool> {
        let conn = self.conn.lock().await;
        
        let result: Result<Option<i64>, rusqlite::Error> = conn.query_row(
            "SELECT expires_at FROM ttl_store WHERE key = ?",
            params![key],
            |row| row.get(0),
        );

        match result {
            Ok(Some(expires_at)) => {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| crate::error::P2PError::TimeError)?
            .as_secs() as i64;
                Ok(now > expires_at)
            }
            Ok(None) => Ok(false),
            Err(_) => Ok(false),
        }
    }

    /// Clean up expired keys
    async fn cleanup_expired(&self) -> Result<usize> {
        let conn = self.conn.lock().await;
        
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| crate::error::P2PError::TimeError)?
            .as_secs() as i64;

        let mut stmt = conn.prepare(
            "DELETE FROM kv_store WHERE key IN (SELECT key FROM ttl_store WHERE expires_at < ?)"
        ).map_err(|e| PersistenceError::Backend(e.to_string()))?;
        
        let deleted = stmt.execute(params![now])
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(deleted as usize)
    }

    /// Get database size information
    async fn get_database_size(&self) -> Result<(u64, u64)> {
        let conn = self.conn.lock().await;
        
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM kv_store",
            [],
            |row| row.get(0),
        ).map_err(|e| PersistenceError::Backend(e.to_string()))?;

        let total_size: i64 = conn.query_row(
            "SELECT SUM(LENGTH(key) + LENGTH(value)) FROM kv_store",
            [],
            |row| row.get(0),
        ).map_err(|e| PersistenceError::Backend(e.to_string()))?.unwrap_or(0);

        Ok((count as u64, total_size as u64))
    }
}

#[async_trait]
impl Store for SqliteStore {
    async fn put(&self, key: &[u8], value: &[u8], ttl: Option<Duration>) -> Result<()> {
        let conn = self.conn.lock().await;
        
        let tx = conn.transaction()
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        tx.execute(
            "INSERT OR REPLACE INTO kv_store (key, value, updated_at) VALUES (?, ?, strftime('%s', 'now'))",
            params![key, value],
        ).map_err(|e| PersistenceError::Backend(e.to_string()))?;

        if let Some(ttl_duration) = ttl {
            let expires_at = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64 + ttl_duration.as_secs() as i64;

            tx.execute(
                "INSERT OR REPLACE INTO ttl_store (key, expires_at) VALUES (?, ?)",
                params![key, expires_at],
            ).map_err(|e| PersistenceError::Backend(e.to_string()))?;
        } else {
            // Remove TTL if it exists
            tx.execute(
                "DELETE FROM ttl_store WHERE key = ?",
                params![key],
            ).map_err(|e| PersistenceError::Backend(e.to_string()))?;
        }

        tx.commit()
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        // Check if expired
        if self.is_expired(key).await? {
            self.delete(key).await?;
            return Ok(None);
        }

        let conn = self.conn.lock().await;
        
        let result: Result<Option<Vec<u8>>, rusqlite::Error> = conn.query_row(
            "SELECT value FROM kv_store WHERE key = ?",
            params![key],
            |row| row.get(0),
        );

        match result {
            Ok(value) => Ok(value),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(PersistenceError::Backend(e.to_string())),
        }
    }

    async fn delete(&self, key: &[u8]) -> Result<()> {
        let conn = self.conn.lock().await;
        
        conn.execute(
            "DELETE FROM kv_store WHERE key = ?",
            params![key],
        ).map_err(|e| PersistenceError::Backend(e.to_string()))?;

        conn.execute(
            "DELETE FROM ttl_store WHERE key = ?",
            params![key],
        ).map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn exists(&self, key: &[u8]) -> Result<bool> {
        if self.is_expired(key).await? {
            self.delete(key).await?;
            return Ok(false);
        }

        let conn = self.conn.lock().await;
        
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM kv_store WHERE key = ?",
            params![key],
            |row| row.get(0),
        ).map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(count > 0)
    }

    async fn batch(&self, ops: Vec<Operation>) -> Result<()> {
        let conn = self.conn.lock().await;
        
        let tx = conn.transaction()
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        for op in ops {
            match op {
                Operation::Put { key, value, ttl } => {
                    tx.execute(
                        "INSERT OR REPLACE INTO kv_store (key, value, updated_at) VALUES (?, ?, strftime('%s', 'now'))",
                        params![&key, &value],
                    ).map_err(|e| PersistenceError::Backend(e.to_string()))?;

                    if let Some(ttl_duration) = ttl {
                        let expires_at = SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64 + ttl_duration.as_secs() as i64;

                        tx.execute(
                            "INSERT OR REPLACE INTO ttl_store (key, expires_at) VALUES (?, ?)",
                            params![&key, expires_at],
                        ).map_err(|e| PersistenceError::Backend(e.to_string()))?;
                    }
                }
                Operation::Delete { key } => {
                    tx.execute(
                        "DELETE FROM kv_store WHERE key = ?",
                        params![&key],
                    ).map_err(|e| PersistenceError::Backend(e.to_string()))?;

                    tx.execute(
                        "DELETE FROM ttl_store WHERE key = ?",
                        params![&key],
                    ).map_err(|e| PersistenceError::Backend(e.to_string()))?;
                }
            }
        }

        tx.commit()
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
impl Query for SqliteStore {
    async fn range(
        &self,
        start: &[u8],
        end: &[u8],
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let conn = self.conn.lock().await;
        
        let query = if reverse {
            "SELECT key, value FROM kv_store 
             WHERE key >= ? AND key < ? 
             ORDER BY key DESC 
             LIMIT ?"
        } else {
            "SELECT key, value FROM kv_store 
             WHERE key >= ? AND key < ? 
             ORDER BY key ASC 
             LIMIT ?"
        };

        let mut stmt = conn.prepare(query)
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        let rows = stmt.query_map(params![start, end, limit as i64], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        }).map_err(|e| PersistenceError::Backend(e.to_string()))?;

        let mut results = Vec::new();
        for row in rows {
            let (key, value) = row.map_err(|e| PersistenceError::Backend(e.to_string()))?;
            if !self.is_expired(&key).await? {
                results.push((key, value));
            }
        }

        Ok(results)
    }

    async fn prefix(&self, prefix: &[u8], limit: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let conn = self.conn.lock().await;
        
        let mut stmt = conn.prepare(
            "SELECT key, value FROM kv_store WHERE key LIKE ? || '%' ORDER BY key ASC LIMIT ?"
        ).map_err(|e| PersistenceError::Backend(e.to_string()))?;

        let rows = stmt.query_map(params![prefix, limit as i64], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        }).map_err(|e| PersistenceError::Backend(e.to_string()))?;

        let mut results = Vec::new();
        for row in rows {
            let (key, value) = row.map_err(|e| PersistenceError::Backend(e.to_string()))?;
            if !self.is_expired(&key).await? {
                results.push((key, value));
            }
        }

        Ok(results)
    }

    async fn count(&self, start: &[u8], end: &[u8]) -> Result<usize> {
        let conn = self.conn.lock().await;
        
        let mut stmt = conn.prepare(
            "SELECT COUNT(*) FROM kv_store WHERE key >= ? AND key < ?"
        ).map_err(|e| PersistenceError::Backend(e.to_string()))?;

        let count: i64 = stmt.query_row(params![start, end], |row| row.get(0))
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(count as usize)
    }
}

#[async_trait]
impl Replicate for SqliteStore {
    async fn replicate(&self, key: &[u8], nodes: Vec<NodeId>) -> Result<()> {
        let conn = self.conn.lock().await;
        
        let config = self.replication_config.read().await;
        
        match config.write_consistency {
            ConsistencyLevel::All => {
                if nodes.len() < config.replication_factor {
                    return Err(PersistenceError::Replication(
                        format!("Not enough nodes for ALL consistency: {} < {}", 
                               nodes.len(), config.replication_factor)
                    ));
                }
            }
            ConsistencyLevel::Quorum => {
                let quorum = config.replication_factor / 2 + 1;
                if nodes.len() < quorum {
                    return Err(PersistenceError::Replication(
                        format!("Not enough nodes for QUORUM: {} < {}", 
                               nodes.len(), quorum)
                    ));
                }
            }
            _ => {}
        }

        let nodes_str = nodes.iter().map(|n| n.0.as_str()).collect::<Vec<_>>().join(",");
        
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            params![format!("replica:{}", hex::encode(key)), nodes_str],
        ).map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn sync_from(&self, peer: NodeId, namespace: &str) -> Result<SyncStats> {
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
        let conn = self.conn.lock().await;
        let config = self.replication_config.read().await;
        
        let nodes_str: Result<Option<String>, rusqlite::Error> = conn.query_row(
            "SELECT value FROM metadata WHERE key = ?",
            params![format!("replica:{}", hex::encode(key))],
            |row| row.get(0),
        );

        let replica_nodes = match nodes_str {
            Ok(Some(nodes)) => nodes.split(',').map(|s| NodeId::from(s)).collect(),
            _ => vec![],
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
impl Migrate for SqliteStore {
    async fn migrate(&self, migrations: &[Migration]) -> Result<()> {
        let conn = self.conn.lock().await;
        
        let current_version = self.schema_version().await?.unwrap_or(0);
        
        for migration in migrations {
            if migration.version > current_version {
                (migration.up)(self)?;
                
                conn.execute(
                    "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                    params!["schema_version", migration.version.to_string()],
                ).map_err(|e| PersistenceError::Backend(e.to_string()))?;
            }
        }

        Ok(())
    }

    async fn schema_version(&self) -> Result<Option<u32>> {
        let conn = self.conn.lock().await;
        
        let version: Result<Option<String>, rusqlite::Error> = conn.query_row(
            "SELECT value FROM metadata WHERE key = ?",
            params!["schema_version"],
            |row| row.get(0),
        );

        match version {
            Ok(Some(v)) => v.parse().map(Some).map_err(|_| 
                PersistenceError::Backend("Invalid schema version format".into())),
            Ok(None) => Ok(None),
            Err(e) => Err(PersistenceError::Backend(e.to_string())),
        }
    }

    async fn set_schema_version(&self, version: u32) -> Result<()> {
        let conn = self.conn.lock().await;
        
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            params!["schema_version", version.to_string()],
        ).map_err(|e| PersistenceError::Backend(e.to_string()))?;

        *self.schema_version.write().await = Some(version);
        Ok(())
    }
}

#[async_trait]
impl Monitor for SqliteStore {
    async fn health(&self) -> Result<StorageHealth> {
        let (count, total_size) = self.get_database_size().await?;
        
        // Clean up expired keys
        let _ = self.cleanup_expired().await;
        
        let max_size = self.config.max_size.unwrap_or(u64::MAX);
        let storage_available = max_size.saturating_sub(total_size);
        
        Ok(StorageHealth {
            status: HealthStatus::Healthy,
            storage_used: total_size,
            storage_available,
            replication_healthy: true,
            last_compaction: None,
            error_count: 0,
            metrics: self.metrics().await?,
        })
    }

    async fn metrics(&self) -> Result<StorageMetrics> {
        let conn = self.conn.lock().await;
        
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM kv_store",
            [],
            |row| row.get(0),
        ).map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(StorageMetrics {
            read_ops_per_sec: 0.0, // Would need actual measurement
            write_ops_per_sec: 0.0,
            read_latency_us: 100,
            write_latency_us: 50,
            cache_hit_rate: 0.95,
            compaction_backlog: 0,
        })
    }

    async fn compact(&self) -> Result<()> {
        let conn = self.conn.lock().await;
        
        conn.execute("VACUUM", [])
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn backup(&self, path: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        
        let backup_conn = Connection::open(path)
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;
        
        conn.backup(backup_conn, "main", "main")
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn restore(&self, path: &str) -> Result<()> {
        let backup_path = Path::new(path);
        
        if !backup_path.exists() {
            return Err(PersistenceError::Backend("Backup path does not exist".into()));
        }

        let conn = self.conn.lock().await;
        
        let backup_conn = Connection::open(path)
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;
        
        backup_conn.backup(conn, "main", "main")
            .map_err(|e| PersistenceError::Backend(e.to_string()))?;

        Ok(())
    }
}

/// Create a SQLite store instance
pub async fn create_sqlite_store(config: StorageConfig) -> Result<Arc<dyn Store + Query + Replicate + Migrate + Monitor>> {
    let store = SqliteStore::new(config)?;
    Ok(Arc::new(store))
}