# Persistence Layer Specification

## Overview
The persistence layer provides durable, encrypted, and replicated storage for the P2P network. It serves as the foundation for storing DHT data, user profiles, messages, and all persistent state required by the network.

## Core Requirements

### Functional Requirements
1. **Durability**: All data must be persisted to disk with configurable sync policies
2. **Encryption**: Support for at-rest encryption using ML-KEM (quantum-resistant)
3. **Replication**: Multi-node replication with configurable replication factor (K=8 default)
4. **Performance**: Sub-millisecond reads, batch writes, efficient range queries
5. **Atomicity**: ACID transactions for critical operations
6. **Versioning**: Git-like content versioning with BLAKE3 hashing
7. **Compression**: Automatic compression for large values
8. **Garbage Collection**: TTL-based and manual cleanup
9. **Migration**: Schema versioning and migration support
10. **Cross-platform**: Support for Linux, macOS, Windows, iOS, Android

### Non-Functional Requirements
1. **Storage Efficiency**: < 10% overhead for metadata
2. **Memory Usage**: Configurable cache size (default 128MB)
3. **Crash Recovery**: Recovery from unexpected shutdowns
4. **Backup/Restore**: Hot backups without stopping the node
5. **Monitoring**: Metrics for storage usage, performance, errors

## Architecture

### Layer Structure
```
┌─────────────────────────────────────────┐
│         Application Layer               │
│  (DHT, Identity, Chat, Projects, etc.)  │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│         Persistence API                 │
│    (Traits: Store, Query, Replicate)    │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│         Storage Engines                 │
│  ┌──────────┐ ┌──────────┐ ┌─────────┐ │
│  │ RocksDB  │ │  SQLite  │ │ Memory  │ │
│  └──────────┘ └──────────┘ └─────────┘ │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│      Encryption & Compression           │
│     (ChaCha20-Poly1305, Zstd)          │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│         Replication Manager             │
│   (Consensus, Sync, Conflict Resolution)│
└─────────────────────────────────────────┘
```

### Data Model

#### Key-Value Store
- **Key**: Up to 256 bytes, hierarchical namespace support
- **Value**: Up to 100MB (chunked for larger data)
- **Metadata**: Timestamp, TTL, version, encryption info
- **Indexes**: Secondary indexes for efficient queries

#### Namespace Organization
```
/system/              - System metadata and configuration
/dht/                 - DHT records and routing table
/identity/            - User identities and keys
/apps/                - Upper-layer application data (saorsa-node)
/files/               - File chunks and metadata
/cache/               - Temporary cached data
```

## Core Traits

### Store Trait
```rust
#[async_trait]
pub trait Store: Send + Sync {
    type Error: std::error::Error;
    
    /// Put a key-value pair with optional TTL
    async fn put(&self, key: &[u8], value: &[u8], ttl: Option<Duration>) 
        -> Result<(), Self::Error>;
    
    /// Get a value by key
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;
    
    /// Delete a key
    async fn delete(&self, key: &[u8]) -> Result<(), Self::Error>;
    
    /// Check if key exists
    async fn exists(&self, key: &[u8]) -> Result<bool, Self::Error>;
    
    /// Batch operations for efficiency
    async fn batch(&self, ops: Vec<Operation>) -> Result<(), Self::Error>;
    
    /// Transaction support
    async fn transaction<F, R>(&self, f: F) -> Result<R, Self::Error>
    where
        F: FnOnce(&Transaction) -> Result<R, Self::Error>;
}
```

### Query Trait
```rust
#[async_trait]
pub trait Query: Store {
    /// Range query with pagination
    async fn range(
        &self,
        start: &[u8],
        end: &[u8],
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Self::Error>;
    
    /// Prefix scan
    async fn prefix(
        &self,
        prefix: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Self::Error>;
    
    /// Count keys in range
    async fn count(&self, start: &[u8], end: &[u8]) -> Result<usize, Self::Error>;
}
```

### Replicate Trait
```rust
#[async_trait]
pub trait Replicate: Store {
    /// Replicate to peer nodes
    async fn replicate(&self, key: &[u8], nodes: Vec<NodeId>) 
        -> Result<(), Self::Error>;
    
    /// Sync from peer
    async fn sync_from(&self, peer: NodeId, namespace: &str) 
        -> Result<SyncStats, Self::Error>;
    
    /// Get replication status
    async fn replication_status(&self, key: &[u8]) 
        -> Result<ReplicationStatus, Self::Error>;
}
```

## Storage Engines

### RocksDB Backend (Primary)
- **Use Case**: Production deployments, high performance
- **Features**: LSM-tree, compression, column families
- **Configuration**: Tunable write buffer, block cache, compaction

### SQLite Backend (Mobile)
- **Use Case**: Mobile devices, embedded systems
- **Features**: Single file, ACID transactions, FTS5
- **Configuration**: WAL mode, pragma optimizations

### Memory Backend (Testing)
- **Use Case**: Testing, development, temporary data
- **Features**: Fast, no persistence, concurrent access
- **Configuration**: Max size limit, eviction policy

## Encryption Layer

### Key Management
```rust
pub struct EncryptionConfig {
    /// Master key derivation
    pub kdf: KeyDerivationFunction,
    
    /// Encryption algorithm
    pub algorithm: EncryptionAlgorithm,
    
    /// Key rotation policy
    pub rotation: KeyRotationPolicy,
}

pub enum EncryptionAlgorithm {
    /// Symmetric encryption (saorsa-pqc)
    ChaCha20Poly1305,
    
    /// No encryption (testing only)
    None,
}
```

### Encryption Flow
1. Derive encryption key from master key
2. Generate random nonce for each value
3. Encrypt value with ChaCha20-Poly1305
4. Store encrypted value with metadata
5. Cache decrypted values in memory

## Replication System

### Replication Strategy
```rust
pub struct ReplicationConfig {
    /// Number of replicas (default: 8)
    pub replication_factor: usize,
    
    /// Write consistency level
    pub write_consistency: ConsistencyLevel,
    
    /// Read consistency level  
    pub read_consistency: ConsistencyLevel,
    
    /// Conflict resolution
    pub conflict_resolver: ConflictResolver,
}

pub enum ConsistencyLevel {
    /// Wait for all replicas
    All,
    
    /// Wait for quorum (N/2 + 1)
    Quorum,
    
    /// Wait for one replica
    One,
    
    /// Fire and forget
    None,
}
```

### Sync Protocol
1. **Merkle Tree Sync**: Efficient detection of differences
2. **Delta Sync**: Transfer only changed keys
3. **Bulk Transfer**: Batch multiple keys for efficiency
4. **Compression**: Zstd compression for network transfer

## Performance Optimizations

### Caching Strategy
- **Read Cache**: LRU cache for frequently accessed keys
- **Write Buffer**: Batch writes for efficiency
- **Bloom Filters**: Quick negative lookups
- **Index Cache**: Cache secondary indexes

### Compaction Policy
- **Level Compaction**: For RocksDB backend
- **Auto-vacuum**: For SQLite backend
- **TTL Cleanup**: Background task for expired keys

## Error Handling

### Error Types
```rust
#[derive(Debug, Error)]
pub enum PersistenceError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Corruption detected: {0}")]
    Corruption(String),
    
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    #[error("Replication failed: {0}")]
    Replication(String),
    
    #[error("Transaction aborted: {0}")]
    Transaction(String),
    
    #[error("Storage full")]
    StorageFull,
    
    #[error("Key not found")]
    NotFound,
}
```

### Recovery Procedures
1. **Corruption Recovery**: Restore from replicas
2. **Network Partition**: Queue operations for retry
3. **Disk Full**: Trigger emergency compaction
4. **Crash Recovery**: WAL replay for consistency

## Migration Support

### Schema Versioning
```rust
pub struct Migration {
    pub version: u32,
    pub description: String,
    pub up: fn(&Store) -> Result<()>,
    pub down: fn(&Store) -> Result<()>,
}
```

### Migration Process
1. Check current schema version
2. Apply migrations sequentially
3. Update version marker
4. Verify data integrity

## Monitoring & Metrics

### Key Metrics
- **Storage Size**: Total bytes used
- **Key Count**: Number of keys stored
- **Read Latency**: P50, P95, P99
- **Write Latency**: P50, P95, P99
- **Cache Hit Rate**: Percentage of cache hits
- **Replication Lag**: Time behind primary
- **Error Rate**: Errors per second

### Health Checks
```rust
pub struct StorageHealth {
    pub status: HealthStatus,
    pub storage_used: u64,
    pub storage_available: u64,
    pub replication_healthy: bool,
    pub last_compaction: SystemTime,
    pub error_count: u64,
}
```

## Testing Strategy

### Unit Tests
- Individual trait implementations
- Encryption/decryption roundtrips
- Error handling paths

### Integration Tests
- Multi-backend consistency
- Replication scenarios
- Migration testing
- Crash recovery

### Property Tests
- Invariant checking with proptest
- Concurrent access patterns
- Large-scale operations

### Benchmarks
- Read/write throughput
- Range query performance
- Replication bandwidth
- Memory usage

## Security Considerations

### Access Control
- Namespace-based permissions
- Key-level access control
- Audit logging for sensitive operations

### Data Protection
- Encryption at rest (mandatory)
- Secure key deletion (overwrite)
- Memory scrubbing for sensitive data

### Network Security
- TLS for replication traffic
- Mutual authentication for peers
- Rate limiting for queries

## Platform-Specific Considerations

### Desktop (Linux/macOS/Windows)
- Full RocksDB features
- Unlimited storage
- Background compaction

### Mobile (iOS/Android)
- SQLite backend preferred
- Storage quotas
- Battery-aware sync

### WebAssembly
- IndexedDB backend
- Browser storage limits
- Simplified replication

## Configuration

### Example Configuration
```toml
[persistence]
# Storage backend
backend = "rocksdb"

# Storage path
path = "~/.saorsa/data"

# Maximum storage size (bytes)
max_size = 10_737_418_240  # 10GB

# Cache configuration
[persistence.cache]
size_mb = 128
ttl_seconds = 3600

# Encryption
[persistence.encryption]
enabled = true
algorithm = "saorsa-pqc-aead"
key_rotation_days = 90

# Replication
[persistence.replication]
factor = 8
write_consistency = "quorum"
read_consistency = "one"

# Compaction
[persistence.compaction]
auto = true
interval_hours = 24
target_file_size_mb = 64
```

## Future Enhancements

### Phase 2 Features
- SQL query layer
- Full-text search
- Time-series data
- Graph relationships

### Phase 3 Features
- Multi-region replication
- Hierarchical storage tiers
- Advanced analytics
- CRDT support

## Acceptance Criteria

### Functionality
- [ ] All trait methods implemented
- [ ] RocksDB backend operational
- [ ] Encryption working correctly
- [ ] Replication achieving K=8
- [ ] TTL cleanup functional

### Performance
- [ ] Read latency < 1ms (P99)
- [ ] Write latency < 10ms (P99)
- [ ] 100K ops/second sustained
- [ ] Memory usage < 256MB

### Reliability
- [ ] Zero data loss on crash
- [ ] Automatic recovery
- [ ] Replication convergence
- [ ] Migration success

### Security
- [ ] All data encrypted at rest
- [ ] Secure key management
- [ ] No sensitive data leaks
- [ ] Audit trail complete
