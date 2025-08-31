# Network Architecture: Multi-Layer Adaptive P2P System

### Purpose
The heart of our innovation - dynamically selects optimal routing strategies using machine learning.

### Core Innovation: Multi-Strategy Routing

Instead of committing to a single routing algorithm, we implement multiple strategies and use **Thompson Sampling** to select the best one for each request:

#### Implemented Routing Strategies

1. **Kademlia Routing** (`adaptive/routing.rs::KademliaRouting`)
   - XOR metric for distance calculation
   - K-buckets with K=8 replication
   - Iterative lookup with α=3 parallelism
   - **Best for**: General DHT operations, stable networks

2. **Hyperbolic Routing** (`adaptive/hyperbolic.rs`)
   - Maps network to hyperbolic space (Poincaré disk)
   - Greedy routing using hyperbolic distance
   - Natural hierarchy emergence
   - **Best for**: Scale-free networks, social graphs

3. **Trust-Based Routing** (`adaptive/trust.rs`)
   - EigenTrust for global reputation
   - Routes through high-trust nodes
   - Sybil attack resistance
   - **Best for**: Adversarial environments, sensitive data

4. **Self-Organizing Map (SOM) Routing** (`adaptive/som.rs`)
   - Neural network topology mapping
   - 2D grid representation of network
   - Similarity-based clustering
   - **Best for**: Content-based routing, semantic search

### Machine Learning Components

#### Multi-Armed Bandit (`adaptive/multi_armed_bandit.rs`)
```rust
// Selects routing strategy based on past performance
let strategy = bandit.select_strategy(
    content_type,
    network_conditions,
    latency_requirements
);
```

**Algorithm**: Thompson Sampling with Beta distributions
- Maintains success/failure counts per strategy
- Samples from posterior distribution
- Balances exploration vs exploitation
- Updates based on routing outcomes

#### Q-Learning Cache (`adaptive/q_learning_cache.rs`)
```rust
// Learns optimal caching policies
let should_cache = q_cache.evaluate_caching_decision(
    content_hash,
    access_frequency,
    storage_cost
);
```

**State Space**: (content_popularity, local_storage, network_distance)
**Action Space**: {cache, don't_cache, evict_other}
**Reward Function**: Hit rate improvement - storage cost

#### Churn Prediction (`adaptive/churn_prediction.rs`)
- **LSTM Network**: Predicts node departures
- **Features**: Connection history, time patterns, bandwidth usage
- **Proactive Replication**: Increases replication before predicted churn
- **Accuracy**: 85% prediction rate at 30-minute horizon

## Layer 4: Protocol Layer

### Purpose
Implements high-level protocols for data distribution and coordination.

### Components

#### Distributed Hash Table (`dht/`)
- **Kademlia Base**: Modified with multi-strategy routing
- **Git-Like Semantics**: Content-addressed with BLAKE3
- **Replication Factor**: K=8 for high availability
- **Record Types**:
  - Immutable content (hash → data)
  - Mutable pointers (pubkey → hash)
  - Peer records (peer_id → connection_info)

#### Gossipsub Protocol (`adaptive/gossip.rs`)
- **Topic-Based Pub/Sub**: Efficient message propagation
- **Mesh Network**: D=6 peers per topic
- **Message Validation**: Cryptographic signatures
- **Flood Prevention**: Seen message cache

#### Trust Network (`adaptive/trust.rs`)
- **EigenTrust Algorithm**: Global trust computation
- **Trust Propagation**: Transitive trust relationships
- **Sybil Resistance**: Cost for creating identities
- **Trust Decay**: Time-based trust reduction

## Layer 5: Service Layer

### Purpose
Provides high-level services that applications can use.

### Components



#### Node Management (`network.rs`)
- **Bootstrap Process**: Initial network joining
- **Peer Discovery**: Multiple discovery mechanisms
- **Health Monitoring**: Liveness and readiness checks
- **Graceful Shutdown**: Clean connection closing

## Layer 6: Application Layer

### Purpose
User-facing applications built on the P2P foundation.

### Applications

Applications can be built on top of this foundation crate to provide:
- Decentralized communication platforms
- Distributed file sharing systems
- Collaborative document editing
- Identity-based access control
- End-to-end encrypted messaging

## Adaptive Behavior Patterns

### 1. Network Condition Adaptation

The system continuously monitors network conditions and adapts:

```rust
// Example: Strategy selection based on conditions
match network_state {
    NetworkState::Stable => {
        // Prefer Kademlia for predictable performance
        router.set_preference(Strategy::Kademlia, 0.7);
    }
    NetworkState::HighChurn => {
        // Use hyperbolic routing for resilience
        router.set_preference(Strategy::Hyperbolic, 0.8);
        // Increase replication factor
        dht.set_replication(12);
    }
    NetworkState::Adversarial => {
        // Route through trusted nodes only
        router.set_preference(Strategy::TrustBased, 0.9);
    }
}
```

### 2. Content-Aware Routing

Different content types use different strategies:

- **Small messages**: Direct Kademlia routing
- **Large files**: Chunked with parallel retrieval
- **Real-time streams**: Low-latency path selection
- **Sensitive data**: Trust-based routing only

### 3. Learning from Failure

Every routing failure updates the ML models:

```rust
// Routing failure triggers learning
on_routing_failure(|failure| {
    // Update multi-armed bandit
    bandit.record_failure(failure.strategy);
    
    // Adjust Q-learning cache
    q_cache.penalize_path(failure.path);
    
    // Update peer trust scores
    trust_network.decrease_trust(failure.peer);
    
    // Trigger alternative strategy
    router.try_alternative_strategy(failure.target);
});
```

## Performance Optimizations

### 1. Intelligent Caching
- **Q-Learning**: Learns optimal cache policies
- **Predictive Prefetching**: Anticipates content requests
- **Collaborative Caching**: Nodes coordinate cache contents
- **Adaptive Eviction**: LRU, LFU, or learned policy

### 2. Connection Pooling
- **Persistent Connections**: Reuse QUIC streams
- **Multiplexing**: Multiple requests per connection
- **Smart Routing**: Choose existing connections when possible
- **Connection Coalescing**: Combine related requests

### 3. Parallel Operations
- **Concurrent Lookups**: α=3 parallel DHT queries
- **Chunked Transfers**: Parallel chunk retrieval
- **Speculative Execution**: Try multiple strategies simultaneously
- **Request Hedging**: Duplicate requests to multiple peers

## Security Considerations

### 1. Sybil Attack Resistance
- **Trust Networks**: Reputation-based filtering (EigenTrust)
- **Resource Testing**: Bandwidth and storage verification
- **Social Graph Analysis**: Detect abnormal connection patterns
- Note: Proof‑of‑Work has been removed from the design and implementation.

### 2. Eclipse Attack Prevention
- **Diverse Peer Selection**: Multiple routing strategies
- **Peer Rotation**: Regular connection refresh
- **Out-of-band Verification**: External peer discovery
- **Topology Monitoring**: Detect isolation attempts

### 3. Data Integrity
- **Content Addressing**: BLAKE3 hash verification
- **Signature Verification**: ML-DSA signatures (post‑quantum)
- **Merkle Trees**: Efficient large file verification
- **Byzantine Fault Tolerance**: Handle malicious nodes

## Monitoring and Metrics

### Key Performance Indicators

```rust
pub struct NetworkMetrics {
    // Routing performance
    pub routing_success_rate: f64,
    pub average_hop_count: f64,
    pub lookup_latency_p50: Duration,
    pub lookup_latency_p99: Duration,
    
    // Learning effectiveness
    pub strategy_selection_accuracy: f64,
    pub cache_hit_rate: f64,
    pub churn_prediction_accuracy: f64,
    
    // Network health
    pub active_connections: usize,
    pub total_peers: usize,
    pub bandwidth_utilization: f64,
    pub storage_utilization: f64,
}
```

### Adaptive Thresholds

The system automatically adjusts operational parameters:

- **Replication Factor**: 3-20 based on churn rate
- **Cache Size**: 10MB-10GB based on available resources
- **Connection Limit**: 10-1000 based on bandwidth
- **Routing Timeout**: 100ms-10s based on network latency

## Future Enhancements

### Planned Features

1. **Neural Architecture Search**: Automatically evolve routing strategies
2. **Federated Learning**: Collaborative model training across nodes
3. **Homomorphic Encryption**: Compute on encrypted data
4. **Zero-Knowledge Proofs**: Enhanced privacy preserving protocols
5. **Quantum Network Support**: Integration with quantum key distribution

### Research Directions

1. **Bio-Inspired Algorithms**: Ant colony optimization for routing
2. **Game Theory**: Nash equilibrium for resource allocation
3. **Topology Optimization**: Small-world network construction
4. **Consensus Mechanisms**: Novel Byzantine fault tolerant protocols

## Implementation Status

### Production Ready ✅
- Kademlia DHT with K=8 replication
- QUIC transport with NAT traversal
- Dual‑stack listeners (IPv6 + IPv4) with Happy Eyeballs dialing
- Four‑word endpoint encoding via `four-word-networking` (endpoints only)
- ML‑DSA cryptographic identity (post‑quantum)
- Basic caching and storage

### Beta Features 🔧
- Multi-armed bandit routing selection
- Q-learning cache optimization
- Hyperbolic routing geometry
- Trust network with EigenTrust
- MCP server integration

### Experimental 🧪
- Self-organizing maps (SOM)
- LSTM churn prediction
- Quantum-resistant cryptography
- Federated learning
- Neural architecture search

## Layer 7: Entity Storage System

### Purpose
Provides decentralized storage with markdown-based web publishing for all entity types (individuals, projects, groups, channels, organizations).

**Note**: The full entity storage system with markdown web publishing is implemented in separate crates that build on this foundation. This core crate provides the essential storage and DHT infrastructure.

### Storage Architecture

Each entity (personal, organization, project, group, channel) has an associated storage object with several key features:

#### 1. Markdown Web Directory
- **Web Directory Structure**: Each entity has a dedicated `web/` directory
- **Index File**: `web/home.md` serves as the markdown equivalent of `index.html`
- **Navigation**: Acts as the entry point for the entity's markdown-based website
- **Editing**: Full markdown editor integration for real-time content management
- **Rendering**: Specialized markdown browser with support for:
  - Images and media embedding
  - Video playback
  - Interactive elements
  - Cross-references between markdown files

#### 2. Collaborative File System
- **Shared Files**: Files outside `web/` directory are collaboratively editable
- **Real-time Collaboration**: Multiple users can edit markdown files simultaneously
- **Identity Integration**: Uses `UserHandle` for user attribution in messaging and collaboration
- **Display Names**: Users have readable handles while the system uses four‑word endpoints strictly for network addressing
- **Version Control**: Git-like versioning for all collaborative documents

#### 3. Reed-Solomon Distribution
- **Implementation**: Uses `saorsa-fec` crate for Reed-Solomon encoding
- **Fairness Mechanism**: All files use Reed-Solomon encoding with witness system
- **High Availability**: 60% of shards required for reconstruction
- **Load Distribution**: Ensures fair resource usage across network participants
- **Redundancy**: Protects against node failures and data loss

#### 4. File Processing Pipeline

**Compression and Sharding**:
1. Files are compressed using efficient algorithms
2. Sharded into 1MB blocks for optimal distribution
3. Each shard XORed with hash of complete file
4. AES encryption using file hash as password

**DHT Storage**:
1. Encrypted shards stored on distributed hash table
2. Metadata retained locally as hidden files
3. Metadata contains reconstruction information
4. First-time users receive files via Reed-Solomon from peers
5. Users can recreate DHT metadata from received shards

#### 5. Storage Classes and Allocation

**Personal Storage** (1:1:2 allocation policy):
- Local storage for immediate access
- DHT replication for backup
- Public DHT contribution (2x personal allocation)

**Group/Organization Storage**:
- Reed-Solomon encoded across group members
- Encrypted backups in DHT
- Collaborative editing capabilities
- Version history and conflict resolution

### Implementation Components

#### Storage Manager (`storage/mod.rs`)
- **Capacity Management**: Enforces 1:1:2 storage allocation
- **Usage Tracking**: Monitors storage utilization across all classes
- **Health Monitoring**: Ensures storage system performance

#### Reed-Solomon Manager
- **Crate**: Utilizes `saorsa-fec` for forward error correction
- **Enhanced Encoding**: 60% availability threshold
- **Shard Distribution**: Optimal placement across network
- **Reconstruction**: Efficient data recovery from partial shards

#### DHT Storage (`dht_storage.rs`)
- **Content Addressing**: BLAKE3-based addressing
- **Encryption**: AES-256 with file-hash derived keys
- **Metadata Management**: Local hidden file system

#### Entity Storage
- **Implementation**: Available in separate application crates
- **Multi-Entity Support**: Handles all 5 entity types
- **Web Directory Management**: Markdown web publishing
- **Collaborative Features**: Real-time editing support

### Security Considerations

#### Encryption Strategy
- **File-Level Encryption**: Each file encrypted with its own derived key
- **Key Derivation**: BLAKE3 hash of file content as password
- **Shard Protection**: XOR with file hash before encryption
- **Identity-Based Access**: Messaging/user features use `UserHandle` for access control; four‑word endpoints are network addresses only

#### Privacy Protection
- **Local Metadata**: Reconstruction data kept locally
- **Anonymous DHT**: Shard storage doesn't reveal content
- **Selective Sharing**: Granular permission system
- **Zero-Knowledge**: Network participants can't access encrypted content

### User Experience Features

#### Markdown Web Publishing
- **WYSIWYG Editor**: Rich editing experience for markdown content
- **Live Preview**: Real-time rendering of markdown changes
- **Media Support**: Drag-and-drop images, videos, and files
- **Cross-Linking**: Easy navigation between related documents
- **Template System**: Pre-built layouts for common use cases

#### Collaborative Editing
- **Operational Transforms**: Conflict-free collaborative editing
- **Presence Indicators**: See who's editing in real-time
- **Comment System**: In-line comments and suggestions
- **History Tracking**: Complete edit history with attribution
- **Merge Conflict Resolution**: Intelligent conflict handling

### Performance Optimizations

#### Intelligent Caching
- **Local-First Access**: Prefer local copies when available
- **Predictive Prefetching**: Anticipate content requests
- **Collaborative Caching**: Coordinate cache contents across group
- **Adaptive Compression**: Optimize compression based on content type

#### Network Efficiency
- **Delta Synchronization**: Only sync changed portions
- **Batch Operations**: Group multiple file operations
- **Compression Pipelines**: Multi-stage compression for different content
- **Smart Routing**: Optimize paths for large file transfers

### Monitoring and Analytics

#### Storage Metrics
- **Utilization Tracking**: Monitor storage usage across all classes
- **Performance Metrics**: Track upload/download speeds and success rates
- **Collaboration Analytics**: Usage patterns for shared documents
- **Health Indicators**: Early warning for storage issues

#### Network Health
- **Shard Availability**: Monitor Reed-Solomon shard distribution
- **Node Reliability**: Track peer availability and performance
- **Reconstruction Success**: Monitor data recovery capabilities
- **Load Distribution**: Ensure fair resource utilization

## Conclusion

Our multi-layer adaptive P2P network represents a paradigm shift in distributed systems design. By combining multiple routing strategies with machine learning, we achieve:

- **Optimal Performance**: Always use the best strategy for current conditions
- **Resilience**: Multiple fallback options for any failure
- **Security**: Quantum-resistant with trust networks
- **Usability**: Human-readable addresses and simple APIs
- **Decentralized Publishing**: Markdown-based web publishing for all entities
- **Collaborative Excellence**: Real-time document collaboration with identity integration
- **Fair Resource Usage**: Reed-Solomon encoding ensures network equity
- **Future-Proof**: Designed for continuous evolution

This architecture enables us to build truly decentralized applications that are fast, secure, and user-friendly - achieving the original vision of a peer-to-peer internet with integrated content management and collaborative capabilities.
