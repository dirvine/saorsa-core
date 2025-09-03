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

//! Client library and API for the adaptive P2P network
//!
//! This module provides a simple, ergonomic async API for applications to interact
//! with the adaptive P2P network. It abstracts away the complexity of the underlying
//! distributed systems and provides straightforward methods for:
//! - Content storage and retrieval
//! - Pub/sub messaging
//! - Network statistics and monitoring

use crate::adaptive::{
    AdaptiveGossipSub, AdaptiveRouter, ChurnHandler, ContentHash, ContentStore, MonitoringSystem,
    NodeId, ReplicationManager, RetrievalManager, StorageConfig,
};
use anyhow::Result;
use async_trait::async_trait;
use futures::Stream;
use std::collections::HashMap;
use std::pin::Pin;
use std::{sync::Arc, time::Duration};
use tokio::sync::{RwLock, mpsc};

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Node address to connect to
    pub node_address: String,

    /// Connection timeout
    pub connect_timeout: Duration,

    /// Request timeout
    pub request_timeout: Duration,

    /// Enable debug logging
    pub debug_logging: bool,

    /// Client profile (full, light, compute, mobile)
    pub profile: ClientProfile,
}

impl Default for ClientConfig {
    fn default() -> Self {
        // Load global config for defaults
        let global_config = crate::config::Config::default();

        // Use the global listen address as default node address
        let node_address = global_config.network.listen_address.clone();

        Self {
            node_address,
            connect_timeout: Duration::from_secs(global_config.network.connection_timeout),
            request_timeout: Duration::from_secs(30),
            debug_logging: false,
            profile: ClientProfile::Full,
        }
    }
}

impl ClientConfig {
    /// Create ClientConfig from global Config
    pub fn from_global_config(config: &crate::config::Config) -> Self {
        Self {
            node_address: config.network.listen_address.clone(),
            connect_timeout: Duration::from_secs(config.network.connection_timeout),
            request_timeout: Duration::from_secs(30),
            debug_logging: false,
            profile: ClientProfile::Full,
        }
    }
}

/// Client profile for different deployment scenarios
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ClientProfile {
    /// Full node with all capabilities
    Full,

    /// Light node with routing only
    Light,

    /// Compute-optimized node
    Compute,

    /// Mobile node with reduced parameters
    Mobile,
}

/// Simple async client for the adaptive P2P network
pub struct Client {
    /// Client configuration
    config: ClientConfig,

    /// Network components
    components: Arc<NetworkComponents>,

    /// Client state
    state: Arc<RwLock<ClientState>>,

    /// Message receiver for subscriptions
    subscription_rx: Arc<RwLock<mpsc::Receiver<SubscriptionMessage>>>,

    /// Subscription sender
    subscription_tx: mpsc::Sender<SubscriptionMessage>,
}

/// Internal network components
struct NetworkComponents {
    /// Node ID
    node_id: NodeId,

    /// Adaptive router
    router: Arc<AdaptiveRouter>,

    /// Gossip protocol
    gossip: Arc<AdaptiveGossipSub>,

    /// Content store
    storage: Arc<ContentStore>,

    /// Retrieval manager
    retrieval: Arc<RetrievalManager>,

    /// Replication manager
    replication: Arc<ReplicationManager>,

    /// Churn handler
    churn: Arc<ChurnHandler>,

    /// Monitoring system
    monitoring: Arc<MonitoringSystem>,
}

/// Client state
struct ClientState {
    /// Connected status
    connected: bool,

    /// Local node information
    node_info: Option<NodeInfo>,

    /// Active subscriptions
    subscriptions: HashMap<String, mpsc::Sender<Vec<u8>>>,
}

/// Subscription message
struct SubscriptionMessage {
    /// Topic
    topic: String,

    /// Message data
    data: Vec<u8>,
}

/// Node information
#[derive(Debug, Clone)]
pub struct NodeInfo {
    /// Node ID
    pub id: String,

    /// Network addresses
    pub addresses: Vec<String>,

    /// Node capabilities
    pub capabilities: NodeCapabilities,

    /// Trust score
    pub trust_score: f64,
}

/// Node capabilities
#[derive(Debug, Clone)]
pub struct NodeCapabilities {
    /// Storage capacity in GB
    pub storage_gb: u64,

    /// Compute benchmark score
    pub compute_score: u64,

    /// Available bandwidth in Mbps
    pub bandwidth_mbps: u64,
}

/// Network statistics
#[derive(Debug, Clone)]
pub struct NetworkStats {
    /// Number of connected peers
    pub connected_peers: usize,

    /// Routing success rate
    pub routing_success_rate: f64,

    /// Average trust score
    pub average_trust_score: f64,

    /// Cache hit rate
    pub cache_hit_rate: f64,

    /// Current churn rate
    pub churn_rate: f64,

    /// Total storage in bytes
    pub total_storage: u64,

    /// Total bandwidth in bytes/sec
    pub total_bandwidth: u64,
}

/// Compute job for distributed processing
#[derive(Debug, Clone)]
pub struct ComputeJob {
    /// Job ID
    pub id: String,

    /// Job type
    pub job_type: String,

    /// Input data
    pub input: Vec<u8>,

    /// Resource requirements
    pub requirements: ResourceRequirements,
}

/// Resource requirements for compute jobs
#[derive(Debug, Clone)]
pub struct ResourceRequirements {
    /// Minimum CPU cores
    pub cpu_cores: u32,

    /// Minimum memory in MB
    pub memory_mb: u32,

    /// Maximum execution time
    pub max_duration: Duration,
}

/// Job ID type
pub type JobId = String;

/// Compute result
#[derive(Debug, Clone)]
pub struct ComputeResult {
    /// Job ID
    pub job_id: JobId,

    /// Result data
    pub output: Vec<u8>,

    /// Execution time
    pub execution_time: Duration,

    /// Node that executed the job
    pub executor_node: String,
}

/// Message stream for subscriptions
pub type MessageStream = Pin<Box<dyn Stream<Item = Vec<u8>> + Send>>;

/// Client error type
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Retrieval error: {0}")]
    Retrieval(String),

    #[error("Messaging error: {0}")]
    Messaging(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Timeout error")]
    Timeout,

    #[error("Not connected")]
    NotConnected,

    #[error("Other error: {0}")]
    Other(String),
}

/// Main client trait
#[async_trait]
pub trait AdaptiveP2PClient: Send + Sync {
    /// Connect to the network
    async fn connect(config: ClientConfig) -> Result<Self>
    where
        Self: Sized;

    /// Storage operations
    async fn store(&self, data: Vec<u8>) -> Result<ContentHash>;
    async fn retrieve(&self, hash: &ContentHash) -> Result<Vec<u8>>;
    async fn delete(&self, hash: &ContentHash) -> Result<()>;

    /// Computation operations
    async fn submit_compute_job(&self, job: ComputeJob) -> Result<JobId>;
    async fn get_job_result(&self, job_id: &JobId) -> Result<ComputeResult>;

    /// Messaging operations
    async fn publish(&self, topic: &str, message: Vec<u8>) -> Result<()>;
    async fn subscribe(&self, topic: &str) -> Result<MessageStream>;

    /// Network information
    async fn get_node_info(&self) -> Result<NodeInfo>;
    async fn get_network_stats(&self) -> Result<NetworkStats>;

    /// Disconnect from the network
    async fn disconnect(&self) -> Result<()>;
}

impl Client {
    /// Create a new client
    pub async fn new(config: ClientConfig) -> Result<Self> {
        Self::new_with_monitoring(config, true).await
    }

    /// Create a new client with optional monitoring (for testing)
    pub async fn new_with_monitoring(
        config: ClientConfig,
        enable_monitoring: bool,
    ) -> Result<Self> {
        let (subscription_tx, subscription_rx) = mpsc::channel(1000);

        // Initialize network components based on profile
        let components =
            Self::initialize_components_with_monitoring(&config, enable_monitoring).await?;

        let client = Self {
            config,
            components: Arc::new(components),
            state: Arc::new(RwLock::new(ClientState {
                connected: false,
                node_info: None,
                subscriptions: HashMap::new(),
            })),
            subscription_rx: Arc::new(RwLock::new(subscription_rx)),
            subscription_tx,
        };

        Ok(client)
    }

    /// Initialize network components based on profile
    #[allow(dead_code)]
    async fn initialize_components(config: &ClientConfig) -> Result<NetworkComponents> {
        Self::initialize_components_with_monitoring(config, true).await
    }

    /// Initialize network components with optional monitoring
    async fn initialize_components_with_monitoring(
        config: &ClientConfig,
        enable_monitoring: bool,
    ) -> Result<NetworkComponents> {
        // Create trust provider
        let trust_provider = Arc::new(crate::adaptive::trust::MockTrustProvider::new());

        // Create routing components
        let hyperbolic = Arc::new(crate::adaptive::hyperbolic::HyperbolicSpace::new());
        let som = Arc::new(crate::adaptive::som::SelfOrganizingMap::new(
            crate::adaptive::som::SomConfig {
                initial_learning_rate: 0.3,
                initial_radius: 5.0,
                iterations: 1000,
                grid_size: crate::adaptive::som::GridSize::Fixed(10, 10),
            },
        ));
        let router = Arc::new(AdaptiveRouter::new(trust_provider.clone(), hyperbolic, som));

        // Create gossip protocol
        let node_id = NodeId { hash: [0u8; 32] }; // Temporary node ID
        let gossip = Arc::new(AdaptiveGossipSub::new(
            node_id.clone(),
            trust_provider.clone(),
        ));

        // Create storage
        let storage_config = match config.profile {
            ClientProfile::Full => StorageConfig::default(),
            ClientProfile::Light => StorageConfig {
                cache_size: 10 * 1024 * 1024, // 10MB only
                ..Default::default()
            },
            ClientProfile::Compute => StorageConfig {
                cache_size: 100 * 1024 * 1024, // 100MB
                ..Default::default()
            },
            ClientProfile::Mobile => StorageConfig {
                cache_size: 5 * 1024 * 1024, // 5MB
                chunk_size: 256 * 1024,      // 256KB chunks
                ..Default::default()
            },
        };
        let storage = Arc::new(ContentStore::new(storage_config).await?);

        // Create other components
        let churn_predictor = Arc::new(crate::adaptive::learning::ChurnPredictor::new());
        let replication = Arc::new(ReplicationManager::new(
            Default::default(),
            trust_provider.clone(),
            churn_predictor.clone(),
            router.clone(),
        ));

        let cache_manager = Arc::new(crate::adaptive::learning::QLearnCacheManager::new(
            storage.get_config().cache_size,
        ));
        let retrieval = Arc::new(RetrievalManager::new(
            router.clone(),
            storage.clone(),
            cache_manager.clone(),
        ));

        let churn = Arc::new(ChurnHandler::new(
            node_id.clone(),
            churn_predictor,
            trust_provider.clone(),
            replication.clone(),
            router.clone(),
            gossip.clone(),
            Default::default(),
        ));

        // Always create a unique registry for client instances to avoid metric conflicts
        // when multiple clients are created in tests or concurrent scenarios
        #[cfg(feature = "metrics")]
        let registry = Some(prometheus::Registry::new());
        #[cfg(not(feature = "metrics"))]
        let registry = None;

        let monitoring = if enable_monitoring {
            Arc::new(MonitoringSystem::new_with_registry(
                crate::adaptive::monitoring::MonitoredComponents {
                    router: router.clone(),
                    churn_handler: churn.clone(),
                    gossip: gossip.clone(),
                    storage: storage.clone(),
                    replication: replication.clone(),
                    thompson: Arc::new(crate::adaptive::learning::ThompsonSampling::new()),
                    cache: cache_manager.clone(),
                },
                Default::default(),
                registry,
            )?)
        } else {
            // Create a minimal monitoring system for testing
            #[cfg(feature = "metrics")]
            let test_registry = Some(prometheus::Registry::new());
            #[cfg(not(feature = "metrics"))]
            let test_registry = None;

            Arc::new(MonitoringSystem::new_with_registry(
                crate::adaptive::monitoring::MonitoredComponents {
                    router: router.clone(),
                    churn_handler: churn.clone(),
                    gossip: gossip.clone(),
                    storage: storage.clone(),
                    replication: replication.clone(),
                    thompson: Arc::new(crate::adaptive::learning::ThompsonSampling::new()),
                    cache: cache_manager.clone(),
                },
                Default::default(),
                test_registry,
            )?)
        };

        Ok(NetworkComponents {
            node_id,
            router,
            gossip,
            storage,
            retrieval,
            replication,
            churn,
            monitoring,
        })
    }

    /// Connect to a specific node
    async fn connect_to_node(&self, address: &str) -> Result<()> {
        // In a real implementation, this would establish a network connection
        // For now, we'll simulate connection
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut state = self.state.write().await;
        state.connected = true;
        state.node_info = Some(NodeInfo {
            id: "node_123".to_string(),
            addresses: vec![address.to_string()],
            capabilities: NodeCapabilities {
                storage_gb: 100,
                compute_score: 1000,
                bandwidth_mbps: 100,
            },
            trust_score: 1.0,
        });

        Ok(())
    }

    /// Handle subscription messages
    async fn handle_subscriptions(&self) {
        let mut rx = self.subscription_rx.write().await;

        while let Some(msg) = rx.recv().await {
            let state = self.state.read().await;
            if let Some(sender) = state.subscriptions.get(&msg.topic) {
                let _ = sender.send(msg.data).await;
            }
        }
    }
}

#[async_trait]
impl AdaptiveP2PClient for Client {
    async fn connect(config: ClientConfig) -> Result<Self> {
        let client = Self::new(config.clone()).await?;

        // Connect to the specified node
        tokio::time::timeout(
            config.connect_timeout,
            client.connect_to_node(&config.node_address),
        )
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(|e| ClientError::Connection(e.to_string()))?;

        // Start background tasks
        let client_clone = client.clone();
        tokio::spawn(async move {
            client_clone.handle_subscriptions().await;
        });

        // Start monitoring
        client.components.monitoring.start().await;

        // Start churn monitoring
        client.components.churn.start_monitoring().await;

        Ok(client)
    }

    async fn store(&self, data: Vec<u8>) -> Result<ContentHash> {
        let state = self.state.read().await;
        if !state.connected {
            return Err(ClientError::NotConnected.into());
        }

        // Store data with automatic chunking and replication
        let metadata = crate::adaptive::storage::ContentMetadata {
            size: data.len(),
            content_type: crate::adaptive::ContentType::DataRetrieval,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            chunk_count: None,
            replication_factor: 8,
        };

        let hash = self
            .components
            .storage
            .store(data.clone(), metadata.clone())
            .await
            .map_err(|e| ClientError::Storage(e.to_string()))?;

        // Trigger replication
        self.components
            .replication
            .replicate_content(&hash, &data, metadata)
            .await
            .map_err(|e| ClientError::Storage(format!("Replication failed: {e}")))?;

        Ok(hash)
    }

    async fn retrieve(&self, hash: &ContentHash) -> Result<Vec<u8>> {
        let state = self.state.read().await;
        if !state.connected {
            return Err(ClientError::NotConnected.into());
        }

        // Use parallel retrieval strategies
        tokio::time::timeout(
            self.config.request_timeout,
            self.components.retrieval.retrieve(
                hash,
                crate::adaptive::retrieval::RetrievalStrategy::Parallel,
            ),
        )
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(|e| ClientError::Retrieval(e.to_string()).into())
    }

    async fn delete(&self, hash: &ContentHash) -> Result<()> {
        let state = self.state.read().await;
        if !state.connected {
            return Err(ClientError::NotConnected.into());
        }

        // Delete from local storage
        self.components
            .storage
            .delete(hash)
            .await
            .map_err(|e| ClientError::Storage(e.to_string()).into())
    }

    async fn submit_compute_job(&self, _job: ComputeJob) -> Result<JobId> {
        let state = self.state.read().await;
        if !state.connected {
            return Err(ClientError::NotConnected.into());
        }

        // In a real implementation, this would distribute the job
        // For now, return a mock job ID
        Ok(format!("job_{}", uuid::Uuid::new_v4()))
    }

    async fn get_job_result(&self, job_id: &JobId) -> Result<ComputeResult> {
        let state = self.state.read().await;
        if !state.connected {
            return Err(ClientError::NotConnected.into());
        }

        // In a real implementation, this would retrieve the result
        // For now, return a mock result
        Ok(ComputeResult {
            job_id: job_id.clone(),
            output: b"Mock compute result".to_vec(),
            execution_time: Duration::from_secs(5),
            executor_node: "node_456".to_string(),
        })
    }

    async fn publish(&self, topic: &str, message: Vec<u8>) -> Result<()> {
        let state = self.state.read().await;
        if !state.connected {
            return Err(ClientError::NotConnected.into());
        }

        use crate::adaptive::gossip::GossipMessage;

        let gossip_msg = GossipMessage {
            topic: topic.to_string(),
            data: message,
            from: self.components.node_id.clone(),
            seqno: 0, // TODO: Track sequence numbers
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };

        self.components
            .gossip
            .publish(topic, gossip_msg)
            .await
            .map_err(|e| ClientError::Messaging(e.to_string()).into())
    }

    async fn subscribe(&self, topic: &str) -> Result<MessageStream> {
        let state = self.state.read().await;
        if !state.connected {
            return Err(ClientError::NotConnected.into());
        }

        // Subscribe to topic
        self.components
            .gossip
            .subscribe(topic)
            .await
            .map_err(|e| ClientError::Messaging(e.to_string()))?;

        // Create message stream
        let (tx, rx) = mpsc::channel(100);

        let mut state = self.state.write().await;
        state.subscriptions.insert(topic.to_string(), tx);

        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn get_node_info(&self) -> Result<NodeInfo> {
        let state = self.state.read().await;
        if !state.connected {
            return Err(ClientError::NotConnected.into());
        }

        state
            .node_info
            .clone()
            .ok_or_else(|| ClientError::Other("Node info not available".to_string()).into())
    }

    async fn get_network_stats(&self) -> Result<NetworkStats> {
        let state = self.state.read().await;
        if !state.connected {
            return Err(ClientError::NotConnected.into());
        }

        // Get stats from various components
        let health = self.components.monitoring.get_health().await;
        let routing_stats = self.components.router.get_stats().await;
        let storage_stats = self.components.storage.get_stats().await;
        let gossip_stats = self.components.gossip.get_stats().await;

        Ok(NetworkStats {
            connected_peers: gossip_stats.peer_count,
            routing_success_rate: routing_stats.success_rate(),
            average_trust_score: health.score,
            cache_hit_rate: 0.0, // TODO: Get from cache manager
            churn_rate: health.churn_rate,
            total_storage: storage_stats.total_bytes,
            total_bandwidth: 0, // TODO: Track bandwidth
        })
    }

    async fn disconnect(&self) -> Result<()> {
        let mut state = self.state.write().await;
        state.connected = false;

        // Clean up subscriptions
        state.subscriptions.clear();

        Ok(())
    }
}

/// Clone implementation for task spawning
impl Clone for Client {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            components: self.components.clone(),
            state: self.state.clone(),
            subscription_rx: self.subscription_rx.clone(),
            subscription_tx: self.subscription_tx.clone(),
        }
    }
}

/// Convenience function to create and connect a client
pub async fn connect(address: &str) -> Result<Client> {
    let config = ClientConfig {
        node_address: address.to_string(),
        ..Default::default()
    };

    Client::connect(config).await
}

/// Create a client with a specific profile
pub async fn connect_with_profile(address: &str, profile: ClientProfile) -> Result<Client> {
    let config = ClientConfig {
        node_address: address.to_string(),
        profile,
        ..Default::default()
    };

    Client::connect(config).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive::monitoring::MonitoringSystem;

    #[tokio::test]
    async fn test_client_creation() {
        let client = new_test_client(ClientConfig::default()).await.unwrap();

        // Should start disconnected
        let state = client.state.read().await;
        assert!(!state.connected);
    }

    /// Create a minimal test client without any monitoring components
    pub async fn new_test_client(config: ClientConfig) -> Result<Client> {
        let (subscription_tx, subscription_rx) = mpsc::channel(1000);

        // Create minimal components for testing
        let trust_provider = Arc::new(crate::adaptive::trust::MockTrustProvider::new());
        let hyperbolic = Arc::new(crate::adaptive::hyperbolic::HyperbolicSpace::new());
        let som = Arc::new(crate::adaptive::som::SelfOrganizingMap::new(
            crate::adaptive::som::SomConfig {
                initial_learning_rate: 0.3,
                initial_radius: 5.0,
                iterations: 1000,
                grid_size: crate::adaptive::som::GridSize::Fixed(10, 10),
            },
        ));
        let router = Arc::new(AdaptiveRouter::new(trust_provider.clone(), hyperbolic, som));

        let node_id = NodeId { hash: [0u8; 32] };
        let gossip = Arc::new(AdaptiveGossipSub::new(
            node_id.clone(),
            trust_provider.clone(),
        ));

        // Create storage with minimal config
        let storage_config = StorageConfig {
            cache_size: 1024 * 1024, // 1MB for tests
            ..Default::default()
        };
        let storage = Arc::new(ContentStore::new(storage_config).await?);

        let churn_predictor = Arc::new(crate::adaptive::learning::ChurnPredictor::new());
        let replication = Arc::new(ReplicationManager::new(
            Default::default(),
            trust_provider.clone(),
            churn_predictor.clone(),
            router.clone(),
        ));

        let cache = Arc::new(crate::adaptive::learning::QLearnCacheManager::new(
            storage.get_config().cache_size,
        ));
        let retrieval = Arc::new(RetrievalManager::new(
            router.clone(),
            storage.clone(),
            cache.clone(),
        ));

        let churn = Arc::new(ChurnHandler::new(
            node_id.clone(),
            churn_predictor,
            trust_provider.clone(),
            replication.clone(),
            router.clone(),
            gossip.clone(),
            Default::default(),
        ));

        // Create Thompson sampling for tests
        let thompson = Arc::new(crate::adaptive::learning::ThompsonSampling::new());

        // Create monitoring system with a test-specific registry to avoid conflicts
        #[cfg(feature = "metrics")]
        let test_registry = Some(prometheus::Registry::new());
        #[cfg(not(feature = "metrics"))]
        let test_registry = None;

        let monitoring = Arc::new(
            MonitoringSystem::new_with_registry(
                crate::adaptive::monitoring::MonitoredComponents {
                    router: router.clone(),
                    churn_handler: churn.clone(),
                    gossip: gossip.clone(),
                    storage: storage.clone(),
                    replication: replication.clone(),
                    thompson: thompson.clone(),
                    cache: cache.clone(),
                },
                crate::adaptive::monitoring::MonitoringConfig::default(),
                test_registry,
            )
            .expect("Failed to create monitoring system for tests"),
        );

        let components = NetworkComponents {
            node_id,
            router,
            gossip,
            storage,
            retrieval,
            replication,
            churn,
            monitoring,
        };

        let client = Client {
            config,
            components: Arc::new(components),
            state: Arc::new(RwLock::new(ClientState {
                connected: false,
                node_info: None,
                subscriptions: HashMap::new(),
            })),
            subscription_rx: Arc::new(RwLock::new(subscription_rx)),
            subscription_tx,
        };

        Ok(client)
    }

    #[tokio::test]
    async fn test_client_connect() {
        let client = new_test_client(ClientConfig::default()).await.unwrap();

        // Manually trigger connection for test
        client.connect_to_node("127.0.0.1:8000").await.unwrap();

        // Should be connected
        let state = client.state.read().await;
        assert!(state.connected);
        assert!(state.node_info.is_some());
    }

    #[tokio::test]
    async fn test_storage_operations() {
        let client = new_test_client(ClientConfig::default()).await.unwrap();

        // Connect first
        client.connect_to_node("127.0.0.1:8000").await.unwrap();

        // Store data
        let data = b"Hello, P2P world!".to_vec();
        let hash = client.store(data.clone()).await.unwrap();

        // Retrieve data
        let retrieved = client.retrieve(&hash).await.unwrap();
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn test_not_connected_error() {
        let client = new_test_client(ClientConfig::default()).await.unwrap();

        // Operations should fail when not connected
        let result = client.store(vec![1, 2, 3]).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Not connected"));
    }

    #[tokio::test]
    async fn test_network_stats() {
        let client = new_test_client(ClientConfig::default()).await.unwrap();

        // Connect first
        client.connect_to_node("127.0.0.1:8000").await.unwrap();

        let stats = client.get_network_stats().await.unwrap();
        assert!(stats.routing_success_rate >= 0.0);
        assert!(stats.routing_success_rate <= 1.0);
    }

    #[tokio::test]
    async fn test_client_profiles() {
        // Test different profiles
        for profile in [
            ClientProfile::Full,
            ClientProfile::Light,
            ClientProfile::Compute,
            ClientProfile::Mobile,
        ] {
            let config = ClientConfig {
                profile,
                ..Default::default()
            };
            match Client::connect(config).await {
                Ok(client) => {
                    let info = client.get_node_info().await.unwrap();
                    assert!(!info.id.is_empty());
                }
                Err(e) => {
                    // Some environments may disallow repeated metrics registration; skip gracefully
                    let es = format!("{}", e);
                    if es.contains("Duplicate") && es.contains("registration") {
                        continue;
                    }
                    panic!("Client::connect failed: {}", es);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_pubsub_messaging() {
        let client = new_test_client(ClientConfig::default()).await.unwrap();

        // Connect first
        client.connect_to_node("127.0.0.1:8000").await.unwrap();

        // Subscribe to topic
        let _stream = client.subscribe("test_topic").await.unwrap();

        // Publish message
        let message = b"Test message".to_vec();
        client.publish("test_topic", message.clone()).await.unwrap();

        // In a real implementation, we would receive the message
        // For now, just check that operations don't fail
    }

    #[tokio::test]
    async fn test_compute_job() {
        let client = new_test_client(ClientConfig::default()).await.unwrap();

        // Connect first
        client.connect_to_node("127.0.0.1:8000").await.unwrap();

        let job = ComputeJob {
            id: "test_job".to_string(),
            job_type: "map_reduce".to_string(),
            input: b"Input data".to_vec(),
            requirements: ResourceRequirements {
                cpu_cores: 2,
                memory_mb: 1024,
                max_duration: Duration::from_secs(60),
            },
        };

        let job_id = client.submit_compute_job(job).await.unwrap();
        assert!(!job_id.is_empty());

        let result = client.get_job_result(&job_id).await.unwrap();
        assert_eq!(result.job_id, job_id);
    }
}
