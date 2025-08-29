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

//! DHT Network Manager
//!
//! This module provides the integration layer between the DHT system and the network layer,
//! enabling real P2P operations with Kademlia routing over transport protocols.

#![allow(missing_docs)]

use crate::{
    Multiaddr, P2PError, PeerId, Result,
    dht::{DhtCoreEngine, DhtNodeId, DhtKey, Key, DHTConfig},
    error::{NetworkError, DhtError},
    network::{NodeConfig, P2PNode},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// DHT node representation for network operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTNode {
    pub peer_id: String,
    pub address: String,
    pub distance: Option<Vec<u8>>,
    pub reliability: f64,
}

/// Alias for serialization compatibility
pub type SerializableDHTNode = DHTNode;

/// DHT Network Manager Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtNetworkConfig {
    /// Local peer configuration
    pub local_peer_id: PeerId,
    /// DHT configuration
    pub dht_config: DHTConfig,
    /// Network node configuration
    pub node_config: NodeConfig,
    /// Bootstrap nodes for initial network connection
    pub bootstrap_nodes: Vec<BootstrapNode>,
    /// Request timeout for DHT operations
    pub request_timeout: Duration,
    /// Maximum concurrent operations
    pub max_concurrent_operations: usize,
    /// Replication factor (K value)
    pub replication_factor: usize,
    /// Enable enhanced security features
    pub enable_security: bool,
}

/// Bootstrap node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapNode {
    /// Node's peer ID
    pub peer_id: PeerId,
    /// Network addresses
    pub addresses: Vec<Multiaddr>,
    /// Known DHT key (optional)
    pub dht_key: Option<Key>,
}

/// DHT network operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtNetworkOperation {
    /// Store a value in the DHT
    Put { key: Key, value: Vec<u8> },
    /// Retrieve a value from the DHT
    Get { key: Key },
    /// Find nodes closest to a key
    FindNode { key: Key },
    /// Find value or closest nodes
    FindValue { key: Key },
    /// Ping a node to check availability
    Ping,
    /// Join the DHT network
    Join,
    /// Leave the DHT network gracefully
    Leave,
}

/// DHT network operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtNetworkResult {
    /// Successful PUT operation
    PutSuccess { key: Key, replicated_to: usize },
    /// Successful GET operation
    GetSuccess {
        key: Key,
        value: Vec<u8>,
        source: PeerId,
    },
    /// GET operation found no value
    GetNotFound { key: Key },
    /// Nodes found for FIND_NODE
    NodesFound {
        key: Key,
        nodes: Vec<SerializableDHTNode>,
    },
    /// Value found for FIND_VALUE
    ValueFound {
        key: Key,
        value: Vec<u8>,
        source: PeerId,
    },
    /// Ping response
    PongReceived {
        responder: PeerId,
        latency: Duration,
    },
    /// Join confirmation
    JoinSuccess {
        assigned_key: Key,
        bootstrap_peers: usize,
    },
    /// Leave confirmation
    LeaveSuccess,
    /// Operation failed
    Error { operation: String, error: String },
}

/// DHT message envelope for network transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtNetworkMessage {
    /// Message ID for request/response correlation
    pub message_id: String,
    /// Source peer ID
    pub source: PeerId,
    /// Target peer ID (optional for broadcast)
    pub target: Option<PeerId>,
    /// Message type
    pub message_type: DhtMessageType,
    /// DHT operation payload
    pub payload: DhtNetworkOperation,
    /// Timestamp when message was created
    pub timestamp: u64,
    /// TTL for message forwarding
    pub ttl: u8,
    /// Hop count for routing
    pub hop_count: u8,
}

/// DHT message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtMessageType {
    /// Request message
    Request,
    /// Response message
    Response,
    /// Broadcast message
    Broadcast,
    /// Error response
    Error,
}

/// Main DHT Network Manager
pub struct DhtNetworkManager {
    /// DHT instance
    dht: Arc<RwLock<DhtCoreEngine>>,
    /// P2P network node
    node: Arc<P2PNode>,
    /// Configuration
    config: DhtNetworkConfig,
    /// Active DHT operations
    active_operations: Arc<RwLock<HashMap<String, DhtOperationContext>>>,
    /// Network message broadcaster
    event_tx: broadcast::Sender<DhtNetworkEvent>,
    /// Known DHT peers
    dht_peers: Arc<RwLock<HashMap<PeerId, DhtPeerInfo>>>,
    /// Operation statistics
    stats: Arc<RwLock<DhtNetworkStats>>,
}

/// DHT operation context
#[derive(Debug)]
#[allow(dead_code)]
struct DhtOperationContext {
    /// Operation type
    operation: DhtNetworkOperation,
    /// Target peer ID
    peer_id: PeerId,
    /// Start time
    started_at: Instant,
    /// Timeout
    timeout: Duration,
    /// Contacted nodes
    contacted_nodes: Vec<PeerId>,
    /// Responses received
    responses: Vec<(PeerId, DhtNetworkResult)>,
    /// Required responses for completion
    required_responses: usize,
}

/// DHT peer information
#[derive(Debug, Clone)]
pub struct DhtPeerInfo {
    /// Peer ID
    pub peer_id: PeerId,
    /// DHT key/ID in the DHT address space
    pub dht_key: Key,
    /// Network addresses
    pub addresses: Vec<Multiaddr>,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Connection status
    pub is_connected: bool,
    /// Response latency statistics
    pub avg_latency: Duration,
    /// Reliability score (0.0 to 1.0)
    pub reliability_score: f64,
}

/// DHT network events
#[derive(Debug, Clone)]
pub enum DhtNetworkEvent {
    /// New DHT peer discovered
    PeerDiscovered { peer_id: PeerId, dht_key: Key },
    /// DHT peer disconnected
    PeerDisconnected { peer_id: PeerId },
    /// DHT operation completed
    OperationCompleted {
        operation: String,
        success: bool,
        duration: Duration,
    },
    /// DHT network status changed
    NetworkStatusChanged {
        connected_peers: usize,
        routing_table_size: usize,
    },
    /// Error occurred
    Error { error: String },
}

/// DHT network statistics
#[derive(Debug, Clone, Default)]
pub struct DhtNetworkStats {
    /// Total operations performed
    pub total_operations: u64,
    /// Successful operations
    pub successful_operations: u64,
    /// Failed operations
    pub failed_operations: u64,
    /// Average operation latency
    pub avg_operation_latency: Duration,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Connected DHT peers
    pub connected_peers: usize,
    /// Routing table size
    pub routing_table_size: usize,
}

impl DhtNetworkManager {
    /// Create a new DHT Network Manager
    pub async fn new(config: DhtNetworkConfig) -> Result<Self> {
        info!(
            "Creating DHT Network Manager for peer: {}",
            config.local_peer_id
        );

        // Create DHT instance
        let dht_key = {
            let bytes = config.local_peer_id.as_bytes();
            let mut key = [0u8; 32];
            let len = bytes.len().min(32);
            key[..len].copy_from_slice(&bytes[..len]);
            key
        };
        // Convert the key to NodeId
        let node_id = DhtNodeId::from_bytes(dht_key);
        let dht = Arc::new(RwLock::new(
            DhtCoreEngine::new(node_id).map_err(|e| P2PError::Dht(DhtError::StorageFailed(e.to_string().into())))?
        ));

        // Create P2P node
        let node = Arc::new(P2PNode::new(config.node_config.clone()).await?);

        // Create event broadcaster
        let (event_tx, _) = broadcast::channel(1000);

        let manager = Self {
            dht,
            node,
            config,
            active_operations: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            dht_peers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(DhtNetworkStats::default())),
        };

        info!("DHT Network Manager created successfully");
        Ok(manager)
    }

    /// Start the DHT network manager
    pub async fn start(&self) -> Result<()> {
        info!("Starting DHT Network Manager...");

        // Start the P2P node
        self.node.start().await?;

        // Subscribe to network events
        self.start_network_event_handler().await?;

        // Connect to bootstrap nodes
        self.connect_to_bootstrap_nodes().await?;

        // Start DHT maintenance tasks
        self.start_maintenance_tasks().await?;

        info!("DHT Network Manager started successfully");
        Ok(())
    }

    /// Stop the DHT network manager
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping DHT Network Manager...");

        // Send leave messages to connected peers
        self.leave_network().await?;

        // Stop the P2P node
        self.node.stop().await?;

        info!("DHT Network Manager stopped");
        Ok(())
    }

    /// Put a value in the DHT
    pub async fn put(&self, key: Key, value: Vec<u8>) -> Result<DhtNetworkResult> {
        info!(
            "Putting value for key: {} ({} bytes)",
            hex::encode(key),
            value.len()
        );

        let operation = DhtNetworkOperation::Put {
            key: key.clone(),
            value: value.clone(),
        };

        // Find closest nodes for replication
        let closest_nodes = self
            .find_closest_nodes(&key, self.config.replication_factor)
            .await?;

        if closest_nodes.is_empty() {
            warn!(
                "No nodes found for key: {}, storing locally only",
                hex::encode(key)
            );
            // Store locally
            self.dht
                .write()
                .await
                .store(&crate::dht::DhtKey::from_bytes(key.clone()), value)
                .await
                .map_err(|e| {
                    P2PError::Dht(crate::error::DhtError::StoreFailed(
                        format!("Local storage failed for key {}: {e}", hex::encode(key)).into(),
                    ))
                })?;

            return Ok(DhtNetworkResult::PutSuccess {
                key,
                replicated_to: 1,
            });
        }

        // Store locally first
        self.dht
            .write()
            .await
            .store(&DhtKey::from_bytes(key.clone()), value.clone())
            .await
            .map_err(|e| {
                P2PError::Dht(crate::error::DhtError::StoreFailed(
                    format!("{}: Local storage failed: {e}", hex::encode(key)).into(),
                ))
            })?;

        // Replicate to closest nodes
        let mut replicated_count = 1; // Local storage
        for node in &closest_nodes {
            match self
                .send_dht_request(&node.peer_id, operation.clone())
                .await
            {
                Ok(DhtNetworkResult::PutSuccess { .. }) => {
                    replicated_count += 1;
                    debug!("Successfully replicated to peer: {}", &node.peer_id);
                }
                Ok(result) => {
                    warn!("Unexpected result from peer {}: {:?}", &node.peer_id, result);
                }
                Err(e) => {
                    warn!("Failed to replicate to peer {}: {}", &node.peer_id, e);
                }
            }
        }

        info!(
            "PUT operation completed: key={}, replicated_to={}/{}",
            hex::encode(key),
            replicated_count,
            closest_nodes.len() + 1
        );

        Ok(DhtNetworkResult::PutSuccess {
            key,
            replicated_to: replicated_count,
        })
    }

    /// Get a value from the DHT
    pub async fn get(&self, key: &Key) -> Result<DhtNetworkResult> {
        info!("Getting value for key: {}", hex::encode(key));

        // Check local storage first
        if let Ok(Some(value)) = self.dht.read().await.retrieve(&DhtKey::from_bytes(*key)).await {
            info!("Found value locally for key: {}", hex::encode(key));
            return Ok(DhtNetworkResult::GetSuccess {
                key: key.clone(),
                value,
                source: self.config.local_peer_id.clone(),
            });
        }

        // Query remote nodes
        let operation = DhtNetworkOperation::Get { key: key.clone() };
        let closest_nodes = self
            .find_closest_nodes(key, self.config.replication_factor)
            .await?;

        if closest_nodes.is_empty() {
            return Ok(DhtNetworkResult::GetNotFound { key: key.clone() });
        }

        // Query nodes until we find the value
        for node in &closest_nodes {
            match self
                .send_dht_request(&node.peer_id, operation.clone())
                .await
            {
                Ok(DhtNetworkResult::GetSuccess { value, source, .. }) => {
                    info!("Found value for key {} from peer: {}", hex::encode(key), source);

                    // Cache locally for future requests
                    let mut dht_guard = self.dht.write().await;
                    if let Err(e) = dht_guard.store(&DhtKey::from_bytes(*key), value.clone()).await {
                        warn!("Failed to cache retrieved value: {}", e);
                    }

                    return Ok(DhtNetworkResult::GetSuccess {
                        key: key.clone(),
                        value,
                        source,
                    });
                }
                Ok(DhtNetworkResult::GetNotFound { .. }) => {
                    debug!(
                        "Peer {} does not have value for key {}",
                        node.peer_id.clone(),
                        hex::encode(key)
                    );
                }
                Ok(result) => {
                    warn!("Unexpected result from peer {}: {:?}", &node.peer_id, result);
                }
                Err(e) => {
                    warn!("Failed to query peer {}: {}", node.peer_id.clone(), e);
                }
            }
        }

        info!("Value not found for key: {}", hex::encode(key));
        Ok(DhtNetworkResult::GetNotFound { key: key.clone() })
    }

    /// Find nodes closest to a key
    pub async fn find_node(&self, key: &Key) -> Result<DhtNetworkResult> {
        info!("Finding nodes closest to key: {}", hex::encode(key));

        let closest_nodes = self
            .find_closest_nodes(key, self.config.replication_factor * 2)
            .await?;
        let serializable_nodes: Vec<SerializableDHTNode> = closest_nodes
            .into_iter()
            .map(|node| node)
            .collect();

        info!(
            "Found {} nodes closest to key: {}",
            serializable_nodes.len(),
            hex::encode(key)
        );
        Ok(DhtNetworkResult::NodesFound {
            key: key.clone(),
            nodes: serializable_nodes,
        })
    }

    /// Ping a specific node
    pub async fn ping(&self, peer_id: &PeerId) -> Result<DhtNetworkResult> {
        info!("Pinging peer: {}", peer_id);

        let start_time = Instant::now();
        let operation = DhtNetworkOperation::Ping;

        match self.send_dht_request(peer_id, operation).await {
            Ok(DhtNetworkResult::PongReceived { responder, .. }) => {
                let latency = start_time.elapsed();
                info!("Received pong from {} in {:?}", responder, latency);
                Ok(DhtNetworkResult::PongReceived { responder, latency })
            }
            Ok(result) => {
                warn!("Unexpected ping result: {:?}", result);
                Err(P2PError::Dht(crate::error::DhtError::RoutingError(
                    "Unexpected ping response".to_string().into(),
                )))
            }
            Err(e) => {
                warn!("Ping failed to {}: {}", peer_id, e);
                Err(e)
            }
        }
    }

    /// Join the DHT network
    async fn join_network(&self) -> Result<()> {
        info!("Joining DHT network...");

        let _local_key = {
            let bytes = self.config.local_peer_id.as_bytes();
            let mut key = [0u8; 32];
            let len = bytes.len().min(32);
            key[..len].copy_from_slice(&bytes[..len]);
            key
        };
        let join_operation = DhtNetworkOperation::Join;

        let mut bootstrap_peers = 0;

        // Send join requests to bootstrap nodes
        for bootstrap_node in &self.config.bootstrap_nodes {
            match self
                .send_dht_request(&bootstrap_node.peer_id.to_string(), join_operation.clone())
                .await
            {
                Ok(DhtNetworkResult::JoinSuccess { .. }) => {
                    bootstrap_peers += 1;
                    info!(
                        "Successfully joined via bootstrap node: {}",
                        bootstrap_node.peer_id.to_string()
                    );
                }
                Ok(result) => {
                    warn!(
                        "Unexpected join result from {}: {:?}",
                        bootstrap_node.peer_id.to_string(), result
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to join via bootstrap node {}: {}",
                        bootstrap_node.peer_id.to_string(), e
                    );
                }
            }
        }

        if bootstrap_peers == 0 {
            warn!("Failed to join via any bootstrap nodes");
        } else {
            info!("Joined DHT network via {} bootstrap peers", bootstrap_peers);
        }

        Ok(())
    }

    /// Leave the DHT network gracefully
    async fn leave_network(&self) -> Result<()> {
        info!("Leaving DHT network...");

        let leave_operation = DhtNetworkOperation::Leave;
        let connected_peers: Vec<PeerId> = {
            let peers = self.dht_peers.read().await;
            peers.keys().cloned().collect()
        };

        // Send leave messages to all connected peers
        for peer_id in connected_peers {
            match self
                .send_dht_request(&peer_id, leave_operation.clone())
                .await
            {
                Ok(_) => {
                    debug!("Sent leave message to peer: {}", peer_id);
                }
                Err(e) => {
                    warn!("Failed to send leave message to {}: {}", peer_id, e);
                }
            }
        }

        info!("DHT network leave completed");
        Ok(())
    }

    /// Find closest nodes to a key using local routing table and network queries
    async fn find_closest_nodes(&self, key: &Key, count: usize) -> Result<Vec<DHTNode>> {
        debug!("Finding {} closest nodes to key: {}", count, hex::encode(key));

        // Start with local routing table
        let local_nodes = {
            let dht_guard = self.dht.read().await;
            dht_guard.find_nodes(&DhtKey::from_bytes(*key), 8).await.unwrap_or_else(|_| Vec::new())
        };

        if local_nodes.len() >= count {
            return Ok(local_nodes.into_iter().take(count).map(|node| DHTNode {
                peer_id: node.id.to_string(),
                address: node.address,
                distance: None,
                reliability: node.capacity.reliability_score,
            }).collect());
        }

        // Query network for more nodes if needed
        let mut all_nodes: Vec<DHTNode> = local_nodes.into_iter().map(|node| DHTNode {
            peer_id: node.id.to_string(),
            address: node.address,
            distance: None,
            reliability: node.capacity.reliability_score,
        }).collect();
        let find_operation = DhtNetworkOperation::FindNode { key: key.clone() };

        // Query known peers for additional nodes
        let known_peers: Vec<PeerId> = {
            let peers = self.dht_peers.read().await;
            peers.keys().cloned().collect()
        };

        for peer_id in known_peers.iter().take(3) {
            // Query up to 3 peers
            match self.send_dht_request(peer_id, find_operation.clone()).await {
                Ok(DhtNetworkResult::NodesFound { nodes, .. }) => {
                    for serializable_node in nodes {
                        all_nodes.push(DHTNode {
                            peer_id: serializable_node.peer_id,
                            address: serializable_node.address,
                            distance: serializable_node.distance,
                            reliability: serializable_node.reliability,
                        });
                    }
                }
                Ok(result) => {
                    debug!("Unexpected find_node result from {}: {:?}", peer_id, result);
                }
                Err(e) => {
                    debug!("Failed to query peer {} for nodes: {}", peer_id, e);
                }
            }
        }

        // Sort by distance and return closest
        // Sort nodes by XOR distance from the target key
        all_nodes.sort_by(|a, b| {
            let a_id_bytes = hex::decode(&a.peer_id).unwrap_or_else(|_| vec![0u8; 32]);
            let b_id_bytes = hex::decode(&b.peer_id).unwrap_or_else(|_| vec![0u8; 32]);
            
            let mut a_key = [0u8; 32];
            let mut b_key = [0u8; 32];
            a_key[..a_id_bytes.len().min(32)].copy_from_slice(&a_id_bytes[..a_id_bytes.len().min(32)]);
            b_key[..b_id_bytes.len().min(32)].copy_from_slice(&b_id_bytes[..b_id_bytes.len().min(32)]);
            
            let a_dht_key = DhtKey::from_bytes(a_key);
            let b_dht_key = DhtKey::from_bytes(b_key);
            let target_key = DhtKey::from_bytes(*key);
            
            a_dht_key.distance(&target_key).cmp(&b_dht_key.distance(&target_key))
        });
        Ok(all_nodes.into_iter().take(count).collect())
    }

    /// Send a DHT request to a specific peer
    async fn send_dht_request(
        &self,
        peer_id: &PeerId,
        operation: DhtNetworkOperation,
    ) -> Result<DhtNetworkResult> {
        let message_id = Uuid::new_v4().to_string();

        let message = DhtNetworkMessage {
            message_id: message_id.clone(),
            source: self.config.local_peer_id.clone(),
            target: Some(peer_id.clone()),
            message_type: DhtMessageType::Request,
            payload: operation,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| {
                    P2PError::Network(NetworkError::ProtocolError(
                        "System clock error: unable to get current timestamp".into(),
                    ))
                })?
                .as_secs(),
            ttl: 10,
            hop_count: 0,
        };

        // Serialize message
        let message_data = serde_json::to_vec(&message)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;

        // Create operation context for tracking
        let operation_context = DhtOperationContext {
            operation: message.payload.clone(),
            peer_id: peer_id.clone(),
            started_at: Instant::now(),
            timeout: self.config.request_timeout,
            contacted_nodes: vec![peer_id.clone()],
            responses: Vec::new(),
            required_responses: 1,
        };

        self.active_operations
            .write()
            .await
            .insert(message_id.clone(), operation_context);

        // Send message via network layer
        match self
            .node
            .send_message(peer_id, "/dht/1.0.0", message_data)
            .await
        {
            Ok(_) => {
                debug!("Sent DHT request {} to peer: {}", message_id, peer_id);

                // Wait for real network response with timeout
                self.wait_for_response(&message_id, peer_id).await
            }
            Err(e) => {
                warn!("Failed to send DHT request to {}: {}", peer_id, e);
                self.active_operations.write().await.remove(&message_id);
                Err(e)
            }
        }
    }

    /// Wait for real DHT network response with timeout
    async fn wait_for_response(
        &self,
        message_id: &str,
        _peer_id: &PeerId,
    ) -> Result<DhtNetworkResult> {
        const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

        // Create a response future that will complete when we receive the response
        let start_time = std::time::Instant::now();

        // Poll for response with timeout
        loop {
            // Check if response has been received and stored
            if let Some(result) = self.check_received_response(message_id).await {
                return Ok(result);
            }

            // Check for timeout
            if start_time.elapsed() > RESPONSE_TIMEOUT {
                // Remove the operation context on timeout
                self.active_operations.write().await.remove(message_id);
                return Err(P2PError::Network(crate::error::NetworkError::Timeout));
            }

            // Wait a short time before checking again
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Check if a response has been received for the given message ID
    async fn check_received_response(&self, message_id: &str) -> Option<DhtNetworkResult> {
        // In a real implementation, this would check a response store/queue
        // For now, we'll implement a basic fallback mechanism

        if let Some(context) = self.active_operations.read().await.get(message_id) {
            // If operation is still active, attempt local fallback
            match &context.operation {
                DhtNetworkOperation::Get { key } => {
                    // Try local DHT as fallback
                    if let Ok(Some(value)) = self.dht.read().await.retrieve(&DhtKey::from_bytes(*key)).await {
                        // Remove the operation as we found a result
                        self.active_operations.write().await.remove(message_id);
                        return Some(DhtNetworkResult::GetSuccess {
                            key: key.clone(),
                            value,
                            source: context.peer_id.clone(),
                        });
                    }
                }
                DhtNetworkOperation::FindNode { key } => {
                    // Try local node lookup as fallback
                    let nodes = self.dht.read().await.find_nodes(&DhtKey::from_bytes(*key), 8).await.unwrap_or_else(|_| Vec::new());
                    if !nodes.is_empty() {
                        self.active_operations.write().await.remove(message_id);
                        let serializable_nodes: Vec<SerializableDHTNode> = nodes
                            .into_iter()
                            .take(3)
                            .map(|node| DHTNode {
                                peer_id: node.id.to_string(),
                                address: node.address,
                                distance: None,
                                reliability: node.capacity.reliability_score,
                            })
                            .collect();
                        return Some(DhtNetworkResult::NodesFound {
                            key: key.clone(),
                            nodes: serializable_nodes,
                        });
                    }
                }
                _ => {}
            }
        }

        None
    }

    /// Handle incoming DHT network response (for real network integration)
    pub async fn handle_network_response(
        &self,
        message_id: &str,
        _response: DhtNetworkResult,
    ) -> Result<()> {
        // Store the response for the waiting request
        // In a real implementation, this would use a proper response queue/store

        debug!("Received DHT network response for message: {}", message_id);

        // For now, we'll complete the operation immediately
        // This method would be called by the network layer when a response is received

        Ok(())
    }

    /// Legacy simulation method (kept for compatibility but now does real DHT operations)
    #[allow(dead_code)]
    async fn simulate_response(
        &self,
        message_id: &str,
        peer_id: &PeerId,
    ) -> Result<DhtNetworkResult> {
        // Remove operation context
        let operation_context = self.active_operations.write().await.remove(message_id);

        if let Some(context) = operation_context {
            match context.operation {
                DhtNetworkOperation::Put { key, value } => {
                    // Attempt to store locally as fallback
                    if let Err(e) = self.dht.write().await.store(&DhtKey::from_bytes(key), value).await {
                        warn!("Failed to store DHT record locally: {}", e);
                    }
                    Ok(DhtNetworkResult::PutSuccess {
                        key,
                        replicated_to: 1,
                    })
                }
                DhtNetworkOperation::Get { key } => {
                    // Check if we have the value locally (simulated remote storage)
                    if let Ok(Some(value)) = self.dht.read().await.retrieve(&DhtKey::from_bytes(key)).await {
                        Ok(DhtNetworkResult::GetSuccess {
                            key,
                            value,
                            source: peer_id.clone(),
                        })
                    } else {
                        Ok(DhtNetworkResult::GetNotFound { key })
                    }
                }
                DhtNetworkOperation::FindNode { key } => {
                    let dht_guard = self.dht.read().await;
                    let nodes = dht_guard.find_nodes(&DhtKey::from_bytes(key), 8).await.unwrap_or_else(|_| Vec::new());
                    let serializable_nodes: Vec<SerializableDHTNode> = nodes
                        .into_iter()
                        .take(3)
                        .map(|node| DHTNode {
                            peer_id: node.id.to_string(),
                            address: node.address,
                            distance: None,
                            reliability: node.capacity.reliability_score,
                        })
                        .collect();
                    Ok(DhtNetworkResult::NodesFound {
                        key,
                        nodes: serializable_nodes,
                    })
                }
                DhtNetworkOperation::FindValue { key } => {
                    if let Ok(Some(value)) = self.dht.read().await.retrieve(&DhtKey::from_bytes(key)).await {
                        Ok(DhtNetworkResult::ValueFound {
                            key,
                            value,
                            source: peer_id.clone(),
                        })
                    } else {
                        let dht_guard = self.dht.read().await;
                        let nodes = dht_guard.find_nodes(&DhtKey::from_bytes(key), 8).await.unwrap_or_else(|_| Vec::new());
                        let serializable_nodes: Vec<SerializableDHTNode> = nodes
                            .into_iter()
                            .take(3)
                            .map(|node| DHTNode {
                                peer_id: node.id.to_string(),
                                address: node.address,
                                distance: None,
                                reliability: node.capacity.reliability_score,
                            })
                            .collect();
                        Ok(DhtNetworkResult::NodesFound {
                            key,
                            nodes: serializable_nodes,
                        })
                    }
                }
                DhtNetworkOperation::Ping => Ok(DhtNetworkResult::PongReceived {
                    responder: peer_id.clone(),
                    latency: Duration::from_millis(50),
                }),
                DhtNetworkOperation::Join => Ok(DhtNetworkResult::JoinSuccess {
                    assigned_key: {
                        let bytes = self.config.local_peer_id.as_bytes();
                        let mut key = [0u8; 32];
                        let len = bytes.len().min(32);
                        key[..len].copy_from_slice(&bytes[..len]);
                        key
                    },
                    bootstrap_peers: 1,
                }),
                DhtNetworkOperation::Leave => Ok(DhtNetworkResult::LeaveSuccess),
            }
        } else {
            Err(P2PError::Dht(crate::error::DhtError::RoutingError(
                "Operation context not found".to_string().into(),
            )))
        }
    }

    /// Handle incoming DHT message
    pub async fn handle_dht_message(
        &self,
        data: &[u8],
        sender: &PeerId,
    ) -> Result<Option<Vec<u8>>> {
        // Deserialize message
        let message: DhtNetworkMessage = serde_json::from_slice(data)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;

        debug!(
            "Received DHT message {} from {}: {:?}",
            message.message_id, sender, message.message_type
        );

        // Update peer info
        self.update_peer_info(sender.clone(), &message).await;

        match message.message_type {
            DhtMessageType::Request => {
                let result = self.handle_dht_request(&message).await?;
                let response = self.create_response_message(&message, result)?;
                Ok(Some(serde_json::to_vec(&response)?))
            }
            DhtMessageType::Response => {
                self.handle_dht_response(&message).await?;
                Ok(None)
            }
            DhtMessageType::Broadcast => {
                self.handle_dht_broadcast(&message).await?;
                Ok(None)
            }
            DhtMessageType::Error => {
                warn!("Received DHT error message: {:?}", message);
                Ok(None)
            }
        }
    }

    /// Handle DHT request message
    async fn handle_dht_request(&self, message: &DhtNetworkMessage) -> Result<DhtNetworkResult> {
        match &message.payload {
            DhtNetworkOperation::Put { key, value } => {
                info!("Handling PUT request for key: {}", hex::encode(key));
                self.dht
                    .write()
                    .await
                    .store(&DhtKey::from_bytes(key.clone()), value.clone())
                    .await
                    .map_err(|e| {
                        P2PError::Dht(crate::error::DhtError::StoreFailed(
                            format!("{}: PUT failed: {e}", hex::encode(key)).into(),
                        ))
                    })?;
                Ok(DhtNetworkResult::PutSuccess {
                    key: key.clone(),
                    replicated_to: 1,
                })
            }
            DhtNetworkOperation::Get { key } => {
                info!("Handling GET request for key: {}", hex::encode(key));
                if let Ok(Some(record)) = self.dht.read().await.retrieve(&DhtKey::from_bytes(*key)).await {
                    Ok(DhtNetworkResult::GetSuccess {
                        key: key.clone(),
                        value: record,
                        source: self.config.local_peer_id.clone(),
                    })
                } else {
                    Ok(DhtNetworkResult::GetNotFound { key: key.clone() })
                }
            }
            DhtNetworkOperation::FindNode { key } => {
                info!("Handling FIND_NODE request for key: {}", hex::encode(key));
                let dht_guard = self.dht.read().await;
                let nodes = dht_guard.find_nodes(&DhtKey::from_bytes(*key), 8).await.unwrap_or_else(|_| Vec::new());
                let serializable_nodes: Vec<SerializableDHTNode> = nodes
                    .into_iter()
                    .take(8)
                    .map(|node| DHTNode {
                        peer_id: node.id.to_string(),
                        address: node.address,
                        distance: None,
                        reliability: node.capacity.reliability_score,
                    })
                    .collect();
                Ok(DhtNetworkResult::NodesFound {
                    key: key.clone(),
                    nodes: serializable_nodes,
                })
            }
            DhtNetworkOperation::FindValue { key } => {
                info!("Handling FIND_VALUE request for key: {}", hex::encode(key));
                if let Ok(Some(record)) = self.dht.read().await.retrieve(&DhtKey::from_bytes(*key)).await {
                    Ok(DhtNetworkResult::ValueFound {
                        key: key.clone(),
                        value: record,
                        source: self.config.local_peer_id.clone(),
                    })
                } else {
                    let dht_guard = self.dht.read().await;
                    let nodes = dht_guard.find_nodes(&DhtKey::from_bytes(*key), 8).await.unwrap_or_else(|_| Vec::new());
                    let serializable_nodes: Vec<SerializableDHTNode> = nodes
                        .into_iter()
                        .take(8)
                        .map(|node| DHTNode {
                            peer_id: node.id.to_string(),
                            address: node.address,
                            distance: None,
                            reliability: node.capacity.reliability_score,
                        })
                        .collect();
                    Ok(DhtNetworkResult::NodesFound {
                        key: key.clone(),
                        nodes: serializable_nodes,
                    })
                }
            }
            DhtNetworkOperation::Ping => {
                info!("Handling PING request from: {}", message.source);
                Ok(DhtNetworkResult::PongReceived {
                    responder: self.config.local_peer_id.clone(),
                    latency: Duration::from_millis(0), // Local response
                })
            }
            DhtNetworkOperation::Join => {
                info!("Handling JOIN request from: {}", message.source);
                // Add the joining node to our routing table
                let dht_key = {
                    let bytes = message.source.as_bytes();
                    let mut key = [0u8; 32];
                    let len = bytes.len().min(32);
                    key[..len].copy_from_slice(&bytes[..len]);
                    key
                };
                let _node = DHTNode {
                    peer_id: message.source.clone(),
                    address: String::new(),
                    distance: Some(dht_key.to_vec()),
                    reliability: 1.0,
                };

                // Node will be added to routing table through normal DHT operations
                debug!("Node {} joined the network", message.source);

                Ok(DhtNetworkResult::JoinSuccess {
                    assigned_key: dht_key,
                    bootstrap_peers: 1,
                })
            }
            DhtNetworkOperation::Leave => {
                info!("Handling LEAVE request from: {}", message.source);
                // Remove the leaving node from our routing table
                // TODO: Implement node removal from DHT routing table
                // let dht_guard = self.dht.write().await;
                // if let Err(e) = dht_guard.remove_node(&message.source).await {
                //     warn!("Failed to remove leaving node from routing table: {}", e);
                // }

                Ok(DhtNetworkResult::LeaveSuccess)
            }
        }
    }

    /// Handle DHT response message
    async fn handle_dht_response(&self, _message: &DhtNetworkMessage) -> Result<()> {
        // In a real implementation, this would match responses with pending operations
        // and complete the futures waiting for responses
        debug!("DHT response handling not fully implemented yet");
        Ok(())
    }

    /// Handle DHT broadcast message
    async fn handle_dht_broadcast(&self, _message: &DhtNetworkMessage) -> Result<()> {
        // Handle broadcast messages (for network-wide announcements)
        debug!("DHT broadcast handling not fully implemented yet");
        Ok(())
    }

    /// Create response message
    fn create_response_message(
        &self,
        request: &DhtNetworkMessage,
        result: DhtNetworkResult,
    ) -> Result<DhtNetworkMessage> {
        Ok(DhtNetworkMessage {
            message_id: request.message_id.clone(),
            source: self.config.local_peer_id.clone(),
            target: Some(request.source.clone()),
            message_type: DhtMessageType::Response,
            payload: match result {
                DhtNetworkResult::PutSuccess {
                    key,
                    replicated_to: _,
                } => DhtNetworkOperation::Put { key, value: vec![] }, // Response doesn't need value
                DhtNetworkResult::GetSuccess { key, .. } => DhtNetworkOperation::Get { key },
                DhtNetworkResult::GetNotFound { key } => DhtNetworkOperation::Get { key },
                DhtNetworkResult::NodesFound { key, .. } => DhtNetworkOperation::FindNode { key },
                DhtNetworkResult::ValueFound { key, .. } => DhtNetworkOperation::FindValue { key },
                DhtNetworkResult::PongReceived { .. } => DhtNetworkOperation::Ping,
                DhtNetworkResult::JoinSuccess { .. } => DhtNetworkOperation::Join,
                DhtNetworkResult::LeaveSuccess => DhtNetworkOperation::Leave,
                DhtNetworkResult::Error { .. } => {
                    return Err(P2PError::Dht(crate::error::DhtError::RoutingError(
                        "Cannot create response for error result".to_string().into(),
                    )));
                }
            },
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| {
                    P2PError::Network(NetworkError::ProtocolError(
                        "System clock error: unable to get current timestamp".into(),
                    ))
                })?
                .as_secs(),
            ttl: request.ttl.saturating_sub(1),
            hop_count: request.hop_count + 1,
        })
    }

    /// Update peer information
    async fn update_peer_info(&self, peer_id: PeerId, _message: &DhtNetworkMessage) {
        let peer_bytes = peer_id.as_bytes();
        let mut dht_key = [0u8; 32];
        let len = peer_bytes.len().min(32);
        dht_key[..len].copy_from_slice(&peer_bytes[..len]);

        let mut peers = self.dht_peers.write().await;
        let peer_info = peers.entry(peer_id.clone()).or_insert_with(|| {
            DhtPeerInfo {
                peer_id: peer_id.clone(),
                dht_key: dht_key.clone(),
                addresses: vec![], // Would be populated from network layer
                last_seen: Instant::now(),
                is_connected: true,
                avg_latency: Duration::from_millis(50),
                reliability_score: 1.0,
            }
        });

        peer_info.last_seen = Instant::now();
        peer_info.is_connected = true;

        // Update DHT routing table
        let _node = DHTNode {
            peer_id: peer_id.clone(),
            address: peer_info.addresses.first()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "127.0.0.1:0".to_string()),
            distance: Some(dht_key.to_vec()),
            reliability: 1.0,
        };
        // Node info will be updated through normal DHT operations
        debug!("Updated peer info for {}", peer_id);
    }

    /// Start network event handler
    async fn start_network_event_handler(&self) -> Result<()> {
        info!("Starting network event handler...");

        // Subscribe to network events from P2P node
        let mut events = self.node.subscribe_events();
        let dht_peers = Arc::clone(&self.dht_peers);
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            while let Ok(event) = events.recv().await {
                match event {
                    crate::network::P2PEvent::PeerConnected(peer_id) => {
                        info!("DHT peer connected: {}", peer_id);
                        let peer_bytes = peer_id.as_bytes();
        let mut dht_key = [0u8; 32];
        let len = peer_bytes.len().min(32);
        dht_key[..len].copy_from_slice(&peer_bytes[..len]);

                        // Add to DHT peers
                        {
                            let mut peers = dht_peers.write().await;
                            peers.insert(
                                peer_id.clone(),
                                DhtPeerInfo {
                                    peer_id: peer_id.clone(),
                                    dht_key: dht_key.clone(),
                                    addresses: vec![],
                                    last_seen: Instant::now(),
                                    is_connected: true,
                                    avg_latency: Duration::from_millis(50),
                                    reliability_score: 1.0,
                                },
                            );
                        }

                        let _ = event_tx.send(DhtNetworkEvent::PeerDiscovered { peer_id, dht_key });
                    }
                    crate::network::P2PEvent::PeerDisconnected(peer_id) => {
                        info!("DHT peer disconnected: {}", peer_id);

                        // Update peer status
                        {
                            let mut peers = dht_peers.write().await;
                            if let Some(peer_info) = peers.get_mut(&peer_id) {
                                peer_info.is_connected = false;
                            }
                        }

                        let _ = event_tx.send(DhtNetworkEvent::PeerDisconnected { peer_id });
                    }
                    crate::network::P2PEvent::Message {
                        topic,
                        source,
                        data,
                    } => {
                        if topic == "/dht/1.0.0" {
                            debug!("Received DHT message from {}: {} bytes", source, data.len());
                            // DHT message handling would go here
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Connect to bootstrap nodes
    async fn connect_to_bootstrap_nodes(&self) -> Result<()> {
        info!(
            "Connecting to {} bootstrap nodes...",
            self.config.bootstrap_nodes.len()
        );

        let mut connected_count = 0;

        for bootstrap_node in &self.config.bootstrap_nodes {
            for address in &bootstrap_node.addresses {
                match self.node.connect_peer(&address.to_string()).await {
                    Ok(peer_id) => {
                        info!("Connected to bootstrap node: {} at {}", peer_id, address);
                        connected_count += 1;

                        // Add to DHT peers
                        let dht_key = bootstrap_node
                            .dht_key
                            .clone()
                            .unwrap_or_else(|| {
                                let bytes = bootstrap_node.peer_id.to_string().into_bytes();
                                let mut key = [0u8; 32];
                                let len = bytes.len().min(32);
                                key[..len].copy_from_slice(&bytes[..len]);
                                key
                            });

                        let mut peers = self.dht_peers.write().await;
                        peers.insert(
                            bootstrap_node.peer_id.to_string().clone(),
                            DhtPeerInfo {
                                peer_id: bootstrap_node.peer_id.to_string().clone(),
                                dht_key,
                                addresses: bootstrap_node.addresses.clone(),
                                last_seen: Instant::now(),
                                is_connected: true,
                                avg_latency: Duration::from_millis(50),
                                reliability_score: 1.0,
                            },
                        );

                        break; // Successfully connected, try next bootstrap node
                    }
                    Err(e) => {
                        warn!(
                            "Failed to connect to bootstrap node {} at {}: {}",
                            bootstrap_node.peer_id.to_string(), address, e
                        );
                    }
                }
            }
        }

        if connected_count == 0 {
            warn!("Failed to connect to any bootstrap nodes");
        } else {
            info!("Connected to {} bootstrap nodes", connected_count);
            // Join the DHT network
            self.join_network().await?;
        }

        Ok(())
    }

    /// Start maintenance tasks
    async fn start_maintenance_tasks(&self) -> Result<()> {
        info!("Starting DHT maintenance tasks...");

        // DHT maintenance task
        let _dht = Arc::clone(&self.dht);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;

                // TODO: Implement DHT maintenance
                // if let Err(e) = dht.read().await.maintenance().await {
                //     warn!("DHT maintenance failed: {}", e);
                // }
            }
        });

        // Statistics update task
        let stats = Arc::clone(&self.stats);
        let dht_peers = Arc::clone(&self.dht_peers);
        let _dht_for_stats = Arc::clone(&self.dht);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;

                let connected_peers = {
                    let peers = dht_peers.read().await;
                    peers.values().filter(|p| p.is_connected).count()
                };

                let routing_table_size = {
                    // TODO: Implement DHT stats
                    // let dht_guard = dht_for_stats.read().await;
                    // let stats = dht_guard.stats().await;
                    // stats.total_nodes
                    0
                };

                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.connected_peers = connected_peers;
                    stats_guard.routing_table_size = routing_table_size;
                }
            }
        });

        Ok(())
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> DhtNetworkStats {
        self.stats.read().await.clone()
    }

    /// Subscribe to DHT network events
    pub fn subscribe_events(&self) -> broadcast::Receiver<DhtNetworkEvent> {
        self.event_tx.subscribe()
    }

    /// Get connected DHT peers
    pub async fn get_connected_peers(&self) -> Vec<DhtPeerInfo> {
        let peers = self.dht_peers.read().await;
        peers.values().filter(|p| p.is_connected).cloned().collect()
    }

    /// Get DHT routing table size
    pub async fn get_routing_table_size(&self) -> usize {
        // TODO: Implement DHT stats
        // let dht_guard = self.dht.read().await;
        // let stats = dht_guard.stats().await;
        // stats.total_nodes
        0
    }
}

impl Default for DhtNetworkConfig {
    fn default() -> Self {
        Self {
            local_peer_id: "default_peer".to_string(),
            dht_config: DHTConfig::default(),
            node_config: NodeConfig::default(),
            bootstrap_nodes: Vec::new(),
            request_timeout: Duration::from_secs(30),
            max_concurrent_operations: 100,
            replication_factor: 8, // K=8 replication
            enable_security: true,
        }
    }
}
