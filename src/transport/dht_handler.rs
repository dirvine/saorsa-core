// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! DHT Protocol Handler for SharedTransport
//!
//! This module implements the `ProtocolHandler` trait from ant-quic
//! for routing DHT-related streams to the appropriate handlers.
//!
//! ## Stream Types Handled
//!
//! | Type | Byte | Purpose |
//! |------|------|---------|
//! | DhtQuery | 0x10 | GET, FIND_NODE, FIND_VALUE requests |
//! | DhtStore | 0x11 | PUT, STORE requests with data |
//! | DhtWitness | 0x12 | Witness requests for BFT |
//! | DhtReplication | 0x13 | Background replication traffic |

use ant_quic::link_transport::{LinkError, LinkResult, ProtocolHandler, StreamType};
use ant_quic::nat_traversal_api::PeerId;
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, error, trace, warn};

use crate::dht::core_engine::DhtCoreEngine;
use crate::dht::network_integration::{DhtMessage, DhtResponse, ErrorCode};
use crate::dht::witness::{OperationId, WitnessReceipt};

/// Event emitted when a DHT stream message is received.
/// This can be used by the unified listener to observe DHT traffic.
#[derive(Debug, Clone)]
pub struct DhtStreamEvent {
    /// The peer that sent the message.
    pub peer_id: PeerId,
    /// The stream type (Query, Store, Witness, Replication).
    pub stream_type: StreamType,
    /// The raw message data.
    pub data: Bytes,
}

/// DHT stream types handled by this handler.
const DHT_STREAM_TYPES: &[StreamType] = &[
    StreamType::DhtQuery,
    StreamType::DhtStore,
    StreamType::DhtWitness,
    StreamType::DhtReplication,
];

/// Default broadcast channel capacity for DHT events
const DEFAULT_DHT_EVENT_CAPACITY: usize = 10_000;

/// DHT protocol handler for SharedTransport.
///
/// Routes incoming DHT streams to the appropriate handlers based on stream type:
/// - DhtQuery: Handles GET, FIND_NODE, FIND_VALUE requests
/// - DhtStore: Handles PUT, STORE requests with data payloads
/// - DhtWitness: Handles witness requests for Byzantine fault tolerance
/// - DhtReplication: Handles background replication and repair traffic
///
/// All handlers automatically broadcast events to the global unified listener.
pub struct DhtStreamHandler {
    /// Reference to the DHT engine for processing requests.
    dht_engine: Arc<RwLock<DhtCoreEngine>>,
    /// Handler name for logging.
    name: String,
    /// Broadcast channel for observing incoming messages.
    /// Used by the unified listener to aggregate DHT traffic.
    event_tx: broadcast::Sender<DhtStreamEvent>,
}

impl DhtStreamHandler {
    /// Create a new DHT stream handler and register with the global listener.
    ///
    /// # Arguments
    ///
    /// * `dht_engine` - The DHT engine to process requests
    pub fn new(dht_engine: Arc<RwLock<DhtCoreEngine>>) -> Self {
        Self::with_capacity(dht_engine, DEFAULT_DHT_EVENT_CAPACITY)
    }

    /// Create a new DHT stream handler with a custom name.
    pub fn with_name(dht_engine: Arc<RwLock<DhtCoreEngine>>, name: impl Into<String>) -> Self {
        let (event_tx, _) = broadcast::channel(DEFAULT_DHT_EVENT_CAPACITY);
        let handler = Self {
            dht_engine,
            name: name.into(),
            event_tx,
        };
        // Auto-register with global listener
        handler.register_global();
        handler
    }

    /// Create a new DHT stream handler with specified event channel capacity.
    pub fn with_capacity(dht_engine: Arc<RwLock<DhtCoreEngine>>, capacity: usize) -> Self {
        let (event_tx, _) = broadcast::channel(capacity);
        let handler = Self {
            dht_engine,
            name: "DhtStreamHandler".to_string(),
            event_tx,
        };
        // Auto-register with global listener
        handler.register_global();
        handler
    }

    /// Create a new DHT stream handler with event broadcasting enabled.
    ///
    /// Events will be broadcast to all subscribers, allowing external
    /// systems (like the unified listener) to observe DHT traffic.
    ///
    /// Deprecated: Use `new()` instead - all handlers now broadcast events.
    #[deprecated(since = "0.11.0", note = "Use new() instead - all handlers now broadcast events")]
    pub fn with_event_broadcast(
        dht_engine: Arc<RwLock<DhtCoreEngine>>,
        capacity: usize,
    ) -> (Self, broadcast::Receiver<DhtStreamEvent>) {
        let handler = Self::with_capacity(dht_engine, capacity);
        let rx = handler.subscribe();
        (handler, rx)
    }

    /// Register this handler with the global unified listener.
    fn register_global(&self) {
        let rx = self.subscribe();
        crate::listener::global_listener().connect_dht_receiver(rx);
    }

    /// Subscribe to DHT stream events.
    pub fn subscribe(&self) -> broadcast::Receiver<DhtStreamEvent> {
        self.event_tx.subscribe()
    }

    /// Get the event sender for external use.
    ///
    /// This allows other components to subscribe without holding a reference
    /// to the handler itself.
    pub fn event_sender(&self) -> broadcast::Sender<DhtStreamEvent> {
        self.event_tx.clone()
    }

    /// Publish an event to subscribers.
    fn publish_event(&self, peer: PeerId, stream_type: StreamType, data: Bytes) {
        let event = DhtStreamEvent {
            peer_id: peer,
            stream_type,
            data,
        };
        // Ignore send errors (no subscribers)
        let _ = self.event_tx.send(event);
    }

    /// Handle a DHT query request.
    async fn handle_query(&self, peer: PeerId, data: Bytes) -> LinkResult<Option<Bytes>> {
        trace!(peer = ?peer, size = data.len(), "Processing DHT query");

        let message: DhtMessage = bincode::deserialize(&data)
            .map_err(|e| LinkError::Internal(format!("Failed to deserialize query: {e}")))?;

        let response = self.process_message(message).await?;

        let response_bytes = bincode::serialize(&response)
            .map_err(|e| LinkError::Internal(format!("Failed to serialize response: {e}")))?;

        Ok(Some(Bytes::from(response_bytes)))
    }

    /// Handle a DHT store request.
    async fn handle_store(&self, peer: PeerId, data: Bytes) -> LinkResult<Option<Bytes>> {
        trace!(peer = ?peer, size = data.len(), "Processing DHT store");

        let message: DhtMessage = bincode::deserialize(&data)
            .map_err(|e| LinkError::Internal(format!("Failed to deserialize store: {e}")))?;

        let response = self.process_message(message).await?;

        let response_bytes = bincode::serialize(&response)
            .map_err(|e| LinkError::Internal(format!("Failed to serialize response: {e}")))?;

        Ok(Some(Bytes::from(response_bytes)))
    }

    /// Handle a DHT witness request.
    async fn handle_witness(&self, peer: PeerId, data: Bytes) -> LinkResult<Option<Bytes>> {
        trace!(peer = ?peer, size = data.len(), "Processing DHT witness");

        let message: DhtMessage = bincode::deserialize(&data)
            .map_err(|e| LinkError::Internal(format!("Failed to deserialize witness: {e}")))?;

        let response = self.process_message(message).await?;

        let response_bytes = bincode::serialize(&response)
            .map_err(|e| LinkError::Internal(format!("Failed to serialize response: {e}")))?;

        Ok(Some(Bytes::from(response_bytes)))
    }

    /// Handle a DHT replication request.
    async fn handle_replication(&self, peer: PeerId, data: Bytes) -> LinkResult<Option<Bytes>> {
        trace!(peer = ?peer, size = data.len(), "Processing DHT replication");

        let message: DhtMessage = bincode::deserialize(&data)
            .map_err(|e| LinkError::Internal(format!("Failed to deserialize replication: {e}")))?;

        let response = self.process_message(message).await?;

        let response_bytes = bincode::serialize(&response)
            .map_err(|e| LinkError::Internal(format!("Failed to serialize response: {e}")))?;

        Ok(Some(Bytes::from(response_bytes)))
    }

    /// Process a DHT message and return the response.
    async fn process_message(&self, message: DhtMessage) -> LinkResult<DhtResponse> {
        match message {
            DhtMessage::Store { key, value, .. } => {
                let value_len = value.len();
                let mut engine = self.dht_engine.write().await;

                match engine.store(&key, value).await {
                    Ok(receipt) => {
                        debug!(key = ?key, "DHT store successful");
                        Ok(DhtResponse::StoreAck {
                            receipt: Box::new(WitnessReceipt {
                                operation_id: OperationId::new(),
                                operation_type: crate::dht::witness::OperationType::Store,
                                content_hash:
                                    crate::dht::content_addressing::ContentAddress::from_bytes(
                                        key.as_bytes(),
                                    ),
                                timestamp: chrono::Utc::now(),
                                participating_nodes: vec![crate::dht::witness::NodeId::new(
                                    "local",
                                )],
                                operation_metadata: crate::dht::witness::OperationMetadata {
                                    size_bytes: value_len,
                                    chunk_count: Some(1),
                                    redundancy_level: Some(1.0),
                                    custom: std::collections::HashMap::new(),
                                },
                                signature: crate::dht::witness::MlKemSignature::placeholder(),
                                witness_proofs: vec![],
                            }),
                            replicas: receipt.stored_at,
                        })
                    }
                    Err(e) => {
                        warn!(key = ?key, error = %e, "DHT store failed");
                        Ok(DhtResponse::Error {
                            code: ErrorCode::InternalError,
                            message: format!("Store failed: {e}"),
                            retry_after: None,
                        })
                    }
                }
            }

            DhtMessage::Retrieve { key, .. } => {
                let engine = self.dht_engine.read().await;

                match engine.retrieve(&key).await {
                    Ok(value) => {
                        debug!(key = ?key, found = value.is_some(), "DHT retrieve completed");
                        Ok(DhtResponse::RetrieveReply {
                            value,
                            witnesses: Vec::new(),
                        })
                    }
                    Err(e) => {
                        warn!(key = ?key, error = %e, "DHT retrieve failed");
                        Ok(DhtResponse::Error {
                            code: ErrorCode::InternalError,
                            message: format!("Retrieve failed: {e}"),
                            retry_after: None,
                        })
                    }
                }
            }

            DhtMessage::FindNode { target, count } => {
                let engine = self.dht_engine.read().await;

                match engine.find_nodes(&target, count).await {
                    Ok(nodes) => {
                        debug!(target = ?target, count = nodes.len(), "DHT find_node completed");
                        Ok(DhtResponse::FindNodeReply {
                            nodes,
                            distances: Vec::new(),
                        })
                    }
                    Err(e) => {
                        warn!(target = ?target, error = %e, "DHT find_node failed");
                        Ok(DhtResponse::Error {
                            code: ErrorCode::NodeNotFound,
                            message: format!("FindNode failed: {e}"),
                            retry_after: None,
                        })
                    }
                }
            }

            DhtMessage::FindValue { key } => {
                let engine = self.dht_engine.read().await;

                match engine.retrieve(&key).await {
                    Ok(value) => {
                        if value.is_some() {
                            Ok(DhtResponse::FindValueReply {
                                value,
                                nodes: Vec::new(),
                            })
                        } else {
                            let nodes = engine.find_nodes(&key, 8).await.unwrap_or_default();
                            Ok(DhtResponse::FindValueReply { value: None, nodes })
                        }
                    }
                    Err(e) => {
                        warn!(key = ?key, error = %e, "DHT find_value failed");
                        Ok(DhtResponse::Error {
                            code: ErrorCode::InternalError,
                            message: format!("FindValue failed: {e}"),
                            retry_after: None,
                        })
                    }
                }
            }

            DhtMessage::Ping {
                timestamp,
                sender_info,
            } => {
                debug!(from = ?sender_info.id, "DHT ping received");
                Ok(DhtResponse::Pong {
                    timestamp,
                    node_info: sender_info,
                })
            }

            DhtMessage::Join { node_info, .. } => {
                debug!(node = ?node_info.id, "DHT join request");
                Ok(DhtResponse::JoinAck {
                    routing_info: crate::dht::network_integration::RoutingInfo {
                        bootstrap_nodes: vec![],
                        network_size: 0,
                        protocol_version: 1,
                    },
                    neighbors: vec![],
                })
            }

            DhtMessage::Leave { node_id, .. } => {
                debug!(node = ?node_id, "DHT leave notification");
                Ok(DhtResponse::LeaveAck { confirmed: true })
            }

            DhtMessage::Replicate {
                key,
                value,
                version,
            } => {
                debug!(key = ?key, version = version, "DHT replication request");
                let mut engine = self.dht_engine.write().await;

                match engine.store(&key, value).await {
                    Ok(receipt) => Ok(DhtResponse::StoreAck {
                        receipt: Box::new(WitnessReceipt {
                            operation_id: OperationId::new(),
                            operation_type: crate::dht::witness::OperationType::Store,
                            content_hash:
                                crate::dht::content_addressing::ContentAddress::from_bytes(
                                    key.as_bytes(),
                                ),
                            timestamp: chrono::Utc::now(),
                            participating_nodes: vec![],
                            operation_metadata: crate::dht::witness::OperationMetadata {
                                size_bytes: 0,
                                chunk_count: None,
                                redundancy_level: None,
                                custom: std::collections::HashMap::new(),
                            },
                            signature: crate::dht::witness::MlKemSignature::placeholder(),
                            witness_proofs: vec![],
                        }),
                        replicas: receipt.stored_at,
                    }),
                    Err(e) => Ok(DhtResponse::Error {
                        code: ErrorCode::InternalError,
                        message: format!("Replication failed: {e}"),
                        retry_after: None,
                    }),
                }
            }

            DhtMessage::RepairRequest {
                key,
                missing_shards,
            } => {
                debug!(key = ?key, shards = ?missing_shards, "DHT repair request");
                Ok(DhtResponse::Error {
                    code: ErrorCode::InvalidMessage,
                    message: "Repair not yet implemented".to_string(),
                    retry_after: Some(std::time::Duration::from_secs(60)),
                })
            }
        }
    }
}

#[async_trait]
impl ProtocolHandler for DhtStreamHandler {
    fn stream_types(&self) -> &[StreamType] {
        DHT_STREAM_TYPES
    }

    async fn handle_stream(
        &self,
        peer: PeerId,
        stream_type: StreamType,
        data: Bytes,
    ) -> LinkResult<Option<Bytes>> {
        // Publish event to subscribers before processing
        self.publish_event(peer, stream_type, data.clone());

        match stream_type {
            StreamType::DhtQuery => self.handle_query(peer, data).await,
            StreamType::DhtStore => self.handle_store(peer, data).await,
            StreamType::DhtWitness => self.handle_witness(peer, data).await,
            StreamType::DhtReplication => self.handle_replication(peer, data).await,
            _ => {
                error!(
                    stream_type = %stream_type,
                    "Unexpected stream type routed to DHT handler"
                );
                Err(LinkError::InvalidStreamType(stream_type.as_byte()))
            }
        }
    }

    async fn handle_datagram(
        &self,
        peer: PeerId,
        stream_type: StreamType,
        data: Bytes,
    ) -> LinkResult<()> {
        trace!(
            peer = ?peer,
            stream_type = %stream_type,
            size = data.len(),
            "DHT datagram received (ignored)"
        );

        // Still publish event to subscribers even though we don't process datagrams
        self.publish_event(peer, stream_type, data);

        Ok(())
    }

    async fn shutdown(&self) -> LinkResult<()> {
        debug!(handler = %self.name, "DHT handler shutting down");
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Message wrapper for typed DHT stream transmission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedDhtMessage {
    /// The stream type to use for this message.
    pub stream_type: DhtStreamType,
    /// The underlying DHT message.
    pub message: DhtMessage,
}

/// DHT-specific stream type mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DhtStreamType {
    /// Query operations (GET, FIND_NODE, FIND_VALUE).
    Query,
    /// Store operations (PUT, STORE).
    Store,
    /// Witness operations for BFT.
    Witness,
    /// Background replication.
    Replication,
}

impl DhtStreamType {
    /// Convert to the ant-quic StreamType.
    pub fn to_stream_type(self) -> StreamType {
        match self {
            Self::Query => StreamType::DhtQuery,
            Self::Store => StreamType::DhtStore,
            Self::Witness => StreamType::DhtWitness,
            Self::Replication => StreamType::DhtReplication,
        }
    }

    /// Determine the appropriate stream type for a DHT message.
    pub fn for_message(message: &DhtMessage) -> Self {
        match message {
            DhtMessage::Retrieve { .. }
            | DhtMessage::FindNode { .. }
            | DhtMessage::FindValue { .. }
            | DhtMessage::Ping { .. } => Self::Query,

            DhtMessage::Store { .. } | DhtMessage::Join { .. } | DhtMessage::Leave { .. } => {
                Self::Store
            }

            DhtMessage::Replicate { .. } | DhtMessage::RepairRequest { .. } => Self::Replication,
        }
    }
}

impl From<DhtStreamType> for StreamType {
    fn from(dht_type: DhtStreamType) -> Self {
        dht_type.to_stream_type()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dht_stream_types() {
        assert_eq!(DHT_STREAM_TYPES.len(), 4);
        assert!(DHT_STREAM_TYPES.contains(&StreamType::DhtQuery));
        assert!(DHT_STREAM_TYPES.contains(&StreamType::DhtStore));
        assert!(DHT_STREAM_TYPES.contains(&StreamType::DhtWitness));
        assert!(DHT_STREAM_TYPES.contains(&StreamType::DhtReplication));
    }

    #[test]
    fn test_dht_stream_type_conversion() {
        assert_eq!(DhtStreamType::Query.to_stream_type(), StreamType::DhtQuery);
        assert_eq!(DhtStreamType::Store.to_stream_type(), StreamType::DhtStore);
        assert_eq!(
            DhtStreamType::Witness.to_stream_type(),
            StreamType::DhtWitness
        );
        assert_eq!(
            DhtStreamType::Replication.to_stream_type(),
            StreamType::DhtReplication
        );
    }
}
