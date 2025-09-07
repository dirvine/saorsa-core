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

//! Node Failure Tracker for DHT Replication Grace Period
//!
//! This module provides the NodeFailureTracker trait and its default implementation
//! for tracking node failures and managing grace periods before replication.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Duration, SystemTime};

use crate::dht::replication_grace_period::*;
use crate::peer_record::UserId as NodeId;

/// Trait for tracking node failures with grace period logic
#[async_trait]
pub trait NodeFailureTracker: Send + Sync {
    /// Record a node failure with grace period
    async fn record_node_failure(
        &self,
        node_id: NodeId,
        reason: NodeFailureReason,
        config: &ReplicationGracePeriodConfig,
    ) -> Result<(), ReplicationError>;

    /// Check if replication should start for a failed node
    async fn should_start_replication(&self, node_id: &NodeId) -> bool;

    /// Check if node has re-registered endpoint during grace period
    async fn check_endpoint_reregistration(&self, node_id: &NodeId) -> bool;

    /// Clean up expired failure records
    async fn cleanup_expired_failures(&self) -> usize;

    /// Get failure info for a node (for testing/debugging)
    async fn get_failure_info(&self, node_id: &NodeId) -> Option<FailedNodeInfo>;

    /// Get all current failed nodes
    async fn get_all_failed_nodes(&self) -> Vec<FailedNodeInfo>;
}

/// DHT client interface for endpoint operations
#[async_trait]
pub trait DhtClient: Send + Sync {
    /// Get the last known endpoint for a node
    async fn get_last_endpoint(&self, node_id: &NodeId) -> Result<Option<String>, ReplicationError>;

    /// Get endpoint registration info for a node
    async fn get_endpoint_registration(&self, node_id: &NodeId) -> Result<Option<EndpointRegistration>, ReplicationError>;
}

/// Production implementation of NodeFailureTracker
#[derive(Clone)]
pub struct DefaultNodeFailureTracker {
    /// Storage for failed node information
    failed_nodes: Arc<RwLock<HashMap<NodeId, FailedNodeInfo>>>,

    /// DHT client for endpoint operations
    dht_client: Arc<dyn DhtClient>,
}

impl DefaultNodeFailureTracker {
    /// Create a new failure tracker
    pub fn new(dht_client: Arc<dyn DhtClient>) -> Self {
        Self {
            failed_nodes: Arc::new(RwLock::new(HashMap::new())),
            dht_client,
        }
    }

    /// Create a new failure tracker with custom storage (for testing)
    pub fn with_storage(
        failed_nodes: Arc<RwLock<HashMap<NodeId, FailedNodeInfo>>>,
        dht_client: Arc<dyn DhtClient>,
    ) -> Self {
        Self {
            failed_nodes,
            dht_client,
        }
    }
}

#[async_trait]
impl NodeFailureTracker for DefaultNodeFailureTracker {
    async fn record_node_failure(
        &self,
        node_id: NodeId,
        reason: NodeFailureReason,
        config: &ReplicationGracePeriodConfig,
    ) -> Result<(), ReplicationError> {
        // Validate configuration first
        config.validate()?;

        let now = SystemTime::now();
        let grace_period_expires = now + config.grace_period_duration;

        // Try to get last known endpoint
        let last_seen_endpoint = self.dht_client.get_last_endpoint(&node_id).await
            .unwrap_or(None);

        let failure_info = FailedNodeInfo {
            node_id: node_id.clone(),
            failed_at: now,
            last_seen_endpoint,
            failure_reason: reason,
            grace_period_expires,
        };

        let mut failures = self.failed_nodes.write().await;
        failures.insert(node_id, failure_info);

        Ok(())
    }

    async fn should_start_replication(&self, node_id: &NodeId) -> bool {
        if let Some(failure_info) = self.failed_nodes.read().await.get(node_id) {
            let now = SystemTime::now();

            // Check if grace period has expired
            let grace_period_expired = now >= failure_info.grace_period_expires;

            // Check if node has re-registered endpoint during grace period
            let has_reregistered = if grace_period_expired {
                false // No need to check if grace period expired
            } else {
                self.check_endpoint_reregistration(node_id).await
            };

            grace_period_expired && !has_reregistered
        } else {
            // Node not in failed state, allow immediate replication
            true
        }
    }

    async fn check_endpoint_reregistration(&self, node_id: &NodeId) -> bool {
        if let Some(failure_info) = self.failed_nodes.read().await.get(node_id) {
            match self.dht_client.get_endpoint_registration(node_id).await {
                Ok(Some(registration)) => {
                    let now = SystemTime::now();
                    // Node re-registered within grace period
                    registration.timestamp > failure_info.failed_at
                        && registration.timestamp <= now
                        && now < failure_info.grace_period_expires
                }
                _ => false
            }
        } else {
            false
        }
    }

    async fn cleanup_expired_failures(&self) -> usize {
        let now = SystemTime::now();
        let mut failures = self.failed_nodes.write().await;
        let initial_count = failures.len();

        // Remove failures older than max retention period (1 hour)
        let max_retention = Duration::from_secs(3600);
        failures.retain(|_, info| {
            now.duration_since(info.failed_at)
                .unwrap_or(Duration::from_secs(0)) < max_retention
        });

        initial_count - failures.len()
    }

    async fn get_failure_info(&self, node_id: &NodeId) -> Option<FailedNodeInfo> {
        self.failed_nodes.read().await.get(node_id).cloned()
    }

    async fn get_all_failed_nodes(&self) -> Vec<FailedNodeInfo> {
        self.failed_nodes.read().await.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // Mock DHT client for testing
    struct MockDhtClient {
        endpoint_registrations: Arc<RwLock<HashMap<NodeId, EndpointRegistration>>>,
        last_endpoints: Arc<RwLock<HashMap<NodeId, String>>>,
    }

    impl MockDhtClient {
        fn new() -> Self {
            Self {
                endpoint_registrations: Arc::new(RwLock::new(HashMap::new())),
                last_endpoints: Arc::new(RwLock::new(HashMap::new())),
            }
        }

        async fn register_endpoint(&self, node_id: NodeId, endpoint: String, timestamp: SystemTime) {
            let registration = EndpointRegistration {
                endpoint,
                timestamp,
            };
            self.endpoint_registrations.write().await.insert(node_id, registration);
        }

        async fn set_last_endpoint(&self, node_id: NodeId, endpoint: String) {
            self.last_endpoints.write().await.insert(node_id, endpoint);
        }
    }

    #[async_trait]
    impl DhtClient for MockDhtClient {
        async fn get_last_endpoint(&self, node_id: &NodeId) -> Result<Option<String>, ReplicationError> {
            Ok(self.last_endpoints.read().await.get(node_id).cloned())
        }

        async fn get_endpoint_registration(&self, node_id: &NodeId) -> Result<Option<EndpointRegistration>, ReplicationError> {
            Ok(self.endpoint_registrations.read().await.get(node_id).cloned())
        }
    }

    fn create_test_node_id(id: u8) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[0] = id;
        NodeId::from_bytes(bytes)
    }

    #[tokio::test]
    async fn test_record_node_failure() {
        let mock_client = Arc::new(MockDhtClient::new());
        let tracker = DefaultNodeFailureTracker::new(mock_client);
        let config = ReplicationGracePeriodConfig::default();
        let node_id = create_test_node_id(1);

        // Record a failure
        let result = tracker.record_node_failure(
            node_id.clone(),
            NodeFailureReason::NetworkTimeout,
            &config
        ).await;

        assert!(result.is_ok());

        // Verify failure was recorded
        let failure_info = tracker.get_failure_info(&node_id).await;
        assert!(failure_info.is_some());
        let info = failure_info.unwrap();
        assert_eq!(info.node_id, node_id);
        assert_eq!(info.failure_reason, NodeFailureReason::NetworkTimeout);
    }

    #[tokio::test]
    async fn test_grace_period_prevents_immediate_replication() {
        let mock_client = Arc::new(MockDhtClient::new());
        let tracker = DefaultNodeFailureTracker::new(mock_client);
        let config = ReplicationGracePeriodConfig::default();
        let node_id = create_test_node_id(2);

        // Record failure
        tracker.record_node_failure(
            node_id.clone(),
            NodeFailureReason::NetworkTimeout,
            &config
        ).await.unwrap();

        // Immediately after failure, should NOT start replication
        assert!(!tracker.should_start_replication(&node_id).await);
    }

    #[tokio::test]
    async fn test_invalid_config_rejected() {
        let mock_client = Arc::new(MockDhtClient::new());
        let tracker = DefaultNodeFailureTracker::new(mock_client);
        let invalid_config = ReplicationGracePeriodConfig {
            grace_period_duration: Duration::from_secs(30), // Below minimum
            ..Default::default()
        };
        let node_id = create_test_node_id(3);

        // Should fail with invalid config
        let result = tracker.record_node_failure(
            node_id,
            NodeFailureReason::NetworkTimeout,
            &invalid_config
        ).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cleanup_expired_failures() {
        let mock_client = Arc::new(MockDhtClient::new());
        let storage = Arc::new(RwLock::new(HashMap::new()));
        let tracker = DefaultNodeFailureTracker::with_storage(storage.clone(), mock_client);
        let config = ReplicationGracePeriodConfig::default();

        // Add some failures
        for i in 0..3 {
            let node_id = create_test_node_id(i);
            tracker.record_node_failure(
                node_id,
                NodeFailureReason::NetworkTimeout,
                &config
            ).await.unwrap();
        }

        // Initially should have 3 failures
        assert_eq!(tracker.get_all_failed_nodes().await.len(), 3);

        // Cleanup should remove old failures (though in this test they won't be old enough)
        let cleaned = tracker.cleanup_expired_failures().await;
        assert_eq!(cleaned, 0); // None should be cleaned in this test
    }

    #[tokio::test]
    async fn test_get_all_failed_nodes() {
        let mock_client = Arc::new(MockDhtClient::new());
        let tracker = DefaultNodeFailureTracker::new(mock_client);
        let config = ReplicationGracePeriodConfig::default();

        // Add multiple failures
        let node_ids = vec![
            create_test_node_id(10),
            create_test_node_id(11),
            create_test_node_id(12),
        ];

        for node_id in &node_ids {
            tracker.record_node_failure(
                node_id.clone(),
                NodeFailureReason::NetworkTimeout,
                &config
            ).await.unwrap();
        }

        let failed_nodes = tracker.get_all_failed_nodes().await;
        assert_eq!(failed_nodes.len(), 3);

        // Verify all node IDs are present
        let returned_ids: Vec<_> = failed_nodes.iter().map(|info| info.node_id.clone()).collect();
        for node_id in &node_ids {
            assert!(returned_ids.contains(node_id));
        }
    }
}