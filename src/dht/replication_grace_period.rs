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

//! Replication Grace Period Configuration and Types
//!
//! This module provides configuration and types for implementing a grace period
//! before starting DHT replication when nodes fail, allowing time for endpoint
//! re-registration during upgrades or port changes.

use crate::peer_record::UserId as NodeId;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// Configuration for replication grace period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationGracePeriodConfig {
    /// Grace period duration before starting replication
    pub grace_period_duration: Duration,

    /// Whether to check for endpoint re-registration
    pub enable_endpoint_check: bool,

    /// Minimum grace period for critical content
    pub min_grace_period: Duration,

    /// Maximum grace period to prevent indefinite delays
    pub max_grace_period: Duration,
}

impl Default for ReplicationGracePeriodConfig {
    fn default() -> Self {
        Self {
            grace_period_duration: Duration::from_secs(300), // 5 minutes
            enable_endpoint_check: true,
            min_grace_period: Duration::from_secs(60), // 1 minute
            max_grace_period: Duration::from_secs(1800), // 30 minutes
        }
    }
}

impl ReplicationGracePeriodConfig {
    /// Validate configuration bounds
    pub fn validate(&self) -> Result<(), ReplicationError> {
        if self.grace_period_duration < self.min_grace_period {
            return Err(ReplicationError::InvalidConfiguration(format!(
                "Grace period {} is below minimum {}",
                self.grace_period_duration.as_secs(),
                self.min_grace_period.as_secs()
            )));
        }

        if self.grace_period_duration > self.max_grace_period {
            return Err(ReplicationError::InvalidConfiguration(format!(
                "Grace period {} exceeds maximum {}",
                self.grace_period_duration.as_secs(),
                self.max_grace_period.as_secs()
            )));
        }

        Ok(())
    }
}

/// Information about a failed node
#[derive(Debug, Clone)]
pub struct FailedNodeInfo {
    /// The node that failed
    pub node_id: NodeId,

    /// When the failure was detected
    pub failed_at: SystemTime,

    /// Last known endpoint before failure
    pub last_seen_endpoint: Option<String>,

    /// Reason for the failure
    pub failure_reason: NodeFailureReason,

    /// When the grace period expires
    pub grace_period_expires: SystemTime,
}

/// Reasons why a node might fail
#[derive(Debug, Clone, PartialEq)]
pub enum NodeFailureReason {
    /// Network timeout - node didn't respond
    NetworkTimeout,

    /// Connection lost - active connection dropped
    ConnectionLost,

    /// Explicit leave - node announced departure
    ExplicitLeave,

    /// Health check failed - node reported unhealthy
    HealthCheckFailed,
}

/// Errors that can occur in replication grace period operations
#[derive(Debug, thiserror::Error)]
pub enum ReplicationError {
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Node not found: {0}")]
    NodeNotFound(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Network error: {0}")]
    NetworkError(String),
}

/// Endpoint registration information
#[derive(Debug, Clone)]
pub struct EndpointRegistration {
    /// The endpoint address
    pub endpoint: String,

    /// When this endpoint was registered
    pub timestamp: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ReplicationGracePeriodConfig::default();
        assert_eq!(config.grace_period_duration, Duration::from_secs(300));
        assert!(config.enable_endpoint_check);
        assert_eq!(config.min_grace_period, Duration::from_secs(60));
        assert_eq!(config.max_grace_period, Duration::from_secs(1800));
    }

    #[test]
    fn test_config_validation() {
        let mut config = ReplicationGracePeriodConfig::default();

        // Valid config should pass
        assert!(config.validate().is_ok());

        // Too short grace period should fail
        config.grace_period_duration = Duration::from_secs(30);
        assert!(config.validate().is_err());

        // Too long grace period should fail
        config.grace_period_duration = Duration::from_secs(3600);
        assert!(config.validate().is_err());

        // Reset to valid
        config.grace_period_duration = Duration::from_secs(300);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_failed_node_info_creation() {
        let node_id = NodeId::from_bytes([1u8; 32]);
        let now = SystemTime::now();
        let grace_expires = now + Duration::from_secs(300);

        let info = FailedNodeInfo {
            node_id: node_id.clone(),
            failed_at: now,
            last_seen_endpoint: Some("127.0.0.1:8080".to_string()),
            failure_reason: NodeFailureReason::NetworkTimeout,
            grace_period_expires: grace_expires,
        };

        assert_eq!(info.node_id, node_id);
        assert_eq!(info.failure_reason, NodeFailureReason::NetworkTimeout);
        assert_eq!(info.last_seen_endpoint, Some("127.0.0.1:8080".to_string()));
    }
}
