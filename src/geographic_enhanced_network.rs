//! Geographic Enhanced Network Module
//!
//! Enhances the core network functionality with geographic-aware routing capabilities.
//! Provides a drop-in enhancement for existing P2P network nodes that adds geographic optimization.

use crate::Multiaddr;
use crate::dht::{
    geographic_network_integration::{
        DhtOperationType, GeographicNetworkIntegration, GeographicRoutingStats,
    },
    geographic_routing::GeographicRegion,
};
use crate::error::P2pResult as Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// Geographic configuration for enhanced network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicNetworkConfig {
    /// Local geographic region
    pub local_region: GeographicRegion,

    /// Enable geographic routing optimization
    pub enable_geographic_routing: bool,

    /// Latency weight in peer selection (0.0 - 1.0)
    pub latency_weight: f64,

    /// Reliability weight in peer selection (0.0 - 1.0)
    pub reliability_weight: f64,

    /// Region preference weight (0.0 - 1.0)
    pub region_preference_weight: f64,

    /// Maximum ratio of cross-region connections (0.0 - 1.0)
    pub max_cross_region_ratio: f64,

    /// Maintenance interval for geographic routing
    pub maintenance_interval: Duration,
}

impl Default for GeographicNetworkConfig {
    fn default() -> Self {
        Self {
            local_region: GeographicRegion::Unknown,
            enable_geographic_routing: true,
            latency_weight: 0.4,
            reliability_weight: 0.3,
            region_preference_weight: 0.3,
            max_cross_region_ratio: 0.3,
            maintenance_interval: Duration::from_secs(300), // 5 minutes
        }
    }
}

impl GeographicNetworkConfig {
    /// Create configuration with auto-detected region
    pub fn with_auto_detection() -> Self {
        Self {
            local_region: Self::auto_detect_region(),
            ..Default::default()
        }
    }

    /// Auto-detect geographic region (simplified heuristic)
    fn auto_detect_region() -> GeographicRegion {
        // This is a simplified detection - in production you'd use proper geolocation
        // For now, default to Unknown to require explicit configuration
        GeographicRegion::Unknown
    }

    /// Create config for specific region
    pub fn for_region(region: GeographicRegion) -> Self {
        Self {
            local_region: region,
            ..Default::default()
        }
    }

    /// Disable geographic routing (fallback to standard routing)
    pub fn disabled() -> Self {
        Self {
            enable_geographic_routing: false,
            ..Default::default()
        }
    }
}

/// Enhanced network statistics including geographic information
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GeographicNetworkStats {
    /// Base network statistics
    pub connections: usize,
    pub successful_connections: u64,
    pub failed_connections: u64,

    /// Geographic routing statistics
    pub routing_stats: Option<GeographicRoutingStats>,

    /// Cross-region routing statistics
    pub cross_region_queries: u64,
    pub same_region_queries: u64,

    /// Performance metrics
    pub avg_query_latency_ms: Option<f64>,
    pub regional_latencies: HashMap<String, f64>,

    /// Maintenance statistics
    pub last_maintenance: Option<SystemTime>,
    pub maintenance_count: u64,
}

/// Service for integrating geographic routing with existing network infrastructure
pub struct GeographicNetworkService {
    /// Geographic integration layer
    geographic_integration: Arc<GeographicNetworkIntegration>,

    /// Configuration
    config: GeographicNetworkConfig,

    /// Statistics
    stats: Arc<RwLock<GeographicNetworkStats>>,

    /// Maintenance task handle
    maintenance_handle: Option<tokio::task::JoinHandle<()>>,
}

impl GeographicNetworkService {
    /// Create new geographic network service
    pub async fn new(config: GeographicNetworkConfig) -> Result<Self> {
        let geographic_integration =
            Arc::new(GeographicNetworkIntegration::new(config.local_region)?);

        info!(
            "Creating geographic network service for region {:?}",
            config.local_region
        );

        Ok(Self {
            geographic_integration,
            config,
            stats: Arc::new(RwLock::new(GeographicNetworkStats::default())),
            maintenance_handle: None,
        })
    }

    /// Start the geographic network service
    pub async fn start(&mut self) -> Result<()> {
        if !self.config.enable_geographic_routing {
            info!("Geographic routing disabled");
            return Ok(());
        }

        info!(
            "Starting geographic network service for region {:?}",
            self.config.local_region
        );

        // Start maintenance task
        self.start_maintenance_task().await?;

        Ok(())
    }

    /// Add a peer to geographic routing
    pub async fn add_peer(&self, peer_id: String, address: Multiaddr) -> Result<()> {
        if !self.config.enable_geographic_routing {
            return Ok(()); // No-op if disabled
        }

        self.geographic_integration
            .add_peer(peer_id.clone(), address)
            .await?;

        // Update connection count
        {
            let mut stats = self.stats.write().await;
            stats.connections += 1;
        }

        debug!("Added peer {} to geographic routing", peer_id);
        Ok(())
    }

    /// Select optimal peers for DHT operation
    pub async fn select_peers_for_operation(
        &self,
        target_key: &[u8],
        operation_type: DhtOperationType,
        count: usize,
    ) -> Result<Vec<String>> {
        if !self.config.enable_geographic_routing {
            return Ok(vec![]); // Return empty if disabled
        }

        let peers = self
            .geographic_integration
            .select_peers_for_operation(target_key, operation_type, count)
            .await?;

        // Update query statistics
        {
            let mut stats = self.stats.write().await;
            let is_cross_region = peers.iter().any(|p| p.region != self.config.local_region);
            if is_cross_region {
                stats.cross_region_queries += 1;
            } else {
                stats.same_region_queries += 1;
            }
        }

        debug!(
            "Selected {} peers for {:?} operation using geographic routing",
            peers.len(),
            operation_type
        );

        Ok(peers.into_iter().map(|p| p.peer_id).collect())
    }

    /// Update peer quality metrics
    pub async fn update_peer_quality(
        &self,
        peer_id: &str,
        success: bool,
        latency: Option<Duration>,
    ) -> Result<()> {
        if !self.config.enable_geographic_routing {
            return Ok(()); // No-op if disabled
        }

        self.geographic_integration
            .update_peer_quality(peer_id, success, latency)
            .await?;

        // Update local statistics
        {
            let mut stats = self.stats.write().await;
            if success {
                stats.successful_connections += 1;
            } else {
                stats.failed_connections += 1;
            }

            if let Some(latency) = latency {
                let latency_ms = latency.as_millis() as f64;
                stats.avg_query_latency_ms = match stats.avg_query_latency_ms {
                    Some(current) => Some((current + latency_ms) / 2.0),
                    None => Some(latency_ms),
                };
            }
        }

        debug!(
            "Updated quality for peer {}: success={}, latency={:?}",
            peer_id, success, latency
        );
        Ok(())
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> Result<GeographicNetworkStats> {
        let mut stats = {
            let stats_guard = self.stats.read().await;
            (*stats_guard).clone()
        };

        if self.config.enable_geographic_routing {
            stats.routing_stats = Some(self.geographic_integration.get_routing_stats().await?);
        }

        Ok(stats)
    }

    /// Get peers in specific region
    pub async fn get_peers_by_region(&self, region: GeographicRegion) -> Result<Vec<String>> {
        if !self.config.enable_geographic_routing {
            return Ok(vec![]);
        }

        let peers = self
            .geographic_integration
            .get_peers_by_region(region)
            .await?;
        Ok(peers.into_iter().map(|p| p.0).collect())
    }

    /// Shutdown the service
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down geographic network service");

        if let Some(handle) = self.maintenance_handle.take() {
            handle.abort();
        }

        info!("Geographic network service shutdown complete");
        Ok(())
    }

    /// Start background maintenance task
    async fn start_maintenance_task(&mut self) -> Result<()> {
        let integration = Arc::clone(&self.geographic_integration);
        let stats = Arc::clone(&self.stats);
        let interval = self.config.maintenance_interval;

        let handle = tokio::spawn(async move {
            let mut maintenance_interval = tokio::time::interval(interval);

            loop {
                maintenance_interval.tick().await;

                debug!("Running geographic routing maintenance");

                match integration.perform_maintenance().await {
                    Ok(()) => {
                        let mut stats_guard = stats.write().await;
                        stats_guard.last_maintenance = Some(SystemTime::now());
                        stats_guard.maintenance_count += 1;
                        debug!("Geographic routing maintenance completed");
                    }
                    Err(e) => {
                        error!("Geographic routing maintenance failed: {}", e);
                    }
                }
            }
        });

        self.maintenance_handle = Some(handle);
        info!("Started geographic routing maintenance task");
        Ok(())
    }
}

/// Helper functions for integrating with existing applications
pub mod integration_helpers {
    use super::*;

    /// Create geographic service for DigitalOcean testing
    pub async fn create_digitalocean_service() -> Result<GeographicNetworkService> {
        let config = GeographicNetworkConfig::for_region(GeographicRegion::Europe);
        GeographicNetworkService::new(config).await
    }

    /// Create geographic service for local development
    pub async fn create_local_service() -> Result<GeographicNetworkService> {
        let config = GeographicNetworkConfig::for_region(GeographicRegion::NorthAmerica);
        GeographicNetworkService::new(config).await
    }

    /// Create disabled geographic service (fallback mode)
    pub async fn create_disabled_service() -> Result<GeographicNetworkService> {
        let config = GeographicNetworkConfig::disabled();
        GeographicNetworkService::new(config).await
    }

    /// Extract peer ID from address (helper function)
    pub fn extract_peer_id_from_address(address: &Multiaddr) -> String {
        format!("peer_from_{}", address.to_string().replace('/', "_"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_geographic_network_config_creation() {
        let config = GeographicNetworkConfig::for_region(GeographicRegion::NorthAmerica);
        assert_eq!(config.local_region, GeographicRegion::NorthAmerica);
        assert!(config.enable_geographic_routing);
    }

    #[tokio::test]
    async fn test_geographic_network_config_disabled() {
        let config = GeographicNetworkConfig::disabled();
        assert!(!config.enable_geographic_routing);
    }

    #[tokio::test]
    async fn test_geographic_service_creation() {
        let config = GeographicNetworkConfig::for_region(GeographicRegion::Europe);
        let service = GeographicNetworkService::new(config).await;
        assert!(service.is_ok());
    }

    #[tokio::test]
    async fn test_integration_helpers() {
        let do_service = integration_helpers::create_digitalocean_service().await;
        assert!(do_service.is_ok());

        let local_service = integration_helpers::create_local_service().await;
        assert!(local_service.is_ok());

        let disabled_service = integration_helpers::create_disabled_service().await;
        assert!(disabled_service.is_ok());
    }

    #[test]
    fn test_peer_id_extraction() {
        let addr: Multiaddr = "/ip4/159.89.81.21/tcp/9110".parse().unwrap();
        let peer_id = integration_helpers::extract_peer_id_from_address(&addr);
        assert_eq!(peer_id, "peer_from__ip4_159.89.81.21_tcp_9110");
    }
}
