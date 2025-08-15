//! Geographic Network Integration Layer
//!
//! Integrates geographic-aware DHT routing with the existing network infrastructure.
//! Provides region detection, latency-aware peer selection, and cross-region routing optimization.

use crate::dht::{
    geographic_routing::{GeographicRegion, PeerQualityMetrics},
    geographic_routing_table::{SafeGeographicRoutingTable, GeographicRoutingConfig, GeographicRoutingTable},
    latency_aware_selection::{LatencyAwarePeerSelection, LatencySelectionConfig, SelectedPeer},
};
use crate::error::{P2pResult as Result};
use crate::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Geographic network integration for DHT operations
pub struct GeographicNetworkIntegration {
    /// Core geographic routing table
    routing_table: SafeGeographicRoutingTable,
    /// Latency-aware peer selection
    peer_selector: Arc<RwLock<LatencyAwarePeerSelection>>,
    /// Region mapping cache for IP addresses
    region_cache: Arc<RwLock<HashMap<IpAddr, GeographicRegion>>>,
    /// Quality metrics tracking
    quality_tracker: Arc<RwLock<HashMap<String, PeerQualityMetrics>>>,
    /// Local node region
    local_region: GeographicRegion,
}

impl GeographicNetworkIntegration {
    /// Create new geographic network integration
    pub fn new(local_region: GeographicRegion) -> Result<Self> {
        let config = GeographicRoutingConfig::default();
        let routing_table = Arc::new(RwLock::new(
            GeographicRoutingTable::new(local_region, config.clone())
        ));
        let selection_config = LatencySelectionConfig {
            max_peers_per_region: 20,
            min_reliability_threshold: 0.3,
            measurement_max_age: Duration::from_secs(300),
            region_preference_bonus: 0.2,
            default_selection_count: 8,
        };
        let peer_selector = Arc::new(RwLock::new(LatencyAwarePeerSelection::new(selection_config, local_region)));

        Ok(Self {
            routing_table,
            peer_selector,
            region_cache: Arc::new(RwLock::new(HashMap::new())),
            quality_tracker: Arc::new(RwLock::new(HashMap::new())),
            local_region,
        })
    }

    /// Detect geographic region for a multiaddr
    pub async fn detect_region(&self, address: &Multiaddr) -> GeographicRegion {
        // Extract IP address from multiaddr
        let ip = match self.extract_ip_from_multiaddr(address) {
            Some(ip) => ip,
            None => {
                warn!("Could not extract IP from multiaddr: {}", address);
                return GeographicRegion::Unknown;
            }
        };

        // Check cache first
        {
            let cache = self.region_cache.read().await;
            if let Some(region) = cache.get(&ip) {
                return *region;
            }
        }

        // Determine region based on IP
        let region = self.determine_region_from_ip(&ip).await;

        // Cache the result
        {
            let mut cache = self.region_cache.write().await;
            cache.insert(ip, region);
        }

        region
    }

    /// Extract IP address from multiaddr (NetworkAddress)
    fn extract_ip_from_multiaddr(&self, address: &Multiaddr) -> Option<IpAddr> {
        // NetworkAddress directly contains the IP address
        Some(address.ip())
    }

    /// Determine geographic region from IP address
    async fn determine_region_from_ip(&self, ip: &IpAddr) -> GeographicRegion {
        match ip {
            IpAddr::V4(ipv4) => self.classify_ipv4_region(ipv4),
            IpAddr::V6(ipv6) => self.classify_ipv6_region(ipv6),
        }
    }

    /// Classify IPv4 address to geographic region
    fn classify_ipv4_region(&self, ip: &Ipv4Addr) -> GeographicRegion {
        let octets = ip.octets();
        
        // Handle special known ranges
        match (octets[0], octets[1], octets[2], octets[3]) {
            // DigitalOcean infrastructure (159.89.81.21 - Europe region)
            (159, 89, 81, 21) => GeographicRegion::Europe,
            
            // Local/private addresses
            (127, _, _, _) => self.local_region, // Localhost uses local region
            (192, 168, _, _) | (10, _, _, _) => self.local_region, // Private ranges
            (172, 16..=31, _, _) => self.local_region, // Private range
            
            // Geographic IP classification (simplified heuristics)
            // Asia-Pacific: specific ranges first
            (1, _, _, _) | (14, _, _, _) | (27, _, _, _) => GeographicRegion::AsiaPacific,
            
            // North America: 3.x.x.x, 4.x.x.x, etc. (major US providers)
            (3..=63, _, _, _) => GeographicRegion::NorthAmerica,
            
            // Europe: 80.x.x.x - 95.x.x.x (European allocation ranges)
            (80..=95, _, _, _) => GeographicRegion::Europe,
            
            // More specific DigitalOcean ranges in Europe
            (159, _, _, _) => GeographicRegion::Europe,
            
            // Default classification
            _ => GeographicRegion::Unknown,
        }
    }

    /// Classify IPv6 address to geographic region  
    fn classify_ipv6_region(&self, ip: &Ipv6Addr) -> GeographicRegion {
        let segments = ip.segments();
        
        // Handle special cases
        if ip.is_loopback() || ip.is_unspecified() {
            return self.local_region;
        }

        // Geographic IPv6 classification (simplified)
        match segments[0] {
            // North America: 2001:4xx, 2600-26ff
            0x2001 if segments[1] >= 0x0400 && segments[1] <= 0x04ff => GeographicRegion::NorthAmerica,
            0x2600..=0x26ff => GeographicRegion::NorthAmerica,
            
            // Europe: 2001:6xx, 2a00-2aff  
            0x2001 if segments[1] >= 0x0600 && segments[1] <= 0x06ff => GeographicRegion::Europe,
            0x2a00..=0x2aff => GeographicRegion::Europe,
            
            // Asia-Pacific: 2001:2xx, 2400-24ff
            0x2001 if segments[1] >= 0x0200 && segments[1] <= 0x02ff => GeographicRegion::AsiaPacific,
            0x2400..=0x24ff => GeographicRegion::AsiaPacific,
            
            _ => GeographicRegion::Unknown,
        }
    }

    /// Add peer with geographic awareness
    pub async fn add_peer(&self, peer_id: String, address: Multiaddr) -> Result<()> {
        let region = self.detect_region(&address).await;
        
        debug!("Adding peer {} in region {:?}", peer_id, region);

        let quality_metrics = PeerQualityMetrics::new(region);

        // Add to routing table
        self.routing_table.write().await.add_peer(peer_id.clone(), region, quality_metrics.clone())?;

        // Initialize quality metrics in tracker
        {
            let mut tracker = self.quality_tracker.write().await;
            tracker.insert(peer_id.clone(), quality_metrics);
        }

        info!("Added peer {} in region {:?} to geographic routing", peer_id, region);
        Ok(())
    }

    /// Select best peers for DHT operation with geographic awareness
    pub async fn select_peers_for_operation(
        &self,
        _target_key: &[u8],
        operation_type: DhtOperationType,
        count: usize,
    ) -> Result<Vec<SelectedPeer>> {
        let mut selector = self.peer_selector.write().await;
        
        // Use latency-aware selection with local region as default target
        let selected = selector.select_peers(Some(self.local_region), Some(count))?;

        debug!(
            "Selected {} peers for {:?} operation with {} total peers requested",
            selected.len(),
            operation_type,
            count
        );

        Ok(selected)
    }

    /// Update peer quality metrics based on operation results
    pub async fn update_peer_quality(&self, peer_id: &str, success: bool, rtt: Option<Duration>) -> Result<()> {
        // Update local quality tracker
        {
            let mut tracker = self.quality_tracker.write().await;
            if let Some(metrics) = tracker.get_mut(peer_id) {
                // Record the request result
                metrics.record_request(success);

                // Update RTT if provided
                if let Some(rtt) = rtt {
                    metrics.record_rtt(rtt);
                }
            }
        }

        // Update peer selector metrics
        {
            let mut selector = self.peer_selector.write().await;
            if let Some(updated_metrics) = self.quality_tracker.read().await.get(peer_id) {
                selector.update_peer_metrics(peer_id.to_string(), updated_metrics.clone())?;
            }
        }

        Ok(())
    }

    /// Get peers by region
    pub async fn get_peers_by_region(&self, region: GeographicRegion) -> Result<Vec<(PeerId, PeerQualityMetrics)>> {
        let routing_table = self.routing_table.read().await;
        Ok(routing_table.get_regional_peers(region))
    }

    /// Get routing statistics for monitoring
    pub async fn get_routing_stats(&self) -> Result<GeographicRoutingStats> {
        let routing_table = self.routing_table.read().await;
        let table_stats = routing_table.get_stats();
        let mut stats = GeographicRoutingStats::default();

        stats.total_peers = table_stats.total_peers;
        
        // Extract regional peer counts
        for (region, count) in table_stats.peers_by_region {
            match region {
                GeographicRegion::NorthAmerica => stats.north_america_peers = count,
                GeographicRegion::Europe => stats.europe_peers = count,
                GeographicRegion::AsiaPacific => stats.asia_pacific_peers = count,
                GeographicRegion::SouthAmerica => stats.south_america_peers = count,
                GeographicRegion::Africa => stats.africa_peers = count,
                GeographicRegion::Oceania => stats.oceania_peers = count,
                GeographicRegion::Unknown => stats.unknown_peers = count,
            }
        }

        // Count peers with RTT data from quality tracker
        {
            let tracker = self.quality_tracker.read().await;
            stats.peers_with_rtt = tracker.values()
                .filter(|metrics| metrics.average_rtt().is_some())
                .count();
        }

        Ok(stats)
    }

    /// Perform maintenance on geographic routing
    pub async fn perform_maintenance(&self) -> Result<()> {
        debug!("Performing geographic routing maintenance");
        
        // Perform routing table maintenance
        self.routing_table.write().await.maintenance()?;
        
        // Clear expired cache entries in peer selector
        {
            let mut selector = self.peer_selector.write().await;
            selector.maintenance()?;
        }

        // Clean up old quality metrics
        {
            let mut tracker = self.quality_tracker.write().await;
            
            // Clean up stale metrics (older than 24 hours)
            let _now = std::time::Instant::now();
            let stale_peers: Vec<String> = tracker.iter()
                .filter(|(_, metrics)| metrics.needs_refresh(Duration::from_secs(24 * 3600)))
                .map(|(peer_id, _)| peer_id.clone())
                .collect();
            
            for peer_id in stale_peers {
                tracker.remove(&peer_id);
            }
            
            // Ensure we don't grow unbounded
            if tracker.len() > 10000 {
                tracker.clear();
                debug!("Cleared quality metrics cache due to size limit");
            }
        }

        debug!("Geographic routing maintenance completed");
        Ok(())
    }
}

/// DHT operation types for peer selection optimization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DhtOperationType {
    Store,
    Retrieve,
    FindNode,
    FindValue,
    Ping,
}

/// Geographic routing statistics for monitoring
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GeographicRoutingStats {
    pub total_peers: usize,
    pub north_america_peers: usize,
    pub europe_peers: usize,
    pub asia_pacific_peers: usize,
    pub south_america_peers: usize,
    pub africa_peers: usize,
    pub oceania_peers: usize,
    pub unknown_peers: usize,
    pub peers_with_rtt: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_geographic_network_integration_creation() {
        let integration = GeographicNetworkIntegration::new(GeographicRegion::NorthAmerica).unwrap();
        assert_eq!(integration.local_region, GeographicRegion::NorthAmerica);
    }
    
    #[tokio::test]
    async fn test_region_detection_digitalocean() {
        let integration = GeographicNetworkIntegration::new(GeographicRegion::NorthAmerica).unwrap();
        
        // Test DigitalOcean IP detection
        let ip = IpAddr::V4(Ipv4Addr::new(159, 89, 81, 21));
        let region = if let IpAddr::V4(ipv4) = ip {
            integration.classify_ipv4_region(&ipv4)
        } else {
            GeographicRegion::Unknown
        };
        assert_eq!(region, GeographicRegion::Europe);
    }
    
    #[tokio::test]
    async fn test_multiaddr_ip_extraction() {
        let integration = GeographicNetworkIntegration::new(GeographicRegion::NorthAmerica).unwrap();
        
        // Test IPv4 multiaddr
        let addr: Multiaddr = "/ip4/159.89.81.21/tcp/9110".parse().unwrap();
        let ip = integration.extract_ip_from_multiaddr(&addr).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(159, 89, 81, 21)));
    }
    
    #[tokio::test]
    async fn test_peer_addition() {
        let integration = GeographicNetworkIntegration::new(GeographicRegion::NorthAmerica).unwrap();
        
        let addr: Multiaddr = "/ip4/159.89.81.21/tcp/9110".parse().unwrap();
        let result = integration.add_peer("test_peer_1".to_string(), addr).await;
        assert!(result.is_ok());
        
        let stats = integration.get_routing_stats().await.unwrap();
        assert_eq!(stats.total_peers, 1);
        assert_eq!(stats.europe_peers, 1); // DigitalOcean IP should be classified as Europe
    }
    
    #[tokio::test] 
    async fn test_quality_metrics_update() {
        let integration = GeographicNetworkIntegration::new(GeographicRegion::NorthAmerica).unwrap();
        
        let addr: Multiaddr = "/ip4/159.89.81.21/tcp/9110".parse().unwrap();
        integration.add_peer("test_peer_1".to_string(), addr).await.unwrap();
        
        // Test successful operation
        let result = integration.update_peer_quality("test_peer_1", true, Some(Duration::from_millis(50))).await;
        assert!(result.is_ok());
        
        // Test failed operation  
        let result = integration.update_peer_quality("test_peer_1", false, None).await;
        assert!(result.is_ok());
    }
}