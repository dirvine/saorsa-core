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

//! Bootstrap Cache System
//!
//! Provides decentralized peer discovery through local caching of known contacts.
//! Eliminates dependency on central bootstrap servers by maintaining a high-quality
//! cache of up to 30,000 peer contacts with automatic conflict resolution for
//! multiple concurrent instances.

pub mod cache;
pub mod contact;
pub mod discovery;
pub mod merge;

pub use cache::{BootstrapCache, CacheConfig, CacheError};
pub use contact::{
    ContactEntry, QualityCalculator, QualityMetrics, QuicConnectionType, QuicContactInfo,
    QuicQualityMetrics,
};
pub use discovery::{BootstrapConfig, BootstrapDiscovery, ConfigurableBootstrapDiscovery};
pub use merge::{MergeCoordinator, MergeResult};
// Use real four-word-networking crate types behind a thin facade
pub use four_word_networking as fourwords;
use four_word_networking::FourWordAdaptiveEncoder;

/// Minimal facade around external four-word types
#[derive(Debug, Clone)]
pub struct FourWordAddress(pub String);

impl FourWordAddress {
    pub fn from_string(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(['.', '-']).collect();
        if parts.len() != 4 {
            return Err(P2PError::Bootstrap(
                crate::error::BootstrapError::InvalidData(
                    "Four-word address must have exactly 4 words"
                        .to_string()
                        .into(),
                ),
            ));
        }
        Ok(FourWordAddress(parts.join("-")))
    }

    pub fn validate(&self, _encoder: &WordEncoder) -> bool {
        let parts: Vec<&str> = self.0.split(['.', '-']).collect();
        parts.len() == 4 && parts.iter().all(|part| !part.is_empty())
    }
}

#[derive(Debug, Clone)]
pub struct WordDictionary;

#[derive(Debug, Clone)]
pub struct WordEncoder;

impl Default for WordEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl WordEncoder {
    pub fn new() -> Self {
        Self
    }

    pub fn encode_multiaddr_string(&self, multiaddr: &str) -> Result<FourWordAddress> {
        // Map multiaddr to IPv4:port if possible, else hash deterministically
        let socket_addr: std::net::SocketAddr = multiaddr.parse().map_err(|e| {
            P2PError::Bootstrap(crate::error::BootstrapError::InvalidData(
                format!("{e}").into(),
            ))
        })?;
        self.encode_socket_addr(&socket_addr)
    }

    pub fn decode_to_socket_addr(&self, words: &FourWordAddress) -> Result<std::net::SocketAddr> {
        let encoder = FourWordAdaptiveEncoder::new().map_err(|e| {
            P2PError::Bootstrap(crate::error::BootstrapError::InvalidData(
                format!("Encoder init failed: {e}").into(),
            ))
        })?;
        // Accept hyphens, spaces or dots; normalize then call adaptive decoder
        let normalized = words.0.replace(' ', "-");
        let decoded = encoder.decode(&normalized).map_err(|e| {
            P2PError::Bootstrap(crate::error::BootstrapError::InvalidData(
                format!("Failed to decode four-word address: {e}").into(),
            ))
        })?;
        decoded.parse::<std::net::SocketAddr>().map_err(|_| {
            P2PError::Bootstrap(crate::error::BootstrapError::InvalidData(
                "Decoded address missing port".to_string().into(),
            ))
        })
    }

    pub fn encode_socket_addr(&self, addr: &std::net::SocketAddr) -> Result<FourWordAddress> {
        let encoder = FourWordAdaptiveEncoder::new().map_err(|e| {
            P2PError::Bootstrap(crate::error::BootstrapError::InvalidData(
                format!("Encoder init failed: {e}").into(),
            ))
        })?;
        let encoded = encoder.encode(&addr.to_string()).map_err(|e| {
            P2PError::Bootstrap(crate::error::BootstrapError::InvalidData(
                format!("{e}").into(),
            ))
        })?;
        Ok(FourWordAddress(encoded.replace(' ', "-")))
    }
}

use crate::error::BootstrapError;
use crate::rate_limit::{JoinRateLimiter, JoinRateLimiterConfig};
use crate::security::{IPDiversityConfig, IPDiversityEnforcer};
use crate::{P2PError, PeerId, Result};
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;

/// Default cache configuration
pub const DEFAULT_MAX_CONTACTS: usize = 30_000;
/// Default directory for storing bootstrap cache files
pub const DEFAULT_CACHE_DIR: &str = ".cache/p2p_foundation";
/// Default interval for merging instance cache files
pub const DEFAULT_MERGE_INTERVAL: Duration = Duration::from_secs(30);
/// Default interval for cleaning up stale contacts (1 hour)
pub const DEFAULT_CLEANUP_INTERVAL: Duration = Duration::from_secs(3600);
/// Default interval for updating contact quality scores (5 minutes)
pub const DEFAULT_QUALITY_UPDATE_INTERVAL: Duration = Duration::from_secs(300);

/// Bootstrap cache initialization and management
pub struct BootstrapManager {
    cache: BootstrapCache,
    merge_coordinator: MergeCoordinator,
    word_encoder: WordEncoder,
    /// Join rate limiter for Sybil attack protection
    join_limiter: JoinRateLimiter,
    /// IP diversity enforcer for geographic and ASN diversity
    diversity_enforcer: IPDiversityEnforcer,
}

impl BootstrapManager {
    /// Create a new bootstrap manager with default configuration
    pub async fn new() -> Result<Self> {
        let cache_dir = home_cache_dir()?;
        let config = CacheConfig::default();

        let cache = BootstrapCache::new(cache_dir.clone(), config).await?;
        let merge_coordinator = MergeCoordinator::new(cache_dir)?;
        let word_encoder = WordEncoder::new();
        let join_limiter = JoinRateLimiter::new(JoinRateLimiterConfig::default());
        let diversity_enforcer = IPDiversityEnforcer::new(IPDiversityConfig::default());

        Ok(Self {
            cache,
            merge_coordinator,
            word_encoder,
            join_limiter,
            diversity_enforcer,
        })
    }

    /// Create a new bootstrap manager with custom configuration
    pub async fn with_config(config: CacheConfig) -> Result<Self> {
        let cache_dir = config.cache_dir.clone();

        let cache = BootstrapCache::new(cache_dir.clone(), config).await?;
        let merge_coordinator = MergeCoordinator::new(cache_dir)?;
        let word_encoder = WordEncoder::new();
        let join_limiter = JoinRateLimiter::new(JoinRateLimiterConfig::default());
        let diversity_enforcer = IPDiversityEnforcer::new(IPDiversityConfig::default());

        Ok(Self {
            cache,
            merge_coordinator,
            word_encoder,
            join_limiter,
            diversity_enforcer,
        })
    }

    /// Create a new bootstrap manager with custom configuration and rate limiting
    pub async fn with_rate_limiting(
        config: CacheConfig,
        rate_limit_config: JoinRateLimiterConfig,
    ) -> Result<Self> {
        let cache_dir = config.cache_dir.clone();

        let cache = BootstrapCache::new(cache_dir.clone(), config).await?;
        let merge_coordinator = MergeCoordinator::new(cache_dir)?;
        let word_encoder = WordEncoder::new();
        let join_limiter = JoinRateLimiter::new(rate_limit_config);
        let diversity_enforcer = IPDiversityEnforcer::new(IPDiversityConfig::default());

        Ok(Self {
            cache,
            merge_coordinator,
            word_encoder,
            join_limiter,
            diversity_enforcer,
        })
    }

    /// Create a new bootstrap manager with full custom configuration
    pub async fn with_full_config(
        config: CacheConfig,
        rate_limit_config: JoinRateLimiterConfig,
        diversity_config: IPDiversityConfig,
    ) -> Result<Self> {
        let cache_dir = config.cache_dir.clone();

        let cache = BootstrapCache::new(cache_dir.clone(), config).await?;
        let merge_coordinator = MergeCoordinator::new(cache_dir)?;
        let word_encoder = WordEncoder::new();
        let join_limiter = JoinRateLimiter::new(rate_limit_config);
        let diversity_enforcer = IPDiversityEnforcer::new(diversity_config);

        Ok(Self {
            cache,
            merge_coordinator,
            word_encoder,
            join_limiter,
            diversity_enforcer,
        })
    }

    /// Get bootstrap peers for initial connection
    pub async fn get_bootstrap_peers(&self, count: usize) -> Result<Vec<ContactEntry>> {
        self.cache.get_bootstrap_peers(count).await
    }

    /// Add a discovered peer to the cache
    ///
    /// This method enforces both rate limiting and IP diversity checks to prevent
    /// Sybil attacks:
    ///
    /// 1. **Rate limiting**: Per-subnet (IPv6 /64, /48 and IPv4 /24) and global limits
    /// 2. **IP diversity**: Ensures geographic and ASN diversity across the network
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The contact has no addresses
    /// - Join rate limit is exceeded for the IP subnet
    /// - IP diversity limits are exceeded
    /// - The cache operation fails
    pub async fn add_contact(&mut self, contact: ContactEntry) -> Result<()> {
        // Extract IP address from contact for rate limiting
        let ip = contact
            .addresses
            .first()
            .map(|addr| addr.ip())
            .ok_or_else(|| {
                P2PError::Bootstrap(BootstrapError::InvalidData(
                    "Contact has no addresses".to_string().into(),
                ))
            })?;

        // Check join rate limit (Sybil protection - temporal)
        self.join_limiter.check_join_allowed(&ip).map_err(|e| {
            tracing::warn!("Join rate limit exceeded for {}: {}", ip, e);
            P2PError::Bootstrap(BootstrapError::RateLimited(e.to_string().into()))
        })?;

        // Convert IP to IPv6 for diversity analysis
        // IPv4 addresses are mapped to IPv6 (::ffff:a.b.c.d)
        let ipv6 = ip_to_ipv6(&ip);

        // Analyze IP for diversity enforcement
        let ip_analysis = self.diversity_enforcer.analyze_ip(ipv6).map_err(|e| {
            tracing::warn!("IP analysis failed for {}: {}", ip, e);
            P2PError::Bootstrap(BootstrapError::InvalidData(
                format!("IP analysis failed: {e}").into(),
            ))
        })?;

        // Check IP diversity limits (Sybil protection - geographic/ASN)
        if !self.diversity_enforcer.can_accept_node(&ip_analysis) {
            tracing::warn!("IP diversity limit exceeded for {}", ip);
            return Err(P2PError::Bootstrap(BootstrapError::RateLimited(
                "IP diversity limits exceeded (too many nodes from same subnet/ASN)"
                    .to_string()
                    .into(),
            )));
        }

        // Add to diversity tracking
        if let Err(e) = self.diversity_enforcer.add_node(&ip_analysis) {
            tracing::warn!("Failed to track IP diversity for {}: {}", ip, e);
            // Don't fail the add - diversity tracking is best-effort
        }

        self.cache.add_contact(contact).await
    }

    /// Add a contact bypassing rate limiting and diversity checks (for internal/trusted sources)
    ///
    /// Use this method only for contacts from trusted sources like:
    /// - Well-known bootstrap nodes
    /// - Pre-configured seed nodes
    /// - Admin-approved contacts
    ///
    /// # Safety
    ///
    /// This method does not enforce rate limiting or diversity checks.
    /// Only use for trusted sources.
    pub async fn add_contact_trusted(&mut self, contact: ContactEntry) -> Result<()> {
        self.cache.add_contact(contact).await
    }

    /// Update contact performance metrics
    pub async fn update_contact_metrics(
        &mut self,
        peer_id: &PeerId,
        metrics: QualityMetrics,
    ) -> Result<()> {
        self.cache.update_contact_metrics(peer_id, metrics).await
    }

    /// Start background maintenance tasks
    pub async fn start_background_tasks(&mut self) -> Result<()> {
        // Start periodic merge of instance caches
        let cache_clone = self.cache.clone();
        let merge_coordinator = self.merge_coordinator.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(DEFAULT_MERGE_INTERVAL);
            loop {
                interval.tick().await;
                if let Err(e) = merge_coordinator.merge_instance_caches(&cache_clone).await {
                    tracing::warn!("Failed to merge instance caches: {}", e);
                }
            }
        });

        // Start quality score updates
        let cache_clone = self.cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(DEFAULT_QUALITY_UPDATE_INTERVAL);
            loop {
                interval.tick().await;
                if let Err(e) = cache_clone.update_quality_scores().await {
                    tracing::warn!("Failed to update quality scores: {}", e);
                }
            }
        });

        // Start cleanup task
        let cache_clone = self.cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(DEFAULT_CLEANUP_INTERVAL);
            loop {
                interval.tick().await;
                if let Err(e) = cache_clone.cleanup_stale_entries().await {
                    tracing::warn!("Failed to cleanup stale entries: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> Result<CacheStats> {
        self.cache.get_stats().await
    }

    /// Force a cache merge operation
    pub async fn force_merge(&self) -> Result<MergeResult> {
        self.merge_coordinator
            .merge_instance_caches(&self.cache)
            .await
    }

    /// Convert socket address to four-word address
    pub fn encode_address(&self, socket_addr: &std::net::SocketAddr) -> Result<FourWordAddress> {
        self.word_encoder
            .encode_socket_addr(socket_addr)
            .map_err(|e| {
                crate::P2PError::Bootstrap(crate::error::BootstrapError::InvalidData(
                    format!("Failed to encode socket address: {e}").into(),
                ))
            })
    }

    /// Convert four-word address to socket address
    pub fn decode_address(&self, words: &FourWordAddress) -> Result<std::net::SocketAddr> {
        self.word_encoder.decode_to_socket_addr(words).map_err(|e| {
            crate::P2PError::Bootstrap(crate::error::BootstrapError::InvalidData(
                format!("Failed to decode four-word address: {e}").into(),
            ))
        })
    }

    /// Validate four-word address format
    pub fn validate_words(&self, words: &FourWordAddress) -> Result<()> {
        if words.validate(&self.word_encoder) {
            Ok(())
        } else {
            Err(crate::P2PError::Bootstrap(
                crate::error::BootstrapError::InvalidData(
                    "Invalid four-word address format".to_string().into(),
                ),
            ))
        }
    }

    /// Get the word encoder for direct access
    pub fn word_encoder(&self) -> &WordEncoder {
        &self.word_encoder
    }

    /// Get well-known bootstrap addresses as four-word addresses
    pub fn get_well_known_word_addresses(&self) -> Vec<(FourWordAddress, std::net::SocketAddr)> {
        let well_known_addrs = vec![
            // Primary bootstrap nodes with well-known addresses
            std::net::SocketAddr::from(([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888], 9000)),
            std::net::SocketAddr::from(([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844], 9001)),
            std::net::SocketAddr::from(([0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111], 9002)),
        ];

        well_known_addrs
            .into_iter()
            .filter_map(|socket_addr| {
                if let Ok(words) = self.encode_address(&socket_addr) {
                    Some((words, socket_addr))
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Cache statistics for monitoring
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CacheStats {
    /// Total number of contacts in the cache
    pub total_contacts: usize,
    /// Number of contacts with high quality scores
    pub high_quality_contacts: usize,
    /// Number of contacts with verified IPv6 identity
    pub verified_contacts: usize,
    /// Timestamp of the last cache merge operation
    pub last_merge: chrono::DateTime<chrono::Utc>,
    /// Timestamp of the last cache cleanup operation
    pub last_cleanup: chrono::DateTime<chrono::Utc>,
    /// Cache hit rate for peer discovery operations
    pub cache_hit_rate: f64,
    /// Average quality score across all contacts
    pub average_quality_score: f64,

    // QUIC-specific statistics
    /// Number of contacts with QUIC networking support
    pub iroh_contacts: usize,
    /// Number of contacts with successful NAT traversal (deprecated)
    pub nat_traversal_contacts: usize,
    /// Average QUIC connection setup time (milliseconds)
    pub avg_iroh_setup_time_ms: f64,
    /// Most successful QUIC connection type
    pub preferred_iroh_connection_type: Option<String>,
}

/// Convert an IP address to IPv6
///
/// IPv4 addresses are converted to IPv6-mapped format (::ffff:a.b.c.d)
/// IPv6 addresses are returned as-is
fn ip_to_ipv6(ip: &IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(ipv4) => ipv4.to_ipv6_mapped(),
        IpAddr::V6(ipv6) => *ipv6,
    }
}

/// Get the home cache directory
fn home_cache_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| {
            P2PError::Bootstrap(BootstrapError::CacheError(
                "Unable to determine home directory".to_string().into(),
            ))
        })?;

    let cache_dir = PathBuf::from(home).join(DEFAULT_CACHE_DIR);

    // Ensure cache directory exists
    std::fs::create_dir_all(&cache_dir).map_err(|e| {
        P2PError::Bootstrap(BootstrapError::CacheError(
            format!("Failed to create cache directory: {e}").into(),
        ))
    })?;

    Ok(cache_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_bootstrap_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = CacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            max_contacts: 1000,
            ..CacheConfig::default()
        };

        let manager = BootstrapManager::with_config(config).await;
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_home_cache_dir() {
        let result = home_cache_dir();
        assert!(result.is_ok());

        let path = result.unwrap();
        assert!(path.exists());
        assert!(path.is_dir());
    }
}
