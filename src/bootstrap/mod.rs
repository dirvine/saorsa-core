// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Bootstrap Cache System
//!
//! Provides decentralized peer discovery through local caching of known contacts.
//! Uses ant-quic's BootstrapCache internally with additional Sybil protection
//! via rate limiting and IP diversity enforcement.

pub mod contact;
pub mod manager;

// Re-export the primary BootstrapManager (wraps ant-quic)
pub use manager::BootstrapManager;
pub use manager::{
    BootstrapConfig, BootstrapStats, CacheConfig, DEFAULT_CLEANUP_INTERVAL, DEFAULT_MAX_CONTACTS,
    DEFAULT_MERGE_INTERVAL, DEFAULT_QUALITY_UPDATE_INTERVAL,
};

// Re-export contact types
pub use contact::{
    ConnectionHistory, ContactEntry, QualityCalculator, QualityMetrics, QuicConnectionType,
    QuicContactInfo, QuicQualityMetrics,
};

// Four-word address encoding (via four-word-networking crate)
pub use four_word_networking as fourwords;
use four_word_networking::FourWordAdaptiveEncoder;

use crate::error::BootstrapError;
use crate::{P2PError, Result};
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::path::PathBuf;

/// Default directory for storing bootstrap cache files
pub const DEFAULT_CACHE_DIR: &str = ".cache/saorsa";

/// Minimal facade around external four-word types
#[derive(Debug, Clone)]
pub struct FourWordAddress(pub String);

impl FourWordAddress {
    pub fn from_string(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(['.', '-']).collect();
        if parts.len() != 4 {
            return Err(P2PError::Bootstrap(BootstrapError::InvalidData(
                "Four-word address must have exactly 4 words"
                    .to_string()
                    .into(),
            )));
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
        let socket_addr: std::net::SocketAddr = multiaddr
            .parse()
            .map_err(|e| P2PError::Bootstrap(BootstrapError::InvalidData(format!("{e}").into())))?;
        self.encode_socket_addr(&socket_addr)
    }

    pub fn decode_to_socket_addr(&self, words: &FourWordAddress) -> Result<std::net::SocketAddr> {
        let encoder = FourWordAdaptiveEncoder::new().map_err(|e| {
            P2PError::Bootstrap(BootstrapError::InvalidData(
                format!("Encoder init failed: {e}").into(),
            ))
        })?;
        let normalized = words.0.replace(' ', "-");
        let decoded = encoder.decode(&normalized).map_err(|e| {
            P2PError::Bootstrap(BootstrapError::InvalidData(
                format!("Failed to decode four-word address: {e}").into(),
            ))
        })?;
        decoded.parse::<std::net::SocketAddr>().map_err(|_| {
            P2PError::Bootstrap(BootstrapError::InvalidData(
                "Decoded address missing port".to_string().into(),
            ))
        })
    }

    pub fn encode_socket_addr(&self, addr: &std::net::SocketAddr) -> Result<FourWordAddress> {
        let encoder = FourWordAdaptiveEncoder::new().map_err(|e| {
            P2PError::Bootstrap(BootstrapError::InvalidData(
                format!("Encoder init failed: {e}").into(),
            ))
        })?;
        let encoded = encoder
            .encode(&addr.to_string())
            .map_err(|e| P2PError::Bootstrap(BootstrapError::InvalidData(format!("{e}").into())))?;
        Ok(FourWordAddress(encoded.replace(' ', "-")))
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
    /// Number of contacts with successful NAT traversal
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
pub fn ip_to_ipv6(ip: &IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(ipv4) => ipv4.to_ipv6_mapped(),
        IpAddr::V6(ipv6) => *ipv6,
    }
}

/// Get the home cache directory
pub fn home_cache_dir() -> Result<PathBuf> {
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
    use crate::rate_limit::JoinRateLimiterConfig;
    use crate::security::IPDiversityConfig;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_bootstrap_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = CacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            max_contacts: 1000,
            ..CacheConfig::default()
        };

        let manager = BootstrapManager::with_full_config(
            config,
            JoinRateLimiterConfig::default(),
            IPDiversityConfig::default(),
        )
        .await;
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
