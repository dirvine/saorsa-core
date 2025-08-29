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

//! # Configuration Management System
//!
//! This module provides comprehensive configuration management for the P2P network,
//! supporting layered configuration (environment > file > defaults) with validation.
//!
//! ## Features
//! - Environment variable override support
//! - TOML/JSON configuration file support
//! - Production and development profiles
//! - IPv4/IPv6 address validation
//! - Secure defaults for production

use crate::address::NetworkAddress;
use crate::error::ConfigError;
use crate::validation::{
    ValidationContext, validate_config_value, validate_file_path, validate_network_address,
};
use crate::{P2PError, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tracing::info;

/// Main configuration structure for the P2P network
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct Config {
    /// Network configuration
    pub network: NetworkConfig,
    /// Security configuration
    pub security: SecurityConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// MCP (Model Context Protocol) configuration
    pub mcp: McpConfig,
    /// DHT configuration
    pub dht: DhtConfig,
    /// Transport configuration
    pub transport: TransportConfig,
    /// Identity configuration
    pub identity: IdentityConfig,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    /// Bootstrap nodes for network discovery
    pub bootstrap_nodes: Vec<String>,
    /// Local listen address (0.0.0.0:9000 for all interfaces)
    pub listen_address: String,
    /// Public address for external connections (auto-detected if empty)
    pub public_address: Option<String>,
    /// Enable IPv6 support
    pub ipv6_enabled: bool,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Keepalive interval in seconds
    pub keepalive_interval: u64,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Rate limit (requests per second)
    pub rate_limit: u32,
    /// Connection limit per IP
    pub connection_limit: u32,
    /// Enable TLS/encryption
    pub encryption_enabled: bool,
    /// Minimum TLS version (e.g., "1.3")
    pub min_tls_version: String,
    /// Security level for identity management
    pub identity_security_level: String,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// Base path for data storage
    pub path: PathBuf,
    /// Maximum storage size (e.g., "10GB")
    pub max_size: String,
    /// Cache size in MB
    pub cache_size: u64,
    /// Enable compression
    pub compression_enabled: bool,
}

/// MCP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct McpConfig {
    /// Enable MCP server
    pub enabled: bool,
    /// MCP server port
    pub port: u16,
    /// Maximum tool execution time in seconds
    pub max_execution_time: u64,
    /// Enable resource monitoring
    pub monitoring_enabled: bool,
}

/// DHT configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DhtConfig {
    /// Replication factor (K value)
    pub replication_factor: u8,
    /// Alpha value for parallel queries
    pub alpha: u8,
    /// Beta value for routing
    pub beta: u8,
    /// Record TTL in seconds
    pub record_ttl: u64,
    /// Enable adaptive routing
    pub adaptive_routing: bool,
}

/// Transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TransportConfig {
    /// Preferred transport protocol
    pub protocol: String,
    /// Enable QUIC transport
    pub quic_enabled: bool,
    /// Enable TCP transport
    pub tcp_enabled: bool,
    /// Enable WebRTC transport
    pub webrtc_enabled: bool,
    /// Transport buffer size
    pub buffer_size: usize,
    /// Server name for TLS (SNI)
    pub server_name: String,
}

/// Identity configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IdentityConfig {
    /// Default key derivation path
    pub derivation_path: String,
    /// Key rotation interval in days
    pub rotation_interval: u32,
    /// Enable automatic backups
    pub backup_enabled: bool,
    /// Backup interval in hours
    pub backup_interval: u32,
}

// Default implementations

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bootstrap_nodes: vec![],
            // Use environment variable or fallback to localhost for development
            listen_address: env::var("SAORSA_LISTEN_ADDRESS")
                .unwrap_or_else(|_| "127.0.0.1:9000".to_string()),
            public_address: None,
            ipv6_enabled: true,
            max_connections: 10000,
            connection_timeout: 30,
            keepalive_interval: 60,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            rate_limit: 1000,
            connection_limit: 100,
            encryption_enabled: true,
            min_tls_version: "1.3".to_string(),
            identity_security_level: "High".to_string(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("./data"),
            max_size: "10GB".to_string(),
            cache_size: 256,
            compression_enabled: true,
        }
    }
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 9001,
            max_execution_time: 300,
            monitoring_enabled: true,
        }
    }
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            replication_factor: 8,
            alpha: 3,
            beta: 1,
            record_ttl: 3600,
            adaptive_routing: true,
        }
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            protocol: "quic".to_string(),
            quic_enabled: true,
            tcp_enabled: true,
            webrtc_enabled: false,
            buffer_size: 65536,
            server_name: "p2p.local".to_string(),
        }
    }
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            rotation_interval: 90,
            backup_enabled: true,
            backup_interval: 24,
        }
    }
}

impl Config {
    /// Load configuration from multiple sources with precedence:
    /// 1. Environment variables (highest)
    /// 2. Configuration file
    /// 3. Default values (lowest)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saorsa_core::config::Config;
    ///
    /// // Load with default locations
    /// let config = Config::load()?;
    ///
    /// // Access configuration values
    /// println!("Listen address: {}", config.network.listen_address);
    /// println!("Rate limit: {}", config.security.rate_limit);
    /// # Ok::<(), saorsa_core::P2PError>(())
    /// ```
    pub fn load() -> Result<Self> {
        Self::load_with_path::<&str>(None)
    }

    /// Load configuration with a specific config file path
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saorsa_core::config::Config;
    ///
    /// // Load from specific file
    /// let config = Config::load_with_path(Some("custom.toml"))?;
    ///
    /// // Load from optional path
    /// let path = std::env::var("CONFIG_PATH").ok();
    /// let config = Config::load_with_path(path.as_ref())?;
    /// # Ok::<(), saorsa_core::P2PError>(())
    /// ```
    pub fn load_with_path<P: AsRef<Path>>(path: Option<P>) -> Result<Self> {
        // Start with defaults
        let mut config = Self::default();

        // Load from file if provided or look for default locations
        if let Some(path) = path {
            config = Self::load_from_file(path)?;
        } else {
            // Try default config locations
            for location in &["saorsa.toml", "config.toml", "/etc/saorsa/config.toml"] {
                if Path::new(location).exists() {
                    info!("Loading config from: {}", location);
                    config = Self::load_from_file(location)?;
                    break;
                }
            }
        }

        // Override with environment variables
        config.apply_env_overrides()?;

        // Validate the final configuration
        config.validate()?;

        Ok(config)
    }

    /// Load configuration from a TOML file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(&path).map_err(|e| {
            P2PError::Config(ConfigError::IoError {
                path: path.as_ref().to_string_lossy().to_string().into(),
                source: e,
            })
        })?;

        toml::from_str(&content)
            .map_err(|e| P2PError::Config(ConfigError::ParseError(e.to_string().into())))
    }

    /// Save configuration to a TOML file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| P2PError::Config(ConfigError::ParseError(e.to_string().into())))?;

        fs::write(&path, content).map_err(|e| {
            P2PError::Config(ConfigError::IoError {
                path: path.as_ref().to_string_lossy().to_string().into(),
                source: e,
            })
        })?;

        Ok(())
    }

    /// Apply environment variable overrides
    fn apply_env_overrides(&mut self) -> Result<()> {
        // Network overrides
        if let Ok(val) = env::var("SAORSA_LISTEN_ADDRESS") {
            self.network.listen_address = val;
        }
        if let Ok(val) = env::var("SAORSA_PUBLIC_ADDRESS") {
            self.network.public_address = Some(val);
        }
        if let Ok(val) = env::var("SAORSA_BOOTSTRAP_NODES") {
            self.network.bootstrap_nodes = val.split(',').map(String::from).collect();
        }
        if let Ok(val) = env::var("SAORSA_MAX_CONNECTIONS") {
            self.network.max_connections = val.parse().map_err(|_| {
                P2PError::Config(ConfigError::InvalidValue {
                    field: "max_connections".to_string().into(),
                    reason: "Invalid value".to_string().into(),
                })
            })?;
        }

        // Security overrides
        if let Ok(val) = env::var("SAORSA_RATE_LIMIT") {
            self.security.rate_limit = val.parse().map_err(|_| {
                P2PError::Config(ConfigError::InvalidValue {
                    field: "rate_limit".to_string().into(),
                    reason: "Invalid value".to_string().into(),
                })
            })?;
        }
        if let Ok(val) = env::var("SAORSA_ENCRYPTION_ENABLED") {
            self.security.encryption_enabled = val.parse().map_err(|_| {
                P2PError::Config(ConfigError::InvalidValue {
                    field: "encryption_enabled".to_string().into(),
                    reason: "Invalid value".to_string().into(),
                })
            })?;
        }

        // Storage overrides
        if let Ok(val) = env::var("SAORSA_DATA_PATH") {
            self.storage.path = PathBuf::from(val);
        }
        if let Ok(val) = env::var("SAORSA_MAX_STORAGE") {
            self.storage.max_size = val;
        }

        // MCP overrides
        if let Ok(val) = env::var("SAORSA_MCP_ENABLED") {
            self.mcp.enabled = val.parse().map_err(|_| {
                P2PError::Config(ConfigError::InvalidValue {
                    field: "mcp_enabled".to_string().into(),
                    reason: "Invalid value".to_string().into(),
                })
            })?;
        }
        if let Ok(val) = env::var("SAORSA_MCP_PORT") {
            self.mcp.port = val.parse().map_err(|_| {
                P2PError::Config(ConfigError::InvalidValue {
                    field: "mcp_port".to_string().into(),
                    reason: "Invalid value".to_string().into(),
                })
            })?;
        }

        Ok(())
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        let mut errors = Vec::new();

        // Validate network addresses
        if let Err(e) = self.validate_address(&self.network.listen_address, "listen_address") {
            errors.push(e);
        }

        if let Some(addr) = &self.network.public_address
            && let Err(e) = self.validate_address(addr, "public_address")
        {
            errors.push(e);
        }

        for (i, node) in self.network.bootstrap_nodes.iter().enumerate() {
            if let Err(e) = self.validate_address(node, &format!("bootstrap_node[{}]", i)) {
                errors.push(e);
            }
        }

        // Validate ranges using validation framework
        if let Err(e) = validate_config_value(
            &self.network.max_connections.to_string(),
            Some(1_usize),
            Some(100000_usize),
        ) {
            errors.push(P2PError::Config(ConfigError::InvalidValue {
                field: "max_connections".to_string().into(),
                reason: e.to_string().into(),
            }));
        }

        if let Err(e) = validate_config_value(
            &self.security.rate_limit.to_string(),
            Some(1_u32),
            Some(1000000_u32),
        ) {
            errors.push(P2PError::Config(ConfigError::InvalidValue {
                field: "rate_limit".to_string().into(),
                reason: e.to_string().into(),
            }));
        }

        // Validate storage path
        if let Err(e) = validate_file_path(&self.storage.path) {
            errors.push(P2PError::Config(ConfigError::InvalidValue {
                field: "storage.path".to_string().into(),
                reason: e.to_string().into(),
            }));
        }

        // Validate storage size format
        if !self.validate_size_format(&self.storage.max_size) {
            errors.push(P2PError::Config(ConfigError::InvalidValue {
                field: "max_size".to_string().into(),
                reason: format!("Invalid storage size format: {}", self.storage.max_size).into(),
            }));
        }

        // Validate transport protocol
        match self.transport.protocol.as_str() {
            "quic" | "tcp" | "webrtc" => {}
            _ => errors.push(P2PError::Config(ConfigError::InvalidValue {
                field: "protocol".to_string().into(),
                reason: format!("Invalid transport protocol: {}", self.transport.protocol).into(),
            })),
        }

        if errors.is_empty() {
            Ok(())
        } else {
            // Return the first error, or a generic error if somehow the vec is empty
            Err(errors.into_iter().next().unwrap_or_else(|| {
                P2PError::Config(ConfigError::InvalidValue {
                    field: "unknown".to_string().into(),
                    reason: "Validation failed with unknown error".to_string().into(),
                })
            }))
        }
    }

    /// Validate network address format
    fn validate_address(&self, addr: &str, field: &str) -> Result<()> {
        // Try parsing as SocketAddr first
        if let Ok(socket_addr) = SocketAddr::from_str(addr) {
            // Use our validation framework
            let ctx = ValidationContext::default()
                .allow_localhost() // Allow localhost for development
                .allow_private_ips(); // Allow private IPs for development

            return validate_network_address(&socket_addr, &ctx).map_err(|e| {
                P2PError::Config(ConfigError::InvalidValue {
                    field: field.to_string().into(),
                    reason: e.to_string().into(),
                })
            });
        }

        // Try parsing as four-word address format (always enabled)
        if let Ok(network_addr) = crate::NetworkAddress::from_four_words(addr) {
            // Validate the parsed socket address
            let ctx = ValidationContext::default()
                .allow_localhost()
                .allow_private_ips();

            return validate_network_address(&network_addr.socket_addr(), &ctx).map_err(|e| {
                P2PError::Config(ConfigError::InvalidValue {
                    field: field.to_string().into(),
                    reason: e.to_string().into(),
                })
            });
        }

        // Try parsing as multiaddr format
        if addr.starts_with("/ip4/") || addr.starts_with("/ip6/") {
            // Basic multiaddr validation
            return Ok(());
        }

        Err(P2PError::Config(ConfigError::InvalidValue {
            field: field.to_string().into(),
            reason: format!("Invalid address format: {}", addr).into(),
        }))
    }

    /// Validate size format (e.g., "10GB", "500MB")
    fn validate_size_format(&self, size: &str) -> bool {
        thread_local! {
            static SIZE_REGEX: std::result::Result<Regex, P2PError> = Regex::new(r"^\\d+(?:\\.\\d+)?\\s*(?:B|KB|MB|GB|TB)$")
                .map_err(|e| P2PError::Config(ConfigError::InvalidValue { field: "size".to_string().into(), reason: e.to_string().into() }));
        }
        SIZE_REGEX.with(|re| re.as_ref().ok().map(|r| r.is_match(size)).unwrap_or(false))
    }

    /// Create development configuration
    pub fn development() -> Self {
        let mut config = Self::default();
        config.network.listen_address = "127.0.0.1:9000".to_string();
        config.security.rate_limit = 10000;
        config.security.connection_limit = 1000;
        config.storage.path = PathBuf::from("./dev-data");
        config
    }

    /// Create production configuration with secure defaults
    pub fn production() -> Self {
        let mut config = Self::default();
        // Use environment variable or fallback to secure default
        config.network.listen_address =
            env::var("SAORSA_LISTEN_ADDRESS").unwrap_or_else(|_| "0.0.0.0:9000".to_string());
        config.security.rate_limit = 1000;
        config.security.connection_limit = 100;
        config.storage.path = PathBuf::from("/var/lib/saorsa");
        config
    }

    /// Get parsed listen address
    pub fn listen_socket_addr(&self) -> Result<SocketAddr> {
        SocketAddr::from_str(&self.network.listen_address).map_err(|e| {
            P2PError::Config(ConfigError::InvalidValue {
                field: "listen_address".to_string().into(),
                reason: format!("Invalid address: {}", e).into(),
            })
        })
    }

    /// Get parsed bootstrap addresses
    pub fn bootstrap_addrs(&self) -> Result<Vec<NetworkAddress>> {
        self.network
            .bootstrap_nodes
            .iter()
            .map(|addr| {
                addr.parse::<NetworkAddress>().map_err(|e| {
                    P2PError::Config(ConfigError::InvalidValue {
                        field: "bootstrap_nodes".to_string().into(),
                        reason: format!("Invalid address: {}", e).into(),
                    })
                })
            })
            .collect()
    }

    /// Parse a size string (e.g., "10GB", "500MB") to bytes
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use saorsa_core::config::Config;
    ///
    /// assert_eq!(Config::parse_size("10B").unwrap(), 10);
    /// assert_eq!(Config::parse_size("1KB").unwrap(), 1024);
    /// assert_eq!(Config::parse_size("5MB").unwrap(), 5 * 1024 * 1024);
    /// ```
    pub fn parse_size(size: &str) -> Result<u64> {
        thread_local! {
            static SIZE_REGEX: std::result::Result<Regex, P2PError> = Regex::new(r"^(\\d+(?:\\.\\d+)?)\\s*(B|KB|MB|GB|TB)$")
                .map_err(|e| P2PError::Config(ConfigError::InvalidValue { field: "size".to_string().into(), reason: e.to_string().into() }));
        }

        SIZE_REGEX.with(|re| -> Result<u64> {
            let re = match re {
                Ok(r) => r,
                Err(e) => {
                    return Err(P2PError::Config(ConfigError::InvalidValue {
                        field: "size".to_string().into(),
                        reason: e.to_string().into(),
                    }));
                }
            };
            if let Some(captures) = re.captures(size) {
                let value: f64 = captures
                    .get(1)
                    .and_then(|m| m.as_str().parse().ok())
                    .ok_or_else(|| {
                        P2PError::Config(ConfigError::InvalidValue {
                            field: "size".to_string().into(),
                            reason: "Invalid numeric value".to_string().into(),
                        })
                    })?;

                let unit = captures.get(2).map(|m| m.as_str()).unwrap_or("B");
                let multiplier = match unit {
                    "B" => 1u64,
                    "KB" => 1024,
                    "MB" => 1024 * 1024,
                    "GB" => 1024 * 1024 * 1024,
                    "TB" => 1024u64.pow(4),
                    _ => {
                        return Err(P2PError::Config(ConfigError::InvalidValue {
                            field: "size".to_string().into(),
                            reason: format!("Unknown unit: {}", unit).into(),
                        }));
                    }
                };

                Ok((value * multiplier as f64) as u64)
            } else {
                Err(P2PError::Config(ConfigError::InvalidValue {
                    field: "size".to_string().into(),
                    reason: format!("Invalid size format: {}", size).into(),
                }))
            }
        })
    }

    /// Get storage max size in bytes
    pub fn storage_max_size_bytes(&self) -> Result<u64> {
        Self::parse_size(&self.storage.max_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.network.listen_address, "0.0.0.0:9000");
        assert_eq!(config.security.rate_limit, 1000);
        assert!(config.security.encryption_enabled);
    }

    #[test]
    fn test_development_config() {
        let config = Config::development();
        assert_eq!(config.network.listen_address, "127.0.0.1:9000");
        assert_eq!(config.security.rate_limit, 10000);
    }

    #[test]
    fn test_production_config() {
        let config = Config::production();
        assert_eq!(config.network.listen_address, "0.0.0.0:9000");
        assert_eq!(config.transport.buffer_size, 131072);
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        assert!(config.validate().is_ok());

        // Invalid address
        config.network.listen_address = "invalid".to_string();
        assert!(config.validate().is_err());

        // Valid multiaddr
        config.network.listen_address = "/ip4/127.0.0.1/tcp/9000".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_save_and_load_config() {
        let config = Config::development();
        let file = NamedTempFile::new().unwrap();

        config.save_to_file(file.path()).unwrap();

        let loaded = Config::load_from_file(file.path()).unwrap();
        assert_eq!(loaded.network.listen_address, config.network.listen_address);
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)] // Required for env::set_var in tests only
    fn test_env_overrides() {
        use std::sync::Mutex;

        // Use a static mutex to ensure thread safety
        static ENV_MUTEX: Mutex<()> = Mutex::new(());
        let _guard = ENV_MUTEX.lock().unwrap();

        // Save original values
        let orig_listen = env::var("SAORSA_LISTEN_ADDRESS").ok();
        let orig_rate = env::var("SAORSA_RATE_LIMIT").ok();

        // Set test values - unsafe blocks required in Rust 2024
        unsafe {
            env::set_var("SAORSA_LISTEN_ADDRESS", "127.0.0.1:8000");
            env::set_var("SAORSA_RATE_LIMIT", "5000");
        }

        let config = Config::load().unwrap();
        assert_eq!(config.network.listen_address, "127.0.0.1:8000");
        assert_eq!(config.security.rate_limit, 5000);

        // Restore original values
        unsafe {
            match orig_listen {
                Some(val) => env::set_var("SAORSA_LISTEN_ADDRESS", val),
                None => env::remove_var("SAORSA_LISTEN_ADDRESS"),
            }
            match orig_rate {
                Some(val) => env::set_var("SAORSA_RATE_LIMIT", val),
                None => env::remove_var("SAORSA_RATE_LIMIT"),
            }
        }
    }

    #[test]
    fn test_size_validation() {
        let config = Config::default();
        assert!(config.validate_size_format("10GB"));
        assert!(config.validate_size_format("500MB"));
        assert!(config.validate_size_format("1.5TB"));
        assert!(!config.validate_size_format("10XB"));
        assert!(!config.validate_size_format("invalid"));
    }

    #[test]
    fn test_size_parsing() {
        assert_eq!(Config::parse_size("10B").unwrap(), 10);
        assert_eq!(Config::parse_size("1KB").unwrap(), 1024);
        assert_eq!(Config::parse_size("5MB").unwrap(), 5 * 1024 * 1024);
        assert_eq!(Config::parse_size("1GB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(Config::parse_size("1.5GB").unwrap(), 1610612736);
        assert_eq!(Config::parse_size("1TB").unwrap(), 1024u64.pow(4));

        // Test error cases
        assert!(Config::parse_size("invalid").is_err());
        assert!(Config::parse_size("10XB").is_err());
        assert!(Config::parse_size("GB").is_err());
    }
}
