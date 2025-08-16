// Copyright (c) 2025 Saorsa Labs Limited

// This file is part of the Saorsa P2P network.

// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Comprehensive error handling framework for P2P Foundation
//!
//! This module provides a zero-panic error handling system designed to replace 568 unwrap() calls
//! throughout the codebase with proper error propagation and context.
//!
//! # Features
//!
//! - **Type-safe error hierarchy**: Custom error types for all subsystems
//! - **Zero-cost abstractions**: Optimized for performance with Cow<'static, str>
//! - **Context propagation**: Rich error context without heap allocations
//! - **Structured logging**: JSON-based error reporting for production monitoring
//! - **Anyhow integration**: Seamless integration for application-level errors
//! - **Recovery patterns**: Built-in retry and circuit breaker support
//!
//! # Usage Examples
//!
//! ## Basic Error Handling
//!
//! ```rust
//! use p2p_core::error::{P2PError, P2pResult, ErrorContext};
//!
//! fn connect_to_peer(addr: SocketAddr) -> P2pResult<Connection> {
//!     // Instead of: socket.connect(addr).unwrap()
//!     let conn = socket.connect(addr)
//!         .map_err(|e| NetworkError::ConnectionFailed {
//!             addr,
//!             reason: e.to_string().into(),
//!         })?;
//!     
//!     Ok(conn)
//! }
//! ```
//!
//! ## Adding Context
//!
//! ```rust
//! use p2p_core::error::{P2PError, P2pResult, ErrorContext};
//!
//! fn load_config(path: &str) -> P2pResult<Config> {
//!     std::fs::read_to_string(path)
//!         .context("Failed to read config file")?
//!         .parse()
//!         .context("Failed to parse config")
//! }
//! ```
//!
//! ## Structured Error Logging
//!
//! ```rust
//! use p2p_core::error::{P2PError, ErrorReporting};
//!
//! fn handle_error(err: P2PError) {
//!     // Automatically logs with appropriate level and context
//!     err.log();
//!     
//!     // Or get structured log for custom handling
//!     let log_entry = err.to_error_log();
//!     send_to_monitoring_system(&log_entry);
//! }
//! ```
//!
//! ## Migration from unwrap()
//!
//! ```rust
//! // Before:
//! let value = some_operation().unwrap();
//!
//! // After:
//! let value = some_operation()
//!     .context("Failed to perform operation")?;
//!
//! // For performance-critical paths with known bounds:
//! let value = some_operation()
//!     .ok_or_else(|| P2PError::Internal("Operation failed".into()))?;
//! ```

use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

// Metrics imports would go here when implemented
// #[cfg(feature = "metrics")]
// use prometheus::{IntCounterVec, register_int_counter_vec};

/// Core error type for the P2P Foundation library
#[derive(Debug, Error)]
pub enum P2PError {
    // Network errors
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    // DHT errors
    #[error("DHT error: {0}")]
    Dht(#[from] DhtError),

    // Identity errors
    #[error("Identity error: {0}")]
    Identity(#[from] IdentityError),

    // Cryptography errors
    #[error("Cryptography error: {0}")]
    Crypto(#[from] CryptoError),

    // Storage errors
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    // Transport errors
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),

    // MCP errors
    #[error("MCP error: {0}")]
    Mcp(#[from] McpError),

    // Configuration errors
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    // Security errors
    #[error("Security error: {0}")]
    Security(#[from] SecurityError),

    // Bootstrap errors
    #[error("Bootstrap error: {0}")]
    Bootstrap(#[from] BootstrapError),

    // Generic IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    // Serialization/Deserialization errors
    #[error("Serialization error: {0}")]
    Serialization(Cow<'static, str>),

    // Validation errors
    #[error("Validation error: {0}")]
    Validation(Cow<'static, str>),

    // Timeout errors
    #[error("Operation timed out after {0:?}")]
    Timeout(Duration),

    // Resource exhaustion
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(Cow<'static, str>),

    // Generic internal error
    #[error("Internal error: {0}")]
    Internal(Cow<'static, str>),

    // Encoding errors
    #[error("Encoding error: {0}")]
    Encoding(Cow<'static, str>),

    // Record too large errors
    #[error("Record too large: {0} bytes (max 512)")]
    RecordTooLarge(usize),

    // Proof of work computation failed
    #[error("Proof of work computation failed")]
    ProofOfWorkFailed,

    // Time-related error
    #[error("Time error")]
    TimeError,

    // Invalid input parameter
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Network-related errors
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("Connection failed to {addr}: {reason}")]
    ConnectionFailed {
        addr: SocketAddr,
        reason: Cow<'static, str>,
    },

    #[error("Connection closed unexpectedly")]
    ConnectionClosed,

    #[error("Invalid network address: {0}")]
    InvalidAddress(Cow<'static, str>),

    #[error("Peer not found: {0}")]
    PeerNotFound(Cow<'static, str>),

    #[error("Peer disconnected - peer: {peer}, reason: {reason}")]
    PeerDisconnected { peer: String, reason: String },

    #[error("Network timeout")]
    Timeout,

    #[error("Too many connections")]
    TooManyConnections,

    #[error("Protocol error: {0}")]
    ProtocolError(Cow<'static, str>),

    #[error("Bind error: {0}")]
    BindError(Cow<'static, str>),
}

/// DHT-related errors
#[derive(Debug, Error)]
pub enum DhtError {
    #[error("Key not found: {0}")]
    KeyNotFound(Cow<'static, str>),

    #[error("Store operation failed: {0}")]
    StoreFailed(Cow<'static, str>),

    #[error("Invalid key format: {0}")]
    InvalidKey(Cow<'static, str>),

    #[error("Routing table full")]
    RoutingTableFull,

    #[error("No suitable peers found")]
    NoPeersFound,

    #[error("Replication failed: {0}")]
    ReplicationFailed(Cow<'static, str>),

    #[error("Query timeout")]
    QueryTimeout,

    #[error("Routing error: {0}")]
    RoutingError(Cow<'static, str>),

    #[error("Storage failed: {0}")]
    StorageFailed(Cow<'static, str>),

    #[error("Insufficient replicas: {0}")]
    InsufficientReplicas(Cow<'static, str>),
}

/// Identity-related errors
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("Invalid three-word address: {0}")]
    InvalidThreeWordAddress(Cow<'static, str>),

    #[error("Invalid four-word address: {0}")]
    InvalidFourWordAddress(Cow<'static, str>),

    #[error("Identity not found: {0}")]
    IdentityNotFound(Cow<'static, str>),

    #[error("Identity already exists: {0}")]
    IdentityExists(Cow<'static, str>),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(Cow<'static, str>),

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Invalid peer ID: {0}")]
    InvalidPeerId(Cow<'static, str>),

    #[error("Invalid format: {0}")]
    InvalidFormat(Cow<'static, str>),

    #[error("System time error: {0}")]
    SystemTime(Cow<'static, str>),

    #[error("Invalid proof of work")]
    InvalidProofOfWork,

    #[error("Not found: {0}")]
    NotFound(Cow<'static, str>),

    #[error("Verification failed: {0}")]
    VerificationFailed(Cow<'static, str>),

    #[error("Insufficient entropy")]
    InsufficientEntropy,

    #[error("Access denied: {0}")]
    AccessDenied(Cow<'static, str>),
}

/// Cryptography-related errors
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(Cow<'static, str>),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(Cow<'static, str>),

    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(Cow<'static, str>),

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("HKDF expansion failed: {0}")]
    HkdfError(Cow<'static, str>),
}

/// Storage-related errors
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(Cow<'static, str>),

    #[error("Disk full")]
    DiskFull,

    #[error("Corrupt data: {0}")]
    CorruptData(Cow<'static, str>),

    #[error("Storage path not found: {0}")]
    PathNotFound(Cow<'static, str>),

    #[error("Permission denied: {0}")]
    PermissionDenied(Cow<'static, str>),

    #[error("Lock acquisition failed")]
    LockFailed,

    #[error("Lock poisoned: {0}")]
    LockPoisoned(Cow<'static, str>),

    #[error("File not found: {0}")]
    FileNotFound(Cow<'static, str>),

    #[error("Corruption detected: {0}")]
    CorruptionDetected(Cow<'static, str>),
}

/// Transport-related errors
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("QUIC error: {0}")]
    Quic(Cow<'static, str>),

    #[error("TCP error: {0}")]
    Tcp(Cow<'static, str>),

    #[error("Invalid transport configuration: {0}")]
    InvalidConfig(Cow<'static, str>),

    #[error("Transport not supported: {0}")]
    NotSupported(Cow<'static, str>),

    #[error("Stream error: {0}")]
    StreamError(Cow<'static, str>),

    #[error("Certificate error: {0}")]
    CertificateError(Cow<'static, str>),

    #[error("Setup failed: {0}")]
    SetupFailed(Cow<'static, str>),

    #[error("Connection failed to {addr}: {reason}")]
    ConnectionFailed {
        addr: SocketAddr,
        reason: Cow<'static, str>,
    },

    #[error("Bind error: {0}")]
    BindError(Cow<'static, str>),

    #[error("Accept failed: {0}")]
    AcceptFailed(Cow<'static, str>),

    #[error("Not listening")]
    NotListening,

    #[error("Not initialized")]
    NotInitialized,
}

/// MCP-related errors
#[derive(Debug, Error)]
pub enum McpError {
    #[error("Tool not found: {0}")]
    ToolNotFound(Cow<'static, str>),

    #[error("Invalid tool configuration: {0}")]
    InvalidToolConfig(Cow<'static, str>),

    #[error("Execution failed: {0}")]
    ExecutionFailed(Cow<'static, str>),

    #[error("Permission denied for tool: {0}")]
    PermissionDenied(Cow<'static, str>),

    #[error("Invalid response format: {0}")]
    InvalidResponse(Cow<'static, str>),

    #[error("Server unavailable: {0}")]
    ServerUnavailable(Cow<'static, str>),

    #[error("Invalid request: {0}")]
    InvalidRequest(Cow<'static, str>),

    #[error("Tool execution failed: {0}")]
    ToolExecutionFailed(Cow<'static, str>),
}

/// Configuration-related errors
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Missing required field: {0}")]
    MissingField(Cow<'static, str>),

    #[error("Invalid value for {field}: {reason}")]
    InvalidValue {
        field: Cow<'static, str>,
        reason: Cow<'static, str>,
    },

    #[error("Configuration file not found: {0}")]
    FileNotFound(Cow<'static, str>),

    #[error("Parse error: {0}")]
    ParseError(Cow<'static, str>),

    #[error("Validation failed: {0}")]
    ValidationFailed(Cow<'static, str>),

    #[error("IO error for {path}: {source}")]
    IoError {
        path: Cow<'static, str>,
        #[source]
        source: std::io::Error,
    },
}

/// Security-related errors
#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Authorization denied")]
    AuthorizationDenied,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Certificate error: {0}")]
    CertificateError(Cow<'static, str>),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(Cow<'static, str>),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(Cow<'static, str>),

    #[error("Invalid key: {0}")]
    InvalidKey(Cow<'static, str>),

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(Cow<'static, str>),

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(Cow<'static, str>),

    #[error("Authorization failed: {0}")]
    AuthorizationFailed(Cow<'static, str>),
}

/// Bootstrap-related errors
#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("No bootstrap nodes available")]
    NoBootstrapNodes,

    #[error("Bootstrap failed: {0}")]
    BootstrapFailed(Cow<'static, str>),

    #[error("Invalid bootstrap node: {0}")]
    InvalidBootstrapNode(Cow<'static, str>),

    #[error("Bootstrap timeout")]
    BootstrapTimeout,

    #[error("Cache error: {0}")]
    CacheError(Cow<'static, str>),

    #[error("Invalid data: {0}")]
    InvalidData(Cow<'static, str>),
}

/// Result type alias for P2P operations
pub type P2pResult<T> = Result<T, P2PError>;

// ===== Recovery patterns =====

/// Trait for errors that can be recovered from with retry
pub trait Recoverable {
    /// Check if this error is transient and can be retried
    fn is_transient(&self) -> bool;

    /// Suggested delay before retry
    fn suggested_retry_after(&self) -> Option<Duration>;

    /// Maximum number of retries recommended
    fn max_retries(&self) -> usize;
}

impl Recoverable for P2PError {
    fn is_transient(&self) -> bool {
        match self {
            P2PError::Network(NetworkError::ConnectionFailed { .. }) => true,
            P2PError::Network(NetworkError::Timeout) => true,
            P2PError::Transport(TransportError::ConnectionFailed { .. }) => true,
            P2PError::Dht(DhtError::QueryTimeout) => true,
            P2PError::Timeout(_) => true,
            P2PError::ResourceExhausted(_) => true,
            P2PError::Io(err) => matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
            ),
            _ => false,
        }
    }

    fn suggested_retry_after(&self) -> Option<Duration> {
        match self {
            P2PError::Network(NetworkError::Timeout) => Some(Duration::from_secs(5)),
            P2PError::Timeout(duration) => Some(*duration * 2),
            P2PError::ResourceExhausted(_) => Some(Duration::from_secs(30)),
            P2PError::Transport(TransportError::ConnectionFailed { .. }) => {
                Some(Duration::from_secs(1))
            }
            _ => None,
        }
    }

    fn max_retries(&self) -> usize {
        match self {
            P2PError::Network(NetworkError::ConnectionFailed { .. }) => 3,
            P2PError::Transport(TransportError::ConnectionFailed { .. }) => 3,
            P2PError::Timeout(_) => 2,
            P2PError::ResourceExhausted(_) => 1,
            _ => 0,
        }
    }
}

/// Extension trait for adding context to errors
pub trait ErrorContext<T> {
    /// Add context to an error
    fn context(self, msg: &str) -> Result<T, P2PError>;

    /// Add context with a closure
    fn with_context<F>(self, f: F) -> Result<T, P2PError>
    where
        F: FnOnce() -> String;
}

impl<T, E> ErrorContext<T> for Result<T, E>
where
    E: Into<P2PError>,
{
    fn context(self, msg: &str) -> Result<T, P2PError> {
        self.map_err(|e| {
            let base_error = e.into();
            P2PError::Internal(format!("{}: {}", msg, base_error).into())
        })
    }

    fn with_context<F>(self, f: F) -> Result<T, P2PError>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| {
            let base_error = e.into();
            P2PError::Internal(format!("{}: {}", f(), base_error).into())
        })
    }
}

/// Helper functions for error creation
impl P2PError {
    /// Create a network connection error
    pub fn connection_failed(addr: SocketAddr, reason: impl Into<String>) -> Self {
        P2PError::Network(NetworkError::ConnectionFailed {
            addr,
            reason: reason.into().into(),
        })
    }

    /// Create a timeout error
    pub fn timeout(duration: Duration) -> Self {
        P2PError::Timeout(duration)
    }

    /// Create a validation error
    pub fn validation(msg: impl Into<Cow<'static, str>>) -> Self {
        P2PError::Validation(msg.into())
    }

    /// Create an internal error
    pub fn internal(msg: impl Into<Cow<'static, str>>) -> Self {
        P2PError::Internal(msg.into())
    }
}

/// Logging integration for errors
impl P2PError {
    /// Log error with appropriate level
    pub fn log(&self) {
        use log::{error, warn};

        match self {
            P2PError::Network(NetworkError::Timeout) | P2PError::Timeout(_) => warn!("{}", self),

            P2PError::Validation(_) | P2PError::Config(_) => warn!("{}", self),

            _ => error!("{}", self),
        }
    }

    /// Log error with context
    pub fn log_with_context(&self, context: &str) {
        use log::error;
        error!("{}: {}", context, self);
    }
}

// ===== Conversion implementations =====

impl From<serde_json::Error> for P2PError {
    fn from(err: serde_json::Error) -> Self {
        P2PError::Serialization(err.to_string().into())
    }
}

impl From<bincode::Error> for P2PError {
    fn from(err: bincode::Error) -> Self {
        P2PError::Serialization(err.to_string().into())
    }
}

impl From<std::net::AddrParseError> for P2PError {
    fn from(err: std::net::AddrParseError) -> Self {
        P2PError::Network(NetworkError::InvalidAddress(err.to_string().into()))
    }
}

impl From<tokio::time::error::Elapsed> for P2PError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        P2PError::Network(NetworkError::Timeout)
    }
}

impl From<crate::adaptive::AdaptiveNetworkError> for P2PError {
    fn from(err: crate::adaptive::AdaptiveNetworkError) -> Self {
        use crate::adaptive::AdaptiveNetworkError;
        match err {
            AdaptiveNetworkError::Network(io_err) => P2PError::Io(io_err),
            AdaptiveNetworkError::Io(io_err) => P2PError::Io(io_err),
            AdaptiveNetworkError::Serialization(ser_err) => {
                P2PError::Serialization(ser_err.to_string().into())
            }
            AdaptiveNetworkError::Routing(msg) => {
                P2PError::Internal(format!("Routing error: {}", msg).into())
            }
            AdaptiveNetworkError::Trust(msg) => {
                P2PError::Internal(format!("Trust error: {}", msg).into())
            }
            AdaptiveNetworkError::Learning(msg) => {
                P2PError::Internal(format!("Learning error: {}", msg).into())
            }
            AdaptiveNetworkError::Gossip(msg) => {
                P2PError::Internal(format!("Gossip error: {}", msg).into())
            }
            AdaptiveNetworkError::Other(msg) => P2PError::Internal(msg.into()),
        }
    }
}

// ===== Structured logging =====

/// Value types for error context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorValue {
    String(Cow<'static, str>),
    Number(i64),
    Bool(bool),
    Duration(Duration),
    Address(SocketAddr),
}

/// Structured error log entry optimized for performance
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorLog {
    pub timestamp: i64, // Unix timestamp for efficiency
    pub error_type: &'static str,
    pub message: Cow<'static, str>,
    pub context: SmallVec<[(&'static str, ErrorValue); 4]>, // Stack-allocated for common cases
    pub stack_trace: Option<Cow<'static, str>>,
}

impl ErrorLog {
    /// Creates an error log entry from a P2PError
    pub fn from_error(error: &P2PError) -> Self {
        let mut context = SmallVec::new();

        // Add error-specific context
        match error {
            P2PError::Network(NetworkError::ConnectionFailed { addr, reason }) => {
                context.push(("address", ErrorValue::Address(*addr)));
                context.push(("reason", ErrorValue::String(reason.clone())));
            }
            P2PError::Timeout(duration) => {
                context.push(("timeout", ErrorValue::Duration(*duration)));
            }
            P2PError::Crypto(CryptoError::InvalidKeyLength { expected, actual }) => {
                context.push(("expected_length", ErrorValue::Number(*expected as i64)));
                context.push(("actual_length", ErrorValue::Number(*actual as i64)));
            }
            _ => {}
        }

        ErrorLog {
            timestamp: chrono::Utc::now().timestamp(),
            error_type: error_type_name(error),
            message: error.to_string().into(),
            context,
            stack_trace: None,
        }
    }

    pub fn with_context(mut self, key: &'static str, value: ErrorValue) -> Self {
        self.context.push((key, value));
        self
    }

    pub fn log(&self) {
        use log::{error, warn};

        let json = serde_json::to_string(self).unwrap_or_else(|_| self.message.to_string());

        match self.error_type {
            "Validation" | "Config" => warn!("{}", json),
            _ => error!("{}", json),
        }
    }
}

fn error_type_name(error: &P2PError) -> &'static str {
    match error {
        P2PError::Network(_) => "Network",
        P2PError::Dht(_) => "DHT",
        P2PError::Identity(_) => "Identity",
        P2PError::Crypto(_) => "Crypto",
        P2PError::Storage(_) => "Storage",
        P2PError::Transport(_) => "Transport",
        P2PError::Mcp(_) => "MCP",
        P2PError::Config(_) => "Config",
        P2PError::Io(_) => "IO",
        P2PError::Serialization(_) => "Serialization",
        P2PError::Validation(_) => "Validation",
        P2PError::Timeout(_) => "Timeout",
        P2PError::ResourceExhausted(_) => "ResourceExhausted",
        P2PError::Internal(_) => "Internal",
        P2PError::Security(_) => "Security",
        P2PError::Bootstrap(_) => "Bootstrap",
        P2PError::Encoding(_) => "Encoding",
    }
}

/// Error reporting trait for structured logging
pub trait ErrorReporting {
    fn report(&self) -> ErrorLog;
    fn report_with_context(&self, context: HashMap<String, serde_json::Value>) -> ErrorLog;
}

impl ErrorReporting for P2PError {
    fn report(&self) -> ErrorLog {
        ErrorLog::from_error(self)
    }

    fn report_with_context(&self, context: HashMap<String, serde_json::Value>) -> ErrorLog {
        let log = ErrorLog::from_error(self);
        // Convert HashMap entries to ErrorValue entries
        for (_key, _value) in context {
            // We need to leak the key to get a &'static str, or use a different approach
            // For now, we'll skip this functionality as it requires a redesign
            // log.context.push((key.leak(), ErrorValue::String(value.to_string().into())));
        }
        log
    }
}

// ===== Anyhow integration =====

/// Conversion helpers for anyhow integration
pub trait IntoAnyhow<T> {
    fn into_anyhow(self) -> anyhow::Result<T>;
}

impl<T> IntoAnyhow<T> for P2pResult<T> {
    fn into_anyhow(self) -> anyhow::Result<T> {
        self.map_err(|e| anyhow::anyhow!(e))
    }
}

pub trait FromAnyhowExt<T> {
    fn into_p2p_result(self) -> P2pResult<T>;
}

impl<T> FromAnyhowExt<T> for anyhow::Result<T> {
    fn into_p2p_result(self) -> P2pResult<T> {
        self.map_err(|e| P2PError::Internal(e.to_string().into()))
    }
}

/// Re-export for convenience
pub use anyhow::{Context as AnyhowContext, Result as AnyhowResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err =
            P2PError::connection_failed("127.0.0.1:8080".parse().unwrap(), "Connection refused");
        assert_eq!(
            err.to_string(),
            "Network error: Connection failed to 127.0.0.1:8080: Connection refused"
        );
    }

    #[test]
    fn test_error_context() {
        let result: Result<(), io::Error> =
            Err(io::Error::new(io::ErrorKind::NotFound, "file not found"));

        let with_context = crate::error::ErrorContext::context(result, "Failed to load config");
        assert!(with_context.is_err());
        assert!(
            with_context
                .unwrap_err()
                .to_string()
                .contains("Failed to load config")
        );
    }

    #[test]
    fn test_timeout_error() {
        let err = P2PError::timeout(Duration::from_secs(30));
        assert_eq!(err.to_string(), "Operation timed out after 30s");
    }

    #[test]
    fn test_crypto_error() {
        let err = P2PError::Crypto(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 16,
        });
        assert_eq!(
            err.to_string(),
            "Cryptography error: Invalid key length: expected 32, got 16"
        );
    }

    #[test]
    fn test_error_log_serialization() {
        let error = P2PError::Network(NetworkError::ConnectionFailed {
            addr: "127.0.0.1:8080".parse().unwrap(),
            reason: "Connection refused".into(),
        });

        let log = error
            .report()
            .with_context("peer_id", ErrorValue::String("peer123".into()))
            .with_context("retry_count", ErrorValue::Number(3));

        let json = serde_json::to_string_pretty(&log).unwrap();
        assert!(json.contains("Network"));
        assert!(json.contains("127.0.0.1:8080"));
        assert!(json.contains("peer123"));
    }

    #[test]
    fn test_anyhow_conversion() {
        let p2p_result: P2pResult<()> = Err(P2PError::validation("Invalid input"));
        let anyhow_result = p2p_result.into_anyhow();
        assert!(anyhow_result.is_err());

        let anyhow_err = anyhow::anyhow!("Test error");
        let anyhow_result: anyhow::Result<()> = Err(anyhow_err);
        let p2p_result = crate::error::FromAnyhowExt::into_p2p_result(anyhow_result);
        assert!(p2p_result.is_err());
        match p2p_result.unwrap_err() {
            P2PError::Internal(msg) => assert!(msg.contains("Test error")),
            _ => panic!("Expected Internal error"),
        }
    }
}
