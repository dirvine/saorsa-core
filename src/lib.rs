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

// Enforce no unwrap/expect/panic in production code only (tests can use them)
#![cfg_attr(not(test), warn(clippy::unwrap_used))]
#![cfg_attr(not(test), warn(clippy::expect_used))]
#![cfg_attr(not(test), warn(clippy::panic))]
// Allow unused_async as many functions are async for API consistency
#![allow(clippy::unused_async)]

//! # Saorsa Core
//!
//! A next-generation peer-to-peer networking foundation built in Rust.
//!
//! ## Features
//!
//! - QUIC-based transport with NAT traversal
//! - IPv4-first with simple addressing
//! - Kademlia DHT for distributed routing
//! - Four-word human-readable addresses
//!
//! ## Example
//!
//! ```rust,ignore
//! use saorsa_core::{P2PNode, NodeConfig, NetworkAddress};
//! use std::str::FromStr;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let addr = "127.0.0.1:9000".parse::<NetworkAddress>()?;
//!     let node = P2PNode::builder()
//!         .listen_on(addr)
//!         .with_mcp_server()
//!         .build()
//!         .await?;
//!
//!     node.run().await?;
//!     Ok(())
//! }
//! ```

#![allow(missing_docs)]
#![allow(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

/// Four-word identifier system
pub mod fwid;

/// Public API matching the spec
pub mod api;

/// Network address types
pub mod address;
/// User directory mapping (UserId <-> FourWordAddress)
pub mod address_book;

/// Network core functionality
pub mod network;

/// Distributed Hash Table implementation
pub mod dht;

/// DHT Network Integration Manager
pub mod dht_network_manager;

/// Transport layer (QUIC, TCP)
pub mod transport;

/// Authentication system for multi-writer records
pub mod auth;

/// Async event bus for watches and state changes
pub mod events;
/// MLS verifier adapter and proof format
pub mod mls;
/// Shared simple structs
pub mod types;

/// Telemetry for metrics and health signals
pub mod telemetry;

// MCP removed; will be redesigned later

/// Security and cryptography
pub mod security;

/// User identity and privacy system
pub mod identity;

/// DHT-based storage for multi-device sync
pub mod storage;

// Re-export main API functions
pub use api::{
    GroupKeyPair,
    MemberRef,
    get_data,
    get_identity,
    get_presence,
    // Group API
    group_identity_canonical_sign_bytes,
    group_identity_create,
    group_identity_fetch,
    group_identity_publish,
    group_identity_update_members_signed,
    identity_fetch,
    register_headless,
    // Identity API
    register_identity,
    // Presence API
    register_presence,
    set_active_device,
    set_dht_client,
    // Storage API
    store_data,
    store_dyad,
    store_with_fec,
};

/// Chat system (Slack-like)
pub mod chat;

/// Rich messaging system (WhatsApp/Slack-style)
pub mod messaging;

/// Discuss system (Discourse-like)
pub mod discuss;

/// Projects system with hierarchical organization
pub mod projects;

/// Threshold cryptography for group operations
pub mod threshold;

/// Quantum-resistant cryptography
pub mod quantum_crypto;

/// Utility functions and types
pub mod utils;

/// Validation framework for input sanitization and rate limiting
pub mod validation;

/// Unified rate limiting engine
pub mod rate_limit;

/// Production hardening features
pub mod production;

/// Bootstrap cache for decentralized peer discovery
pub mod bootstrap;

/// Error types
pub mod error;

/// Peer record system for DHT-based peer discovery
pub mod peer_record;

/// Monotonic counter system for replay attack prevention
pub mod monotonic_counter;

/// Secure memory management for cryptographic operations
pub mod secure_memory;

/// Hierarchical key derivation system
pub mod key_derivation;

/// Encrypted key storage with Argon2id and ChaCha20-Poly1305
pub mod encrypted_key_storage;

/// Persistent state management with crash recovery
pub mod persistent_state;

/// Adaptive P2P network implementation
pub mod adaptive;

/// Configuration management system
pub mod config;

/// Health check system for monitoring and metrics
pub mod health;

/// Geographic-aware networking enhancements for P2P routing optimization
pub mod geographic_enhanced_network;

/// Placement Loop & Storage Orchestration System
pub mod placement;

/// Virtual disk for encrypted file storage
pub mod virtual_disk;

/// Entity-based system for unified identity, storage, and collaboration
pub mod entities;

/// Mock DHT for testing
#[cfg(any(test, feature = "test-utils"))]
pub mod mock_dht;

// Re-export main types
pub use address::{AddressBook, NetworkAddress};
pub use address_book::{
    address_book, get_user_by_four_words, get_user_four_words, register_user_address,
};
pub use identity::FourWordAddress;

// New spec-compliant API exports
pub use auth::{
    DelegatedWriteAuth, MlsWriteAuth, PubKey, Sig, SingleWriteAuth, ThresholdWriteAuth, WriteAuth,
};
pub use bootstrap::{BootstrapCache, BootstrapManager, CacheConfig, ContactEntry};
pub use dht::{Key, Record};
pub use dht_network_manager::{
    BootstrapNode, DhtNetworkConfig, DhtNetworkEvent, DhtNetworkManager, DhtNetworkOperation,
    DhtNetworkResult, DhtPeerInfo,
};
pub use encrypted_key_storage::{
    Argon2Config, DerivationPriority as KeyDerivationPriority, EncryptedKeyStorageManager,
    KeyMetadata, PasswordValidation, SecurityLevel, StorageStats,
};
pub use error::{P2PError, P2pResult as Result};
pub use events::{Subscription, TopologyEvent, device_subscribe, dht_watch, subscribe_topology};
pub use fwid::{FourWordsV1, Key as FwKey, fw_check, fw_to_key};
pub use health::{
    ComponentChecker, ComponentHealth, HealthEndpoints, HealthManager, HealthResponse,
    HealthServer, HealthStatus, PrometheusExporter,
};
pub use key_derivation::{
    BatchDerivationRequest, BatchDerivationResult, DerivationPath, DerivationPriority,
    DerivationStats, DerivedKey, HierarchicalKeyDerivation, MasterSeed,
};
pub use monotonic_counter::{
    BatchUpdateRequest, BatchUpdateResult, CounterStats, MonotonicCounterSystem, PeerCounter,
    SequenceValidationResult,
};
pub use network::{NodeBuilder, NodeConfig, P2PEvent, P2PNode};
pub use telemetry::{Metrics, StreamClass, record_lookup, record_timeout, telemetry};
// Back-compat exports for tests
pub use config::Config;
pub use network::P2PNode as Node;
pub use peer_record::{EndpointId, NatType, PeerDHTRecord, PeerEndpoint, SignatureCache, UserId};
pub use persistent_state::{
    FlushStrategy, IntegrityReport, PersistentStateManager, RecoveryMode, RecoveryStats,
    StateChangeEvent, StateConfig, TransactionType, WalEntry,
};
pub use production::{ProductionConfig, ResourceManager, ResourceMetrics};
pub use secure_memory::{
    PoolStats, SecureMemory, SecureMemoryPool, SecureString, SecureVec, allocate_secure,
    secure_string_with_capacity, secure_vec_with_capacity,
};
pub use validation::{
    RateLimitConfig, RateLimiter, Sanitize, Validate, ValidationContext, ValidationError,
    sanitize_string, validate_dht_key, validate_dht_value, validate_file_path,
    validate_message_size, validate_network_address, validate_peer_id,
};

// Enhanced identity removed

// Storage exports
pub use storage::{FileChunker, StorageManager}; // SyncManager temporarily disabled

// Chat exports
pub use chat::{Call, Channel, ChannelId, ChannelType, ChatManager, Message, MessageId, Thread};

// Discuss exports
pub use discuss::{
    Badge, Category, CategoryId, DiscussManager, Poll, Reply, ReplyId, Topic, TopicId, UserStats,
};

// Projects exports
pub use projects::{
    Document, DocumentId, Folder, Project, ProjectAnalytics, ProjectId, ProjectsManager,
    WorkflowState,
};

// Threshold exports
pub use threshold::{
    GroupMetadata, ParticipantInfo, ThresholdGroup, ThresholdGroupManager, ThresholdSignature,
};

// Post-quantum cryptography exports (using ant-quic types exclusively)
pub use quantum_crypto::{
    CryptoCapabilities,
    KemAlgorithm,
    NegotiatedAlgorithms,
    ProtocolVersion,
    // Core types and errors (compatibility layer only)
    QuantumCryptoError,
    SignatureAlgorithm,
    // Functions (compatibility layer only)
    negotiate_algorithms,
};

// Saorsa-PQC exports (primary and only post-quantum crypto types)
pub use quantum_crypto::{
    // Symmetric encryption (quantum-resistant)
    ChaCha20Poly1305Cipher,
    // Encrypted message types
    EncryptedMessage,
    // Hybrid modes (classical + post-quantum)
    HybridKem,
    HybridKemCiphertext,
    HybridKemPublicKey,
    HybridKemSecretKey,
    HybridPublicKeyEncryption,

    // HybridSignature,
    HybridSignaturePublicKey,
    HybridSignatureSecretKey,
    HybridSignatureValue,

    MlDsa65,

    MlDsaOperations,

    // Use ant-quic types for better trait implementations
    MlDsaPublicKey as AntMlDsaPublicKey,
    MlDsaSecretKey as AntMlDsaSecretKey,
    MlDsaSignature as AntMlDsaSignature,
    // Algorithm implementations
    MlKem768,
    MlKemCiphertext,
    // Core traits for operations
    MlKemOperations,
    // Key types
    MlKemPublicKey,
    MlKemSecretKey,
    // Errors and results
    PqcError,
    SaorsaPqcResult,

    SharedSecret,
    SymmetricEncryptedMessage,

    SymmetricError,
    SymmetricKey,

    // Library initialization
    saorsa_pqc_init,
};

// Legacy ant-quic integration (for backward compatibility only)
pub use quantum_crypto::ant_quic_integration::{
    // Configuration functions (deprecated - migrate to saorsa-pqc)
    create_default_pqc_config,
    create_pqc_only_config,
};

// Legacy types (deprecated - migrate to saorsa-pqc equivalents)
pub use quantum_crypto::types::{
    FrostCommitment,
    FrostGroupPublicKey,
    FrostKeyShare,
    // FROST threshold signatures (may need migration to saorsa-pqc later)
    FrostPublicKey,
    FrostSignature,
    // Session and group management types (still needed)
    GroupId,
    HandshakeParameters,

    ParticipantId,
    PeerId as QuantumPeerId,
    QuantumPeerIdentity,
    SecureSession,
    SessionId,
    SessionState,
};

// Placement system exports
pub use placement::{
    AuditSystem, DataPointer, DhtRecord, DiversityEnforcer, GeographicLocation, GroupBeacon,
    NetworkRegion, NodeAd, PlacementConfig, PlacementDecision, PlacementEngine, PlacementMetrics,
    PlacementOrchestrator, RegisterPointer, RepairSystem, StorageOrchestrator,
    WeightedPlacementStrategy,
};

// Network address types
/// Peer identifier used throughout Saorsa
///
/// Currently implemented as a String for simplicity, but can be enhanced
/// with cryptographic verification in future versions.
pub type PeerId = String;

/// Network address used for peer-to-peer communication
///
/// Supports both traditional IP:port format and human-readable four-word format.
pub type Multiaddr = NetworkAddress;

/// Saorsa Core version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
