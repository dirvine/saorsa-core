// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! # Entangled Attestation System
//!
//! This module implements the "Entangled Attestation" protocol for the Saorsa P2P network.
//! It provides cryptographic mechanisms to ensure nodes are running authorized software
//! without relying on centralized authorities or proprietary hardware.
//!
//! ## Core Concept
//!
//! A node's identity is mathematically "entangled" with:
//! - Its public key (ML-DSA-65)
//! - The hash of its executing binary
//! - A unique nonce
//!
//! This binding ensures that any modification to the software forces a change in identity,
//! preventing attackers from maintaining reputation while running malicious code.
//!
//! ## Phases
//!
//! - **Phase 1**: Entangled Identity (this module) ✅
//! - **Phase 2**: Core Logic Extraction (saorsa-logic) ✅
//!   - Pure derivation logic in `saorsa-logic` crate (no_std, zkVM-compatible)
//!   - Integration via `derive_entangled_id`, `verify_entangled_id`, `xor_distance`
//!   - zkVM proof structures defined in [`zkvm`] module
//! - **Phase 3**: zkVM Integration (SP1 proofs) ✅
//!   - [`prover`] module: Proof generation with `AttestationProver`
//!   - [`verifier`] module: Proof verification with `AttestationVerifier`
//!   - [`handshake`] module: Protocol for exchanging proofs during connection
//!   - [`metrics`] module: Observability for verification timing and success rates
//!   - Uses STARKs for post-quantum security (Groth16 available via feature flag)
//!   - Mock prover for testing, real SP1 prover with `zkvm-prover` feature
//!   - Groth16 verification with `zkvm-verifier-groth16` feature (NOT post-quantum)
//! - **Phase 4**: Lightweight Signed Heartbeats ✅
//!   - [`signed_heartbeat`] module: ML-DSA signed heartbeat proofs
//!   - [`SignedHeartbeat`]: Lightweight liveness proof (microseconds vs VDF seconds)
//!   - [`HeartbeatSigner`]: Generates signed heartbeats
//!   - No expensive VDF computation - suitable for resource-constrained devices
//!   - Multi-node-per-device deployment support
//! - **Phase 5**: Heartbeat Protocol Integration ✅
//!   - [`signed_heartbeat_manager`] module: Coordination of heartbeat lifecycle
//!   - [`SignedHeartbeatManager`]: Generates, verifies, and tracks heartbeats
//!   - [`network_resilience`] module: Intelligent network disruption handling
//!   - [`trust_integration`] module: EigenTrust integration for heartbeat compliance
//!   - Epoch-based scheduling with configurable intervals
//!   - Peer status tracking (Healthy → Suspect → Unresponsive)
//!   - Trust score adjustments based on heartbeat compliance
//!   - Network resilience: startup grace, partition detection, quiescence handling
//!
//! ## NodeId vs EntangledId Transition Plan
//!
//! ### Current State (Phase 1)
//!
//! - **NodeId**: `SHA256(public_key)` - 32 bytes, used for DHT routing
//! - **EntangledId**: `BLAKE3(public_key || binary_hash || nonce)` - 32 bytes
//!
//! These are currently **different values**. NodeId is the legacy routing identity,
//! while EntangledId is the software-attested identity.
//!
//! ### Phase 1 Behavior
//!
//! - NodeId remains the primary routing address for DHT operations
//! - EntangledId is exchanged during handshake for attestation verification
//! - Verification failures are **logged only** (soft enforcement)
//! - No connections are rejected based on attestation
//!
//! ### Current Implementation (Phases 1-3 Complete)
//!
//! The attestation system now provides:
//!
//! 1. **EntangledId derivation**: Cryptographic binding of identity to software
//! 2. **Handshake protocol**: [`AttestationHello`] exchange during connection
//! 3. **zkVM proofs**: Verify correct EntangledId derivation without revealing secrets
//! 4. **Enforcement modes**: [`EnforcementMode::Soft`] (current) logs but doesn't reject
//!
//! ### Phase 4-5 (Complete)
//!
//! Signed heartbeats prove continuous liveness using ML-DSA signatures.
//! Network resilience handles partitions, quiescence, and graceful recovery.
//!
//! ### Full Migration (Future)
//!
//! Once Phase 4 is complete, the network may transition to:
//! - **NodeId == EntangledId** for fully attested nodes
//! - Legacy NodeId supported during migration with configurable enforcement
//!
//! ### Migration Considerations
//!
//! - Nodes can derive their EntangledId at any time using [`EntangledId::derive`]
//! - The `to_node_id()` method converts an EntangledId to a NodeId for DHT routing
//! - During transition, nodes should support both addressing schemes
//! - The enforcement mode (`Soft` → `Hard`) will be configurable per-node
//!
//! ## Example
//!
//! ```rust,ignore
//! use saorsa_core::attestation::{EntangledId, AttestationConfig};
//! use saorsa_core::quantum_crypto::generate_ml_dsa_keypair;
//!
//! // Generate a keypair
//! let (public_key, _secret_key) = generate_ml_dsa_keypair()?;
//!
//! // Hash of the running binary
//! let binary_hash = compute_binary_hash();
//!
//! // Derive entangled identity
//! let nonce = 12345u64;
//! let entangled_id = EntangledId::derive(&public_key, &binary_hash, nonce);
//!
//! // Verify the identity
//! assert!(entangled_id.verify(&public_key));
//! ```

pub mod batch_verifier;
pub mod blacklist;
mod config;
mod entangled_id;
pub mod handshake;
pub mod metrics;
pub mod network_resilience;
pub mod proof_cache;
pub mod prover;
pub mod proving_service;
pub mod security;
pub mod signed_handshake;
pub mod signed_heartbeat;
pub mod signed_heartbeat_manager;
mod sunset;
pub mod trust_integration;
mod types;
pub mod verification_cache;
pub mod verifier;
mod zkvm;

pub use batch_verifier::{
    BatchVerificationResult, BatchVerifier, BatchVerifierConfig, VerificationRequest,
};
pub use blacklist::{AttestationBlacklist, BlacklistConfig, BlacklistEntry, BlacklistStats};
pub use config::{AttestationConfig, EnforcementMode};
pub use entangled_id::EntangledId;
pub use handshake::{
    AttestationHandshake, AttestationHello, AttestationRejection, AttestationRejectionReason,
    AttestationVerificationResult, EnforcementDecision, PeerAttestationStatus,
};
pub use metrics::{AttestationMetrics, AttestationMetricsCollector, VerificationTimer};
pub use network_resilience::{
    HealthyRatioTracker, HeartbeatAction, HeartbeatDecisionEngine, NetworkHealthContext,
    PersistedNetworkState, PersistedPeerState, QuiescenceDetector, RecoveryHandler,
    ResilienceConfig,
};
pub use proof_cache::ProofCache;
pub use prover::{AttestationProof, AttestationProver, MockAttestationProver, ProofType};
pub use proving_service::{
    ProofRequest, ProofRequestError, ProofResponse, ProvingClient, ProvingClientConfig,
    ProvingService, ProvingServiceConfig, ProvingServiceStats,
};
pub use security::{
    NonceRegistry, NonceRegistryConfig, NonceRegistryStats, SecurityAuditLog, SecurityAuditSummary,
    SecurityEvent, SecurityEventType, SecuritySeverity, ct_eq, ct_eq_16, ct_eq_32,
    generate_ownership_challenge, verify_ownership,
};
pub use signed_handshake::{
    HandshakeChallenge, HandshakeHelloData, HandshakeVerifyResult, SignedHandshake,
    SignedHandshakeConfig, SignedHandshakeResponse, SignedHandshakeVerifier,
};
pub use signed_heartbeat::{
    HeartbeatConfig as SignedHeartbeatConfig, HeartbeatSigner, HeartbeatVerifyResult,
    SignedHeartbeat,
};
pub use signed_heartbeat_manager::{
    DisconnectReason, SIGNED_HEARTBEAT_GOSSIP_TOPIC, SignedHeartbeatHello, SignedHeartbeatManager,
    SignedHeartbeatMessage, SignedHeartbeatStats, SignedHeartbeatTrustCallback,
    SignedPeerHeartbeatState, SignedPeerStatus,
};
pub use sunset::SunsetTimestamp;
pub use trust_integration::{HeartbeatTrustConfig, HeartbeatTrustIntegration};
pub use types::{AttestationError, AttestationResult};
pub use verification_cache::{
    VerificationCache, VerificationCacheConfig, VerificationCacheMetrics,
};
pub use verifier::{AttestationVerifier, AttestationVerifierConfig};
pub use zkvm::{AttestationProofPublicInputs, AttestationProofResult, AttestationProofWitness};

// Re-export saorsa-logic constants for downstream use
pub use entangled_id::{ENTANGLED_ID_SIZE, HASH_SIZE, ML_DSA_65_PUBLIC_KEY_SIZE};
