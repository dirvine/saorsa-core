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
//! - **Phase 4**: VDF Heartbeats (Wesolowski VDFs) ✅
//!   - [`vdf`] module: VDF heartbeat generation and verification
//!   - [`HeartbeatChallenge`]: Challenge structure binding to identity
//!   - [`HeartbeatProof`]: VDF proof structure
//!   - [`VdfHeartbeat`]: Unified VDF manager (mock or real via `vdf` feature)
//!   - Uses Class Groups of Imaginary Quadratic Fields (no trusted setup)
//!   - 2048-bit discriminants for mainnet security
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
//! ### Phase 4 (Future)
//!
//! VDF heartbeats will prove continuous execution of attested binary, preventing
//! node impersonation after initial attestation.
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

mod config;
mod entangled_id;
pub mod handshake;
pub mod metrics;
pub mod proof_cache;
pub mod prover;
mod sunset;
mod types;
pub mod vdf;
pub mod verifier;
mod zkvm;

pub use config::{AttestationConfig, EnforcementMode};
pub use entangled_id::EntangledId;
pub use handshake::{
    AttestationHandshake, AttestationHello, AttestationVerificationResult, PeerAttestationStatus,
};
pub use metrics::{AttestationMetrics, AttestationMetricsCollector, VerificationTimer};
pub use proof_cache::ProofCache;
pub use prover::{AttestationProof, AttestationProver, MockAttestationProver, ProofType};
pub use sunset::SunsetTimestamp;
pub use types::{AttestationError, AttestationResult};
pub use vdf::{
    HeartbeatChallenge, HeartbeatNodeStatus, HeartbeatProof, HeartbeatVerificationResult,
    NodeHeartbeatStatus, VdfConfig, VdfHeartbeat, VdfProofType,
};
pub use verifier::{AttestationVerifier, AttestationVerifierConfig};
pub use zkvm::{AttestationProofPublicInputs, AttestationProofResult, AttestationProofWitness};

// Re-export saorsa-logic constants for downstream use
pub use entangled_id::{ENTANGLED_ID_SIZE, HASH_SIZE, ML_DSA_65_PUBLIC_KEY_SIZE};
