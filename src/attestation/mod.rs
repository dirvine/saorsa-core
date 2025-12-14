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
//! - **Phase 3**: zkVM Integration (SP1/RISC Zero proofs)
//! - **Phase 4**: VDF Heartbeats (Wesolowski VDFs)
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
//! ### Future Phases (2+)
//!
//! The transition to using EntangledId as the canonical routing address will occur
//! incrementally:
//!
//! 1. **Phase 2**: EntangledId becomes part of the handshake protocol
//! 2. **Phase 3**: zkVM proofs validate that EntangledId was correctly derived
//! 3. **Phase 4**: VDF heartbeats prove continuous execution of attested binary
//!
//! Once these phases are complete, the network may transition to:
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
mod sunset;
mod types;
mod zkvm;

pub use config::{AttestationConfig, EnforcementMode};
pub use entangled_id::EntangledId;
pub use sunset::SunsetTimestamp;
pub use types::{AttestationError, AttestationResult};
pub use zkvm::{AttestationProofPublicInputs, AttestationProofResult, AttestationProofWitness};

// Re-export saorsa-logic constants for downstream use
pub use entangled_id::{ENTANGLED_ID_SIZE, HASH_SIZE, ML_DSA_65_PUBLIC_KEY_SIZE};
