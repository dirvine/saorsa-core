// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Attestation error types and common definitions.

use thiserror::Error;

/// Errors that can occur during attestation operations.
#[derive(Debug, Error)]
pub enum AttestationError {
    /// The entangled identity verification failed.
    #[error("Entangled identity verification failed: {reason}")]
    VerificationFailed {
        /// Reason for the failure.
        reason: String,
    },

    /// The binary hash is not in the allowed list.
    #[error("Binary hash not allowed: {hash}")]
    BinaryNotAllowed {
        /// The disallowed binary hash (hex-encoded).
        hash: String,
    },

    /// The binary version has expired (past sunset timestamp).
    #[error("Binary version expired: sunset at {sunset_time}")]
    VersionExpired {
        /// The sunset timestamp when the version expired.
        sunset_time: u64,
    },

    /// The node is in probationary mode and cannot perform this operation.
    #[error("Node is in probationary mode")]
    ProbationaryMode,

    /// Invalid nonce provided.
    #[error("Invalid nonce: {reason}")]
    InvalidNonce {
        /// Reason the nonce is invalid.
        reason: String,
    },

    /// Cryptographic operation failed.
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Serialization/deserialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid or malformed proof.
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
}

/// Result type for attestation operations.
pub type AttestationResult<T> = std::result::Result<T, AttestationError>;
