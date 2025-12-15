// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Network Proving Service (Phase 6C).
//!
//! This module provides a proving service for resource-constrained nodes
//! (e.g., Raspberry Pi) that cannot generate their own zkVM proofs.
//!
//! ## Security Model
//!
//! The proving service only needs PUBLIC information to generate proofs:
//! - Public key (ML-DSA-65, 1952 bytes)
//! - Binary hash (32 bytes)
//! - Nonce (8 bytes)
//!
//! **No private keys are transmitted.** The proof only demonstrates correct
//! EntangledId derivation. Key ownership is proven separately via ML-DSA
//! signatures during the handshake protocol.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────┐         ┌─────────────────────┐
//! │  Resource-Limited   │         │   Proving Service   │
//! │       Node          │         │   (GPU/Powerful)    │
//! │                     │         │                     │
//! │  1. Create request  │────────▶│  2. Validate req    │
//! │     (pub_key,       │         │  3. Generate proof  │
//! │      bin_hash,      │         │     (SP1 zkVM)      │
//! │      nonce)         │◀────────│  4. Return proof    │
//! │                     │         │                     │
//! │  5. Cache & use     │         │                     │
//! │     proof locally   │         │                     │
//! └─────────────────────┘         └─────────────────────┘
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! // Client side (resource-constrained node)
//! let client = ProvingClient::new(service_url, ProvingClientConfig::default());
//! let request = ProofRequest::new(public_key, binary_hash, nonce);
//! let proof = client.request_proof(&request).await?;
//!
//! // Server side (proving service)
//! let service = ProvingService::new(prover, ProvingServiceConfig::default());
//! let proof = service.generate_proof(&request).await?;
//! ```

use super::{
    AttestationError,
    prover::{AttestationProof, AttestationProver},
    zkvm::AttestationProofWitness,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{
    RwLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Counter for generating unique request IDs.
static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request for proof generation from the proving service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequest {
    /// Unique request ID for tracking.
    pub request_id: [u8; 16],

    /// ML-DSA-65 public key (1952 bytes).
    pub public_key: Vec<u8>,

    /// Binary hash to bind the identity to.
    pub binary_hash: [u8; 32],

    /// Nonce for uniqueness.
    pub nonce: u64,

    /// Unix timestamp when request was created.
    pub timestamp: u64,

    /// Optional signature proving key ownership (ML-DSA signature over request_id).
    /// This prevents unauthorized parties from requesting proofs for others' keys.
    pub ownership_signature: Option<Vec<u8>>,
}

impl ProofRequest {
    /// Create a new proof request.
    pub fn new(public_key: Vec<u8>, binary_hash: [u8; 32], nonce: u64) -> Self {
        // Generate unique request ID from counter + timestamp + nonce
        let counter = REQUEST_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
        let timestamp = current_timestamp();
        let request_id = generate_request_id(counter, timestamp, nonce);

        Self {
            request_id,
            public_key,
            binary_hash,
            nonce,
            timestamp,
            ownership_signature: None,
        }
    }

    /// Add ownership signature to the request.
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.ownership_signature = Some(signature);
        self
    }

    /// Get the data that should be signed for ownership proof.
    #[must_use]
    pub fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(16 + 32 + 8);
        data.extend_from_slice(&self.request_id);
        data.extend_from_slice(&self.binary_hash);
        data.extend_from_slice(&self.nonce.to_le_bytes());
        data
    }

    /// Convert to attestation proof witness.
    #[must_use]
    pub fn to_witness(&self) -> AttestationProofWitness {
        AttestationProofWitness {
            public_key: self.public_key.clone(),
            binary_hash: self.binary_hash,
            nonce: self.nonce,
            allowed_binaries: vec![], // Service doesn't enforce allowlist
            timestamp: self.timestamp,
        }
    }

    /// Validate the request structure.
    pub fn validate(&self) -> Result<(), ProofRequestError> {
        // Check public key size (ML-DSA-65 = 1952 bytes)
        if self.public_key.len() != 1952 {
            return Err(ProofRequestError::InvalidPublicKeySize {
                expected: 1952,
                actual: self.public_key.len(),
            });
        }

        // Check timestamp freshness (within 5 minutes)
        let now = current_timestamp();
        let age = now.saturating_sub(self.timestamp);
        if age > 300 {
            return Err(ProofRequestError::RequestExpired { age_secs: age });
        }

        // Check for future timestamps (clock skew tolerance: 60 seconds)
        if self.timestamp > now + 60 {
            return Err(ProofRequestError::FutureTimestamp);
        }

        Ok(())
    }
}

/// Response from the proving service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResponse {
    /// The original request ID this response is for.
    pub request_id: [u8; 16],

    /// The generated proof (if successful).
    pub proof: Option<AttestationProof>,

    /// Error message (if failed).
    pub error: Option<String>,

    /// Time taken to generate the proof in milliseconds.
    pub generation_time_ms: u64,

    /// Unix timestamp of response.
    pub timestamp: u64,
}

impl ProofResponse {
    /// Create a successful response.
    pub fn success(request_id: [u8; 16], proof: AttestationProof, generation_time_ms: u64) -> Self {
        Self {
            request_id,
            proof: Some(proof),
            error: None,
            generation_time_ms,
            timestamp: current_timestamp(),
        }
    }

    /// Create a failed response.
    pub fn failure(request_id: [u8; 16], error: String) -> Self {
        Self {
            request_id,
            proof: None,
            error: Some(error),
            generation_time_ms: 0,
            timestamp: current_timestamp(),
        }
    }

    /// Check if the response contains a valid proof.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.proof.is_some() && self.error.is_none()
    }
}

/// Errors that can occur during proof request processing.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProofRequestError {
    #[error("Invalid public key size: expected {expected}, got {actual}")]
    InvalidPublicKeySize { expected: usize, actual: usize },

    #[error("Request expired: {age_secs} seconds old")]
    RequestExpired { age_secs: u64 },

    #[error("Request timestamp is in the future")]
    FutureTimestamp,

    #[error("Missing ownership signature")]
    MissingSignature,

    #[error("Invalid ownership signature")]
    InvalidSignature,

    #[error("Rate limit exceeded: try again in {retry_after_secs} seconds")]
    RateLimited { retry_after_secs: u64 },

    #[error("Service unavailable: {reason}")]
    ServiceUnavailable { reason: String },

    #[error("Proof generation failed: {reason}")]
    GenerationFailed { reason: String },
}

// ============================================================================
// Rate Limiting
// ============================================================================

/// Rate limiter for proof requests.
#[derive(Debug)]
struct RateLimiter {
    /// Requests per key (keyed by public key hash).
    requests: HashMap<[u8; 32], Vec<Instant>>,

    /// Maximum requests per window.
    max_requests: usize,

    /// Window duration.
    window: Duration,
}

impl RateLimiter {
    fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            requests: HashMap::new(),
            max_requests,
            window,
        }
    }

    /// Check if a request is allowed and record it if so.
    fn check_and_record(&mut self, key_hash: &[u8; 32]) -> Result<(), u64> {
        let now = Instant::now();
        // Use checked_sub to handle potential overflow on Windows where Instant
        // represents time since boot and may overflow if window is large
        let cutoff = now.checked_sub(self.window);

        // Get or create entry for this key
        let timestamps = self.requests.entry(*key_hash).or_default();

        // Remove old timestamps (if cutoff overflowed, keep all timestamps as they're all "recent")
        if let Some(cutoff_time) = cutoff {
            timestamps.retain(|t| *t > cutoff_time);
        }

        // Check if under limit
        if timestamps.len() >= self.max_requests {
            // Calculate retry time
            if let Some(oldest) = timestamps.first() {
                let retry_after = self.window.saturating_sub(oldest.elapsed());
                return Err(retry_after.as_secs());
            }
            return Err(self.window.as_secs());
        }

        // Record this request
        timestamps.push(now);
        Ok(())
    }

    /// Cleanup old entries to prevent memory growth.
    fn cleanup(&mut self) {
        let now = Instant::now();
        let cutoff = now - self.window;

        self.requests.retain(|_, timestamps| {
            timestamps.retain(|t| *t > cutoff);
            !timestamps.is_empty()
        });
    }
}

// ============================================================================
// Proving Service
// ============================================================================

/// Configuration for the proving service.
#[derive(Debug, Clone)]
pub struct ProvingServiceConfig {
    /// Whether to require ownership signatures.
    pub require_signature: bool,

    /// Maximum requests per key per hour.
    pub rate_limit_per_hour: usize,

    /// Maximum concurrent proof generations.
    pub max_concurrent: usize,

    /// Request timeout in seconds.
    pub request_timeout_secs: u64,
}

impl Default for ProvingServiceConfig {
    fn default() -> Self {
        Self {
            require_signature: true,
            rate_limit_per_hour: 10,
            max_concurrent: 4,
            request_timeout_secs: 600, // 10 minutes for proof gen
        }
    }
}

impl ProvingServiceConfig {
    /// Create a permissive config for testing.
    #[must_use]
    pub fn testing() -> Self {
        Self {
            require_signature: false,
            rate_limit_per_hour: 1000,
            max_concurrent: 1,
            request_timeout_secs: 60,
        }
    }

    /// Create a strict config for production.
    #[must_use]
    pub fn production() -> Self {
        Self {
            require_signature: true,
            rate_limit_per_hour: 5,
            max_concurrent: 8,
            request_timeout_secs: 1800, // 30 minutes
        }
    }
}

/// Statistics for the proving service.
#[derive(Debug, Clone, Default)]
pub struct ProvingServiceStats {
    /// Total requests received.
    pub total_requests: u64,

    /// Successful proof generations.
    pub successful_proofs: u64,

    /// Failed proof generations.
    pub failed_proofs: u64,

    /// Requests rejected due to rate limiting.
    pub rate_limited: u64,

    /// Requests rejected due to validation errors.
    pub validation_errors: u64,

    /// Total proof generation time in milliseconds.
    pub total_generation_time_ms: u64,

    /// Currently active proof generations.
    pub active_generations: usize,
}

impl ProvingServiceStats {
    /// Calculate average proof generation time.
    #[must_use]
    pub fn avg_generation_time_ms(&self) -> u64 {
        if self.successful_proofs == 0 {
            0
        } else {
            self.total_generation_time_ms / self.successful_proofs
        }
    }

    /// Calculate success rate as a percentage.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let total = self.successful_proofs + self.failed_proofs;
        if total == 0 {
            100.0
        } else {
            (self.successful_proofs as f64 / total as f64) * 100.0
        }
    }
}

/// Network proving service for resource-constrained nodes.
#[derive(Debug)]
pub struct ProvingService {
    /// The underlying prover.
    prover: AttestationProver,

    /// Service configuration.
    config: ProvingServiceConfig,

    /// Rate limiter.
    rate_limiter: RwLock<RateLimiter>,

    /// Service statistics.
    stats: RwLock<ProvingServiceStats>,
}

impl ProvingService {
    /// Create a new proving service.
    pub fn new(prover: AttestationProver, config: ProvingServiceConfig) -> Self {
        let rate_limiter = RateLimiter::new(
            config.rate_limit_per_hour,
            Duration::from_secs(3600), // 1 hour window
        );

        Self {
            prover,
            config,
            rate_limiter: RwLock::new(rate_limiter),
            stats: RwLock::new(ProvingServiceStats::default()),
        }
    }

    /// Process a proof request.
    pub fn process_request(&self, request: &ProofRequest) -> ProofResponse {
        // Record request
        self.increment_requests();

        // Validate request
        if let Err(e) = request.validate() {
            self.increment_validation_errors();
            return ProofResponse::failure(request.request_id, e.to_string());
        }

        // Check ownership signature if required
        if self.config.require_signature {
            let Some(signature) = &request.ownership_signature else {
                self.increment_validation_errors();
                return ProofResponse::failure(
                    request.request_id,
                    ProofRequestError::MissingSignature.to_string(),
                );
            };

            // Verify ML-DSA signature over the signing data
            let challenge = request.signing_data();
            if !super::security::verify_ownership(&request.public_key, &challenge, signature) {
                self.increment_validation_errors();
                tracing::warn!(
                    request_id = hex::encode(&request.request_id[..8]),
                    "Invalid ownership signature in proof request"
                );
                return ProofResponse::failure(
                    request.request_id,
                    ProofRequestError::InvalidSignature.to_string(),
                );
            }
        }

        // Check rate limit
        let key_hash = hash_public_key(&request.public_key);
        if let Err(retry_after) = self.check_rate_limit(&key_hash) {
            self.increment_rate_limited();
            return ProofResponse::failure(
                request.request_id,
                ProofRequestError::RateLimited {
                    retry_after_secs: retry_after,
                }
                .to_string(),
            );
        }

        // Generate proof
        let start = Instant::now();
        self.increment_active();

        let witness = request.to_witness();
        let result = self.prover.generate_proof(&witness);

        self.decrement_active();
        let generation_time_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(proof) => {
                self.record_success(generation_time_ms);
                ProofResponse::success(request.request_id, proof, generation_time_ms)
            }
            Err(e) => {
                self.increment_failed();
                ProofResponse::failure(
                    request.request_id,
                    ProofRequestError::GenerationFailed {
                        reason: e.to_string(),
                    }
                    .to_string(),
                )
            }
        }
    }

    /// Check rate limit for a key.
    fn check_rate_limit(&self, key_hash: &[u8; 32]) -> Result<(), u64> {
        let Ok(mut limiter) = self.rate_limiter.write() else {
            return Ok(()); // If lock fails, allow request
        };
        limiter.check_and_record(key_hash)
    }

    /// Get service statistics.
    #[must_use]
    pub fn stats(&self) -> ProvingServiceStats {
        self.stats.read().map(|s| s.clone()).unwrap_or_default()
    }

    /// Cleanup rate limiter to free memory.
    pub fn cleanup(&self) {
        if let Ok(mut limiter) = self.rate_limiter.write() {
            limiter.cleanup();
        }
    }

    // Stats helpers
    fn increment_requests(&self) {
        if let Ok(mut stats) = self.stats.write() {
            stats.total_requests += 1;
        }
    }

    fn increment_validation_errors(&self) {
        if let Ok(mut stats) = self.stats.write() {
            stats.validation_errors += 1;
        }
    }

    fn increment_rate_limited(&self) {
        if let Ok(mut stats) = self.stats.write() {
            stats.rate_limited += 1;
        }
    }

    fn increment_active(&self) {
        if let Ok(mut stats) = self.stats.write() {
            stats.active_generations += 1;
        }
    }

    fn decrement_active(&self) {
        if let Ok(mut stats) = self.stats.write() {
            stats.active_generations = stats.active_generations.saturating_sub(1);
        }
    }

    fn record_success(&self, generation_time_ms: u64) {
        if let Ok(mut stats) = self.stats.write() {
            stats.successful_proofs += 1;
            stats.total_generation_time_ms += generation_time_ms;
        }
    }

    fn increment_failed(&self) {
        if let Ok(mut stats) = self.stats.write() {
            stats.failed_proofs += 1;
        }
    }
}

// ============================================================================
// Proving Client
// ============================================================================

/// Configuration for the proving client.
#[derive(Debug, Clone)]
pub struct ProvingClientConfig {
    /// Service endpoint URL.
    pub service_url: String,

    /// Request timeout in seconds.
    pub timeout_secs: u64,

    /// Number of retry attempts.
    pub max_retries: u32,

    /// Backoff between retries in seconds.
    pub retry_backoff_secs: u64,
}

impl Default for ProvingClientConfig {
    fn default() -> Self {
        Self {
            service_url: String::new(),
            timeout_secs: 600,
            max_retries: 3,
            retry_backoff_secs: 30,
        }
    }
}

/// Client for requesting proofs from a network proving service.
#[derive(Debug, Clone)]
pub struct ProvingClient {
    config: ProvingClientConfig,
}

impl ProvingClient {
    /// Create a new proving client.
    pub fn new(config: ProvingClientConfig) -> Self {
        Self { config }
    }

    /// Create a proof request.
    pub fn create_request(
        &self,
        public_key: Vec<u8>,
        binary_hash: [u8; 32],
        nonce: u64,
    ) -> ProofRequest {
        ProofRequest::new(public_key, binary_hash, nonce)
    }

    /// Get the service URL.
    #[must_use]
    pub fn service_url(&self) -> &str {
        &self.config.service_url
    }

    /// Serialize a request for transmission.
    pub fn serialize_request(&self, request: &ProofRequest) -> Result<Vec<u8>, AttestationError> {
        serde_json::to_vec(request).map_err(|e| {
            AttestationError::SerializationError(format!("Failed to serialize request: {e}"))
        })
    }

    /// Deserialize a response.
    pub fn deserialize_response(&self, data: &[u8]) -> Result<ProofResponse, AttestationError> {
        serde_json::from_slice(data).map_err(|e| {
            AttestationError::SerializationError(format!("Failed to deserialize response: {e}"))
        })
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Hash a public key to a 32-byte value.
fn hash_public_key(public_key: &[u8]) -> [u8; 32] {
    *blake3::hash(public_key).as_bytes()
}

/// Generate a unique request ID from counter, timestamp, and nonce.
fn generate_request_id(counter: u64, timestamp: u64, nonce: u64) -> [u8; 16] {
    // Combine inputs using BLAKE3 and take first 16 bytes
    let mut input = [0u8; 24];
    input[0..8].copy_from_slice(&counter.to_le_bytes());
    input[8..16].copy_from_slice(&timestamp.to_le_bytes());
    input[16..24].copy_from_slice(&nonce.to_le_bytes());

    let hash = blake3::hash(&input);
    let mut request_id = [0u8; 16];
    request_id.copy_from_slice(&hash.as_bytes()[0..16]);
    request_id
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::prover::ProofType;

    fn create_test_public_key() -> Vec<u8> {
        vec![0x42u8; 1952] // ML-DSA-65 public key size
    }

    #[test]
    fn test_proof_request_new() {
        let pk = create_test_public_key();
        let binary_hash = [0x11u8; 32];
        let nonce = 12345u64;

        let request = ProofRequest::new(pk.clone(), binary_hash, nonce);

        assert_eq!(request.public_key, pk);
        assert_eq!(request.binary_hash, binary_hash);
        assert_eq!(request.nonce, nonce);
        assert!(request.ownership_signature.is_none());
    }

    #[test]
    fn test_proof_request_validate_success() {
        let request = ProofRequest::new(create_test_public_key(), [0u8; 32], 0);
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_proof_request_validate_invalid_key_size() {
        let mut request = ProofRequest::new(create_test_public_key(), [0u8; 32], 0);
        request.public_key = vec![0u8; 100]; // Wrong size

        let result = request.validate();
        assert!(matches!(
            result,
            Err(ProofRequestError::InvalidPublicKeySize { .. })
        ));
    }

    #[test]
    fn test_proof_request_validate_expired() {
        let mut request = ProofRequest::new(create_test_public_key(), [0u8; 32], 0);
        request.timestamp = current_timestamp() - 400; // 6+ minutes ago

        let result = request.validate();
        assert!(matches!(
            result,
            Err(ProofRequestError::RequestExpired { .. })
        ));
    }

    #[test]
    fn test_proof_response_success() {
        use crate::attestation::AttestationProofPublicInputs;

        let proof = AttestationProof {
            proof_bytes: vec![1, 2, 3],
            public_inputs: AttestationProofPublicInputs {
                entangled_id: [0u8; 32],
                binary_hash: [0u8; 32],
                public_key_hash: [0u8; 32],
                proof_timestamp: 0,
            },
            vkey_hash: [0u8; 32],
            proof_type: ProofType::Mock,
        };

        let response = ProofResponse::success([0u8; 16], proof, 1000);
        assert!(response.is_success());
        assert!(response.proof.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_proof_response_failure() {
        let response = ProofResponse::failure([0u8; 16], "Test error".to_string());
        assert!(!response.is_success());
        assert!(response.proof.is_none());
        assert!(response.error.is_some());
    }

    #[test]
    fn test_proving_service_process_request() {
        let prover = AttestationProver::mock();
        let config = ProvingServiceConfig::testing();
        let service = ProvingService::new(prover, config);

        let request = ProofRequest::new(create_test_public_key(), [0x11u8; 32], 12345);

        let response = service.process_request(&request);

        assert!(response.is_success());
        assert!(response.proof.is_some());
    }

    #[test]
    fn test_proving_service_invalid_request() {
        let prover = AttestationProver::mock();
        let config = ProvingServiceConfig::testing();
        let service = ProvingService::new(prover, config);

        let mut request = ProofRequest::new(create_test_public_key(), [0x11u8; 32], 12345);
        request.public_key = vec![0u8; 100]; // Invalid size

        let response = service.process_request(&request);

        assert!(!response.is_success());
        assert!(response.error.is_some());
    }

    #[test]
    fn test_proving_service_rate_limit() {
        let prover = AttestationProver::mock();
        let config = ProvingServiceConfig {
            require_signature: false,
            rate_limit_per_hour: 2,
            max_concurrent: 1,
            request_timeout_secs: 60,
        };
        let service = ProvingService::new(prover, config);

        let pk = create_test_public_key();

        // First two requests should succeed
        let request1 = ProofRequest::new(pk.clone(), [0x11u8; 32], 1);
        assert!(service.process_request(&request1).is_success());

        let request2 = ProofRequest::new(pk.clone(), [0x11u8; 32], 2);
        assert!(service.process_request(&request2).is_success());

        // Third request should be rate limited
        let request3 = ProofRequest::new(pk, [0x11u8; 32], 3);
        let response = service.process_request(&request3);
        assert!(!response.is_success());
        assert!(response.error.unwrap().contains("Rate limit"));
    }

    #[test]
    fn test_proving_service_stats() {
        let prover = AttestationProver::mock();
        let config = ProvingServiceConfig::testing();
        let service = ProvingService::new(prover, config);

        // Process a request
        let request = ProofRequest::new(create_test_public_key(), [0x11u8; 32], 12345);
        let _ = service.process_request(&request);

        let stats = service.stats();
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.successful_proofs, 1);
        assert_eq!(stats.failed_proofs, 0);
    }

    #[test]
    fn test_proving_client_serialize_request() {
        let client = ProvingClient::new(ProvingClientConfig::default());
        let request = client.create_request(create_test_public_key(), [0u8; 32], 0);

        let serialized = client.serialize_request(&request);
        assert!(serialized.is_ok());

        let response = ProofResponse::failure([0u8; 16], "test".to_string());
        let response_bytes = serde_json::to_vec(&response).unwrap();
        let deserialized = client.deserialize_response(&response_bytes);
        assert!(deserialized.is_ok());
    }

    #[test]
    fn test_config_presets() {
        let testing = ProvingServiceConfig::testing();
        assert!(!testing.require_signature);
        assert_eq!(testing.rate_limit_per_hour, 1000);

        let production = ProvingServiceConfig::production();
        assert!(production.require_signature);
        assert_eq!(production.rate_limit_per_hour, 5);
    }

    #[test]
    fn test_stats_calculations() {
        let mut stats = ProvingServiceStats::default();

        // Initially 100% success rate (no attempts)
        assert_eq!(stats.success_rate(), 100.0);
        assert_eq!(stats.avg_generation_time_ms(), 0);

        // Add some data
        stats.successful_proofs = 8;
        stats.failed_proofs = 2;
        stats.total_generation_time_ms = 10000;

        assert_eq!(stats.success_rate(), 80.0);
        assert_eq!(stats.avg_generation_time_ms(), 1250);
    }
}
