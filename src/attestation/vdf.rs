// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Verifiable Delay Function (VDF) heartbeats for temporal attestation.
//!
//! This module implements Phase 4 of the Entangled Attestation system:
//! VDF heartbeats that prove continuous execution on a single CPU core.
//!
//! ## Purpose
//!
//! VDFs bind attestation proofs to physical nodes by requiring sequential
//! computation that cannot be parallelized. This prevents:
//!
//! - **Sybil attacks**: One machine cannot maintain multiple identities
//! - **Relay attacks**: Challenges cannot be forwarded to remote provers
//! - **Emulation attacks**: Lightweight scripts cannot fake heartbeats
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────┐
//! │ HeartbeatChallenge│
//! │ (entangled_id +  │
//! │  timestamp +     │
//! │  epoch_number)   │
//! └────────┬─────────┘
//!          │
//!          ▼
//! ┌──────────────────┐
//! │ VDF Computation  │
//! │ (sequential,     │
//! │  non-parallel)   │
//! │ ~T iterations    │
//! └────────┬─────────┘
//!          │
//!          ▼
//! ┌──────────────────┐
//! │ HeartbeatProof   │
//! │ (constant size,  │
//! │  fast verify)    │
//! └──────────────────┘
//! ```
//!
//! ## Wesolowski VDF with Class Groups
//!
//! We use Wesolowski's VDF over Class Groups of Imaginary Quadratic Fields:
//!
//! - **No trusted setup**: Unlike RSA groups, Class Groups don't need ceremonies
//! - **Constant-size proofs**: Important for gossip bandwidth
//! - **Post-quantum candidate**: Hash-based security model
//!
//! ## Security Parameters
//!
//! | Discriminant Size | Security | Verification Time |
//! |-------------------|----------|-------------------|
//! | 1024-bit          | Low      | ~1ms              |
//! | 2048-bit          | Medium   | ~2-3ms            |
//! | 4096-bit          | High     | ~5-10ms           |
//!
//! Mainnet uses 2048-bit discriminants by default.
//!
//! ## Feature Flags
//!
//! - `vdf`: Enable real Wesolowski VDF (requires GMP system library)
//! - Default: Mock VDF for testing (instant computation, no security)
//!
//! ## Example
//!
//! ```rust,ignore
//! use saorsa_core::attestation::vdf::{VdfHeartbeat, VdfConfig, HeartbeatChallenge};
//!
//! // Create heartbeat manager
//! let config = VdfConfig::mainnet();
//! let vdf = VdfHeartbeat::new(config)?;
//!
//! // Generate challenge from our identity
//! let challenge = HeartbeatChallenge::new(entangled_id, epoch);
//!
//! // Solve VDF (takes ~heartbeat_interval_secs)
//! let proof = vdf.solve(&challenge)?;
//!
//! // Fast verification (2-3ms)
//! assert!(vdf.verify(&challenge, &proof)?);
//! ```

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::AttestationError;

// ============================================================================
// Configuration
// ============================================================================

/// VDF configuration parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VdfConfig {
    /// Discriminant bit size for Class Groups.
    /// Higher = more secure but slower verification.
    /// Mainnet default: 2048 bits.
    pub discriminant_bits: u16,

    /// Number of VDF iterations (difficulty).
    /// Higher = longer computation time.
    /// Calibrated to match heartbeat interval.
    pub iterations: u64,

    /// Heartbeat interval in seconds.
    /// Nodes must produce one proof per interval.
    pub heartbeat_interval_secs: u64,

    /// Maximum acceptable proof age in seconds.
    /// Proofs older than this are rejected as stale.
    pub max_proof_age_secs: u64,

    /// Number of missed heartbeats before marking node as suspect.
    pub suspect_threshold: u32,

    /// Number of missed heartbeats before eviction.
    pub eviction_threshold: u32,
}

impl Default for VdfConfig {
    fn default() -> Self {
        Self::development()
    }
}

impl VdfConfig {
    /// Development configuration with fast iterations.
    #[must_use]
    pub fn development() -> Self {
        Self {
            discriminant_bits: 1024,     // Lower security for speed
            iterations: 1000,            // ~10ms on modern CPU
            heartbeat_interval_secs: 60, // 1 minute
            max_proof_age_secs: 120,     // 2 minutes
            suspect_threshold: 3,        // 3 missed = suspect
            eviction_threshold: 5,       // 5 missed = evicted
        }
    }

    /// Testnet configuration with moderate security.
    #[must_use]
    pub fn testnet() -> Self {
        Self {
            discriminant_bits: 1536,
            iterations: 100_000,          // ~1 second
            heartbeat_interval_secs: 300, // 5 minutes
            max_proof_age_secs: 600,      // 10 minutes
            suspect_threshold: 3,
            eviction_threshold: 5,
        }
    }

    /// Mainnet configuration with full security.
    #[must_use]
    pub fn mainnet() -> Self {
        Self {
            discriminant_bits: 2048,      // Full security
            iterations: 1_000_000,        // ~10 seconds (calibrate per CPU)
            heartbeat_interval_secs: 600, // 10 minutes
            max_proof_age_secs: 900,      // 15 minutes
            suspect_threshold: 3,
            eviction_threshold: 6, // 1 hour of missed heartbeats
        }
    }

    /// Calculate expected computation time based on iterations.
    ///
    /// This is an estimate; actual time varies by CPU.
    #[must_use]
    pub fn estimated_compute_time(&self) -> Duration {
        // Rough estimate: ~10ns per iteration on modern CPU
        let nanos = self.iterations.saturating_mul(10);
        Duration::from_nanos(nanos)
    }
}

// ============================================================================
// Challenge and Proof Types
// ============================================================================

/// A heartbeat challenge that must be solved with a VDF.
///
/// The challenge binds the VDF computation to a specific node
/// and time period, preventing replay and relay attacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatChallenge {
    /// The node's EntangledId (software-attested identity).
    pub entangled_id: [u8; 32],

    /// Epoch number (increments each heartbeat interval).
    pub epoch: u64,

    /// Challenge timestamp (Unix seconds).
    pub timestamp: u64,

    /// Random nonce for additional entropy.
    pub nonce: [u8; 16],
}

impl HeartbeatChallenge {
    /// Create a new heartbeat challenge.
    #[must_use]
    pub fn new(entangled_id: [u8; 32], epoch: u64) -> Self {
        let timestamp = current_timestamp();
        let mut nonce = [0u8; 16];
        // Use fastrand for non-cryptographic randomness (sufficient for nonce)
        for byte in &mut nonce {
            *byte = fastrand::u8(..);
        }

        Self {
            entangled_id,
            epoch,
            timestamp,
            nonce,
        }
    }

    /// Create a challenge with a specific timestamp (for testing).
    #[must_use]
    pub fn with_timestamp(entangled_id: [u8; 32], epoch: u64, timestamp: u64) -> Self {
        let mut nonce = [0u8; 16];
        for byte in &mut nonce {
            *byte = fastrand::u8(..);
        }

        Self {
            entangled_id,
            epoch,
            timestamp,
            nonce,
        }
    }

    /// Serialize challenge to bytes for VDF input.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 8 + 8 + 16);
        bytes.extend_from_slice(&self.entangled_id);
        bytes.extend_from_slice(&self.epoch.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes
    }

    /// Check if this challenge is fresh (not expired).
    #[must_use]
    pub fn is_fresh(&self, max_age_secs: u64, current_time: u64) -> bool {
        current_time.saturating_sub(self.timestamp) <= max_age_secs
    }
}

/// A VDF heartbeat proof.
///
/// This proves that the node performed sequential computation
/// on the challenge, demonstrating physical presence and
/// preventing Sybil attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatProof {
    /// The VDF output (proof of sequential work).
    pub vdf_output: Vec<u8>,

    /// The VDF proof (for fast verification).
    pub vdf_proof: Vec<u8>,

    /// Number of iterations performed.
    pub iterations: u64,

    /// Discriminant size used.
    pub discriminant_bits: u16,

    /// When the proof was generated (Unix seconds).
    pub generated_at: u64,

    /// Computation time in milliseconds.
    pub compute_time_ms: u64,

    /// Proof type indicator.
    pub proof_type: VdfProofType,
}

/// Type of VDF proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VdfProofType {
    /// Mock proof for testing (no security).
    Mock,
    /// Real Wesolowski VDF proof.
    Wesolowski,
    /// Real Pietrzak VDF proof (larger but simpler verification).
    Pietrzak,
}

impl HeartbeatProof {
    /// Check if this is a real (non-mock) proof.
    #[must_use]
    pub fn is_real(&self) -> bool {
        !matches!(self.proof_type, VdfProofType::Mock)
    }

    /// Check if this proof is fresh.
    #[must_use]
    pub fn is_fresh(&self, max_age_secs: u64, current_time: u64) -> bool {
        current_time.saturating_sub(self.generated_at) <= max_age_secs
    }
}

// ============================================================================
// Verification Result
// ============================================================================

/// Result of verifying a heartbeat proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatVerificationResult {
    /// Proof is valid.
    Valid,
    /// Proof is invalid (cryptographic verification failed).
    Invalid(String),
    /// Proof is stale (too old).
    Stale,
    /// Wrong number of iterations.
    WrongIterations,
    /// Wrong discriminant size.
    WrongDiscriminant,
    /// Challenge mismatch.
    ChallengeMismatch,
}

impl HeartbeatVerificationResult {
    /// Check if verification was successful.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

// ============================================================================
// Mock VDF Provider (Default)
// ============================================================================

/// Mock VDF provider for testing.
///
/// This provider generates instant "proofs" without actual VDF computation.
/// Use only for development and testing.
#[derive(Debug, Default)]
pub struct MockVdfProvider;

impl MockVdfProvider {
    /// Create a new mock provider.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Solve a challenge with mock computation.
    #[must_use]
    pub fn solve(&self, challenge: &HeartbeatChallenge, config: &VdfConfig) -> HeartbeatProof {
        // Simulate some computation time
        let start = std::time::Instant::now();

        // Hash the challenge as mock output
        let challenge_bytes = challenge.to_bytes();
        let output = blake3::hash(&challenge_bytes);

        // Create mock proof
        let compute_time = start.elapsed();

        HeartbeatProof {
            vdf_output: output.as_bytes().to_vec(),
            vdf_proof: vec![0u8; 32], // Mock proof
            iterations: config.iterations,
            discriminant_bits: config.discriminant_bits,
            generated_at: current_timestamp(),
            compute_time_ms: compute_time.as_millis() as u64,
            proof_type: VdfProofType::Mock,
        }
    }

    /// Verify a mock proof.
    #[must_use]
    pub fn verify(
        &self,
        challenge: &HeartbeatChallenge,
        proof: &HeartbeatProof,
        config: &VdfConfig,
    ) -> HeartbeatVerificationResult {
        // Check iterations match
        if proof.iterations != config.iterations {
            return HeartbeatVerificationResult::WrongIterations;
        }

        // Check discriminant matches
        if proof.discriminant_bits != config.discriminant_bits {
            return HeartbeatVerificationResult::WrongDiscriminant;
        }

        // Check freshness
        let current = current_timestamp();
        if !proof.is_fresh(config.max_proof_age_secs, current) {
            return HeartbeatVerificationResult::Stale;
        }

        // For mock proofs, verify the hash matches
        let challenge_bytes = challenge.to_bytes();
        let expected_output = blake3::hash(&challenge_bytes);

        if proof.vdf_output != expected_output.as_bytes() {
            return HeartbeatVerificationResult::ChallengeMismatch;
        }

        HeartbeatVerificationResult::Valid
    }
}

// ============================================================================
// Real Wesolowski VDF Provider (Feature-gated)
// ============================================================================

/// Wesolowski VDF provider using Class Groups.
///
/// This provider uses the POA Network `vdf` crate for real VDF computation.
/// Requires the `vdf` feature flag and GMP system library.
#[cfg(feature = "vdf")]
pub struct WesolowskiVdfProvider {
    discriminant_bits: u16,
}

#[cfg(feature = "vdf")]
impl WesolowskiVdfProvider {
    /// Create a new Wesolowski VDF provider.
    #[must_use]
    pub fn new(discriminant_bits: u16) -> Self {
        Self { discriminant_bits }
    }

    /// Solve a challenge with real VDF computation.
    ///
    /// # Errors
    ///
    /// Returns an error if VDF computation fails.
    pub fn solve(
        &self,
        challenge: &HeartbeatChallenge,
        config: &VdfConfig,
    ) -> Result<HeartbeatProof, AttestationError> {
        use vdf::{VDFParams, WesolowskiVDFParams};

        let start = std::time::Instant::now();

        // Create VDF instance with configured discriminant size
        let vdf_params = WesolowskiVDFParams(self.discriminant_bits);
        let vdf_instance = vdf_params.new();

        // Serialize challenge as input
        let challenge_bytes = challenge.to_bytes();

        // Compute VDF (this takes time proportional to iterations)
        let solution = vdf_instance
            .solve(&challenge_bytes, config.iterations)
            .map_err(|e| AttestationError::VdfError(format!("VDF solve failed: {:?}", e)))?;

        let compute_time = start.elapsed();

        Ok(HeartbeatProof {
            vdf_output: solution.clone(),
            vdf_proof: solution, // Wesolowski proofs are self-contained
            iterations: config.iterations,
            discriminant_bits: self.discriminant_bits,
            generated_at: current_timestamp(),
            compute_time_ms: compute_time.as_millis() as u64,
            proof_type: VdfProofType::Wesolowski,
        })
    }

    /// Verify a Wesolowski VDF proof.
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails unexpectedly.
    pub fn verify(
        &self,
        challenge: &HeartbeatChallenge,
        proof: &HeartbeatProof,
        config: &VdfConfig,
    ) -> Result<HeartbeatVerificationResult, AttestationError> {
        use vdf::{VDFParams, WesolowskiVDFParams};

        // Check parameters match
        if proof.iterations != config.iterations {
            return Ok(HeartbeatVerificationResult::WrongIterations);
        }

        if proof.discriminant_bits != self.discriminant_bits {
            return Ok(HeartbeatVerificationResult::WrongDiscriminant);
        }

        // Check freshness
        let current = current_timestamp();
        if !proof.is_fresh(config.max_proof_age_secs, current) {
            return Ok(HeartbeatVerificationResult::Stale);
        }

        // Create VDF instance for verification
        let vdf_params = WesolowskiVDFParams(self.discriminant_bits);
        let vdf_instance = vdf_params.new();

        // Serialize challenge
        let challenge_bytes = challenge.to_bytes();

        // Verify the proof
        match vdf_instance.verify(&challenge_bytes, config.iterations, &proof.vdf_proof) {
            Ok(()) => Ok(HeartbeatVerificationResult::Valid),
            Err(_) => Ok(HeartbeatVerificationResult::Invalid(
                "VDF verification failed".to_string(),
            )),
        }
    }
}

// ============================================================================
// Unified VDF Heartbeat Interface
// ============================================================================

/// VDF heartbeat manager that selects implementation based on features.
///
/// # Usage
///
/// ```rust,ignore
/// use saorsa_core::attestation::vdf::{VdfHeartbeat, VdfConfig, HeartbeatChallenge};
///
/// let config = VdfConfig::mainnet();
/// let vdf = VdfHeartbeat::new(config)?;
///
/// let challenge = HeartbeatChallenge::new(entangled_id, epoch);
/// let proof = vdf.solve(&challenge)?;
///
/// assert!(vdf.verify(&challenge, &proof)?.is_valid());
/// ```
pub struct VdfHeartbeat {
    config: VdfConfig,
    provider: VdfProvider,
}

/// Internal provider enum for implementation selection.
enum VdfProvider {
    Mock(MockVdfProvider),
    #[cfg(feature = "vdf")]
    Wesolowski(WesolowskiVdfProvider),
}

impl VdfHeartbeat {
    /// Create a new VDF heartbeat manager.
    ///
    /// - With `vdf` feature: Uses real Wesolowski VDF
    /// - Without feature: Uses mock VDF for testing
    #[cfg(feature = "vdf")]
    #[must_use]
    pub fn new(config: VdfConfig) -> Self {
        let provider =
            VdfProvider::Wesolowski(WesolowskiVdfProvider::new(config.discriminant_bits));
        Self { config, provider }
    }

    /// Create a new VDF heartbeat manager (mock when vdf feature disabled).
    #[cfg(not(feature = "vdf"))]
    #[must_use]
    pub fn new(config: VdfConfig) -> Self {
        let provider = VdfProvider::Mock(MockVdfProvider::new());
        Self { config, provider }
    }

    /// Create a mock VDF heartbeat manager explicitly (for testing).
    #[must_use]
    pub fn mock(config: VdfConfig) -> Self {
        let provider = VdfProvider::Mock(MockVdfProvider::new());
        Self { config, provider }
    }

    /// Solve a heartbeat challenge.
    ///
    /// This performs sequential VDF computation that cannot be parallelized.
    /// Computation time is proportional to `config.iterations`.
    ///
    /// # Errors
    ///
    /// Returns an error if VDF computation fails.
    pub fn solve(
        &self,
        challenge: &HeartbeatChallenge,
    ) -> Result<HeartbeatProof, AttestationError> {
        match &self.provider {
            VdfProvider::Mock(provider) => Ok(provider.solve(challenge, &self.config)),
            #[cfg(feature = "vdf")]
            VdfProvider::Wesolowski(provider) => provider.solve(challenge, &self.config),
        }
    }

    /// Verify a heartbeat proof.
    ///
    /// Verification is fast (~2-3ms for 2048-bit discriminant).
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails unexpectedly.
    pub fn verify(
        &self,
        challenge: &HeartbeatChallenge,
        proof: &HeartbeatProof,
    ) -> Result<HeartbeatVerificationResult, AttestationError> {
        match &self.provider {
            VdfProvider::Mock(provider) => Ok(provider.verify(challenge, proof, &self.config)),
            #[cfg(feature = "vdf")]
            VdfProvider::Wesolowski(provider) => provider.verify(challenge, proof, &self.config),
        }
    }

    /// Get the current configuration.
    #[must_use]
    pub fn config(&self) -> &VdfConfig {
        &self.config
    }

    /// Check if using real VDF.
    #[must_use]
    pub fn is_real_vdf(&self) -> bool {
        match &self.provider {
            VdfProvider::Mock(_) => false,
            #[cfg(feature = "vdf")]
            VdfProvider::Wesolowski(_) => true,
        }
    }

    /// Calculate expected epochs for a time range.
    #[must_use]
    pub fn calculate_epoch(&self, timestamp: u64) -> u64 {
        timestamp / self.config.heartbeat_interval_secs
    }

    /// Get the next heartbeat deadline.
    #[must_use]
    pub fn next_heartbeat_deadline(&self, current_epoch: u64) -> u64 {
        (current_epoch + 1) * self.config.heartbeat_interval_secs
    }
}

impl Default for VdfHeartbeat {
    fn default() -> Self {
        Self::mock(VdfConfig::development())
    }
}

// ============================================================================
// Node Heartbeat Status Tracking
// ============================================================================

/// Tracks a node's heartbeat status for Close Group consensus.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeHeartbeatStatus {
    /// The node's EntangledId.
    pub entangled_id: Option<[u8; 32]>,

    /// Last valid heartbeat epoch.
    pub last_valid_epoch: u64,

    /// Last valid heartbeat timestamp.
    pub last_valid_timestamp: u64,

    /// Number of consecutive missed heartbeats.
    pub missed_heartbeats: u32,

    /// Total heartbeats verified.
    pub total_verified: u64,

    /// Total heartbeats failed.
    pub total_failed: u64,

    /// Current status.
    pub status: HeartbeatNodeStatus,
}

/// Node status based on heartbeat history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum HeartbeatNodeStatus {
    /// Node is healthy (recent valid heartbeat).
    #[default]
    Healthy,
    /// Node missed some heartbeats (under observation).
    Suspect,
    /// Node missed too many heartbeats (should be evicted).
    Evicted,
}

impl NodeHeartbeatStatus {
    /// Create a new status for a node.
    #[must_use]
    pub fn new(entangled_id: [u8; 32]) -> Self {
        Self {
            entangled_id: Some(entangled_id),
            last_valid_epoch: 0,
            last_valid_timestamp: 0,
            missed_heartbeats: 0,
            total_verified: 0,
            total_failed: 0,
            status: HeartbeatNodeStatus::Healthy,
        }
    }

    /// Record a successful heartbeat.
    pub fn record_success(&mut self, epoch: u64, timestamp: u64) {
        self.last_valid_epoch = epoch;
        self.last_valid_timestamp = timestamp;
        self.missed_heartbeats = 0;
        self.total_verified += 1;
        self.status = HeartbeatNodeStatus::Healthy;
    }

    /// Record a missed heartbeat.
    pub fn record_miss(&mut self, config: &VdfConfig) {
        self.missed_heartbeats += 1;
        self.total_failed += 1;

        // Update status based on thresholds
        if self.missed_heartbeats >= config.eviction_threshold {
            self.status = HeartbeatNodeStatus::Evicted;
        } else if self.missed_heartbeats >= config.suspect_threshold {
            self.status = HeartbeatNodeStatus::Suspect;
        }
    }

    /// Check if node should be evicted.
    #[must_use]
    pub fn should_evict(&self) -> bool {
        self.status == HeartbeatNodeStatus::Evicted
    }

    /// Check if node is suspect.
    #[must_use]
    pub fn is_suspect(&self) -> bool {
        self.status == HeartbeatNodeStatus::Suspect
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdf_config_defaults() {
        let dev = VdfConfig::development();
        assert_eq!(dev.discriminant_bits, 1024);
        assert_eq!(dev.heartbeat_interval_secs, 60);

        let mainnet = VdfConfig::mainnet();
        assert_eq!(mainnet.discriminant_bits, 2048);
        assert_eq!(mainnet.heartbeat_interval_secs, 600);
    }

    #[test]
    fn test_heartbeat_challenge_creation() {
        let entangled_id = [0x42u8; 32];
        let epoch = 12345u64;

        let challenge = HeartbeatChallenge::new(entangled_id, epoch);

        assert_eq!(challenge.entangled_id, entangled_id);
        assert_eq!(challenge.epoch, epoch);
        assert!(challenge.timestamp > 0);
        assert!(challenge.nonce.iter().any(|&b| b != 0)); // Unlikely all zeros
    }

    #[test]
    fn test_challenge_serialization() {
        let entangled_id = [0x42u8; 32];
        let challenge = HeartbeatChallenge::with_timestamp(entangled_id, 100, 1000);

        let bytes = challenge.to_bytes();
        assert_eq!(bytes.len(), 32 + 8 + 8 + 16); // id + epoch + timestamp + nonce
    }

    #[test]
    fn test_challenge_freshness() {
        let entangled_id = [0x42u8; 32];
        let now = current_timestamp();
        let challenge = HeartbeatChallenge::with_timestamp(entangled_id, 1, now);

        // Fresh challenge
        assert!(challenge.is_fresh(60, now + 30));

        // Stale challenge
        assert!(!challenge.is_fresh(60, now + 120));
    }

    #[test]
    fn test_mock_vdf_solve_and_verify() {
        let config = VdfConfig::development();
        let vdf = VdfHeartbeat::mock(config.clone());

        let entangled_id = [0x42u8; 32];
        let challenge = HeartbeatChallenge::new(entangled_id, 1);

        // Solve
        let proof = vdf.solve(&challenge).expect("solve failed");
        assert_eq!(proof.proof_type, VdfProofType::Mock);
        assert_eq!(proof.iterations, config.iterations);

        // Verify
        let result = vdf.verify(&challenge, &proof).expect("verify failed");
        assert!(result.is_valid());
    }

    #[test]
    fn test_mock_vdf_rejects_wrong_iterations() {
        let config = VdfConfig::development();
        let vdf = VdfHeartbeat::mock(config.clone());

        let entangled_id = [0x42u8; 32];
        let challenge = HeartbeatChallenge::new(entangled_id, 1);

        let mut proof = vdf.solve(&challenge).expect("solve failed");
        proof.iterations = 999; // Wrong iterations

        let result = vdf.verify(&challenge, &proof).expect("verify failed");
        assert_eq!(result, HeartbeatVerificationResult::WrongIterations);
    }

    #[test]
    fn test_mock_vdf_rejects_stale_proof() {
        let config = VdfConfig {
            max_proof_age_secs: 1, // Very short for testing
            ..VdfConfig::development()
        };
        let vdf = VdfHeartbeat::mock(config);

        let entangled_id = [0x42u8; 32];
        let challenge = HeartbeatChallenge::new(entangled_id, 1);

        let mut proof = vdf.solve(&challenge).expect("solve failed");
        proof.generated_at = 1000; // Very old timestamp

        let result = vdf.verify(&challenge, &proof).expect("verify failed");
        assert_eq!(result, HeartbeatVerificationResult::Stale);
    }

    #[test]
    fn test_node_heartbeat_status_tracking() {
        let config = VdfConfig::development();
        let entangled_id = [0x42u8; 32];

        let mut status = NodeHeartbeatStatus::new(entangled_id);
        assert_eq!(status.status, HeartbeatNodeStatus::Healthy);
        assert_eq!(status.missed_heartbeats, 0);

        // Record success
        status.record_success(1, current_timestamp());
        assert_eq!(status.total_verified, 1);
        assert_eq!(status.last_valid_epoch, 1);

        // Record misses until suspect
        for _ in 0..config.suspect_threshold {
            status.record_miss(&config);
        }
        assert!(status.is_suspect());
        assert!(!status.should_evict());

        // More misses until eviction
        for _ in 0..(config.eviction_threshold - config.suspect_threshold) {
            status.record_miss(&config);
        }
        assert!(status.should_evict());
    }

    #[test]
    fn test_epoch_calculation() {
        let config = VdfConfig {
            heartbeat_interval_secs: 60,
            ..VdfConfig::development()
        };
        let vdf = VdfHeartbeat::mock(config);

        assert_eq!(vdf.calculate_epoch(0), 0);
        assert_eq!(vdf.calculate_epoch(59), 0);
        assert_eq!(vdf.calculate_epoch(60), 1);
        assert_eq!(vdf.calculate_epoch(119), 1);
        assert_eq!(vdf.calculate_epoch(120), 2);
    }

    #[test]
    fn test_next_heartbeat_deadline() {
        let config = VdfConfig {
            heartbeat_interval_secs: 60,
            ..VdfConfig::development()
        };
        let vdf = VdfHeartbeat::mock(config);

        assert_eq!(vdf.next_heartbeat_deadline(0), 60);
        assert_eq!(vdf.next_heartbeat_deadline(1), 120);
        assert_eq!(vdf.next_heartbeat_deadline(10), 660);
    }

    #[test]
    fn test_vdf_heartbeat_default_is_mock() {
        let vdf = VdfHeartbeat::default();
        assert!(!vdf.is_real_vdf());
    }

    #[test]
    fn test_heartbeat_proof_freshness() {
        let proof = HeartbeatProof {
            vdf_output: vec![],
            vdf_proof: vec![],
            iterations: 1000,
            discriminant_bits: 1024,
            generated_at: current_timestamp(),
            compute_time_ms: 10,
            proof_type: VdfProofType::Mock,
        };

        let current = current_timestamp();
        assert!(proof.is_fresh(60, current));
        assert!(!proof.is_fresh(60, current + 120));
    }

    #[test]
    fn test_verification_result_variants() {
        assert!(HeartbeatVerificationResult::Valid.is_valid());
        assert!(!HeartbeatVerificationResult::Invalid("test".to_string()).is_valid());
        assert!(!HeartbeatVerificationResult::Stale.is_valid());
        assert!(!HeartbeatVerificationResult::WrongIterations.is_valid());
        assert!(!HeartbeatVerificationResult::WrongDiscriminant.is_valid());
        assert!(!HeartbeatVerificationResult::ChallengeMismatch.is_valid());
    }
}
