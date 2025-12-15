// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Verifiable Delay Function (VDF) heartbeats using SP1 zkVM.
//!
//! This module implements Phase 4 of the Entangled Attestation system:
//! VDF heartbeats that prove continuous execution on a single CPU core.
//!
//! ## SP1-VDF Implementation
//!
//! Instead of using specialized mathematical groups (like RSA or Class Groups)
//! which often require GMP or Trusted Setups, this implementation uses
//! **Iterated Hashing** inside the **SP1 zkVM**.
//!
//! - **Algorithm**: `H(H(...H(seed)))` inside the zkVM.
//! - **Guest Program**: `saorsa-vdf-guest`
//! - **Proof**: SP1 STARK Proof (Pure Rust, Quantum Secure, No Trusted Setup).
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────┐
//! │ HeartbeatChallenge│
//! │ (entangled_id +  │
//! │  epoch_number)   │
//! └────────┬─────────┘
//!          │
//!          ▼
//! ┌──────────────────┐
//! │ SP1 Guest        │
//! │ (Iterated Hashing│
//! │  ~T iterations)  │
//! └────────┬─────────┘
//!          │           SP1 Proof
//!          ▼
//! ┌──────────────────┐
//! │ HeartbeatProof   │
//! │ (STARK Proof +   │
//! │  Public Outputs) │
//! └──────────────────┘
//! ```

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use super::AttestationError;

// ELF for the VDF guest program (compiled by build.rs)
// Uses sp1_sdk::include_elf! which reads from SP1_ELF_saorsa_vdf_guest env var
#[cfg(feature = "vdf")]
pub const VDF_GUEST_ELF: &[u8] = sp1_sdk::include_elf!("saorsa-vdf-guest");

// ============================================================================
// Configuration
// ============================================================================

/// VDF configuration parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VdfConfig {
    /// Number of VDF iterations (difficulty).
    /// BLAKE3 hashing difficulty.
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
            iterations: 10_000,          // ~10ms in zkVM
            heartbeat_interval_secs: 60, // 1 minute
            max_proof_age_secs: 120,     // 2 minutes
            suspect_threshold: 3,        // 3 missed = suspect
            eviction_threshold: 5,       // 5 missed = evicted
        }
    }

    /// Testnet configuration.
    #[must_use]
    pub fn testnet() -> Self {
        Self {
            iterations: 1_000_000,        // ~1 second in zkVM
            heartbeat_interval_secs: 300, // 5 minutes
            max_proof_age_secs: 600,      // 10 minutes
            suspect_threshold: 3,
            eviction_threshold: 5,
        }
    }

    /// Mainnet configuration.
    #[must_use]
    pub fn mainnet() -> Self {
        Self {
            iterations: 10_000_000,       // ~10 seconds in zkVM (calibrate!)
            heartbeat_interval_secs: 600, // 10 minutes
            max_proof_age_secs: 900,      // 15 minutes
            suspect_threshold: 3,
            eviction_threshold: 6, // 1 hour of missed heartbeats
        }
    }
}

// ============================================================================
// Challenge and Proof Types
// ============================================================================

/// A heartbeat challenge that must be solved with a VDF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatChallenge {
    pub entangled_id: [u8; 32],
    pub epoch: u64,
    pub timestamp: u64,
    pub nonce: [u8; 16],
}

impl HeartbeatChallenge {
    pub fn new(entangled_id: [u8; 32], epoch: u64) -> Self {
        let timestamp = current_timestamp();
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

    pub fn to_seed(&self) -> [u8; 32] {
        // Hash everything to get a 32-byte seed for the VDF
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.entangled_id);
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.nonce);
        *hasher.finalize().as_bytes()
    }
    
    pub fn is_fresh(&self, max_age_secs: u64, current_time: u64) -> bool {
        current_time.saturating_sub(self.timestamp) <= max_age_secs
    }
}

/// A VDF heartbeat proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatProof {
    /// The VDF output (final hash state).
    pub vdf_output: [u8; 32],

    /// The SP1 Proof bytes.
    pub proof_bytes: Vec<u8>,
    
    /// Verification key hash (to check which program ran).
    pub vkey_hash: [u8; 32],

    /// Number of iterations performed.
    pub iterations: u64,

    /// When the proof was generated (Unix seconds).
    pub generated_at: u64,
    
    /// Proof type indicator.
    pub proof_type: VdfProofType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VdfProofType {
    Mock,
    Sp1Core,
    Sp1Compressed,
}

impl HeartbeatProof {
    pub fn is_real(&self) -> bool {
        !matches!(self.proof_type, VdfProofType::Mock)
    }

    pub fn is_fresh(&self, max_age_secs: u64, current_time: u64) -> bool {
        current_time.saturating_sub(self.generated_at) <= max_age_secs
    }
}

// ============================================================================
// Verification Result
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatVerificationResult {
    Valid,
    Invalid(String),
    Stale,
    WrongIterations,
    ChallengeMismatch,
}

impl HeartbeatVerificationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

// ============================================================================
// Mock VDF Provider (Default)
// ============================================================================

#[derive(Debug, Default)]
pub struct MockVdfProvider;

impl MockVdfProvider {
    pub fn new() -> Self {
        Self
    }
    
    pub fn solve(&self, challenge: &HeartbeatChallenge, config: &VdfConfig) -> HeartbeatProof {
        let seed = challenge.to_seed();
        // Mock computation: just hash the seed once
        let output = *blake3::hash(&seed).as_bytes();
        
        HeartbeatProof {
            vdf_output: output,
            proof_bytes: vec![0u8; 32],
            vkey_hash: [0u8; 32],
            iterations: config.iterations,
            generated_at: current_timestamp(),
            proof_type: VdfProofType::Mock,
        }
    }

    pub fn verify(
        &self,
        challenge: &HeartbeatChallenge,
        proof: &HeartbeatProof,
        config: &VdfConfig,
    ) -> HeartbeatVerificationResult {
        if proof.iterations != config.iterations {
            return HeartbeatVerificationResult::WrongIterations;
        }
        
        // Check freshness
        let current = current_timestamp();
        if !proof.is_fresh(config.max_proof_age_secs, current) {
            return HeartbeatVerificationResult::Stale;
        }
        
        let seed = challenge.to_seed();
        let expected = *blake3::hash(&seed).as_bytes();
        
        if proof.vdf_output != expected {
            HeartbeatVerificationResult::ChallengeMismatch
        } else {
            HeartbeatVerificationResult::Valid
        }
    }
}

// ============================================================================
// SP1 VDF Provider (Feature-gated)
// ============================================================================

#[cfg(feature = "vdf")]
pub struct Sp1VdfProvider {
    prover: sp1_sdk::env::EnvProver,
    pk: sp1_sdk::SP1ProvingKey,
    vk: sp1_sdk::SP1VerifyingKey,
}

#[cfg(feature = "vdf")]
impl Sp1VdfProvider {
    pub fn new() -> Result<Self, AttestationError> {
        use sp1_sdk::HashableKey;

        let prover = sp1_sdk::ProverClient::from_env();
        let (pk, vk) = prover.setup(VDF_GUEST_ELF);
        tracing::info!(
            vkey_hash = %hex::encode(vk.hash_bytes()),
            "SP1 VDF provider initialized"
        );
        Ok(Self { prover, pk, vk })
    }

    pub fn solve(
        &self,
        challenge: &HeartbeatChallenge,
        config: &VdfConfig,
    ) -> Result<HeartbeatProof, AttestationError> {
        use sp1_sdk::{SP1Stdin, HashableKey};

        let seed = challenge.to_seed();

        let mut stdin = SP1Stdin::new();
        stdin.write(&seed);
        stdin.write(&config.iterations);

        // Generate proof using SP1 v5 API
        // .core() generates a Core proof (faster proving, larger size)
        // Alternative: .compressed() for smaller proofs
        let proof = self
            .prover
            .prove(&self.pk, &stdin)
            .core()
            .run()
            .map_err(|e| AttestationError::InvalidProof(format!("SP1 solve failed: {e}")))?;

        // Read output from public values
        let mut public_values = proof.public_values.clone();
        let output: [u8; 32] = public_values.read();

        Ok(HeartbeatProof {
            vdf_output: output,
            proof_bytes: bincode::serialize(&proof)
                .map_err(|e| AttestationError::InvalidProof(format!("Serialization failed: {e}")))?,
            vkey_hash: self.vk.hash_bytes(),
            iterations: config.iterations,
            generated_at: current_timestamp(),
            proof_type: VdfProofType::Sp1Core,
        })
    }

    pub fn verify(
        &self,
        _challenge: &HeartbeatChallenge,
        proof: &HeartbeatProof,
        config: &VdfConfig,
    ) -> Result<HeartbeatVerificationResult, AttestationError> {
        use sp1_sdk::HashableKey;

        // Basic checks
        if proof.iterations != config.iterations {
            return Ok(HeartbeatVerificationResult::WrongIterations);
        }

        // Freshness
        let current = current_timestamp();
        if !proof.is_fresh(config.max_proof_age_secs, current) {
            return Ok(HeartbeatVerificationResult::Stale);
        }

        // Check VKey hash
        if proof.vkey_hash != self.vk.hash_bytes() {
            return Ok(HeartbeatVerificationResult::Invalid("Wrong program vkey".to_string()));
        }

        // Deserialize and verify SP1 Proof
        let sp1_proof: sp1_sdk::SP1ProofWithPublicValues = bincode::deserialize(&proof.proof_bytes)
            .map_err(|e| AttestationError::InvalidProof(format!("Deserialization failed: {e}")))?;

        self.prover.verify(&sp1_proof, &self.vk)
            .map_err(|e| AttestationError::InvalidProof(format!("SP1 verify failed: {e}")))?;

        Ok(HeartbeatVerificationResult::Valid)
    }
}

// ============================================================================
// Unified Interface
// ============================================================================

pub struct VdfHeartbeat {
    config: VdfConfig,
    provider: VdfProvider,
}

enum VdfProvider {
    // Mock is always available for testing, even when vdf feature is enabled
    #[allow(dead_code)]
    Mock(MockVdfProvider),
    #[cfg(feature = "vdf")]
    Sp1(Sp1VdfProvider),
}

impl VdfHeartbeat {
    #[cfg(feature = "vdf")]
    pub fn new(config: VdfConfig) -> Result<Self, AttestationError> {
        let provider = Sp1VdfProvider::new()?;
        Ok(Self {
            config,
            provider: VdfProvider::Sp1(provider),
        })
    }
    
    #[cfg(not(feature = "vdf"))]
    pub fn new(config: VdfConfig) -> Result<Self, AttestationError> {
        Ok(Self {
            config,
            provider: VdfProvider::Mock(MockVdfProvider::new()),
        })
    }
    
    pub fn solve(&self, challenge: &HeartbeatChallenge) -> Result<HeartbeatProof, AttestationError> {
        match &self.provider {
            VdfProvider::Mock(p) => Ok(p.solve(challenge, &self.config)),
            #[cfg(feature = "vdf")]
            VdfProvider::Sp1(p) => p.solve(challenge, &self.config),
        }
    }
    
    pub fn verify(&self, challenge: &HeartbeatChallenge, proof: &HeartbeatProof) -> Result<HeartbeatVerificationResult, AttestationError> {
        match &self.provider {
            VdfProvider::Mock(p) => Ok(p.verify(challenge, proof, &self.config)),
            #[cfg(feature = "vdf")]
            VdfProvider::Sp1(p) => p.verify(challenge, proof, &self.config),
        }
    }
}

// Node Heartbeat Status Tracking (Unchanged from original)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeHeartbeatStatus {
    pub entangled_id: Option<[u8; 32]>,
    pub last_valid_epoch: u64,
    pub last_valid_timestamp: u64,
    pub missed_heartbeats: u32,
    pub total_verified: u64,
    pub total_failed: u64,
    pub status: HeartbeatNodeStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum HeartbeatNodeStatus {
    #[default]
    Healthy,
    Suspect,
    Evicted,
}

impl NodeHeartbeatStatus {
    pub fn new(entangled_id: [u8; 32]) -> Self {
        Self {
            entangled_id: Some(entangled_id),
            ..Default::default()
        }
    }
    
    pub fn record_success(&mut self, epoch: u64, timestamp: u64) {
        self.last_valid_epoch = epoch;
        self.last_valid_timestamp = timestamp;
        self.missed_heartbeats = 0;
        self.total_verified += 1;
        self.status = HeartbeatNodeStatus::Healthy;
    }

    pub fn record_miss(&mut self, config: &VdfConfig) {
        self.missed_heartbeats += 1;
        self.total_failed += 1;
        if self.missed_heartbeats >= config.eviction_threshold {
            self.status = HeartbeatNodeStatus::Evicted;
        } else if self.missed_heartbeats >= config.suspect_threshold {
            self.status = HeartbeatNodeStatus::Suspect;
        }
    }

    pub fn should_evict(&self) -> bool {
        self.status == HeartbeatNodeStatus::Evicted
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_flow() {
        let config = VdfConfig::development();
        let vdf = VdfHeartbeat::new(config.clone()).expect("new");
        
        let challenge = HeartbeatChallenge::new([0u8; 32], 1);
        let proof = vdf.solve(&challenge).expect("solve");
        
        assert!(vdf.verify(&challenge, &proof).expect("verify").is_valid());
    }
}
