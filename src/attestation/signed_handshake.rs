// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Signed Handshake Protocol for software-attested P2P connections.
//!
//! This module implements a challenge-response handshake that proves:
//! 1. **Key ownership** - Node controls the private key
//! 2. **Liveness** - Fresh challenge-response prevents replay
//! 3. **Identity consistency** - EntangledId derivation is correct
//!
//! ## Protocol Flow
//!
//! ```text
//! Node A                                    Node B
//!   |                                          |
//!   |  1. Challenge (random_a, timestamp)      |
//!   |----------------------------------------->|
//!   |                                          |
//!   |  2. Challenge (random_b, timestamp)      |
//!   |<-----------------------------------------|
//!   |                                          |
//!   |  3. SignedResponse (hello, sig(random_b))|
//!   |----------------------------------------->|
//!   |                                          |
//!   |  4. SignedResponse (hello, sig(random_a))|
//!   |<-----------------------------------------|
//!   |                                          |
//!   |  5. Both verify:                         |
//!   |     - Signature covers their challenge   |
//!   |     - EntangledId derivation correct     |
//!   |     - Timestamp fresh                    |
//!   |                                          |
//! ```
//!
//! ## Security Properties
//!
//! - **Replay Prevention**: Each challenge is unique and short-lived
//! - **Key Binding**: Signature proves private key ownership
//! - **Identity Binding**: Derivation check ensures EntangledId consistency
//! - **Freshness**: Timestamp prevents stale response reuse

use super::AttestationError;
use super::signed_heartbeat::SignedHeartbeat;
use crate::quantum_crypto::ant_quic_integration::{
    MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, ml_dsa_sign, ml_dsa_verify,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for signed handshake verification.
#[derive(Debug, Clone)]
pub struct SignedHandshakeConfig {
    /// Maximum age for handshake messages (seconds).
    pub max_hello_age_secs: u64,

    /// Maximum age for challenges (seconds).
    pub max_challenge_age_secs: u64,

    /// Allowed binary hashes (empty = allow all).
    pub allowed_binaries: Vec<[u8; 32]>,
}

impl Default for SignedHandshakeConfig {
    fn default() -> Self {
        Self {
            max_hello_age_secs: 60,       // 1 minute
            max_challenge_age_secs: 30,   // 30 seconds
            allowed_binaries: Vec::new(), // Allow all
        }
    }
}

// ============================================================================
// Challenge
// ============================================================================

/// Challenge sent to initiate handshake.
///
/// The peer must sign their response including this challenge
/// to prove liveness and prevent replay attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeChallenge {
    /// Random challenge bytes (32 bytes for security).
    pub challenge: [u8; 32],

    /// Timestamp when challenge was created.
    pub timestamp: u64,

    /// Challenger's EntangledId (so peer knows who is asking).
    pub from_entangled_id: [u8; 32],
}

impl HandshakeChallenge {
    /// Create a new random challenge.
    pub fn new(from_entangled_id: [u8; 32]) -> Self {
        let mut challenge = [0u8; 32];
        for byte in &mut challenge {
            *byte = fastrand::u8(..);
        }

        Self {
            challenge,
            timestamp: current_timestamp(),
            from_entangled_id,
        }
    }

    /// Check if the challenge is still fresh.
    #[must_use]
    pub fn is_fresh(&self, max_age_secs: u64) -> bool {
        let now = current_timestamp();
        now.saturating_sub(self.timestamp) <= max_age_secs
    }
}

// ============================================================================
// Hello Data
// ============================================================================

/// Core attestation data in handshake.
///
/// Contains all information needed to verify a node's identity
/// and software attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeHelloData {
    /// Software-attested identity.
    pub entangled_id: [u8; 32],

    /// ML-DSA-65 public key.
    pub public_key: Vec<u8>,

    /// Binary hash used in EntangledId derivation.
    pub binary_hash: [u8; 32],

    /// Nonce used in derivation.
    pub derivation_nonce: u64,

    /// Fresh timestamp.
    pub timestamp: u64,

    /// Random nonce for uniqueness.
    pub nonce: [u8; 16],

    /// Protocol version (3 = signed handshake).
    pub protocol_version: u8,

    /// Latest signed heartbeat (proves recent liveness).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_heartbeat: Option<SignedHeartbeat>,
}

impl HandshakeHelloData {
    /// Current protocol version for signed handshake.
    pub const PROTOCOL_VERSION: u8 = 3;

    /// Create the payload bytes for signing.
    ///
    /// The signature covers: hello_data || challenge
    #[must_use]
    pub fn signing_payload(&self, challenge: &[u8; 32]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(128);

        // Hello data
        payload.extend_from_slice(&self.entangled_id);
        payload.extend_from_slice(&self.public_key);
        payload.extend_from_slice(&self.binary_hash);
        payload.extend_from_slice(&self.derivation_nonce.to_le_bytes());
        payload.extend_from_slice(&self.timestamp.to_le_bytes());
        payload.extend_from_slice(&self.nonce);
        payload.push(self.protocol_version);

        // Challenge (what we're responding to)
        payload.extend_from_slice(challenge);

        payload
    }

    /// Verify the EntangledId derivation is correct.
    #[must_use]
    pub fn verify_derivation(&self) -> bool {
        let derived =
            derive_entangled_id(&self.public_key, &self.binary_hash, self.derivation_nonce);
        derived == self.entangled_id
    }
}

// ============================================================================
// Signed Response
// ============================================================================

/// Signed response to a handshake challenge.
///
/// Contains the hello data and a signature proving the node
/// controls the private key and is responding to a specific challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHandshakeResponse {
    /// The hello data being attested.
    pub hello: HandshakeHelloData,

    /// ML-DSA signature over (hello || challenge).
    pub signature: Vec<u8>,

    /// The challenge we're responding to.
    pub challenge: [u8; 32],
}

impl SignedHandshakeResponse {
    /// Create a signed response to a challenge.
    pub fn create(
        hello: HandshakeHelloData,
        secret_key: &MlDsaSecretKey,
        challenge: &[u8; 32],
    ) -> Result<Self, AttestationError> {
        let payload = hello.signing_payload(challenge);

        let signature = ml_dsa_sign(secret_key, &payload)
            .map_err(|e| AttestationError::CryptoError(format!("Signing failed: {}", e)))?;

        Ok(Self {
            hello,
            signature: signature.as_bytes().to_vec(),
            challenge: *challenge,
        })
    }
}

// ============================================================================
// Verification
// ============================================================================

/// Result of handshake verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeVerifyResult {
    /// Fully verified - handshake successful.
    Valid,

    /// Wrong challenge - not responding to our challenge.
    ChallengeMismatch,

    /// Challenge is too old.
    ChallengeExpired,

    /// Signature invalid.
    InvalidSignature(String),

    /// Timestamp too old.
    HelloStale,

    /// EntangledId derivation doesn't match.
    DerivationMismatch,

    /// Binary not in allowed list.
    BinaryNotAllowed,

    /// Invalid public key format.
    InvalidPublicKey(String),

    /// Protocol version mismatch.
    UnsupportedProtocol(u8),
}

impl HandshakeVerifyResult {
    /// Check if verification succeeded.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// Verifier for signed handshake responses.
pub struct SignedHandshakeVerifier {
    config: SignedHandshakeConfig,
}

impl SignedHandshakeVerifier {
    /// Create a new verifier with the given configuration.
    #[must_use]
    pub fn new(config: SignedHandshakeConfig) -> Self {
        Self { config }
    }

    /// Verify a signed handshake response.
    ///
    /// # Arguments
    /// * `response` - The signed response to verify
    /// * `expected_challenge` - The challenge we sent
    ///
    /// # Returns
    /// Verification result indicating success or specific failure reason.
    pub fn verify(
        &self,
        response: &SignedHandshakeResponse,
        expected_challenge: &[u8; 32],
    ) -> HandshakeVerifyResult {
        // 1. Protocol version check
        if response.hello.protocol_version < HandshakeHelloData::PROTOCOL_VERSION {
            return HandshakeVerifyResult::UnsupportedProtocol(response.hello.protocol_version);
        }

        // 2. Challenge matches what we sent
        if response.challenge != *expected_challenge {
            return HandshakeVerifyResult::ChallengeMismatch;
        }

        // 3. Hello timestamp freshness
        let now = current_timestamp();
        if now.saturating_sub(response.hello.timestamp) > self.config.max_hello_age_secs {
            return HandshakeVerifyResult::HelloStale;
        }

        // 4. Binary allowlist check (if configured)
        if !self.config.allowed_binaries.is_empty()
            && !self
                .config
                .allowed_binaries
                .contains(&response.hello.binary_hash)
        {
            return HandshakeVerifyResult::BinaryNotAllowed;
        }

        // 5. EntangledId derivation verification
        if !response.hello.verify_derivation() {
            return HandshakeVerifyResult::DerivationMismatch;
        }

        // 6. Parse public key
        let public_key = match MlDsaPublicKey::from_bytes(&response.hello.public_key) {
            Ok(pk) => pk,
            Err(e) => return HandshakeVerifyResult::InvalidPublicKey(e.to_string()),
        };

        // 7. Parse signature
        let signature = match MlDsaSignature::from_bytes(&response.signature) {
            Ok(sig) => sig,
            Err(e) => return HandshakeVerifyResult::InvalidSignature(format!("Bad format: {}", e)),
        };

        // 8. Verify signature
        let payload = response.hello.signing_payload(&response.challenge);
        match ml_dsa_verify(&public_key, &payload, &signature) {
            Ok(true) => HandshakeVerifyResult::Valid,
            Ok(false) => HandshakeVerifyResult::InvalidSignature("Signature mismatch".into()),
            Err(e) => HandshakeVerifyResult::InvalidSignature(e.to_string()),
        }
    }
}

// ============================================================================
// Handshake State Machine
// ============================================================================

/// State machine for managing signed handshakes.
///
/// Tracks pending challenges and provides methods for creating
/// challenges, responses, and verifying peer responses.
pub struct SignedHandshake {
    /// Our EntangledId.
    local_entangled_id: [u8; 32],

    /// Our public key.
    public_key: MlDsaPublicKey,

    /// Our secret key.
    secret_key: MlDsaSecretKey,

    /// Our binary hash.
    binary_hash: [u8; 32],

    /// Our derivation nonce.
    derivation_nonce: u64,

    /// Verifier for peer responses.
    verifier: SignedHandshakeVerifier,

    /// Pending outbound challenges (peer_id -> challenge).
    pending_challenges: HashMap<[u8; 32], HandshakeChallenge>,

    /// Our cached hello data (refreshed periodically).
    cached_hello: Option<HandshakeHelloData>,

    /// Latest heartbeat to include in hello.
    latest_heartbeat: Option<SignedHeartbeat>,
}

impl SignedHandshake {
    /// Create a new signed handshake handler.
    pub fn new(
        entangled_id: [u8; 32],
        public_key: MlDsaPublicKey,
        secret_key: MlDsaSecretKey,
        binary_hash: [u8; 32],
        derivation_nonce: u64,
        config: SignedHandshakeConfig,
    ) -> Self {
        Self {
            local_entangled_id: entangled_id,
            public_key,
            secret_key,
            binary_hash,
            derivation_nonce,
            verifier: SignedHandshakeVerifier::new(config),
            pending_challenges: HashMap::new(),
            cached_hello: None,
            latest_heartbeat: None,
        }
    }

    /// Create from raw key bytes.
    pub fn from_bytes(
        entangled_id: [u8; 32],
        public_key_bytes: &[u8],
        secret_key_bytes: &[u8],
        binary_hash: [u8; 32],
        derivation_nonce: u64,
        config: SignedHandshakeConfig,
    ) -> Result<Self, AttestationError> {
        let public_key = MlDsaPublicKey::from_bytes(public_key_bytes)
            .map_err(|e| AttestationError::CryptoError(format!("Invalid public key: {}", e)))?;
        let secret_key = MlDsaSecretKey::from_bytes(secret_key_bytes)
            .map_err(|e| AttestationError::CryptoError(format!("Invalid secret key: {}", e)))?;

        Ok(Self::new(
            entangled_id,
            public_key,
            secret_key,
            binary_hash,
            derivation_nonce,
            config,
        ))
    }

    /// Get our EntangledId.
    #[must_use]
    pub fn entangled_id(&self) -> &[u8; 32] {
        &self.local_entangled_id
    }

    /// Update the latest heartbeat to include in hellos.
    pub fn set_latest_heartbeat(&mut self, heartbeat: SignedHeartbeat) {
        self.latest_heartbeat = Some(heartbeat);
        // Invalidate cached hello
        self.cached_hello = None;
    }

    /// Create a fresh hello data structure.
    fn create_hello(&self) -> HandshakeHelloData {
        let mut nonce = [0u8; 16];
        for byte in &mut nonce {
            *byte = fastrand::u8(..);
        }

        HandshakeHelloData {
            entangled_id: self.local_entangled_id,
            public_key: self.public_key.as_bytes().to_vec(),
            binary_hash: self.binary_hash,
            derivation_nonce: self.derivation_nonce,
            timestamp: current_timestamp(),
            nonce,
            protocol_version: HandshakeHelloData::PROTOCOL_VERSION,
            latest_heartbeat: self.latest_heartbeat.clone(),
        }
    }

    // ========================================================================
    // Protocol Steps
    // ========================================================================

    /// Step 1: Create a challenge to send to a peer.
    ///
    /// Call this when initiating a connection. Store the returned challenge
    /// and send it to the peer.
    pub fn create_challenge(&mut self, peer_entangled_id: [u8; 32]) -> HandshakeChallenge {
        let challenge = HandshakeChallenge::new(self.local_entangled_id);

        // Store for later verification
        self.pending_challenges
            .insert(peer_entangled_id, challenge.clone());

        challenge
    }

    /// Step 2: Respond to a challenge from a peer.
    ///
    /// Call this when you receive a challenge. Returns a signed response
    /// proving your identity.
    pub fn respond_to_challenge(
        &self,
        challenge: &HandshakeChallenge,
    ) -> Result<SignedHandshakeResponse, AttestationError> {
        // Create fresh hello
        let hello = self.create_hello();

        // Create signed response
        SignedHandshakeResponse::create(hello, &self.secret_key, &challenge.challenge)
    }

    /// Step 3: Verify a peer's response to our challenge.
    ///
    /// Call this when you receive a response. Returns the verification result.
    pub fn verify_response(
        &mut self,
        peer_entangled_id: &[u8; 32],
        response: &SignedHandshakeResponse,
    ) -> HandshakeVerifyResult {
        // Get the challenge we sent to this peer
        let challenge = match self.pending_challenges.remove(peer_entangled_id) {
            Some(c) => c,
            None => {
                tracing::warn!(
                    peer = %hex::encode(&peer_entangled_id[..8]),
                    "No pending challenge for peer"
                );
                return HandshakeVerifyResult::ChallengeMismatch;
            }
        };

        // Check challenge freshness
        if !challenge.is_fresh(self.verifier.config.max_challenge_age_secs) {
            return HandshakeVerifyResult::ChallengeExpired;
        }

        // Verify the response
        let result = self.verifier.verify(response, &challenge.challenge);

        // Log result
        if result.is_valid() {
            tracing::debug!(
                peer = %hex::encode(&peer_entangled_id[..8]),
                "Handshake verification successful"
            );
        } else {
            tracing::warn!(
                peer = %hex::encode(&peer_entangled_id[..8]),
                result = ?result,
                "Handshake verification failed"
            );
        }

        result
    }

    /// Cancel a pending challenge (e.g., on connection timeout).
    pub fn cancel_challenge(&mut self, peer_entangled_id: &[u8; 32]) {
        self.pending_challenges.remove(peer_entangled_id);
    }

    /// Clean up expired challenges.
    pub fn cleanup_expired_challenges(&mut self) {
        let max_age = self.verifier.config.max_challenge_age_secs;
        self.pending_challenges.retain(|_, c| c.is_fresh(max_age));
    }
}

// ============================================================================
// EntangledId Derivation
// ============================================================================

/// Derive an EntangledId from components.
///
/// Uses BLAKE3: `EntangledId = BLAKE3(public_key || binary_hash || nonce)`
fn derive_entangled_id(public_key: &[u8], binary_hash: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(public_key);
    hasher.update(binary_hash);
    hasher.update(&nonce.to_le_bytes());
    *hasher.finalize().as_bytes()
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get current Unix timestamp in seconds.
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
    use crate::quantum_crypto::ant_quic_integration::generate_ml_dsa_keypair;

    fn create_test_handshake(id: u8) -> SignedHandshake {
        let (pk, sk) = generate_ml_dsa_keypair().expect("keygen");
        let binary_hash = [id; 32];
        let nonce = id as u64;

        // Derive the actual EntangledId
        let entangled_id = derive_entangled_id(pk.as_bytes(), &binary_hash, nonce);

        SignedHandshake::new(
            entangled_id,
            pk,
            sk,
            binary_hash,
            nonce,
            SignedHandshakeConfig::default(),
        )
    }

    #[test]
    fn test_challenge_creation() {
        let mut handshake = create_test_handshake(1);
        let peer_id = [2u8; 32];

        let challenge = handshake.create_challenge(peer_id);

        assert_eq!(challenge.from_entangled_id, *handshake.entangled_id());
        assert!(challenge.is_fresh(60));
    }

    #[test]
    fn test_full_handshake_success() {
        let mut alice = create_test_handshake(1);
        let bob = create_test_handshake(2);

        // Alice sends challenge to Bob
        let alice_challenge = alice.create_challenge(*bob.entangled_id());

        // Bob responds to Alice's challenge
        let bob_response = bob.respond_to_challenge(&alice_challenge).expect("respond");

        // Alice verifies Bob's response
        let result = alice.verify_response(bob.entangled_id(), &bob_response);

        assert!(result.is_valid(), "Expected Valid, got {:?}", result);
    }

    #[test]
    fn test_mutual_handshake() {
        let mut alice = create_test_handshake(1);
        let mut bob = create_test_handshake(2);

        // Both send challenges
        let alice_challenge = alice.create_challenge(*bob.entangled_id());
        let bob_challenge = bob.create_challenge(*alice.entangled_id());

        // Both respond
        let alice_response = alice
            .respond_to_challenge(&bob_challenge)
            .expect("alice respond");
        let bob_response = bob
            .respond_to_challenge(&alice_challenge)
            .expect("bob respond");

        // Both verify
        let alice_result = alice.verify_response(bob.entangled_id(), &bob_response);
        let bob_result = bob.verify_response(alice.entangled_id(), &alice_response);

        assert!(alice_result.is_valid());
        assert!(bob_result.is_valid());
    }

    #[test]
    fn test_wrong_challenge_rejected() {
        let mut alice = create_test_handshake(1);
        let bob = create_test_handshake(2);

        // Alice sends challenge
        let _alice_challenge = alice.create_challenge(*bob.entangled_id());

        // Bob responds to a DIFFERENT challenge (replay attack simulation)
        let fake_challenge = HandshakeChallenge::new([99u8; 32]);
        let bob_response = bob.respond_to_challenge(&fake_challenge).expect("respond");

        // Alice verifies - should fail because Bob responded to wrong challenge
        let result = alice.verify_response(bob.entangled_id(), &bob_response);

        assert_eq!(result, HandshakeVerifyResult::ChallengeMismatch);
    }

    #[test]
    fn test_tampered_response_rejected() {
        let mut alice = create_test_handshake(1);
        let bob = create_test_handshake(2);

        // Normal handshake start
        let alice_challenge = alice.create_challenge(*bob.entangled_id());
        let mut bob_response = bob.respond_to_challenge(&alice_challenge).expect("respond");

        // Tamper with the response (change entangled_id)
        bob_response.hello.entangled_id[0] ^= 0xFF;

        // Verification should fail (derivation won't match)
        let result = alice.verify_response(bob.entangled_id(), &bob_response);

        assert!(
            matches!(
                result,
                HandshakeVerifyResult::DerivationMismatch
                    | HandshakeVerifyResult::InvalidSignature(_)
            ),
            "Expected DerivationMismatch or InvalidSignature, got {:?}",
            result
        );
    }

    #[test]
    fn test_replay_attack_prevented() {
        let mut alice = create_test_handshake(1);
        let bob = create_test_handshake(2);

        // First handshake
        let challenge1 = alice.create_challenge(*bob.entangled_id());
        let response1 = bob.respond_to_challenge(&challenge1).expect("respond");
        let result1 = alice.verify_response(bob.entangled_id(), &response1);
        assert!(result1.is_valid());

        // Try to replay the same response with a new challenge
        let _challenge2 = alice.create_challenge(*bob.entangled_id());
        let result2 = alice.verify_response(bob.entangled_id(), &response1);

        // Should fail because response was for challenge1, not challenge2
        assert_eq!(result2, HandshakeVerifyResult::ChallengeMismatch);
    }

    #[test]
    fn test_no_pending_challenge_rejected() {
        let mut alice = create_test_handshake(1);
        let bob = create_test_handshake(2);

        // Bob creates a response without Alice sending a challenge
        let fake_challenge = HandshakeChallenge::new([99u8; 32]);
        let bob_response = bob.respond_to_challenge(&fake_challenge).expect("respond");

        // Alice tries to verify (but never sent a challenge)
        let result = alice.verify_response(bob.entangled_id(), &bob_response);

        assert_eq!(result, HandshakeVerifyResult::ChallengeMismatch);
    }

    #[test]
    fn test_derivation_verification() {
        let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen");
        let binary_hash = [42u8; 32];
        let nonce = 12345u64;

        let entangled_id = derive_entangled_id(pk.as_bytes(), &binary_hash, nonce);

        let hello = HandshakeHelloData {
            entangled_id,
            public_key: pk.as_bytes().to_vec(),
            binary_hash,
            derivation_nonce: nonce,
            timestamp: current_timestamp(),
            nonce: [0u8; 16],
            protocol_version: 3,
            latest_heartbeat: None,
        };

        assert!(hello.verify_derivation());

        // Wrong nonce should fail
        let mut bad_hello = hello.clone();
        bad_hello.derivation_nonce = 99999;
        assert!(!bad_hello.verify_derivation());
    }

    #[test]
    fn test_binary_allowlist() {
        let mut alice = create_test_handshake(1);
        let bob = create_test_handshake(2);

        // Configure Alice to only allow specific binary
        alice.verifier.config.allowed_binaries = vec![[99u8; 32]]; // Not Bob's binary

        let challenge = alice.create_challenge(*bob.entangled_id());
        let response = bob.respond_to_challenge(&challenge).expect("respond");
        let result = alice.verify_response(bob.entangled_id(), &response);

        assert_eq!(result, HandshakeVerifyResult::BinaryNotAllowed);
    }

    #[test]
    fn test_stale_hello_rejected() {
        let mut alice = create_test_handshake(1);
        let bob = create_test_handshake(2);

        let challenge = alice.create_challenge(*bob.entangled_id());
        let mut response = bob.respond_to_challenge(&challenge).expect("respond");

        // Manually set timestamp to be old (2 minutes ago)
        response.hello.timestamp = current_timestamp().saturating_sub(120);

        // Configure max age to be 60 seconds
        alice.verifier.config.max_hello_age_secs = 60;

        // Response should be stale
        let result = alice.verify_response(bob.entangled_id(), &response);

        // Will fail as either stale OR signature mismatch (since we changed timestamp after signing)
        assert!(
            matches!(
                result,
                HandshakeVerifyResult::HelloStale | HandshakeVerifyResult::InvalidSignature(_)
            ),
            "Expected HelloStale or InvalidSignature, got {:?}",
            result
        );
    }

    #[test]
    fn test_cleanup_expired_challenges() {
        let mut handshake = create_test_handshake(1);

        // Create challenges
        handshake.create_challenge([2u8; 32]);
        handshake.create_challenge([3u8; 32]);

        assert_eq!(handshake.pending_challenges.len(), 2);

        // Manually make the challenges old by modifying their timestamps
        for challenge in handshake.pending_challenges.values_mut() {
            challenge.timestamp = current_timestamp().saturating_sub(120); // 2 minutes ago
        }

        // Set max age to 60 seconds
        handshake.verifier.config.max_challenge_age_secs = 60;

        // Cleanup should remove them (they're now older than 60 seconds)
        handshake.cleanup_expired_challenges();

        assert_eq!(handshake.pending_challenges.len(), 0);
    }

    #[test]
    fn test_signing_payload_deterministic() {
        let hello = HandshakeHelloData {
            entangled_id: [1u8; 32],
            public_key: vec![2u8; 100],
            binary_hash: [3u8; 32],
            derivation_nonce: 12345,
            timestamp: 1000000,
            nonce: [4u8; 16],
            protocol_version: 3,
            latest_heartbeat: None,
        };

        let challenge = [5u8; 32];

        let payload1 = hello.signing_payload(&challenge);
        let payload2 = hello.signing_payload(&challenge);

        assert_eq!(payload1, payload2);
    }
}
