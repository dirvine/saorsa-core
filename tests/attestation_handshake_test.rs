// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Integration tests for the attestation handshake protocol.
//!
//! These tests verify the handshake exchange between peers, including:
//! - Mutual attestation proof exchange
//! - Verification of peer proofs
//! - Enforcement mode behavior (Off, Soft, Hard)
//! - Metrics collection during handshake
//!
//! ## Test Strategy
//!
//! Tests simulate two-party handshakes using the `AttestationHandshake` handler,
//! verifying that both parties correctly exchange and validate proofs.

use saorsa_core::attestation::{
    AttestationConfig, AttestationHandshake, AttestationMetricsCollector, AttestationProof,
    AttestationProofPublicInputs, AttestationVerificationResult, EnforcementMode, EntangledId,
    ProofType, VerificationTimer,
};
use saorsa_core::quantum_crypto::generate_ml_dsa_keypair;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Helper to get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs()
}

/// Create a mock attestation proof for testing.
fn create_mock_proof(entangled_id: [u8; 32], binary_hash: [u8; 32]) -> AttestationProof {
    AttestationProof {
        proof_bytes: vec![0u8; 32],
        public_inputs: AttestationProofPublicInputs {
            entangled_id,
            binary_hash,
            public_key_hash: [0u8; 32],
            proof_timestamp: current_timestamp(),
        },
        vkey_hash: [0u8; 32],
        proof_type: ProofType::Mock,
    }
}

/// Helper to create a handshake handler for a peer.
fn create_peer_handshake(
    config: AttestationConfig,
) -> (AttestationHandshake, EntangledId, AttestationProof) {
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let binary_hash = [0x42u8; 32];
    let nonce = fastrand::u64(..);

    let entangled_id = EntangledId::derive(&pk, &binary_hash, nonce);
    let proof = create_mock_proof(*entangled_id.id(), binary_hash);
    let handshake = AttestationHandshake::new(entangled_id.clone(), proof.clone(), config);

    (handshake, entangled_id, proof)
}

// ============================================================================
// Test: Basic Handshake Flow
// ============================================================================

#[test]
fn test_two_party_handshake_success() {
    // Arrange: Create two peers
    let config = AttestationConfig::development();
    let (alice_handshake, alice_id, _alice_proof) = create_peer_handshake(config.clone());
    let (bob_handshake, bob_id, _bob_proof) = create_peer_handshake(config);

    // Act: Exchange hello messages
    let alice_hello = alice_handshake.create_hello();
    let bob_hello = bob_handshake.create_hello();

    // Verify each other's proofs
    let (alice_result, alice_status) = bob_handshake.verify_hello(&alice_hello);
    let (bob_result, bob_status) = alice_handshake.verify_hello(&bob_hello);

    // Assert: Both verifications succeed
    assert!(alice_result.is_valid());
    assert!(bob_result.is_valid());
    assert!(alice_status.proof_valid);
    assert!(bob_status.proof_valid);

    // Verify the EntangledIds are captured
    assert_eq!(alice_status.entangled_id, Some(*alice_id.id()));
    assert_eq!(bob_status.entangled_id, Some(*bob_id.id()));
}

#[test]
fn test_hello_message_contains_correct_data() {
    // Arrange
    let config = AttestationConfig::development();
    let (handshake, entangled_id, proof) = create_peer_handshake(config);

    // Act
    let hello = handshake.create_hello();

    // Assert
    assert_eq!(hello.entangled_id, *entangled_id.id());
    assert_eq!(hello.protocol_version, 1);
    assert_eq!(hello.proof.proof_type, proof.proof_type);
}

// ============================================================================
// Test: Enforcement Mode Behavior
// ============================================================================

#[test]
fn test_soft_enforcement_logs_but_proceeds() {
    // Arrange
    let config = AttestationConfig::new(EnforcementMode::Soft);
    let (handshake, _id, _proof) = create_peer_handshake(config);

    // Create an invalid verification result
    let invalid_result = AttestationVerificationResult::Invalid("test failure".to_string());

    // Act: Check if connection should proceed
    let should_proceed = handshake.should_proceed(&invalid_result);

    // Assert: Soft mode proceeds even with invalid result
    assert!(should_proceed);
}

#[test]
fn test_hard_enforcement_rejects_invalid_proofs() {
    // Arrange
    let config = AttestationConfig::new(EnforcementMode::Hard);
    let (handshake, _id, _proof) = create_peer_handshake(config);

    // Create an invalid verification result
    let invalid_result = AttestationVerificationResult::Invalid("test failure".to_string());

    // Act
    let should_proceed = handshake.should_proceed(&invalid_result);

    // Assert: Hard mode rejects
    assert!(!should_proceed);
}

#[test]
fn test_off_enforcement_always_proceeds() {
    // Arrange
    let config = AttestationConfig::new(EnforcementMode::Off);
    let (handshake, _id, _proof) = create_peer_handshake(config);

    // Create various invalid results
    let results = vec![
        AttestationVerificationResult::Invalid("test".to_string()),
        AttestationVerificationResult::Stale,
        AttestationVerificationResult::BinaryNotAllowed,
        AttestationVerificationResult::NoProof,
    ];

    // Act & Assert: All proceed in Off mode
    for result in results {
        assert!(handshake.should_proceed(&result));
    }
}

#[test]
fn test_valid_proof_proceeds_in_all_modes() {
    let modes = vec![
        EnforcementMode::Off,
        EnforcementMode::Soft,
        EnforcementMode::Hard,
    ];

    for mode in modes {
        let config = AttestationConfig::new(mode);
        let (handshake, _id, _proof) = create_peer_handshake(config);

        let valid_result = AttestationVerificationResult::Valid;
        assert!(
            handshake.should_proceed(&valid_result),
            "Valid proof should proceed in {:?} mode",
            mode
        );
    }
}

// ============================================================================
// Test: Verification Failures
// ============================================================================

#[test]
fn test_verification_fails_for_id_mismatch() {
    // Arrange
    let config = AttestationConfig::development();
    let (handshake, _id, _proof) = create_peer_handshake(config);

    // Create a hello with mismatched ID (proof claims different ID than message)
    let wrong_entangled_id = [0x99u8; 32];
    let (_, _, fake_proof) = create_peer_handshake(AttestationConfig::development());
    // The proof still has its original entangled_id, but we'll use a different one in the hello
    let hello = saorsa_core::attestation::AttestationHello {
        entangled_id: wrong_entangled_id,
        proof: fake_proof,
        protocol_version: 1,
        heartbeat: None,
    };

    // Act
    let (result, status) = handshake.verify_hello(&hello);

    // Assert: ID mismatch detected
    assert!(!result.is_valid());
    assert!(!status.proof_valid);
}

#[test]
fn test_verification_fails_for_unsupported_protocol_version() {
    // Arrange
    let config = AttestationConfig::development();
    let (handshake, id, proof) = create_peer_handshake(config);

    // Create a hello with unsupported protocol version
    let hello = saorsa_core::attestation::AttestationHello {
        entangled_id: *id.id(),
        proof,
        protocol_version: 99, // Unsupported version
        heartbeat: None,
    };

    // Act
    let (result, status) = handshake.verify_hello(&hello);

    // Assert: Protocol version error
    assert!(!result.is_valid());
    assert!(!status.proof_valid);
    assert!(status.last_failure_reason.is_some());
}

// ============================================================================
// Test: Metrics Collection
// ============================================================================

#[tokio::test]
async fn test_metrics_collection_during_handshake() {
    // Arrange
    let metrics = Arc::new(AttestationMetricsCollector::new());

    // Simulate handshake operations
    metrics.record_handshake_initiated();

    let timer = VerificationTimer::start();
    // Simulate some verification work
    std::thread::sleep(std::time::Duration::from_micros(100));
    let duration = timer.elapsed_us();

    metrics.record_verification(true, duration);
    metrics.record_handshake_completed();

    // Act
    let snapshot = metrics.get_metrics().await;

    // Assert
    assert_eq!(snapshot.handshakes_initiated_total, 1);
    assert_eq!(snapshot.handshakes_completed_total, 1);
    assert_eq!(snapshot.verifications_total, 1);
    assert_eq!(snapshot.verifications_success_total, 1);
    assert!(snapshot.verification_time_us_avg > 0);
}

#[tokio::test]
async fn test_metrics_track_verification_failures() {
    // Arrange
    let metrics = Arc::new(AttestationMetricsCollector::new());

    // Record various verification failures
    metrics.record_verification(false, 100);
    metrics.record_stale_proof();
    metrics.record_binary_rejected();
    metrics.record_id_mismatch();

    // Act
    let snapshot = metrics.get_metrics().await;

    // Assert
    assert_eq!(snapshot.verifications_failed_total, 1);
    assert_eq!(snapshot.verifications_stale_total, 1);
    assert_eq!(snapshot.verifications_binary_rejected_total, 1);
    assert_eq!(snapshot.verifications_id_mismatch_total, 1);
}

#[tokio::test]
async fn test_metrics_track_enforcement_rejections() {
    // Arrange
    let metrics = Arc::new(AttestationMetricsCollector::new());

    metrics.record_enforcement_mode_change(2); // Hard mode
    metrics.record_hard_enforcement_rejection();
    metrics.record_hard_enforcement_rejection();

    // Act
    let snapshot = metrics.get_metrics().await;

    // Assert
    assert_eq!(snapshot.enforcement_mode_current, 2);
    assert_eq!(snapshot.hard_enforcement_rejections_total, 2);
}

// ============================================================================
// Test: Multiple Handshake Scenarios
// ============================================================================

#[test]
fn test_multiple_peer_handshakes() {
    // Simulate a node handshaking with multiple peers
    let config = AttestationConfig::development();
    let (my_handshake, _my_id, _my_proof) = create_peer_handshake(config.clone());

    // Create several peers
    let peers: Vec<_> = (0..5)
        .map(|_| create_peer_handshake(config.clone()))
        .collect();

    // Verify each peer
    for (peer_handshake, _peer_id, _peer_proof) in &peers {
        let peer_hello = peer_handshake.create_hello();
        let (result, status) = my_handshake.verify_hello(&peer_hello);

        assert!(result.is_valid());
        assert!(status.proof_valid);
        assert!(status.verified_at.is_some());
    }
}

#[test]
fn test_handshake_with_same_binary_hash() {
    // All peers running same authorized binary
    let config = AttestationConfig::development();
    let (handshake1, _id1, _proof1) = create_peer_handshake(config.clone());
    let (handshake2, _id2, _proof2) = create_peer_handshake(config);

    // Both using same binary hash (0x42... from create_peer_handshake)
    let hello1 = handshake1.create_hello();
    let hello2 = handshake2.create_hello();

    // Verify binary hashes match
    assert_eq!(
        hello1.proof.public_inputs.binary_hash,
        hello2.proof.public_inputs.binary_hash
    );

    // Both should verify successfully
    let (result1, _) = handshake2.verify_hello(&hello1);
    let (result2, _) = handshake1.verify_hello(&hello2);

    assert!(result1.is_valid());
    assert!(result2.is_valid());
}

// ============================================================================
// Test: Peer Attestation Status Tracking
// ============================================================================

#[test]
fn test_peer_status_tracking_verified() {
    let config = AttestationConfig::development();
    let (handshake, _id, _proof) = create_peer_handshake(config.clone());
    let (peer_handshake, _peer_id, _peer_proof) = create_peer_handshake(config);

    let peer_hello = peer_handshake.create_hello();
    let (result, status) = handshake.verify_hello(&peer_hello);

    assert!(result.is_valid());
    assert!(status.proof_valid);
    assert!(status.entangled_id.is_some());
    assert!(status.verified_at.is_some());
    assert!(status.binary_hash.is_some());
    assert_eq!(status.verification_attempts, 1);
    assert!(status.last_failure_reason.is_none());
}

#[test]
fn test_peer_status_tracking_failed() {
    let config = AttestationConfig::development();
    let (handshake, _id, _proof) = create_peer_handshake(config);

    // Create invalid hello
    let hello = saorsa_core::attestation::AttestationHello {
        entangled_id: [0x99u8; 32],
        proof: create_mock_proof([0x11u8; 32], [0x42u8; 32]), // Mismatched ID
        protocol_version: 1,
        heartbeat: None,
    };

    let (result, status) = handshake.verify_hello(&hello);

    assert!(!result.is_valid());
    assert!(!status.proof_valid);
    assert!(status.entangled_id.is_none());
    assert!(status.last_failure_reason.is_some());
}

// ============================================================================
// Test: Timer Accuracy
// ============================================================================

#[test]
fn test_verification_timer_measures_elapsed_time() {
    let timer = VerificationTimer::start();

    // Sleep for a known duration
    std::thread::sleep(std::time::Duration::from_millis(10));

    let elapsed = timer.elapsed_us();

    // Should be at least 10000 microseconds (10ms)
    assert!(
        elapsed >= 10000,
        "Expected at least 10000us, got {}us",
        elapsed
    );
    // Should be less than 50ms (accounting for overhead)
    assert!(
        elapsed < 50000,
        "Expected less than 50000us, got {}us",
        elapsed
    );
}

// ============================================================================
// Test: Production Configuration
// ============================================================================

#[test]
fn test_production_config_binary_enforcement() {
    // Production config with specific allowed binary
    let allowed_binary = [0x42u8; 32];
    let config = AttestationConfig::production(vec![allowed_binary]);

    let (handshake, _id, _proof) = create_peer_handshake(config);

    // Create peer with allowed binary (same as our binary hash)
    let peer_config = AttestationConfig::development();
    let (peer_handshake, _peer_id, _peer_proof) = create_peer_handshake(peer_config);

    let peer_hello = peer_handshake.create_hello();
    let (result, _status) = handshake.verify_hello(&peer_hello);

    // Should succeed because peer's binary (0x42...) is in allowed list
    assert!(result.is_valid());
}
