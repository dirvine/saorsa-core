// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Integration tests for VDF heartbeat system.
//!
//! These tests verify the heartbeat lifecycle including:
//! - Challenge generation and serialization
//! - VDF proof generation and verification
//! - Node status tracking and eviction
//! - Multi-epoch heartbeat sequences
//!
//! ## Test Strategy
//!
//! Tests use mock VDF for speed but exercise the full protocol flow.
//! Real VDF tests are available with the `vdf` feature flag.

use saorsa_core::attestation::{
    EntangledId, HeartbeatChallenge, HeartbeatNodeStatus, HeartbeatProof,
    HeartbeatVerificationResult, NodeHeartbeatStatus, VdfConfig, VdfHeartbeat, VdfProofType,
};
use saorsa_core::quantum_crypto::generate_ml_dsa_keypair;
use std::time::{SystemTime, UNIX_EPOCH};

/// Helper to get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs()
}

// ============================================================================
// Test: Challenge Lifecycle
// ============================================================================

#[test]
fn test_challenge_creation_binds_to_identity() {
    // Create an entangled identity
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let binary_hash = [0x42u8; 32];
    let nonce = fastrand::u64(..);
    let entangled_id = EntangledId::derive(&pk, &binary_hash, nonce);

    // Create challenge bound to identity
    let challenge = HeartbeatChallenge::new(*entangled_id.id(), 1);

    // Verify binding
    assert_eq!(challenge.entangled_id, *entangled_id.id());
    assert_eq!(challenge.epoch, 1);
    assert!(challenge.timestamp > 0);
}

#[test]
fn test_challenge_serialization_deterministic() {
    let entangled_id = [0x42u8; 32];
    let epoch = 100u64;
    let timestamp = 1700000000u64;

    // Create two challenges with same parameters
    let mut challenge1 = HeartbeatChallenge::with_timestamp(entangled_id, epoch, timestamp);
    let nonce = [0xAAu8; 16];
    challenge1.nonce = nonce;

    let mut challenge2 = HeartbeatChallenge::with_timestamp(entangled_id, epoch, timestamp);
    challenge2.nonce = nonce;

    // Serializations should match
    assert_eq!(challenge1.to_bytes(), challenge2.to_bytes());
}

#[test]
fn test_challenge_freshness_window() {
    let config = VdfConfig {
        max_proof_age_secs: 60,
        ..VdfConfig::development()
    };

    let now = current_timestamp();
    let fresh_challenge = HeartbeatChallenge::with_timestamp([0x42u8; 32], 1, now);
    let stale_challenge = HeartbeatChallenge::with_timestamp([0x42u8; 32], 1, now - 120);

    assert!(fresh_challenge.is_fresh(config.max_proof_age_secs, now));
    assert!(!stale_challenge.is_fresh(config.max_proof_age_secs, now));
}

// ============================================================================
// Test: VDF Solve and Verify Flow
// ============================================================================

#[test]
fn test_full_vdf_solve_verify_cycle() {
    let config = VdfConfig::development();
    let vdf = VdfHeartbeat::mock(config.clone());

    // Create identity and challenge
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let binary_hash = [0x42u8; 32];
    let entangled_id = EntangledId::derive(&pk, &binary_hash, 12345);

    let challenge = HeartbeatChallenge::new(*entangled_id.id(), 1);

    // Solve
    let proof = vdf.solve(&challenge).expect("solve failed");

    // Verify
    let result = vdf.verify(&challenge, &proof).expect("verify failed");
    assert!(result.is_valid());

    // Check proof properties
    assert_eq!(proof.proof_type, VdfProofType::Mock);
    assert_eq!(proof.iterations, config.iterations);
    assert_eq!(proof.discriminant_bits, config.discriminant_bits);
}

#[test]
fn test_vdf_rejects_tampered_proof() {
    let config = VdfConfig::development();
    let vdf = VdfHeartbeat::mock(config);

    let challenge = HeartbeatChallenge::new([0x42u8; 32], 1);

    let mut proof = vdf.solve(&challenge).expect("solve failed");

    // Tamper with the output
    if !proof.vdf_output.is_empty() {
        proof.vdf_output[0] ^= 0xFF;
    }

    // Verification should fail
    let result = vdf.verify(&challenge, &proof).expect("verify failed");
    assert!(!result.is_valid());
    assert!(matches!(
        result,
        HeartbeatVerificationResult::ChallengeMismatch
    ));
}

#[test]
fn test_vdf_rejects_wrong_challenge() {
    let config = VdfConfig::development();
    let vdf = VdfHeartbeat::mock(config);

    // Solve for one challenge
    let challenge1 = HeartbeatChallenge::new([0x42u8; 32], 1);
    let proof = vdf.solve(&challenge1).expect("solve failed");

    // Try to verify against different challenge
    let challenge2 = HeartbeatChallenge::new([0x99u8; 32], 1);
    let result = vdf.verify(&challenge2, &proof).expect("verify failed");

    assert!(!result.is_valid());
}

// ============================================================================
// Test: Node Status Tracking
// ============================================================================

#[test]
fn test_node_status_healthy_after_success() {
    let entangled_id = [0x42u8; 32];

    let mut status = NodeHeartbeatStatus::new(entangled_id);
    assert_eq!(status.status, HeartbeatNodeStatus::Healthy);

    // Record successful heartbeat
    let now = current_timestamp();
    status.record_success(1, now);

    assert_eq!(status.status, HeartbeatNodeStatus::Healthy);
    assert_eq!(status.total_verified, 1);
    assert_eq!(status.last_valid_epoch, 1);
    assert_eq!(status.missed_heartbeats, 0);
}

#[test]
fn test_node_status_becomes_suspect_after_misses() {
    let config = VdfConfig {
        suspect_threshold: 3,
        eviction_threshold: 5,
        ..VdfConfig::development()
    };

    let mut status = NodeHeartbeatStatus::new([0x42u8; 32]);

    // Miss heartbeats until suspect
    for _ in 0..config.suspect_threshold {
        assert_eq!(
            status.status,
            HeartbeatNodeStatus::Healthy,
            "Should be healthy before {} misses",
            config.suspect_threshold
        );
        status.record_miss(&config);
    }

    assert!(status.is_suspect());
    assert!(!status.should_evict());
    assert_eq!(status.total_failed, config.suspect_threshold as u64);
}

#[test]
fn test_node_status_evicted_after_threshold() {
    let config = VdfConfig {
        suspect_threshold: 3,
        eviction_threshold: 5,
        ..VdfConfig::development()
    };

    let mut status = NodeHeartbeatStatus::new([0x42u8; 32]);

    // Miss enough heartbeats for eviction
    for _ in 0..config.eviction_threshold {
        status.record_miss(&config);
    }

    assert!(status.should_evict());
    assert_eq!(status.status, HeartbeatNodeStatus::Evicted);
}

#[test]
fn test_node_status_recovers_after_success() {
    let config = VdfConfig {
        suspect_threshold: 3,
        eviction_threshold: 5,
        ..VdfConfig::development()
    };

    let mut status = NodeHeartbeatStatus::new([0x42u8; 32]);

    // Miss enough to become suspect
    for _ in 0..config.suspect_threshold {
        status.record_miss(&config);
    }
    assert!(status.is_suspect());

    // Successful heartbeat should recover
    status.record_success(1, current_timestamp());

    assert_eq!(status.status, HeartbeatNodeStatus::Healthy);
    assert_eq!(status.missed_heartbeats, 0);
}

// ============================================================================
// Test: Multi-Epoch Sequences
// ============================================================================

#[test]
fn test_multi_epoch_heartbeat_sequence() {
    let config = VdfConfig::development();
    let vdf = VdfHeartbeat::mock(config.clone());

    let entangled_id = [0x42u8; 32];
    let mut status = NodeHeartbeatStatus::new(entangled_id);

    // Simulate 10 successful heartbeats across epochs
    for epoch in 1..=10 {
        let challenge = HeartbeatChallenge::new(entangled_id, epoch);
        let proof = vdf.solve(&challenge).expect("solve failed");
        let result = vdf.verify(&challenge, &proof).expect("verify failed");

        assert!(result.is_valid());
        status.record_success(epoch, current_timestamp());
    }

    assert_eq!(status.total_verified, 10);
    assert_eq!(status.last_valid_epoch, 10);
    assert_eq!(status.status, HeartbeatNodeStatus::Healthy);
}

#[test]
fn test_mixed_success_and_failure_sequence() {
    let config = VdfConfig {
        suspect_threshold: 2,
        eviction_threshold: 4,
        ..VdfConfig::development()
    };

    let mut status = NodeHeartbeatStatus::new([0x42u8; 32]);

    // Success, miss, success, miss, miss (becomes suspect), success (recovers)
    status.record_success(1, current_timestamp());
    assert_eq!(status.status, HeartbeatNodeStatus::Healthy);

    status.record_miss(&config);
    assert_eq!(status.status, HeartbeatNodeStatus::Healthy);

    status.record_success(2, current_timestamp());
    assert_eq!(status.status, HeartbeatNodeStatus::Healthy);
    assert_eq!(status.missed_heartbeats, 0); // Reset by success

    status.record_miss(&config);
    status.record_miss(&config);
    assert!(status.is_suspect());

    status.record_success(3, current_timestamp());
    assert_eq!(status.status, HeartbeatNodeStatus::Healthy);
}

// ============================================================================
// Test: Epoch Calculation
// ============================================================================

#[test]
fn test_epoch_calculation_boundaries() {
    let config = VdfConfig {
        heartbeat_interval_secs: 60,
        ..VdfConfig::development()
    };
    let vdf = VdfHeartbeat::mock(config);

    // Test epoch boundaries
    assert_eq!(vdf.calculate_epoch(0), 0);
    assert_eq!(vdf.calculate_epoch(59), 0);
    assert_eq!(vdf.calculate_epoch(60), 1);
    assert_eq!(vdf.calculate_epoch(61), 1);
    assert_eq!(vdf.calculate_epoch(119), 1);
    assert_eq!(vdf.calculate_epoch(120), 2);
    assert_eq!(vdf.calculate_epoch(3600), 60); // 1 hour = 60 epochs
}

#[test]
fn test_next_deadline_calculation() {
    let config = VdfConfig {
        heartbeat_interval_secs: 300, // 5 minutes
        ..VdfConfig::development()
    };
    let vdf = VdfHeartbeat::mock(config);

    assert_eq!(vdf.next_heartbeat_deadline(0), 300);
    assert_eq!(vdf.next_heartbeat_deadline(1), 600);
    assert_eq!(vdf.next_heartbeat_deadline(10), 3300);
}

// ============================================================================
// Test: Configuration Variants
// ============================================================================

#[test]
fn test_development_config() {
    let config = VdfConfig::development();

    assert_eq!(config.discriminant_bits, 1024);
    assert_eq!(config.heartbeat_interval_secs, 60);
    assert!(config.iterations < 10000); // Fast for testing
}

#[test]
fn test_testnet_config() {
    let config = VdfConfig::testnet();

    assert_eq!(config.discriminant_bits, 1536);
    assert_eq!(config.heartbeat_interval_secs, 300);
    assert!(config.iterations > 10000);
}

#[test]
fn test_mainnet_config() {
    let config = VdfConfig::mainnet();

    assert_eq!(config.discriminant_bits, 2048);
    assert_eq!(config.heartbeat_interval_secs, 600);
    assert!(config.iterations >= 1_000_000);
}

// ============================================================================
// Test: Proof Properties
// ============================================================================

#[test]
fn test_proof_contains_timing_info() {
    let config = VdfConfig::development();
    let vdf = VdfHeartbeat::mock(config.clone());

    let challenge = HeartbeatChallenge::new([0x42u8; 32], 1);
    let proof = vdf.solve(&challenge).expect("solve failed");

    assert!(proof.generated_at > 0);
    // compute_time_ms is set (mock is instant, so typically 0)
}

#[test]
fn test_proof_freshness_check() {
    let now = current_timestamp();

    let fresh_proof = HeartbeatProof {
        vdf_output: vec![],
        vdf_proof: vec![],
        iterations: 1000,
        discriminant_bits: 1024,
        generated_at: now,
        compute_time_ms: 10,
        proof_type: VdfProofType::Mock,
    };

    let stale_proof = HeartbeatProof {
        generated_at: now - 3600, // 1 hour old
        ..fresh_proof.clone()
    };

    assert!(fresh_proof.is_fresh(60, now));
    assert!(!stale_proof.is_fresh(60, now));
}

// ============================================================================
// Test: Error Cases
// ============================================================================

#[test]
fn test_wrong_iterations_rejected() {
    let config = VdfConfig::development();
    let vdf = VdfHeartbeat::mock(config.clone());

    let challenge = HeartbeatChallenge::new([0x42u8; 32], 1);
    let mut proof = vdf.solve(&challenge).expect("solve failed");

    // Change iterations
    proof.iterations = 999;

    let result = vdf.verify(&challenge, &proof).expect("verify failed");
    assert_eq!(result, HeartbeatVerificationResult::WrongIterations);
}

#[test]
fn test_wrong_discriminant_rejected() {
    let config = VdfConfig::development();
    let vdf = VdfHeartbeat::mock(config.clone());

    let challenge = HeartbeatChallenge::new([0x42u8; 32], 1);
    let mut proof = vdf.solve(&challenge).expect("solve failed");

    // Change discriminant
    proof.discriminant_bits = 4096;

    let result = vdf.verify(&challenge, &proof).expect("verify failed");
    assert_eq!(result, HeartbeatVerificationResult::WrongDiscriminant);
}

#[test]
fn test_stale_proof_rejected() {
    let config = VdfConfig {
        max_proof_age_secs: 1, // Very short for testing
        ..VdfConfig::development()
    };
    let vdf = VdfHeartbeat::mock(config);

    let challenge = HeartbeatChallenge::new([0x42u8; 32], 1);
    let mut proof = vdf.solve(&challenge).expect("solve failed");

    // Make proof old
    proof.generated_at = 1000;

    let result = vdf.verify(&challenge, &proof).expect("verify failed");
    assert_eq!(result, HeartbeatVerificationResult::Stale);
}

// ============================================================================
// Test: Integration with EntangledId
// ============================================================================

#[test]
fn test_vdf_with_real_entangled_id() {
    let config = VdfConfig::development();
    let vdf = VdfHeartbeat::mock(config);

    // Create a real entangled identity
    let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen failed");
    let binary_hash = [0x42u8; 32];
    let nonce = 12345u64;
    let entangled_id = EntangledId::derive(&pk, &binary_hash, nonce);

    // Generate heartbeat challenge for this identity
    let challenge = HeartbeatChallenge::new(*entangled_id.id(), 1);

    // Solve and verify
    let proof = vdf.solve(&challenge).expect("solve failed");
    let result = vdf.verify(&challenge, &proof).expect("verify failed");

    assert!(result.is_valid());
}

#[test]
fn test_different_identities_produce_different_proofs() {
    let config = VdfConfig::development();
    let vdf = VdfHeartbeat::mock(config);

    // Two different identities
    let (pk1, _) = generate_ml_dsa_keypair().expect("keygen1 failed");
    let (pk2, _) = generate_ml_dsa_keypair().expect("keygen2 failed");

    let binary_hash = [0x42u8; 32];
    let id1 = EntangledId::derive(&pk1, &binary_hash, 1);
    let id2 = EntangledId::derive(&pk2, &binary_hash, 2);

    // Same epoch, different identities
    let challenge1 = HeartbeatChallenge::new(*id1.id(), 1);
    let challenge2 = HeartbeatChallenge::new(*id2.id(), 1);

    let proof1 = vdf.solve(&challenge1).expect("solve1 failed");
    let proof2 = vdf.solve(&challenge2).expect("solve2 failed");

    // Proofs should be different
    assert_ne!(proof1.vdf_output, proof2.vdf_output);

    // Each proof should only verify against its own challenge
    assert!(vdf.verify(&challenge1, &proof1).expect("verify").is_valid());
    assert!(vdf.verify(&challenge2, &proof2).expect("verify").is_valid());
    assert!(!vdf.verify(&challenge1, &proof2).expect("verify").is_valid());
    assert!(!vdf.verify(&challenge2, &proof1).expect("verify").is_valid());
}
