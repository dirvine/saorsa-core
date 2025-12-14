// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Integration tests for saorsa-logic integration.
//!
//! These tests verify that the saorsa-logic crate produces identical results
//! to the original implementation. This is critical for backward compatibility.
//!
//! ## TDD Approach
//!
//! These tests are written FIRST, before the integration code.
//! They define the contract that the integration must satisfy:
//!
//! 1. Derivation produces identical results to original implementation
//! 2. Verification is symmetric (what we derive, we can verify)
//! 3. XOR distance calculation matches
//! 4. Binary allowlist verification works correctly
//! 5. Constants are consistent

use saorsa_core::attestation::EntangledId;
use saorsa_core::quantum_crypto::generate_ml_dsa_keypair;

/// Test that EntangledId derivation produces identical results to saorsa-logic.
///
/// This is the critical test - we must ensure backward compatibility.
#[test]
fn test_derivation_matches_saorsa_logic() {
    let (pk, _sk) = generate_ml_dsa_keypair().expect("key generation failed");
    let binary_hash = [0x42u8; 32];
    let nonce = 12345u64;

    // Derive using saorsa-core's EntangledId
    let entangled_id = EntangledId::derive(&pk, &binary_hash, nonce);

    // Derive directly using saorsa-logic
    let logic_id =
        saorsa_logic::attestation::derive_entangled_id(pk.as_bytes(), &binary_hash, nonce);

    // They MUST be identical
    assert_eq!(
        entangled_id.id(),
        &logic_id,
        "EntangledId derivation must match saorsa-logic"
    );
}

/// Test that verification using saorsa-logic produces same result as internal verify.
#[test]
fn test_verification_matches_saorsa_logic() {
    let (pk, _sk) = generate_ml_dsa_keypair().expect("key generation failed");
    let binary_hash = [0x42u8; 32];
    let nonce = 12345u64;

    let entangled_id = EntangledId::derive(&pk, &binary_hash, nonce);

    // Verify using saorsa-core's method
    let core_result = entangled_id.verify(&pk);

    // Verify using saorsa-logic directly
    let logic_result = saorsa_logic::attestation::verify_entangled_id(
        entangled_id.id(),
        pk.as_bytes(),
        &binary_hash,
        nonce,
    );

    assert_eq!(core_result, logic_result, "verification results must match");
    assert!(
        core_result,
        "verification should succeed for correctly derived ID"
    );
}

/// Test that XOR distance calculation matches saorsa-logic.
#[test]
fn test_xor_distance_matches_saorsa_logic() {
    let (pk1, _) = generate_ml_dsa_keypair().expect("key generation failed");
    let (pk2, _) = generate_ml_dsa_keypair().expect("key generation failed");

    let id1 = EntangledId::derive(&pk1, &[1u8; 32], 100);
    let id2 = EntangledId::derive(&pk2, &[2u8; 32], 200);

    // Calculate using saorsa-core
    let core_distance = id1.xor_distance(&id2);

    // Calculate using saorsa-logic
    let logic_distance = saorsa_logic::attestation::xor_distance(id1.id(), id2.id());

    assert_eq!(
        core_distance, logic_distance,
        "XOR distance calculation must match"
    );
}

/// Test that XOR distance to self is zero (identity property).
#[test]
fn test_xor_distance_self_is_zero() {
    let (pk, _) = generate_ml_dsa_keypair().expect("key generation failed");
    let id = EntangledId::derive(&pk, &[0u8; 32], 0);

    let distance = id.xor_distance(&id);
    let expected = [0u8; 32];

    assert_eq!(distance, expected, "XOR distance to self must be zero");
}

/// Test that XOR distance is symmetric.
#[test]
fn test_xor_distance_symmetric() {
    let (pk1, _) = generate_ml_dsa_keypair().expect("key generation failed");
    let (pk2, _) = generate_ml_dsa_keypair().expect("key generation failed");

    let id1 = EntangledId::derive(&pk1, &[1u8; 32], 100);
    let id2 = EntangledId::derive(&pk2, &[2u8; 32], 200);

    let d1 = id1.xor_distance(&id2);
    let d2 = id2.xor_distance(&id1);

    assert_eq!(d1, d2, "XOR distance must be symmetric");
}

/// Test binary allowlist verification using saorsa-logic.
#[test]
fn test_binary_allowlist_verification() {
    let binary_hash = [0x42u8; 32];
    let allowlist = [
        [0x41u8; 32],
        [0x42u8; 32], // This one matches
        [0x43u8; 32],
    ];

    let result = saorsa_logic::attestation::verify_binary_allowlist(&binary_hash, &allowlist);
    assert!(result.is_ok(), "binary should be in allowlist");
}

/// Test binary allowlist verification fails for non-matching hash.
#[test]
fn test_binary_allowlist_verification_fails() {
    let binary_hash = [0x99u8; 32]; // Not in allowlist
    let allowlist = [[0x41u8; 32], [0x42u8; 32], [0x43u8; 32]];

    let result = saorsa_logic::attestation::verify_binary_allowlist(&binary_hash, &allowlist);
    assert!(result.is_err(), "binary should not be in allowlist");
}

/// Test that derivation is deterministic - same inputs always produce same output.
#[test]
fn test_derivation_deterministic() {
    let (pk, _) = generate_ml_dsa_keypair().expect("key generation failed");
    let binary_hash = [0xABu8; 32];
    let nonce = 999999u64;

    // Derive twice
    let id1 = EntangledId::derive(&pk, &binary_hash, nonce);
    let id2 = EntangledId::derive(&pk, &binary_hash, nonce);

    // Also derive via saorsa-logic twice
    let logic_id1 =
        saorsa_logic::attestation::derive_entangled_id(pk.as_bytes(), &binary_hash, nonce);
    let logic_id2 =
        saorsa_logic::attestation::derive_entangled_id(pk.as_bytes(), &binary_hash, nonce);

    assert_eq!(id1, id2, "core derivation must be deterministic");
    assert_eq!(
        logic_id1, logic_id2,
        "logic derivation must be deterministic"
    );
    assert_eq!(id1.id(), &logic_id1, "both must produce identical results");
}

/// Test that different public keys produce different IDs.
#[test]
fn test_different_keys_different_ids() {
    let (pk1, _) = generate_ml_dsa_keypair().expect("key generation failed");
    let (pk2, _) = generate_ml_dsa_keypair().expect("key generation failed");
    let binary_hash = [0x42u8; 32];
    let nonce = 12345u64;

    let id1 = EntangledId::derive(&pk1, &binary_hash, nonce);
    let id2 = EntangledId::derive(&pk2, &binary_hash, nonce);

    assert_ne!(
        id1.id(),
        id2.id(),
        "different keys must produce different IDs"
    );
}

/// Test that different binary hashes produce different IDs.
#[test]
fn test_different_binaries_different_ids() {
    let (pk, _) = generate_ml_dsa_keypair().expect("key generation failed");
    let binary_hash1 = [0x42u8; 32];
    let binary_hash2 = [0x43u8; 32];
    let nonce = 12345u64;

    let id1 = EntangledId::derive(&pk, &binary_hash1, nonce);
    let id2 = EntangledId::derive(&pk, &binary_hash2, nonce);

    assert_ne!(
        id1.id(),
        id2.id(),
        "different binaries must produce different IDs"
    );
}

/// Test that different nonces produce different IDs.
#[test]
fn test_different_nonces_different_ids() {
    let (pk, _) = generate_ml_dsa_keypair().expect("key generation failed");
    let binary_hash = [0x42u8; 32];

    let id1 = EntangledId::derive(&pk, &binary_hash, 1);
    let id2 = EntangledId::derive(&pk, &binary_hash, 2);

    assert_ne!(
        id1.id(),
        id2.id(),
        "different nonces must produce different IDs"
    );
}

/// Test verification fails with wrong public key.
#[test]
fn test_verification_wrong_key_fails() {
    let (pk1, _) = generate_ml_dsa_keypair().expect("key generation failed");
    let (pk2, _) = generate_ml_dsa_keypair().expect("key generation failed");
    let binary_hash = [0x42u8; 32];
    let nonce = 12345u64;

    let id = EntangledId::derive(&pk1, &binary_hash, nonce);

    // Verification with wrong key should fail
    assert!(!id.verify(&pk2), "verification with wrong key must fail");

    // saorsa-logic should also report failure
    let logic_result = saorsa_logic::attestation::verify_entangled_id(
        id.id(),
        pk2.as_bytes(),
        &binary_hash,
        nonce,
    );
    assert!(
        !logic_result,
        "saorsa-logic verification with wrong key must fail"
    );
}

/// Test verification with binary hash check.
#[test]
fn test_verify_with_binary() {
    let (pk, _) = generate_ml_dsa_keypair().expect("key generation failed");
    let binary_hash = [0x42u8; 32];
    let wrong_binary_hash = [0x99u8; 32];
    let nonce = 12345u64;

    let id = EntangledId::derive(&pk, &binary_hash, nonce);

    // Should succeed with correct binary hash
    assert!(
        id.verify_with_binary(&pk, &binary_hash),
        "verification with correct binary should succeed"
    );

    // Should fail with wrong binary hash
    assert!(
        !id.verify_with_binary(&pk, &wrong_binary_hash),
        "verification with wrong binary should fail"
    );
}

/// Test that hash size constants are consistent.
#[test]
fn test_hash_size_constants() {
    assert_eq!(
        saorsa_logic::attestation::HASH_SIZE,
        32,
        "HASH_SIZE should be 32"
    );
    assert_eq!(
        saorsa_logic::attestation::ENTANGLED_ID_SIZE,
        32,
        "ENTANGLED_ID_SIZE should be 32"
    );
}

/// Test with realistic key size (ML-DSA-65 public key is 1952 bytes).
#[test]
fn test_realistic_key_size() {
    let (pk, _) = generate_ml_dsa_keypair().expect("key generation failed");

    // ML-DSA-65 public key should be 1952 bytes
    assert_eq!(
        pk.as_bytes().len(),
        saorsa_logic::attestation::ML_DSA_65_PUBLIC_KEY_SIZE,
        "public key size should match ML-DSA-65 spec"
    );
}

/// Property test: Derivation and verification round-trip.
#[test]
fn test_derivation_verification_roundtrip() {
    // Test with multiple random-ish inputs
    for i in 0..10 {
        let (pk, _) = generate_ml_dsa_keypair().expect("key generation failed");
        let binary_hash = [i as u8; 32];
        let nonce = (i as u64) * 12345;

        let id = EntangledId::derive(&pk, &binary_hash, nonce);

        // Core verification
        assert!(
            id.verify(&pk),
            "round-trip verification must succeed (iteration {i})"
        );

        // Logic verification
        let logic_result = saorsa_logic::attestation::verify_entangled_id(
            id.id(),
            pk.as_bytes(),
            &binary_hash,
            nonce,
        );
        assert!(
            logic_result,
            "logic round-trip verification must succeed (iteration {i})"
        );
    }
}

/// Test content hashing from saorsa-logic::data.
#[test]
fn test_content_hashing() {
    let data = b"Hello, Saorsa!";
    let hash = saorsa_logic::data::compute_content_hash(data);

    // Should be 32 bytes
    assert_eq!(hash.len(), 32);

    // Should be deterministic
    let hash2 = saorsa_logic::data::compute_content_hash(data);
    assert_eq!(hash, hash2);

    // Different data should produce different hash
    let different_data = b"Different data";
    let different_hash = saorsa_logic::data::compute_content_hash(different_data);
    assert_ne!(hash, different_hash);
}

/// Test content hash verification from saorsa-logic::data.
#[test]
fn test_content_hash_verification() {
    let data = b"Test data for verification";
    let hash = saorsa_logic::data::compute_content_hash(data);

    // Verification should succeed
    assert!(saorsa_logic::data::verify_content_hash(data, &hash).is_ok());

    // Verification with wrong hash should fail
    let wrong_hash = [0u8; 32];
    assert!(saorsa_logic::data::verify_content_hash(data, &wrong_hash).is_err());
}

/// Test Merkle proof generation and verification from saorsa-logic.
#[test]
fn test_merkle_proof() {
    use saorsa_logic::merkle::{build_tree_root, generate_proof, hash_leaf};

    // Create some leaves
    let leaves: Vec<[u8; 32]> = (0..4).map(|i| hash_leaf(&[i as u8])).collect();

    // Build tree and get root
    let root = build_tree_root(&leaves);

    // Generate and verify proof for each leaf
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = generate_proof(&leaves, i).expect("proof should exist");
        assert!(
            proof.verify(leaf, &root).is_ok(),
            "proof for leaf {i} should be valid"
        );
    }
}
