// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Property-based tests for the Attestation system.
//!
//! These tests use proptest to verify invariants that must hold
//! across all possible inputs for the Entangled Attestation protocol.
//!
//! Key properties tested:
//! - Determinism: Same inputs always produce same outputs
//! - Uniqueness: Different inputs produce different outputs
//! - Verification: Valid derivations always verify, invalid ones don't
//! - Serialization: Round-trip serialization preserves all data

use proptest::prelude::*;
use saorsa_core::attestation::{AttestationConfig, EnforcementMode, EntangledId, SunsetTimestamp};
use saorsa_core::quantum_crypto::generate_ml_dsa_keypair;

/// Strategy for generating random 32-byte binary hashes.
fn binary_hash_strategy() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Strategy for generating random nonces.
fn nonce_strategy() -> impl Strategy<Value = u64> {
    any::<u64>()
}

/// Strategy for generating enforcement modes.
fn enforcement_mode_strategy() -> impl Strategy<Value = EnforcementMode> {
    prop_oneof![
        Just(EnforcementMode::Off),
        Just(EnforcementMode::Soft),
        Just(EnforcementMode::Hard),
    ]
}

/// Strategy for generating sunset grace days (0-365).
fn grace_days_strategy() -> impl Strategy<Value = u32> {
    0u32..365
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    // =============================================================================
    // EntangledId Properties
    // =============================================================================

    /// Property: EntangledId derivation is deterministic.
    /// The same public key, binary hash, and nonce must always produce the same ID.
    #[test]
    fn prop_entangled_id_deterministic(
        binary_hash in binary_hash_strategy(),
        nonce in nonce_strategy()
    ) {
        let (pk, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");

        let id1 = EntangledId::derive(&pk, &binary_hash, nonce);
        let id2 = EntangledId::derive(&pk, &binary_hash, nonce);

        prop_assert_eq!(id1.id(), id2.id(), "Entangled ID derivation must be deterministic");
        prop_assert_eq!(id1.binary_hash(), id2.binary_hash());
        prop_assert_eq!(id1.nonce(), id2.nonce());
    }

    /// Property: Different binary hashes produce different IDs (with same key and nonce).
    /// This ensures the binary hash is properly incorporated into the derivation.
    #[test]
    fn prop_different_binaries_different_ids(
        binary_hash1 in binary_hash_strategy(),
        binary_hash2 in binary_hash_strategy(),
        nonce in nonce_strategy()
    ) {
        // Skip if hashes happen to be identical
        prop_assume!(binary_hash1 != binary_hash2);

        let (pk, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");

        let id1 = EntangledId::derive(&pk, &binary_hash1, nonce);
        let id2 = EntangledId::derive(&pk, &binary_hash2, nonce);

        prop_assert_ne!(
            id1.id(),
            id2.id(),
            "Different binary hashes must produce different IDs"
        );
    }

    /// Property: Different nonces produce different IDs (with same key and binary hash).
    /// This ensures the nonce is properly incorporated into the derivation.
    #[test]
    fn prop_different_nonces_different_ids(
        binary_hash in binary_hash_strategy(),
        nonce1 in nonce_strategy(),
        nonce2 in nonce_strategy()
    ) {
        // Skip if nonces happen to be identical
        prop_assume!(nonce1 != nonce2);

        let (pk, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");

        let id1 = EntangledId::derive(&pk, &binary_hash, nonce1);
        let id2 = EntangledId::derive(&pk, &binary_hash, nonce2);

        prop_assert_ne!(
            id1.id(),
            id2.id(),
            "Different nonces must produce different IDs"
        );
    }

    /// Property: Different public keys produce different IDs.
    /// This is the core identity binding property.
    #[test]
    fn prop_different_keys_different_ids(
        binary_hash in binary_hash_strategy(),
        nonce in nonce_strategy()
    ) {
        let (pk1, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
        let (pk2, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");

        let id1 = EntangledId::derive(&pk1, &binary_hash, nonce);
        let id2 = EntangledId::derive(&pk2, &binary_hash, nonce);

        prop_assert_ne!(
            id1.id(),
            id2.id(),
            "Different public keys must produce different IDs"
        );
    }

    /// Property: An entangled ID always verifies against the key it was derived from.
    #[test]
    fn prop_verify_valid_key(
        binary_hash in binary_hash_strategy(),
        nonce in nonce_strategy()
    ) {
        let (pk, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");

        let id = EntangledId::derive(&pk, &binary_hash, nonce);

        prop_assert!(
            id.verify(&pk),
            "EntangledId must verify against its deriving key"
        );
    }

    /// Property: An entangled ID never verifies against a different key.
    #[test]
    fn prop_verify_rejects_wrong_key(
        binary_hash in binary_hash_strategy(),
        nonce in nonce_strategy()
    ) {
        let (pk1, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
        let (pk2, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");

        let id = EntangledId::derive(&pk1, &binary_hash, nonce);

        prop_assert!(
            !id.verify(&pk2),
            "EntangledId must NOT verify against a different key"
        );
    }

    /// Property: verify_with_binary succeeds with correct key and binary hash.
    #[test]
    fn prop_verify_with_binary_correct(
        binary_hash in binary_hash_strategy(),
        nonce in nonce_strategy()
    ) {
        let (pk, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");

        let id = EntangledId::derive(&pk, &binary_hash, nonce);

        prop_assert!(
            id.verify_with_binary(&pk, &binary_hash),
            "verify_with_binary must succeed with correct inputs"
        );
    }

    /// Property: verify_with_binary fails with wrong binary hash.
    #[test]
    fn prop_verify_with_binary_rejects_wrong_hash(
        binary_hash1 in binary_hash_strategy(),
        binary_hash2 in binary_hash_strategy(),
        nonce in nonce_strategy()
    ) {
        prop_assume!(binary_hash1 != binary_hash2);

        let (pk, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");

        let id = EntangledId::derive(&pk, &binary_hash1, nonce);

        prop_assert!(
            !id.verify_with_binary(&pk, &binary_hash2),
            "verify_with_binary must fail with wrong binary hash"
        );
    }

    /// Property: XOR distance is symmetric.
    #[test]
    fn prop_xor_distance_symmetric(
        binary_hash1 in binary_hash_strategy(),
        binary_hash2 in binary_hash_strategy(),
        nonce1 in nonce_strategy(),
        nonce2 in nonce_strategy()
    ) {
        let (pk1, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
        let (pk2, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");

        let id1 = EntangledId::derive(&pk1, &binary_hash1, nonce1);
        let id2 = EntangledId::derive(&pk2, &binary_hash2, nonce2);

        let dist1 = id1.xor_distance(&id2);
        let dist2 = id2.xor_distance(&id1);

        prop_assert_eq!(dist1, dist2, "XOR distance must be symmetric");
    }

    /// Property: XOR distance to self is zero.
    #[test]
    fn prop_xor_distance_to_self_is_zero(
        binary_hash in binary_hash_strategy(),
        nonce in nonce_strategy()
    ) {
        let (pk, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");

        let id = EntangledId::derive(&pk, &binary_hash, nonce);
        let distance = id.xor_distance(&id);

        prop_assert_eq!(distance, [0u8; 32], "XOR distance to self must be zero");
    }

    /// Property: Serialization round-trip preserves all data.
    #[test]
    fn prop_serialization_roundtrip(
        binary_hash in binary_hash_strategy(),
        nonce in nonce_strategy()
    ) {
        let (pk, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");

        let id = EntangledId::derive(&pk, &binary_hash, nonce);

        // JSON round-trip
        let json = serde_json::to_string(&id).expect("Serialization should succeed");
        let restored: EntangledId = serde_json::from_str(&json).expect("Deserialization should succeed");

        prop_assert_eq!(id.id(), restored.id());
        prop_assert_eq!(id.binary_hash(), restored.binary_hash());
        prop_assert_eq!(id.nonce(), restored.nonce());
    }

    /// Property: to_node_id preserves the ID bytes.
    #[test]
    fn prop_to_node_id_preserves_bytes(
        binary_hash in binary_hash_strategy(),
        nonce in nonce_strategy()
    ) {
        let (pk, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");

        let entangled_id = EntangledId::derive(&pk, &binary_hash, nonce);
        let node_id = entangled_id.to_node_id();

        prop_assert_eq!(
            node_id.to_bytes(),
            entangled_id.id(),
            "NodeId bytes must match EntangledId bytes"
        );
    }

    // =============================================================================
    // AttestationConfig Properties
    // =============================================================================

    /// Property: Empty allowlist permits all binaries.
    #[test]
    fn prop_empty_allowlist_permits_all(binary_hash in binary_hash_strategy()) {
        let config = AttestationConfig::default();

        prop_assert!(
            config.is_binary_allowed(&binary_hash),
            "Empty allowlist must permit all binaries"
        );
    }

    /// Property: Non-empty allowlist only permits listed binaries.
    #[test]
    fn prop_allowlist_only_permits_listed(
        allowed_hash in binary_hash_strategy(),
        other_hash in binary_hash_strategy()
    ) {
        prop_assume!(allowed_hash != other_hash);

        let mut config = AttestationConfig::default();
        config.allow_binary(allowed_hash);

        prop_assert!(
            config.is_binary_allowed(&allowed_hash),
            "Allowlist must permit listed binary"
        );
        prop_assert!(
            !config.is_binary_allowed(&other_hash),
            "Allowlist must reject unlisted binary"
        );
    }

    /// Property: Enforcement mode consistency.
    #[test]
    fn prop_enforcement_mode_consistency(mode in enforcement_mode_strategy()) {
        let config = AttestationConfig::new(mode);

        match mode {
            EnforcementMode::Off => {
                prop_assert!(!config.enabled);
                prop_assert!(!config.is_hard_enforcement());
                prop_assert!(!config.is_soft_enforcement());
            }
            EnforcementMode::Soft => {
                prop_assert!(config.enabled);
                prop_assert!(!config.is_hard_enforcement());
                prop_assert!(config.is_soft_enforcement());
            }
            EnforcementMode::Hard => {
                prop_assert!(config.enabled);
                prop_assert!(config.is_hard_enforcement());
                prop_assert!(!config.is_soft_enforcement());
            }
        }
    }

    // =============================================================================
    // SunsetTimestamp Properties
    // =============================================================================

    /// Property: Sunset created for future days is not expired.
    #[test]
    fn prop_future_sunset_not_expired(days in 1u32..365) {
        let sunset = SunsetTimestamp::days_from_now(days);

        prop_assert!(
            !sunset.is_expired(),
            "Future sunset timestamp must not be expired"
        );
        prop_assert!(
            sunset.days_until_sunset() > 0,
            "Future sunset must have days remaining"
        );
    }

    /// Property: Grace period includes non-expired timestamps.
    #[test]
    fn prop_grace_period_includes_valid(days in 1u32..365, grace in grace_days_strategy()) {
        let sunset = SunsetTimestamp::days_from_now(days);

        prop_assert!(
            sunset.is_within_grace_period(grace),
            "Non-expired sunset must be within any grace period"
        );
    }

    /// Property: days_until_sunset is approximately correct.
    #[test]
    fn prop_days_until_sunset_approximate(days in 1u32..365) {
        let sunset = SunsetTimestamp::days_from_now(days);
        let reported_days = sunset.days_until_sunset();

        // Allow 1 day tolerance for test timing
        prop_assert!(
            reported_days >= days - 1 && reported_days <= days,
            "days_until_sunset should be approximately correct: expected ~{}, got {}",
            days,
            reported_days
        );
    }
}

// =============================================================================
// Adversarial Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// Adversarial: Modifying the stored ID bytes breaks verification.
    /// This simulates an attacker trying to tamper with an EntangledId.
    #[test]
    fn prop_adversarial_id_tampering(
        binary_hash in binary_hash_strategy(),
        nonce in nonce_strategy(),
        tamper_byte_index in 0usize..32,
        tamper_value in any::<u8>()
    ) {
        let (pk, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");

        let original = EntangledId::derive(&pk, &binary_hash, nonce);

        // Create tampered ID
        let mut tampered_bytes = *original.id();
        // Skip if tampering would result in same value
        prop_assume!(tampered_bytes[tamper_byte_index] != tamper_value);
        tampered_bytes[tamper_byte_index] = tamper_value;

        let tampered = EntangledId::from_raw(tampered_bytes, binary_hash, nonce);

        // Tampered ID should NOT verify
        prop_assert!(
            !tampered.verify(&pk),
            "Tampered EntangledId must not verify"
        );
    }

    /// Adversarial: Modifying the stored binary hash breaks verify_with_binary.
    #[test]
    fn prop_adversarial_binary_hash_tampering(
        binary_hash in binary_hash_strategy(),
        nonce in nonce_strategy(),
        tamper_byte_index in 0usize..32,
        tamper_value in any::<u8>()
    ) {
        let (pk, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");

        let original = EntangledId::derive(&pk, &binary_hash, nonce);

        // Create tampered binary hash
        let mut tampered_binary_hash = binary_hash;
        prop_assume!(tampered_binary_hash[tamper_byte_index] != tamper_value);
        tampered_binary_hash[tamper_byte_index] = tamper_value;

        let tampered = EntangledId::from_raw(*original.id(), tampered_binary_hash, nonce);

        // Tampered ID should fail verify_with_binary with original hash
        prop_assert!(
            !tampered.verify_with_binary(&pk, &binary_hash),
            "ID with tampered binary hash must not verify with original hash"
        );
    }

    /// Adversarial: Modifying the stored nonce breaks verification.
    #[test]
    fn prop_adversarial_nonce_tampering(
        binary_hash in binary_hash_strategy(),
        nonce in nonce_strategy(),
        tampered_nonce in nonce_strategy()
    ) {
        prop_assume!(nonce != tampered_nonce);

        let (pk, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");

        let original = EntangledId::derive(&pk, &binary_hash, nonce);

        // Create tampered ID with different nonce
        let tampered = EntangledId::from_raw(*original.id(), binary_hash, tampered_nonce);

        // Tampered ID should NOT verify (since internal nonce is used in re-derivation)
        prop_assert!(
            !tampered.verify(&pk),
            "ID with tampered nonce must not verify"
        );
    }
}
