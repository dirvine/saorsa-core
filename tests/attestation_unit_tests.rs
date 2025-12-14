// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Unit tests for the Entangled Attestation system (Phase 1)
//!
//! These tests are written FIRST following TDD methodology.
//! The implementation should be written to make these tests pass.

use saorsa_core::attestation::{AttestationConfig, EnforcementMode, EntangledId, SunsetTimestamp};
use saorsa_core::quantum_crypto::generate_ml_dsa_keypair;

// =============================================================================
// EntangledId Derivation Tests
// =============================================================================

#[test]
fn test_entangled_id_derive_deterministic() {
    // Given: Fixed public key, binary hash, and nonce
    let (public_key, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let binary_hash = [0x42u8; 32];
    let nonce = 12345u64;

    // When: Identity derived twice with same inputs
    let id1 = EntangledId::derive(&public_key, &binary_hash, nonce);
    let id2 = EntangledId::derive(&public_key, &binary_hash, nonce);

    // Then: Results are identical
    assert_eq!(
        id1.id(),
        id2.id(),
        "Entangled ID derivation must be deterministic"
    );
}

#[test]
fn test_entangled_id_different_keys_produce_different_ids() {
    // Given: Two different public keys
    let (pk1, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let (pk2, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let binary_hash = [0x42u8; 32];
    let nonce = 12345u64;

    // When: Identities derived with different keys
    let id1 = EntangledId::derive(&pk1, &binary_hash, nonce);
    let id2 = EntangledId::derive(&pk2, &binary_hash, nonce);

    // Then: Results are different
    assert_ne!(
        id1.id(),
        id2.id(),
        "Different keys must produce different IDs"
    );
}

#[test]
fn test_entangled_id_different_binaries_produce_different_ids() {
    // Given: Same key but different binary hashes
    let (public_key, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let binary_hash1 = [0x42u8; 32];
    let binary_hash2 = [0x43u8; 32];
    let nonce = 12345u64;

    // When: Identities derived with different binary hashes
    let id1 = EntangledId::derive(&public_key, &binary_hash1, nonce);
    let id2 = EntangledId::derive(&public_key, &binary_hash2, nonce);

    // Then: Results are different
    assert_ne!(
        id1.id(),
        id2.id(),
        "Different binary hashes must produce different IDs"
    );
}

#[test]
fn test_entangled_id_different_nonces_produce_different_ids() {
    // Given: Same key and binary but different nonces
    let (public_key, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let binary_hash = [0x42u8; 32];
    let nonce1 = 12345u64;
    let nonce2 = 12346u64;

    // When: Identities derived with different nonces
    let id1 = EntangledId::derive(&public_key, &binary_hash, nonce1);
    let id2 = EntangledId::derive(&public_key, &binary_hash, nonce2);

    // Then: Results are different
    assert_ne!(
        id1.id(),
        id2.id(),
        "Different nonces must produce different IDs"
    );
}

// =============================================================================
// EntangledId Verification Tests
// =============================================================================

#[test]
fn test_entangled_id_verify_valid() {
    // Given: A valid entangled identity
    let (public_key, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let binary_hash = [0x42u8; 32];
    let nonce = 12345u64;
    let id = EntangledId::derive(&public_key, &binary_hash, nonce);

    // When: Verified with correct inputs
    let result = id.verify(&public_key);

    // Then: Verification succeeds
    assert!(result, "Verification should succeed with correct inputs");
}

#[test]
fn test_entangled_id_verify_wrong_key_fails() {
    // Given: An entangled identity
    let (pk1, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let (pk2, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let binary_hash = [0x42u8; 32];
    let nonce = 12345u64;
    let id = EntangledId::derive(&pk1, &binary_hash, nonce);

    // When: Verified with wrong public key
    let result = id.verify(&pk2);

    // Then: Verification fails
    assert!(!result, "Verification should fail with wrong public key");
}

#[test]
fn test_entangled_id_verify_with_binary_hash_wrong_binary_fails() {
    // Given: An entangled identity
    let (public_key, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let binary_hash1 = [0x42u8; 32];
    let binary_hash2 = [0x43u8; 32];
    let nonce = 12345u64;
    let id = EntangledId::derive(&public_key, &binary_hash1, nonce);

    // When: Verified with wrong binary hash
    let result = id.verify_with_binary(&public_key, &binary_hash2);

    // Then: Verification fails
    assert!(!result, "Verification should fail with wrong binary hash");
}

#[test]
fn test_entangled_id_verify_with_binary_hash_correct_binary_succeeds() {
    // Given: An entangled identity
    let (public_key, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let binary_hash = [0x42u8; 32];
    let nonce = 12345u64;
    let id = EntangledId::derive(&public_key, &binary_hash, nonce);

    // When: Verified with correct binary hash
    let result = id.verify_with_binary(&public_key, &binary_hash);

    // Then: Verification succeeds
    assert!(
        result,
        "Verification should succeed with correct binary hash"
    );
}

// =============================================================================
// EntangledId Serialization Tests
// =============================================================================

#[test]
fn test_entangled_id_serialization_roundtrip() {
    // Given: An entangled identity
    let (public_key, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let binary_hash = [0x42u8; 32];
    let nonce = 12345u64;
    let id = EntangledId::derive(&public_key, &binary_hash, nonce);

    // When: Serialized and deserialized
    let serialized = serde_json::to_string(&id).expect("Serialization should succeed");
    let deserialized: EntangledId =
        serde_json::from_str(&serialized).expect("Deserialization should succeed");

    // Then: Identical to original
    assert_eq!(
        id.id(),
        deserialized.id(),
        "Serialization roundtrip must preserve ID"
    );
    assert_eq!(
        id.binary_hash(),
        deserialized.binary_hash(),
        "Serialization roundtrip must preserve binary hash"
    );
    assert_eq!(
        id.nonce(),
        deserialized.nonce(),
        "Serialization roundtrip must preserve nonce"
    );
}

// =============================================================================
// AttestationConfig Tests
// =============================================================================

#[test]
fn test_attestation_config_defaults() {
    // Given: Default config
    let config = AttestationConfig::default();

    // Then: Has sensible defaults
    assert!(!config.enabled, "Attestation should be disabled by default");
    assert_eq!(
        config.enforcement_mode,
        EnforcementMode::Off,
        "Default enforcement should be Off"
    );
    assert!(
        config.allowed_binary_hashes.is_empty(),
        "No binary hashes allowed by default"
    );
    assert_eq!(
        config.sunset_grace_days, 30,
        "Default grace period should be 30 days"
    );
}

#[test]
fn test_attestation_config_soft_enforcement() {
    // Given: Config with soft enforcement
    let config = AttestationConfig {
        enabled: true,
        enforcement_mode: EnforcementMode::Soft,
        allowed_binary_hashes: vec![[0x42u8; 32]],
        sunset_grace_days: 60,
    };

    // Then: Soft enforcement is enabled
    assert!(config.enabled);
    assert_eq!(config.enforcement_mode, EnforcementMode::Soft);
    assert!(!config.is_hard_enforcement());
    assert!(config.is_soft_enforcement());
}

#[test]
fn test_attestation_config_hard_enforcement() {
    // Given: Config with hard enforcement
    let config = AttestationConfig {
        enabled: true,
        enforcement_mode: EnforcementMode::Hard,
        allowed_binary_hashes: vec![[0x42u8; 32]],
        sunset_grace_days: 30,
    };

    // Then: Hard enforcement is enabled
    assert!(config.enabled);
    assert_eq!(config.enforcement_mode, EnforcementMode::Hard);
    assert!(config.is_hard_enforcement());
    assert!(!config.is_soft_enforcement());
}

#[test]
fn test_attestation_config_is_binary_allowed() {
    // Given: Config with specific allowed binary hashes
    let allowed_hash = [0x42u8; 32];
    let disallowed_hash = [0x43u8; 32];
    let config = AttestationConfig {
        enabled: true,
        enforcement_mode: EnforcementMode::Hard,
        allowed_binary_hashes: vec![allowed_hash],
        sunset_grace_days: 30,
    };

    // Then: Only allowed hashes pass
    assert!(config.is_binary_allowed(&allowed_hash));
    assert!(!config.is_binary_allowed(&disallowed_hash));
}

#[test]
fn test_attestation_config_empty_allowed_list_allows_all() {
    // Given: Config with empty allowed list (permissive mode)
    let config = AttestationConfig {
        enabled: true,
        enforcement_mode: EnforcementMode::Soft,
        allowed_binary_hashes: vec![],
        sunset_grace_days: 30,
    };

    // Then: All binaries are allowed when list is empty
    let any_hash = [0x42u8; 32];
    assert!(
        config.is_binary_allowed(&any_hash),
        "Empty allowed list should allow all binaries"
    );
}

// =============================================================================
// SunsetTimestamp Tests
// =============================================================================

#[test]
fn test_sunset_timestamp_not_expired() {
    // Given: A sunset timestamp in the future
    let future_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 86400; // 1 day in the future
    let sunset = SunsetTimestamp::new(future_time);

    // Then: Not expired
    assert!(
        !sunset.is_expired(),
        "Future timestamp should not be expired"
    );
}

#[test]
fn test_sunset_timestamp_expired() {
    // Given: A sunset timestamp in the past
    let past_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 86400; // 1 day in the past
    let sunset = SunsetTimestamp::new(past_time);

    // Then: Expired
    assert!(sunset.is_expired(), "Past timestamp should be expired");
}

#[test]
fn test_sunset_timestamp_with_grace_period() {
    // Given: A sunset timestamp that just expired, but within grace period
    let just_past = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 3600; // 1 hour in the past
    let sunset = SunsetTimestamp::new(just_past);
    let grace_days = 1; // 1 day grace period

    // Then: Within grace period
    assert!(
        sunset.is_within_grace_period(grace_days),
        "Recently expired should be within grace period"
    );
}

#[test]
fn test_sunset_timestamp_beyond_grace_period() {
    // Given: A sunset timestamp well past grace period
    let long_past = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - (7 * 86400); // 7 days in the past
    let sunset = SunsetTimestamp::new(long_past);
    let grace_days = 1; // 1 day grace period

    // Then: Beyond grace period
    assert!(
        !sunset.is_within_grace_period(grace_days),
        "Long expired should be beyond grace period"
    );
}

// =============================================================================
// Integration with Existing NodeId Tests
// =============================================================================

#[test]
fn test_entangled_id_to_node_id() {
    // Given: An entangled identity
    let (public_key, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let binary_hash = [0x42u8; 32];
    let nonce = 12345u64;
    let entangled_id = EntangledId::derive(&public_key, &binary_hash, nonce);

    // When: Converted to NodeId
    let node_id = entangled_id.to_node_id();

    // Then: NodeId is derived from the entangled ID
    assert_eq!(node_id.to_bytes().len(), 32, "NodeId should be 32 bytes");
}

#[test]
fn test_entangled_id_xor_distance() {
    // Given: Two entangled identities
    let (pk1, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let (pk2, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let binary_hash = [0x42u8; 32];
    let id1 = EntangledId::derive(&pk1, &binary_hash, 1);
    let id2 = EntangledId::derive(&pk2, &binary_hash, 2);

    // When: Calculate XOR distance
    let distance = id1.xor_distance(&id2);

    // Then: Distance is calculated correctly
    assert_eq!(distance.len(), 32, "XOR distance should be 32 bytes");
    // Self-distance should be zero
    let self_distance = id1.xor_distance(&id1);
    assert_eq!(self_distance, [0u8; 32], "Self XOR distance should be zero");
}

// =============================================================================
// Display and Debug Tests
// =============================================================================

#[test]
fn test_entangled_id_display() {
    // Given: An entangled identity
    let (public_key, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let binary_hash = [0x42u8; 32];
    let nonce = 12345u64;
    let id = EntangledId::derive(&public_key, &binary_hash, nonce);

    // When: Formatted for display
    let display = format!("{}", id);

    // Then: Has reasonable format (hex prefix of ID)
    assert!(!display.is_empty(), "Display should not be empty");
    assert!(display.len() <= 20, "Display should be abbreviated");
}

#[test]
fn test_entangled_id_debug() {
    // Given: An entangled identity
    let (public_key, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let binary_hash = [0x42u8; 32];
    let nonce = 12345u64;
    let id = EntangledId::derive(&public_key, &binary_hash, nonce);

    // When: Formatted for debug
    let debug = format!("{:?}", id);

    // Then: Contains relevant info
    assert!(
        debug.contains("EntangledId"),
        "Debug should contain type name"
    );
}

// =============================================================================
// Error Handling Tests
// =============================================================================

#[test]
fn test_entangled_id_handles_zero_nonce() {
    // Given: Zero nonce (edge case)
    let (public_key, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let binary_hash = [0x42u8; 32];
    let nonce = 0u64;

    // When: Identity derived with zero nonce
    let id = EntangledId::derive(&public_key, &binary_hash, nonce);

    // Then: Still produces valid ID
    assert_ne!(
        id.id(),
        &[0u8; 32],
        "Zero nonce should still produce non-zero ID"
    );
}

#[test]
fn test_entangled_id_handles_max_nonce() {
    // Given: Maximum nonce value (edge case)
    let (public_key, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let binary_hash = [0x42u8; 32];
    let nonce = u64::MAX;

    // When: Identity derived with max nonce
    let id = EntangledId::derive(&public_key, &binary_hash, nonce);

    // Then: Still produces valid ID
    assert_ne!(
        id.id(),
        &[0u8; 32],
        "Max nonce should still produce non-zero ID"
    );
}

#[test]
fn test_entangled_id_handles_zero_binary_hash() {
    // Given: Zero binary hash (edge case - should still work)
    let (public_key, _) = generate_ml_dsa_keypair().expect("Key generation should succeed");
    let binary_hash = [0u8; 32];
    let nonce = 12345u64;

    // When: Identity derived with zero binary hash
    let id = EntangledId::derive(&public_key, &binary_hash, nonce);

    // Then: Still produces valid ID (though this binary hash shouldn't be used in production)
    assert_ne!(
        id.id(),
        &[0u8; 32],
        "Zero binary hash should still produce non-zero ID"
    );
}
