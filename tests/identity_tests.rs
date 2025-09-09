// Copyright 2024 Saorsa Labs Limited
// Tests for identity registration and management

use anyhow::Result;
use saorsa_core::types::MlDsaKeyPair;
use saorsa_core::{get_identity, register_identity};

#[tokio::test]
async fn test_identity_registration_valid_words() -> Result<()> {
    // Test valid four-word registration - using known valid dictionary words
    let words = ["welfare", "absurd", "king", "ridge"];
    let keypair = MlDsaKeyPair::generate()?;

    let handle = register_identity(words, &keypair).await?;

    assert_eq!(handle.identity().words, words);
    assert!(!handle.identity().public_key.is_empty());
    let words_owned: [String; 4] = [
        words[0].to_string(),
        words[1].to_string(),
        words[2].to_string(),
        words[3].to_string(),
    ];
    assert_eq!(
        handle.identity().key,
        saorsa_core::fwid::fw_to_key(words_owned)?
    );

    Ok(())
}

#[tokio::test]
async fn test_identity_registration_invalid_words() -> Result<()> {
    // Test invalid words (not in dictionary)
    let words = ["invalid", "word", "test", "here"];
    let keypair = MlDsaKeyPair::generate()?;

    let result = register_identity(words, &keypair).await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_identity_duplicate_prevention() -> Result<()> {
    // Test that same words can't be registered twice
    let words = ["welfare", "absurd", "kind", "ridge"];
    let keypair1 = MlDsaKeyPair::generate()?;
    let keypair2 = MlDsaKeyPair::generate()?;

    // First registration should succeed
    let handle1 = register_identity(words, &keypair1).await?;
    assert_eq!(handle1.identity().words, words);

    // Second registration with same words should fail
    let result = register_identity(words, &keypair2).await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_identity_fetch() -> Result<()> {
    // Test fetching an identity by key
    let words = ["component", "abuja", "a", "kenneth"];
    let keypair = MlDsaKeyPair::generate()?;

    let handle = register_identity(words, &keypair).await?;
    let identity_key = handle.key();

    // Fetch the identity
    let fetched = get_identity(identity_key.clone()).await?;

    assert_eq!(fetched.words, words);
    assert_eq!(fetched.key, identity_key);
    assert_eq!(fetched.public_key, handle.identity().public_key);

    Ok(())
}

#[tokio::test]
async fn test_identity_signature_operations() -> Result<()> {
    // Test signing and verification with identity
    let words = ["court", "absurd", "a", "picture"];
    let keypair = MlDsaKeyPair::generate()?;

    let handle = register_identity(words, &keypair).await?;

    // Test signing
    let message = b"Test message for signing";
    let signature = handle.sign(message)?;
    assert!(!signature.is_empty());

    // Test verification
    let is_valid = handle.verify(message, &signature)?;
    assert!(is_valid);

    // Test invalid signature
    let bad_signature = vec![0u8; signature.len()];
    let is_invalid = handle.verify(message, &bad_signature)?;
    assert!(!is_invalid);

    Ok(())
}

#[tokio::test]
async fn test_identity_key_derivation() -> Result<()> {
    // Test that key derivation is deterministic
    let words = ["welfare", "absurd", "king", "ridge"];

    let words_owned: [String; 4] = [
        words[0].to_string(),
        words[1].to_string(),
        words[2].to_string(),
        words[3].to_string(),
    ];
    let key1 = saorsa_core::fwid::fw_to_key(words_owned.clone())?;
    let key2 = saorsa_core::fwid::fw_to_key(words_owned)?;

    assert_eq!(key1, key2);

    // Different words should give different keys
    let words2 = ["court", "absurd", "a", "picture"];
    let words2_owned: [String; 4] = [
        words2[0].to_string(),
        words2[1].to_string(),
        words2[2].to_string(),
        words2[3].to_string(),
    ];
    let key3 = saorsa_core::fwid::fw_to_key(words2_owned)?;

    assert_ne!(key1, key3);

    Ok(())
}

#[tokio::test]
async fn test_identity_public_key_format() -> Result<()> {
    // Test that public keys are properly formatted
    let words = ["regime", "ancient", "ok", "ancient"];
    let keypair = MlDsaKeyPair::generate()?;

    let handle = register_identity(words, &keypair).await?;

    // ML-DSA-65 public key should be specific size
    assert!(!handle.identity().public_key.is_empty());
    // Actual size depends on ML-DSA-65 spec
    assert!(handle.identity().public_key.len() > 1000);

    Ok(())
}

#[tokio::test]
async fn test_identity_handle_cloning() -> Result<()> {
    // Test that identity handles can be cloned
    let words = ["huge", "yours", "zurich", "picture"];
    let keypair = MlDsaKeyPair::generate()?;

    let handle1 = register_identity(words, &keypair).await?;
    let handle2 = handle1.clone();

    assert_eq!(handle1.key(), handle2.key());
    assert_eq!(handle1.identity().words, handle2.identity().words);

    // Both should be able to sign
    let message = b"Test cloning";
    let sig1 = handle1.sign(message)?;
    let sig2 = handle2.sign(message)?;

    // Signatures should be different (due to randomness)
    // but both should verify
    assert!(handle1.verify(message, &sig2)?);
    assert!(handle2.verify(message, &sig1)?);

    Ok(())
}

#[tokio::test]
async fn test_identity_cross_verification() -> Result<()> {
    // Test that different identities can't verify each other's signatures
    let words1 = ["thrive", "scott", "liechtenstein", "ridge"];
    let words2 = ["addition", "almaty", "kite", "almaty"];
    let keypair1 = MlDsaKeyPair::generate()?;
    let keypair2 = MlDsaKeyPair::generate()?;

    let handle1 = register_identity(words1, &keypair1).await?;
    let handle2 = register_identity(words2, &keypair2).await?;

    let message = b"Cross verification test";
    let sig1 = handle1.sign(message)?;

    // handle2 should not be able to verify handle1's signature
    let result = handle2.verify(message, &sig1);
    assert!(result.is_err() || !result.unwrap());

    Ok(())
}

#[tokio::test]
async fn test_identity_persistence() -> Result<()> {
    // Test that identities persist in DHT
    let words = ["bless", "abstract", "assess", "abstract"];
    let keypair = MlDsaKeyPair::generate()?;

    let handle = register_identity(words, &keypair).await?;
    let key = handle.key();

    // Should be able to fetch multiple times
    let fetch1 = get_identity(key.clone()).await?;
    let fetch2 = get_identity(key).await?;

    assert_eq!(fetch1.words, fetch2.words);
    assert_eq!(fetch1.key, fetch2.key);
    assert_eq!(fetch1.public_key, fetch2.public_key);

    Ok(())
}
