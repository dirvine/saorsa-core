//! Comprehensive Identity Management Test Suite
//!
//! This test suite validates the complete identity system for the P2P network:
//! - Four-word human-readable addresses
//! - Ed25519 cryptographic identities  
//! - Identity encryption and secure storage
//! - Proof-of-work Sybil resistance
//! - Cross-system identity consistency

use anyhow::Result;
use saorsa_core::identity::{
    four_words::{FourWordAddress, WordEncoder},
    node_identity::{NodeId, NodeIdentity, ProofOfWork},
    encryption::{encrypt_with_device_password, decrypt_with_device_password, EncryptedData},
};
use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha256};

/// Helper to create deterministic test identity
fn create_test_identity(seed: u64) -> NodeIdentity {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[0..8].copy_from_slice(&seed.to_le_bytes());
    let signing_key = SigningKey::from_bytes(&seed_bytes);
    NodeIdentity::from_signing_key(signing_key)
}

/// Helper to create random test data
fn create_random_data(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    thread_rng().fill_bytes(&mut data);
    data
}

#[tokio::test]
async fn test_four_word_address_generation() -> Result<()> {
    println!("🔤 Testing Four-Word Address Generation");

    // Test deterministic generation from node IDs
    let test_cases = [
        (1u64, "alpha-alpha-alpha-amber"),
        (255u64, "alpha-alpha-alpha-zombie"),  
        (1000000u64, "alpha-alpha-chaos-dance"),
    ];

    for (seed, expected_pattern) in &test_cases {
        let identity = create_test_identity(*seed);
        let node_id = identity.node_id();
        let four_word_addr = FourWordAddress::from_node_id(&node_id);
        
        // Four-word address should be deterministic for same node ID
        let four_word_addr2 = FourWordAddress::from_node_id(&node_id);
        assert_eq!(four_word_addr, four_word_addr2, 
                  "Four-word address should be deterministic");
        
        let addr_string = four_word_addr.to_string();
        
        // Should contain exactly 4 words separated by hyphens
        let parts: Vec<&str> = addr_string.split('-').collect();
        assert_eq!(parts.len(), 4, "Should have exactly 4 words: {}", addr_string);
        
        // Each word should be from the word list (non-empty, alphabetic)
        for word in &parts {
            assert!(!word.is_empty(), "Word should not be empty");
            assert!(word.chars().all(|c| c.is_ascii_lowercase()), 
                   "Word should be lowercase alphabetic: {}", word);
        }
        
        // Should be able to parse back
        let parsed = FourWordAddress::from_str(&addr_string)?;
        assert_eq!(parsed, four_word_addr, "Should parse back to same address");
        
        println!("  ✅ Seed {}: {} -> {}", seed, node_id, addr_string);
    }

    // Test uniqueness across different node IDs
    let mut addresses = HashSet::new();
    for seed in 0..1000 {
        let identity = create_test_identity(seed);
        let node_id = identity.node_id();
        let addr = FourWordAddress::from_node_id(&node_id);
        let addr_string = addr.to_string();
        
        assert!(!addresses.contains(&addr_string), 
               "Address should be unique: {} (seed {})", addr_string, seed);
        addresses.insert(addr_string);
    }
    
    println!("  ✅ Generated {} unique addresses", addresses.len());
    println!("✅ Four-word address generation test passed");
    Ok(())
}

#[tokio::test]
async fn test_node_identity_cryptography() -> Result<()> {
    println!("🔐 Testing Node Identity Cryptography");

    // Test identity creation and consistency
    let identity = create_test_identity(42);
    let node_id = identity.node_id();
    let public_key = identity.verifying_key();
    let signing_key = identity.signing_key();

    // Node ID should be derived from public key
    let expected_node_id = NodeId::from_public_key(&public_key);
    assert_eq!(node_id, expected_node_id, "Node ID should match public key derivation");

    // Test signing and verification
    let test_message = b"Hello P2P Network!";
    let signature = identity.sign(test_message);
    
    // Should verify with identity's public key
    assert!(public_key.verify(test_message, &signature).is_ok(),
           "Signature should verify with identity's public key");
    
    // Should not verify with different public key
    let other_identity = create_test_identity(43);
    let other_public_key = other_identity.verifying_key();
    assert!(other_public_key.verify(test_message, &signature).is_err(),
           "Signature should not verify with different public key");

    // Test message tamper detection
    let tampered_message = b"Hello P2P Network?"; // Changed ! to ?
    assert!(public_key.verify(tampered_message, &signature).is_err(),
           "Signature should not verify with tampered message");

    // Test signature uniqueness
    let signature2 = identity.sign(test_message);
    // Ed25519 signatures are deterministic, so they should be the same
    assert_eq!(signature.to_bytes(), signature2.to_bytes(),
              "Ed25519 signatures should be deterministic");

    // Test different messages produce different signatures
    let other_message = b"Different message";
    let other_signature = identity.sign(other_message);
    assert_ne!(signature.to_bytes(), other_signature.to_bytes(),
              "Different messages should produce different signatures");

    println!("  ✅ Identity creation and key derivation works");
    println!("  ✅ Digital signatures work correctly");
    println!("  ✅ Signature verification prevents tampering");
    println!("✅ Node identity cryptography test passed");
    Ok(())
}

#[tokio::test]
async fn test_node_id_properties() -> Result<()> {
    println!("🆔 Testing Node ID Properties");

    // Test XOR distance calculation (important for Kademlia DHT)
    let id1 = create_test_identity(100).node_id();
    let id2 = create_test_identity(200).node_id();
    let id3 = create_test_identity(300).node_id();

    // XOR distance should be symmetric
    let dist_12 = id1.xor_distance(&id2);
    let dist_21 = id2.xor_distance(&id1);
    assert_eq!(dist_12, dist_21, "XOR distance should be symmetric");

    // XOR distance to self should be zero
    let self_dist = id1.xor_distance(&id1);
    assert_eq!(self_dist, [0u8; 32], "XOR distance to self should be zero");

    // Triangle inequality: d(a,c) <= d(a,b) + d(b,c)
    let dist_13 = id1.xor_distance(&id3);
    let dist_23 = id2.xor_distance(&id3);
    
    // In XOR metric, triangle inequality is actually: d(a,c) = d(a,b) ⊕ d(b,c)
    let computed_dist = xor_arrays(&dist_12, &dist_23);
    assert_eq!(dist_13, computed_dist, "XOR metric should satisfy d(a,c) = d(a,b) ⊕ d(b,c)");

    // Test conversion functions
    let bytes = id1.to_bytes();
    assert_eq!(bytes.len(), 32, "Node ID should be 32 bytes");
    
    // Test Display implementation
    let id_string = id1.to_string();
    assert_eq!(id_string.len(), 16, "Display should show first 8 bytes as hex (16 chars)");
    assert!(id_string.chars().all(|c| c.is_ascii_hexdigit()),
           "Display should be valid hex");

    // Test uniqueness
    let mut node_ids = HashSet::new();
    for seed in 0..1000 {
        let id = create_test_identity(seed).node_id();
        assert!(!node_ids.contains(&id), "Node IDs should be unique");
        node_ids.insert(id);
    }
    
    println!("  ✅ XOR distance properties verified");
    println!("  ✅ Node ID uniqueness confirmed");
    println!("  ✅ Display and conversion functions work");
    println!("✅ Node ID properties test passed");
    Ok(())
}

#[tokio::test]
async fn test_identity_encryption() -> Result<()> {
    println!("🔒 Testing Identity Encryption");

    let test_passwords = ["simple123", "ComplexP@ssw0rd!", "🔑 unicode-password 🚀"];
    let test_data_sizes = [0, 1, 32, 100, 1024, 10000];

    for password in &test_passwords {
        for &data_size in &test_data_sizes {
            let original_data = create_random_data(data_size);
            
            // Test encryption
            let encrypted = encrypt_with_device_password(&original_data, password)?;
            
            // Verify encryption structure
            assert_eq!(encrypted.nonce.len(), 12, "Nonce should be 12 bytes for AES-GCM");
            assert_eq!(encrypted.salt.len(), 32, "Salt should be 32 bytes");
            assert!(!encrypted.ciphertext.is_empty() || original_data.is_empty(),
                   "Ciphertext should not be empty (unless input is empty)");
            
            // Ciphertext should be different from original data
            if !original_data.is_empty() {
                assert_ne!(encrypted.ciphertext, original_data,
                          "Ciphertext should be different from original data");
            }
            
            // Test decryption with correct password
            let decrypted = decrypt_with_device_password(&encrypted, password)?;
            assert_eq!(decrypted, original_data, 
                      "Decrypted data should match original (size: {})", data_size);
            
            // Test decryption with wrong password
            let wrong_password = &format!("{}_wrong", password);
            let result = decrypt_with_device_password(&encrypted, wrong_password);
            assert!(result.is_err(), "Decryption with wrong password should fail");
            
            // Test encryption produces different results (due to random nonce/salt)
            let encrypted2 = encrypt_with_device_password(&original_data, password)?;
            assert_ne!(encrypted.nonce, encrypted2.nonce, "Nonces should be different");
            assert_ne!(encrypted.salt, encrypted2.salt, "Salts should be different");
            if !original_data.is_empty() {
                assert_ne!(encrypted.ciphertext, encrypted2.ciphertext,
                          "Ciphertexts should be different due to different nonces");
            }
            
            // But both should decrypt to the same original data
            let decrypted2 = decrypt_with_device_password(&encrypted2, password)?;
            assert_eq!(decrypted2, original_data, "Both encryptions should decrypt to same data");
        }
    }
    
    println!("  ✅ Encryption/decryption works for various data sizes");
    println!("  ✅ Password verification prevents unauthorized access");  
    println!("  ✅ Random nonce/salt ensures different ciphertexts");
    println!("✅ Identity encryption test passed");
    Ok(())
}

#[tokio::test]
async fn test_proof_of_work() -> Result<()> {
    println!("⛏️ Testing Proof of Work");

    let identity = create_test_identity(123);
    let node_id = identity.node_id();

    // Test proof of work generation with different difficulties
    let difficulties = [8, 12, 16]; // Start with easier difficulties for testing
    
    for &difficulty in &difficulties {
        println!("  Testing difficulty: {} bits", difficulty);
        
        let start_time = Instant::now();
        let proof = ProofOfWork::generate(node_id.to_bytes(), difficulty)?;
        let generation_time = start_time.elapsed();
        
        // Verify the proof is valid
        assert!(proof.verify(node_id.to_bytes(), difficulty)?, 
               "Generated proof should be valid");
        
        // Test that the hash actually meets the difficulty requirement
        let mut hasher = Sha256::new();
        hasher.update(node_id.to_bytes());
        hasher.update(&proof.nonce.to_le_bytes());
        let hash = hasher.finalize();
        
        let leading_zeros = count_leading_zero_bits(&hash);
        assert!(leading_zeros >= difficulty,
               "Hash should have at least {} leading zero bits, got {}", 
               difficulty, leading_zeros);
        
        println!("    ✅ Generated valid proof in {:?} (nonce: {})", 
                generation_time, proof.nonce);
    }

    // Test proof verification with wrong data
    let proof = ProofOfWork::generate(node_id.to_bytes(), 8)?;
    let other_identity = create_test_identity(456);
    let other_node_id = other_identity.node_id();
    
    assert!(!proof.verify(other_node_id.to_bytes(), 8)?,
           "Proof should not verify with different node ID");

    // Test proof with wrong difficulty
    assert!(!proof.verify(node_id.to_bytes(), 16)?,
           "Proof generated for difficulty 8 should not verify for difficulty 16");

    println!("  ✅ Proof of work generation and verification works");
    println!("  ✅ Proof validation prevents cheating");
    println!("✅ Proof of work test passed");
    Ok(())
}

#[tokio::test]
async fn test_identity_consistency() -> Result<()> {
    println!("🔄 Testing Identity Consistency");

    // Test that the same seed produces the same identity consistently
    let seed = 9999u64;
    let identity1 = create_test_identity(seed);
    let identity2 = create_test_identity(seed);
    
    assert_eq!(identity1.node_id(), identity2.node_id(), 
              "Same seed should produce same node ID");
    assert_eq!(identity1.verifying_key().as_bytes(), identity2.verifying_key().as_bytes(),
              "Same seed should produce same public key");
    
    // Test four-word address consistency
    let addr1 = FourWordAddress::from_node_id(&identity1.node_id());
    let addr2 = FourWordAddress::from_node_id(&identity2.node_id());
    assert_eq!(addr1, addr2, "Same node ID should produce same four-word address");

    // Test cross-system consistency (node ID -> four words -> parse -> verify)
    let original_node_id = identity1.node_id();
    let four_word_addr = FourWordAddress::from_node_id(&original_node_id);
    let addr_string = four_word_addr.to_string();
    let parsed_addr = FourWordAddress::from_str(&addr_string)?;
    
    assert_eq!(four_word_addr, parsed_addr, 
              "Four-word address should parse back consistently");

    // Test that different seeds produce different identities
    let different_identity = create_test_identity(seed + 1);
    assert_ne!(identity1.node_id(), different_identity.node_id(),
              "Different seeds should produce different identities");

    // Test signature consistency
    let message = b"Consistency test message";
    let sig1 = identity1.sign(message);
    let sig2 = identity2.sign(message);
    assert_eq!(sig1.to_bytes(), sig2.to_bytes(),
              "Same identity should produce same signature for same message");

    println!("  ✅ Deterministic identity generation");
    println!("  ✅ Cross-system consistency maintained");  
    println!("  ✅ Different seeds produce different identities");
    println!("✅ Identity consistency test passed");
    Ok(())
}

#[tokio::test]
async fn test_identity_performance() -> Result<()> {
    println!("⚡ Testing Identity Performance");

    // Benchmark identity generation
    let generation_count = 100;
    let start = Instant::now();
    
    let mut identities = Vec::new();
    for i in 0..generation_count {
        let identity = create_test_identity(i as u64);
        identities.push(identity);
    }
    
    let generation_time = start.elapsed();
    let generation_rate = generation_count as f64 / generation_time.as_secs_f64();
    println!("  Identity generation: {:.0} identities/sec", generation_rate);

    // Benchmark four-word address generation
    let start = Instant::now();
    let mut addresses = Vec::new();
    
    for identity in &identities {
        let addr = FourWordAddress::from_node_id(&identity.node_id());
        addresses.push(addr);
    }
    
    let addr_time = start.elapsed();
    let addr_rate = generation_count as f64 / addr_time.as_secs_f64();
    println!("  Four-word address generation: {:.0} addresses/sec", addr_rate);

    // Benchmark signing
    let message = b"Performance test message for signing benchmark";
    let start = Instant::now();
    let mut signatures = Vec::new();
    
    for identity in &identities {
        let signature = identity.sign(message);
        signatures.push(signature);
    }
    
    let signing_time = start.elapsed();
    let signing_rate = generation_count as f64 / signing_time.as_secs_f64();
    println!("  Signature generation: {:.0} signatures/sec", signing_rate);

    // Benchmark verification
    let start = Instant::now();
    let mut verification_count = 0;
    
    for (identity, signature) in identities.iter().zip(signatures.iter()) {
        let is_valid = identity.verifying_key().verify(message, signature).is_ok();
        assert!(is_valid, "All signatures should be valid");
        verification_count += 1;
    }
    
    let verification_time = start.elapsed();
    let verification_rate = verification_count as f64 / verification_time.as_secs_f64();
    println!("  Signature verification: {:.0} verifications/sec", verification_rate);

    // Benchmark encryption
    let test_data = create_random_data(1024); // 1KB test data
    let password = "performance_test_password";
    let encrypt_count = 50;
    
    let start = Instant::now();
    let mut encrypted_data = Vec::new();
    
    for _ in 0..encrypt_count {
        let encrypted = encrypt_with_device_password(&test_data, password)?;
        encrypted_data.push(encrypted);
    }
    
    let encrypt_time = start.elapsed();
    let encrypt_rate = encrypt_count as f64 / encrypt_time.as_secs_f64();
    println!("  Encryption (1KB): {:.1} operations/sec", encrypt_rate);

    // Benchmark decryption
    let start = Instant::now();
    let mut decrypted_count = 0;
    
    for encrypted in &encrypted_data {
        let decrypted = decrypt_with_device_password(encrypted, password)?;
        assert_eq!(decrypted.len(), test_data.len());
        decrypted_count += 1;
    }
    
    let decrypt_time = start.elapsed();
    let decrypt_rate = decrypted_count as f64 / decrypt_time.as_secs_f64();
    println!("  Decryption (1KB): {:.1} operations/sec", decrypt_rate);

    // Performance assertions (these should be reasonable for production use)
    assert!(generation_rate > 50.0, "Identity generation should be >50/sec");
    assert!(addr_rate > 1000.0, "Address generation should be >1000/sec");
    assert!(signing_rate > 500.0, "Signing should be >500/sec");
    assert!(verification_rate > 200.0, "Verification should be >200/sec");
    
    println!("✅ Identity performance test passed");
    Ok(())
}

#[tokio::test]
async fn test_identity_edge_cases() -> Result<()> {
    println!("🔍 Testing Identity Edge Cases");

    // Test with maximum and minimum values
    let max_identity = create_test_identity(u64::MAX);
    let min_identity = create_test_identity(u64::MIN);
    
    assert_ne!(max_identity.node_id(), min_identity.node_id(),
              "Max and min seeds should produce different identities");

    // Test four-word address parsing edge cases
    let valid_addresses = [
        "alpha-bravo-charlie-delta",
        "a-b-c-d", // Minimal length words
        "zebra-zephyr-zenith-zodiac", // Z-words
    ];
    
    for addr_str in &valid_addresses {
        let parsed = FourWordAddress::from_str(addr_str);
        assert!(parsed.is_ok(), "Should parse valid address: {}", addr_str);
        
        let addr = parsed.unwrap();
        let regenerated = addr.to_string();
        assert_eq!(&regenerated, addr_str, "Should regenerate same string");
    }

    // Test invalid four-word addresses
    let invalid_addresses = [
        "alpha-bravo-charlie", // Only 3 words
        "alpha-bravo-charlie-delta-echo", // 5 words
        "alpha.bravo.charlie.delta", // Wrong separator
        "alpha-bravo-charlie-", // Trailing separator
        "-alpha-bravo-charlie-delta", // Leading separator
        "alpha--bravo-charlie-delta", // Double separator
        "alpha-bravo-charlie-DELTA", // Uppercase
        "alpha-bravo-charlie-123", // Number
        "", // Empty
        "   ", // Whitespace only
    ];

    for addr_str in &invalid_addresses {
        let result = FourWordAddress::from_str(addr_str);
        assert!(result.is_err(), "Should reject invalid address: {}", addr_str);
    }

    // Test encryption with edge case passwords and data
    let edge_passwords = ["", "a", "🚀", &"x".repeat(1000)];
    let edge_data_sizes = [0, 1, 1000000]; // Empty, tiny, large
    
    for password in &edge_passwords {
        for &size in &edge_data_sizes {
            let data = create_random_data(size);
            
            if password.is_empty() {
                // Empty password should be handled gracefully
                let result = encrypt_with_device_password(&data, password);
                // This might succeed or fail depending on implementation - just shouldn't panic
                let _ = result;
            } else {
                // Non-empty passwords should work
                let encrypted = encrypt_with_device_password(&data, password)?;
                let decrypted = decrypt_with_device_password(&encrypted, password)?;
                assert_eq!(decrypted, data, "Should handle edge case data size {}", size);
            }
        }
    }

    // Test XOR distance edge cases
    let id1 = create_test_identity(0).node_id();
    let id_max = NodeId([0xFF; 32]); // All bits set
    let id_zero = NodeId([0x00; 32]); // All bits clear
    
    let dist_max = id1.xor_distance(&id_max);
    let dist_zero = id1.xor_distance(&id_zero);
    
    // Distance should be different for max and zero
    assert_ne!(dist_max, dist_zero, "Distance to max and zero should be different");

    println!("  ✅ Edge case identities handled correctly");
    println!("  ✅ Invalid address parsing rejected properly");
    println!("  ✅ Encryption edge cases handled gracefully");
    println!("  ✅ XOR distance edge cases work correctly");
    println!("✅ Identity edge cases test passed");
    Ok(())
}

// Helper function to XOR two byte arrays
fn xor_arrays(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

// Helper function to count leading zero bits in a hash
fn count_leading_zero_bits(hash: &[u8]) -> u32 {
    let mut count = 0;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Integration test validating the complete identity system
#[tokio::test]
async fn test_identity_system_integration() -> Result<()> {
    println!("🔗 Identity System Integration Test");

    // Simulate a network with multiple identities
    let network_size = 20;
    let mut network_identities = Vec::new();
    let mut four_word_registry = HashMap::new();
    
    // Phase 1: Network bootstrap - create identities
    println!("  Phase 1: Network bootstrap");
    for i in 0..network_size {
        let identity = create_test_identity(1000 + i as u64);
        let four_word_addr = FourWordAddress::from_node_id(&identity.node_id());
        
        // Ensure no collisions in four-word addresses
        let addr_string = four_word_addr.to_string();
        assert!(!four_word_registry.contains_key(&addr_string),
               "Four-word address collision detected: {}", addr_string);
        
        four_word_registry.insert(addr_string.clone(), identity.node_id());
        network_identities.push((identity, four_word_addr));
        
        println!("    Node {}: {} -> {}", i, identity.node_id(), addr_string);
    }

    // Phase 2: Identity operations
    println!("  Phase 2: Identity operations");
    let test_message = b"Network consensus message";
    let mut signatures = Vec::new();
    
    // All nodes sign the same message
    for (identity, addr) in &network_identities {
        let signature = identity.sign(test_message);
        signatures.push((identity.node_id(), signature));
        
        // Verify signature immediately
        assert!(identity.verifying_key().verify(test_message, &signature).is_ok(),
               "Signature should verify for node: {}", addr);
    }

    // Phase 3: Cross-verification
    println!("  Phase 3: Cross-verification");
    for (node_id, signature) in &signatures {
        // Find the identity that created this signature
        let (identity, _) = network_identities.iter()
            .find(|(id, _)| id.node_id() == *node_id)
            .expect("Should find identity for node ID");
        
        // Verify with correct identity
        assert!(identity.verifying_key().verify(test_message, signature).is_ok(),
               "Signature should verify with correct identity");
        
        // Verify it doesn't work with other identities
        for (other_identity, _) in &network_identities {
            if other_identity.node_id() != *node_id {
                assert!(other_identity.verifying_key().verify(test_message, signature).is_err(),
                       "Signature should not verify with wrong identity");
            }
        }
    }

    // Phase 4: Identity encryption scenarios
    println!("  Phase 4: Identity encryption");
    let device_password = "network_sync_password_123";
    let sync_data = b"Identity sync package for network node";
    
    // Test encryption/decryption for each node
    for (identity, addr) in &network_identities {
        let encrypted = encrypt_with_device_password(sync_data, device_password)?;
        let decrypted = decrypt_with_device_password(&encrypted, device_password)?;
        
        assert_eq!(decrypted, sync_data, 
                  "Identity sync should work for node: {}", addr);
    }

    // Phase 5: Proof of work integration
    println!("  Phase 5: Proof of work validation");
    let difficulty = 8; // Light difficulty for testing
    
    for (identity, addr) in network_identities.iter().take(5) { // Test first 5 nodes
        let node_id = identity.node_id();
        let proof = ProofOfWork::generate(node_id.to_bytes(), difficulty)?;
        
        assert!(proof.verify(node_id.to_bytes(), difficulty)?,
               "Proof of work should be valid for node: {}", addr);
    }

    // Phase 6: Network health validation
    println!("  Phase 6: Network health validation");
    
    // All node IDs should be unique
    let mut node_id_set = HashSet::new();
    for (identity, _) in &network_identities {
        let node_id = identity.node_id();
        assert!(!node_id_set.contains(&node_id), "Node IDs should be unique");
        node_id_set.insert(node_id);
    }
    
    // All four-word addresses should be unique
    assert_eq!(four_word_registry.len(), network_size, 
              "All four-word addresses should be unique");
    
    // Address registry should be consistent with identities
    for (identity, addr) in &network_identities {
        let registered_node_id = four_word_registry.get(&addr.to_string())
            .expect("Address should be registered");
        assert_eq!(registered_node_id, &identity.node_id(),
                  "Registry should match identity node ID");
    }

    println!("  ✅ {} network identities created and validated", network_size);
    println!("  ✅ All signatures verified correctly");
    println!("  ✅ Identity encryption works for all nodes");
    println!("  ✅ Proof of work integration successful");
    println!("  ✅ Network health checks passed");
    println!("✅ Identity system integration test passed");
    Ok(())
}