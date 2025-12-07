//! Data attestation using nonce-prepended hash challenges
//!
//! This module provides cryptographic challenges to verify that nodes
//! are actually storing the data they claim to store. Nonces are PREPENDED
//! to prevent sponge property abuse attacks.
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use crate::dht::DhtKey;
use anyhow::Result;
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

/// Compute attested hash: BLAKE3(nonce || data)
/// Nonce is PREPENDED to prevent sponge property abuse
#[must_use]
pub fn compute_attested_hash(nonce: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(nonce); // PREPEND nonce - critical for security
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// A challenge issued to verify data possession
#[derive(Debug, Clone)]
pub struct DataChallenge {
    /// The DHT key being challenged
    pub key: DhtKey,
    /// Random nonce for this challenge (prevents precomputation)
    pub nonce: [u8; 32],
    /// When the challenge was created
    pub timestamp: u64,
}

impl DataChallenge {
    /// Create a new data challenge with a random nonce
    ///
    /// # Errors
    /// Returns an error if system time is before UNIX epoch
    pub fn new(key: &DhtKey) -> Result<Self> {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("Time error: {}", e))?
            .as_millis() as u64;

        Ok(Self {
            key: key.clone(),
            nonce,
            timestamp,
        })
    }

    /// Compute the expected hash for given data
    #[must_use]
    pub fn compute_expected_hash(&self, data: &[u8]) -> [u8; 32] {
        compute_attested_hash(&self.nonce, data)
    }

    /// Verify a response matches the expected hash
    #[must_use]
    pub fn verify_response(&self, data: &[u8], response_hash: &[u8; 32]) -> bool {
        let expected = self.compute_expected_hash(data);
        expected == *response_hash
    }
}

/// Response to a data challenge
#[derive(Debug, Clone)]
pub struct ChallengeResponse {
    /// The DHT key that was challenged
    pub key: DhtKey,
    /// The computed hash: BLAKE3(nonce || data)
    pub attested_hash: [u8; 32],
    /// Whether the node claims to have the data
    pub has_data: bool,
}

impl ChallengeResponse {
    /// Create a response for data we have
    #[must_use]
    pub fn with_data(key: DhtKey, challenge: &DataChallenge, data: &[u8]) -> Self {
        let attested_hash = challenge.compute_expected_hash(data);
        Self {
            key,
            attested_hash,
            has_data: true,
        }
    }

    /// Create a response indicating we don't have the data
    #[must_use]
    pub fn without_data(key: DhtKey) -> Self {
        Self {
            key,
            attested_hash: [0u8; 32],
            has_data: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_prepend_prevents_precomputation() {
        let data = b"secret data";
        let nonce1 = [1u8; 32];
        let nonce2 = [2u8; 32];

        let hash1 = compute_attested_hash(&nonce1, data);
        let hash2 = compute_attested_hash(&nonce2, data);

        // Different nonces MUST produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_nonce_prepend_is_deterministic() {
        let data = b"test data";
        let nonce = [42u8; 32];

        let hash1 = compute_attested_hash(&nonce, data);
        let hash2 = compute_attested_hash(&nonce, data);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_attestation_challenge_creation() {
        let key = DhtKey::random();
        let challenge = DataChallenge::new(&key).unwrap();

        assert_ne!(challenge.nonce, [0u8; 32]); // Nonce must be random
        assert!(challenge.timestamp > 0);
    }

    #[test]
    fn test_challenge_response_matches() {
        let data = b"stored data";
        let key = DhtKey::random();
        let challenge = DataChallenge::new(&key).unwrap();

        let response_hash = compute_attested_hash(&challenge.nonce, data);
        let expected_hash = challenge.compute_expected_hash(data);

        assert_eq!(response_hash, expected_hash);
    }

    #[test]
    fn test_challenge_response_fails_for_wrong_data() {
        let stored_data = b"real data";
        let fake_data = b"fake data";
        let key = DhtKey::random();
        let challenge = DataChallenge::new(&key).unwrap();

        let response_hash = compute_attested_hash(&challenge.nonce, fake_data);
        let expected_hash = challenge.compute_expected_hash(stored_data);

        assert_ne!(response_hash, expected_hash);
    }

    #[test]
    fn test_verify_response_correct_data() {
        let data = b"my secret data";
        let key = DhtKey::random();
        let challenge = DataChallenge::new(&key).unwrap();

        let response_hash = challenge.compute_expected_hash(data);
        assert!(challenge.verify_response(data, &response_hash));
    }

    #[test]
    fn test_verify_response_wrong_data() {
        let real_data = b"real data";
        let fake_data = b"fake data";
        let key = DhtKey::random();
        let challenge = DataChallenge::new(&key).unwrap();

        let fake_hash = challenge.compute_expected_hash(fake_data);
        assert!(!challenge.verify_response(real_data, &fake_hash));
    }

    #[test]
    fn test_challenge_response_with_data() {
        let data = b"stored data";
        let key = DhtKey::random();
        let challenge = DataChallenge::new(&key).unwrap();

        let response = ChallengeResponse::with_data(key.clone(), &challenge, data);
        assert!(response.has_data);
        assert_eq!(
            response.attested_hash,
            challenge.compute_expected_hash(data)
        );
    }

    #[test]
    fn test_challenge_response_without_data() {
        let key = DhtKey::random();
        let response = ChallengeResponse::without_data(key);

        assert!(!response.has_data);
        assert_eq!(response.attested_hash, [0u8; 32]);
    }

    #[test]
    fn test_different_data_different_hash() {
        let nonce = [1u8; 32];
        let data1 = b"data one";
        let data2 = b"data two";

        let hash1 = compute_attested_hash(&nonce, data1);
        let hash2 = compute_attested_hash(&nonce, data2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_empty_data_still_hashes() {
        let nonce = [1u8; 32];
        let empty_data: &[u8] = &[];

        let hash = compute_attested_hash(&nonce, empty_data);
        // Should not be all zeros (that would indicate a bug)
        assert_ne!(hash, [0u8; 32]);
    }
}
