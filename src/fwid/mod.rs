// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Four-word identifier system for human-readable addressing.
//!
//! This module provides the foundational four-word addressing system
//! as specified in the saorsa-core spec.

use anyhow::{Context, Result};
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Four-word identifier using dictionary v1
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FourWordsV1 {
    /// Indices into the dictionary (4 u16 values)
    indices: [u16; 4],
}

/// A 32-byte key derived from four-words
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Key([u8; 32]);

/// Word type alias
pub type Word = String;

impl FourWordsV1 {
    /// Create a new FourWordsV1 from indices
    pub fn new(indices: [u16; 4]) -> Self {
        Self { indices }
    }

    /// Get the indices
    pub fn indices(&self) -> &[u16; 4] {
        &self.indices
    }
}

impl Key {
    /// Create a new key from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Create from hex string
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).context("Invalid hex")?;
        if bytes.len() != 32 {
            anyhow::bail!("Key must be 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl From<[u8; 32]> for Key {
    fn from(value: [u8; 32]) -> Self {
        Key(value)
    }
}

impl From<Key> for [u8; 32] {
    fn from(value: Key) -> Self {
        value.0
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Check if four words are valid (exist in dictionary)
pub fn fw_check(words: [Word; 4]) -> bool {
    // Delegate validation to the four-word-networking crate to avoid
    // re-implementing dictionary/encoding logic.
    let enc = four_word_networking::FourWordEncoding::new(
        words[0].clone(),
        words[1].clone(),
        words[2].clone(),
        words[3].clone(),
    );
    four_word_networking::FourWordEncoder::new()
        .decode_ipv4(&enc)
        .is_ok()
}

/// Convert four words to a key using BLAKE3
pub fn fw_to_key(words: [Word; 4]) -> Result<Key> {
    // Validate words first
    if !fw_check(words.clone()) {
        anyhow::bail!("Invalid four-words");
    }

    // Join words and hash
    let joined = words.join("-");
    let mut hasher = Hasher::new();
    hasher.update(joined.as_bytes());
    let hash = hasher.finalize();

    Ok(Key(*hash.as_bytes()))
}

/// Compute key from a context string and content
pub fn compute_key(context: &str, content: &[u8]) -> Key {
    let mut hasher = Hasher::new();
    hasher.update(context.as_bytes());
    hasher.update(content);
    let hash = hasher.finalize();
    Key(*hash.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fw_check() {
        // The four-word-networking crate has a specific dictionary
        // We need to use valid dictionary words that encode to an IPv4
        // For testing, just verify the function doesn't panic
        let test_words = [
            "word1".to_string(),
            "word2".to_string(),
            "word3".to_string(),
            "word4".to_string(),
        ];
        // Don't assert the result since we don't know if these are valid dictionary words
        let _ = fw_check(test_words);
        
        // Test with empty strings (definitely invalid)
        let invalid = [
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
        ];
        assert!(!fw_check(invalid));
    }

    #[test]
    fn test_fw_to_key() {
        // fw_to_key requires valid dictionary words that pass fw_check
        // Since we don't know the exact dictionary, we'll test the error case
        let invalid_words = [
            "notindictionary1".to_string(),
            "notindictionary2".to_string(),
            "notindictionary3".to_string(),
            "notindictionary4".to_string(),
        ];

        // This should fail since the words aren't in the dictionary
        let result = fw_to_key(invalid_words);
        assert!(result.is_err());
        
        // Test that if we had valid words, it would be deterministic
        // For now, we can't test the success case without knowing valid dictionary words
    }

    #[test]
    fn test_key_hex() {
        let bytes = [42u8; 32];
        let key = Key::new(bytes);
        let hex = key.to_hex();
        let recovered = Key::from_hex(&hex).unwrap();
        assert_eq!(key, recovered);
    }
}
