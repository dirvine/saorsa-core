// Copyright (c) 2025 Saorsa Labs Limited

// This file is part of the Saorsa P2P network.

// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Copyright 2024 P2P Foundation
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity encryption utilities for secure data transport and storage

use crate::error::SecurityError;
use crate::{P2PError, Result};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, SaltString, rand_core::RngCore},
};
use saorsa_pqc::{
    ChaCha20Poly1305Cipher, SymmetricKey, SymmetricEncryptedMessage,
};
// TODO: Replace with saorsa-pqc HKDF once correct import path is found
use hkdf::Hkdf;
use sha2::Sha256;
use serde::{Deserialize, Serialize};

/// Size of ChaCha20Poly1305 key in bytes
const CHACHA_KEY_SIZE: usize = 32;

/// Size of ChaCha20Poly1305 nonce in bytes  
const NONCE_SIZE: usize = 12;

/// Size of salt for key derivation
const SALT_SIZE: usize = 32;

/// Default Argon2id parameters for device password encryption
const DEVICE_ARGON2_MEMORY: u32 = 32768; // 32MB
const DEVICE_ARGON2_TIME: u32 = 2;
const DEVICE_ARGON2_PARALLELISM: u32 = 2;

/// Encrypted data container for identity sync packages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// The encrypted message from saorsa-pqc
    pub encrypted_message: SymmetricEncryptedMessage,
    /// The salt used for key derivation
    pub salt: [u8; SALT_SIZE],
}

/// Encrypt data with a device password for sync packages
pub fn encrypt_with_device_password(data: &[u8], device_password: &str) -> Result<EncryptedData> {
    // Generate random salt
    let mut salt = [0u8; SALT_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);

    // Derive key from device password using Argon2id
    let key_bytes = derive_key_from_password(device_password, &salt)?;
    let symmetric_key = SymmetricKey::from_bytes(key_bytes);

    // Encrypt data with ChaCha20Poly1305
    let cipher = ChaCha20Poly1305Cipher::new(&symmetric_key);
    let (ciphertext, nonce) = cipher.encrypt(data, None).map_err(|e| {
        P2PError::Security(SecurityError::EncryptionFailed(
            format!("ChaCha20Poly1305 encryption failed: {:?}", e).into(),
        ))
    })?;

    let encrypted_message = SymmetricEncryptedMessage::new(ciphertext, nonce, None);

    Ok(EncryptedData {
        encrypted_message,
        salt,
    })
}

/// Decrypt data with a device password
pub fn decrypt_with_device_password(
    encrypted: &EncryptedData,
    device_password: &str,
) -> Result<Vec<u8>> {
    // Derive key from device password
    let key_bytes = derive_key_from_password(device_password, &encrypted.salt)?;
    let symmetric_key = SymmetricKey::from_bytes(key_bytes);

    // Decrypt data
    let cipher = ChaCha20Poly1305Cipher::new(&symmetric_key);
    let plaintext = cipher.decrypt(
        &encrypted.encrypted_message.ciphertext,
        &encrypted.encrypted_message.nonce,
        None
    ).map_err(|e| {
        P2PError::Security(SecurityError::DecryptionFailed(
            format!("ChaCha20Poly1305 decryption failed: {:?}", e).into(),
        ))
    })?;

    Ok(plaintext)
}

/// Derive a ChaCha20Poly1305 key from a password using Argon2id
fn derive_key_from_password(password: &str, salt: &[u8; SALT_SIZE]) -> Result<[u8; CHACHA_KEY_SIZE]> {
    // Configure Argon2id
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            DEVICE_ARGON2_MEMORY,
            DEVICE_ARGON2_TIME,
            DEVICE_ARGON2_PARALLELISM,
            Some(CHACHA_KEY_SIZE),
        )
        .map_err(|e| {
            P2PError::Security(SecurityError::InvalidKey(
                format!("Invalid Argon2 params: {}", e).into(),
            ))
        })?,
    );

    // Create salt string
    let salt_string = SaltString::encode_b64(salt).map_err(|e| {
        P2PError::Security(SecurityError::InvalidKey(
            format!("Failed to encode salt: {}", e).into(),
        ))
    })?;

    // Derive key
    let hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| {
            P2PError::Security(SecurityError::KeyGenerationFailed(
                format!("Argon2id key derivation failed: {}", e).into(),
            ))
        })?;

    let hash_output = hash.hash.ok_or_else(|| {
        P2PError::Security(SecurityError::KeyGenerationFailed(
            "No hash output from Argon2".to_string().into(),
        ))
    })?;

    let key_bytes = hash_output.as_bytes();
    if key_bytes.len() < CHACHA_KEY_SIZE {
        return Err(P2PError::Security(SecurityError::KeyGenerationFailed(
            "Insufficient key material from Argon2".to_string().into(),
        )));
    }

    let mut result = [0u8; CHACHA_KEY_SIZE];
    result.copy_from_slice(&key_bytes[..CHACHA_KEY_SIZE]);
    Ok(result)
}

/// Encrypt data with a shared secret (for peer-to-peer encryption)
pub fn encrypt_with_shared_secret(
    data: &[u8],
    shared_secret: &[u8; 32],
    info: &[u8],
) -> Result<EncryptedData> {
    // Generate random salt for HKDF
    let mut salt = [0u8; SALT_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);

    // TODO: Use saorsa-pqc HKDF-SHA3 when available  
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut key_bytes = [0u8; CHACHA_KEY_SIZE];
    hkdf.expand(info, &mut key_bytes).map_err(|e| {
        P2PError::Security(SecurityError::KeyGenerationFailed(
            format!("HKDF-SHA3 expansion failed: {:?}", e).into(),
        ))
    })?;

    let symmetric_key = SymmetricKey::from_bytes(key_bytes);

    // Encrypt data with ChaCha20Poly1305
    let cipher = ChaCha20Poly1305Cipher::new(&symmetric_key);
    let (ciphertext, nonce) = cipher.encrypt(data, None).map_err(|e| {
        P2PError::Security(SecurityError::EncryptionFailed(
            format!("ChaCha20Poly1305 encryption failed: {:?}", e).into(),
        ))
    })?;

    let encrypted_message = SymmetricEncryptedMessage::new(ciphertext, nonce, None);

    Ok(EncryptedData {
        encrypted_message,
        salt,
    })
}

/// Decrypt data with a shared secret
pub fn decrypt_with_shared_secret(
    encrypted: &EncryptedData,
    shared_secret: &[u8; 32],
    info: &[u8],
) -> Result<Vec<u8>> {
    // TODO: Use saorsa-pqc HKDF-SHA3 when available  
    let hkdf = Hkdf::<Sha256>::new(Some(&encrypted.salt), shared_secret);
    let mut key_bytes = [0u8; CHACHA_KEY_SIZE];
    hkdf.expand(info, &mut key_bytes).map_err(|e| {
        P2PError::Security(SecurityError::KeyGenerationFailed(
            format!("HKDF-SHA3 expansion failed: {:?}", e).into(),
        ))
    })?;

    let symmetric_key = SymmetricKey::from_bytes(key_bytes);

    // Decrypt data
    let cipher = ChaCha20Poly1305Cipher::new(&symmetric_key);
    let plaintext = cipher.decrypt(
        &encrypted.encrypted_message.ciphertext,
        &encrypted.encrypted_message.nonce,
        None
    ).map_err(|e| {
        P2PError::Security(SecurityError::DecryptionFailed(
            format!("ChaCha20Poly1305 decryption failed: {:?}", e).into(),
        ))
    })?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_password_encryption() {
        let data = b"Secret identity data";
        let password = "MyDevicePassword123!";

        // Encrypt
        let encrypted =
            encrypt_with_device_password(data, password).expect("Encryption should succeed");

        // Verify encrypted data exists
        assert!(!encrypted.encrypted_message.ciphertext.is_empty());

        // Decrypt
        let decrypted =
            decrypt_with_device_password(&encrypted, password).expect("Decryption should succeed");

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encryption_serialization() {
        let data = b"Test data for serialization";
        let password = "SerializeTest123!";

        // Create encrypted data
        let encrypted =
            encrypt_with_device_password(data, password).expect("Encryption should succeed");

        // Serialize
        let serialized = bincode::serialize(&encrypted).expect("Serialization should succeed");

        // Deserialize
        let deserialized: EncryptedData =
            bincode::deserialize(&serialized).expect("Deserialization should succeed");

        // Verify fields match
        assert_eq!(
            encrypted.encrypted_message.ciphertext,
            deserialized.encrypted_message.ciphertext
        );
        assert_eq!(encrypted.salt, deserialized.salt);

        // Verify can decrypt after deserialize
        let decrypted = decrypt_with_device_password(&deserialized, password)
            .expect("Decryption should succeed");

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_wrong_password_fails() {
        let data = b"Secret identity data";
        let password = "MyDevicePassword123!";
        let wrong_password = "WrongPassword456!";

        // Encrypt
        let encrypted =
            encrypt_with_device_password(data, password).expect("Encryption should succeed");

        // Try to decrypt with wrong password
        let result = decrypt_with_device_password(&encrypted, wrong_password);

        assert!(result.is_err());
    }

    #[test]
    fn test_shared_secret_encryption() {
        let data = b"Peer to peer message";
        let shared_secret = [42u8; 32];
        let info = b"p2p-identity-sync";

        // Encrypt
        let encrypted = encrypt_with_shared_secret(data, &shared_secret, info)
            .expect("Encryption should succeed");

        // Decrypt
        let decrypted = decrypt_with_shared_secret(&encrypted, &shared_secret, info)
            .expect("Decryption should succeed");

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_different_info_fails() {
        let data = b"Peer to peer message";
        let shared_secret = [42u8; 32];
        let info1 = b"p2p-identity-sync";
        let info2 = b"different-context";

        // Encrypt with info1
        let encrypted = encrypt_with_shared_secret(data, &shared_secret, info1)
            .expect("Encryption should succeed");

        // Try to decrypt with info2
        let result = decrypt_with_shared_secret(&encrypted, &shared_secret, info2);

        assert!(result.is_err());
    }

    #[test]
    fn test_encryption_produces_unique_nonces() {
        let data = b"Test data";
        let password = "TestPassword123!";

        // Encrypt same data twice
        let encrypted1 =
            encrypt_with_device_password(data, password).expect("First encryption should succeed");
        let encrypted2 =
            encrypt_with_device_password(data, password).expect("Second encryption should succeed");

        // Salts should be different
        assert_ne!(encrypted1.salt, encrypted2.salt);
        // Ciphertexts should be different due to different salts and nonces
        assert_ne!(
            encrypted1.encrypted_message.ciphertext,
            encrypted2.encrypted_message.ciphertext
        );
    }
}
