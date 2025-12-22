// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! ML-KEM (Module-Lattice Key Encapsulation Mechanism) implementation
//!
//! Implements FIPS 203 standard for quantum-resistant key exchange

use super::{QuantumCryptoError, Result};
use crate::quantum_crypto::types::*;
// use ml_kem::{MlKem768, EncapsulatePair, DecapsulatePair}; // Temporarily disabled

/// Generate ML-KEM keypair using ant-quic's implementation
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    use crate::quantum_crypto::ant_quic_integration;

    ant_quic_integration::generate_ml_kem_keypair()
        .map_err(|e| QuantumCryptoError::KeyGenerationError(e.to_string()))
}

/// Encapsulate a shared secret using ML-KEM public key
pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, SharedSecret)> {
    use crate::quantum_crypto::ant_quic_integration;

    let (ciphertext, shared_secret_bytes) = ant_quic_integration::ml_kem_encapsulate(public_key)
        .map_err(|e| QuantumCryptoError::MlKemError(e.to_string()))?;

    // Convert raw bytes to our SharedSecret type
    let shared_secret =
        SharedSecret(shared_secret_bytes.try_into().map_err(|_| {
            QuantumCryptoError::MlKemError("Invalid shared secret length".to_string())
        })?);

    Ok((ciphertext, shared_secret))
}

/// Decapsulate shared secret using ML-KEM private key
pub fn decapsulate(private_key: &[u8], ciphertext: &[u8]) -> Result<SharedSecret> {
    use crate::quantum_crypto::ant_quic_integration;

    let shared_secret_bytes = ant_quic_integration::ml_kem_decapsulate(private_key, ciphertext)
        .map_err(|e| QuantumCryptoError::MlKemError(e.to_string()))?;

    // Convert raw bytes to our SharedSecret type
    let shared_secret =
        SharedSecret(shared_secret_bytes.try_into().map_err(|_| {
            QuantumCryptoError::MlKemError("Invalid shared secret length".to_string())
        })?);

    Ok(shared_secret)
}

/// ML-KEM key exchange state for handshake protocol
pub struct MlKemState {
    /// Our keypair
    pub keypair: Option<(MlKemPublicKey, MlKemPrivateKey)>,

    /// Remote public key
    pub remote_public_key: Option<MlKemPublicKey>,

    /// Shared secret (after exchange)
    pub shared_secret: Option<SharedSecret>,

    /// Role in the exchange
    pub role: KeyExchangeRole,
}

/// Role in key exchange
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyExchangeRole {
    Initiator,
    Responder,
}

impl MlKemState {
    /// Create new ML-KEM state
    pub fn new(role: KeyExchangeRole) -> Self {
        Self {
            keypair: None,
            remote_public_key: None,
            shared_secret: None,
            role,
        }
    }

    /// Generate our keypair
    pub fn generate_keypair(&mut self) -> Result<MlKemPublicKey> {
        let (public_key, private_key) = generate_keypair()?;

        let public = MlKemPublicKey(public_key);
        let private = MlKemPrivateKey(private_key);

        self.keypair = Some((public.clone(), private));

        Ok(public)
    }

    /// Set remote public key
    pub fn set_remote_public_key(&mut self, public_key: MlKemPublicKey) {
        self.remote_public_key = Some(public_key);
    }

    /// Complete key exchange as initiator
    pub fn complete_as_initiator(&mut self, ciphertext: &MlKemCiphertext) -> Result<SharedSecret> {
        match self.role {
            KeyExchangeRole::Initiator => {
                let (_, private_key) = self.keypair.as_ref().ok_or_else(|| {
                    QuantumCryptoError::InvalidKeyError("No local keypair generated".to_string())
                })?;

                let shared_secret = decapsulate(&private_key.0, &ciphertext.0)?;
                self.shared_secret = Some(shared_secret.clone());

                Ok(shared_secret)
            }
            KeyExchangeRole::Responder => Err(QuantumCryptoError::InvalidKeyError(
                "Cannot complete as initiator when role is responder".to_string(),
            )),
        }
    }

    /// Complete key exchange as responder
    pub fn complete_as_responder(&mut self) -> Result<(MlKemCiphertext, SharedSecret)> {
        match self.role {
            KeyExchangeRole::Responder => {
                let remote_key = self.remote_public_key.as_ref().ok_or_else(|| {
                    QuantumCryptoError::InvalidKeyError("No remote public key set".to_string())
                })?;

                let (ciphertext, shared_secret) = encapsulate(&remote_key.0)?;
                self.shared_secret = Some(shared_secret.clone());

                Ok((MlKemCiphertext(ciphertext), shared_secret))
            }
            KeyExchangeRole::Initiator => Err(QuantumCryptoError::InvalidKeyError(
                "Cannot complete as responder when role is initiator".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_key_exchange() {
        // Alice (initiator) generates keypair
        let mut alice_state = MlKemState::new(KeyExchangeRole::Initiator);
        let alice_public = alice_state.generate_keypair().unwrap();

        // Bob (responder) receives Alice's public key
        let mut bob_state = MlKemState::new(KeyExchangeRole::Responder);
        bob_state.set_remote_public_key(alice_public);

        // Bob encapsulates shared secret
        let (ciphertext, bob_secret) = bob_state.complete_as_responder().unwrap();

        // Alice decapsulates shared secret
        let alice_secret = alice_state.complete_as_initiator(&ciphertext).unwrap();

        // Secrets should match
        assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    }

    #[test]
    fn test_keypair_generation() {
        let (public_key, private_key) = generate_keypair().unwrap();

        // Check key sizes (ML-KEM-768)
        assert_eq!(public_key.len(), 1184);
        assert_eq!(private_key.len(), 2400);
    }

    #[test]
    fn test_invalid_role_operations() {
        let mut initiator = MlKemState::new(KeyExchangeRole::Initiator);
        let mut responder = MlKemState::new(KeyExchangeRole::Responder);

        // Initiator cannot complete as responder
        assert!(initiator.complete_as_responder().is_err());

        // Responder cannot complete as initiator
        let dummy_ciphertext = MlKemCiphertext(vec![0; 1088]);
        assert!(responder.complete_as_initiator(&dummy_ciphertext).is_err());
    }
}
