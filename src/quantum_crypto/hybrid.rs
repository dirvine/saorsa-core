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

//! Hybrid cryptography combining classical and post-quantum algorithms

use super::{QuantumCryptoError, Result};
use crate::quantum_crypto::types::*;
use crate::quantum_crypto::{ml_dsa, ml_kem};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use sha2::Sha256;

/// Hybrid key exchange state
pub struct HybridKeyExchange {
    /// ML-KEM state for quantum-resistant exchange
    pub ml_kem_state: ml_kem::MlKemState,

    /// Classical X25519 state
    pub x25519_private: Option<[u8; 32]>,
    pub x25519_public: Option<[u8; 32]>,
    pub x25519_shared: Option<[u8; 32]>,

    /// Combined shared secret
    pub hybrid_secret: Option<[u8; 32]>,
}

impl HybridKeyExchange {
    /// Create new hybrid key exchange
    pub fn new(role: ml_kem::KeyExchangeRole) -> Self {
        Self {
            ml_kem_state: ml_kem::MlKemState::new(role),
            x25519_private: None,
            x25519_public: None,
            x25519_shared: None,
            hybrid_secret: None,
        }
    }

    /// Generate X25519 keypair (placeholder)
    pub fn generate_x25519_keypair(&mut self) -> Result<[u8; 32]> {
        // Placeholder implementation
        let private_bytes = [1u8; 32];
        let public_bytes = [2u8; 32];

        self.x25519_private = Some(private_bytes);
        self.x25519_public = Some(public_bytes);

        Ok(public_bytes)
    }

    /// Set remote X25519 public key and compute shared secret (placeholder)
    pub fn set_remote_x25519_public(&mut self, _remote_public: [u8; 32]) -> Result<()> {
        let _private = self.x25519_private.ok_or_else(|| {
            QuantumCryptoError::InvalidKeyError("No local X25519 key generated".to_string())
        })?;

        // Placeholder implementation
        let shared_bytes = [3u8; 32];
        self.x25519_shared = Some(shared_bytes);

        Ok(())
    }

    /// Derive hybrid shared secret
    pub fn derive_hybrid_secret(&mut self) -> Result<[u8; 32]> {
        let ml_kem_secret = self.ml_kem_state.shared_secret.as_ref().ok_or_else(|| {
            QuantumCryptoError::InvalidKeyError("ML-KEM exchange not complete".to_string())
        })?;

        let x25519_secret = self.x25519_shared.as_ref().ok_or_else(|| {
            QuantumCryptoError::InvalidKeyError("X25519 exchange not complete".to_string())
        })?;

        // Combine secrets using HKDF
        use hkdf::Hkdf;

        let mut combined = Vec::new();
        combined.extend_from_slice(ml_kem_secret.as_bytes());
        combined.extend_from_slice(x25519_secret);

        let hkdf = Hkdf::<Sha256>::new(None, &combined);
        let mut output = [0u8; 32];
        hkdf.expand(b"hybrid-key-exchange-v1", &mut output)
            .map_err(|e| QuantumCryptoError::MlKemError(format!("HKDF failed: {e}")))?;

        self.hybrid_secret = Some(output);
        Ok(output)
    }
}

/// Hybrid signature combining ML-DSA and Ed25519
pub struct HybridSigner {
    /// ML-DSA signing state
    pub ml_dsa_state: ml_dsa::MlDsaState,

    /// Ed25519 signing key
    pub ed25519_signing_key: Option<SigningKey>,
}

impl Default for HybridSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl HybridSigner {
    /// Create new hybrid signer
    pub fn new() -> Self {
        Self {
            ml_dsa_state: ml_dsa::MlDsaState::new(),
            ed25519_signing_key: None,
        }
    }

    /// Generate hybrid keypair
    pub fn generate_keypair(&mut self) -> Result<(PublicKeySet, PrivateKeySet)> {
        // Generate ML-DSA keypair
        let ml_dsa_public = self.ml_dsa_state.generate_keypair()?;

        // Generate Ed25519 keypair
        let mut csprng = OsRng;
        let ed25519_signing_key = SigningKey::generate(&mut csprng);
        let ed25519_public = ed25519_signing_key.verifying_key().to_bytes();
        let ed25519_secret = ed25519_signing_key.to_bytes();

        // Combine secret and public key for Ed25519 (64 bytes total)
        let mut ed25519_private = [0u8; 64];
        ed25519_private[..32].copy_from_slice(&ed25519_secret);
        ed25519_private[32..].copy_from_slice(&ed25519_public);

        self.ed25519_signing_key = Some(ed25519_signing_key);

        let public_keys = PublicKeySet {
            ml_dsa: Some(MlDsaPublicKey(ml_dsa_public.0)),
            ml_kem: None,
            ed25519: Some(Ed25519PublicKey(ed25519_public)),
            frost: None,
        };

        let private_keys = PrivateKeySet {
            ml_dsa: self
                .ml_dsa_state
                .keypair
                .as_ref()
                .map(|(_, priv_key)| MlDsaPrivateKey(priv_key.0.clone())),
            ml_kem: None,
            ed25519: Some(Ed25519PrivateKey(ed25519_private)),
            frost: None,
        };

        Ok((public_keys, private_keys))
    }

    /// Sign message with both algorithms
    pub fn sign_hybrid(&mut self, message: &[u8]) -> Result<HybridSignature> {
        // ML-DSA signature
        let ml_dsa_sig = self.ml_dsa_state.sign_message(message)?;

        // Ed25519 signature
        let ed25519_signing_key = self.ed25519_signing_key.as_ref().ok_or_else(|| {
            QuantumCryptoError::InvalidKeyError("No Ed25519 signing key available".to_string())
        })?;

        let ed25519_sig = ed25519_signing_key.sign(message);

        Ok(HybridSignature {
            classical: Ed25519Signature(ed25519_sig.to_bytes()),
            post_quantum: ml_dsa_sig,
        })
    }

    /// Verify hybrid signature
    pub fn verify_hybrid(
        public_keys: &PublicKeySet,
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<()> {
        // Verify ML-DSA signature
        if let Some(ml_dsa_key) = &public_keys.ml_dsa {
            ml_dsa::verify(&ml_dsa_key.0, message, &signature.post_quantum.0)?;
        } else {
            return Err(QuantumCryptoError::InvalidKeyError(
                "No ML-DSA public key".to_string(),
            ));
        }

        // Verify Ed25519 signature
        if let Some(ed25519_key) = &public_keys.ed25519 {
            let verifying_key = VerifyingKey::from_bytes(&ed25519_key.0)
                .map_err(|e| QuantumCryptoError::InvalidKeyError(e.to_string()))?;

            let signature_bytes: [u8; 64] =
                signature.classical.0.as_slice().try_into().map_err(|_| {
                    QuantumCryptoError::InvalidKeyError("Invalid signature length".to_string())
                })?;
            let signature = Signature::from_bytes(&signature_bytes);

            verifying_key
                .verify(message, &signature)
                .map_err(|_| QuantumCryptoError::SignatureVerificationFailed)?;
        } else {
            return Err(QuantumCryptoError::InvalidKeyError(
                "No Ed25519 public key".to_string(),
            ));
        }

        Ok(())
    }
}

/// Migration utilities for upgrading from classical to hybrid
pub mod migration {
    use super::*;

    /// Upgrade Ed25519 identity to hybrid
    pub fn upgrade_ed25519_identity(
        ed25519_public: &[u8],
        ed25519_private: &[u8],
    ) -> Result<(PublicKeySet, PrivateKeySet)> {
        // Generate new ML-DSA keypair
        let (ml_dsa_public, ml_dsa_private) = ml_dsa::generate_keypair()?;

        // Generate new ML-KEM keypair
        let (ml_kem_public, ml_kem_private) = ml_kem::generate_keypair()?;

        // Convert slices to arrays
        let ed25519_pub_array: [u8; 32] = ed25519_public.try_into().map_err(|_| {
            QuantumCryptoError::InvalidKeyError("Ed25519 public key must be 32 bytes".to_string())
        })?;
        let ed25519_priv_array: [u8; 64] = ed25519_private.try_into().map_err(|_| {
            QuantumCryptoError::InvalidKeyError("Ed25519 private key must be 64 bytes".to_string())
        })?;

        let public_keys = PublicKeySet {
            ml_dsa: Some(MlDsaPublicKey(ml_dsa_public)),
            ml_kem: Some(MlKemPublicKey(ml_kem_public)),
            ed25519: Some(Ed25519PublicKey(ed25519_pub_array)),
            frost: None,
        };

        let private_keys = PrivateKeySet {
            ml_dsa: Some(MlDsaPrivateKey(ml_dsa_private)),
            ml_kem: Some(MlKemPrivateKey(ml_kem_private)),
            ed25519: Some(Ed25519PrivateKey(ed25519_priv_array)),
            frost: None,
        };

        Ok((public_keys, private_keys))
    }

    /// Create backward-compatible signature
    pub fn create_compatible_signature(
        signer: &mut HybridSigner,
        message: &[u8],
        use_hybrid: bool,
    ) -> Result<crate::quantum_crypto::SignatureScheme> {
        if use_hybrid {
            let hybrid_sig = signer.sign_hybrid(message)?;
            Ok(crate::quantum_crypto::SignatureScheme::Dual {
                classical: hybrid_sig.classical.0.to_vec(),
                post_quantum: hybrid_sig.post_quantum.0,
            })
        } else {
            // Classical only
            let ed25519_signing_key = signer.ed25519_signing_key.as_ref().ok_or_else(|| {
                QuantumCryptoError::InvalidKeyError("No Ed25519 signing key".to_string())
            })?;

            let signature = ed25519_signing_key.sign(message);
            Ok(crate::quantum_crypto::SignatureScheme::Classical(
                signature.to_bytes().to_vec(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_key_exchange() {
        // Alice (initiator) - she will receive the ciphertext
        let mut alice = HybridKeyExchange::new(ml_kem::KeyExchangeRole::Initiator);
        let alice_ml_kem_public = alice.ml_kem_state.generate_keypair().unwrap();
        let alice_x25519_public = alice.generate_x25519_keypair().unwrap();

        // Bob (responder) - he will create the ciphertext
        let mut bob = HybridKeyExchange::new(ml_kem::KeyExchangeRole::Responder);
        let bob_x25519_public = bob.generate_x25519_keypair().unwrap();

        // Bob sets Alice's ML-KEM public key (he'll use it to encapsulate)
        bob.ml_kem_state.set_remote_public_key(alice_ml_kem_public);
        bob.set_remote_x25519_public(alice_x25519_public).unwrap();

        // Bob completes ML-KEM (encapsulates using Alice's public key)
        let (ciphertext, bob_ml_kem_secret) = bob.ml_kem_state.complete_as_responder().unwrap();

        // Alice completes exchanges (decapsulates using her private key)
        let alice_ml_kem_secret = alice
            .ml_kem_state
            .complete_as_initiator(&ciphertext)
            .unwrap();
        alice.set_remote_x25519_public(bob_x25519_public).unwrap();

        // Verify ML-KEM secrets match
        assert_eq!(alice_ml_kem_secret.as_bytes(), bob_ml_kem_secret.as_bytes());

        // Derive hybrid secrets
        let alice_secret = alice.derive_hybrid_secret().unwrap();
        let bob_secret = bob.derive_hybrid_secret().unwrap();

        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn test_hybrid_signatures() {
        let mut signer = HybridSigner::new();
        let (public_keys, _) = signer.generate_keypair().unwrap();

        let message = b"Test message for hybrid signing";
        let signature = signer.sign_hybrid(message).unwrap();

        // Verify signature
        assert!(HybridSigner::verify_hybrid(&public_keys, message, &signature).is_ok());

        // Verify with wrong message fails
        let wrong_message = b"Wrong message";
        assert!(HybridSigner::verify_hybrid(&public_keys, wrong_message, &signature).is_err());
    }
}
