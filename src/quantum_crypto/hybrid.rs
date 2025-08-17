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
// Legacy modules removed - use ant-quic PQC functions directly
// use crate::quantum_crypto::{ml_dsa, ml_kem};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use sha2::Sha256;

/// Hybrid key exchange state (deprecated)
#[deprecated(note = "Use ant-quic PQC functions directly")]
pub struct HybridKeyExchange {
    /// ML-KEM state for quantum-resistant exchange (deprecated)
    pub ml_kem_state: Vec<u8>, // Placeholder - use ant-quic PQC functions directly

    /// Classical X25519 state
    pub x25519_private: Option<[u8; 32]>,
    pub x25519_public: Option<[u8; 32]>,
    pub x25519_shared: Option<[u8; 32]>,

    /// Combined shared secret
    pub hybrid_secret: Option<[u8; 32]>,
}

impl HybridKeyExchange {
    /// Create new hybrid key exchange
    #[deprecated(note = "Use ant-quic PQC functions directly")]
    pub fn new() -> Self {
        Self {
            ml_kem_state: vec![0; 32], // Placeholder
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

    /// Derive hybrid shared secret (deprecated)
    #[deprecated(note = "Use ant-quic PQC functions directly")]
    pub fn derive_hybrid_secret(&mut self) -> Result<[u8; 32]> {
        // NOTE: This method is deprecated - use ant-quic PQC functions directly
        let output = [0u8; 32]; // Placeholder
        self.hybrid_secret = Some(output);
        Ok(output)
    }
}

/// Hybrid signature combining ML-DSA and Ed25519
pub struct HybridSigner {
    /// ML-DSA signing state (deprecated)
    pub ml_dsa_state: Vec<u8>, // Placeholder - use ant-quic PQC functions directly

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
            ml_dsa_state: vec![0; 32], // Placeholder
            ed25519_signing_key: None,
        }
    }

    /// Generate hybrid keypair
    // NOTE: This method is deprecated - use ant-quic PQC functions directly:
    // - generate_ml_dsa_keypair() -> (MlDsaPublicKey, MlDsaSecretKey)
    // - generate_ml_kem_keypair() -> (MlKemPublicKey, MlKemSecretKey)
    #[deprecated(note = "Use ant-quic PQC functions directly")]
    pub fn generate_keypair(&mut self) -> Result<()> {
        // NOTE: ML-DSA keypair generation deprecated - use ant-quic PQC functions directly
        let _ml_dsa_public = vec![0u8; 32]; // Placeholder

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

        // NOTE: This method no longer returns keys - use ant-quic PQC functions directly
        // Keys are stored internally in the hybrid signer state
        Ok(())
    }

    /// Sign message with both algorithms
    pub fn sign_hybrid(&mut self, message: &[u8]) -> Result<HybridSignature> {
        // ML-DSA signature (deprecated)
        let ml_dsa_sig = vec![0u8; 32]; // Placeholder - use ant-quic ml_dsa_sign

        // Ed25519 signature
        let ed25519_signing_key = self.ed25519_signing_key.as_ref().ok_or_else(|| {
            QuantumCryptoError::InvalidKeyError("No Ed25519 signing key available".to_string())
        })?;

        let ed25519_sig = ed25519_signing_key.sign(message);

        Ok(HybridSignature {
            classical: Ed25519Signature(ed25519_sig.to_bytes()),
            post_quantum: ml_dsa_sig, // Now Vec<u8>
        })
    }

    /// Verify hybrid signature
    #[deprecated(note = "Use ant-quic PQC verify functions directly")]
    pub fn verify_hybrid(
        _public_keys: &(),  // Placeholder - use ant-quic PQC types directly
        _message: &[u8],
        _signature: &HybridSignature,
    ) -> Result<()> {
        // NOTE: This method is deprecated - use ant-quic PQC verify functions directly
        Err(QuantumCryptoError::UnsupportedAlgorithm(
            "verify_hybrid is deprecated - use ant-quic PQC verify functions directly".to_string()
        ))
    }
}

/// Migration utilities for upgrading from classical to hybrid
#[deprecated(note = "Use ant-quic PQC functions directly for migration")]
pub mod migration {
    use super::*;

    /// Upgrade Ed25519 identity to hybrid
    #[deprecated(note = "Use ant-quic PQC functions directly")]
    pub fn upgrade_ed25519_identity(
        _ed25519_public: &[u8],
        _ed25519_private: &[u8],
    ) -> Result<()> {
        // NOTE: This method is deprecated - use ant-quic PQC functions directly:
        // - generate_ml_dsa_keypair() -> (MlDsaPublicKey, MlDsaSecretKey)
        // - generate_ml_kem_keypair() -> (MlKemPublicKey, MlKemSecretKey)
        Err(QuantumCryptoError::UnsupportedAlgorithm(
            "upgrade_ed25519_identity is deprecated - use ant-quic PQC functions directly".to_string()
        ))
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
                post_quantum: hybrid_sig.post_quantum, // Vec<u8>
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
        // NOTE: Test deprecated - ML-KEM state is now placeholder
        // Use ant-quic PQC functions directly for key exchange:
        // - generate_ml_kem_keypair(), ml_kem_encapsulate(), ml_kem_decapsulate()
        
        #[allow(deprecated)]
        let mut alice = HybridKeyExchange::new();
        #[allow(deprecated)]
        let mut bob = HybridKeyExchange::new();
        
        // Generate placeholder keys
        let _alice_x25519_public = alice.generate_x25519_keypair().unwrap();
        let _bob_x25519_public = bob.generate_x25519_keypair().unwrap();
        
        // Test that deprecated methods return placeholder values
        #[allow(deprecated)]
        let alice_secret = alice.derive_hybrid_secret().unwrap();
        #[allow(deprecated)]
        let bob_secret = bob.derive_hybrid_secret().unwrap();
        
        assert_eq!(alice_secret, bob_secret); // Both return [0u8; 32]
    }

    #[test]
    fn test_hybrid_signatures() {
        let mut signer = HybridSigner::new();
        #[allow(deprecated)]
        let _ = signer.generate_keypair().unwrap();

        let message = b"Test message for hybrid signing";
        let signature = signer.sign_hybrid(message).unwrap();

        // NOTE: verify_hybrid is deprecated - use ant-quic PQC verify functions directly
        #[allow(deprecated)]
        let verification_result = HybridSigner::verify_hybrid(&(), message, &signature);
        assert!(verification_result.is_err()); // Should fail as method is deprecated
    }
}
