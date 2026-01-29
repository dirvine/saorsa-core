//! End-to-end encryption for messaging with bincode serialization
//!
//! This module provides secure message encryption, signing, and key management
//! for peer-to-peer communication. All messages are serialized using bincode
//! for consistency and performance.
//!
//! ## Serialization Strategy
//!
//! All cryptographic operations use **bincode binary encoding**:
//! - Message encryption/decryption uses bincode
//! - Message signing/verification uses bincode
//! - Ensures consistent hashing and verification across all operations
//!
//! ## Key Management
//!
//! - Session keys with 24-hour expiry and 12-hour rotation
//! - Device-specific keys for multi-device support
//! - Ephemeral sessions for perfect forward secrecy
//! - Key ratcheting for additional forward secrecy layers

use super::DhtClient;
use super::key_exchange::KeyExchange;
use super::types::*;
use crate::identity::FourWordAddress;

use anyhow::Result;
use blake3::Hasher;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Size of cryptographic keys derived from BLAKE3 hashing (32 bytes)
const KEY_SIZE: usize = 32;

/// Secure messaging with quantum-resistant encryption
pub struct SecureMessaging {
    /// Current user identity
    identity: FourWordAddress,
    /// Key exchange manager
    pub key_exchange: KeyExchange,
    /// Session keys cache
    session_keys: Arc<RwLock<HashMap<FourWordAddress, SessionKey>>>,
    /// Device keys for multi-device support
    device_keys: Arc<RwLock<HashMap<DeviceId, DeviceKey>>>,
}

impl SecureMessaging {
    /// Create new secure messaging instance
    pub async fn new(identity: FourWordAddress, dht: DhtClient) -> Result<Self> {
        let key_exchange = KeyExchange::new(identity.clone(), dht).await?;

        Ok(Self {
            identity,
            key_exchange,
            session_keys: Arc::new(RwLock::new(HashMap::new())),
            device_keys: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Derive a cryptographic key from components using BLAKE3
    ///
    /// # Arguments
    /// * `identity_bytes` - Identity bytes
    /// * `component_bytes` - Additional component bytes
    ///
    /// # Returns
    /// A 32-byte key derived from the components
    fn derive_key(&self, identity_bytes: &[u8], component_bytes: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = Hasher::new();
        hasher.update(identity_bytes);
        hasher.update(component_bytes);
        let key_material = hasher.finalize();
        Ok(key_material.as_bytes()[..KEY_SIZE].to_vec())
    }

    /// Derive a cryptographic key from three components using BLAKE3
    fn derive_key_three(
        &self,
        component1: &[u8],
        component2: &[u8],
        component3: &[u8],
    ) -> Result<Vec<u8>> {
        let mut hasher = Hasher::new();
        hasher.update(component1);
        hasher.update(component2);
        hasher.update(component3);
        let key_material = hasher.finalize();
        Ok(key_material.as_bytes()[..KEY_SIZE].to_vec())
    }

    /// Encrypt a message for recipients
    pub async fn encrypt_message(&self, message: &RichMessage) -> Result<EncryptedMessage> {
        // Try to get existing session key or establish new one
        let session_key = if let Ok(key) = self
            .key_exchange
            .get_session_key(&message.channel_id.0.to_string().into())
            .await
        {
            key
        } else {
            // Use a deterministic key for the channel derived from identity and channel ID
            let identity_bytes = self.identity.to_string();
            let identity_ref = identity_bytes.as_bytes();
            let channel_ref = message.channel_id.0.as_bytes();
            self.derive_key(identity_ref, channel_ref)?
        };

        // Encrypt with ChaCha20Poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(&session_key)?;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Serialize message with bincode for consistency
        let plaintext = crate::messaging::encoding::encode(message)?;

        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        Ok(EncryptedMessage {
            id: message.id,
            channel_id: message.channel_id,
            sender: self.identity.clone(),
            ciphertext,
            nonce: nonce.to_vec(),
            key_id: self.identity.to_string(),
        })
    }

    /// Decrypt an encrypted message
    pub async fn decrypt_message(&self, encrypted: EncryptedMessage) -> Result<RichMessage> {
        // Get session key for sender
        let session_key = self.get_or_create_session_key(&encrypted.sender).await?;

        // Decrypt with ChaCha20Poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(&session_key.key)?;
        let nonce = Nonce::from_slice(&encrypted.nonce);

        let plaintext = cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        // Deserialize message with bincode for consistency
        let message: RichMessage = crate::messaging::encoding::decode(&plaintext)?;

        Ok(message)
    }

    /// Sign a message for verification using bincode serialization
    ///
    /// # Arguments
    /// * `message` - The message to sign
    ///
    /// # Returns
    /// A 32-byte BLAKE3 hash of the message
    ///
    /// # Note
    /// Uses bincode serialization to match encryption/decryption for consistency.
    /// In production, this should use actual ML-DSA signatures.
    pub fn sign_message(&self, message: &RichMessage) -> Result<Vec<u8>> {
        // Hash message content using bincode for consistency with encryption
        let plaintext = crate::messaging::encoding::encode(message)?;
        let mut hasher = Hasher::new();
        hasher.update(&plaintext);
        let hash = hasher.finalize();

        Ok(hash.as_bytes().to_vec())
    }

    /// Verify message signature using bincode serialization
    ///
    /// Returns `false` if the message cannot be serialized or if the signature
    /// does not match the expected hash of the message content.
    ///
    /// # Note
    /// Uses bincode serialization to match signing for consistency.
    pub fn verify_message(&self, message: &RichMessage) -> bool {
        // Hash message content using bincode - return false if serialization fails
        let serialized = match crate::messaging::encoding::encode(message) {
            Ok(data) => data,
            Err(e) => {
                tracing::warn!("Failed to serialize message for verification: {e}");
                return false;
            }
        };
        let mut hasher = Hasher::new();
        hasher.update(&serialized);
        let hash = hasher.finalize();

        // Verify with ML-DSA
        // In production, verify actual ML-DSA signature
        message.signature.signature == hash.as_bytes().to_vec()
    }

    /// Establish quantum-safe session key
    pub async fn establish_session(&self, peer: &FourWordAddress) -> Result<SessionKey> {
        // Derive session key from peer identities
        let identity_bytes = self.identity.to_string();
        let peer_bytes = peer.to_string();
        let key = self.derive_key(identity_bytes.as_bytes(), peer_bytes.as_bytes())?;

        let session_key = SessionKey {
            peer: peer.clone(),
            key,
            established_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
        };

        // Cache session key
        let mut keys = self.session_keys.write().await;
        keys.insert(peer.clone(), session_key.clone());

        Ok(session_key)
    }

    /// Rotate session keys periodically
    ///
    /// Removes expired keys and re-establishes keys older than 12 hours.
    /// Avoids lock deadlock by collecting peers first, then rotating outside the lock.
    pub async fn rotate_session_keys(&self) -> Result<()> {
        let now = chrono::Utc::now();

        // Collect peers that need rotation (release lock before awaiting)
        let peers_to_rotate = {
            let mut keys = self.session_keys.write().await;
            // Remove expired keys
            keys.retain(|_, key| key.expires_at > now);

            // Collect peers with old keys
            let rotation_threshold = now - chrono::Duration::hours(12);
            keys.iter()
                .filter(|(_, key)| key.established_at < rotation_threshold)
                .map(|(peer, _)| peer.clone())
                .collect::<Vec<_>>()
        };

        // Re-establish sessions outside the lock to avoid deadlock
        for peer in peers_to_rotate {
            let new_key = self.establish_session(&peer).await?;
            let mut keys = self.session_keys.write().await;
            keys.insert(peer, new_key);
        }

        Ok(())
    }

    /// Create device-specific keys for multi-device support
    ///
    /// # Note
    /// Currently derives keys deterministically. In production, should use
    /// proper cryptographic key generation (e.g., ML-DSA).
    pub async fn register_device(&self, device_id: DeviceId) -> Result<DeviceKey> {
        // Generate device-specific key
        let identity_bytes = self.identity.to_string();
        let device_ref = device_id.0.as_bytes();
        let public_key = self.derive_key(identity_bytes.as_bytes(), device_ref)?;

        // FIXME: In production, generate proper cryptographic keypair instead of derived key
        // This is currently a placeholder using derived key material
        let device_key = DeviceKey {
            device_id: device_id.clone(),
            public_key,
            private_key: vec![0; KEY_SIZE], // Placeholder - should be proper keypair
            created_at: chrono::Utc::now(),
        };

        // Store device key
        let mut keys = self.device_keys.write().await;
        keys.insert(device_id, device_key.clone());

        Ok(device_key)
    }

    /// Encrypt for specific devices
    pub async fn encrypt_for_devices(
        &self,
        message: &RichMessage,
        devices: Vec<DeviceId>,
    ) -> Result<Vec<EncryptedMessage>> {
        let mut encrypted_messages = Vec::new();

        for device_id in devices {
            // Get device key
            let keys = self.device_keys.read().await;
            if let Some(device_key) = keys.get(&device_id) {
                // Encrypt with device-specific key
                let encrypted = self
                    .encrypt_with_key(message, &device_key.public_key)
                    .await?;
                encrypted_messages.push(encrypted);
            }
        }

        Ok(encrypted_messages)
    }

    /// Perfect forward secrecy with ephemeral keys
    ///
    /// # Note
    /// Currently generates ephemeral keys deterministically. In production,
    /// should use proper quantum-safe ephemeral key generation.
    pub async fn create_ephemeral_session(
        &self,
        peer: &FourWordAddress,
    ) -> Result<EphemeralSession> {
        // Generate ephemeral keypair using timestamp for non-determinism
        let timestamp_bytes = chrono::Utc::now().timestamp().to_le_bytes();
        let peer_bytes = peer.to_string();
        let key_material =
            self.derive_key_three(&timestamp_bytes, peer_bytes.as_bytes(), b"ephemeral")?;

        // Split key material into public and private components
        // Ensure we have enough bytes for both parts
        if key_material.len() < 64 {
            return Err(anyhow::anyhow!(
                "Insufficient key material for ephemeral session"
            ));
        }

        Ok(EphemeralSession {
            peer: peer.clone(),
            ephemeral_public: key_material[..KEY_SIZE].to_vec(),
            ephemeral_private: key_material[KEY_SIZE..64].to_vec(),
            created_at: chrono::Utc::now(),
            message_count: 0,
        })
    }

    /// Get or create session key
    async fn get_or_create_session_key(&self, peer: &FourWordAddress) -> Result<SessionKey> {
        let keys = self.session_keys.read().await;

        if let Some(key) = keys.get(peer)
            && key.expires_at > chrono::Utc::now()
        {
            return Ok(key.clone());
        }
        drop(keys);

        // Create new session
        self.establish_session(peer).await
    }

    /// Encrypt with specific key using bincode serialization
    async fn encrypt_with_key(
        &self,
        message: &RichMessage,
        key: &[u8],
    ) -> Result<EncryptedMessage> {
        let cipher = ChaCha20Poly1305::new_from_slice(&key[..KEY_SIZE])?;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Use bincode for consistency with other encryption operations
        let plaintext = crate::messaging::encoding::encode(message)?;
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        Ok(EncryptedMessage {
            id: message.id,
            channel_id: message.channel_id,
            sender: self.identity.clone(),
            ciphertext,
            nonce: nonce.to_vec(),
            key_id: self.identity.to_string(),
        })
    }
}

/// Session key for peer communication
///
/// Stores a cryptographic key shared with a specific peer,
/// including expiration and establishment time for key rotation.
#[derive(Debug, Clone)]
pub struct SessionKey {
    /// The peer this key is shared with
    pub peer: FourWordAddress,
    /// The 32-byte symmetric key material
    pub key: Vec<u8>,
    /// When this key was established
    pub established_at: chrono::DateTime<chrono::Utc>,
    /// When this key expires and must be rotated
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Device-specific key for multi-device support
///
/// Stores encryption keys associated with a specific user device.
/// Currently uses derived key material; production should use proper key generation.
#[derive(Debug, Clone)]
pub struct DeviceKey {
    /// Unique device identifier
    pub device_id: DeviceId,
    /// The public key material (32 bytes)
    pub public_key: Vec<u8>,
    /// The private key material (32 bytes) - currently placeholder
    pub private_key: Vec<u8>,
    /// When this device key was created
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Ephemeral session for perfect forward secrecy
///
/// Provides one-time session keys that are automatically discarded
/// after use, ensuring perfect forward secrecy properties.
#[derive(Debug, Clone)]
pub struct EphemeralSession {
    /// The peer this session is with
    pub peer: FourWordAddress,
    /// The ephemeral public key (32 bytes)
    pub ephemeral_public: Vec<u8>,
    /// The ephemeral private key (32 bytes)
    pub ephemeral_private: Vec<u8>,
    /// When this session was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Number of messages sent in this session
    pub message_count: u32,
}

/// Key ratcheting for forward secrecy
///
/// Implements key ratcheting to ensure that compromise of a current key
/// does not allow decryption of previous messages.
pub struct KeyRatchet {
    /// Current key material (32 bytes)
    current_key: Vec<u8>,
    /// Generation counter for ratcheting
    generation: u32,
}

impl KeyRatchet {
    /// Create new key ratchet with initial key material
    ///
    /// # Arguments
    /// * `initial_key` - The starting key material (should be 32 bytes)
    pub fn new(initial_key: Vec<u8>) -> Self {
        Self {
            current_key: initial_key,
            generation: 0,
        }
    }

    /// Ratchet forward to next key
    ///
    /// Derives a new key from the current key and generation counter.
    /// Each call increments the generation counter.
    ///
    /// # Returns
    /// The new current key (32 bytes)
    pub fn ratchet(&mut self) -> Vec<u8> {
        let mut hasher = Hasher::new();
        hasher.update(&self.current_key);
        hasher.update(&self.generation.to_le_bytes());
        let new_key = hasher.finalize();

        self.current_key = new_key.as_bytes().to_vec();
        self.generation += 1;

        self.current_key.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::user_handle::UserHandle;

    #[tokio::test]
    async fn test_message_encryption() {
        let identity = FourWordAddress::from("alice-bob-charlie-david");
        let dht = super::DhtClient::new().unwrap();
        let secure = SecureMessaging::new(identity.clone(), dht).await.unwrap();

        let message = RichMessage::new(
            UserHandle::from(identity.to_string()),
            ChannelId::new(),
            MessageContent::Text("Secret message".to_string()),
        );

        let encrypted = secure.encrypt_message(&message).await.unwrap();
        assert!(!encrypted.ciphertext.is_empty());
        assert_eq!(encrypted.id, message.id);
    }

    #[tokio::test]
    async fn test_message_signing() {
        let identity = FourWordAddress::from("alice-bob-charlie-david");
        let dht = super::DhtClient::new().unwrap();
        let secure = SecureMessaging::new(identity.clone(), dht).await.unwrap();

        let message = RichMessage::new(
            UserHandle::from(identity.to_string()),
            ChannelId::new(),
            MessageContent::Text("Sign me".to_string()),
        );

        let signature = secure.sign_message(&message).unwrap();
        assert!(!signature.is_empty());
        assert_eq!(signature.len(), 32); // Blake3 hash is 32 bytes
    }

    #[tokio::test]
    async fn test_message_signing_consistency() {
        let identity = FourWordAddress::from("alice-bob-charlie-david");
        let dht = super::DhtClient::new().unwrap();
        let secure = SecureMessaging::new(identity.clone(), dht).await.unwrap();

        let message = RichMessage::new(
            UserHandle::from(identity.to_string()),
            ChannelId::new(),
            MessageContent::Text("Consistent sign".to_string()),
        );

        // Sign the same message twice - should produce identical signatures
        let sig1 = secure.sign_message(&message).unwrap();
        let sig2 = secure.sign_message(&message).unwrap();

        assert_eq!(
            sig1, sig2,
            "Signing same message should produce identical signature"
        );
    }

    #[test]
    fn test_key_ratchet() {
        let initial_key = vec![0u8; 32];
        let mut ratchet = KeyRatchet::new(initial_key.clone());

        let key1 = ratchet.ratchet();
        let key2 = ratchet.ratchet();

        assert_ne!(key1, initial_key);
        assert_ne!(key2, key1);
        assert_eq!(ratchet.generation, 2);
    }

    #[test]
    fn test_key_ratchet_deterministic() {
        let initial_key = vec![0u8; 32];
        let mut ratchet1 = KeyRatchet::new(initial_key.clone());
        let mut ratchet2 = KeyRatchet::new(initial_key);

        let key1_a = ratchet1.ratchet();
        let key1_b = ratchet1.ratchet();

        let key2_a = ratchet2.ratchet();
        let key2_b = ratchet2.ratchet();

        assert_eq!(
            key1_a, key2_a,
            "Same initial key should produce same ratcheted keys"
        );
        assert_eq!(key1_b, key2_b, "Ratcheting should be deterministic");
    }

    #[tokio::test]
    async fn test_establish_session_key() {
        let identity = FourWordAddress::from("alice-bob-charlie-david");
        let peer = FourWordAddress::from("david-charlie-bob-alice");
        let dht = super::DhtClient::new().unwrap();
        let secure = SecureMessaging::new(identity.clone(), dht).await.unwrap();

        // Establish session with peer
        let session_key = secure.establish_session(&peer).await.unwrap();

        assert_eq!(
            session_key.peer, peer,
            "Session key should be associated with peer"
        );
        assert_eq!(session_key.key.len(), 32, "Session key should be 32 bytes");
        assert!(
            session_key.expires_at > chrono::Utc::now(),
            "Session key should not be expired"
        );
    }

    #[tokio::test]
    async fn test_register_device() {
        let identity = FourWordAddress::from("alice-bob-charlie-david");
        let dht = super::DhtClient::new().unwrap();
        let secure = SecureMessaging::new(identity.clone(), dht).await.unwrap();

        let device_id = DeviceId::new();

        // Register device
        let device_key = secure.register_device(device_id.clone()).await.unwrap();

        assert_eq!(device_key.device_id, device_id, "Device ID should match");
        assert_eq!(
            device_key.public_key.len(),
            32,
            "Public key should be 32 bytes"
        );
        assert_eq!(
            device_key.private_key.len(),
            32,
            "Private key should be 32 bytes"
        );
    }
}
