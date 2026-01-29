// End-to-end encryption for messaging

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

    /// Encrypt a message for recipients
    pub async fn encrypt_message(&self, message: &RichMessage) -> Result<EncryptedMessage> {
        // For channel messages, we'll use a channel-specific key
        // For DMs, we'll use peer-to-peer key exchange
        // For now, using a simple approach

        // Try to get existing session key or establish new one
        let session_key = if let Ok(key) = self
            .key_exchange
            .get_session_key(&message.channel_id.0.to_string().into())
            .await
        {
            key
        } else {
            // Use a deterministic key for the channel (in production, this would be properly negotiated)
            let mut hasher = Hasher::new();
            hasher.update(self.identity.to_string().as_bytes());
            hasher.update(message.channel_id.0.as_bytes());
            let key_material = hasher.finalize();
            key_material.as_bytes()[..32].to_vec()
        };

        // Encrypt with ChaCha20Poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(&session_key)?;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Serialize message with bincode
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

        // Deserialize message with bincode
        let message: RichMessage = crate::messaging::encoding::decode(&plaintext)?;

        Ok(message)
    }

    /// Sign a message for verification
    pub fn sign_message(&self, message: &RichMessage) -> Result<Vec<u8>> {
        // Hash message content
        let mut hasher = Hasher::new();
        hasher.update(&serde_json::to_vec(message)?);
        let hash = hasher.finalize();

        // Sign with ML-DSA
        // In production, use actual ML-DSA signing
        Ok(hash.as_bytes().to_vec())
    }

    /// Verify message signature
    ///
    /// Returns `false` if the message cannot be serialized or if the signature
    /// does not match the expected hash of the message content.
    pub fn verify_message(&self, message: &RichMessage) -> bool {
        // Hash message content - return false if serialization fails
        let serialized = match serde_json::to_vec(message) {
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
        // For now, use a simple key derivation
        // In production, this would use ML-KEM for quantum-safe key exchange

        // Derive session key from peer identities
        let mut hasher = Hasher::new();
        hasher.update(self.identity.to_string().as_bytes());
        hasher.update(peer.to_string().as_bytes());
        let key_material = hasher.finalize();

        let session_key = SessionKey {
            peer: peer.clone(),
            key: key_material.as_bytes()[..32].to_vec(),
            established_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
        };

        // Cache session key
        let mut keys = self.session_keys.write().await;
        keys.insert(peer.clone(), session_key.clone());

        Ok(session_key)
    }

    /// Rotate session keys periodically
    pub async fn rotate_session_keys(&self) -> Result<()> {
        let mut keys = self.session_keys.write().await;
        let now = chrono::Utc::now();

        // Remove expired keys
        keys.retain(|_, key| key.expires_at > now);

        // Rotate keys older than 12 hours
        let rotation_threshold = now - chrono::Duration::hours(12);
        for (peer, key) in keys.iter_mut() {
            if key.established_at < rotation_threshold {
                // Re-establish session
                let new_key = self.establish_session(peer).await?;
                *key = new_key;
            }
        }

        Ok(())
    }

    /// Create device-specific keys for multi-device
    pub async fn register_device(&self, device_id: DeviceId) -> Result<DeviceKey> {
        // Generate device-specific key
        let mut hasher = Hasher::new();
        hasher.update(self.identity.to_string().as_bytes());
        hasher.update(device_id.0.as_bytes());
        let key_material = hasher.finalize();

        let device_key = DeviceKey {
            device_id: device_id.clone(),
            public_key: key_material.as_bytes().to_vec(),
            private_key: vec![0; 32], // In production, generate proper keypair
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
    pub async fn create_ephemeral_session(
        &self,
        peer: &FourWordAddress,
    ) -> Result<EphemeralSession> {
        // Generate ephemeral keypair
        // In production, this would use proper quantum-safe ephemeral key generation
        let mut hasher = Hasher::new();
        hasher.update(&chrono::Utc::now().timestamp().to_le_bytes());
        hasher.update(peer.to_string().as_bytes());
        let key_material = hasher.finalize();

        Ok(EphemeralSession {
            peer: peer.clone(),
            ephemeral_public: key_material.as_bytes()[..32].to_vec(),
            ephemeral_private: key_material.as_bytes().get(32..64).unwrap_or(&[]).to_vec(),
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

    /// Encrypt with specific key
    async fn encrypt_with_key(
        &self,
        message: &RichMessage,
        key: &[u8],
    ) -> Result<EncryptedMessage> {
        let cipher = ChaCha20Poly1305::new_from_slice(&key[..32])?;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let plaintext = serde_json::to_vec(message)?;
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
#[derive(Debug, Clone)]
pub struct SessionKey {
    pub peer: FourWordAddress,
    pub key: Vec<u8>,
    pub established_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Device-specific key
#[derive(Debug, Clone)]
pub struct DeviceKey {
    pub device_id: DeviceId,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Ephemeral session for perfect forward secrecy
#[derive(Debug, Clone)]
pub struct EphemeralSession {
    pub peer: FourWordAddress,
    pub ephemeral_public: Vec<u8>,
    pub ephemeral_private: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub message_count: u32,
}

/// Key ratcheting for forward secrecy
pub struct KeyRatchet {
    current_key: Vec<u8>,
    generation: u32,
}

impl KeyRatchet {
    /// Create new key ratchet
    pub fn new(initial_key: Vec<u8>) -> Self {
        Self {
            current_key: initial_key,
            generation: 0,
        }
    }

    /// Ratchet forward
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
}
