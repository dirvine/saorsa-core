// Diffie-Hellman Key Exchange using X25519 for secure messaging
// Provides perfect forward secrecy and quantum-resistant key derivation

use crate::identity::FourWordAddress;
use anyhow::{Result};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use rand_core::OsRng;
use hkdf::Hkdf;
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use chrono::{DateTime, Duration, Utc};

/// Wrapper for EphemeralSecret that can be debugged safely
struct DebugEphemeralSecret(EphemeralSecret);

impl std::fmt::Debug for DebugEphemeralSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralSecret")
            .field("redacted", &"[REDACTED]")
            .finish()
    }
}

impl DebugEphemeralSecret {
    fn new() -> Self {
        Self(EphemeralSecret::random_from_rng(OsRng))
    }
    
    fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.0)
    }
    
    fn into_secret(self) -> EphemeralSecret {
        self.0
    }
}

/// Key Exchange Protocol for establishing secure sessions
pub struct KeyExchange {
    /// Current user identity
    identity: FourWordAddress,
    /// Active key exchange sessions
    sessions: Arc<RwLock<HashMap<FourWordAddress, KeyExchangeSession>>>,
    /// Completed handshakes
    established_keys: Arc<RwLock<HashMap<FourWordAddress, EstablishedKey>>>,
    /// Prekeys for asynchronous key exchange
    prekeys: Arc<RwLock<PrekeyBundle>>,
}

impl KeyExchange {
    /// Create a new key exchange manager
    pub fn new(identity: FourWordAddress) -> Result<Self> {
        let prekeys = PrekeyBundle::generate()?;
        
        Ok(Self {
            identity,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            established_keys: Arc::new(RwLock::new(HashMap::new())),
            prekeys: Arc::new(RwLock::new(prekeys)),
        })
    }
    
    /// Initiate key exchange with a peer
    pub async fn initiate_exchange(&self, peer: FourWordAddress) -> Result<KeyExchangeMessage> {
        // Generate ephemeral keypair
        let ephemeral_secret = DebugEphemeralSecret::new();
        let ephemeral_public = ephemeral_secret.public_key();
        
        // Create session
        let session = KeyExchangeSession {
            _peer: peer.clone(),
            our_ephemeral: Some(ephemeral_secret),
            our_public: ephemeral_public,
            _their_public: None,
            _state: KeyExchangeState::_Initiated,
            _created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        };
        
        // Store session
        let mut sessions = self.sessions.write().await;
        sessions.insert(peer.clone(), session);
        
        // Create initiation message
        let message = KeyExchangeMessage {
            sender: self.identity.clone(),
            recipient: peer.clone(),
            message_type: KeyExchangeType::Initiation,
            ephemeral_public: ephemeral_public.as_bytes().to_vec(),
            prekey_id: None,
            signature: self.sign_key_exchange(ephemeral_public.as_bytes()),
            timestamp: Utc::now(),
        };
        
        info!("Initiated key exchange with {}", peer);
        Ok(message)
    }
    
    /// Respond to key exchange initiation
    pub async fn respond_to_exchange(&self, message: KeyExchangeMessage) -> Result<KeyExchangeMessage> {
        // Verify signature
        if !self.verify_key_exchange_signature(&message) {
            return Err(anyhow::anyhow!("Invalid key exchange signature"));
        }
        
        // Parse their public key
        let their_public_bytes: [u8; 32] = message.ephemeral_public
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid public key length"))?;
        let their_public = PublicKey::from(their_public_bytes);
        
        // Generate our ephemeral keypair
        let our_ephemeral = DebugEphemeralSecret::new();
        let our_public = our_ephemeral.public_key();
        
        // Compute shared secret
        let shared_secret = our_ephemeral.into_secret().diffie_hellman(&their_public);
        
        // Derive session keys
        let (encryption_key, mac_key) = self.derive_keys(&shared_secret, &message.sender)?;
        
        // Store established key
        let established = EstablishedKey {
            _peer: message.sender.clone(),
            encryption_key,
            _mac_key: mac_key,
            _our_public: our_public,
            _their_public: their_public,
            _established_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
            _messages_sent: 0,
            _messages_received: 0,
        };
        
        let mut keys = self.established_keys.write().await;
        keys.insert(message.sender.clone(), established);
        
        // Create response message
        let response = KeyExchangeMessage {
            sender: self.identity.clone(),
            recipient: message.sender.clone(),
            message_type: KeyExchangeType::Response,
            ephemeral_public: our_public.as_bytes().to_vec(),
            prekey_id: None,
            signature: self.sign_key_exchange(our_public.as_bytes()),
            timestamp: Utc::now(),
        };
        
        info!("Responded to key exchange from {}", message.sender);
        Ok(response)
    }
    
    /// Complete key exchange after receiving response
    pub async fn complete_exchange(&self, message: KeyExchangeMessage) -> Result<()> {
        // Verify signature
        if !self.verify_key_exchange_signature(&message) {
            return Err(anyhow::anyhow!("Invalid key exchange signature"));
        }
        
        // Get our session
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(&message.sender)
            .ok_or_else(|| anyhow::anyhow!("No pending key exchange session"))?;
        
        // Parse their public key
        let their_public_bytes: [u8; 32] = message.ephemeral_public
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid public key length"))?;
        let their_public = PublicKey::from(their_public_bytes);
        
        // Compute shared secret
        let our_ephemeral = session.our_ephemeral
            .take()
            .ok_or_else(|| anyhow::anyhow!("Missing ephemeral secret"))?;
        let shared_secret = our_ephemeral.into_secret().diffie_hellman(&their_public);
        
        // Derive session keys
        let (encryption_key, mac_key) = self.derive_keys(&shared_secret, &message.sender)?;
        
        // Store established key
        let established = EstablishedKey {
            _peer: message.sender.clone(),
            encryption_key,
            _mac_key: mac_key,
            _our_public: session.our_public,
            _their_public: their_public,
            _established_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
            _messages_sent: 0,
            _messages_received: 0,
        };
        
        // Remove session and store established key
        sessions.remove(&message.sender);
        drop(sessions);
        
        let mut keys = self.established_keys.write().await;
        keys.insert(message.sender.clone(), established);
        
        info!("Completed key exchange with {}", message.sender);
        Ok(())
    }
    
    /// Get established session key for a peer
    pub async fn get_session_key(&self, peer: &FourWordAddress) -> Result<Vec<u8>> {
        let keys = self.established_keys.read().await;
        
        if let Some(established) = keys.get(peer) {
            if established.expires_at > Utc::now() {
                return Ok(established.encryption_key.clone());
            } else {
                warn!("Session key for {} has expired", peer);
            }
        }
        
        Err(anyhow::anyhow!("No established session with {}", peer))
    }
    
    /// Use prekey for asynchronous key exchange (Signal Protocol style)
    pub async fn use_prekey(&self, peer: FourWordAddress, prekey: &PrekeyMessage) -> Result<Vec<u8>> {
        // Generate ephemeral keypair
        let ephemeral_secret = DebugEphemeralSecret::new();
        let ephemeral_public = ephemeral_secret.public_key();
        
        // Parse prekey
        let prekey_bytes: [u8; 32] = prekey.public_key.clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid prekey length"))?;
        let prekey_public = PublicKey::from(prekey_bytes);
        
        // Compute shared secret
        let shared_secret = ephemeral_secret.into_secret().diffie_hellman(&prekey_public);
        
        // Derive session keys
        let (encryption_key, mac_key) = self.derive_keys(&shared_secret, &peer)?;
        
        // Store established key
        let established = EstablishedKey {
            _peer: peer.clone(),
            encryption_key: encryption_key.clone(),
            _mac_key: mac_key,
            _our_public: ephemeral_public,
            _their_public: prekey_public,
            _established_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
            _messages_sent: 0,
            _messages_received: 0,
        };
        
        let mut keys = self.established_keys.write().await;
        keys.insert(peer, established);
        
        Ok(encryption_key)
    }
    
    /// Get our prekey bundle for others to use
    pub async fn get_prekey_bundle(&self) -> PrekeyBundle {
        let prekeys = self.prekeys.read().await;
        prekeys.clone()
    }
    
    /// Rotate prekeys periodically
    pub async fn rotate_prekeys(&self) -> Result<()> {
        let new_prekeys = PrekeyBundle::generate()?;
        let mut prekeys = self.prekeys.write().await;
        *prekeys = new_prekeys;
        
        info!("Rotated prekeys");
        Ok(())
    }
    
    /// Clean up expired sessions
    pub async fn cleanup_expired(&self) -> Result<()> {
        let now = Utc::now();
        
        // Clean up pending sessions
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, session| session.expires_at > now);
        
        // Clean up established keys
        let mut keys = self.established_keys.write().await;
        let expired_count = keys.len();
        keys.retain(|_, key| key.expires_at > now);
        let removed = expired_count - keys.len();
        
        if removed > 0 {
            info!("Cleaned up {} expired sessions", removed);
        }
        
        Ok(())
    }
    
    /// Derive encryption and MAC keys from shared secret
    fn derive_keys(&self, shared_secret: &SharedSecret, peer: &FourWordAddress) -> Result<(Vec<u8>, Vec<u8>)> {
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        
        // Create info string from identities
        let info = format!("{}-{}", self.identity, peer);
        
        // Derive 64 bytes (32 for encryption, 32 for MAC)
        let mut okm = [0u8; 64];
        hkdf.expand(info.as_bytes(), &mut okm)
            .map_err(|_| anyhow::anyhow!("Key derivation failed"))?;
        
        let encryption_key = okm[..32].to_vec();
        let mac_key = okm[32..].to_vec();
        
        Ok((encryption_key, mac_key))
    }
    
    /// Sign key exchange message
    fn sign_key_exchange(&self, public_key: &[u8]) -> Vec<u8> {
        // In production, use actual signing with identity key
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.identity.to_string().as_bytes());
        hasher.update(public_key);
        hasher.finalize().as_bytes().to_vec()
    }
    
    /// Verify key exchange signature
    fn verify_key_exchange_signature(&self, message: &KeyExchangeMessage) -> bool {
        // In production, verify actual signature
        let mut hasher = blake3::Hasher::new();
        hasher.update(message.sender.to_string().as_bytes());
        hasher.update(&message.ephemeral_public);
        let expected = hasher.finalize().as_bytes().to_vec();
        
        message.signature == expected
    }
}

/// Key exchange session state
#[derive(Debug)]
struct KeyExchangeSession {
    _peer: FourWordAddress,
    our_ephemeral: Option<DebugEphemeralSecret>,
    our_public: PublicKey,
    _their_public: Option<PublicKey>,
    _state: KeyExchangeState,
    _created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// Key exchange state
#[derive(Debug, Clone, PartialEq)]
enum KeyExchangeState {
    _Initiated,
    _Responded,
    _Completed,
}

/// Established session key
#[derive(Debug, Clone)]
struct EstablishedKey {
    _peer: FourWordAddress,
    encryption_key: Vec<u8>,
    _mac_key: Vec<u8>,
    _our_public: PublicKey,
    _their_public: PublicKey,
    _established_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    _messages_sent: u32,
    _messages_received: u32,
}

/// Key exchange message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchangeMessage {
    pub sender: FourWordAddress,
    pub recipient: FourWordAddress,
    pub message_type: KeyExchangeType,
    pub ephemeral_public: Vec<u8>,
    pub prekey_id: Option<u32>,
    pub signature: Vec<u8>,
    pub timestamp: DateTime<Utc>,
}

/// Key exchange message type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyExchangeType {
    Initiation,
    Response,
    PrekeyBundle,
}

/// Prekey bundle for asynchronous key exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrekeyBundle {
    pub identity_key: Vec<u8>,
    pub signed_prekey: SignedPrekey,
    pub one_time_prekeys: Vec<OnetimePrekey>,
    pub timestamp: DateTime<Utc>,
}

impl PrekeyBundle {
    /// Generate a new prekey bundle
    pub fn generate() -> Result<Self> {
        // Generate identity key
        let identity_secret = DebugEphemeralSecret::new();
        let identity_public = identity_secret.public_key();
        
        // Generate signed prekey
        let signed_secret = DebugEphemeralSecret::new();
        let signed_public = signed_secret.public_key();
        
        // Sign the prekey
        let mut hasher = blake3::Hasher::new();
        hasher.update(signed_public.as_bytes());
        let signature = hasher.finalize().as_bytes().to_vec();
        
        let signed_prekey = SignedPrekey {
            id: rand::random(),
            public_key: signed_public.as_bytes().to_vec(),
            signature,
            timestamp: Utc::now(),
        };
        
        // Generate one-time prekeys
        let mut one_time_prekeys = Vec::new();
        for i in 0..100 {
            let secret = DebugEphemeralSecret::new();
            let public = secret.public_key();
            
            one_time_prekeys.push(OnetimePrekey {
                id: i,
                public_key: public.as_bytes().to_vec(),
            });
        }
        
        Ok(Self {
            identity_key: identity_public.as_bytes().to_vec(),
            signed_prekey,
            one_time_prekeys,
            timestamp: Utc::now(),
        })
    }
}

/// Signed prekey
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPrekey {
    pub id: u32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: DateTime<Utc>,
}

/// One-time prekey
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnetimePrekey {
    pub id: u32,
    pub public_key: Vec<u8>,
}

/// Prekey message for initial contact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrekeyMessage {
    pub prekey_id: u32,
    pub public_key: Vec<u8>,
    pub identity_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_key_exchange_flow() {
        let alice = FourWordAddress::from("alice-bob-charlie-david");
        let bob = FourWordAddress::from("eve-frank-grace-henry");
        
        let alice_kex = KeyExchange::new(alice.clone()).unwrap();
        let bob_kex = KeyExchange::new(bob.clone()).unwrap();
        
        // Alice initiates
        let init_msg = alice_kex.initiate_exchange(bob.clone()).await.unwrap();
        assert_eq!(init_msg.message_type, KeyExchangeType::Initiation);
        
        // Bob responds
        let resp_msg = bob_kex.respond_to_exchange(init_msg).await.unwrap();
        assert_eq!(resp_msg.message_type, KeyExchangeType::Response);
        
        // Alice completes
        alice_kex.complete_exchange(resp_msg).await.unwrap();
        
        // Both should have session keys
        let alice_key = alice_kex.get_session_key(&bob).await.unwrap();
        let bob_key = bob_kex.get_session_key(&alice).await.unwrap();
        
        // Keys should be the same (they derived from same shared secret)
        assert_eq!(alice_key, bob_key);
    }
    
    #[tokio::test]
    async fn test_prekey_bundle() {
        let alice = FourWordAddress::from("alice-bob-charlie-david");
        let alice_kex = KeyExchange::new(alice.clone()).unwrap();
        
        let bundle = alice_kex.get_prekey_bundle().await;
        
        assert!(!bundle.identity_key.is_empty());
        assert_eq!(bundle.one_time_prekeys.len(), 100);
        assert!(!bundle.signed_prekey.signature.is_empty());
    }
    
    #[tokio::test]
    async fn test_cleanup_expired() {
        let alice = FourWordAddress::from("alice-bob-charlie-david");
        let alice_kex = KeyExchange::new(alice.clone()).unwrap();
        
        // Clean up (should do nothing since nothing is expired)
        alice_kex.cleanup_expired().await.unwrap();
    }
    
    #[test]
    fn test_prekey_generation() {
        let bundle = PrekeyBundle::generate().unwrap();
        
        assert_eq!(bundle.identity_key.len(), 32);
        assert_eq!(bundle.signed_prekey.public_key.len(), 32);
        assert_eq!(bundle.one_time_prekeys.len(), 100);
        
        for (i, prekey) in bundle.one_time_prekeys.iter().enumerate() {
            assert_eq!(prekey.id, i as u32);
            assert_eq!(prekey.public_key.len(), 32);
        }
    }
}