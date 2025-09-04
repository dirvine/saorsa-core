use crate::identity::FourWordAddress;
use crate::messaging::DhtClient;
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::quantum_crypto::ant_quic_integration::{
    MlKemCiphertext, MlKemPublicKey, MlKemSecretKey,
};

const DHT_KEM_PREFIX: &str = "pqc:kem:";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyExchangeType {
    Initiation,
    Response,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchangeMessage {
    pub sender: FourWordAddress,
    pub recipient: FourWordAddress,
    pub message_type: KeyExchangeType,
    pub payload: Vec<u8>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct EstablishedKey {
    _peer: FourWordAddress,
    encryption_key: Vec<u8>,
    _established_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    _messages_sent: u64,
    _messages_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KemInitiationPayload {
    ciphertext: Vec<u8>,
}

/// PQC-only Key Exchange using ML-KEM with DHT-published public keys
pub struct KeyExchange {
    identity: FourWordAddress,
    dht: DhtClient,
    kem_public: MlKemPublicKey,
    kem_secret: MlKemSecretKey,
    established_keys: Arc<RwLock<HashMap<FourWordAddress, EstablishedKey>>>,
}

impl KeyExchange {
    pub async fn new(identity: FourWordAddress, dht: DhtClient) -> Result<Self> {
        let (kem_public, kem_secret) =
            crate::quantum_crypto::ant_quic_integration::generate_ml_kem_keypair()?;
        // Publish KEM pubkey
        let dht_key = format!("{}{}", DHT_KEM_PREFIX, identity);
        dht.put(dht_key, kem_public.as_bytes().to_vec()).await?;
        Ok(Self {
            identity,
            dht,
            kem_public,
            kem_secret,
            established_keys: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Get the public KEM key for this node
    pub fn kem_public_key(&self) -> &MlKemPublicKey {
        &self.kem_public
    }
    async fn fetch_peer_kem_public(&self, peer: &FourWordAddress) -> Result<MlKemPublicKey> {
        let key = format!("{}{}", DHT_KEM_PREFIX, peer);
        let bytes = self
            .dht
            .get(key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("No KEM public key for {}", peer))?;
        MlKemPublicKey::from_bytes(&bytes)
            .map_err(|e| anyhow::anyhow!("Invalid KEM public key for {}: {:?}", peer, e))
    }

    fn derive_session_key(shared_secret: &[u8]) -> Result<Vec<u8>> {
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
        let mut okm = [0u8; 32];
        hkdf.expand(b"saorsa-messaging-session", &mut okm)
            .map_err(|e| anyhow::anyhow!("HKDF expand failed: {:?}", e))?;
        Ok(okm.to_vec())
    }

    pub async fn initiate_exchange(&self, peer: FourWordAddress) -> Result<KeyExchangeMessage> {
        let peer_pub = self.fetch_peer_kem_public(&peer).await?;
        let (ciphertext, shared) =
            crate::quantum_crypto::ant_quic_integration::ml_kem_encapsulate(&peer_pub)?;
        let session_key = Self::derive_session_key(shared.as_bytes())?;
        self.store_session(peer.clone(), session_key).await;
        let payload = KemInitiationPayload {
            ciphertext: ciphertext.as_bytes().to_vec(),
        };
        let payload_bytes = bincode::serialize(&payload)?;
        Ok(KeyExchangeMessage {
            sender: self.identity.clone(),
            recipient: peer,
            message_type: KeyExchangeType::Initiation,
            payload: payload_bytes,
            timestamp: Utc::now(),
        })
    }

    pub async fn respond_to_exchange(&self, msg: KeyExchangeMessage) -> Result<KeyExchangeMessage> {
        if msg.message_type != KeyExchangeType::Initiation {
            return Err(anyhow::anyhow!("Unexpected message type"));
        }
        let payload: KemInitiationPayload = bincode::deserialize(&msg.payload)?;
        let kem_ct = MlKemCiphertext::from_bytes(&payload.ciphertext)
            .map_err(|e| anyhow::anyhow!("Invalid KEM ciphertext: {:?}", e))?;
        let shared = crate::quantum_crypto::ant_quic_integration::ml_kem_decapsulate(
            &self.kem_secret,
            &kem_ct,
        )?;
        let session_key = Self::derive_session_key(shared.as_bytes())?;
        self.store_session(msg.sender.clone(), session_key).await;
        Ok(KeyExchangeMessage {
            sender: self.identity.clone(),
            recipient: msg.sender,
            message_type: KeyExchangeType::Response,
            payload: Vec::new(),
            timestamp: Utc::now(),
        })
    }

    pub async fn complete_exchange(&self, _message: KeyExchangeMessage) -> Result<()> {
        Ok(())
    }

    async fn store_session(&self, peer: FourWordAddress, key: Vec<u8>) {
        let mut map = self.established_keys.write().await;
        map.insert(
            peer.clone(),
            EstablishedKey {
                _peer: peer,
                encryption_key: key,
                _established_at: Utc::now(),
                expires_at: Utc::now() + Duration::hours(24),
                _messages_sent: 0,
                _messages_received: 0,
            },
        );
    }

    pub async fn get_session_key(&self, peer: &FourWordAddress) -> Result<Vec<u8>> {
        let keys = self.established_keys.read().await;
        if let Some(established) = keys.get(peer)
            && established.expires_at > Utc::now()
        {
            return Ok(established.encryption_key.clone());
        }
        Err(anyhow::anyhow!("No established PQC session with {}", peer))
    }
}
