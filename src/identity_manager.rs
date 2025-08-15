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

//! # Identity Management System
//!
//! This module provides comprehensive identity management for the P2P network,
//! including Ed25519/X25519 key pair generation, lifecycle management, and
//! secure multi-device synchronization.
//!
//! ## Security Features
//! - Dual key system: Ed25519 for signing, X25519 for key exchange
//! - Hierarchical key derivation for deterministic generation
//! - Secure key storage with encryption at rest
//! - Key rotation and revocation support
//! - Replay attack prevention with monotonic counters
//!
//! ## Performance Features
//! - Efficient batch operations for multiple identities
//! - Caching for frequently accessed identities
//! - Lazy verification for improved performance
//! - Background key rotation and sync

#![allow(missing_docs)]

use crate::crypto_verify::EnhancedSignatureVerifier;
use crate::encrypted_key_storage::{EncryptedKeyStorageManager, SecurityLevel};
use crate::error::{IdentityError, SecurityError, StorageError};
use crate::key_derivation::{DerivationPath, DerivedKey, HierarchicalKeyDerivation};
use crate::monotonic_counter::MonotonicCounterSystem;
use crate::peer_record::{PeerDHTRecord, PeerEndpoint, UserId};
use crate::secure_memory::SecureString;
use crate::{P2PError, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use bincode;
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, generic_array::GenericArray},
};
use ed25519_dalek::{
    Signature, Signer, SigningKey as Ed25519SigningKey, Verifier,
    VerifyingKey as Ed25519VerifyingKey,
};
use hkdf;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock as AsyncRwLock;
use tracing;

/// Identity version for forward compatibility
const IDENTITY_VERSION: u8 = 1;

/// Default key lifetime (90 days)
const DEFAULT_KEY_LIFETIME: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// Key rotation warning period (7 days before expiration)
const KEY_ROTATION_WARNING: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Maximum identity metadata size (prevents abuse)
const MAX_METADATA_SIZE: usize = 10240; // 10KB

/// Identity states in the lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityState {
    /// Identity is being created
    Creating,
    /// Identity is active and can be used
    Active,
    /// Identity is being rotated (new keys being generated)
    Rotating,
    /// Identity has been revoked
    Revoked,
    /// Identity has expired
    Expired,
}

/// Identity key pair containing both Ed25519 and X25519 keys
#[derive(Debug)]
pub struct IdentityKeyPair {
    /// Ed25519 key pair for signatures
    pub ed25519_secret: Ed25519SigningKey,
    pub ed25519_public: Ed25519VerifyingKey,
    /// X25519 key pair for key exchange (stored as raw bytes)
    pub x25519_secret: [u8; 32],
    pub x25519_public: [u8; 32],
    /// Creation timestamp
    pub created_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Key version for rotation tracking
    pub version: u32,
}

impl Clone for IdentityKeyPair {
    fn clone(&self) -> Self {
        // SigningKey doesn't implement Clone, so we need to recreate it from bytes
        let secret_bytes = self.ed25519_secret.to_bytes();
        let ed25519_secret = Ed25519SigningKey::from_bytes(&secret_bytes);

        Self {
            ed25519_secret,
            ed25519_public: self.ed25519_public,
            x25519_secret: self.x25519_secret,
            x25519_public: self.x25519_public,
            created_at: self.created_at,
            expires_at: self.expires_at,
            version: self.version,
        }
    }
}

/// Complete identity including keys and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Unique identity ID (derived from public key)
    pub id: UserId,
    /// Four-word human-readable address
    pub four_word_address: String,
    /// Current state in lifecycle
    pub state: IdentityState,
    /// Display name (optional)
    pub display_name: Option<String>,
    /// Avatar URL (optional)
    pub avatar_url: Option<String>,
    /// Bio/description (optional)
    pub bio: Option<String>,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
    /// Current key version
    pub key_version: u32,
    /// Creation timestamp
    pub created_at: u64,
    /// Last update timestamp
    pub updated_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Previous key hashes for rotation tracking
    pub previous_keys: Vec<[u8; 32]>,
    /// Revocation certificate (if revoked)
    pub revocation_cert: Option<RevocationCertificate>,
}

/// Certificate for identity revocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationCertificate {
    /// Identity being revoked
    pub identity_id: UserId,
    /// Reason for revocation
    pub reason: RevocationReason,
    /// Revocation timestamp
    pub revoked_at: u64,
    /// Signature by the identity's key
    pub signature: Vec<u8>,
    /// Optional replacement identity
    pub replacement_id: Option<UserId>,
}

/// Reasons for identity revocation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// Key was compromised
    KeyCompromise,
    /// User requested revocation
    UserRequested,
    /// Identity superseded by new one
    Superseded,
    /// Other/unspecified reason
    Other,
}

/// Identity creation parameters
#[derive(Debug, Clone, Default)]
pub struct IdentityCreationParams {
    /// Display name
    pub display_name: Option<String>,
    /// Avatar URL
    pub avatar_url: Option<String>,
    /// Bio/description
    pub bio: Option<String>,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
    /// Custom key lifetime (defaults to 90 days)
    pub key_lifetime: Option<Duration>,
    /// Derivation path for deterministic generation
    pub derivation_path: Option<String>,
}

/// Identity verification result
#[derive(Debug, Clone)]
pub struct IdentityVerification {
    /// Whether the identity is valid
    pub valid: bool,
    /// Verification timestamp
    pub verified_at: u64,
    /// Issues found during verification
    pub issues: Vec<String>,
    /// Trust level (0-100)
    pub trust_level: u8,
}

/// Identity update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityUpdate {
    /// Updated display name
    pub display_name: Option<String>,
    /// Updated avatar URL
    pub avatar_url: Option<String>,
    /// Updated bio
    pub bio: Option<String>,
    /// Updated metadata
    pub metadata: Option<HashMap<String, String>>,
    /// Update timestamp
    pub timestamp: u64,
    /// Update sequence number
    pub sequence: u64,
    /// Signature of the update
    pub signature: Vec<u8>,
}

/// Identity manager for lifecycle management
pub struct IdentityManager {
    /// Storage path for identities
    storage_path: PathBuf,
    /// Encrypted key storage
    key_storage: Arc<EncryptedKeyStorageManager>,
    /// Key derivation system
    key_derivation: Arc<AsyncRwLock<HierarchicalKeyDerivation>>,
    /// Signature verifier
    verifier: Arc<EnhancedSignatureVerifier>,
    /// Monotonic counter system
    counter_system: Arc<MonotonicCounterSystem>,
    /// Active identities cache
    identities: Arc<RwLock<HashMap<UserId, Identity>>>,
    /// Key pairs (not persisted, regenerated from storage)
    key_pairs: Arc<RwLock<HashMap<UserId, IdentityKeyPair>>>,
    /// Background tasks for key rotation
    background_tasks: Arc<AsyncRwLock<HashMap<UserId, tokio::task::JoinHandle<Result<()>>>>>,
    /// Performance statistics
    stats: Arc<RwLock<IdentityStats>>,
}

/// Statistics for identity operations
#[derive(Debug, Clone, Default)]
pub struct IdentityStats {
    /// Total identities created
    pub identities_created: u64,
    /// Total identities revoked
    pub identities_revoked: u64,
    /// Total key rotations
    pub key_rotations: u64,
    /// Total verifications performed
    pub verifications_performed: u64,
    /// Average verification time in microseconds
    pub avg_verification_time_us: u64,
    /// Current active identities
    pub active_identities: u64,
}

/// Multi-device sync package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentitySyncPackage {
    /// Encrypted identity data
    pub encrypted_identity: Vec<u8>,
    /// Encrypted key material
    pub encrypted_keys: Vec<u8>,
    /// Sync timestamp
    pub timestamp: u64,
    /// Device fingerprint that created this package
    pub device_fingerprint: [u8; 32],
    /// Package signature
    pub signature: Vec<u8>,
}

/// Profile access permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProfilePermissions {
    /// Read-only access
    ReadOnly,
    /// Read and write access
    ReadWrite,
    /// Full administrative access
    Admin,
}

/// Access grant record
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessGrant {
    /// Identity granting access
    grantor_id: UserId,
    /// Identity receiving access
    grantee_id: UserId,
    /// Permissions granted
    permissions: ProfilePermissions,
    /// When access was granted
    granted_at: u64,
    /// When access expires (None = never)
    expires_at: Option<u64>,
}

/// Access information
#[derive(Debug, Clone)]
pub struct AccessInfo {
    /// Permissions granted
    pub permissions: ProfilePermissions,
    /// When access was granted
    pub granted_at: u64,
    /// When access expires (None = never)
    pub expires_at: Option<u64>,
}

impl IdentityKeyPair {
    /// Create from derived key
    pub fn from_derived_key(key: &DerivedKey, lifetime: Duration) -> Result<Self> {
        let created_at = current_timestamp();
        let expires_at = created_at + lifetime.as_secs();

        Ok(Self {
            ed25519_secret: Ed25519SigningKey::from_bytes(&key.secret_key.to_bytes()),
            ed25519_public: key.public_key,
            x25519_secret: key.x25519_secret,
            x25519_public: key.x25519_public,
            created_at,
            expires_at,
            version: 1,
        })
    }

    /// Check if the key pair is expired
    pub fn is_expired(&self) -> bool {
        current_timestamp() >= self.expires_at
    }

    /// Check if the key pair needs rotation
    pub fn needs_rotation(&self) -> bool {
        let now = current_timestamp();
        let rotation_time = self
            .expires_at
            .saturating_sub(KEY_ROTATION_WARNING.as_secs());
        now >= rotation_time
    }

    /// Sign data with Ed25519 key
    pub fn sign(&self, data: &[u8]) -> Result<Signature> {
        Ok(self.ed25519_secret.sign(data))
    }

    /// Verify signature with Ed25519 public key
    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<()> {
        self.ed25519_public.verify(data, signature).map_err(|_| {
            P2PError::Security(SecurityError::SignatureVerificationFailed(
                "Signature verification failed".into(),
            ))
        })
    }
}

impl Identity {
    /// Create identity from key pair
    pub fn from_key_pair(
        key_pair: &IdentityKeyPair,
        four_word_address: String,
        params: IdentityCreationParams,
    ) -> Result<Self> {
        // Derive user ID from public key
        let id = UserId::from_public_key(&key_pair.ed25519_public);

        // Validate metadata size
        let metadata_size: usize = params.metadata.values().map(|v| v.len()).sum();

        if metadata_size > MAX_METADATA_SIZE {
            return Err(P2PError::Config(crate::error::ConfigError::InvalidValue {
                field: "metadata_size".into(),

                reason: format!("Metadata size exceeds maximum {MAX_METADATA_SIZE}").into(),
            }));
        }

        let now = current_timestamp();

        Ok(Self {
            id,
            four_word_address,
            state: IdentityState::Active,
            display_name: params.display_name,
            avatar_url: params.avatar_url,
            bio: params.bio,
            metadata: params.metadata,
            key_version: key_pair.version,
            created_at: key_pair.created_at,
            updated_at: now,
            expires_at: key_pair.expires_at,
            previous_keys: Vec::new(),
            revocation_cert: None,
        })
    }

    /// Check if identity is valid
    pub fn is_valid(&self) -> bool {
        match self.state {
            IdentityState::Active => !self.is_expired(),
            _ => false,
        }
    }

    /// Check if identity is expired
    pub fn is_expired(&self) -> bool {
        current_timestamp() >= self.expires_at
    }

    /// Create a DHT record for this identity
    pub fn to_dht_record(&self, endpoints: Vec<PeerEndpoint>) -> Result<PeerDHTRecord> {
        let public_key =
            ed25519_dalek::VerifyingKey::from_bytes(self.id.as_bytes()).map_err(|e| {
                P2PError::Identity(IdentityError::InvalidFormat(
                    format!("invalid public key: {}", e).into(),
                ))
            })?;

        Ok(PeerDHTRecord {
            version: IDENTITY_VERSION,
            user_id: self.id.clone(),
            public_key,
            sequence_number: self.updated_at,
            name: self.display_name.clone(),
            endpoints,
            timestamp: self.updated_at,
            ttl: (self.expires_at - current_timestamp()) as u32,
            signature: ed25519_dalek::Signature::from_bytes(&[0u8; 64]), // Will be set by signing
        })
    }

    /// Apply an update to the identity
    pub fn apply_update(&mut self, update: &IdentityUpdate) -> Result<()> {
        if update.timestamp <= self.updated_at {
            return Err(P2PError::Identity(
                crate::error::IdentityError::InvalidFormat("Update timestamp is not newer".into()),
            ));
        }

        if let Some(name) = &update.display_name {
            self.display_name = Some(name.clone());
        }

        if let Some(avatar) = &update.avatar_url {
            self.avatar_url = Some(avatar.clone());
        }

        if let Some(bio) = &update.bio {
            self.bio = Some(bio.clone());
        }

        if let Some(metadata) = &update.metadata {
            self.metadata = metadata.clone();
        }

        self.updated_at = update.timestamp;

        Ok(())
    }
}

impl IdentityManager {
    /// Create a new identity manager
    pub async fn new<P: AsRef<Path>>(
        storage_path: P,
        security_level: SecurityLevel,
    ) -> Result<Self> {
        let storage_path = storage_path.as_ref().to_path_buf();

        // Create storage directory
        tokio::fs::create_dir_all(&storage_path)
            .await
            .map_err(|e| {
                P2PError::Storage(StorageError::Database(
                    format!("Failed to create identity storage: {e}").into(),
                ))
            })?;

        // Initialize components
        let key_storage = Arc::new(EncryptedKeyStorageManager::new(
            storage_path.join("keys.enc"),
            security_level,
        )?);

        let verifier = Arc::new(EnhancedSignatureVerifier::new());

        let counter_system = MonotonicCounterSystem::new_with_sync_interval(
            storage_path.join("counters"),
            Duration::from_secs(60),
        )
        .await?;

        Ok(Self {
            storage_path,
            key_storage,
            key_derivation: Arc::new(AsyncRwLock::new(HierarchicalKeyDerivation::new(
                crate::key_derivation::MasterSeed::generate()?,
            ))),
            verifier,
            counter_system: Arc::new(counter_system),
            identities: Arc::new(RwLock::new(HashMap::new())),
            key_pairs: Arc::new(RwLock::new(HashMap::new())),
            background_tasks: Arc::new(AsyncRwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(IdentityStats::default())),
        })
    }

    /// Initialize with a password
    pub async fn initialize(&self, password: &SecureString) -> Result<()> {
        self.key_storage.initialize(password).await?;
        Ok(())
    }

    /// Create a new identity
    pub async fn create_identity(
        &self,
        password: &SecureString,
        params: IdentityCreationParams,
    ) -> Result<Identity> {
        // Generate four-word address
        let four_word_address = self.generate_four_word_address().await?;

        // Derive key pair
        let derivation_path = params
            .derivation_path
            .as_deref()
            .unwrap_or("m/44'/0'/0'/0/0");

        let path = DerivationPath::from_string(derivation_path)?;
        let derived_key = {
            let mut key_derivation = self.key_derivation.write().await;
            key_derivation.derive_key(&path)?
        };

        let lifetime = params.key_lifetime.unwrap_or(DEFAULT_KEY_LIFETIME);
        let key_pair = IdentityKeyPair::from_derived_key(&derived_key, lifetime)?;

        // Create identity
        let identity = Identity::from_key_pair(&key_pair, four_word_address, params)?;

        // Store in encrypted storage
        // Note: We need to create a new master seed for this identity
        let identity_seed = crate::key_derivation::MasterSeed::generate()?;

        self.key_storage
            .store_master_seed(&identity.id.to_string(), &identity_seed, password)
            .await?;

        // Cache identity and key pair
        {
            let mut identities = self.identities.write().map_err(|_| {
                P2PError::Identity(IdentityError::SystemTime("write lock failed".into()))
            })?;
            identities.insert(identity.id.clone(), identity.clone());
        }

        {
            let mut key_pairs = self.key_pairs.write().map_err(|_| {
                P2PError::Identity(IdentityError::SystemTime("write lock failed".into()))
            })?;
            key_pairs.insert(identity.id.clone(), key_pair);
        }

        // Update stats
        {
            let mut stats = self.stats.write().map_err(|_| {
                P2PError::Identity(IdentityError::SystemTime("write lock failed".into()))
            })?;
            stats.identities_created += 1;
            stats.active_identities += 1;
        }

        // Schedule key rotation check
        self.schedule_key_rotation_check(identity.id.clone())
            .await?;

        Ok(identity)
    }

    /// Load identity from storage
    pub async fn load_identity(
        &self,
        identity_id: &UserId,
        password: &SecureString,
    ) -> Result<Identity> {
        // Check cache first
        {
            let identities = self.identities.read().map_err(|_| {
                P2PError::Identity(IdentityError::SystemTime("read lock failed".into()))
            })?;
            if let Some(identity) = identities.get(identity_id) {
                return Ok(identity.clone());
            }
        }

        // Try to load encrypted file first (.enc)
        let encrypted_path = self.storage_path.join(format!("{identity_id}.enc"));
        let plaintext_path = self.storage_path.join(format!("{identity_id}.json"));

        let identity: Identity = if encrypted_path.exists() {
            // Load encrypted file
            let encrypted_data = tokio::fs::read(&encrypted_path).await.map_err(|e| {
                P2PError::Storage(StorageError::Database(
                    format!("Failed to read encrypted identity: {e}").into(),
                ))
            })?;

            // Parse encrypted format
            if encrypted_data.len() < 1 + 32 + 12 {
                return Err(P2PError::Security(SecurityError::DecryptionFailed(
                    "Invalid encrypted file format".into(),
                )));
            }

            let version = encrypted_data[0];
            if version != 1 {
                return Err(P2PError::Security(SecurityError::DecryptionFailed(
                    format!("Unsupported encryption version: {version}").into(),
                )));
            }

            let _salt = &encrypted_data[1..33];
            let nonce = &encrypted_data[33..45];
            let ciphertext = &encrypted_data[45..];

            // Derive decryption key
            let decryption_key = self
                .derive_encryption_key_for_identity(identity_id, password)
                .await?;

            // Decrypt
            let plaintext = self.decrypt_data(
                ciphertext,
                &decryption_key,
                nonce.try_into().map_err(|_| {
                    P2PError::Security(SecurityError::DecryptionFailed("Invalid nonce".into()))
                })?,
            )?;

            // Deserialize
            serde_json::from_slice(&plaintext)
                .map_err(|e| P2PError::Serialization(e.to_string().into()))?
        } else if plaintext_path.exists() {
            // Load legacy plaintext file (for migration)
            let identity_data = tokio::fs::read(&plaintext_path).await.map_err(|e| {
                P2PError::Storage(StorageError::Database(
                    format!("Failed to read identity: {e}").into(),
                ))
            })?;

            serde_json::from_slice(&identity_data)
                .map_err(|e| P2PError::Serialization(e.to_string().into()))?
        } else {
            return Err(P2PError::Storage(StorageError::FileNotFound(
                identity_id.to_string().into(),
            )));
        };

        // Load key pair
        let master_seed = self
            .key_storage
            .retrieve_master_seed(&identity_id.to_string(), password)
            .await?;

        let mut key_derivation = HierarchicalKeyDerivation::new(master_seed);
        let path = DerivationPath::from_string("m/44'/0'/0'/0/0")?;
        let derived_key = key_derivation.derive_key(&path)?;

        let key_pair = IdentityKeyPair::from_derived_key(
            &derived_key,
            Duration::from_secs(identity.expires_at - identity.created_at),
        )?;

        // Cache
        {
            let mut identities = self.identities.write().map_err(|_| {
                P2PError::Identity(IdentityError::SystemTime("write lock failed".into()))
            })?;
            identities.insert(identity.id.clone(), identity.clone());
        }

        {
            let mut key_pairs = self.key_pairs.write().map_err(|_| {
                P2PError::Identity(IdentityError::SystemTime("write lock failed".into()))
            })?;
            key_pairs.insert(identity.id.clone(), key_pair);
        }

        Ok(identity)
    }

    /// Verify an identity
    pub async fn verify_identity(&self, identity: &Identity) -> Result<IdentityVerification> {
        let start_time = std::time::Instant::now();
        let mut issues = Vec::new();
        let mut trust_level = 100u8;

        // Check state
        if identity.state != IdentityState::Active {
            issues.push(format!("Identity is not active: {:?}", identity.state));
            trust_level = 0;
        }

        // Check expiration
        if identity.is_expired() {
            issues.push("Identity has expired".to_string());
            trust_level = 0;
        }

        // Verify public key matches ID
        match Ed25519VerifyingKey::from_bytes(identity.id.as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                issues.push(format!("Invalid public key in ID: {e}"));
                trust_level = 0;
            }
        }

        // Check revocation
        if identity.revocation_cert.is_some() {
            issues.push("Identity has been revoked".to_string());
            trust_level = 0;
        }

        // Check metadata size
        let metadata_size: usize = identity.metadata.values().map(|v| v.len()).sum();

        if metadata_size > MAX_METADATA_SIZE {
            issues.push("Metadata exceeds size limit".to_string());
            trust_level = trust_level.saturating_sub(20);
        }

        // Update stats
        {
            let mut stats = self.stats.write().map_err(|_| {
                P2PError::Identity(IdentityError::SystemTime("write lock failed".into()))
            })?;
            stats.verifications_performed += 1;
            let elapsed = start_time.elapsed().as_micros() as u64;
            stats.avg_verification_time_us = (stats.avg_verification_time_us + elapsed) / 2;
        }

        Ok(IdentityVerification {
            valid: issues.is_empty(),
            verified_at: current_timestamp(),
            issues,
            trust_level,
        })
    }

    /// Rotate identity keys
    pub async fn rotate_keys(&self, identity_id: &UserId, password: &SecureString) -> Result<()> {
        // Load current identity
        let mut identity = self.load_identity(identity_id, password).await?;

        if identity.state != IdentityState::Active {
            return Err(P2PError::Identity(
                crate::error::IdentityError::InvalidFormat(
                    "Cannot rotate keys for inactive identity"
                        .to_string()
                        .into(),
                ),
            ));
        }

        // Update state
        identity.state = IdentityState::Rotating;

        // Generate new key pair
        let new_version = identity.key_version + 1;
        let path = DerivationPath::from_string(&format!("m/44'/0'/0'/0/{new_version}"))?;

        let derived_key = {
            let mut key_derivation = self.key_derivation.write().await;
            key_derivation.derive_key(&path)?
        };

        let lifetime = Duration::from_secs(identity.expires_at - identity.created_at);
        let mut new_key_pair = IdentityKeyPair::from_derived_key(&derived_key, lifetime)?;
        new_key_pair.version = new_version;

        // Add old key hash to previous keys
        let old_key_hash = *blake3::hash(identity.id.as_bytes()).as_bytes();
        identity.previous_keys.push(old_key_hash);

        // Update identity
        identity.key_version = new_version;
        identity.updated_at = current_timestamp();
        identity.expires_at = new_key_pair.expires_at;
        identity.state = IdentityState::Active;

        // Save updated identity
        self.save_identity(&identity, password).await?;

        // Update caches
        {
            let mut identities = self.identities.write().map_err(|_| {
                P2PError::Identity(IdentityError::SystemTime("write lock failed".into()))
            })?;
            identities.insert(identity.id.clone(), identity);
        }

        {
            let mut key_pairs = self.key_pairs.write().map_err(|_| {
                P2PError::Identity(IdentityError::SystemTime("write lock failed".into()))
            })?;
            key_pairs.insert(identity_id.clone(), new_key_pair);
        }

        // Update stats
        {
            let mut stats = self.stats.write().map_err(|_| {
                P2PError::Identity(IdentityError::SystemTime("write lock failed".into()))
            })?;
            stats.key_rotations += 1;
        }

        Ok(())
    }

    /// Revoke an identity
    pub async fn revoke_identity(
        &self,
        identity_id: &UserId,
        password: &SecureString,
        reason: RevocationReason,
        replacement_id: Option<UserId>,
    ) -> Result<RevocationCertificate> {
        // Load identity and key pair
        let mut identity = self.load_identity(identity_id, password).await?;
        let key_pair = self.get_key_pair(identity_id)?;

        // Create revocation certificate
        let cert = RevocationCertificate {
            identity_id: identity_id.clone(),
            reason,
            revoked_at: current_timestamp(),
            signature: Vec::new(),
            replacement_id,
        };

        // Sign certificate
        let cert_data = bincode::serialize(&cert).map_err(|e| {
            P2PError::Storage(StorageError::Database(
                format!("Failed to serialize certificate: {e}").into(),
            ))
        })?;
        let signature = key_pair.sign(&cert_data)?;

        let mut signed_cert = cert;
        signed_cert.signature = signature.to_bytes().to_vec();

        // Update identity
        identity.state = IdentityState::Revoked;
        identity.revocation_cert = Some(signed_cert.clone());
        identity.updated_at = current_timestamp();

        // Save updated identity
        self.save_identity(&identity, password).await?;

        // Remove from active caches
        {
            let mut identities = self.identities.write().map_err(|_| {
                P2PError::Identity(IdentityError::SystemTime("write lock failed".into()))
            })?;
            identities.remove(identity_id);
        }

        {
            let mut key_pairs = self.key_pairs.write().map_err(|_| {
                P2PError::Identity(IdentityError::SystemTime("write lock failed".into()))
            })?;
            key_pairs.remove(identity_id);
        }

        // Cancel background tasks
        {
            let mut tasks = self.background_tasks.write().await;
            if let Some(task) = tasks.remove(identity_id) {
                task.abort();
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write().map_err(|_| {
                P2PError::Identity(IdentityError::SystemTime("write lock failed".into()))
            })?;
            stats.identities_revoked += 1;
            stats.active_identities = stats.active_identities.saturating_sub(1);
        }

        Ok(signed_cert)
    }

    /// Get statistics
    pub fn get_stats(&self) -> IdentityStats {
        self.stats.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Derive encryption key from password using Argon2id
    fn derive_encryption_key(&self, password: &SecureString, salt: &[u8]) -> Result<[u8; 32]> {
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(64 * 1024, 3, 4, Some(32)).map_err(|e| {
                P2PError::Security(SecurityError::KeyGenerationFailed(
                    format!("Invalid Argon2 params: {e}").into(),
                ))
            })?,
        );

        let mut key = [0u8; 32];
        // Convert SecureString to UTF-8 bytes for hashing
        let password_str = password.as_str()?;
        argon2
            .hash_password_into(password_str.as_bytes(), salt, &mut key)
            .map_err(|e| {
                P2PError::Security(SecurityError::KeyGenerationFailed(
                    format!("Argon2 failed: {e}").into(),
                ))
            })?;

        Ok(key)
    }

    /// Encrypt data using ChaCha20Poly1305
    fn encrypt_data(&self, data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
        let nonce = GenericArray::from_slice(nonce);

        cipher.encrypt(nonce, data).map_err(|e| {
            P2PError::Security(SecurityError::EncryptionFailed(
                format!("ChaCha20Poly1305 encryption failed: {e}").into(),
            ))
        })
    }

    /// Decrypt data using ChaCha20Poly1305
    fn decrypt_data(&self, encrypted: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
        let nonce = GenericArray::from_slice(nonce);

        cipher.decrypt(nonce, encrypted).map_err(|e| {
            P2PError::Security(SecurityError::DecryptionFailed(
                format!("ChaCha20Poly1305 decryption failed: {e}").into(),
            ))
        })
    }

    /// Derive encryption key for a specific identity
    async fn derive_encryption_key_for_identity(
        &self,
        identity_id: &UserId,
        password: &SecureString,
    ) -> Result<[u8; 32]> {
        // Use a consistent salt derived from identity ID
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"saorsa-identity-encryption-v1");
        hasher.update(identity_id.to_string().as_bytes());
        let salt = hasher.finalize();

        // Get master key from secure key storage
        // First, try to retrieve the existing master seed for identity encryption
        let master_seed = match self
            .key_storage
            .retrieve_master_seed("identity_encryption_master", password)
            .await
        {
            Ok(seed) => seed,
            Err(_) => {
                // If no master seed exists, generate and store one
                let new_seed = crate::key_derivation::MasterSeed::generate()?;
                self.key_storage
                    .store_master_seed("identity_encryption_master", &new_seed, password)
                    .await?;
                new_seed
            }
        };

        // Get the seed material as master key
        let master_key = master_seed.seed_material();

        // Derive identity-specific key using HKDF
        let mut key = [0u8; 32];
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt.as_bytes()), master_key);
        hkdf.expand(b"identity-encryption", &mut key).map_err(|_| {
            P2PError::Security(SecurityError::KeyGenerationFailed(
                "HKDF expansion failed".into(),
            ))
        })?;

        Ok(key)
    }

    /// Create a sync package for multi-device sync
    pub async fn create_sync_package(
        &self,
        identity_id: &UserId,
        password: &SecureString,
        device_password: &SecureString,
    ) -> Result<IdentitySyncPackage> {
        // Load identity
        let identity = self.load_identity(identity_id, password).await?;

        // Serialize identity
        let identity_data = serde_json::to_vec(&identity)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;

        // Get key material
        let master_seed = self
            .key_storage
            .retrieve_master_seed(&identity_id.to_string(), password)
            .await?;

        let key_data = master_seed.seed_material().to_vec();

        // Generate salt and nonce for encryption
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 12];
        rand::RngCore::fill_bytes(&mut thread_rng(), &mut salt);
        rand::RngCore::fill_bytes(&mut thread_rng(), &mut nonce);

        // Derive encryption key from device password
        let encryption_key = self.derive_encryption_key(device_password, &salt)?;

        // Encrypt identity and key data
        let encrypted_identity = self.encrypt_data(&identity_data, &encryption_key, &nonce)?;
        let encrypted_keys = self.encrypt_data(&key_data, &encryption_key, &nonce)?;

        // Create device fingerprint
        let mut device_fingerprint = [0u8; 32];
        rand::RngCore::fill_bytes(&mut thread_rng(), &mut device_fingerprint);

        // Combine salt and nonce with encrypted data for storage
        let mut final_encrypted_identity =
            Vec::with_capacity(salt.len() + nonce.len() + encrypted_identity.len());
        final_encrypted_identity.extend_from_slice(&salt);
        final_encrypted_identity.extend_from_slice(&nonce);
        final_encrypted_identity.extend_from_slice(&encrypted_identity);

        let mut final_encrypted_keys =
            Vec::with_capacity(salt.len() + nonce.len() + encrypted_keys.len());
        final_encrypted_keys.extend_from_slice(&salt);
        final_encrypted_keys.extend_from_slice(&nonce);
        final_encrypted_keys.extend_from_slice(&encrypted_keys);

        // Create package
        let package = IdentitySyncPackage {
            encrypted_identity: final_encrypted_identity,
            encrypted_keys: final_encrypted_keys,
            timestamp: current_timestamp(),
            device_fingerprint,
            signature: Vec::new(),
        };

        // Sign package
        let key_pair = self.get_key_pair(identity_id)?;
        let package_data = bincode::serialize(&package).map_err(|e| {
            P2PError::Storage(StorageError::Database(
                format!("Failed to serialize package: {e}").into(),
            ))
        })?;
        let signature = key_pair.sign(&package_data)?;

        let mut signed_package = package;
        signed_package.signature = signature.to_bytes().to_vec();

        Ok(signed_package)
    }

    /// Import identity from sync package
    pub async fn import_sync_package(
        &self,
        package: &IdentitySyncPackage,
        device_password: &SecureString,
        storage_password: &SecureString,
    ) -> Result<Identity> {
        // Extract salt and nonce from encrypted data
        if package.encrypted_identity.len() < 44 || package.encrypted_keys.len() < 44 {
            return Err(P2PError::Security(SecurityError::DecryptionFailed(
                "Invalid encrypted data length".into(),
            )));
        }

        let salt = &package.encrypted_identity[..32];
        let nonce = &package.encrypted_identity[32..44];
        let encrypted_identity_data = &package.encrypted_identity[44..];
        let encrypted_key_data = &package.encrypted_keys[44..];

        // Derive decryption key from device password
        let decryption_key = self.derive_encryption_key(device_password, salt)?;

        // Decrypt identity and key data
        let identity_data = self.decrypt_data(
            encrypted_identity_data,
            &decryption_key,
            nonce.try_into().map_err(|_| {
                P2PError::Security(SecurityError::DecryptionFailed(
                    "Invalid nonce length".into(),
                ))
            })?,
        )?;
        let key_data = self.decrypt_data(
            encrypted_key_data,
            &decryption_key,
            nonce.try_into().map_err(|_| {
                P2PError::Security(SecurityError::DecryptionFailed(
                    "Invalid nonce length".into(),
                ))
            })?,
        )?;

        // Deserialize identity
        let identity: Identity = serde_json::from_slice(&identity_data)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;

        // Store key material
        let master_seed = crate::key_derivation::MasterSeed::from_entropy(&key_data)?;

        self.key_storage
            .store_master_seed(&identity.id.to_string(), &master_seed, storage_password)
            .await?;

        // Save identity
        self.save_identity(&identity, storage_password).await?;

        // Load into cache
        self.load_identity(&identity.id, storage_password).await
    }

    // Helper methods

    /// Generate a four-word address
    async fn generate_four_word_address(&self) -> Result<String> {
        // TODO: Integrate with four-word-networking crate
        Ok("alpha.bravo.charlie.delta".to_string())
    }

    /// Migrate existing plaintext identities to encrypted format
    pub async fn migrate_existing_identities(&self, password: &SecureString) -> Result<()> {
        use tokio::fs;

        // List all files in storage directory
        let mut entries = fs::read_dir(&self.storage_path).await.map_err(|e| {
            P2PError::Storage(StorageError::Database(
                format!("Failed to read directory: {e}").into(),
            ))
        })?;

        let mut migrated_count = 0;

        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            P2PError::Storage(StorageError::Database(
                format!("Failed to read directory entry: {e}").into(),
            ))
        })? {
            let path = entry.path();

            // Only process .json files (plaintext identities)
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                // Read plaintext data
                let plaintext_data = fs::read(&path).await.map_err(|e| {
                    P2PError::Storage(StorageError::Database(
                        format!("Failed to read file: {e}").into(),
                    ))
                })?;

                // Try to deserialize as Identity
                if let Ok(identity) = serde_json::from_slice::<Identity>(&plaintext_data) {
                    // Save encrypted version
                    self.save_identity(&identity, password).await?;

                    // Remove old plaintext file
                    fs::remove_file(&path).await.map_err(|e| {
                        P2PError::Storage(StorageError::Database(
                            format!("Failed to remove old file: {e}").into(),
                        ))
                    })?;

                    migrated_count += 1;
                    tracing::info!("Migrated identity {} to encrypted format", identity.id);
                }
            }
        }

        if migrated_count > 0 {
            tracing::info!(
                "Successfully migrated {} identities to encrypted format",
                migrated_count
            );
        }

        Ok(())
    }

    /// Get key pair from cache
    fn get_key_pair(&self, identity_id: &UserId) -> Result<IdentityKeyPair> {
        let key_pairs = self.key_pairs.read().map_err(|_| {
            P2PError::Identity(IdentityError::SystemTime("read lock failed".into()))
        })?;
        key_pairs.get(identity_id).cloned().ok_or_else(|| {
            P2PError::Storage(crate::error::StorageError::FileNotFound(
                "key_pair_cache".into(),
            ))
        })
    }

    /// Grant access to another identity
    pub async fn grant_access(
        &self,
        grantor_id: &UserId,
        grantee_id: &UserId,
        permissions: ProfilePermissions,
        password: &SecureString,
    ) -> Result<()> {
        // Load grantor's identity to verify ownership
        let _grantor = self.load_identity(grantor_id, password).await?;

        // Create access grant record
        let grant = AccessGrant {
            grantor_id: grantor_id.clone(),
            grantee_id: grantee_id.clone(),
            permissions,
            granted_at: current_timestamp(),
            expires_at: None, // TODO: Add expiration support
        };

        // Encrypt and store the grant
        let grant_data = serde_json::to_vec(&grant)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;

        // Generate encryption key for access grants
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"saorsa-access-grant-v1");
        hasher.update(grantor_id.to_string().as_bytes());
        hasher.update(grantee_id.to_string().as_bytes());
        let grant_key_salt = hasher.finalize();

        // Derive grant-specific encryption key
        let mut grant_key = [0u8; 32];
        let encryption_key = self
            .derive_encryption_key_for_identity(grantor_id, password)
            .await?;
        let hkdf =
            hkdf::Hkdf::<sha2::Sha256>::new(Some(grant_key_salt.as_bytes()), &encryption_key);
        hkdf.expand(b"access-grant", &mut grant_key).map_err(|_| {
            P2PError::Security(SecurityError::KeyGenerationFailed(
                "HKDF expansion failed".into(),
            ))
        })?;

        // Encrypt grant data
        let mut nonce = [0u8; 12];
        rand::RngCore::fill_bytes(&mut thread_rng(), &mut nonce);
        let ciphertext = self.encrypt_data(&grant_data, &grant_key, &nonce)?;

        // Store encrypted grant
        let grant_path = self
            .storage_path
            .join("grants")
            .join(format!("{}-{}.grant", grantor_id, grantee_id));
        tokio::fs::create_dir_all(grant_path.parent().ok_or_else(|| {
            P2PError::Storage(StorageError::Database("Invalid grant path".into()))
        })?)
        .await
        .map_err(|e| {
            P2PError::Storage(StorageError::Database(
                format!("Failed to create grants directory: {e}").into(),
            ))
        })?;

        let mut grant_file = Vec::with_capacity(12 + ciphertext.len());
        grant_file.extend_from_slice(&nonce);
        grant_file.extend_from_slice(&ciphertext);

        tokio::fs::write(&grant_path, grant_file)
            .await
            .map_err(|e| {
                P2PError::Storage(StorageError::Database(
                    format!("Failed to save access grant: {e}").into(),
                ))
            })?;

        tracing::info!(
            "Granted {:?} access from {} to {}",
            permissions,
            grantor_id,
            grantee_id
        );

        Ok(())
    }

    /// Revoke access from another identity
    pub async fn revoke_access(
        &self,
        grantor_id: &UserId,
        grantee_id: &UserId,
        password: &SecureString,
    ) -> Result<()> {
        // Verify ownership
        let _grantor = self.load_identity(grantor_id, password).await?;

        // Remove grant file
        let grant_path = self
            .storage_path
            .join("grants")
            .join(format!("{}-{}.grant", grantor_id, grantee_id));

        if grant_path.exists() {
            tokio::fs::remove_file(&grant_path).await.map_err(|e| {
                P2PError::Storage(StorageError::Database(
                    format!("Failed to remove access grant: {e}").into(),
                ))
            })?;

            tracing::info!("Revoked access from {} to {}", grantor_id, grantee_id);
        }

        Ok(())
    }

    /// Get access information
    pub async fn get_access_info(
        &self,
        grantor_id: &UserId,
        grantee_id: &UserId,
        password: &SecureString,
    ) -> Result<AccessInfo> {
        // Load grant file
        let grant_path = self
            .storage_path
            .join("grants")
            .join(format!("{}-{}.grant", grantor_id, grantee_id));

        if !grant_path.exists() {
            return Err(P2PError::Identity(IdentityError::AccessDenied(
                "No access grant found".into(),
            )));
        }

        let grant_data = tokio::fs::read(&grant_path).await.map_err(|e| {
            P2PError::Storage(StorageError::Database(
                format!("Failed to read access grant: {e}").into(),
            ))
        })?;

        if grant_data.len() < 12 {
            return Err(P2PError::Security(SecurityError::DecryptionFailed(
                "Invalid grant file format".into(),
            )));
        }

        let nonce = &grant_data[..12];
        let ciphertext = &grant_data[12..];

        // Derive decryption key
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"saorsa-access-grant-v1");
        hasher.update(grantor_id.to_string().as_bytes());
        hasher.update(grantee_id.to_string().as_bytes());
        let grant_key_salt = hasher.finalize();

        let mut grant_key = [0u8; 32];
        let encryption_key = self
            .derive_encryption_key_for_identity(grantor_id, password)
            .await?;
        let hkdf =
            hkdf::Hkdf::<sha2::Sha256>::new(Some(grant_key_salt.as_bytes()), &encryption_key);
        hkdf.expand(b"access-grant", &mut grant_key).map_err(|_| {
            P2PError::Security(SecurityError::KeyGenerationFailed(
                "HKDF expansion failed".into(),
            ))
        })?;

        // Decrypt
        let plaintext = self.decrypt_data(
            ciphertext,
            &grant_key,
            nonce.try_into().map_err(|_| {
                P2PError::Security(SecurityError::DecryptionFailed("Invalid nonce".into()))
            })?,
        )?;

        // Deserialize grant
        let grant: AccessGrant = serde_json::from_slice(&plaintext)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;

        Ok(AccessInfo {
            permissions: grant.permissions,
            granted_at: grant.granted_at,
            expires_at: grant.expires_at,
        })
    }

    /// Save identity to disk with encryption
    async fn save_identity(&self, identity: &Identity, password: &SecureString) -> Result<()> {
        // Serialize identity
        let identity_data = serde_json::to_vec(identity)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;

        // Generate random salt and nonce
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 12];
        rand::RngCore::fill_bytes(&mut thread_rng(), &mut salt);
        rand::RngCore::fill_bytes(&mut thread_rng(), &mut nonce);

        // Derive encryption key from master password
        // This uses secure key storage with the provided password
        let encryption_key = self
            .derive_encryption_key_for_identity(&identity.id, password)
            .await?;

        // Encrypt the identity data
        let ciphertext = self.encrypt_data(&identity_data, &encryption_key, &nonce)?;

        // Create encrypted file format: version (1 byte) + salt (32 bytes) + nonce (12 bytes) + ciphertext
        let mut encrypted_file = Vec::with_capacity(1 + 32 + 12 + ciphertext.len());
        encrypted_file.push(1u8); // Version 1
        encrypted_file.extend_from_slice(&salt);
        encrypted_file.extend_from_slice(&nonce);
        encrypted_file.extend_from_slice(&ciphertext);

        // Save to disk with .enc extension
        let identity_path = self.storage_path.join(format!("{}.enc", identity.id));
        tokio::fs::write(&identity_path, encrypted_file)
            .await
            .map_err(|e| {
                P2PError::Storage(StorageError::Database(
                    format!("Failed to save encrypted identity: {e}").into(),
                ))
            })?;

        Ok(())
    }

    /// Schedule key rotation check
    async fn schedule_key_rotation_check(&self, identity_id: UserId) -> Result<()> {
        let manager = self.clone();
        let id_clone = identity_id.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await; // Check hourly

                // Check if identity needs rotation
                let needs_rotation = {
                    let key_pairs = manager.key_pairs.read().map_err(|_| {
                        P2PError::Identity(IdentityError::SystemTime("read lock failed".into()))
                    })?;
                    key_pairs
                        .get(&id_clone)
                        .map(|kp| kp.needs_rotation())
                        .unwrap_or(false)
                };

                if needs_rotation {
                    // TODO: Notify user about key rotation
                    tracing::info!("Identity {:?} needs key rotation", id_clone);
                }
            }
        });

        let mut tasks = self.background_tasks.write().await;
        tasks.insert(identity_id, task);

        Ok(())
    }
}

// Implement Clone for IdentityManager to support the schedule_key_rotation_check method
impl Clone for IdentityManager {
    fn clone(&self) -> Self {
        Self {
            storage_path: self.storage_path.clone(),
            key_storage: self.key_storage.clone(),
            key_derivation: self.key_derivation.clone(),
            verifier: self.verifier.clone(),
            counter_system: self.counter_system.clone(),
            identities: self.identities.clone(),
            key_pairs: self.key_pairs.clone(),
            background_tasks: self.background_tasks.clone(),
            stats: self.stats.clone(),
        }
    }
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_identity_creation() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let manager = IdentityManager::new(temp_dir.path(), SecurityLevel::Fast).await?;

        let password = SecureString::from_str("test_password_123!").expect("Test assertion failed");
        manager.initialize(&password).await?;

        let params = IdentityCreationParams {
            display_name: Some("Test User".to_string()),
            avatar_url: None,
            bio: Some("Test bio".to_string()),
            metadata: HashMap::new(),
            key_lifetime: None,
            derivation_path: None,
        };

        let identity = manager.create_identity(&password, params).await?;

        assert_eq!(identity.state, IdentityState::Active);
        assert_eq!(identity.display_name, Some("Test User".to_string()));
        assert!(identity.is_valid());
        Ok(())
    }

    #[tokio::test]
    async fn test_identity_verification() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let manager = IdentityManager::new(temp_dir.path(), SecurityLevel::Fast).await?;

        let password = SecureString::from_str("test_password_123!").expect("Test assertion failed");
        manager.initialize(&password).await?;

        let params = IdentityCreationParams::default();
        let identity = manager.create_identity(&password, params).await?;

        let verification = manager.verify_identity(&identity).await?;
        assert!(verification.valid);
        assert_eq!(verification.trust_level, 100);
        assert!(verification.issues.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_key_rotation() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let manager = IdentityManager::new(temp_dir.path(), SecurityLevel::Fast).await?;

        let password = SecureString::from_str("test_password_123!").expect("Test assertion failed");
        manager.initialize(&password).await?;

        let params = IdentityCreationParams::default();
        let identity = manager.create_identity(&password, params).await?;
        let original_version = identity.key_version;

        // Rotate keys
        manager.rotate_keys(&identity.id, &password).await?;

        // Load updated identity
        let updated_identity = manager.load_identity(&identity.id, &password).await?;
        assert_eq!(updated_identity.key_version, original_version + 1);
        assert!(!updated_identity.previous_keys.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_identity_revocation() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let manager = IdentityManager::new(temp_dir.path(), SecurityLevel::Fast).await?;

        let password = SecureString::from_str("test_password_123!").expect("Test assertion failed");
        manager.initialize(&password).await?;

        let params = IdentityCreationParams::default();
        let identity = manager.create_identity(&password, params).await?;

        // Revoke identity
        let cert = manager
            .revoke_identity(
                &identity.id,
                &password,
                RevocationReason::UserRequested,
                None,
            )
            .await?;

        assert_eq!(cert.reason, RevocationReason::UserRequested);
        assert!(!cert.signature.is_empty());

        // Try to load revoked identity
        let revoked = manager.load_identity(&identity.id, &password).await?;
        assert_eq!(revoked.state, IdentityState::Revoked);
        assert!(!revoked.is_valid());
        Ok(())
    }

    #[tokio::test]
    async fn test_multi_device_sync() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let manager1 =
            IdentityManager::new(temp_dir.path().join("device1"), SecurityLevel::Fast).await?;

        let manager2 =
            IdentityManager::new(temp_dir.path().join("device2"), SecurityLevel::Fast).await?;

        let password = SecureString::from_str("test_password_123!").expect("Test assertion failed");
        let device_password =
            SecureString::from_str("device_sync_password").expect("Test assertion failed");

        manager1.initialize(&password).await?;
        manager2.initialize(&password).await?;

        // Create identity on device 1
        let params = IdentityCreationParams {
            display_name: Some("Sync Test User".to_string()),
            ..Default::default()
        };

        let identity = manager1.create_identity(&password, params).await?;

        // Create sync package
        let sync_package = manager1
            .create_sync_package(&identity.id, &password, &device_password)
            .await?;

        // Import on device 2
        let imported = manager2
            .import_sync_package(&sync_package, &device_password, &password)
            .await?;

        assert_eq!(imported.id, identity.id);
        assert_eq!(imported.display_name, identity.display_name);
        Ok(())
    }
}

// Include migration module
pub mod migration;

// Implement Default for IdentityCreationParams
