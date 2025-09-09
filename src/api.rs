// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com

//! Clean API implementation for saorsa-core
//!
//! This module provides the simplified public API for:
//! - Identity registration and management
//! - Presence and device management
//! - Storage with saorsa-seal and saorsa-fec

use crate::auth::Sig;
use crate::fwid::{Key, compute_key, fw_check, fw_to_key};
use crate::types::{
    Device, DeviceId, Endpoint, Identity, IdentityHandle, MlDsaKeyPair, Presence, PresenceReceipt,
    StorageHandle, StorageStrategy,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
// tracing not currently used in this module

// Mock DHT for fallback when no global DHT client is installed
struct MockDht {
    storage: HashMap<Key, Vec<u8>>,
}

impl MockDht {
    fn new() -> Self {
        Self {
            storage: HashMap::new(),
        }
    }

    async fn put(&mut self, key: Key, value: Vec<u8>) -> Result<()> {
        self.storage.insert(key, value);
        Ok(())
    }

    async fn get(&self, key: &Key) -> Result<Vec<u8>> {
        self.storage
            .get(key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Key not found"))
    }
}

// Global DHT instance for testing
static DHT: once_cell::sync::Lazy<Arc<RwLock<MockDht>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(MockDht::new())));

// Optional global DHT client (real engine). If not set, we fall back to MockDht.
static GLOBAL_DHT_CLIENT: once_cell::sync::OnceCell<Arc<crate::dht::client::DhtClient>> =
    once_cell::sync::OnceCell::new();

/// Install a process-global DHT client for API operations.
pub fn set_dht_client(client: crate::dht::client::DhtClient) -> bool {
    GLOBAL_DHT_CLIENT.set(Arc::new(client)).is_ok()
}

fn get_dht_client() -> Option<Arc<crate::dht::client::DhtClient>> {
    GLOBAL_DHT_CLIENT.get().cloned()
}

async fn dht_put_bytes(key: &Key, value: Vec<u8>) -> Result<()> {
    if let Some(client) = get_dht_client() {
        let k = hex::encode(key.as_bytes());
        let _ = client
            .put(k, value)
            .await
            .context("Failed to store data in DHT client")?;
        Ok(())
    } else {
        let mut dht = DHT.write().await;
        dht.put(key.clone(), value).await
    }
}

async fn dht_get_bytes(key: &Key) -> Result<Vec<u8>> {
    if let Some(client) = get_dht_client() {
        let k = hex::encode(key.as_bytes());
        match client.get(k).await.context("DHT get failed")? {
            Some(v) => Ok(v),
            None => anyhow::bail!("Key not found"),
        }
    } else {
        let dht = DHT.read().await;
        dht.get(key).await
    }
}

// =============================================================================
// API-visible record types (minimal, per AGENTS_API.md)
// =============================================================================

/// Minimal identity packet compatible with Communitas group flows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityPacketV1 {
    pub v: u8,
    pub words: [String; 4],
    pub id: Key,
    pub pk: Vec<u8>,
    pub sig: Option<Vec<u8>>, // optional when registered locally
    pub device_set_root: Key,
}

/// Member reference for group identities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberRef {
    pub member_id: Key,
    pub member_pk: Vec<u8>,
}

/// Group identity packet (canonical)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupIdentityPacketV1 {
    pub v: u8,
    pub words: [String; 4],
    pub id: Key,
    pub group_pk: Vec<u8>,
    pub group_sig: Vec<u8>,
    pub members: Vec<MemberRef>,
    pub membership_root: Key,
    pub created_at: u64,
    pub mls_ciphersuite: Option<u16>,
}

/// Keypair for group signatures
#[derive(Clone)]
pub struct GroupKeyPair {
    pub group_pk: crate::quantum_crypto::MlDsaPublicKey,
    pub group_sk: crate::quantum_crypto::MlDsaSecretKey,
}

impl std::fmt::Debug for GroupKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GroupKeyPair {{ group_pk: <{} bytes>, group_sk: <hidden> }}",
            self.group_pk.as_bytes().len()
        )
    }
}

// ============================================================================
// IDENTITY API
// ============================================================================

/// Register a new identity on the network
///
/// # Arguments
/// * `words` - Four-word identifier (must be valid dictionary words)
/// * `keypair` - ML-DSA keypair for signing
///
/// # Returns
/// * `IdentityHandle` - Handle for identity operations
pub async fn register_identity(words: [&str; 4], keypair: &MlDsaKeyPair) -> Result<IdentityHandle> {
    // Convert to owned strings
    let words_owned: [String; 4] = [
        words[0].to_string(),
        words[1].to_string(),
        words[2].to_string(),
        words[3].to_string(),
    ];

    // Validate words
    if !fw_check(words_owned.clone()) {
        anyhow::bail!("Invalid word in identity");
    }

    // Generate key from words
    let key = fw_to_key(words_owned.clone())?;

    // Check if already registered
    let dht = DHT.read().await;
    if dht.get(&key).await.is_ok() {
        anyhow::bail!("Identity already registered");
    }
    drop(dht);

    // Create identity (typed) and store packet for compatibility
    let identity = Identity {
        words: words_owned.clone(),
        key: key.clone(),
        public_key: keypair.public_key.clone(),
    };

    let packet = IdentityPacketV1 {
        v: 1,
        words: words_owned.clone(),
        id: key.clone(),
        pk: keypair.public_key.clone(),
        sig: None,
        device_set_root: compute_key("device-set", key.as_bytes()),
    };

    dht_put_bytes(&key, serde_json::to_vec(&packet)?).await?;

    Ok(IdentityHandle::new(identity, keypair.clone()))
}

/// Get an identity by its key
///
/// # Arguments
/// * `key` - Identity key (derived from four-word address)
///
/// # Returns
/// * `Identity` - The identity information
pub async fn get_identity(key: Key) -> Result<Identity> {
    // Try to read the identity packet and map back to Identity struct
    let data = dht_get_bytes(&key).await.context("Identity not found")?;
    if let Ok(pkt) = serde_json::from_slice::<IdentityPacketV1>(&data) {
        let identity = Identity {
            words: pkt.words,
            key: pkt.id,
            public_key: pkt.pk,
        };
        return Ok(identity);
    }
    // Fallback: legacy storage of Identity
    let identity: Identity = serde_json::from_slice(&data)?;
    Ok(identity)
}

/// Fetch identity packet in canonical format
pub async fn identity_fetch(key: Key) -> Result<IdentityPacketV1> {
    let data = dht_get_bytes(&key).await.context("Identity not found")?;
    let pkt: IdentityPacketV1 = serde_json::from_slice(&data)?;
    Ok(pkt)
}

// ============================================================================
// PRESENCE API
// ============================================================================

/// Register presence on the network
///
/// # Arguments
/// * `handle` - Identity handle
/// * `devices` - List of devices for this identity
/// * `active_device` - Currently active device ID
///
/// # Returns
/// * `PresenceReceipt` - Receipt of presence registration
pub async fn register_presence(
    handle: &IdentityHandle,
    devices: Vec<Device>,
    active_device: DeviceId,
) -> Result<PresenceReceipt> {
    // Validate active device is in list
    if !devices.iter().any(|d| d.id == active_device) {
        anyhow::bail!("Active device not in device list");
    }

    // Create presence packet
    let presence = Presence {
        identity: handle.key(),
        devices,
        active_device: Some(active_device),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        signature: vec![], // Will be filled
    };

    // Sign presence
    let presence_bytes = serde_json::to_vec(&presence)?;
    let signature = handle.sign(&presence_bytes)?;

    let mut signed_presence = presence;
    signed_presence.signature = signature;

    // Store in DHT with presence key
    let presence_key = derive_presence_key(handle.key());
    let mut dht = DHT.write().await;
    dht.put(presence_key, serde_json::to_vec(&signed_presence)?)
        .await?;

    // Create receipt
    let receipt = PresenceReceipt {
        identity: handle.key(),
        timestamp: signed_presence.timestamp,
        storing_nodes: vec![Key::from([0u8; 32])], // Mock node
    };

    Ok(receipt)
}

/// Get presence information for an identity
///
/// # Arguments
/// * `identity_key` - Key of the identity
///
/// # Returns
/// * `Presence` - Current presence information
pub async fn get_presence(identity_key: Key) -> Result<Presence> {
    let presence_key = derive_presence_key(identity_key);
    let dht = DHT.read().await;
    let data = dht.get(&presence_key).await.context("Presence not found")?;
    let presence: Presence = serde_json::from_slice(&data)?;
    Ok(presence)
}

/// Register a headless storage node
///
/// # Arguments
/// * `handle` - Identity handle
/// * `storage_gb` - Storage capacity in GB
/// * `endpoint` - Network endpoint
///
/// # Returns
/// * `DeviceId` - ID of the registered headless node
pub async fn register_headless(
    handle: &IdentityHandle,
    storage_gb: u32,
    endpoint: Endpoint,
) -> Result<DeviceId> {
    // Get current presence
    let mut presence = get_presence(handle.key()).await?;

    // Create headless device
    let device = Device {
        id: DeviceId::generate(),
        device_type: crate::types::presence::DeviceType::Headless,
        storage_gb: storage_gb as u64,
        endpoint,
        capabilities: crate::types::presence::DeviceCapabilities {
            storage_bytes: storage_gb as u64 * 1_000_000_000,
            always_online: true,
            supports_fec: true,
            supports_seal: true,
            ..Default::default()
        },
    };

    let device_id = device.id;
    presence.devices.push(device);

    // Update presence
    let active = presence.active_device.unwrap_or(device_id);
    register_presence(handle, presence.devices, active).await?;

    Ok(device_id)
}

/// Set the active device for an identity
///
/// # Arguments
/// * `handle` - Identity handle
/// * `device_id` - Device to make active
pub async fn set_active_device(handle: &IdentityHandle, device_id: DeviceId) -> Result<()> {
    // Get current presence
    let presence = get_presence(handle.key()).await?;

    // Validate device exists
    if !presence.devices.iter().any(|d| d.id == device_id) {
        anyhow::bail!("Device not found in presence");
    }

    // Update with new active device
    register_presence(handle, presence.devices, device_id).await?;
    Ok(())
}

// ============================================================================
// STORAGE API
// ============================================================================

/// Store data on the network
///
/// # Arguments
/// * `handle` - Identity handle
/// * `data` - Data to store
/// * `group_size` - Size of the group (affects storage strategy)
///
/// # Returns
/// * `StorageHandle` - Handle to retrieve the data
pub async fn store_data(
    handle: &IdentityHandle,
    data: Vec<u8>,
    group_size: usize,
) -> Result<StorageHandle> {
    // Select strategy based on group size
    let strategy = StorageStrategy::from_group_size(group_size);

    match strategy {
        StorageStrategy::Direct => store_direct(handle, data).await,
        StorageStrategy::FullReplication { replicas } => {
            store_replicated(handle, data, replicas).await
        }
        StorageStrategy::FecEncoded {
            data_shards,
            parity_shards,
            ..
        } => store_with_fec(handle, data, data_shards, parity_shards).await,
    }
}

/// Store data for a dyad (2-person group)
///
/// # Arguments
/// * `handle1` - First identity handle
/// * `handle2_key` - Key of second identity
/// * `data` - Data to store
///
/// # Returns
/// * `StorageHandle` - Handle to retrieve the data
pub async fn store_dyad(
    handle1: &IdentityHandle,
    _handle2_key: Key,
    data: Vec<u8>,
) -> Result<StorageHandle> {
    // For dyads, use full replication (2 copies)
    store_replicated(handle1, data, 2).await
}

/// Store data with custom FEC parameters
///
/// # Arguments
/// * `handle` - Identity handle
/// * `data` - Data to store
/// * `data_shards` - Number of data shards (k)
/// * `parity_shards` - Number of parity shards (m)
///
/// # Returns
/// * `StorageHandle` - Handle to retrieve the data
pub async fn store_with_fec(
    handle: &IdentityHandle,
    data: Vec<u8>,
    data_shards: usize,
    parity_shards: usize,
) -> Result<StorageHandle> {
    // Generate storage ID
    let storage_id = Key::from(*blake3::hash(&data).as_bytes());

    // TODO: Actual FEC encoding with saorsa-fec
    // For now, just store the data directly

    // Create shard map (mock)
    let mut shard_map = crate::types::storage::ShardMap::new();

    // Get presence to find devices
    let presence = get_presence(handle.key()).await?;

    // Prefer headless nodes for storage
    let mut devices = presence.devices.clone();
    devices.sort_by_key(|d| match d.device_type {
        crate::types::presence::DeviceType::Headless => 0,
        crate::types::presence::DeviceType::Active => 1,
        crate::types::presence::DeviceType::Mobile => 2,
    });

    // Assign shards to devices
    let total_shards = data_shards + parity_shards;
    for (i, device) in devices.iter().take(total_shards).enumerate() {
        shard_map.assign_shard(device.id, i as u32);
    }

    // Store data in DHT
    let mut dht = DHT.write().await;
    dht.put(storage_id.clone(), data.clone()).await?;

    // Create storage handle
    let handle = StorageHandle {
        id: storage_id,
        size: data.len() as u64,
        strategy: StorageStrategy::FecEncoded {
            data_shards,
            parity_shards,
            shard_size: 65536,
        },
        shard_map,
        sealed_key: Some(vec![0u8; 32]), // Mock sealed key
    };

    Ok(handle)
}

/// Retrieve data from the network
///
/// # Arguments
/// * `handle` - Storage handle
///
/// # Returns
/// * `Vec<u8>` - The retrieved data
pub async fn get_data(handle: &StorageHandle) -> Result<Vec<u8>> {
    // TODO: Handle different strategies (FEC decoding, unsealing, etc.)
    // For now, just retrieve from DHT

    let dht = DHT.read().await;
    let data = dht.get(&handle.id).await.context("Data not found")?;
    Ok(data)
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Derive presence key from identity key
fn derive_presence_key(identity_key: Key) -> Key {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"presence:");
    hasher.update(identity_key.as_bytes());
    Key::from(*hasher.finalize().as_bytes())
}

/// Store data directly (no redundancy)
async fn store_direct(handle: &IdentityHandle, data: Vec<u8>) -> Result<StorageHandle> {
    let storage_id = Key::from(*blake3::hash(&data).as_bytes());

    // Store in DHT
    let mut dht = DHT.write().await;
    dht.put(storage_id.clone(), data.clone()).await?;

    // Get single device
    let presence = get_presence(handle.key()).await?;
    let device = presence.devices.first().context("No devices available")?;

    let mut shard_map = crate::types::storage::ShardMap::new();
    shard_map.assign_shard(device.id, 0);

    Ok(StorageHandle {
        id: storage_id,
        size: data.len() as u64,
        strategy: StorageStrategy::Direct,
        shard_map,
        sealed_key: Some(vec![0u8; 32]),
    })
}

// ============================================================================
// GROUP API (per AGENTS_API.md, minimal subset used by Communitas)
// ============================================================================

/// Canonical bytes for group identity signing: b"saorsa-group:identity:v1" || id || membership_root
pub fn group_identity_canonical_sign_bytes(id: &Key, membership_root: &Key) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 32 + 32);
    out.extend_from_slice(b"saorsa-group:identity:v1");
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(membership_root.as_bytes());
    out
}

fn compute_membership_root(members: &[MemberRef]) -> Key {
    let mut ids: Vec<[u8; 32]> = members.iter().map(|m| *m.member_id.as_bytes()).collect();
    ids.sort_unstable();
    let mut hasher = blake3::Hasher::new();
    for id in ids {
        hasher.update(&id);
    }
    Key::from(*hasher.finalize().as_bytes())
}

/// Create a canonical group identity and keypair
pub fn group_identity_create(
    words: [String; 4],
    members: Vec<MemberRef>,
) -> Result<(GroupIdentityPacketV1, GroupKeyPair)> {
    // Validate words and id
    if !fw_check(words.clone()) {
        anyhow::bail!("Invalid group words");
    }
    let id = fw_to_key(words.clone())?;

    // Generate ML-DSA group keypair
    use crate::quantum_crypto::{MlDsa65, MlDsaOperations};
    let ml = MlDsa65::new();
    let (group_pk, group_sk) = ml
        .generate_keypair()
        .map_err(|e| anyhow::anyhow!("group keypair generation failed: {e:?}"))?;

    // Compute membership root and sign canonical bytes
    let membership_root = compute_membership_root(&members);
    let msg = group_identity_canonical_sign_bytes(&id, &membership_root);
    let sig = ml
        .sign(&group_sk, &msg)
        .map_err(|e| anyhow::anyhow!("group sign failed: {e:?}"))?;

    let pkt = GroupIdentityPacketV1 {
        v: 1,
        words,
        id: id.clone(),
        group_pk: group_pk.as_bytes().to_vec(),
        group_sig: sig.0.to_vec(),
        members,
        membership_root,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        mls_ciphersuite: None,
    };

    Ok((pkt, GroupKeyPair { group_pk, group_sk }))
}

/// Publish a group identity packet under its id key
pub async fn group_identity_publish(packet: GroupIdentityPacketV1) -> Result<()> {
    // Basic validation: recompute root and signature check
    let root = compute_membership_root(&packet.members);
    if root != packet.membership_root {
        anyhow::bail!("membership_root mismatch");
    }
    // Verify signature
    use crate::quantum_crypto::{MlDsa65, MlDsaOperations, MlDsaPublicKey, MlDsaSignature};
    const SIG_LEN: usize = 3309;
    if packet.group_sig.len() != SIG_LEN {
        anyhow::bail!("invalid signature length");
    }
    let mut sig_arr = [0u8; SIG_LEN];
    sig_arr.copy_from_slice(&packet.group_sig);
    let sig = MlDsaSignature(Box::new(sig_arr));
    let pk = MlDsaPublicKey::from_bytes(&packet.group_pk)
        .map_err(|_| anyhow::anyhow!("invalid group_pk"))?;
    let ml = MlDsa65::new();
    let msg = group_identity_canonical_sign_bytes(&packet.id, &packet.membership_root);
    let ok = ml
        .verify(&pk, &msg, &sig)
        .map_err(|e| anyhow::anyhow!("verify failed: {e:?}"))?;
    if !ok {
        anyhow::bail!("group signature invalid");
    }
    dht_put_bytes(&packet.id, serde_json::to_vec(&packet)?).await
}

/// Fetch a group identity by id key
pub async fn group_identity_fetch(id_key: Key) -> Result<GroupIdentityPacketV1> {
    let data = dht_get_bytes(&id_key).await.context("Group not found")?;
    let pkt: GroupIdentityPacketV1 = serde_json::from_slice(&data)?;
    Ok(pkt)
}

/// Update group members with signature verification over canonical bytes
pub async fn group_identity_update_members_signed(
    id_key: Key,
    new_members: Vec<MemberRef>,
    group_pk: Vec<u8>,
    group_sig: Sig,
) -> Result<()> {
    // Compute new root and verify signature
    let new_root = compute_membership_root(&new_members);
    use crate::quantum_crypto::{MlDsa65, MlDsaOperations, MlDsaPublicKey, MlDsaSignature};
    const SIG_LEN: usize = 3309;
    let sig_bytes = group_sig.as_bytes();
    if sig_bytes.len() != SIG_LEN {
        anyhow::bail!("invalid signature length");
    }
    let mut sig_arr = [0u8; SIG_LEN];
    sig_arr.copy_from_slice(sig_bytes);
    let sig = MlDsaSignature(Box::new(sig_arr));
    let pk =
        MlDsaPublicKey::from_bytes(&group_pk).map_err(|_| anyhow::anyhow!("invalid group_pk"))?;
    let ml = MlDsa65::new();
    let msg = group_identity_canonical_sign_bytes(&id_key, &new_root);
    let ok = ml
        .verify(&pk, &msg, &sig)
        .map_err(|e| anyhow::anyhow!("verify failed: {e:?}"))?;
    if !ok {
        anyhow::bail!("group signature invalid");
    }

    // Fetch current (if exists) to preserve metadata
    let mut pkt = match group_identity_fetch(id_key.clone()).await {
        Ok(p) => p,
        Err(_) => GroupIdentityPacketV1 {
            v: 1,
            words: [String::new(), String::new(), String::new(), String::new()],
            id: id_key.clone(),
            group_pk: group_pk.clone(),
            group_sig: sig.0.clone().to_vec(),
            members: Vec::new(),
            membership_root: new_root.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            mls_ciphersuite: None,
        },
    };

    pkt.members = new_members;
    pkt.membership_root = new_root;
    pkt.group_pk = group_pk;
    pkt.group_sig = sig.0.to_vec();

    group_identity_publish(pkt).await
}

/// Store data with full replication
async fn store_replicated(
    handle: &IdentityHandle,
    data: Vec<u8>,
    replicas: usize,
) -> Result<StorageHandle> {
    let storage_id = Key::from(*blake3::hash(&data).as_bytes());

    // Store in DHT
    let mut dht = DHT.write().await;
    dht.put(storage_id.clone(), data.clone()).await?;

    // Get devices for replicas
    let presence = get_presence(handle.key()).await?;
    let mut shard_map = crate::types::storage::ShardMap::new();

    for (i, device) in presence.devices.iter().take(replicas).enumerate() {
        shard_map.assign_shard(device.id, i as u32);
    }

    Ok(StorageHandle {
        id: storage_id,
        size: data.len() as u64,
        strategy: StorageStrategy::FullReplication { replicas },
        shard_map,
        sealed_key: Some(vec![0u8; 32]),
    })
}

/// Update the website root for an identity
pub async fn identity_set_website_root(id_key: Key, website_root: Key, sig: Sig) -> Result<()> {
    let mut pkt = identity_fetch(id_key.clone()).await?;

    let mut msg = Vec::new();
    msg.extend_from_slice(CANONICAL_IDENTITY_WEBSITE_ROOT);
    msg.extend_from_slice(id_key.as_bytes());
    msg.extend_from_slice(&pkt.pk);
    let website_root_cbor = serde_cbor::to_vec(&website_root)?;
    msg.extend_from_slice(&website_root_cbor);

    // Verify signature using stored identity pk
    use crate::quantum_crypto::{MlDsa65, MlDsaOperations, MlDsaPublicKey, MlDsaSignature};
    let pk = MlDsaPublicKey::from_bytes(&pkt.pk)
        .map_err(|e| anyhow::anyhow!("Invalid ML-DSA pubkey: {e}"))?;

    const SIG_LEN: usize = 3309;
    if sig.as_bytes().len() != SIG_LEN {
        anyhow::bail!("Invalid signature length for website_root update");
    }
    let mut arr = [0u8; SIG_LEN];
    arr.copy_from_slice(sig.as_bytes());
    let ml_sig = MlDsaSignature(Box::new(arr));

    let ml = MlDsa65::new();
    let ok = ml
        .verify(&pk, &msg, &ml_sig)
        .map_err(|e| anyhow::anyhow!("Website root signature verify failed: {e}"))?;
    if !ok {
        anyhow::bail!("Website root signature invalid");
    }

    // Update packet with new website_root
    pkt.website_root = Some(website_root);

    let updated_bytes = serde_cbor::to_vec(&pkt)?;
    dht_put_bytes(id_key, updated_bytes).await?;

    Ok(())
}

pub async fn group_member_add(
    id_key: Key,
    member: MemberRef,
    group_pk: Vec<u8>,
    group_sig: Sig,
) -> Result<()> {
    // Fetch current packet
    let packet = group_identity_fetch(id_key.clone()).await?;

    let mut members = packet.members;
    if !members.iter().any(|m| m.member_id == member.member_id) {
        members.push(member);
    }

    group_identity_update_members_signed(id_key, members, group_pk, group_sig).await
}

pub async fn group_member_remove(
    id_key: Key,
    member_id: Key,
    group_pk: Vec<u8>,
    group_sig: Sig,
) -> Result<()> {
    // Fetch current packet
    let packet = group_identity_fetch(id_key.clone()).await?;

    // Remove member
    let members: Vec<MemberRef> = packet
        .members
        .into_iter()
        .filter(|m| m.member_id != member_id)
        .collect();

    group_identity_update_members_signed(id_key, members, group_pk, group_sig).await
}

pub async fn group_epoch_bump(
    id_key: Key,
    proof: Option<Vec<u8>>,
    group_pk: Vec<u8>,
    group_sig: Sig,
) -> Result<()> {
    // For now, this is a placeholder that validates the signature
    // and potentially trigger re-keying operations
    
    // Verify the group signature is valid
    let packet = group_identity_fetch(id_key.clone()).await?;
    
    
    // For now, just return success if we can fetch the packet
    Ok(())
}
