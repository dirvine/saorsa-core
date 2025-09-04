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

//! Public API implementation matching the saorsa-core specification.

use crate::adaptive::TrustProvider;
use crate::adaptive::trust::EigenTrustEngine;
use crate::auth::{PubKey, Sig, WriteAuth};
use crate::events::Subscription;
use crate::fwid::{Key, fw_check, fw_to_key};
use crate::identity::node_identity::NodeId;
use crate::peer_record::UserId;
use crate::quantum_crypto::{
    MlDsa65, MlDsaOperations, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
};
use crate::telemetry::StreamClass;
use crate::types::Forward;
use crate::{dht as twdht_mod, telemetry};
use anyhow::Result;
use blake3::Hasher as Blakesum;
use bytes::Bytes;
use once_cell::sync::{Lazy, OnceCell};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;
use twdht_mod::{Dht as TwDhtTrait, TrustWeightedKademlia as TwDht};

// Re-export key spec types
pub use crate::fwid::Word;

/// Group member reference (snapshot entry)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemberRef {
    pub member_id: Key,
    pub member_pk: Vec<u8>,
}

/// Group identity packet (V1)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

/// Group keypair container
pub struct GroupKeyPair {
    pub group_pk: MlDsaPublicKey,
    pub group_sk: MlDsaSecretKey,
}

fn compute_membership_root(members: &[MemberRef]) -> Key {
    let mut ids: Vec<[u8; 32]> = members.iter().map(|m| *m.member_id.as_bytes()).collect();
    ids.sort_unstable();
    let mut hasher = Blakesum::new();
    for id in ids {
        hasher.update(&id);
    }
    let out = hasher.finalize();
    Key::from(*out.as_bytes())
}

fn group_identity_canonical_message(id: &Key, membership_root: &Key) -> Vec<u8> {
    const DST: &[u8] = b"saorsa-group:identity:v1";
    let mut msg = Vec::with_capacity(DST.len() + 64);
    msg.extend_from_slice(DST);
    msg.extend_from_slice(id.as_bytes());
    msg.extend_from_slice(membership_root.as_bytes());
    msg
}

/// Network endpoint representation for identity owner
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkEndpoint {
    /// IPv4 address and port, if available (e.g., "203.0.113.10", 443)
    pub ipv4: Option<(String, u16)>,
    /// IPv6 address and port, if available (e.g., "2001:db8::1", 443)
    pub ipv6: Option<(String, u16)>,
    /// Four-word representation for IPv4 endpoint (for user display)
    pub fw4: Option<String>,
    /// Extended word representation for IPv6 endpoint (for user display)
    pub fw6: Option<String>,
}

/// Identity packet version 1 (single-writer)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IdentityPacketV1 {
    pub v: u8,
    /// Four words chosen by the user
    pub words: [String; 4],
    /// Identity key = blake3(utf8(words))
    pub id: Key,
    /// ML-DSA public key (bytes)
    pub pk: Vec<u8>,
    /// ML-DSA signature over utf8(words)
    pub sig: Vec<u8>,
    /// Publicly reachable endpoints for this identity
    pub endpoints: Vec<NetworkEndpoint>,
    /// ML-DSA signature over (id || pk || CBOR(endpoints)) when endpoints are present
    pub ep_sig: Option<Vec<u8>>,
    /// Optional website root key
    pub website_root: Option<Key>,
    /// Device set root key
    pub device_set_root: Key,
}

/// Device set version 1 (multi-writer CRDT)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceSetV1 {
    pub v: u8,
    pub crdt: String,
    pub forwards: Vec<Forward>,
    /// Signature over canonical CBOR of `forwards` and the device-set key
    /// This signature is verified against `WriteAuth` (Single or Delegated)
    /// and is never included in the canonical signing bytes to avoid
    /// signature malleability affecting identity.
    pub sig: Option<Vec<u8>>,
}

// Forward entry for device set - moved to crate::types::Forward

/// Group packet version 1
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroupPacketV1 {
    pub v: u8,
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub membership: Key,
    pub forwards_root: Key,
    pub container_root: Key,
    /// MLS proof bytes (opaque)
    pub proof: Option<Vec<u8>>,
}

/// Group forwards version 1
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroupForwardsV1 {
    pub v: u8,
    pub endpoints: Vec<GroupEndpoint>,
    /// MLS proof bytes (opaque)
    pub proof: Option<Vec<u8>>,
}

/// Group endpoint entry
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroupEndpoint {
    pub member_pub: Vec<u8>,
    pub forward: Forward,
    pub ts: u64,
}

/// Container manifest version 1
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContainerManifestV1 {
    pub v: u8,
    pub object: Key,
    pub fec: FecParams,
    pub assets: Vec<Key>,
    pub sealed_meta: Option<Key>,
}

/// FEC parameters
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FecParams {
    pub k: u16,
    pub m: u16,
    pub shard_size: u32,
}

// Convenience helpers for CBOR+Keyed storage of Group and Container types
/// Store GroupPacketV1 under key blake3("group" || group_id)
pub async fn group_put(pkt: &GroupPacketV1, policy: &PutPolicy) -> Result<PutReceipt> {
    let key = crate::fwid::compute_key("group", &pkt.group_id);
    let bytes = serde_cbor::to_vec(pkt)?;
    dht_put(key, Bytes::from(bytes), policy).await
}

/// Fetch GroupPacketV1 by group_id
pub async fn group_fetch(group_id: &[u8]) -> Result<GroupPacketV1> {
    let key = crate::fwid::compute_key("group", group_id);
    let bytes = dht_get(key, 1).await?;
    Ok(serde_cbor::from_slice(&bytes)?)
}

/// Store GroupForwardsV1 under key blake3("group-fwd" || group_id)
pub async fn group_forwards_put(
    fwd: &GroupForwardsV1,
    group_id: &[u8],
    policy: &PutPolicy,
) -> Result<PutReceipt> {
    let key = crate::fwid::compute_key("group-fwd", group_id);
    let bytes = serde_cbor::to_vec(fwd)?;
    dht_put(key, Bytes::from(bytes), policy).await
}

/// Fetch GroupForwardsV1 by group_id
pub async fn group_forwards_fetch(group_id: &[u8]) -> Result<GroupForwardsV1> {
    let key = crate::fwid::compute_key("group-fwd", group_id);
    let bytes = dht_get(key, 1).await?;
    Ok(serde_cbor::from_slice(&bytes)?)
}

/// Store ContainerManifestV1 under key blake3("manifest" || object)
pub async fn container_manifest_put(
    manifest: &ContainerManifestV1,
    policy: &PutPolicy,
) -> Result<PutReceipt> {
    let key = crate::fwid::compute_key("manifest", manifest.object.as_bytes());
    let bytes = serde_cbor::to_vec(manifest)?;
    dht_put(key, Bytes::from(bytes), policy).await
}

/// Fetch ContainerManifestV1 by object root
pub async fn container_manifest_fetch(object: &[u8; 32]) -> Result<ContainerManifestV1> {
    let key = crate::fwid::compute_key("manifest", object);
    let bytes = dht_get(key, 1).await?;
    Ok(serde_cbor::from_slice(&bytes)?)
}

/// Create a new group identity and return the packet + keypair
pub fn group_identity_create(
    words: [Word; 4],
    members: Vec<MemberRef>,
) -> Result<(GroupIdentityPacketV1, GroupKeyPair)> {
    if !fw_check(words.clone()) {
        anyhow::bail!("Invalid four words for group");
    }
    let id = fw_to_key(words.clone())?;
    let membership_root = compute_membership_root(&members);
    let ml = MlDsa65::new();
    let (group_pk, group_sk) = ml
        .generate_keypair()
        .map_err(|e| anyhow::anyhow!("Failed to generate group keypair: {e}"))?;
    let msg = group_identity_canonical_message(&id, &membership_root);
    let sig = ml
        .sign(&group_sk, &msg)
        .map_err(|e| anyhow::anyhow!("Failed to sign group identity: {e}"))?;
    let packet = GroupIdentityPacketV1 {
        v: 1,
        words: [
            words[0].clone(),
            words[1].clone(),
            words[2].clone(),
            words[3].clone(),
        ],
        id: id.clone(),
        group_pk: group_pk.as_bytes().to_vec(),
        group_sig: sig.0.to_vec(),
        members,
        membership_root,
        created_at: (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default())
        .as_secs(),
        mls_ciphersuite: None,
    };
    Ok((packet, GroupKeyPair { group_pk, group_sk }))
}

/// Publish a group identity (validated) to DHT
pub async fn group_identity_publish(packet: GroupIdentityPacketV1) -> Result<()> {
    let id_key = packet.id.clone();
    let bytes = serde_cbor::to_vec(&packet)?;
    let pol = PutPolicy {
        quorum: 3,
        ttl: None,
        auth: Box::new(crate::auth::SingleWriteAuth::new(PubKey::new(
            packet.group_pk.clone(),
        ))),
    };
    let _ = dht_put(id_key, Bytes::from(bytes), &pol).await?;
    Ok(())
}

/// Fetch a group identity packet by id key
pub async fn group_identity_fetch(id_key: Key) -> Result<GroupIdentityPacketV1> {
    let bytes = dht_get(id_key, 1).await?;
    Ok(serde_cbor::from_slice(&bytes)?)
}

/// DHT put policy
pub struct PutPolicy {
    pub quorum: usize,
    pub ttl: Option<Duration>,
    pub auth: Box<dyn WriteAuth>,
}

/// DHT put receipt
#[derive(Debug, Clone)]
pub struct PutReceipt {
    pub key: Key,
    pub timestamp: u64,
    pub storing_nodes: Vec<Vec<u8>>,
}

/// Routing outcome for trust tracking
#[derive(Debug, Clone)]
pub enum Outcome {
    Ok,
    Timeout,
    BadData,
    Refused,
}

/// Network contact information
#[derive(Debug, Clone)]
pub struct Contact {
    pub node_id: Vec<u8>,
    pub endpoint: String,
}

/// Repair plan for storage
#[derive(Debug, Clone)]
pub struct RepairPlan {
    pub object_id: [u8; 32],
    pub missing_shards: Vec<usize>,
    pub repair_nodes: Vec<Vec<u8>>,
}

// ============================================================================
// Identity API
// ============================================================================

/// Claim an identity with four words
pub async fn identity_claim(words: [Word; 4], _pubkey: PubKey, _sig: Sig) -> Result<()> {
    // Validate four words using four_word_networking crate
    if !fw_check(words.clone()) {
        anyhow::bail!("Invalid four words");
    }

    // Verify signature over UTF-8 words (joined with '-') using ML-DSA
    use crate::quantum_crypto::{MlDsa65, MlDsaOperations, MlDsaPublicKey, MlDsaSignature};

    let message = words.join("-");
    let pub_key = MlDsaPublicKey::from_bytes(_pubkey.as_bytes())
        .map_err(|e| anyhow::anyhow!("Invalid ML-DSA public key: {e}"))?;
    // ML-DSA-65 signature is 3309 bytes
    const ML_DSA_SIG_LEN: usize = 3309;
    if _sig.as_bytes().len() != ML_DSA_SIG_LEN {
        anyhow::bail!("Invalid ML-DSA signature length: {}", _sig.as_bytes().len());
    }
    let mut sig_arr = [0u8; ML_DSA_SIG_LEN];
    sig_arr.copy_from_slice(_sig.as_bytes());
    let sig = MlDsaSignature(Box::new(sig_arr));
    let ml = MlDsa65::new();
    let ok = ml
        .verify(&pub_key, message.as_bytes(), &sig)
        .map_err(|e| anyhow::anyhow!("ML-DSA verify failed: {e}"))?;
    if !ok {
        anyhow::bail!("Identity signature invalid");
    }

    // Compute identity key and device-set root
    let id_key = fw_to_key(words.clone())?;
    let device_set_root = crate::fwid::compute_key("device-set", id_key.as_bytes());

    // Build packet and store as CBOR in DHT
    let pkt = IdentityPacketV1 {
        v: 1,
        words: [
            words[0].clone(),
            words[1].clone(),
            words[2].clone(),
            words[3].clone(),
        ],
        id: id_key.clone(),
        pk: _pubkey.as_bytes().to_vec(),
        sig: _sig.as_bytes().to_vec(),
        endpoints: Vec::new(),
        ep_sig: None,
        website_root: None,
        device_set_root,
    };

    let bytes = serde_cbor::to_vec(&pkt)?;

    // Store with quorum policy and publish event for watchers of this key
    let pol = PutPolicy {
        quorum: 3,
        ttl: None,
        auth: Box::new(crate::auth::SingleWriteAuth::new(_pubkey.clone())),
    };
    let _ = dht_put(id_key.clone(), Bytes::from(bytes.clone()), &pol).await?;
    crate::events::global_bus()
        .publish_dht_update(id_key.clone(), Bytes::from(bytes))
        .await?;

    Ok(())
}

/// Fetch an identity packet
pub async fn identity_fetch(key: Key) -> Result<IdentityPacketV1> {
    let bytes = dht_get(key.clone(), 1).await?;
    let pkt: IdentityPacketV1 = serde_cbor::from_slice(&bytes)?;
    Ok(pkt)
}

/// Publish a device forward
pub async fn device_publish_forward(id_key: Key, fwd: Forward) -> Result<()> {
    // Derive device-set key from identity key
    let device_set_key = crate::fwid::compute_key("device-set", id_key.as_bytes());

    // Fetch existing device set if present
    let existing = dht_get(device_set_key.clone(), 1).await.ok();
    let mut set: DeviceSetV1 = match existing {
        Some(bytes) if !bytes.is_empty() => serde_cbor::from_slice(&bytes)?,
        _ => DeviceSetV1 {
            v: 1,
            crdt: "or-set".to_string(),
            forwards: Vec::new(),
            sig: None,
        },
    };

    // OR-Set semantics: dedupe by (proto, addr)
    if let Some(existing_idx) = set
        .forwards
        .iter()
        .position(|e| e.proto == fwd.proto && e.addr == fwd.addr)
    {
        set.forwards[existing_idx] = fwd.clone();
    } else {
        set.forwards.push(fwd.clone());
    }

    // Store updated set (will be rejected by dht_put without signature)
    let bytes = serde_cbor::to_vec(&set)?;
    let pol = PutPolicy {
        quorum: 3,
        ttl: None,
        auth: Box::new(crate::auth::DelegatedWriteAuth::new(vec![])),
    };
    let _ = dht_put(device_set_key.clone(), Bytes::from(bytes.clone()), &pol).await?;
    crate::events::global_bus()
        .publish_dht_update(device_set_key, Bytes::from(bytes))
        .await?;

    // Publish forward event for subscribers to this identity
    crate::events::global_bus()
        .publish_forward_for(id_key, fwd.clone())
        .await?;

    Ok(())
}

/// Signed variant for updating device forwards. The signature must be over
/// the canonical message: b"device-set" || key || canonical_cbor(forwards)
pub async fn device_publish_forward_signed(id_key: Key, fwd: Forward, sig: Sig) -> Result<()> {
    // Derive device-set key and fetch existing
    let device_set_key = crate::fwid::compute_key("device-set", id_key.as_bytes());
    let existing = dht_get(device_set_key.clone(), 1).await.ok();
    let mut set: DeviceSetV1 = match existing {
        Some(bytes) if !bytes.is_empty() => serde_cbor::from_slice(&bytes)?,
        _ => DeviceSetV1 {
            v: 1,
            crdt: "or-set".to_string(),
            forwards: Vec::new(),
            sig: None,
        },
    };
    // OR-Set semantics
    if let Some(idx) = set
        .forwards
        .iter()
        .position(|e| e.proto == fwd.proto && e.addr == fwd.addr)
    {
        set.forwards[idx] = fwd.clone();
    } else {
        set.forwards.push(fwd.clone());
    }

    set.sig = Some(sig.as_bytes().to_vec());

    // Store with delegated auth policy (keys managed by auth adapter)
    let bytes = serde_cbor::to_vec(&set)?;
    let pol = PutPolicy {
        quorum: 3,
        ttl: None,
        auth: Box::new(crate::auth::DelegatedWriteAuth::new(vec![])),
    };
    let _ = dht_put(device_set_key, Bytes::from(bytes), &pol).await?;

    Ok(())
}

/// Publish publicly reachable endpoints for an identity.
/// Computes four-word representations for IPv4 endpoints for user display.
pub async fn identity_publish_endpoints_signed(
    id_key: Key,
    mut endpoints: Vec<NetworkEndpoint>,
    ep_sig: Sig,
) -> Result<()> {
    // Compute four-word representations where possible
    #[allow(clippy::collapsible_if)]
    for ep in endpoints.iter_mut() {
        if let Some((ref ip, port)) = ep.ipv4 {
            if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
                let enc = four_word_networking::FourWordEncoder::new()
                    .encode_ipv4(addr, port)
                    .map_err(|e| anyhow::anyhow!("four-word encode ipv4 failed: {e}"))?;
                ep.fw4 = Some(enc.to_string().replace(' ', "-"));
            }
        }
        if let Some((ref ip6, port6)) = ep.ipv6 {
            if let Ok(addr6) = ip6.parse::<std::net::Ipv6Addr>() {
                use four_word_networking::four_word_ipv6_encoder::FourWordIpv6Encoder;
                let enc6 = FourWordIpv6Encoder::new()
                    .encode(&std::net::SocketAddrV6::new(addr6, port6, 0, 0))
                    .map_err(|e| anyhow::anyhow!("four-word encode ipv6 failed: {e}"))?;
                ep.fw6 = Some(enc6.to_dashed_string());
            }
        }
    }

    // Load existing identity packet
    let mut pkt = identity_fetch(id_key.clone()).await?;

    // Verify ep_sig over (id || pk || CBOR(endpoints)) using stored pk
    let mut msg = Vec::with_capacity(32 + pkt.pk.len() + 64);
    msg.extend_from_slice(pkt.id.as_bytes());
    msg.extend_from_slice(&pkt.pk);
    let ep_cbor = serde_cbor::to_vec(&endpoints)?;
    msg.extend_from_slice(&ep_cbor);

    use crate::quantum_crypto::{MlDsa65, MlDsaOperations, MlDsaPublicKey, MlDsaSignature};
    let pk = MlDsaPublicKey::from_bytes(&pkt.pk)
        .map_err(|e| anyhow::anyhow!("Invalid ML-DSA pubkey: {e}"))?;
    const SIG_LEN: usize = 3309;
    if ep_sig.as_bytes().len() != SIG_LEN {
        anyhow::bail!("Invalid endpoints signature length");
    }
    let mut arr = [0u8; SIG_LEN];
    arr.copy_from_slice(ep_sig.as_bytes());
    let sig = MlDsaSignature(Box::new(arr));
    let ml = MlDsa65::new();
    let ok = ml
        .verify(&pk, &msg, &sig)
        .map_err(|e| anyhow::anyhow!("Endpoints signature verify failed: {e}"))?;
    if !ok {
        anyhow::bail!("Endpoints signature invalid");
    }

    pkt.endpoints = endpoints;
    pkt.ep_sig = Some(sig.0.to_vec());

    // Store back to DHT
    let bytes = serde_cbor::to_vec(&pkt)?;
    let pol = PutPolicy {
        quorum: 3,
        ttl: None,
        auth: Box::new(crate::auth::SingleWriteAuth::new(PubKey::new(
            pkt.pk.clone(),
        ))),
    };
    let _ = dht_put(id_key.clone(), Bytes::from(bytes.clone()), &pol).await?;
    crate::events::global_bus()
        .publish_dht_update(id_key, Bytes::from(bytes))
        .await?;

    Ok(())
}

/// Subscribe to device forwards
pub async fn device_subscribe(id_key: Key) -> Subscription<Forward> {
    crate::events::device_subscribe(id_key).await
}

// ============================================================================
// DHT API
// ============================================================================

/// Store data in the DHT with policy
pub async fn dht_put(key: Key, _bytes: Bytes, _policy: &PutPolicy) -> Result<PutReceipt> {
    static GLOBAL_TWDHT: Lazy<Arc<TwDht>> = Lazy::new(|| {
        // Use a deterministic local NodeId for the embedded DHT instance
        Arc::new(TwDht::new(NodeId([7u8; 32])))
    });
    static DHT_REGISTRY: OnceCell<Arc<TwDht>> = OnceCell::new();
    let dht = DHT_REGISTRY
        .get()
        .cloned()
        .unwrap_or_else(|| GLOBAL_TWDHT.clone());

    let dht_key: [u8; 32] = *key.as_bytes();
    let pol = twdht_mod::PutPolicy {
        ttl: _policy.ttl,
        quorum: _policy.quorum,
    };

    // Attempt to extract signatures from known CBOR records
    let mut sigs: Vec<crate::auth::Sig> = Vec::new();
    // By default verify over raw bytes; some records override this with
    // canonical content to avoid including signatures (malleability).
    let mut record_for_auth: Cow<'_, [u8]> = Cow::Borrowed(&_bytes);
    // Group identity enforcement
    if let Ok(gip) = serde_cbor::from_slice::<GroupIdentityPacketV1>(&_bytes) {
        if !fw_check([
            gip.words[0].clone(),
            gip.words[1].clone(),
            gip.words[2].clone(),
            gip.words[3].clone(),
        ]) {
            telemetry::telemetry().record_auth_failure();
            anyhow::bail!("Invalid group words");
        }
        let id_calc = fw_to_key([
            gip.words[0].clone(),
            gip.words[1].clone(),
            gip.words[2].clone(),
            gip.words[3].clone(),
        ])?;
        if id_calc != gip.id {
            telemetry::telemetry().record_auth_failure();
            anyhow::bail!("Group id mismatch");
        }
        let root_calc = compute_membership_root(&gip.members);
        if root_calc != gip.membership_root {
            telemetry::telemetry().record_auth_failure();
            anyhow::bail!("membership_root mismatch");
        }
        const SIG_LEN: usize = 3309;
        if gip.group_sig.len() != SIG_LEN {
            telemetry::telemetry().record_auth_failure();
            anyhow::bail!("Invalid group signature length");
        }
        let pk = MlDsaPublicKey::from_bytes(&gip.group_pk)
            .map_err(|e| anyhow::anyhow!("Invalid group public key: {e}"))?;
        let mut arr = [0u8; SIG_LEN];
        arr.copy_from_slice(&gip.group_sig);
        let sig = MlDsaSignature(Box::new(arr));
        let ml = MlDsa65::new();
        let msg = group_identity_canonical_message(&gip.id, &gip.membership_root);
        let ok = ml
            .verify(&pk, &msg, &sig)
            .map_err(|e| anyhow::anyhow!("Group signature verify failed: {e}"))?;
        if !ok {
            telemetry::telemetry().record_auth_failure();
            anyhow::bail!("Group signature invalid");
        }
        // Use canonical bytes for WriteAuth
        record_for_auth = Cow::Owned(msg);
        sigs.push(crate::auth::Sig::new(gip.group_sig.clone()));
    }

    // Identity verification: enforce words validity, id match, and signature over utf8(words)
    if let Ok(pkt) = serde_cbor::from_slice::<IdentityPacketV1>(&_bytes) {
        // 1) validate words via four-word networking
        if !fw_check([
            pkt.words[0].clone(),
            pkt.words[1].clone(),
            pkt.words[2].clone(),
            pkt.words[3].clone(),
        ]) {
            telemetry::telemetry().record_auth_failure();
            anyhow::bail!("Invalid four words in identity packet");
        }
        // 2) ensure id matches blake3(utf8(words))
        let id_calc = fw_to_key([
            pkt.words[0].clone(),
            pkt.words[1].clone(),
            pkt.words[2].clone(),
            pkt.words[3].clone(),
        ])?;
        if id_calc != pkt.id {
            telemetry::telemetry().record_auth_failure();
            anyhow::bail!("Identity key mismatch for words");
        }
        // 3) verify signature over utf8(words)
        use crate::auth::Sig as AuthSig;
        use crate::quantum_crypto::{MlDsa65, MlDsaOperations, MlDsaPublicKey, MlDsaSignature};
        let pk = MlDsaPublicKey::from_bytes(&pkt.pk)
            .map_err(|e| anyhow::anyhow!("Invalid ML-DSA pubkey: {e}"))?;
        const SIG_LEN: usize = 3309;
        if pkt.sig.len() != SIG_LEN {
            telemetry::telemetry().record_auth_failure();
            anyhow::bail!("Invalid ML-DSA signature length");
        }
        let mut arr = [0u8; SIG_LEN];
        arr.copy_from_slice(&pkt.sig);
        let sig = MlDsaSignature(Box::new(arr));
        let ml = MlDsa65::new();
        let msg = pkt.words.join("-");
        let ok = ml
            .verify(&pk, msg.as_bytes(), &sig)
            .map_err(|e| anyhow::anyhow!("ML-DSA verify failed: {e}"))?;
        if !ok {
            telemetry::telemetry().record_auth_failure();
            anyhow::bail!("Identity signature invalid");
        }
        // Prepare sigs vector for WriteAuth verification and switch to message utf8(words)
        sigs.push(AuthSig::new(pkt.sig.clone()));
        record_for_auth = Cow::Owned(pkt.words.join("-").into_bytes());

        // If endpoints present, ep_sig must be present and valid
        if !pkt.endpoints.is_empty() {
            let ep_sig = pkt
                .ep_sig
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing endpoints signature"))?;
            // verify ep_sig over (id || pk || CBOR(endpoints))
            use crate::quantum_crypto::{MlDsa65, MlDsaOperations, MlDsaPublicKey, MlDsaSignature};
            let pk = MlDsaPublicKey::from_bytes(&pkt.pk)
                .map_err(|e| anyhow::anyhow!("Invalid ML-DSA pubkey: {e}"))?;
            const SIG_LEN: usize = 3309;
            if ep_sig.len() != SIG_LEN {
                telemetry::telemetry().record_auth_failure();
                anyhow::bail!("Invalid endpoints signature length");
            }
            let mut arr = [0u8; SIG_LEN];
            arr.copy_from_slice(ep_sig);
            let sig = MlDsaSignature(Box::new(arr));
            let ml = MlDsa65::new();
            let mut msg = Vec::with_capacity(32 + pkt.pk.len() + 64);
            msg.extend_from_slice(pkt.id.as_bytes());
            msg.extend_from_slice(&pkt.pk);
            let ep_cbor = serde_cbor::to_vec(&pkt.endpoints)?;
            msg.extend_from_slice(&ep_cbor);
            let ok = ml
                .verify(&pk, &msg, &sig)
                .map_err(|e| anyhow::anyhow!("Endpoints signature verify failed: {e}"))?;
            if !ok {
                telemetry::telemetry().record_auth_failure();
                anyhow::bail!("Endpoints signature invalid");
            }
            // Include ep_sig in sigs vector for WriteAuth if needed
            sigs.push(AuthSig::new(ep_sig.clone()));
        }
    }

    // DeviceSet verification: verify signature over canonical content that excludes signature field
    if let Ok(ds) = serde_cbor::from_slice::<DeviceSetV1>(&_bytes) {
        use crate::auth::Sig as AuthSig;
        // Require signature
        let ds_sig = ds
            .sig
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing device-set signature"))?;
        // Build canonical CBOR of forwards
        let mut forwards_sorted = ds.forwards.clone();
        forwards_sorted.sort_by(|a, b| {
            a.proto
                .cmp(&b.proto)
                .then_with(|| a.addr.cmp(&b.addr))
                .then_with(|| a.exp.cmp(&b.exp))
        });
        let buf = serde_cbor::to_vec(&forwards_sorted)?;
        // Build auth message: b"device-set" || key || canonical(forwards)
        let mut msg = Vec::with_capacity(9 + 32 + buf.len());
        msg.extend_from_slice(b"device-set");
        msg.extend_from_slice(key.as_bytes());
        msg.extend_from_slice(&buf);
        record_for_auth = Cow::Owned(msg);
        sigs.push(AuthSig::new(ds_sig.clone()));
    }

    // If Group types, extract MLS proof and include in sigs for WriteAuth
    if let Ok(gpkt) = serde_cbor::from_slice::<GroupPacketV1>(&_bytes) {
        if let Some(p) = gpkt.proof.as_ref() {
            sigs.push(crate::auth::Sig::new(p.clone()));
        }
    } else if let Ok(gfwd) = serde_cbor::from_slice::<GroupForwardsV1>(&_bytes)
        && let Some(p) = gfwd.proof.as_ref()
    {
        sigs.push(crate::auth::Sig::new(p.clone()));
    }

    // Enforce write authorization policy before storing
    match _policy.auth.verify(&record_for_auth, &sigs).await {
        Ok(true) => {}
        Ok(false) => {
            telemetry::telemetry().record_auth_failure();
            anyhow::bail!("Write authorization failed")
        }
        Err(e) => {
            telemetry::telemetry().record_auth_failure();
            return Err(e);
        }
    }

    let rec = dht.put(dht_key, _bytes.clone(), pol).await?;
    // Notify watchers for this key
    crate::events::global_bus()
        .publish_dht_update(key.clone(), _bytes.clone())
        .await?;

    // Telemetry counter
    telemetry::telemetry().record_dht_put();

    let storing_nodes = rec
        .providers
        .into_iter()
        .map(|nid| nid.0.to_vec())
        .collect();

    Ok(PutReceipt {
        key,
        timestamp: chrono::Utc::now().timestamp() as u64,
        storing_nodes,
    })
}

/// Retrieve data from the DHT
pub async fn dht_get(_key: Key, quorum: usize) -> Result<Bytes> {
    static DHT_REGISTRY: OnceCell<Arc<TwDht>> = OnceCell::new();
    let dht = DHT_REGISTRY.get().cloned().unwrap_or_else(|| {
        static GLOBAL_TWDHT: Lazy<Arc<TwDht>> =
            Lazy::new(|| Arc::new(TwDht::new(NodeId([7u8; 32]))));
        GLOBAL_TWDHT.clone()
    });

    let dht_key: [u8; 32] = *_key.as_bytes();
    let bytes = dht.get(dht_key, quorum).await?;

    // Telemetry counter
    telemetry::telemetry().record_dht_get();

    Ok(bytes)
}

/// Watch a DHT key for changes
pub async fn dht_watch(key: Key) -> Subscription<Bytes> {
    crate::events::dht_watch(key).await
}

/// Install a DHT instance to be used by the global API functions
pub fn set_dht_instance(dht: Arc<TwDht>) -> bool {
    static DHT_REGISTRY: OnceCell<Arc<TwDht>> = OnceCell::new();
    DHT_REGISTRY.set(dht).is_ok()
}

// ============================================================================
// Routing & Trust API
// ============================================================================

/// Record an interaction outcome for trust tracking
pub async fn record_interaction(peer: Vec<u8>, outcome: Outcome) -> Result<()> {
    use crate::adaptive::TrustProvider;
    use crate::peer_record::UserId;
    use std::collections::HashSet;

    // Create UserId from peer bytes
    let peer_id = if peer.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&peer);
        UserId { hash: arr }
    } else {
        // Handle invalid peer ID
        return Err(anyhow::anyhow!("Invalid peer ID length"));
    };

    // Get local node ID (using a fixed ID for this context)
    let local_id = UserId { hash: [0u8; 32] };

    // Update trust based on outcome
    let success = matches!(outcome, Outcome::Ok);

    // Create a local trust engine instance for this interaction
    let mut pre_trusted = HashSet::new();
    pre_trusted.insert(UserId { hash: [1u8; 32] });
    let trust_engine = EigenTrustEngine::new(pre_trusted);
    trust_engine.update_trust(&local_id, &peer_id, success);

    // Record telemetry based on outcome
    match outcome {
        Outcome::Ok => {
            // Success - no special telemetry
        }
        Outcome::Timeout => {
            telemetry::telemetry().record_timeout();
        }
        Outcome::BadData | Outcome::Refused => {
            telemetry::telemetry().record_auth_failure();
        }
    }

    Ok(())
}

/// Run EigenTrust epoch computation
pub async fn eigen_trust_epoch() -> Result<()> {
    // The EigenTrustEngine's update happens via update_trust calls
    // There's no explicit update_global_trust method exposed

    // Record telemetry for the operation
    telemetry::telemetry().record_dht_get(); // Using available telemetry method

    Ok(())
}

/// Get next hop for routing to target
pub fn route_next_hop(target: Vec<u8>) -> Option<Contact> {
    // Get the global DHT and Trust instances
    static DHT_REGISTRY: OnceCell<Arc<TwDht>> = OnceCell::new();
    static TRUST_ENGINE: Lazy<Arc<EigenTrustEngine>> = Lazy::new(|| {
        use std::collections::HashSet;
        let mut pre_trusted = HashSet::new();
        pre_trusted.insert(UserId { hash: [7u8; 32] });
        Arc::new(EigenTrustEngine::new(pre_trusted))
    });

    let _dht = DHT_REGISTRY.get().cloned().unwrap_or_else(|| {
        static GLOBAL_TWDHT: Lazy<Arc<TwDht>> =
            Lazy::new(|| Arc::new(TwDht::new(NodeId([7u8; 32]))));
        GLOBAL_TWDHT.clone()
    });

    // Convert target to NodeId
    let target_id = if target.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&target);
        UserId { hash: arr }
    } else {
        return None; // Invalid target ID
    };

    // Get closest nodes from DHT routing table
    // Simplify: generate deterministic closest nodes based on target
    // In production, would use proper DHT routing table
    let mut closest_nodes = Vec::new();
    for i in 0..3 {
        let mut node_bytes = target_id.hash;
        node_bytes[0] = node_bytes[0].wrapping_add(i);
        closest_nodes.push(UserId { hash: node_bytes });
    }

    if closest_nodes.is_empty() {
        return None;
    }

    // Apply trust weighting to select the best next hop
    let mut best_node = None;
    let mut best_score = 0.0;

    for node in closest_nodes {
        // Compute composite score: distance + trust
        let distance_score = 1.0
            / (1.0 + {
                // Calculate XOR distance manually
                let node_bytes = node.hash;
                let target_bytes = target_id.hash;
                let mut xor_distance = 0u32;
                for i in 0..32 {
                    xor_distance += (node_bytes[i] ^ target_bytes[i]) as u32;
                }
                xor_distance
            } as f64);
        let trust_engine = &*TRUST_ENGINE;
        let trust_score = trust_engine.get_trust(&node);
        let composite_score = 0.6 * distance_score + 0.4 * trust_score;

        if composite_score > best_score {
            best_score = composite_score;
            best_node = Some(node);
        }
    }

    // Return the best node as a Contact
    best_node.map(|node| {
        // Default endpoint for now, in production would query DHT metadata
        let endpoint = "127.0.0.1:9000".to_string();

        Contact {
            node_id: node.hash.to_vec(),
            endpoint,
        }
    })
}

// ============================================================================
// Transport API (placeholder - actual implementation in transport module)
// ============================================================================

/// QUIC endpoint type
pub struct Endpoint {
    pub address: String,
}

/// QUIC connection type
pub struct Conn {
    pub peer: Vec<u8>,
}

/// QUIC stream type
pub struct Stream {
    pub id: u64,
    pub class: StreamClass,
}

/// Connect to QUIC endpoint
pub async fn quic_connect(ep: &Endpoint) -> Result<Conn> {
    // Create or get the global P2P node instance
    use crate::transport::ant_quic_adapter::P2PNetworkNode;
    use std::net::SocketAddr;

    static P2P_NODE: OnceCell<Arc<P2PNetworkNode>> = OnceCell::new();

    let node = P2P_NODE
        .get_or_try_init(|| {
            // Create P2P node with default local address
            let bind_addr: SocketAddr = "0.0.0.0:0"
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid bind address: {} ({e})", "0.0.0.0:0"))?;
            let node_res = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async { P2PNetworkNode::new(bind_addr).await })
            });
            let node = node_res.map_err(|e| anyhow::anyhow!("Failed to create P2P node: {e}"))?;
            Ok::<Arc<P2PNetworkNode>, anyhow::Error>(Arc::new(node))
        })
        .map_err(|e| anyhow::anyhow!("P2P node init error: {e}"))?;

    // Parse endpoint address and connect
    let addr: SocketAddr = ep
        .address
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid endpoint address '{}': {e}", ep.address))?;

    let peer_id = node.connect_to_peer(addr).await?;

    // Store peer ID as connection identifier
    // Store PeerId as bytes (use debug format for now)
    let peer_bytes = format!("{:?}", peer_id).into_bytes();
    Ok(Conn { peer: peer_bytes })
}

/// Open a stream with specified class
pub async fn quic_open(conn: &Conn, class: StreamClass) -> Result<Stream> {
    use crate::transport::ant_quic_adapter::P2PNetworkNode;

    static P2P_NODE: OnceCell<Arc<P2PNetworkNode>> = OnceCell::new();

    let _node = P2P_NODE
        .get()
        .ok_or_else(|| anyhow::anyhow!("P2P node not initialized"))?;

    // For now, we'll treat the peer connection as valid if we have any peer data
    // In production, would properly deserialize the PeerId
    if conn.peer.is_empty() {
        return Err(anyhow::anyhow!("Invalid peer connection"));
    }

    // Check if peer is connected
    // Skip peer validation for now - assume connection is valid

    // Generate a unique stream ID based on timestamp and class
    let stream_id = {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let class_id = match class {
            StreamClass::Control => 0,
            StreamClass::Mls => 1,
            StreamClass::File => 2,
            StreamClass::Media => 3,
        };
        (timestamp << 4) | class_id
    };

    // Record telemetry for stream creation
    telemetry::telemetry()
        .record_stream_class_usage(class)
        .await;

    Ok(Stream {
        id: stream_id,
        class,
    })
}

// ============================================================================
// Storage Control API
// ============================================================================

/// Select nodes for shard placement
pub fn place_shards(object_id: [u8; 32], count: usize) -> Vec<Vec<u8>> {
    // Get global trust engine instance
    static TRUST_ENGINE: Lazy<Arc<EigenTrustEngine>> = Lazy::new(|| {
        use std::collections::HashSet;
        let mut pre_trusted = HashSet::new();
        pre_trusted.insert(UserId { hash: [7u8; 32] });
        Arc::new(EigenTrustEngine::new(pre_trusted))
    });

    // Simplified placement without full PlacementEngine integration

    // Get available nodes from DHT
    static DHT_REGISTRY: OnceCell<Arc<TwDht>> = OnceCell::new();
    let _dht = DHT_REGISTRY.get().cloned().unwrap_or_else(|| {
        static GLOBAL_TWDHT: Lazy<Arc<TwDht>> =
            Lazy::new(|| Arc::new(TwDht::new(NodeId([7u8; 32]))));
        GLOBAL_TWDHT.clone()
    });

    // Get candidate nodes from DHT (closest to object_id)
    let target_id = UserId { hash: object_id };
    // Simplify: generate deterministic candidates based on object_id
    // In production, would use proper DHT routing table
    let mut candidates = Vec::new();
    for i in 0..(count * 3) {
        let mut node_bytes = object_id;
        node_bytes[0] = node_bytes[0].wrapping_add(i as u8);
        candidates.push(UserId { hash: node_bytes });
    }

    if candidates.len() < count {
        // Fallback: generate deterministic nodes if not enough real nodes
        let mut nodes = Vec::new();
        for i in 0..count {
            let mut node_id = object_id;
            node_id[0] = node_id[0].wrapping_add(i as u8);
            nodes.push(node_id.to_vec());
        }
        return nodes;
    }

    // Select nodes based on trust scores and XOR distance
    // This is a simplified version that doesn't need full placement engine integration
    let mut scored_candidates: Vec<(UserId, f64)> = candidates
        .into_iter()
        .map(|node| {
            let trust_engine = &*TRUST_ENGINE;
            let trust_score = trust_engine.get_trust(&node);
            let distance_score = 1.0
                / (1.0 + {
                    // Calculate XOR distance manually
                    let node_bytes = node.hash;
                    let target_bytes = target_id.hash;
                    let mut xor_distance = 0u32;
                    for i in 0..32 {
                        xor_distance += (node_bytes[i] ^ target_bytes[i]) as u32;
                    }
                    xor_distance
                } as f64);
            let composite_score = 0.6 * trust_score + 0.4 * distance_score;
            (node, composite_score)
        })
        .collect();

    // Sort by score (highest first) and take the requested count
    scored_candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    scored_candidates
        .into_iter()
        .take(count)
        .map(|(node, _score)| node.hash.to_vec())
        .collect()
}

/// Advertise available storage space
pub fn provider_advertise_space(free: u64, total: u64) {
    // Create a provider capacity record
    #[derive(serde::Serialize)]
    struct ProviderCapacity {
        node_id: Vec<u8>,
        free_bytes: u64,
        total_bytes: u64,
        timestamp: u64,
    }

    // Use a fixed local node ID for now
    let node_id = vec![7u8; 32];

    let capacity = ProviderCapacity {
        node_id: node_id.clone(),
        free_bytes: free,
        total_bytes: total,
        timestamp: chrono::Utc::now().timestamp() as u64,
    };

    // Serialize and publish to DHT under a well-known key pattern
    if let Ok(bytes) = serde_cbor::to_vec(&capacity) {
        // Key pattern: "provider-capacity-" + node_id
        let mut key_data = b"provider-capacity-".to_vec();
        key_data.extend_from_slice(&node_id);
        let key = Key::new(blake3::hash(&key_data).into());

        // Fire and forget - publish capacity info asynchronously
        tokio::spawn(async move {
            let policy = PutPolicy {
                quorum: 1,
                ttl: Some(std::time::Duration::from_secs(3600)), // 1 hour TTL
                auth: Box::new(crate::auth::SingleWriteAuth::new(PubKey::new(vec![]))), // Public record
            };
            let _ = dht_put(key, Bytes::from(bytes), &policy).await;
        });
    }
}

/// Create repair plan for object
pub fn repair_request(object_id: [u8; 32]) -> RepairPlan {
    // Get current shard locations from DHT
    static DHT_REGISTRY: OnceCell<Arc<TwDht>> = OnceCell::new();
    let _dht = DHT_REGISTRY.get().cloned().unwrap_or_else(|| {
        static GLOBAL_TWDHT: Lazy<Arc<TwDht>> =
            Lazy::new(|| Arc::new(TwDht::new(NodeId([7u8; 32]))));
        GLOBAL_TWDHT.clone()
    });

    // Query for shard metadata (in production, this would involve DHT lookups)
    let mut missing_shards = Vec::new();
    let mut repair_nodes = Vec::new();

    // Check each shard (assuming 8 shards for demo)
    for shard_id in 0..8u8 {
        // Simplified repair check - in production would do actual DHT queries
        // For now, simulate that shards 3 and 6 are missing
        if shard_id == 3 || shard_id == 6 {
            missing_shards.push(shard_id as usize);

            // Generate a deterministic repair node based on shard_id
            let mut repair_node = object_id;
            repair_node[0] = repair_node[0].wrapping_add(shard_id);
            repair_nodes.push(repair_node.to_vec());
        }
    }

    RepairPlan {
        object_id,
        missing_shards,
        repair_nodes,
    }
}

// ============================================================================
// Friend Mesh Backup API
// ============================================================================

/// Friend mesh member info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendMeshMember {
    pub member_id: Key,
    pub public_key: Vec<u8>,
    pub endpoint: Option<String>,
    pub storage_commitment: u64, // bytes
}

/// Friend mesh configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendMeshConfig {
    pub mesh_id: Key,
    pub members: Vec<FriendMeshMember>,
    pub replication_factor: usize,
    pub rotation_schedule: Duration,
}

/// Get friend mesh backup plan for data
pub fn friend_mesh_plan(data_size: u64, mesh_config: &FriendMeshConfig) -> FriendBackupPlan {
    let shard_size = data_size / mesh_config.replication_factor as u64;
    let mut assignments = Vec::new();

    // Simple round-robin assignment for now
    for (idx, member) in mesh_config.members.iter().enumerate() {
        if idx < mesh_config.replication_factor {
            assignments.push(FriendBackupAssignment {
                member_id: member.member_id.clone(),
                shard_indices: vec![idx],
                shard_size,
                next_rotation: chrono::Utc::now().timestamp() as u64
                    + mesh_config.rotation_schedule.as_secs(),
            });
        }
    }

    FriendBackupPlan {
        mesh_id: mesh_config.mesh_id.clone(),
        total_shards: mesh_config.replication_factor,
        shard_size,
        assignments,
    }
}

/// Friend backup plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendBackupPlan {
    pub mesh_id: Key,
    pub total_shards: usize,
    pub shard_size: u64,
    pub assignments: Vec<FriendBackupAssignment>,
}

/// Friend backup assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendBackupAssignment {
    pub member_id: Key,
    pub shard_indices: Vec<usize>,
    pub shard_size: u64,
    pub next_rotation: u64,
}

// ============================================================================
// Hyperbolic Routing Assist
// ============================================================================

/// Enable hyperbolic routing assist for improved greedy routing
#[cfg(feature = "h2_greedy")]
pub fn enable_hyperbolic_assist(_coordinates: Option<(f64, f64)>) -> Result<()> {
    // Greedy routing assist is currently not wired; this feature flag
    // exists to allow compiling optional helpers without pulling in
    // incomplete dependencies. No-op for now.
    Ok(())
}

/// Get hyperbolic distance to a target (for routing decisions)
#[cfg(feature = "h2_greedy")]
pub fn hyperbolic_distance(_target: Vec<u8>) -> Option<f64> {
    None
}

// ============================================================================
// Events API (already exposed through events module)
// ============================================================================

pub use crate::events::subscribe_topology;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_packet_serialization() {
        let packet = IdentityPacketV1 {
            v: 1,
            words: [
                "alpha".to_string(),
                "beta".to_string(),
                "gamma".to_string(),
                "delta".to_string(),
            ],
            pk: vec![5, 6, 7],
            sig: vec![8, 9, 10],
            id: Key::new([0u8; 32]),
            endpoints: vec![],
            ep_sig: None,
            website_root: None,
            device_set_root: Key::new([11u8; 32]),
        };

        let json = serde_json::to_string(&packet).unwrap();
        let recovered: IdentityPacketV1 = serde_json::from_str(&json).unwrap();

        assert_eq!(packet.v, recovered.v);
        assert_eq!(packet.words, recovered.words);
    }

    #[test]
    fn test_container_manifest() {
        let manifest = ContainerManifestV1 {
            v: 1,
            object: Key::new([1u8; 32]),
            fec: FecParams {
                k: 8,
                m: 4,
                shard_size: 65536,
            },
            assets: vec![Key::new([2u8; 32])],
            sealed_meta: None,
        };

        assert_eq!(manifest.fec.k, 8);
        assert_eq!(manifest.fec.m, 4);
    }
}
