// MLS verifier scaffolding and proof format

use crate::api::GroupIdentityPacketV1;
use anyhow::Result;
use saorsa_pqc::MlDsaOperations; // bring trait into scope for verify()
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Provider that supplies a snapshot of a group's identity packet
/// given a group_id (words hash).
pub trait MlsGroupStateProvider: Send + Sync {
    fn fetch_group_identity(&self, group_id: &[u8]) -> Result<GroupIdentityPacketV1>;
}

/// Supported proof modes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofMode {
    Member,
    Group,
}

/// CBOR-encoded MLS proof (version 1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsProofV1 {
    pub ver: u8,                      // must be 1
    pub mode: ProofMode,              // "member" or "group"
    pub cipher: u16,                  // ciphersuite id
    pub epoch: u64,                   // epoch being proven
    pub signer_id: Option<Vec<u8>>,   // member id for Member mode
    pub key_id: Option<Vec<u8>>,      // external key id for Group mode
    pub sig: Vec<u8>,                 // signature bytes
    pub roster_hash: Option<Vec<u8>>, // optional roster hash pin
    pub signer_pub: Option<Vec<u8>>,  // optional signer pub override
}

/// Default verifier using a provided group-state provider.
pub struct DefaultMlsVerifier {
    provider: Arc<dyn MlsGroupStateProvider>,
}

impl DefaultMlsVerifier {
    pub fn new(provider: Arc<dyn MlsGroupStateProvider>) -> Self {
        Self { provider }
    }

    fn make_msg(group_id: &[u8], epoch: u64, record: &[u8]) -> Vec<u8> {
        const DST: &[u8] = b"saorsa-mls:dht-proof:v1";
        let mut hasher = Sha256::new();
        hasher.update(record);
        let record_hash = hasher.finalize();
        let mut msg = Vec::with_capacity(DST.len() + group_id.len() + 8 + 32);
        msg.extend_from_slice(DST);
        msg.extend_from_slice(group_id);
        msg.extend_from_slice(&epoch.to_be_bytes());
        msg.extend_from_slice(&record_hash);
        msg
    }
}

impl crate::auth::MlsProofVerifier for DefaultMlsVerifier {
    fn verify(&self, group_id: &[u8], epoch: u64, proof: &[u8], record: &[u8]) -> Result<bool> {
        // Parse CBOR proof
        let proof: MlsProofV1 = match serde_cbor::from_slice(proof) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };
        if proof.ver != 1 || proof.epoch != epoch {
            return Ok(false);
        }

        // Fetch and validate the group identity snapshot
        let group = self.provider.fetch_group_identity(group_id)?;
        // Sanity: group id must match
        if group.id.as_bytes() != group_id {
            return Ok(false);
        }

        // Build canonical MLS message
        let msg = Self::make_msg(group_id, epoch, record);

        // Verify based on mode
        match proof.mode {
            ProofMode::Member => {
                // Resolve signer public key: proof.signer_pub OR lookup via signer_id in roster
                let signer_pk_bytes = if let Some(pk) = proof.signer_pub.as_ref() {
                    pk.as_slice()
                } else {
                    // Find member by signer_id
                    let sid = match &proof.signer_id {
                        Some(s) => s,
                        None => return Ok(false),
                    };
                    let member = match group
                        .members
                        .iter()
                        .find(|m| m.member_id.as_bytes() == sid.as_slice())
                    {
                        Some(m) => m,
                        None => return Ok(false),
                    };
                    member.member_pk.as_slice()
                };

                // Verify signature using saorsa-pqc ML-DSA
                let pk = match crate::quantum_crypto::MlDsaPublicKey::from_bytes(signer_pk_bytes) {
                    Ok(p) => p,
                    Err(_) => return Ok(false),
                };
                // Expect fixed ML-DSA-65 signature length
                const SIG_LEN: usize = 3309;
                if proof.sig.len() != SIG_LEN {
                    return Ok(false);
                }
                let mut arr = [0u8; SIG_LEN];
                arr.copy_from_slice(&proof.sig);
                let sig = crate::quantum_crypto::MlDsaSignature(Box::new(arr));
                let ml = crate::quantum_crypto::MlDsa65::new();
                let ok = ml.verify(&pk, &msg, &sig).unwrap_or(false);
                Ok(ok)
            }
            ProofMode::Group => {
                // Verify with group external key (not stored yet) – fallback to group_pk from identity
                let pk = match crate::quantum_crypto::MlDsaPublicKey::from_bytes(&group.group_pk) {
                    Ok(p) => p,
                    Err(_) => return Ok(false),
                };
                const SIG_LEN: usize = 3309;
                if proof.sig.len() != SIG_LEN {
                    return Ok(false);
                }
                let mut arr = [0u8; SIG_LEN];
                arr.copy_from_slice(&proof.sig);
                let sig = crate::quantum_crypto::MlDsaSignature(Box::new(arr));
                let ml = crate::quantum_crypto::MlDsa65::new();
                let ok = ml.verify(&pk, &msg, &sig).unwrap_or(false);
                Ok(ok)
            }
        }
    }
}
