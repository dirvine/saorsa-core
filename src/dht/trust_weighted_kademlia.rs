//! Trust-weighted Kademlia DHT with EigenTrust integration
//!
//! Implements XOR-based Kademlia with trust bias for routing, eviction, and provider selection.
//! Includes capacity signaling for PUT pricing and EigenTrust computation.

use crate::identity::node_identity::NodeId;
use anyhow::Result;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

/// DHT key type (256-bit)
pub type Key = [u8; 32];

/// Peer identifier
pub type PeerId = NodeId;

/// Contact information for routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub peer: PeerId,
    pub address: String,
    pub rtt_est: Duration,
    pub last_seen: SystemTime,
    pub trust_score: f32,
}

/// Capacity gossip message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityGossip {
    pub peer: PeerId,
    pub free_bytes: u64,
    pub total_bytes: u64,
    pub epoch: u64,
}

/// PUT operation policy
#[derive(Debug, Clone)]
pub struct PutPolicy {
    pub ttl: Option<Duration>,
    pub quorum: usize,
}

/// PUT operation receipt
#[derive(Debug, Clone)]
pub struct PutReceipt {
    pub key: Key,
    pub providers: Vec<PeerId>,
    pub proof: Vec<u8>,
}

/// Interaction outcome for trust recording
#[derive(Debug, Clone, Copy)]
pub enum Outcome {
    Ok,
    Timeout,
    BadData,
    Refused,
}

/// Trust-weighted Kademlia DHT implementation
pub struct TrustWeightedKademlia {
    /// Local node ID
    local_id: NodeId,
    /// Kademlia routing table (160 buckets for 160-bit prefix)
    routing_table: Arc<RwLock<[KBucket; 160]>>,
    /// Content storage
    storage: Arc<RwLock<HashMap<Key, (Bytes, SystemTime)>>>,
    /// Provider registry (what keys are provided by which peers)
    providers: Arc<RwLock<HashMap<Key, HashSet<PeerId>>>>,
    /// Trust matrix for EigenTrust computation
    trust_matrix: Arc<RwLock<HashMap<PeerId, HashMap<PeerId, f32>>>>,
    /// Capacity information
    capacities: Arc<RwLock<HashMap<PeerId, CapacityGossip>>>,
    /// Recent interactions for trust computation
    interactions: Arc<RwLock<VecDeque<(PeerId, Outcome, SystemTime)>>>,
    /// EigenTrust scores
    eigen_trust_scores: Arc<RwLock<HashMap<PeerId, f32>>>,
    /// Kademlia parameters
    k: usize, // bucket size
    _alpha: usize, // parallelism factor
}

/// Kademlia bucket with trust-weighted ordering
#[derive(Debug, Clone)]
struct KBucket {
    contacts: Vec<Contact>,
    _max_size: usize,
}

impl KBucket {
    fn new(max_size: usize) -> Self {
        Self {
            contacts: Vec::new(),
            _max_size: max_size,
        }
    }

    /// Add or update contact with trust bias
    fn _add_contact(&mut self, contact: Contact) {
        // Remove existing contact if present
        self.contacts.retain(|c| c.peer != contact.peer);

        // Insert in trust-biased order
        let insert_pos = self
            .contacts
            .iter()
            .position(|c| c.trust_score < contact.trust_score)
            .unwrap_or(self.contacts.len());

        self.contacts.insert(insert_pos, contact);

        // Evict least trusted if bucket is full
        if self.contacts.len() > self._max_size {
            self.contacts.pop();
        }
    }

    /// Get contacts sorted by trust bias
    fn _get_contacts(&self, count: usize) -> Vec<Contact> {
        self.contacts.iter().take(count).cloned().collect()
    }
}

impl TrustWeightedKademlia {
    /// Create new DHT instance
    pub fn new(local_id: NodeId) -> Self {
        let routing_table = Arc::new(RwLock::new(
            array_init::array_init(|_| KBucket::new(20)), // k=20
        ));

        Self {
            local_id,
            routing_table,
            storage: Arc::new(RwLock::new(HashMap::new())),
            providers: Arc::new(RwLock::new(HashMap::new())),
            trust_matrix: Arc::new(RwLock::new(HashMap::new())),
            capacities: Arc::new(RwLock::new(HashMap::new())),
            interactions: Arc::new(RwLock::new(VecDeque::new())),
            eigen_trust_scores: Arc::new(RwLock::new(HashMap::new())),
            k: 20,
            _alpha: 3,
        }
    }

    /// Record interaction outcome for trust computation
    pub async fn record_interaction(&self, peer: PeerId, outcome: Outcome) {
        let mut interactions = self.interactions.write().await;
        interactions.push_back((peer.clone(), outcome, SystemTime::now()));

        // Keep only recent interactions (last 1000)
        while interactions.len() > 1000 {
            interactions.pop_front();
        }

        // Update trust matrix
        self.update_trust_matrix(peer, outcome).await;
    }

    /// Update trust matrix based on interaction
    async fn update_trust_matrix(&self, peer: PeerId, outcome: Outcome) {
        let mut trust_matrix = self.trust_matrix.write().await;

        // Simple trust update: good outcomes increase trust, bad decrease
        let trust_delta = match outcome {
            Outcome::Ok => 0.1,
            Outcome::Timeout => -0.2,
            Outcome::BadData => -0.3,
            Outcome::Refused => -0.1,
        };

        let local_trust = trust_matrix
            .entry(self.local_id.clone())
            .or_insert_with(HashMap::new);
        let current_trust = local_trust.get(&peer).copied().unwrap_or(0.5);
        let new_trust = (current_trust + trust_delta).clamp(0.0, 1.0);
        local_trust.insert(peer, new_trust);
    }

    /// Compute EigenTrust scores using power iteration
    pub async fn eigen_trust_epoch(&self) {
        let trust_matrix = self.trust_matrix.read().await;
        let mut scores = HashMap::new();

        // Initialize with uniform trust
        let all_peers: HashSet<_> = trust_matrix.keys().collect();
        for peer in &all_peers {
            scores.insert((**peer).clone(), 1.0 / all_peers.len() as f32);
        }

        // Power iteration (simplified)
        for _ in 0..10 {
            let mut new_scores = HashMap::new();

            for peer in &all_peers {
                let mut score = 0.0;
                let mut total_weight = 0.0;

                for (rater, ratings) in &*trust_matrix {
                    if let Some(rating) = ratings.get(peer) {
                        let rater_score = scores.get(rater).copied().unwrap_or(0.5);
                        score += rater_score * rating;
                        total_weight += rater_score;
                    }
                }

                new_scores.insert(
                    (**peer).clone(),
                    if total_weight > 0.0 {
                        score / total_weight
                    } else {
                        0.5
                    },
                );
            }

            scores = new_scores;
        }

        // Update EigenTrust scores
        let mut eigen_trust_scores = self.eigen_trust_scores.write().await;
        *eigen_trust_scores = scores;
    }

    /// Find k closest nodes to target with trust bias
    async fn find_closest_nodes(&self, target: &NodeId, k: usize) -> Vec<Contact> {
        let routing_table = self.routing_table.read().await;
        let eigen_trust_scores = self.eigen_trust_scores.read().await;

        let mut candidates = Vec::new();

        // Collect candidates from appropriate buckets
        for bucket in &*routing_table {
            for contact in &bucket.contacts {
                candidates.push(contact.clone());
            }
        }

        // Sort by (XOR distance, -trust_score, RTT)
        candidates.sort_by(|a, b| {
            let a_distance = self.xor_distance(&a.peer, target);
            let b_distance = self.xor_distance(&b.peer, target);

            let a_trust = eigen_trust_scores.get(&a.peer).copied().unwrap_or(0.5);
            let b_trust = eigen_trust_scores.get(&b.peer).copied().unwrap_or(0.5);

            a_distance
                .cmp(&b_distance)
                .then_with(|| {
                    (-a_trust)
                        .partial_cmp(&(-b_trust))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| a.rtt_est.cmp(&b.rtt_est))
        });

        candidates.into_iter().take(k).collect()
    }

    /// Calculate XOR distance between two node IDs
    fn xor_distance(&self, a: &NodeId, b: &NodeId) -> [u8; 32] {
        let mut result = [0u8; 32];
        let a_bytes = a.to_bytes();
        let b_bytes = b.to_bytes();

        for (i, out) in result.iter_mut().enumerate() {
            *out = a_bytes[i] ^ b_bytes[i];
        }
        result
    }

    /// Update routing table with new contact
    async fn _update_routing_table(&self, contact: Contact) {
        let bucket_index = self._bucket_index(&contact.peer);
        let mut routing_table = self.routing_table.write().await;
        routing_table[bucket_index]._add_contact(contact);
    }
}

// NodeId::to_bytes() is already implemented in identity/node_identity.rs

impl TrustWeightedKademlia {
    fn _bucket_index(&self, peer: &NodeId) -> usize {
        // Calculate bucket index based on XOR distance from local node
        let distance = self.xor_distance(&self.local_id, peer);

        // Find the highest bit set in the distance
        for (i, &byte) in distance.iter().enumerate() {
            if byte != 0 {
                return i * 8 + (7 - byte.leading_zeros() as usize);
            }
        }

        0 // Fallback for identical nodes
    }
}

/// DHT trait implementation
#[async_trait::async_trait]
impl super::Dht for TrustWeightedKademlia {
    async fn put(&self, key: super::Key, value: Bytes, policy: super::PutPolicy) -> Result<super::PutReceipt> {
        // Find providers with capacity and trust bias
        // Convert key type
        let local_key: Key = key;
        let providers = self.select_providers(&local_key, policy.quorum).await?;

        // Store locally if we're a provider
        if providers.contains(&self.local_id) {
            let mut storage = self.storage.write().await;
            let ttl = policy.ttl.unwrap_or(Duration::from_secs(3600));
            storage.insert(local_key, (value.clone(), SystemTime::now() + ttl));
        }

        // Generate proof (simplified)
        let proof = vec![0u8; 32]; // TODO: Implement proper proof generation

        Ok(super::PutReceipt {
            key,
            providers,
            proof,
        })
    }

    async fn get(&self, key: super::Key, quorum: usize) -> Result<Bytes> {
        // Check local storage first
        let local_key: Key = key;
        {
            let storage = self.storage.read().await;
            if let Some((value, expiry)) = storage.get(&local_key) {
                if SystemTime::now() < *expiry {
                    return Ok(value.clone());
                }
            }
        }

        // Find providers
        let providers = self.find_providers(&local_key, quorum).await?;

        // Try to retrieve from providers (simplified)
        for _provider in providers {
            // In a real implementation, this would make network requests
            // For now, just return an error
        }

        Err(anyhow::anyhow!("Value not found"))
    }

    async fn find_node(&self, target: super::PeerId) -> Result<Vec<super::Contact>> {
        let closest = self.find_closest_nodes(&target, self.k).await;
        let converted: Vec<super::Contact> = closest.into_iter().map(|contact| super::Contact {
            peer: contact.peer,
            address: contact.address,
        }).collect();
        Ok(converted)
    }

    async fn provide(&self, key: super::Key) -> Result<()> {
        let local_key: Key = key;
        let mut providers = self.providers.write().await;
        providers
            .entry(local_key)
            .or_insert_with(HashSet::new)
            .insert(self.local_id.clone());
        Ok(())
    }
}

impl TrustWeightedKademlia {
    /// Select providers based on capacity and trust
    async fn select_providers(&self, key: &Key, count: usize) -> Result<Vec<PeerId>> {
        // Create a NodeId from the key bytes for XOR distance calculation
        let target_node = NodeId(*key);
        let providers = self.find_closest_nodes(&target_node, count * 2).await;

        let capacities = self.capacities.read().await;
        let eigen_trust_scores = self.eigen_trust_scores.read().await;

        // Filter by capacity and sort by trust
        let mut candidates: Vec<_> = providers
            .into_iter()
            .filter(|contact| {
                if let Some(capacity) = capacities.get(&contact.peer) {
                    capacity.free_bytes > 0
                } else {
                    false
                }
            })
            .collect();

        candidates.sort_by(|a, b| {
            let a_trust = eigen_trust_scores.get(&a.peer).copied().unwrap_or(0.5);
            let b_trust = eigen_trust_scores.get(&b.peer).copied().unwrap_or(0.5);
            b_trust
                .partial_cmp(&a_trust)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(candidates.into_iter().take(count).map(|c| c.peer).collect())
    }

    /// Find providers for a key
    async fn find_providers(&self, key: &Key, count: usize) -> Result<Vec<PeerId>> {
        let providers = self.providers.read().await;
        if let Some(key_providers) = providers.get(key) {
            let mut result: Vec<_> = key_providers.iter().cloned().collect();
            result.truncate(count);
            Ok(result)
        } else {
            Ok(Vec::new())
        }
    }
}

/// Global trust recording function
pub async fn record_interaction(_peer: PeerId, _outcome: Outcome) {
    // This would need to be implemented with a global DHT instance
    // For now, this is a placeholder
}

/// Global EigenTrust computation
pub async fn eigen_trust_epoch() {
    // This would need to be implemented with a global DHT instance
    // For now, this is a placeholder
}
