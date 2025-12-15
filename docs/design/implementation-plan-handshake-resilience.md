# Implementation Plan: Signed Handshake & Network Resilience

## Part 1: Signed Handshake Protocol

### Overview

Replace the current `AttestationHello` with a challenge-response signed protocol that proves:
1. Key ownership (signature verification)
2. Liveness (fresh challenge-response)
3. Identity consistency (derivation verification)

### Data Structures

```rust
// src/attestation/signed_handshake.rs

/// Challenge sent to initiate handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeChallenge {
    /// Random challenge bytes
    pub challenge: [u8; 32],

    /// Timestamp when challenge was created
    pub timestamp: u64,

    /// Our EntangledId (so peer knows who is asking)
    pub from_entangled_id: [u8; 32],
}

/// Signed response to a handshake challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHandshakeResponse {
    /// The hello data being attested
    pub hello: HandshakeHelloData,

    /// ML-DSA signature over (hello || challenge)
    pub signature: Vec<u8>,

    /// The challenge we're responding to
    pub challenge: [u8; 32],
}

/// Core attestation data in handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeHelloData {
    /// Our software-attested identity
    pub entangled_id: [u8; 32],

    /// Our ML-DSA-65 public key
    pub public_key: Vec<u8>,

    /// Binary hash used in EntangledId derivation
    pub binary_hash: [u8; 32],

    /// Nonce used in derivation
    pub derivation_nonce: u64,

    /// Fresh timestamp
    pub timestamp: u64,

    /// Random nonce for uniqueness
    pub nonce: [u8; 16],

    /// Protocol version (v3 for signed handshake)
    pub protocol_version: u8,

    /// Latest signed heartbeat (proves recent liveness)
    pub latest_heartbeat: Option<SignedHeartbeat>,
}

impl HandshakeHelloData {
    /// Create signing payload
    pub fn signing_payload(&self, challenge: &[u8; 32]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.entangled_id);
        payload.extend_from_slice(&self.public_key);
        payload.extend_from_slice(&self.binary_hash);
        payload.extend_from_slice(&self.derivation_nonce.to_le_bytes());
        payload.extend_from_slice(&self.timestamp.to_le_bytes());
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(challenge);
        payload
    }
}
```

### Verification Logic

```rust
/// Result of handshake verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeVerifyResult {
    /// Fully verified
    Valid,
    /// Challenge mismatch (wrong challenge responded to)
    ChallengeMismatch,
    /// Signature invalid
    InvalidSignature(String),
    /// Timestamp too old
    Stale,
    /// EntangledId derivation doesn't match
    DerivationMismatch,
    /// Binary not in allowed list
    BinaryNotAllowed,
}

pub struct SignedHandshakeVerifier {
    /// Allowed binary hashes (empty = allow all)
    allowed_binaries: HashSet<[u8; 32]>,

    /// Maximum hello age
    max_age_secs: u64,
}

impl SignedHandshakeVerifier {
    pub fn verify(
        &self,
        response: &SignedHandshakeResponse,
        expected_challenge: &[u8; 32],
    ) -> HandshakeVerifyResult {
        // 1. Challenge matches
        if response.challenge != *expected_challenge {
            return HandshakeVerifyResult::ChallengeMismatch;
        }

        // 2. Timestamp freshness
        let now = current_timestamp();
        if now.saturating_sub(response.hello.timestamp) > self.max_age_secs {
            return HandshakeVerifyResult::Stale;
        }

        // 3. Binary allowlist (if configured)
        if !self.allowed_binaries.is_empty()
            && !self.allowed_binaries.contains(&response.hello.binary_hash)
        {
            return HandshakeVerifyResult::BinaryNotAllowed;
        }

        // 4. EntangledId derivation check
        let derived = derive_entangled_id(
            &response.hello.public_key,
            &response.hello.binary_hash,
            response.hello.derivation_nonce,
        );
        if derived != response.hello.entangled_id {
            return HandshakeVerifyResult::DerivationMismatch;
        }

        // 5. Signature verification
        let public_key = match MlDsaPublicKey::from_bytes(&response.hello.public_key) {
            Ok(pk) => pk,
            Err(e) => return HandshakeVerifyResult::InvalidSignature(e.to_string()),
        };

        let payload = response.hello.signing_payload(&response.challenge);
        let signature = match MlDsaSignature::from_bytes(&response.signature) {
            Ok(sig) => sig,
            Err(e) => return HandshakeVerifyResult::InvalidSignature(e.to_string()),
        };

        match ml_dsa_verify(&public_key, &payload, &signature) {
            Ok(true) => HandshakeVerifyResult::Valid,
            Ok(false) => HandshakeVerifyResult::InvalidSignature("Signature mismatch".into()),
            Err(e) => HandshakeVerifyResult::InvalidSignature(e.to_string()),
        }
    }
}
```

### Protocol Flow

```rust
/// Handshake state machine
pub struct SignedHandshake {
    /// Our signer for creating responses
    signer: HeartbeatSigner,

    /// Our hello data (cached)
    local_hello: HandshakeHelloData,

    /// Verifier for peer responses
    verifier: SignedHandshakeVerifier,

    /// Pending outbound challenges (peer_id -> challenge)
    pending_challenges: HashMap<[u8; 32], HandshakeChallenge>,
}

impl SignedHandshake {
    /// Step 1: Create challenge to send to peer
    pub fn create_challenge(&mut self, peer_entangled_id: [u8; 32]) -> HandshakeChallenge {
        let mut challenge = [0u8; 32];
        for byte in &mut challenge {
            *byte = fastrand::u8(..);
        }

        let msg = HandshakeChallenge {
            challenge,
            timestamp: current_timestamp(),
            from_entangled_id: *self.signer.entangled_id(),
        };

        // Store for later verification
        self.pending_challenges.insert(peer_entangled_id, msg.clone());

        msg
    }

    /// Step 2: Respond to a challenge from peer
    pub fn respond_to_challenge(
        &self,
        challenge: &HandshakeChallenge,
    ) -> Result<SignedHandshakeResponse, AttestationError> {
        // Create fresh hello data
        let hello = self.local_hello.clone();

        // Sign (hello || challenge)
        let payload = hello.signing_payload(&challenge.challenge);
        let signature = ml_dsa_sign(self.signer.secret_key(), &payload)?;

        Ok(SignedHandshakeResponse {
            hello,
            signature: signature.as_bytes().to_vec(),
            challenge: challenge.challenge,
        })
    }

    /// Step 3: Verify peer's response
    pub fn verify_response(
        &mut self,
        peer_entangled_id: &[u8; 32],
        response: &SignedHandshakeResponse,
    ) -> HandshakeVerifyResult {
        // Get the challenge we sent
        let expected_challenge = match self.pending_challenges.remove(peer_entangled_id) {
            Some(c) => c.challenge,
            None => return HandshakeVerifyResult::ChallengeMismatch,
        };

        self.verifier.verify(response, &expected_challenge)
    }
}
```

---

## Part 2: Network Resilience with Quiescence Support

### Key Insight: Distinguish Downtime Types

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Downtime Types                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. PEER DOWN, WE'RE UP                                            │
│     - We're online, peer stops responding                           │
│     - Action: Gradual trust decay, eventual eviction               │
│                                                                     │
│  2. WE'RE DOWN, PEER STATUS UNKNOWN                                │
│     - We restart after being offline                                │
│     - Action: Don't penalize anyone, re-establish connections      │
│                                                                     │
│  3. NETWORK QUIESCENT                                              │
│     - Whole network offline (planned/unplanned)                     │
│     - Action: Preserve all trust scores, resume cleanly            │
│                                                                     │
│  4. NETWORK PARTITION                                              │
│     - We can reach some peers but not others                        │
│     - Action: Freeze scores, wait for healing                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Persistence Model

```rust
/// Persisted network state (survives restarts)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedNetworkState {
    /// When we last had healthy network activity
    pub last_healthy_activity: u64,

    /// When we shut down (set on graceful shutdown)
    pub shutdown_timestamp: Option<u64>,

    /// Peer states at last save
    pub peer_states: HashMap<[u8; 32], PersistedPeerState>,

    /// Our trust scores at last save
    pub trust_scores: HashMap<[u8; 32], f64>,

    /// Was this a graceful shutdown?
    pub graceful_shutdown: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPeerState {
    /// Peer's EntangledId
    pub entangled_id: [u8; 32],

    /// Peer's public key
    pub public_key: Vec<u8>,

    /// Last verified heartbeat epoch
    pub last_heartbeat_epoch: u64,

    /// Heartbeat streak at last save
    pub streak: u32,

    /// Trust score at last save
    pub trust_score: f64,

    /// Status at last save (for logging only, not for decisions)
    pub last_known_status: SignedPeerStatus,
}
```

### Startup Recovery Logic

```rust
impl SignedHeartbeatManager {
    /// Recover from persisted state
    pub async fn recover_from_persistence(
        signer: HeartbeatSigner,
        config: HeartbeatConfig,
        persisted: PersistedNetworkState,
    ) -> Self {
        let now = current_timestamp();
        let our_downtime = now.saturating_sub(
            persisted.shutdown_timestamp.unwrap_or(persisted.last_healthy_activity)
        );

        tracing::info!(
            downtime_secs = our_downtime,
            peer_count = persisted.peer_states.len(),
            graceful = persisted.graceful_shutdown,
            "Recovering network state after downtime"
        );

        let mut manager = Self::new(signer, config);

        // Restore peer states WITHOUT penalizing for our downtime
        for (peer_id, peer_state) in persisted.peer_states {
            // Key insight: Don't count epochs missed during our downtime
            // The peer might have been sending heartbeats - we just weren't there
            let restored = SignedPeerHeartbeatState {
                entangled_id: Some(peer_state.entangled_id),
                public_key: Some(peer_state.public_key),
                last_verified_epoch: peer_state.last_heartbeat_epoch,
                streak: 0,  // Reset streak - we don't know what happened
                missed_count: 0,  // Don't penalize for our downtime
                total_verified: 0,  // Start fresh
                recent_epochs: Vec::new(),
                status: SignedPeerStatus::Unknown,  // Re-verify on first contact
            };

            manager.peer_states.write().await.insert(peer_id, restored);
        }

        // Restore trust scores (these should persist through restarts)
        // Trust is earned over time and shouldn't be lost to downtime

        manager
    }
}
```

### Network Health Context

```rust
/// Runtime context for network health decisions
pub struct NetworkHealthContext {
    // === Peer Statistics ===
    pub total_tracked_peers: usize,
    pub healthy_peers: usize,
    pub suspect_peers: usize,
    pub unresponsive_peers: usize,
    pub unknown_peers: usize,

    // === Connectivity Indicators ===
    /// Can we reach external endpoints?
    pub external_connectivity: bool,

    /// How many bootstrap nodes can we reach?
    pub bootstrap_nodes_reachable: usize,

    /// Current gossip mesh size
    pub gossip_mesh_size: usize,

    /// Successful connections in last 5 minutes
    pub recent_connection_successes: usize,

    // === Trend Detection ===
    /// Healthy ratio now
    pub healthy_ratio_now: f64,

    /// Healthy ratio 1 epoch ago
    pub healthy_ratio_1_epoch: f64,

    /// Healthy ratio 5 epochs ago
    pub healthy_ratio_5_epochs: f64,

    // === Startup State ===
    /// Time since we started (or recovered)
    pub uptime_secs: u64,

    /// Are we in startup grace period?
    pub in_startup_grace: bool,

    /// Did we just recover from downtime?
    pub recovered_from_downtime: bool,
}

impl NetworkHealthContext {
    /// Minimum peers needed to make eviction decisions
    const MIN_PEERS_FOR_CONSENSUS: usize = 3;

    /// Startup grace period (don't evict anyone)
    const STARTUP_GRACE_SECS: u64 = 300; // 5 minutes

    /// Threshold for "sudden drop" detection
    const SUDDEN_DROP_THRESHOLD: f64 = 0.3; // 30% drop

    /// Are we likely experiencing network issues ourselves?
    pub fn likely_self_problem(&self) -> bool {
        !self.external_connectivity
            && self.bootstrap_nodes_reachable == 0
            && self.gossip_mesh_size == 0
    }

    /// Did we experience a sudden drop in healthy peers?
    pub fn sudden_drop_detected(&self) -> bool {
        let drop = self.healthy_ratio_5_epochs - self.healthy_ratio_now;
        drop > Self::SUDDEN_DROP_THRESHOLD && self.healthy_ratio_5_epochs > 0.5
    }

    /// Are we in a state where eviction decisions are safe?
    pub fn eviction_safe(&self) -> bool {
        // Not safe if:
        // 1. We're in startup grace period
        if self.in_startup_grace {
            return false;
        }

        // 2. We just recovered from downtime (give peers time to reconnect)
        if self.recovered_from_downtime && self.uptime_secs < Self::STARTUP_GRACE_SECS {
            return false;
        }

        // 3. We appear to have connectivity issues
        if self.likely_self_problem() {
            return false;
        }

        // 4. Sudden mass drop (likely partition)
        if self.sudden_drop_detected() {
            return false;
        }

        // 5. Not enough peers to form consensus
        if self.healthy_peers < Self::MIN_PEERS_FOR_CONSENSUS {
            return false;
        }

        true
    }
}
```

### Heartbeat Decision Engine

```rust
/// Decision for how to handle heartbeat status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatAction {
    /// Normal processing - update status normally
    Normal,

    /// Grace period - don't penalize missed heartbeats
    Grace,

    /// Freeze - don't change any status
    Freeze,

    /// Recovery mode - actively try to reconnect
    Reconnect,
}

pub struct HeartbeatDecisionEngine {
    config: HeartbeatConfig,
}

impl HeartbeatDecisionEngine {
    /// Decide what action to take for a peer's heartbeat status
    pub fn decide(
        &self,
        peer: &SignedPeerHeartbeatState,
        context: &NetworkHealthContext,
    ) -> HeartbeatAction {
        // Priority 1: Startup grace period
        if context.in_startup_grace {
            tracing::debug!("In startup grace period, not penalizing peers");
            return HeartbeatAction::Grace;
        }

        // Priority 2: Recovery from downtime
        if context.recovered_from_downtime
            && context.uptime_secs < NetworkHealthContext::STARTUP_GRACE_SECS
        {
            tracing::debug!("Recovering from downtime, not penalizing peers");
            return HeartbeatAction::Reconnect;
        }

        // Priority 3: We're offline
        if context.likely_self_problem() {
            tracing::warn!("Connectivity issues detected, freezing peer status");
            return HeartbeatAction::Freeze;
        }

        // Priority 4: Network partition / mass drop
        if context.sudden_drop_detected() {
            tracing::warn!(
                "Sudden drop in healthy peers ({:.0}% -> {:.0}%), freezing status",
                context.healthy_ratio_5_epochs * 100.0,
                context.healthy_ratio_now * 100.0,
            );
            return HeartbeatAction::Freeze;
        }

        // Priority 5: Not enough peers
        if !context.eviction_safe() {
            tracing::info!("Below safe eviction threshold, using grace mode");
            return HeartbeatAction::Grace;
        }

        // Normal operation
        HeartbeatAction::Normal
    }

    /// Apply action to peer state
    pub fn apply_action(
        action: HeartbeatAction,
        peer: &mut SignedPeerHeartbeatState,
        config: &HeartbeatConfig,
    ) {
        match action {
            HeartbeatAction::Normal => {
                // Normal miss recording
                peer.record_miss(config);
            }

            HeartbeatAction::Grace => {
                // Don't increment missed_count, but don't reset streak either
                // This is a "pause" in evaluation
            }

            HeartbeatAction::Freeze => {
                // Completely frozen - no changes
            }

            HeartbeatAction::Reconnect => {
                // Reset to unknown, try to reconnect
                peer.status = SignedPeerStatus::Unknown;
                peer.missed_count = 0;
            }
        }
    }
}
```

### Quiescence Detection

```rust
/// Detect and handle network quiescence
pub struct QuiescenceDetector {
    /// Last time we saw healthy activity
    last_healthy_activity: Instant,

    /// Threshold for considering network quiescent
    quiescence_threshold: Duration,

    /// Are we currently in quiescent mode?
    is_quiescent: bool,
}

impl QuiescenceDetector {
    /// Check if network appears quiescent
    pub fn check_quiescence(&mut self, context: &NetworkHealthContext) -> bool {
        // Network is quiescent if:
        // 1. Very few or no active peers
        // 2. We've had no successful heartbeat exchanges for a while
        // 3. But we still have external connectivity (so it's not us)

        let low_activity = context.healthy_peers == 0
            && context.recent_connection_successes == 0;

        let we_are_ok = context.external_connectivity;

        if low_activity && we_are_ok {
            if self.last_healthy_activity.elapsed() > self.quiescence_threshold {
                if !self.is_quiescent {
                    tracing::info!(
                        "Network appears quiescent (no activity for {:?})",
                        self.last_healthy_activity.elapsed()
                    );
                    self.is_quiescent = true;
                }
                return true;
            }
        } else {
            // Activity detected
            if self.is_quiescent {
                tracing::info!("Network activity resumed, exiting quiescent mode");
                self.is_quiescent = false;
            }
            self.last_healthy_activity = Instant::now();
        }

        false
    }
}
```

---

## Implementation Order

### Phase 1: Signed Handshake (Immediate)
1. Create `src/attestation/signed_handshake.rs`
2. Implement `HandshakeChallenge`, `SignedHandshakeResponse`, `HandshakeHelloData`
3. Implement `SignedHandshakeVerifier`
4. Implement `SignedHandshake` state machine
5. Add tests for replay prevention, signature verification, derivation check

### Phase 2: Persistence & Recovery (Next)
1. Create `src/attestation/persistence.rs`
2. Implement `PersistedNetworkState`, `PersistedPeerState`
3. Add save/load methods to `SignedHeartbeatManager`
4. Implement graceful shutdown handling
5. Implement recovery logic that doesn't penalize peers

### Phase 3: Network Health Context (Then)
1. Create `src/attestation/network_health.rs`
2. Implement `NetworkHealthContext`
3. Add connectivity checking (external endpoints, bootstrap nodes)
4. Add trend tracking (rolling healthy ratios)
5. Integrate with `SignedHeartbeatManager`

### Phase 4: Decision Engine (Finally)
1. Implement `HeartbeatDecisionEngine`
2. Implement `QuiescenceDetector`
3. Integrate decision logic into heartbeat checking
4. Add comprehensive tests for partition/quiescence scenarios

---

## Test Scenarios

### Signed Handshake Tests
1. ✅ Valid challenge-response completes
2. ✅ Replay attack rejected (reused challenge)
3. ✅ Wrong challenge rejected
4. ✅ Invalid signature rejected
5. ✅ Stale timestamp rejected
6. ✅ Derivation mismatch rejected
7. ✅ Binary not in allowlist rejected

### Network Resilience Tests
1. ✅ Graceful shutdown preserves state
2. ✅ Recovery doesn't penalize peers for our downtime
3. ✅ Startup grace period prevents early evictions
4. ✅ Partition detected and scores frozen
5. ✅ Quiescence detected and handled
6. ✅ Recovery from quiescence resumes normally
7. ✅ Single peer failure handled normally
8. ✅ Mass failure triggers protective mode

---

## Configuration

```rust
/// Network resilience configuration
pub struct ResilienceConfig {
    /// Startup grace period (no evictions)
    pub startup_grace_secs: u64,

    /// Minimum peers for eviction decisions
    pub min_peers_for_eviction: usize,

    /// Threshold for sudden drop detection (0.0-1.0)
    pub sudden_drop_threshold: f64,

    /// Time without activity before quiescence mode
    pub quiescence_threshold_secs: u64,

    /// External connectivity check interval
    pub connectivity_check_interval_secs: u64,

    /// Bootstrap nodes to check for connectivity
    pub bootstrap_endpoints: Vec<String>,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            startup_grace_secs: 300,          // 5 minutes
            min_peers_for_eviction: 3,
            sudden_drop_threshold: 0.3,       // 30% drop
            quiescence_threshold_secs: 600,   // 10 minutes
            connectivity_check_interval_secs: 60,
            bootstrap_endpoints: vec![
                "https://bootstrap1.saorsa.network/health".into(),
                "https://bootstrap2.saorsa.network/health".into(),
            ],
        }
    }
}
```
