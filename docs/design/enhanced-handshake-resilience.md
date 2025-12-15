# Enhanced Handshake & Network Resilience Design

## Problem Statement

### 1. Software Attestation in Handshake

**Current State:**
- Handshake exchanges `AttestationHello` with EntangledId + zkVM proof
- Proof verifies: `derive(public_key, binary_hash, nonce) == entangled_id`
- **Gap:** The `binary_hash` is self-reported - a malicious node could lie

**What We Can Prove (Pure Software):**
| Property | Can Prove? | Mechanism |
|----------|------------|-----------|
| Key ownership | ✅ Yes | Signature verification |
| Consistent derivation | ✅ Yes | Math verification |
| Liveness | ✅ Yes | Fresh timestamp/challenge |
| Running authorized code | ❌ No | No trusted hardware |

**Economic Enforcement:**
The binary_hash binding provides economic enforcement:
- Change software → New binary_hash → New EntangledId → **Zero reputation**
- Building reputation takes time and honest behavior
- Lying about binary_hash gains nothing if you can't use existing reputation

### 2. Catastrophic Network Failure Prevention

**The Core Problem:**
When a node stops receiving heartbeats from many peers, who is at fault?

| Scenario | Reality | What Node Sees | Wrong Response |
|----------|---------|----------------|----------------|
| Network partition | Node is cut off | "50% peers silent" | Mass eviction |
| Local ISP issue | Node offline | "All peers silent" | Evict everyone |
| Regional outage | Real event | "Many peers silent" | Should detect |
| Single peer down | Peer failed | "One peer silent" | Evict ✅ |

**Danger:** Mass eviction during partition → All nodes evict each other → Network collapse

---

## Proposed Solution: Defense-in-Depth Handshake

### Phase 1: Signed Handshake (Immediate)

```rust
/// Enhanced handshake with signature binding
pub struct SignedAttestationHello {
    /// The core attestation data
    pub hello: AttestationHelloData,

    /// ML-DSA signature over hello || challenge
    pub signature: Vec<u8>,

    /// Fresh challenge from the other peer (prevents replay)
    pub challenge_response: [u8; 32],
}

pub struct AttestationHelloData {
    /// Software-attested identity
    pub entangled_id: [u8; 32],

    /// Public key (for signature verification AND derivation check)
    pub public_key: Vec<u8>,

    /// Binary hash used in derivation
    pub binary_hash: [u8; 32],

    /// Nonce used in derivation
    pub derivation_nonce: u64,

    /// Fresh timestamp (prevents replay)
    pub timestamp: u64,

    /// Random nonce (uniqueness)
    pub nonce: [u8; 16],

    /// Latest signed heartbeat (liveness proof)
    pub latest_heartbeat: Option<SignedHeartbeat>,
}
```

**Verification Steps:**

1. **Timestamp freshness:** `now - timestamp < MAX_HELLO_AGE`
2. **Challenge-response:** Verify signature covers the challenge we sent
3. **Signature validity:** `ml_dsa_verify(public_key, hello || challenge, signature)`
4. **Derivation check:** `derive(public_key, binary_hash, nonce) == entangled_id`
5. **Heartbeat validity:** If present, verify the signed heartbeat

**What This Proves:**
- ✅ Node controls the private key for this public key
- ✅ Public key was used to derive the claimed EntangledId
- ✅ Node is live (fresh timestamp + challenge response)
- ⚠️ Binary hash is self-reported (but economically bound)

### Phase 2: Mutual Challenge Protocol

```
Node A                                    Node B
  |                                          |
  |  1. ChallengeRequest (random_a)         |
  |----------------------------------------->|
  |                                          |
  |  2. ChallengeRequest (random_b)         |
  |<-----------------------------------------|
  |                                          |
  |  3. SignedAttestationHello              |
  |     (signs over hello || random_b)       |
  |----------------------------------------->|
  |                                          |
  |  4. SignedAttestationHello              |
  |     (signs over hello || random_a)       |
  |<-----------------------------------------|
  |                                          |
  |  5. Both verify:                         |
  |     - Signature covers their challenge   |
  |     - Derivation is correct              |
  |     - Timestamp is fresh                 |
```

This prevents:
- **Replay attacks:** Challenge is unique per connection
- **Man-in-middle:** Attacker can't produce valid signature
- **Identity theft:** Can't reuse captured hellos

---

## Proposed Solution: Network Resilience

### Principle: "Suspect Self Before Blaming Others"

When many peers go silent, the node should ask:
1. Am I still connected to the network?
2. Can other peers confirm this peer is down?
3. Is this a local or global event?

### Network Health Context

```rust
/// Context for making trust decisions
pub struct NetworkHealthContext {
    // Current peer counts
    pub total_known_peers: usize,
    pub healthy_peers: usize,
    pub suspect_peers: usize,
    pub unresponsive_peers: usize,

    // Connectivity indicators
    pub external_connectivity_confirmed: bool,
    pub gossip_mesh_size: usize,
    pub bootstrap_nodes_reachable: usize,
    pub recent_successful_connections: usize,

    // Trend detection
    pub healthy_ratio_1min_ago: f64,
    pub healthy_ratio_5min_ago: f64,
    pub healthy_ratio_now: f64,
}

impl NetworkHealthContext {
    /// Detect if we might be partitioned
    pub fn is_likely_partitioned(&self) -> bool {
        // Sudden drop in healthy peers
        let sudden_drop = self.healthy_ratio_now < 0.5
            && self.healthy_ratio_5min_ago > 0.8;

        // But we can still reach external services
        let still_connected = self.external_connectivity_confirmed
            || self.bootstrap_nodes_reachable > 0;

        sudden_drop && still_connected
    }

    /// Detect if we're likely offline
    pub fn is_likely_offline(&self) -> bool {
        self.healthy_peers == 0
            && !self.external_connectivity_confirmed
            && self.bootstrap_nodes_reachable == 0
    }

    /// Check if we have enough data to make eviction decisions
    pub fn can_make_eviction_decisions(&self) -> bool {
        // Minimum requirements
        self.healthy_peers >= MIN_PEERS_FOR_CONSENSUS
            && !self.is_likely_partitioned()
            && !self.is_likely_offline()
    }
}
```

### Resilient Heartbeat Decision Logic

```rust
pub enum HeartbeatDecision {
    /// Normal operation - proceed with eviction
    NormalEviction,

    /// Gradual trust decay only (no hard eviction)
    GradualDecay,

    /// Freeze all trust scores (network disruption mode)
    FreezeScores,

    /// Self-heal mode (we're probably the problem)
    SelfHealMode,
}

pub fn decide_heartbeat_action(
    peer: &PeerState,
    context: &NetworkHealthContext,
    config: &HeartbeatConfig,
) -> HeartbeatDecision {
    // Priority 1: Are WE the problem?
    if context.is_likely_offline() {
        tracing::warn!("Node appears offline, entering self-heal mode");
        return HeartbeatDecision::SelfHealMode;
    }

    // Priority 2: Network partition detected?
    if context.is_likely_partitioned() {
        tracing::warn!(
            "Possible network partition detected \
             (healthy: {:.1}% -> {:.1}%), freezing trust scores",
            context.healthy_ratio_5min_ago * 100.0,
            context.healthy_ratio_now * 100.0,
        );
        return HeartbeatDecision::FreezeScores;
    }

    // Priority 3: Not enough healthy peers for consensus?
    if context.healthy_peers < MIN_PEERS_FOR_CONSENSUS {
        tracing::info!(
            "Below minimum peer threshold ({}/{}), using gradual decay only",
            context.healthy_peers,
            MIN_PEERS_FOR_CONSENSUS
        );
        return HeartbeatDecision::GradualDecay;
    }

    // Priority 4: Normal operation
    if peer.missed_count >= config.eviction_threshold {
        HeartbeatDecision::NormalEviction
    } else {
        HeartbeatDecision::GradualDecay
    }
}
```

### Trust Score Adjustments

Instead of binary eviction, use gradual trust decay:

```rust
/// Apply heartbeat decision to trust scores
pub fn apply_heartbeat_decision(
    peer_id: &[u8; 32],
    decision: HeartbeatDecision,
    trust_engine: &EigenTrustEngine,
    missed_count: u32,
) {
    match decision {
        HeartbeatDecision::NormalEviction => {
            // Hard penalty - mark as unresponsive
            for _ in 0..3 {
                trust_engine.update_local_trust(peer_id, false);
            }
        }

        HeartbeatDecision::GradualDecay => {
            // Soft penalty - proportional to missed count
            let decay_factor = (missed_count as f64 * 0.05).min(0.5);
            trust_engine.decay_trust(peer_id, decay_factor);
        }

        HeartbeatDecision::FreezeScores => {
            // No changes during network disruption
        }

        HeartbeatDecision::SelfHealMode => {
            // No changes - we're the problem
            // Maybe trigger reconnection attempts
        }
    }
}
```

### Recovery Detection

```rust
/// Detect recovery from network disruption
pub fn check_recovery(
    context: &NetworkHealthContext,
    disruption_started: Instant,
) -> bool {
    let now_ratio = context.healthy_ratio_now;
    let duration = disruption_started.elapsed();

    // Recovery criteria:
    // 1. Healthy ratio back above 70%
    // 2. Or we've been in disruption mode too long (safety valve)
    now_ratio > 0.7 || duration > DISRUPTION_MODE_MAX_DURATION
}
```

---

## Implementation Considerations

### Constants

```rust
/// Minimum healthy peers required to make eviction decisions
const MIN_PEERS_FOR_CONSENSUS: usize = 5;

/// Maximum time in network disruption mode before forcing recovery
const DISRUPTION_MODE_MAX_DURATION: Duration = Duration::from_secs(3600); // 1 hour

/// Maximum age for handshake hello (prevents replay)
const MAX_HELLO_AGE_SECS: u64 = 60;

/// Trust decay rate per missed heartbeat (gradual mode)
const GRADUAL_DECAY_RATE: f64 = 0.05;
```

### External Connectivity Check

```rust
/// Check if we can reach external services
pub async fn check_external_connectivity() -> bool {
    // Try multiple endpoints for reliability
    let checks = [
        check_dns_resolution("saorsa.network"),
        check_http_head("https://api.saorsa.network/health"),
        check_icmp("8.8.8.8"), // Fallback to Google DNS
    ];

    // At least one must succeed
    futures::future::join_all(checks)
        .await
        .iter()
        .any(|&success| success)
}
```

### Corroboration (Future Enhancement)

For important decisions (like evicting a high-reputation node), we could ask other trusted peers:

```rust
/// Ask trusted peers if they can reach a suspect peer
pub async fn corroborate_peer_status(
    suspect_peer: &[u8; 32],
    trusted_peers: &[PeerConnection],
) -> CorroborationResult {
    let votes: Vec<bool> = futures::future::join_all(
        trusted_peers.iter().map(|p| p.can_reach(suspect_peer))
    ).await;

    let unreachable_count = votes.iter().filter(|&&v| !v).count();
    let total = votes.len();

    if unreachable_count as f64 / total as f64 > 0.7 {
        CorroborationResult::ConfirmedUnreachable
    } else if unreachable_count as f64 / total as f64 > 0.3 {
        CorroborationResult::MixedResults
    } else {
        CorroborationResult::ProbablyReachable
    }
}
```

---

## Summary

### Enhanced Handshake
1. **Mutual challenge-response** prevents replay attacks
2. **Signed hello** proves key ownership
3. **Derivation verification** ensures EntangledId consistency
4. **Latest heartbeat** proves recent liveness

### Network Resilience
1. **Self-diagnosis first** - check own connectivity before blaming others
2. **Partition detection** - recognize mass silence patterns
3. **Gradual trust decay** - avoid catastrophic eviction cascades
4. **Recovery detection** - automatically exit disruption mode
5. **Corroboration** - ask trusted peers before major decisions

### Key Principle
> "A single failing peer is their problem. Mass failure is probably our problem."

---

## Migration Path

1. **Phase 1:** Add `SignedAttestationHello` alongside existing protocol
2. **Phase 2:** Add `NetworkHealthContext` to heartbeat manager
3. **Phase 3:** Implement resilient decision logic
4. **Phase 4:** Add corroboration for high-stakes decisions
5. **Phase 5:** Deprecate unsigned handshake (protocol version bump)
