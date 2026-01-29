# Encryption Architecture Decision - Phase 1 Review Follow-up

**Date**: 2026-01-29
**Status**: DECISION REQUIRED
**Context**: Codex review raised valid concern about removing application-layer encryption

---

## Background

Phase 1 baseline measurements identified redundant encryption:
- **Application layer**: ChaCha20Poly1305 (classical, 28B overhead per message)
- **Transport layer**: ant-quic ML-KEM-768 (post-quantum, 16B overhead per packet)

**Proposal**: Remove application-layer encryption, rely exclusively on ant-quic's PQC

---

## Codex Review Concern (HIGH Severity)

> "The baseline doc asserts 'no downsides' to removing application-layer encryption and treats
> transport QUIC as full E2E. That is unsafe if messages are stored, relayed, or routed via
> headless nodes/DHT—transport crypto only protects in-transit hops, not at-rest data or
> offline verification."

**Valid Point**: Transport encryption (ant-quic) only protects data **in transit**, not:
- Messages stored in DHT
- Messages relayed through headless nodes
- Offline message queues
- Multi-hop routing scenarios

---

## Encryption Decision Tree

### Scenario 1: Direct Peer-to-Peer Messages
**Characteristics**:
- Direct QUIC connection between two active devices
- No intermediate storage
- No relaying through third parties
- Real-time synchronous communication

**Encryption Approach**:
- ✅ **ant-quic ML-KEM-768 ONLY**
- Provides: Post-quantum E2E encryption, integrity, replay protection
- Overhead: 16 bytes per packet (AES-GCM tag)
- Security: End-to-end between connected peers

**Verdict**: Application-layer encryption **NOT NEEDED**

---

### Scenario 2: Messages Stored in DHT
**Characteristics**:
- Messages persisted in distributed hash table
- Stored on headless nodes (untrusted storage)
- Retrieved later by recipient
- No direct P2P connection during storage

**Encryption Approach**:
- ❌ **ant-quic protection ENDS at storage boundary**
- ✅ **REQUIRES message-level encryption**:
  - Encrypt with recipient's public key (ML-KEM-768 encapsulation)
  - Sign with sender's private key (ML-DSA-65 signature)
  - Store encrypted+signed message in DHT

**Overhead**:
- ML-KEM-768 ciphertext: 1,088 bytes (per message, not per packet)
- ML-DSA-65 signature: ~3,300 bytes
- **Total**: ~4,400 bytes per stored message

**Verdict**: Application-layer encryption **REQUIRED**

---

### Scenario 3: Multi-Hop Routing via Headless Nodes
**Characteristics**:
- Message routed through intermediate headless nodes
- Each hop is a separate QUIC connection
- Transport encryption ends/restarts at each hop
- Intermediate nodes should NOT see message content

**Encryption Approach**:
- ❌ **ant-quic protects hop-by-hop, NOT end-to-end in multi-hop**
- ✅ **REQUIRES onion routing OR message-level encryption**:
  - Option A: Onion routing (layer encryption per hop)
  - Option B: Single message-level encryption (simpler)

**Recommendation**: Message-level ML-KEM-768 encryption + ML-DSA-65 signature

**Verdict**: Application-layer encryption **REQUIRED**

---

### Scenario 4: Offline Message Delivery
**Characteristics**:
- Recipient is offline when message is sent
- Message stored until recipient comes online
- May be stored on sender's device, relay nodes, or DHT

**Encryption Approach**:
- ❌ **No active QUIC connection during offline storage**
- ✅ **REQUIRES message-level encryption + signing**

**Verdict**: Application-layer encryption **REQUIRED**

---

## Current Saorsa Architecture Analysis

### Question 1: Does Saorsa use DHT storage?
**Answer**: YES
- `src/dht/` module exists with Kademlia implementation
- DHT used for peer discovery and data storage
- Headless devices act as storage nodes

**Implication**: **Message-level encryption IS NEEDED** for DHT-stored data

---

### Question 2: Does Saorsa support offline message delivery?
**Answer**: LIKELY YES (needs confirmation)
- Presence system (`src/messaging/presence.rs`) suggests online/offline states
- Multi-device support suggests asynchronous messaging
- Headless devices could act as message queues

**Implication**: **Message-level encryption IS NEEDED** for offline messages

---

### Question 3: Does Saorsa use multi-hop routing?
**Answer**: UNCLEAR (needs confirmation)
- Adaptive routing (`src/adaptive/`) suggests intelligent path selection
- Trust-based routing might imply indirect paths
- Network topology may require relaying

**Implication**: If multi-hop routing exists, **message-level encryption IS NEEDED**

---

## Revised Architecture Proposal

### Phase 4: Remove REDUNDANT Encryption (Not ALL encryption)

**Keep**:
- ✅ **Message-level ML-DSA-65 signatures** (for integrity + non-repudiation)
- ✅ **Message-level ML-KEM-768 encryption** (for DHT storage + offline delivery)
- ✅ **Transport-level ant-quic ML-KEM-768** (for in-transit protection)

**Remove**:
- ❌ **ChaCha20Poly1305** (classical, weaker than ML-KEM-768)
- ❌ **Redundant EncryptedMessage wrapper** (simplify to single encryption layer)

### Updated Message Flow

#### For Direct P2P Messages (Synchronous)
```
RichMessage
  → Bincode
    → ML-DSA-65 signature (for integrity)
      → ant-quic ML-KEM-768 (transport)
        → Wire
```

**Rationale**: Signature provides integrity, transport provides confidentiality

#### For DHT Storage / Offline Messages
```
RichMessage
  → Bincode
    → ML-KEM-768 encrypt (with recipient public key)
      → ML-DSA-65 sign (with sender private key)
        → ant-quic ML-KEM-768 (transport to DHT node)
          → Wire → DHT Storage
```

**Rationale**: Message-level encryption protects at-rest data, signature ensures authenticity

---

## Performance Impact Re-Analysis

### Current Architecture (ChaCha20 + ant-quic)
```
Overhead per message: 28B (ChaCha20) + 16B (ant-quic) = 44B
Encryption operations: 2 (ChaCha20 + ML-KEM-768)
Key exchange: Separate + QUIC handshake
```

### Revised Architecture (ML-KEM-768 message + ant-quic transport)

**Direct P2P (Synchronous)**:
```
Overhead per message: 3,300B (ML-DSA-65 sig) + 16B (ant-quic) = 3,316B
Encryption operations: 1 (ML-KEM-768 via ant-quic)
Signing operations: 1 (ML-DSA-65 for integrity)
```

**DHT Storage / Offline**:
```
Overhead per message: 1,088B (ML-KEM-768 ciphertext) + 3,300B (ML-DSA-65 sig) + 16B (ant-quic) = 4,404B
Encryption operations: 2 (ML-KEM-768 message + ant-quic transport)
Signing operations: 1 (ML-DSA-65)
```

### Trade-off Analysis

**Direct P2P**:
- **Downside**: 3,316B overhead (vs 44B ChaCha20+antquic)
- **Upside**: Provides non-repudiation via signature
- **Mitigation**: Could make signature optional for ephemeral chat messages

**DHT Storage**:
- **Upside**: Proper end-to-end encryption (solves Codex concern)
- **Overhead**: 4,404B (but necessary for security)
- **Note**: This is correct architecture, not optional

---

## Recommendation: Hybrid Approach

### Message Classification

**Type A: Ephemeral Direct Messages** (e.g., real-time chat)
- Transport encryption only (ant-quic ML-KEM-768)
- Optional: ML-DSA-65 signature for integrity
- Overhead: 16B (or 3,316B with signature)

**Type B: Stored/Relayed Messages** (e.g., offline messages, DHT data)
- Message-level ML-KEM-768 encryption
- Mandatory ML-DSA-65 signature
- Transport encryption (ant-quic)
- Overhead: 4,404B

### Implementation Strategy

1. **Add message type field** to RichMessage:
   ```rust
   enum MessageType {
       Ephemeral,  // Direct P2P, no storage
       Persistent, // May be stored/relayed
   }
   ```

2. **Conditional encryption**:
   - Ephemeral: ant-quic transport only
   - Persistent: ML-KEM-768 + ML-DSA-65 + ant-quic

3. **Default to Persistent** for safety:
   - All messages encrypted by default
   - Opt-in to ephemeral mode for performance

---

## Phase 2 Action Items

### Before Implementation (Architecture Analysis):
1. ✅ **Confirm Saorsa's message flow patterns**:
   - Are all messages direct P2P, or are some stored/relayed?
   - Does DHT store user messages, or only metadata?
   - Is multi-hop routing used?

2. ✅ **Document threat model**:
   - What are we protecting against?
   - Who are the adversaries (network eavesdroppers, malicious nodes, etc.)?
   - What data needs at-rest vs in-transit protection?

3. ✅ **Design encryption API**:
   - Message classification (ephemeral vs persistent)
   - Encryption selection based on message type
   - Key management for message-level encryption

### Phase 4 Revised Scope:
- Remove **ChaCha20Poly1305** (classical encryption)
- Keep **ML-DSA-65 signatures** (integrity + non-repudiation)
- Add **conditional ML-KEM-768 message encryption** (for stored/relayed messages)
- Simplify to single encryption layer per message (no double wrapping)

---

## Conclusion

**Codex's concern is VALID and IMPORTANT**:
- Removing ALL application-layer encryption is unsafe for stored/relayed messages
- Transport-only encryption (ant-quic) is insufficient for DHT storage

**Revised Proposal**:
- Remove **classical** encryption (ChaCha20)
- Keep/add **post-quantum** message-level encryption (ML-KEM-768) for non-ephemeral messages
- Keep **post-quantum** signatures (ML-DSA-65) for integrity
- Use **ant-quic ML-KEM-768** for transport

**Net Result**:
- Stronger security (all PQC, no classical crypto)
- Simplified architecture (no redundant double encryption)
- Proper protection for all message types
- Performance tradeoff: Larger overhead for stored messages, but necessary for security

---

**Status**: Awaiting architectural analysis in Phase 2
**Next Steps**:
1. Confirm Saorsa's message storage/routing patterns
2. Update Phase 4 plan based on findings
3. Design message classification API
