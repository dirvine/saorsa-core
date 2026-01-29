# Encryption Layer Audit

## Overview

**Complete encryption stack identified**: 2 layers with distinct purposes

**Finding**: Layers are NOT redundant - each serves different security requirements

---

## Question 1: How many encryption layers exist?

**Answer**: **2 encryption layers**

1. **Transport Layer**: ant-quic ML-KEM-768 (in-transit encryption)
2. **Application Layer**: ChaCha20Poly1305 (end-to-end encryption)

**Evidence**:
- Transport: `src/transport/ant_quic_adapter.rs` (ant-quic integration)
- Application: `src/messaging/encryption.rs:44-74` (ChaCha20Poly1305)

---

## Question 2: Which layer uses ChaCha20Poly1305?

**Answer**: **Application Layer (E2E encryption)**

**Implementation**:
- Function: `src/messaging/encryption.rs:44` (`encrypt_message()`)
- Algorithm: ChaCha20Poly1305 AEAD
- Key size: 32 bytes (256-bit)
- Nonce: 12 bytes (random)
- Auth tag: 16 bytes (Poly1305 MAC)

**Overhead**:
- Nonce: 12 bytes
- Auth tag: 16 bytes
- Total: **28 bytes** (from baseline measurements)

**Purpose**:
- End-to-end encryption (sender to recipient)
- Protects message content from DHT nodes
- Protects message content from relay nodes

---

## Question 3: Which layer uses ML-KEM-768?

**Answer**: **Transport Layer (ant-quic QUIC encryption)**

**Implementation**:
- ant-quic library (external dependency)
- ML-KEM-768: Post-quantum key encapsulation
- ML-DSA-65: Post-quantum signatures (optional)

**Overhead**:
- Encapsulation: ~1568 bytes (ML-KEM-768 ciphertext)
- Per-connection handshake overhead (not per-message)
- Amortized: **~16 bytes per message** (from baseline measurements)

**Purpose**:
- Transport security (sender to relay, relay to recipient)
- NAT traversal
- Connection-level encryption (QUIC)

---

## Question 4: Where is the redundancy?

**Answer**: **NO REDUNDANCY** - Layers serve different purposes

**Why both layers are necessary**:

1. **Application Layer (ChaCha20Poly1305)**:
   - Required for: DHT storage (untrusted nodes)
   - Required for: Relay nodes (untrusted intermediaries)
   - Provides: End-to-end confidentiality

2. **Transport Layer (ant-quic ML-KEM-768)**:
   - Required for: In-transit protection
   - Required for: NAT traversal, firewall bypass
   - Provides: Transport confidentiality, forward secrecy

**Scenarios requiring both**:
- ✅ DHT storage: Application encryption protects at rest
- ✅ Direct P2P: Transport encryption protects in transit
- ✅ Relay delivery: Both layers protect through untrusted relay

**No scenario where one layer alone is sufficient**:
- Transport only: Would expose messages in DHT storage
- Application only: Would expose messages to network observers

---

## Question 5: Can any encryption layer be safely removed?

**Answer**: **NO** - Both layers are necessary

**Cannot remove Application Layer because**:
1. DHT storage requires encryption (Task 2 finding)
2. Relay nodes are untrusted intermediaries
3. E2E encryption is core security property

**Cannot remove Transport Layer because**:
1. Network-level protection required
2. NAT traversal depends on QUIC
3. ant-quic provides connection management

**Conclusion**: Current architecture requires both encryption layers.

---

## Encryption Stack Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ COMPLETE ENCRYPTION STACK                                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Layer 4: Application (RichMessage)                         │
│  ├─ Plaintext: User message content                         │
│  └─ Format: JSON                                            │
│        │                                                    │
│        ▼                                                    │
│  Layer 3: E2E Encryption (EncryptedMessage)                 │
│  ├─ Algorithm: ChaCha20Poly1305 AEAD                        │
│  ├─ Key: Ephemeral ML-KEM-768 or Deterministic             │
│  ├─ Overhead: +28 bytes (12B nonce + 16B auth tag)         │
│  └─ Protection: Sender → DHT → Recipient                    │
│        │                                                    │
│        ▼                                                    │
│  Layer 2: Serialization                                     │
│  ├─ Format: JSON (EncryptedMessage struct)                  │
│  └─ Overhead: ~84-92 bytes metadata                         │
│        │                                                    │
│        ▼                                                    │
│  Layer 1: Transport Encryption (QUIC)                       │
│  ├─ Algorithm: ant-quic ML-KEM-768                          │
│  ├─ Overhead: ~16 bytes per message (amortized)             │
│  └─ Protection: Sender → Relay → Recipient                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Overhead Calculation

**Per-message overhead**:

| Layer | Overhead | Purpose |
|-------|----------|---------|
| Application metadata | ~84-92 bytes | Message ID, channel ID, sender, nonce, key_id |
| ChaCha20Poly1305 | +28 bytes | Nonce (12B) + Auth tag (16B) |
| ant-quic ML-KEM-768 | +16 bytes | Amortized transport overhead |
| **Total** | **~128-136 bytes** | **Per message** |

**From baseline measurements** (`.planning/baseline-measurements.md`):
- Small message (100B plaintext): ~228-236 bytes total (128-136B overhead)
- Medium message (1KB plaintext): ~1152-1160 bytes total (128-136B overhead)
- Large message (10KB plaintext): ~10368-10376 bytes total (128-136B overhead)

**Overhead percentage**:
- Small (100B): 128-136% overhead
- Medium (1KB): 12-14% overhead
- Large (10KB): 1.3-1.4% overhead

---

## Security Properties by Layer

### Layer 1: Transport (ant-quic ML-KEM-768)

**Provides**:
- ✅ Confidentiality: In-transit encryption
- ✅ Integrity: QUIC packet authentication
- ✅ Forward secrecy: Ephemeral key exchange
- ✅ Post-quantum security: ML-KEM-768 resistant to quantum attacks

**Protects against**:
- ✅ Network eavesdropping
- ✅ Man-in-the-middle attacks
- ✅ Packet injection/modification

**Does NOT protect**:
- ❌ DHT storage (messages at rest)
- ❌ Relay nodes seeing plaintext (if no E2E encryption)

### Layer 2: Application (ChaCha20Poly1305)

**Provides**:
- ✅ End-to-end confidentiality: Only sender and recipient decrypt
- ✅ Integrity: Poly1305 MAC prevents tampering
- ✅ Authenticated encryption: AEAD guarantees
- ⚠️ Forward secrecy: Only if ephemeral keys used (not deterministic)

**Protects against**:
- ✅ DHT node eavesdropping
- ✅ Relay node eavesdropping
- ✅ Retroactive decryption (if ephemeral keys)

**Does NOT protect** (by design):
- Message metadata: ID, channel, sender, nonce visible to DHT
- Routing information: Endpoints visible to network

---

## Redundant vs Complementary

**NOT redundant because**:
1. **Different threat models**:
   - Transport: Network-level adversaries
   - Application: Storage/relay adversaries

2. **Different protection scopes**:
   - Transport: Connection (sender ↔ relay ↔ recipient)
   - Application: Message lifecycle (sender → DHT → recipient)

3. **Different failure modes**:
   - Transport compromise: Only affects in-transit messages
   - Application compromise: Affects stored messages in DHT

**Complementary layers**:
- Transport protects against network observers
- Application protects against storage providers
- Both together: Defense in depth

---

## Code Evidence Summary

| Finding | File | Line(s) | Evidence |
|---------|------|---------|----------|
| ChaCha20Poly1305 encryption | encryption.rs | 44-74 | `encrypt_message()` |
| EncryptedMessage structure | types.rs | 362-369 | Metadata + ciphertext |
| ant-quic integration | ant_quic_adapter.rs | - | ML-KEM-768 transport |
| DHT storage | transport.rs | 95 | Stores EncryptedMessage |
| Overhead measurements | baseline-measurements.md | - | 128-136 bytes per message |

---

## Summary

**Encryption Layers in Saorsa**:
- **2 layers**: Transport (ant-quic) + Application (ChaCha20Poly1305)
- **Total overhead**: ~128-136 bytes per message
- **Redundancy**: NONE - layers serve different purposes
- **Can remove**: NO - both layers required for security

**Critical finding for Phase 2**:
The double encryption is NOT redundant. Transport layer protects in-transit, application layer protects at-rest (DHT) and through relay nodes. Both are necessary for the current architecture.

---

## Answer to Encryption Removal Question

**Can any encryption layer be safely removed?**

**Answer**: **NO**

**Justification**:
1. **Application layer required**: DHT storage (Task 2), relay nodes (Task 4)
2. **Transport layer required**: Network protection, NAT traversal, QUIC features
3. **No redundancy**: Each layer has distinct security purpose
4. **Overhead justified**: 128-136 bytes ensures E2E + transport security

**Recommendation**: Keep both encryption layers in current architecture.

---

**Task 7 Complete**: 2026-01-29
**Next**: Task 8 - Synthesis and Architectural Decision
