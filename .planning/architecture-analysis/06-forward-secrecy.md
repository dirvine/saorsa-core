# Forward Secrecy Analysis

## Overview

**Answer to Critical Question 5**: **Forward secrecy NOT guaranteed for DHT-stored messages** with current deterministic key derivation fallback.

**Key finding**: Ephemeral session keys (ML-KEM-768) provide forward secrecy, but deterministic fallback (BLAKE3 of identity + channel_id) does not.

---

## Question 1: Is forward secrecy required for historical messages in DHT?

**Answer**: **RECOMMENDED but NOT ENFORCED** - Current implementation has gaps

**Rationale for forward secrecy**:
- ✅ Messages stored in DHT (untrusted nodes) for up to 1 hour
- ✅ If key compromised, historical DHT messages could be decrypted
- ✅ Privacy-first architecture should prevent retroactive decryption

**Current gaps**:
- ⚠️ Deterministic key derivation (fallback) provides NO forward secrecy
- ⚠️ Keys derived from identity + channel_id are long-lived
- ⚠️ Compromise of identity reveals all past messages in channel

**Evidence**:
- Ephemeral session: `src/messaging/encryption.rs:230-260` (`create_ephemeral_session()`)
- Deterministic fallback: `src/messaging/encryption.rs:57-63` (BLAKE3 of identity + channel)

---

## Question 2: Are ephemeral keys used per message, or long-lived keys?

**Answer**: **Hybrid** - Ephemeral when available, deterministic fallback otherwise

**Ephemeral session keys** (`src/messaging/encryption.rs:230-260`):
- ✅ Generated per session using ML-KEM-768
- ✅ Provides forward secrecy
- ✅ Compromise of current key doesn't reveal past messages
- ⚠️ Requires key exchange (may fail for offline users)

**Deterministic keys** (`src/messaging/encryption.rs:57-63`):
- ❌ Derived from identity + channel_id (BLAKE3 hash)
- ❌ Same key used for all messages in channel
- ❌ No forward secrecy (compromise reveals all past messages)
- ✅ Works without key exchange (always available)

**Current behavior**:
```rust
// src/messaging/encryption.rs:49-63
let session_key = if let Ok(key) = self
    .key_exchange
    .get_session_key(&message.channel_id.0.to_string().into())
    .await
{
    key  // Ephemeral key (forward secrecy ✓)
} else {
    // Deterministic fallback (NO forward secrecy ✗)
    let mut hasher = Hasher::new();
    hasher.update(self.identity.to_string().as_bytes());
    hasher.update(&message.channel_id.0.to_bytes());
    let key_material = hasher.finalize();
    key_material.as_bytes()[..32].to_vec()
};
```

---

## Question 3: How often are encryption keys rotated?

**Answer**: **Depends on key type**

**Ephemeral session keys**:
- Rotation: Per session (implementation-specific)
- Lifetime: Configurable (likely 24 hours, `src/messaging/encryption.rs:211`)
- Trigger: Session establishment/expiration

**Deterministic keys**:
- Rotation: **NEVER** (derived from immutable identity + channel_id)
- Lifetime: **Forever** (as long as channel exists)
- Trigger: None (always same key)

**Implication**:
- Channels using deterministic keys have ZERO forward secrecy
- Channels using ephemeral keys have forward secrecy within session lifetime

---

## Question 4: If keys are compromised, can historical DHT messages be decrypted?

**Answer**: **YES (for deterministic keys), NO (for ephemeral keys)**

**Deterministic key compromise** (WORST CASE):
- ✅ Attacker can decrypt: **ALL past and future messages in channel**
- ✅ Attacker can derive key: From public identity + channel_id
- ✅ DHT messages accessible: Up to 1 hour old (TTL)
- ❌ No forward secrecy: Single compromise reveals entire history

**Ephemeral key compromise** (BETTER):
- ✅ Attacker can decrypt: **Only messages from compromised session**
- ❌ Cannot decrypt: Past sessions (different ephemeral keys)
- ❌ Cannot decrypt: Future sessions (new ephemeral keys)
- ✅ Forward secrecy: Limited blast radius

**Risk assessment**:
- **High risk**: Deterministic fallback enables retroactive decryption
- **Medium risk**: DHT stores encrypted messages for 1 hour (attack window)
- **Mitigation**: Force ephemeral key exchange, remove deterministic fallback

---

## Question 5: Does ant-quic PQC provide forward secrecy for in-transit messages?

**Answer**: **YES** - ant-quic uses ML-KEM-768 with ephemeral keys

**Evidence**:
- ML-KEM-768 key encapsulation (post-quantum)
- Ephemeral session keys per connection
- Forward secrecy guaranteed for transport layer

**Distinction**:
- ✅ **In-transit**: ant-quic ML-KEM-768 provides forward secrecy
- ⚠️ **At-rest (DHT)**: Application-layer encryption may NOT provide forward secrecy (deterministic fallback)

**Architecture**:
```
┌─────────────────────────────────────────────────────┐
│ MESSAGE ENCRYPTION LAYERS                           │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Application Layer (E2E):                           │
│  ├─ Ephemeral session: ML-KEM-768 ✓ Forward Secrecy│
│  └─ Deterministic fallback: BLAKE3 ✗ NO Forward Sec│
│                                                     │
│  Transport Layer (In-Transit):                      │
│  └─ ant-quic ML-KEM-768 ✓ Forward Secrecy          │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## Architectural Implications

### Impact on Encryption Strategy

**Forward secrecy gaps create risk**:
- ⚠️ Deterministic keys allow retroactive decryption
- ⚠️ DHT stores encrypted messages for 1 hour (attack window)
- ⚠️ Identity compromise reveals all channel messages

**Recommendations**:
1. **Remove deterministic fallback**: Force ephemeral key exchange
2. **Enforce ephemeral keys**: Reject messages without valid session
3. **Reduce DHT TTL**: Shorter attack window (already 1 hour)
4. **Key rotation policy**: Mandatory session expiration

### Comparison to Perfect Forward Secrecy

**Perfect Forward Secrecy requires**:
- ✅ Ephemeral keys per message or session
- ✅ Immediate key deletion after use
- ✅ No key derivation from long-lived secrets

**Current state**:
- ✅ ant-quic: Perfect forward secrecy (ML-KEM-768 ephemeral)
- ⚠️ Application E2E: Conditional (ephemeral if available, deterministic fallback)

**Gap**: Deterministic fallback violates forward secrecy

---

## Code Evidence Summary

| Finding | File | Line(s) | Evidence |
|---------|------|---------|----------|
| Ephemeral session creation | encryption.rs | 230-260 | `create_ephemeral_session()` |
| Deterministic fallback | encryption.rs | 57-63 | BLAKE3(identity + channel_id) |
| Session key retrieval | encryption.rs | 49-56 | Try ephemeral, fallback to deterministic |
| Session lifetime | encryption.rs | 211 | 24-hour expiration |
| ML-KEM key exchange | key_exchange.rs | - | Quantum-safe key agreement |
| ant-quic PQC | ant_quic_adapter.rs | - | ML-KEM-768 transport encryption |

---

## Summary

**Forward Secrecy in Saorsa**:
- **Transport layer (ant-quic)**: ✅ Forward secrecy guaranteed
- **Application layer (E2E)**: ⚠️ Conditional (ephemeral preferred, deterministic fallback)
- **DHT storage**: ⚠️ Vulnerable to retroactive decryption (deterministic keys)

**Critical finding for Phase 2**:
The deterministic key derivation fallback creates a forward secrecy gap. If identity is compromised, all past DHT-stored messages (up to 1-hour TTL window) can be decrypted.

**Architectural decision impact**:
- ❌ **Cannot remove application-layer encryption**: Still needed for DHT storage
- ⚠️ **Should remove deterministic fallback**: Enforce ephemeral keys for forward secrecy
- ✅ **ant-quic provides forward secrecy**: Transport layer is secure

---

## Answer to Question 5

**Is forward secrecy required for historical messages in DHT?**

**Answer**: **YES (recommended)** - But not currently guaranteed due to deterministic fallback

**Current state**:
- ✅ Ephemeral keys: Forward secrecy when ML-KEM-768 exchange succeeds
- ❌ Deterministic keys: NO forward secrecy (fallback when exchange fails)
- ⚠️ DHT storage: 1-hour attack window for retroactive decryption

**Recommendation**:
- Remove deterministic fallback
- Enforce ephemeral key exchange
- Reject messages without valid session keys
- Short DHT TTL (1 hour) limits but doesn't eliminate risk

**Risk**: Identity compromise + deterministic fallback = all channel history decryptable

---

**Task 6 Complete**: 2026-01-29
**Next**: Task 7 - Encryption Layer Audit
