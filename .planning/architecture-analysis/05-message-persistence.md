# Message Persistence Classification

## Overview

**Answer to Critical Question 4**: **All messages are effectively ephemeral** (1-hour maximum due to DHT TTL)

**From ADR-013**: No extended offline delivery - all messages expire after 1-hour DHT TTL

---

## Question 1: Are all messages persistent, or are some ephemeral?

**Answer**: **All messages are ephemeral** (1-hour maximum lifetime)

**Evidence**:
- DHT TTL: `src/placement/dht_records.rs:97` (DEFAULT_TTL = 3600 seconds)
- All messages in DHT expire after 1 hour
- Ephemeral field: `src/messaging/types.rs:138` (may indicate user preference)
- No long-term persistence (ADR-013)

**Behavior**:
- All messages stored in DHT with 1-hour TTL
- Messages automatically removed after expiration
- No persistent message storage beyond TTL

---

## Question 2: What determines if a message is ephemeral vs persistent?

**Answer**: **ALL messages are ephemeral by default** (1-hour DHT TTL)

**`ephemeral` field** (`src/messaging/types.rs:138`):
- May indicate user preference for extra-ephemeral messages
- But has no effect on current implementation
- All messages expire after 1 hour regardless

**Future consideration**:
- If long-term persistence is added (ADR-013 future), `ephemeral` field may distinguish:
  - Ephemeral: 1-hour TTL (current default)
  - Persistent: Extended TTL (7 days, 30 days, etc.)

---

## Question 3: Are ephemeral messages stored in DHT?

**Answer**: **YES** - All messages (ephemeral) are stored in DHT with encryption

**Evidence**:
- DHT storage: `src/messaging/transport.rs:95` (`store_in_dht()`)
- All messages go to DHT with 1-hour TTL
- Stored encrypted (EncryptedMessage)

**No contradiction**:
- "Ephemeral" means short-lived (1 hour), not "never stored"
- DHT storage enables delivery to offline users (within 1-hour window)
- Encryption protects ephemeral data in DHT

---

## Question 4: Do ephemeral messages skip encryption?

**Answer**: **NO** - All messages are encrypted before DHT storage

**Evidence**:
- Encryption: `src/messaging/encryption.rs:44-74` (ChaCha20Poly1305)
- DHT storage: `src/messaging/transport.rs:324-332` (stores EncryptedMessage)
- No conditional encryption based on `ephemeral` field

**Rationale**:
- DHT nodes are untrusted (from Task 2 analysis)
- All messages must be encrypted for DHT storage
- Ephemeral doesn't mean "less secure"

---

## Question 5: What is the default: ephemeral or persistent?

**Answer**: **Ephemeral (1-hour TTL)** - All messages

**Current implementation**:
- Default TTL: 3600 seconds (1 hour)
- No persistent storage option
- All messages expire automatically

**From ADR-013**:
- v1: All messages ephemeral (1-hour maximum)
- Future: May add persistent storage based on user feedback

---

## Architectural Implications

### Impact on Encryption Strategy

**Ephemeral nature does NOT reduce encryption requirements**:
- ✅ DHT storage still requires encryption (untrusted nodes)
- ✅ Application-layer encryption (ChaCha20Poly1305) REQUIRED
- ✅ Ephemeral messages get same encryption as persistent would

**No performance optimization from ephemeral**:
- Cannot skip encryption for ephemeral messages
- Cannot skip DHT storage for ephemeral messages
- Ephemeral only affects TTL, not security

### Comparison to Persistent Storage

**If we added persistent storage (future)**:
- Persistent messages: Extended TTL (7 days, 30 days)
- Ephemeral messages: Current 1-hour TTL
- Both would still require encryption
- Both would still use DHT storage

**Current state (all ephemeral)**:
- Simpler architecture (no dual storage paths)
- Privacy-preserving (short retention)
- Reduced storage requirements

---

## Code Evidence Summary

| Finding | File | Line(s) | Evidence |
|---------|------|---------|----------|
| Ephemeral field | types.rs | 138 | `ephemeral: bool` in RichMessage |
| Expires_at field | types.rs | 135 | `expires_at: Option<DateTime<Utc>>` |
| DHT TTL constant | dht_records.rs | 97 | `DEFAULT_TTL = 3600 seconds` |
| DHT storage call | transport.rs | 95 | `store_in_dht()` for all messages |
| Encryption | encryption.rs | 44-74 | ChaCha20Poly1305 for all messages |
| Cleanup function | database.rs | 584 | `cleanup_ephemeral()` (may be unused) |

---

## Summary

**Message Persistence in Saorsa**:
- **All messages**: Ephemeral (1-hour maximum)
- **Storage**: DHT with 1-hour TTL
- **Encryption**: Required for all messages (ephemeral or not)
- **Future**: May add persistent storage option (ADR-013)

**Critical finding for Phase 2**:
Message persistence classification does NOT change encryption requirements. All messages (currently ephemeral) require application-layer encryption for DHT storage.

---

## Answer to Question 4

**Are messages ephemeral (live) or persistent?**

**Answer**: **All ephemeral** (1-hour maximum lifetime)

**Breakdown**:
- ✅ All messages ephemeral: 1-hour DHT TTL
- ❌ No persistent storage: Messages expire after 1 hour
- ✅ Stored in DHT: For offline delivery (within 1-hour window)
- ✅ Encrypted storage: ChaCha20Poly1305 before DHT

**`ephemeral` field**: Currently has no effect (all messages ephemeral). May be used in future if persistent storage added.

**Reference**: ADR-013 (No Offline Message Delivery v1)

---

**Task 5 Complete**: 2026-01-29
**Next**: Task 6 - Forward Secrecy Analysis
