# Offline Message Delivery Analysis

## Overview

**Answer to Critical Question 2**: **NO** - Saorsa does NOT implement extended offline message delivery beyond the 1-hour DHT TTL.

**Architectural Decision**: See ADR-013 (docs/adr/ADR-013-no-offline-delivery-v1.md)

**Status**: Future consideration - may be added based on user feedback

---

## Question 1: Does Saorsa queue messages for offline users?

**Answer**: **YES (short-term only)** - Messages queue for retry within the 1-hour TTL window.

**Evidence**:
- Queue implementation: `src/messaging/transport.rs:312-319` (`queue_message()`)
- Message queue field: `src/messaging/transport.rs:27` (`message_queue: Arc<RwLock<MessageQueue>>`)
- Retry logic: `src/messaging/transport.rs:87-88`

**Behavior**:
- Messages queue locally on sender when delivery fails
- Queue retries delivery periodically (every 30 seconds)
- Messages expire after 1 hour (DHT TTL)
- No long-term offline storage

---

## Question 2: Where are offline messages stored?

**Answer**: **Sender device + DHT (encrypted, 1-hour TTL)**

**Storage locations**:
1. **Sender's local queue**: For retry attempts (in-memory, process lifetime)
2. **DHT**: Encrypted EncryptedMessage with 3600-second TTL

**Evidence**:
- DHT storage: `src/messaging/transport.rs:95` (`self.store_in_dht(message).await?`)
- DHT TTL: `src/placement/dht_records.rs:97` (`DEFAULT_TTL = 3600 seconds`)
- Queue storage: In-memory MessageQueue (not persisted to disk)

**NOT stored**:
- ❌ Dedicated offline message storage
- ❌ Long-term persistence beyond 1 hour
- ❌ Headless nodes as offline mailboxes

---

## Question 3: How are offline users notified when they come online?

**Answer**: **Passive retrieval from DHT** (no active notification)

**Mechanism**:
- Recipient's device polls DHT for messages when online
- No push notifications or out-of-band alerts
- Message retrieval is recipient-initiated

**Implication**: Recipients must come online within 1-hour TTL to receive messages.

---

## Question 4: Are ephemeral messages stored offline?

**Answer**: **All messages are ephemeral** (1-hour maximum)

**Evidence**:
- Ephemeral field: `src/messaging/types.rs:138-145`
- All messages in DHT have 1-hour TTL (ephemeral by default)
- No persistent storage beyond TTL

**Distinction**:
- The `ephemeral` field in RichMessage may indicate user preference
- But all messages are effectively ephemeral due to 1-hour DHT TTL
- No distinction in storage behavior

---

## Question 5: What is the retention period for offline messages?

**Answer**: **1 hour (3600 seconds)** - DHT TTL default

**Evidence**:
- DHT TTL: `src/placement/dht_records.rs:97`
- Cleanup mechanism: `src/dht/optimized_storage.rs:201-255`
- Record expiration: `expires_at = created_at + TTL`

**Behavior**:
- Messages older than 1 hour automatically removed from DHT
- Sender's local queue may expire earlier (process restart)
- No republish or TTL extension

---

## Architectural Implications

### Impact on Encryption Strategy

**From ADR-013**:
- ✅ Short TTL (1 hour) supports privacy-first approach
- ✅ Reduced storage requirements on DHT nodes
- ✅ Aligns with real-time collaboration model

**Does NOT change encryption requirements**:
- Application-layer encryption still REQUIRED for DHT storage
- ChaCha20Poly1305 must be maintained (from Task 2 finding)
- No change to encryption architecture based on offline delivery decision

### User Experience Implications

**Current behavior**:
- Messages delivered if recipient online within 1 hour
- Messages lost if recipient offline > 1 hour
- No delivery confirmation for expired messages

**User expectation**:
- Real-time communication model (like chat, not email)
- Users should be online for active communication
- Asynchronous workflows may require application-level solutions

---

## Future Considerations (from ADR-013)

If offline delivery is added later:

### Potential Approaches
1. **Configurable TTL**: User/channel-specific TTL (1 hour - 7 days)
2. **Mailbox Nodes**: Dedicated nodes for offline storage (opt-in)
3. **Encrypted Relay**: Store encrypted messages on recipient's designated nodes
4. **Forward Error Correction**: FEC codes for resilient long-term storage

### Triggers for Reconsideration
- User feedback indicating need for longer offline windows
- Saorsa expanding beyond real-time collaboration
- Better privacy-preserving storage solutions emerge
- DHT storage economics improve

---

## Code Evidence Summary

| Finding | File | Line(s) | Evidence |
|---------|------|---------|----------|
| Message queue implementation | transport.rs | 312-319 | `queue_message()` function |
| Message queue field | transport.rs | 27 | `message_queue: Arc<RwLock<MessageQueue>>` |
| DHT storage call | transport.rs | 95 | `self.store_in_dht(message).await?` |
| DHT TTL constant | dht_records.rs | 97 | `DEFAULT_TTL = Duration::from_secs(3600)` |
| DHT cleanup | optimized_storage.rs | 201-255 | `cleanup_expired()` |
| Ephemeral field | types.rs | 138-145 | `ephemeral: bool` in RichMessage |
| Record expiration | dht/mod.rs | 90-124 | `expires_at = created_at + record_ttl` |

---

## Summary

**Offline Message Delivery in Saorsa**:
- **Supported**: Short-term (1 hour) via DHT storage and sender queue
- **Not supported**: Long-term offline delivery (> 1 hour)
- **Architectural decision**: No extended offline delivery (v1)
- **Future**: May add based on user feedback (see ADR-013)

**Critical finding for Phase 2**:
This decision does NOT change the encryption strategy. Application-layer encryption (ChaCha20Poly1305) is still required for DHT storage, regardless of message lifetime.

---

## Answer to Question 2

**Does Saorsa support offline message delivery?**

**Answer**: **YES (limited)** - Short-term offline delivery via 1-hour DHT TTL

**Clarification**:
- ✅ Messages stored in DHT for 1 hour (encrypted)
- ✅ Sender queues locally for retry attempts
- ❌ No long-term offline storage (> 1 hour)
- ❌ No dedicated offline delivery infrastructure

**Architectural Decision**: Saorsa v1 prioritizes real-time communication with 1-hour maximum offline window. Extended offline delivery is deferred to future versions based on user feedback.

**Reference**: ADR-013 (docs/adr/ADR-013-no-offline-delivery-v1.md)

---

**Task 3 Complete**: 2026-01-29
**Decision**: ADR-013 created for future consideration
**Next**: Task 4 - Routing Strategy Analysis
