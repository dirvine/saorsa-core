# Phase 2: Architecture Analysis - Task Plan

**Project**: Message Encoding Optimization for saorsa-core
**Phase**: Architecture Analysis (Milestone 1)
**Goal**: Answer 5 critical architectural questions and document complete message flow

---

## Overview

This phase focuses on understanding the exact message flow patterns in saorsa-core to determine the correct encryption strategy. We need to answer the 5 critical questions identified in `.planning/ARCHITECTURE-ENCRYPTION.md`:

1. Does Saorsa use DHT storage for user messages?
2. Does Saorsa support offline message delivery?
3. Does Saorsa use multi-hop routing?
4. Are messages ephemeral (live) or persistent?
5. Is forward secrecy required for historical messages?

---

## Task 1: Message Flow Mapping (Direct P2P)

**Goal**: Document the complete message flow for direct peer-to-peer communication

**Files to analyze**:
- `src/messaging/service.rs` (lines 1-350)
- `src/messaging/transport.rs` (lines 1-200)
- `src/transport/ant_quic_adapter.rs` (lines 1-100)
- `src/messaging/types.rs` (lines 80-145 - RichMessage structure)

**Questions to answer**:
1. What is the exact flow from `send_message()` to wire transmission?
2. Which layers perform serialization (JSON vs bincode)?
3. Where does ant-quic encryption begin and end?
4. What is the packet format at each layer?
5. Are direct messages always synchronous, or can they be queued?

**Output**:
- Create `.planning/architecture-analysis/01-direct-p2p-flow.md`
- Include sequence diagram (text-based) showing:
  - RichMessage creation
  - Encryption steps
  - Serialization layers
  - Transport handoff
  - Wire format

**Acceptance criteria**:
- All serialization points identified with line numbers
- Encryption boundaries clearly marked
- Packet overhead calculated at each layer
- Flow diagram validated against code

---

## Task 2: DHT Storage Analysis

**Goal**: Determine if and how user messages are stored in DHT

**Files to analyze**:
- `src/messaging/transport.rs` (line 95, 324-350 - `store_in_dht()`)
- `src/messaging/database.rs` (lines 187-285 - `store_message()`)
- `src/dht/core_engine.rs` (lines 1-100 - DHT operations)
- `src/dht/client.rs` (find `put()` and `get()` methods)
- `src/messaging/encryption.rs` (check for DHT key encryption)

**Questions to answer**:
1. **CRITICAL**: Are RichMessages stored in DHT, or only metadata?
2. What is stored in DHT: encrypted message, or DHT pointer?
3. Who can read DHT-stored data (headless nodes, anyone)?
4. How long are messages persisted in DHT?
5. Is message-level encryption applied before DHT storage?

**Output**:
- Create `.planning/architecture-analysis/02-dht-storage.md`
- Document:
  - What data is stored in DHT (with byte sizes)
  - Encryption state before DHT storage
  - Access control for DHT records
  - Persistence duration and cleanup

**Acceptance criteria**:
- Answer Question 1: "Does Saorsa use DHT storage for user messages?" (YES/NO with evidence)
- Line numbers showing exact DHT storage calls
- Identify if messages are encrypted before DHT storage
- Determine if headless nodes can read message content

---

## Task 3: Offline Message Delivery Analysis

**Goal**: Understand offline message queue and delivery mechanisms

**Files to analyze**:
- `src/messaging/transport.rs` (line 27, 87-88 - `message_queue`, `queue_message()`)
- `src/messaging/types.rs` (lines 138-145 - ephemeral field)
- `src/types/presence.rs` (device online/offline states)
- `src/messaging/service.rs` (offline message handling)

**Questions to answer**:
1. **CRITICAL**: Does Saorsa queue messages for offline users?
2. Where are offline messages stored (sender device, headless node, DHT)?
3. How are offline users notified when they come online?
4. Are ephemeral messages (line 138 in types.rs) stored offline?
5. What is the retention period for offline messages?

**Output**:
- Create `.planning/architecture-analysis/03-offline-delivery.md`
- Document:
  - Offline detection mechanism
  - Queue storage location (local vs distributed)
  - Delivery trigger when user comes online
  - Ephemeral vs persistent message handling

**Acceptance criteria**:
- Answer Question 2: "Does Saorsa support offline message delivery?" (YES/NO with evidence)
- Identify all offline message storage locations
- Determine if offline messages need end-to-end encryption
- Document retention and expiry policies

---

## Task 4: Routing Strategy Analysis

**Goal**: Determine if messages use multi-hop routing or relaying

**Files to analyze**:
- `src/adaptive/mod.rs` (routing strategies)
- `src/network.rs` (message routing logic)
- `src/messaging/transport.rs` (direct delivery vs relaying)
- `src/bootstrap/manager.rs` (relay node usage)
- `src/types/presence.rs` (headless device roles)

**Questions to answer**:
1. **CRITICAL**: Are messages routed through intermediate nodes (multi-hop)?
2. Do headless devices act as message relays?
3. Is routing strategy selected dynamically (adaptive)?
4. What information do intermediate nodes see (metadata, content)?
5. Are there scenarios where direct P2P is impossible, requiring relay?

**Output**:
- Create `.planning/architecture-analysis/04-routing-strategies.md`
- Document:
  - Direct P2P conditions
  - Multi-hop routing scenarios (if any)
  - Relay node selection criteria
  - NAT traversal vs relaying trade-offs
  - What data intermediate nodes can access

**Acceptance criteria**:
- Answer Question 3: "Does Saorsa use multi-hop routing?" (YES/NO with evidence)
- Identify all routing paths (direct, NAT-traversed, relayed)
- Determine if relays can read message content
- Document when multi-hop is used vs avoided

---

## Task 5: Message Persistence Classification

**Goal**: Classify messages by persistence requirements (ephemeral vs persistent)

**Files to analyze**:
- `src/messaging/types.rs` (line 138 - `ephemeral` field, lines 135 - `expires_at`)
- `src/messaging/service.rs` (ephemeral message handling)
- `src/messaging/database.rs` (line 584 - `cleanup_ephemeral()`)
- `src/messaging/transport.rs` (line 95 - DHT storage for all messages?)

**Questions to answer**:
1. **CRITICAL**: Are all messages persistent, or are some ephemeral?
2. What determines if a message is ephemeral vs persistent?
3. Are ephemeral messages stored in DHT (contradictory to ephemeral nature)?
4. Do ephemeral messages skip encryption (performance optimization)?
5. What is the default: ephemeral or persistent?

**Output**:
- Create `.planning/architecture-analysis/05-message-persistence.md`
- Document:
  - Message classification (ephemeral vs persistent)
  - Storage behavior for each type
  - Encryption requirements for each type
  - Default behavior (user choice vs automatic)

**Acceptance criteria**:
- Answer Question 4: "Are messages ephemeral (live) or persistent?" (with breakdown)
- Identify message type selection logic
- Determine if ephemeral messages still get encrypted
- Document TTL and cleanup for both types

---

## Task 6: Forward Secrecy Analysis

**Goal**: Assess forward secrecy requirements for stored messages

**Files to analyze**:
- `src/messaging/encryption.rs` (lines 230-260 - `create_ephemeral_session()`)
- `src/messaging/key_exchange.rs` (key rotation mechanisms)
- `src/dht/core_engine.rs` (message retention periods)
- `.planning/ARCHITECTURE-ENCRYPTION.md` (lines 230-253 - hybrid approach)

**Questions to answer**:
1. **CRITICAL**: Is forward secrecy required for historical messages in DHT?
2. Are ephemeral keys used per message, or long-lived keys?
3. How often are encryption keys rotated?
4. If keys are compromised, can historical DHT messages be decrypted?
5. Does ant-quic PQC provide forward secrecy for in-transit messages?

**Output**:
- Create `.planning/architecture-analysis/06-forward-secrecy.md`
- Document:
  - Current key management strategy
  - Forward secrecy guarantees (transport vs storage)
  - Key rotation frequency
  - Impact of key compromise on historical data

**Acceptance criteria**:
- Answer Question 5: "Is forward secrecy required for historical messages?" (YES/NO with rationale)
- Identify key lifetime (ephemeral vs persistent)
- Document gaps in forward secrecy coverage
- Assess risk of stored message exposure

---

## Task 7: Encryption Layer Audit

**Goal**: Map all encryption layers and identify redundancy

**Files to analyze**:
- `src/messaging/encryption.rs` (application-layer encryption)
- `src/transport/ant_quic_adapter.rs` (transport-layer PQC)
- `src/messaging/types.rs` (line 360-369 - EncryptedMessage wrapper)
- `.planning/baseline-measurements.md` (encryption overhead data)

**Questions to answer**:
1. How many encryption layers exist in the current implementation?
2. Which layer uses ChaCha20Poly1305 (28B overhead)?
3. Which layer uses ML-KEM-768 (16B overhead)?
4. Where is the redundancy (same data encrypted multiple times)?
5. Can any encryption layer be safely removed?

**Output**:
- Create `.planning/architecture-analysis/07-encryption-layers.md`
- Document:
  - Complete encryption stack (bottom to top)
  - Overhead at each layer
  - Security properties provided by each layer
  - Redundant encryption identification

**Acceptance criteria**:
- Visual diagram of encryption stack
- Overhead calculation (total and per-layer)
- Identify which encryption is redundant for direct P2P
- Identify which encryption is necessary for DHT storage

---

## Task 8: Synthesis and Architectural Decision

**Goal**: Answer all 5 questions and update encryption strategy

**Inputs**:
- All 7 task outputs from above
- `.planning/ARCHITECTURE-ENCRYPTION.md` (original threat model)
- `.planning/baseline-measurements.md` (performance data)

**Questions to answer** (final summary):
1. **Q1**: Does Saorsa use DHT storage for user messages? → **YES/NO**
2. **Q2**: Does Saorsa support offline message delivery? → **YES/NO**
3. **Q3**: Does Saorsa use multi-hop routing? → **YES/NO**
4. **Q4**: Are messages ephemeral or persistent? → **BOTH/EPHEMERAL/PERSISTENT**
5. **Q5**: Is forward secrecy required? → **YES/NO**

**Output**:
- Create `.planning/architecture-analysis/08-synthesis.md`
- Document:
  - Answer all 5 questions with YES/NO and evidence summary
  - Recommend encryption strategy:
    - **Scenario A**: Direct P2P ephemeral messages
    - **Scenario B**: DHT-stored persistent messages
    - **Scenario C**: Offline queued messages
    - **Scenario D**: Multi-hop routed messages (if applicable)
  - Update `.planning/ARCHITECTURE-ENCRYPTION.md` with findings
  - Validate/revise "Hybrid Approach" recommendation (lines 220-253)

**Acceptance criteria**:
- All 5 questions definitively answered with code evidence
- Clear encryption recommendation for each message scenario
- Updated threat model in ARCHITECTURE-ENCRYPTION.md
- Ready for Phase 3: Solution Design

---

## Success Criteria for Phase 2

- ✅ All 8 tasks completed with documentation artifacts
- ✅ All 5 architectural questions answered with code line references
- ✅ Complete message flow documented from sender to recipient
- ✅ Encryption strategy validated or revised based on findings
- ✅ No ambiguity remaining about when application-layer encryption is needed
- ✅ Phase 3 can proceed with confident architectural decisions

---

## Timeline Estimate

- Task 1-2: 2 hours (message flow + DHT analysis)
- Task 3-4: 2 hours (offline delivery + routing)
- Task 5-6: 1 hour (persistence + forward secrecy)
- Task 7-8: 2 hours (encryption audit + synthesis)

**Total**: ~7 hours (1 day)

---

## Notes

- **READ-ONLY**: No code changes in this phase
- **Evidence-based**: Every claim must cite file:line numbers
- **Comprehensive**: Don't skip edge cases or "probably" scenarios
- **Output format**: Markdown with code snippets and line references
