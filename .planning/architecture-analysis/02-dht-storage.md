# DHT Storage Analysis

## Overview

**Answer to Critical Question 1**: **YES** - Saorsa DOES use DHT storage for user messages, but only in **encrypted form**.

**What is stored**: EncryptedMessage structures (with ciphertext), NOT plaintext RichMessages.

**Privacy model**: DHT nodes (including headless) store encrypted blobs they cannot decrypt. Only recipients with session keys can decrypt message content.

---

## DHT Storage Flow

```
1. RichMessage Creation
   └─> src/messaging/service.rs:331-335

2. Encryption (ChaCha20Poly1305)
   └─> src/messaging/encryption.rs:44-74
   └─> RichMessage → JSON → encrypt → EncryptedMessage
   └─> Session key from key exchange or channel-derived

3. DHT Storage Decision
   └─> src/messaging/transport.rs:95
   └─> self.store_in_dht(message).await?;

4. Serialization for DHT
   └─> src/messaging/transport.rs:326
   └─> serde_json::to_vec(&encrypted_message)?

5. DHT Put Operation
   └─> src/messaging/transport.rs:328
   └─> self.dht_client.put(key, value).await?
   └─> Key format: "msg:{message_id}"
   └─> Value: JSON-serialized EncryptedMessage

6. DHT Distribution
   └─> src/dht/core_engine.rs:622-668
   └─> K=8 replication (stored on 8 nodes)
   └─> Geographic distribution via routing table
   └─> Load-balanced across nodes

7. Retrieval
   └─> Any node can retrieve by key (gets encrypted blob)
   └─> Decryption requires session key
```

---

## Data Stored in DHT

### EncryptedMessage Structure

**Location**: src/messaging/types.rs:362-369

```rust
pub struct EncryptedMessage {
    pub id: MessageId,            // 16 bytes (UUID)
    pub channel_id: ChannelId,    // 16 bytes (UUID)
    pub sender: FourWordAddress,  // ~20-30 bytes (string)
    pub ciphertext: Vec<u8>,      // ENCRYPTED RichMessage payload
    pub nonce: Vec<u8>,           // 12 bytes
    pub key_id: String,           // ~20-30 bytes
}
```

**Size estimate**:
- Metadata: ~84-92 bytes (id, channel_id, sender, nonce, key_id)
- Ciphertext: Variable (encrypted RichMessage JSON + 16-byte auth tag)
- Typical total: ~300-1000 bytes for text messages
- Large messages: Up to several KB for attachments

**Serialization**: JSON (serde_json) before DHT storage (src/messaging/transport.rs:326)

---

## Encryption State Before DHT Storage

### YES - Fully Encrypted

**Encryption flow** (src/messaging/encryption.rs:44-74):

1. **Input**: RichMessage (plaintext)
2. **Serialization**: RichMessage → JSON bytes
3. **Encryption**: ChaCha20Poly1305 AEAD
   - Algorithm: ChaCha20 stream cipher + Poly1305 MAC
   - Key size: 32 bytes (256-bit)
   - Nonce: 12 bytes (random, stored in EncryptedMessage.nonce)
   - Auth tag: 16 bytes (appended to ciphertext)
4. **Output**: EncryptedMessage with opaque ciphertext

**Key derivation** (src/messaging/encryption.rs:57-63):
- **Option 1**: From ML-KEM-768 key exchange (ephemeral session keys)
- **Option 2**: Deterministic from channel: `blake3(identity + channel_id)`

**Security properties**:
- ✅ Confidentiality: Ciphertext reveals no plaintext
- ✅ Integrity: Poly1305 MAC prevents tampering
- ✅ Authenticated encryption: AEAD guarantees
- ⚠️ Forward secrecy: Only if ephemeral keys used (key exchange)

---

## Access Control & Visibility

### Who Can Read DHT-Stored Data

**DHT nodes (including headless)**:
- ✅ Can read: Encrypted EncryptedMessage blobs
- ❌ Cannot decrypt: No access to session keys
- ❌ Cannot infer: Sender/recipient metadata from ciphertext

**Recipients**:
- ✅ Can decrypt: If they have session key from key exchange
- ✅ Can retrieve: By message ID (DHT key lookup)

**Third parties**:
- ❌ Cannot read: Encrypted blobs
- ❌ Cannot decrypt: No session keys
- ⚠️ Can observe: DHT key patterns (message IDs)

### DHT Visibility Model

**Location**: src/dht/core_engine.rs:622-668

**Replication**:
- K=8 nodes store each message (src/dht/mod.rs:24)
- Nodes selected via Kademlia XOR distance
- Geographic distribution for fault tolerance

**Access pattern**:
- Any node can call `dht.get(key)` → receives encrypted blob
- No authentication required to retrieve (public DHT)
- Decryption requires session key (cryptographic access control)

**Threat model**:
- **DHT nodes are untrusted**: Can read encrypted blobs, cannot decrypt
- **Network observers**: Can see DHT traffic (keys requested), not content
- **Colluding nodes**: Cannot decrypt even if all 8 replicas collude

---

## Persistence & Cleanup

### TTL Duration

**Default**: 3600 seconds (1 hour)

**Location**: src/dht/mod.rs:81, 115

```rust
pub struct DHTConfig {
    pub record_ttl: Duration, // Default: Duration::from_secs(3600)
    // ...
}
```

**Configurable**: Yes, via DHTConfig.record_ttl

### Record Structure

**Location**: src/dht/mod.rs:90-124

```rust
pub struct Record {
    pub key: Key,                  // DHT key (e.g., "msg:{uuid}")
    pub value: Vec<u8>,            // Serialized EncryptedMessage
    pub publisher: PeerId,         // Node that stored it
    pub created_at: SystemTime,    // Storage timestamp
    pub expires_at: SystemTime,    // created_at + record_ttl
}
```

### Cleanup Mechanisms

**Location**: src/dht/optimized_storage.rs:201-255

**Function**: `cleanup_expired()`

**Algorithm**:
- Performance: O(log n + k) where k = expired records
- Data structure: BTreeMap<SystemTime, Vec<Key>> (expiration index)
- Trigger: Automatic, periodic (implementation-specific)
- Action: Remove records where `SystemTime::now() > expires_at`

**Efficiency**:
- Uses expiration index for fast lookup
- No full table scan required
- Removes expired records in batches

### Retention Policy

**Messages persist for**:
- **1 hour (default)** from storage time
- **Extendable**: Republish to reset TTL (Kademlia republish protocol)
- **Non-renewable**: After expiration, permanently removed

**Implications**:
- Short TTL (1 hour) limits offline message delivery window
- Recipients must come online within 1 hour to retrieve
- May be too short for typical offline scenarios (days/weeks)

---

## Answer to Question 1

### Does Saorsa use DHT storage for user messages?

**YES**

**Evidence**:
- **Storage call**: src/messaging/transport.rs:95 - `self.store_in_dht(message).await?;`
- **Implementation**: src/messaging/transport.rs:324-332 - `store_in_dht()` function
- **DHT client**: src/messaging/transport.rs:328 - `self.dht_client.put(key, value).await?`
- **Record type**: EncryptedMessage (encrypted), not RichMessage (plaintext)

**What is stored**:
- EncryptedMessage with opaque ciphertext
- Session key NOT stored in DHT (maintained separately)
- Metadata visible: message ID, channel ID, sender address, nonce, key_id

**Privacy guarantee**:
- DHT nodes store encrypted blobs they cannot decrypt
- Only recipients with session keys can decrypt content
- Headless nodes act as encrypted relay/storage

---

## Answers to All 5 Questions

### 1. Are RichMessages stored in DHT, or only metadata?

**Answer**: **EncryptedMessages** (not RichMessages, not metadata only)

**Clarification**:
- **Not RichMessage**: Plaintext never touches DHT
- **Not metadata only**: Full encrypted payload stored
- **EncryptedMessage**: Encrypted RichMessage with ciphertext

**Evidence**: src/messaging/transport.rs:324-332 (stores EncryptedMessage)

---

### 2. What is stored in DHT: encrypted message, or DHT pointer?

**Answer**: **Encrypted message** (full EncryptedMessage structure)

**Not a pointer**:
- DHT value is the full serialized EncryptedMessage
- Contains ciphertext of entire RichMessage
- Not a reference to external storage

**Evidence**: src/messaging/transport.rs:326-328 (serializes and stores full EncryptedMessage)

---

### 3. Who can read DHT-stored data?

**Answer**: Anyone can **read** (retrieve encrypted blobs), only recipients can **decrypt**

**Read access** (retrieve encrypted blobs):
- ✅ DHT nodes (including headless)
- ✅ Network participants with DHT client
- ✅ Any node can call `dht.get(key)`

**Decrypt access** (read plaintext):
- ✅ Recipients with session keys
- ❌ DHT nodes (no session keys)
- ❌ Third parties

**Evidence**:
- DHT visibility: src/dht/core_engine.rs:622-668 (public read)
- Encryption: src/messaging/encryption.rs:44-74 (session keys required)

---

### 4. How long are messages persisted in DHT?

**Answer**: **1 hour (3600 seconds)** by default

**TTL configuration**:
- Default: src/dht/mod.rs:81, 115 (3600 seconds)
- Configurable: DHTConfig.record_ttl
- Cleanup: src/dht/optimized_storage.rs:201-255 (automatic expiration)

**Implications**:
- Short window for offline message delivery
- Messages older than 1 hour automatically removed
- May need republish for longer persistence

**Evidence**: src/dht/mod.rs:90-124 (Record.expires_at = created_at + record_ttl)

---

### 5. Is message-level encryption applied before DHT storage?

**Answer**: **YES** - ChaCha20Poly1305 encryption before DHT storage

**Encryption flow**:
1. RichMessage (plaintext)
2. Encrypt with ChaCha20Poly1305 → EncryptedMessage (ciphertext)
3. Serialize EncryptedMessage → JSON bytes
4. Store in DHT → encrypted blob

**Evidence**:
- Encryption: src/messaging/encryption.rs:44-74
- Storage: src/messaging/transport.rs:324-332 (stores EncryptedMessage, not RichMessage)

**Security properties**:
- ✅ Confidentiality: DHT nodes cannot read message content
- ✅ Integrity: Poly1305 MAC prevents tampering
- ✅ Privacy-preserving: DHT storage is encrypted relay

---

## Architectural Implications for Encryption Strategy

### Current Design Assessment

**Strengths**:
- ✅ **Privacy-preserving DHT**: Headless nodes store encrypted blobs they cannot decrypt
- ✅ **Double encryption**: E2E (ChaCha20Poly1305) + Transport (ant-quic ML-KEM-768)
- ✅ **Symmetric AEAD**: Fast encryption with authenticated encryption
- ✅ **Untrusted nodes**: DHT nodes don't need to be trusted

**Weaknesses**:
- ⚠️ **Short TTL (1 hour)**: May be too short for offline recipients
- ⚠️ **No forward secrecy**: If deterministic key derivation used (channel-based)
- ⚠️ **Session key persistence**: Keys may be reused across messages

### Implications for Question 1 (Architectural Decision)

**From `.planning/ARCHITECTURE-ENCRYPTION.md`**:

The 5 critical questions were:
1. ✅ **DHT storage for user messages?** → YES (encrypted)
2. Offline message delivery? → (Task 3 analysis needed)
3. Multi-hop routing? → (Task 4 analysis needed)
4. Ephemeral vs persistent? → (Task 5 analysis needed)
5. Forward secrecy required? → (Task 6 analysis needed)

**Decision impact**:
- **DHT storage = YES** → Application-layer encryption REQUIRED
- Cannot rely on transport-only encryption (ant-quic)
- DHT nodes are untrusted third parties
- Must maintain E2E encryption even when stored

**Encryption removal verdict (from threat model)**:
- ❌ **Cannot remove application-layer encryption** for DHT-stored messages
- ✅ **Must maintain ChaCha20Poly1305** before DHT storage
- ⚠️ **Could optimize direct P2P** (non-DHT) if desired

**Recommendation**:
- Keep application-layer encryption for DHT storage
- Consider hybrid approach: direct P2P (transport-only) vs DHT (E2E)
- Requires conditional logic based on delivery path

---

## Code Evidence Summary

| Finding | File | Line(s) | Evidence |
|---------|------|---------|----------|
| DHT storage call | transport.rs | 95 | `self.store_in_dht(message).await?` |
| Storage implementation | transport.rs | 324-332 | `store_in_dht()` function |
| DHT put operation | transport.rs | 328 | `self.dht_client.put(key, value)` |
| EncryptedMessage structure | types.rs | 362-369 | 6 fields (id, channel_id, sender, ciphertext, nonce, key_id) |
| Encryption before storage | encryption.rs | 44-74 | ChaCha20Poly1305 encryption |
| Key derivation | encryption.rs | 57-63 | Key exchange or channel-based |
| DHT replication | core_engine.rs | 622-668 | K=8 replication factor |
| Record TTL | mod.rs | 81, 115 | 3600 seconds default |
| Record structure | mod.rs | 90-124 | expires_at = created_at + TTL |
| Cleanup mechanism | optimized_storage.rs | 201-255 | `cleanup_expired()` O(log n + k) |

---

## Summary

**DHT Storage in Saorsa**:
- **Used**: YES, for encrypted message storage and relay
- **Privacy**: Preserved via application-layer encryption
- **Access**: Public read (encrypted blobs), cryptographic decrypt control
- **Persistence**: 1 hour default TTL with automatic cleanup
- **Threat model**: DHT nodes are untrusted, cannot decrypt

**Critical architectural finding**:
Saorsa's use of DHT storage for encrypted messages means **application-layer encryption cannot be removed** without compromising privacy. The double encryption (E2E + transport) is necessary because DHT nodes are untrusted third parties that store message data.

This definitively answers the first of the 5 architectural questions required for Phase 2.
