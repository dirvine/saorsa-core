# Direct P2P Message Flow Analysis

## Overview

The direct P2P message flow in saorsa-core follows a 5-layer architecture from RichMessage creation to wire transmission. Messages are serialized three times (JSON for RichMessage→ciphertext, JSON for EncryptedMessage→transport, JSON for Protocol wrapper→wire), encrypted once with ChaCha20Poly1305, and wrapped in a protocol envelope before transmission via ant-quic QUIC streams. Messages that fail direct delivery are queued for retry with a 30-second interval and expire after 7 days.

## Message Flow Sequence

```
1. RichMessage Creation (MessagingService::send_message)
   └─> src/messaging/service.rs:331-335

2. Key Exchange (if needed)
   └─> src/messaging/service.rs:354-393
   └─> ML-KEM-768 key exchange via DHT-published public keys
   └─> src/messaging/key_exchange.rs:48-85 (PQC-only key exchange with DHT)
   └─> Public keys stored in DHT with "pqc:kem:" prefix (src/messaging/key_exchange.rs:16, 62)

3. RichMessage → JSON Serialization
   └─> src/messaging/service.rs:664 (serde_json::to_vec)
   └─> Plaintext: ~500-2000 bytes (varies by content)

4. ChaCha20Poly1305 Encryption
   └─> src/messaging/service.rs:662-674
   └─> Input: JSON plaintext
   └─> Output: ciphertext + 12-byte nonce
   └─> Overhead: 28 bytes (16 auth tag + 12 nonce)

5. EncryptedMessage Construction
   └─> src/messaging/service.rs:676-683
   └─> Wraps ciphertext with metadata

6. EncryptedMessage → JSON Serialization
   └─> src/messaging/transport.rs:246 (serde_json::to_vec)
   └─> Second JSON serialization!

7. Protocol Message Wrapper (P2PNode)
   └─> src/network.rs:1645-1669
   └─> Wraps in JSON: {"protocol", "data", "from", "timestamp"}
   └─> Third JSON serialization!

8. ant-quic QUIC Stream Transmission
   └─> src/transport/ant_quic_adapter.rs:388-409
   └─> Unidirectional QUIC stream
   └─> ML-KEM-768 post-quantum encryption at transport layer
   └─> QUIC framing overhead: ~20-40 bytes per packet
```

## Serialization Points

### Serialization Point 1: RichMessage → Plaintext
- **Location**: src/messaging/service.rs:664
- **Format**: JSON (serde_json)
- **Size overhead**: ~40% over raw data (JSON field names, structure)
- **Purpose**: Convert structured message to bytes for encryption
- **Input**: RichMessage struct with 21 fields
- **Output**: JSON bytes (plaintext)

**Estimated overhead calculation**:
```
RichMessage fields (from types.rs:82-144):
- UUIDs: 48 bytes (id, thread_id, channel_id as UUIDs)
- Strings: Variable (sender, sender_device, content)
- Timestamps: 24 bytes (created_at, edited_at, deleted_at, expires_at)
- Collections: Variable (attachments, mentions, reactions, read_by, delivered_to)
- Metadata: ~50 bytes (flags, counters)

Typical message (text only): ~200 bytes raw → ~300 bytes JSON (~50% overhead)
```

### Serialization Point 2: EncryptedMessage → Wire Format
- **Location**: src/messaging/transport.rs:246
- **Format**: JSON (serde_json)
- **Size overhead**: ~25% over encrypted payload
- **Purpose**: Transport-layer message format
- **Input**: EncryptedMessage (6 fields)
- **Output**: JSON bytes ready for P2P protocol wrapper

**EncryptedMessage structure** (src/messaging/types.rs:362-369):
```rust
pub struct EncryptedMessage {
    pub id: MessageId,            // 16 bytes (UUID)
    pub channel_id: ChannelId,    // 16 bytes (UUID)
    pub sender: FourWordAddress,  // ~20-30 bytes (string)
    pub ciphertext: Vec<u8>,      // Variable (encrypted RichMessage)
    pub nonce: Vec<u8>,           // 12 bytes
    pub key_id: String,           // ~20-30 bytes
}
```

**Overhead**: JSON field names add ~80 bytes for structure

### Serialization Point 3: Protocol Message Wrapper
- **Location**: src/network.rs:1645-1669
- **Format**: JSON (serde_json)
- **Size overhead**: ~100 bytes for protocol metadata
- **Purpose**: P2P protocol multiplexing and routing
- **Structure**:
```json
{
  "protocol": "messaging",      // ~10 bytes
  "data": [encrypted_message],  // From serialization point 2
  "from": "peer_id_hex",       // 64 bytes (hex string)
  "timestamp": 1234567890       // 8 bytes
}
```

## Encryption Boundaries

### Boundary 1: Application Layer E2E Encryption (ChaCha20Poly1305)
- **Start**: src/messaging/service.rs:662 (ChaCha20Poly1305Cipher::new)
- **End**: src/messaging/service.rs:673 (cipher.encrypt() completes)
- **Algorithm**: ChaCha20Poly1305 (saorsa-pqc crate)
- **Overhead**: 28 bytes
  - 16 bytes: Poly1305 authentication tag
  - 12 bytes: Nonce (stored in EncryptedMessage.nonce)
- **Key Source**: Session key from ML-KEM-768 key exchange
- **Protects**: RichMessage content and metadata (everything in JSON)

### Boundary 2: Transport Layer PQC Encryption (ant-quic)
- **Start**: src/transport/ant_quic_adapter.rs:391 (transport.dial())
- **End**: src/transport/ant_quic_adapter.rs:407 (stream.finish())
- **Algorithm**: ML-KEM-768 (post-quantum key exchange) + QUIC encryption
- **Overhead**: ~16 bytes per QUIC packet (built into QUIC)
- **Key Source**: ant-quic's automatic post-quantum key exchange
- **Protects**: Entire protocol message (double-encrypted payload at this layer)

**Note**: ant-quic handles encryption transparently via QUIC's built-in encryption, enhanced with post-quantum ML-KEM-768 for key exchange.

## Packet Format at Each Layer

### Layer 1: RichMessage (Application)
```
[RichMessage Structure - src/messaging/types.rs:82-144]
├─ id: MessageId (16 bytes UUID)
├─ thread_id: Option<ThreadId> (0 or 18 bytes)
├─ channel_id: ChannelId (16 bytes UUID)
├─ sender: UserHandle (String, ~20-50 bytes)
├─ sender_device: DeviceId (String, ~10-20 bytes)
├─ content: MessageContent (Variable, 10-10,000+ bytes)
├─ attachments: Vec<Attachment> (Variable, 0-N * 100+ bytes)
├─ mentions: Vec<UserHandle> (Variable)
├─ reply_to: Option<MessageId> (0 or 18 bytes)
├─ thread_count: u32 (4 bytes)
├─ last_thread_reply: Option<DateTime> (0 or 12 bytes)
├─ reactions: HashMap<String, Vec<UserHandle>> (Variable)
├─ read_by: HashMap<UserHandle, DateTime> (Variable)
├─ delivered_to: HashMap<UserHandle, DateTime> (Variable)
├─ created_at: DateTime<Utc> (12 bytes)
├─ edited_at: Option<DateTime> (0 or 12 bytes)
├─ deleted_at: Option<DateTime> (0 or 12 bytes)
├─ expires_at: Option<DateTime> (0 or 12 bytes)
├─ ephemeral: bool (1 byte)
├─ encryption: EncryptionMethod (1 byte enum)
└─ signature: MessageSignature (2 + Vec<u8> bytes)

Typical size (text message): 200-500 bytes binary, 300-700 bytes JSON
```

### Layer 2: EncryptedMessage (After Encryption)
```
[EncryptedMessage Structure - src/messaging/types.rs:362-369]
├─ id: MessageId (16 bytes UUID)
├─ channel_id: ChannelId (16 bytes UUID)
├─ sender: FourWordAddress (String, ~20-30 bytes)
├─ ciphertext: Vec<u8> (RichMessage JSON + 16 bytes auth tag)
├─ nonce: Vec<u8> (12 bytes)
└─ key_id: String (~20-30 bytes)

Serialization: JSON
Total overhead from Layer 1:
- Encryption: +28 bytes (auth tag + nonce)
- JSON field names: +80 bytes
- Total: ~400-800 bytes for typical message
```

### Layer 3: Protocol Message (Network Layer)
```
[P2P Protocol Wrapper - src/network.rs:1658-1663]
{
  "protocol": "messaging" (String),      // +10 bytes
  "data": [EncryptedMessage JSON],       // From Layer 2
  "from": "peer_id_hex" (String),       // +64 bytes (32-byte PeerId as hex)
  "timestamp": unix_timestamp (u64)      // +8 bytes
}

Serialization: JSON (again!)
Total overhead from Layer 2:
- Protocol metadata: +82 bytes
- JSON wrapping: +20 bytes
- Total: ~500-900 bytes for typical message
```

### Layer 4: QUIC Transport (ant-quic)
```
[QUIC Stream - src/transport/ant_quic_adapter.rs:395-407]
├─ QUIC packet header (~20-40 bytes variable)
│  ├─ Connection ID (0-20 bytes)
│  ├─ Packet number (1-4 bytes)
│  └─ Frame type markers (~5 bytes)
├─ Stream frame header (~8 bytes)
│  ├─ Stream ID (variable int)
│  └─ Length field (variable int)
├─ QUIC encryption overhead (~16 bytes per packet)
│  └─ Authentication tag (built into QUIC)
└─ Payload (Protocol Message JSON)

Transport: Unidirectional QUIC stream (stream.open_uni())
Post-quantum: ML-KEM-768 key exchange (handled by ant-quic)
Total overhead from Layer 3: +44-64 bytes per packet
Final wire size: ~550-970 bytes for typical text message
```

## Message Queueing Analysis

**Are messages queued?** YES (src/messaging/transport.rs:552-587)

**Conditions for queueing** (src/messaging/transport.rs:78-90):
1. Direct delivery fails (connection error, peer unreachable)
2. Peer not found in DHT
3. Network error during send

**Queue location**: MessageTransport maintains Arc<RwLock<MessageQueue>>

**Queue structure** (src/messaging/transport.rs:552-562):
```rust
struct MessageQueue {
    messages: HashMap<MessageId, QueuedMessage>,
    by_recipient: HashMap<FourWordAddress, Vec<MessageId>>,
}
```

**Queued message details** (src/messaging/transport.rs:608-614):
```rust
struct QueuedMessage {
    message: EncryptedMessage,
    recipient: FourWordAddress,
    queued_at: DateTime<Utc>,
    retry_count: u32,
}
```

**Queue processing** (src/messaging/transport.rs:212-237):
- Background task runs every 30 seconds (src/messaging/transport.rs:217)
- Retries delivery for all queued messages (src/messaging/transport.rs:225-230)
- **CRITICAL**: retry_count is checked at line 583 (`q.retry_count < 5`) but NEVER INCREMENTED
- Messages expire after 7 days based on queued_at timestamp (src/messaging/transport.rs:597-604)

**Actual retry behavior** (important correction):
- retry_count is initialized to 0 (src/messaging/transport.rs:570)
- retry_count is checked: `q.retry_count < 5` filter (src/messaging/transport.rs:583)
- **retry_count is NEVER incremented** anywhere in the queue processing loop
- This means messages will retry indefinitely every 30 seconds until they expire
- Expiration trigger: messages older than 7 days are removed (src/messaging/transport.rs:598)

**Message lifecycle**:
1. Direct delivery attempted (src/messaging/transport.rs:78)
2. On failure: queued with DeliveryStatus::Queued (src/messaging/transport.rs:87-89)
3. Background retry every 30 seconds (src/messaging/transport.rs:217)
4. Success: removed from queue via mark_delivered (src/messaging/transport.rs:228, 588-595)
5. No success: remains queued and retries indefinitely
6. Cleanup: messages older than 7 days removed (src/messaging/transport.rs:597-604)

**Important architectural note**:
- The `retry_count` field suggests bounded retries (max 5), but the implementation is incomplete
- The code initializes retry_count=0 and checks <5, but never increments it during retries
- This is either a bug in the implementation or the field is unused legacy code
- **Actual behavior is unbounded retries with 7-day TTL, not 5-retry limit**

**Messages are asynchronous**: Direct delivery attempts are non-blocking, but failures result in async retry via background queue processor running on 30-second tick.

## Code Evidence

**Message creation and encryption flow**:
- src/messaging/service.rs:331-335 - RichMessage::new() creates base message
- src/messaging/service.rs:354-393 - Key exchange initiated if no session key exists
- src/messaging/service.rs:664 - RichMessage serialized to JSON: `serde_json::to_vec(message)?`
- src/messaging/service.rs:670-674 - ChaCha20Poly1305 encryption with 32-byte key
- src/messaging/service.rs:676-683 - EncryptedMessage constructed with ciphertext + nonce

**Transport serialization and transmission**:
- src/messaging/transport.rs:246 - EncryptedMessage serialized to JSON: `serde_json::to_vec(message)?`
- src/network.rs:1625-1626 - Protocol wrapper created: `create_protocol_message(protocol, data)`
- src/network.rs:1658-1663 - JSON wrapper with protocol, from, timestamp fields
- src/network.rs:1665 - Protocol message serialized: `serde_json::to_vec(&message)?`
- src/network.rs:1629 - Final transmission: `dual_node.send_to_peer_string(peer_id, &_message_data)`

**ant-quic transmission**:
- src/transport/ant_quic_adapter.rs:391 - Dial peer: `transport.dial(*peer_id, SAORSA_DHT_PROTOCOL)`
- src/transport/ant_quic_adapter.rs:395-398 - Open unidirectional stream: `conn.open_uni()`
- src/transport/ant_quic_adapter.rs:401-404 - Write data: `stream.write_all(data)`
- src/transport/ant_quic_adapter.rs:405-407 - Finalize stream: `stream.finish()`

**Message queueing**:
- src/messaging/transport.rs:84-89 - Failed delivery triggers queueing
- src/messaging/transport.rs:565-578 - Queue adds message with retry_count=0 and timestamp
- src/messaging/transport.rs:217 - Background task: `interval(Duration::from_secs(30))`
- src/messaging/transport.rs:225-230 - Retry delivery for queued messages
- src/messaging/transport.rs:583 - Filter check: `q.retry_count < 5` (NOTE: retry_count never incremented)
- src/messaging/transport.rs:588-595 - mark_delivered() removes message from queue on success
- src/messaging/transport.rs:597-604 - Cleanup expired: messages older than 7 days removed

## Overhead Summary

| Layer | Serialization | Encryption | Metadata | Total Overhead |
|-------|---------------|------------|----------|----------------|
| RichMessage → JSON | ~150 bytes | N/A | N/A | ~150 bytes |
| ChaCha20Poly1305 | N/A | 28 bytes | N/A | 28 bytes |
| EncryptedMessage JSON | ~80 bytes | N/A | ~90 bytes | ~170 bytes |
| Protocol Wrapper JSON | ~20 bytes | N/A | ~82 bytes | ~102 bytes |
| QUIC Transport | N/A | 16 bytes | ~28-48 bytes | ~44-64 bytes |
| **Total** | **~250 bytes** | **44 bytes** | **~200-220 bytes** | **~494-514 bytes** |

**For a typical text message** (e.g., "Hello World" - 11 bytes of actual content):
- Raw message: ~11 bytes
- After RichMessage JSON: ~300 bytes (serialization 1)
- After encryption: ~328 bytes (ChaCha20Poly1305 adds 28 bytes)
- After EncryptedMessage JSON: ~498 bytes (serialization 2)
- After Protocol Wrapper JSON: ~600 bytes (serialization 3)
- On wire (with QUIC): ~644-664 bytes

**Overhead ratio**: ~59x for minimal message, ~2-3x for typical messages (100-500 bytes content)

**Key observations**:
1. **Triple JSON serialization** is the primary overhead source (~250 bytes combined)
   - Layer 1: RichMessage → JSON (~150 bytes overhead)
   - Layer 2: EncryptedMessage → JSON (~80 bytes overhead)
   - Layer 3: Protocol Wrapper → JSON (~20 bytes overhead)
2. **Double encryption** (E2E + QUIC) adds only 44 bytes total
3. **Metadata overhead** (UUIDs, timestamps, addresses) adds ~200 bytes
4. **Small messages have disproportionate overhead** (59x for "Hello World")
5. **Larger messages amortize overhead better** (2-3x for 500+ byte content)
