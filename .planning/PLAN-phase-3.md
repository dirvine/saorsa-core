# Phase 3: Solution Design

**Phase ID**: phase-3-solution-design
**Milestone**: milestone-1-analysis-baseline
**Status**: planning
**Created**: 2026-01-29T14:00:00Z

---

## Phase Overview

**Objective**: Design implementation strategy for message encoding optimization based on Phase 2 findings.

**Phase 2 Key Findings**:
1. ✅ Both encryption layers necessary (transport + application) - NO REMOVAL
2. ⚠️ Deterministic key fallback creates forward secrecy gap - MUST REMOVE
3. ✅ 3 JSON serializations create overhead - OPTIMIZE with binary encoding
4. ✅ Overhead: ~128-136 bytes per message (justified for security)
5. ✅ DHT storage mandates E2E encryption for all messages

**Architectural Decision from Phase 2**: KEEP CURRENT ENCRYPTION ARCHITECTURE

**Optimization Strategy**: Focus on serialization (not encryption) + remove forward secrecy gap

---

## Tasks

### Task 1: Design Forward Secrecy Enforcement

**Goal**: Remove deterministic key fallback, enforce ephemeral ML-KEM-768 key exchange

**Current Issue** (from Phase 2 Task 6):
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

**Risk**: Identity compromise + deterministic fallback = all channel history decryptable

**Design Requirements**:
1. Remove deterministic fallback entirely
2. Enforce ephemeral key exchange before message encryption
3. Fail fast when session key unavailable (return error, don't fallback)
4. Add key rotation policy (time-based session expiration)

**Deliverables**:
- [ ] Design document: `.planning/solution-design/01-forward-secrecy-enforcement.md`
- [ ] Error handling strategy: What happens when key exchange fails?
- [ ] Key rotation policy: Session expiration time, rotation triggers
- [ ] Backward compatibility: Breaking change analysis

**Files to modify**:
- `src/messaging/encryption.rs:49-63` - Remove fallback logic
- `src/messaging/encryption.rs:230-260` - Ensure ephemeral key enforcement
- `src/messaging/key_exchange.rs` - Add mandatory key exchange check

---

### Task 2: Design Binary Encoding Migration

**Goal**: Replace JSON with binary encoding (MessagePack or Protobuf) for 30-40% size reduction

**Current Overhead** (from Phase 2 Task 1):
- **3 JSON serializations** per message:
  1. RichMessage → JSON
  2. Encrypt → EncryptedMessage → JSON
  3. Wrap → Transport format → JSON
- **Metadata overhead**: ~84-92 bytes (JSON field names, quotes, commas)

**Expected Savings**: 30-40% size reduction with binary encoding

**Binary Format Options**:

| Format | Pros | Cons | Size Efficiency |
|--------|------|------|-----------------|
| **MessagePack** | Fast, simple, no schema | No schema validation | 30-40% smaller |
| **Protobuf** | Schema-based, versioning | Requires .proto files | 40-50% smaller |
| **Bincode** | Rust-native, fastest | No cross-language support | 40-50% smaller |
| **CBOR** | Standards-based, extensible | Slightly larger than MessagePack | 25-35% smaller |

**Design Requirements**:
1. Choose binary format (recommend: MessagePack for simplicity + efficiency)
2. Maintain type safety (no raw byte arrays)
3. Version negotiation (support both JSON and binary during migration)
4. Performance benchmarks (serialization speed vs size)

**Migration Strategy**:
- Phase 1: Add binary encoding support alongside JSON
- Phase 2: Default to binary, fallback to JSON for compatibility
- Phase 3: Remove JSON support (breaking change)

**Deliverables**:
- [ ] Design document: `.planning/solution-design/02-binary-encoding-migration.md`
- [ ] Format comparison benchmarks
- [ ] Migration path (phased rollout)
- [ ] API changes (transparent to users?)

**Files to modify**:
- `src/messaging/types.rs` - Add binary serialization traits
- `src/messaging/transport.rs:78-95` - Binary encoding in send path
- `src/messaging/encryption.rs:44-74` - Binary format for EncryptedMessage

---

### Task 3: Design Key Rotation Policy

**Goal**: Implement automatic session key rotation to limit blast radius of key compromise

**Current Gap** (from Phase 2 Task 6):
- Ephemeral keys: Session-based (lifetime ~24 hours, `src/messaging/encryption.rs:211`)
- Deterministic keys: **NEVER** rotated (removed in Task 1)
- No automatic rotation triggers

**Design Requirements**:
1. Time-based rotation: Maximum session lifetime (recommend: 24 hours)
2. Message-based rotation: Maximum messages per key (recommend: 10,000)
3. Manual rotation: API for explicit key rotation
4. Graceful rotation: Handle in-flight messages during rotation

**Key Rotation Triggers**:
- ✅ Time: 24 hours since session establishment
- ✅ Message count: 10,000 messages encrypted with same key
- ✅ Manual: User-initiated key rotation
- ✅ Security event: Suspicious activity detected

**Deliverables**:
- [ ] Design document: `.planning/solution-design/03-key-rotation-policy.md`
- [ ] Rotation trigger thresholds
- [ ] Graceful rotation algorithm (no message loss)
- [ ] Monitoring/metrics for key rotation events

**Files to modify**:
- `src/messaging/encryption.rs:211-229` - Add rotation logic
- `src/messaging/key_exchange.rs` - Track session age, message count
- `src/messaging/transport.rs` - Handle rotation during message send

---

### Task 4: Design Compression Integration

**Goal**: Compress plaintext RichMessage before encryption for additional size savings

**Opportunity** (from Phase 2 Task 8):
- Compress plaintext before encryption
- Use fast compression (zstd, lz4, or similar)
- May reduce ciphertext size significantly for text-heavy messages

**Trade-off Analysis**:
- **Pro**: Significant size reduction for compressible data (text, JSON metadata)
- **Pro**: Reduces network bandwidth and DHT storage
- **Con**: CPU cost for compression/decompression
- **Con**: Encrypted data is incompressible (must compress before encryption)

**Compression Candidates**:

| Algorithm | Compression Ratio | Speed | Use Case |
|-----------|------------------|-------|----------|
| **zstd** | 2-3x | Very fast | General-purpose |
| **lz4** | 1.5-2x | Extremely fast | Speed-critical |
| **brotli** | 3-4x | Slower | Size-critical |
| **snappy** | 1.5-2x | Very fast | Real-time |

**Design Requirements**:
1. Choose compression algorithm (recommend: zstd for balance)
2. Compression threshold: Only compress if message > N bytes
3. Automatic detection: Skip compression for incompressible data
4. Version negotiation: Support uncompressed for compatibility

**Deliverables**:
- [ ] Design document: `.planning/solution-design/04-compression-integration.md`
- [ ] Compression algorithm comparison benchmarks
- [ ] Threshold analysis (when to compress?)
- [ ] API changes (transparent compression?)

**Files to modify**:
- `src/messaging/encryption.rs:44-74` - Add compression before encryption
- `src/messaging/types.rs` - Add compression flag to EncryptedMessage
- `src/messaging/transport.rs` - Handle compressed payloads

---

## Success Criteria

**Phase 3 Complete When**:
1. ✅ All 4 design documents created
2. ✅ Forward secrecy enforcement strategy validated
3. ✅ Binary encoding format selected with benchmarks
4. ✅ Key rotation policy defined with thresholds
5. ✅ Compression strategy defined with performance analysis
6. ✅ Implementation plan ready for Phase 4

**Deliverables Summary**:
- `.planning/solution-design/01-forward-secrecy-enforcement.md`
- `.planning/solution-design/02-binary-encoding-migration.md`
- `.planning/solution-design/03-key-rotation-policy.md`
- `.planning/solution-design/04-compression-integration.md`

**Quality Gates**:
- [ ] All designs reviewed and approved
- [ ] No architectural contradictions with Phase 2 findings
- [ ] Implementation feasibility validated
- [ ] Performance impact estimated

---

## Phase Completion

**Next Phase**: phase-4-remove-redundant-encryption (skip or repurpose - none found)
**Estimated Duration**: 4 tasks

**Notes**:
- Phase 2 found NO redundant encryption (both layers necessary)
- Phase 4 may be skipped or repurposed for implementation of Phase 3 designs
- Focus: Security (Task 1, 3) and Efficiency (Task 2, 4)

---

**Created**: 2026-01-29T14:00:00Z
**Last Updated**: 2026-01-29T14:00:00Z
**Status**: planning
