# Task 1: Forward Secrecy Enforcement Design

**Task ID**: task-1-forward-secrecy
**Phase**: phase-3-solution-design
**Created**: 2026-01-29T14:00:00Z
**Status**: design

---

## Problem Statement

**Critical Security Gap**: The current encryption implementation contains a deterministic key derivation fallback that compromises forward secrecy.

### Current Vulnerable Code

```rust
// src/messaging/encryption.rs:50-63
let session_key = if let Ok(key) = self
    .key_exchange
    .get_session_key(&message.channel_id.0.to_string().into())
    .await
{
    key  // Ephemeral key (forward secrecy ✓)
} else {
    // VULNERABILITY: Deterministic fallback (NO forward secrecy ✗)
    let mut hasher = Hasher::new();
    hasher.update(self.identity.to_string().as_bytes());
    hasher.update(message.channel_id.0.as_bytes());
    let key_material = hasher.finalize();
    key_material.as_bytes()[..32].to_vec()  // SAME KEY for all channel messages
};
```

### Security Risk

**Threat Model**:
- **Attacker**: Adversary who compromises user's identity key
- **Attack Window**: DHT stores messages for 1 hour (3600 seconds TTL)
- **Impact**: Retroactive decryption of all messages in the channel (past + future)

**Attack Scenario**:
1. User sends 100 messages in channel over 1 hour using deterministic keys
2. Attacker compromises user's identity key
3. Attacker computes: `key = BLAKE3(identity + channel_id)`
4. Attacker retrieves encrypted messages from DHT (up to 1-hour old)
5. Attacker decrypts ALL messages with the single derived key

**Blast Radius**: ALL messages in channel history (no forward secrecy)

### Why This Exists

From code comment: `"(in production, this would be properly negotiated)"`

**Original Intent**: Provide fallback when ML-KEM-768 key exchange fails
**Actual Effect**: Creates permanent security vulnerability that bypasses proper key exchange

---

## Current Implementation Analysis

### Key Exchange Mechanism (ML-KEM-768)

**File**: `src/messaging/key_exchange.rs`

**Proper Flow**:
1. **Initiate**: `initiate_exchange()` (lines 96-113)
   - Fetch peer's KEM public key from DHT
   - Encapsulate to generate shared secret
   - Derive 32-byte session key via HKDF-SHA256
   - Store session with 24-hour expiration

2. **Respond**: `respond_to_exchange()` (lines 115-135)
   - Decapsulate ciphertext with KEM secret key
   - Derive same session key
   - Store session with 24-hour expiration

3. **Retrieve**: `get_session_key()` (lines 156-164)
   - Return key if session exists AND not expired
   - Return error if no session or expired

**Session Lifetime**: 24 hours (`Duration::hours(24)` at line 149)

### Why Fallback is Used

**Trigger Condition**: `get_session_key()` returns `Err` when:
- No session exists (never established)
- Session expired (>24 hours old)
- Peer's KEM public key not in DHT

**Problem**: Instead of failing fast and forcing key exchange, the code silently falls back to insecure deterministic derivation.

---

## Proposed Solution

### Design Principle

**Fail Secure, Not Silent**: When ephemeral key exchange is unavailable, the system MUST reject the encryption attempt rather than falling back to insecure methods.

### Remove Deterministic Fallback

**Change**: `src/messaging/encryption.rs:44-74` (`encrypt_message()`)

**Before**:
```rust
let session_key = if let Ok(key) = self
    .key_exchange
    .get_session_key(&message.channel_id.0.to_string().into())
    .await
{
    key
} else {
    // Deterministic fallback
    let mut hasher = Hasher::new();
    hasher.update(self.identity.to_string().as_bytes());
    hasher.update(message.channel_id.0.as_bytes());
    let key_material = hasher.finalize();
    key_material.as_bytes()[..32].to_vec()
};
```

**After**:
```rust
// Enforce ephemeral key exchange - FAIL if no session
let session_key = self
    .key_exchange
    .get_session_key(&message.channel_id.0.to_string().into())
    .await
    .context("No ephemeral session key available. Call initiate_exchange() first.")?;
```

**Behavior Change**:
- **Before**: Always succeeds (fallback to deterministic)
- **After**: Fails with error if no ephemeral session exists
- **Breaking Change**: YES - applications must establish session before encrypting

### Enforce Session Establishment

**API Contract**:
1. Before encrypting messages, caller MUST call `key_exchange.initiate_exchange(peer)`
2. Wait for response from peer
3. Call `key_exchange.complete_exchange(response)`
4. Then `encrypt_message()` will succeed

**Error Handling**:
```rust
// Application code must handle session establishment
match encryption.encrypt_message(&message).await {
    Ok(encrypted) => send(encrypted),
    Err(e) if e.to_string().contains("No ephemeral session") => {
        // Establish session first
        let exchange_msg = key_exchange.initiate_exchange(peer).await?;
        send_key_exchange(exchange_msg).await?;
        // Retry after session established
        encryption.encrypt_message(&message).await?
    }
    Err(e) => return Err(e),
}
```

---

## Key Rotation Policy

### Current Session Lifetime

**Implementation**: `src/messaging/key_exchange.rs:149`
```rust
expires_at: Utc::now() + Duration::hours(24),
```

**Current Policy**: Sessions expire after 24 hours

### Proposed Rotation Triggers

**Multi-factor rotation policy**:

| Trigger | Threshold | Rationale |
|---------|-----------|-----------|
| **Time-based** | 24 hours | Limit temporal exposure |
| **Message-based** | 10,000 messages | Limit per-key message count |
| **Manual** | User/admin request | Emergency rotation capability |
| **Security event** | Suspicious activity | Proactive rotation on threat detection |

### Enhanced Session Structure

**File**: `src/messaging/key_exchange.rs:34-41`

**Current**:
```rust
pub struct EstablishedKey {
    _peer: FourWordAddress,
    encryption_key: Vec<u8>,
    _established_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    _messages_sent: u64,      // Not used for rotation
    _messages_received: u64,  // Not used for rotation
}
```

**Proposed**:
```rust
pub struct EstablishedKey {
    peer: FourWordAddress,
    encryption_key: Vec<u8>,
    established_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    messages_encrypted: u64,   // Track usage
    last_rotation_trigger: Option<RotationTrigger>,
}

pub enum RotationTrigger {
    TimeExpired,
    MessageLimitReached,
    ManualRequest,
    SecurityEvent,
}
```

### Rotation Implementation

**Add to `KeyExchange` impl**:
```rust
impl KeyExchange {
    /// Check if session needs rotation
    pub async fn needs_rotation(&self, peer: &FourWordAddress) -> bool {
        let keys = self.established_keys.read().await;
        if let Some(key) = keys.get(peer) {
            // Time-based rotation
            if key.expires_at < Utc::now() {
                return true;
            }
            // Message-based rotation
            if key.messages_encrypted >= 10_000 {
                return true;
            }
        }
        false
    }

    /// Increment message count
    pub async fn record_message_encrypted(&self, peer: &FourWordAddress) -> Result<()> {
        let mut keys = self.established_keys.write().await;
        if let Some(key) = keys.get_mut(peer) {
            key.messages_encrypted += 1;
        }
        Ok(())
    }

    /// Force rotation (manual or security event)
    pub async fn force_rotation(&self, peer: &FourWordAddress) -> Result<()> {
        // Remove existing session to force re-establishment
        let mut keys = self.established_keys.write().await;
        keys.remove(peer);
        Ok(())
    }
}
```

### Graceful Rotation

**Challenge**: Messages in-flight during rotation must not be lost

**Solution**: Dual-key overlap period
1. Generate new session key (rotation_key_new)
2. Keep old session key for 60 seconds (rotation_key_old)
3. Decrypt with either key during overlap
4. After overlap, purge rotation_key_old

**Implementation**:
```rust
pub struct EstablishedKey {
    current_key: KeySlot,
    previous_key: Option<KeySlot>,  // For rotation overlap
}

pub struct KeySlot {
    encryption_key: Vec<u8>,
    established_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl EstablishedKey {
    /// Try both current and previous keys during rotation
    pub fn decrypt_with_rotation(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Try current key first
        if let Ok(plaintext) = decrypt_with_key(&self.current_key.encryption_key, ciphertext) {
            return Ok(plaintext);
        }
        // Try previous key if in overlap period
        if let Some(prev) = &self.previous_key {
            if prev.expires_at > Utc::now() {
                return decrypt_with_key(&prev.encryption_key, ciphertext);
            }
        }
        Err(anyhow::anyhow!("Decryption failed with all available keys"))
    }
}
```

---

## Implementation Strategy

**Direct Implementation** (Breaking Change Acceptable)

**Project Constraints**:
- `no_backward_compatibility: true`
- `breaking_change_acceptable: true`

**Approach**: Remove deterministic fallback immediately, no gradual migration needed.

### Remove Fallback Entirely

**Implementation**:
```rust
pub async fn encrypt_message(&self, message: &RichMessage) -> Result<EncryptedMessage> {
    // Enforce ephemeral key exchange - FAIL if no session
    let session_key = self
        .key_exchange
        .get_session_key(&message.channel_id.0.to_string().into())
        .await
        .context("No ephemeral session key available. Call initiate_exchange() first.")?;

    let cipher = ChaCha20Poly1305::new_from_slice(&session_key)?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    // Serialize and encrypt
    let plaintext = encode(message, preferred_encoding())?;
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())?;

    Ok(EncryptedMessage { ... })
}
```

**Changes**:
- ❌ Remove lines 56-63 (deterministic fallback)
- ✅ Add proper error context
- ✅ Force session establishment before encryption

### Application Requirements

**Session Establishment Pattern**:
```rust
// Ensure session exists before encrypting
if key_exchange.get_session_key(&peer).await.is_err() {
    let exchange_msg = key_exchange.initiate_exchange(peer.clone()).await?;
    transport.send_key_exchange(exchange_msg).await?;
    // Wait for response and complete exchange
}
let encrypted = encryption.encrypt_message(&msg).await?;
```

**Breaking Change Impact**: Acceptable per project constraints

---

## Performance Impact

### Encryption Performance

**No change**: ChaCha20Poly1305 encryption speed unchanged (same key size)

### Key Exchange Overhead

**Current (with fallback)**:
- Session exists: 0ms (cache hit)
- No session: 0ms (deterministic fallback)

**Proposed (without fallback)**:
- Session exists: 0ms (cache hit)
- No session: **KEY EXCHANGE REQUIRED**
  - ML-KEM-768 encapsulation: ~0.5ms
  - DHT round-trip: ~50-200ms (network latency)
  - Total: ~50-200ms one-time cost

**Amortization**: 24-hour session lifetime means key exchange cost is negligible over message lifetime

### Message Throughput

**Steady State**: No impact (session already established)
**Cold Start**: 50-200ms delay for first message (one-time per session)

---

## Security Considerations

### Threat Mitigation

| Threat | Before (Deterministic) | After (Ephemeral Only) |
|--------|------------------------|------------------------|
| Identity compromise → All messages | ✗ VULNERABLE | ✅ MITIGATED |
| DHT message retrieval → Decryption | ✗ VULNERABLE | ✅ MITIGATED |
| Quantum retroactive decryption | ✗ VULNERABLE | ✅ MITIGATED (ML-KEM-768) |

### Remaining Risks

**Session Key Compromise**:
- **Risk**: If current session key is compromised, attacker can decrypt messages encrypted with that key
- **Mitigation**: Key rotation limits blast radius to 24 hours or 10,000 messages
- **Residual Risk**: Acceptable (bounded exposure)

**Denial of Service**:
- **Risk**: Attacker could prevent key exchange by blocking DHT access
- **Mitigation**: Retry logic, fallback to alternative DHT nodes
- **Residual Risk**: Acceptable (availability vs security trade-off)

---

## Testing Strategy

### Unit Tests

**File**: `src/messaging/encryption_tests.rs` (new)

**Test Cases**:
1. `test_encrypt_with_ephemeral_session_succeeds()`
   - Establish session, encrypt message, verify success

2. `test_encrypt_without_session_fails_strict_mode()`
   - No session, strict_mode=true, verify error

3. `test_encrypt_without_session_fallback_legacy()`
   - No session, strict_mode=false, verify deprecation warning

4. `test_key_rotation_time_trigger()`
   - Mock time to 24+ hours, verify rotation triggered

5. `test_key_rotation_message_count_trigger()`
   - Encrypt 10,000 messages, verify rotation triggered

6. `test_graceful_rotation_no_message_loss()`
   - Rotate key while messages in-flight, verify all decrypt

### Integration Tests

**File**: `tests/forward_secrecy_test.rs` (new)

**Scenarios**:
1. **E2E Key Exchange**: Initiate → Respond → Encrypt → Decrypt
2. **Session Expiration**: Wait 24+ hours, verify re-exchange required
3. **Message Count Rotation**: Send 10,001 messages, verify rotation
4. **Concurrent Sessions**: Multiple peers, verify independent sessions

### Security Tests

**File**: `tests/security_forward_secrecy_test.rs` (new)

**Attack Simulations**:
1. **Retroactive Decryption Attempt**:
   - Encrypt 100 messages with ephemeral keys
   - "Compromise" identity (simulate key leak)
   - Attempt to derive keys → Verify FAILURE

2. **Replay Attack**:
   - Capture encrypted message
   - Replay after key rotation
   - Verify decryption failure

---

## Monitoring and Metrics

### Key Exchange Metrics

**Prometheus Metrics** (if `metrics` feature enabled):
```rust
// Counter: Total key exchanges initiated
saorsa_key_exchange_initiated_total

// Counter: Total key exchanges completed
saorsa_key_exchange_completed_total

// Counter: Total key exchanges failed
saorsa_key_exchange_failed_total

// Histogram: Key exchange duration
saorsa_key_exchange_duration_seconds

// Gauge: Active sessions
saorsa_active_sessions_count

// Counter: Key rotations by trigger type
saorsa_key_rotations_total{trigger="time|messages|manual|security"}
```

### Alerting Thresholds

**Production Monitoring**:
- `key_exchange_failed_total` > 5% of initiated → ALERT (DHT or network issue)
- `key_exchange_duration_seconds` > 1s (p99) → WARN (performance degradation)
- `active_sessions_count` = 0 for > 5 minutes → WARN (no peer connectivity)

---

## Documentation Updates

### API Documentation

**File**: `src/messaging/encryption.rs`

**Add to `encrypt_message()` doc comment**:
```rust
/// Encrypt a message for recipients
///
/// # Forward Secrecy
///
/// This function REQUIRES an established ephemeral session key (ML-KEM-768).
/// If no session exists, this function will return an error.
///
/// # Session Establishment
///
/// Before calling `encrypt_message()`, ensure a session exists:
/// ```rust
/// // Check if session exists
/// if key_exchange.get_session_key(&peer).await.is_err() {
///     // Initiate key exchange
///     let exchange_msg = key_exchange.initiate_exchange(peer).await?;
///     transport.send_key_exchange(exchange_msg).await?;
///     // Wait for response...
/// }
/// // Now encrypt_message() will succeed
/// let encrypted = encryption.encrypt_message(&msg).await?;
/// ```
///
/// # Errors
///
/// Returns `Err` if:
/// - No ephemeral session key exists for the channel
/// - Session has expired (>24 hours old)
/// - Encryption fails (rare, indicates corrupted key)
///
/// # Security
///
/// This design enforces forward secrecy: if your identity key is compromised,
/// past messages remain secure because they were encrypted with ephemeral session keys.
```

### Migration Guide

**File**: `docs/migration/forward-secrecy-enforcement.md` (new)

**Contents**:
1. What changed and why
2. Migration timeline (Phase 1, 2, 3)
3. Code examples (old vs new)
4. Troubleshooting common errors

---

## Implementation Checklist

**Phase 1: Add Strict Mode** (v0.4.0, non-breaking)
- [ ] Add `strict_mode: bool` to `EncryptionManager`
- [ ] Add conditional error in `encrypt_message()` for strict mode
- [ ] Add deprecation warning for fallback path
- [ ] Write unit tests for strict mode
- [ ] Update API documentation
- [ ] Write migration guide

**Phase 2: Enable Strict Mode by Default** (v0.5.0, breaking warning)
- [ ] Change default: `strict_mode = true`
- [ ] Update release notes with breaking change notice
- [ ] Add examples for proper session establishment
- [ ] Integration tests for key exchange flow

**Phase 3: Remove Fallback** (v1.0.0, clean implementation)
- [ ] Remove deterministic fallback code entirely
- [ ] Remove `strict_mode` flag (always enforced)
- [ ] Add key rotation tracking fields
- [ ] Implement rotation triggers (time, message count, manual)
- [ ] Implement graceful rotation (dual-key overlap)
- [ ] Add rotation metrics
- [ ] Security tests for retroactive decryption prevention
- [ ] Update all documentation

---

## Success Criteria

**Design Approved When**:
1. ✅ Security gap clearly identified and solution validates threat model
2. ✅ Implementation plan is feasible (no architectural blockers)
3. ✅ Migration strategy minimizes disruption (phased rollout)
4. ✅ Performance impact is acceptable (amortized key exchange cost)
5. ✅ Testing strategy covers all security edge cases
6. ✅ Documentation is comprehensive for API users

**Implementation Complete When**:
1. ✅ Deterministic fallback removed (strict enforcement)
2. ✅ Key rotation implemented (time + message triggers)
3. ✅ Graceful rotation (no message loss)
4. ✅ All tests passing (unit, integration, security)
5. ✅ Metrics and monitoring in place
6. ✅ Documentation updated (API docs + migration guide)

---

**Task Status**: Design complete, ready for review
**Next Task**: Task 2 - Binary Encoding Migration Design
**Created**: 2026-01-29T14:00:00Z
**Last Updated**: 2026-01-29T14:00:00Z
