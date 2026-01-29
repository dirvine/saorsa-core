# Task 3: Key Rotation Policy Design

**Task ID**: task-3-key-rotation
**Phase**: phase-3-solution-design
**Created**: 2026-01-29T14:30:00Z
**Status**: design

---

## Problem Statement

**Security Gap**: Current session keys have a fixed 24-hour lifetime with no message-based rotation, creating potential security exposure.

### Current Implementation

**File**: `src/messaging/key_exchange.rs:149`

```rust
EstablishedKey {
    _peer: peer,
    encryption_key: key,
    _established_at: Utc::now(),
    expires_at: Utc::now() + Duration::hours(24),  // Fixed 24-hour lifetime
    _messages_sent: 0,       // Tracked but not used for rotation
    _messages_received: 0,   // Tracked but not used for rotation
}
```

**Current Policy**:
- ✅ Time-based expiration: 24 hours
- ❌ No message-count rotation
- ❌ No manual rotation API
- ❌ No security-event rotation

### Security Risk

**Attack Scenario**: Session key compromise
- **Exposure Window**: Up to 24 hours of messages
- **Message Count**: Unlimited messages with single key
- **Blast Radius**: ALL messages encrypted with compromised key

**Example**:
- User sends 50,000 messages over 23 hours (high-volume bot)
- Single session key compromised
- Attacker decrypts ALL 50,000 messages

**Risk Mitigation Need**: Limit both time AND message count per key

---

## Rotation Trigger Design

### Multi-Factor Rotation Policy

**Design Principle**: Rotate session keys based on **ANY** of the following triggers (whichever occurs first)

| Trigger Type | Threshold | Rationale | Priority |
|--------------|-----------|-----------|----------|
| **Time-based** | 24 hours | Limit temporal exposure | High |
| **Message-based** | 10,000 messages | Limit per-key message count | High |
| **Manual** | User/admin request | Emergency rotation | Critical |
| **Security Event** | Threat detection | Proactive defense | Critical |

### Time-Based Rotation

**Current**: 24-hour fixed expiration

**Proposed**: Configurable with sane default

```rust
pub const DEFAULT_SESSION_LIFETIME: Duration = Duration::hours(24);
pub const MIN_SESSION_LIFETIME: Duration = Duration::hours(1);
pub const MAX_SESSION_LIFETIME: Duration = Duration::hours(168);  // 1 week
```

**Configuration**:
```rust
pub struct KeyRotationConfig {
    pub session_lifetime: Duration,  // Default: 24 hours
    // ... other fields
}
```

**Rotation Logic**:
```rust
impl EstablishedKey {
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    pub fn time_until_expiration(&self) -> Duration {
        self.expires_at.signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(Duration::from_secs(0))
    }
}
```

### Message-Based Rotation

**Threshold**: 10,000 messages per session key

**Rationale**:
- Limit cryptanalysis opportunities (less ciphertext per key)
- Balance security vs performance (avoid too-frequent rotation)
- Industry standard (TLS rotates after ~2^24 messages, we're more conservative)

**Implementation**:
```rust
pub const DEFAULT_MESSAGE_LIMIT: u64 = 10_000;
pub const MIN_MESSAGE_LIMIT: u64 = 1_000;
pub const MAX_MESSAGE_LIMIT: u64 = 1_000_000;

pub struct EstablishedKey {
    peer: FourWordAddress,
    encryption_key: Vec<u8>,
    established_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    messages_encrypted: u64,      // Track usage
    message_limit: u64,            // Configurable threshold
}

impl EstablishedKey {
    pub fn is_message_limit_reached(&self) -> bool {
        self.messages_encrypted >= self.message_limit
    }

    pub fn increment_message_count(&mut self) {
        self.messages_encrypted += 1;
    }
}
```

**Tracking**:
```rust
impl EncryptionManager {
    pub async fn encrypt_message(&self, message: &RichMessage) -> Result<EncryptedMessage> {
        // Get session key
        let peer = &message.channel_id.0.to_string().into();
        let session_key = self.key_exchange.get_session_key(peer).await?;

        // Check rotation needed BEFORE encrypting
        if self.key_exchange.needs_rotation(peer).await {
            warn!("Session key rotation needed for {}", peer);
            // Trigger rotation (async, non-blocking)
            self.trigger_rotation(peer.clone()).await?;
        }

        // Encrypt message
        let encrypted = self.encrypt_with_key(&session_key, message).await?;

        // Increment message count AFTER successful encryption
        self.key_exchange.record_message_encrypted(peer).await?;

        Ok(encrypted)
    }
}
```

### Manual Rotation

**Use Case**: Emergency rotation on suspected compromise

**API**:
```rust
impl KeyExchange {
    /// Force immediate rotation of session key
    ///
    /// # Use Cases
    /// - Security incident (suspected key compromise)
    /// - User-initiated rotation (privacy preference)
    /// - Administrative action (policy enforcement)
    pub async fn force_rotation(&self, peer: &FourWordAddress) -> Result<()> {
        info!("Manual rotation requested for {}", peer);

        // Invalidate current session
        let mut keys = self.established_keys.write().await;
        keys.remove(peer);

        // Initiate new key exchange
        drop(keys);  // Release lock before async call
        self.initiate_exchange(peer.clone()).await?;

        Ok(())
    }

    /// Rotate all active sessions (emergency rotation)
    pub async fn force_rotation_all(&self) -> Result<()> {
        warn!("EMERGENCY: Rotating all active sessions");

        let peers: Vec<FourWordAddress> = {
            let keys = self.established_keys.read().await;
            keys.keys().cloned().collect()
        };

        for peer in peers {
            self.force_rotation(&peer).await?;
        }

        Ok(())
    }
}
```

### Security-Event Rotation

**Triggers**:
- Repeated decryption failures (potential tampering)
- Suspicious message patterns (frequency anomaly)
- External threat intelligence (known attack)

**Implementation**:
```rust
pub struct SecurityMonitor {
    key_exchange: Arc<KeyExchange>,
    // ... other fields
}

impl SecurityMonitor {
    /// Check for suspicious activity and trigger rotation
    pub async fn check_and_rotate_if_needed(&self, peer: &FourWordAddress) -> Result<()> {
        let should_rotate = self.detect_threat(peer).await?;

        if should_rotate {
            warn!("Security event detected for {}, rotating key", peer);
            self.key_exchange.force_rotation(peer).await?;
        }

        Ok(())
    }

    async fn detect_threat(&self, _peer: &FourWordAddress) -> Result<bool> {
        // TODO: Implement threat detection logic
        // - Check decryption failure rate
        // - Monitor message frequency anomalies
        // - Query external threat feeds
        Ok(false)
    }
}
```

---

## Graceful Rotation Implementation

### Problem: In-Flight Messages

**Challenge**: Messages encrypted with old key but not yet delivered when rotation occurs

**Scenario**:
1. Sender encrypts message at T=0 with key_v1
2. Rotation triggers at T=1 (new key_v2 established)
3. Message arrives at recipient at T=2
4. Recipient only has key_v2, cannot decrypt

**Impact**: Message loss, delivery failure

### Solution: Dual-Key Overlap Period

**Design**: Keep both old and new keys active for overlap period

```
Time:        T=0          T=1 (rotation)   T=60        T=61
Old Key:     [Active] ────> [Overlap] ────────────> [Purged]
New Key:                    [Active] ────────────────────────>

Messages:    Encrypt with   Encrypt with    Encrypt with
             old key        new key         new key

             Decrypt with   Decrypt with    Decrypt with
             old key        old OR new      new key only
```

**Overlap Duration**: 60 seconds (configurable)

### Key Slot Structure

**Enhanced EstablishedKey**:
```rust
#[derive(Debug, Clone)]
pub struct EstablishedKey {
    peer: FourWordAddress,
    current_slot: KeySlot,            // Active encryption key
    previous_slot: Option<KeySlot>,   // For decryption during overlap
    rotation_history: Vec<RotationEvent>,
}

#[derive(Debug, Clone)]
pub struct KeySlot {
    encryption_key: Vec<u8>,
    established_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    messages_encrypted: u64,
    slot_version: u32,                // Track key version
}

#[derive(Debug, Clone)]
pub struct RotationEvent {
    trigger: RotationTrigger,
    timestamp: DateTime<Utc>,
    old_key_version: u32,
    new_key_version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationTrigger {
    TimeExpired,
    MessageLimitReached,
    ManualRequest,
    SecurityEvent,
}
```

### Encryption During Rotation

**Always use current_slot** for encryption:
```rust
impl EstablishedKey {
    pub fn encrypt_key(&self) -> &[u8] {
        &self.current_slot.encryption_key
    }
}
```

### Decryption During Rotation

**Try both current and previous slots**:
```rust
impl EstablishedKey {
    pub fn decrypt(&self, encrypted: &EncryptedMessage) -> Result<RichMessage> {
        // Try current key first (most common case)
        if let Ok(plaintext) = self.try_decrypt_with_key(
            &self.current_slot.encryption_key,
            encrypted
        ) {
            return Ok(plaintext);
        }

        // Try previous key if in overlap period
        if let Some(prev) = &self.previous_slot {
            if prev.expires_at > Utc::now() {
                if let Ok(plaintext) = self.try_decrypt_with_key(
                    &prev.encryption_key,
                    encrypted
                ) {
                    return Ok(plaintext);
                }
            }
        }

        Err(anyhow::anyhow!("Decryption failed with all available keys"))
    }

    fn try_decrypt_with_key(&self, key: &[u8], encrypted: &EncryptedMessage) -> Result<RichMessage> {
        let cipher = ChaCha20Poly1305::new_from_slice(key)?;
        let plaintext = cipher.decrypt(
            &encrypted.nonce.as_ref(),
            encrypted.ciphertext.as_ref()
        )?;
        decode::<RichMessage>(&plaintext)
    }
}
```

### Rotation Execution

**Rotate with overlap**:
```rust
impl KeyExchange {
    pub async fn rotate_session(&self, peer: &FourWordAddress, trigger: RotationTrigger) -> Result<()> {
        info!("Rotating session for {} (trigger: {:?})", peer, trigger);

        // Initiate new key exchange
        let exchange_msg = self.initiate_exchange(peer.clone()).await?;
        // ... send exchange_msg and wait for response ...

        // Update key store with new key + overlap
        let mut keys = self.established_keys.write().await;
        if let Some(existing) = keys.get_mut(peer) {
            // Move current to previous (overlap period)
            let mut previous_slot = existing.current_slot.clone();
            previous_slot.expires_at = Utc::now() + Duration::seconds(60);  // Overlap

            // Install new key
            existing.previous_slot = Some(previous_slot);
            existing.current_slot = KeySlot {
                encryption_key: new_session_key,
                established_at: Utc::now(),
                expires_at: Utc::now() + Duration::hours(24),
                messages_encrypted: 0,
                slot_version: existing.current_slot.slot_version + 1,
            };

            // Record rotation event
            existing.rotation_history.push(RotationEvent {
                trigger,
                timestamp: Utc::now(),
                old_key_version: existing.current_slot.slot_version - 1,
                new_key_version: existing.current_slot.slot_version,
            });
        }

        Ok(())
    }

    /// Cleanup expired previous keys (called periodically)
    pub async fn cleanup_expired_keys(&self) {
        let mut keys = self.established_keys.write().await;
        let now = Utc::now();

        for key in keys.values_mut() {
            if let Some(prev) = &key.previous_slot {
                if prev.expires_at < now {
                    key.previous_slot = None;  // Purge expired overlap key
                }
            }
        }
    }
}
```

---

## Configuration Design

### KeyRotationConfig Structure

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationConfig {
    /// Maximum session lifetime before rotation
    pub session_lifetime: Duration,

    /// Maximum messages per session key before rotation
    pub message_limit: u64,

    /// Overlap period for graceful rotation (seconds)
    pub overlap_period_secs: u64,

    /// Enable automatic rotation on thresholds
    pub auto_rotate: bool,

    /// Rotation history retention (number of events to keep)
    pub history_retention: usize,
}

impl Default for KeyRotationConfig {
    fn default() -> Self {
        Self {
            session_lifetime: Duration::hours(24),
            message_limit: 10_000,
            overlap_period_secs: 60,
            auto_rotate: true,
            history_retention: 100,
        }
    }
}
```

### Configuration Loading

```rust
impl KeyExchange {
    pub async fn new_with_config(
        identity: FourWordAddress,
        dht: DhtClient,
        config: KeyRotationConfig,
    ) -> Result<Self> {
        // ... existing initialization ...

        // Spawn background task for periodic checks
        if config.auto_rotate {
            let key_exchange = Arc::new(self);
            tokio::spawn(rotation_monitor(key_exchange.clone(), config.clone()));
        }

        Ok(self)
    }
}

/// Background task that monitors and triggers rotation
async fn rotation_monitor(key_exchange: Arc<KeyExchange>, config: KeyRotationConfig) {
    let mut interval = tokio::time::interval(Duration::from_secs(300));  // Check every 5 min

    loop {
        interval.tick().await;

        // Check all active sessions
        let peers: Vec<FourWordAddress> = {
            let keys = key_exchange.established_keys.read().await;
            keys.keys().cloned().collect()
        };

        for peer in peers {
            if key_exchange.needs_rotation(&peer).await {
                match key_exchange.rotate_session(&peer, RotationTrigger::TimeExpired).await {
                    Ok(_) => info!("Auto-rotated session for {}", peer),
                    Err(e) => warn!("Failed to auto-rotate session for {}: {}", peer, e),
                }
            }
        }

        // Cleanup expired overlap keys
        key_exchange.cleanup_expired_keys().await;
    }
}
```

---

## Success Criteria

**Design Approved When**:
1. ✅ Multi-factor rotation triggers defined (time, messages, manual, security)
2. ✅ Graceful rotation prevents message loss (dual-key overlap)
3. ✅ Configuration is flexible (sane defaults, tunable)
4. ✅ Performance impact is negligible (amortized overhead)
5. ✅ Security properties improved (limited blast radius)

**Implementation Complete When**:
1. ✅ All rotation triggers implemented and tested
2. ✅ Graceful rotation working (no message loss during rotation)
3. ✅ Configuration system working (defaults + overrides)
4. ✅ Metrics tracking rotation events
5. ✅ All tests passing (unit, integration, load)
6. ✅ Documentation complete (API + operational guide)

---

**Task Status**: Design complete, ready for review
**Next Task**: Task 4 - Compression Integration Design
**Created**: 2026-01-29T14:30:00Z
**Last Updated**: 2026-01-29T14:30:00Z
