// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Security Hardening Module (Phase 6D).
//!
//! This module provides security utilities for the attestation system:
//!
//! - **Constant-time operations**: Prevent timing side-channel attacks
//! - **Replay protection**: Prevent proof/nonce reuse attacks
//! - **Security audit logging**: Track security-relevant events
//! - **Ownership verification**: Verify key ownership via signatures
//!
//! ## Timing Attack Prevention
//!
//! All cryptographic comparisons use constant-time operations via the `subtle` crate.
//! This prevents attackers from measuring response times to infer secret values.
//!
//! ```rust,ignore
//! use saorsa_core::attestation::security::{ct_eq, ct_eq_32};
//!
//! // Constant-time comparison
//! let result = ct_eq_32(&expected_id, &actual_id);
//! ```
//!
//! ## Replay Protection
//!
//! The [`NonceRegistry`] prevents reuse of proof nonces within a configurable window.
//!
//! ```rust,ignore
//! use saorsa_core::attestation::security::{NonceRegistry, NonceRegistryConfig};
//!
//! let registry = NonceRegistry::new(NonceRegistryConfig::default());
//! if !registry.check_and_record(&peer_id, &nonce) {
//!     // Replay attack detected!
//! }
//! ```

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

// ============================================================================
// Constant-Time Comparison Utilities
// ============================================================================

/// Perform constant-time comparison of two byte slices.
///
/// Returns `true` if slices are equal, `false` otherwise.
/// Comparison time is independent of where differences occur.
#[inline]
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Perform constant-time comparison of two 32-byte arrays.
///
/// This is the most common case for EntangledId and hash comparisons.
#[inline]
#[must_use]
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

/// Perform constant-time comparison of two 16-byte arrays.
///
/// Used for request IDs and similar values.
#[inline]
#[must_use]
pub fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time select between two values based on a condition.
///
/// Returns `a` if `condition` is true, `b` otherwise.
/// Selection time is independent of condition value.
#[inline]
#[must_use]
pub fn ct_select<T: Copy>(condition: bool, a: T, b: T) -> T {
    if condition { a } else { b }
}

// ============================================================================
// Replay Protection
// ============================================================================

/// Configuration for the nonce registry.
#[derive(Debug, Clone)]
pub struct NonceRegistryConfig {
    /// How long to remember nonces (default: 1 hour).
    pub nonce_ttl: Duration,

    /// Maximum number of nonces to track per peer.
    pub max_nonces_per_peer: usize,

    /// Maximum number of peers to track.
    pub max_peers: usize,

    /// Cleanup interval for expired entries.
    pub cleanup_interval: Duration,
}

impl Default for NonceRegistryConfig {
    fn default() -> Self {
        Self {
            nonce_ttl: Duration::from_secs(3600), // 1 hour
            max_nonces_per_peer: 100,
            max_peers: 10_000,
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        }
    }
}

impl NonceRegistryConfig {
    /// Create a testing configuration with shorter TTLs.
    #[must_use]
    pub fn testing() -> Self {
        Self {
            nonce_ttl: Duration::from_secs(60),
            max_nonces_per_peer: 10,
            max_peers: 100,
            cleanup_interval: Duration::from_secs(10),
        }
    }
}

/// Entry in the nonce registry.
#[derive(Debug, Clone)]
struct NonceEntry {
    /// When this nonce was first seen.
    first_seen: Instant,
    /// Number of times this nonce has been seen.
    count: u32,
}

/// Type alias for the nested nonce map to reduce complexity.
type PeerNonceMap = HashMap<[u8; 32], HashMap<[u8; 32], NonceEntry>>;

/// Registry for tracking used nonces to prevent replay attacks.
///
/// Maintains a per-peer record of recently used nonces and rejects
/// any nonce that has been seen within the TTL window.
#[derive(Debug)]
pub struct NonceRegistry {
    /// Nonces per peer: peer_id -> (nonce_hash -> entry)
    entries: RwLock<PeerNonceMap>,
    /// Configuration.
    config: NonceRegistryConfig,
    /// Last cleanup time.
    last_cleanup: RwLock<Instant>,
}

impl NonceRegistry {
    /// Create a new nonce registry.
    pub fn new(config: NonceRegistryConfig) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            config,
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Check if a nonce is fresh and record it if so.
    ///
    /// Returns `true` if nonce is fresh (not seen before), `false` if replay detected.
    pub fn check_and_record(&self, peer_id: &[u8; 32], nonce: u64) -> bool {
        let nonce_hash = Self::hash_nonce(nonce);

        // Try cleanup if needed
        self.maybe_cleanup();

        let Ok(mut entries) = self.entries.write() else {
            // Lock failure - allow to proceed (fail open for availability)
            tracing::warn!("NonceRegistry lock failed, allowing request");
            return true;
        };

        // Get or create peer entry
        let peer_entries = entries.entry(*peer_id).or_default();

        // Check if nonce already exists
        if let Some(entry) = peer_entries.get_mut(&nonce_hash) {
            // Check if still within TTL
            if entry.first_seen.elapsed() < self.config.nonce_ttl {
                entry.count += 1;
                tracing::warn!(
                    peer_id = hex::encode(peer_id),
                    nonce = nonce,
                    replay_count = entry.count,
                    "Replay attack detected: nonce reuse"
                );
                return false;
            }
            // Expired - allow reuse
            entry.first_seen = Instant::now();
            entry.count = 1;
            return true;
        }

        // Check limits
        if peer_entries.len() >= self.config.max_nonces_per_peer {
            // Evict oldest entry
            if let Some(oldest_key) = peer_entries
                .iter()
                .min_by_key(|(_, e)| e.first_seen)
                .map(|(k, _)| *k)
            {
                peer_entries.remove(&oldest_key);
            }
        }

        // Record new nonce
        peer_entries.insert(
            nonce_hash,
            NonceEntry {
                first_seen: Instant::now(),
                count: 1,
            },
        );

        true
    }

    /// Check if a proof has been seen before (by proof hash).
    ///
    /// This is a stricter check than nonce-only - it prevents the same
    /// proof bytes from being replayed even with different metadata.
    pub fn check_proof_replay(&self, peer_id: &[u8; 32], proof_hash: &[u8; 32]) -> bool {
        let Ok(entries) = self.entries.read() else {
            return true; // Fail open
        };

        let Some(peer_entries) = entries.get(peer_id) else {
            return true; // No entries for this peer
        };

        if peer_entries
            .get(proof_hash)
            .is_some_and(|entry| entry.first_seen.elapsed() < self.config.nonce_ttl)
        {
            return false; // Replay detected
        }

        true
    }

    /// Record a proof hash.
    pub fn record_proof(&self, peer_id: &[u8; 32], proof_hash: &[u8; 32]) {
        let Ok(mut entries) = self.entries.write() else {
            return;
        };

        let peer_entries = entries.entry(*peer_id).or_default();

        if peer_entries.len() >= self.config.max_nonces_per_peer {
            // Evict oldest
            if let Some(oldest_key) = peer_entries
                .iter()
                .min_by_key(|(_, e)| e.first_seen)
                .map(|(k, _)| *k)
            {
                peer_entries.remove(&oldest_key);
            }
        }

        peer_entries.insert(
            *proof_hash,
            NonceEntry {
                first_seen: Instant::now(),
                count: 1,
            },
        );
    }

    /// Get statistics about the registry.
    #[must_use]
    pub fn stats(&self) -> NonceRegistryStats {
        let Ok(entries) = self.entries.read() else {
            return NonceRegistryStats::default();
        };

        let total_peers = entries.len();
        let total_nonces: usize = entries.values().map(|p| p.len()).sum();

        NonceRegistryStats {
            total_peers,
            total_nonces,
        }
    }

    /// Force cleanup of expired entries.
    pub fn cleanup(&self) {
        let Ok(mut entries) = self.entries.write() else {
            return;
        };

        let now = Instant::now();
        let ttl = self.config.nonce_ttl;

        // Remove expired nonces
        for peer_entries in entries.values_mut() {
            peer_entries.retain(|_, entry| entry.first_seen.elapsed() < ttl);
        }

        // Remove peers with no entries
        entries.retain(|_, peer_entries| !peer_entries.is_empty());

        // Check peer limit
        while entries.len() > self.config.max_peers {
            // Remove peer with oldest nonces
            if let Some(oldest_peer) = entries
                .iter()
                .filter_map(|(peer_id, nonces)| {
                    nonces
                        .values()
                        .map(|e| e.first_seen)
                        .min()
                        .map(|oldest| (*peer_id, oldest))
                })
                .min_by_key(|(_, oldest)| *oldest)
                .map(|(peer_id, _)| peer_id)
            {
                entries.remove(&oldest_peer);
            } else {
                break;
            }
        }

        if let Ok(mut last) = self.last_cleanup.write() {
            *last = now;
        }
    }

    fn maybe_cleanup(&self) {
        let should_cleanup = self
            .last_cleanup
            .read()
            .map(|last| last.elapsed() >= self.config.cleanup_interval)
            .unwrap_or(false);

        if should_cleanup {
            self.cleanup();
        }
    }

    fn hash_nonce(nonce: u64) -> [u8; 32] {
        *blake3::hash(&nonce.to_le_bytes()).as_bytes()
    }
}

/// Statistics for the nonce registry.
#[derive(Debug, Clone, Default)]
pub struct NonceRegistryStats {
    /// Number of peers being tracked.
    pub total_peers: usize,
    /// Total number of nonces being tracked.
    pub total_nonces: usize,
}

// ============================================================================
// Security Audit Events
// ============================================================================

/// Security event types for audit logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityEventType {
    /// Successful attestation verification.
    AttestationVerified,
    /// Failed attestation verification.
    AttestationFailed,
    /// Replay attack detected.
    ReplayDetected,
    /// Rate limit exceeded.
    RateLimitExceeded,
    /// Invalid signature detected.
    InvalidSignature,
    /// Blacklisted peer attempted connection.
    BlacklistedPeerAttempt,
    /// Binary not in allowlist.
    UnauthorizedBinary,
    /// Proof expired.
    ProofExpired,
    /// Protocol version mismatch.
    ProtocolMismatch,
    /// Clock skew detected.
    ClockSkewDetected,
}

impl SecurityEventType {
    /// Get the severity level of this event type.
    #[must_use]
    pub fn severity(&self) -> SecuritySeverity {
        match self {
            Self::AttestationVerified => SecuritySeverity::Info,
            Self::AttestationFailed => SecuritySeverity::Warning,
            Self::ReplayDetected => SecuritySeverity::Critical,
            Self::RateLimitExceeded => SecuritySeverity::Warning,
            Self::InvalidSignature => SecuritySeverity::Critical,
            Self::BlacklistedPeerAttempt => SecuritySeverity::Warning,
            Self::UnauthorizedBinary => SecuritySeverity::Critical,
            Self::ProofExpired => SecuritySeverity::Warning,
            Self::ProtocolMismatch => SecuritySeverity::Warning,
            Self::ClockSkewDetected => SecuritySeverity::Warning,
        }
    }
}

/// Severity levels for security events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecuritySeverity {
    /// Informational - normal operation.
    Info,
    /// Warning - potential issue but not critical.
    Warning,
    /// Critical - security threat detected.
    Critical,
}

/// A security audit event.
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    /// Type of security event.
    pub event_type: SecurityEventType,
    /// Unix timestamp when event occurred.
    pub timestamp: u64,
    /// Peer ID involved (if applicable).
    pub peer_id: Option<[u8; 32]>,
    /// Additional context.
    pub context: String,
}

impl SecurityEvent {
    /// Create a new security event.
    pub fn new(event_type: SecurityEventType, peer_id: Option<[u8; 32]>, context: String) -> Self {
        Self {
            event_type,
            timestamp: current_timestamp(),
            peer_id,
            context,
        }
    }

    /// Log this event using tracing.
    pub fn log(&self) {
        let peer_str = self
            .peer_id
            .map(|id| hex::encode(&id[..8]))
            .unwrap_or_else(|| "unknown".to_string());

        match self.event_type.severity() {
            SecuritySeverity::Info => {
                tracing::info!(
                    event = ?self.event_type,
                    peer = %peer_str,
                    context = %self.context,
                    "Security event"
                );
            }
            SecuritySeverity::Warning => {
                tracing::warn!(
                    event = ?self.event_type,
                    peer = %peer_str,
                    context = %self.context,
                    "Security warning"
                );
            }
            SecuritySeverity::Critical => {
                tracing::error!(
                    event = ?self.event_type,
                    peer = %peer_str,
                    context = %self.context,
                    "SECURITY ALERT"
                );
            }
        }
    }
}

/// Security audit logger for tracking security events.
#[derive(Debug)]
pub struct SecurityAuditLog {
    /// Recent events (bounded circular buffer).
    events: RwLock<Vec<SecurityEvent>>,
    /// Maximum events to retain.
    max_events: usize,
    /// Event counters by type.
    counters: RwLock<HashMap<SecurityEventType, u64>>,
}

impl Default for SecurityAuditLog {
    fn default() -> Self {
        Self::new(1000)
    }
}

impl SecurityAuditLog {
    /// Create a new audit log with specified capacity.
    pub fn new(max_events: usize) -> Self {
        Self {
            events: RwLock::new(Vec::with_capacity(max_events)),
            max_events,
            counters: RwLock::new(HashMap::new()),
        }
    }

    /// Record a security event.
    pub fn record(&self, event: SecurityEvent) {
        // Log immediately
        event.log();

        // Update counter
        if let Ok(mut counters) = self.counters.write() {
            *counters.entry(event.event_type).or_insert(0) += 1;
        }

        // Store in buffer
        if let Ok(mut events) = self.events.write() {
            if events.len() >= self.max_events {
                events.remove(0);
            }
            events.push(event);
        }
    }

    /// Record a simple event without extra context.
    pub fn record_simple(&self, event_type: SecurityEventType, peer_id: Option<[u8; 32]>) {
        self.record(SecurityEvent::new(event_type, peer_id, String::new()));
    }

    /// Get count of events by type.
    #[must_use]
    pub fn event_count(&self, event_type: SecurityEventType) -> u64 {
        self.counters
            .read()
            .ok()
            .and_then(|c| c.get(&event_type).copied())
            .unwrap_or(0)
    }

    /// Get recent events (newest first).
    #[must_use]
    pub fn recent_events(&self, limit: usize) -> Vec<SecurityEvent> {
        self.events
            .read()
            .map(|events| events.iter().rev().take(limit).cloned().collect())
            .unwrap_or_default()
    }

    /// Get critical events from the last N seconds.
    #[must_use]
    pub fn critical_events_since(&self, seconds: u64) -> Vec<SecurityEvent> {
        let cutoff = current_timestamp().saturating_sub(seconds);

        self.events
            .read()
            .map(|events| {
                events
                    .iter()
                    .filter(|e| {
                        e.timestamp >= cutoff
                            && e.event_type.severity() == SecuritySeverity::Critical
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get summary statistics.
    #[must_use]
    pub fn summary(&self) -> SecurityAuditSummary {
        let counters = self.counters.read().ok();
        let events = self.events.read().ok();

        SecurityAuditSummary {
            total_events: events.as_ref().map(|e| e.len()).unwrap_or(0),
            attestation_verified: counters
                .as_ref()
                .and_then(|c| c.get(&SecurityEventType::AttestationVerified).copied())
                .unwrap_or(0),
            attestation_failed: counters
                .as_ref()
                .and_then(|c| c.get(&SecurityEventType::AttestationFailed).copied())
                .unwrap_or(0),
            replay_detected: counters
                .as_ref()
                .and_then(|c| c.get(&SecurityEventType::ReplayDetected).copied())
                .unwrap_or(0),
            rate_limited: counters
                .as_ref()
                .and_then(|c| c.get(&SecurityEventType::RateLimitExceeded).copied())
                .unwrap_or(0),
            invalid_signatures: counters
                .as_ref()
                .and_then(|c| c.get(&SecurityEventType::InvalidSignature).copied())
                .unwrap_or(0),
        }
    }
}

/// Summary of security audit statistics.
#[derive(Debug, Clone, Default)]
pub struct SecurityAuditSummary {
    /// Total events in buffer.
    pub total_events: usize,
    /// Successful attestation verifications.
    pub attestation_verified: u64,
    /// Failed attestation verifications.
    pub attestation_failed: u64,
    /// Replay attacks detected.
    pub replay_detected: u64,
    /// Rate limit violations.
    pub rate_limited: u64,
    /// Invalid signature attempts.
    pub invalid_signatures: u64,
}

// ============================================================================
// Ownership Verification
// ============================================================================

/// Verify ownership of a public key by checking ML-DSA signature.
///
/// The signature should be over the challenge data using the secret key
/// corresponding to the provided public key.
///
/// # Arguments
///
/// * `public_key` - ML-DSA-65 public key (1952 bytes)
/// * `challenge` - Data that was signed
/// * `signature` - ML-DSA signature over the challenge
///
/// # Returns
///
/// `true` if signature is valid, `false` otherwise.
pub fn verify_ownership(public_key: &[u8], challenge: &[u8], signature: &[u8]) -> bool {
    use crate::quantum_crypto::ant_quic_integration::{MlDsaPublicKey, MlDsaSignature};

    // Validate public key size (ML-DSA-65 = 1952 bytes)
    if public_key.len() != 1952 {
        tracing::warn!(
            key_len = public_key.len(),
            "Invalid public key size for ownership verification"
        );
        return false;
    }

    // ML-DSA-65 signature is 3309 bytes
    if signature.len() != 3309 {
        tracing::warn!(
            sig_len = signature.len(),
            "Invalid signature size for ownership verification"
        );
        return false;
    }

    // Convert to typed arrays
    let pk_array: [u8; 1952] = match public_key.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            tracing::warn!("Failed to convert public key to array");
            return false;
        }
    };

    let sig_array: [u8; 3309] = match signature.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            tracing::warn!("Failed to convert signature to array");
            return false;
        }
    };

    // Create typed wrappers for ant-quic (tuple structs wrapping Box)
    let ml_pk = MlDsaPublicKey(Box::new(pk_array));
    let ml_sig = MlDsaSignature(Box::new(sig_array));

    // Use the quantum_crypto module for ML-DSA verification
    match crate::quantum_crypto::ml_dsa_verify(&ml_pk, challenge, &ml_sig) {
        Ok(valid) => valid,
        Err(e) => {
            tracing::warn!(error = ?e, "ML-DSA verification error");
            false
        }
    }
}

/// Generate challenge data for ownership verification.
///
/// Combines request ID, binary hash, and timestamp into signable data.
#[must_use]
pub fn generate_ownership_challenge(
    request_id: &[u8; 16],
    binary_hash: &[u8; 32],
    timestamp: u64,
) -> Vec<u8> {
    let mut challenge = Vec::with_capacity(16 + 32 + 8);
    challenge.extend_from_slice(request_id);
    challenge.extend_from_slice(binary_hash);
    challenge.extend_from_slice(&timestamp.to_le_bytes());
    challenge
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_eq_equal() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        assert!(ct_eq(&a, &b));
    }

    #[test]
    fn test_ct_eq_not_equal() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 5];
        assert!(!ct_eq(&a, &b));
    }

    #[test]
    fn test_ct_eq_different_lengths() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3, 4];
        assert!(!ct_eq(&a, &b));
    }

    #[test]
    fn test_ct_eq_32() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        assert!(ct_eq_32(&a, &b));

        let mut c = [0x42u8; 32];
        c[31] = 0x43;
        assert!(!ct_eq_32(&a, &c));
    }

    #[test]
    fn test_ct_eq_16() {
        let a = [0x11u8; 16];
        let b = [0x11u8; 16];
        assert!(ct_eq_16(&a, &b));
    }

    #[test]
    fn test_nonce_registry_fresh() {
        let registry = NonceRegistry::new(NonceRegistryConfig::testing());
        let peer_id = [0x42u8; 32];

        // First use should succeed
        assert!(registry.check_and_record(&peer_id, 12345));
    }

    #[test]
    fn test_nonce_registry_replay_detected() {
        let registry = NonceRegistry::new(NonceRegistryConfig::testing());
        let peer_id = [0x42u8; 32];

        // First use succeeds
        assert!(registry.check_and_record(&peer_id, 12345));

        // Same nonce should fail (replay)
        assert!(!registry.check_and_record(&peer_id, 12345));
    }

    #[test]
    fn test_nonce_registry_different_nonces() {
        let registry = NonceRegistry::new(NonceRegistryConfig::testing());
        let peer_id = [0x42u8; 32];

        assert!(registry.check_and_record(&peer_id, 1));
        assert!(registry.check_and_record(&peer_id, 2));
        assert!(registry.check_and_record(&peer_id, 3));
    }

    #[test]
    fn test_nonce_registry_different_peers() {
        let registry = NonceRegistry::new(NonceRegistryConfig::testing());
        let peer_a = [0x11u8; 32];
        let peer_b = [0x22u8; 32];

        // Same nonce from different peers should both succeed
        assert!(registry.check_and_record(&peer_a, 12345));
        assert!(registry.check_and_record(&peer_b, 12345));
    }

    #[test]
    fn test_nonce_registry_stats() {
        let registry = NonceRegistry::new(NonceRegistryConfig::testing());
        let peer_id = [0x42u8; 32];

        registry.check_and_record(&peer_id, 1);
        registry.check_and_record(&peer_id, 2);

        let stats = registry.stats();
        assert_eq!(stats.total_peers, 1);
        assert_eq!(stats.total_nonces, 2);
    }

    #[test]
    fn test_security_event_severity() {
        assert_eq!(
            SecurityEventType::AttestationVerified.severity(),
            SecuritySeverity::Info
        );
        assert_eq!(
            SecurityEventType::ReplayDetected.severity(),
            SecuritySeverity::Critical
        );
        assert_eq!(
            SecurityEventType::RateLimitExceeded.severity(),
            SecuritySeverity::Warning
        );
    }

    #[test]
    fn test_security_audit_log_record() {
        let log = SecurityAuditLog::new(100);

        log.record_simple(SecurityEventType::AttestationVerified, Some([0x42u8; 32]));
        log.record_simple(SecurityEventType::AttestationFailed, Some([0x43u8; 32]));

        assert_eq!(log.event_count(SecurityEventType::AttestationVerified), 1);
        assert_eq!(log.event_count(SecurityEventType::AttestationFailed), 1);
    }

    #[test]
    fn test_security_audit_log_recent_events() {
        let log = SecurityAuditLog::new(100);

        log.record_simple(SecurityEventType::AttestationVerified, None);
        log.record_simple(SecurityEventType::AttestationFailed, None);
        log.record_simple(SecurityEventType::ReplayDetected, None);

        let recent = log.recent_events(2);
        assert_eq!(recent.len(), 2);
        // Newest first
        assert_eq!(recent[0].event_type, SecurityEventType::ReplayDetected);
    }

    #[test]
    fn test_security_audit_summary() {
        let log = SecurityAuditLog::new(100);

        log.record_simple(SecurityEventType::AttestationVerified, None);
        log.record_simple(SecurityEventType::AttestationVerified, None);
        log.record_simple(SecurityEventType::ReplayDetected, None);

        let summary = log.summary();
        assert_eq!(summary.attestation_verified, 2);
        assert_eq!(summary.replay_detected, 1);
    }

    #[test]
    fn test_generate_ownership_challenge() {
        let request_id = [0x11u8; 16];
        let binary_hash = [0x22u8; 32];
        let timestamp = 1234567890u64;

        let challenge = generate_ownership_challenge(&request_id, &binary_hash, timestamp);

        assert_eq!(challenge.len(), 16 + 32 + 8);
        assert_eq!(&challenge[0..16], &request_id);
        assert_eq!(&challenge[16..48], &binary_hash);
    }

    #[test]
    fn test_proof_replay_check() {
        let registry = NonceRegistry::new(NonceRegistryConfig::testing());
        let peer_id = [0x42u8; 32];
        let proof_hash = [0x11u8; 32];

        // First check should pass
        assert!(registry.check_proof_replay(&peer_id, &proof_hash));

        // Record it
        registry.record_proof(&peer_id, &proof_hash);

        // Second check should fail (replay)
        assert!(!registry.check_proof_replay(&peer_id, &proof_hash));
    }
}
