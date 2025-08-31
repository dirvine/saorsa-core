// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Security hardening for the adaptive P2P network
//!
//! This module implements comprehensive security measures including:
//! - Rate limiting to prevent DoS attacks
//! - Blacklist management for malicious nodes
//! - Eclipse attack detection
//! - Data integrity verification
//! - Security audit tools

use super::*;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::{Mutex, RwLock};

/// Security configuration
#[derive(Debug, Clone, Default)]
pub struct SecurityConfig {
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,

    /// Blacklist configuration
    pub blacklist: BlacklistConfig,

    /// Eclipse detection configuration
    pub eclipse_detection: EclipseDetectionConfig,

    /// Data integrity configuration
    pub integrity: IntegrityConfig,

    /// Audit configuration
    pub audit: AuditConfig,
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Max requests per node per window
    pub node_requests_per_window: u32,

    /// Max requests per IP per window
    pub ip_requests_per_window: u32,

    /// Time window for rate limiting
    pub window_duration: Duration,

    /// Max concurrent connections per node
    pub max_connections_per_node: u32,

    /// Max join requests per hour
    pub max_joins_per_hour: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            node_requests_per_window: 100,
            ip_requests_per_window: 500,
            window_duration: Duration::from_secs(60),
            max_connections_per_node: 10,
            max_joins_per_hour: 20,
        }
    }
}

/// Blacklist configuration
#[derive(Debug, Clone)]
pub struct BlacklistConfig {
    /// Blacklist entry expiration
    pub entry_ttl: Duration,

    /// Max blacklist size
    pub max_entries: usize,

    /// Auto-blacklist threshold
    pub violation_threshold: u32,
}

impl Default for BlacklistConfig {
    fn default() -> Self {
        Self {
            entry_ttl: Duration::from_secs(86400), // 24 hours
            max_entries: 10000,
            violation_threshold: 3,
        }
    }
}

/// Eclipse detection configuration
#[derive(Debug, Clone)]
pub struct EclipseDetectionConfig {
    /// Minimum routing table diversity score
    pub min_diversity_score: f64,

    /// Maximum allowed nodes from same subnet
    pub max_subnet_ratio: f64,

    /// Suspicious pattern threshold
    pub pattern_threshold: f64,
}

impl Default for EclipseDetectionConfig {
    fn default() -> Self {
        Self {
            min_diversity_score: 0.5,
            max_subnet_ratio: 0.2,
            pattern_threshold: 0.7,
        }
    }
}

/// Data integrity configuration
#[derive(Debug, Clone)]
pub struct IntegrityConfig {
    /// Enable content hash verification
    pub verify_content_hash: bool,

    /// Enable message signatures
    pub require_signatures: bool,

    /// Maximum message size
    pub max_message_size: usize,
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            verify_content_hash: true,
            require_signatures: true,
            max_message_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

/// Audit configuration
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Enable audit logging
    pub enabled: bool,

    /// Log security events
    pub log_security_events: bool,

    /// Log rate limit violations
    pub log_rate_limits: bool,

    /// Audit log retention
    pub retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_security_events: true,
            log_rate_limits: true,
            retention_days: 30,
        }
    }
}

/// Security manager
pub struct SecurityManager {
    /// Configuration
    config: SecurityConfig,

    /// Rate limiter
    rate_limiter: Arc<RateLimiter>,

    /// Blacklist manager
    blacklist: Arc<BlacklistManager>,

    /// Eclipse detector
    eclipse_detector: Arc<EclipseDetector>,

    /// Integrity verifier
    integrity_verifier: Arc<IntegrityVerifier>,

    /// Security auditor
    auditor: Arc<SecurityAuditor>,

    /// Node identity for signing
    _identity: crate::peer_record::UserId,
}

/// Rate limiter
pub struct RateLimiter {
    /// Configuration
    config: RateLimitConfig,

    /// Node request counts
    node_requests: Arc<RwLock<HashMap<NodeId, RequestWindow>>>,

    /// IP request counts
    ip_requests: Arc<RwLock<HashMap<IpAddr, RequestWindow>>>,

    /// Connection counts
    _connections: Arc<RwLock<HashMap<NodeId, u32>>>,

    /// Join request tracking
    join_requests: Arc<RwLock<VecDeque<Instant>>>,
}

/// Request tracking window
#[derive(Debug, Clone)]
struct RequestWindow {
    /// Request count
    count: u32,

    /// Window start time
    window_start: Instant,
}

/// Blacklist manager
pub struct BlacklistManager {
    /// Configuration
    config: BlacklistConfig,

    /// Blacklisted nodes
    blacklist: Arc<RwLock<HashMap<NodeId, BlacklistEntry>>>,

    /// Violation counts
    violations: Arc<RwLock<HashMap<NodeId, u32>>>,
}

/// Blacklist entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistEntry {
    /// Node ID
    pub node_id: NodeId,

    /// Reason for blacklisting
    pub reason: BlacklistReason,

    /// Timestamp when blacklisted
    pub timestamp: SystemTime,

    /// Reporter node
    pub reporter: Option<NodeId>,
}

/// Blacklist reason
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlacklistReason {
    /// Exceeded rate limits
    RateLimitViolation,

    /// Malicious behavior detected
    MaliciousBehavior(String),

    /// Eclipse attack attempt
    EclipseAttack,

    /// Data corruption
    DataCorruption,

    /// Invalid cryptographic proofs
    InvalidCrypto,

    /// Manual blacklist
    Manual(String),
}

/// Eclipse attack detector
pub struct EclipseDetector {
    /// Configuration
    config: EclipseDetectionConfig,

    /// Anomaly patterns
    patterns: Arc<RwLock<AnomalyPatterns>>,
}

/// Anomaly patterns for detection
#[derive(Debug, Default)]
struct AnomalyPatterns {
    /// Rapid connection attempts
    _rapid_connections: HashMap<NodeId, Vec<Instant>>,

    /// Subnet distribution
    subnet_distribution: HashMap<String, u32>,

    /// Suspicious routing updates
    routing_anomalies: Vec<RoutingAnomaly>,
}

/// Routing anomaly
#[derive(Debug, Clone)]
struct RoutingAnomaly {
    /// Node exhibiting anomaly
    _node_id: NodeId,

    /// Type of anomaly
    _anomaly_type: AnomalyType,

    /// Detection time
    timestamp: Instant,
}

/// Anomaly types
#[derive(Debug, Clone)]
pub enum AnomalyType {
    /// Too many nodes from same subnet
    SubnetConcentration,

    /// Rapid routing table changes
    RapidChurn,

    /// Suspicious connection patterns
    ConnectionPattern,

    /// Coordinated behavior
    CoordinatedActivity,
}

/// Data integrity verifier
pub struct IntegrityVerifier {
    /// Configuration
    _config: IntegrityConfig,

    /// Message verification stats
    stats: Arc<RwLock<VerificationStats>>,
}

/// Verification statistics
#[derive(Debug, Default)]
struct VerificationStats {
    /// Total messages verified
    total_verified: u64,

    /// Failed verifications
    failed_verifications: u64,

    /// Invalid hashes
    invalid_hashes: u64,

    /// Invalid signatures
    _invalid_signatures: u64,
}

/// Security auditor
pub struct SecurityAuditor {
    /// Configuration
    config: AuditConfig,

    /// Audit log
    audit_log: Arc<Mutex<VecDeque<AuditEntry>>>,

    /// Event counts
    event_counts: Arc<RwLock<HashMap<String, u64>>>,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Entry timestamp
    pub timestamp: SystemTime,

    /// Event type
    pub event_type: SecurityEvent,

    /// Associated node
    pub node_id: Option<NodeId>,

    /// Event details
    pub details: String,

    /// Severity level
    pub severity: Severity,
}

/// Security event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEvent {
    /// Rate limit exceeded
    RateLimitExceeded,

    /// Node blacklisted
    NodeBlacklisted,

    /// Eclipse attack detected
    EclipseAttackDetected,

    /// Data integrity failure
    IntegrityFailure,

    /// Authentication failure
    AuthenticationFailure,

    /// Suspicious activity
    SuspiciousActivity,

    /// Security configuration change
    ConfigurationChange,
}

/// Event severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

/// Security errors
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Node is blacklisted")]
    Blacklisted,

    #[error("Invalid cryptographic identity")]
    InvalidIdentity,

    #[error("Data integrity check failed")]
    IntegrityCheckFailed,

    #[error("Eclipse attack detected")]
    EclipseAttackDetected,

    #[error("Message too large")]
    MessageTooLarge,

    #[error("Invalid signature")]
    InvalidSignature,
}

impl SecurityManager {
    /// Create new security manager
    pub fn new(config: SecurityConfig, identity: &NodeIdentity) -> Self {
        let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit.clone()));
        let blacklist = Arc::new(BlacklistManager::new(config.blacklist.clone()));
        let eclipse_detector = Arc::new(EclipseDetector::new(config.eclipse_detection.clone()));
        let integrity_verifier = Arc::new(IntegrityVerifier::new(config.integrity.clone()));
        let auditor = Arc::new(SecurityAuditor::new(config.audit.clone()));

        Self {
            config,
            rate_limiter,
            blacklist,
            eclipse_detector,
            integrity_verifier,
            auditor,
            _identity: identity.to_user_id(),
        }
    }

    /// Validate node join request
    pub async fn validate_node_join(&self, node: &NodeDescriptor) -> Result<(), SecurityError> {
        // Check blacklist
        if self.blacklist.is_blacklisted(&node.id).await {
            self.auditor
                .log_event(
                    SecurityEvent::NodeBlacklisted,
                    Some(node.id.clone()),
                    "Node attempted to join while blacklisted".to_string(),
                    Severity::Warning,
                )
                .await;
            return Err(SecurityError::Blacklisted);
        }

        // Check rate limits for joins
        if !self.rate_limiter.check_join_rate().await {
            self.auditor
                .log_event(
                    SecurityEvent::RateLimitExceeded,
                    Some(node.id.clone()),
                    "Join rate limit exceeded".to_string(),
                    Severity::Warning,
                )
                .await;
            return Err(SecurityError::RateLimitExceeded);
        }

        // Verify cryptographic identity
        if !self.verify_identity(node).await {
            return Err(SecurityError::InvalidIdentity);
        }

        Ok(())
    }

    /// Check if request should be rate limited
    pub async fn check_rate_limit(
        &self,
        node_id: &NodeId,
        ip: Option<IpAddr>,
    ) -> Result<(), SecurityError> {
        // Check node rate limit
        if !self.rate_limiter.check_node_rate(node_id).await {
            self.blacklist
                .record_violation(node_id, BlacklistReason::RateLimitViolation)
                .await;
            self.auditor
                .log_event(
                    SecurityEvent::RateLimitExceeded,
                    Some(node_id.clone()),
                    "Node request rate limit exceeded".to_string(),
                    Severity::Warning,
                )
                .await;
            return Err(SecurityError::RateLimitExceeded);
        }

        // Check IP rate limit if provided
        if let Some(ip_addr) = ip
            && !self.rate_limiter.check_ip_rate(&ip_addr).await
        {
            self.auditor
                .log_event(
                    SecurityEvent::RateLimitExceeded,
                    None,
                    format!("IP {ip_addr} rate limit exceeded"),
                    Severity::Warning,
                )
                .await;
            return Err(SecurityError::RateLimitExceeded);
        }

        Ok(())
    }

    /// Detect eclipse attack
    pub async fn detect_eclipse_attack(
        &self,
        routing_table: &[NodeId],
    ) -> Result<(), SecurityError> {
        let diversity_score = self
            .eclipse_detector
            .calculate_diversity_score(routing_table)
            .await;

        if diversity_score < self.config.eclipse_detection.min_diversity_score {
            self.auditor
                .log_event(
                    SecurityEvent::EclipseAttackDetected,
                    None,
                    format!("Low routing table diversity: {diversity_score:.2}"),
                    Severity::Critical,
                )
                .await;
            return Err(SecurityError::EclipseAttackDetected);
        }

        if self
            .eclipse_detector
            .detect_suspicious_patterns(routing_table)
            .await
        {
            self.auditor
                .log_event(
                    SecurityEvent::EclipseAttackDetected,
                    None,
                    "Suspicious routing patterns detected".to_string(),
                    Severity::Critical,
                )
                .await;
            return Err(SecurityError::EclipseAttackDetected);
        }

        Ok(())
    }

    /// Verify message integrity
    pub async fn verify_message_integrity(
        &self,
        message: &[u8],
        hash: &[u8],
        signature: Option<&[u8]>,
    ) -> Result<(), SecurityError> {
        // Basic anti-replay check using timestamp prefix if present
        if message.len() >= 8 {
            let mut ts_bytes = [0u8; 8];
            ts_bytes.copy_from_slice(&message[..8]);
            let msg_ts = u64::from_be_bytes(ts_bytes);
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // 5-minute future tolerance window
            if msg_ts > now + 300 {
                return Err(SecurityError::IntegrityCheckFailed);
            }
        }
        // Check message size
        if message.len() > self.config.integrity.max_message_size {
            return Err(SecurityError::MessageTooLarge);
        }

        // Verify content hash
        if self.config.integrity.verify_content_hash
            && !self.integrity_verifier.verify_hash(message, hash).await
        {
            self.auditor
                .log_event(
                    SecurityEvent::IntegrityFailure,
                    None,
                    "Content hash verification failed".to_string(),
                    Severity::Error,
                )
                .await;
            return Err(SecurityError::IntegrityCheckFailed);
        }

        // Verify signature if required
        if self.config.integrity.require_signatures {
            if let Some(sig) = signature {
                if !self.integrity_verifier.verify_signature(message, sig).await {
                    self.auditor
                        .log_event(
                            SecurityEvent::IntegrityFailure,
                            None,
                            "Message signature verification failed".to_string(),
                            Severity::Error,
                        )
                        .await;
                    return Err(SecurityError::InvalidSignature);
                }
            } else {
                return Err(SecurityError::InvalidSignature);
            }
        }

        Ok(())
    }

    /// Blacklist a node
    pub async fn blacklist_node(&self, node_id: NodeId, reason: BlacklistReason) {
        self.blacklist
            .add_entry(node_id.clone(), reason.clone())
            .await;

        self.auditor
            .log_event(
                SecurityEvent::NodeBlacklisted,
                Some(node_id),
                format!("Node blacklisted: {reason:?}"),
                Severity::Warning,
            )
            .await;
    }

    /// Get security metrics
    pub async fn get_metrics(&self) -> SecurityMetrics {
        SecurityMetrics {
            rate_limit_violations: self.rate_limiter.get_violation_count().await,
            blacklisted_nodes: self.blacklist.get_blacklist_size().await,
            verification_failures: self.integrity_verifier.get_failure_count().await,
            eclipse_detections: self.eclipse_detector.get_detection_count().await,
            audit_entries: self.auditor.get_entry_count().await,
        }
    }

    /// Verify node identity by binding NodeId to the advertised ML-DSA public key
    async fn verify_identity(&self, node: &NodeDescriptor) -> bool {
        // Derive BLAKE3 hash of ML-DSA public key bytes to match UserId
        let bytes = node.public_key.as_bytes();
        let hash = blake3::hash(bytes);
        node.id.as_bytes() == hash.as_bytes()
    }
}

impl RateLimiter {
    /// Create new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            node_requests: Arc::new(RwLock::new(HashMap::new())),
            ip_requests: Arc::new(RwLock::new(HashMap::new())),
            _connections: Arc::new(RwLock::new(HashMap::new())),
            join_requests: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    /// Check node rate limit
    pub async fn check_node_rate(&self, node_id: &NodeId) -> bool {
        let mut requests = self.node_requests.write().await;
        let now = Instant::now();

        let window = requests.entry(node_id.clone()).or_insert(RequestWindow {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(window.window_start) > self.config.window_duration {
            window.count = 0;
            window.window_start = now;
        }

        // Check if under limit
        if window.count < self.config.node_requests_per_window {
            window.count += 1;
            true
        } else {
            false
        }
    }

    /// Check IP rate limit
    pub async fn check_ip_rate(&self, ip: &IpAddr) -> bool {
        let mut requests = self.ip_requests.write().await;
        let now = Instant::now();

        let window = requests.entry(*ip).or_insert(RequestWindow {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(window.window_start) > self.config.window_duration {
            window.count = 0;
            window.window_start = now;
        }

        // Check if under limit
        if window.count < self.config.ip_requests_per_window {
            window.count += 1;
            true
        } else {
            false
        }
    }

    /// Check join rate limit
    pub async fn check_join_rate(&self) -> bool {
        let mut join_requests = self.join_requests.write().await;
        let now = Instant::now();
        let hour_ago = now - Duration::from_secs(3600);

        // Remove old entries
        while let Some(front) = join_requests.front() {
            if *front < hour_ago {
                join_requests.pop_front();
            } else {
                break;
            }
        }

        // Check if under limit
        if join_requests.len() < self.config.max_joins_per_hour as usize {
            join_requests.push_back(now);
            true
        } else {
            false
        }
    }

    /// Get violation count
    pub async fn get_violation_count(&self) -> u64 {
        // In a real implementation, would track violations
        0
    }
}

impl BlacklistManager {
    /// Create new blacklist manager
    pub fn new(config: BlacklistConfig) -> Self {
        Self {
            config,
            blacklist: Arc::new(RwLock::new(HashMap::new())),
            violations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if node is blacklisted
    pub async fn is_blacklisted(&self, node_id: &NodeId) -> bool {
        let blacklist = self.blacklist.read().await;

        if let Some(entry) = blacklist.get(node_id) {
            // Check if entry has expired
            let now = SystemTime::now();
            let elapsed = now
                .duration_since(entry.timestamp)
                .unwrap_or(Duration::ZERO);

            elapsed < self.config.entry_ttl
        } else {
            false
        }
    }

    /// Add blacklist entry
    pub async fn add_entry(&self, node_id: NodeId, reason: BlacklistReason) {
        let mut blacklist = self.blacklist.write().await;

        // Enforce max size
        if blacklist.len() >= self.config.max_entries {
            // Remove oldest entry
            if let Some(oldest) = blacklist
                .iter()
                .min_by_key(|(_, entry)| entry.timestamp)
                .map(|(id, _)| id.clone())
            {
                blacklist.remove(&oldest);
            }
        }

        blacklist.insert(
            node_id.clone(),
            BlacklistEntry {
                node_id,
                reason,
                timestamp: SystemTime::now(),
                reporter: None,
            },
        );
    }

    /// Record violation
    pub async fn record_violation(&self, node_id: &NodeId, reason: BlacklistReason) {
        let mut violations = self.violations.write().await;
        let count = violations.entry(node_id.clone()).or_insert(0);
        *count += 1;

        // Auto-blacklist if threshold exceeded
        if *count >= self.config.violation_threshold {
            drop(violations);
            self.add_entry(node_id.clone(), reason).await;
        }
    }

    /// Get blacklist size
    pub async fn get_blacklist_size(&self) -> usize {
        self.blacklist.read().await.len()
    }

    /// Export blacklist for sharing
    pub async fn export_blacklist(&self) -> Vec<BlacklistEntry> {
        let blacklist = self.blacklist.read().await;
        let now = SystemTime::now();

        blacklist
            .values()
            .filter(|entry| {
                let elapsed = now
                    .duration_since(entry.timestamp)
                    .unwrap_or(Duration::ZERO);
                elapsed < self.config.entry_ttl
            })
            .cloned()
            .collect()
    }

    /// Import blacklist entries
    pub async fn import_blacklist(&self, entries: Vec<BlacklistEntry>) {
        let mut blacklist = self.blacklist.write().await;

        for entry in entries {
            // Only import if not already present or newer
            match blacklist.get(&entry.node_id) {
                Some(existing) if existing.timestamp >= entry.timestamp => continue,
                _ => {
                    blacklist.insert(entry.node_id.clone(), entry);
                }
            }
        }
    }
}

impl EclipseDetector {
    /// Create new eclipse detector
    pub fn new(config: EclipseDetectionConfig) -> Self {
        Self {
            config,
            patterns: Arc::new(RwLock::new(AnomalyPatterns::default())),
        }
    }

    /// Calculate diversity score of routing table
    pub async fn calculate_diversity_score(&self, routing_table: &[NodeId]) -> f64 {
        if routing_table.is_empty() {
            return 0.0;
        }

        // Calculate based on unique hash prefixes
        let mut prefixes = HashSet::new();
        for node_id in routing_table {
            // Use first 4 bytes as prefix
            let prefix = &node_id.hash[..4];
            prefixes.insert(prefix.to_vec());
        }

        // Diversity score is ratio of unique prefixes to total nodes
        prefixes.len() as f64 / routing_table.len() as f64
    }

    /// Detect suspicious patterns
    pub async fn detect_suspicious_patterns(&self, routing_table: &[NodeId]) -> bool {
        let mut patterns = self.patterns.write().await;

        // Check for subnet concentration
        // In a real implementation, would extract IPs from node descriptors
        // For now, use hash prefix as proxy
        patterns.subnet_distribution.clear();

        for node_id in routing_table {
            let subnet = format!("{:02x}{:02x}", node_id.hash[0], node_id.hash[1]);
            *patterns.subnet_distribution.entry(subnet).or_insert(0) += 1;
        }

        // Check if any subnet has too many nodes
        let max_allowed = (routing_table.len() as f64 * self.config.max_subnet_ratio) as u32;
        for count in patterns.subnet_distribution.values() {
            if *count > max_allowed {
                return true;
            }
        }

        false
    }

    /// Record routing anomaly
    pub async fn record_anomaly(&self, node_id: NodeId, anomaly_type: AnomalyType) {
        let mut patterns = self.patterns.write().await;

        patterns.routing_anomalies.push(RoutingAnomaly {
            _node_id: node_id,
            _anomaly_type: anomaly_type,
            timestamp: Instant::now(),
        });

        // Keep only recent anomalies (last hour)
        let cutoff = Instant::now() - Duration::from_secs(3600);
        patterns.routing_anomalies.retain(|a| a.timestamp > cutoff);
    }

    /// Get detection count
    pub async fn get_detection_count(&self) -> u64 {
        self.patterns.read().await.routing_anomalies.len() as u64
    }
}

impl IntegrityVerifier {
    /// Create new integrity verifier
    pub fn new(config: IntegrityConfig) -> Self {
        Self {
            _config: config,
            stats: Arc::new(RwLock::new(VerificationStats::default())),
        }
    }

    /// Verify content hash
    pub async fn verify_hash(&self, content: &[u8], expected_hash: &[u8]) -> bool {
        let mut stats = self.stats.write().await;
        stats.total_verified += 1;

        let mut hasher = Sha256::new();
        hasher.update(content);
        let computed_hash = hasher.finalize();

        if computed_hash.as_slice() == expected_hash {
            true
        } else {
            stats.failed_verifications += 1;
            stats.invalid_hashes += 1;
            false
        }
    }

    /// Verify signature (placeholder)
    pub async fn verify_signature(&self, _message: &[u8], _signature: &[u8]) -> bool {
        // In a real implementation, would verify Ed25519 signature
        // For now, always return true
        true
    }

    /// Get failure count
    pub async fn get_failure_count(&self) -> u64 {
        self.stats.read().await.failed_verifications
    }
}

impl SecurityAuditor {
    /// Create new security auditor
    pub fn new(config: AuditConfig) -> Self {
        Self {
            config,
            audit_log: Arc::new(Mutex::new(VecDeque::new())),
            event_counts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Log security event
    pub async fn log_event(
        &self,
        event_type: SecurityEvent,
        node_id: Option<NodeId>,
        details: String,
        severity: Severity,
    ) {
        if !self.config.enabled {
            return;
        }

        let entry = AuditEntry {
            timestamp: SystemTime::now(),
            event_type: event_type.clone(),
            node_id,
            details,
            severity,
        };

        // Add to log
        let mut log = self.audit_log.lock().await;
        log.push_back(entry);

        // Enforce retention
        let retention_duration = Duration::from_secs(self.config.retention_days as u64 * 86400);
        let cutoff = SystemTime::now() - retention_duration;

        while let Some(front) = log.front() {
            if front.timestamp < cutoff {
                log.pop_front();
            } else {
                break;
            }
        }

        // Update event counts
        let event_name = format!("{event_type:?}");
        let mut counts = self.event_counts.write().await;
        *counts.entry(event_name).or_insert(0) += 1;
    }

    /// Get audit entries
    pub async fn get_entries(
        &self,
        since: Option<SystemTime>,
        severity_filter: Option<Severity>,
    ) -> Vec<AuditEntry> {
        let log = self.audit_log.lock().await;

        log.iter()
            .filter(|entry| {
                if let Some(min_time) = since
                    && entry.timestamp < min_time
                {
                    return false;
                }
                if let Some(min_severity) = severity_filter
                    && (entry.severity as u8) < (min_severity as u8)
                {
                    return false;
                }
                true
            })
            .cloned()
            .collect()
    }

    /// Get entry count
    pub async fn get_entry_count(&self) -> u64 {
        self.audit_log.lock().await.len() as u64
    }

    /// Export audit report
    pub async fn export_report(&self) -> AuditReport {
        let entries = self.get_entries(None, None).await;
        let event_counts = self.event_counts.read().await.clone();

        AuditReport {
            generated_at: SystemTime::now(),
            total_entries: entries.len(),
            event_counts,
            severity_breakdown: self.calculate_severity_breakdown(&entries),
            recent_critical_events: entries
                .iter()
                .filter(|e| e.severity == Severity::Critical)
                .take(10)
                .cloned()
                .collect(),
        }
    }

    /// Calculate severity breakdown
    fn calculate_severity_breakdown(&self, entries: &[AuditEntry]) -> HashMap<Severity, u64> {
        let mut breakdown = HashMap::new();

        for entry in entries {
            *breakdown.entry(entry.severity).or_insert(0) += 1;
        }

        breakdown
    }
}

/// Security metrics
#[derive(Debug, Clone, Default)]
pub struct SecurityMetrics {
    pub rate_limit_violations: u64,
    pub blacklisted_nodes: usize,
    pub verification_failures: u64,
    pub eclipse_detections: u64,
    pub audit_entries: u64,
}

/// Audit report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub generated_at: SystemTime,
    pub total_entries: usize,
    pub event_counts: HashMap<String, u64>,
    pub severity_breakdown: HashMap<Severity, u64>,
    pub recent_critical_events: Vec<AuditEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_node_limits() {
        let config = RateLimitConfig {
            node_requests_per_window: 5,
            window_duration: Duration::from_secs(1),
            ..Default::default()
        };

        let limiter = RateLimiter::new(config);
        let node_id = NodeId { hash: [1u8; 32] };

        // Should allow first 5 requests
        for _ in 0..5 {
            assert!(limiter.check_node_rate(&node_id).await);
        }

        // 6th request should fail
        assert!(!limiter.check_node_rate(&node_id).await);

        // Wait for window to reset
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Should allow again
        assert!(limiter.check_node_rate(&node_id).await);
    }

    #[tokio::test]
    async fn test_blacklist_management() {
        let config = BlacklistConfig::default();
        let blacklist = BlacklistManager::new(config);

        let node_id = NodeId { hash: [2u8; 32] };

        // Should not be blacklisted initially
        assert!(!blacklist.is_blacklisted(&node_id).await);

        // Add to blacklist
        blacklist
            .add_entry(
                node_id.clone(),
                BlacklistReason::MaliciousBehavior("Test".to_string()),
            )
            .await;

        // Should now be blacklisted
        assert!(blacklist.is_blacklisted(&node_id).await);

        // Check blacklist size
        assert_eq!(blacklist.get_blacklist_size().await, 1);
    }

    #[tokio::test]
    async fn test_eclipse_detection() {
        let config = EclipseDetectionConfig {
            min_diversity_score: 0.5,
            max_subnet_ratio: 0.3,
            pattern_threshold: 0.7,
        };

        let detector = EclipseDetector::new(config);

        // Create routing table with low diversity
        let mut routing_table = vec![];
        for i in 0..10 {
            let mut hash = [0u8; 32];
            hash[0] = 1; // Same prefix
            hash[31] = i;
            routing_table.push(NodeId { hash });
        }

        // Should have low diversity score
        let score = detector.calculate_diversity_score(&routing_table).await;
        assert!(score < 0.5);

        // Create diverse routing table
        let mut diverse_table = vec![];
        for i in 0..10 {
            let mut hash = [0u8; 32];
            hash[0] = i * 25; // Different prefixes
            diverse_table.push(NodeId { hash });
        }

        // Should have high diversity score
        let diverse_score = detector.calculate_diversity_score(&diverse_table).await;
        assert!(diverse_score > 0.8);
    }

    #[tokio::test]
    async fn test_integrity_verification() {
        let config = IntegrityConfig::default();
        let verifier = IntegrityVerifier::new(config);

        let content = b"Test content";
        let mut hasher = Sha256::new();
        hasher.update(content);
        let correct_hash = hasher.finalize();

        // Should verify correct hash
        assert!(verifier.verify_hash(content, &correct_hash).await);

        // Should fail with incorrect hash
        let wrong_hash = [0u8; 32];
        assert!(!verifier.verify_hash(content, &wrong_hash).await);

        // Check failure count
        assert_eq!(verifier.get_failure_count().await, 1);
    }

    #[tokio::test]
    async fn test_security_auditor() {
        let config = AuditConfig::default();
        let auditor = SecurityAuditor::new(config);

        // Log some events
        auditor
            .log_event(
                SecurityEvent::RateLimitExceeded,
                None,
                "Test rate limit".to_string(),
                Severity::Warning,
            )
            .await;

        auditor
            .log_event(
                SecurityEvent::EclipseAttackDetected,
                None,
                "Test eclipse attack".to_string(),
                Severity::Critical,
            )
            .await;

        // Check entry count
        assert_eq!(auditor.get_entry_count().await, 2);

        // Get critical events
        let entries = auditor.get_entries(None, Some(Severity::Critical)).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].severity, Severity::Critical);

        // Export report
        let report = auditor.export_report().await;
        assert_eq!(report.total_entries, 2);
        assert_eq!(report.recent_critical_events.len(), 1);
    }

    #[tokio::test]
    async fn test_security_manager_integration() {
        let config = SecurityConfig::default();
        let identity = NodeIdentity::generate().unwrap();
        let manager = SecurityManager::new(config, identity);

        // Test node join validation
        // Generate a valid ML-DSA key and derive matching UserId via blake3(pubkey)
        let (ml_pub, _ml_sec) = crate::quantum_crypto::generate_ml_dsa_keypair().unwrap();
        let derived_hash = blake3::hash(ml_pub.as_bytes());
        let derived_id = crate::peer_record::UserId::from_bytes(*derived_hash.as_bytes());
        let node = NodeDescriptor {
            id: derived_id,
            public_key: ml_pub,
            addresses: vec![],
            hyperbolic: None,
            som_position: None,
            trust: 0.5,
            capabilities: NodeCapabilities {
                storage: 100,
                compute: 50,
                bandwidth: 10,
            },
        };

        // Should pass validation
        assert!(manager.validate_node_join(&node).await.is_ok());

        // Blacklist the node
        manager
            .blacklist_node(node.id.clone(), BlacklistReason::Manual("Test".to_string()))
            .await;

        // Should now fail validation
        assert!(matches!(
            manager.validate_node_join(&node).await,
            Err(SecurityError::Blacklisted)
        ));

        // Check metrics
        let metrics = manager.get_metrics().await;
        assert_eq!(metrics.blacklisted_nodes, 1);
        assert!(metrics.audit_entries > 0);
    }
}
