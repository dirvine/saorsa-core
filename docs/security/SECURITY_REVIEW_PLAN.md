# Comprehensive S/Kademlia Security Review Plan

## Executive Summary

This document outlines a comprehensive security review plan for the saorsa-core S/Kademlia implementation, focusing on production readiness with emphasis on:

1. **EigenTrust Integration** - Reputation-based node trust
2. **Geo-blocking** - Geographic diversity and blocking
3. **Security Measures** - Sybil, collusion, eclipse attack prevention
4. **Data Integrity Checks** - Attestation and verification
5. **Routing Table Refresh** - Close group validation during refresh
6. **Comprehensive Metrics** - Security, node health, and data health monitoring

---

## Current Implementation Assessment

### Implemented Security Components

| Component | File | Status | Notes |
|-----------|------|--------|-------|
| Sybil Detection | `src/dht/sybil_detector.rs` | ✅ Implemented | 4 detection vectors |
| Collusion Detection | `src/dht/collusion_detector.rs` | ✅ Implemented | 5 evidence types |
| Close Group Validator | `src/dht/routing_maintenance/close_group_validator.rs` | ✅ Implemented | Hybrid trust/BFT |
| Security Metrics | `src/dht/metrics/security_metrics.rs` | ✅ Implemented | Thread-safe collector |
| Node Age Verification | `src/dht/node_age_verifier.rs` | ✅ Implemented | Age-based trust |
| Data Attestation | `src/dht/routing_maintenance/attestation.rs` | ✅ Implemented | Nonce-prepended hash |
| Witness Protocol | `src/dht/witness_protocol.rs` | ⚠️ Partial | Network TODOs remain |
| Bucket Refresh | `src/dht/routing_maintenance/refresh.rs` | ✅ Implemented | Tiered refresh |
| Eviction Manager | `src/dht/routing_maintenance/eviction.rs` | ✅ Implemented | Multi-reason eviction |

### Gap Analysis

#### Critical Gaps

1. **Routing Table Refresh Integration**
   - Close group validation exists but not fully integrated into refresh cycle
   - Need to verify removed nodes are properly tracked across the network
   - Missing: Automatic propagation of close group changes

2. **Witness Network Protocol**
   - Several `TODO` markers for actual network queries
   - Need to implement cross-validation with other nodes
   - Proof generation currently mocked (32 zero bytes)

3. **Metrics Integration**
   - Detectors exist but not all connected to metrics collector
   - Need unified dashboard for security events

---

## Phase 1: Close Group Validation During Routing Table Refresh

### Objective
Ensure that during routing table refresh, each node is validated and confirmed to still be a valid member of its close group, with network-wide consensus.

### Current Implementation Review

The `BucketRefreshManager` (`refresh.rs:164-425`) already includes:
- Tiered refresh strategy (Critical/Important/Standard/Background)
- Validation tracking per bucket
- Attack mode detection based on validation failures

The `CloseGroupValidator` (`close_group_validator.rs:282-611`) provides:
- Hybrid trust-weighted/BFT validation
- Attack indicator tracking with automatic BFT escalation
- Geographic diversity requirements
- Collusion detection in responses

### Enhancement Plan

#### 1.1 Integrate Close Group Validation into Refresh Cycle

```rust
// In routing_maintenance/refresh.rs

/// Enhanced refresh that includes close group validation
pub async fn refresh_bucket_with_validation(
    &mut self,
    bucket_idx: usize,
    nodes_in_bucket: &[NodeInfo],
    trust_provider: &impl TrustProvider,
    network: &impl NetworkProtocol,
) -> BucketRefreshResult {
    let mut result = BucketRefreshResult::default();

    // For each node in bucket, validate close group membership
    for node in nodes_in_bucket {
        // 1. Query close group peers about this node
        let responses = self.query_close_group_peers(node, network).await?;

        // 2. Validate membership with hybrid approach
        let validation = self.validator.validate_membership(
            &node.id,
            &responses,
            trust_provider.get_trust_score(&node.id),
        );

        // 3. Process result
        self.process_validation_result(bucket_idx, &validation);

        // 4. If node removed from close group, propagate change
        if !validation.is_valid {
            self.handle_invalid_node(node, &validation, network).await;
        }

        result.record_validation(validation);
    }

    result
}
```

#### 1.2 Cross-Node Close Group Agreement Protocol

```rust
/// Query multiple nodes about a target's close group membership
pub async fn verify_close_group_consensus(
    &self,
    target: &DhtNodeId,
    witnesses: &[NodeInfo],
    network: &impl NetworkProtocol,
) -> CloseGroupConsensusResult {
    // Query each witness: "Is target_id in your close group?"
    let responses = join_all(witnesses.iter().map(|w| {
        network.query_close_group_membership(w, target)
    })).await;

    // Build response set for validation
    let close_group_responses: Vec<CloseGroupResponse> = responses
        .into_iter()
        .filter_map(|r| r.ok())
        .collect();

    // Use validator for consensus decision
    self.validator.validate_membership(target, &close_group_responses, None)
}
```

#### 1.3 Track Nodes Removed from Close Groups

```rust
/// Track nodes that have been evicted from any close group
pub struct CloseGroupEvictionTracker {
    /// Nodes evicted with reasons and timestamps
    evicted_nodes: HashMap<DhtNodeId, EvictionRecord>,
    /// Broadcast channel for eviction events
    eviction_events: broadcast::Sender<CloseGroupEviction>,
}

impl CloseGroupEvictionTracker {
    pub fn record_eviction(&mut self, node_id: DhtNodeId, reasons: Vec<CloseGroupFailure>) {
        let record = EvictionRecord {
            evicted_at: SystemTime::now(),
            reasons: reasons.clone(),
            consensus_count: 1,
        };
        self.evicted_nodes.insert(node_id.clone(), record);

        // Broadcast to network
        let _ = self.eviction_events.send(CloseGroupEviction {
            node_id,
            reasons,
            timestamp: SystemTime::now(),
        });
    }

    /// Check if a node was recently evicted
    pub fn was_evicted(&self, node_id: &DhtNodeId, within: Duration) -> bool {
        self.evicted_nodes.get(node_id)
            .map(|r| r.evicted_at.elapsed().unwrap_or_default() < within)
            .unwrap_or(false)
    }
}
```

---

## Phase 2: EigenTrust Integration Points

### Current Implementation

Trust-weighted Kademlia exists in `src/dht/trust_weighted_kademlia.rs` with:
- Trust matrix building
- Power iteration for global trust
- Interaction outcome tracking

### Enhancement Plan

#### 2.1 Connect Trust Scores to All Security Decisions

```rust
/// Unified trust score provider for all security decisions
pub struct SecurityTrustIntegration {
    eigentrust: Arc<RwLock<EigenTrustEngine>>,
    node_age_verifier: Arc<NodeAgeVerifier>,
    sybil_detector: Arc<RwLock<SybilDetector>>,
    collusion_detector: Arc<RwLock<CollusionDetector>>,
}

impl SecurityTrustIntegration {
    /// Get composite security score for a node (0.0 - 1.0)
    pub fn get_security_score(&self, node_id: &DhtNodeId) -> f64 {
        let base_trust = self.eigentrust.read().get_trust(node_id).unwrap_or(0.5);
        let age_multiplier = self.node_age_verifier.get_trust_multiplier(node_id);
        let sybil_penalty = self.sybil_detector.read().sybil_risk_score(node_id);
        let collusion_penalty = self.collusion_detector.read().collusion_risk_score(node_id);

        // Composite score with penalties
        let score = base_trust * age_multiplier * (1.0 - sybil_penalty * 0.5) * (1.0 - collusion_penalty * 0.5);
        score.clamp(0.0, 1.0)
    }

    /// Should this node be used for critical operations?
    pub fn is_eligible_for_critical_ops(&self, node_id: &DhtNodeId) -> bool {
        self.get_security_score(node_id) >= 0.7
            && self.node_age_verifier.can_participate_critical(node_id)
            && !self.sybil_detector.read().is_peer_suspected(node_id)
            && !self.collusion_detector.read().is_peer_suspected(node_id)
    }
}
```

#### 2.2 Trust-Weighted Witness Selection

```rust
/// Select witnesses with trust-based weighting
pub fn select_witnesses(
    &self,
    target: &DhtNodeId,
    count: usize,
    trust_provider: &impl TrustProvider,
) -> Vec<NodeInfo> {
    let candidates = self.get_witness_candidates(target);

    // Weight by trust score using Efraimidis-Spirakis
    let mut rng = thread_rng();
    let mut weighted: Vec<_> = candidates
        .iter()
        .filter(|n| trust_provider.get_security_score(&n.id) >= MIN_WITNESS_TRUST)
        .map(|n| {
            let weight = trust_provider.get_security_score(&n.id);
            let key = rng.gen::<f64>().powf(1.0 / weight);
            (key, n.clone())
        })
        .collect();

    weighted.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(Ordering::Equal));

    weighted.into_iter().take(count).map(|(_, n)| n).collect()
}
```

---

## Phase 3: Geographic Diversity and Blocking

### Current Implementation

Geographic routing exists in `src/dht/geographic_routing.rs` with:
- 7 geographic regions
- Region-based peer selection
- IP-based region detection

### Enhancement Plan

#### 3.1 Enhanced Geographic Validation

```rust
/// Geographic security validator
pub struct GeographicSecurityValidator {
    /// Minimum regions required for consensus
    pub min_regions_for_consensus: usize,
    /// Maximum nodes from single region in close group
    pub max_nodes_per_region: usize,
    /// Blocked regions (if any)
    pub blocked_regions: HashSet<GeographicRegion>,
    /// Region trust adjustments
    pub region_trust_factors: HashMap<GeographicRegion, f64>,
}

impl GeographicSecurityValidator {
    /// Validate geographic diversity of a node set
    pub fn validate_diversity(&self, nodes: &[NodeInfo]) -> GeoDiversityResult {
        let region_counts = self.count_by_region(nodes);
        let unique_regions = region_counts.len();

        // Check minimum regions
        if unique_regions < self.min_regions_for_consensus {
            return GeoDiversityResult::InsufficientDiversity {
                required: self.min_regions_for_consensus,
                actual: unique_regions,
            };
        }

        // Check concentration in any single region
        for (region, count) in &region_counts {
            if *count > self.max_nodes_per_region {
                return GeoDiversityResult::RegionConcentration {
                    region: *region,
                    count: *count,
                    max_allowed: self.max_nodes_per_region,
                };
            }
        }

        // Check for blocked regions
        for region in region_counts.keys() {
            if self.blocked_regions.contains(region) {
                return GeoDiversityResult::BlockedRegion(*region);
            }
        }

        GeoDiversityResult::Valid { regions: unique_regions }
    }

    /// Validate latency matches claimed region
    pub fn validate_claimed_region(
        &self,
        node: &NodeInfo,
        measured_latency: Duration,
    ) -> bool {
        let expected_range = node.region.expected_latency_range();
        measured_latency >= expected_range.0 && measured_latency <= expected_range.1
    }
}
```

#### 3.2 Geo-Blocking for Routing

```rust
/// Filter nodes based on geographic policies
pub fn filter_by_geo_policy(
    &self,
    nodes: Vec<NodeInfo>,
    policy: &GeoPolicy,
) -> Vec<NodeInfo> {
    nodes
        .into_iter()
        .filter(|n| {
            // Check blocked regions
            if policy.blocked_regions.contains(&n.region) {
                return false;
            }

            // Check allowed regions (if whitelist mode)
            if !policy.allowed_regions.is_empty()
               && !policy.allowed_regions.contains(&n.region) {
                return false;
            }

            // Check latency matches claimed region (anti-spoofing)
            if let Some(latency) = n.last_measured_latency {
                if !self.validate_claimed_region(n, latency) {
                    return false;
                }
            }

            true
        })
        .collect()
}
```

---

## Phase 4: Data Integrity Checks

### Current Implementation

Data attestation exists in `src/dht/routing_maintenance/attestation.rs` with:
- Nonce-prepended hash challenges
- Deterministic verification
- Replay prevention

### Enhancement Plan

#### 4.1 Continuous Data Integrity Monitoring

```rust
/// Data integrity monitor for continuous health checking
pub struct DataIntegrityMonitor {
    /// Challenge scheduler
    challenge_interval: Duration,
    /// Failed attestations by node
    failed_attestations: HashMap<DhtNodeId, Vec<FailedAttestation>>,
    /// Data health scores by key
    data_health: HashMap<DhtKey, DataHealthScore>,
}

impl DataIntegrityMonitor {
    /// Schedule periodic attestation challenges
    pub async fn run_integrity_checks(&mut self, dht: &DhtEngine) {
        loop {
            // Get all stored keys
            for key in dht.local_keys() {
                // Get nodes storing this key
                let storage_nodes = dht.get_storage_nodes(&key);

                // Challenge each node
                for node in storage_nodes {
                    let challenge = DataChallenge::new_random();

                    match dht.send_attestation_challenge(&node, &key, &challenge).await {
                        Ok(response) => {
                            let valid = challenge.verify_response(&response);
                            self.record_attestation_result(&node.id, &key, valid);
                        }
                        Err(_) => {
                            self.record_attestation_failure(&node.id, &key, "no_response");
                        }
                    }
                }

                // Update data health score
                self.update_data_health(&key, &storage_nodes);
            }

            sleep(self.challenge_interval).await;
        }
    }

    /// Get health score for a piece of data
    pub fn get_data_health(&self, key: &DhtKey) -> DataHealthScore {
        self.data_health.get(key).cloned().unwrap_or_default()
    }
}

/// Health score for stored data
#[derive(Debug, Clone, Default)]
pub struct DataHealthScore {
    /// Number of valid replicas
    pub valid_replicas: usize,
    /// Total expected replicas
    pub expected_replicas: usize,
    /// Geographic diversity of replicas
    pub geographic_diversity: usize,
    /// Average trust of storage nodes
    pub average_trust: f64,
    /// Last verification time
    pub last_verified: Option<SystemTime>,
    /// Health percentage (0.0 - 1.0)
    pub health_percentage: f64,
}
```

#### 4.2 Repair Mechanism for Degraded Data

```rust
/// Automatic repair for degraded data
pub async fn repair_degraded_data(
    &self,
    key: &DhtKey,
    dht: &DhtEngine,
    trust_provider: &impl TrustProvider,
) -> RepairResult {
    let health = self.get_data_health(key);

    if health.health_percentage >= 0.9 {
        return RepairResult::NotNeeded;
    }

    // Find healthy replicas
    let healthy_nodes: Vec<_> = dht.get_storage_nodes(key)
        .into_iter()
        .filter(|n| !self.has_failed_attestation(&n.id, key))
        .collect();

    if healthy_nodes.is_empty() {
        return RepairResult::DataLost;
    }

    // Find new storage nodes with high trust
    let needed = health.expected_replicas - health.valid_replicas;
    let new_nodes = self.select_repair_nodes(key, needed, trust_provider);

    // Replicate from healthy to new nodes
    for new_node in new_nodes {
        if let Err(e) = dht.replicate_data(key, &healthy_nodes[0], &new_node).await {
            tracing::warn!("Repair replication failed: {}", e);
        }
    }

    RepairResult::Repaired { nodes_added: needed }
}
```

---

## Phase 5: Comprehensive Security Metrics

### Current Implementation

Security metrics collector exists in `src/dht/metrics/security_metrics.rs` with:
- Attack risk scores
- Event counters
- Eviction tracking
- Churn rate monitoring

### Enhancement Plan

#### 5.1 Unified Metrics Dashboard

```rust
/// Comprehensive security dashboard metrics
pub struct SecurityDashboard {
    pub security_metrics: SecurityMetrics,
    pub trust_metrics: TrustMetrics,
    pub data_health_metrics: DataHealthMetrics,
    pub network_health_metrics: NetworkHealthMetrics,
}

/// Node health metrics
#[derive(Debug, Clone)]
pub struct NodeHealthMetrics {
    /// Total nodes in routing table
    pub total_nodes: usize,
    /// Nodes by trust tier
    pub nodes_by_trust_tier: HashMap<TrustTier, usize>,
    /// Nodes by age category
    pub nodes_by_age: HashMap<AgeCategory, usize>,
    /// Nodes by geographic region
    pub nodes_by_region: HashMap<GeographicRegion, usize>,
    /// Average trust score
    pub average_trust: f64,
    /// Nodes suspected of Sybil
    pub sybil_suspected_count: usize,
    /// Nodes suspected of collusion
    pub collusion_suspected_count: usize,
    /// Recently evicted count (last hour)
    pub recently_evicted: usize,
}

/// Data health metrics
#[derive(Debug, Clone)]
pub struct DataHealthMetrics {
    /// Total keys stored locally
    pub total_keys: usize,
    /// Keys with healthy replication
    pub healthy_keys: usize,
    /// Keys with degraded replication
    pub degraded_keys: usize,
    /// Keys at risk (< 3 replicas)
    pub at_risk_keys: usize,
    /// Average replication factor
    pub average_replication: f64,
    /// Attestation success rate
    pub attestation_success_rate: f64,
    /// Repairs in progress
    pub repairs_in_progress: usize,
}

/// Network health metrics
#[derive(Debug, Clone)]
pub struct NetworkHealthMetrics {
    /// Current churn rate
    pub churn_rate: f64,
    /// Attack mode active
    pub attack_mode_active: bool,
    /// BFT escalation count
    pub bft_escalations: u64,
    /// Geographic diversity score
    pub geographic_diversity: f64,
    /// Close group stability (average time since last change)
    pub close_group_stability: Duration,
    /// Routing table health score
    pub routing_table_health: f64,
}
```

#### 5.2 Alerting Thresholds

```rust
/// Security alert configuration
pub struct AlertConfig {
    // Attack thresholds
    pub eclipse_score_threshold: f64,      // Default: 0.5
    pub sybil_score_threshold: f64,        // Default: 0.5
    pub collusion_score_threshold: f64,    // Default: 0.5

    // Churn thresholds
    pub high_churn_threshold: f64,         // Default: 0.3 (30%)
    pub critical_churn_threshold: f64,     // Default: 0.5 (50%)

    // Data health thresholds
    pub degraded_key_threshold: f64,       // Default: 0.1 (10% degraded)
    pub at_risk_key_threshold: f64,        // Default: 0.01 (1% at risk)

    // Trust thresholds
    pub low_trust_node_threshold: f64,     // Default: 0.2 (20% low trust)

    // Geographic thresholds
    pub min_region_diversity: usize,       // Default: 3
    pub max_region_concentration: f64,     // Default: 0.5 (50% in one region)
}

impl AlertConfig {
    pub fn check_alerts(&self, dashboard: &SecurityDashboard) -> Vec<SecurityAlert> {
        let mut alerts = Vec::new();

        if dashboard.security_metrics.eclipse_score >= self.eclipse_score_threshold {
            alerts.push(SecurityAlert::EclipseAttackDetected {
                score: dashboard.security_metrics.eclipse_score,
            });
        }

        if dashboard.security_metrics.sybil_score >= self.sybil_score_threshold {
            alerts.push(SecurityAlert::SybilAttackDetected {
                score: dashboard.security_metrics.sybil_score,
            });
        }

        // ... more checks

        alerts
    }
}
```

---

## Phase 6: Production Readiness Checklist

### Code Quality

- [ ] Remove all `unwrap()` calls from production code
- [ ] Remove all `expect()` calls from production code
- [ ] Replace all `TODO` markers with implementations
- [ ] Ensure all public APIs have documentation
- [ ] Run clippy with `-D warnings`
- [ ] Achieve 80%+ test coverage

### Security Audits

- [ ] Audit all cryptographic operations
- [ ] Verify signature validation paths
- [ ] Check for timing side channels
- [ ] Review all trust score calculations
- [ ] Verify rate limiting is effective
- [ ] Test under adversarial conditions

### Integration Testing

- [ ] Test Sybil attack scenarios
- [ ] Test collusion scenarios
- [ ] Test eclipse attack scenarios
- [ ] Test high churn scenarios
- [ ] Test network partition scenarios
- [ ] Test Byzantine fault tolerance limits

### Metrics Verification

- [ ] Verify all metrics are being collected
- [ ] Test alerting thresholds
- [ ] Verify metrics under load
- [ ] Test metrics reset functionality

---

## Implementation Priority

### Immediate (Week 1)
1. Complete witness network protocol implementation
2. Connect close group validation to refresh cycle
3. Add eviction tracking and propagation

### Short-term (Week 2-3)
4. Integrate all detectors with metrics collector
5. Implement geographic validation improvements
6. Add continuous data integrity monitoring

### Medium-term (Week 4-6)
7. Build unified security dashboard
8. Implement automated repair mechanisms
9. Add comprehensive alerting

### Long-term
10. Performance optimization
11. Extended test coverage
12. Formal security audit

---

## Metrics Summary

### Security Metrics to Track

| Metric | Source | Threshold | Alert Level |
|--------|--------|-----------|-------------|
| Eclipse Score | SecurityMetrics | > 0.5 | Critical |
| Sybil Score | SecurityMetrics | > 0.5 | Critical |
| Collusion Score | SecurityMetrics | > 0.5 | High |
| Churn Rate | SecurityMetrics | > 30% | Warning |
| BFT Mode Active | SecurityMetrics | true | Info |
| Attestation Failure Rate | DataIntegrityMonitor | > 10% | High |
| Low Trust Nodes | TrustMetrics | > 20% | Warning |
| Geographic Concentration | GeoMetrics | > 50% | Warning |
| Close Group Validation Failures | SecurityMetrics | > 10/hour | High |
| Witness Validation Failures | SecurityMetrics | > 5% | Warning |

### Node Health Metrics

| Metric | Description | Healthy Range |
|--------|-------------|---------------|
| Average Trust Score | Mean EigenTrust score | > 0.6 |
| Established Node Ratio | Nodes > 24h old | > 60% |
| Veteran Node Ratio | Nodes > 7 days old | > 30% |
| Region Coverage | Unique regions | >= 3 |
| Eviction Rate | Evictions/hour | < 5 |

### Data Health Metrics

| Metric | Description | Healthy Range |
|--------|-------------|---------------|
| Healthy Key Ratio | Keys with full replication | > 95% |
| Average Replication | Mean replicas per key | >= 6 |
| Attestation Success | Pass rate | > 95% |
| Repair Queue Size | Pending repairs | < 100 |

---

## Conclusion

This security review plan provides a comprehensive roadmap for ensuring the saorsa-core S/Kademlia implementation is production-ready with robust security measures. The existing implementation provides a solid foundation with:

- Comprehensive attack detection (Sybil, collusion, eclipse)
- Hybrid trust/BFT consensus for close group validation
- Age-based trust with anti-Sybil properties
- Detailed security metrics collection

Key areas for enhancement include:
1. Completing witness network protocol implementation
2. Integrating close group validation into refresh cycle
3. Building unified metrics dashboard with alerting
4. Continuous data integrity monitoring with repair

Following this plan will result in a robust, secure, and well-monitored DHT implementation suitable for production deployment.
