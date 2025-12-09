// Copyright 2024 Saorsa Labs Limited
//
//! Security metrics integration tests
//!
//! Tests the enhanced security metrics system including:
//! - Attestation challenge tracking
//! - Trust threshold violation metrics
//! - Close group failure type tracking
//! - Low trust eviction with severity bucketing

use std::sync::Arc;

use saorsa_core::dht::{SecurityMetrics, SecurityMetricsCollector};

/// Test attestation challenge metrics recording
#[tokio::test]
async fn test_attestation_challenge_metrics() {
    let collector = Arc::new(SecurityMetricsCollector::new());

    // Record some attestation challenges sent
    collector.record_attestation_challenge_sent();
    collector.record_attestation_challenge_sent();
    collector.record_attestation_challenge_sent();

    // Record results - 2 passed, 1 failed
    collector.record_attestation_result(true);
    collector.record_attestation_result(true);
    collector.record_attestation_result(false);

    // Get metrics and verify
    let metrics = collector.get_metrics().await;

    assert_eq!(
        metrics.attestation_challenges_sent_total, 3,
        "Should have 3 challenges sent"
    );
    assert_eq!(
        metrics.attestation_challenges_passed_total, 2,
        "Should have 2 challenges passed"
    );
    assert_eq!(
        metrics.attestation_challenges_failed_total, 1,
        "Should have 1 challenge failed"
    );
}

/// Test trust threshold violation tracking
#[tokio::test]
async fn test_trust_threshold_violations() {
    let collector = Arc::new(SecurityMetricsCollector::new());

    // Record some trust threshold violations
    collector.record_trust_threshold_violation();
    collector.record_trust_threshold_violation();
    collector.record_trust_threshold_violation();

    // Set low trust node count
    collector.set_low_trust_nodes_count(5);

    // Get metrics and verify
    let metrics = collector.get_metrics().await;

    assert_eq!(
        metrics.trust_threshold_violations_total, 3,
        "Should have 3 trust threshold violations"
    );
    assert_eq!(
        metrics.low_trust_nodes_current, 5,
        "Should have 5 low trust nodes"
    );

    // Update low trust node count
    collector.set_low_trust_nodes_count(2);
    let metrics = collector.get_metrics().await;
    assert_eq!(
        metrics.low_trust_nodes_current, 2,
        "Should have updated to 2 low trust nodes"
    );
}

/// Test close group failure type recording
#[tokio::test]
async fn test_close_group_failure_types() {
    let collector = Arc::new(SecurityMetricsCollector::new());

    // Record various failure types
    collector
        .record_close_group_failure_type("insufficient_responses")
        .await;
    collector
        .record_close_group_failure_type("insufficient_responses")
        .await;
    collector
        .record_close_group_failure_type("consensus_failure")
        .await;
    collector
        .record_close_group_failure_type("trust_below_threshold")
        .await;
    collector
        .record_close_group_failure_type("trust_below_threshold")
        .await;
    collector
        .record_close_group_failure_type("trust_below_threshold")
        .await;

    // Get metrics and verify
    let metrics = collector.get_metrics().await;

    assert_eq!(
        metrics
            .close_group_failure_by_type
            .get("insufficient_responses"),
        Some(&2),
        "Should have 2 insufficient_responses failures"
    );
    assert_eq!(
        metrics.close_group_failure_by_type.get("consensus_failure"),
        Some(&1),
        "Should have 1 consensus_failure"
    );
    assert_eq!(
        metrics
            .close_group_failure_by_type
            .get("trust_below_threshold"),
        Some(&3),
        "Should have 3 trust_below_threshold failures"
    );
}

/// Test enforcement mode tracking
#[tokio::test]
async fn test_enforcement_mode_tracking() {
    let collector = Arc::new(SecurityMetricsCollector::new());

    // Default should be false (permissive)
    let metrics = collector.get_metrics().await;
    assert!(
        !metrics.enforcement_mode_strict,
        "Default enforcement mode should not be strict"
    );

    // Set to strict
    collector.set_enforcement_mode_strict(true);
    let metrics = collector.get_metrics().await;
    assert!(
        metrics.enforcement_mode_strict,
        "Enforcement mode should be strict"
    );

    // Set back to permissive
    collector.set_enforcement_mode_strict(false);
    let metrics = collector.get_metrics().await;
    assert!(
        !metrics.enforcement_mode_strict,
        "Enforcement mode should be permissive"
    );
}

/// Test low trust eviction with severity bucketing
#[tokio::test]
async fn test_low_trust_eviction_severity_buckets() {
    let collector = Arc::new(SecurityMetricsCollector::new());

    // Record evictions at different trust levels
    // Critical: < 0.05
    collector.record_low_trust_eviction(0.01).await;
    collector.record_low_trust_eviction(0.03).await;

    // Severe: 0.05 - 0.10
    collector.record_low_trust_eviction(0.06).await;
    collector.record_low_trust_eviction(0.08).await;
    collector.record_low_trust_eviction(0.09).await;

    // Moderate: 0.10 - 0.15 (threshold)
    collector.record_low_trust_eviction(0.11).await;
    collector.record_low_trust_eviction(0.12).await;

    // Get metrics and verify
    let metrics = collector.get_metrics().await;

    // Verify trust threshold violations are tracked
    // Each low trust eviction records a violation
    assert_eq!(
        metrics.trust_threshold_violations_total, 7,
        "Should have 7 trust threshold violations (one per eviction)"
    );

    // Verify eviction reasons contain our buckets
    assert!(
        metrics
            .eviction_by_reason
            .contains_key("low_trust_critical"),
        "Should have critical severity evictions"
    );
    assert!(
        metrics.eviction_by_reason.contains_key("low_trust_severe"),
        "Should have severe severity evictions"
    );
    assert!(
        metrics
            .eviction_by_reason
            .contains_key("low_trust_moderate"),
        "Should have moderate severity evictions"
    );

    // Check counts
    assert_eq!(
        metrics.eviction_by_reason.get("low_trust_critical"),
        Some(&2),
        "Should have 2 critical evictions"
    );
    assert_eq!(
        metrics.eviction_by_reason.get("low_trust_severe"),
        Some(&3),
        "Should have 3 severe evictions"
    );
    assert_eq!(
        metrics.eviction_by_reason.get("low_trust_moderate"),
        Some(&2),
        "Should have 2 moderate evictions"
    );
}

/// Test combined metrics collection
#[tokio::test]
async fn test_combined_security_metrics() {
    let collector = Arc::new(SecurityMetricsCollector::new());

    // Simulate a security incident scenario

    // 1. First, some attestation challenges
    for _ in 0..10 {
        collector.record_attestation_challenge_sent();
    }
    for _ in 0..8 {
        collector.record_attestation_result(true);
    }
    for _ in 0..2 {
        collector.record_attestation_result(false);
    }

    // 2. Switch to strict enforcement after failed attestations
    collector.set_enforcement_mode_strict(true);

    // 3. Record some close group failures during investigation
    collector
        .record_close_group_failure_type("trust_below_threshold")
        .await;
    collector
        .record_close_group_failure_type("trust_below_threshold")
        .await;

    // 4. Evict the low trust nodes
    collector.record_low_trust_eviction(0.08).await;
    collector.record_low_trust_eviction(0.04).await;

    // 5. Update low trust node count after eviction
    collector.set_low_trust_nodes_count(3);

    // Get comprehensive metrics
    let metrics = collector.get_metrics().await;

    // Verify attestation metrics
    assert_eq!(metrics.attestation_challenges_sent_total, 10);
    assert_eq!(metrics.attestation_challenges_passed_total, 8);
    assert_eq!(metrics.attestation_challenges_failed_total, 2);

    // Verify enforcement mode
    assert!(metrics.enforcement_mode_strict);

    // Verify close group failures
    assert_eq!(
        metrics
            .close_group_failure_by_type
            .get("trust_below_threshold"),
        Some(&2)
    );

    // Verify trust threshold violations from evictions
    assert_eq!(metrics.trust_threshold_violations_total, 2);

    // Verify low trust node count
    assert_eq!(metrics.low_trust_nodes_current, 3);
}

/// Test reset clears all new metrics
#[tokio::test]
async fn test_metrics_reset_clears_new_fields() {
    let collector = Arc::new(SecurityMetricsCollector::new());

    // Add some data to all new fields
    collector.record_attestation_challenge_sent();
    collector.record_attestation_result(true);
    collector.record_attestation_result(false);
    collector.record_trust_threshold_violation();
    collector.set_low_trust_nodes_count(5);
    collector.set_enforcement_mode_strict(true);
    collector
        .record_close_group_failure_type("test_failure")
        .await;
    collector.record_low_trust_eviction(0.05).await;

    // Verify data was recorded
    let metrics_before = collector.get_metrics().await;
    assert!(metrics_before.attestation_challenges_sent_total > 0);
    assert!(metrics_before.trust_threshold_violations_total > 0);
    assert!(!metrics_before.close_group_failure_by_type.is_empty());

    // Reset
    collector.reset().await;

    // Verify all cleared
    let metrics_after = collector.get_metrics().await;

    assert_eq!(
        metrics_after.attestation_challenges_sent_total, 0,
        "Attestation sent should be reset"
    );
    assert_eq!(
        metrics_after.attestation_challenges_passed_total, 0,
        "Attestation passed should be reset"
    );
    assert_eq!(
        metrics_after.attestation_challenges_failed_total, 0,
        "Attestation failed should be reset"
    );
    assert_eq!(
        metrics_after.trust_threshold_violations_total, 0,
        "Trust violations should be reset"
    );
    assert_eq!(
        metrics_after.low_trust_nodes_current, 0,
        "Low trust nodes should be reset"
    );
    assert!(
        !metrics_after.enforcement_mode_strict,
        "Enforcement mode should be reset to permissive"
    );
    assert!(
        metrics_after.close_group_failure_by_type.is_empty(),
        "Close group failures should be reset"
    );
}

/// Test SecurityMetrics struct creation and defaults
#[test]
fn test_security_metrics_struct_defaults() {
    let metrics = SecurityMetrics::default();

    // Verify new fields have correct defaults
    assert_eq!(metrics.attestation_challenges_sent_total, 0);
    assert_eq!(metrics.attestation_challenges_passed_total, 0);
    assert_eq!(metrics.attestation_challenges_failed_total, 0);
    assert_eq!(metrics.trust_threshold_violations_total, 0);
    assert_eq!(metrics.low_trust_nodes_current, 0);
    assert!(!metrics.enforcement_mode_strict);
    assert!(metrics.close_group_failure_by_type.is_empty());
}

/// Test concurrent access to metrics
#[tokio::test]
async fn test_concurrent_metrics_recording() {
    let collector = Arc::new(SecurityMetricsCollector::new());
    let mut handles = vec![];

    // Spawn multiple tasks recording metrics concurrently
    for _ in 0..10 {
        let c = Arc::clone(&collector);
        handles.push(tokio::spawn(async move {
            c.record_attestation_challenge_sent();
            c.record_attestation_result(true);
            c.record_trust_threshold_violation();
        }));
    }

    // Spawn tasks for async methods
    for _ in 0..10 {
        let c = Arc::clone(&collector);
        handles.push(tokio::spawn(async move {
            c.record_close_group_failure_type("concurrent_test").await;
            c.record_low_trust_eviction(0.08).await;
        }));
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }

    // Get metrics
    let metrics = collector.get_metrics().await;

    // Verify counts are correct despite concurrent access
    assert_eq!(
        metrics.attestation_challenges_sent_total, 10,
        "Should have 10 challenges sent"
    );
    assert_eq!(
        metrics.attestation_challenges_passed_total, 10,
        "Should have 10 passed"
    );
    // Trust violations: 10 from record_trust_threshold_violation + 10 from record_low_trust_eviction
    assert_eq!(
        metrics.trust_threshold_violations_total, 20,
        "Should have 20 trust violations"
    );
    assert_eq!(
        metrics.close_group_failure_by_type.get("concurrent_test"),
        Some(&10),
        "Should have 10 concurrent test failures"
    );
}
