// Copyright 2024 Saorsa Labs Limited
//
//! Security metrics integration tests
//!
//! Tests the enhanced security metrics system including:
//! - Trust threshold violation metrics
//! - Close group failure type tracking
//! - Low trust eviction with severity bucketing
//! - Geographic diversity tracking

use std::sync::Arc;

use saorsa_core::dht::SecurityMetricsCollector;

/// Test trust threshold violation tracking
#[tokio::test]
async fn test_trust_threshold_violations() {
    let collector = Arc::new(SecurityMetricsCollector::new());

    collector.record_trust_threshold_violation();
    collector.record_trust_threshold_violation();
    collector.record_trust_threshold_violation();

    collector.set_low_trust_nodes_count(5);

    let metrics = collector.get_metrics().await;

    assert_eq!(
        metrics.trust_threshold_violations_total, 3,
        "Should have 3 trust threshold violations"
    );
    assert_eq!(
        metrics.low_trust_nodes_current, 5,
        "Should have 5 low trust nodes"
    );

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
        Some(&2),
        "Should have 2 trust_below_threshold failures"
    );
}

/// Test enforcement mode tracking
#[tokio::test]
async fn test_enforcement_mode_tracking() {
    let collector = Arc::new(SecurityMetricsCollector::new());

    let metrics = collector.get_metrics().await;
    assert!(
        !metrics.enforcement_mode_strict,
        "Default enforcement mode should not be strict"
    );

    collector.set_enforcement_mode_strict(true);
    let metrics = collector.get_metrics().await;
    assert!(metrics.enforcement_mode_strict, "Mode should be strict");

    collector.set_enforcement_mode_strict(false);
    let metrics = collector.get_metrics().await;
    assert!(
        !metrics.enforcement_mode_strict,
        "Mode should be permissive"
    );
}

/// Test low trust eviction with severity bucketing
#[tokio::test]
async fn test_low_trust_eviction_severity_buckets() {
    let collector = Arc::new(SecurityMetricsCollector::new());

    collector.record_low_trust_eviction(0.01).await;
    collector.record_low_trust_eviction(0.06).await;
    collector.record_low_trust_eviction(0.11).await;

    let metrics = collector.get_metrics().await;

    assert_eq!(
        metrics.trust_threshold_violations_total, 3,
        "Should have 3 trust threshold violations"
    );
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
}

/// Test geographic diversity metrics
#[tokio::test]
async fn test_geographic_diversity_metrics() {
    let collector = Arc::new(SecurityMetricsCollector::new());

    collector.record_geographic_diversity_rejection();
    collector.record_geographic_diversity_rejection();

    collector.set_region_node_count("NorthAmerica", 3).await;
    collector.set_region_node_count("Europe", 2).await;

    let metrics = collector.get_metrics().await;

    assert_eq!(metrics.geographic_diversity_rejections_total, 2);
    assert_eq!(
        metrics.nodes_per_region.get("NorthAmerica").copied(),
        Some(3)
    );
    assert_eq!(metrics.nodes_per_region.get("Europe").copied(), Some(2));
}
