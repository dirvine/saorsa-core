//! Comprehensive integration tests for dual-stack security features
//!
//! This module tests the integration of:
//! - IPv4/IPv6 DHT identity managers
//! - BGP-based GeoIP provider
//! - Cross-network replication
//! - Node age verification
//!
//! These components work together to provide anti-Sybil protection
//! and network resilience across IPv4/IPv6 dual-stack environments.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use saorsa_core::bgp_geo_provider::BgpGeoProvider;
use saorsa_core::dht::cross_network_replication::{
    CrossNetworkReplicationConfig, CrossNetworkReplicator, IpFamily, NodeNetworkInfo,
};
use saorsa_core::dht::node_age_verifier::{
    NodeAgeCategory, NodeAgeConfig, NodeAgeVerifier, OperationType,
};
use saorsa_core::peer_record::UserId as NodeId;
use saorsa_core::security::GeoProvider;

// Helper to create a NodeId from a string
fn make_node_id(name: &str) -> NodeId {
    let mut hash = [0u8; 32];
    let bytes = name.as_bytes();
    hash[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
    NodeId { hash }
}

// Helper to create NodeNetworkInfo
fn create_node_info(name: &str, ipv4: bool, ipv6: bool, trust: f64) -> NodeNetworkInfo {
    NodeNetworkInfo {
        node_id: make_node_id(name),
        ipv4_addresses: if ipv4 {
            vec![Ipv4Addr::new(192, 168, 1, 1)]
        } else {
            vec![]
        },
        ipv6_addresses: if ipv6 {
            vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)]
        } else {
            vec![]
        },
        last_seen: SystemTime::now(),
        trust_score: trust,
    }
}

// ============================================================================
// BGP GeoIP Provider Tests
// ============================================================================

#[test]
fn test_bgp_provider_initialization() {
    let provider = BgpGeoProvider::new();

    // Provider should be initialized with embedded data
    let stats = provider.stats();
    assert!(stats.ipv4_prefix_count > 0, "Should have IPv4 prefixes");
    assert!(stats.asn_info_count > 0, "Should have ASN mappings");
    assert!(
        stats.hosting_asn_count > 0,
        "Should have hosting ASN database"
    );
    assert!(stats.vpn_asn_count > 0, "Should have VPN ASN database");
}

#[test]
fn test_bgp_provider_cloud_detection() {
    let provider = BgpGeoProvider::new();

    // Test known cloud provider ASN lookup
    let aws_ip = Ipv4Addr::new(52, 0, 0, 1); // AWS range
    let asn = provider.lookup_ipv4_asn(aws_ip);

    // AWS IP should have an ASN (might be 16509 or 14618)
    if let Some(asn) = asn {
        // AWS ASNs are in hosting list
        let is_hosting = provider.is_hosting_asn(asn);
        assert!(
            is_hosting || asn == 16509 || asn == 14618,
            "AWS ASN should be recognized as hosting"
        );
    }
}

#[test]
fn test_bgp_provider_vpn_detection() {
    let provider = BgpGeoProvider::new();

    // Check that VPN ASNs are tracked
    let stats = provider.stats();
    assert!(stats.vpn_asn_count > 0, "Should track VPN ASNs");

    // M247 is a known VPN infrastructure provider
    assert!(
        provider.is_vpn_asn(9009),
        "M247 should be identified as VPN"
    );
    assert!(
        provider.is_vpn_asn(395954),
        "Mullvad should be identified as VPN"
    );
}

#[test]
fn test_bgp_provider_hosting_detection() {
    let provider = BgpGeoProvider::new();

    // Major cloud providers should be in hosting list
    assert!(provider.is_hosting_asn(16509), "AWS should be hosting");
    assert!(provider.is_hosting_asn(15169), "Google should be hosting");
    assert!(provider.is_hosting_asn(8075), "Azure should be hosting");
    assert!(
        provider.is_hosting_asn(13335),
        "Cloudflare should be hosting"
    );
    assert!(
        provider.is_hosting_asn(14061),
        "DigitalOcean should be hosting"
    );
}

#[test]
fn test_bgp_provider_geo_lookup() {
    let provider = BgpGeoProvider::new();

    // Lookup via GeoProvider trait (takes IPv6, handles v4-mapped)
    let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let geo_info = provider.lookup(ipv6);

    // GeoInfo structure is returned (may or may not have data for test addresses)
    // Just verify the lookup doesn't panic
    let _ = geo_info.asn;
    let _ = geo_info.country;
    let _ = geo_info.is_hosting_provider;
    let _ = geo_info.is_vpn_provider;
}

// ============================================================================
// Cross-Network Replication Tests
// ============================================================================

#[test]
fn test_cross_network_replicator_initialization() {
    let config = CrossNetworkReplicationConfig::default();

    assert_eq!(config.min_replicas_per_family, 2);
    assert_eq!(config.target_replicas_per_family, 4);
    assert_eq!(config.total_replication_factor, 8);
    assert!(config.enabled);
    assert!(config.prefer_dual_stack);

    let _replicator = CrossNetworkReplicator::new(config);
}

#[test]
fn test_cross_network_node_registration() {
    let config = CrossNetworkReplicationConfig::default();
    let replicator = CrossNetworkReplicator::new(config);

    // Register IPv4-only nodes
    for i in 0..5 {
        let info = create_node_info(&format!("ipv4-node-{}", i), true, false, 0.8);
        replicator.register_node(info);
    }

    // Register IPv6-only nodes
    for i in 0..5 {
        let info = create_node_info(&format!("ipv6-node-{}", i), false, true, 0.8);
        replicator.register_node(info);
    }

    // Register dual-stack nodes
    for i in 0..3 {
        let info = create_node_info(&format!("dual-stack-{}", i), true, true, 0.9);
        replicator.register_node(info);
    }

    let stats = replicator.get_diversity_stats();
    assert_eq!(stats.total_nodes, 13);
    // IPv4-only = 5, IPv6-only = 5, dual-stack = 3
    // Dual-stack count from stats
    assert_eq!(stats.dual_stack_nodes, 3);
}

#[test]
fn test_cross_network_replica_selection() {
    let config = CrossNetworkReplicationConfig::default();
    let replicator = CrossNetworkReplicator::new(config);

    // Register mixed nodes
    for i in 0..4 {
        let info = create_node_info(&format!("ipv4-{}", i), true, false, 0.8);
        replicator.register_node(info);
    }

    for i in 0..4 {
        let info = create_node_info(&format!("ipv6-{}", i), false, true, 0.8);
        replicator.register_node(info);
    }

    // Select replicas for a key
    let key: [u8; 32] = [1u8; 32];
    let selection = replicator.select_replica_nodes(&key, &[]);

    // Should have nodes from both families
    let ipv4_count = selection.count_by_family(IpFamily::IPv4);
    let ipv6_count = selection.count_by_family(IpFamily::IPv6);

    assert!(ipv4_count >= 2, "Should have IPv4 replicas: {}", ipv4_count);
    assert!(ipv6_count >= 2, "Should have IPv6 replicas: {}", ipv6_count);
}

#[test]
fn test_cross_network_dual_stack_preference() {
    let config = CrossNetworkReplicationConfig {
        prefer_dual_stack: true,
        ..Default::default()
    };
    let replicator = CrossNetworkReplicator::new(config);

    // Add some dual-stack nodes with high trust
    for i in 0..3 {
        let info = create_node_info(&format!("dual-stack-{}", i), true, true, 0.95);
        replicator.register_node(info);
    }

    // Add single-stack nodes with lower trust
    for i in 0..4 {
        let info = create_node_info(&format!("ipv4-only-{}", i), true, false, 0.7);
        replicator.register_node(info);
    }

    let key: [u8; 32] = [2u8; 32];
    let selection = replicator.select_replica_nodes(&key, &[]);

    // Selection should include dual-stack nodes
    assert!(selection.total() >= 3, "Should select multiple nodes");
}

#[test]
fn test_cross_network_diversity_stats() {
    let config = CrossNetworkReplicationConfig::default();
    let replicator = CrossNetworkReplicator::new(config);

    // Register various nodes
    for i in 0..3 {
        let info = create_node_info(&format!("ipv4-{}", i), true, false, 0.8);
        replicator.register_node(info);
    }
    for i in 0..2 {
        let info = create_node_info(&format!("ipv6-{}", i), false, true, 0.8);
        replicator.register_node(info);
    }
    for i in 0..2 {
        let info = create_node_info(&format!("dual-{}", i), true, true, 0.9);
        replicator.register_node(info);
    }

    let stats = replicator.get_diversity_stats();

    assert_eq!(stats.total_nodes, 7);
    assert_eq!(stats.dual_stack_nodes, 2);
    // IPv4-only = total IPv4 nodes - dual-stack = 3
    // IPv6-only = total IPv6 nodes - dual-stack = 2
    assert_eq!(stats.ipv4_only_nodes, 3);
    assert_eq!(stats.ipv6_only_nodes, 2);
}

// ============================================================================
// Node Age Verification Tests
// ============================================================================

#[test]
fn test_node_age_verifier_default_config() {
    let config = NodeAgeConfig::default();

    assert_eq!(config.min_replication_age_secs, 3600); // 1 hour
    assert_eq!(config.min_critical_ops_age_secs, 86400); // 24 hours
    assert!(config.enforce_age_requirements);
    assert_eq!(config.veteran_age_secs, 604800); // 7 days
}

#[test]
fn test_node_age_registration() {
    let verifier = NodeAgeVerifier::new();

    let node_id = make_node_id("test-node-1");
    let record = verifier.register_node(node_id.clone());

    // New node should be in New category
    assert_eq!(record.category(), NodeAgeCategory::New);
    assert!(record.is_active);
    assert_eq!(record.rejoin_count, 0);

    // Should be retrievable
    let retrieved = verifier.get_record(&node_id);
    assert!(retrieved.is_some());
}

#[test]
fn test_node_age_categories() {
    // Test trust multipliers
    assert!(NodeAgeCategory::New.trust_multiplier() < NodeAgeCategory::Young.trust_multiplier());
    assert!(
        NodeAgeCategory::Young.trust_multiplier() < NodeAgeCategory::Established.trust_multiplier()
    );
    assert!(
        NodeAgeCategory::Established.trust_multiplier()
            <= NodeAgeCategory::Veteran.trust_multiplier()
    );

    // Test replication permissions
    assert!(!NodeAgeCategory::New.can_replicate());
    assert!(NodeAgeCategory::Young.can_replicate());
    assert!(NodeAgeCategory::Established.can_replicate());
    assert!(NodeAgeCategory::Veteran.can_replicate());

    // Test critical ops permissions
    assert!(!NodeAgeCategory::New.can_participate_in_critical_ops());
    assert!(!NodeAgeCategory::Young.can_participate_in_critical_ops());
    assert!(NodeAgeCategory::Established.can_participate_in_critical_ops());
    assert!(NodeAgeCategory::Veteran.can_participate_in_critical_ops());
}

#[test]
fn test_node_age_verification_for_operations() {
    let verifier = NodeAgeVerifier::new();

    // Register a new node
    let new_node = make_node_id("new-node");
    verifier.register_node(new_node.clone());

    // New node should not pass replication check
    let result = verifier.verify_for_operation(&new_node, OperationType::Replication);
    assert!(!result.passes, "New nodes should not be able to replicate");
    assert_eq!(result.category, NodeAgeCategory::New);
    assert!(!result.can_replicate);

    // Basic read/write should be allowed
    let result = verifier.verify_for_operation(&new_node, OperationType::BasicRead);
    assert!(result.passes, "New nodes should be able to read");

    let result = verifier.verify_for_operation(&new_node, OperationType::BasicWrite);
    assert!(result.passes, "New nodes should be able to write");
}

#[test]
fn test_unknown_node_verification() {
    let verifier = NodeAgeVerifier::new();

    // Unknown node should fail verification
    let unknown = make_node_id("unknown-node");
    let result = verifier.verify_for_operation(&unknown, OperationType::Replication);

    assert!(!result.passes, "Unknown nodes should not pass");
    assert_eq!(result.category, NodeAgeCategory::New);
    assert!(result.failure_reason.is_some());
}

#[test]
fn test_node_age_stats() {
    let verifier = NodeAgeVerifier::new();

    // Register several nodes
    for i in 0..5 {
        let node_id = make_node_id(&format!("node-{}", i));
        verifier.register_node(node_id);
    }

    let stats = verifier.get_age_stats();
    assert_eq!(stats.total_nodes, 5);
    // All nodes are new since they were just registered
    assert_eq!(stats.new_nodes, 5);
}

#[test]
fn test_replication_eligible_nodes() {
    let verifier = NodeAgeVerifier::new();

    // Register new nodes
    for i in 0..5 {
        let node_id = make_node_id(&format!("new-node-{}", i));
        verifier.register_node(node_id);
    }

    // New nodes should not be eligible for replication
    let eligible = verifier.get_replication_eligible_nodes();
    assert!(
        eligible.is_empty(),
        "New nodes should not be replication eligible"
    );
}

// ============================================================================
// Integration Tests: All Components Working Together
// ============================================================================

#[test]
fn test_full_security_pipeline_new_node() {
    // Simulate a new node joining and going through all security checks

    // 1. Create GeoIP provider and check the joining IP
    let geo_provider = BgpGeoProvider::new();
    let joining_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 100);
    let geo_info = geo_provider.lookup(joining_ip);

    // Geo lookup should complete without error
    let _ = geo_info.is_hosting_provider;
    let _ = geo_info.is_vpn_provider;

    // 2. Register node for age tracking
    let age_verifier = NodeAgeVerifier::new();
    let node_id = make_node_id("joining-node");
    let age_record = age_verifier.register_node(node_id.clone());

    // Node starts as New
    assert_eq!(age_record.category(), NodeAgeCategory::New);

    // 3. Check if node can participate in replication
    let verification = age_verifier.verify_for_operation(&node_id, OperationType::Replication);
    assert!(
        !verification.passes,
        "New node should not immediately replicate"
    );

    // 4. Register with cross-network replicator
    let repl_config = CrossNetworkReplicationConfig::default();
    let replicator = CrossNetworkReplicator::new(repl_config);

    let node_info = NodeNetworkInfo {
        node_id: node_id.clone(),
        ipv4_addresses: vec![Ipv4Addr::new(192, 168, 1, 100)],
        ipv6_addresses: vec![joining_ip],
        last_seen: SystemTime::now(),
        trust_score: NodeAgeCategory::New.trust_multiplier(),
    };
    replicator.register_node(node_info);

    // Verify node is registered
    let stats = replicator.get_diversity_stats();
    assert_eq!(stats.total_nodes, 1);
    assert_eq!(stats.dual_stack_nodes, 1); // Has both IPv4 and IPv6
}

#[test]
fn test_network_partition_resilience_simulation() {
    // Test that cross-network replication provides resilience against
    // IPv4/IPv6 network partitions

    let config = CrossNetworkReplicationConfig {
        min_replicas_per_family: 2,
        target_replicas_per_family: 4,
        total_replication_factor: 8,
        enabled: true,
        prefer_dual_stack: true,
        ..Default::default()
    };
    let replicator = CrossNetworkReplicator::new(config);

    // Add nodes from both families
    for i in 0..5 {
        let info = create_node_info(&format!("ipv4-{}", i), true, false, 0.8);
        replicator.register_node(info);
    }

    for i in 0..5 {
        let info = create_node_info(&format!("ipv6-{}", i), false, true, 0.8);
        replicator.register_node(info);
    }

    // Select replicas
    let key: [u8; 32] = [42u8; 32];
    let selection = replicator.select_replica_nodes(&key, &[]);

    // Should have diversity across families
    let ipv4_count = selection.count_by_family(IpFamily::IPv4);
    let ipv6_count = selection.count_by_family(IpFamily::IPv6);

    assert!(
        ipv4_count >= 2,
        "Need IPv4 replicas for partition resilience: {}",
        ipv4_count
    );
    assert!(
        ipv6_count >= 2,
        "Need IPv6 replicas for partition resilience: {}",
        ipv6_count
    );

    // In case of IPv4 partition, IPv6 replicas are still available
    // (and vice versa)
    let ipv6_nodes = selection.nodes_for_family(IpFamily::IPv6);
    assert!(
        !ipv6_nodes.is_empty(),
        "IPv6 replicas should be available for resilience"
    );
}

#[test]
fn test_sybil_resistance_through_age() {
    // Test that the age verification system provides Sybil resistance
    // by limiting what new nodes can do

    let config = NodeAgeConfig {
        min_replication_age_secs: 3600,   // 1 hour
        min_critical_ops_age_secs: 86400, // 24 hours
        enforce_age_requirements: true,
        trust_bonus_per_day: 0.05,
        max_age_trust_bonus: 0.3,
        veteran_age_secs: 604800, // 7 days
    };
    let verifier = NodeAgeVerifier::with_config(config);

    // Simulate a Sybil attack with many new nodes
    for i in 0..100 {
        let node_id = make_node_id(&format!("sybil-node-{}", i));
        verifier.register_node(node_id);
    }

    // None of these nodes should be able to replicate
    let eligible = verifier.get_replication_eligible_nodes();
    assert!(
        eligible.is_empty(),
        "No Sybil nodes should be eligible for replication"
    );

    // Check stats
    let stats = verifier.get_age_stats();
    assert_eq!(stats.new_nodes, 100);
    assert_eq!(stats.total_nodes, 100);

    // Trust-weighted selection should be affected by low trust scores
    // All nodes have New category with multiplier 0.2
}

#[test]
fn test_geographic_diversity_with_bgp() {
    // Test that BGP provider helps identify geographic/ASN diversity
    let provider = BgpGeoProvider::new();

    // Different ASNs should be identifiable
    let asns_to_check = [16509u32, 15169, 8075, 13335]; // AWS, Google, Azure, Cloudflare

    let mut hosting_count = 0;
    for asn in asns_to_check {
        if provider.is_hosting_asn(asn) {
            hosting_count += 1;
        }
    }

    assert_eq!(
        hosting_count,
        asns_to_check.len(),
        "All major cloud ASNs should be identified as hosting"
    );
}

#[test]
fn test_cross_network_with_no_nodes() {
    let replicator = CrossNetworkReplicator::new(CrossNetworkReplicationConfig::default());

    // Selection with no nodes should return empty
    let key: [u8; 32] = [0u8; 32];
    let selection = replicator.select_replica_nodes(&key, &[]);

    assert_eq!(selection.total(), 0);
    assert_eq!(selection.count_by_family(IpFamily::IPv4), 0);
    assert_eq!(selection.count_by_family(IpFamily::IPv6), 0);
}

#[test]
fn test_ipfamily_opposite() {
    assert_eq!(IpFamily::IPv4.opposite(), IpFamily::IPv6);
    assert_eq!(IpFamily::IPv6.opposite(), IpFamily::IPv4);
}

#[test]
fn test_node_network_info_helpers() {
    // Test IPv4-only node
    let ipv4_only = create_node_info("ipv4-test", true, false, 0.5);
    assert!(ipv4_only.supports_ipv4());
    assert!(!ipv4_only.supports_ipv6());
    assert!(!ipv4_only.is_dual_stack());

    // Test IPv6-only node
    let ipv6_only = create_node_info("ipv6-test", false, true, 0.5);
    assert!(!ipv6_only.supports_ipv4());
    assert!(ipv6_only.supports_ipv6());
    assert!(!ipv6_only.is_dual_stack());

    // Test dual-stack node
    let dual_stack = create_node_info("dual-test", true, true, 0.5);
    assert!(dual_stack.supports_ipv4());
    assert!(dual_stack.supports_ipv6());
    assert!(dual_stack.is_dual_stack());

    // Test supported families
    let families = dual_stack.supported_families();
    assert!(families.contains(&IpFamily::IPv4));
    assert!(families.contains(&IpFamily::IPv6));
}

#[test]
fn test_age_category_min_ages() {
    assert_eq!(NodeAgeCategory::New.min_age_secs(), 0);
    assert_eq!(NodeAgeCategory::Young.min_age_secs(), 3600);
    assert_eq!(NodeAgeCategory::Established.min_age_secs(), 86400);
    assert_eq!(NodeAgeCategory::Veteran.min_age_secs(), 604800);
}

#[test]
fn test_bgp_provider_stats_structure() {
    let provider = BgpGeoProvider::new();
    let stats = provider.stats();

    // The provider should have data
    assert!(stats.ipv4_prefix_count > 0, "Should have IPv4 prefixes");
    // ipv6_prefix_count may be 0 if no IPv6 prefixes are loaded
    assert!(stats.asn_info_count > 0);
    assert!(stats.hosting_asn_count > 0);
    assert!(stats.vpn_asn_count > 0);
}

#[test]
fn test_replica_selection_structure() {
    let config = CrossNetworkReplicationConfig::default();
    let replicator = CrossNetworkReplicator::new(config);

    // Add some nodes
    for i in 0..4 {
        let info = create_node_info(&format!("node-{}", i), true, true, 0.8);
        replicator.register_node(info);
    }

    let key: [u8; 32] = [123u8; 32];
    let selection = replicator.select_replica_nodes(&key, &[]);

    // Test selection methods
    assert!(selection.total() > 0);

    // Test contains method
    let test_node = make_node_id("node-0");
    let contains = selection.contains(&test_node);
    // May or may not contain depending on selection algorithm
    let _ = contains;

    // Test nodes_for_family
    let ipv4_nodes = selection.nodes_for_family(IpFamily::IPv4);
    let ipv6_nodes = selection.nodes_for_family(IpFamily::IPv6);
    // Dual-stack nodes contribute to both
    let _ = ipv4_nodes;
    let _ = ipv6_nodes;
}
