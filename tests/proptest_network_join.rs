use proptest::prelude::*;
use saorsa_core::identity::restart::{RestartManager, RestartConfig};
use saorsa_core::identity::RegenerationDecision;
use saorsa_core::identity::rejection::{RejectionInfo, RejectionReason, TargetRegion, KeyspaceRegion};
use saorsa_core::identity::node_identity::NodeIdentity;
use saorsa_core::identity::targeting::TargetingConfig;
use saorsa_core::identity::fitness::FitnessConfig;
use saorsa_core::identity::regeneration::RegenerationConfig;
use std::sync::Arc;
use tempfile::tempdir;

// Helper to create a test RestartManager
fn create_test_manager() -> Arc<RestartManager> {
    let dir = tempdir().unwrap();
    let config = RestartConfig {
        fitness: FitnessConfig::default(),
        regeneration: RegenerationConfig::default(),
        targeting: TargetingConfig::default(),
        state_path: dir.path().join("restart_state.json"),
        auto_start_monitoring: false,
        event_channel_capacity: 100,
        persist_on_shutdown: false,
    };
    
    let identity = NodeIdentity::generate().unwrap();
    RestartManager::new(config, identity).unwrap()
}

proptest! {
    #[test]
    fn test_handle_rejection_fuzz(
        reason_byte in 0u8..12, // Generate various rejection reasons (0-12 covers known variants)
        msg in "\\PC*", // Random message strings
        has_suggestion in proptest::bool::ANY,
        suggestion_prefix in proptest::collection::vec(0u8..255, 0..4),
        suggestion_confidence in 0.0f64..1.0f64
    ) {
        let manager = create_test_manager();
        
        // Construct RejectionReason from byte (simulating network deserialization)
        let reason = RejectionReason::from_byte(reason_byte);
        
        // Construct RejectionInfo
        let mut info = RejectionInfo::new(reason)
            .with_message(msg)
            .with_rejecting_node("test_peer");
            
        if has_suggestion {
            let region = KeyspaceRegion {
                prefix: suggestion_prefix,
                prefix_len: 8, // Simplified
                saturation: 0.5,
                estimated_nodes: 10,
            };
            let target = TargetRegion {
                region,
                confidence: suggestion_confidence,
                reason: "test suggestion".to_string(),
            };
            info = info.with_suggested_target(target);
        }
        
        // Handle rejection
        let decision = manager.handle_rejection(info);
        
        // Invariants:
        // 1. Should never panic
        // 2. Decision should be consistent with reason (e.g. Blocklisted -> Blocked)
        
        match reason {
            RejectionReason::Blocklisted => assert!(matches!(decision, RegenerationDecision::Blocked { .. })),
            RejectionReason::GeoIpPolicy => {
                 // GeoIP might trigger regeneration or wait depending on config
                 // For default config, it might be Recommend or Proceed
            }
            _ => {}
        }
    }
}
