//! Simple test to verify EigenTrust functionality
#![cfg(feature = "adaptive-ml")]

#[cfg(test)]
mod tests {
    use saorsa_core::adaptive::NodeId;
    use saorsa_core::adaptive::trust::*;
    use std::collections::HashSet;

    #[tokio::test]
    async fn test_simple_trust() {
        println!("Starting simple trust test");

        // Create simple test
        let engine = EigenTrustEngine::new(HashSet::new());

        let node1 = NodeId::from_bytes([1u8; 32]);
        let node2 = NodeId::from_bytes([2u8; 32]);

        // Update trust
        engine.update_local_trust(&node1, &node2, true).await;

        // Compute global trust with timeout
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            engine.compute_global_trust(),
        )
        .await;

        match result {
            Ok(trust_map) => {
                println!("Trust computation succeeded, {} nodes", trust_map.len());
                assert!(!trust_map.is_empty());
            }
            Err(_) => {
                panic!("Trust computation timed out!");
            }
        }
    }
}
