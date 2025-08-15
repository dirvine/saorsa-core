// Mock implementations for testing
// These implementations provide test doubles that don't require network access

use super::DhtClient;
use crate::network::P2PNode;

// Mock implementations are provided via extension methods
// The actual implementations need to be in the main modules to have access to private fields

// For P2PNode mock
impl P2PNode {
    /// Create a mock P2P node for testing
    /// This returns a panic as it should be replaced with proper initialization
    pub fn new_mock() -> Self {
        // This will be called in test context only
        // For now, panic to indicate it needs proper implementation
        panic!("P2PNode::new_mock() needs proper test implementation - use builder pattern or test fixtures")
    }
}

// For DhtClient mock  
impl DhtClient {
    /// Create a mock DHT client for testing
    #[cfg(test)]
    pub fn new_mock() -> Self {
        // This will be called in test context only
        // For now, panic to indicate it needs proper implementation
        panic!("DhtClient::new_mock() needs proper test implementation - use builder pattern or test fixtures")
    }
}