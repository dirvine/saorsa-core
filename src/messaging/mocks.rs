// Mock implementations for testing
// These implementations provide test doubles that don't require network access

use super::DhtClient;
use crate::network::P2PNode;

// Mock implementations are provided via extension methods
// The actual implementations need to be in the main modules to have access to private fields

// For P2PNode mock
impl P2PNode {
    /// Create a mock P2P node for testing
    /// Minimal non-networking mock suitable for unit tests
    pub fn new_mock() -> Self {
        // Provide a deterministic, no-op implementation for tests that only
        // need a placeholder instance. For full integration, use real builder.
        // Fall back to a trivial constructor if available, otherwise build a
        // minimal instance via a dedicated test helper. This avoids panics in
        // clippy and keeps production code free of unwrap/expect.
        Self::new_for_tests()
    }
}

// For DhtClient mock  
impl DhtClient {
    /// Create a mock DHT client for testing
    #[cfg(test)]
    pub fn new_mock() -> Self {
        // Return an in-memory, no-op DHT client suitable for unit tests
        Self::in_memory()
    }
}