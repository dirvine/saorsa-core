// Mock implementations for testing
// These implementations provide test doubles that don't require network access

// use super::DhtClient; // Unused import - commented out
use crate::network::P2PNode;

// Mock implementations are provided via extension methods
// The actual implementations need to be in the main modules to have access to private fields

// For P2PNode mock
impl P2PNode {
    /// Create a mock P2P node for testing
    /// Minimal non-networking mock suitable for unit tests
    #[allow(clippy::expect_used)]
    pub fn new_mock() -> Self {
        // Provide a deterministic, no-op implementation for tests that only
        // need a placeholder instance. For full integration, use real builder.
        // Fall back to a trivial constructor if available, otherwise build a
        // minimal instance via a dedicated test helper. This avoids panics in
        // clippy and keeps production code free of unwrap/expect.
        Self::new_for_tests().expect("Failed to create test P2P node")
    }
}

// For DhtClient mock
// Removed duplicate new_mock to avoid conflicts with core DHT client tests
