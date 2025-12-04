// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com

//! Witness Client for S/Kademlia Byzantine Fault Tolerance
//!
//! This module provides the high-level client for witness operations:
//! - Requesting witnesses for DHT operations
//! - Collecting and aggregating witness responses
//! - Verifying witness consensus for BFT

use crate::dht::witness::OperationType;
use crate::dht::witness_protocol::{
    AggregatedWitnessProof, WitnessOperationId, WitnessRequest, WitnessResponse,
};
use crate::dht::witness_selection::{WitnessCandidate, WitnessSelection, WitnessSelector};
use crate::dht::DhtKey;
use crate::error::{P2PError, P2pResult as Result};
use crate::PeerId;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Configuration for the witness client
#[derive(Debug, Clone)]
pub struct WitnessClientConfig {
    /// Timeout for individual witness requests
    pub request_timeout: Duration,
    /// Maximum concurrent witness requests
    pub max_concurrent_requests: usize,
    /// Minimum witnesses required for BFT
    pub min_witnesses_for_bft: usize,
    /// Whether to retry failed witness requests
    pub retry_failed_requests: bool,
    /// Maximum retry attempts per witness
    pub max_retry_attempts: usize,
}

impl Default for WitnessClientConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(5),
            max_concurrent_requests: 7,
            min_witnesses_for_bft: 3,
            retry_failed_requests: true,
            max_retry_attempts: 2,
        }
    }
}

/// Statistics for witness operations
#[derive(Debug, Clone, Default)]
pub struct WitnessStats {
    /// Total witness requests sent
    pub requests_sent: u64,
    /// Successful responses received
    pub responses_received: u64,
    /// Failed requests (timeout or error)
    pub failed_requests: u64,
    /// BFT consensus achieved
    pub bft_achieved_count: u64,
    /// BFT consensus failed
    pub bft_failed_count: u64,
    /// Average response latency in milliseconds
    pub avg_latency_ms: f64,
}

/// Trait for network transport layer to send/receive witness messages
/// This is implemented by the actual transport layer
pub trait WitnessTransport: Send + Sync {
    /// Send a witness request and receive response
    fn send_witness_request(
        &self,
        peer: &PeerId,
        request: &WitnessRequest,
    ) -> impl std::future::Future<Output = Result<WitnessResponse>> + Send;

    /// Get the local node's peer ID
    fn local_peer_id(&self) -> &PeerId;

    /// Calculate XOR distance between two keys
    fn calculate_distance(&self, key1: &[u8; 32], key2: &[u8; 32]) -> [u8; 32] {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = key1[i] ^ key2[i];
        }
        result
    }
}

/// Mock transport for testing
#[cfg(any(test, feature = "mocks"))]
pub struct MockWitnessTransport {
    local_id: PeerId,
    responses: Arc<RwLock<std::collections::HashMap<PeerId, WitnessResponse>>>,
}

#[cfg(any(test, feature = "mocks"))]
impl MockWitnessTransport {
    pub fn new(local_id: PeerId) -> Self {
        Self {
            local_id,
            responses: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    pub async fn set_response(&self, peer: PeerId, response: WitnessResponse) {
        let mut responses = self.responses.write().await;
        responses.insert(peer, response);
    }
}

#[cfg(any(test, feature = "mocks"))]
impl WitnessTransport for MockWitnessTransport {
    async fn send_witness_request(
        &self,
        peer: &PeerId,
        request: &WitnessRequest,
    ) -> Result<WitnessResponse> {
        let responses = self.responses.read().await;
        if let Some(response) = responses.get(peer) {
            return Ok(response.clone());
        }

        // Default: create accepting response
        let mut attestation = crate::dht::witness_protocol::WitnessAttestation::new(
            request.operation_id.clone(),
            peer.clone(),
            self.calculate_distance(&request.target_key, &[0u8; 32]),
        )?;
        attestation.signature = vec![1, 2, 3, 4]; // Mock signature

        Ok(WitnessResponse::accept(attestation, 10))
    }

    fn local_peer_id(&self) -> &PeerId {
        &self.local_id
    }
}

/// Result of a witness operation
#[derive(Debug, Clone)]
pub struct WitnessOperationResult {
    /// The operation ID
    pub operation_id: WitnessOperationId,
    /// Aggregated proof from witnesses
    pub proof: AggregatedWitnessProof,
    /// Selected witnesses
    pub witnesses: Vec<WitnessCandidate>,
    /// Time taken for the operation
    pub duration: Duration,
    /// Whether BFT was achieved
    pub bft_achieved: bool,
}

/// High-level witness client for S/Kademlia operations
pub struct WitnessClient<T: WitnessTransport + 'static> {
    config: WitnessClientConfig,
    selector: WitnessSelector,
    transport: Arc<T>,
    stats: Arc<RwLock<WitnessStats>>,
}

impl<T: WitnessTransport + 'static> WitnessClient<T> {
    /// Create a new witness client
    pub fn new(transport: Arc<T>, config: WitnessClientConfig) -> Self {
        Self {
            selector: WitnessSelector::new(),
            transport,
            config,
            stats: Arc::new(RwLock::new(WitnessStats::default())),
        }
    }

    /// Create with custom witness selector configuration
    pub fn with_selector(
        transport: Arc<T>,
        config: WitnessClientConfig,
        selector: WitnessSelector,
    ) -> Self {
        Self {
            selector,
            transport,
            config,
            stats: Arc::new(RwLock::new(WitnessStats::default())),
        }
    }

    /// Get current statistics
    pub async fn stats(&self) -> WitnessStats {
        self.stats.read().await.clone()
    }

    /// Request witnesses for a DHT operation
    pub async fn request_witnesses(
        &self,
        target_key: [u8; 32],
        operation_type: OperationType,
        candidates: &[WitnessCandidate],
    ) -> Result<WitnessOperationResult> {
        let start = Instant::now();

        // Select witnesses
        let source = self.transport.local_peer_id();
        let selection = self.selector.select_witnesses(candidates, Some(source), None)?;

        if selection.witnesses.is_empty() {
            return Err(P2PError::InvalidInput(
                "No suitable witnesses available".to_string(),
            ));
        }

        // Create witness request
        let request = WitnessRequest::new(source.clone(), target_key, operation_type)?;

        // Send requests to all witnesses concurrently
        let responses = self
            .send_requests_to_witnesses(&request, &selection)
            .await?;

        // Update stats
        self.update_stats(&responses).await;

        // Aggregate proof
        let proof = AggregatedWitnessProof::from_responses(
            request.operation_id.clone(),
            responses,
            self.config.min_witnesses_for_bft,
        );

        let bft_achieved = proof.bft_achieved;

        // Update BFT stats
        {
            let mut stats = self.stats.write().await;
            if bft_achieved {
                stats.bft_achieved_count += 1;
            } else {
                stats.bft_failed_count += 1;
            }
        }

        Ok(WitnessOperationResult {
            operation_id: request.operation_id,
            proof,
            witnesses: selection.witnesses,
            duration: start.elapsed(),
            bft_achieved,
        })
    }

    /// Send requests to all selected witnesses
    async fn send_requests_to_witnesses(
        &self,
        request: &WitnessRequest,
        selection: &WitnessSelection,
    ) -> Result<Vec<WitnessResponse>> {
        let mut responses = Vec::new();
        let mut handles = Vec::new();

        // Spawn concurrent requests (limited by max_concurrent_requests)
        for witness in selection.witnesses.iter().take(self.config.max_concurrent_requests) {
            let transport = Arc::clone(&self.transport);
            let request = request.clone();
            let peer_id = witness.peer_id.clone();
            let timeout = self.config.request_timeout;
            let retry = self.config.retry_failed_requests;
            let max_retries = self.config.max_retry_attempts;

            let handle = tokio::spawn(async move {
                Self::send_with_retry(&transport, &peer_id, &request, timeout, retry, max_retries)
                    .await
            });

            handles.push((witness.peer_id.clone(), handle));
        }

        // Collect responses
        for (peer_id, handle) in handles {
            match handle.await {
                Ok(Ok(response)) => {
                    responses.push(response);
                }
                Ok(Err(_e)) => {
                    // Create rejection response for failed request
                    if let Ok(reject) = WitnessResponse::reject(
                        request.operation_id.clone(),
                        peer_id.clone(),
                        "Request failed",
                    ) {
                        responses.push(reject);
                    }
                }
                Err(_) => {
                    // Task panicked - create rejection
                    if let Ok(reject) = WitnessResponse::reject(
                        request.operation_id.clone(),
                        peer_id.clone(),
                        "Task failed",
                    ) {
                        responses.push(reject);
                    }
                }
            }
        }

        Ok(responses)
    }

    /// Send request with retry logic
    async fn send_with_retry(
        transport: &Arc<T>,
        peer: &PeerId,
        request: &WitnessRequest,
        timeout: Duration,
        retry: bool,
        max_retries: usize,
    ) -> Result<WitnessResponse> {
        let mut attempts = 0;
        let max_attempts = if retry { max_retries + 1 } else { 1 };

        loop {
            attempts += 1;

            let result = tokio::time::timeout(timeout, transport.send_witness_request(peer, request))
                .await;

            match result {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(_)) if attempts < max_attempts => {
                    // Retry on error
                    tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                    continue;
                }
                Ok(Err(e)) => return Err(e),
                Err(_) if attempts < max_attempts => {
                    // Retry on timeout
                    continue;
                }
                Err(_) => {
                    return Err(P2PError::Timeout(timeout));
                }
            }
        }
    }

    /// Update statistics from responses
    async fn update_stats(&self, responses: &[WitnessResponse]) {
        let mut stats = self.stats.write().await;

        stats.requests_sent += responses.len() as u64;

        let accepted: Vec<_> = responses.iter().filter(|r| r.accepted).collect();
        stats.responses_received += accepted.len() as u64;
        stats.failed_requests += (responses.len() - accepted.len()) as u64;

        // Update average latency
        if !accepted.is_empty() {
            let total_latency: u64 = accepted.iter().map(|r| r.response_latency_ms).sum();
            let new_avg = total_latency as f64 / accepted.len() as f64;

            // Exponential moving average
            if stats.avg_latency_ms == 0.0 {
                stats.avg_latency_ms = new_avg;
            } else {
                stats.avg_latency_ms = stats.avg_latency_ms * 0.9 + new_avg * 0.1;
            }
        }
    }

    /// Verify a DHT operation with witnesses
    /// Returns true if BFT consensus is achieved
    pub async fn verify_operation(
        &self,
        target_key: [u8; 32],
        operation_type: OperationType,
        candidates: &[WitnessCandidate],
    ) -> Result<bool> {
        let result = self
            .request_witnesses(target_key, operation_type, candidates)
            .await?;
        Ok(result.bft_achieved)
    }

    /// Calculate XOR distance for witness verification
    pub fn calculate_xor_distance(key1: &[u8; 32], key2: &[u8; 32]) -> [u8; 32] {
        DhtKey::from_bytes(*key1).distance(&DhtKey::from_bytes(*key2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::geographic_routing::GeographicRegion;

    fn create_test_candidates() -> Vec<WitnessCandidate> {
        vec![
            WitnessCandidate::new(
                "witness1".to_string(),
                [1u8; 32],
                GeographicRegion::Europe,
                0.8,
            )
            .unwrap(),
            WitnessCandidate::new(
                "witness2".to_string(),
                [2u8; 32],
                GeographicRegion::NorthAmerica,
                0.7,
            )
            .unwrap(),
            WitnessCandidate::new(
                "witness3".to_string(),
                [3u8; 32],
                GeographicRegion::AsiaPacific,
                0.9,
            )
            .unwrap(),
            WitnessCandidate::new(
                "witness4".to_string(),
                [4u8; 32],
                GeographicRegion::Africa,
                0.6,
            )
            .unwrap(),
        ]
    }

    // ==================== WitnessClientConfig Tests ====================

    #[test]
    fn test_config_defaults() {
        let config = WitnessClientConfig::default();

        assert_eq!(config.request_timeout, Duration::from_secs(5));
        assert_eq!(config.max_concurrent_requests, 7);
        assert_eq!(config.min_witnesses_for_bft, 3);
        assert!(config.retry_failed_requests);
        assert_eq!(config.max_retry_attempts, 2);
    }

    // ==================== WitnessStats Tests ====================

    #[test]
    fn test_stats_default() {
        let stats = WitnessStats::default();

        assert_eq!(stats.requests_sent, 0);
        assert_eq!(stats.responses_received, 0);
        assert_eq!(stats.failed_requests, 0);
        assert_eq!(stats.bft_achieved_count, 0);
        assert_eq!(stats.bft_failed_count, 0);
        assert_eq!(stats.avg_latency_ms, 0.0);
    }

    // ==================== MockWitnessTransport Tests ====================

    #[tokio::test]
    async fn test_mock_transport_default_response() {
        let transport = MockWitnessTransport::new("local".to_string());

        let request =
            WitnessRequest::new("source".to_string(), [0u8; 32], OperationType::Store).unwrap();

        let response = transport
            .send_witness_request(&"peer1".to_string(), &request)
            .await
            .unwrap();

        assert!(response.accepted);
        assert!(response.attestation.is_signed());
    }

    #[tokio::test]
    async fn test_mock_transport_custom_response() {
        let transport = MockWitnessTransport::new("local".to_string());

        let custom_response =
            WitnessResponse::reject(WitnessOperationId::new(), "peer1".to_string(), "Custom reason")
                .unwrap();

        transport
            .set_response("peer1".to_string(), custom_response)
            .await;

        let request =
            WitnessRequest::new("source".to_string(), [0u8; 32], OperationType::Store).unwrap();

        let response = transport
            .send_witness_request(&"peer1".to_string(), &request)
            .await
            .unwrap();

        assert!(!response.accepted);
    }

    // ==================== WitnessClient Tests ====================

    #[tokio::test]
    async fn test_client_creation() {
        let transport = Arc::new(MockWitnessTransport::new("local".to_string()));
        let config = WitnessClientConfig::default();

        let client = WitnessClient::new(transport, config);

        let stats = client.stats().await;
        assert_eq!(stats.requests_sent, 0);
    }

    #[tokio::test]
    async fn test_client_request_witnesses() {
        let transport = Arc::new(MockWitnessTransport::new("local".to_string()));
        let config = WitnessClientConfig::default();

        let client = WitnessClient::new(transport, config);
        let candidates = create_test_candidates();

        let result = client
            .request_witnesses([0u8; 32], OperationType::Store, &candidates)
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(!result.witnesses.is_empty());
        // With mock transport, all requests should succeed
        assert!(result.bft_achieved);
    }

    #[tokio::test]
    async fn test_client_verify_operation() {
        let transport = Arc::new(MockWitnessTransport::new("local".to_string()));
        let config = WitnessClientConfig::default();

        let client = WitnessClient::new(transport, config);
        let candidates = create_test_candidates();

        let verified = client
            .verify_operation([0u8; 32], OperationType::Store, &candidates)
            .await;

        assert!(verified.is_ok());
        assert!(verified.unwrap());
    }

    #[tokio::test]
    async fn test_client_empty_candidates() {
        let transport = Arc::new(MockWitnessTransport::new("local".to_string()));
        let config = WitnessClientConfig::default();

        let client = WitnessClient::new(transport, config);

        let result = client
            .request_witnesses([0u8; 32], OperationType::Store, &[])
            .await;

        // Should fail with no candidates
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_client_stats_update() {
        let transport = Arc::new(MockWitnessTransport::new("local".to_string()));
        let config = WitnessClientConfig::default();

        let client = WitnessClient::new(transport, config);
        let candidates = create_test_candidates();

        // Make a request
        let _ = client
            .request_witnesses([0u8; 32], OperationType::Store, &candidates)
            .await;

        let stats = client.stats().await;
        assert!(stats.requests_sent > 0);
        assert!(stats.responses_received > 0);
        assert!(stats.bft_achieved_count > 0);
    }

    #[tokio::test]
    async fn test_client_insufficient_witnesses() {
        let transport = Arc::new(MockWitnessTransport::new("local".to_string()));

        // Require 5 witnesses for BFT but only provide 2 candidates
        let config = WitnessClientConfig {
            min_witnesses_for_bft: 5,
            ..Default::default()
        };

        let client = WitnessClient::new(transport, config);

        // Only 2 candidates from different regions
        let candidates = vec![
            WitnessCandidate::new(
                "witness1".to_string(),
                [1u8; 32],
                GeographicRegion::Europe,
                0.8,
            )
            .unwrap(),
            WitnessCandidate::new(
                "witness2".to_string(),
                [2u8; 32],
                GeographicRegion::NorthAmerica,
                0.7,
            )
            .unwrap(),
        ];

        let result = client
            .request_witnesses([0u8; 32], OperationType::Store, &candidates)
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        // BFT should not be achieved with only 2 witnesses when 5 required
        assert!(!result.bft_achieved);
    }

    // ==================== XOR Distance Tests ====================

    #[test]
    fn test_calculate_xor_distance() {
        let key1 = [0xFF; 32];
        let key2 = [0x00; 32];

        let distance = WitnessClient::<MockWitnessTransport>::calculate_xor_distance(&key1, &key2);

        assert_eq!(distance, [0xFF; 32]);
    }

    #[test]
    fn test_calculate_xor_distance_same() {
        let key = [0x42; 32];

        let distance = WitnessClient::<MockWitnessTransport>::calculate_xor_distance(&key, &key);

        assert_eq!(distance, [0x00; 32]);
    }
}
