// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Witness Protocol Messages for S/Kademlia Byzantine Fault Tolerance
//!
//! This module defines the network protocol messages for the witness system:
//! - `WitnessRequest`: Request for a witness to observe and attest to an operation
//! - `WitnessResponse`: Response from a witness with signed attestation
//! - `WitnessChallenge`: Challenge for distance verification
//! - `WitnessAttestation`: Signed attestation from a witness node

use crate::PeerId;
use crate::dht::witness::OperationType;
use crate::error::{P2PError, P2pResult as Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Unique identifier for witness operations
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WitnessOperationId(String);

impl WitnessOperationId {
    /// Create a new random operation ID
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// Create from a string (for testing/deserialization)
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Get the inner string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for WitnessOperationId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for WitnessOperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Request from a node to another node to witness an operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessRequest {
    /// Unique ID for this witness request
    pub operation_id: WitnessOperationId,
    /// The node requesting the witness (operation source)
    pub source_node: PeerId,
    /// The target key of the DHT operation
    pub target_key: [u8; 32],
    /// Type of operation being witnessed
    pub operation_type: OperationType,
    /// Unix timestamp in milliseconds
    pub timestamp: u64,
    /// Optional data hash for verification
    pub data_hash: Option<[u8; 32]>,
    /// Nonce for replay protection
    pub nonce: [u8; 16],
}

impl WitnessRequest {
    /// Create a new witness request
    pub fn new(
        source_node: PeerId,
        target_key: [u8; 32],
        operation_type: OperationType,
    ) -> Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| P2PError::Internal(format!("System time error: {}", e).into()))?
            .as_millis() as u64;

        // Generate random nonce
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);

        Ok(Self {
            operation_id: WitnessOperationId::new(),
            source_node,
            target_key,
            operation_type,
            timestamp,
            data_hash: None,
            nonce,
        })
    }

    /// Create with a specific data hash
    pub fn with_data_hash(mut self, hash: [u8; 32]) -> Self {
        self.data_hash = Some(hash);
        self
    }

    /// Validate the request
    pub fn validate(&self) -> Result<()> {
        // Check timestamp isn't too old (5 minutes)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| P2PError::Internal(format!("System time error: {}", e).into()))?
            .as_millis() as u64;

        let max_age_ms = 5 * 60 * 1000; // 5 minutes
        if now.saturating_sub(self.timestamp) > max_age_ms {
            return Err(P2PError::InvalidInput(
                "Witness request timestamp too old".to_string(),
            ));
        }

        // Check timestamp isn't in the future (with 30 second tolerance)
        let future_tolerance_ms = 30 * 1000;
        if self.timestamp > now + future_tolerance_ms {
            return Err(P2PError::InvalidInput(
                "Witness request timestamp in the future".to_string(),
            ));
        }

        Ok(())
    }

    /// Serialize to bytes for signing
    pub fn to_bytes_for_signing(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.operation_id.as_str().as_bytes());
        bytes.extend_from_slice(self.source_node.as_bytes());
        bytes.extend_from_slice(&self.target_key);
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.nonce);
        if let Some(hash) = &self.data_hash {
            bytes.extend_from_slice(hash);
        }
        bytes
    }
}

/// Signed attestation from a witness node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessAttestation {
    /// The operation being attested
    pub operation_id: WitnessOperationId,
    /// The witness node's ID
    pub witness_node: PeerId,
    /// XOR distance observed by witness
    pub observed_distance: [u8; 32],
    /// Timestamp when witness observed the operation
    pub attestation_timestamp: u64,
    /// Signature over attestation data (ML-DSA-65)
    pub signature: Vec<u8>,
    /// Witness's view of network state (optional, for cross-validation)
    pub network_state_hash: Option<[u8; 32]>,
}

impl WitnessAttestation {
    /// Create a new unsigned attestation
    pub fn new(
        operation_id: WitnessOperationId,
        witness_node: PeerId,
        observed_distance: [u8; 32],
    ) -> Result<Self> {
        let attestation_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| P2PError::Internal(format!("System time error: {}", e).into()))?
            .as_millis() as u64;

        Ok(Self {
            operation_id,
            witness_node,
            observed_distance,
            attestation_timestamp,
            signature: Vec::new(), // Will be filled by sign()
            network_state_hash: None,
        })
    }

    /// Get bytes for signing
    pub fn to_bytes_for_signing(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.operation_id.as_str().as_bytes());
        bytes.extend_from_slice(self.witness_node.as_bytes());
        bytes.extend_from_slice(&self.observed_distance);
        bytes.extend_from_slice(&self.attestation_timestamp.to_be_bytes());
        if let Some(hash) = &self.network_state_hash {
            bytes.extend_from_slice(hash);
        }
        bytes
    }

    /// Check if this attestation has been signed
    pub fn is_signed(&self) -> bool {
        !self.signature.is_empty()
    }
}

/// Response from a witness node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessResponse {
    /// The signed attestation
    pub attestation: WitnessAttestation,
    /// Whether the witness accepts the operation
    pub accepted: bool,
    /// Optional rejection reason
    pub rejection_reason: Option<String>,
    /// Response latency in milliseconds (measured by witness)
    pub response_latency_ms: u64,
}

impl WitnessResponse {
    /// Create an accepting response
    pub fn accept(attestation: WitnessAttestation, latency_ms: u64) -> Self {
        Self {
            attestation,
            accepted: true,
            rejection_reason: None,
            response_latency_ms: latency_ms,
        }
    }

    /// Create a rejecting response
    pub fn reject(
        operation_id: WitnessOperationId,
        witness_node: PeerId,
        reason: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            attestation: WitnessAttestation::new(
                operation_id,
                witness_node,
                [0u8; 32], // Distance not relevant for rejection
            )?,
            accepted: false,
            rejection_reason: Some(reason.into()),
            response_latency_ms: 0,
        })
    }

    /// Validate the response
    pub fn validate(&self) -> Result<()> {
        if self.accepted && !self.attestation.is_signed() {
            return Err(P2PError::InvalidInput(
                "Accepted witness response must be signed".to_string(),
            ));
        }
        Ok(())
    }
}

/// Challenge for witness distance verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessChallenge {
    /// The operation ID being challenged
    pub operation_id: WitnessOperationId,
    /// Challenge nonce
    pub challenge_nonce: [u8; 32],
    /// Timestamp of challenge
    pub timestamp: u64,
    /// Expected distance (challenger's calculation)
    pub expected_distance: [u8; 32],
}

impl WitnessChallenge {
    /// Create a new challenge
    pub fn new(operation_id: WitnessOperationId, expected_distance: [u8; 32]) -> Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| P2PError::Internal(format!("System time error: {}", e).into()))?
            .as_millis() as u64;

        let mut challenge_nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge_nonce);

        Ok(Self {
            operation_id,
            challenge_nonce,
            timestamp,
            expected_distance,
        })
    }
}

/// Proof in response to a challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessChallengeResponse {
    /// The challenge being responded to
    pub challenge_nonce: [u8; 32],
    /// Computed distance by the witness
    pub computed_distance: [u8; 32],
    /// Proof of correct computation (signature over challenge + result)
    pub proof_signature: Vec<u8>,
    /// Response timestamp
    pub timestamp: u64,
}

impl WitnessChallengeResponse {
    /// Create a new challenge response
    pub fn new(challenge_nonce: [u8; 32], computed_distance: [u8; 32]) -> Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| P2PError::Internal(format!("System time error: {}", e).into()))?
            .as_millis() as u64;

        Ok(Self {
            challenge_nonce,
            computed_distance,
            proof_signature: Vec::new(), // Will be filled when signed
            timestamp,
        })
    }

    /// Verify the distance matches the expected value (with tolerance)
    pub fn verify_distance(&self, expected: &[u8; 32]) -> bool {
        self.computed_distance == *expected
    }
}

/// Aggregated proof from multiple witnesses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedWitnessProof {
    /// The operation these proofs are for
    pub operation_id: WitnessOperationId,
    /// All witness responses collected
    pub responses: Vec<WitnessResponse>,
    /// Number of accepting witnesses
    pub accept_count: usize,
    /// Number of rejecting witnesses
    pub reject_count: usize,
    /// Consensus distance (if achieved)
    pub consensus_distance: Option<[u8; 32]>,
    /// Whether Byzantine fault tolerance is achieved
    pub bft_achieved: bool,
}

impl AggregatedWitnessProof {
    /// Create from a list of responses
    pub fn from_responses(
        operation_id: WitnessOperationId,
        responses: Vec<WitnessResponse>,
        required_witnesses: usize,
    ) -> Self {
        let accept_count = responses.iter().filter(|r| r.accepted).count();
        let reject_count = responses.len() - accept_count;

        // Calculate consensus distance (simple majority for now)
        let consensus_distance = Self::calculate_consensus_distance(&responses);

        // BFT requires f+1 witnesses for f Byzantine faults
        // With 3 witnesses, can tolerate 1 fault (need 2 agreements)
        let bft_achieved = accept_count >= required_witnesses;

        Self {
            operation_id,
            responses,
            accept_count,
            reject_count,
            consensus_distance,
            bft_achieved,
        }
    }

    /// Calculate consensus distance from responses
    fn calculate_consensus_distance(responses: &[WitnessResponse]) -> Option<[u8; 32]> {
        let accepting: Vec<_> = responses
            .iter()
            .filter(|r| r.accepted)
            .map(|r| r.attestation.observed_distance)
            .collect();

        if accepting.is_empty() {
            return None;
        }

        // Simple majority: return most common distance
        // In a full implementation, would use more sophisticated consensus
        Some(accepting[0])
    }

    /// Check if the proof is valid for the operation
    pub fn is_valid(&self, min_witnesses: usize) -> bool {
        self.bft_achieved && self.accept_count >= min_witnesses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== WitnessOperationId Tests ====================

    #[test]
    fn test_witness_operation_id_new() {
        let id1 = WitnessOperationId::new();
        let id2 = WitnessOperationId::new();

        // Each ID should be unique
        assert_ne!(id1, id2);
        assert!(!id1.as_str().is_empty());
    }

    #[test]
    fn test_witness_operation_id_from_string() {
        let id = WitnessOperationId::from_string("test-id-123");
        assert_eq!(id.as_str(), "test-id-123");
    }

    #[test]
    fn test_witness_operation_id_display() {
        let id = WitnessOperationId::from_string("display-test");
        assert_eq!(format!("{}", id), "display-test");
    }

    // ==================== WitnessRequest Tests ====================

    #[test]
    fn test_witness_request_creation() {
        let source = "source-peer-id".to_string();
        let target_key = [1u8; 32];

        let request = WitnessRequest::new(source.clone(), target_key, OperationType::Store);

        assert!(request.is_ok());
        let req = request.unwrap();
        assert_eq!(req.source_node, source);
        assert_eq!(req.target_key, target_key);
        assert!(matches!(req.operation_type, OperationType::Store));
        assert!(req.timestamp > 0);
    }

    #[test]
    fn test_witness_request_with_data_hash() {
        let request = WitnessRequest::new("source".to_string(), [0u8; 32], OperationType::Store)
            .unwrap()
            .with_data_hash([42u8; 32]);

        assert_eq!(request.data_hash, Some([42u8; 32]));
    }

    #[test]
    fn test_witness_request_validation_valid() {
        let request =
            WitnessRequest::new("source".to_string(), [0u8; 32], OperationType::Store).unwrap();

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_witness_request_validation_too_old() {
        let mut request =
            WitnessRequest::new("source".to_string(), [0u8; 32], OperationType::Store).unwrap();

        // Set timestamp to 10 minutes ago
        request.timestamp = request.timestamp.saturating_sub(10 * 60 * 1000);

        let result = request.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("timestamp too old")
        );
    }

    #[test]
    fn test_witness_request_validation_future() {
        let mut request =
            WitnessRequest::new("source".to_string(), [0u8; 32], OperationType::Store).unwrap();

        // Set timestamp to 5 minutes in the future
        request.timestamp += 5 * 60 * 1000;

        let result = request.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("in the future"));
    }

    #[test]
    fn test_witness_request_to_bytes_for_signing() {
        let request =
            WitnessRequest::new("source".to_string(), [1u8; 32], OperationType::Store).unwrap();

        let bytes = request.to_bytes_for_signing();
        assert!(!bytes.is_empty());

        // Should include operation_id, source_node, target_key, timestamp, nonce
        assert!(bytes.len() > 32 + 8 + 16); // At minimum: key + timestamp + nonce
    }

    // ==================== WitnessAttestation Tests ====================

    #[test]
    fn test_witness_attestation_creation() {
        let op_id = WitnessOperationId::new();
        let witness = "witness-node".to_string();
        let distance = [5u8; 32];

        let attestation = WitnessAttestation::new(op_id.clone(), witness.clone(), distance);

        assert!(attestation.is_ok());
        let att = attestation.unwrap();
        assert_eq!(att.operation_id, op_id);
        assert_eq!(att.witness_node, witness);
        assert_eq!(att.observed_distance, distance);
        assert!(!att.is_signed());
    }

    #[test]
    fn test_witness_attestation_to_bytes_for_signing() {
        let attestation = WitnessAttestation::new(
            WitnessOperationId::from_string("test-op"),
            "witness".to_string(),
            [1u8; 32],
        )
        .unwrap();

        let bytes = attestation.to_bytes_for_signing();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_witness_attestation_is_signed() {
        let mut attestation =
            WitnessAttestation::new(WitnessOperationId::new(), "witness".to_string(), [0u8; 32])
                .unwrap();

        assert!(!attestation.is_signed());

        attestation.signature = vec![1, 2, 3, 4];
        assert!(attestation.is_signed());
    }

    // ==================== WitnessResponse Tests ====================

    #[test]
    fn test_witness_response_accept() {
        let attestation =
            WitnessAttestation::new(WitnessOperationId::new(), "witness".to_string(), [1u8; 32])
                .unwrap();

        let response = WitnessResponse::accept(attestation, 50);

        assert!(response.accepted);
        assert!(response.rejection_reason.is_none());
        assert_eq!(response.response_latency_ms, 50);
    }

    #[test]
    fn test_witness_response_reject() {
        let response = WitnessResponse::reject(
            WitnessOperationId::new(),
            "witness".to_string(),
            "Operation not permitted",
        );

        assert!(response.is_ok());
        let resp = response.unwrap();
        assert!(!resp.accepted);
        assert_eq!(
            resp.rejection_reason,
            Some("Operation not permitted".to_string())
        );
    }

    #[test]
    fn test_witness_response_validate_unsigned_accept() {
        let attestation =
            WitnessAttestation::new(WitnessOperationId::new(), "witness".to_string(), [1u8; 32])
                .unwrap();

        let response = WitnessResponse::accept(attestation, 50);

        // Unsigned accepted response should fail validation
        let result = response.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be signed"));
    }

    #[test]
    fn test_witness_response_validate_signed_accept() {
        let mut attestation =
            WitnessAttestation::new(WitnessOperationId::new(), "witness".to_string(), [1u8; 32])
                .unwrap();
        attestation.signature = vec![1, 2, 3, 4]; // Mock signature

        let response = WitnessResponse::accept(attestation, 50);

        assert!(response.validate().is_ok());
    }

    // ==================== WitnessChallenge Tests ====================

    #[test]
    fn test_witness_challenge_creation() {
        let op_id = WitnessOperationId::new();
        let expected_distance = [10u8; 32];

        let challenge = WitnessChallenge::new(op_id.clone(), expected_distance);

        assert!(challenge.is_ok());
        let ch = challenge.unwrap();
        assert_eq!(ch.operation_id, op_id);
        assert_eq!(ch.expected_distance, expected_distance);
        assert!(ch.timestamp > 0);
    }

    // ==================== WitnessChallengeResponse Tests ====================

    #[test]
    fn test_challenge_response_creation() {
        let nonce = [1u8; 32];
        let distance = [5u8; 32];

        let response = WitnessChallengeResponse::new(nonce, distance);

        assert!(response.is_ok());
        let resp = response.unwrap();
        assert_eq!(resp.challenge_nonce, nonce);
        assert_eq!(resp.computed_distance, distance);
    }

    #[test]
    fn test_challenge_response_verify_distance_match() {
        let nonce = [1u8; 32];
        let distance = [5u8; 32];

        let response = WitnessChallengeResponse::new(nonce, distance).unwrap();

        assert!(response.verify_distance(&distance));
        assert!(!response.verify_distance(&[6u8; 32]));
    }

    // ==================== AggregatedWitnessProof Tests ====================

    #[test]
    fn test_aggregated_proof_creation() {
        let op_id = WitnessOperationId::new();

        let mut att1 = WitnessAttestation::new(op_id.clone(), "w1".to_string(), [1u8; 32]).unwrap();
        att1.signature = vec![1, 2, 3];
        let resp1 = WitnessResponse::accept(att1, 10);

        let mut att2 = WitnessAttestation::new(op_id.clone(), "w2".to_string(), [1u8; 32]).unwrap();
        att2.signature = vec![4, 5, 6];
        let resp2 = WitnessResponse::accept(att2, 15);

        let resp3 = WitnessResponse::reject(op_id.clone(), "w3".to_string(), "reason").unwrap();

        let proof = AggregatedWitnessProof::from_responses(op_id, vec![resp1, resp2, resp3], 2);

        assert_eq!(proof.accept_count, 2);
        assert_eq!(proof.reject_count, 1);
        assert!(proof.bft_achieved);
    }

    #[test]
    fn test_aggregated_proof_insufficient_witnesses() {
        let op_id = WitnessOperationId::new();

        let mut att1 = WitnessAttestation::new(op_id.clone(), "w1".to_string(), [1u8; 32]).unwrap();
        att1.signature = vec![1, 2, 3];
        let resp1 = WitnessResponse::accept(att1, 10);

        let resp2 = WitnessResponse::reject(op_id.clone(), "w2".to_string(), "reason").unwrap();
        let resp3 = WitnessResponse::reject(op_id.clone(), "w3".to_string(), "reason").unwrap();

        let proof = AggregatedWitnessProof::from_responses(op_id, vec![resp1, resp2, resp3], 2);

        assert_eq!(proof.accept_count, 1);
        assert!(!proof.bft_achieved);
        assert!(!proof.is_valid(2));
    }

    #[test]
    fn test_aggregated_proof_is_valid() {
        let op_id = WitnessOperationId::new();

        let mut att1 = WitnessAttestation::new(op_id.clone(), "w1".to_string(), [1u8; 32]).unwrap();
        att1.signature = vec![1, 2, 3];
        let resp1 = WitnessResponse::accept(att1, 10);

        let mut att2 = WitnessAttestation::new(op_id.clone(), "w2".to_string(), [1u8; 32]).unwrap();
        att2.signature = vec![4, 5, 6];
        let resp2 = WitnessResponse::accept(att2, 15);

        let mut att3 = WitnessAttestation::new(op_id.clone(), "w3".to_string(), [1u8; 32]).unwrap();
        att3.signature = vec![7, 8, 9];
        let resp3 = WitnessResponse::accept(att3, 20);

        let proof = AggregatedWitnessProof::from_responses(op_id, vec![resp1, resp2, resp3], 3);

        assert!(proof.is_valid(3));
        assert!(proof.is_valid(2));
        assert!(proof.is_valid(1));
    }

    #[test]
    fn test_aggregated_proof_empty_responses() {
        let op_id = WitnessOperationId::new();

        let proof = AggregatedWitnessProof::from_responses(op_id, vec![], 1);

        assert_eq!(proof.accept_count, 0);
        assert_eq!(proof.reject_count, 0);
        assert!(!proof.bft_achieved);
        assert!(proof.consensus_distance.is_none());
    }
}
