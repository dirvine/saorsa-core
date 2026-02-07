// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Integration tests for the request/response API and trust feedback.
//!
//! Tests cover:
//! - `PeerFailureReason` enum semantics
//! - `PeerStoreOutcome` construction and enriched `DhtNetworkResult` variants
//! - `RequestResponseEnvelope` serialization round-trip
//! - `P2PNode::parse_request_envelope` helper

use saorsa_core::error::PeerFailureReason;
use saorsa_core::{DhtNetworkResult, PeerStoreOutcome};

/// Mirror of the private `RequestResponseEnvelope` for constructing test bytes.
#[derive(serde::Serialize, serde::Deserialize)]
struct TestEnvelope {
    message_id: String,
    is_response: bool,
    payload: Vec<u8>,
}

// ---- PeerFailureReason tests ----

#[test]
fn test_failure_reason_transient_classification() {
    assert!(PeerFailureReason::Timeout.is_transient());
    assert!(PeerFailureReason::ConnectionFailed.is_transient());
    assert!(!PeerFailureReason::DataUnavailable.is_transient());
    assert!(!PeerFailureReason::CorruptedData.is_transient());
    assert!(!PeerFailureReason::ProtocolError.is_transient());
    assert!(!PeerFailureReason::Refused.is_transient());
}

#[test]
fn test_failure_reason_severity_ranges() {
    let all_reasons = [
        PeerFailureReason::Timeout,
        PeerFailureReason::ConnectionFailed,
        PeerFailureReason::DataUnavailable,
        PeerFailureReason::CorruptedData,
        PeerFailureReason::ProtocolError,
        PeerFailureReason::Refused,
    ];

    for reason in &all_reasons {
        let severity = reason.trust_severity();
        assert!(
            (0.0..=1.0).contains(&severity),
            "{:?} severity {} out of range",
            reason,
            severity
        );
    }

    // Transient failures have lower severity than data integrity failures
    assert!(
        PeerFailureReason::Timeout.trust_severity()
            < PeerFailureReason::CorruptedData.trust_severity()
    );
    assert!(
        PeerFailureReason::ConnectionFailed.trust_severity()
            < PeerFailureReason::ProtocolError.trust_severity()
    );
}

#[test]
fn test_failure_reason_display() {
    assert_eq!(PeerFailureReason::Timeout.to_string(), "timeout");
    assert_eq!(
        PeerFailureReason::ConnectionFailed.to_string(),
        "connection_failed"
    );
    assert_eq!(
        PeerFailureReason::DataUnavailable.to_string(),
        "data_unavailable"
    );
    assert_eq!(
        PeerFailureReason::CorruptedData.to_string(),
        "corrupted_data"
    );
    assert_eq!(
        PeerFailureReason::ProtocolError.to_string(),
        "protocol_error"
    );
    assert_eq!(PeerFailureReason::Refused.to_string(), "refused");
}

#[test]
fn test_failure_reason_serde_roundtrip() {
    for reason in &[
        PeerFailureReason::Timeout,
        PeerFailureReason::ConnectionFailed,
        PeerFailureReason::DataUnavailable,
        PeerFailureReason::CorruptedData,
        PeerFailureReason::ProtocolError,
        PeerFailureReason::Refused,
    ] {
        let json = serde_json::to_string(reason).unwrap();
        let roundtripped: PeerFailureReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, roundtripped);
    }
}

// ---- PeerStoreOutcome tests ----

#[test]
fn test_peer_store_outcome_success() {
    let outcome = PeerStoreOutcome {
        peer_id: "peer_abc123".to_string(),
        success: true,
        error: None,
    };
    assert!(outcome.success);
    assert!(outcome.error.is_none());
}

#[test]
fn test_peer_store_outcome_failure() {
    let outcome = PeerStoreOutcome {
        peer_id: "peer_def456".to_string(),
        success: false,
        error: Some("Connection refused".to_string()),
    };
    assert!(!outcome.success);
    assert_eq!(outcome.error.as_deref(), Some("Connection refused"));
}

#[test]
fn test_peer_store_outcome_serde_roundtrip() {
    let outcome = PeerStoreOutcome {
        peer_id: "peer_test".to_string(),
        success: false,
        error: Some("timeout".to_string()),
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let roundtripped: PeerStoreOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtripped.peer_id, "peer_test");
    assert!(!roundtripped.success);
    assert_eq!(roundtripped.error.as_deref(), Some("timeout"));
}

#[test]
fn test_peer_store_outcome_serde_default_fields() {
    // Simulate old wire format without optional fields
    let json = r#"{"peer_id":"peer_old","success":true}"#;
    let outcome: PeerStoreOutcome = serde_json::from_str(json).unwrap();
    assert_eq!(outcome.peer_id, "peer_old");
    assert!(outcome.success);
    assert!(outcome.error.is_none());
    assert!(outcome.error.is_none());
}

// ---- Enriched DhtNetworkResult tests ----

#[test]
fn test_put_success_with_peer_outcomes() {
    let key = [42u8; 32];
    let outcomes = vec![
        PeerStoreOutcome {
            peer_id: "peer_a".to_string(),
            success: true,
            error: None,
        },
        PeerStoreOutcome {
            peer_id: "peer_b".to_string(),
            success: false,
            error: Some("timeout".to_string()),
        },
    ];

    let result = DhtNetworkResult::PutSuccess {
        key,
        replicated_to: 2,
        peer_outcomes: outcomes.clone(),
    };

    match result {
        DhtNetworkResult::PutSuccess {
            replicated_to,
            peer_outcomes,
            ..
        } => {
            assert_eq!(replicated_to, 2);
            assert_eq!(peer_outcomes.len(), 2);
            assert!(peer_outcomes[0].success);
            assert!(!peer_outcomes[1].success);
        }
        _ => panic!("Expected PutSuccess"),
    }
}

#[test]
fn test_put_success_backward_compat_serde() {
    // Old wire format without peer_outcomes
    let json = r#"{"PutSuccess":{"key":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"replicated_to":1}}"#;
    let result: DhtNetworkResult = serde_json::from_str(json).unwrap();
    match result {
        DhtNetworkResult::PutSuccess {
            peer_outcomes,
            replicated_to,
            ..
        } => {
            assert_eq!(replicated_to, 1);
            assert!(peer_outcomes.is_empty());
        }
        _ => panic!("Expected PutSuccess"),
    }
}

#[test]
fn test_get_not_found_with_diagnostics() {
    let key = [7u8; 32];
    let result = DhtNetworkResult::GetNotFound {
        key,
        peers_queried: 5,
        peers_failed: 2,
        last_error: Some("connection timeout".to_string()),
    };

    match result {
        DhtNetworkResult::GetNotFound {
            peers_queried,
            peers_failed,
            last_error,
            ..
        } => {
            assert_eq!(peers_queried, 5);
            assert_eq!(peers_failed, 2);
            assert_eq!(last_error.as_deref(), Some("connection timeout"));
        }
        _ => panic!("Expected GetNotFound"),
    }
}

#[test]
fn test_get_not_found_backward_compat_serde() {
    // Old wire format without diagnostic fields
    let json = r#"{"GetNotFound":{"key":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}"#;
    let result: DhtNetworkResult = serde_json::from_str(json).unwrap();
    match result {
        DhtNetworkResult::GetNotFound {
            peers_queried,
            peers_failed,
            last_error,
            ..
        } => {
            assert_eq!(peers_queried, 0);
            assert_eq!(peers_failed, 0);
            assert!(last_error.is_none());
        }
        _ => panic!("Expected GetNotFound"),
    }
}

// ---- RequestResponseEnvelope tests ----

#[test]
fn test_request_envelope_roundtrip() {
    use saorsa_core::P2PNode;

    let data = b"hello world".to_vec();

    let envelope = TestEnvelope {
        message_id: "test-msg-id-123".to_string(),
        is_response: false,
        payload: data.clone(),
    };
    let bytes = postcard::to_allocvec(&envelope).unwrap();

    let parsed = P2PNode::parse_request_envelope(&bytes);
    assert!(parsed.is_some());
    let (msg_id, is_response, payload) = parsed.unwrap();
    assert_eq!(msg_id, "test-msg-id-123");
    assert!(!is_response);
    assert_eq!(payload, data);
}

#[test]
fn test_response_envelope_roundtrip() {
    use saorsa_core::P2PNode;

    let response_data = b"response payload".to_vec();
    let envelope = TestEnvelope {
        message_id: "resp-456".to_string(),
        is_response: true,
        payload: response_data.clone(),
    };
    let bytes = postcard::to_allocvec(&envelope).unwrap();

    let parsed = P2PNode::parse_request_envelope(&bytes);
    assert!(parsed.is_some());
    let (msg_id, is_response, payload) = parsed.unwrap();
    assert_eq!(msg_id, "resp-456");
    assert!(is_response);
    assert_eq!(payload, response_data);
}

#[test]
fn test_parse_invalid_envelope() {
    use saorsa_core::P2PNode;

    // Random bytes should fail to parse
    let garbage = vec![0xFF, 0xFE, 0xFD];
    assert!(P2PNode::parse_request_envelope(&garbage).is_none());
}
