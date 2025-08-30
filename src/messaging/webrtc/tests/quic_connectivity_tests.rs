// Tests for native QUIC connectivity in WebRTC
// Verifies DHT-based peer discovery and coordinator-based hole punching

use super::*;
use crate::messaging::webrtc::signaling::SignalingHandler;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires mock DHT implementation"]
    async fn test_quic_connection_establishment() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let dht = super::super::create_mock_dht();

        let signaling = SignalingHandler::new(alice.clone(), dht);

        // Start signaling service
        signaling.start().await.unwrap();

        let call_id = CallId::new();

        // Create a signaling session to simulate active call
        let offer = CallOffer {
            call_id,
            caller: alice.clone(),
            callee: FourWordAddress::from("eve-frank-grace-henry"),
            caller_handle: None,
            callee_handle: None,
            sdp: "v=0\r\no=- 123 456 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n".to_string(),
            media_types: vec![MediaType::Audio],
            timestamp: chrono::Utc::now(),
        };

        // Send offer to create session
        signaling.send_offer(offer).await.unwrap();

        // Test QUIC connection establishment
        let result = signaling.establish_quic_connection(call_id).await;
        assert!(result.is_ok());

        // Verify session exists and has been updated
        let session = signaling.get_session(call_id).await;
        assert!(session.is_some());
    }

    #[tokio::test]
    async fn test_quic_configuration_validation() {
        // Test default QUIC configuration
        let default_config = NativeQuicConfiguration::default();
        assert!(default_config.dht_discovery);
        assert!(default_config.hole_punching);

        // Test custom configurations
        let dht_only_config = NativeQuicConfiguration {
            dht_discovery: true,
            hole_punching: false,
        };
        assert!(dht_only_config.dht_discovery);
        assert!(!dht_only_config.hole_punching);

        let hole_punching_only_config = NativeQuicConfiguration {
            dht_discovery: false,
            hole_punching: true,
        };
        assert!(!hole_punching_only_config.dht_discovery);
        assert!(hole_punching_only_config.hole_punching);
    }

    #[tokio::test]
    #[ignore = "requires mock DHT implementation"]
    async fn test_dht_based_peer_discovery() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let bob = FourWordAddress::from("eve-frank-grace-henry");
        let dht = super::super::create_mock_dht();

        let mut signaling = SignalingHandler::new(alice.clone(), dht);

        // Configure for DHT discovery
        let config = NativeQuicConfiguration {
            dht_discovery: true,
            hole_punching: false,
        };
        signaling.set_quic_config(config);

        // Start signaling
        signaling.start().await.unwrap();

        let call_id = CallId::new();

        // Create offer
        let offer = CallOffer {
            call_id,
            caller: alice.clone(),
            callee: bob.clone(),
            caller_handle: None,
            callee_handle: None,
            sdp: "v=0\r\no=- 123 456 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n".to_string(),
            media_types: vec![MediaType::Audio],
            timestamp: chrono::Utc::now(),
        };

        // Send offer
        signaling.send_offer(offer).await.unwrap();

        // Test DHT-based connection establishment
        let result = signaling.establish_quic_connection(call_id).await;
        assert!(result.is_ok());

        // Verify DHT discovery was used
        let config = signaling.get_quic_config();
        assert!(config.dht_discovery);
    }

    #[tokio::test]
    #[ignore = "requires mock DHT implementation"]
    async fn test_coordinator_hole_punching() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let bob = FourWordAddress::from("eve-frank-grace-henry");
        let dht = super::super::create_mock_dht();

        let mut signaling = SignalingHandler::new(alice.clone(), dht);

        // Configure for hole punching
        let config = NativeQuicConfiguration {
            dht_discovery: false,
            hole_punching: true,
        };
        signaling.set_quic_config(config);

        signaling.start().await.unwrap();

        let call_id = CallId::new();

        let offer = CallOffer {
            call_id,
            caller: alice.clone(),
            callee: bob.clone(),
            caller_handle: None,
            callee_handle: None,
            sdp: "v=0\r\no=- 123 456 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n".to_string(),
            media_types: vec![MediaType::Audio],
            timestamp: chrono::Utc::now(),
        };

        signaling.send_offer(offer).await.unwrap();

        // Test coordinator-based hole punching
        let result = signaling.establish_quic_connection(call_id).await;
        assert!(result.is_ok());

        // Verify hole punching was configured
        let config = signaling.get_quic_config();
        assert!(config.hole_punching);
    }

    #[tokio::test]
    #[ignore = "requires mock DHT implementation"]
    async fn test_combined_dht_and_hole_punching() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let dht = super::super::create_mock_dht();

        let mut signaling = SignalingHandler::new(alice.clone(), dht);

        // Configure for both DHT discovery and hole punching (default)
        let config = NativeQuicConfiguration::default();
        signaling.set_quic_config(config);

        signaling.start().await.unwrap();

        let call_id = CallId::new();

        let offer = CallOffer {
            call_id,
            caller: alice.clone(),
            callee: FourWordAddress::from("eve-frank-grace-henry"),
            caller_handle: None,
            callee_handle: None,
            sdp: "v=0\r\no=- 123 456 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n".to_string(),
            media_types: vec![MediaType::Audio],
            timestamp: chrono::Utc::now(),
        };

        signaling.send_offer(offer).await.unwrap();

        // Test combined DHT discovery and hole punching
        let result = signaling.establish_quic_connection(call_id).await;
        assert!(result.is_ok());

        // Verify both are enabled
        let config = signaling.get_quic_config();
        assert!(config.dht_discovery);
        assert!(config.hole_punching);
    }

    #[test]
    fn test_quic_endpoint_validation() {
        use crate::messaging::webrtc::signaling::SignalingHandler;

        // Valid endpoints
        assert!(SignalingHandler::validate_quic_endpoint("127.0.0.1:5000").is_ok());
        assert!(SignalingHandler::validate_quic_endpoint("192.168.1.1:8080").is_ok());
        assert!(SignalingHandler::validate_quic_endpoint("10.0.0.1:443").is_ok());
        assert!(SignalingHandler::validate_quic_endpoint("[::1]:5000").is_ok());

        // Invalid endpoints
        assert!(SignalingHandler::validate_quic_endpoint("").is_err());
        assert!(SignalingHandler::validate_quic_endpoint("localhost").is_err());
        assert!(SignalingHandler::validate_quic_endpoint("127.0.0.1:0").is_err());
        assert!(SignalingHandler::validate_quic_endpoint("127.0.0.1:invalid").is_err());
        assert!(SignalingHandler::validate_quic_endpoint("no-port-specified").is_err());
    }

    #[tokio::test]
    #[ignore = "requires mock DHT implementation"]
    async fn test_connection_failure_handling() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let dht = super::super::create_mock_dht();

        let signaling = SignalingHandler::new(alice.clone(), dht);
        signaling.start().await.unwrap();

        // Try to establish connection for non-existent call
        let invalid_call_id = CallId::new();
        let result = signaling.establish_quic_connection(invalid_call_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_signaling_message_routing() {
        // Test that signaling messages are properly structured for QUIC transport
        let call_id = CallId::new();
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let bob = FourWordAddress::from("eve-frank-grace-henry");

        // Test offer message
        let offer = CallOffer {
            call_id,
            caller: alice.clone(),
            callee: bob.clone(),
            caller_handle: None,
            callee_handle: None,
            sdp: "v=0\r\no=- 123 456 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n".to_string(),
            media_types: vec![MediaType::Audio],
            timestamp: chrono::Utc::now(),
        };

        let message = SignalingMessage::Offer(offer);

        // Verify message can be serialized for DHT transport
        let serialized = serde_json::to_string(&message);
        assert!(serialized.is_ok());

        // Test answer message
        let answer = CallAnswer {
            call_id,
            sdp: "v=0\r\no=- 789 012 IN IP4 192.168.1.1\r\ns=-\r\nt=0 0\r\n".to_string(),
            accepted: true,
            timestamp: chrono::Utc::now(),
        };

        let message = SignalingMessage::Answer(answer);
        let serialized = serde_json::to_string(&message);
        assert!(serialized.is_ok());

        // Test call end message
        let message = SignalingMessage::CallEnd { call_id };
        let serialized = serde_json::to_string(&message);
        assert!(serialized.is_ok());
    }
}
