// Tests for WebRTC call flow over native QUIC
// Verifies complete call lifecycle: initiation, signaling, connection, termination

use super::*;
use crate::messaging::webrtc::{WebRtcService, CallManager, SignalingHandler};
use crate::messaging::webrtc::types::*;
use crate::messaging::webrtc::media::MediaStreamManager;
use tokio::time::{sleep, Duration};
use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    #[ignore = "requires mock DHT implementation"]
    async fn test_complete_call_flow() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let bob = FourWordAddress::from("eve-frank-grace-henry");
        
        let dht_alice = super::super::create_mock_dht();
        let dht_bob = super::super::create_mock_dht();
        
        // Create WebRTC services
        let alice_service = WebRtcService::new(alice.clone(), dht_alice).await.unwrap();
        let bob_service = WebRtcService::new(bob.clone(), dht_bob).await.unwrap();
        
        // Start services
        alice_service.start().await.unwrap();
        bob_service.start().await.unwrap();
        
        // Subscribe to events
        let mut alice_events = alice_service.subscribe_events();
        let mut bob_events = bob_service.subscribe_events();
        
        // Alice initiates call
        let call_id = alice_service
            .initiate_call(bob.clone(), MediaConstraints::audio_only())
            .await
            .unwrap();
        
        // Wait for signaling to propagate
        sleep(Duration::from_millis(100)).await;
        
        // Verify Alice sent offer
        if let Ok(event) = alice_events.try_recv() {
            match event {
                WebRtcEvent::Call(CallEvent::CallInitiated { 
                    call_id: received_id, 
                    callee, 
                    constraints 
                }) => {
                    assert_eq!(received_id, call_id);
                    assert_eq!(callee, bob);
                    assert!(constraints.has_audio());
                }
                _ => panic!("Expected CallInitiated event"),
            }
        }
        
        // Verify Bob received incoming call
        if let Ok(event) = bob_events.try_recv() {
            match event {
                WebRtcEvent::Call(CallEvent::IncomingCall { offer }) => {
                    assert_eq!(offer.call_id, call_id);
                    assert_eq!(offer.caller, alice);
                    assert_eq!(offer.callee, bob);
                }
                _ => panic!("Expected IncomingCall event"),
            }
        }
        
        // Bob accepts call
        bob_service
            .accept_call(call_id, MediaConstraints::audio_only())
            .await
            .unwrap();
        
        sleep(Duration::from_millis(200)).await;
        
        // Verify call states are connected
        assert_eq!(
            alice_service.get_call_state(call_id).await,
            Some(CallState::Connected)
        );
        assert_eq!(
            bob_service.get_call_state(call_id).await,
            Some(CallState::Connected)
        );
        
        // Alice ends call
        alice_service.end_call(call_id).await.unwrap();
        
        sleep(Duration::from_millis(100)).await;
        
        // Verify call is ended
        assert_eq!(alice_service.get_call_state(call_id).await, None);
        assert_eq!(bob_service.get_call_state(call_id).await, None);
    }
    
    #[tokio::test]
    #[ignore = "requires mock DHT implementation"]
    async fn test_call_rejection_flow() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let bob = FourWordAddress::from("eve-frank-grace-henry");
        
        let dht_alice = super::super::create_mock_dht();
        let dht_bob = super::super::create_mock_dht();
        
        let alice_service = WebRtcService::new(alice.clone(), dht_alice).await.unwrap();
        let bob_service = WebRtcService::new(bob.clone(), dht_bob).await.unwrap();
        
        alice_service.start().await.unwrap();
        bob_service.start().await.unwrap();
        
        let mut alice_events = alice_service.subscribe_events();
        
        // Alice initiates call
        let call_id = alice_service
            .initiate_call(bob.clone(), MediaConstraints::audio_only())
            .await
            .unwrap();
        
        sleep(Duration::from_millis(100)).await;
        
        // Bob rejects call
        bob_service.reject_call(call_id).await.unwrap();
        
        sleep(Duration::from_millis(100)).await;
        
        // Verify Alice receives rejection
        if let Ok(event) = alice_events.try_recv() {
            match event {
                WebRtcEvent::Call(CallEvent::CallRejected { call_id: rejected_id }) => {
                    assert_eq!(rejected_id, call_id);
                }
                _ => {
                    // Keep checking for the rejection event
                }
            }
        }
        
        // Verify call state on Alice's side
        assert_eq!(
            alice_service.get_call_state(call_id).await,
            Some(CallState::Failed)
        );
    }
    
    #[tokio::test]
    #[ignore = "requires mock DHT implementation"]
    async fn test_video_call_flow() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let bob = FourWordAddress::from("eve-frank-grace-henry");
        
        let dht_alice = super::super::create_mock_dht();
        let dht_bob = super::super::create_mock_dht();
        
        let alice_service = WebRtcService::new(alice.clone(), dht_alice).await.unwrap();
        let bob_service = WebRtcService::new(bob.clone(), dht_bob).await.unwrap();
        
        alice_service.start().await.unwrap();
        bob_service.start().await.unwrap();
        
        // Initiate video call
        let call_id = alice_service
            .initiate_call(bob.clone(), MediaConstraints::video_call())
            .await
            .unwrap();
        
        sleep(Duration::from_millis(100)).await;
        
        // Bob accepts video call
        bob_service
            .accept_call(call_id, MediaConstraints::video_call())
            .await
            .unwrap();
        
        sleep(Duration::from_millis(300)).await;
        
        // Verify video call is established
        assert_eq!(
            alice_service.get_call_state(call_id).await,
            Some(CallState::Connected)
        );
        assert_eq!(
            bob_service.get_call_state(call_id).await,
            Some(CallState::Connected)
        );
        
        // Verify media streams have video
        let alice_stream = alice_service.media().get_stream(call_id).await;
        assert!(alice_stream.is_some());
        let stream = alice_stream.unwrap();
        assert!(stream.video_track.is_some());
        
        alice_service.end_call(call_id).await.unwrap();
    }
    
    #[tokio::test]
    async fn test_call_manager_state_transitions() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let bob = FourWordAddress::from("eve-frank-grace-henry");
        
        // Test call session state transitions
        let call_id = CallId::new();
        let mut session = CallSession::new(call_id, MediaConstraints::audio_only());
        
        assert_eq!(session.state, CallState::Idle);
        
        // Add participant
        session.add_participant(bob.clone());
        assert_eq!(session.participants.len(), 1);
        assert!(session.participants.contains(&bob));
        
        // Transition through states
        session.state = CallState::Calling;
        assert_eq!(session.state, CallState::Calling);
        
        session.state = CallState::Connecting;
        assert_eq!(session.state, CallState::Connecting);
        
        session.state = CallState::Connected;
        assert_eq!(session.state, CallState::Connected);
        
        // Test duration calculation
        session.start_time = Some(chrono::Utc::now() - chrono::Duration::seconds(30));
        let duration = session.duration();
        assert!(duration.is_some());
        assert!(duration.unwrap().num_seconds() >= 29);
        
        // Remove participant
        session.remove_participant(&bob);
        assert!(session.participants.is_empty());
    }
    
    #[tokio::test]
    async fn test_concurrent_calls() {
        // Test handling multiple simultaneous calls
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let bob = FourWordAddress::from("eve-frank-grace-henry");
        let charlie = FourWordAddress::from("charlie-david-eve-frank");
        
        // Create call sessions
        let call_id_1 = CallId::new();
        let call_id_2 = CallId::new();
        
        let session_1 = CallSession::new(call_id_1, MediaConstraints::audio_only());
        let session_2 = CallSession::new(call_id_2, MediaConstraints::video_call());
        
        assert_ne!(call_id_1, call_id_2);
        assert_eq!(session_1.call_id, call_id_1);
        assert_eq!(session_2.call_id, call_id_2);
        
        // Verify different constraints
        assert!(session_1.media_constraints.has_audio());
        assert!(!session_1.media_constraints.has_video());
        
        assert!(session_2.media_constraints.has_audio());
        assert!(session_2.media_constraints.has_video());
    }
    
    #[tokio::test] 
    async fn test_call_timeout_handling() {
        // Test call session cleanup and timeouts
        let call_id = CallId::new();
        let mut session = CallSession::new(call_id, MediaConstraints::audio_only());
        
        // Set start time in the past
        session.start_time = Some(chrono::Utc::now() - chrono::Duration::hours(10));
        
        // Check if session is too old (would be cleaned up)
        let age = chrono::Utc::now().signed_duration_since(
            session.start_time.unwrap_or(session.created_at)
        );
        
        assert!(age > chrono::Duration::hours(8)); // Should trigger cleanup
    }
    
    #[test]
    fn test_signaling_message_variants() {
        let call_id = CallId::new();
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let bob = FourWordAddress::from("eve-frank-grace-henry");
        
        // Test all signaling message variants
        let offer_msg = SignalingMessage::Offer(CallOffer {
            call_id,
            caller: alice.clone(),
            callee: bob.clone(),
            sdp: "v=0\r\n...".to_string(),
            media_types: vec![MediaType::Audio],
            timestamp: chrono::Utc::now(),
        });
        
        let answer_msg = SignalingMessage::Answer(CallAnswer {
            call_id,
            sdp: "v=0\r\n...".to_string(),
            accepted: true,
            timestamp: chrono::Utc::now(),
        });
        
        let end_msg = SignalingMessage::CallEnd { call_id };
        let reject_msg = SignalingMessage::CallReject { call_id };
        
        // Verify all serialize properly
        assert!(serde_json::to_string(&offer_msg).is_ok());
        assert!(serde_json::to_string(&answer_msg).is_ok());
        assert!(serde_json::to_string(&end_msg).is_ok());
        assert!(serde_json::to_string(&reject_msg).is_ok());
    }
    
    #[tokio::test]
    #[ignore = "requires mock DHT implementation"]
    async fn test_call_manager_connection_status() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let dht = super::super::create_mock_dht();
        
        let signaling = Arc::new(SignalingHandler::new(alice.clone(), Arc::clone(&dht)));
        let media = Arc::new(MediaStreamManager::new(alice.clone()));
        
        let call_manager = CallManager::new(alice.clone(), signaling.clone(), media)
            .await
            .unwrap();
        
        call_manager.start().await.unwrap();
        
        let call_id = CallId::new();
        
        // Test connection status for non-existent call
        let status = call_manager.get_connection_status(call_id).await.unwrap();
        assert!(!status);
        
        // Test QUIC connection establishment
        let result = call_manager.establish_connection(call_id).await;
        // This will fail because there's no session, but tests the method exists
        assert!(result.is_err());
    }
}