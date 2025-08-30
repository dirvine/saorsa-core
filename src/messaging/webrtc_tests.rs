// WebRTC Voice/Video Call Tests

#[cfg(test)]
mod tests {
    use super::super::webrtc::*;
    use crate::identity::FourWordAddress;
    use crate::messaging::types::*;
    use anyhow::Result;
    use tokio;
    
    #[tokio::test]
    async fn test_create_call_offer() {
        let caller = FourWordAddress::from("alice-bob-charlie-david");
        let callee = FourWordAddress::from("eve-frank-grace-henry");
        
        let call_manager = CallManager::new(caller.clone()).await.unwrap();
        
        let offer = call_manager.create_offer(
            callee.clone(),
            MediaConstraints {
                audio: true,
                video: false,
                screen_share: false,
            }
        ).await.unwrap();
        
        assert_eq!(offer.caller, caller);
        assert_eq!(offer.callee, callee);
        assert!(!offer.sdp.is_empty());
        assert_eq!(offer.media_types, vec![MediaType::Audio]);
    }
    
    #[tokio::test]
    async fn test_handle_call_answer() {
        let caller = FourWordAddress::from("alice-bob-charlie-david");
        let callee = FourWordAddress::from("eve-frank-grace-henry");
        
        let call_manager = CallManager::new(caller.clone()).await.unwrap();
        
        // Create offer first
        let offer = call_manager.create_offer(
            callee.clone(),
            MediaConstraints {
                audio: true,
                video: true,
                screen_share: false,
            }
        ).await.unwrap();
        
        // Simulate answer
        let answer = CallAnswer {
            call_id: offer.call_id,
            sdp: "v=0\r\no=- 123 456 IN IP4 127.0.0.1\r\n...".to_string(),
            accepted: true,
            timestamp: chrono::Utc::now(),
        };
        
        let result = call_manager.handle_answer(answer).await;
        assert!(result.is_ok());
        
        // Check call state
        let state = call_manager.get_call_state(offer.call_id).await.unwrap();
        assert_eq!(state, CallState::Connecting);
    }
    
    #[tokio::test]
    async fn test_ice_candidate_exchange() {
        let caller = FourWordAddress::from("alice-bob-charlie-david");
        let call_manager = CallManager::new(caller.clone()).await.unwrap();
        
        let call_id = CallId::new();
        
        let ice_candidate = IceCandidate {
            call_id,
            candidate: "candidate:1 1 UDP 2130706431 192.168.1.1 54400 typ host".to_string(),
            sdp_mid: Some("0".to_string()),
            sdp_mline_index: Some(0),
        };
        
        // Add ICE candidate
        let result = call_manager.add_ice_candidate(ice_candidate.clone()).await;
        assert!(result.is_ok());
        
        // Get ICE candidates
        let candidates = call_manager.get_ice_candidates(call_id).await.unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].candidate, ice_candidate.candidate);
    }
    
    #[tokio::test]
    async fn test_call_state_transitions() {
        let caller = FourWordAddress::from("alice-bob-charlie-david");
        let call_manager = CallManager::new(caller.clone()).await.unwrap();
        
        let call_id = CallId::new();
        
        // Initial state
        let state = call_manager.get_call_state(call_id).await.unwrap_or(CallState::Idle);
        assert_eq!(state, CallState::Idle);
        
        // Transition to Calling
        call_manager.set_call_state(call_id, CallState::Calling).await.unwrap();
        let state = call_manager.get_call_state(call_id).await.unwrap();
        assert_eq!(state, CallState::Calling);
        
        // Transition to Connecting
        call_manager.set_call_state(call_id, CallState::Connecting).await.unwrap();
        let state = call_manager.get_call_state(call_id).await.unwrap();
        assert_eq!(state, CallState::Connecting);
        
        // Transition to Connected
        call_manager.set_call_state(call_id, CallState::Connected).await.unwrap();
        let state = call_manager.get_call_state(call_id).await.unwrap();
        assert_eq!(state, CallState::Connected);
        
        // End call
        call_manager.end_call(call_id).await.unwrap();
        let state = call_manager.get_call_state(call_id).await.unwrap();
        assert_eq!(state, CallState::Ending);
    }
    
    #[tokio::test]
    async fn test_media_constraints() {
        let constraints = MediaConstraints {
            audio: true,
            video: true,
            screen_share: false,
        };
        
        assert!(constraints.has_audio());
        assert!(constraints.has_video());
        assert!(!constraints.has_screen_share());
        
        let media_types = constraints.to_media_types();
        assert_eq!(media_types.len(), 2);
        assert!(media_types.contains(&MediaType::Audio));
        assert!(media_types.contains(&MediaType::Video));
    }
    
    #[tokio::test]
    async fn test_signaling_message_serialization() {
        let offer = CallOffer {
            call_id: CallId::new(),
            caller: FourWordAddress::from("alice-bob-charlie-david"),
            callee: FourWordAddress::from("eve-frank-grace-henry"),
            caller_handle: None,
            callee_handle: None,
            sdp: "v=0\r\no=- 123 456 IN IP4 127.0.0.1\r\n...".to_string(),
            media_types: vec![MediaType::Audio, MediaType::Video],
            timestamp: chrono::Utc::now(),
        };
        
        // Serialize
        let json = serde_json::to_string(&offer).unwrap();
        
        // Deserialize
        let deserialized: CallOffer = serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.call_id, offer.call_id);
        assert_eq!(deserialized.caller, offer.caller);
        assert_eq!(deserialized.callee, offer.callee);
        assert_eq!(deserialized.sdp, offer.sdp);
        assert_eq!(deserialized.media_types, offer.media_types);
    }
    
    #[tokio::test]
    async fn test_call_quality_metrics() {
        let metrics = CallQualityMetrics {
            rtt_ms: 25,
            packet_loss_percent: 0.5,
            jitter_ms: 5,
            bandwidth_kbps: 1500,
            timestamp: chrono::Utc::now(),
        };
        
        assert!(metrics.is_good_quality());
        assert!(!metrics.needs_adaptation());
        
        let poor_metrics = CallQualityMetrics {
            rtt_ms: 500,
            packet_loss_percent: 10.0,
            jitter_ms: 50,
            bandwidth_kbps: 100,
            timestamp: chrono::Utc::now(),
        };
        
        assert!(!poor_metrics.is_good_quality());
        assert!(poor_metrics.needs_adaptation());
    }
    
    #[tokio::test]
    async fn test_multi_party_call() {
        let initiator = FourWordAddress::from("alice-bob-charlie-david");
        let call_manager = CallManager::new(initiator.clone()).await.unwrap();
        
        let participants = vec![
            FourWordAddress::from("eve-frank-grace-henry"),
            FourWordAddress::from("ivan-julia-kevin-laura"),
            FourWordAddress::from("mike-nancy-oscar-paul"),
        ];
        
        // Create multi-party call
        let call = call_manager.create_multi_party_call(
            participants.clone(),
            MediaConstraints {
                audio: true,
                video: true,
                screen_share: false,
            }
        ).await.unwrap();
        
        assert_eq!(call.participants.len(), 4); // initiator + 3 participants
        assert!(call.participants.contains(&initiator));
        for participant in &participants {
            assert!(call.participants.contains(participant));
        }
        
        // Check if mesh or SFU mode
        if participants.len() <= 4 {
            assert_eq!(call.architecture, CallArchitecture::Mesh);
        } else {
            assert_eq!(call.architecture, CallArchitecture::SFU);
        }
    }
    
    #[tokio::test]
    async fn test_call_recording_consent() {
        let caller = FourWordAddress::from("alice-bob-charlie-david");
        let call_manager = CallManager::new(caller.clone()).await.unwrap();
        
        let call_id = CallId::new();
        
        // Request recording consent
        let consent_request = RecordingConsent {
            call_id,
            requester: caller.clone(),
            participants: vec![
                FourWordAddress::from("eve-frank-grace-henry"),
            ],
        };
        
        let result = call_manager.request_recording_consent(consent_request).await;
        assert!(result.is_ok());
        
        // Check consent status (should be pending)
        let status = call_manager.get_recording_consent_status(call_id).await.unwrap();
        assert_eq!(status, ConsentStatus::Pending);
        
        // Simulate consent given
        call_manager.grant_recording_consent(call_id, caller).await.unwrap();
        
        let status = call_manager.get_recording_consent_status(call_id).await.unwrap();
        assert_eq!(status, ConsentStatus::Granted);
    }
    
    #[tokio::test]
    async fn test_network_adaptation() {
        let mut adapter = NetworkAdapter::new();
        
        // Good network conditions
        let good_metrics = CallQualityMetrics {
            rtt_ms: 20,
            packet_loss_percent: 0.1,
            jitter_ms: 2,
            bandwidth_kbps: 2000,
            timestamp: chrono::Utc::now(),
        };
        
        let settings = adapter.adapt(good_metrics).await.unwrap();
        assert_eq!(settings.video_bitrate_kbps, 1500);
        assert_eq!(settings.video_resolution, VideoResolution::HD720);
        assert_eq!(settings.video_fps, 30);
        
        // Poor network conditions
        let poor_metrics = CallQualityMetrics {
            rtt_ms: 300,
            packet_loss_percent: 5.0,
            jitter_ms: 30,
            bandwidth_kbps: 300,
            timestamp: chrono::Utc::now(),
        };
        
        let settings = adapter.adapt(poor_metrics).await.unwrap();
        assert!(settings.video_bitrate_kbps < 500);
        assert_eq!(settings.video_resolution, VideoResolution::SD480);
        assert!(settings.video_fps <= 15);
    }
    
    #[tokio::test]
    async fn test_stun_configuration() {
        let config = StunConfiguration::default();
        
        assert!(!config.servers.is_empty());
        assert!(config.servers.contains(&"stun:stun.l.google.com:19302".to_string()));
        assert!(config.servers.contains(&"stun:stun1.l.google.com:19302".to_string()));
    }
    
    #[tokio::test]
    async fn test_call_cleanup() {
        let caller = FourWordAddress::from("alice-bob-charlie-david");
        let call_manager = CallManager::new(caller.clone()).await.unwrap();
        
        let callee = FourWordAddress::from("eve-frank-grace-henry");
        
        // Create and start a call
        let offer = call_manager.create_offer(
            callee,
            MediaConstraints {
                audio: true,
                video: false,
                screen_share: false,
            }
        ).await.unwrap();
        
        let call_id = offer.call_id;
        
        // Simulate active call
        call_manager.set_call_state(call_id, CallState::Connected).await.unwrap();
        
        // End call
        call_manager.end_call(call_id).await.unwrap();
        
        // Verify cleanup
        let state = call_manager.get_call_state(call_id).await;
        assert!(state.is_none() || state == Some(CallState::Idle));
        
        // Verify resources freed
        let candidates = call_manager.get_ice_candidates(call_id).await.unwrap();
        assert_eq!(candidates.len(), 0);
    }
}
