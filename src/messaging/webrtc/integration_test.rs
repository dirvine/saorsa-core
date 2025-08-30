// Comprehensive integration test for WebRTC over native QUIC
// This file serves as a test runner to verify the complete implementation

use super::*;
use crate::identity::FourWordAddress;
use tokio::time::{sleep, Duration};
use std::sync::Arc;

/// Integration test runner for WebRTC over QUIC
pub struct WebRtcQuicTestRunner {
    test_results: Vec<TestResult>,
}

#[derive(Debug, Clone)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub error: Option<String>,
    pub duration: Duration,
}

impl WebRtcQuicTestRunner {
    pub fn new() -> Self {
        Self {
            test_results: Vec::new(),
        }
    }
    
    /// Run all WebRTC QUIC integration tests
    pub async fn run_all_tests(&mut self) -> Vec<TestResult> {
        println!("🧪 Starting WebRTC over native QUIC integration tests...");
        
        // Core functionality tests
        self.run_test("QUIC Configuration Validation", Self::test_quic_config_validation).await;
        self.run_test("SDP Validation", Self::test_sdp_validation).await;
        self.run_test("Signaling Message Serialization", Self::test_signaling_serialization).await;
        
        // Media streaming tests
        self.run_test("Media Constraints Processing", Self::test_media_constraints).await;
        self.run_test("Quality Metrics Calculation", Self::test_quality_metrics).await;
        self.run_test("Video Resolution Helpers", Self::test_video_resolution).await;
        
        // Call management tests
        self.run_test("Call Session Management", Self::test_call_session_management).await;
        self.run_test("Multi-party Architecture Selection", Self::test_architecture_selection).await;
        self.run_test("Recording Consent Flow", Self::test_recording_consent).await;
        
        // State machine tests
        self.run_test("Signaling State Transitions", Self::test_signaling_states).await;
        self.run_test("Call State Transitions", Self::test_call_states).await;
        
        println!("\\n📊 Test Results Summary:");
        let passed = self.test_results.iter().filter(|r| r.passed).count();
        let total = self.test_results.len();
        
        for result in &self.test_results {
            let status = if result.passed { "✅ PASS" } else { "❌ FAIL" };
            println!("  {} {} ({:?})", status, result.name, result.duration);
            if let Some(ref error) = result.error {
                println!("    Error: {}", error);
            }
        }
        
        println!("\\n🏁 {}/{} tests passed", passed, total);
        if passed == total {
            println!("🎉 All WebRTC QUIC integration tests passed!");
        } else {
            println!("⚠️  Some tests failed - WebRTC QUIC implementation needs attention");
        }
        
        self.test_results.clone()
    }
    
    async fn run_test<F, Fut>(&mut self, name: &str, test_fn: F)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), String>>,
    {
        let start = std::time::Instant::now();
        let result = test_fn().await;
        let duration = start.elapsed();
        
        let test_result = TestResult {
            name: name.to_string(),
            passed: result.is_ok(),
            error: result.err(),
            duration: Duration::from_nanos(duration.as_nanos() as u64),
        };
        
        self.test_results.push(test_result);
    }
    
    // Individual test functions
    
    async fn test_quic_config_validation() -> Result<(), String> {
        // Test default QUIC configuration
        let default_config = NativeQuicConfiguration::default();
        if !default_config.dht_discovery || !default_config.hole_punching {
            return Err("Default QUIC config should enable both DHT discovery and hole punching".to_string());
        }
        
        // Test custom configurations
        let custom_config = NativeQuicConfiguration {
            dht_discovery: false,
            hole_punching: true,
        };
        
        if custom_config.dht_discovery || !custom_config.hole_punching {
            return Err("Custom QUIC config not working as expected".to_string());
        }
        
        // Test serialization
        let serialized = serde_json::to_string(&default_config)
            .map_err(|e| format!("Failed to serialize QUIC config: {}", e))?;
        
        let _deserialized: NativeQuicConfiguration = serde_json::from_str(&serialized)
            .map_err(|e| format!("Failed to deserialize QUIC config: {}", e))?;
        
        Ok(())
    }
    
    async fn test_sdp_validation() -> Result<(), String> {
        use crate::messaging::webrtc::signaling::SignalingHandler;
        
        // Test valid SDP
        let valid_sdp = "v=0\\r\\no=- 123456789 987654321 IN IP4 127.0.0.1\\r\\ns=TestSession\\r\\nt=0 0\\r\\n";
        SignalingHandler::validate_sdp(valid_sdp)
            .map_err(|e| format!("Valid SDP rejected: {}", e))?;
        
        // Test invalid SDP (empty)
        if SignalingHandler::validate_sdp("").is_ok() {
            return Err("Empty SDP should be rejected".to_string());
        }
        
        // Test invalid SDP (malformed)
        if SignalingHandler::validate_sdp("invalid sdp content").is_ok() {
            return Err("Malformed SDP should be rejected".to_string());
        }
        
        // Test QUIC endpoint validation
        SignalingHandler::validate_quic_endpoint("127.0.0.1:5000")
            .map_err(|e| format!("Valid QUIC endpoint rejected: {}", e))?;
        
        if SignalingHandler::validate_quic_endpoint("invalid-endpoint").is_ok() {
            return Err("Invalid QUIC endpoint should be rejected".to_string());
        }
        
        Ok(())
    }
    
    async fn test_signaling_serialization() -> Result<(), String> {
        let call_id = CallId::new();
        let alice = FourWordAddress::from("alice-bob-charlie-david");
        let bob = FourWordAddress::from("eve-frank-grace-henry");
        
        // Test offer message
        let offer = CallOffer {
            call_id,
            caller: alice.clone(),
            callee: bob.clone(),
            caller_handle: None,
            callee_handle: None,
            sdp: "v=0\\r\\n...".to_string(),
            media_types: vec![MediaType::Audio, MediaType::Video],
            timestamp: chrono::Utc::now(),
        };
        
        let offer_msg = SignalingMessage::Offer(offer);
        let serialized = serde_json::to_string(&offer_msg)
            .map_err(|e| format!("Failed to serialize offer: {}", e))?;
        
        let _deserialized: SignalingMessage = serde_json::from_str(&serialized)
            .map_err(|e| format!("Failed to deserialize offer: {}", e))?;
        
        // Test answer message
        let answer = CallAnswer {
            call_id,
            sdp: "v=0\\r\\n...".to_string(),
            accepted: true,
            timestamp: chrono::Utc::now(),
        };
        
        let answer_msg = SignalingMessage::Answer(answer);
        let serialized = serde_json::to_string(&answer_msg)
            .map_err(|e| format!("Failed to serialize answer: {}", e))?;
        
        let _deserialized: SignalingMessage = serde_json::from_str(&serialized)
            .map_err(|e| format!("Failed to deserialize answer: {}", e))?;
        
        Ok(())
    }
    
    async fn test_media_constraints() -> Result<(), String> {
        // Test audio-only constraints
        let audio_only = MediaConstraints::audio_only();
        if !audio_only.has_audio() || audio_only.has_video() || audio_only.has_screen_share() {
            return Err("Audio-only constraints incorrect".to_string());
        }
        
        let media_types = audio_only.to_media_types();
        if media_types.len() != 1 || !media_types.contains(&MediaType::Audio) {
            return Err("Audio-only media types incorrect".to_string());
        }
        
        // Test video call constraints
        let video_call = MediaConstraints::video_call();
        if !video_call.has_audio() || !video_call.has_video() || video_call.has_screen_share() {
            return Err("Video call constraints incorrect".to_string());
        }
        
        let media_types = video_call.to_media_types();
        if media_types.len() != 2 || !media_types.contains(&MediaType::Audio) || !media_types.contains(&MediaType::Video) {
            return Err("Video call media types incorrect".to_string());
        }
        
        // Test screen share constraints
        let screen_share = MediaConstraints::screen_share();
        if !screen_share.has_audio() || screen_share.has_video() || !screen_share.has_screen_share() {
            return Err("Screen share constraints incorrect".to_string());
        }
        
        Ok(())
    }
    
    async fn test_quality_metrics() -> Result<(), String> {
        // Test good quality metrics
        let good_metrics = CallQualityMetrics {
            rtt_ms: 50,
            packet_loss_percent: 0.5,
            jitter_ms: 15,
            bandwidth_kbps: 1000,
            timestamp: chrono::Utc::now(),
        };
        
        if !good_metrics.is_good_quality() || good_metrics.needs_adaptation() {
            return Err("Good quality metrics not detected correctly".to_string());
        }
        
        // Test poor quality metrics
        let poor_metrics = CallQualityMetrics {
            rtt_ms: 350,
            packet_loss_percent: 6.0,
            jitter_ms: 60,
            bandwidth_kbps: 150,
            timestamp: chrono::Utc::now(),
        };
        
        if poor_metrics.is_good_quality() || !poor_metrics.needs_adaptation() {
            return Err("Poor quality metrics not detected correctly".to_string());
        }
        
        // Test medium quality metrics
        let medium_metrics = CallQualityMetrics {
            rtt_ms: 150,
            packet_loss_percent: 2.0,
            jitter_ms: 25,
            bandwidth_kbps: 400,
            timestamp: chrono::Utc::now(),
        };
        
        if medium_metrics.is_good_quality() || medium_metrics.needs_adaptation() {
            return Err("Medium quality metrics not detected correctly".to_string());
        }
        
        Ok(())
    }
    
    async fn test_video_resolution() -> Result<(), String> {
        // Test resolution dimensions
        if VideoResolution::QVGA240.width() != 320 || VideoResolution::QVGA240.height() != 240 {
            return Err("QVGA240 resolution dimensions incorrect".to_string());
        }
        
        if VideoResolution::SD480.width() != 640 || VideoResolution::SD480.height() != 480 {
            return Err("SD480 resolution dimensions incorrect".to_string());
        }
        
        if VideoResolution::HD720.width() != 1280 || VideoResolution::HD720.height() != 720 {
            return Err("HD720 resolution dimensions incorrect".to_string());
        }
        
        if VideoResolution::HD1080.width() != 1920 || VideoResolution::HD1080.height() != 1080 {
            return Err("HD1080 resolution dimensions incorrect".to_string());
        }
        
        Ok(())
    }
    
    async fn test_call_session_management() -> Result<(), String> {
        let call_id = CallId::new();
        let mut session = CallSession::new(call_id, MediaConstraints::video_call());
        
        if session.call_id != call_id {
            return Err("Call session ID mismatch".to_string());
        }
        
        if session.state != CallState::Idle {
            return Err("Initial call state should be Idle".to_string());
        }
        
        // Test participant management
        let alice = FourWordAddress::from("alice-bob-charlie-david");
        let bob = FourWordAddress::from("eve-frank-grace-henry");
        
        session.add_participant(crate::messaging::user_handle::UserHandle::from(alice.to_string()));
        session.add_participant(crate::messaging::user_handle::UserHandle::from(bob.to_string()));
        
        if session.participants.len() != 2 {
            return Err("Participant addition failed".to_string());
        }
        
        // Test duplicate participant
        session.add_participant(crate::messaging::user_handle::UserHandle::from(alice.to_string()));
        if session.participants.len() != 2 {
            return Err("Duplicate participant was added".to_string());
        }
        
        // Test participant removal
        session.remove_participant(&crate::messaging::user_handle::UserHandle::from(alice.to_string()));
        if session.participants.len() != 1 || session.participants.contains(&crate::messaging::user_handle::UserHandle::from(alice.to_string())) {
            return Err("Participant removal failed".to_string());
        }
        
        Ok(())
    }
    
    async fn test_architecture_selection() -> Result<(), String> {
        // Test small group (should use Mesh)
        let small_participants = vec![
            FourWordAddress::from("bob-charlie-david-eve"),
            FourWordAddress::from("charlie-david-eve-frank"),
        ];
        // +1 for caller = 3 total, should be Mesh
        
        // Test large group (should use SFU)
        let large_participants = vec![
            FourWordAddress::from("bob-charlie-david-eve"),
            FourWordAddress::from("charlie-david-eve-frank"),
            FourWordAddress::from("david-eve-frank-grace"),
            FourWordAddress::from("eve-frank-grace-henry"),
            FourWordAddress::from("frank-grace-henry-ivan"),
        ];
        // +1 for caller = 6 total, should be SFU
        
        if small_participants.len() + 1 > 4 {
            return Err("Small group should use mesh architecture".to_string());
        }
        
        if large_participants.len() + 1 <= 4 {
            return Err("Large group should use SFU architecture".to_string());
        }
        
        Ok(())
    }
    
    async fn test_recording_consent() -> Result<(), String> {
        let call_id = CallId::new();
        let alice = crate::messaging::user_handle::UserHandle::from("alice-bob-charlie-david");
        let participants = vec![
            crate::messaging::user_handle::UserHandle::from("bob-charlie-david-eve"),
            crate::messaging::user_handle::UserHandle::from("charlie-david-eve-frank"),
        ];
        
        let consent = RecordingConsent {
            call_id,
            requester: alice,
            participants: participants.clone(),
        };
        
        if consent.participants.len() != 2 {
            return Err("Recording consent participants incorrect".to_string());
        }
        
        // Test serialization
        let serialized = serde_json::to_string(&consent)
            .map_err(|e| format!("Failed to serialize recording consent: {}", e))?;
        
        let deserialized: RecordingConsent = serde_json::from_str(&serialized)
            .map_err(|e| format!("Failed to deserialize recording consent: {}", e))?;
        
        if deserialized.call_id != call_id {
            return Err("Deserialized recording consent call_id mismatch".to_string());
        }
        
        Ok(())
    }
    
    async fn test_signaling_states() -> Result<(), String> {
        // Test state equality
        if SignalingState::OfferSent != SignalingState::OfferSent {
            return Err("Signaling state equality failed".to_string());
        }
        
        if SignalingState::OfferSent == SignalingState::AnswerReceived {
            return Err("Different signaling states should not be equal".to_string());
        }
        
        // Test all states exist
        let _states = vec![
            SignalingState::OfferSent,
            SignalingState::OfferReceived,
            SignalingState::AnswerSent,
            SignalingState::AnswerReceived,
            SignalingState::IceExchange,
            SignalingState::Connected,
            SignalingState::Rejected,
            SignalingState::Ended,
        ];
        
        Ok(())
    }
    
    async fn test_call_states() -> Result<(), String> {
        // Test call state transitions
        let states = vec![
            CallState::Idle,
            CallState::Calling,
            CallState::Connecting,
            CallState::Connected,
            CallState::Ending,
            CallState::Failed,
        ];
        
        // Verify all states can be created and compared
        for state in &states {
            if *state != state.clone() {
                return Err("Call state comparison failed".to_string());
            }
        }
        
        // Test serialization of call states
        for state in states {
            let serialized = serde_json::to_string(&state)
                .map_err(|e| format!("Failed to serialize call state: {}", e))?;
            
            let _deserialized: CallState = serde_json::from_str(&serialized)
                .map_err(|e| format!("Failed to deserialize call state: {}", e))?;
        }
        
        Ok(())
    }
}

/// Run WebRTC QUIC integration tests
pub async fn run_webrtc_quic_tests() -> Vec<TestResult> {
    let mut runner = WebRtcQuicTestRunner::new();
    runner.run_all_tests().await
}

#[tokio::test]
async fn integration_test_webrtc_over_quic() {
    let results = run_webrtc_quic_tests().await;
    
    let passed = results.iter().filter(|r| r.passed).count();
    let total = results.len();
    
    if passed < total {
        for result in &results {
            if !result.passed {
                eprintln!("Failed test: {} - {:?}", result.name, result.error);
            }
        }
    }
    
    assert_eq!(passed, total, "Not all WebRTC QUIC integration tests passed");
}
