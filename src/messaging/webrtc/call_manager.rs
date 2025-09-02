// WebRTC Call Manager
// High-level call management with state handling and quality monitoring

use super::media::{MediaEvent, MediaStreamManager};
use super::signaling::{SignalingEvent, SignalingHandler, SignalingState};
use super::types::*;
use crate::identity::FourWordAddress;
use crate::messaging::user_handle::UserHandle;
use crate::messaging::user_resolver::resolve_handle;
use anyhow::Result;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, error, info};

/// High-level call manager that coordinates signaling and media
pub struct CallManager {
    /// Local peer identity
    local_identity: FourWordAddress,
    /// Signaling handler
    signaling: Arc<SignalingHandler>,
    /// Media stream manager
    media: Arc<MediaStreamManager>,
    /// Active call sessions
    calls: Arc<RwLock<HashMap<CallId, CallSession>>>,
    /// Network adapter for quality management
    network_adapter: Arc<NetworkAdapter>,
    /// Event broadcaster
    event_sender: broadcast::Sender<CallEvent>,
    /// Cleanup task handle
    _cleanup_handle: tokio::task::JoinHandle<()>,
}

impl CallManager {
    /// Create new call manager
    pub async fn new(
        local_identity: FourWordAddress,
        signaling: Arc<SignalingHandler>,
        media: Arc<MediaStreamManager>,
    ) -> Result<Self> {
        let (event_sender, _) = broadcast::channel(1000);
        let calls = Arc::new(RwLock::new(HashMap::new()));
        let network_adapter = Arc::new(NetworkAdapter::new());

        // Start cleanup task
        let cleanup_calls = Arc::clone(&calls);
        let cleanup_handle = tokio::spawn(async move {
            Self::cleanup_task(cleanup_calls).await;
        });

        Ok(Self {
            local_identity,
            signaling,
            media,
            calls,
            network_adapter,
            event_sender,
            _cleanup_handle: cleanup_handle,
        })
    }

    /// Start the call manager
    pub async fn start(&self) -> Result<()> {
        info!("Starting call manager");

        // Subscribe to signaling events
        let mut signaling_events = self.signaling.subscribe_events();
        let calls = Arc::clone(&self.calls);
        let media = Arc::clone(&self.media);
        let event_sender = self.event_sender.clone();
        let network_adapter = Arc::clone(&self.network_adapter);

        tokio::spawn(async move {
            while let Ok(event) = signaling_events.recv().await {
                if let Err(e) = Self::handle_signaling_event(
                    event,
                    &calls,
                    &media,
                    &event_sender,
                    &network_adapter,
                )
                .await
                {
                    error!("Error handling signaling event: {}", e);
                }
            }
        });

        // Subscribe to media events
        let mut media_events = self.media.subscribe_events();
        let calls = Arc::clone(&self.calls);
        let event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            while let Ok(event) = media_events.recv().await {
                if let Err(e) = Self::handle_media_event(event, &calls, &event_sender).await {
                    error!("Error handling media event: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Initiate a call to another peer
    pub async fn initiate_call(
        &self,
        callee: FourWordAddress,
        constraints: MediaConstraints,
    ) -> Result<CallId> {
        let call_id = CallId::new();

        info!("Initiating call {} to {}", call_id.0, callee);

        // Create call session
        let mut session = CallSession::new(call_id, constraints.clone());
        session.add_participant(UserHandle::from(callee.to_string()));
        session.state = CallState::Calling;
        session.start_time = Some(Utc::now());

        // Store session
        let mut calls = self.calls.write().await;
        calls.insert(call_id, session);
        drop(calls);

        // Create media stream
        let stream = self
            .media
            .create_stream(call_id, constraints.clone())
            .await?;

        // Create and send offer
        let offer = CallOffer {
            call_id,
            caller: self.local_identity.clone(),
            callee: callee.clone(),
            caller_handle: Some(resolve_handle(&self.local_identity)),
            callee_handle: Some(resolve_handle(&callee)),
            sdp: self.generate_sdp_offer(&stream).await?,
            media_types: constraints.to_media_types(),
            timestamp: Utc::now(),
        };

        self.signaling.send_offer(offer).await?;

        // Start media capture
        self.media.start_capture(call_id).await?;

        // Emit event
        let _ = self.event_sender.send(CallEvent::CallInitiated {
            call_id,
            callee: UserHandle::from(callee.to_string()),
            constraints,
        });

        Ok(call_id)
    }

    /// Accept an incoming call
    pub async fn accept_call(&self, call_id: CallId, constraints: MediaConstraints) -> Result<()> {
        info!("Accepting call {}", call_id.0);

        // Update call session
        let mut calls = self.calls.write().await;
        if let Some(session) = calls.get_mut(&call_id) {
            session.state = CallState::Connecting;
            session.media_constraints = constraints.clone();
            session.start_time = Some(Utc::now());
        } else {
            return Err(anyhow::anyhow!("Call {} not found", call_id.0));
        }
        drop(calls);

        // Create media stream
        let stream = self.media.create_stream(call_id, constraints).await?;

        // Create and send answer
        let answer = CallAnswer {
            call_id,
            sdp: self.generate_sdp_answer(&stream).await?,
            accepted: true,
            timestamp: Utc::now(),
        };

        // Clone answer before moving it
        let answer_clone = answer.clone();

        self.signaling.send_answer(answer).await?;

        // Start media capture
        self.media.start_capture(call_id).await?;

        // Emit event
        let _ = self.event_sender.send(CallEvent::CallAccepted {
            call_id,
            answer: answer_clone,
        });

        Ok(())
    }

    /// Reject an incoming call
    pub async fn reject_call(&self, call_id: CallId) -> Result<()> {
        info!("Rejecting call {}", call_id.0);

        // Update call session
        let mut calls = self.calls.write().await;
        if let Some(session) = calls.get_mut(&call_id) {
            session.state = CallState::Failed;
            session.end_time = Some(Utc::now());
        }
        drop(calls);

        // Send rejection via signaling
        self.signaling.reject_call(call_id).await?;

        // Emit event
        let _ = self.event_sender.send(CallEvent::CallRejected { call_id });

        Ok(())
    }

    /// End an active call
    pub async fn end_call(&self, call_id: CallId) -> Result<()> {
        info!("Ending call {}", call_id.0);

        // Update call session
        let mut calls = self.calls.write().await;
        if let Some(session) = calls.get_mut(&call_id) {
            session.state = CallState::Ending;
            session.end_time = Some(Utc::now());
        }
        drop(calls);

        // Stop media capture
        self.media.stop_capture(call_id).await?;

        // Remove media stream
        self.media.remove_stream(call_id).await?;

        // Send end signal
        self.signaling.end_call(call_id).await?;

        // Remove call session
        let mut calls = self.calls.write().await;
        calls.remove(&call_id);

        // Emit event
        let _ = self.event_sender.send(CallEvent::CallEnded { call_id });

        Ok(())
    }

    /// Get call state
    pub async fn get_call_state(&self, call_id: CallId) -> Option<CallState> {
        let calls = self.calls.read().await;
        calls.get(&call_id).map(|session| session.state.clone())
    }

    /// Get call session
    pub async fn get_call_session(&self, call_id: CallId) -> Option<CallSession> {
        let calls = self.calls.read().await;
        calls.get(&call_id).cloned()
    }

    /// Set call state
    pub async fn set_call_state(&self, call_id: CallId, state: CallState) -> Result<()> {
        let mut calls = self.calls.write().await;

        if let Some(session) = calls.get_mut(&call_id) {
            let old_state = session.state.clone();
            session.state = state.clone();

            // Handle state transitions
            match (old_state, state) {
                (CallState::Connecting, CallState::Connected) => {
                    // Call successfully connected
                    let _ = self
                        .event_sender
                        .send(CallEvent::ConnectionEstablished { call_id });
                }
                (_, CallState::Failed) => {
                    session.end_time = Some(Utc::now());
                    let _ = self.event_sender.send(CallEvent::ConnectionFailed {
                        call_id,
                        error: "Call failed".to_string(),
                    });
                }
                _ => {}
            }

            Ok(())
        } else {
            Err(anyhow::anyhow!("Call {} not found", call_id.0))
        }
    }

    /// Establish native QUIC connection for call
    pub async fn establish_connection(&self, call_id: CallId) -> Result<()> {
        debug!("Establishing native QUIC connection for call {}", call_id.0);

        // Use signaling handler to establish QUIC connection
        self.signaling.establish_quic_connection(call_id).await?;

        // Update call state to connecting
        self.set_call_state(call_id, CallState::Connecting).await?;

        Ok(())
    }

    /// Get QUIC connection status for a call
    pub async fn get_connection_status(&self, call_id: CallId) -> Result<bool> {
        // Check if signaling session exists and is active
        if let Some(session) = self.signaling.get_session(call_id).await {
            // In production, this would check the actual QUIC connection state
            Ok(session.state != SignalingState::Rejected && session.state != SignalingState::Ended)
        } else {
            Ok(false)
        }
    }

    /// Create multi-party call
    pub async fn create_multi_party_call(
        &self,
        participants: Vec<FourWordAddress>,
        _constraints: MediaConstraints,
    ) -> Result<MultiPartyCall> {
        let call_id = CallId::new();

        // Determine architecture based on participant count
        let architecture = if participants.len() <= 4 {
            CallArchitecture::Mesh
        } else {
            CallArchitecture::SFU
        };

        let mut all_participants = participants;
        all_participants.push(self.local_identity.clone());

        let multi_call = MultiPartyCall {
            call_id,
            participants: all_participants
                .into_iter()
                .map(|p| UserHandle::from(p.to_string()))
                .collect(),
            architecture: architecture.clone(),
            created_at: Utc::now(),
        };

        info!(
            "Created multi-party call {} with {} participants using {:?} architecture",
            call_id.0,
            multi_call.participants.len(),
            architecture
        );

        Ok(multi_call)
    }

    /// Request recording consent
    pub async fn request_recording_consent(&self, consent: RecordingConsent) -> Result<()> {
        info!(
            "Requesting recording consent for call {}",
            consent.call_id.0
        );

        // In production, this would send consent requests to all participants
        // For now, we'll just store the request

        Ok(())
    }

    /// Grant recording consent
    pub async fn grant_recording_consent(
        &self,
        call_id: CallId,
        _participant: FourWordAddress,
    ) -> Result<()> {
        info!("Granting recording consent for call {}", call_id.0);

        // In production, this would update the consent status

        Ok(())
    }

    /// Get recording consent status
    pub async fn get_recording_consent_status(&self, _call_id: CallId) -> Result<ConsentStatus> {
        // In production, this would check actual consent status
        Ok(ConsentStatus::Pending)
    }

    /// Subscribe to call events
    pub fn subscribe_events(&self) -> broadcast::Receiver<CallEvent> {
        self.event_sender.subscribe()
    }

    /// Handle signaling events
    async fn handle_signaling_event(
        event: SignalingEvent,
        calls: &Arc<RwLock<HashMap<CallId, CallSession>>>,
        media: &Arc<MediaStreamManager>,
        event_sender: &broadcast::Sender<CallEvent>,
        _network_adapter: &Arc<NetworkAdapter>,
    ) -> Result<()> {
        match event {
            SignalingEvent::IncomingCall { offer } => {
                // Create call session for incoming call
                let mut session = CallSession::new(offer.call_id, MediaConstraints::audio_only());
                session.add_participant(UserHandle::from(offer.caller.to_string()));
                session.state = CallState::Calling;

                let mut calls = calls.write().await;
                calls.insert(offer.call_id, session);

                // Emit event
                let _ = event_sender.send(CallEvent::IncomingCall { offer });
            }
            SignalingEvent::AnswerReceived { answer } => {
                if answer.accepted {
                    // Update call state
                    let mut calls = calls.write().await;
                    if let Some(session) = calls.get_mut(&answer.call_id) {
                        session.state = CallState::Connecting;
                    }

                    // Emit event
                    let _ = event_sender.send(CallEvent::CallAccepted {
                        call_id: answer.call_id,
                        answer: answer.clone(),
                    });
                } else {
                    // Call was rejected
                    let mut calls = calls.write().await;
                    if let Some(session) = calls.get_mut(&answer.call_id) {
                        session.state = CallState::Failed;
                        session.end_time = Some(Utc::now());
                    }

                    let _ = event_sender.send(CallEvent::CallRejected {
                        call_id: answer.call_id,
                    });
                }
            }
            SignalingEvent::CallEnded { call_id } => {
                // Clean up call
                media.remove_stream(call_id).await?;

                let mut calls = calls.write().await;
                calls.remove(&call_id);

                let _ = event_sender.send(CallEvent::CallEnded { call_id });
            }
            SignalingEvent::CallRejected { call_id } => {
                let _ = event_sender.send(CallEvent::CallRejected { call_id });
            }
            SignalingEvent::ConnectionEstablishing { call_id } => {
                // QUIC connection being established
                debug!("QUIC connection establishing for call {}", call_id.0);
                let _ = event_sender.send(CallEvent::ConnectionEstablished { call_id });
            }
            _ => {
                debug!("Unhandled signaling event: {:?}", event);
            }
        }

        Ok(())
    }

    /// Handle media events
    async fn handle_media_event(
        event: MediaEvent,
        calls: &Arc<RwLock<HashMap<CallId, CallSession>>>,
        event_sender: &broadcast::Sender<CallEvent>,
    ) -> Result<()> {
        match event {
            MediaEvent::CaptureStarted { call_id } => {
                // Update call state when media starts
                let mut calls = calls.write().await;
                if let Some(session) = calls.get_mut(&call_id)
                    && session.state == CallState::Connecting
                {
                    session.state = CallState::Connected;

                    let _ = event_sender.send(CallEvent::ConnectionEstablished { call_id });
                }
            }
            MediaEvent::QualityAdapted {
                call_id, metrics, ..
            } => {
                // Add quality metrics to call session
                let mut calls = calls.write().await;
                if let Some(session) = calls.get_mut(&call_id) {
                    session.add_quality_metric(metrics.clone());
                }

                let _ = event_sender.send(CallEvent::QualityChanged { call_id, metrics });
            }
            _ => {
                debug!("Unhandled media event: {:?}", event);
            }
        }

        Ok(())
    }

    /// Generate SDP offer for media stream
    async fn generate_sdp_offer(&self, _stream: &super::media::MediaStream) -> Result<String> {
        // In production, generate real SDP offer
        Ok("v=0\r\no=- 123456789 987654321 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n...".to_string())
    }

    /// Generate SDP answer for media stream
    async fn generate_sdp_answer(&self, _stream: &super::media::MediaStream) -> Result<String> {
        // In production, generate real SDP answer
        Ok("v=0\r\no=- 987654321 123456789 IN IP4 192.168.1.1\r\ns=-\r\nt=0 0\r\n...".to_string())
    }

    /// Cleanup task for expired calls
    async fn cleanup_task(calls: Arc<RwLock<HashMap<CallId, CallSession>>>) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // 5 minutes

        loop {
            interval.tick().await;

            let now = Utc::now();
            let mut calls = calls.write().await;
            let initial_count = calls.len();

            // Remove calls older than 8 hours or in failed state for more than 1 hour
            calls.retain(|_, session| {
                let age =
                    now.signed_duration_since(session.start_time.unwrap_or(session.created_at));
                let max_age = Duration::hours(8);

                if age > max_age {
                    return false; // Too old
                }

                if session.state == CallState::Failed {
                    let failed_age =
                        now.signed_duration_since(session.end_time.unwrap_or(session.created_at));
                    return failed_age < Duration::hours(1);
                }

                true
            });

            let removed = initial_count - calls.len();
            if removed > 0 {
                info!("Cleaned up {} expired call sessions", removed);
            }
        }
    }
}

/// Network adapter for quality management
pub struct NetworkAdapter {
    quality_history: Arc<RwLock<Vec<CallQualityMetrics>>>,
}

impl Default for NetworkAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkAdapter {
    pub fn new() -> Self {
        Self {
            quality_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Adapt settings based on network quality
    pub async fn adapt(&self, metrics: CallQualityMetrics) -> Result<AdaptationSettings> {
        // Store metrics
        let mut history = self.quality_history.write().await;
        history.push(metrics.clone());

        // Keep only last 10 metrics
        if history.len() > 10 {
            history.remove(0);
        }

        // Determine adaptation based on current and recent metrics
        let settings = if metrics.needs_adaptation() {
            // Poor quality - reduce settings
            AdaptationSettings {
                video_bitrate_kbps: 400,
                video_resolution: VideoResolution::SD480,
                video_fps: 15,
                audio_bitrate_kbps: 32,
                enable_dtx: true,
            }
        } else if metrics.is_good_quality() {
            // Good quality - increase settings
            AdaptationSettings {
                video_bitrate_kbps: 1500,
                video_resolution: VideoResolution::HD720,
                video_fps: 30,
                audio_bitrate_kbps: 64,
                enable_dtx: false,
            }
        } else {
            // Medium quality - balanced settings
            AdaptationSettings {
                video_bitrate_kbps: 800,
                video_resolution: VideoResolution::SD480,
                video_fps: 24,
                audio_bitrate_kbps: 48,
                enable_dtx: true,
            }
        };

        Ok(settings)
    }
}

// CallEvent enum is now defined in types.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::core_engine::DhtCoreEngine;

    fn create_mock_dht() -> Arc<RwLock<DhtCoreEngine>> {
        // Mock DHT for testing
        unimplemented!("Mock DHT for testing")
    }

    #[tokio::test]
    #[ignore = "requires mock DHT and signaling"]
    async fn test_call_manager_creation() {
        let _identity = FourWordAddress::from("alice-bob-charlie-david");
        let _dht = create_mock_dht();

        // This test would require proper mocking of signaling and media components
        // For now, we'll skip the actual implementation
    }

    #[tokio::test]
    async fn test_network_adapter() {
        let adapter = NetworkAdapter::new();

        // Test good quality metrics
        let good_metrics = CallQualityMetrics {
            rtt_ms: 20,
            packet_loss_percent: 0.1,
            jitter_ms: 2,
            bandwidth_kbps: 2000,
            timestamp: Utc::now(),
        };

        let settings = adapter.adapt(good_metrics).await.unwrap();
        assert_eq!(settings.video_bitrate_kbps, 1500);
        assert_eq!(settings.video_resolution, VideoResolution::HD720);

        // Test poor quality metrics
        let poor_metrics = CallQualityMetrics {
            rtt_ms: 300,
            packet_loss_percent: 5.0,
            jitter_ms: 50,
            bandwidth_kbps: 200,
            timestamp: Utc::now(),
        };

        let settings = adapter.adapt(poor_metrics).await.unwrap();
        assert_eq!(settings.video_bitrate_kbps, 400);
        assert_eq!(settings.video_resolution, VideoResolution::SD480);
    }

    #[test]
    fn test_call_session() {
        let call_id = CallId::new();
        let constraints = MediaConstraints::video_call();

        let mut session = CallSession::new(call_id, constraints);

        assert_eq!(session.call_id, call_id);
        assert_eq!(session.state, CallState::Idle);
        assert!(session.participants.is_empty());

        // Test adding participant
        let participant =
            crate::messaging::user_handle::UserHandle::from("alice-bob-charlie-david");
        session.add_participant(participant.clone());
        assert_eq!(session.participants.len(), 1);
        assert!(session.participants.contains(&participant));

        // Test adding duplicate participant
        session.add_participant(participant.clone());
        assert_eq!(session.participants.len(), 1); // Should not duplicate

        // Test removing participant
        session.remove_participant(&participant);
        assert!(session.participants.is_empty());
    }
}
