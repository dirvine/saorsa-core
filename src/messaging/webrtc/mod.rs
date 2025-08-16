// WebRTC Module for Voice and Video Calling
// Main module that orchestrates signaling, media, and call management
//
// ## Native QUIC Transport
//
// This WebRTC implementation uses native QUIC connectivity instead of traditional ICE/STUN/TURN:
// - **DHT-based peer discovery**: Uses the distributed hash table for finding peer endpoints
// - **Coordinator-based hole punching**: ant-quic handles NAT traversal without STUN servers
// - **Reliable media transport**: QUIC streams provide ordered, reliable delivery for WebRTC media
// - **Better performance**: Lower latency and improved congestion control compared to UDP
//
// The signaling still uses standard WebRTC SDP for codec negotiation, but connection
// establishment bypasses ICE candidates in favor of direct QUIC connections.

pub mod call_manager;
pub mod media;
pub mod signaling;
pub mod types;

pub use call_manager::{CallManager, NetworkAdapter};
pub use media::{
    AudioDevice, AudioTrack, MediaEvent, MediaStream, MediaStreamManager, VideoDevice, VideoTrack,
};
pub use signaling::{SignalingEvent, SignalingHandler, SignalingSession, SignalingState};
pub use types::*;

use crate::dht::core_engine::DhtCoreEngine;
use crate::identity::FourWordAddress;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tracing::info;

/// Main WebRTC service that coordinates all components
pub struct WebRtcService {
    /// Local peer identity
    local_identity: FourWordAddress,
    /// Signaling handler for offer/answer exchange
    signaling: Arc<SignalingHandler>,
    /// Media stream manager
    media: Arc<MediaStreamManager>,
    /// Call manager for high-level call operations
    call_manager: Arc<CallManager>,
    /// Event broadcaster for WebRTC events
    event_sender: broadcast::Sender<WebRtcEvent>,
}

impl WebRtcService {
    /// Create new WebRTC service
    pub async fn new(
        local_identity: FourWordAddress,
        dht_client: Arc<RwLock<DhtCoreEngine>>,
    ) -> Result<Self> {
        let (event_sender, _) = broadcast::channel(1000);

        // Initialize signaling
        let signaling = Arc::new(SignalingHandler::new(
            local_identity.clone(),
            Arc::clone(&dht_client),
        ));

        // Initialize media manager
        let media = Arc::new(MediaStreamManager::new(local_identity.clone()));

        // Initialize call manager
        let call_manager = Arc::new(
            CallManager::new(
                local_identity.clone(),
                Arc::clone(&signaling),
                Arc::clone(&media),
            )
            .await?,
        );

        Ok(Self {
            local_identity,
            signaling,
            media,
            call_manager,
            event_sender,
        })
    }

    /// Start the WebRTC service
    pub async fn start(&self) -> Result<()> {
        info!("Starting WebRTC service for {}", self.local_identity);

        // Start signaling service
        self.signaling.start().await?;

        // Initialize media devices
        self.media.initialize().await?;

        // Start call manager
        self.call_manager.start().await?;

        // Start event forwarding
        self.start_event_forwarding().await;

        info!("WebRTC service started successfully");
        Ok(())
    }

    /// Initiate a call to another peer
    pub async fn initiate_call(
        &self,
        callee: FourWordAddress,
        constraints: MediaConstraints,
    ) -> Result<CallId> {
        self.call_manager.initiate_call(callee, constraints).await
    }

    /// Accept an incoming call
    pub async fn accept_call(&self, call_id: CallId, constraints: MediaConstraints) -> Result<()> {
        self.call_manager.accept_call(call_id, constraints).await
    }

    /// Reject an incoming call
    pub async fn reject_call(&self, call_id: CallId) -> Result<()> {
        self.call_manager.reject_call(call_id).await
    }

    /// End an active call
    pub async fn end_call(&self, call_id: CallId) -> Result<()> {
        self.call_manager.end_call(call_id).await
    }

    /// Get call state
    pub async fn get_call_state(&self, call_id: CallId) -> Option<CallState> {
        self.call_manager.get_call_state(call_id).await
    }

    /// Subscribe to WebRTC events
    pub fn subscribe_events(&self) -> broadcast::Receiver<WebRtcEvent> {
        self.event_sender.subscribe()
    }

    /// Get signaling handler reference
    pub fn signaling(&self) -> &Arc<SignalingHandler> {
        &self.signaling
    }

    /// Get media manager reference
    pub fn media(&self) -> &Arc<MediaStreamManager> {
        &self.media
    }

    /// Get call manager reference
    pub fn call_manager(&self) -> &Arc<CallManager> {
        &self.call_manager
    }

    /// Start event forwarding from sub-components
    async fn start_event_forwarding(&self) {
        let event_sender = self.event_sender.clone();

        // Forward signaling events
        let mut signaling_events = self.signaling.subscribe_events();
        let signaling_sender = event_sender.clone();
        tokio::spawn(async move {
            while let Ok(event) = signaling_events.recv().await {
                let webrtc_event = WebRtcEvent::Signaling(event);
                if signaling_sender.send(webrtc_event).is_err() {
                    break; // No more receivers
                }
            }
        });

        // Forward media events
        let mut media_events = self.media.subscribe_events();
        let media_sender = event_sender.clone();
        tokio::spawn(async move {
            while let Ok(event) = media_events.recv().await {
                let webrtc_event = WebRtcEvent::Media(event);
                if media_sender.send(webrtc_event).is_err() {
                    break; // No more receivers
                }
            }
        });

        // Forward call events
        let mut call_events = self.call_manager.subscribe_events();
        let call_sender = event_sender;
        tokio::spawn(async move {
            while let Ok(event) = call_events.recv().await {
                let webrtc_event = WebRtcEvent::Call(event);
                if call_sender.send(webrtc_event).is_err() {
                    break; // No more receivers
                }
            }
        });
    }
}

/// Top-level WebRTC events
#[derive(Debug, Clone)]
pub enum WebRtcEvent {
    /// Signaling-related events
    Signaling(SignalingEvent),
    /// Media-related events
    Media(MediaEvent),
    /// Call management events
    Call(CallEvent),
}

/// WebRTC configuration
#[derive(Debug, Clone)]
pub struct WebRtcConfig {
    /// Native QUIC connectivity configuration
    pub quic_config: NativeQuicConfiguration,
    /// Default media constraints
    pub default_constraints: MediaConstraints,
    /// Enable echo cancellation
    pub echo_cancellation: bool,
    /// Enable noise suppression
    pub noise_suppression: bool,
    /// Enable automatic gain control
    pub auto_gain_control: bool,
    /// Maximum call duration (for cleanup)
    pub max_call_duration_hours: u32,
}

impl Default for WebRtcConfig {
    fn default() -> Self {
        Self {
            quic_config: NativeQuicConfiguration::default(),
            default_constraints: MediaConstraints::audio_only(),
            echo_cancellation: true,
            noise_suppression: true,
            auto_gain_control: true,
            max_call_duration_hours: 8,
        }
    }
}

/// WebRTC service builder for easier configuration
pub struct WebRtcServiceBuilder {
    identity: FourWordAddress,
    dht_client: Arc<RwLock<DhtCoreEngine>>,
    config: WebRtcConfig,
}

impl WebRtcServiceBuilder {
    /// Create new builder
    pub fn new(identity: FourWordAddress, dht_client: Arc<RwLock<DhtCoreEngine>>) -> Self {
        Self {
            identity,
            dht_client,
            config: WebRtcConfig::default(),
        }
    }

    /// Set native QUIC configuration
    pub fn with_quic_config(mut self, quic_config: NativeQuicConfiguration) -> Self {
        self.config.quic_config = quic_config;
        self
    }

    /// Set default media constraints
    pub fn with_default_constraints(mut self, constraints: MediaConstraints) -> Self {
        self.config.default_constraints = constraints;
        self
    }

    /// Enable/disable echo cancellation
    pub fn with_echo_cancellation(mut self, enabled: bool) -> Self {
        self.config.echo_cancellation = enabled;
        self
    }

    /// Enable/disable noise suppression
    pub fn with_noise_suppression(mut self, enabled: bool) -> Self {
        self.config.noise_suppression = enabled;
        self
    }

    /// Build the WebRTC service
    pub async fn build(self) -> Result<WebRtcService> {
        let service = WebRtcService::new(self.identity, self.dht_client).await?;

        // Apply configuration
        // In production, this would configure the sub-components with the settings

        Ok(service)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod basic_tests {
    use super::*;
    use std::sync::Arc;

    // Mock DHT for testing
    struct MockDhtEngine;

    impl MockDhtEngine {
        fn new() -> Self {
            Self
        }
    }

    fn create_mock_dht() -> Arc<RwLock<DhtCoreEngine>> {
        // In real tests, we would create a proper mock
        // For now, this is a placeholder
        unimplemented!("Mock DHT for testing")
    }

    #[tokio::test]
    #[ignore = "requires mock DHT implementation"]
    async fn test_webrtc_service_creation() {
        let identity = FourWordAddress::from("alice-bob-charlie-david");
        let dht = create_mock_dht();

        let service = WebRtcService::new(identity, dht).await;
        assert!(service.is_ok());
    }

    #[tokio::test]
    #[ignore = "requires mock DHT implementation"]
    async fn test_webrtc_service_builder() {
        let identity = FourWordAddress::from("alice-bob-charlie-david");
        let dht = create_mock_dht();

        let service = WebRtcServiceBuilder::new(identity, dht)
            .with_echo_cancellation(true)
            .with_noise_suppression(true)
            .with_default_constraints(MediaConstraints::video_call())
            .build()
            .await;

        assert!(service.is_ok());
    }

    #[test]
    fn test_webrtc_config_default() {
        let config = WebRtcConfig::default();

        assert!(config.echo_cancellation);
        assert!(config.noise_suppression);
        assert!(config.auto_gain_control);
        assert_eq!(config.max_call_duration_hours, 8);
        assert!(config.quic_config.dht_discovery);
        assert!(config.quic_config.hole_punching);
    }

    #[test]
    fn test_webrtc_events() {
        // Test event enum variants exist
        let _signaling_event = WebRtcEvent::Signaling(SignalingEvent::CallEnded {
            call_id: CallId::new(),
        });

        // Other event types would be tested similarly
    }
}
