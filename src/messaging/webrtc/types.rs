// WebRTC Types and Data Structures

use crate::identity::FourWordAddress;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a call
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CallId(pub Uuid);

impl CallId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for CallId {
    fn default() -> Self {
        Self::new()
    }
}

/// Media constraints for a call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaConstraints {
    pub audio: bool,
    pub video: bool,
    pub screen_share: bool,
}

impl MediaConstraints {
    pub fn audio_only() -> Self {
        Self {
            audio: true,
            video: false,
            screen_share: false,
        }
    }
    
    pub fn video_call() -> Self {
        Self {
            audio: true,
            video: true,
            screen_share: false,
        }
    }
    
    pub fn screen_share() -> Self {
        Self {
            audio: true,
            video: false,
            screen_share: true,
        }
    }
    
    pub fn has_audio(&self) -> bool {
        self.audio
    }
    
    pub fn has_video(&self) -> bool {
        self.video
    }
    
    pub fn has_screen_share(&self) -> bool {
        self.screen_share
    }
    
    pub fn to_media_types(&self) -> Vec<MediaType> {
        let mut types = Vec::new();
        if self.audio {
            types.push(MediaType::Audio);
        }
        if self.video {
            types.push(MediaType::Video);
        }
        if self.screen_share {
            types.push(MediaType::ScreenShare);
        }
        types
    }
}

/// Types of media in a call
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaType {
    Audio,
    Video,
    ScreenShare,
    DataChannel,
}

/// Call offer message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallOffer {
    pub call_id: CallId,
    pub caller: FourWordAddress,
    pub callee: FourWordAddress,
    pub sdp: String,
    pub media_types: Vec<MediaType>,
    pub timestamp: DateTime<Utc>,
}

/// Call answer message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallAnswer {
    pub call_id: CallId,
    pub sdp: String,
    pub accepted: bool,
    pub timestamp: DateTime<Utc>,
}

/// ICE candidate for WebRTC connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidate {
    pub call_id: CallId,
    pub candidate: String,
    pub sdp_mid: Option<String>,
    pub sdp_mline_index: Option<u32>,
}

/// Call state enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallState {
    Idle,
    Calling,
    Connecting,
    Connected,
    Ending,
    Failed,
}

/// Call quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallQualityMetrics {
    pub rtt_ms: u32,
    pub packet_loss_percent: f32,
    pub jitter_ms: u32,
    pub bandwidth_kbps: u32,
    pub timestamp: DateTime<Utc>,
}

impl CallQualityMetrics {
    pub fn is_good_quality(&self) -> bool {
        self.rtt_ms < 100 
            && self.packet_loss_percent < 1.0 
            && self.jitter_ms < 20
            && self.bandwidth_kbps > 500
    }
    
    pub fn needs_adaptation(&self) -> bool {
        self.rtt_ms > 200 
            || self.packet_loss_percent > 3.0 
            || self.jitter_ms > 40
            || self.bandwidth_kbps < 300
    }
}

/// Multi-party call information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiPartyCall {
    pub call_id: CallId,
    pub participants: Vec<FourWordAddress>,
    pub architecture: CallArchitecture,
    pub created_at: DateTime<Utc>,
}

/// Call architecture for multi-party calls
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallArchitecture {
    Mesh,  // Direct P2P between all participants (2-4 people)
    SFU,   // Selective Forwarding Unit (5+ people)
}

/// Recording consent management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingConsent {
    pub call_id: CallId,
    pub requester: FourWordAddress,
    pub participants: Vec<FourWordAddress>,
}

/// Consent status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentStatus {
    Pending,
    Granted,
    Denied,
    Revoked,
}

/// Network adaptation settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptationSettings {
    pub video_bitrate_kbps: u32,
    pub video_resolution: VideoResolution,
    pub video_fps: u32,
    pub audio_bitrate_kbps: u32,
    pub enable_dtx: bool,  // Discontinuous transmission
}

/// Video resolution options
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VideoResolution {
    QVGA240,   // 320x240
    SD480,     // 640x480
    HD720,     // 1280x720
    HD1080,    // 1920x1080
}

impl VideoResolution {
    pub fn width(&self) -> u32 {
        match self {
            VideoResolution::QVGA240 => 320,
            VideoResolution::SD480 => 640,
            VideoResolution::HD720 => 1280,
            VideoResolution::HD1080 => 1920,
        }
    }
    
    pub fn height(&self) -> u32 {
        match self {
            VideoResolution::QVGA240 => 240,
            VideoResolution::SD480 => 480,
            VideoResolution::HD720 => 720,
            VideoResolution::HD1080 => 1080,
        }
    }
}

/// P2P Foundation native QUIC connectivity configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeQuicConfiguration {
    /// DHT-based peer discovery is enabled by default
    pub dht_discovery: bool,
    /// Coordinator-based hole punching configuration
    pub hole_punching: bool,
}

impl Default for NativeQuicConfiguration {
    fn default() -> Self {
        Self {
            dht_discovery: true,
            hole_punching: true,
        }
    }
}

/// WebRTC signaling message wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignalingMessage {
    Offer(CallOffer),
    Answer(CallAnswer),
    CallEnd { call_id: CallId },
    CallReject { call_id: CallId },
}

/// Call event for notifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CallEvent {
    IncomingCall {
        offer: CallOffer,
    },
    CallInitiated {
        call_id: CallId,
        callee: FourWordAddress,
        constraints: MediaConstraints,
    },
    CallAccepted {
        call_id: CallId,
        answer: CallAnswer,
    },
    CallRejected {
        call_id: CallId,
    },
    CallEnded {
        call_id: CallId,
    },
    ConnectionEstablished {
        call_id: CallId,
    },
    ConnectionFailed {
        call_id: CallId,
        error: String,
    },
    QualityChanged {
        call_id: CallId,
        metrics: CallQualityMetrics,
    },
}

/// Call session information
#[derive(Debug, Clone)]
pub struct CallSession {
    pub call_id: CallId,
    pub participants: Vec<FourWordAddress>,
    pub state: CallState,
    pub media_constraints: MediaConstraints,
    pub created_at: DateTime<Utc>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub quality_metrics: Vec<CallQualityMetrics>,
}

impl CallSession {
    pub fn new(call_id: CallId, constraints: MediaConstraints) -> Self {
        Self {
            call_id,
            participants: Vec::new(),
            state: CallState::Idle,
            media_constraints: constraints,
            created_at: Utc::now(),
            start_time: None,
            end_time: None,
            quality_metrics: Vec::new(),
        }
    }
    
    pub fn duration(&self) -> Option<chrono::Duration> {
        if let (Some(start), Some(end)) = (self.start_time, self.end_time) {
            Some(end - start)
        } else { self.start_time.map(|start| Utc::now() - start) }
    }
    
    pub fn add_participant(&mut self, participant: FourWordAddress) {
        if !self.participants.contains(&participant) {
            self.participants.push(participant);
        }
    }
    
    pub fn remove_participant(&mut self, participant: &FourWordAddress) {
        self.participants.retain(|p| p != participant);
    }
    
    pub fn add_quality_metric(&mut self, metric: CallQualityMetrics) {
        self.quality_metrics.push(metric);
        
        // Keep only last 100 metrics
        if self.quality_metrics.len() > 100 {
            self.quality_metrics.remove(0);
        }
    }
    
    pub fn latest_quality(&self) -> Option<&CallQualityMetrics> {
        self.quality_metrics.last()
    }
}