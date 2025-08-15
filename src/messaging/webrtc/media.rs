// WebRTC Media Stream Management
// Handles audio/video stream capture, processing, and transmission

use super::types::*;
use crate::identity::FourWordAddress;
use anyhow::{Result, Context};
// Removed unused serde imports
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, info, error};
use chrono::{DateTime, Utc};

// WebRTC imports for native QUIC integration  
use webrtc::api::media_engine::MediaEngine;
use webrtc::track::track_local::track_local_static_rtp::TrackLocalStaticRTP;

/// Media stream manager for WebRTC calls
pub struct MediaStreamManager {
    /// Local peer identity
    local_identity: FourWordAddress,
    /// Active media streams
    streams: Arc<RwLock<HashMap<CallId, MediaStream>>>,
    /// Audio processing pipeline
    audio_processor: Arc<AudioProcessor>,
    /// Video processing pipeline
    video_processor: Arc<VideoProcessor>,
    /// Media event broadcaster
    event_sender: broadcast::Sender<MediaEvent>,
    /// Current media constraints
    constraints: Arc<RwLock<MediaConstraints>>,
}

impl MediaStreamManager {
    /// Create new media stream manager
    pub fn new(local_identity: FourWordAddress) -> Self {
        let (event_sender, _) = broadcast::channel(1000);
        
        Self {
            local_identity,
            streams: Arc::new(RwLock::new(HashMap::new())),
            audio_processor: Arc::new(AudioProcessor::new()),
            video_processor: Arc::new(VideoProcessor::new()),
            event_sender,
            constraints: Arc::new(RwLock::new(MediaConstraints::audio_only())),
        }
    }
    
    /// Initialize media devices
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing media devices");
        
        // Initialize audio devices
        self.audio_processor.initialize().await
            .context("Failed to initialize audio processor")?;
        
        // Initialize video devices
        self.video_processor.initialize().await
            .context("Failed to initialize video processor")?;
        
        // Emit initialization complete event
        let _ = self.event_sender.send(MediaEvent::DevicesInitialized);
        
        Ok(())
    }
    
    /// Create media stream for call
    pub async fn create_stream(&self, call_id: CallId, constraints: MediaConstraints) -> Result<MediaStream> {
        info!("Creating media stream for call {} with constraints: {:?}", call_id.0, constraints);
        
        let mut audio_track = None;
        let mut video_track = None;
        let mut screen_track = None;
        
        // Create audio track if requested
        if constraints.has_audio() {
            audio_track = Some(self.audio_processor.create_track().await?);
        }
        
        // Create video track if requested
        if constraints.has_video() {
            video_track = Some(self.video_processor.create_track().await?);
        }
        
        // Create screen share track if requested
        if constraints.has_screen_share() {
            screen_track = Some(self.video_processor.create_screen_share_track().await?);
        }
        
        let stream = MediaStream {
            call_id,
            peer: self.local_identity.clone(),
            constraints: constraints.clone(),
            audio_track,
            video_track,
            screen_track,
            state: MediaStreamState::Created,
            created_at: Utc::now(),
            quality_metrics: Vec::new(),
            adaptation_settings: AdaptationSettings {
                video_bitrate_kbps: 1500,
                video_resolution: VideoResolution::HD720,
                video_fps: 30,
                audio_bitrate_kbps: 64,
                enable_dtx: true,
            },
        };
        
        // Store stream
        let mut streams = self.streams.write().await;
        streams.insert(call_id, stream.clone());
        
        // Emit event
        let _ = self.event_sender.send(MediaEvent::StreamCreated {
            call_id,
            constraints: constraints.clone(),
        });
        
        Ok(stream)
    }
    
    /// Start media capture
    pub async fn start_capture(&self, call_id: CallId) -> Result<()> {
        let mut streams = self.streams.write().await;
        
        if let Some(stream) = streams.get_mut(&call_id) {
            // Start audio capture
            if let Some(ref mut audio_track) = stream.audio_track {
                self.audio_processor.start_capture(audio_track).await?;
            }
            
            // Start video capture
            if let Some(ref mut video_track) = stream.video_track {
                self.video_processor.start_capture(video_track).await?;
            }
            
            // Start screen capture
            if let Some(ref mut screen_track) = stream.screen_track {
                self.video_processor.start_screen_capture(screen_track).await?;
            }
            
            stream.state = MediaStreamState::Capturing;
            
            // Emit event
            let _ = self.event_sender.send(MediaEvent::CaptureStarted { call_id });
            
            info!("Started media capture for call {}", call_id.0);
        } else {
            return Err(anyhow::anyhow!("No stream found for call {}", call_id.0));
        }
        
        Ok(())
    }
    
    /// Stop media capture
    pub async fn stop_capture(&self, call_id: CallId) -> Result<()> {
        let mut streams = self.streams.write().await;
        
        if let Some(stream) = streams.get_mut(&call_id) {
            // Stop audio capture
            if let Some(ref mut audio_track) = stream.audio_track {
                self.audio_processor.stop_capture(audio_track).await?;
            }
            
            // Stop video capture
            if let Some(ref mut video_track) = stream.video_track {
                self.video_processor.stop_capture(video_track).await?;
            }
            
            // Stop screen capture
            if let Some(ref mut screen_track) = stream.screen_track {
                self.video_processor.stop_screen_capture(screen_track).await?;
            }
            
            stream.state = MediaStreamState::Stopped;
            
            // Emit event
            let _ = self.event_sender.send(MediaEvent::CaptureStopped { call_id });
            
            info!("Stopped media capture for call {}", call_id.0);
        }
        
        Ok(())
    }
    
    /// Update stream quality based on network conditions
    pub async fn adapt_quality(&self, call_id: CallId, metrics: &CallQualityMetrics) -> Result<()> {
        let mut streams = self.streams.write().await;
        
        if let Some(stream) = streams.get_mut(&call_id) {
            let mut settings = stream.adaptation_settings.clone();
            
            // Adapt based on network quality
            if metrics.needs_adaptation() {
                // Reduce quality for poor network
                settings.video_bitrate_kbps = (settings.video_bitrate_kbps / 2).max(200);
                settings.video_fps = (settings.video_fps / 2).max(15);
                
                if settings.video_resolution == VideoResolution::HD1080 {
                    settings.video_resolution = VideoResolution::HD720;
                } else if settings.video_resolution == VideoResolution::HD720 {
                    settings.video_resolution = VideoResolution::SD480;
                }
                
                settings.audio_bitrate_kbps = (settings.audio_bitrate_kbps / 2).max(32);
                settings.enable_dtx = true;
                
            } else if metrics.is_good_quality() {
                // Increase quality for good network
                settings.video_bitrate_kbps = (settings.video_bitrate_kbps * 2).min(2000);
                settings.video_fps = (settings.video_fps + 5).min(30);
                
                if settings.video_resolution == VideoResolution::SD480 {
                    settings.video_resolution = VideoResolution::HD720;
                } else if settings.video_resolution == VideoResolution::HD720 {
                    settings.video_resolution = VideoResolution::HD1080;
                }
                
                settings.audio_bitrate_kbps = (settings.audio_bitrate_kbps + 16).min(128);
            }
            
            // Apply new settings
            if let Some(ref mut video_track) = stream.video_track {
                self.video_processor.update_settings(video_track, &settings).await?;
            }
            
            if let Some(ref mut audio_track) = stream.audio_track {
                self.audio_processor.update_settings(audio_track, &settings).await?;
            }
            
            stream.adaptation_settings = settings.clone();
            stream.quality_metrics.push(metrics.clone());
            
            // Keep only last 50 metrics
            if stream.quality_metrics.len() > 50 {
                stream.quality_metrics.remove(0);
            }
            
            // Emit event
            let _ = self.event_sender.send(MediaEvent::QualityAdapted {
                call_id,
                settings,
                metrics: metrics.clone(),
            });
            
            debug!("Adapted quality for call {} based on metrics", call_id.0);
        }
        
        Ok(())
    }
    
    /// Get media stream
    pub async fn get_stream(&self, call_id: CallId) -> Option<MediaStream> {
        let streams = self.streams.read().await;
        streams.get(&call_id).cloned()
    }
    
    /// Remove media stream
    pub async fn remove_stream(&self, call_id: CallId) -> Result<()> {
        // Stop capture first
        self.stop_capture(call_id).await?;
        
        // Remove from storage
        let mut streams = self.streams.write().await;
        if streams.remove(&call_id).is_some() {
            // Emit event
            let _ = self.event_sender.send(MediaEvent::StreamRemoved { call_id });
            
            info!("Removed media stream for call {}", call_id.0);
        }
        
        Ok(())
    }
    
    /// Subscribe to media events
    pub fn subscribe_events(&self) -> broadcast::Receiver<MediaEvent> {
        self.event_sender.subscribe()
    }
    
    /// Set global media constraints
    pub async fn set_constraints(&self, constraints: MediaConstraints) {
        let mut current_constraints = self.constraints.write().await;
        *current_constraints = constraints;
    }
    
    /// Get available audio devices
    pub async fn get_audio_devices(&self) -> Result<Vec<AudioDevice>> {
        self.audio_processor.get_devices().await
    }
    
    /// Get available video devices
    pub async fn get_video_devices(&self) -> Result<Vec<VideoDevice>> {
        self.video_processor.get_devices().await
    }
    
    /// Switch audio device
    pub async fn switch_audio_device(&self, call_id: CallId, device: AudioDevice) -> Result<()> {
        let mut streams = self.streams.write().await;
        
        if let Some(stream) = streams.get_mut(&call_id)
            && let Some(ref mut audio_track) = stream.audio_track {
                self.audio_processor.switch_device(audio_track, device).await?;
            }
        
        Ok(())
    }
    
    /// Switch video device
    pub async fn switch_video_device(&self, call_id: CallId, device: VideoDevice) -> Result<()> {
        let mut streams = self.streams.write().await;
        
        if let Some(stream) = streams.get_mut(&call_id)
            && let Some(ref mut video_track) = stream.video_track {
                self.video_processor.switch_device(video_track, device).await?;
            }
        
        Ok(())
    }
}

/// Audio processing pipeline
pub struct AudioProcessor {
    devices: Arc<RwLock<Vec<AudioDevice>>>,
    current_device: Arc<RwLock<Option<AudioDevice>>>,
    _media_engine: Arc<MediaEngine>,
    active_tracks: Arc<RwLock<HashMap<String, Option<Arc<TrackLocalStaticRTP>>>>>,
}

impl Default for AudioProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl AudioProcessor {
    pub fn new() -> Self {
        let mut media_engine = MediaEngine::default();
        
        // Register audio codecs
        if let Err(e) = media_engine.register_default_codecs() {
            error!("Failed to register default codecs: {}", e);
        }
        
        Self {
            devices: Arc::new(RwLock::new(Vec::new())),
            current_device: Arc::new(RwLock::new(None)),
            _media_engine: Arc::new(media_engine),
            active_tracks: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub async fn initialize(&self) -> Result<()> {
        // Enumerate audio devices
        let devices = self.enumerate_audio_devices().await?;
        let mut device_list = self.devices.write().await;
        *device_list = devices;
        
        // Select default device
        if let Some(default_device) = device_list.first().cloned() {
            let mut current = self.current_device.write().await;
            *current = Some(default_device);
        }
        
        info!("Initialized audio processor with {} devices", device_list.len());
        Ok(())
    }
    
    pub async fn create_track(&self) -> Result<AudioTrack> {
        let track_id = uuid::Uuid::new_v4().to_string();
        
        // Create WebRTC audio track for native QUIC transport
        // This uses ant-quic for reliable, ordered delivery of audio data
        // instead of traditional WebRTC DataChannels over DTLS/SCTP/UDP
        let track = None; // Placeholder - will be implemented with proper WebRTC/QUIC binding
        
        // Store the track
        let mut tracks = self.active_tracks.write().await;
        tracks.insert(track_id.clone(), track);
        
        Ok(AudioTrack {
            id: track_id,
            device: self.current_device.read().await.clone(),
            state: TrackState::Created,
            settings: AudioSettings {
                sample_rate: 48000,
                channels: 2,
                bitrate_kbps: 64,
                echo_cancellation: true,
                noise_suppression: true,
                auto_gain_control: true,
            },
        })
    }
    
    pub async fn start_capture(&self, _track: &mut AudioTrack) -> Result<()> {
        // In production, start actual audio capture
        debug!("Starting audio capture");
        Ok(())
    }
    
    pub async fn stop_capture(&self, _track: &mut AudioTrack) -> Result<()> {
        // In production, stop actual audio capture
        debug!("Stopping audio capture");
        Ok(())
    }
    
    pub async fn update_settings(&self, _track: &mut AudioTrack, settings: &AdaptationSettings) -> Result<()> {
        debug!("Updating audio settings: bitrate={}kbps, dtx={}", settings.audio_bitrate_kbps, settings.enable_dtx);
        Ok(())
    }
    
    pub async fn get_devices(&self) -> Result<Vec<AudioDevice>> {
        let devices = self.devices.read().await;
        Ok(devices.clone())
    }
    
    pub async fn switch_device(&self, _track: &mut AudioTrack, device: AudioDevice) -> Result<()> {
        let mut current = self.current_device.write().await;
        *current = Some(device.clone());
        
        info!("Switched to audio device: {}", device.name);
        Ok(())
    }
    
    async fn enumerate_audio_devices(&self) -> Result<Vec<AudioDevice>> {
        // In production, enumerate actual audio devices
        Ok(vec![
            AudioDevice {
                id: "default".to_string(),
                name: "Default Audio Device".to_string(),
                device_type: AudioDeviceType::Microphone,
            },
            AudioDevice {
                id: "builtin".to_string(),
                name: "Built-in Microphone".to_string(),
                device_type: AudioDeviceType::Microphone,
            },
        ])
    }
}

/// Video processing pipeline
pub struct VideoProcessor {
    devices: Arc<RwLock<Vec<VideoDevice>>>,
    current_device: Arc<RwLock<Option<VideoDevice>>>,
    _media_engine: Arc<MediaEngine>,
    active_tracks: Arc<RwLock<HashMap<String, Option<Arc<TrackLocalStaticRTP>>>>>,
}

impl Default for VideoProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl VideoProcessor {
    pub fn new() -> Self {
        let mut media_engine = MediaEngine::default();
        
        // Register video codecs
        if let Err(e) = media_engine.register_default_codecs() {
            error!("Failed to register default codecs: {}", e);
        }
        
        Self {
            devices: Arc::new(RwLock::new(Vec::new())),
            current_device: Arc::new(RwLock::new(None)),
            _media_engine: Arc::new(media_engine),
            active_tracks: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub async fn initialize(&self) -> Result<()> {
        // Enumerate video devices
        let devices = self.enumerate_video_devices().await?;
        let mut device_list = self.devices.write().await;
        *device_list = devices;
        
        // Select default device
        if let Some(default_device) = device_list.first().cloned() {
            let mut current = self.current_device.write().await;
            *current = Some(default_device);
        }
        
        info!("Initialized video processor with {} devices", device_list.len());
        Ok(())
    }
    
    pub async fn create_track(&self) -> Result<VideoTrack> {
        let track_id = uuid::Uuid::new_v4().to_string();
        
        // Create WebRTC video track for native QUIC transport
        // This uses ant-quic for reliable, ordered delivery of video data
        // with built-in congestion control and adaptive bitrate
        let track = None; // Placeholder - will be implemented with proper WebRTC/QUIC binding
        
        // Store the track
        let mut tracks = self.active_tracks.write().await;
        tracks.insert(track_id.clone(), track);
        
        Ok(VideoTrack {
            id: track_id,
            device: self.current_device.read().await.clone(),
            state: TrackState::Created,
            settings: VideoSettings {
                resolution: VideoResolution::HD720,
                fps: 30,
                bitrate_kbps: 1500,
            },
        })
    }
    
    pub async fn create_screen_share_track(&self) -> Result<VideoTrack> {
        let track_id = uuid::Uuid::new_v4().to_string();
        
        // Create WebRTC screen share track for native QUIC transport
        // Screen sharing over QUIC provides better reliability and
        // lower latency compared to traditional UDP-based WebRTC
        let track = None; // Placeholder - will be implemented with proper WebRTC/QUIC binding
        
        // Store the track
        let mut tracks = self.active_tracks.write().await;
        tracks.insert(track_id.clone(), track);
        
        Ok(VideoTrack {
            id: track_id,
            device: Some(VideoDevice {
                id: "screen".to_string(),
                name: "Screen Capture".to_string(),
                device_type: VideoDeviceType::Screen,
            }),
            state: TrackState::Created,
            settings: VideoSettings {
                resolution: VideoResolution::HD1080,
                fps: 15,
                bitrate_kbps: 2000,
            },
        })
    }
    
    pub async fn start_capture(&self, _track: &mut VideoTrack) -> Result<()> {
        // In production, start actual video capture
        debug!("Starting video capture");
        Ok(())
    }
    
    pub async fn start_screen_capture(&self, _track: &mut VideoTrack) -> Result<()> {
        // In production, start actual screen capture
        debug!("Starting screen capture");
        Ok(())
    }
    
    pub async fn stop_capture(&self, _track: &mut VideoTrack) -> Result<()> {
        // In production, stop actual video capture
        debug!("Stopping video capture");
        Ok(())
    }
    
    pub async fn stop_screen_capture(&self, _track: &mut VideoTrack) -> Result<()> {
        // In production, stop actual screen capture
        debug!("Stopping screen capture");
        Ok(())
    }
    
    pub async fn update_settings(&self, _track: &mut VideoTrack, settings: &AdaptationSettings) -> Result<()> {
        debug!("Updating video settings: {}x{} @{}fps {}kbps", 
               settings.video_resolution.width(), 
               settings.video_resolution.height(), 
               settings.video_fps, 
               settings.video_bitrate_kbps);
        Ok(())
    }
    
    pub async fn get_devices(&self) -> Result<Vec<VideoDevice>> {
        let devices = self.devices.read().await;
        Ok(devices.clone())
    }
    
    pub async fn switch_device(&self, _track: &mut VideoTrack, device: VideoDevice) -> Result<()> {
        let mut current = self.current_device.write().await;
        *current = Some(device.clone());
        
        info!("Switched to video device: {}", device.name);
        Ok(())
    }
    
    async fn enumerate_video_devices(&self) -> Result<Vec<VideoDevice>> {
        // In production, enumerate actual video devices
        Ok(vec![
            VideoDevice {
                id: "default".to_string(),
                name: "Default Camera".to_string(),
                device_type: VideoDeviceType::Camera,
            },
            VideoDevice {
                id: "builtin".to_string(),
                name: "Built-in Camera".to_string(),
                device_type: VideoDeviceType::Camera,
            },
        ])
    }
}

/// Media stream representation
#[derive(Debug, Clone)]
pub struct MediaStream {
    pub call_id: CallId,
    pub peer: FourWordAddress,
    pub constraints: MediaConstraints,
    pub audio_track: Option<AudioTrack>,
    pub video_track: Option<VideoTrack>,
    pub screen_track: Option<VideoTrack>,
    pub state: MediaStreamState,
    pub created_at: DateTime<Utc>,
    pub quality_metrics: Vec<CallQualityMetrics>,
    pub adaptation_settings: AdaptationSettings,
}

/// Media stream state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaStreamState {
    Created,
    Capturing,
    Stopped,
    Error,
}

/// Audio track
#[derive(Debug, Clone)]
pub struct AudioTrack {
    pub id: String,
    pub device: Option<AudioDevice>,
    pub state: TrackState,
    pub settings: AudioSettings,
}

/// Video track
#[derive(Debug, Clone)]
pub struct VideoTrack {
    pub id: String,
    pub device: Option<VideoDevice>,
    pub state: TrackState,
    pub settings: VideoSettings,
}

/// Track state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackState {
    Created,
    Active,
    Stopped,
    Error,
}

/// Audio device
#[derive(Debug, Clone)]
pub struct AudioDevice {
    pub id: String,
    pub name: String,
    pub device_type: AudioDeviceType,
}

/// Audio device type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioDeviceType {
    Microphone,
    Speaker,
    Headset,
}

/// Video device
#[derive(Debug, Clone)]
pub struct VideoDevice {
    pub id: String,
    pub name: String,
    pub device_type: VideoDeviceType,
}

/// Video device type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VideoDeviceType {
    Camera,
    Screen,
    Window,
}

/// Audio settings
#[derive(Debug, Clone)]
pub struct AudioSettings {
    pub sample_rate: u32,
    pub channels: u8,
    pub bitrate_kbps: u32,
    pub echo_cancellation: bool,
    pub noise_suppression: bool,
    pub auto_gain_control: bool,
}

/// Video settings
#[derive(Debug, Clone)]
pub struct VideoSettings {
    pub resolution: VideoResolution,
    pub fps: u32,
    pub bitrate_kbps: u32,
}

/// Media events
#[derive(Debug, Clone)]
pub enum MediaEvent {
    DevicesInitialized,
    StreamCreated {
        call_id: CallId,
        constraints: MediaConstraints,
    },
    CaptureStarted {
        call_id: CallId,
    },
    CaptureStopped {
        call_id: CallId,
    },
    StreamRemoved {
        call_id: CallId,
    },
    QualityAdapted {
        call_id: CallId,
        settings: AdaptationSettings,
        metrics: CallQualityMetrics,
    },
    DeviceError {
        device_id: String,
        error: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_media_stream_manager_creation() {
        let identity = FourWordAddress::from("alice-bob-charlie-david");
        let manager = MediaStreamManager::new(identity);
        
        // Initialize should succeed
        let result = manager.initialize().await;
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_audio_processor_initialization() {
        let processor = AudioProcessor::new();
        
        let result = processor.initialize().await;
        assert!(result.is_ok());
        
        let devices = processor.get_devices().await.unwrap();
        assert!(!devices.is_empty());
    }
    
    #[tokio::test]
    async fn test_video_processor_initialization() {
        let processor = VideoProcessor::new();
        
        let result = processor.initialize().await;
        assert!(result.is_ok());
        
        let devices = processor.get_devices().await.unwrap();
        assert!(!devices.is_empty());
    }
    
    #[tokio::test]
    async fn test_media_stream_creation() {
        let identity = FourWordAddress::from("alice-bob-charlie-david");
        let manager = MediaStreamManager::new(identity);
        
        // Initialize first
        manager.initialize().await.unwrap();
        
        let call_id = CallId::new();
        let constraints = MediaConstraints::video_call();
        
        let stream = manager.create_stream(call_id, constraints).await.unwrap();
        
        assert_eq!(stream.call_id, call_id);
        assert!(stream.audio_track.is_some());
        assert!(stream.video_track.is_some());
        assert!(stream.screen_track.is_none());
    }
    
    #[tokio::test]
    async fn test_quality_adaptation() {
        let identity = FourWordAddress::from("alice-bob-charlie-david");
        let manager = MediaStreamManager::new(identity);
        
        manager.initialize().await.unwrap();
        
        let call_id = CallId::new();
        let constraints = MediaConstraints::video_call();
        
        // Create stream
        manager.create_stream(call_id, constraints).await.unwrap();
        
        // Test poor quality adaptation
        let poor_metrics = CallQualityMetrics {
            rtt_ms: 500,
            packet_loss_percent: 10.0,
            jitter_ms: 50,
            bandwidth_kbps: 200,
            timestamp: Utc::now(),
        };
        
        let result = manager.adapt_quality(call_id, &poor_metrics).await;
        assert!(result.is_ok());
        
        // Check that stream was adapted
        let stream = manager.get_stream(call_id).await.unwrap();
        assert!(stream.adaptation_settings.video_bitrate_kbps < 1500);
    }
    
    #[test]
    fn test_video_resolution_dimensions() {
        assert_eq!(VideoResolution::HD720.width(), 1280);
        assert_eq!(VideoResolution::HD720.height(), 720);
        
        assert_eq!(VideoResolution::HD1080.width(), 1920);
        assert_eq!(VideoResolution::HD1080.height(), 1080);
    }
    
    #[test]
    fn test_media_constraints() {
        let constraints = MediaConstraints::video_call();
        
        assert!(constraints.has_audio());
        assert!(constraints.has_video());
        assert!(!constraints.has_screen_share());
        
        let media_types = constraints.to_media_types();
        assert_eq!(media_types.len(), 2);
        assert!(media_types.contains(&MediaType::Audio));
        assert!(media_types.contains(&MediaType::Video));
    }
}