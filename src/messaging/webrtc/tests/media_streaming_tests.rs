// Tests for WebRTC media streaming over native QUIC
// Verifies audio/video track creation, quality adaptation, and QUIC transport

use super::*;
use crate::messaging::webrtc::media::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_media_stream_manager_initialization() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let manager = MediaStreamManager::new(alice);

        // Test initialization
        let result = manager.initialize().await;
        assert!(result.is_ok());

        // Test device enumeration
        let audio_devices = manager.get_audio_devices().await.unwrap();
        assert!(!audio_devices.is_empty());

        let video_devices = manager.get_video_devices().await.unwrap();
        assert!(!video_devices.is_empty());
    }

    #[tokio::test]
    async fn test_audio_only_stream_creation() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let manager = MediaStreamManager::new(alice);

        manager.initialize().await.unwrap();

        let call_id = CallId::new();
        let constraints = MediaConstraints::audio_only();

        // Create audio-only stream
        let stream = manager.create_stream(call_id, constraints).await.unwrap();

        assert_eq!(stream.call_id, call_id);
        assert!(stream.audio_track.is_some());
        assert!(stream.video_track.is_none());
        assert!(stream.screen_track.is_none());
        assert_eq!(stream.state, MediaStreamState::Created);

        // Verify audio track properties
        let audio_track = stream.audio_track.unwrap();
        assert_eq!(audio_track.settings.sample_rate, 48000);
        assert_eq!(audio_track.settings.channels, 2);
        assert_eq!(audio_track.settings.bitrate_kbps, 64);
        assert!(audio_track.settings.echo_cancellation);
        assert!(audio_track.settings.noise_suppression);
        assert!(audio_track.settings.auto_gain_control);
    }

    #[tokio::test]
    async fn test_video_call_stream_creation() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let manager = MediaStreamManager::new(alice);

        manager.initialize().await.unwrap();

        let call_id = CallId::new();
        let constraints = MediaConstraints::video_call();

        // Create video call stream
        let stream = manager.create_stream(call_id, constraints).await.unwrap();

        assert_eq!(stream.call_id, call_id);
        assert!(stream.audio_track.is_some());
        assert!(stream.video_track.is_some());
        assert!(stream.screen_track.is_none());

        // Verify video track properties
        let video_track = stream.video_track.unwrap();
        assert_eq!(video_track.settings.resolution, VideoResolution::HD720);
        assert_eq!(video_track.settings.fps, 30);
        assert_eq!(video_track.settings.bitrate_kbps, 1500);
    }

    #[tokio::test]
    async fn test_screen_share_stream_creation() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let manager = MediaStreamManager::new(alice);

        manager.initialize().await.unwrap();

        let call_id = CallId::new();
        let constraints = MediaConstraints::screen_share();

        // Create screen share stream
        let stream = manager.create_stream(call_id, constraints).await.unwrap();

        assert_eq!(stream.call_id, call_id);
        assert!(stream.audio_track.is_some());
        assert!(stream.video_track.is_none());
        assert!(stream.screen_track.is_some());

        // Verify screen share track properties
        let screen_track = stream.screen_track.unwrap();
        assert_eq!(screen_track.settings.resolution, VideoResolution::HD1080);
        assert_eq!(screen_track.settings.fps, 15);
        assert_eq!(screen_track.settings.bitrate_kbps, 2000);

        // Verify screen device
        let device = screen_track.device.unwrap();
        assert_eq!(device.device_type, VideoDeviceType::Screen);
        assert_eq!(device.name, "Screen Capture");
    }

    #[tokio::test]
    async fn test_media_capture_lifecycle() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let manager = MediaStreamManager::new(alice);

        manager.initialize().await.unwrap();

        let call_id = CallId::new();
        let constraints = MediaConstraints::video_call();

        // Create stream
        manager.create_stream(call_id, constraints).await.unwrap();

        // Start capture
        let result = manager.start_capture(call_id).await;
        assert!(result.is_ok());

        // Verify stream state changed
        let stream = manager.get_stream(call_id).await.unwrap();
        assert_eq!(stream.state, MediaStreamState::Capturing);

        // Stop capture
        let result = manager.stop_capture(call_id).await;
        assert!(result.is_ok());

        // Verify stream state changed
        let stream = manager.get_stream(call_id).await.unwrap();
        assert_eq!(stream.state, MediaStreamState::Stopped);

        // Remove stream
        let result = manager.remove_stream(call_id).await;
        assert!(result.is_ok());

        // Verify stream is gone
        let stream = manager.get_stream(call_id).await;
        assert!(stream.is_none());
    }

    #[tokio::test]
    async fn test_quality_adaptation_poor_network() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let manager = MediaStreamManager::new(alice);

        manager.initialize().await.unwrap();

        let call_id = CallId::new();
        let constraints = MediaConstraints::video_call();

        // Create video stream
        manager.create_stream(call_id, constraints).await.unwrap();

        // Simulate poor network conditions
        let poor_metrics = CallQualityMetrics {
            rtt_ms: 400,
            packet_loss_percent: 8.0,
            jitter_ms: 60,
            bandwidth_kbps: 150,
            timestamp: chrono::Utc::now(),
        };

        // Adapt quality
        let result = manager.adapt_quality(call_id, &poor_metrics).await;
        assert!(result.is_ok());

        // Verify quality was reduced
        let stream = manager.get_stream(call_id).await.unwrap();
        let settings = &stream.adaptation_settings;

        // Should have reduced bitrate and resolution
        assert!(settings.video_bitrate_kbps < 1500);
        assert!(settings.video_fps < 30);
        assert_eq!(settings.video_resolution, VideoResolution::SD480);
        assert!(settings.enable_dtx);

        // Verify metrics were recorded
        assert_eq!(stream.quality_metrics.len(), 1);
        assert_eq!(stream.quality_metrics[0].rtt_ms, 400);
    }

    #[tokio::test]
    async fn test_quality_adaptation_good_network() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let manager = MediaStreamManager::new(alice);

        manager.initialize().await.unwrap();

        let call_id = CallId::new();
        let constraints = MediaConstraints::video_call();

        // Create stream with initial poor settings
        manager.create_stream(call_id, constraints).await.unwrap();

        // First simulate poor conditions
        let poor_metrics = CallQualityMetrics {
            rtt_ms: 300,
            packet_loss_percent: 5.0,
            jitter_ms: 50,
            bandwidth_kbps: 200,
            timestamp: chrono::Utc::now(),
        };

        manager.adapt_quality(call_id, &poor_metrics).await.unwrap();

        // Then simulate good network conditions
        let good_metrics = CallQualityMetrics {
            rtt_ms: 50,
            packet_loss_percent: 0.5,
            jitter_ms: 10,
            bandwidth_kbps: 2000,
            timestamp: chrono::Utc::now(),
        };

        let result = manager.adapt_quality(call_id, &good_metrics).await;
        assert!(result.is_ok());

        // Verify quality was increased
        let stream = manager.get_stream(call_id).await.unwrap();
        let settings = &stream.adaptation_settings;

        // Should have increased quality from the poor settings
        assert!(settings.video_bitrate_kbps > 200);
        assert!(settings.video_fps > 15);
        assert_ne!(settings.video_resolution, VideoResolution::SD480);

        // Verify both metrics were recorded
        assert_eq!(stream.quality_metrics.len(), 2);
    }

    #[tokio::test]
    async fn test_device_switching() {
        let alice = FourWordAddress::from("alice-bob-charlie-delta");
        let manager = MediaStreamManager::new(alice);

        manager.initialize().await.unwrap();

        let call_id = CallId::new();
        let constraints = MediaConstraints::video_call();

        manager.create_stream(call_id, constraints).await.unwrap();

        // Get available devices
        let audio_devices = manager.get_audio_devices().await.unwrap();
        let video_devices = manager.get_video_devices().await.unwrap();

        assert!(!audio_devices.is_empty());
        assert!(!video_devices.is_empty());

        // Switch to different audio device
        if audio_devices.len() > 1 {
            let new_device = audio_devices[1].clone();
            let result = manager.switch_audio_device(call_id, new_device).await;
            assert!(result.is_ok());
        }

        // Switch to different video device
        if video_devices.len() > 1 {
            let new_device = video_devices[1].clone();
            let result = manager.switch_video_device(call_id, new_device).await;
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_video_resolution_helpers() {
        // Test resolution width/height helpers
        assert_eq!(VideoResolution::QVGA240.width(), 320);
        assert_eq!(VideoResolution::QVGA240.height(), 240);

        assert_eq!(VideoResolution::SD480.width(), 640);
        assert_eq!(VideoResolution::SD480.height(), 480);

        assert_eq!(VideoResolution::HD720.width(), 1280);
        assert_eq!(VideoResolution::HD720.height(), 720);

        assert_eq!(VideoResolution::HD1080.width(), 1920);
        assert_eq!(VideoResolution::HD1080.height(), 1080);
    }

    #[test]
    fn test_media_constraints_helpers() {
        // Test audio-only constraints
        let audio_only = MediaConstraints::audio_only();
        assert!(audio_only.has_audio());
        assert!(!audio_only.has_video());
        assert!(!audio_only.has_screen_share());

        let media_types = audio_only.to_media_types();
        assert_eq!(media_types.len(), 1);
        assert!(media_types.contains(&MediaType::Audio));

        // Test video call constraints
        let video_call = MediaConstraints::video_call();
        assert!(video_call.has_audio());
        assert!(video_call.has_video());
        assert!(!video_call.has_screen_share());

        let media_types = video_call.to_media_types();
        assert_eq!(media_types.len(), 2);
        assert!(media_types.contains(&MediaType::Audio));
        assert!(media_types.contains(&MediaType::Video));

        // Test screen share constraints
        let screen_share = MediaConstraints::screen_share();
        assert!(screen_share.has_audio());
        assert!(!screen_share.has_video());
        assert!(screen_share.has_screen_share());

        let media_types = screen_share.to_media_types();
        assert_eq!(media_types.len(), 2);
        assert!(media_types.contains(&MediaType::Audio));
        assert!(media_types.contains(&MediaType::ScreenShare));
    }

    #[test]
    fn test_call_quality_metrics() {
        // Test good quality detection
        let good_metrics = CallQualityMetrics {
            rtt_ms: 50,
            packet_loss_percent: 0.5,
            jitter_ms: 15,
            bandwidth_kbps: 1000,
            timestamp: chrono::Utc::now(),
        };

        assert!(good_metrics.is_good_quality());
        assert!(!good_metrics.needs_adaptation());

        // Test poor quality detection
        let poor_metrics = CallQualityMetrics {
            rtt_ms: 300,
            packet_loss_percent: 5.0,
            jitter_ms: 50,
            bandwidth_kbps: 200,
            timestamp: chrono::Utc::now(),
        };

        assert!(!poor_metrics.is_good_quality());
        assert!(poor_metrics.needs_adaptation());

        // Test medium quality
        let medium_metrics = CallQualityMetrics {
            rtt_ms: 150,
            packet_loss_percent: 2.0,
            jitter_ms: 25,
            bandwidth_kbps: 400,
            timestamp: chrono::Utc::now(),
        };

        assert!(!medium_metrics.is_good_quality());
        assert!(!medium_metrics.needs_adaptation());
    }

    #[tokio::test]
    async fn test_media_processor_initialization() {
        // Test audio processor
        let audio_processor = AudioProcessor::new();
        let result = audio_processor.initialize().await;
        assert!(result.is_ok());

        let devices = audio_processor.get_devices().await.unwrap();
        assert!(!devices.is_empty());

        // Verify default devices are available
        assert!(devices.iter().any(|d| d.name == "Default Audio Device"));
        assert!(devices.iter().any(|d| d.name == "Built-in Microphone"));

        // Test video processor
        let video_processor = VideoProcessor::new();
        let result = video_processor.initialize().await;
        assert!(result.is_ok());

        let devices = video_processor.get_devices().await.unwrap();
        assert!(!devices.is_empty());

        // Verify default devices are available
        assert!(devices.iter().any(|d| d.name == "Default Camera"));
        assert!(devices.iter().any(|d| d.name == "Built-in Camera"));
    }

    #[tokio::test]
    async fn test_media_track_creation() {
        let audio_processor = AudioProcessor::new();
        audio_processor.initialize().await.unwrap();

        let audio_track = audio_processor.create_track().await.unwrap();
        assert_eq!(audio_track.state, TrackState::Created);
        assert!(audio_track.device.is_some());

        let video_processor = VideoProcessor::new();
        video_processor.initialize().await.unwrap();

        let video_track = video_processor.create_track().await.unwrap();
        assert_eq!(video_track.state, TrackState::Created);
        assert!(video_track.device.is_some());

        // Test screen share track
        let screen_track = video_processor.create_screen_share_track().await.unwrap();
        assert_eq!(screen_track.state, TrackState::Created);
        assert!(screen_track.device.is_some());

        let device = screen_track.device.unwrap();
        assert_eq!(device.device_type, VideoDeviceType::Screen);
    }
}
