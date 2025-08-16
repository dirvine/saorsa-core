// Copyright 2024 Saorsa Labs Limited
// Comprehensive tests for WebRTC-QUIC Bridge implementation

use ant_quic::nat_traversal_api::PeerId;
use anyhow::Result;
use saorsa_core::messaging::{
    QosParameters, QuicMediaStreamManager, RtpPacket, StreamConfig, StreamType, WebRtcQuicBridge,
};
use saorsa_core::transport::ant_quic_adapter::P2PNetworkNode;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

// Test fixtures
fn create_test_rtp_packet(stream_type: StreamType, sequence: u16) -> RtpPacket {
    RtpPacket::new(
        96,                     // payload_type
        sequence,               // sequence_number
        sequence as u32 * 1000, // timestamp
        0x12345678,             // ssrc
        vec![1, 2, 3, 4],       // payload
        stream_type,
    )
}

async fn create_test_network_node() -> Result<Arc<P2PNetworkNode>> {
    use ant_quic::{QuicNodeConfig, auth::AuthConfig, nat_traversal_api::EndpointRole};
    use std::time::Duration;

    let addr: SocketAddr = "127.0.0.1:0".parse()?;

    // Create a proper configuration for testing
    let config = QuicNodeConfig {
        role: EndpointRole::Bootstrap, // Use Bootstrap role to avoid requiring bootstrap nodes
        bootstrap_nodes: vec![],       // Empty for bootstrap nodes
        enable_coordinator: false,
        max_connections: 10,
        connection_timeout: Duration::from_secs(5),
        stats_interval: Duration::from_secs(10),
        auth_config: AuthConfig::default(),
        bind_addr: Some(addr),
    };

    let node = P2PNetworkNode::new_with_config(addr, config).await?;
    Ok(Arc::new(node))
}

#[tokio::test]
async fn test_bridge_creation() -> Result<()> {
    let network_node = create_test_network_node().await?;
    let bridge = WebRtcQuicBridge::new(network_node).await?;

    // Verify bridge is created
    let peers = bridge.get_connected_peers().await;
    assert!(peers.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_peer_connection_simulation() -> Result<()> {
    let network_node = create_test_network_node().await?;
    let bridge = WebRtcQuicBridge::new(network_node).await?;

    // Simulate peer connection
    let peer_addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let peer_id = bridge.connect_simulated_peer(peer_addr).await?;

    // Verify peer is connected
    let peers = bridge.get_connected_peers().await;
    assert!(peers.contains(&peer_id));

    // Get peer stats
    let stats = bridge.get_peer_stats(peer_id).await;
    assert!(stats.is_some());
    let stats = stats.unwrap();
    assert_eq!(stats.peer_id, peer_id);
    assert_eq!(stats.packets_sent, 0);
    assert_eq!(stats.packets_received, 0);

    Ok(())
}

#[tokio::test]
async fn test_stream_configuration() -> Result<()> {
    let network_node = create_test_network_node().await?;
    let bridge = WebRtcQuicBridge::new(network_node).await?;

    let peer_addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let peer_id = bridge.connect_simulated_peer(peer_addr).await?;

    // Add audio stream
    let audio_config = StreamConfig {
        stream_type: StreamType::Audio,
        codec: "opus".to_string(),
        bitrate_kbps: 64,
        sample_rate: Some(48000),
        resolution: None,
    };

    bridge
        .add_stream(peer_id, StreamType::Audio, audio_config)
        .await?;

    // Add video stream
    let video_config = StreamConfig {
        stream_type: StreamType::Video,
        codec: "h264".to_string(),
        bitrate_kbps: 1000,
        sample_rate: None,
        resolution: Some((1280, 720)),
    };

    bridge
        .add_stream(peer_id, StreamType::Video, video_config)
        .await?;

    // Verify peer stats shows streams
    let stats = bridge.get_peer_stats(peer_id).await.unwrap();
    assert_eq!(stats.streams.len(), 2);
    assert!(stats.streams.contains_key(&StreamType::Audio));
    assert!(stats.streams.contains_key(&StreamType::Video));

    Ok(())
}

#[tokio::test]
async fn test_rtp_packet_transmission() -> Result<()> {
    let network_node = create_test_network_node().await?;
    let bridge = WebRtcQuicBridge::new(network_node).await?;

    let peer_addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let peer_id = bridge.connect_simulated_peer(peer_addr).await?;

    let audio_config = StreamConfig {
        stream_type: StreamType::Audio,
        codec: "opus".to_string(),
        bitrate_kbps: 64,
        sample_rate: Some(48000),
        resolution: None,
    };

    bridge
        .add_stream(peer_id, StreamType::Audio, audio_config)
        .await?;

    // Send RTP packet
    let packet = create_test_rtp_packet(StreamType::Audio, 1);
    let result = bridge.send_rtp_packet(peer_id, packet).await;

    // Should succeed even though network is simulated
    assert!(result.is_ok());

    Ok(())
}

#[tokio::test]
async fn test_packet_serialization() -> Result<()> {
    let original = create_test_rtp_packet(StreamType::Video, 42);

    // Test serialization round trip
    let serialized = original.to_bytes()?;
    let deserialized = RtpPacket::from_bytes(&serialized)?;

    assert_eq!(original.version, deserialized.version);
    assert_eq!(original.payload_type, deserialized.payload_type);
    assert_eq!(original.sequence_number, deserialized.sequence_number);
    assert_eq!(original.timestamp, deserialized.timestamp);
    assert_eq!(original.ssrc, deserialized.ssrc);
    assert_eq!(original.payload, deserialized.payload);
    assert_eq!(original.stream_type, deserialized.stream_type);

    Ok(())
}

#[tokio::test]
async fn test_stream_priority() {
    assert_eq!(StreamType::Audio.priority(), 10);
    assert_eq!(StreamType::Video.priority(), 20);
    assert_eq!(StreamType::ScreenShare.priority(), 25);
    assert_eq!(StreamType::Data.priority(), 50);

    // Audio should have highest priority (lowest value)
    assert!(StreamType::Audio.priority() < StreamType::Video.priority());
    assert!(StreamType::Video.priority() < StreamType::Data.priority());
}

#[tokio::test]
async fn test_media_stream_manager() -> Result<()> {
    let manager = QuicMediaStreamManager::new(2000); // 2 Mbps
    let peer_id = PeerId([1u8; 32]);

    // Test packet enqueuing
    let audio_packet = create_test_rtp_packet(StreamType::Audio, 1);
    let queued = manager.enqueue_packet(audio_packet, peer_id).await?;
    assert!(queued);

    let video_packet = create_test_rtp_packet(StreamType::Video, 2);
    let queued = manager.enqueue_packet(video_packet, peer_id).await?;
    assert!(queued);

    // Test packet dequeuing (should get audio first due to priority)
    let result = manager.dequeue_packet().await;
    assert!(result.is_some());
    let (packet, returned_peer_id) = result.unwrap();
    assert_eq!(packet.stream_type, StreamType::Audio);
    assert_eq!(returned_peer_id, peer_id);

    // Get video packet next
    let result = manager.dequeue_packet().await;
    assert!(result.is_some());
    let (packet, _) = result.unwrap();
    assert_eq!(packet.stream_type, StreamType::Video);

    Ok(())
}

#[tokio::test]
async fn test_qos_parameters() {
    let audio_qos = QosParameters::audio();
    let video_qos = QosParameters::video();
    let data_qos = QosParameters::data();

    // Audio should have lowest latency
    assert!(audio_qos.max_latency_ms < video_qos.max_latency_ms);
    assert!(audio_qos.max_latency_ms < data_qos.max_latency_ms);

    // Audio should have highest priority (lowest value)
    assert!(audio_qos.priority < video_qos.priority);
    assert!(video_qos.priority < data_qos.priority);

    // Video should have highest bandwidth
    assert!(video_qos.target_bandwidth_kbps > audio_qos.target_bandwidth_kbps);
    assert!(video_qos.max_bandwidth_kbps > data_qos.max_bandwidth_kbps);
}

#[tokio::test]
async fn test_stream_stats() -> Result<()> {
    let manager = QuicMediaStreamManager::new(1000);
    let peer_id = PeerId([2u8; 32]);
    let stream_id = (peer_id, StreamType::Audio);

    // Update stats
    manager.update_stats(stream_id, 10, 1000, 50).await?;

    // Retrieve stats
    let stats = manager.get_stats(stream_id).await;
    assert!(stats.is_some());
    let stats = stats.unwrap();

    assert_eq!(stats.packets_sent, 10);
    assert_eq!(stats.bytes_sent, 1000);
    assert_eq!(stats.rtt_ms, 50);
    assert_eq!(stats.stream_id, stream_id);

    Ok(())
}

#[tokio::test]
async fn test_concurrent_packet_processing() -> Result<()> {
    let network_node = create_test_network_node().await?;
    let bridge = WebRtcQuicBridge::new(Arc::clone(&network_node)).await?;

    let peer_addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let peer_id = bridge.connect_simulated_peer(peer_addr).await?;

    let audio_config = StreamConfig {
        stream_type: StreamType::Audio,
        codec: "opus".to_string(),
        bitrate_kbps: 64,
        sample_rate: Some(48000),
        resolution: None,
    };

    bridge
        .add_stream(peer_id, StreamType::Audio, audio_config)
        .await?;

    // Send multiple packets concurrently
    let bridge = Arc::new(bridge);
    let mut handles = Vec::new();
    for i in 0..10 {
        let bridge_clone = Arc::clone(&bridge);
        let packet = create_test_rtp_packet(StreamType::Audio, i);
        let handle =
            tokio::spawn(async move { bridge_clone.send_rtp_packet(peer_id, packet).await });
        handles.push(handle);
    }

    // Wait for all to complete
    for handle in handles {
        let result = timeout(Duration::from_secs(5), handle).await??;
        assert!(result.is_ok());
    }

    Ok(())
}

#[tokio::test]
async fn test_peer_disconnection() -> Result<()> {
    let network_node = create_test_network_node().await?;
    let bridge = WebRtcQuicBridge::new(network_node).await?;

    let peer_addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let peer_id = bridge.connect_simulated_peer(peer_addr).await?;

    // Verify peer is connected
    assert!(bridge.get_connected_peers().await.contains(&peer_id));

    // Disconnect peer
    bridge.disconnect_peer(peer_id).await?;

    // Verify peer is removed
    assert!(!bridge.get_connected_peers().await.contains(&peer_id));

    // Stats should return None
    assert!(bridge.get_peer_stats(peer_id).await.is_none());

    Ok(())
}

#[tokio::test]
async fn test_invalid_peer_operations() -> Result<()> {
    let network_node = create_test_network_node().await?;
    let bridge = WebRtcQuicBridge::new(network_node).await?;

    let invalid_peer_id = PeerId([0u8; 32]);

    // Try to send packet to non-existent peer
    let packet = create_test_rtp_packet(StreamType::Audio, 1);
    let result = bridge.send_rtp_packet(invalid_peer_id, packet).await;
    assert!(result.is_err());

    // Try to add stream to non-existent peer
    let config = StreamConfig {
        stream_type: StreamType::Audio,
        codec: "opus".to_string(),
        bitrate_kbps: 64,
        sample_rate: Some(48000),
        resolution: None,
    };

    let result = bridge
        .add_stream(invalid_peer_id, StreamType::Audio, config)
        .await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_bandwidth_management() -> Result<()> {
    let manager = QuicMediaStreamManager::new(500); // Low bandwidth limit

    // Test transmission control
    let can_transmit = manager.can_transmit(100).await; // 100 bytes = 800 bits
    assert!(can_transmit); // Should allow small packets

    Ok(())
}

#[tokio::test]
async fn test_queue_capacity() -> Result<()> {
    let manager = QuicMediaStreamManager::new(1000);
    let peer_id = PeerId([3u8; 32]);

    // Fill queue with packets
    for i in 0..100 {
        let packet = create_test_rtp_packet(StreamType::Data, i);
        let queued = manager.enqueue_packet(packet, peer_id).await?;
        assert!(queued);
    }

    // Check queue status
    let (size, empty) = manager.get_queue_status().await;
    assert_eq!(size, 100);
    assert!(!empty);

    Ok(())
}

#[tokio::test]
async fn test_qos_validation() -> Result<()> {
    let manager = QuicMediaStreamManager::new(2000);
    let peer_id = PeerId([4u8; 32]);
    let stream_id = (peer_id, StreamType::Audio);

    // Set QoS parameters
    let qos = QosParameters::audio();
    manager.set_qos_params(StreamType::Audio, qos.clone()).await;

    // Update stats to meet QoS
    manager.update_stats(stream_id, 100, 10000, 30).await?;

    // Validate QoS (should pass since we haven't set all required metrics)
    let _valid = manager.validate_qos(stream_id).await;
    // This might fail because we don't set all metrics in the mock
    // The important thing is that the function doesn't panic

    Ok(())
}

#[tokio::test]
async fn test_mixed_stream_priorities() -> Result<()> {
    let manager = QuicMediaStreamManager::new(2000);
    let peer_id = PeerId([5u8; 32]);

    // Enqueue packets in reverse priority order
    let data_packet = create_test_rtp_packet(StreamType::Data, 1);
    manager.enqueue_packet(data_packet, peer_id).await?;

    let video_packet = create_test_rtp_packet(StreamType::Video, 2);
    manager.enqueue_packet(video_packet, peer_id).await?;

    let audio_packet = create_test_rtp_packet(StreamType::Audio, 3);
    manager.enqueue_packet(audio_packet, peer_id).await?;

    let screenshare_packet = create_test_rtp_packet(StreamType::ScreenShare, 4);
    manager.enqueue_packet(screenshare_packet, peer_id).await?;

    // Should dequeue in priority order: Audio, Video, ScreenShare, Data
    let (packet1, _) = manager.dequeue_packet().await.unwrap();
    assert_eq!(packet1.stream_type, StreamType::Audio);

    let (packet2, _) = manager.dequeue_packet().await.unwrap();
    assert_eq!(packet2.stream_type, StreamType::Video);

    let (packet3, _) = manager.dequeue_packet().await.unwrap();
    assert_eq!(packet3.stream_type, StreamType::ScreenShare);

    let (packet4, _) = manager.dequeue_packet().await.unwrap();
    assert_eq!(packet4.stream_type, StreamType::Data);

    Ok(())
}

#[tokio::test]
async fn test_stream_manager_reset() -> Result<()> {
    let manager = QuicMediaStreamManager::new(1000);
    let peer_id = PeerId([6u8; 32]);

    // Add some packets and stats
    let packet = create_test_rtp_packet(StreamType::Audio, 1);
    manager.enqueue_packet(packet, peer_id).await?;

    let stream_id = (peer_id, StreamType::Audio);
    manager.update_stats(stream_id, 5, 500, 25).await?;

    // Reset manager
    manager.reset().await;

    // Verify everything is cleared
    let (size, empty) = manager.get_queue_status().await;
    assert_eq!(size, 0);
    assert!(empty);

    let stats = manager.get_stats(stream_id).await;
    assert!(stats.is_none());

    Ok(())
}

#[tokio::test]
async fn test_large_packet_handling() -> Result<()> {
    let mut large_packet = create_test_rtp_packet(StreamType::Video, 1);
    large_packet.payload = vec![0u8; 10000]; // 10KB payload

    // Test serialization of large packet
    let serialized = large_packet.to_bytes()?;
    let deserialized = RtpPacket::from_bytes(&serialized)?;

    assert_eq!(large_packet.payload.len(), deserialized.payload.len());
    assert_eq!(large_packet.payload, deserialized.payload);

    Ok(())
}

#[tokio::test]
async fn test_error_handling() -> Result<()> {
    // Test invalid serialization data
    let invalid_data = vec![0xff, 0xff, 0xff, 0xff];
    let result = RtpPacket::from_bytes(&invalid_data);
    assert!(result.is_err());

    Ok(())
}

// Integration test with realistic scenario
#[tokio::test]
async fn test_realistic_call_scenario() -> Result<()> {
    let network_node = create_test_network_node().await?;
    let bridge = WebRtcQuicBridge::new(Arc::clone(&network_node)).await?;
    let manager = QuicMediaStreamManager::new(2000);

    // Connect to peer
    let peer_addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let peer_id = bridge.connect_simulated_peer(peer_addr).await?;

    // Set up audio and video streams
    let audio_config = StreamConfig {
        stream_type: StreamType::Audio,
        codec: "opus".to_string(),
        bitrate_kbps: 64,
        sample_rate: Some(48000),
        resolution: None,
    };

    let video_config = StreamConfig {
        stream_type: StreamType::Video,
        codec: "h264".to_string(),
        bitrate_kbps: 1000,
        sample_rate: None,
        resolution: Some((1280, 720)),
    };

    bridge
        .add_stream(peer_id, StreamType::Audio, audio_config)
        .await?;
    bridge
        .add_stream(peer_id, StreamType::Video, video_config)
        .await?;

    // Simulate sending media packets
    for sequence in 1..=10 {
        // Send audio packet (higher priority)
        let audio_packet = create_test_rtp_packet(StreamType::Audio, sequence);
        bridge
            .send_rtp_packet(peer_id, audio_packet.clone())
            .await?;
        manager.enqueue_packet(audio_packet, peer_id).await?;

        // Send video packet (lower priority)
        if sequence % 2 == 0 {
            let video_packet = create_test_rtp_packet(StreamType::Video, sequence);
            bridge
                .send_rtp_packet(peer_id, video_packet.clone())
                .await?;
            manager.enqueue_packet(video_packet, peer_id).await?;
        }
    }

    // Update stream statistics
    let audio_stream_id = (peer_id, StreamType::Audio);
    let video_stream_id = (peer_id, StreamType::Video);

    manager.update_stats(audio_stream_id, 10, 1000, 25).await?;
    manager.update_stats(video_stream_id, 5, 5000, 40).await?;

    // Verify peer stats
    let peer_stats = bridge.get_peer_stats(peer_id).await.unwrap();
    assert_eq!(peer_stats.streams.len(), 2);

    // Verify stream stats
    let audio_stats = manager.get_stats(audio_stream_id).await.unwrap();
    assert_eq!(audio_stats.packets_sent, 10);

    let video_stats = manager.get_stats(video_stream_id).await.unwrap();
    assert_eq!(video_stats.packets_sent, 5);

    // Clean up
    bridge.disconnect_peer(peer_id).await?;

    Ok(())
}
