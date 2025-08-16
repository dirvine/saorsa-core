// Copyright 2024 Saorsa Labs Limited
// WebRTC-QUIC Bridge Demo
//
// This example demonstrates how to use the WebRTC-QUIC bridge to send
// media packets over ant-quic transport while maintaining WebRTC compatibility.

use anyhow::Result;
use saorsa_core::messaging::{
    QosParameters, QuicMediaStreamManager, RtpPacket, StreamConfig, StreamType, WebRtcQuicBridge,
};
use saorsa_core::transport::ant_quic_adapter::P2PNetworkNode;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🚀 WebRTC-QUIC Bridge Demo");
    println!("==========================");

    // Step 1: Create network nodes
    println!("\n📡 Creating network nodes...");
    let node1 = create_network_node("127.0.0.1:0").await?;
    let node2 = create_network_node("127.0.0.1:0").await?;

    let node1_addr = node1.local_address();
    let node2_addr = node2.local_address();

    info!("Node 1 listening on: {}", node1_addr);
    info!("Node 2 listening on: {}", node2_addr);

    // Step 2: Create bridges
    println!("\n🌉 Creating WebRTC-QUIC bridges...");
    let bridge1 = WebRtcQuicBridge::new(node1).await?;
    let _bridge2 = WebRtcQuicBridge::new(node2).await?;

    // Step 3: Create stream managers
    println!("\n📊 Creating stream managers...");
    let manager1 = QuicMediaStreamManager::new(2000); // 2 Mbps
    let manager2 = QuicMediaStreamManager::new(2000); // 2 Mbps

    // Start background tasks for adaptation
    manager1.start_background_tasks().await?;
    manager2.start_background_tasks().await?;

    // Step 4: Connect peers (simulated)
    println!("\n🔗 Connecting peers...");
    let peer_id = simulate_peer_connection(&bridge1, node2_addr).await?;
    info!("Connected to peer: {}", peer_id);

    // Step 5: Configure media streams
    println!("\n🎵 Configuring media streams...");
    configure_media_streams(&bridge1, peer_id).await?;

    // Step 6: Set up QoS parameters
    println!("\n⚙️ Setting up QoS parameters...");
    setup_qos_parameters(&manager1).await;

    // Step 7: Simulate media transmission
    println!("\n📺 Simulating media transmission...");
    simulate_media_call(&bridge1, &manager1, peer_id).await?;

    // Step 8: Monitor performance
    println!("\n📈 Monitoring performance...");
    monitor_performance(&bridge1, &manager1, peer_id).await?;

    // Step 9: Demonstrate bandwidth adaptation
    println!("\n🔄 Demonstrating bandwidth adaptation...");
    demonstrate_bandwidth_adaptation(&manager1).await?;

    // Step 10: Clean up
    println!("\n🧹 Cleaning up...");
    bridge1.disconnect_peer(peer_id).await?;
    info!("Demo completed successfully!");

    Ok(())
}

async fn create_network_node(addr: &str) -> Result<Arc<P2PNetworkNode>> {
    let socket_addr = addr.parse()?;
    let node = P2PNetworkNode::new(socket_addr).await?;
    Ok(Arc::new(node))
}

async fn simulate_peer_connection(
    bridge: &WebRtcQuicBridge,
    peer_addr: std::net::SocketAddr,
) -> Result<ant_quic::nat_traversal_api::PeerId> {
    // In a real scenario, this would establish an actual connection
    // For demo purposes, we simulate the connection
    let peer_id = bridge.connect_simulated_peer(peer_addr).await?;
    info!("Simulated connection to peer at {}", peer_addr);
    Ok(peer_id)
}

async fn configure_media_streams(
    bridge: &WebRtcQuicBridge,
    peer_id: ant_quic::nat_traversal_api::PeerId,
) -> Result<()> {
    // Configure audio stream (high priority, low latency)
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
    info!("✅ Audio stream configured: Opus @ 64 kbps, 48 kHz");

    // Configure video stream (medium priority, adaptive quality)
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
    info!("✅ Video stream configured: H.264 @ 1000 kbps, 720p");

    // Configure data channel (low priority, reliable)
    let data_config = StreamConfig {
        stream_type: StreamType::Data,
        codec: "datachannel".to_string(),
        bitrate_kbps: 100,
        sample_rate: None,
        resolution: None,
    };

    bridge
        .add_stream(peer_id, StreamType::Data, data_config)
        .await?;
    info!("✅ Data channel configured: 100 kbps");

    Ok(())
}

async fn setup_qos_parameters(manager: &QuicMediaStreamManager) {
    // Set QoS for different stream types
    let audio_qos = QosParameters::audio();
    manager
        .set_qos_params(StreamType::Audio, audio_qos.clone())
        .await;
    info!(
        "🎵 Audio QoS: max_latency={}ms, priority={}",
        audio_qos.max_latency_ms, audio_qos.priority
    );

    let video_qos = QosParameters::video();
    manager
        .set_qos_params(StreamType::Video, video_qos.clone())
        .await;
    info!(
        "📹 Video QoS: max_latency={}ms, priority={}",
        video_qos.max_latency_ms, video_qos.priority
    );

    let data_qos = QosParameters::data();
    manager
        .set_qos_params(StreamType::Data, data_qos.clone())
        .await;
    info!(
        "💾 Data QoS: max_latency={}ms, priority={}",
        data_qos.max_latency_ms, data_qos.priority
    );
}

async fn simulate_media_call(
    bridge: &WebRtcQuicBridge,
    manager: &QuicMediaStreamManager,
    peer_id: ant_quic::nat_traversal_api::PeerId,
) -> Result<()> {
    info!("📞 Starting media call simulation...");

    // Simulate 5 seconds of media transmission
    for second in 1..=5 {
        info!("⏰ Second {}/5", second);

        // Send audio packets (50 packets per second for 20ms intervals)
        for audio_seq in 1..=50 {
            let audio_packet = create_rtp_packet(
                StreamType::Audio,
                (second - 1) * 50 + audio_seq,
                96,              // Opus payload type
                vec![0xAA; 160], // Simulate Opus frame (20ms @ 48kHz)
            );

            // Queue in manager (handles prioritization)
            manager
                .enqueue_packet(audio_packet.clone(), peer_id)
                .await?;

            // Send via bridge
            bridge.send_rtp_packet(peer_id, audio_packet).await?;
        }

        // Send video packets (30 packets per second for 33ms intervals)
        for video_seq in 1..=30 {
            let video_packet = create_rtp_packet(
                StreamType::Video,
                (second - 1) * 30 + video_seq,
                97,               // H.264 payload type
                vec![0xBB; 1200], // Simulate H.264 frame
            );

            manager
                .enqueue_packet(video_packet.clone(), peer_id)
                .await?;
            bridge.send_rtp_packet(peer_id, video_packet).await?;
        }

        // Send occasional data packets
        if second % 2 == 0 {
            let data_packet = create_rtp_packet(
                StreamType::Data,
                second,
                98,              // Data payload type
                vec![0xCC; 100], // Small data payload
            );

            manager.enqueue_packet(data_packet.clone(), peer_id).await?;
            bridge.send_rtp_packet(peer_id, data_packet).await?;
        }

        // Update statistics
        update_stream_stats(manager, peer_id, second).await?;

        // Process queued packets
        process_queued_packets(manager, 10).await;

        // Short delay between seconds
        sleep(Duration::from_millis(100)).await;
    }

    info!("✅ Media call simulation completed");
    Ok(())
}

fn create_rtp_packet(
    stream_type: StreamType,
    sequence: u16,
    payload_type: u8,
    payload: Vec<u8>,
) -> RtpPacket {
    RtpPacket::new(
        payload_type,
        sequence,
        sequence as u32 * 1000, // Simple timestamp calculation
        match stream_type {
            StreamType::Audio => 0x12345678,
            StreamType::Video => 0x87654321,
            StreamType::Data => 0x11111111,
            StreamType::ScreenShare => 0x22222222,
        },
        payload,
        stream_type,
    )
}

async fn update_stream_stats(
    manager: &QuicMediaStreamManager,
    peer_id: ant_quic::nat_traversal_api::PeerId,
    second: u16,
) -> Result<()> {
    // Simulate varying network conditions
    let base_rtt = 50 + (second as u32 * 10) % 100; // RTT between 50-150ms
    let _jitter = (second as u32 * 3) % 20; // Jitter 0-20ms

    // Update audio stats
    let audio_stream_id = (peer_id, StreamType::Audio);
    manager
        .update_stats(audio_stream_id, 50, 64 * 1024 / 8, base_rtt)
        .await?;

    // Update video stats
    let video_stream_id = (peer_id, StreamType::Video);
    manager
        .update_stats(video_stream_id, 30, 1000 * 1024 / 8, base_rtt + 10)
        .await?;

    // Update data stats
    if second % 2 == 0 {
        let data_stream_id = (peer_id, StreamType::Data);
        manager
            .update_stats(data_stream_id, 1, 100, base_rtt + 50)
            .await?;
    }

    Ok(())
}

async fn process_queued_packets(manager: &QuicMediaStreamManager, count: usize) {
    for i in 0..count {
        if let Some((packet, peer_id)) = manager.dequeue_packet().await {
            // Simulate processing delay based on priority
            let delay_ms = match packet.stream_type {
                StreamType::Audio => 1,       // Highest priority, minimal delay
                StreamType::Video => 5,       // Medium priority
                StreamType::ScreenShare => 7, // Medium-low priority
                StreamType::Data => 10,       // Lowest priority, highest delay
            };

            if i < 3 {
                // Only log first few for brevity
                info!(
                    "📦 Processed {:?} packet from {}, delay: {}ms",
                    packet.stream_type, peer_id, delay_ms
                );
            }

            sleep(Duration::from_millis(delay_ms)).await;
        } else {
            break;
        }
    }
}

async fn monitor_performance(
    bridge: &WebRtcQuicBridge,
    manager: &QuicMediaStreamManager,
    peer_id: ant_quic::nat_traversal_api::PeerId,
) -> Result<()> {
    info!("📊 Performance Statistics:");

    // Bridge statistics
    if let Some(peer_stats) = bridge.get_peer_stats(peer_id).await {
        info!("🔗 Bridge Stats:");
        info!("   Packets sent: {}", peer_stats.packets_sent);
        info!("   Packets received: {}", peer_stats.packets_received);
        info!("   Bytes sent: {}", peer_stats.bytes_sent);
        info!("   Bytes received: {}", peer_stats.bytes_received);
        info!("   Active streams: {}", peer_stats.streams.len());
    }

    // Stream manager statistics
    let all_stats = manager.get_all_stats().await;
    info!("📈 Stream Stats:");
    for ((stream_peer_id, stream_type), stats) in all_stats {
        if stream_peer_id == peer_id {
            info!("   {:?}:", stream_type);
            info!("     Packets: {}", stats.packets_sent);
            info!("     Bytes: {}", stats.bytes_sent);
            info!("     RTT: {}ms", stats.rtt_ms);
            info!("     Loss: {:.2}%", stats.loss_percentage());
        }
    }

    // Queue status
    let (queue_size, is_empty) = manager.get_queue_status().await;
    info!("📋 Queue Status:");
    info!("   Size: {}", queue_size);
    info!("   Empty: {}", is_empty);

    Ok(())
}

async fn demonstrate_bandwidth_adaptation(manager: &QuicMediaStreamManager) -> Result<()> {
    info!("🔄 Bandwidth Adaptation Demo:");

    // Check for bandwidth recommendations
    if let Some(adjustment) = manager.check_bandwidth_adaptation().await {
        match adjustment {
            saorsa_core::messaging::quic_media_streams::BandwidthAdjustment::Increase {
                current,
                recommended,
            } => {
                info!(
                    "📈 Recommendation: Increase bandwidth from {} to {} kbps",
                    current, recommended
                );
            }
            saorsa_core::messaging::quic_media_streams::BandwidthAdjustment::Decrease {
                current,
                recommended,
            } => {
                warn!(
                    "📉 Recommendation: Decrease bandwidth from {} to {} kbps",
                    current, recommended
                );
            }
        }
    } else {
        info!("✅ No bandwidth adjustment needed");
    }

    // Simulate bandwidth constraint
    let can_transmit_large = manager.can_transmit(10000).await; // 10KB packet
    let can_transmit_small = manager.can_transmit(100).await; // 100B packet

    info!("🚦 Transmission Control:");
    info!("   Can send 10KB packet: {}", can_transmit_large);
    info!("   Can send 100B packet: {}", can_transmit_small);

    Ok(())
}

/// Helper function to demonstrate QoS validation
#[allow(dead_code)]
async fn demonstrate_qos_validation(
    manager: &QuicMediaStreamManager,
    peer_id: ant_quic::nat_traversal_api::PeerId,
) -> Result<()> {
    info!("🎯 QoS Validation Demo:");

    let stream_types = [StreamType::Audio, StreamType::Video, StreamType::Data];

    for stream_type in stream_types {
        let stream_id = (peer_id, stream_type);
        let meets_qos = manager.validate_qos(stream_id).await;

        let status = if meets_qos { "✅ PASS" } else { "❌ FAIL" };
        info!("   {:?} QoS: {}", stream_type, status);
    }

    Ok(())
}

/// Helper function to demonstrate error scenarios
#[allow(dead_code)]
async fn demonstrate_error_handling(bridge: &WebRtcQuicBridge) -> Result<()> {
    info!("⚠️ Error Handling Demo:");

    // Try to send packet to non-existent peer
    let invalid_peer_id = ant_quic::nat_traversal_api::PeerId([0u8; 32]);
    let test_packet = create_rtp_packet(StreamType::Audio, 1, 96, vec![1, 2, 3, 4]);

    match bridge.send_rtp_packet(invalid_peer_id, test_packet).await {
        Ok(_) => info!("   Unexpected success sending to invalid peer"),
        Err(e) => info!("   ✅ Correctly handled invalid peer error: {}", e),
    }

    // Try to add stream to non-existent peer
    let test_config = StreamConfig {
        stream_type: StreamType::Audio,
        codec: "opus".to_string(),
        bitrate_kbps: 64,
        sample_rate: Some(48000),
        resolution: None,
    };

    match bridge
        .add_stream(invalid_peer_id, StreamType::Audio, test_config)
        .await
    {
        Ok(_) => info!("   Unexpected success adding stream to invalid peer"),
        Err(e) => info!("   ✅ Correctly handled invalid stream error: {}", e),
    }

    Ok(())
}
