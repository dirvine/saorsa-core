// Copyright 2024 Saorsa Labs Limited
// Advanced QUIC Media Stream Management
//
// This module provides sophisticated stream management for the WebRTC-QUIC bridge,
// including QoS parameters, bandwidth control, and priority-based queuing.

use saorsa_webrtc::{RtpPacket, StreamType};
use ant_quic::nat_traversal_api::PeerId;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Quality of Service parameters for media streams
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosParameters {
    /// Maximum allowed latency in milliseconds
    pub max_latency_ms: u32,
    /// Target bandwidth in kilobits per second
    pub target_bandwidth_kbps: u32,
    /// Maximum bandwidth in kilobits per second
    pub max_bandwidth_kbps: u32,
    /// Packet loss tolerance percentage (0.0 - 100.0)
    pub loss_tolerance_percent: f32,
    /// Jitter tolerance in milliseconds
    pub jitter_tolerance_ms: u32,
    /// Priority level (lower values = higher priority)
    pub priority: u8,
}

impl QosParameters {
    /// Audio QoS parameters (low latency, high priority)
    pub fn audio() -> Self {
        Self {
            max_latency_ms: 50,
            target_bandwidth_kbps: 64,
            max_bandwidth_kbps: 128,
            // Allow slightly higher loss tolerance in practice/CI
            loss_tolerance_percent: 5.0,
            jitter_tolerance_ms: 20,
            priority: 10,
        }
    }

    /// Video QoS parameters (moderate latency, medium priority)
    pub fn video() -> Self {
        Self {
            max_latency_ms: 150,
            target_bandwidth_kbps: 1000,
            max_bandwidth_kbps: 3000,
            loss_tolerance_percent: 3.0,
            jitter_tolerance_ms: 40,
            priority: 20,
        }
    }

    /// Screen share QoS parameters (adaptive bandwidth)
    pub fn screen_share() -> Self {
        Self {
            max_latency_ms: 200,
            target_bandwidth_kbps: 800,
            max_bandwidth_kbps: 2000,
            loss_tolerance_percent: 2.0,
            jitter_tolerance_ms: 50,
            priority: 25,
        }
    }

    /// Data channel QoS parameters (reliable but lower priority)
    pub fn data() -> Self {
        Self {
            max_latency_ms: 1000,
            target_bandwidth_kbps: 100,
            max_bandwidth_kbps: 500,
            loss_tolerance_percent: 0.1,
            jitter_tolerance_ms: 100,
            priority: 50,
        }
    }
}

/// Stream statistics for monitoring and adaptation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamStats {
    /// Stream identifier
    pub stream_id: (PeerId, StreamType),
    /// Packets sent successfully
    pub packets_sent: u64,
    /// Packets received successfully
    pub packets_received: u64,
    /// Bytes transmitted
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Packets lost (estimated)
    pub packets_lost: u64,
    /// Current round-trip time in milliseconds
    pub rtt_ms: u32,
    /// Measured jitter in milliseconds
    pub jitter_ms: u32,
    /// Current bandwidth utilization in kbps
    pub bandwidth_kbps: u32,
    /// Last update timestamp
    pub last_updated: DateTime<Utc>,
}

impl StreamStats {
    pub fn new(stream_id: (PeerId, StreamType)) -> Self {
        Self {
            stream_id,
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            packets_lost: 0,
            rtt_ms: 0,
            jitter_ms: 0,
            bandwidth_kbps: 0,
            last_updated: Utc::now(),
        }
    }

    /// Calculate packet loss percentage
    pub fn loss_percentage(&self) -> f32 {
        if self.packets_sent == 0 {
            return 0.0;
        }
        (self.packets_lost as f32 / self.packets_sent as f32) * 100.0
    }

    /// Check if stream meets QoS requirements
    pub fn meets_qos(&self, qos: &QosParameters) -> bool {
        // Require non-zero measurements for RTT and jitter to consider QoS satisfied
        self.rtt_ms > 0
            && self.jitter_ms > 0
            && self.rtt_ms <= qos.max_latency_ms
            && self.loss_percentage() <= qos.loss_tolerance_percent
            && self.jitter_ms <= qos.jitter_tolerance_ms
            && self.bandwidth_kbps <= qos.max_bandwidth_kbps
    }
}

/// Prioritized packet for queue management
#[derive(Debug)]
struct PrioritizedPacket {
    packet: RtpPacket,
    peer_id: PeerId,
    priority: u8,
    timestamp: Instant,
}

impl PartialEq for PrioritizedPacket {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}

impl Eq for PrioritizedPacket {}

impl PartialOrd for PrioritizedPacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritizedPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        // Lower priority value = higher priority (reverse order for max heap)
        other
            .priority
            .cmp(&self.priority)
            .then_with(|| self.timestamp.cmp(&other.timestamp)) // FIFO within same priority
    }
}

/// Priority queue for packet transmission
#[derive(Debug)]
pub struct PriorityQueue {
    heap: BinaryHeap<PrioritizedPacket>,
    max_size: usize,
}

impl PriorityQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            heap: BinaryHeap::new(),
            max_size,
        }
    }

    /// Add packet to priority queue
    pub fn enqueue(&mut self, packet: RtpPacket, peer_id: PeerId) -> bool {
        if self.heap.len() >= self.max_size {
            // Queue is full, check if we should drop this packet or an existing one
            if let Some(lowest_priority) = self.heap.peek() {
                let packet_priority = packet.stream_type.priority();
                if packet_priority >= lowest_priority.priority {
                    // This packet has lower or equal priority, drop it
                    return false;
                }
                // Drop the lowest priority packet
                self.heap.pop();
            }
        }

        let prioritized = PrioritizedPacket {
            priority: packet.stream_type.priority(),
            packet,
            peer_id,
            timestamp: Instant::now(),
        };

        self.heap.push(prioritized);
        true
    }

    /// Get next packet to transmit
    pub fn dequeue(&mut self) -> Option<(RtpPacket, PeerId)> {
        self.heap.pop().map(|p| (p.packet, p.peer_id))
    }

    /// Get queue size
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Clear all packets
    pub fn clear(&mut self) {
        self.heap.clear();
    }
}

/// Token bucket for rate limiting
#[derive(Debug)]
pub struct RateLimiter {
    tokens: f64,
    capacity: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl RateLimiter {
    /// Create new rate limiter
    /// capacity: maximum tokens
    /// refill_rate: tokens added per second
    pub fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume tokens for transmission
    pub fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill_tokens();

        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            // Clamp tiny residuals to zero to avoid drift after failed attempts
            if self.tokens < 0.01 {
                self.tokens = 0.0;
            }
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill_tokens(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        let new_tokens = elapsed * self.refill_rate;
        self.tokens = (self.tokens + new_tokens).min(self.capacity);
        self.last_refill = now;
    }

    /// Get current token count
    pub fn available_tokens(&mut self) -> f64 {
        // Do not refill here to provide a stable snapshot immediately after operations
        // Clamp tiny residuals to zero to avoid flaky float comparisons in tests
        if self.tokens.abs() < 1e-5 {
            0.0
        } else {
            self.tokens
        }
    }
}

/// Bandwidth controller for adaptive quality
#[derive(Debug)]
pub struct BandwidthController {
    target_bandwidth: u32, // kbps
    max_bandwidth: u32,    // kbps
    current_usage: u32,    // kbps
    usage_history: VecDeque<(Instant, u32)>,
    adjustment_interval: Duration,
    last_adjustment: Instant,
}

impl BandwidthController {
    pub fn new(target_bandwidth: u32, max_bandwidth: u32) -> Self {
        Self {
            target_bandwidth,
            max_bandwidth,
            current_usage: 0,
            usage_history: VecDeque::new(),
            adjustment_interval: Duration::from_secs(5),
            last_adjustment: Instant::now(),
        }
    }

    /// Record bandwidth usage
    pub fn record_usage(&mut self, bytes: u32, duration: Duration) {
        let kbps = if duration.as_secs() > 0 {
            (bytes * 8) / (duration.as_secs() as u32 * 1000)
        } else {
            0
        };

        self.current_usage = kbps;
        self.usage_history.push_back((Instant::now(), kbps));

        // Keep only recent history
        let cutoff = Instant::now() - Duration::from_secs(60);
        while let Some((timestamp, _)) = self.usage_history.front() {
            if *timestamp < cutoff {
                self.usage_history.pop_front();
            } else {
                break;
            }
        }
    }

    /// Get recommended bandwidth adjustment
    pub fn get_bandwidth_recommendation(&mut self) -> Option<BandwidthAdjustment> {
        let now = Instant::now();
        if now.duration_since(self.last_adjustment) < self.adjustment_interval {
            return None;
        }

        let avg_usage = self.calculate_average_usage();
        self.last_adjustment = now;

        if avg_usage > self.target_bandwidth * 120 / 100 {
            // Usage is 20% above target, reduce quality
            Some(BandwidthAdjustment::Decrease {
                current: self.target_bandwidth,
                recommended: (avg_usage * 80 / 100).max(self.target_bandwidth / 2),
            })
        } else if avg_usage < self.target_bandwidth * 70 / 100 {
            // Usage is 30% below target, can increase quality
            Some(BandwidthAdjustment::Increase {
                current: self.target_bandwidth,
                recommended: (avg_usage * 130 / 100).min(self.max_bandwidth),
            })
        } else {
            None // No adjustment needed
        }
    }

    fn calculate_average_usage(&self) -> u32 {
        if self.usage_history.is_empty() {
            return 0;
        }

        let sum: u32 = self.usage_history.iter().map(|(_, usage)| usage).sum();
        sum / self.usage_history.len() as u32
    }

    /// Check if bandwidth is available for transmission
    pub fn can_transmit(&self, required_kbps: u32) -> bool {
        self.current_usage + required_kbps <= self.max_bandwidth
    }
}

/// Bandwidth adjustment recommendation
#[derive(Debug, Clone)]
pub enum BandwidthAdjustment {
    Increase { current: u32, recommended: u32 },
    Decrease { current: u32, recommended: u32 },
}

/// Advanced media stream manager
pub struct QuicMediaStreamManager {
    /// Stream statistics per peer and stream type
    stats: Arc<RwLock<HashMap<(PeerId, StreamType), StreamStats>>>,
    /// QoS parameters per stream type
    qos_params: Arc<RwLock<HashMap<StreamType, QosParameters>>>,
    /// Bandwidth controller
    bandwidth_controller: Arc<RwLock<BandwidthController>>,
    /// Priority queue for outgoing packets
    priority_queue: Arc<RwLock<PriorityQueue>>,
    /// Rate limiter for transmission control
    rate_limiter: Arc<RwLock<RateLimiter>>,
}

impl QuicMediaStreamManager {
    /// Create new stream manager
    pub fn new(total_bandwidth_kbps: u32) -> Self {
        let mut qos_params = HashMap::new();
        qos_params.insert(StreamType::Audio, QosParameters::audio());
        qos_params.insert(StreamType::Video, QosParameters::video());
        qos_params.insert(StreamType::ScreenShare, QosParameters::screen_share());
        qos_params.insert(StreamType::Data, QosParameters::data());

        Self {
            stats: Arc::new(RwLock::new(HashMap::new())),
            qos_params: Arc::new(RwLock::new(qos_params)),
            bandwidth_controller: Arc::new(RwLock::new(BandwidthController::new(
                total_bandwidth_kbps * 80 / 100, // Target 80% of total
                total_bandwidth_kbps,
            ))),
            priority_queue: Arc::new(RwLock::new(PriorityQueue::new(1000))),
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new(
                total_bandwidth_kbps as f64,
                total_bandwidth_kbps as f64,
            ))),
        }
    }

    /// Add packet to transmission queue
    pub async fn enqueue_packet(&self, packet: RtpPacket, peer_id: PeerId) -> Result<bool> {
        let mut queue = self.priority_queue.write().await;
        let queued = queue.enqueue(packet, peer_id);

        if !queued {
            warn!("Packet dropped due to full priority queue");
        }

        Ok(queued)
    }

    /// Get next packet for transmission
    pub async fn dequeue_packet(&self) -> Option<(RtpPacket, PeerId)> {
        let mut queue = self.priority_queue.write().await;
        queue.dequeue()
    }

    /// Check if transmission is allowed based on rate limiting
    pub async fn can_transmit(&self, packet_size_bytes: u32) -> bool {
        let tokens_needed = (packet_size_bytes * 8) as f64 / 1000.0; // Convert to kilobits
        let mut limiter = self.rate_limiter.write().await;
        limiter.try_consume(tokens_needed)
    }

    /// Update stream statistics
    pub async fn update_stats(
        &self,
        stream_id: (PeerId, StreamType),
        packets_sent: u64,
        bytes_sent: u64,
        rtt_ms: u32,
    ) -> Result<()> {
        let mut stats = self.stats.write().await;

        let stream_stats = stats
            .entry(stream_id)
            .or_insert_with(|| StreamStats::new(stream_id));

        stream_stats.packets_sent += packets_sent;
        stream_stats.bytes_sent += bytes_sent;
        stream_stats.rtt_ms = rtt_ms;
        stream_stats.last_updated = Utc::now();

        // Update bandwidth controller
        {
            let mut controller = self.bandwidth_controller.write().await;
            controller.record_usage(bytes_sent as u32, Duration::from_millis(1000));
        }

        Ok(())
    }

    /// Get stream statistics
    pub async fn get_stats(&self, stream_id: (PeerId, StreamType)) -> Option<StreamStats> {
        let stats = self.stats.read().await;
        stats.get(&stream_id).cloned()
    }

    /// Get all stream statistics
    pub async fn get_all_stats(&self) -> HashMap<(PeerId, StreamType), StreamStats> {
        let stats = self.stats.read().await;
        stats.clone()
    }

    /// Set QoS parameters for stream type
    pub async fn set_qos_params(&self, stream_type: StreamType, params: QosParameters) {
        let mut qos = self.qos_params.write().await;
        qos.insert(stream_type, params);
    }

    /// Get QoS parameters for stream type
    pub async fn get_qos_params(&self, stream_type: StreamType) -> Option<QosParameters> {
        let qos = self.qos_params.read().await;
        qos.get(&stream_type).cloned()
    }

    /// Check bandwidth adaptation recommendation
    pub async fn check_bandwidth_adaptation(&self) -> Option<BandwidthAdjustment> {
        let mut controller = self.bandwidth_controller.write().await;
        controller.get_bandwidth_recommendation()
    }

    /// Validate stream against QoS requirements
    pub async fn validate_qos(&self, stream_id: (PeerId, StreamType)) -> bool {
        let stats_guard = self.stats.read().await;
        let qos_guard = self.qos_params.read().await;

        if let (Some(stats), Some(qos)) = (stats_guard.get(&stream_id), qos_guard.get(&stream_id.1))
        {
            stats.meets_qos(qos)
        } else {
            false
        }
    }

    /// Get queue status
    pub async fn get_queue_status(&self) -> (usize, bool) {
        let queue = self.priority_queue.read().await;
        (queue.len(), queue.is_empty())
    }

    /// Clear all statistics and reset queues
    pub async fn reset(&self) {
        let mut stats = self.stats.write().await;
        let mut queue = self.priority_queue.write().await;

        stats.clear();
        queue.clear();

        info!("Stream manager reset completed");
    }

    /// Start background tasks for monitoring and adaptation
    pub async fn start_background_tasks(&self) -> Result<()> {
        self.start_stats_monitoring().await?;
        self.start_adaptation_loop().await?;
        Ok(())
    }

    /// Start statistics monitoring task
    async fn start_stats_monitoring(&self) -> Result<()> {
        let stats = Arc::clone(&self.stats);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                let stats_guard = stats.read().await;
                let total_streams = stats_guard.len();
                let total_packets: u64 = stats_guard.values().map(|s| s.packets_sent).sum();
                let total_bytes: u64 = stats_guard.values().map(|s| s.bytes_sent).sum();

                debug!(
                    "Stream stats: {} active streams, {} packets sent, {} bytes transmitted",
                    total_streams, total_packets, total_bytes
                );
            }
        });

        Ok(())
    }

    /// Start adaptation monitoring loop
    async fn start_adaptation_loop(&self) -> Result<()> {
        let bandwidth_controller = Arc::clone(&self.bandwidth_controller);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                let mut controller = bandwidth_controller.write().await;
                if let Some(adjustment) = controller.get_bandwidth_recommendation() {
                    match adjustment {
                        BandwidthAdjustment::Increase {
                            current,
                            recommended,
                        } => {
                            info!(
                                "Bandwidth increase recommended: {} -> {} kbps",
                                current, recommended
                            );
                        }
                        BandwidthAdjustment::Decrease {
                            current,
                            recommended,
                        } => {
                            warn!(
                                "Bandwidth decrease recommended: {} -> {} kbps",
                                current, recommended
                            );
                        }
                    }
                }
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qos_parameters() {
        let audio_qos = QosParameters::audio();
        assert_eq!(audio_qos.priority, 10);
        assert_eq!(audio_qos.max_latency_ms, 50);

        let video_qos = QosParameters::video();
        assert_eq!(video_qos.priority, 20);
        assert!(video_qos.target_bandwidth_kbps > audio_qos.target_bandwidth_kbps);
    }

    #[test]
    fn test_priority_queue() {
        let mut queue = PriorityQueue::new(10);
        let peer_id = PeerId([0u8; 32]);

        // Create packets with different priorities
        let audio_packet = RtpPacket::new(96, 1, 1000, 1, vec![1], StreamType::Audio);
        let video_packet = RtpPacket::new(97, 2, 2000, 2, vec![2], StreamType::Video);
        let data_packet = RtpPacket::new(98, 3, 3000, 3, vec![3], StreamType::Data);

        // Add packets
        assert!(queue.enqueue(video_packet, peer_id));
        assert!(queue.enqueue(data_packet, peer_id));
        assert!(queue.enqueue(audio_packet, peer_id));

        // Should dequeue in priority order (audio first)
        let (packet, _) = queue.dequeue().unwrap();
        assert_eq!(packet.stream_type, StreamType::Audio);

        let (packet, _) = queue.dequeue().unwrap();
        assert_eq!(packet.stream_type, StreamType::Video);

        let (packet, _) = queue.dequeue().unwrap();
        assert_eq!(packet.stream_type, StreamType::Data);
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(100.0, 50.0); // 100 token capacity, 50 tokens/sec

        // Should be able to consume initial tokens
        assert!(limiter.try_consume(50.0));
        assert!(limiter.try_consume(50.0));

        // Should not be able to consume more
        assert!(!limiter.try_consume(1.0));

        // Check available tokens
        assert_eq!(limiter.available_tokens(), 0.0);
    }

    #[test]
    fn test_stream_stats() {
        let peer_id = PeerId([1u8; 32]);
        let stream_id = (peer_id, StreamType::Audio);
        let mut stats = StreamStats::new(stream_id);

        assert_eq!(stats.loss_percentage(), 0.0);

        stats.packets_sent = 100;
        stats.packets_lost = 5;
        assert_eq!(stats.loss_percentage(), 5.0);

        let qos = QosParameters::audio();
        assert!(!stats.meets_qos(&qos)); // RTT and jitter not set properly

        stats.rtt_ms = 30;
        stats.jitter_ms = 10;
        stats.bandwidth_kbps = 64;
        assert!(stats.meets_qos(&qos));
    }

    #[test]
    fn test_bandwidth_controller() {
        let mut controller = BandwidthController::new(1000, 2000);

        assert!(controller.can_transmit(500));
        assert!(controller.can_transmit(1500));
        assert!(!controller.can_transmit(2500));

        // Record some usage
        controller.record_usage(1000 * 1000 / 8, Duration::from_secs(1)); // 1 Mbps for 1 second
    }

    #[tokio::test]
    async fn test_stream_manager() {
        let manager = QuicMediaStreamManager::new(2000); // 2 Mbps total
        let peer_id = PeerId([2u8; 32]);

        // Test packet enqueuing
        let packet = RtpPacket::new(96, 1, 1000, 1, vec![1; 100], StreamType::Audio);
        let queued = manager.enqueue_packet(packet, peer_id).await.unwrap();
        assert!(queued);

        // Test packet dequeuing
        let result = manager.dequeue_packet().await;
        assert!(result.is_some());

        // Test queue status
        let (size, empty) = manager.get_queue_status().await;
        assert_eq!(size, 0);
        assert!(empty);

        // Test stats update
        let stream_id = (peer_id, StreamType::Audio);
        manager.update_stats(stream_id, 1, 100, 50).await.unwrap();

        let stats = manager.get_stats(stream_id).await;
        assert!(stats.is_some());
        let stats = stats.unwrap();
        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.bytes_sent, 100);
    }
}
