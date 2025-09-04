// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Telemetry module for metrics, tracing, and health signals.
//!
//! Provides observability into system performance and health.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Core metrics structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    /// Lookup latency P95 in milliseconds
    pub lookups_p95_ms: u64,
    /// Hop count P95
    pub hop_p95: u8,
    /// Timeout rate (0.0 to 1.0)
    pub timeout_rate: f32,
}

/// Stream class for QoS tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StreamClass {
    Control,
    Mls,
    File,
    Media,
}

/// Telemetry collector for system metrics
pub struct TelemetryCollector {
    /// Lookup latencies in microseconds
    lookup_latencies: Arc<RwLock<VecDeque<u64>>>,
    /// Hop counts
    hop_counts: Arc<RwLock<VecDeque<u8>>>,
    /// Total operations count
    total_ops: Arc<AtomicUsize>,
    /// Timeout count
    timeouts: Arc<AtomicUsize>,
    /// DHT put counter
    dht_puts: Arc<AtomicU64>,
    /// DHT get counter
    dht_gets: Arc<AtomicU64>,
    /// Auth failure counter
    auth_failures: Arc<AtomicU64>,
    /// Stream bandwidth by class (bytes/sec)
    stream_bandwidth: Arc<RwLock<HashMap<StreamClass, VecDeque<u64>>>>,
    /// Stream RTT by class (microseconds)
    stream_rtt: Arc<RwLock<HashMap<StreamClass, VecDeque<u64>>>>,
}

use std::collections::HashMap;

impl TelemetryCollector {
    /// Create a new telemetry collector
    pub fn new() -> Self {
        Self {
            lookup_latencies: Arc::new(RwLock::new(VecDeque::with_capacity(1000))),
            hop_counts: Arc::new(RwLock::new(VecDeque::with_capacity(1000))),
            total_ops: Arc::new(AtomicUsize::new(0)),
            timeouts: Arc::new(AtomicUsize::new(0)),
            dht_puts: Arc::new(AtomicU64::new(0)),
            dht_gets: Arc::new(AtomicU64::new(0)),
            auth_failures: Arc::new(AtomicU64::new(0)),
            stream_bandwidth: Arc::new(RwLock::new(HashMap::new())),
            stream_rtt: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a lookup operation
    pub async fn record_lookup(&self, latency: Duration, hops: u8) {
        self.total_ops.fetch_add(1, Ordering::Relaxed);

        let micros = latency.as_micros() as u64;
        let mut latencies = self.lookup_latencies.write().await;
        if latencies.len() >= 1000 {
            latencies.pop_front();
        }
        latencies.push_back(micros);

        let mut hop_counts = self.hop_counts.write().await;
        if hop_counts.len() >= 1000 {
            hop_counts.pop_front();
        }
        hop_counts.push_back(hops);
    }

    /// Record a timeout
    pub fn record_timeout(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
        self.total_ops.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a DHT put operation
    pub fn record_dht_put(&self) {
        self.dht_puts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a DHT get operation
    pub fn record_dht_get(&self) {
        self.dht_gets.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an auth failure
    pub fn record_auth_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record stream bandwidth
    pub async fn record_stream_bandwidth(&self, class: StreamClass, bytes_per_sec: u64) {
        let mut bandwidth = self.stream_bandwidth.write().await;
        let samples = bandwidth
            .entry(class)
            .or_insert_with(|| VecDeque::with_capacity(100));

        if samples.len() >= 100 {
            samples.pop_front();
        }
        samples.push_back(bytes_per_sec);
    }

    /// Record stream RTT
    pub async fn record_stream_rtt(&self, class: StreamClass, rtt: Duration) {
        let micros = rtt.as_micros() as u64;
        let mut rtts = self.stream_rtt.write().await;
        let samples = rtts
            .entry(class)
            .or_insert_with(|| VecDeque::with_capacity(100));

        if samples.len() >= 100 {
            samples.pop_front();
        }
        samples.push_back(micros);
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> Metrics {
        let latencies = self.lookup_latencies.read().await;
        let hops = self.hop_counts.read().await;

        let lookups_p95_ms = calculate_percentile(&latencies, 95) / 1000;
        let hop_p95 = calculate_percentile_u8(&hops, 95);

        let total = self.total_ops.load(Ordering::Relaxed) as f32;
        let timeouts = self.timeouts.load(Ordering::Relaxed) as f32;
        let timeout_rate = if total > 0.0 { timeouts / total } else { 0.0 };

        Metrics {
            lookups_p95_ms,
            hop_p95,
            timeout_rate,
        }
    }

    /// Get event counters
    pub fn get_counters(&self) -> EventCounters {
        EventCounters {
            dht_puts: self.dht_puts.load(Ordering::Relaxed),
            dht_gets: self.dht_gets.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
        }
    }

    /// Get stream metrics for a class
    pub async fn get_stream_metrics(&self, class: StreamClass) -> Option<StreamMetrics> {
        let bandwidth = self.stream_bandwidth.read().await;
        let rtts = self.stream_rtt.read().await;

        let bw_samples = bandwidth.get(&class)?;
        let rtt_samples = rtts.get(&class)?;

        if bw_samples.is_empty() || rtt_samples.is_empty() {
            return None;
        }

        Some(StreamMetrics {
            bandwidth_p50: calculate_percentile(bw_samples, 50),
            bandwidth_p95: calculate_percentile(bw_samples, 95),
            rtt_p50_ms: calculate_percentile(rtt_samples, 50) / 1000,
            rtt_p95_ms: calculate_percentile(rtt_samples, 95) / 1000,
        })
    }

    /// Record stream class usage
    pub async fn record_stream_class_usage(&self, class: StreamClass) {
        // Track stream class usage for QoS monitoring
        let class_id = match class {
            StreamClass::Control => "control",
            StreamClass::Mls => "mls",
            StreamClass::File => "file",
            StreamClass::Media => "media",
        };

        // For now, just log the usage - could be extended to track counts
        tracing::debug!("Stream class {} opened", class_id);

        // Record a bandwidth sample for the class (placeholder value)
        self.record_stream_bandwidth(class, 1024).await;
    }

    /// Reset all metrics
    pub async fn reset(&self) {
        self.lookup_latencies.write().await.clear();
        self.hop_counts.write().await.clear();
        self.total_ops.store(0, Ordering::Relaxed);
        self.timeouts.store(0, Ordering::Relaxed);
        self.dht_puts.store(0, Ordering::Relaxed);
        self.dht_gets.store(0, Ordering::Relaxed);
        self.auth_failures.store(0, Ordering::Relaxed);
        self.stream_bandwidth.write().await.clear();
        self.stream_rtt.write().await.clear();
    }
}

impl Default for TelemetryCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Event counters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventCounters {
    pub dht_puts: u64,
    pub dht_gets: u64,
    pub auth_failures: u64,
}

/// Stream metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamMetrics {
    pub bandwidth_p50: u64,
    pub bandwidth_p95: u64,
    pub rtt_p50_ms: u64,
    pub rtt_p95_ms: u64,
}

/// Calculate percentile for u64 values
fn calculate_percentile(samples: &VecDeque<u64>, percentile: usize) -> u64 {
    if samples.is_empty() {
        return 0;
    }

    let mut sorted: Vec<u64> = samples.iter().copied().collect();
    sorted.sort_unstable();

    let index = (sorted.len() * percentile) / 100;
    let index = index.min(sorted.len() - 1);

    sorted[index]
}

/// Calculate percentile for u8 values
fn calculate_percentile_u8(samples: &VecDeque<u8>, percentile: usize) -> u8 {
    if samples.is_empty() {
        return 0;
    }

    let mut sorted: Vec<u8> = samples.iter().copied().collect();
    sorted.sort_unstable();

    let index = (sorted.len() * percentile) / 100;
    let index = index.min(sorted.len() - 1);

    sorted[index]
}

/// Health check status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub uptime: Duration,
    pub metrics: Metrics,
    pub counters: EventCounters,
}

/// Health monitor
pub struct HealthMonitor {
    start_time: Instant,
    collector: Arc<TelemetryCollector>,
}

impl HealthMonitor {
    /// Create a new health monitor
    pub fn new(collector: Arc<TelemetryCollector>) -> Self {
        Self {
            start_time: Instant::now(),
            collector,
        }
    }

    /// Get health status
    pub async fn get_status(&self) -> HealthStatus {
        let metrics = self.collector.get_metrics().await;
        let counters = self.collector.get_counters();

        // Simple health check: timeout rate < 10% and latency < 5 seconds
        let healthy = metrics.timeout_rate < 0.1 && metrics.lookups_p95_ms < 5000;

        HealthStatus {
            healthy,
            uptime: self.start_time.elapsed(),
            metrics,
            counters,
        }
    }
}

/// Global telemetry instance
static GLOBAL_TELEMETRY: once_cell::sync::Lazy<Arc<TelemetryCollector>> =
    once_cell::sync::Lazy::new(|| Arc::new(TelemetryCollector::new()));

/// Get the global telemetry collector
pub fn telemetry() -> Arc<TelemetryCollector> {
    GLOBAL_TELEMETRY.clone()
}

/// Record a lookup operation globally
pub async fn record_lookup(latency: Duration, hops: u8) {
    telemetry().record_lookup(latency, hops).await;
}

/// Record a timeout globally
pub fn record_timeout() {
    telemetry().record_timeout();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_telemetry_collector() {
        let collector = TelemetryCollector::new();

        // Record some lookups
        collector.record_lookup(Duration::from_millis(10), 3).await;
        collector.record_lookup(Duration::from_millis(20), 4).await;
        collector.record_lookup(Duration::from_millis(30), 5).await;

        // Record a timeout
        collector.record_timeout();

        // Get metrics
        let metrics = collector.get_metrics().await;
        assert!(metrics.lookups_p95_ms > 0);
        assert!(metrics.hop_p95 > 0);
        assert!(metrics.timeout_rate > 0.0);
    }

    #[tokio::test]
    async fn test_event_counters() {
        let collector = TelemetryCollector::new();

        collector.record_dht_put();
        collector.record_dht_put();
        collector.record_dht_get();
        collector.record_auth_failure();

        let counters = collector.get_counters();
        assert_eq!(counters.dht_puts, 2);
        assert_eq!(counters.dht_gets, 1);
        assert_eq!(counters.auth_failures, 1);
    }

    #[tokio::test]
    async fn test_stream_metrics() {
        let collector = TelemetryCollector::new();

        collector
            .record_stream_bandwidth(StreamClass::Media, 1000000)
            .await;
        collector
            .record_stream_bandwidth(StreamClass::Media, 2000000)
            .await;

        collector
            .record_stream_rtt(StreamClass::Media, Duration::from_millis(10))
            .await;
        collector
            .record_stream_rtt(StreamClass::Media, Duration::from_millis(20))
            .await;

        let metrics = collector
            .get_stream_metrics(StreamClass::Media)
            .await
            .unwrap();
        assert!(metrics.bandwidth_p50 > 0);
        assert!(metrics.rtt_p50_ms > 0);
    }

    #[tokio::test]
    async fn test_health_monitor() {
        let collector = Arc::new(TelemetryCollector::new());
        let monitor = HealthMonitor::new(collector.clone());

        // Record some healthy operations
        collector.record_lookup(Duration::from_millis(100), 3).await;

        let status = monitor.get_status().await;
        assert!(status.healthy);
        assert!(status.uptime.as_secs() < 10);
    }

    #[test]
    fn test_percentile_calculation() {
        let mut samples = VecDeque::new();
        for i in 1..=100 {
            samples.push_back(i as u64);
        }

        // Due to 0-based indexing, 50th percentile of 1-100 gives index 50 which is value 51
        assert_eq!(calculate_percentile(&samples, 50), 51);
        assert_eq!(calculate_percentile(&samples, 95), 96);
    }
}
