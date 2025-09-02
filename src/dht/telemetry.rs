//! DHT telemetry and performance monitoring
//!
//! Tracks P50/P95 lookup latency, hops, success rates, and churn metrics
//! for DHT performance analysis and optimization.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;

/// Telemetry data point
#[derive(Debug, Clone)]
pub struct TelemetryPoint {
    pub timestamp: SystemTime,
    pub operation: OperationType,
    pub duration: Duration,
    pub hops: usize,
    pub success: bool,
    pub error_type: Option<String>,
}

/// Operation types for telemetry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationType {
    Put,
    Get,
    FindNode,
    Provide,
}

/// DHT telemetry collector
pub struct DhtTelemetry {
    /// Recent telemetry points (rolling window)
    points: Arc<RwLock<VecDeque<TelemetryPoint>>>,
    /// Maximum number of points to keep
    max_points: usize,
    /// Start time for uptime calculation
    start_time: Instant,
}

impl DhtTelemetry {
    /// Create new telemetry collector
    pub fn new(max_points: usize) -> Self {
        Self {
            points: Arc::new(RwLock::new(VecDeque::new())),
            max_points,
            start_time: Instant::now(),
        }
    }

    /// Record a telemetry point
    pub async fn record(&self, point: TelemetryPoint) {
        let mut points = self.points.write().await;
        points.push_back(point);

        // Maintain rolling window
        while points.len() > self.max_points {
            points.pop_front();
        }
    }

    /// Record a PUT operation
    pub async fn record_put(
        &self,
        duration: Duration,
        hops: usize,
        success: bool,
        error: Option<String>,
    ) {
        self.record(TelemetryPoint {
            timestamp: SystemTime::now(),
            operation: OperationType::Put,
            duration,
            hops,
            success,
            error_type: error,
        })
        .await;
    }

    /// Record a GET operation
    pub async fn record_get(
        &self,
        duration: Duration,
        hops: usize,
        success: bool,
        error: Option<String>,
    ) {
        self.record(TelemetryPoint {
            timestamp: SystemTime::now(),
            operation: OperationType::Get,
            duration,
            hops,
            success,
            error_type: error,
        })
        .await;
    }

    /// Record a FIND_NODE operation
    pub async fn record_find_node(
        &self,
        duration: Duration,
        hops: usize,
        success: bool,
        error: Option<String>,
    ) {
        self.record(TelemetryPoint {
            timestamp: SystemTime::now(),
            operation: OperationType::FindNode,
            duration,
            hops,
            success,
            error_type: error,
        })
        .await;
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> TelemetryStats {
        let points = self.points.read().await;

        if points.is_empty() {
            return TelemetryStats::default();
        }

        // Calculate latency percentiles
        let mut latencies: Vec<_> = points
            .iter()
            .map(|p| p.duration.as_millis() as u64)
            .collect();
        latencies.sort();

        let p50 = percentile(&latencies, 50);
        let p95 = percentile(&latencies, 95);
        let p99 = percentile(&latencies, 99);

        // Calculate success rates by operation type
        let mut operation_stats = HashMap::new();
        for op_type in &[
            OperationType::Put,
            OperationType::Get,
            OperationType::FindNode,
            OperationType::Provide,
        ] {
            let op_points: Vec<_> = points.iter().filter(|p| p.operation == *op_type).collect();

            if !op_points.is_empty() {
                let total = op_points.len();
                let successful = op_points.iter().filter(|p| p.success).count();
                let success_rate = successful as f64 / total as f64;

                let avg_hops =
                    op_points.iter().map(|p| p.hops).sum::<usize>() as f64 / total as f64;
                let avg_latency = op_points
                    .iter()
                    .map(|p| p.duration.as_millis())
                    .sum::<u128>() as f64
                    / total as f64;

                operation_stats.insert(
                    *op_type,
                    OperationStats {
                        total_operations: total,
                        success_rate,
                        avg_hops,
                        avg_latency_ms: avg_latency,
                    },
                );
            }
        }

        // Calculate churn (simplified: operations per minute)
        let uptime_minutes = self.start_time.elapsed().as_secs() / 60;
        let churn_rate = if uptime_minutes > 0 {
            points.len() as f64 / uptime_minutes as f64
        } else {
            0.0
        };

        TelemetryStats {
            total_operations: points.len(),
            p50_latency_ms: p50,
            p95_latency_ms: p95,
            p99_latency_ms: p99,
            operation_stats,
            churn_rate_per_minute: churn_rate,
            uptime_seconds: self.start_time.elapsed().as_secs(),
        }
    }

    /// Get recent error summary
    pub async fn get_error_summary(&self) -> HashMap<String, usize> {
        let points = self.points.read().await;
        let mut errors = HashMap::new();

        for point in points.iter() {
            if !point.success {
                if let Some(error_type) = &point.error_type {
                    *errors.entry(error_type.clone()).or_insert(0) += 1;
                } else {
                    *errors.entry("unknown".to_string()).or_insert(0) += 1;
                }
            }
        }

        errors
    }
}

/// Telemetry statistics
#[derive(Debug, Clone)]
pub struct TelemetryStats {
    pub total_operations: usize,
    pub p50_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub p99_latency_ms: u64,
    pub operation_stats: HashMap<OperationType, OperationStats>,
    pub churn_rate_per_minute: f64,
    pub uptime_seconds: u64,
}

impl Default for TelemetryStats {
    fn default() -> Self {
        Self {
            total_operations: 0,
            p50_latency_ms: 0,
            p95_latency_ms: 0,
            p99_latency_ms: 0,
            operation_stats: HashMap::new(),
            churn_rate_per_minute: 0.0,
            uptime_seconds: 0,
        }
    }
}

/// Statistics for a specific operation type
#[derive(Debug, Clone)]
pub struct OperationStats {
    pub total_operations: usize,
    pub success_rate: f64,
    pub avg_hops: f64,
    pub avg_latency_ms: f64,
}

/// Calculate percentile from sorted data
fn percentile(sorted_data: &[u64], percentile: u8) -> u64 {
    if sorted_data.is_empty() {
        return 0;
    }

    let pos = percentile as f64 / 100.0 * (sorted_data.len() - 1) as f64;
    let index = pos.ceil() as usize;
    sorted_data[index.min(sorted_data.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_telemetry_recording() {
        let telemetry = DhtTelemetry::new(1000);

        // Record some operations
        telemetry
            .record_put(Duration::from_millis(50), 3, true, None)
            .await;
        telemetry
            .record_get(Duration::from_millis(100), 4, true, None)
            .await;
        telemetry
            .record_find_node(Duration::from_millis(25), 2, true, None)
            .await;
        telemetry
            .record_put(
                Duration::from_millis(200),
                5,
                false,
                Some("timeout".to_string()),
            )
            .await;

        let stats = telemetry.get_stats().await;

        assert_eq!(stats.total_operations, 4);
        assert!(stats.p50_latency_ms > 0);
        assert!(stats.p95_latency_ms > 0);

        // Check operation-specific stats
        assert!(stats.operation_stats.contains_key(&OperationType::Put));
        assert!(stats.operation_stats.contains_key(&OperationType::Get));

        let put_stats = &stats.operation_stats[&OperationType::Put];
        assert_eq!(put_stats.total_operations, 2);
        assert_eq!(put_stats.success_rate, 0.5); // 1 success out of 2
    }

    #[test]
    fn test_percentile_calculation() {
        let data = vec![10, 20, 30, 40, 50];
        assert_eq!(percentile(&data, 50), 30); // Median
        assert_eq!(percentile(&data, 95), 50); // 95th percentile
    }

    #[tokio::test]
    async fn test_error_summary() {
        let telemetry = DhtTelemetry::new(1000);

        telemetry
            .record_put(
                Duration::from_millis(100),
                3,
                false,
                Some("timeout".to_string()),
            )
            .await;
        telemetry
            .record_get(
                Duration::from_millis(100),
                3,
                false,
                Some("timeout".to_string()),
            )
            .await;
        telemetry
            .record_put(
                Duration::from_millis(100),
                3,
                false,
                Some("network_error".to_string()),
            )
            .await;

        let errors = telemetry.get_error_summary().await;

        assert_eq!(errors.get("timeout").copied().unwrap_or(0), 2);
        assert_eq!(errors.get("network_error").copied().unwrap_or(0), 1);
    }
}
