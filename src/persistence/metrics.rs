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

//! Storage metrics collection and reporting

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Metrics collector for storage operations
pub struct MetricsCollector {
    /// Read operation metrics
    read_metrics: Arc<RwLock<OperationMetrics>>,
    
    /// Write operation metrics
    write_metrics: Arc<RwLock<OperationMetrics>>,
    
    /// Delete operation metrics
    delete_metrics: Arc<RwLock<OperationMetrics>>,
}

#[derive(Debug, Default)]
struct OperationMetrics {
    count: u64,
    total_duration: Duration,
    min_duration: Option<Duration>,
    max_duration: Option<Duration>,
    errors: u64,
}

impl MetricsCollector {
    /// Create new metrics collector
    pub fn new() -> Self {
        Self {
            read_metrics: Arc::new(RwLock::new(OperationMetrics::default())),
            write_metrics: Arc::new(RwLock::new(OperationMetrics::default())),
            delete_metrics: Arc::new(RwLock::new(OperationMetrics::default())),
        }
    }
    
    /// Record a read operation
    pub async fn record_read(&self, duration: Duration, success: bool) {
        let mut metrics = self.read_metrics.write().await;
        Self::record_operation(&mut metrics, duration, success);
    }
    
    /// Record a write operation
    pub async fn record_write(&self, duration: Duration, success: bool) {
        let mut metrics = self.write_metrics.write().await;
        Self::record_operation(&mut metrics, duration, success);
    }
    
    /// Record a delete operation
    pub async fn record_delete(&self, duration: Duration, success: bool) {
        let mut metrics = self.delete_metrics.write().await;
        Self::record_operation(&mut metrics, duration, success);
    }
    
    /// Record an operation in metrics
    fn record_operation(metrics: &mut OperationMetrics, duration: Duration, success: bool) {
        metrics.count += 1;
        metrics.total_duration += duration;
        
        if success {
            // Update min/max
            if let Some(min) = metrics.min_duration {
                if duration < min {
                    metrics.min_duration = Some(duration);
                }
            } else {
                metrics.min_duration = Some(duration);
            }
            
            if let Some(max) = metrics.max_duration {
                if duration > max {
                    metrics.max_duration = Some(duration);
                }
            } else {
                metrics.max_duration = Some(duration);
            }
        } else {
            metrics.errors += 1;
        }
    }
    
    /// Get average read latency
    pub async fn avg_read_latency(&self) -> Duration {
        let metrics = self.read_metrics.read().await;
        if metrics.count > 0 {
            metrics.total_duration / metrics.count as u32
        } else {
            Duration::ZERO
        }
    }
    
    /// Get average write latency
    pub async fn avg_write_latency(&self) -> Duration {
        let metrics = self.write_metrics.read().await;
        if metrics.count > 0 {
            metrics.total_duration / metrics.count as u32
        } else {
            Duration::ZERO
        }
    }
    
    /// Reset all metrics
    pub async fn reset(&self) {
        *self.read_metrics.write().await = OperationMetrics::default();
        *self.write_metrics.write().await = OperationMetrics::default();
        *self.delete_metrics.write().await = OperationMetrics::default();
    }
}

/// Timer for measuring operation duration
pub struct Timer {
    start: Instant,
}

impl Timer {
    /// Start a new timer
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }
    
    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}