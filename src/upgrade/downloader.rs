// Copyright (c) 2025 Saorsa Labs Limited

// This file is part of the Saorsa P2P network.

// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Copyright 2024 P2P Foundation
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP downloader for update binaries with resume support.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

use super::error::UpgradeError;

/// Progress callback for download tracking.
pub type ProgressCallback = Box<dyn Fn(DownloadProgress) + Send + Sync>;

/// Download progress information.
#[derive(Debug, Clone, Copy)]
pub struct DownloadProgress {
    /// Bytes downloaded so far.
    pub downloaded: u64,

    /// Total bytes to download.
    pub total: u64,

    /// Current download speed in bytes per second.
    pub speed_bps: u64,

    /// Estimated time remaining in seconds.
    pub eta_seconds: u64,
}

impl DownloadProgress {
    /// Get progress as a percentage (0.0 to 100.0).
    #[must_use]
    pub fn percentage(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.downloaded as f64 / self.total as f64) * 100.0
        }
    }
}

/// Configuration for the downloader.
#[derive(Debug, Clone)]
pub struct DownloaderConfig {
    /// Maximum download size in bytes.
    pub max_size: u64,

    /// Connection timeout.
    pub connect_timeout: Duration,

    /// Read timeout.
    pub read_timeout: Duration,

    /// Number of retry attempts.
    pub max_retries: u32,

    /// Delay between retries.
    pub retry_delay: Duration,

    /// User-Agent header.
    pub user_agent: String,

    /// Buffer size for reads.
    pub buffer_size: usize,

    /// Progress update interval.
    pub progress_interval: Duration,
}

impl Default for DownloaderConfig {
    fn default() -> Self {
        Self {
            max_size: 500 * 1024 * 1024, // 500 MB
            connect_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(60),
            max_retries: 3,
            retry_delay: Duration::from_secs(5),
            user_agent: format!("saorsa-core/{}", env!("CARGO_PKG_VERSION")),
            buffer_size: 64 * 1024, // 64 KB
            progress_interval: Duration::from_millis(500),
        }
    }
}

/// HTTP downloader with resume support.
pub struct Downloader {
    config: DownloaderConfig,
    client: reqwest::Client,
    cancelled: Arc<AtomicBool>,
}

impl Downloader {
    /// Create a new downloader with default configuration.
    pub fn new() -> Result<Self, UpgradeError> {
        Self::with_config(DownloaderConfig::default())
    }

    /// Create a new downloader with custom configuration.
    pub fn with_config(config: DownloaderConfig) -> Result<Self, UpgradeError> {
        let client = reqwest::Client::builder()
            .connect_timeout(config.connect_timeout)
            .timeout(config.read_timeout)
            .user_agent(&config.user_agent)
            .build()
            .map_err(|e| UpgradeError::download(format!("failed to create HTTP client: {}", e)))?;

        Ok(Self {
            config,
            client,
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Get a cancellation token for this downloader.
    #[must_use]
    pub fn cancel_token(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    /// Cancel the current download.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Reset the cancellation flag.
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::Release);
    }

    /// Download a file from URL to the specified path.
    ///
    /// Supports resume if the file already partially exists.
    pub async fn download(
        &self,
        url: &str,
        dest: &Path,
        expected_size: Option<u64>,
        progress: Option<ProgressCallback>,
    ) -> Result<u64, UpgradeError> {
        self.reset();

        // Check size limit
        if let Some(size) = expected_size
            && size > self.config.max_size
        {
            return Err(UpgradeError::DownloadTooLarge {
                actual: size,
                max: self.config.max_size,
            });
        }

        let mut last_error = None;
        let mut attempt = 0;

        while attempt < self.config.max_retries {
            attempt += 1;

            match self
                .download_attempt(url, dest, expected_size, progress.as_ref())
                .await
            {
                Ok(size) => return Ok(size),
                Err(e) => {
                    if self.cancelled.load(Ordering::Acquire) {
                        return Err(UpgradeError::Cancelled("download cancelled".into()));
                    }

                    if !e.is_recoverable() {
                        return Err(e);
                    }

                    last_error = Some(e);

                    if attempt < self.config.max_retries {
                        tokio::time::sleep(self.config.retry_delay).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| UpgradeError::download("download failed after retries")))
    }

    /// Single download attempt.
    async fn download_attempt(
        &self,
        url: &str,
        dest: &Path,
        expected_size: Option<u64>,
        progress: Option<&ProgressCallback>,
    ) -> Result<u64, UpgradeError> {
        // Check for existing partial download
        let existing_size = if dest.exists() {
            tokio::fs::metadata(dest)
                .await
                .map(|m| m.len())
                .unwrap_or(0)
        } else {
            0
        };

        // Build request with optional Range header for resume
        let mut request = self.client.get(url);

        if existing_size > 0 {
            request = request.header("Range", format!("bytes={}-", existing_size));
        }

        let response = request
            .send()
            .await
            .map_err(|e| UpgradeError::download(format!("request failed: {}", e)))?;

        let status = response.status();

        // Handle different status codes
        if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
            // File is complete
            return Ok(existing_size);
        }

        if !status.is_success() && status != reqwest::StatusCode::PARTIAL_CONTENT {
            return Err(UpgradeError::download(format!(
                "server returned status: {}",
                status
            )));
        }

        // Determine total size
        let content_length = response.content_length();
        let total_size = if status == reqwest::StatusCode::PARTIAL_CONTENT {
            // For partial content, try to parse Content-Range header
            response
                .headers()
                .get("Content-Range")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split('/').next_back())
                .and_then(|s| s.parse::<u64>().ok())
                .or(expected_size)
                .unwrap_or(existing_size + content_length.unwrap_or(0))
        } else {
            content_length.or(expected_size).unwrap_or(0)
        };

        // Validate size
        if total_size > self.config.max_size {
            return Err(UpgradeError::DownloadTooLarge {
                actual: total_size,
                max: self.config.max_size,
            });
        }

        // Open file for writing (append if resuming)
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(existing_size > 0)
            .truncate(existing_size == 0)
            .open(dest)
            .await
            .map_err(|e| UpgradeError::io(format!("failed to open file: {}", e)))?;

        // Download with progress tracking
        let downloaded = Arc::new(AtomicU64::new(existing_size));
        let start_time = std::time::Instant::now();

        let mut stream = response.bytes_stream();

        use futures::StreamExt;

        while let Some(chunk_result) = stream.next().await {
            // Check cancellation
            if self.cancelled.load(Ordering::Acquire) {
                return Err(UpgradeError::Cancelled("download cancelled".into()));
            }

            let chunk = chunk_result.map_err(|e| UpgradeError::download(format!("stream error: {}", e)))?;

            file.write_all(&chunk)
                .await
                .map_err(|e| UpgradeError::io(format!("write error: {}", e)))?;

            let current = downloaded.fetch_add(chunk.len() as u64, Ordering::Relaxed) + chunk.len() as u64;

            // Report progress
            if let Some(ref callback) = progress {
                let elapsed = start_time.elapsed().as_secs_f64();
                let speed_bps = if elapsed > 0.0 {
                    ((current - existing_size) as f64 / elapsed) as u64
                } else {
                    0
                };

                let remaining = total_size.saturating_sub(current);
                let eta_seconds = if speed_bps > 0 {
                    remaining / speed_bps
                } else {
                    0
                };

                callback(DownloadProgress {
                    downloaded: current,
                    total: total_size,
                    speed_bps,
                    eta_seconds,
                });
            }
        }

        file.flush()
            .await
            .map_err(|e| UpgradeError::io(format!("flush error: {}", e)))?;

        let final_size = downloaded.load(Ordering::Acquire);

        // Verify size if expected
        if let Some(expected) = expected_size
            && final_size != expected
        {
            return Err(UpgradeError::download(format!(
                "size mismatch: expected {}, got {}",
                expected, final_size
            )));
        }

        Ok(final_size)
    }

    /// Fetch a manifest from URL.
    pub async fn fetch_manifest(&self, url: &str) -> Result<String, UpgradeError> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| UpgradeError::manifest_fetch(format!("request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(UpgradeError::manifest_fetch(format!(
                "server returned status: {}",
                response.status()
            )));
        }

        let text = response
            .text()
            .await
            .map_err(|e| UpgradeError::manifest_fetch(format!("failed to read response: {}", e)))?;

        Ok(text)
    }
}

// Note: No Default impl since Downloader::new() can fail.
// Use Downloader::new() directly.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_percentage() {
        let progress = DownloadProgress {
            downloaded: 50,
            total: 100,
            speed_bps: 1000,
            eta_seconds: 0,
        };

        assert!((progress.percentage() - 50.0).abs() < 0.001);

        let zero_progress = DownloadProgress {
            downloaded: 0,
            total: 0,
            speed_bps: 0,
            eta_seconds: 0,
        };

        assert!((zero_progress.percentage() - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_config_defaults() {
        let config = DownloaderConfig::default();
        assert_eq!(config.max_size, 500 * 1024 * 1024);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.buffer_size, 64 * 1024);
    }

    #[test]
    fn test_downloader_creation() {
        let downloader = Downloader::new();
        assert!(downloader.is_ok());
    }

    #[test]
    fn test_cancel_token() {
        let downloader = Downloader::new().unwrap();
        let token = downloader.cancel_token();

        assert!(!token.load(Ordering::Acquire));

        downloader.cancel();
        assert!(token.load(Ordering::Acquire));

        downloader.reset();
        assert!(!token.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn test_size_validation() {
        let config = DownloaderConfig {
            max_size: 100,
            ..Default::default()
        };

        let downloader = Downloader::with_config(config).unwrap();

        let result = downloader
            .download(
                "http://example.com/file",
                Path::new("/tmp/test"),
                Some(1000),
                None,
            )
            .await;

        assert!(matches!(result, Err(UpgradeError::DownloadTooLarge { .. })));
    }
}
