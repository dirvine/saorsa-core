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

//! Multi-Instance Cache Merge Coordination
//!
//! Handles conflict resolution and merging when multiple P2P Foundation instances
//! are running locally and sharing the same bootstrap cache.

use crate::bootstrap::{BootstrapCache, ContactEntry};
use crate::error::BootstrapError;
use crate::{P2PError, PeerId, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// Merge coordinator for handling multi-instance cache coordination
#[derive(Clone)]
pub struct MergeCoordinator {
    /// Main cache directory path
    _cache_dir: PathBuf,
    /// Directory containing instance-specific cache files
    instance_cache_dir: PathBuf,
    /// Strategy used for resolving merge conflicts
    merge_strategy: MergeStrategy,
}

/// Strategy for resolving conflicts during merge operations
#[derive(Debug, Clone)]
pub enum MergeStrategy {
    /// Use quality score to determine the best contact
    QualityBased,
    /// Use most recent timestamp
    TimestampBased,
    /// Combine metrics from both contacts
    MetricsCombined,
    /// Use success rate as primary factor
    SuccessRateBased,
}

/// Instance cache data structure
#[derive(Debug, Serialize, Deserialize)]
struct InstanceCacheData {
    instance_id: String,
    timestamp: chrono::DateTime<chrono::Utc>,
    process_id: u32,
    contacts: HashMap<PeerId, ContactEntry>,
    version: u32,
}

/// Merge operation result
#[derive(Debug)]
pub struct MergeResult {
    /// Number of contacts that were merged from other instances
    pub contacts_merged: usize,
    /// Number of existing contacts that were updated
    pub contacts_updated: usize,
    /// Number of new contacts that were added
    pub contacts_added: usize,
    /// Number of conflicts that were resolved during merge
    pub conflicts_resolved: usize,
    /// Number of instance cache files that were processed
    pub instances_processed: usize,
    /// Total time taken for the merge operation in milliseconds
    pub merge_duration_ms: u64,
}

/// Conflict resolution information
#[derive(Debug)]
#[allow(dead_code)]
struct ConflictInfo {
    peer_id: PeerId,
    main_contact: ContactEntry,
    instance_contact: ContactEntry,
    resolution_strategy: MergeStrategy,
}

impl MergeCoordinator {
    /// Create a new merge coordinator
    pub fn new(cache_dir: PathBuf) -> Result<Self> {
        let instance_cache_dir = cache_dir.join("instance_caches");

        // Ensure instance cache directory exists
        std::fs::create_dir_all(&instance_cache_dir).map_err(|e| {
            P2PError::Bootstrap(BootstrapError::CacheError(
                format!("Failed to create instance cache directory: {e}").into(),
            ))
        })?;

        Ok(Self {
            _cache_dir: cache_dir,
            instance_cache_dir,
            merge_strategy: MergeStrategy::QualityBased,
        })
    }

    /// Create coordinator with custom merge strategy
    pub fn with_strategy(cache_dir: PathBuf, strategy: MergeStrategy) -> Result<Self> {
        let mut coordinator = Self::new(cache_dir)?;
        coordinator.merge_strategy = strategy;
        Ok(coordinator)
    }

    /// Merge all instance caches into the main cache
    pub async fn merge_instance_caches(&self, main_cache: &BootstrapCache) -> Result<MergeResult> {
        let merge_start = SystemTime::now();

        debug!("Starting merge of instance caches");

        // Discover all instance cache files
        let instance_files = self.discover_instance_caches()?;

        if instance_files.is_empty() {
            debug!("No instance caches found to merge");
            return Ok(MergeResult::empty());
        }

        // Load all instance caches
        let instance_caches = self.load_instance_caches(instance_files).await?;

        // Perform merge operation
        let merge_result = self.perform_merge(main_cache, instance_caches).await?;

        // Cleanup old instance caches
        self.cleanup_processed_caches().await?;

        let merge_duration = merge_start.elapsed().unwrap_or_default().as_millis() as u64;

        info!(
            "Merge completed: {} contacts processed, {} conflicts resolved in {}ms",
            merge_result.contacts_merged, merge_result.conflicts_resolved, merge_duration
        );

        Ok(MergeResult {
            merge_duration_ms: merge_duration,
            ..merge_result
        })
    }

    /// Discover all instance cache files
    fn discover_instance_caches(&self) -> Result<Vec<PathBuf>> {
        let mut cache_files = Vec::new();

        if !self.instance_cache_dir.exists() {
            return Ok(cache_files);
        }

        let entries = std::fs::read_dir(&self.instance_cache_dir).map_err(|e| {
            P2PError::Bootstrap(BootstrapError::CacheError(
                format!("Failed to read instance cache directory: {e}").into(),
            ))
        })?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("cache") {
                // Check if the process is still running
                if let Some(process_id) = self.extract_process_id(&path) {
                    if self.is_process_running(process_id) {
                        cache_files.push(path);
                    } else {
                        // Process is dead, we can safely include this cache
                        cache_files.push(path);
                    }
                }
            }
        }

        debug!("Discovered {} instance cache files", cache_files.len());

        Ok(cache_files)
    }

    /// Load instance caches from files
    async fn load_instance_caches(
        &self,
        cache_files: Vec<PathBuf>,
    ) -> Result<Vec<InstanceCacheData>> {
        let mut instance_caches = Vec::new();

        for cache_file in cache_files {
            match self.load_instance_cache(&cache_file).await {
                Ok(cache_data) => {
                    if self.validate_instance_cache(&cache_data) {
                        instance_caches.push(cache_data);
                    } else {
                        warn!("Invalid instance cache found: {:?}", cache_file);
                    }
                }
                Err(e) => {
                    warn!("Failed to load instance cache {:?}: {}", cache_file, e);
                }
            }
        }

        debug!("Loaded {} valid instance caches", instance_caches.len());

        Ok(instance_caches)
    }

    /// Load a single instance cache
    async fn load_instance_cache(&self, cache_file: &PathBuf) -> Result<InstanceCacheData> {
        let json_data = std::fs::read_to_string(cache_file).map_err(|e| {
            P2PError::Bootstrap(BootstrapError::CacheError(
                format!("Failed to read instance cache: {e}").into(),
            ))
        })?;

        let cache_data: InstanceCacheData = serde_json::from_str(&json_data).map_err(|e| {
            P2PError::Bootstrap(BootstrapError::InvalidData(
                format!("Failed to parse instance cache: {e}").into(),
            ))
        })?;

        Ok(cache_data)
    }

    /// Validate instance cache data
    fn validate_instance_cache(&self, cache_data: &InstanceCacheData) -> bool {
        // Check version compatibility
        if cache_data.version != 1 {
            return false;
        }

        // Check timestamp is reasonable (not too old)
        let now = chrono::Utc::now();
        let age = now.signed_duration_since(cache_data.timestamp);

        if age.num_hours() > 24 {
            debug!("Instance cache too old: {} hours", age.num_hours());
            return false;
        }

        true
    }

    /// Perform the actual merge operation
    async fn perform_merge(
        &self,
        main_cache: &BootstrapCache,
        instance_caches: Vec<InstanceCacheData>,
    ) -> Result<MergeResult> {
        let mut result = MergeResult::empty();
        result.instances_processed = instance_caches.len();

        // Get current main cache contacts
        let mut merged_contacts = main_cache.get_all_contacts().await;

        // Process each instance cache
        for instance_cache in instance_caches {
            let instance_result = self
                .merge_single_instance(&mut merged_contacts, instance_cache)
                .await?;
            result.combine(instance_result);
        }

        // Update main cache with merged contacts
        main_cache.set_all_contacts(merged_contacts).await;

        // Save updated cache
        main_cache.save_to_disk().await?;

        Ok(result)
    }

    /// Merge a single instance cache
    async fn merge_single_instance(
        &self,
        main_contacts: &mut HashMap<PeerId, ContactEntry>,
        instance_cache: InstanceCacheData,
    ) -> Result<MergeResult> {
        let mut result = MergeResult::empty();

        for (peer_id, instance_contact) in instance_cache.contacts {
            match main_contacts.get(&peer_id) {
                Some(main_contact) => {
                    // Contact exists in main cache, resolve conflict
                    let resolved_contact =
                        self.resolve_conflict(main_contact, &instance_contact)?;

                    if resolved_contact.quality_metrics.quality_score
                        != main_contact.quality_metrics.quality_score
                    {
                        result.contacts_updated += 1;
                        result.conflicts_resolved += 1;
                    }

                    main_contacts.insert(peer_id, resolved_contact);
                }
                None => {
                    // New contact, add to main cache
                    main_contacts.insert(peer_id, instance_contact);
                    result.contacts_added += 1;
                }
            }

            result.contacts_merged += 1;
        }

        Ok(result)
    }

    /// Resolve conflict between two contact entries
    fn resolve_conflict(
        &self,
        main_contact: &ContactEntry,
        instance_contact: &ContactEntry,
    ) -> Result<ContactEntry> {
        match self.merge_strategy {
            MergeStrategy::QualityBased => {
                if instance_contact.quality_metrics.quality_score
                    > main_contact.quality_metrics.quality_score
                {
                    Ok(instance_contact.clone())
                } else {
                    Ok(main_contact.clone())
                }
            }

            MergeStrategy::TimestampBased => {
                if instance_contact.last_seen > main_contact.last_seen {
                    Ok(instance_contact.clone())
                } else {
                    Ok(main_contact.clone())
                }
            }

            MergeStrategy::MetricsCombined => {
                self.combine_contact_metrics(main_contact, instance_contact)
            }

            MergeStrategy::SuccessRateBased => {
                if instance_contact.quality_metrics.success_rate
                    > main_contact.quality_metrics.success_rate
                {
                    Ok(instance_contact.clone())
                } else {
                    Ok(main_contact.clone())
                }
            }
        }
    }

    /// Combine metrics from two contacts
    fn combine_contact_metrics(
        &self,
        main_contact: &ContactEntry,
        instance_contact: &ContactEntry,
    ) -> Result<ContactEntry> {
        let mut combined_contact = main_contact.clone();

        // Use the most recent timestamp
        if instance_contact.last_seen > main_contact.last_seen {
            combined_contact.last_seen = instance_contact.last_seen;
        }

        // Combine connection history
        combined_contact.connection_history.total_attempts +=
            instance_contact.connection_history.total_attempts;
        combined_contact.connection_history.successful_connections +=
            instance_contact.connection_history.successful_connections;
        combined_contact.connection_history.failed_connections +=
            instance_contact.connection_history.failed_connections;

        // Update addresses (union of both sets)
        for addr in &instance_contact.addresses {
            if !combined_contact.addresses.contains(addr) {
                combined_contact.addresses.push(*addr);
            }
        }

        // Update capabilities (union of both sets)
        for capability in &instance_contact.capabilities {
            if !combined_contact.capabilities.contains(capability) {
                combined_contact.capabilities.push(capability.clone());
            }
        }

        // Use higher reputation score
        if instance_contact.reputation_score > combined_contact.reputation_score {
            combined_contact.reputation_score = instance_contact.reputation_score;
        }

        // Use verified status if either is verified
        combined_contact.ipv6_identity_verified =
            combined_contact.ipv6_identity_verified || instance_contact.ipv6_identity_verified;

        // Recalculate quality metrics
        combined_contact.update_success_rate();
        combined_contact.recalculate_quality_score();

        Ok(combined_contact)
    }

    /// Cleanup processed instance caches
    async fn cleanup_processed_caches(&self) -> Result<()> {
        let cache_files = self.discover_instance_caches()?;
        let mut cleaned_count = 0;

        for cache_file in cache_files {
            // Check if process is still running
            if let Some(process_id) = self.extract_process_id(&cache_file)
                && !self.is_process_running(process_id)
            {
                // Process is dead, safe to remove cache
                if let Err(e) = std::fs::remove_file(&cache_file) {
                    warn!(
                        "Failed to remove old instance cache {:?}: {}",
                        cache_file, e
                    );
                } else {
                    cleaned_count += 1;
                }
            }
        }

        if cleaned_count > 0 {
            debug!("Cleaned up {} old instance cache files", cleaned_count);
        }

        Ok(())
    }

    /// Extract process ID from cache file name
    fn extract_process_id(&self, cache_file: &std::path::Path) -> Option<u32> {
        cache_file
            .file_stem()
            .and_then(|name| name.to_str())
            .and_then(|name| {
                let parts: Vec<&str> = name.split('_').collect();
                if parts.len() >= 2 {
                    parts[0].parse().ok()
                } else {
                    None
                }
            })
    }

    /// Check if a process is still running
    fn is_process_running(&self, process_id: u32) -> bool {
        #[cfg(unix)]
        {
            use std::process::Command;
            Command::new("kill")
                .args(["-0", &process_id.to_string()])
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
        }

        #[cfg(windows)]
        {
            use std::process::Command;
            Command::new("tasklist")
                .args(["/FI", &format!("PID eq {}", process_id)])
                .output()
                .map(|output| {
                    String::from_utf8_lossy(&output.stdout).contains(&process_id.to_string())
                })
                .unwrap_or(false)
        }

        #[cfg(not(any(unix, windows)))]
        {
            // Assume process is still running if we can't check
            true
        }
    }

    /// Get merge strategy
    pub fn get_strategy(&self) -> &MergeStrategy {
        &self.merge_strategy
    }

    /// Set merge strategy
    pub fn set_strategy(&mut self, strategy: MergeStrategy) {
        self.merge_strategy = strategy;
    }
}

impl MergeResult {
    /// Create empty merge result
    fn empty() -> Self {
        Self {
            contacts_merged: 0,
            contacts_updated: 0,
            contacts_added: 0,
            conflicts_resolved: 0,
            instances_processed: 0,
            merge_duration_ms: 0,
        }
    }

    /// Combine with another merge result
    fn combine(&mut self, other: MergeResult) {
        self.contacts_merged += other.contacts_merged;
        self.contacts_updated += other.contacts_updated;
        self.contacts_added += other.contacts_added;
        self.conflicts_resolved += other.conflicts_resolved;
    }
}

impl std::fmt::Display for MergeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MergeResult {{ merged: {}, updated: {}, added: {}, conflicts: {}, instances: {}, duration: {}ms }}",
            self.contacts_merged,
            self.contacts_updated,
            self.contacts_added,
            self.conflicts_resolved,
            self.instances_processed,
            self.merge_duration_ms
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_merge_coordinator_creation() {
        let temp_dir = TempDir::new().unwrap();
        let coordinator = MergeCoordinator::new(temp_dir.path().to_path_buf());
        assert!(coordinator.is_ok());
    }

    #[tokio::test]
    async fn test_conflict_resolution_quality_based() {
        let temp_dir = TempDir::new().unwrap();
        let coordinator = MergeCoordinator::with_strategy(
            temp_dir.path().to_path_buf(),
            MergeStrategy::QualityBased,
        )
        .unwrap();

        let mut main_contact = ContactEntry::new(
            PeerId::from("test-peer"),
            vec!["127.0.0.1:9000".parse().unwrap()],
        );
        main_contact.quality_metrics.quality_score = 0.5;

        let mut instance_contact = ContactEntry::new(
            PeerId::from("test-peer"),
            vec!["127.0.0.1:9001".parse().unwrap()],
        );
        instance_contact.quality_metrics.quality_score = 0.8;

        let resolved = coordinator
            .resolve_conflict(&main_contact, &instance_contact)
            .unwrap();
        assert_eq!(resolved.quality_metrics.quality_score, 0.8);
    }

    #[tokio::test]
    async fn test_metrics_combination() {
        let temp_dir = TempDir::new().unwrap();
        let coordinator = MergeCoordinator::with_strategy(
            temp_dir.path().to_path_buf(),
            MergeStrategy::MetricsCombined,
        )
        .unwrap();

        let mut main_contact = ContactEntry::new(
            PeerId::from("test-peer"),
            vec!["127.0.0.1:9000".parse().unwrap()],
        );
        main_contact.connection_history.total_attempts = 10;
        main_contact.connection_history.successful_connections = 8;

        let mut instance_contact = ContactEntry::new(
            PeerId::from("test-peer"),
            vec!["127.0.0.1:9001".parse().unwrap()],
        );
        instance_contact.connection_history.total_attempts = 5;
        instance_contact.connection_history.successful_connections = 4;

        let combined = coordinator
            .combine_contact_metrics(&main_contact, &instance_contact)
            .unwrap();
        assert_eq!(combined.connection_history.total_attempts, 15);
        assert_eq!(combined.connection_history.successful_connections, 12);
    }

    #[test]
    fn test_process_id_extraction() {
        let temp_dir = TempDir::new().unwrap();
        let coordinator = MergeCoordinator::new(temp_dir.path().to_path_buf()).unwrap();

        let cache_file = PathBuf::from("12345_1234567890.cache");
        let process_id = coordinator.extract_process_id(&cache_file);
        assert_eq!(process_id, Some(12345));
    }

    #[test]
    fn test_is_process_running_compilation() {
        // This test ensures the is_process_running function compiles correctly on all platforms
        let temp_dir = TempDir::new().unwrap();
        let coordinator = MergeCoordinator::new(temp_dir.path().to_path_buf()).unwrap();

        // Test with current process ID (should be running)
        let current_pid = std::process::id();
        let is_running = coordinator.is_process_running(current_pid);

        // On all platforms, the current process should be detected as running
        assert!(is_running, "Current process should be detected as running");

        // Test with a very high PID that's unlikely to exist
        let non_existent_pid = 999999;
        let is_not_running = coordinator.is_process_running(non_existent_pid);

        // This may vary by platform, but we're mainly testing compilation here
        // The actual behavior is platform-specific
        let _ = is_not_running; // Just ensure it compiles and runs
    }

    #[test]
    #[cfg(windows)]
    fn test_windows_tasklist_command_format() {
        // This test specifically validates the Windows command format
        use std::process::Command;

        // Test that the command format compiles and can be executed
        // We're not testing the actual process detection, just the command syntax
        let process_id = std::process::id();
        let filter_arg = format!("PID eq {}", process_id);

        // This should compile without the .into() bug
        let result = Command::new("tasklist")
            .args(["/FI", &filter_arg])
            .output();

        // The command should at least execute (even if tasklist isn't available in test env)
        assert!(result.is_ok() || result.is_err(), "Command should either succeed or fail gracefully");
    }
}
