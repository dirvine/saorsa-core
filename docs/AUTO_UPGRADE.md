# Auto-Upgrade System

Saorsa Core includes a comprehensive auto-upgrade system for cross-platform binary updates with post-quantum signature verification, rollback support, and configurable update policies.

## Overview

The upgrade system provides:

- **Secure Updates**: ML-DSA-65 post-quantum signatures and SHA-256 checksums
- **Cross-Platform**: Windows, macOS, and Linux with platform-specific strategies
- **Configurable Policies**: Silent, notify-only, or manual update modes
- **Rollback Support**: Automatic backup and restore capabilities
- **Resume Support**: HTTP range requests for resumable downloads

## Quick Start

### Basic Update Check

```rust
use saorsa_core::upgrade::{
    UpdateConfig, UpdatePolicy, Downloader, SignatureVerifier,
    StagedUpdateManager, RollbackManager, create_applier, ApplierConfig,
};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create configuration with default manifest URL
    let config = UpdateConfig::default()
        .with_policy(UpdatePolicy::Silent)
        .with_channel(ReleaseChannel::Stable);

    // Check for updates
    let downloader = Downloader::new()?;
    let manifest_json = downloader.fetch_manifest(&config.manifest_url).await?;
    let manifest = UpdateManifest::from_json(&manifest_json)?;

    // Find latest release for our channel
    if let Some(release) = manifest.latest_for_channel(config.channel) {
        let current_version = env!("CARGO_PKG_VERSION");

        if release.version > current_version.to_string() {
            println!("Update available: {} -> {}", current_version, release.version);

            // Download and apply (see full example below)
        }
    }

    Ok(())
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Update Flow                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐       │
│  │   Manifest  │ ──▶ │  Download   │ ──▶ │   Verify    │       │
│  │    Check    │     │   Binary    │     │  Signature  │       │
│  └─────────────┘     └─────────────┘     └─────────────┘       │
│         │                   │                   │               │
│         │                   │                   ▼               │
│         │                   │            ┌─────────────┐       │
│         │                   │            │    Stage    │       │
│         │                   │            │   Update    │       │
│         │                   │            └─────────────┘       │
│         │                   │                   │               │
│         │                   │                   ▼               │
│         │                   │            ┌─────────────┐       │
│         │                   │            │   Backup    │       │
│         │                   │            │   Current   │       │
│         │                   │            └─────────────┘       │
│         │                   │                   │               │
│         │                   │                   ▼               │
│  ┌──────────────────────────────────────────────────────┐      │
│  │              Platform-Specific Applier               │      │
│  ├──────────────────────────────────────────────────────┤      │
│  │  Windows: Rename-and-restart (can't replace running) │      │
│  │  macOS: Binary replacement + quarantine clearing     │      │
│  │  Linux: Binary replacement + optional systemd        │      │
│  └──────────────────────────────────────────────────────┘      │
│                             │                                   │
│                             ▼                                   │
│                      ┌─────────────┐                           │
│                      │   Restart   │                           │
│                      │   Process   │                           │
│                      └─────────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

## Platform Strategies

### Windows

Windows cannot replace a running executable, so we use a **rename-and-restart** strategy:

1. Rename `current.exe` → `current.exe.old`
2. Copy new binary → `current.exe`
3. Spawn new process with `--post-update` flag
4. Exit current process
5. New process cleans up `.old` files on startup

```rust
use saorsa_core::upgrade::applier::WindowsApplier;

let applier = WindowsApplier::new();
// On startup, clean up old binaries
applier.cleanup_old_binaries(&current_binary_path).await?;
```

### macOS

macOS can replace binaries directly but downloaded files have quarantine attributes:

1. Clear `com.apple.quarantine` extended attribute
2. Replace binary directly
3. Set executable permissions (0755)
4. Optionally sign with ad-hoc signature
5. Use `exec()` for seamless restart

```rust
use saorsa_core::upgrade::applier::MacOsApplier;

let applier = MacOsApplier::new()
    .with_adhoc_sign();  // Optional: sign with ad-hoc signature
```

### Linux

Linux supports direct binary replacement:

1. Replace binary directly
2. Set executable permissions (0755)
3. Restart via `exec()` or systemd

```rust
use saorsa_core::upgrade::applier::LinuxApplier;

// For systemd-managed services
let applier = LinuxApplier::new()
    .with_systemd_service("saorsa-node");

// For direct execution
let applier = LinuxApplier::new(); // Uses exec() by default
```

## Update Policies

Configure how updates are handled:

```rust
use saorsa_core::upgrade::UpdatePolicy;

// Automatic download and apply (default for headless nodes)
let policy = UpdatePolicy::Silent;

// Download automatically, but ask before applying
let policy = UpdatePolicy::DownloadAndNotify;

// Only notify about updates, don't download
let policy = UpdatePolicy::NotifyOnly;

// User must manually trigger all updates
let policy = UpdatePolicy::Manual;

// Only auto-apply critical security patches
let policy = UpdatePolicy::CriticalOnly;
```

## Release Channels

```rust
use saorsa_core::upgrade::ReleaseChannel;

// Stable releases - thoroughly tested (default)
let channel = ReleaseChannel::Stable;

// Beta releases - feature complete, still testing
let channel = ReleaseChannel::Beta;

// Nightly builds - latest development
let channel = ReleaseChannel::Nightly;
```

## Signature Verification

All updates are signed with ML-DSA-65 (post-quantum) signatures:

```rust
use saorsa_core::upgrade::{SignatureVerifier, PinnedKey};

// Create verifier with pinned keys
let mut verifier = SignatureVerifier::new(vec![
    PinnedKey {
        key_id: "saorsa-2025-prod".to_string(),
        public_key: "base64-encoded-ml-dsa-65-public-key".to_string(),
        valid_from: 1704067200,  // 2024-01-01
        valid_until: 0,          // No expiry
    },
]);

// Verify a signature
let is_valid = verifier.verify_signature(
    "saorsa-2025-prod",
    &binary_data,
    &base64_signature,
)?;

// Verify file with checksum and signature
verifier.verify_file(
    &binary_path,
    &expected_sha256,
    "saorsa-2025-prod",
    &base64_signature,
).await?;
```

## Full Integration Example

Here's a complete example showing how to integrate the upgrade system into an application like `saorsa-node`:

```rust
use saorsa_core::upgrade::{
    UpdateConfig, UpdatePolicy, ReleaseChannel, PinnedKey,
    Downloader, DownloaderConfig, DownloadProgress,
    SignatureVerifier, UpdateManifest, Platform,
    StagedUpdate, StagedUpdateManager,
    RollbackManager, BackupMetadata,
    create_applier, ApplierConfig, ApplyResult,
    UpgradeError,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Upgrade manager for saorsa-node
pub struct NodeUpgradeManager {
    config: UpdateConfig,
    downloader: Downloader,
    verifier: SignatureVerifier,
    staging: StagedUpdateManager,
    rollback: RollbackManager,
    current_version: String,
}

impl NodeUpgradeManager {
    /// Create a new upgrade manager
    pub fn new(
        manifest_url: String,
        signing_keys: Vec<PinnedKey>,
    ) -> Result<Self, UpgradeError> {
        let config = UpdateConfig::default()
            .with_manifest_url(manifest_url)
            .with_policy(UpdatePolicy::Silent)
            .with_channel(ReleaseChannel::Stable);

        // Add signing keys
        let mut config = config;
        for key in signing_keys {
            config = config.with_signing_key(key);
        }

        let downloader = Downloader::new()?;
        let verifier = SignatureVerifier::new(config.signing_keys.clone());
        let staging = StagedUpdateManager::new(config.staging_dir.clone());
        let rollback = RollbackManager::new(config.backup_dir.clone());

        Ok(Self {
            config,
            downloader,
            verifier,
            staging,
            rollback,
            current_version: env!("CARGO_PKG_VERSION").to_string(),
        })
    }

    /// Check for available updates
    pub async fn check_for_updates(&self) -> Result<Option<UpdateInfo>, UpgradeError> {
        // Fetch and parse manifest
        let manifest_json = self.downloader
            .fetch_manifest(&self.config.manifest_url)
            .await?;
        let manifest = UpdateManifest::from_json(&manifest_json)?;

        // Verify manifest signature
        let canonical = manifest.canonical_bytes()?;
        let valid = self.verifier.verify_signature(
            &manifest.signing_key_id,
            &canonical,
            &manifest.signature,
        )?;

        if !valid {
            return Err(UpgradeError::ManifestSignature(
                "manifest signature verification failed".into()
            ));
        }

        // Find latest release for our channel
        let release = match manifest.latest_for_channel(self.config.channel) {
            Some(r) => r,
            None => return Ok(None),
        };

        // Check if newer than current
        if release.version <= self.current_version {
            return Ok(None);
        }

        // Check platform support
        let binary = match release.binary_for_current_platform() {
            Some(b) => b.clone(),
            None => return Ok(None),
        };

        Ok(Some(UpdateInfo {
            version: release.version.clone(),
            channel: release.channel,
            is_critical: release.is_critical,
            release_notes: release.release_notes.clone(),
            binary,
            manifest_url: self.config.manifest_url.clone(),
        }))
    }

    /// Download and stage an update
    pub async fn download_update(
        &self,
        update: &UpdateInfo,
        progress_tx: Option<mpsc::Sender<DownloadProgress>>,
    ) -> Result<StagedUpdate, UpgradeError> {
        // Ensure staging directory exists
        self.staging.ensure_staging_dir().await?;

        // Determine download path
        let binary_path = self.staging.staged_binary_path(
            &update.version,
            Platform::current(),
        );

        // Create progress callback
        let progress_callback = progress_tx.map(|tx| {
            Box::new(move |progress: DownloadProgress| {
                let _ = tx.blocking_send(progress);
            }) as Box<dyn Fn(DownloadProgress) + Send + Sync>
        });

        // Download the binary
        self.downloader.download(
            &update.binary.url,
            &binary_path,
            Some(update.binary.size),
            progress_callback,
        ).await?;

        // Verify checksum
        self.verifier.verify_checksum(
            &tokio::fs::read(&binary_path).await?,
            &update.binary.sha256,
        )?;

        // Verify signature
        self.verifier.verify_file(
            &binary_path,
            &update.binary.sha256,
            &self.config.signing_keys[0].key_id,
            &update.binary.signature,
        ).await?;

        // Create staged update
        let staged = StagedUpdate::new(
            &update.version,
            binary_path,
            Platform::current(),
            &update.binary.sha256,
            update.binary.size,
        )
        .with_critical(update.is_critical)
        .with_release_notes(&update.release_notes);

        // Save metadata
        self.staging.save_metadata(&staged).await?;

        Ok(staged)
    }

    /// Apply a staged update
    pub async fn apply_update(
        &self,
        staged: StagedUpdate,
    ) -> Result<ApplyResult, UpgradeError> {
        // Get current executable path
        let current_exe = std::env::current_exe()
            .map_err(|e| UpgradeError::platform(format!("cannot find current exe: {}", e)))?;

        // Create applier for current platform
        let applier = create_applier();

        // Configure application
        let config = ApplierConfig::new(current_exe)
            .with_auto_restart()
            .with_restart_args(vec![
                "--post-update".to_string(),
                format!("--from-version={}", self.current_version),
            ]);

        // Apply the update
        let result = applier.apply(&staged, &config, &self.rollback).await?;

        // Clean up staged files on success
        staged.cleanup().await?;
        self.staging.clear_metadata().await?;

        Ok(result)
    }

    /// Rollback to previous version
    pub async fn rollback(&self) -> Result<BackupMetadata, UpgradeError> {
        self.rollback.rollback().await
    }

    /// Check if rollback is available
    pub async fn can_rollback(&self) -> bool {
        self.rollback.can_rollback().await
    }

    /// Run automatic update check and apply based on policy
    pub async fn auto_update(&self) -> Result<Option<String>, UpgradeError> {
        // Check for updates
        let update = match self.check_for_updates().await? {
            Some(u) => u,
            None => return Ok(None),
        };

        // Check policy
        let should_apply = match self.config.policy {
            UpdatePolicy::Silent => true,
            UpdatePolicy::CriticalOnly => update.is_critical,
            _ => false,
        };

        if !should_apply {
            // Just return the version info without applying
            return Ok(Some(update.version));
        }

        // Download
        let staged = self.download_update(&update, None).await?;

        // Apply
        let result = self.apply_update(staged).await?;

        // The process will restart, but return version for logging
        Ok(Some(result.version))
    }
}

/// Update information
#[derive(Debug, Clone)]
pub struct UpdateInfo {
    pub version: String,
    pub channel: ReleaseChannel,
    pub is_critical: bool,
    pub release_notes: String,
    pub binary: saorsa_core::upgrade::PlatformBinary,
    pub manifest_url: String,
}
```

## Background Update Service

For applications that need periodic update checks:

```rust
use std::time::Duration;
use tokio::time::interval;

/// Background service for automatic updates
pub struct UpdateService {
    manager: Arc<NodeUpgradeManager>,
    check_interval: Duration,
}

impl UpdateService {
    pub fn new(manager: NodeUpgradeManager) -> Self {
        Self {
            manager: Arc::new(manager),
            check_interval: Duration::from_secs(6 * 3600), // 6 hours
        }
    }

    /// Start the background update service
    pub async fn run(&self, shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut interval = interval(self.check_interval);
        let mut shutdown = shutdown;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match self.manager.auto_update().await {
                        Ok(Some(version)) => {
                            tracing::info!("Update to {} initiated", version);
                        }
                        Ok(None) => {
                            tracing::debug!("No updates available");
                        }
                        Err(e) => {
                            if e.is_recoverable() {
                                tracing::warn!("Update check failed (will retry): {}", e);
                            } else {
                                tracing::error!("Update check failed: {}", e);
                            }
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Update service shutting down");
                        break;
                    }
                }
            }
        }
    }
}
```

## Post-Update Handling

Handle the `--post-update` flag on startup:

```rust
use clap::Parser;

#[derive(Parser)]
struct Args {
    /// Run post-update tasks (set by auto-updater)
    #[arg(long)]
    post_update: bool,

    /// Version we upgraded from
    #[arg(long)]
    from_version: Option<String>,
}

async fn main() {
    let args = Args::parse();

    if args.post_update {
        handle_post_update(args.from_version.as_deref()).await;
    }

    // Normal startup...
}

async fn handle_post_update(from_version: Option<&str>) {
    tracing::info!(
        "Post-update tasks running (upgraded from {})",
        from_version.unwrap_or("unknown")
    );

    // Run migrations if needed
    if let Some(from) = from_version {
        run_migrations(from).await;
    }

    // Clean up old binaries (Windows)
    #[cfg(target_os = "windows")]
    {
        use saorsa_core::upgrade::applier::WindowsApplier;
        let applier = WindowsApplier::new();
        let current = std::env::current_exe().unwrap();
        let _ = applier.cleanup_old_binaries(&current).await;
    }

    // Verify installation
    tracing::info!("Now running version {}", env!("CARGO_PKG_VERSION"));
}
```

## Manifest Format

The update manifest is a signed JSON document:

```json
{
  "manifest_version": 1,
  "generated_at": 1704067200,
  "signature": "base64-ml-dsa-65-signature",
  "signing_key_id": "saorsa-2025-prod",
  "next_signing_key_url": "https://releases.saorsa.io/keys/2026.json",
  "releases": [
    {
      "version": "1.2.0",
      "channel": "stable",
      "is_critical": false,
      "release_notes": "## What's New\n- Feature X\n- Bug fix Y",
      "minimum_from_version": "1.0.0",
      "published_at": 1704067200,
      "binaries": {
        "windows-x64": {
          "url": "https://releases.saorsa.io/v1.2.0/saorsa-node-windows-x64.exe",
          "sha256": "abc123...",
          "signature": "base64-signature...",
          "size": 15000000
        },
        "macos-arm64": {
          "url": "https://releases.saorsa.io/v1.2.0/saorsa-node-macos-arm64",
          "sha256": "def456...",
          "signature": "base64-signature...",
          "size": 12000000
        },
        "linux-x64": {
          "url": "https://releases.saorsa.io/v1.2.0/saorsa-node-linux-x64",
          "sha256": "789abc...",
          "signature": "base64-signature...",
          "size": 14000000
        }
      }
    }
  ]
}
```

## Error Handling

The upgrade system provides detailed error types:

```rust
use saorsa_core::upgrade::UpgradeError;

match upgrade_manager.check_for_updates().await {
    Ok(Some(update)) => {
        println!("Update available: {}", update.version);
    }
    Ok(None) => {
        println!("Already at latest version");
    }
    Err(e) => {
        // Check error category
        if e.is_security_issue() {
            // Signature/checksum failures - DO NOT proceed
            tracing::error!("Security violation: {}", e);
            std::process::exit(1);
        } else if e.is_recoverable() {
            // Network issues - can retry
            tracing::warn!("Recoverable error: {}", e);
        } else {
            // Other errors
            tracing::error!("Update error: {}", e);
        }
    }
}
```

## Security Considerations

1. **Always verify signatures**: Never skip signature verification in production
2. **Pin signing keys**: Embed production signing keys in your binary
3. **Use HTTPS**: The manifest URL should always use HTTPS
4. **Validate checksums**: Always verify SHA-256 before applying
5. **Keep backups**: Enable backup creation before updates
6. **Test rollback**: Verify rollback works in your deployment

## API Reference

### Core Types

| Type | Description |
|------|-------------|
| `UpdateConfig` | Configuration for the update system |
| `UpdatePolicy` | How updates are handled (Silent, Manual, etc.) |
| `ReleaseChannel` | Which releases to follow (Stable, Beta, Nightly) |
| `UpdateManifest` | Parsed manifest with releases |
| `StagedUpdate` | A downloaded update ready to apply |
| `ApplyResult` | Result of applying an update |
| `UpgradeError` | Error types for upgrade operations |

### Key Functions

| Function | Description |
|----------|-------------|
| `Downloader::new()` | Create HTTP downloader |
| `Downloader::fetch_manifest()` | Fetch manifest JSON |
| `Downloader::download()` | Download with progress |
| `SignatureVerifier::verify_signature()` | Verify ML-DSA-65 signature |
| `SignatureVerifier::verify_file()` | Verify file checksum + signature |
| `create_applier()` | Get platform-specific applier |
| `RollbackManager::rollback()` | Restore previous version |

## See Also

- [ARCHITECTURE.md](../ARCHITECTURE.md) - Overall system architecture
- [Security Documentation](../SECURITY.md) - Security practices
- [saorsa-node](https://github.com/saorsa/saorsa-node) - Reference implementation
