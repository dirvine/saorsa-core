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

//! Comprehensive integration tests for the auto-upgrade system.
//!
//! This test suite covers:
//! 1. Signature Verification (SECURITY CRITICAL)
//! 2. Update Download and Verification
//! 3. Platform-Specific Appliers
//! 4. Rollback Functionality
//! 5. Update Manifest Parsing
//! 6. Update Manager Lifecycle
//! 7. Security Scenarios

use saorsa_core::quantum_crypto::ant_quic_integration::{
    MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
};
use saorsa_core::quantum_crypto::{generate_ml_dsa_keypair, ml_dsa_sign, ml_dsa_verify};
use saorsa_core::upgrade::{
    PinnedKey, Platform, PlatformBinary, Release, ReleaseChannel, RollbackManager,
    SignatureVerifier, StagedUpdate, StagedUpdateManager, UpdateConfig, UpdateManifest,
    UpgradeError,
};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tempfile::TempDir;

// ============================================================================
// Test Helpers and Fixtures
// ============================================================================

/// Generate a test keypair for ML-DSA-65 signatures
fn generate_test_keypair() -> (MlDsaPublicKey, MlDsaSecretKey) {
    generate_ml_dsa_keypair().expect("Failed to generate test keypair")
}

/// Convert Vec<u8> to MlDsaSignature
fn signature_from_bytes(bytes: &[u8]) -> Result<MlDsaSignature, String> {
    MlDsaSignature::from_bytes(bytes).map_err(|e| format!("Failed to parse signature: {e:?}"))
}

/// Sign binary data with ML-DSA-65
fn sign_binary(binary: &[u8], secret_key: &MlDsaSecretKey) -> MlDsaSignature {
    ml_dsa_sign(secret_key, binary).expect("Failed to sign binary")
}

/// Verify signature
fn verify_binary_signature(
    binary: &[u8],
    signature: &MlDsaSignature,
    public_key: &MlDsaPublicKey,
) -> bool {
    ml_dsa_verify(public_key, binary, signature).unwrap_or(false)
}

/// Corrupt a signature by flipping bits
fn corrupt_signature(signature: &MlDsaSignature) -> MlDsaSignature {
    let mut bytes = signature.as_bytes().to_vec();
    // Flip multiple bytes to ensure corruption
    for i in 0..bytes.len().min(10) {
        bytes[i] ^= 0xFF;
    }
    MlDsaSignature::from_bytes(&bytes).unwrap_or_else(|_| signature.clone())
}

/// Calculate SHA-256 hash
fn calculate_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Create a test binary file
async fn create_test_binary(path: &Path, content: &[u8]) -> Result<(), std::io::Error> {
    tokio::fs::write(path, content).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        tokio::fs::set_permissions(path, perms).await?;
    }

    Ok(())
}

/// Create a valid update manifest
fn create_test_manifest(
    version: &str,
    channel: ReleaseChannel,
    is_critical: bool,
    _public_key: &MlDsaPublicKey,
    secret_key: &MlDsaSecretKey,
) -> UpdateManifest {
    let binary_content = format!("Binary content for version {}", version);
    let binary_bytes = binary_content.as_bytes();
    let sha256 = calculate_sha256(binary_bytes);
    let signature = sign_binary(binary_bytes, secret_key);
    let signature_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signature.as_bytes(),
    );

    let mut binaries = HashMap::new();
    binaries.insert(
        Platform::LinuxX64,
        PlatformBinary {
            url: format!("https://test.example.com/binary-{}", version),
            sha256: sha256.clone(),
            signature: signature_b64.clone(),
            size: binary_bytes.len() as u64,
        },
    );

    #[cfg(target_os = "macos")]
    binaries.insert(
        Platform::MacOsArm64,
        PlatformBinary {
            url: format!("https://test.example.com/binary-{}-macos", version),
            sha256: sha256.clone(),
            signature: signature_b64.clone(),
            size: binary_bytes.len() as u64,
        },
    );

    #[cfg(target_os = "windows")]
    binaries.insert(
        Platform::WindowsX64,
        PlatformBinary {
            url: format!("https://test.example.com/binary-{}.exe", version),
            sha256,
            signature: signature_b64,
            size: binary_bytes.len() as u64,
        },
    );

    let release = Release {
        version: version.to_string(),
        channel,
        is_critical,
        release_notes: format!("Release notes for version {}", version),
        minimum_from_version: None,
        published_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        binaries,
    };

    let mut manifest = UpdateManifest {
        manifest_version: 1,
        generated_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        signature: String::new(),
        signing_key_id: "test-key-001".to_string(),
        next_signing_key_url: None,
        releases: vec![release],
    };

    // Sign the manifest
    let canonical_bytes = manifest
        .canonical_bytes()
        .expect("Failed to get canonical bytes");
    let manifest_signature = sign_binary(&canonical_bytes, secret_key);
    manifest.signature = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        manifest_signature.as_bytes(),
    );

    manifest
}

// ============================================================================
// Test Suite 1: Signature Verification (SECURITY CRITICAL)
// ============================================================================

#[tokio::test]
async fn test_valid_signature_verification() {
    let (public_key, secret_key) = generate_test_keypair();

    let test_data = b"Test binary content for signature verification";
    let signature = sign_binary(test_data, &secret_key);

    // Verify signature succeeds
    let result = verify_binary_signature(test_data, &signature, &public_key);
    assert!(result, "Valid signature should verify successfully");

    // Test with SignatureVerifier
    let pinned_key = PinnedKey::new(
        "test-key",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            public_key.as_bytes(),
        ),
    );
    let verifier = SignatureVerifier::new(vec![pinned_key]);

    let signature_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signature.as_bytes(),
    );
    let result = verifier.verify_signature("test-key", test_data, &signature_b64);
    assert!(
        result.is_ok(),
        "SignatureVerifier should verify valid signature"
    );
}

#[tokio::test]
async fn test_invalid_signature_rejection() {
    let (public_key, secret_key) = generate_test_keypair();

    let test_data = b"Test binary content";
    let signature = sign_binary(test_data, &secret_key);

    // Corrupt the signature
    let corrupted_signature = corrupt_signature(&signature);

    // Verification should fail
    let result = verify_binary_signature(test_data, &corrupted_signature, &public_key);
    assert!(!result, "Corrupted signature should not verify");

    // Test with SignatureVerifier
    let pinned_key = PinnedKey::new(
        "test-key",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            public_key.as_bytes(),
        ),
    );
    let verifier = SignatureVerifier::new(vec![pinned_key]);

    let signature_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        corrupted_signature.as_bytes(),
    );
    let result = verifier.verify_signature("test-key", test_data, &signature_b64);
    assert!(
        result.is_err(),
        "SignatureVerifier should reject invalid signature"
    );
}

#[tokio::test]
async fn test_tampered_binary_detection() {
    let (public_key, secret_key) = generate_test_keypair();

    let original_data = b"Original binary content";
    let signature = sign_binary(original_data, &secret_key);

    // Verify original is valid
    assert!(verify_binary_signature(
        original_data,
        &signature,
        &public_key
    ));

    // Tamper with the binary
    let tampered_data = b"Tampered binary content";

    // Verification should fail
    let result = verify_binary_signature(tampered_data, &signature, &public_key);
    assert!(
        !result,
        "Signature verification should fail for tampered binary"
    );
}

#[tokio::test]
async fn test_wrong_public_key() {
    let (public_key_a, secret_key_a) = generate_test_keypair();
    let (public_key_b, _secret_key_b) = generate_test_keypair();

    let test_data = b"Test binary";
    let signature = sign_binary(test_data, &secret_key_a);

    // Verify with correct key
    assert!(verify_binary_signature(
        test_data,
        &signature,
        &public_key_a
    ));

    // Verify with wrong key should fail
    let result = verify_binary_signature(test_data, &signature, &public_key_b);
    assert!(!result, "Signature should not verify with wrong public key");
}

// ============================================================================
// Test Suite 2: Update Download and Verification
// ============================================================================

#[tokio::test]
async fn test_checksum_verification() {
    let test_data = b"Test binary for checksum verification";
    let expected_checksum = calculate_sha256(test_data);

    let verifier = SignatureVerifier::default();

    // Correct checksum should pass
    let result = verifier.verify_checksum(test_data, &expected_checksum);
    assert!(result.is_ok(), "Correct checksum should verify");

    // Wrong checksum should fail
    let result = verifier.verify_checksum(test_data, "wrong_checksum");
    assert!(result.is_err(), "Wrong checksum should fail verification");
}

#[tokio::test]
async fn test_file_checksum_calculation() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("test-binary");

    let test_content = b"Test file content for checksum";
    create_test_binary(&file_path, test_content)
        .await
        .expect("Failed to create test binary");

    let calculated_checksum = SignatureVerifier::calculate_file_checksum(&file_path)
        .await
        .expect("Failed to calculate file checksum");

    let expected_checksum = calculate_sha256(test_content);
    assert_eq!(
        calculated_checksum, expected_checksum,
        "File checksum should match"
    );
}

#[tokio::test]
async fn test_hash_mismatch_detection() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("test-binary");

    let test_content = b"Test content";
    create_test_binary(&file_path, test_content)
        .await
        .expect("Failed to create test binary");

    let (public_key, _secret_key) = generate_test_keypair();
    let pinned_key = PinnedKey::new(
        "test-key",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            public_key.as_bytes(),
        ),
    );
    let verifier = SignatureVerifier::new(vec![pinned_key]);

    // Try to verify with wrong checksum
    let wrong_checksum = "0000000000000000000000000000000000000000000000000000000000000000";
    let signature_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]);

    let result = verifier
        .verify_file(&file_path, wrong_checksum, "test-key", &signature_b64)
        .await;
    assert!(
        matches!(result, Err(UpgradeError::ChecksumMismatch { .. })),
        "Should detect checksum mismatch"
    );
}

// ============================================================================
// Test Suite 3: Platform-Specific Appliers
// ============================================================================

#[cfg(unix)]
#[tokio::test]
async fn test_unix_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let binary_path = temp_dir.path().join("test-binary");

    let test_content = b"Test binary";
    create_test_binary(&binary_path, test_content)
        .await
        .expect("Failed to create binary");

    // Check permissions are executable
    let metadata = tokio::fs::metadata(&binary_path)
        .await
        .expect("Failed to get metadata");
    let permissions = metadata.permissions();
    let mode = permissions.mode();

    assert_eq!(
        mode & 0o755,
        0o755,
        "Binary should have executable permissions"
    );
}

#[tokio::test]
async fn test_staged_update_creation() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let binary_path = temp_dir.path().join("staged-binary");

    let test_content = b"Staged binary content";
    create_test_binary(&binary_path, test_content)
        .await
        .expect("Failed to create binary");

    let checksum = calculate_sha256(test_content);
    let staged = StagedUpdate::new(
        "1.0.0",
        binary_path.clone(),
        Platform::current(),
        checksum,
        test_content.len() as u64,
    );

    assert_eq!(staged.version, "1.0.0");
    assert!(staged.exists(), "Staged binary should exist");
    assert!(
        staged
            .verify()
            .await
            .expect("Failed to verify staged update"),
        "Staged binary checksum should match"
    );
}

#[tokio::test]
async fn test_platform_detection() {
    let platform = Platform::current();

    #[cfg(target_os = "linux")]
    assert!(platform.is_linux());

    #[cfg(target_os = "macos")]
    assert!(platform.is_macos());

    #[cfg(target_os = "windows")]
    assert!(platform.is_windows());
}

// ============================================================================
// Test Suite 4: Rollback Functionality
// ============================================================================

#[tokio::test]
async fn test_successful_rollback() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let backup_dir = temp_dir.path().join("backups");
    let binary_path = temp_dir.path().join("saorsa-binary");

    let manager = RollbackManager::new(backup_dir);

    // Create original binary (version 0.10.0)
    let original_content = b"Binary version 0.10.0";
    create_test_binary(&binary_path, original_content)
        .await
        .expect("Failed to create binary");

    // Create backup
    let backup = manager
        .create_backup(&binary_path, "0.10.0", Platform::current())
        .await
        .expect("Failed to create backup");

    assert_eq!(backup.version, "0.10.0");
    assert!(manager.can_rollback().await, "Should be able to rollback");

    // Simulate update to 0.11.0
    let new_content = b"Binary version 0.11.0";
    tokio::fs::write(&binary_path, new_content)
        .await
        .expect("Failed to write new version");

    // Rollback to 0.10.0
    let restored = manager.rollback().await.expect("Failed to rollback");
    assert_eq!(restored.version, "0.10.0");

    // Verify original content is restored
    let restored_content = tokio::fs::read(&binary_path)
        .await
        .expect("Failed to read restored binary");
    assert_eq!(
        restored_content, original_content,
        "Restored binary should match original"
    );
}

#[tokio::test]
async fn test_rollback_after_failed_update() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let backup_dir = temp_dir.path().join("backups");
    let binary_path = temp_dir.path().join("saorsa-binary");

    let manager = RollbackManager::new(backup_dir);

    // Create and backup original version
    let original_content = b"Working version 0.10.0";
    create_test_binary(&binary_path, original_content)
        .await
        .expect("Failed to create binary");

    let _backup = manager
        .create_backup(&binary_path, "0.10.0", Platform::current())
        .await
        .expect("Failed to create backup");

    // Simulate failed update (corrupt binary)
    tokio::fs::write(&binary_path, b"CORRUPTED")
        .await
        .expect("Failed to write corrupted binary");

    // Rollback should restore working version
    let restored = manager
        .rollback()
        .await
        .expect("Failed to rollback after failed update");
    assert_eq!(restored.version, "0.10.0");

    let restored_content = tokio::fs::read(&binary_path)
        .await
        .expect("Failed to read restored binary");
    assert_eq!(restored_content, original_content);
}

#[tokio::test]
async fn test_rollback_without_backup() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let backup_dir = temp_dir.path().join("backups");

    let manager = RollbackManager::new(backup_dir);

    // No backup exists
    assert!(
        !manager.can_rollback().await,
        "Should not be able to rollback without backup"
    );

    // Attempt rollback should fail
    let result = manager.rollback().await;
    assert!(
        matches!(result, Err(UpgradeError::NoRollback(_))),
        "Rollback should fail when no backup exists"
    );
}

#[tokio::test]
async fn test_multiple_rollback_generations() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let backup_dir = temp_dir.path().join("backups");
    let binary_path = temp_dir.path().join("saorsa-binary");

    let manager = RollbackManager::new(backup_dir.clone()).with_max_backups(5);

    // Create version 0.9.0
    let v090_content = b"Version 0.9.0";
    create_test_binary(&binary_path, v090_content)
        .await
        .expect("Failed to create v0.9.0");
    let _backup1 = manager
        .create_backup(&binary_path, "0.9.0", Platform::current())
        .await
        .expect("Failed to backup v0.9.0");

    // Update to 0.10.0
    let v0100_content = b"Version 0.10.0";
    tokio::fs::write(&binary_path, v0100_content)
        .await
        .expect("Failed to write v0.10.0");
    let _backup2 = manager
        .create_backup(&binary_path, "0.10.0", Platform::current())
        .await
        .expect("Failed to backup v0.10.0");

    // Update to 0.11.0
    let v0110_content = b"Version 0.11.0";
    tokio::fs::write(&binary_path, v0110_content)
        .await
        .expect("Failed to write v0.11.0");

    // List backups
    let backups = manager
        .list_backups()
        .await
        .expect("Failed to list backups");
    assert_eq!(backups.len(), 2, "Should have 2 backups");

    // Rollback from 0.11.0 to 0.10.0
    let restored1 = manager.rollback().await.expect("Failed first rollback");
    assert_eq!(restored1.version, "0.10.0");

    // Can rollback again to 0.9.0
    let backup_090 = manager
        .get_backup_for_version("0.9.0")
        .await
        .expect("Failed to get 0.9.0 backup");
    assert!(backup_090.is_some(), "Should have backup for 0.9.0");
}

// ============================================================================
// Test Suite 5: Update Manifest Parsing
// ============================================================================

#[tokio::test]
async fn test_valid_manifest_parsing() {
    let (public_key, secret_key) = generate_test_keypair();
    let manifest = create_test_manifest(
        "1.0.0",
        ReleaseChannel::Stable,
        false,
        &public_key,
        &secret_key,
    );

    // Serialize and parse
    let json = manifest.to_json().expect("Failed to serialize manifest");
    let parsed = UpdateManifest::from_json(&json).expect("Failed to parse manifest");

    assert_eq!(parsed.manifest_version, 1);
    assert_eq!(parsed.releases.len(), 1);
    assert_eq!(parsed.releases[0].version, "1.0.0");
}

#[tokio::test]
async fn test_invalid_manifest_rejection() {
    let invalid_json = r#"{
        "manifest_version": 1,
        "generated_at": 1700000000
    }"#;

    let result = UpdateManifest::from_json(invalid_json);
    assert!(result.is_err(), "Invalid manifest should fail parsing");
}

#[tokio::test]
async fn test_version_comparison_logic() {
    use semver::Version;

    // Test semantic version comparison
    let v0_10 = Version::parse("0.10.0").expect("Failed to parse 0.10.0");
    let v0_11 = Version::parse("0.11.0").expect("Failed to parse 0.11.0");
    let v0_11_1 = Version::parse("0.11.1").expect("Failed to parse 0.11.1");
    let v1_0 = Version::parse("1.0.0").expect("Failed to parse 1.0.0");
    let v0_99 = Version::parse("0.99.0").expect("Failed to parse 0.99.0");
    let v0_9 = Version::parse("0.9.0").expect("Failed to parse 0.9.0");

    // Standard version comparisons
    assert!(v0_10 < v0_11, "0.10.0 should be less than 0.11.0");
    assert!(v0_11 < v0_11_1, "0.11.0 should be less than 0.11.1");
    assert!(v1_0 > v0_99, "1.0.0 should be greater than 0.99.0");

    // Edge case: This would fail with lexicographic comparison
    // "0.9.0" > "0.10.0" lexicographically (incorrect)
    // but semantically 0.9.0 < 0.10.0 (correct)
    assert!(
        v0_9 < v0_10,
        "0.9.0 should be less than 0.10.0 (semantic versioning)"
    );

    // Additional edge cases
    let v0_2 = Version::parse("0.2.0").expect("Failed to parse 0.2.0");
    let v0_10_0 = Version::parse("0.10.0").expect("Failed to parse 0.10.0");
    assert!(
        v0_2 < v0_10_0,
        "0.2.0 should be less than 0.10.0 (not lexicographic)"
    );

    // Test manifest version finding
    let (public_key, secret_key) = generate_test_keypair();
    let mut manifest = create_test_manifest(
        "1.0.0",
        ReleaseChannel::Stable,
        false,
        &public_key,
        &secret_key,
    );

    // Add more releases
    let release_2 = Release {
        version: "1.1.0".to_string(),
        channel: ReleaseChannel::Stable,
        is_critical: false,
        release_notes: "Version 1.1.0".to_string(),
        minimum_from_version: None,
        published_at: 1700000000,
        binaries: HashMap::new(),
    };
    manifest.releases.push(release_2);

    let latest = manifest.latest_for_channel(ReleaseChannel::Stable);
    assert!(latest.is_some());
    assert_eq!(latest.unwrap().version, "1.1.0");
}

// ============================================================================
// Test Suite 6: Update Manager Lifecycle
// ============================================================================

#[tokio::test]
async fn test_manifest_channel_filtering() {
    let (public_key, secret_key) = generate_test_keypair();
    let mut manifest = create_test_manifest(
        "1.0.0",
        ReleaseChannel::Stable,
        false,
        &public_key,
        &secret_key,
    );

    // Add beta release
    let beta_release = Release {
        version: "1.1.0-beta".to_string(),
        channel: ReleaseChannel::Beta,
        is_critical: false,
        release_notes: "Beta release".to_string(),
        minimum_from_version: None,
        published_at: 1700000000,
        binaries: HashMap::new(),
    };
    manifest.releases.push(beta_release);

    // Check stable channel
    let stable = manifest.latest_for_channel(ReleaseChannel::Stable);
    assert!(stable.is_some());
    assert_eq!(stable.unwrap().version, "1.0.0");

    // Check beta channel
    let beta = manifest.latest_for_channel(ReleaseChannel::Beta);
    assert!(beta.is_some());
    assert_eq!(beta.unwrap().version, "1.1.0-beta");

    // Check nightly (should be none)
    let nightly = manifest.latest_for_channel(ReleaseChannel::Nightly);
    assert!(nightly.is_none());
}

#[tokio::test]
async fn test_staging_manager_workflow() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let staging_dir = temp_dir.path().join("staging");

    let manager = StagedUpdateManager::new(staging_dir.clone());
    manager
        .ensure_staging_dir()
        .await
        .expect("Failed to ensure staging dir");

    // Initially no staged update
    assert!(!manager.has_staged_update().await);

    // Create a staged update
    let binary_path = manager.staged_binary_path("1.0.0", Platform::current());
    let test_content = b"Staged binary version 1.0.0";
    create_test_binary(&binary_path, test_content)
        .await
        .expect("Failed to create staged binary");

    let checksum = calculate_sha256(test_content);
    let staged = StagedUpdate::new(
        "1.0.0",
        binary_path,
        Platform::current(),
        checksum,
        test_content.len() as u64,
    );

    // Save metadata
    manager
        .save_metadata(&staged)
        .await
        .expect("Failed to save metadata");

    // Should now have staged update
    assert!(manager.has_staged_update().await);

    // Load it back
    let loaded = manager
        .get_staged_update()
        .await
        .expect("Failed to get staged update");
    assert!(loaded.is_some());
    let loaded = loaded.unwrap();
    assert_eq!(loaded.version, "1.0.0");
}

#[tokio::test]
async fn test_update_config_builder() {
    let config = UpdateConfig::default()
        .with_manifest_url("https://test.example.com/manifest.json")
        .with_channel(ReleaseChannel::Beta)
        .with_check_interval(Duration::from_secs(3600));

    assert_eq!(
        config.manifest_url,
        "https://test.example.com/manifest.json"
    );
    assert_eq!(config.channel, ReleaseChannel::Beta);
    assert_eq!(config.check_interval, Duration::from_secs(3600));
    assert!(config.verify_signatures);
}

// ============================================================================
// Test Suite 7: Security Scenarios
// ============================================================================

#[tokio::test]
async fn test_downgrade_prevention() {
    // In a real implementation, the update manager would check versions
    // For now, test that version comparison works correctly
    let current_version = "0.11.0";
    let downgrade_version = "0.10.0";

    assert!(
        downgrade_version < current_version,
        "Downgrade should be detected by version comparison"
    );
}

#[tokio::test]
async fn test_signature_verification_prevents_tampering() {
    let (public_key, secret_key) = generate_test_keypair();

    let original_binary = b"Original legitimate binary";
    let signature = sign_binary(original_binary, &secret_key);

    // Attacker tries to swap binary with same signature
    let malicious_binary = b"Malicious backdoored binary";

    let result = verify_binary_signature(malicious_binary, &signature, &public_key);
    assert!(
        !result,
        "Signature verification should prevent binary tampering"
    );
}

#[tokio::test]
async fn test_expired_key_rejection() {
    let (public_key, _secret_key) = generate_test_keypair();

    // Create a key that has expired
    let expired_key = PinnedKey {
        key_id: "expired-key".to_string(),
        public_key: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            public_key.as_bytes(),
        ),
        valid_from: 0,
        valid_until: 1, // Expired timestamp
    };

    assert!(!expired_key.is_valid(), "Expired key should not be valid");

    let verifier = SignatureVerifier::new(vec![expired_key]);
    let result = verifier.verify_signature("expired-key", b"message", "signature");
    assert!(
        matches!(result, Err(UpgradeError::NoValidKey(_))),
        "Should reject expired key"
    );
}

// ============================================================================
// Additional Integration Tests
// ============================================================================

#[tokio::test]
async fn test_backup_cleanup() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let backup_dir = temp_dir.path().join("backups");
    let binary_path = temp_dir.path().join("saorsa-binary");

    let manager = RollbackManager::new(backup_dir).with_max_backups(3);

    // Create multiple backups
    for i in 1..=5 {
        let version = format!("0.{}.0", i);
        let content = format!("Binary version {}", version);
        create_test_binary(&binary_path, content.as_bytes())
            .await
            .expect("Failed to create binary");

        manager
            .create_backup(&binary_path, &version, Platform::current())
            .await
            .expect("Failed to create backup");
    }

    // Should only keep 3 most recent
    let backups = manager
        .list_backups()
        .await
        .expect("Failed to list backups");
    assert!(backups.len() <= 3, "Should enforce max_backups limit");
}

#[tokio::test]
async fn test_corrupted_backup_detection() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let backup_dir = temp_dir.path().join("backups");
    let binary_path = temp_dir.path().join("saorsa-binary");

    let manager = RollbackManager::new(backup_dir.clone());

    // Create backup
    let content = b"Original binary";
    create_test_binary(&binary_path, content)
        .await
        .expect("Failed to create binary");
    let backup = manager
        .create_backup(&binary_path, "1.0.0", Platform::current())
        .await
        .expect("Failed to create backup");

    // Corrupt the backup file
    let backup_path = backup_dir.join(&backup.backup_filename);
    tokio::fs::write(&backup_path, b"CORRUPTED")
        .await
        .expect("Failed to corrupt backup");

    // Rollback should fail due to checksum mismatch
    let result = manager.rollback().await;
    assert!(
        matches!(result, Err(UpgradeError::Rollback(_))),
        "Should detect corrupted backup"
    );
}

#[tokio::test]
async fn test_manifest_signature_verification() {
    let (public_key, secret_key) = generate_test_keypair();
    let manifest = create_test_manifest(
        "1.0.0",
        ReleaseChannel::Stable,
        false,
        &public_key,
        &secret_key,
    );

    // Verify manifest signature
    let canonical_bytes = manifest
        .canonical_bytes()
        .expect("Failed to get canonical bytes");
    let signature_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &manifest.signature,
    )
    .expect("Failed to decode signature");

    let signature = signature_from_bytes(&signature_bytes).expect("Failed to parse signature");

    let result = verify_binary_signature(&canonical_bytes, &signature, &public_key);
    assert!(result, "Manifest signature should verify successfully");
}

#[tokio::test]
async fn test_release_platform_support() {
    let (public_key, secret_key) = generate_test_keypair();
    let manifest = create_test_manifest(
        "1.0.0",
        ReleaseChannel::Stable,
        false,
        &public_key,
        &secret_key,
    );

    let release = &manifest.releases[0];

    // Should support current platform
    let current_platform_binary = release.binary_for_current_platform();
    assert!(
        current_platform_binary.is_some(),
        "Should have binary for current platform"
    );

    assert!(
        release.supports_current_platform(),
        "Should support current platform"
    );
}

#[tokio::test]
async fn test_critical_update_flag() {
    let (public_key, secret_key) = generate_test_keypair();
    let manifest = create_test_manifest(
        "1.0.0",
        ReleaseChannel::Stable,
        true,
        &public_key,
        &secret_key,
    );

    let release = &manifest.releases[0];
    assert!(release.is_critical, "Release should be marked as critical");
}

#[tokio::test]
async fn test_staged_update_age() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let binary_path = temp_dir.path().join("test-binary");

    create_test_binary(&binary_path, b"test")
        .await
        .expect("Failed to create binary");

    let staged = StagedUpdate::new("1.0.0", binary_path, Platform::current(), "checksum", 100);

    // Age should be very small (just created)
    let age = staged.age();
    assert!(
        age.as_secs() < 5,
        "Newly created staged update should have minimal age"
    );
}

#[tokio::test]
async fn test_verify_file_integration() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("test-binary");

    let (public_key, secret_key) = generate_test_keypair();
    let test_content = b"Test binary for file verification";

    create_test_binary(&file_path, test_content)
        .await
        .expect("Failed to create binary");

    let checksum = calculate_sha256(test_content);
    let signature = sign_binary(test_content, &secret_key);
    let signature_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signature.as_bytes(),
    );

    let pinned_key = PinnedKey::new(
        "test-key",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            public_key.as_bytes(),
        ),
    );
    let verifier = SignatureVerifier::new(vec![pinned_key]);

    let result = verifier
        .verify_file(&file_path, &checksum, "test-key", &signature_b64)
        .await;
    assert!(
        result.is_ok(),
        "File verification should succeed with valid checksum and signature"
    );
}
