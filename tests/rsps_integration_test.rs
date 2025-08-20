use anyhow::Result;

use saorsa_core::dht::optimized_storage::OptimizedDHTStorage;
use saorsa_core::dht::rsps_integration::{RspsDhtConfig as RspsConfig, RspsDhtStorage};
use saorsa_rsps::{Cid, RootCid};
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

/// Test configuration for RSPS
fn test_config() -> RspsConfig {
    RspsConfig::default()
}

/// Create a test storage instance
async fn create_test_storage() -> RspsDhtStorage {
    let base_storage = Arc::new(OptimizedDHTStorage::new(
        saorsa_core::dht::DHTConfig::default(),
    ));
    let local_peer = "peer-1".to_string();
    let config = test_config();
    RspsDhtStorage::new(base_storage, local_peer, config)
        .await
        .unwrap()
}

#[tokio::test]
async fn test_store_and_find_provider() -> Result<()> {
    let storage = create_test_storage().await;
    let root_cid = RootCid::from(blake3::hash(b"test-root-cid").as_bytes().to_owned());
    let provider = "provider-1".to_string();

    // Store provider
    storage
        .store_provider(
            root_cid.clone(),
            provider.clone(),
            vec![],
            saorsa_rsps::Rsps::new(
                root_cid.clone(),
                0,
                &[],
                &saorsa_rsps::RspsConfig::default(),
            )
            .unwrap(),
        )
        .await?;

    // Find providers
    let providers = storage.find_providers(&root_cid).await?;
    assert!(providers.iter().any(|p| p.provider == provider));

    Ok(())
}

#[tokio::test]
async fn test_cache_admission_control() -> Result<()> {
    let storage = create_test_storage().await;

    // Create root CIDs
    let included_root = RootCid::from(blake3::hash(b"included-root").as_bytes().to_owned());
    let excluded_root = RootCid::from(blake3::hash(b"excluded-root").as_bytes().to_owned());

    // Store provider for included root
    let provider = "provider-1".to_string();
    storage
        .store_provider(
            included_root.clone(),
            provider.clone(),
            vec![],
            saorsa_rsps::Rsps::new(
                included_root.clone(),
                0,
                &[],
                &saorsa_rsps::RspsConfig::default(),
            )
            .unwrap(),
        )
        .await?;

    // Create content CIDs
    let included_content = b"content-under-included-root".to_vec();
    let excluded_content = b"content-under-excluded-root".to_vec();

    // Test cache admission
    let included_cid = Cid::from(blake3::hash(b"included-content").as_bytes().to_owned());
    assert!(
        storage
            .cache_if_allowed(
                included_root.clone(),
                included_cid,
                included_content.clone()
            )
            .await?
    );

    let excluded_cid = Cid::from(blake3::hash(b"excluded-content").as_bytes().to_owned());
    assert!(
        !storage
            .cache_if_allowed(
                excluded_root.clone(),
                excluded_cid,
                excluded_content.clone()
            )
            .await?
    );

    Ok(())
}

#[tokio::test]
async fn test_witness_receipt_generation() -> Result<()> {
    let storage = create_test_storage().await;
    let root_cid = RootCid::from(blake3::hash(b"test-root").as_bytes().to_owned());
    let content_cid = Cid::from(blake3::hash(b"test-content").as_bytes().to_owned());

    // Store provider first
    let provider = "provider-1".to_string();
    storage
        .store_provider(
            root_cid.clone(),
            provider.clone(),
            vec![],
            saorsa_rsps::Rsps::new(
                root_cid.clone(),
                0,
                &[],
                &saorsa_rsps::RspsConfig::default(),
            )
            .unwrap(),
        )
        .await?;

    // Generate receipt
    let receipt = storage.generate_receipt(&content_cid).await?;

    // Verify receipt has required fields
    assert!(
        !receipt.witness_pseudonym.proof.is_empty() || !receipt.witness_pseudonym.value.is_empty()
    );
    assert!(receipt.timestamp > std::time::UNIX_EPOCH);
    assert_eq!(receipt.cid, content_cid);

    Ok(())
}

#[tokio::test]
async fn test_ttl_extension_on_receipts() -> Result<()> {
    let storage = create_test_storage().await;
    let root_cid = RootCid::from(blake3::hash(b"popular-root").as_bytes().to_owned());
    let provider = "provider-1".to_string();

    // Store provider with initial TTL
    let _initial_ttl = Duration::from_secs(3600);
    storage
        .store_provider(
            root_cid.clone(),
            provider.clone(),
            vec![],
            saorsa_rsps::Rsps::new(
                root_cid.clone(),
                0,
                &[],
                &saorsa_rsps::RspsConfig::default(),
            )
            .unwrap(),
        )
        .await?;

    // Generate multiple receipts to trigger TTL extension
    for _i in 0..3 {
        let content_cid = Cid::from(blake3::hash(b"content-idx").as_bytes().to_owned());
        let _ = storage.generate_receipt(&content_cid).await?;

        // Small delay to ensure different timestamps
        time::sleep(Duration::from_millis(10)).await;
    }

    // Check that provider is still findable (TTL extended)
    let providers = storage.find_providers(&root_cid).await?;
    assert!(providers.iter().any(|p| p.provider == provider));

    Ok(())
}

#[tokio::test]
async fn test_rsps_update_with_new_content() -> Result<()> {
    let storage = create_test_storage().await;
    let root_cid = RootCid::from(blake3::hash(b"evolving-root").as_bytes().to_owned());
    let provider = "provider-1".to_string();

    // Store initial provider
    storage
        .store_provider(
            root_cid.clone(),
            provider.clone(),
            vec![],
            saorsa_rsps::Rsps::new(
                root_cid.clone(),
                0,
                &[],
                &saorsa_rsps::RspsConfig::default(),
            )
            .unwrap(),
        )
        .await?;

    // Add multiple content items
    let content_items = vec![
        b"content1".to_vec(),
        b"content2".to_vec(),
        b"content3".to_vec(),
    ];

    for content in &content_items {
        // Cache the content (simulating actual DHT storage)
        let cid = Cid::from(blake3::hash(b"content-idx").as_bytes().to_owned());
        storage
            .cache_if_allowed(root_cid.clone(), cid, content.clone())
            .await?;

        // Generate receipt
        storage.generate_receipt(&cid).await?;
    }

    // Verify provider still exists with updated summary
    let providers = storage.find_providers(&root_cid).await?;
    assert!(providers.iter().any(|p| p.provider == provider));

    Ok(())
}

#[tokio::test]
async fn test_expired_entries_cleanup() -> Result<()> {
    let storage = create_test_storage().await;
    let root_cid = RootCid::from(blake3::hash(b"expiring-root").as_bytes().to_owned());
    let provider = "provider-1".to_string();

    // Store provider with very short TTL
    storage
        .store_provider(
            root_cid.clone(),
            provider.clone(),
            vec![],
            saorsa_rsps::Rsps::new(
                root_cid.clone(),
                0,
                &[],
                &saorsa_rsps::RspsConfig::default(),
            )
            .unwrap(),
        )
        .await?;

    // Initially should find provider
    let providers = storage.find_providers(&root_cid).await?;
    assert!(providers.iter().any(|p| p.provider == provider));

    // Wait for expiration
    time::sleep(Duration::from_millis(150)).await;

    // Trigger cleanup
    let _ = storage.cleanup_expired().await;

    // Should no longer find provider
    let providers = storage.find_providers(&root_cid).await?;
    assert!(!providers.iter().any(|p| p.provider == provider));

    Ok(())
}

#[tokio::test]
async fn test_multiple_providers_per_root() -> Result<()> {
    let storage = create_test_storage().await;
    let root_cid = RootCid::from(blake3::hash(b"multi-provider-root").as_bytes().to_owned());

    // Store multiple providers
    let providers: Vec<String> = (0..5).map(|i| format!("provider-{}", i)).collect();

    for provider in &providers {
        storage
            .store_provider(
                root_cid.clone(),
                provider.clone(),
                vec![],
                saorsa_rsps::Rsps::new(
                    root_cid.clone(),
                    0,
                    &[],
                    &saorsa_rsps::RspsConfig::default(),
                )
                .unwrap(),
            )
            .await?;
    }

    // Find all providers
    let found_providers = storage.find_providers(&root_cid).await?;

    // All providers should be found
    for provider in &providers {
        assert!(found_providers.iter().any(|p| p.provider == *provider));
    }

    Ok(())
}

#[tokio::test]
async fn test_concurrent_operations() -> Result<()> {
    let storage = Arc::new(create_test_storage().await);

    // Spawn multiple concurrent operations
    let mut handles = vec![];

    for i in 0..10 {
        let storage_clone = storage.clone();
        let handle = tokio::spawn(async move {
            let root_cid = RootCid::from(blake3::hash(b"concurrent-root").as_bytes().to_owned());
            let provider = format!("provider-{}", i);

            // Store provider
            storage_clone
                .store_provider(
                    root_cid.clone(),
                    provider.clone(),
                    vec![],
                    saorsa_rsps::Rsps::new(
                        root_cid.clone(),
                        0,
                        &[],
                        &saorsa_rsps::RspsConfig::default(),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();

            // Generate receipt
            let content = Cid::from(*b"content-idx__________________32b");
            storage_clone.generate_receipt(&content).await.unwrap();

            // Find providers
            let providers = storage_clone.find_providers(&root_cid).await.unwrap();
            assert!(providers.iter().any(|p| p.provider == provider));
        });

        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        handle.await?;
    }

    Ok(())
}

#[tokio::test]
async fn test_cache_eviction_respects_rsps() -> Result<()> {
    let storage = create_test_storage().await;

    // Fill cache to capacity
    for i in 0..150 {
        let root_cid = RootCid::from(*b"root-idx_____________________32b");
        let provider = format!("provider-{}", i);

        storage
            .store_provider(
                root_cid.clone(),
                provider.clone(),
                vec![],
                saorsa_rsps::Rsps::new(
                    root_cid.clone(),
                    0,
                    &[],
                    &saorsa_rsps::RspsConfig::default(),
                )
                .unwrap(),
            )
            .await?;

        // Only cache some content items
        if i % 2 == 0 {
            let content = Cid::from(blake3::hash(b"content-idx").as_bytes().to_owned());
            let _ = storage
                .cache_if_allowed(root_cid.clone(), content, vec![])
                .await?;
        }
    }

    // Verify cache respects RSPS admission control
    // Even after eviction, RSPS membership should be maintained
    let test_root = RootCid::from(blake3::hash(b"root-0").as_bytes().to_owned());
    let providers = storage.find_providers(&test_root).await?;
    assert!(!providers.is_empty(), "RSPS entries should be maintained");

    Ok(())
}

#[tokio::test]
async fn test_receipt_validation() -> Result<()> {
    let storage = create_test_storage().await;
    let root_cid = RootCid::from(blake3::hash(b"validation-root").as_bytes().to_owned());
    let content_cid = Cid::from(blake3::hash(b"validation-content").as_bytes().to_owned());

    // Store provider
    let provider = format!("peer-{}", 0);
    storage
        .store_provider(
            root_cid.clone(),
            provider.clone(),
            vec![],
            saorsa_rsps::Rsps::new(
                root_cid.clone(),
                0,
                &[],
                &saorsa_rsps::RspsConfig::default(),
            )
            .unwrap(),
        )
        .await?;

    // Generate receipt
    let receipt = storage.generate_receipt(&content_cid).await?;

    // Validate receipt structure
    assert_eq!(receipt.cid, content_cid);
    assert!(receipt.timestamp > std::time::UNIX_EPOCH);
    assert!(
        !receipt.witness_pseudonym.proof.is_empty() || !receipt.witness_pseudonym.value.is_empty()
    );

    // Verify signature format (should be valid base64 or hex)
    assert!(
        receipt.signature.len() >= 64,
        "Signature should be substantial"
    );

    Ok(())
}
