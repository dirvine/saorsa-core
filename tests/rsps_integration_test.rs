use anyhow::Result;
use saorsa_core::dht::rsps_integration::{RspsDhtStorage, RspsConfig};
use saorsa_core::dht::optimized_storage::{OptimizedDHTStorage, StorageConfig};
use saorsa_rsps::{RootCid, ProviderRecord, GolombCodedSet, WitnessKey, ReceiptData};
use libp2p::PeerId;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

/// Test configuration for RSPS
fn test_config() -> RspsConfig {
    RspsConfig {
        cache_capacity: 100,
        false_positive_rate: 0.001,
        min_receipts_for_extension: 2,
        cleanup_interval: Duration::from_secs(60),
        default_ttl: Duration::from_secs(3600),
    }
}

/// Create a test storage instance
async fn create_test_storage() -> RspsDhtStorage {
    let storage_config = StorageConfig {
        max_entries: 1000,
        eviction_batch_size: 10,
        ttl_check_interval: Duration::from_secs(30),
        replication_factor: 3,
    };
    
    let base_storage = Arc::new(OptimizedDHTStorage::new(storage_config));
    let local_peer = PeerId::random();
    let config = test_config();
    
    RspsDhtStorage::new(base_storage, local_peer, config)
}

#[tokio::test]
async fn test_store_and_find_provider() -> Result<()> {
    let storage = create_test_storage().await;
    let root_cid = RootCid::from(b"test-root-cid".to_vec());
    let provider = PeerId::random();
    
    // Store provider
    storage.store_provider(
        root_cid.clone(),
        provider,
        Duration::from_secs(3600),
    ).await?;
    
    // Find providers
    let providers = storage.find_providers(&root_cid).await?;
    assert!(providers.contains(&provider));
    
    Ok(())
}

#[tokio::test]
async fn test_cache_admission_control() -> Result<()> {
    let storage = create_test_storage().await;
    
    // Create root CIDs
    let included_root = RootCid::from(b"included-root".to_vec());
    let excluded_root = RootCid::from(b"excluded-root".to_vec());
    
    // Store provider for included root
    let provider = PeerId::random();
    storage.store_provider(
        included_root.clone(),
        provider,
        Duration::from_secs(3600),
    ).await?;
    
    // Create content CIDs
    let included_content = b"content-under-included-root".to_vec();
    let excluded_content = b"content-under-excluded-root".to_vec();
    
    // Test cache admission
    assert!(
        storage.cache_if_allowed(&included_root, &included_content).await,
        "Content under included root should be cached"
    );
    
    assert!(
        !storage.cache_if_allowed(&excluded_root, &excluded_content).await,
        "Content under excluded root should not be cached"
    );
    
    Ok(())
}

#[tokio::test]
async fn test_witness_receipt_generation() -> Result<()> {
    let storage = create_test_storage().await;
    let root_cid = RootCid::from(b"test-root".to_vec());
    let content_cid = b"test-content".to_vec();
    
    // Store provider first
    let provider = PeerId::random();
    storage.store_provider(
        root_cid.clone(),
        provider,
        Duration::from_secs(3600),
    ).await?;
    
    // Generate receipt
    let receipt = storage.generate_receipt(&root_cid, &content_cid).await?;
    
    // Verify receipt has required fields
    assert!(!receipt.pseudonym.is_empty());
    assert!(receipt.timestamp > 0);
    assert!(!receipt.signature.is_empty());
    assert_eq!(receipt.root_cid, root_cid.0);
    
    Ok(())
}

#[tokio::test]
async fn test_ttl_extension_on_receipts() -> Result<()> {
    let storage = create_test_storage().await;
    let root_cid = RootCid::from(b"popular-root".to_vec());
    let provider = PeerId::random();
    
    // Store provider with initial TTL
    let initial_ttl = Duration::from_secs(3600);
    storage.store_provider(
        root_cid.clone(),
        provider,
        initial_ttl,
    ).await?;
    
    // Generate multiple receipts to trigger TTL extension
    for i in 0..3 {
        let content_cid = format!("content-{}", i).into_bytes();
        let _ = storage.generate_receipt(&root_cid, &content_cid).await?;
        
        // Small delay to ensure different timestamps
        time::sleep(Duration::from_millis(10)).await;
    }
    
    // Check that provider is still findable (TTL extended)
    let providers = storage.find_providers(&root_cid).await?;
    assert!(providers.contains(&provider));
    
    Ok(())
}

#[tokio::test]
async fn test_rsps_update_with_new_content() -> Result<()> {
    let storage = create_test_storage().await;
    let root_cid = RootCid::from(b"evolving-root".to_vec());
    let provider = PeerId::random();
    
    // Store initial provider
    storage.store_provider(
        root_cid.clone(),
        provider,
        Duration::from_secs(3600),
    ).await?;
    
    // Add multiple content items
    let content_items = vec![
        b"content1".to_vec(),
        b"content2".to_vec(),
        b"content3".to_vec(),
    ];
    
    for content in &content_items {
        // Cache the content (simulating actual DHT storage)
        storage.cache_if_allowed(&root_cid, content).await;
        
        // Generate receipt
        storage.generate_receipt(&root_cid, content).await?;
    }
    
    // Verify provider still exists with updated summary
    let providers = storage.find_providers(&root_cid).await?;
    assert!(providers.contains(&provider));
    
    Ok(())
}

#[tokio::test]
async fn test_expired_entries_cleanup() -> Result<()> {
    let storage = create_test_storage().await;
    let root_cid = RootCid::from(b"expiring-root".to_vec());
    let provider = PeerId::random();
    
    // Store provider with very short TTL
    storage.store_provider(
        root_cid.clone(),
        provider,
        Duration::from_millis(100),
    ).await?;
    
    // Initially should find provider
    let providers = storage.find_providers(&root_cid).await?;
    assert!(providers.contains(&provider));
    
    // Wait for expiration
    time::sleep(Duration::from_millis(150)).await;
    
    // Trigger cleanup
    storage.cleanup_expired().await;
    
    // Should no longer find provider
    let providers = storage.find_providers(&root_cid).await?;
    assert!(!providers.contains(&provider));
    
    Ok(())
}

#[tokio::test]
async fn test_multiple_providers_per_root() -> Result<()> {
    let storage = create_test_storage().await;
    let root_cid = RootCid::from(b"multi-provider-root".to_vec());
    
    // Store multiple providers
    let providers: Vec<PeerId> = (0..5).map(|_| PeerId::random()).collect();
    
    for provider in &providers {
        storage.store_provider(
            root_cid.clone(),
            *provider,
            Duration::from_secs(3600),
        ).await?;
    }
    
    // Find all providers
    let found_providers = storage.find_providers(&root_cid).await?;
    
    // All providers should be found
    for provider in &providers {
        assert!(found_providers.contains(provider));
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
            let root_cid = RootCid::from(format!("concurrent-root-{}", i).into_bytes());
            let provider = PeerId::random();
            
            // Store provider
            storage_clone.store_provider(
                root_cid.clone(),
                provider,
                Duration::from_secs(3600),
            ).await.unwrap();
            
            // Generate receipt
            let content = format!("content-{}", i).into_bytes();
            storage_clone.generate_receipt(&root_cid, &content).await.unwrap();
            
            // Find providers
            let providers = storage_clone.find_providers(&root_cid).await.unwrap();
            assert!(providers.contains(&provider));
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
        let root_cid = RootCid::from(format!("root-{}", i).into_bytes());
        let provider = PeerId::random();
        
        storage.store_provider(
            root_cid.clone(),
            provider,
            Duration::from_secs(3600),
        ).await?;
        
        // Only cache some content items
        if i % 2 == 0 {
            let content = format!("content-{}", i).into_bytes();
            storage.cache_if_allowed(&root_cid, &content).await;
        }
    }
    
    // Verify cache respects RSPS admission control
    // Even after eviction, RSPS membership should be maintained
    let test_root = RootCid::from(b"root-0".to_vec());
    let providers = storage.find_providers(&test_root).await?;
    assert!(!providers.is_empty(), "RSPS entries should be maintained");
    
    Ok(())
}

#[tokio::test]
async fn test_receipt_validation() -> Result<()> {
    let storage = create_test_storage().await;
    let root_cid = RootCid::from(b"validation-root".to_vec());
    let content_cid = b"validation-content".to_vec();
    
    // Store provider
    let provider = PeerId::random();
    storage.store_provider(
        root_cid.clone(),
        provider,
        Duration::from_secs(3600),
    ).await?;
    
    // Generate receipt
    let receipt = storage.generate_receipt(&root_cid, &content_cid).await?;
    
    // Validate receipt structure
    assert_eq!(receipt.root_cid, root_cid.0);
    assert!(receipt.timestamp > 0);
    assert!(!receipt.pseudonym.is_empty());
    assert!(!receipt.signature.is_empty());
    
    // Verify signature format (should be valid base64 or hex)
    assert!(receipt.signature.len() >= 64, "Signature should be substantial");
    
    Ok(())
}