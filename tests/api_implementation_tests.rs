// Copyright 2024 Saorsa Labs Limited
//
// Focused integration checks for higher-level APIs that remain implemented in
// the current saorsa-core tree.

use anyhow::Result;
use saorsa_core::fwid::Key;
use saorsa_core::messaging::service::channel_recipients;
use saorsa_core::messaging::types::ChannelId;
use saorsa_core::virtual_disk::{
    Asset, DiskConfig, DiskType, FileMetadata, disk_create, disk_delete, disk_list, disk_read,
    disk_sync, disk_write, website_publish, website_set_home,
};

#[tokio::test]
async fn test_channel_recipients_helper() -> Result<()> {
    // The helper currently returns an empty list, but exercise the pathway to
    // ensure the plumbing stays wired during refactors.
    let channel_id = ChannelId::new();
    let recipients = channel_recipients(&channel_id).await?;
    assert!(recipients.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_virtual_disk_basic_operations() -> Result<()> {
    let entity_id = Key::from([1u8; 32]);
    let handle = disk_create(entity_id.clone(), DiskType::Private, DiskConfig::default()).await?;

    let content = b"Hello, Virtual Disk!";
    let receipt = disk_write(&handle, "test.txt", content, FileMetadata::default()).await?;
    assert_eq!(receipt.path.to_str().unwrap(), "test.txt");
    assert_eq!(receipt.bytes_written, content.len() as u64);

    let read_back = disk_read(&handle, "test.txt").await?;
    assert_eq!(read_back.as_slice(), content);

    let listing = disk_list(&handle, ".", false).await?;
    assert_eq!(listing.len(), 1);

    disk_delete(&handle, "test.txt").await?;
    let listing_after = disk_list(&handle, ".", false).await?;
    assert!(listing_after.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_website_helpers() -> Result<()> {
    let entity_id = Key::from([2u8; 32]);
    let handle = disk_create(
        entity_id.clone(),
        DiskType::Public,
        DiskConfig {
            encrypted: false,
            ..DiskConfig::default()
        },
    )
    .await?;

    let markdown = "# Welcome\n\nSample site";
    let assets = vec![
        Asset {
            path: "style.css".into(),
            content: b"body { font-family: sans-serif; }".to_vec(),
            mime_type: "text/css".into(),
        },
        Asset {
            path: "logo.png".into(),
            content: vec![0x89, 0x50, 0x4E, 0x47],
            mime_type: "image/png".into(),
        },
    ];

    website_set_home(&handle, markdown, assets).await?;
    let files = disk_list(&handle, ".", true).await?;
    assert_eq!(files.len(), 3);

    let website_root = Key::from([3u8; 32]);
    let receipt = website_publish(entity_id.clone(), website_root.clone()).await?;
    assert_eq!(receipt.entity_id, entity_id);
    assert_eq!(receipt.website_root, website_root);
    Ok(())
}

#[tokio::test]
async fn test_disk_sync_counts_written_files() -> Result<()> {
    let entity_id = Key::from([4u8; 32]);
    let handle = disk_create(entity_id, DiskType::Private, DiskConfig::default()).await?;

    for i in 0..5 {
        let path = format!("file{}.txt", i);
        let data = format!("content {}", i);
        disk_write(&handle, &path, data.as_bytes(), FileMetadata::default()).await?;
    }

    let status = disk_sync(&handle).await?;
    assert_eq!(status.files_synced, 5);
    assert!(status.bytes_synced > 0);
    assert!(status.errors.is_empty());
    Ok(())
}
