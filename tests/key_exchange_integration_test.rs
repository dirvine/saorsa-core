// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Saorsa Labs
// See LICENSE file for more information.

//! Integration tests for PQC key exchange functionality

use anyhow::Result;
use saorsa_core::identity::FourWordAddress;
use saorsa_core::messaging::{
    DhtClient, MessagingService, MessageContent, ChannelId, SendOptions,
};
use std::time::Duration;
use tokio::time::sleep;
use tracing_subscriber;

/// Initialize logging for tests
fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug,ant_quic=warn")
        .with_test_writer()
        .try_init();
}

/// Test basic key exchange between two peers
#[tokio::test]
async fn test_key_exchange_initiation_and_response() -> Result<()> {
    init_logging();

    // Create two messaging services
    let dht1 = DhtClient::new()?;
    let dht2 = DhtClient::new()?;

    let alice_addr = FourWordAddress("alice-test-one-alpha".to_string());
    let bob_addr = FourWordAddress("bob-test-one-beta".to_string());

    let alice_service = MessagingService::new(alice_addr.clone(), dht1).await?;
    let bob_service = MessagingService::new(bob_addr.clone(), dht2).await?;

    // Start message receivers to process key exchange
    let _alice_rx = alice_service.subscribe_messages(None).await;
    let _bob_rx = bob_service.subscribe_messages(None).await;

    // Connect peers via their network addresses
    // Convert 0.0.0.0 to localhost for local testing
    let bob_addrs = bob_service.listen_addrs().await;
    if let Some(bob_addr) = bob_addrs.first() {
        let connect_addr = format!("127.0.0.1:{}", bob_addr.port());
        alice_service.connect_peer(&connect_addr).await?;
    }

    // Give time for connection establishment
    sleep(Duration::from_millis(500)).await;

    // Attempt to send a message from Alice to Bob
    // This should trigger automatic key exchange
    let message_content = MessageContent::Text("Hello Bob!".to_string());
    let channel = ChannelId::new();
    let options = SendOptions::default();

    let result = alice_service
        .send_message(vec![bob_addr], message_content, channel, options)
        .await;

    // The send should complete successfully after key exchange
    match result {
        Ok((message_id, receipt)) => {
            tracing::info!("Message sent successfully: {:?}", message_id);
            tracing::info!("Delivery receipt: {:?}", receipt);
            Ok(())
        }
        Err(e) => {
            tracing::error!("Message send failed: {}", e);
            Err(e)
        }
    }
}

/// Test that session keys are cached and reused
#[tokio::test]
async fn test_session_key_caching() -> Result<()> {
    init_logging();

    let dht1 = DhtClient::new()?;
    let dht2 = DhtClient::new()?;

    let alice_addr = FourWordAddress("alice-test-two-alpha".to_string());
    let bob_addr = FourWordAddress("bob-test-two-beta".to_string());

    let alice_service = MessagingService::new(alice_addr.clone(), dht1).await?;
    let bob_service = MessagingService::new(bob_addr.clone(), dht2).await?;

    let _alice_rx = alice_service.subscribe_messages(None).await;
    let _bob_rx = bob_service.subscribe_messages(None).await;

    // Connect peers
    let bob_addrs = bob_service.listen_addrs().await;
    if let Some(bob_addr) = bob_addrs.first() {
        let connect_addr = format!("127.0.0.1:{}", bob_addr.port());
        alice_service.connect_peer(&connect_addr).await?;
    }

    sleep(Duration::from_millis(500)).await;

    // Send first message (triggers key exchange)
    let channel = ChannelId::new();
    let options = SendOptions::default();

    let result1 = alice_service
        .send_message(
            vec![bob_addr.clone()],
            MessageContent::Text("First message".to_string()),
            channel,
            options.clone(),
        )
        .await;

    assert!(result1.is_ok(), "First message should trigger key exchange and succeed");

    // Send second message immediately (should reuse session key)
    let result2 = alice_service
        .send_message(
            vec![bob_addr],
            MessageContent::Text("Second message".to_string()),
            channel,
            options,
        )
        .await;

    assert!(result2.is_ok(), "Second message should reuse cached session key");

    Ok(())
}

/// Test key exchange timeout handling
#[tokio::test]
async fn test_key_exchange_timeout() -> Result<()> {
    init_logging();

    let dht = DhtClient::new()?;
    let alice_addr = FourWordAddress("alice-test-three-alpha".to_string());
    let nonexistent_addr = FourWordAddress("nonexistent-peer-fake".to_string());

    let alice_service = MessagingService::new(alice_addr, dht).await?;
    let _alice_rx = alice_service.subscribe_messages(None).await;

    // Try to send to a peer that doesn't exist
    // This should timeout during key exchange
    let result = alice_service
        .send_message(
            vec![nonexistent_addr],
            MessageContent::Text("Test".to_string()),
            ChannelId::new(),
            SendOptions::default(),
        )
        .await;

    // Should fail due to inability to establish key exchange
    assert!(result.is_err(), "Should fail to send to nonexistent peer");

    Ok(())
}

/// Test bidirectional key exchange
#[tokio::test]
async fn test_bidirectional_key_exchange() -> Result<()> {
    init_logging();

    let dht1 = DhtClient::new()?;
    let dht2 = DhtClient::new()?;

    let alice_addr = FourWordAddress("alice-test-four-alpha".to_string());
    let bob_addr = FourWordAddress("bob-test-four-beta".to_string());

    let alice_service = MessagingService::new(alice_addr.clone(), dht1).await?;
    let bob_service = MessagingService::new(bob_addr.clone(), dht2).await?;

    let _alice_rx = alice_service.subscribe_messages(None).await;
    let _bob_rx = bob_service.subscribe_messages(None).await;

    // Connect peers
    let bob_addrs = bob_service.listen_addrs().await;
    let alice_addrs = alice_service.listen_addrs().await;

    if let Some(bob_addr) = bob_addrs.first() {
        let connect_addr = format!("127.0.0.1:{}", bob_addr.port());
        alice_service.connect_peer(&connect_addr).await?;
    }
    if let Some(alice_addr) = alice_addrs.first() {
        let connect_addr = format!("127.0.0.1:{}", alice_addr.port());
        bob_service.connect_peer(&connect_addr).await?;
    }

    sleep(Duration::from_millis(500)).await;

    // Alice sends to Bob
    let result1 = alice_service
        .send_message(
            vec![bob_addr.clone()],
            MessageContent::Text("Alice to Bob".to_string()),
            ChannelId::new(),
            SendOptions::default(),
        )
        .await;

    assert!(result1.is_ok(), "Alice should be able to send to Bob");

    sleep(Duration::from_millis(200)).await;

    // Bob sends to Alice (should establish independent session)
    let result2 = bob_service
        .send_message(
            vec![alice_addr],
            MessageContent::Text("Bob to Alice".to_string()),
            ChannelId::new(),
            SendOptions::default(),
        )
        .await;

    assert!(result2.is_ok(), "Bob should be able to send to Alice");

    Ok(())
}
