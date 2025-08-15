// Integration tests for the messaging API
use super::*;
use crate::messaging::{MessagingService, MessageContent, ChannelId};
use crate::identity::FourWordAddress;
use anyhow::Result;
use tokio::sync::broadcast;

#[cfg(test)]
mod messaging_api_tests {
    use super::*;

    // Helper to create test messaging service
    async fn create_test_service() -> Result<MessagingService> {
        let identity = FourWordAddress::from("test-user-alpha-beta");
        let dht_client = crate::messaging::DhtClient::new_mock();
        MessagingService::new(identity, dht_client).await
    }

    #[tokio::test]
    async fn test_send_simple_text_message() {
        let service = create_test_service().await.unwrap();
        let channel = ChannelId::new();
        let recipient = FourWordAddress::from("test-user-gamma-delta");
        
        // Send message
        let result = service.send_message(
            vec![recipient.clone()],
            MessageContent::Text("Hello, P2P!".to_string()),
            channel,
            Default::default(),
        ).await;
        
        assert!(result.is_ok());
        let (message_id, receipt) = result.unwrap();
        assert!(!message_id.to_string().is_empty());
        assert_eq!(receipt.delivery_status.len(), 1);
    }

    #[tokio::test]
    async fn test_receive_message_subscription() {
        let service = create_test_service().await.unwrap();
        let channel = ChannelId::new();
        
        // Subscribe to messages
        let mut receiver = service.subscribe_messages(Some(channel)).await;
        
        // Simulate receiving a message
        let sender = FourWordAddress::from("test-sender-alpha-beta");
        let test_message = service.create_test_message(
            sender,
            channel,
            MessageContent::Text("Test message".to_string())
        );
        
        service.inject_test_message(test_message.clone()).await.unwrap();
        
        // Should receive the message
        let received = receiver.recv().await;
        assert!(received.is_ok());
        let msg = received.unwrap();
        assert_eq!(msg.message.id, test_message.id);
    }

    #[tokio::test]
    async fn test_message_encryption_decryption() {
        let service = create_test_service().await.unwrap();
        let channel = ChannelId::new();
        let recipient = FourWordAddress::from("test-recipient-one-two");
        
        // Create and encrypt message
        let content = MessageContent::Text("Secret message".to_string());
        let encrypted = service.encrypt_message(
            recipient.clone(),
            channel,
            content.clone()
        ).await.unwrap();
        
        assert!(!encrypted.ciphertext.is_empty());
        assert!(!encrypted.nonce.is_empty());
        
        // Decrypt message
        let decrypted = service.decrypt_message(encrypted).await.unwrap();
        
        match decrypted.content {
            MessageContent::Text(text) => assert_eq!(text, "Secret message"),
            _ => panic!("Wrong content type"),
        }
    }

    #[tokio::test]
    async fn test_message_persistence() {
        let service = create_test_service().await.unwrap();
        let channel = ChannelId::new();
        let recipient = FourWordAddress::from("test-user-store-test");
        
        // Send message
        let (message_id, _receipt) = service.send_message(
            vec![recipient],
            MessageContent::Text("Persistent message".to_string()),
            channel,
            Default::default(),
        ).await.unwrap();
        
        // Retrieve from storage
        let retrieved = service.get_message(message_id).await.unwrap();
        assert_eq!(retrieved.id, message_id);
        
        match retrieved.content {
            MessageContent::Text(text) => assert_eq!(text, "Persistent message"),
            _ => panic!("Wrong content type"),
        }
    }

    #[tokio::test]
    async fn test_message_delivery_status() {
        let service = create_test_service().await.unwrap();
        let channel = ChannelId::new();
        let recipient = FourWordAddress::from("test-user-status-check");
        
        // Send message
        let (message_id, initial_receipt) = service.send_message(
            vec![recipient.clone()],
            MessageContent::Text("Status test".to_string()),
            channel,
            Default::default(),
        ).await.unwrap();
        
        // Check initial status (should be Queued)
        let status = service.get_message_status(message_id).await.unwrap();
        assert!(matches!(status, crate::messaging::types::DeliveryStatus::Queued));
        
        // Simulate delivery
        service.mark_delivered(message_id, recipient).await.unwrap();
        
        // Check updated status
        let status = service.get_message_status(message_id).await.unwrap();
        assert!(matches!(status, crate::messaging::types::DeliveryStatus::Delivered(_)));
    }

    #[tokio::test]
    async fn test_ephemeral_message() {
        let service = create_test_service().await.unwrap();
        let channel = ChannelId::new();
        let recipient = FourWordAddress::from("test-ephemeral-recv");
        
        // Send ephemeral message with 1 second expiry
        let options = crate::messaging::SendOptions {
            ephemeral: true,
            expiry_seconds: Some(1),
            ..Default::default()
        };
        
        let (message_id, _) = service.send_message(
            vec![recipient],
            MessageContent::Text("Disappearing message".to_string()),
            channel,
            options,
        ).await.unwrap();
        
        // Message should exist initially
        let msg = service.get_message(message_id).await.unwrap();
        assert!(msg.ephemeral);
        
        // Wait for expiry
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        
        // Message should be expired
        let msg = service.get_message(message_id).await.unwrap();
        assert!(msg.is_expired());
    }

    #[tokio::test]
    async fn test_message_with_attachment() {
        let service = create_test_service().await.unwrap();
        let channel = ChannelId::new();
        let recipient = FourWordAddress::from("test-attachment-user");
        
        // Create attachment
        let attachment = crate::messaging::types::Attachment {
            id: "test-file".to_string(),
            filename: "document.pdf".to_string(),
            mime_type: "application/pdf".to_string(),
            size_bytes: 1024,
            thumbnail: None,
            dht_hash: "hash123".to_string(),
            encryption_key: Some(vec![1, 2, 3, 4]),
            metadata: Default::default(),
        };
        
        let options = crate::messaging::SendOptions {
            attachments: vec![attachment.clone()],
            ..Default::default()
        };
        
        // Send message with attachment
        let (message_id, _) = service.send_message(
            vec![recipient],
            MessageContent::Text("See attached".to_string()),
            channel,
            options,
        ).await.unwrap();
        
        // Retrieve and verify
        let msg = service.get_message(message_id).await.unwrap();
        assert_eq!(msg.attachments.len(), 1);
        assert_eq!(msg.attachments[0].filename, "document.pdf");
    }

    #[tokio::test]
    async fn test_thread_reply() {
        let service = create_test_service().await.unwrap();
        let channel = ChannelId::new();
        let recipient = FourWordAddress::from("test-thread-user");
        
        // Send parent message
        let (parent_id, _) = service.send_message(
            vec![recipient.clone()],
            MessageContent::Text("Parent message".to_string()),
            channel,
            Default::default(),
        ).await.unwrap();
        
        // Send reply in thread
        let options = crate::messaging::SendOptions {
            reply_to: Some(parent_id),
            thread_id: Some(crate::messaging::types::ThreadId::new()),
            ..Default::default()
        };
        
        let (reply_id, _) = service.send_message(
            vec![recipient],
            MessageContent::Text("Thread reply".to_string()),
            channel,
            options,
        ).await.unwrap();
        
        // Verify thread relationship
        let reply = service.get_message(reply_id).await.unwrap();
        assert_eq!(reply.reply_to, Some(parent_id));
        assert!(reply.thread_id.is_some());
    }

    #[tokio::test]
    async fn test_message_queue_offline_delivery() {
        let service = create_test_service().await.unwrap();
        let channel = ChannelId::new();
        let offline_user = FourWordAddress::from("offline-user-test");
        
        // Send to offline recipient
        let (message_id, receipt) = service.send_message(
            vec![offline_user.clone()],
            MessageContent::Text("Queued for later".to_string()),
            channel,
            Default::default(),
        ).await.unwrap();
        
        // Should be queued
        assert!(matches!(
            receipt.delivery_status[0].1,
            crate::messaging::types::DeliveryStatus::Queued
        ));
        
        // Simulate user coming online
        service.mark_user_online(offline_user.clone()).await.unwrap();
        
        // Process queue
        service.process_message_queue().await.unwrap();
        
        // Check delivery status
        let status = service.get_message_status(message_id).await.unwrap();
        assert!(matches!(status, crate::messaging::types::DeliveryStatus::Delivered(_)));
    }

    #[tokio::test] 
    async fn test_bulk_message_operations() {
        let service = create_test_service().await.unwrap();
        let channel = ChannelId::new();
        let recipients = vec![
            FourWordAddress::from("user-one-two-three"),
            FourWordAddress::from("user-four-five-six"),
            FourWordAddress::from("user-seven-eight-nine"),
        ];
        
        // Send to multiple recipients
        let (message_id, receipt) = service.send_message(
            recipients.clone(),
            MessageContent::Text("Broadcast message".to_string()),
            channel,
            Default::default(),
        ).await.unwrap();
        
        // Should have delivery status for each recipient
        assert_eq!(receipt.delivery_status.len(), 3);
        
        // Each should be queued initially
        for (recipient, status) in &receipt.delivery_status {
            assert!(recipients.contains(recipient));
            assert!(matches!(status, crate::messaging::types::DeliveryStatus::Queued));
        }
    }
}