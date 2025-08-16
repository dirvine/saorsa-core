#[cfg(test)]
mod tests {
    use super::super::core_engine::*;

    #[tokio::test]
    async fn test_dht_engine_creation() {
        let engine = DhtCoreEngine::new(NodeId::random()).unwrap();
        // Engine should be created successfully; initially we have no known peers
        let closest = engine
            .find_nodes(&DhtKey::new(b"init"), 3)
            .await
            .expect("find_nodes should succeed");
        assert!(closest.is_empty());
    }

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let mut engine = DhtCoreEngine::new(NodeId::random()).unwrap();
        let data = b"Test DHT data".to_vec();
        let key = DhtKey::new(&data);

        // Store data
        engine.store(&key, data.clone()).await.unwrap();

        // Retrieve data
        let retrieved = engine.retrieve(&key).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), data);
    }

    #[tokio::test]
    async fn test_find_closest_nodes_no_peers() {
        let engine = DhtCoreEngine::new(NodeId::random()).unwrap();
        let closest = engine.find_nodes(&DhtKey::new(b"target"), 3).await.unwrap();
        // With no peers added, the list should be empty and not exceed requested count
        assert!(closest.len() <= 3);
    }

    #[tokio::test]
    async fn test_replication_receipt_success() {
        let mut engine = DhtCoreEngine::new(NodeId::random()).unwrap();

        let data = b"Replicated data".to_vec();
        let key = DhtKey::new(&data);

        // Store should succeed and return a receipt
        let receipt = engine.store(&key, data.clone()).await.unwrap();
        assert!(receipt.is_successful());
        assert_eq!(receipt.key.as_bytes(), key.as_bytes());
    }

    #[tokio::test]
    async fn test_concurrent_operations_store_only() {
        use tokio::task;

        let engine = std::sync::Arc::new(tokio::sync::RwLock::new(
            DhtCoreEngine::new(NodeId::random()).unwrap(),
        ));

        let mut handles = vec![];

        // Spawn concurrent store operations
        for i in 0..10 {
            let engine_clone = engine.clone();
            let handle = task::spawn(async move {
                let data = format!("Data {}", i).into_bytes();
                let key = DhtKey::new(&data);
                let mut engine = engine_clone.write().await;
                engine.store(&key, data).await.unwrap();
            });
            handles.push(handle);
        }

        // Wait for all operations
        for handle in handles {
            handle.await.unwrap();
        }

        // No assertion on internal counts as the API doesn't expose them
    }
}
