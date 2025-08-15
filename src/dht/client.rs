// DHT Client wrapper for messaging integration
// Provides a clean interface between messaging and the DHT core engine

use crate::dht::core_engine::{DhtCoreEngine, DhtKey, NodeId, NodeInfo, StoreReceipt};
use anyhow::{Result, Context};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// DHT Client for messaging system
/// 
/// This wraps the core DHT engine and provides a simple interface
/// for storing and retrieving messages and other data.
#[derive(Clone)]
pub struct DhtClient {
    /// The underlying DHT engine
    engine: Arc<RwLock<DhtCoreEngine>>,
    
    /// Local node ID
    node_id: NodeId,
}

impl DhtClient {
    /// Create a new DHT client with a random node ID
    pub fn new() -> Result<Self> {
        let node_id = NodeId::random();
        let engine = DhtCoreEngine::new(node_id.clone())?;
        
        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
            node_id,
        })
    }
    
    /// Create a DHT client with a specific node ID (derived from four-word address)
    pub fn with_node_id(node_id: NodeId) -> Result<Self> {
        let engine = DhtCoreEngine::new(node_id.clone())?;
        
        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
            node_id,
        })
    }
    
    /// Get the core DHT engine for advanced operations
    pub fn core_engine(&self) -> Arc<RwLock<DhtCoreEngine>> {
        Arc::clone(&self.engine)
    }
    
    /// Store data in the DHT
    pub async fn put(&self, key: String, value: Vec<u8>) -> Result<StoreReceipt> {
        // Convert string key to DhtKey
        let dht_key = DhtKey::new(key.as_bytes());
        
        // Store in DHT
        let mut engine = self.engine.write().await;
        let receipt = engine.store(&dht_key, value).await
            .context("Failed to store data in DHT")?;
        
        Ok(receipt)
    }
    
    /// Retrieve data from the DHT
    pub async fn get(&self, key: String) -> Result<Option<Vec<u8>>> {
        // Convert string key to DhtKey
        let dht_key = DhtKey::new(key.as_bytes());
        
        // Retrieve from DHT
        let engine = self.engine.read().await;
        let value = engine.retrieve(&dht_key).await
            .context("Failed to retrieve data from DHT")?;
        
        Ok(value)
    }
    
    /// Store a serializable object in the DHT
    pub async fn put_object<T: Serialize>(&self, key: String, object: &T) -> Result<StoreReceipt> {
        let value = serde_json::to_vec(object)
            .context("Failed to serialize object")?;
        self.put(key, value).await
    }
    
    /// Retrieve and deserialize an object from the DHT
    pub async fn get_object<T: for<'de> Deserialize<'de>>(&self, key: String) -> Result<Option<T>> {
        match self.get(key).await? {
            Some(value) => {
                let object = serde_json::from_slice(&value)
                    .context("Failed to deserialize object")?;
                Ok(Some(object))
            }
            None => Ok(None),
        }
    }
    
    /// Join the DHT network with bootstrap nodes
    pub async fn join_network(&self, bootstrap_nodes: Vec<NodeInfo>) -> Result<()> {
        let mut engine = self.engine.write().await;
        engine.join_network(bootstrap_nodes).await
            .context("Failed to join DHT network")?;
        Ok(())
    }
    
    /// Leave the DHT network gracefully
    pub async fn leave_network(&self) -> Result<()> {
        let mut engine = self.engine.write().await;
        engine.leave_network().await
            .context("Failed to leave DHT network")?;
        Ok(())
    }
    
    /// Find nodes closest to a key
    pub async fn find_nodes(&self, key: String, count: usize) -> Result<Vec<NodeInfo>> {
        let dht_key = DhtKey::new(key.as_bytes());
        let engine = self.engine.read().await;
        engine.find_nodes(&dht_key, count).await
            .context("Failed to find nodes")
    }
    
    /// Get the local node ID
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }
    
    /// Check if data exists in the DHT
    pub async fn exists(&self, key: String) -> Result<bool> {
        let result = self.get(key).await?;
        Ok(result.is_some())
    }
    
    /// Delete data from the DHT (soft delete by storing empty value)
    pub async fn delete(&self, key: String) -> Result<StoreReceipt> {
        self.put(key, Vec::new()).await
    }
}

/// Create a mock DHT client for testing
/// This is a temporary function to maintain compatibility during migration
impl DhtClient {
    pub fn new_mock() -> Self {
        // Create a mock client with a random node ID
        // This uses the real DHT engine but in single-node mode
        Self::new().expect("Failed to create mock DHT client")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_dht_client_store_retrieve() -> Result<()> {
        let client = DhtClient::new()?;
        
        // Store data
        let key = "test-key".to_string();
        let value = b"test-value".to_vec();
        
        let receipt = client.put(key.clone(), value.clone()).await?;
        assert!(receipt.is_successful());
        
        // Retrieve data
        let retrieved = client.get(key).await?;
        assert_eq!(retrieved, Some(value));
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_dht_client_object_storage() -> Result<()> {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct TestObject {
            id: u32,
            name: String,
        }
        
        let client = DhtClient::new()?;
        
        let obj = TestObject {
            id: 42,
            name: "Test".to_string(),
        };
        
        // Store object
        let key = "test-object".to_string();
        client.put_object(key.clone(), &obj).await?;
        
        // Retrieve object
        let retrieved: Option<TestObject> = client.get_object(key).await?;
        assert_eq!(retrieved, Some(obj));
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_dht_client_exists() -> Result<()> {
        let client = DhtClient::new()?;
        
        let key = "exists-test".to_string();
        
        // Check non-existent key
        assert!(!client.exists(key.clone()).await?);
        
        // Store data
        client.put(key.clone(), b"data".to_vec()).await?;
        
        // Check existing key
        assert!(client.exists(key).await?);
        
        Ok(())
    }
}