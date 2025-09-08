// Copyright 2024 Saorsa Labs Limited
//
// Mock DHT implementation for testing

use crate::dht::PutPolicy;
use crate::fwid::Key;
use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Mock DHT storage for testing
pub struct MockDht {
    storage: Arc<RwLock<HashMap<Key, Bytes>>>,
}

impl MockDht {
    /// Create a new mock DHT
    pub fn new() -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Store data in mock DHT
    pub async fn put(&self, key: Key, data: Bytes, _policy: &PutPolicy) -> Result<()> {
        let mut storage = self.storage.write().await;
        storage.insert(key, data);
        Ok(())
    }

    /// Retrieve data from mock DHT
    pub async fn get(&self, key: Key, _quorum: u8) -> Result<Bytes> {
        let storage = self.storage.read().await;
        storage
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Key not found in mock DHT"))
    }

    /// Check if key exists
    pub async fn exists(&self, key: Key) -> bool {
        let storage = self.storage.read().await;
        storage.contains_key(&key)
    }

    /// Clear all data (for test cleanup)
    pub async fn clear(&self) {
        let mut storage = self.storage.write().await;
        storage.clear();
    }

    /// Get storage size (for testing)
    pub async fn size(&self) -> usize {
        let storage = self.storage.read().await;
        storage.len()
    }
}

impl Default for MockDht {
    fn default() -> Self {
        Self::new()
    }
}

use once_cell::sync::Lazy;

/// Global mock DHT instance for testing
static MOCK_DHT_INSTANCE: Lazy<Arc<MockDht>> = Lazy::new(|| Arc::new(MockDht::new()));

/// Get or create the global mock DHT instance
pub fn get_mock_dht() -> Arc<MockDht> {
    MOCK_DHT_INSTANCE.clone()
}

// Stub types for packet structures
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IdentityPacketV1 {
    pub id: Key,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroupPacketV1 {
    pub group_id: Vec<u8>,
    pub members: Vec<Key>,
    pub signature: Vec<u8>,
}

/// Mock DHT operations that replace real DHT calls in tests
pub mod mock_ops {
    use super::*;
    use crate::mls::GroupIdentityPacketV1;

    /// Mock dht_put for testing
    pub async fn dht_put(key: Key, value: Bytes, policy: &PutPolicy) -> Result<()> {
        let dht = get_mock_dht();
        dht.put(key, value, policy).await
    }

    /// Mock dht_get for testing  
    pub async fn dht_get(key: Key, quorum: u8) -> Result<Bytes> {
        let dht = get_mock_dht();
        dht.get(key, quorum).await
    }

    /// Mock container_manifest_put for testing
    pub async fn container_manifest_put(
        manifest: &crate::virtual_disk::ContainerManifestV1,
        policy: &PutPolicy,
    ) -> Result<()> {
        let key = crate::fwid::compute_key("container", manifest.object.as_bytes());
        let bytes = serde_cbor::to_vec(manifest)?;
        dht_put(key, Bytes::from(bytes), policy).await
    }

    /// Mock container_manifest_fetch for testing
    pub async fn container_manifest_fetch(
        object: &[u8],
    ) -> Result<crate::virtual_disk::ContainerManifestV1> {
        let key = crate::fwid::compute_key("container", object);
        let bytes = dht_get(key, 1).await?;
        Ok(serde_cbor::from_slice(&bytes)?)
    }

    /// Mock identity_publish for testing
    pub async fn identity_publish(packet: super::IdentityPacketV1) -> Result<()> {
        let key = crate::fwid::compute_key("identity", packet.id.as_bytes());
        let bytes = serde_cbor::to_vec(&packet)?;
        let policy = PutPolicy {
            quorum: 3,
            ttl: None,
        };
        dht_put(key, Bytes::from(bytes), &policy).await
    }

    /// Mock identity_fetch for testing
    pub async fn identity_fetch(id_key: Key) -> Result<super::IdentityPacketV1> {
        let key = crate::fwid::compute_key("identity", id_key.as_bytes());
        let bytes = dht_get(key, 1).await?;
        Ok(serde_cbor::from_slice(&bytes)?)
    }

    /// Mock group_identity_publish for testing
    pub async fn group_identity_publish(packet: GroupIdentityPacketV1) -> Result<()> {
        let key = crate::fwid::compute_key("group-identity", packet.id.as_bytes());
        let bytes = serde_cbor::to_vec(&packet)?;
        let policy = PutPolicy {
            quorum: 3,
            ttl: None,
        };
        dht_put(key, Bytes::from(bytes), &policy).await
    }

    /// Mock group_identity_fetch for testing
    pub async fn group_identity_fetch(id_key: Key) -> Result<GroupIdentityPacketV1> {
        let key = crate::fwid::compute_key("group-identity", id_key.as_bytes());
        let bytes = dht_get(key, 1).await?;
        Ok(serde_cbor::from_slice(&bytes)?)
    }

    /// Mock group_put for testing
    pub async fn group_put(packet: &super::GroupPacketV1, policy: &PutPolicy) -> Result<()> {
        let key = crate::fwid::compute_key("group", &packet.group_id);
        let bytes = serde_cbor::to_vec(packet)?;
        dht_put(key, Bytes::from(bytes), policy).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_dht_basic_operations() {
        let dht = MockDht::new();

        // Test put and get
        let key = Key::from([1u8; 32]);
        let data = Bytes::from("test data");
        let policy = PutPolicy {
            quorum: 1,
            ttl: None,
        };

        dht.put(key.clone(), data.clone(), &policy).await.unwrap();

        let retrieved = dht.get(key.clone(), 1).await.unwrap();
        assert_eq!(data, retrieved);

        // Test exists
        assert!(dht.exists(key).await);

        // Test non-existent key
        let missing_key = Key::from([2u8; 32]);
        assert!(!dht.exists(missing_key.clone()).await);
        assert!(dht.get(missing_key, 1).await.is_err());
    }

    #[tokio::test]
    async fn test_mock_dht_clear() {
        let dht = MockDht::new();

        // Add some data
        for i in 0..5 {
            let key = Key::from([i; 32]);
            let data = Bytes::from(vec![i; 100]);
            let policy = PutPolicy {
                quorum: 1,
                ttl: None,
            };
            dht.put(key, data, &policy).await.unwrap();
        }

        assert_eq!(dht.size().await, 5);

        // Clear and verify
        dht.clear().await;
        assert_eq!(dht.size().await, 0);
    }
}
