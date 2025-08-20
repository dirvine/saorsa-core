#[cfg(test)]
mod tests {
    use super::super::content_addressing::*;

    #[test]
    fn test_content_hash_creation() {
        let data = b"Hello, DHT!";
        let hash = ContentAddress::new(data);

        // Verify hash is deterministic
        let hash2 = ContentAddress::new(data);
        assert_eq!(hash, hash2);

        // Verify different data produces different hash
        let different_data = b"Different data";
        let different_hash = ContentAddress::new(different_data);
        assert_ne!(hash, different_hash);
    }

    #[test]
    fn test_content_verification() {
        let data = b"Test data for verification";
        let hash = ContentAddress::new(data);

        assert!(hash.verify(data));
        assert!(!hash.verify(b"Wrong data"));
    }

    #[test]
    fn test_content_store_and_retrieve() {
        let mut store = ContentStore::new();
        let data = b"Store this data";
        let hash = ContentAddress::new(data);

        // Store data
        store.store(hash.clone(), data.to_vec());

        // Retrieve data
        let retrieved = store.retrieve(&hash);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), data);

        // Try to retrieve non-existent data
        let non_existent = ContentAddress::new(b"not stored");
        assert!(store.retrieve(&non_existent).is_none());
    }

    #[test]
    fn test_content_deduplication() {
        let mut store = ContentStore::new();
        let data = b"Duplicate data";
        let hash = ContentAddress::new(data);

        // Store same data multiple times
        store.store(hash.clone(), data.to_vec());
        store.store(hash.clone(), data.to_vec());

        // Should only store once (deduplication)
        assert_eq!(store.size(), 1);
    }

    // #[test]
    // fn test_content_metadata() {
    //     // Commented out - types need to be defined
    // }

    // #[test]
    // fn test_content_serialization() {
    //     // Commented out - types need to be defined
    // }

    #[test]
    fn test_large_content_handling() {
        let large_data = vec![0u8; 1_000_000]; // 1MB
        let hash = ContentAddress::new(&large_data);

        let mut store = ContentStore::new();
        store.store(hash.clone(), large_data.clone());

        let retrieved = store.retrieve(&hash).unwrap();
        assert_eq!(retrieved.len(), 1_000_000);
    }

    // #[test]
    // fn test_content_type_variants() {
    //     // Commented out - types need to be defined
    // }
}
