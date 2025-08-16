#[cfg(test)]
mod tests {
    use super::super::reed_solomon::ReedSolomonEncoder;
    use super::super::reed_solomon::*;

    #[test]
    fn test_reed_solomon_creation() {
        let rs = ReedSolomonEncoder::new(4, 2).unwrap();
        assert_eq!(rs.config.k, 4);
        assert_eq!(rs.config.m, 2);
        assert_eq!(rs.config.n(), 6);
    }

    #[test]
    fn test_encode_decode_small_data() {
        let rs = ReedSolomonEncoder::new(4, 2).unwrap();
        let data = b"Hello, Reed-Solomon!";

        // Encode
        let encoded = tokio_test::block_on(rs.encode(data.to_vec())).unwrap();
        assert_eq!(encoded.len(), 6); // 4 data + 2 parity

        // Decode without errors
        let chunks = encoded.into_iter().map(Some).collect();
        let decoded = tokio_test::block_on(rs.decode(chunks)).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_error_correction_single_shard() {
        let rs = ReedSolomonEncoder::new(4, 2).unwrap();
        let data = b"Test data for error correction";

        let mut encoded = tokio_test::block_on(rs.encode(data.to_vec())).unwrap();

        // Corrupt one shard
        encoded[0] = vec![0; encoded[0].len()];

        // Should still decode correctly
        let chunks = encoded.into_iter().map(Some).collect();
        let decoded = tokio_test::block_on(rs.decode(chunks)).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_error_correction_multiple_shards() {
        let rs = ReedSolomonEncoder::new(4, 2).unwrap();
        let data = b"Multiple error correction test";

        let mut encoded = tokio_test::block_on(rs.encode(data.to_vec())).unwrap();

        // Corrupt two shards (equal to parity count)
        encoded[0] = vec![0; encoded[0].len()];
        encoded[3] = vec![0; encoded[3].len()];

        // Should still decode correctly
        let chunks = encoded.into_iter().map(Some).collect();
        let decoded = tokio_test::block_on(rs.decode(chunks)).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_too_many_errors() {
        let rs = ReedSolomonEncoder::new(4, 2).unwrap();
        let data = b"Too many errors test";

        let mut encoded = tokio_test::block_on(rs.encode(data.to_vec())).unwrap();

        // Corrupt three shards (more than parity count)
        encoded[0] = vec![0; encoded[0].len()];
        encoded[1] = vec![0; encoded[1].len()];
        encoded[2] = vec![0; encoded[2].len()];

        // Should fail to decode
        let mut chunks: Vec<Option<Vec<u8>>> = encoded.into_iter().map(Some).collect();
        chunks[0] = None;
        chunks[1] = None;
        chunks[2] = None;
        assert!(tokio_test::block_on(rs.decode(chunks)).is_err());
    }

    #[test]
    fn test_large_data_encoding() {
        let rs = ReedSolomonEncoder::new(8, 4).unwrap();
        let large_data = vec![42u8; 10_000]; // 10KB

        let encoded = tokio_test::block_on(rs.encode(large_data.clone())).unwrap();
        assert_eq!(encoded.len(), 12); // 8 data + 4 parity

        let chunks = encoded.into_iter().map(Some).collect();
        let decoded = tokio_test::block_on(rs.decode(chunks)).unwrap();
        assert_eq!(decoded, large_data);
    }

    #[test]
    fn test_different_configurations() {
        let configs = vec![
            (2, 1),  // Minimal configuration
            (4, 2),  // Standard configuration
            (8, 4),  // High redundancy
            (16, 8), // Maximum redundancy
        ];

        for (data_shards, parity_shards) in configs {
            let rs = ReedSolomonEncoder::new(data_shards, parity_shards).unwrap();
            let test_data = b"Configuration test data";

            let encoded = tokio_test::block_on(rs.encode(test_data.to_vec())).unwrap();
            assert_eq!(encoded.len(), data_shards + parity_shards);

            let chunks = encoded.into_iter().map(Some).collect();
            let decoded = tokio_test::block_on(rs.decode(chunks)).unwrap();
            assert_eq!(decoded, test_data);
        }
    }

    #[test]
    fn test_shard_verification() {
        let rs = ReedSolomonEncoder::new(4, 2).unwrap();
        let data = b"Verification test";

        let encoded = tokio_test::block_on(rs.encode(data.to_vec())).unwrap();
        assert_eq!(encoded.len(), 6);
    }

    #[test]
    fn test_incremental_encoding() {
        let rs = ReedSolomonEncoder::new(4, 2).unwrap();

        // Encode data in chunks
        let chunk1 = b"First chunk";
        let chunk2 = b"Second chunk";
        let chunk3 = b"Third chunk";

        let encoded1 = tokio_test::block_on(rs.encode(chunk1.to_vec())).unwrap();
        let encoded2 = tokio_test::block_on(rs.encode(chunk2.to_vec())).unwrap();
        let encoded3 = tokio_test::block_on(rs.encode(chunk3.to_vec())).unwrap();

        // Decode each chunk
        assert_eq!(
            tokio_test::block_on(rs.decode(encoded1.into_iter().map(Some).collect())).unwrap(),
            chunk1
        );
        assert_eq!(
            tokio_test::block_on(rs.decode(encoded2.into_iter().map(Some).collect())).unwrap(),
            chunk2
        );
        assert_eq!(
            tokio_test::block_on(rs.decode(encoded3.into_iter().map(Some).collect())).unwrap(),
            chunk3
        );
    }

    #[test]
    fn test_parallel_encoding() {
        use std::sync::Arc;
        use std::thread;

        let rs = Arc::new(ReedSolomonEncoder::new(4, 2).unwrap());
        let mut handles = vec![];

        for i in 0..10 {
            let rs_clone = rs.clone();
            let handle = thread::spawn(move || {
                let data = format!("Thread {} data", i).into_bytes();
                let encoded = tokio_test::block_on(rs_clone.encode(data.clone())).unwrap();
                let decoded =
                    tokio_test::block_on(rs_clone.decode(encoded.into_iter().map(Some).collect()))
                        .unwrap();
                assert_eq!(decoded, data);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_empty_data() {
        let rs = ReedSolomonEncoder::new(4, 2).unwrap();
        let empty_data = Vec::new();

        assert!(tokio_test::block_on(rs.encode(empty_data)).is_err());
    }

    #[test]
    fn test_invalid_parameters() {
        // Zero data shards
        assert!(ReedSolomonEncoder::new(0, 2).is_err());

        // Zero parity shards
        assert!(ReedSolomonEncoder::new(4, 0).is_err());

        // Too many total shards
        assert!(ReedSolomonEncoder::new(128, 128).is_err());
    }
}
