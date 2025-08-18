// Test script to explore saorsa-pqc 0.3.5 API

#[cfg(test)]
mod test {
    #[test]
    fn explore_saorsa_pqc_api() {
        // Test that core types are available
        use saorsa_pqc::*;
        
        println!("Exploring saorsa-pqc 0.3.5 API");
        
        // Test ML-KEM and ML-DSA types are available
        let _ml_kem = MlKem768::default();
        let _ml_dsa = MlDsa65::default();
        println!("✅ ML-KEM and ML-DSA types available");
        
        // Test hybrid types are available
        let _hybrid_kem = HybridKem::default();
        let _hybrid_sig = HybridSignature::default();
        let _hybrid_pke = HybridPublicKeyEncryption::default();
        println!("✅ Hybrid crypto types available");
        
        // Test symmetric encryption is available
        let _chacha = ChaCha20Poly1305Cipher::default();
        println!("✅ ChaCha20Poly1305 cipher available");
        
        // Test key generation (using Result type correctly)
        let key_result = SymmetricKey::generate();
        match key_result {
            Ok(_key) => println!("✅ SymmetricKey generation works"),
            Err(e) => println!("❌ SymmetricKey generation failed: {}", e),
        }
        
        // Test error types
        let _sym_error: Option<SymmetricError> = None;
        println!("✅ Error types available");
        
        // Test what's in the pqc::types module
        {
            use saorsa_pqc::pqc::types::*;
            println!("✅ PQC types module accessible");
            
            // Test that we can work with the types
            let _pqc_error: Option<PqcError> = None;
            println!("✅ PqcError type available");
        }
        
        println!("Exploring saorsa-pqc 0.3.5 API complete");
    }
}