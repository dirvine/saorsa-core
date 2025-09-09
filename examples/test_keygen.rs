use saorsa_core::types::MlDsaKeyPair;

fn main() {
    println!("Testing ML-DSA key generation...");
    match MlDsaKeyPair::generate() {
        Ok(_) => println!("Key generation successful!"),
        Err(e) => println!("Key generation failed: {:?}", e),
    }
}
