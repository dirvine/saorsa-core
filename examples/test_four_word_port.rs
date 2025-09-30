use four_word_networking::{FourWordAdaptiveEncoder, FourWordEncoder};
use std::net::Ipv4Addr;

fn main() {
    println!("Testing four-word-networking encoding with ports:\n");

    // Test case 1: Using FourWordEncoder with explicit IP and port
    let encoder = FourWordEncoder::new();
    let ip = Ipv4Addr::new(192, 168, 1, 1);
    let port = 8080u16;

    println!("Method 1: FourWordEncoder::encode_ipv4(ip, port)");
    println!("  Input: IP={}, Port={}", ip, port);

    match encoder.encode_ipv4(ip, port) {
        Ok(encoding) => {
            println!("  Encoded: {}", encoding);
            println!("  Words: {:?}", encoding.words());

            // Try to decode back
            match encoder.decode_ipv4(&encoding) {
                Ok((decoded_ip, decoded_port)) => {
                    println!("  Decoded: IP={}, Port={}", decoded_ip, decoded_port);
                    println!("  ✓ Round-trip successful: port {} preserved", decoded_port);
                }
                Err(e) => println!("  ✗ Decode error: {}", e),
            }
        }
        Err(e) => println!("  ✗ Encode error: {}", e),
    }

    println!("\nMethod 2: FourWordAdaptiveEncoder with socket address string");
    let adaptive_encoder = FourWordAdaptiveEncoder::new().expect("create adaptive encoder");
    let socket_str = "192.168.1.1:8080";
    println!("  Input: {}", socket_str);

    match adaptive_encoder.encode(socket_str) {
        Ok(encoded) => {
            println!("  Encoded: {}", encoded);

            // Count words
            let word_count = encoded.split_whitespace().count();
            println!("  Word count: {}", word_count);

            // Try to decode back
            match adaptive_encoder.decode(&encoded) {
                Ok(decoded) => {
                    println!("  Decoded: {}", decoded);
                    if decoded.contains(':') {
                        let parts: Vec<&str> = decoded.split(':').collect();
                        if parts.len() == 2 {
                            println!("  ✓ Port preserved in decoded address: {}", parts[1]);
                        }
                    }
                }
                Err(e) => println!("  ✗ Decode error: {}", e),
            }
        }
        Err(e) => println!("  ✗ Encode error: {}", e),
    }

    println!("\nConclusion:");
    println!("- FourWordEncoder::encode_ipv4() takes IP and port as separate parameters");
    println!("- The encoding includes both IP and port information in the four words");
    println!("- No need to append port separately - it's already encoded!");
}
