use four_word_networking::FourWordEncoder;

fn main() {
    let encoder = FourWordEncoder::new();

    // Try to encode some IP addresses to get valid words
    let test_ips = vec![
        (std::net::Ipv4Addr::new(192, 168, 1, 1), 8080),
        (std::net::Ipv4Addr::new(10, 0, 0, 1), 3000),
        (std::net::Ipv4Addr::new(127, 0, 0, 1), 9000),
        (std::net::Ipv4Addr::new(172, 16, 0, 1), 5000),
        (std::net::Ipv4Addr::new(192, 168, 0, 1), 8080),
        (std::net::Ipv4Addr::new(10, 10, 10, 10), 3000),
        (std::net::Ipv4Addr::new(172, 31, 255, 255), 9999),
        (std::net::Ipv4Addr::new(192, 168, 100, 200), 7777),
        (std::net::Ipv4Addr::new(8, 8, 8, 8), 53),
        (std::net::Ipv4Addr::new(1, 1, 1, 1), 443),
        (std::net::Ipv4Addr::new(192, 168, 2, 1), 8080),
        (std::net::Ipv4Addr::new(10, 0, 1, 1), 3000),
        (std::net::Ipv4Addr::new(172, 16, 1, 1), 5000),
        (std::net::Ipv4Addr::new(192, 168, 3, 1), 8080),
        (std::net::Ipv4Addr::new(10, 0, 2, 1), 3000),
        (std::net::Ipv4Addr::new(172, 16, 2, 1), 5000),
        (std::net::Ipv4Addr::new(192, 168, 4, 1), 8080),
    ];

    for (ip, port) in test_ips {
        match encoder.encode_ipv4(ip, port) {
            Ok(encoding) => {
                println!("Valid words for IP {}:{}", ip, port);
                // Use Display trait to get the words
                let words_str = format!("{}", encoding);
                println!("  Words string: {}", words_str);

                // Parse back to get individual words
                let words: Vec<&str> = words_str.split(' ').collect();
                if words.len() == 4 {
                    println!(
                        "  Words array: [\"{}\", \"{}\", \"{}\", \"{}\"]",
                        words[0], words[1], words[2], words[3]
                    );
                }

                // Test decoding back
                let result = encoder.decode_ipv4(&encoding);
                if result.is_ok() {
                    println!("  ✓ Successfully decoded back!");
                }
            }
            Err(e) => {
                println!("Error encoding {}:{} - {:?}", ip, port, e);
            }
        }
    }
}
