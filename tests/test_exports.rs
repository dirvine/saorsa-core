// Test that the address_book exports are accessible
use saorsa_core::{
    FourWordAddress, get_user_by_four_words, get_user_four_words, register_user_address,
};

#[tokio::test]
async fn test_exports_are_accessible() {
    // Just verify the functions and types are accessible
    // This test doesn't need to actually run the functions

    // Type check - ensure FourWordAddress is accessible
    let _addr: Option<FourWordAddress> = None;

    // These are just compile-time checks to ensure the functions exist
    // We're not actually calling them, just verifying they're exported

    // Test that we can reference the functions (compile-time check)
    let _fn1 = get_user_four_words;
    let _fn2 = get_user_by_four_words;
    let _fn3 = register_user_address;

    println!("All exports are accessible!");
}
