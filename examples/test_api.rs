use saorsa_core::types::MlDsaKeyPair;
use saorsa_core::{get_identity, register_identity};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Testing API registration...");

    let words = ["welfare", "absurd", "king", "ridge"];
    let keypair = MlDsaKeyPair::generate()?;

    println!("Registering identity with words: {:?}", words);
    let handle = register_identity(words, &keypair).await?;
    println!("Registration successful! Key: {}", handle.key());

    println!("Fetching identity...");
    let fetched = get_identity(handle.key()).await?;
    println!("Identity fetched! Words: {:?}", fetched.words);

    Ok(())
}
