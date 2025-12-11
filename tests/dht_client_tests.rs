// Copyright 2024 Saorsa Labs Limited
//
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Verify that the public API uses a configured global DHT client instead of the
// in-memory mock.

use anyhow::Result;
use saorsa_core::dht::client::DhtClient;
use saorsa_core::{
    clear_dht_client, identity_fetch, register_identity, set_dht_client, types::MlDsaKeyPair,
};
use std::net::Ipv4Addr;

fn valid_four_words(seed: u16) -> [String; 4] {
    use four_word_networking::FourWordEncoder;
    let encoder = FourWordEncoder::new();
    let ip = Ipv4Addr::new(
        10,
        (seed >> 8) as u8,
        (seed & 0xFF) as u8,
        (seed % 200) as u8,
    );
    let port = 20000 + seed;
    let encoding = encoder
        .encode_ipv4(ip, port)
        .unwrap_or_else(|_| panic!("encode seed {seed}"));
    let words = encoding.words();
    [
        words[0].clone(),
        words[1].clone(),
        words[2].clone(),
        words[3].clone(),
    ]
}

fn words_refs(words: &[String; 4]) -> [&str; 4] {
    [
        words[0].as_str(),
        words[1].as_str(),
        words[2].as_str(),
        words[3].as_str(),
    ]
}

#[tokio::test]
async fn test_global_dht_client_usage() -> Result<()> {
    clear_dht_client().await;
    let client = DhtClient::new()?;
    set_dht_client(client.clone()).await;

    let words = valid_four_words(700);
    let keypair = MlDsaKeyPair::generate()?;
    let handle = register_identity(words_refs(&words), &keypair).await?;

    // Identity should be available while the client is installed.
    let identity = identity_fetch(handle.key()).await?;
    assert_eq!(identity.id, handle.key());

    // Removing the client should prevent lookups (data lives only in the client).
    clear_dht_client().await;
    let err = identity_fetch(handle.key()).await.unwrap_err();
    assert!(
        err.to_string().contains("Identity not found"),
        "unexpected error: {err}"
    );

    // Reinstalling the same client restores access.
    set_dht_client(client.clone()).await;
    let identity = identity_fetch(handle.key()).await?;
    assert_eq!(identity.id, handle.key());

    clear_dht_client().await;
    Ok(())
}
