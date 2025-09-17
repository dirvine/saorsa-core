// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
// Example usage of the Saorsa Core specification modules

//! Minimal example aligned with current saorsa-core API.
use anyhow::Result;
use saorsa_core::fwid::{Word, fw_check, fw_to_key};
use saorsa_core::types::{
    Device, DeviceId, Endpoint, MlDsaKeyPair, presence::DeviceType as DevType,
};
use saorsa_core::{get_data, identity_fetch, register_identity, register_presence, store_data};

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Saorsa Core Quick Start ===\n");
    quick_start_identity_presence_storage().await?;
    println!("\n=== Completed ===");
    Ok(())
}

async fn quick_start_identity_presence_storage() -> Result<()> {
    println!("--- Identity, Presence, Storage ---");

    // Identity
    let words: [Word; 4] = [
        "welfare".to_string(),
        "absurd".to_string(),
        "king".to_string(),
        "ridge".to_string(),
    ];
    assert!(fw_check(words.clone()));
    let key = fw_to_key(words.clone())?;
    let kp = MlDsaKeyPair::generate()?;
    let handle = register_identity([&words[0], &words[1], &words[2], &words[3]], &kp).await?;
    let pkt = identity_fetch(key).await?;
    println!("✓ Registered identity: {}", pkt.words.join("-"));

    // Presence (single device)
    let devices = vec![Device {
        id: DeviceId::generate(),
        device_type: DevType::Active,
        storage_gb: 128,
        endpoint: Endpoint {
            protocol: "quic".into(),
            address: "127.0.0.1:9000".into(),
        },
        capabilities: Default::default(),
    }];
    let _ = register_presence(&handle, devices.clone(), devices[0].id).await?;
    println!("✓ Presence registered with {} device(s)", devices.len());

    // Storage
    let data = b"Hello, Saorsa!".to_vec();
    let sh = store_data(&handle, data.clone(), 1).await?;
    let out = get_data(&sh).await?;
    println!("✓ Stored + fetched {} bytes", out.len());
    Ok(())
}
