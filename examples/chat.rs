// Copyright 2024 Saorsa Labs Limited
//
#![allow(clippy::unwrap_used, clippy::expect_used)]
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

use anyhow::Result;
use clap::Parser;
use saorsa_core::Multiaddr;
use saorsa_core::network::{NodeConfig, P2PNode};
use std::str::FromStr;
use tokio::io::{self, AsyncBufReadExt};
use tracing::{info, warn};

/// A simple P2P chat application using three-word addresses
#[derive(Parser, Debug)]
#[command(name = "p2p-chat")]
#[command(about = "P2P chat with three-word address support")]
struct Args {
    /// The port to listen on
    #[arg(short, long, default_value = "0")]
    port: u16,

    /// A peer to bootstrap from (multiaddr format)
    #[arg(long)]
    bootstrap: Vec<String>,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = if args.debug {
        "debug,ant_quic=info"
    } else {
        "info"
    };

    tracing_subscriber::fmt().with_env_filter(filter).init();

    info!("P2P Foundation Chat");
    info!("======================");

    // Create node configuration
    let config = NodeConfig {
        listen_addr: format!("127.0.0.1:{}", args.port)
            .parse()
            .expect("valid listen address"),
        ..Default::default()
    };

    // Create and start the node
    let node = P2PNode::new(config).await?;
    node.start().await?;

    // Handle bootstrap peers
    let mut bootstrap_addrs: Vec<Multiaddr> = Vec::new();

    // Add traditional multiaddrs
    for addr_str in &args.bootstrap {
        match Multiaddr::from_str(addr_str) {
            Ok(addr) => bootstrap_addrs.push(addr),
            Err(e) => warn!("Invalid multiaddr '{}': {}", addr_str, e),
        }
    }

    // Connect to bootstrap peers
    for addr in &bootstrap_addrs {
        match node.connect_peer(&addr.to_string()).await {
            Ok(peer_id) => info!("Connected to bootstrap: {}", peer_id),
            Err(e) => warn!("Failed to connect to {}: {}", addr, e),
        }
    }

    // Get our listening address
    let listen_addrs = node.listen_addrs().await;
    info!("Listening on: {:?}", listen_addrs);

    info!("");
    info!("Type messages to send to all connected peers");
    info!("Commands: /peers, /status, /quit");
    info!("");

    // Start reading from stdin
    let stdin = io::stdin();
    let mut reader = io::BufReader::new(stdin).lines();

    while let Some(line) = reader.next_line().await? {
        match line.trim() {
            "/quit" => {
                info!("Goodbye!");
                break;
            }
            "/peers" => {
                let peers = node.connected_peers().await;
                info!("Connected peers: {}", peers.len());
                for peer in peers {
                    info!("   - {}", peer);
                }
            }
            "/status" => {
                info!("Network Status: Active");
            }
            msg if !msg.is_empty() => {
                // In a real chat app, we'd publish to a topic or send to specific peers
                // For now, just echo locally
                info!("[You]: {}", msg);

                // Here you would normally do something like:
                // node.publish("chat", msg.as_bytes()).await?;
            }
            _ => {}
        }
    }

    Ok(())
}
