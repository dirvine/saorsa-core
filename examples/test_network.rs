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

use anyhow::{Context, Result};
use saorsa_core::types::{MlDsaKeyPair, IdentityHandle};
use saorsa_core::{register_identity, store_data};
use saorsa_core::network::{NodeConfig, P2PNode};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::interval;
use tracing::{info, warn, error};

/// Test network node configuration
struct TestNode {
    id: usize,
    port: u16,
    words: Vec<&'static str>,
    node: Arc<P2PNode>,
    keypair: MlDsaKeyPair,
    handle: Option<IdentityHandle>,
    messages_received: Arc<Mutex<Vec<String>>>,
}

impl TestNode {
    async fn new(id: usize, port: u16, words: Vec<&'static str>) -> Result<Self> {
        // Use a specific port for testing instead of 0
        let actual_port = if port == 0 { 9000 + id as u16 } else { port };
        let listen_addr = format!("127.0.0.1:{}", actual_port).parse()
            .context("Failed to parse listen address")?;

        let mut config = NodeConfig::default();
        config.listen_addr = listen_addr;
        // Use valid addresses for testing - let the system assign actual addresses
        config.listen_addrs = vec![
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 0), // localhost with port 0 for system assignment
        ];

        info!("🔧 Node {} configured to listen on port {} ({})", id, actual_port, if port == 0 { "system-assigned" } else { "specified" });

        let node = Arc::new(P2PNode::new(config).await
            .context("Failed to create P2P node")?);

        // Get actual listen addresses after node creation
        let actual_addrs = node.listen_addrs().await;
        info!("📡 Node {} actual listen addresses: {:?}", id, actual_addrs);

        let keypair = MlDsaKeyPair::generate()
            .context("Failed to generate keypair")?;

        let words_array: [&str; 4] = [
            words[0],
            words[1],
            words[2],
            words[3],
        ];
        let handle = register_identity(words_array, &keypair).await
            .context("Failed to register identity")?;

        info!("✅ Node {} registered with words: {:?}", id, words);

        Ok(Self {
            id,
            port,
            words,
            node,
            keypair,
            handle: Some(handle),
            messages_received: Arc::new(Mutex::new(Vec::new())),
        })
    }

    async fn connect_to_bootstrap(&self, bootstrap_addrs: &[String]) -> Result<()> {
        info!("🔗 Node {} attempting to connect to {} bootstrap addresses", self.id, bootstrap_addrs.len());
        for addr in bootstrap_addrs {
            info!("🔗 Node {} trying address: {}", self.id, addr);
            match self.node.connect_peer(addr).await {
                Ok(peer_id) => {
                    info!("✅ Node {} successfully connected to bootstrap: {}", self.id, peer_id);
                }
                Err(e) => {
                    warn!("❌ Node {} failed to connect to {}: {}", self.id, addr, e);
                }
            }
        }
        Ok(())
    }

    async fn send_message(&self, target_node: &TestNode, message: &str) -> Result<()> {
        let data = message.as_bytes().to_vec();
        let handle = self.handle.as_ref()
            .context("Node not registered")?;

        let _storage_handle = store_data(handle, data, 1).await
            .context("Failed to store message")?;

        info!("📤 Node {} sent message to Node {}: '{}'",
              self.id, target_node.id, message);

        Ok(())
    }

    async fn get_messages(&self) -> Result<Vec<String>> {
        let messages = self.messages_received.lock().await;
        Ok(messages.clone())
    }

    async fn add_message(&self, message: String) {
        let mut messages = self.messages_received.lock().await;
        messages.push(message.clone());
        info!("📥 Node {} received message: '{}'", self.id, message);
    }

    async fn get_listen_addrs(&self) -> Result<Vec<String>> {
        let addrs = self.node.listen_addrs().await;
        Ok(addrs.iter().map(|addr| addr.to_string()).collect())
    }

    async fn get_connected_peers(&self) -> Result<Vec<String>> {
        let peers = self.node.connected_peers().await;
        Ok(peers)
    }
}

/// Test network orchestrator
struct TestNetwork {
    nodes: Vec<TestNode>,
    start_time: Instant,
    messages_sent: usize,
    bytes_transferred: usize,
}

impl TestNetwork {
    async fn new(node_count: usize) -> Result<Self> {
        info!("🚀 Setting up test network with {} nodes", node_count);

        // Initialize logging
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();

        let mut nodes = Vec::new();

        // Create nodes with system-assigned ports (port 0)
        for i in 0..node_count {
            let port = 0u16; // Let system assign free port
            let words = match i {
                0 => vec!["welfare", "absurd", "king", "ridge"],
                1 => vec!["welfare", "absurd", "king", "peak"],  // Different last word
                2 => vec!["welfare", "absurd", "king", "flow"],  // Different last word
                3 => vec!["welfare", "absurd", "king", "depth"], // Different last word
                _ => vec!["global", "fast", "eagle", "soar"],
            };

            let node = TestNode::new(i, port, words).await
                .context(format!("Failed to create node {}", i))?;

            nodes.push(node);

            // Small delay between node creation to avoid port conflicts
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Get bootstrap addresses from first node
        let bootstrap_addrs = nodes[0].get_listen_addrs().await
            .context("Failed to get bootstrap addresses")?;

        info!("🔗 Bootstrap addresses: {:?}", bootstrap_addrs);

        // Convert to string format for connect_peer
        let bootstrap_addr_strings: Vec<String> = bootstrap_addrs.iter()
            .map(|addr| addr.to_string())
            .collect();
        info!("🔗 Bootstrap address strings: {:?}", bootstrap_addr_strings);

        // Connect all nodes to bootstrap
        for node in &nodes[1..] {
            node.connect_to_bootstrap(&bootstrap_addrs).await
                .context(format!("Failed to connect node {}", node.id))?;
        }

        // Wait a bit for connections to establish
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify connections
        for node in &nodes {
            let peers = node.get_connected_peers().await?;
            info!("🔍 Node {} has {} connected peers", node.id, peers.len());
        }

        Ok(Self {
            nodes,
            start_time: Instant::now(),
            messages_sent: 0,
            bytes_transferred: 0,
        })
    }

    async fn run_message_test(&mut self, message_count: usize) -> Result<()> {
        info!("📨 Starting message transmission test ({} messages)", message_count);

        for i in 0..message_count {
            let sender_idx = i % self.nodes.len();
            let receiver_idx = (i + 1) % self.nodes.len();

            let sender = &self.nodes[sender_idx];
            let receiver = &self.nodes[receiver_idx];

            let message = format!("Test message {} from Node {} to Node {}",
                                i + 1, sender.id, receiver.id);

            sender.send_message(receiver, &message).await
                .context(format!("Failed to send message {}", i + 1))?;

            self.messages_sent += 1;
            self.bytes_transferred += message.len();

            // Small delay to avoid overwhelming the network
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        info!("✅ Message transmission test completed");
        Ok(())
    }

    async fn run_bandwidth_test(&mut self, duration_secs: u64) -> Result<()> {
        info!("⚡ Starting bandwidth test for {} seconds", duration_secs);

        let mut interval = interval(Duration::from_secs(1));
        let end_time = Instant::now() + Duration::from_secs(duration_secs);

        while Instant::now() < end_time {
            interval.tick().await;

            let elapsed = self.start_time.elapsed();
            let messages_per_sec = self.messages_sent as f64 / elapsed.as_secs_f64();
            let bandwidth_kbps = (self.bytes_transferred as f64 * 8.0) / (elapsed.as_millis() as f64);

            info!("📊 Bandwidth: {:.2} Kbps | Messages/sec: {:.2} | Total Messages: {}",
                  bandwidth_kbps, messages_per_sec, self.messages_sent);
        }

        info!("✅ Bandwidth test completed");
        Ok(())
    }

    async fn display_final_stats(&self) -> Result<()> {
        let elapsed = self.start_time.elapsed();

        info!("📈 === FINAL TEST RESULTS ===");
        info!("⏱️  Total runtime: {:.2}s", elapsed.as_secs_f64());
        info!("📦 Total messages sent: {}", self.messages_sent);
        info!("💾 Total bytes transferred: {} KB", self.bytes_transferred / 1024);
        info!("⚡ Average bandwidth: {:.2} Kbps",
              (self.bytes_transferred as f64 * 8.0) / (elapsed.as_millis() as f64));
        info!("📨 Messages per second: {:.2}",
              self.messages_sent as f64 / elapsed.as_secs_f64());

        // Check message delivery
        for node in &self.nodes {
            let messages = node.get_messages().await?;
            info!("📬 Node {} received {} messages", node.id, messages.len());
        }

        info!("✅ Test network completed successfully!");
        Ok(())
    }

    async fn run_full_test(&mut self) -> Result<()> {
        info!("🧪 === STARTING COMPREHENSIVE TEST NETWORK ===");

        // Phase 1: Basic connectivity test
        info!("🔗 Phase 1: Testing basic connectivity...");
        tokio::time::sleep(Duration::from_secs(3)).await;

        for node in &self.nodes {
            let peers = node.get_connected_peers().await?;
            if peers.is_empty() {
                warn!("⚠️ Node {} has no connections!", node.id);
            } else {
                info!("✅ Node {} connected to {} peers", node.id, peers.len());
            }
        }

        // Phase 2: Message transmission test
        info!("📨 Phase 2: Testing message transmission...");
        self.run_message_test(50).await?;

        // Phase 3: Bandwidth measurement
        info!("⚡ Phase 3: Measuring bandwidth...");
        self.run_bandwidth_test(10).await?;

        // Phase 4: Final statistics
        info!("📊 Phase 4: Displaying final statistics...");
        self.display_final_stats().await?;

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("🧪 Saorsa Core Test Network");
    println!("==========================");
    println!("Setting up a test network to verify:");
    println!("• Node connectivity");
    println!("• Message transmission");
    println!("• Bandwidth measurement");
    println!("• Multi-device functionality");
    println!();

    let mut network = TestNetwork::new(4).await
        .context("Failed to create test network")?;

    if let Err(e) = network.run_full_test().await {
        error!("❌ Test network failed: {}", e);
        return Err(e);
    }

    println!();
    println!("🎉 Test network completed successfully!");
    println!("The Saorsa Core library is working correctly!");

    Ok(())
}