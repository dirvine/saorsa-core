#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Live monitoring tool for the adaptive network
//! Run with: cargo run --example adaptive_network_monitor

use saorsa_core::adaptive::learning::ThompsonSampling;
use saorsa_core::adaptive::multi_armed_bandit::{MABConfig, MultiArmedBandit};
use saorsa_core::adaptive::q_learning_cache::{
    QLearnCacheManager as QLearningCache, QLearningConfig,
};
use saorsa_core::network::{NodeConfig, P2PNode as Network};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::RwLock,
    time::{interval, sleep},
};

#[derive(Default)]
struct NetworkMetrics {
    // Thompson Sampling metrics
    thompson_arms: HashMap<usize, (usize, usize)>, // arm -> (successes, attempts)

    // MAB metrics
    mab_rewards: Vec<f64>,
    mab_selections: HashMap<usize, usize>,

    // Q-Learning metrics
    cache_hits: usize,
    cache_misses: usize,

    // Network metrics
    messages_sent: usize,
    messages_received: usize,
    active_connections: usize,
    total_bandwidth: usize,

    // Churn metrics
    nodes_joined: usize,
    nodes_left: usize,
    average_session_length: Duration,

    // Security metrics
    suspicious_events: usize,
    blocked_connections: usize,
}

impl NetworkMetrics {
    fn thompson_success_rate(&self) -> f64 {
        let total: usize = self.thompson_arms.values().map(|(s, _)| *s).sum();
        let attempts: usize = self.thompson_arms.values().map(|(_, a)| *a).sum();
        if attempts > 0 {
            total as f64 / attempts as f64
        } else {
            0.0
        }
    }

    fn mab_average_reward(&self) -> f64 {
        if !self.mab_rewards.is_empty() {
            self.mab_rewards.iter().sum::<f64>() / self.mab_rewards.len() as f64
        } else {
            0.0
        }
    }

    fn cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total > 0 {
            self.cache_hits as f64 / total as f64
        } else {
            0.0
        }
    }
}

struct AdaptiveNetworkMonitor {
    network: Arc<Network>,
    metrics: Arc<RwLock<NetworkMetrics>>,
}

impl AdaptiveNetworkMonitor {
    async fn new() -> anyhow::Result<Self> {
        // Build core network
        let node_cfg = NodeConfig::default();
        let network = Arc::new(Network::new(node_cfg).await?);

        Ok(Self {
            network,
            metrics: Arc::new(RwLock::new(NetworkMetrics::default())),
        })
    }

    async fn start(&self) -> anyhow::Result<()> {
        println!("Adaptive Network Monitor Started");
        println!(
            "Listening addresses: {:?}",
            self.network.listen_addrs().await
        );
        Ok(())
    }

    async fn display_dashboard(&self) {
        loop {
            // Clear screen (ANSI escape code)
            print!("\x1B[2J\x1B[1;1H");

            let metrics = self.metrics.read().await;
            let _now = Instant::now();

            println!("╔══════════════════════════════════════════════════════════════╗");
            println!("║          ADAPTIVE NETWORK MONITOR - LIVE DASHBOARD          ║");
            println!("╠══════════════════════════════════════════════════════════════╣");

            // Thompson Sampling Section
            println!("║ THOMPSON SAMPLING                                           ║");
            println!(
                "║   Success Rate: {:<6.2}%                                     ║",
                metrics.thompson_success_rate() * 100.0
            );
            println!(
                "║   Active Arms: {:<3}                                          ║",
                metrics.thompson_arms.len()
            );

            // MAB Routing Section
            println!("║                                                              ║");
            println!("║ MULTI-ARMED BANDIT ROUTING                                  ║");
            println!(
                "║   Average Reward: {:<6.3}                                    ║",
                metrics.mab_average_reward()
            );
            println!(
                "║   Total Selections: {:<6}                                   ║",
                metrics.mab_selections.values().sum::<usize>()
            );

            // Q-Learning Cache Section
            println!("║                                                              ║");
            println!("║ Q-LEARNING CACHE                                            ║");
            println!(
                "║   Hit Rate: {:<6.2}%                                         ║",
                metrics.cache_hit_rate() * 100.0
            );
            println!(
                "║   Total Hits: {:<6} | Misses: {:<6}                        ║",
                metrics.cache_hits, metrics.cache_misses
            );

            // Network Performance Section
            println!("║                                                              ║");
            println!("║ NETWORK PERFORMANCE                                         ║");
            println!(
                "║   Active Connections: {:<3}                                  ║",
                metrics.active_connections
            );
            println!(
                "║   Messages (Sent/Recv): {:<6} / {:<6}                      ║",
                metrics.messages_sent, metrics.messages_received
            );
            println!(
                "║   Bandwidth Used: {:<6} KB                                  ║",
                metrics.total_bandwidth / 1024
            );

            // Churn Prediction Section
            println!("║                                                              ║");
            println!("║ CHURN PREDICTION                                            ║");
            println!(
                "║   Nodes Joined: {:<3} | Left: {:<3}                          ║",
                metrics.nodes_joined, metrics.nodes_left
            );
            println!(
                "║   Avg Session: {:?}                                    ║",
                metrics.average_session_length
            );

            // Security Section
            println!("║                                                              ║");
            println!("║ SECURITY MONITORING                                         ║");
            println!(
                "║   Suspicious Events: {:<4}                                  ║",
                metrics.suspicious_events
            );
            println!(
                "║   Blocked Connections: {:<4}                                ║",
                metrics.blocked_connections
            );

            println!("╚══════════════════════════════════════════════════════════════╝");
            println!("\nPress Ctrl+C to exit");

            sleep(Duration::from_secs(1)).await;
        }
    }

    async fn simulate_activity(&self) {
        let metrics = self.metrics.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(500));
            let _thompson = ThompsonSampling::new();
            let _mab = MultiArmedBandit::new(MABConfig::default()).await.unwrap();
            let cache = QLearningCache::new(QLearningConfig::default(), 1024);

            loop {
                interval.tick().await;

                // Simulate Thompson Sampling (placeholder as API is async in core)
                let success = rand::random::<bool>();

                let mut m = metrics.write().await;
                let arm = 0usize;
                let entry = m.thompson_arms.entry(arm).or_insert((0, 0));
                entry.1 += 1; // Increment attempts
                if success {
                    entry.0 += 1; // Increment successes
                }

                // Simulate MAB (placeholder values)
                let reward = rand::random::<f64>();
                m.mab_rewards.push(reward);
                let route = 0usize;
                *m.mab_selections.entry(route).or_insert(0) += 1;

                // Simulate cache operations
                use saorsa_core::adaptive::coordinator_extensions::QLearningCacheExtensions;
                let key: saorsa_core::dht::Key = [0u8; 32];
                let h = saorsa_core::adaptive::ContentHash(key);
                if cache.get(&h).await.is_some() {
                    m.cache_hits += 1;
                } else {
                    m.cache_misses += 1;
                    // simulate insert by updating statistics directly
                    let h = saorsa_core::adaptive::ContentHash(key);
                    let _ = cache
                        .update_statistics(
                            &saorsa_core::adaptive::CacheAction::Cache(h),
                            &h,
                            100,
                            false,
                        )
                        .await;
                }

                // Simulate network activity
                m.messages_sent += rand::random::<usize>() % 5;
                m.messages_received += rand::random::<usize>() % 5;
                m.total_bandwidth += rand::random::<usize>() % 1024;

                // Simulate churn
                if rand::random::<f64>() < 0.05 {
                    if rand::random::<bool>() {
                        m.nodes_joined += 1;
                    } else {
                        m.nodes_left += 1;
                    }
                }

                // Simulate security events
                if rand::random::<f64>() < 0.01 {
                    m.suspicious_events += 1;
                }
                if rand::random::<f64>() < 0.005 {
                    m.blocked_connections += 1;
                }
            }
        });
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("Starting Adaptive Network Monitor...\n");

    let monitor = AdaptiveNetworkMonitor::new().await?;
    monitor.start().await?;

    // Start simulating network activity
    monitor.simulate_activity().await;

    // Display live dashboard
    monitor.display_dashboard().await;

    Ok(())
}
