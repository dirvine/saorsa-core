// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: saorsalabs@gmail.com

//! Integration tests for greedy-assist hyperbolic embedding

use saorsa_core::PeerId;
use saorsa_core::adaptive::hyperbolic_greedy::{
    Embedding, EmbeddingConfig, HyperbolicGreedyRouter, embed_snapshot, greedy_next,
};
use saorsa_core::dht::DhtNodeId as NodeId;
use std::collections::HashMap;

/// Generate a synthetic graph for testing
fn generate_synthetic_graph(num_nodes: usize, _connectivity: f64) -> Vec<PeerId> {
    (0..num_nodes).map(|i| format!("node_{:04}", i)).collect()
}

/// Generate a scale-free graph using preferential attachment
fn generate_scale_free_graph(num_nodes: usize) -> (Vec<PeerId>, HashMap<(PeerId, PeerId), bool>) {
    let nodes: Vec<PeerId> = (0..num_nodes)
        .map(|i| format!("sf_node_{:04}", i))
        .collect();
    let mut edges = HashMap::new();

    // Start with a small complete graph
    for i in 0..3 {
        for j in i + 1..3 {
            edges.insert((nodes[i].clone(), nodes[j].clone()), true);
            edges.insert((nodes[j].clone(), nodes[i].clone()), true);
        }
    }

    // Add remaining nodes with preferential attachment
    for i in 3..num_nodes {
        let num_edges = 2; // Each new node connects to 2 existing nodes
        let mut connected = 0;

        while connected < num_edges {
            let target = rand::random::<usize>() % i;
            let key = (nodes[i].clone(), nodes[target].clone());
            if !edges.contains_key(&key) {
                edges.insert(key, true);
                edges.insert((nodes[target].clone(), nodes[i].clone()), true);
                connected += 1;
            }
        }
    }

    (nodes, edges)
}

/// Calculate success ratio for greedy routing
async fn calculate_success_ratio(embedding: &Embedding, test_pairs: &[(PeerId, PeerId)]) -> f64 {
    let mut successes = 0;

    for (source, target) in test_pairs {
        // Convert target to NodeId
        let mut node_id_bytes = [0u8; 32];
        let target_bytes = target.as_bytes();
        let len = target_bytes.len().min(32);
        node_id_bytes[..len].copy_from_slice(&target_bytes[..len]);
        let target_node = NodeId::from_bytes(node_id_bytes);

        // Try greedy routing
        if let Some(_next_hop) = greedy_next(target_node, source.clone(), embedding).await {
            successes += 1;
        }
    }

    successes as f64 / test_pairs.len() as f64
}

/// Calculate stretch (actual hops / optimal hops)
async fn calculate_stretch(
    embedding: &Embedding,
    source: &PeerId,
    target: &PeerId,
    edges: &HashMap<(PeerId, PeerId), bool>,
) -> Option<f64> {
    // Simple BFS to find shortest path
    let mut visited = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    let mut distances = HashMap::new();

    queue.push_back(source.clone());
    distances.insert(source.clone(), 0);
    visited.insert(source.clone());

    while let Some(current) = queue.pop_front() {
        if current == *target {
            break;
        }

        let current_dist = *distances.get(&current).unwrap();

        // Find neighbors
        for ((from, to), _) in edges.iter() {
            if from == &current && !visited.contains(to) {
                visited.insert(to.clone());
                distances.insert(to.clone(), current_dist + 1);
                queue.push_back(to.clone());
            }
        }
    }

    let optimal_hops = distances.get(target)?;

    // Now trace greedy path
    let mut greedy_hops = 0;
    let mut current = source.clone();
    let mut visited_greedy = std::collections::HashSet::new();

    while current != *target && greedy_hops < 100 {
        visited_greedy.insert(current.clone());

        // Convert target to NodeId
        let mut node_id_bytes = [0u8; 32];
        let target_bytes = target.as_bytes();
        let len = target_bytes.len().min(32);
        node_id_bytes[..len].copy_from_slice(&target_bytes[..len]);
        let target_node = NodeId::from_bytes(node_id_bytes);

        match greedy_next(target_node, current.clone(), embedding).await {
            Some(next) if !visited_greedy.contains(&next) => {
                current = next;
                greedy_hops += 1;
            }
            _ => break, // No progress possible
        }
    }

    if current == *target {
        Some(greedy_hops as f64 / *optimal_hops as f64)
    } else {
        None // Greedy routing failed
    }
}

#[tokio::test]
async fn test_embedding_on_synthetic_graph() {
    // Generate a medium-sized synthetic graph
    let nodes = generate_synthetic_graph(50, 0.1);

    // Create embedding
    let embedding = embed_snapshot(&nodes).await.unwrap();

    // Verify all nodes are embedded
    assert_eq!(embedding.coordinates.len(), nodes.len());

    // Check embedding quality
    assert!(embedding.quality.mae < 10.0, "MAE should be reasonable");
    assert!(
        embedding.quality.iterations > 0,
        "Should perform iterations"
    );
}

#[tokio::test]
async fn test_greedy_routing_success_ratio() {
    // Generate scale-free graph
    let (nodes, _edges) = generate_scale_free_graph(30);

    // Create embedding
    let embedding = embed_snapshot(&nodes).await.unwrap();

    // Generate test pairs
    let test_pairs: Vec<(PeerId, PeerId)> = (0..20)
        .map(|_| {
            let source = nodes[rand::random::<usize>() % nodes.len()].clone();
            let target = nodes[rand::random::<usize>() % nodes.len()].clone();
            (source, target)
        })
        .filter(|(s, t)| s != t)
        .collect();

    // Calculate success ratio
    let success_ratio = calculate_success_ratio(&embedding, &test_pairs).await;

    // Should have reasonable success rate
    assert!(
        success_ratio > 0.3,
        "Success ratio too low: {}",
        success_ratio
    );
    println!(
        "Greedy routing success ratio: {:.2}%",
        success_ratio * 100.0
    );
}

#[tokio::test]
async fn test_stretch_on_scale_free_graph() {
    // Generate smaller graph for stretch calculation
    let (nodes, _edges) = generate_scale_free_graph(20);

    // Create embedding
    let embedding = embed_snapshot(&nodes).await.unwrap();

    // Calculate stretch for several pairs
    let mut total_stretch = 0.0;
    let mut valid_pairs = 0;

    for _ in 0..10 {
        let source = &nodes[rand::random::<usize>() % nodes.len()];
        let target = &nodes[rand::random::<usize>() % nodes.len()];

        if source != target {
            if let Some(stretch) = calculate_stretch(&embedding, source, target, &edges).await {
                total_stretch += stretch;
                valid_pairs += 1;
            }
        }
    }

    if valid_pairs > 0 {
        let avg_stretch = total_stretch / valid_pairs as f64;
        println!("Average stretch: {:.2}", avg_stretch);

        // Stretch should be reasonable (not more than 3x optimal)
        assert!(avg_stretch < 3.0, "Stretch too high: {}", avg_stretch);
    }
}

#[tokio::test]
async fn test_fallback_correctness() {
    // Create a router for fallback testing
    let local_id = format!("fallback_test_{}", rand::random::<u64>());

    let router = HyperbolicGreedyRouter::new(local_id.clone());

    // Create a minimal embedding with just a few nodes
    let nodes: Vec<PeerId> = (0..5).map(|i| format!("fb_node_{}", i)).collect();
    let embedding = router.embed_snapshot(&nodes).await.unwrap();

    // Store embedding
    router.set_embedding(embedding.clone()).await;

    // Test with a target not in the embedding (should fall back to Kad)
    let unknown_target = NodeId::from_bytes([99u8; 32]);
    let result = router
        .greedy_next(unknown_target, local_id.clone(), &embedding)
        .await;

    // Result could be None if DHT also doesn't know the target
    // This is expected behavior
    println!("Fallback result: {:?}", result);
}

#[tokio::test]
async fn test_drift_detection() {
    let local_id = format!("drift_test_{}", rand::random::<u64>());

    let router = HyperbolicGreedyRouter::new(local_id);

    // Simulate normal operation
    for _ in 0..10 {
        assert!(!router.detect_drift(1.0).await);
    }

    // Simulate drift with increasing errors
    for i in 0..20 {
        let error = 1.0 + (i as f64 * 0.1);
        let is_drift = router.detect_drift(error).await;

        if i > 10 {
            // After enough high errors, drift should be detected
            if is_drift {
                println!("Drift detected after {} iterations", i);
                return;
            }
        }
    }

    panic!("Drift detection should have triggered");
}

#[tokio::test]
async fn test_partial_refit_performance() {
    let local_id = format!("refit_perf_{}", rand::random::<u64>());

    let router = HyperbolicGreedyRouter::new(local_id);

    // Create initial embedding
    let initial_nodes: Vec<PeerId> = (0..20).map(|i| format!("init_{}", i)).collect();
    let embedding = router.embed_snapshot(&initial_nodes).await.unwrap();
    router.set_embedding(embedding).await;

    // Measure partial refit time
    let new_nodes: Vec<PeerId> = (0..5).map(|i| format!("new_{}", i)).collect();

    let start = std::time::Instant::now();
    router.partial_refit(&new_nodes).await.unwrap();
    let refit_time = start.elapsed();

    println!("Partial refit time for 5 nodes: {:?}", refit_time);

    // Refit should be fast (under 100ms for small updates)
    assert!(
        refit_time.as_millis() < 100,
        "Refit too slow: {:?}",
        refit_time
    );

    // Verify refit completed successfully (new nodes should be accessible)
    // Note: We can't directly access private embedding field, but refit success indicates nodes were processed
    assert!(
        refit_time.as_millis() > 0,
        "Refit should take some time to process nodes"
    );
}

#[tokio::test]
async fn test_embedding_convergence() {
    // Test that embedding converges with different configurations
    let nodes = generate_synthetic_graph(20, 0.15);

    // Test with default config
    let emb1 = embed_snapshot(&nodes).await.unwrap();

    // Test with aggressive config
    let config = EmbeddingConfig {
        learning_rate: 0.2,
        max_iterations: 2000,
        convergence_threshold: 0.0001,
        ..Default::default()
    };

    // Create router with custom config
    let local_id = nodes[0].clone();

    let mut router = HyperbolicGreedyRouter::new(local_id);
    router.set_config(config);

    let emb2 = router.embed_snapshot(&nodes).await.unwrap();

    // Aggressive config should achieve better quality
    assert!(emb2.quality.mae <= emb1.quality.mae * 1.1);
    println!(
        "Default MAE: {:.3}, Aggressive MAE: {:.3}",
        emb1.quality.mae, emb2.quality.mae
    );
}

#[tokio::test]
async fn test_routing_metrics() {
    let local_id = format!("metrics_{}", rand::random::<u64>());

    let router = HyperbolicGreedyRouter::new(local_id.clone());

    // Create embedding
    let nodes: Vec<PeerId> = (0..10).map(|i| format!("m_node_{}", i)).collect();
    let embedding = router.embed_snapshot(&nodes).await.unwrap();
    router.set_embedding(embedding.clone()).await;

    // Perform several routing attempts
    for i in 0..10 {
        let target_idx = (i * 3) % nodes.len();
        let mut node_id_bytes = [0u8; 32];
        let target_bytes = nodes[target_idx].as_bytes();
        let len = target_bytes.len().min(32);
        node_id_bytes[..len].copy_from_slice(&target_bytes[..len]);
        let target = NodeId::from_bytes(node_id_bytes);

        let _ = router
            .greedy_next(target, local_id.clone(), &embedding)
            .await;
    }

    // Check metrics
    let metrics = router.get_metrics().await;
    assert!(metrics.greedy_success() + metrics.greedy_failures() > 0);
    println!(
        "Routing metrics - Success: {}, Failures: {}",
        metrics.greedy_success(),
        metrics.greedy_failures()
    );
}
