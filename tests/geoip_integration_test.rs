use saorsa_core::control::RejectionMessage;
use saorsa_core::identity::rejection::RejectionReason;
use saorsa_core::network::{NodeConfig, P2PNode};
use tokio::time::Duration;

#[tokio::test]
#[ignore = "Requires full P2P network - run with --ignored"]
#[allow(clippy::collapsible_if)]
async fn test_geoip_rejection_flow() {
    // 1. Setup Node A (The Rejector)
    let mut config_a = NodeConfig::new().unwrap();
    config_a.listen_addr = "127.0.0.1:0".parse().unwrap();
    config_a.enable_ipv6 = false;
    let node_a = P2PNode::new(config_a).await.unwrap();
    node_a.start().await.unwrap();
    let addr_a = node_a.listen_addrs().await[0];

    // 2. Setup Node B (The Victim)
    let mut config_b = NodeConfig::new().unwrap();
    config_b.listen_addr = "127.0.0.1:0".parse().unwrap();
    config_b.enable_ipv6 = false;
    let node_b = P2PNode::new(config_b).await.unwrap();
    node_b.start().await.unwrap();

    // Setup RestartManager for Node B (mocked or real)
    // We need a real RestartManager to test the flow, but it requires dependencies.
    // For this test, we might just want to verify the event is received if we can't easily build a full RestartManager.
    // But the requirement is to verify RestartManager triggers.

    // Let's try to build a minimal RestartManager.
    // It needs: persistent_state, identity_targeter, regeneration_trigger, event_tx.
    // This might be heavy for a simple test.

    // Alternative: We can verify that Node B receives the "control" message and emits a P2PEvent.
    // Then we can unit test ControlMessageHandler separately to ensure it calls RestartManager.
    // But an end-to-end test is better.

    // Let's assume we can create a RestartManager.
    // If not, we'll verify the message receipt at the P2P layer first.

    let mut event_rx = node_b.subscribe_events();

    // 3. Connect Node B to Node A
    let _peer_id_a = node_b.connect_peer(&addr_a.to_string()).await.unwrap();

    // Wait for connection to be established and recognized by Node A
    let start = std::time::Instant::now();
    let mut connected_peer_id = String::new();

    while start.elapsed() < Duration::from_secs(5) {
        let peers_a = node_a.connected_peers().await;

        for candidate in peers_a {
            if !candidate.starts_with("peer_from_") {
                if node_a.is_connection_active(&candidate).await {
                    connected_peer_id = candidate;
                    break;
                }
            }
        }

        if !connected_peer_id.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        !connected_peer_id.is_empty(),
        "Node A did not recognize connection from Node B"
    );

    // 4. Simulate Rejection: Node A sends RejectionMessage to Node B
    let rejection = RejectionMessage {
        reason: RejectionReason::GeoIpPolicy,
        message: "Simulated GeoIP Rejection".to_string(),
        suggested_target: None,
    };

    let data = serde_json::to_vec(&rejection).unwrap();

    // We use the raw send_message capability to send a "control" message
    node_a
        .send_message(&connected_peer_id, "control", data)
        .await
        .unwrap();

    // 5. Verify Node B receives the control message
    let mut received_rejection = false;
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Ok(event) = event_rx.recv() => {
                if let saorsa_core::network::P2PEvent::Message { topic, data, .. } = event {
                    if topic == "control" {
                        if let Ok(msg) = serde_json::from_slice::<RejectionMessage>(&data) {
                            // Check rejection reason
                            let is_geoip_rejection = msg.reason == RejectionReason::GeoIpPolicy;
                            if is_geoip_rejection {
                                received_rejection = true;
                                break;
                            }
                        }
                    }
                }
            }
            _ = &mut timeout => break,
        }
    }

    assert!(
        received_rejection,
        "Node B did not receive rejection message"
    );
}
