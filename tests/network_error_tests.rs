// Copyright (c) 2025 Saorsa Labs Limited

// This file is part of the Saorsa P2P network.

// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Network module error handling tests

use saorsa_core::Result;
use saorsa_core::error::{NetworkError, P2PError};
use saorsa_core::network::{NodeConfig as P2PNodeConfig, P2PNode};
use std::net::SocketAddr;
use std::time::Duration;

#[tokio::test]
async fn test_invalid_address_parsing() {
    // Test that invalid addresses return proper errors instead of panicking
    let invalid_addrs = vec![
        "invalid:address",
        "256.256.256.256:8080",
        "localhost:not_a_port",
        "[invalid::ipv6]:8080",
    ];

    for addr in invalid_addrs {
        let result: Result<SocketAddr> = addr.parse().map_err(|e: std::net::AddrParseError| {
            NetworkError::InvalidAddress(e.to_string().into()).into()
        });

        assert!(result.is_err());
        if let Err(P2PError::Network(NetworkError::InvalidAddress(_))) = result {
            // Expected error occurred
        } else {
            panic!("Expected InvalidAddress error");
        }
    }
}

#[tokio::test]
async fn test_network_config_with_invalid_addresses() {
    // Test that config creation handles invalid addresses gracefully
    let _config = P2PNodeConfig::default();

    // This should not panic
    let result = P2PNodeConfig::with_listen_addr("invalid:address");
    assert!(result.is_err());
}

#[tokio::test]
async fn test_bind_error_handling() {
    // Test that binding to an invalid address returns proper error
    // Try to bind to a privileged port (should fail without root)
    let config = P2PNodeConfig {
        listen_addr: "127.0.0.1:80".parse().expect("valid test address"),
        ..Default::default()
    };

    let result = P2PNode::new(config).await;

    // Should get a bind error, not panic
    assert!(result.is_err());
}

#[tokio::test]
async fn test_connection_failure_handling() {
    // Test that connection failures return proper errors
    let config = P2PNodeConfig::default();
    let node = P2PNode::new(config).await.unwrap();

    // Try to connect to non-existent peer
    let result = node.connect_peer("192.168.255.255:9999").await;

    assert!(result.is_err());
    assert!(result.is_err());
}

#[tokio::test]
async fn test_peer_info_missing_handling() {
    // Test that missing peer info doesn't panic
    let config = P2PNodeConfig::default();
    let node = P2PNode::new(config).await.unwrap();

    // Request info for non-existent peer
    let result = node.peer_info(&"non_existent_peer_id".to_string()).await;
    // Should return None, not panic
    assert!(result.is_none());
}

#[tokio::test]
async fn test_event_stream_error_handling() {
    // Test that event stream errors don't panic
    let config = P2PNodeConfig::default();
    let node = P2PNode::new(config).await.unwrap();

    // Get event stream
    let mut events = node.events();

    // Shutdown node to cause stream to end
    node.shutdown().await.unwrap();

    // Next event should be None or error, not panic
    let event = events.recv().await;
    assert!(event.is_err());
}

#[tokio::test]
async fn test_default_address_fallback() {
    // Test that address handling works correctly without panicking
    let config = P2PNodeConfig::default();

    // Default config may have empty bootstrap_peers - that's valid
    // Test that we can handle both empty and non-empty lists gracefully

    // Empty bootstrap_peers should not cause issues
    for addr in &config.bootstrap_peers {
        let parsed: Result<SocketAddr> = addr.to_string().parse().map_err(|e| {
            let e: std::net::AddrParseError = e;
            NetworkError::InvalidAddress(e.to_string().into()).into()
        });
        assert!(parsed.is_ok());
    }

    // Test with some bootstrap peers
    let test_addrs: Vec<SocketAddr> = vec![
        "127.0.0.1:8080".parse().unwrap(),
        "192.168.1.1:9000".parse().unwrap(),
    ];

    for addr in &test_addrs {
        let parsed: Result<SocketAddr> = addr.to_string().parse().map_err(|e| {
            let e: std::net::AddrParseError = e;
            NetworkError::InvalidAddress(e.to_string().into()).into()
        });
        assert!(parsed.is_ok());
    }
}

#[tokio::test]
async fn test_connection_timeout_config_handling() {
    // Test that connection timeout configuration works properly
    let config = P2PNodeConfig {
        connection_timeout: Duration::from_secs(30),
        ..Default::default()
    };

    // Should create node with custom timeout, not panic
    let result = P2PNode::new(config).await;
    assert!(result.is_ok());

    let node = result.unwrap();
    // Node should be created successfully with custom timeout

    node.shutdown().await.unwrap();
}
