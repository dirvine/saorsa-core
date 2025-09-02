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

//! Test for new node identity implementation

use saorsa_core::Result;
use saorsa_core::identity::{NodeId, NodeIdentity};

#[test]
fn test_node_identity_generation() -> Result<()> {
    // Generate with easy difficulty for testing
    let identity = NodeIdentity::generate().unwrap();

    // Check all fields are set
    // Word address functionality removed - using PQC addresses instead
    assert!(!identity.node_id().to_string().is_empty());
    // POW functionality removed - using PQC signatures instead
    let message = b"test message";
    let signature = identity.sign(message).unwrap();
    assert!(identity.verify(message, &signature).unwrap());

    println!("Generated identity:");
    println!("  Node ID: {}", identity.node_id());
    println!("  Node ID: {}", identity.node_id());
    println!(
        "  PoW computation time: {:?}",
        // POW computation time no longer tracked
        0u64
    );
    Ok(())
}

#[test]
fn test_deterministic_identity() {
    let seed = [0x42; 32];

    // Generate same identity twice
    let id1 = NodeIdentity::from_seed(&seed).unwrap();
    let id2 = NodeIdentity::from_seed(&seed).unwrap();

    // Should be identical
    assert_eq!(id1.node_id(), id2.node_id());
    assert_eq!(id1.node_id(), id2.node_id());
}

#[test]
fn test_signing_and_verification() {
    let identity = NodeIdentity::generate().unwrap();
    let message = b"Test message for P2P network";

    // Sign message
    let signature = identity.sign(message).unwrap();

    // Verify with same identity
    assert!(identity.verify(message, &signature).unwrap());

    // Verify with wrong message should fail
    assert!(!identity.verify(b"Wrong message", &signature).unwrap());
}

#[test]
fn test_persistence() {
    let identity = NodeIdentity::generate().unwrap();
    let original_id = identity.node_id().clone();

    // Export to data
    let data = identity.export();

    // Import from data
    let restored = NodeIdentity::import(&data).unwrap();

    // Should be identical
    assert_eq!(restored.node_id(), &original_id);

    // Should be able to sign with restored identity
    let msg = b"Persistence test";
    let sig = restored.sign(msg).unwrap();
    assert!(identity.verify(msg, &sig).unwrap());
}

#[test]
fn test_node_id_xor_distance() {
    let id1 = NodeId([0xFF; 32]);
    let id2 = NodeId([0x00; 32]);

    let distance = id1.xor_distance(&id2);

    // Distance should be all 0xFF
    for byte in distance.iter() {
        assert_eq!(*byte, 0xFF);
    }
}
