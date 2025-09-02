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

// SPDX-License-Identifier: AGPL-3.0-only
// (c) 2025 Saorsa P2P Foundation

use saorsa_core::identity::manager::{IdentityManager, IdentityManagerConfig};

/// Basic test that identity creation works
#[tokio::test]
async fn test_basic_identity_creation() {
    // Create identity manager with default config
    let config = IdentityManagerConfig::default();
    let manager = IdentityManager::new(config);

    // Create an identity with current API
    let identity = manager
        .create_identity(
            "Test User".to_string(),
            "test.user.address".to_string(),
            None,
            None,
        )
        .await
        .unwrap();

    // Test that identity was created successfully
    assert!(!identity.user_id.is_empty());
    assert_eq!(identity.display_name_hint, "Test User");
    assert!(!identity.three_word_address.is_empty());
    assert!(!identity.public_key.is_empty());
}
