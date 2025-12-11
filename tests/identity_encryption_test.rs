// Copyright 2024 Saorsa Labs Limited
//
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

use saorsa_core::identity::manager::{IdentityManager, IdentityManagerConfig};

#[tokio::test]
async fn test_identity_creation() {
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
