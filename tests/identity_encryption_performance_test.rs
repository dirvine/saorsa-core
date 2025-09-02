use saorsa_core::identity::manager::{IdentityManager, IdentityManagerConfig};

/// Test that identity creation works
#[tokio::test]
async fn test_identity_creation() {
    let config = IdentityManagerConfig::default();
    let manager = IdentityManager::new(config);

    let identity = manager
        .create_identity(
            "Test User".to_string(),
            "test.user.address".to_string(),
            None,
            None,
        )
        .await
        .unwrap();

    assert!(!identity.user_id.is_empty());
    assert_eq!(identity.display_name_hint, "Test User");
}
