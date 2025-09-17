// Copyright 2024 Saorsa Labs Limited
//
// Entity type definitions for the unified entity system

use crate::fwid::{Key, fw_to_key};
use crate::virtual_disk::DiskHandle;
use crate::identity::enhanced::Permission;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::SystemTime;
use uuid::Uuid;

/// Unique entity identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntityId(pub String);

impl EntityId {
    /// Create a new random entity ID
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Create from four-word address
    pub fn from_address(address: &FourWordAddress) -> Self {
        // Generate deterministic ID from address
        match fw_to_key(address.words.clone()) {
            Ok(key) => {
                // Use first 16 bytes of the key for ID
                let bytes = key.as_bytes();
                Self(hex::encode(&bytes[..16]))
            }
            Err(_) => {
                // Fallback to new random ID if key generation fails
                Self::new()
            }
        }
    }
}

impl Default for EntityId {
    fn default() -> Self {
        Self::new()
    }
}

/// Human-readable four-word address for entities
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FourWordAddress {
    pub words: [String; 4],
}

impl FourWordAddress {
    /// Create from four words
    pub fn from_words(words: [String; 4]) -> Result<Self> {
        // Validate words (could check against dictionary)
        for word in &words {
            if word.is_empty() {
                return Err(anyhow!("Empty word not allowed"));
            }
            if word.len() > 20 {
                return Err(anyhow!("Word too long: {}", word));
            }
        }

        Ok(Self { words })
    }

    /// Convert to URL format
    pub fn to_url(&self) -> String {
        format!("https://{}.saorsa", self.words.join("-"))
    }

    /// Convert to DHT key for resolution
    pub fn to_dht_key(&self) -> Result<Key> {
        fw_to_key(self.words.clone())
    }

    /// Format as hyphenated string
    pub fn to_string(&self) -> String {
        self.words.join("-")
    }
}

/// Entity type enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntityType {
    /// Individual user entity
    Individual,
    /// Group of users
    Group,
    /// Broadcast/discussion channel
    Channel,
    /// Collaborative project
    Project,
    /// Formal organization
    Organization,
}

impl EntityType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Individual => "individual",
            Self::Group => "group",
            Self::Channel => "channel",
            Self::Project => "project",
            Self::Organization => "organization",
        }
    }
}

/// Core entity structure shared by all entity types
#[derive(Debug, Clone)]
pub struct EntityCore {
    /// Unique entity identifier
    pub id: EntityId,

    /// Human-readable name
    pub name: String,

    /// Four-word address for human-readable identification
    pub four_word_address: FourWordAddress,

    /// Private encrypted virtual disk
    pub private_disk: DiskHandle,

    /// Public virtual disk for website
    pub public_disk: DiskHandle,

    /// Collaborative spaces this entity participates in
    pub collaborative_spaces: Vec<CollaborativeSpaceRef>,

    /// Entity metadata
    pub metadata: EntityMetadata,
}

/// Entity metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityMetadata {
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
    pub description: Option<String>,
    pub avatar_url: Option<String>,
    pub settings: EntitySettings,
}

/// Entity settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySettings {
    /// Privacy level
    pub privacy: PrivacyLevel,

    /// Whether the public website is enabled
    pub website_enabled: bool,

    /// Custom domain for website (if any)
    pub custom_domain: Option<String>,

    /// Storage quota in bytes
    pub storage_quota: u64,

    /// Collaboration settings
    pub collaboration: CollaborationSettings,
}

impl Default for EntitySettings {
    fn default() -> Self {
        Self {
            privacy: PrivacyLevel::Private,
            website_enabled: false,
            custom_domain: None,
            storage_quota: 10 * 1024 * 1024 * 1024, // 10 GB default
            collaboration: CollaborationSettings::default(),
        }
    }
}

/// Privacy level for entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivacyLevel {
    /// Completely public - anyone can view
    Public,
    /// Unlisted - accessible via direct link only
    Unlisted,
    /// Private - requires permission to access
    Private,
}

/// Collaboration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationSettings {
    /// Who can invite new members
    pub invite_permission: Permission,

    /// Who can create collaborative documents
    pub create_permission: Permission,

    /// Whether to allow anonymous viewing
    pub allow_anonymous_view: bool,

    /// Whether to allow commenting
    pub allow_comments: bool,
}

impl Default for CollaborationSettings {
    fn default() -> Self {
        Self {
            invite_permission: Permission::ChatInviteMembers,
            create_permission: Permission::ProjectCreate,
            allow_anonymous_view: false,
            allow_comments: true,
        }
    }
}

/// Reference to a collaborative space
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborativeSpaceRef {
    pub space_id: CollaborativeSpaceId,
    pub joined_at: SystemTime,
    pub role: CollaboratorRole,
}

/// Collaborative space identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CollaborativeSpaceId(pub String);

impl CollaborativeSpaceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl Default for CollaborativeSpaceId {
    fn default() -> Self {
        Self::new()
    }
}

/// Role in a collaborative space
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CollaboratorRole {
    Owner,
    Editor,
    Viewer,
    Commenter,
}

/// Complete entity with type-specific data
#[derive(Debug, Clone)]
pub struct Entity {
    /// Core entity data
    pub core: EntityCore,

    /// Type-specific data
    pub entity_type: EntityType,
}

impl Entity {
    /// Get entity information
    pub fn info(&self) -> EntityInfo {
        EntityInfo {
            id: self.core.id.clone(),
            name: self.core.name.clone(),
            entity_type: self.entity_type.clone(),
            four_word_address: self.core.four_word_address.clone(),
            created_at: self.core.metadata.created_at,
            website_enabled: self.core.metadata.settings.website_enabled,
        }
    }

    /// Get website URL if enabled
    pub fn website_url(&self) -> Option<String> {
        if self.core.metadata.settings.website_enabled {
            Some(self.core.four_word_address.to_url())
        } else {
            None
        }
    }
}

/// Entity information for listings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityInfo {
    pub id: EntityId,
    pub name: String,
    pub entity_type: EntityType,
    pub four_word_address: FourWordAddress,
    pub created_at: SystemTime,
    pub website_enabled: bool,
}

/// Handle to an entity with convenient access methods
pub struct EntityHandle {
    pub id: EntityId,
    pub address: FourWordAddress,
    pub entity: Arc<Entity>,
}

impl EntityHandle {
    /// Get the entity's website URL
    pub fn website_url(&self) -> Option<String> {
        self.entity.website_url()
    }

    /// Access the private disk
    pub fn private_disk(&self) -> &DiskHandle {
        &self.entity.core.private_disk
    }

    /// Access the public disk
    pub fn public_disk(&self) -> &DiskHandle {
        &self.entity.core.public_disk
    }
}

/// Entity creation parameters
#[derive(Debug, Clone)]
pub struct CreateEntityParams {
    pub name: String,
    pub entity_type: EntityType,
    pub four_words: [String; 4],
    pub description: Option<String>,
    pub settings: Option<EntitySettings>,
}

/// Entity member for group/org/project entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityMember {
    pub user_id: EntityId,
    pub name: String,
    pub role: MemberRole,
    pub joined_at: SystemTime,
    pub permissions: Vec<Permission>,
}

/// Member role in an entity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MemberRole {
    Owner,
    Admin,
    Moderator,
    Member,
    Guest,
}

impl MemberRole {
    /// Check if role has admin privileges
    pub fn is_admin(&self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    /// Check if role can moderate
    pub fn can_moderate(&self) -> bool {
        matches!(self, Self::Owner | Self::Admin | Self::Moderator)
    }
}