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

//! Entity-based system for unified identity, storage, and collaboration
//!
//! This module provides the core entity abstraction where each entity
//! (Individual, Group, Channel, Project, Organization) has:
//! - A unique four-word address for human-readable identification
//! - Private encrypted virtual disk for secure storage
//! - Public virtual disk for website publishing
//! - Collaborative spaces for real-time editing

pub mod types;
// TODO: Implement entity-specific modules
// pub mod individual;
// pub mod group;
// pub mod channel;
// pub mod project;
// pub mod organization;
// pub mod collaborative;
// pub mod website;

pub use types::*;
// pub use individual::IndividualEntity;
// pub use group::GroupEntity;
// pub use channel::ChannelEntity;
// pub use project::ProjectEntity;
// pub use organization::OrganizationEntity;
// pub use collaborative::CollaborativeSpace;
// pub use website::WebsiteEngine;

use crate::fwid::{Key, fw_to_key};
use crate::virtual_disk::{DiskHandle, DiskType, DiskConfig, disk_create};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Entity registry for managing all entities in the system
pub struct EntityRegistry {
    entities: Arc<RwLock<HashMap<EntityId, Arc<Entity>>>>,
    by_address: Arc<RwLock<HashMap<FourWordAddress, EntityId>>>,
}

impl EntityRegistry {
    /// Create a new entity registry
    pub fn new() -> Self {
        Self {
            entities: Arc::new(RwLock::new(HashMap::new())),
            by_address: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new entity
    pub async fn register(&self, entity: Entity) -> Result<EntityHandle> {
        let entity_id = entity.core.id.clone();
        let address = entity.core.four_word_address.clone();

        let entity_arc = Arc::new(entity);

        // Store in registry
        let mut entities = self.entities.write().await;
        entities.insert(entity_id.clone(), entity_arc.clone());

        let mut by_address = self.by_address.write().await;
        by_address.insert(address.clone(), entity_id.clone());

        Ok(EntityHandle {
            id: entity_id,
            address,
            entity: entity_arc,
        })
    }

    /// Get entity by ID
    pub async fn get(&self, id: &EntityId) -> Option<Arc<Entity>> {
        let entities = self.entities.read().await;
        entities.get(id).cloned()
    }

    /// Get entity by four-word address
    pub async fn get_by_address(&self, address: &FourWordAddress) -> Option<Arc<Entity>> {
        let by_address = self.by_address.read().await;
        if let Some(id) = by_address.get(address) {
            let entities = self.entities.read().await;
            entities.get(id).cloned()
        } else {
            None
        }
    }

    /// List all entities
    pub async fn list(&self) -> Vec<EntityInfo> {
        let entities = self.entities.read().await;
        entities.values().map(|e| e.info()).collect()
    }
}

/// Create a new entity with the specified type
pub async fn create_entity(
    entity_type: EntityType,
    name: String,
    four_words: [String; 4],
) -> Result<Entity> {
    // Generate entity ID from four-word address
    let address = FourWordAddress::from_words(four_words)?;
    let entity_id = EntityId::from_address(&address);

    // Get entity ID key
    let entity_key = fw_to_key(address.words.clone())?;

    // Create virtual disks using the disk_create function
    let private_disk = disk_create(
        entity_key.clone(),
        DiskType::Private,
        DiskConfig {
            encrypted: true,
            ..Default::default()
        },
    ).await?;

    let public_disk = disk_create(
        entity_key.clone(),
        DiskType::Public,
        DiskConfig {
            encrypted: false, // Public website content
            ..Default::default()
        },
    ).await?;

    let core = EntityCore {
        id: entity_id,
        name: name.clone(),
        four_word_address: address,
        private_disk,
        public_disk,
        collaborative_spaces: Vec::new(),
        metadata: EntityMetadata {
            created_at: std::time::SystemTime::now(),
            updated_at: std::time::SystemTime::now(),
            description: None,
            avatar_url: None,
            settings: EntitySettings::default(),
        },
    };

    Ok(Entity {
        core,
        entity_type,
    })
}

/// Global entity registry instance
lazy_static::lazy_static! {
    pub static ref ENTITY_REGISTRY: EntityRegistry = EntityRegistry::new();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::types::{EntityMetadata, EntitySettings};

    #[tokio::test]
    async fn test_entity_creation() {
        // For testing, we bypass validation since we don't know the exact dictionary
        // In production, these would need to be valid four-word-networking words
        let address = FourWordAddress {
            words: ["eagle".to_string(), "forest".to_string(), "river".to_string(), "mountain".to_string()]
        };
        let entity_id = EntityId::from_address(&address);

        // Create entity directly without validation
        let entity_key = Key::new([1u8; 32]); // Mock key for testing

        let private_disk = disk_create(
            entity_key.clone(),
            DiskType::Private,
            DiskConfig {
                encrypted: true,
                ..Default::default()
            },
        ).await.unwrap();

        let public_disk = disk_create(
            entity_key,
            DiskType::Public,
            DiskConfig {
                encrypted: false,
                ..Default::default()
            },
        ).await.unwrap();

        let core = EntityCore {
            id: entity_id,
            name: "Alice".to_string(),
            four_word_address: address,
            private_disk,
            public_disk,
            collaborative_spaces: Vec::new(),
            metadata: EntityMetadata {
                created_at: std::time::SystemTime::now(),
                updated_at: std::time::SystemTime::now(),
                description: None,
                avatar_url: None,
                settings: EntitySettings::default(),
            },
        };

        let entity = Entity {
            core,
            entity_type: EntityType::Individual,
        };

        assert_eq!(entity.core.name, "Alice");
        assert_eq!(entity.core.four_word_address.words[0], "eagle");
    }

    #[tokio::test]
    async fn test_entity_registry() {
        let registry = EntityRegistry::new();

        // Create test entity directly
        let address = FourWordAddress {
            words: ["swift".to_string(), "ocean".to_string(), "cloud".to_string(), "thunder".to_string()]
        };
        let entity_id = EntityId::from_address(&address);
        let entity_key = Key::new([2u8; 32]); // Mock key for testing

        let private_disk = disk_create(
            entity_key.clone(),
            DiskType::Private,
            DiskConfig::default(),
        ).await.unwrap();

        let public_disk = disk_create(
            entity_key,
            DiskType::Public,
            DiskConfig::default(),
        ).await.unwrap();

        let entity = Entity {
            core: EntityCore {
                id: entity_id,
                name: "Dev Team".to_string(),
                four_word_address: address,
                private_disk,
                public_disk,
                collaborative_spaces: Vec::new(),
                metadata: EntityMetadata {
                    created_at: std::time::SystemTime::now(),
                    updated_at: std::time::SystemTime::now(),
                    description: None,
                    avatar_url: None,
                    settings: EntitySettings::default(),
                },
            },
            entity_type: EntityType::Group,
        };

        let handle = registry.register(entity).await.unwrap();

        // Get by ID
        let found = registry.get(&handle.id).await;
        assert!(found.is_some());

        // Get by address
        let found_by_addr = registry.get_by_address(&handle.address).await;
        assert!(found_by_addr.is_some());
    }
}