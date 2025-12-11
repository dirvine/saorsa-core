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

//! Database migration support

use crate::persistence::{PersistenceError, Result, Store};

/// Migration runner
pub struct MigrationRunner;

impl MigrationRunner {
    /// Apply migrations up to target version
    pub async fn migrate_to(store: &dyn Store, target_version: u32) -> Result<()> {
        // Get current version
        let current = store
            .get(b"schema_version")
            .await?
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        if current >= target_version {
            return Ok(());
        }

        // Apply migrations
        for version in (current + 1)..=target_version {
            // Apply migration for this version
            let version_bytes = version.to_string().into_bytes();
            store.put(b"schema_version", &version_bytes, None).await?;
        }

        Ok(())
    }

    /// Rollback to previous version
    pub async fn rollback(store: &dyn Store, target_version: u32) -> Result<()> {
        // Get current version
        let current = store
            .get(b"schema_version")
            .await?
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        if current <= target_version {
            return Ok(());
        }

        // Rollback migrations
        for version in (target_version + 1..=current).rev() {
            // Rollback migration for this version
            let version_bytes = (version - 1).to_string().into_bytes();
            store.put(b"schema_version", &version_bytes, None).await?;
        }

        Ok(())
    }
}
