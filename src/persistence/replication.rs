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

//! Replication layer for distributed storage

use async_trait::async_trait;
use std::sync::Arc;
use crate::persistence::{
    Store, Query, Replicate, Migrate, Monitor, ReplicationConfig,
    Result, NodeId, ReplicationStatus, SyncStats,
};

/// Replicated storage wrapper
pub struct ReplicatedStore {
    inner: Arc<dyn Store + Query + Replicate + Migrate + Monitor>,
    _config: ReplicationConfig,
}

impl ReplicatedStore {
    /// Create new replicated store
    pub fn new(
        inner: impl Store + Query + Replicate + Migrate + Monitor + 'static,
        config: ReplicationConfig,
    ) -> Self {
        Self {
            inner: Arc::new(inner),
            _config: config,
        }
    }
}

#[async_trait]
impl Replicate for ReplicatedStore {
    async fn replicate(&self, key: &[u8], nodes: Vec<NodeId>) -> Result<()> {
        self.inner.replicate(key, nodes).await
    }
    
    async fn sync_from(&self, peer: NodeId, namespace: &str) -> Result<SyncStats> {
        self.inner.sync_from(peer, namespace).await
    }
    
    async fn replication_status(&self, key: &[u8]) -> Result<ReplicationStatus> {
        self.inner.replication_status(key).await
    }
    
    async fn set_replication_config(&self, config: ReplicationConfig) -> Result<()> {
        self.inner.set_replication_config(config).await
    }
}