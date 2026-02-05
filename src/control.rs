// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Control module for network-level control messages and handling.
//!
//! This module defines messages used for network control, such as connection
//! rejection notifications, and provides handlers for processing them.

use crate::identity::rejection::{RejectionInfo, RejectionReason, TargetRegion};
use crate::identity::restart::RestartManager;
use crate::network::P2PEvent;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, info};

/// Message sent to a peer when their connection is rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectionMessage {
    /// The reason for rejection.
    pub reason: RejectionReason,
    /// Optional message explaining the rejection.
    pub message: String,
    /// Optional suggestion for where to connect instead.
    pub suggested_target: Option<TargetRegion>,
}

/// Handler for control messages.
pub struct ControlMessageHandler {
    restart_manager: Arc<RestartManager>,
}

impl ControlMessageHandler {
    /// Create a new control message handler.
    pub fn new(restart_manager: Arc<RestartManager>) -> Self {
        Self { restart_manager }
    }

    /// Start listening for control messages.
    pub async fn start(self: Arc<Self>, mut events: broadcast::Receiver<P2PEvent>) {
        tokio::spawn(async move {
            info!("Control message handler started");

            while let Ok(event) = events.recv().await {
                if let P2PEvent::Message {
                    topic,
                    source,
                    data,
                } = event
                    && topic == "control"
                {
                    self.handle_control_message(&source, &data).await;
                }
            }

            info!("Control message handler stopped");
        });
    }

    /// Handle a received control message.
    async fn handle_control_message(&self, source: &str, data: &[u8]) {
        // Try to deserialize as RejectionMessage
        if let Ok(rejection) = serde_json::from_slice::<RejectionMessage>(data) {
            info!(
                "Received rejection from {}: {} ({:?})",
                source, rejection.message, rejection.reason
            );

            // Convert to RejectionInfo
            let info = RejectionInfo::new(rejection.reason)
                .with_message(rejection.message)
                .with_rejecting_node(source);

            // If suggested target is present, add it
            let info = if let Some(target) = rejection.suggested_target {
                info.with_suggested_target(target)
            } else {
                info
            };

            // Trigger restart manager
            self.restart_manager.handle_rejection(info).await;
        } else {
            debug!("Received unknown control message from {}", source);
        }
    }
}
