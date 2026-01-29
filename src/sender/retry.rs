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

//! Retry logic and pending message tracking for the sender system.
//!
//! This module handles:
//! - Tracking pending messages awaiting delivery confirmation
//! - Background retry task for failed deliveries
//! - Exponential backoff and timeout management

use super::types::{
    DeliveryEvent, DeliveryTracking, EncodedPayload, MessageDestination, MessageId,
};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tokio::time::Instant;

/// A message pending delivery confirmation
#[derive(Debug, Clone)]
pub(crate) struct PendingMessage {
    /// Unique message identifier
    pub id: MessageId,
    /// Where the message should be sent
    pub destination: MessageDestination,
    /// The encoded payload to send
    pub payload: EncodedPayload,
    /// Tracking configuration
    pub tracking: DeliveryTracking,
    /// Number of send attempts made
    pub attempts: u32,
    /// When to attempt the next retry
    pub next_retry: Instant,
    /// When the message was first created
    pub created_at: DateTime<Utc>,
    /// When the last send attempt was made
    pub last_attempt_at: Option<DateTime<Utc>>,
}

impl PendingMessage {
    /// Create a new pending message
    pub fn new(
        id: MessageId,
        destination: MessageDestination,
        payload: EncodedPayload,
        tracking: DeliveryTracking,
    ) -> Self {
        Self {
            id,
            destination,
            payload,
            tracking,
            attempts: 0,
            next_retry: Instant::now(),
            created_at: Utc::now(),
            last_attempt_at: None,
        }
    }

    /// Check if the message has timed out
    pub fn is_timed_out(&self) -> bool {
        let elapsed = Utc::now()
            .signed_duration_since(self.created_at)
            .to_std()
            .unwrap_or_default();
        elapsed >= self.tracking.timeout
    }

    /// Check if the message has exhausted all retries
    pub fn is_exhausted(&self) -> bool {
        self.attempts > self.tracking.retry_policy.max_retries
    }

    /// Check if the message is ready for a retry attempt
    pub fn is_ready_for_retry(&self) -> bool {
        Instant::now() >= self.next_retry
    }

    /// Record a send attempt and update retry timing
    pub fn record_attempt(&mut self) {
        self.attempts += 1;
        self.last_attempt_at = Some(Utc::now());

        // Calculate next retry time with exponential backoff
        let delay = self.tracking.retry_policy.delay_for_attempt(self.attempts);
        self.next_retry = Instant::now() + delay;
    }

    /// Create a Sent event for this message
    pub fn sent_event(&self) -> DeliveryEvent {
        DeliveryEvent::Sent {
            message_id: self.id,
            destination: self.destination.clone(),
            attempt: self.attempts.saturating_sub(1),
            sent_at: self.last_attempt_at.unwrap_or_else(Utc::now),
        }
    }

    /// Create a Retrying event for this message
    pub fn retrying_event(&self, reason: String) -> DeliveryEvent {
        DeliveryEvent::Retrying {
            message_id: self.id,
            destination: self.destination.clone(),
            attempt: self.attempts,
            reason,
            retry_at: Utc::now()
                + chrono::Duration::from_std(self.next_retry.duration_since(Instant::now()))
                    .unwrap_or_default(),
        }
    }

    /// Create a Failed event for this message
    pub fn failed_event(&self, error: String) -> DeliveryEvent {
        DeliveryEvent::Failed {
            message_id: self.id,
            destination: self.destination.clone(),
            attempts: self.attempts,
            error,
            failed_at: Utc::now(),
        }
    }

    /// Create a TimedOut event for this message
    pub fn timed_out_event(&self) -> DeliveryEvent {
        DeliveryEvent::TimedOut {
            message_id: self.id,
            destination: self.destination.clone(),
            attempts: self.attempts,
            timed_out_at: Utc::now(),
        }
    }

    /// Create a Delivered event for this message
    pub fn delivered_event(&self, rtt: std::time::Duration) -> DeliveryEvent {
        DeliveryEvent::Delivered {
            message_id: self.id,
            destination: self.destination.clone(),
            attempts: self.attempts,
            delivered_at: Utc::now(),
            rtt,
        }
    }
}

/// Manager for pending messages with retry tracking
#[derive(Debug, Default)]
pub(crate) struct PendingMessageManager {
    /// Messages awaiting confirmation
    messages: HashMap<MessageId, PendingMessage>,
}

impl PendingMessageManager {
    /// Create a new manager
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new pending message
    pub fn add(&mut self, message: PendingMessage) {
        self.messages.insert(message.id, message);
    }

    /// Remove a message by ID
    pub fn remove(&mut self, id: &MessageId) -> Option<PendingMessage> {
        self.messages.remove(id)
    }

    /// Get a mutable reference to a message
    pub fn get_mut(&mut self, id: &MessageId) -> Option<&mut PendingMessage> {
        self.messages.get_mut(id)
    }

    /// Get the number of pending messages
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Check if there are no pending messages
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Get messages ready for retry
    pub fn ready_for_retry(&self) -> Vec<MessageId> {
        self.messages
            .iter()
            .filter(|(_, msg)| msg.is_ready_for_retry() && !msg.is_timed_out() && !msg.is_exhausted())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get messages that have timed out
    pub fn timed_out(&self) -> Vec<MessageId> {
        self.messages
            .iter()
            .filter(|(_, msg)| msg.is_timed_out())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get messages that have exhausted retries
    pub fn exhausted(&self) -> Vec<MessageId> {
        self.messages
            .iter()
            .filter(|(_, msg)| msg.is_exhausted() && !msg.is_timed_out())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Iterate over all pending messages
    #[allow(dead_code)]
    pub fn iter(&self) -> impl Iterator<Item = (&MessageId, &PendingMessage)> {
        self.messages.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sender::types::RetryPolicy;
    use std::time::Duration;

    fn create_test_message(id: u64) -> PendingMessage {
        PendingMessage::new(
            MessageId(id),
            MessageDestination::gossip("test"),
            EncodedPayload::raw(vec![1, 2, 3]),
            DeliveryTracking {
                require_ack: true,
                timeout: Duration::from_secs(10),
                retry_policy: RetryPolicy {
                    max_retries: 3,
                    initial_delay: Duration::from_millis(10),
                    backoff_multiplier: 2.0,
                    max_delay: Duration::from_secs(1),
                },
            },
        )
    }

    #[test]
    fn test_pending_message_creation() {
        let msg = create_test_message(1);
        assert_eq!(msg.id, MessageId(1));
        assert_eq!(msg.attempts, 0);
        assert!(!msg.is_timed_out());
        assert!(!msg.is_exhausted());
    }

    #[test]
    fn test_record_attempt() {
        let mut msg = create_test_message(1);
        assert_eq!(msg.attempts, 0);

        msg.record_attempt();
        assert_eq!(msg.attempts, 1);
        assert!(msg.last_attempt_at.is_some());
    }

    #[test]
    fn test_exhausted_after_max_retries() {
        let mut msg = create_test_message(1);
        msg.tracking.retry_policy.max_retries = 2;

        msg.record_attempt(); // 1
        assert!(!msg.is_exhausted());

        msg.record_attempt(); // 2
        assert!(!msg.is_exhausted());

        msg.record_attempt(); // 3 (exceeds max_retries of 2)
        assert!(msg.is_exhausted());
    }

    #[test]
    fn test_manager_operations() {
        let mut manager = PendingMessageManager::new();
        assert!(manager.is_empty());

        let msg1 = create_test_message(1);
        let msg2 = create_test_message(2);

        manager.add(msg1);
        manager.add(msg2);

        assert_eq!(manager.len(), 2);
        assert!(!manager.is_empty());

        let removed = manager.remove(&MessageId(1));
        assert!(removed.is_some());
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_ready_for_retry() {
        let mut manager = PendingMessageManager::new();

        let mut msg = create_test_message(1);
        // Set next_retry to now, so it's ready
        msg.next_retry = Instant::now();
        manager.add(msg);

        let ready = manager.ready_for_retry();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], MessageId(1));
    }

    #[test]
    fn test_event_creation() {
        let mut msg = create_test_message(1);
        msg.record_attempt();

        let sent = msg.sent_event();
        assert!(matches!(sent, DeliveryEvent::Sent { message_id, .. } if message_id == MessageId(1)));

        let retrying = msg.retrying_event("test error".into());
        assert!(matches!(retrying, DeliveryEvent::Retrying { message_id, .. } if message_id == MessageId(1)));

        let failed = msg.failed_event("permanent failure".into());
        assert!(matches!(failed, DeliveryEvent::Failed { message_id, .. } if message_id == MessageId(1)));

        let timed_out = msg.timed_out_event();
        assert!(matches!(timed_out, DeliveryEvent::TimedOut { message_id, .. } if message_id == MessageId(1)));

        let delivered = msg.delivered_event(Duration::from_millis(50));
        assert!(matches!(delivered, DeliveryEvent::Delivered { message_id, .. } if message_id == MessageId(1)));
    }
}
