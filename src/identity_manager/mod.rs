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

//! Identity Manager Module
//!
//! This module provides comprehensive identity management functionality
//! for the P2P network, including creation, encryption, verification,
//! and multi-device synchronization.

pub mod migration;

#[cfg(test)]
mod test;

// Re-export main types for convenience
pub use migration::*;
