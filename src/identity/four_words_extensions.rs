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

//! Extensions to FourWordAddress for comprehensive test support

use super::four_words::{FourWordAddress, WordEncoder};
use super::node_identity::NodeId;
use crate::{P2PError, Result, error::IdentityError};

impl FourWordAddress {
    /// Create from NodeId (uses facade in four_words.rs)
    pub fn from_node_id(node_id: &NodeId) -> Result<Self> {
        Ok(super::four_words::FourWordAddress::from_node_id(node_id))
    }

    /// Parse from string format (alias for parse_str)
    pub fn from_string(s: &str) -> Result<Self> {
        Self::parse_str(s)
    }

    /// Convert to string (compat helper)
    pub fn to_string(&self) -> String {
        self.as_str().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_four_word_address_format() {
        let node_id = NodeId([0x42; 32]);
        let address =
            FourWordAddress::from_node_id(&node_id).expect("Should create address from node ID");

        // Should have 4 words
        assert_eq!(address.words().len(), 4);

        // Should be formatted with hyphens
        let formatted = address.to_string();
        assert_eq!(formatted.matches('-').count(), 3);
    }
}
