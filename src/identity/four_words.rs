// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

// Four-word address integration: delegate to external crate API, keep our API facade
use super::node_identity::NodeId;
use crate::error::IdentityError;
use crate::{P2PError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FourWordAddress(pub String);

impl FourWordAddress {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Interpret first 6 bytes as IPv4+port for compatibility
        if bytes.len() < 6 {
            return Err(P2PError::Identity(IdentityError::InvalidFourWordAddress(
                "Need at least 6 bytes".into(),
            )));
        }
        let ip = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
        let port = u16::from_be_bytes([bytes[4], bytes[5]]);
        let enc = four_word_networking::FourWordEncoder::new()
            .encode_ipv4(ip, port)
            .map_err(|e| {
                P2PError::Identity(IdentityError::InvalidFourWordAddress(
                    format!("{}", e).into(),
                ))
            })?;
        Ok(Self(enc.to_string().replace(' ', "-")))
    }

    pub fn parse_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = if s.contains('-') {
            s.split('-').collect()
        } else {
            s.split_whitespace().collect()
        };

        if parts.len() != 4 || parts.iter().any(|segment| segment.is_empty()) {
            return Err(P2PError::Identity(IdentityError::InvalidFourWordAddress(
                format!("Expected 4 words, got {}", parts.len()).into(),
            )));
        }

        if parts
            .iter()
            .any(|segment| !segment.chars().all(|c| c.is_ascii_lowercase()))
        {
            return Err(P2PError::Identity(IdentityError::InvalidFourWordAddress(
                "Words must contain only lowercase ASCII letters".into(),
            )));
        }

        Ok(Self(parts.join("-")))
    }

    /// Back-compat helper expected by tests
    pub fn parse(s: &str) -> Result<Self> {
        Self::parse_str(s)
    }

    /// Construct from a `NodeId` by encoding first 6 bytes as IPv4+port
    pub fn from_node_id(node_id: &NodeId) -> Self {
        // Safe: always 32 bytes; take first 6 for IPv4+port derivation
        let bytes = node_id.to_bytes();
        match Self::from_bytes(&bytes[..6]) {
            Ok(addr) => addr,
            Err(_) => FourWordAddress(hex::encode(&bytes[..4])),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn words(&self) -> Vec<String> {
        self.0.split('-').map(|w| w.to_string()).collect()
    }

    pub fn to_hash_prefix(&self) -> Result<[u8; 6]> {
        // Interpret address as IPv4+port derived encoding if possible
        let words = self.0.replace('-', " ");
        let (ip, port) = four_word_networking::FourWordEncoder::new()
            .decode_ipv4(&four_word_networking::FourWordEncoding::new(
                words.split_whitespace().nth(0).unwrap_or("").to_string(),
                words.split_whitespace().nth(1).unwrap_or("").to_string(),
                words.split_whitespace().nth(2).unwrap_or("").to_string(),
                words.split_whitespace().nth(3).unwrap_or("").to_string(),
            ))
            .map_err(|e| {
                P2PError::Identity(IdentityError::InvalidFourWordAddress(
                    format!("{}", e).into(),
                ))
            })?;
        let mut bytes = Vec::with_capacity(6);
        bytes.extend_from_slice(&ip.octets());
        bytes.extend_from_slice(&port.to_be_bytes());
        let mut out = [0u8; 6];
        let len = bytes.len().min(6);
        out[..len].copy_from_slice(&bytes[..len]);
        Ok(out)
    }
}

impl fmt::Display for FourWordAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub struct WordEncoder;
impl WordEncoder {
    pub fn encode(bytes: &[u8]) -> Result<FourWordAddress> {
        FourWordAddress::from_bytes(bytes)
    }
    pub fn decode(addr: &FourWordAddress) -> Result<Vec<u8>> {
        // Decode hyphen-separated words back into IPv4 + port bytes
        let parts: Vec<&str> = addr.as_str().split('-').collect();
        if parts.len() != 4 {
            return Err(P2PError::Identity(IdentityError::InvalidFourWordAddress(
                format!("Expected 4 words, got {}", parts.len()).into(),
            )));
        }
        let encoding = four_word_networking::FourWordEncoding::new(
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].to_string(),
            parts[3].to_string(),
        );
        let (ip, port) = four_word_networking::FourWordEncoder::new()
            .decode_ipv4(&encoding)
            .map_err(|e| {
                P2PError::Identity(IdentityError::InvalidFourWordAddress(
                    format!("{}", e).into(),
                ))
            })?;
        let mut out = Vec::with_capacity(6);
        out.extend_from_slice(&ip.octets());
        out.extend_from_slice(&port.to_be_bytes());
        Ok(out)
    }
}

impl From<&str> for FourWordAddress {
    fn from(s: &str) -> Self {
        FourWordAddress(s.to_lowercase())
    }
}

impl From<String> for FourWordAddress {
    fn from(s: String) -> Self {
        FourWordAddress(s.to_lowercase())
    }
}
