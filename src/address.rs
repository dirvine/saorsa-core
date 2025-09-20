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

//! # Address Types
//!
//! This module provides address types for the P2P network using IP:port combinations
//! and four-word human-readable representations.

use std::fmt::{self, Display};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use four_word_networking::FourWordAdaptiveEncoder;

/// Network address that can be represented as IP:port or four-word format
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkAddress {
    /// The socket address (IP + port)
    pub socket_addr: SocketAddr,
    /// Optional four-word representation
    pub four_words: Option<String>,
}

impl NetworkAddress {
    /// Create a new `NetworkAddress` from a `SocketAddr`
    #[must_use]
    pub fn new(socket_addr: SocketAddr) -> Self {
        let four_words = Self::encode_four_words(&socket_addr);
        Self {
            socket_addr,
            four_words,
        }
    }

    /// Create a `NetworkAddress` from an IP address and port
    #[must_use]
    pub fn from_ip_port(ip: IpAddr, port: u16) -> Self {
        let socket_addr = SocketAddr::new(ip, port);
        Self::new(socket_addr)
    }

    /// Create a `NetworkAddress` from IPv4 address and port
    #[must_use]
    pub fn from_ipv4(ip: Ipv4Addr, port: u16) -> Self {
        Self::from_ip_port(IpAddr::V4(ip), port)
    }

    /// Create a `NetworkAddress` from IPv6 address and port
    #[must_use]
    pub fn from_ipv6(ip: Ipv6Addr, port: u16) -> Self {
        Self::from_ip_port(IpAddr::V6(ip), port)
    }

    /// Get the IP address
    #[must_use]
    pub fn ip(&self) -> IpAddr {
        self.socket_addr.ip()
    }

    /// Get the port
    pub fn port(&self) -> u16 {
        self.socket_addr.port()
    }

    /// Get the socket address
    pub fn socket_addr(&self) -> SocketAddr {
        self.socket_addr
    }

    /// Get the four-word representation if available
    pub fn four_words(&self) -> Option<&str> {
        self.four_words.as_deref()
    }

    /// Force regeneration of four-word representation
    pub fn regenerate_four_words(&mut self) {
        self.four_words = Self::encode_four_words(&self.socket_addr);
    }

    /// Encode a SocketAddr to four-word format using four-word-networking
    fn encode_four_words(addr: &SocketAddr) -> Option<String> {
        match FourWordAdaptiveEncoder::new().and_then(|enc| enc.encode(&addr.to_string())) {
            Ok(s) => Some(s.replace(' ', "-")),
            Err(e) => {
                tracing::warn!("Failed to encode address {addr}: {e}");
                None
            }
        }
    }

    /// Decode four-word format to NetworkAddress using four-word-networking
    pub fn from_four_words(words: &str) -> Result<Self> {
        let enc = FourWordAdaptiveEncoder::new()?;
        let normalized = words.replace('-', " ");
        let decoded = enc.decode(&normalized)?; // returns a normalized address string
        let socket_addr: SocketAddr = decoded.parse()?; // must include port
        Ok(Self::new(socket_addr))
    }

    /// Check if this is an IPv4 address
    pub fn is_ipv4(&self) -> bool {
        self.socket_addr.is_ipv4()
    }

    /// Check if this is an IPv6 address
    pub fn is_ipv6(&self) -> bool {
        self.socket_addr.is_ipv6()
    }

    /// Check if this is a loopback address
    pub fn is_loopback(&self) -> bool {
        self.socket_addr.ip().is_loopback()
    }

    /// Check if this is a private/local address
    pub fn is_private(&self) -> bool {
        match self.socket_addr.ip() {
            IpAddr::V4(ip) => ip.is_private(),
            IpAddr::V6(ip) => {
                // Check for unique local addresses (fc00::/7)
                let octets = ip.octets();
                (octets[0] & 0xfe) == 0xfc
            }
        }
    }
}

impl Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref words) = self.four_words {
            write!(f, "{} ({})", self.socket_addr, words)
        } else {
            write!(f, "{}", self.socket_addr)
        }
    }
}

impl FromStr for NetworkAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        // First try to parse as a socket address
        if let Ok(socket_addr) = SocketAddr::from_str(s) {
            return Ok(Self::new(socket_addr));
        }

        // Basic Multiaddr support: /ip4/<ip>/tcp/<port> or /ip6/<ip>/tcp/<port>
        if s.starts_with("/ip4/") || s.starts_with("/ip6/") {
            let parts: Vec<&str> = s.split('/').filter(|p| !p.is_empty()).collect();
            // Expect: ["ip4"|"ip6", ip, "tcp", port]
            #[allow(clippy::collapsible_if)]
            if parts.len() >= 4 && (parts[0] == "ip4" || parts[0] == "ip6") && parts[2] == "tcp" {
                if let Ok(port) = parts[3].parse::<u16>() {
                    // Parse IP
                    let ip_str = parts[1];
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        let socket_addr = SocketAddr::new(ip, port);
                        return Ok(Self::new(socket_addr));
                    }
                }
            }
        }

        // Then try to parse as four-word format
        if let Ok(addr) = Self::from_four_words(s) {
            return Ok(addr);
        }

        Err(anyhow!("Invalid address format: {}", s))
    }
}

impl From<SocketAddr> for NetworkAddress {
    fn from(socket_addr: SocketAddr) -> Self {
        Self::new(socket_addr)
    }
}

impl From<&SocketAddr> for NetworkAddress {
    fn from(socket_addr: &SocketAddr) -> Self {
        Self::new(*socket_addr)
    }
}

impl From<NetworkAddress> for SocketAddr {
    fn from(addr: NetworkAddress) -> Self {
        addr.socket_addr
    }
}

impl From<&NetworkAddress> for SocketAddr {
    fn from(addr: &NetworkAddress) -> Self {
        addr.socket_addr
    }
}

/// Collection of network addresses for a peer
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressBook {
    /// Primary addresses for this peer
    pub addresses: Vec<NetworkAddress>,
    /// Last known good address
    pub last_known_good: Option<NetworkAddress>,
}

impl AddressBook {
    /// Create a new empty address book
    pub fn new() -> Self {
        Self {
            addresses: Vec::new(),
            last_known_good: None,
        }
    }

    /// Create an address book with a single address
    pub fn with_address(address: NetworkAddress) -> Self {
        Self {
            addresses: vec![address.clone()],
            last_known_good: Some(address),
        }
    }

    /// Add an address to the book
    pub fn add_address(&mut self, address: NetworkAddress) {
        if !self.addresses.contains(&address) {
            self.addresses.push(address);
        }
    }

    /// Remove an address from the book
    pub fn remove_address(&mut self, address: &NetworkAddress) {
        self.addresses.retain(|a| a != address);
        if self.last_known_good.as_ref() == Some(address) {
            self.last_known_good = self.addresses.first().cloned();
        }
    }

    /// Update the last known good address
    pub fn update_last_known_good(&mut self, address: NetworkAddress) {
        if self.addresses.contains(&address) {
            self.last_known_good = Some(address);
        }
    }

    /// Get the best address to try first
    pub fn best_address(&self) -> Option<&NetworkAddress> {
        self.last_known_good
            .as_ref()
            .or_else(|| self.addresses.first())
    }

    /// Get all addresses
    pub fn addresses(&self) -> &[NetworkAddress] {
        &self.addresses
    }

    /// Check if the address book is empty
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Get the number of addresses
    pub fn len(&self) -> usize {
        self.addresses.len()
    }
}

impl Default for AddressBook {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for AddressBook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.addresses.is_empty() {
            write!(f, "Empty address book")
        } else {
            write!(
                f,
                "Addresses: [{}]",
                self.addresses
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_network_address_creation() {
        let addr = NetworkAddress::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 8080);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(addr.port(), 8080);
        assert!(addr.is_ipv4());
        assert!(addr.is_loopback());
    }

    #[test]
    fn test_network_address_from_string() {
        let addr = "127.0.0.1:8080".parse::<NetworkAddress>().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_network_address_display() {
        let addr = NetworkAddress::from_ipv4(Ipv4Addr::new(192, 168, 1, 1), 9000);
        let display = addr.to_string();
        assert!(display.contains("192.168.1.1:9000"));
    }

    #[test]
    fn test_address_book() {
        let mut book = AddressBook::new();
        let addr1 = NetworkAddress::from_ipv4(Ipv4Addr::new(192, 168, 1, 1), 9000);
        let addr2 = NetworkAddress::from_ipv4(Ipv4Addr::new(192, 168, 1, 2), 9001);

        book.add_address(addr1.clone());
        book.add_address(addr2.clone());

        assert_eq!(book.len(), 2);
        assert_eq!(book.best_address(), Some(&addr1));

        book.update_last_known_good(addr2.clone());
        assert_eq!(book.best_address(), Some(&addr2));
    }

    #[test]
    fn test_private_address_detection() {
        let private_addr = NetworkAddress::from_ipv4(Ipv4Addr::new(192, 168, 1, 1), 9000);
        assert!(private_addr.is_private());

        let public_addr = NetworkAddress::from_ipv4(Ipv4Addr::new(8, 8, 8, 8), 53);
        assert!(!public_addr.is_private());
    }

    #[test]
    fn test_ipv6_address() {
        let addr = NetworkAddress::from_ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 8080);
        assert!(addr.is_ipv6());
        assert!(addr.is_loopback());
    }
}
