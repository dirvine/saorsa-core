# Saorsa Core - Project Overview

## Purpose
Saorsa Core is a comprehensive P2P networking library designed for the Saorsa platform. It provides distributed storage, networking, and communication capabilities with a focus on security, performance, and adaptive routing.

## Key Features
- **DHT (Distributed Hash Table)**: Advanced DHT implementation with RSPS (Root-Scoped Provider Summaries)
- **Placement System**: Intelligent shard placement with EigenTrust integration and Byzantine fault tolerance
- **QUIC Transport**: High-performance networking with ant-quic (v0.8.1) 
- **Post-Quantum Cryptography**: NIST Level 3 quantum-resistant security (ML-DSA-65, ML-KEM-768)
- **Four-Word Addresses**: Human-readable network addresses

- **WebRTC over QUIC**: Advanced real-time media streaming
- **Adaptive Networking**: ML-driven routing with Thompson Sampling and Q-Learning
- **Geographic Routing**: Location-aware peer selection
- **Identity Management**: Ed25519-based identity system with quantum resistance
- **Secure Storage**: Database persistence with SQLx
- **Monitoring**: Prometheus metrics integration

## Technology Stack
- **Language**: Rust (2024 edition)
- **Version**: 0.3.5 (published on crates.io)
- **Networking**: ant-quic 0.8.1 (QUIC with PQC)
- **Database**: SQLite via SQLx 0.8
- **Cryptography**: Ed25519, X25519, ML-DSA-65, ML-KEM-768
- **Async Runtime**: Tokio 1.35
- **Testing**: Cargo test with proptest for property-based testing
- **Documentation**: docs.rs

## Target Use Cases
- Decentralized applications requiring P2P networking
- Secure data storage and retrieval systems
- Real-time communication platforms
- Applications requiring post-quantum security

## Architecture
Multi-layer architecture with transport, DHT, adaptive networking, identity management, and application layers.