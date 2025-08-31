# Security Model

This document summarizes the Saorsa Core security posture and controls.

- Cryptography: Pure post-quantum
  - Signatures: ML‑DSA‑65 (FIPS 204) via `saorsa-pqc`
  - KEM: ML‑KEM‑768 (FIPS 203)
  - Symmetric: ChaCha20‑Poly1305 with PQC-derived keys
  - Hashing: BLAKE3 for content addressing

- Identity & Attestation
  - NodeId binds to ML‑DSA public key: `NodeId = blake3(serialize(pubkey))`
  - Join validation verifies binding; messages require signatures and basic anti‑replay

- Network Protections
  - Input validation for addresses, sizes, paths, and API inputs
  - Rate limiting (per‑IP, per‑node, global) and blacklisting
  - Eclipse detection (routing diversity + pattern heuristics)
  - IP diversity enforcement (/64, /48, /32, ASN, geo) with pluggable GeoIP provider

- Storage & DHT
  - Record size limits; canonical serialization; signature verification
  - Replication based on trust/perf/diversity; continuous audit/repair

- Memory Safety
  - Secure memory pools for sensitive material
  - Zeroization on drop where applicable

- Observability
  - Structured security audit events and metrics (Prometheus)

Planned hardening
- Unified rate limiter shared across layers
- Full monotonic counter integration for anti‑replay
- ASN/GeoIP provider with caching and policy hooks

