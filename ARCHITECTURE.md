# Architecture Overview

This repository is a Rust library crate that provides a modular, post‑quantum secure P2P foundation. It favors clear boundaries, strict linting (no panics in lib code), and testable components.

## Goals & Scope
- Reliable QUIC transport, DHT routing, dual‑stack endpoints (IPv6 + IPv4), and human‑readable endpoint encoding.
- Strong security defaults using saorsa‑pqc, safe memory, and validation.
- Extensible higher‑level features (chat, messaging, projects) on the same core.

## Layered Architecture
- Transport & Networking: `transport/`, `network/` (QUIC, NAT traversal, events, dual‑stack listeners, Happy Eyeballs dialing).
- Routing & Discovery: `dht/`, `dht_network_manager/`, `peer_record/`.
- Security: `quantum_crypto/`, `security.rs`, `secure_memory.rs`, `key_derivation.rs`, `encrypted_key_storage.rs`.
- Data & Storage: `storage/`, `persistence/`, `placement/` (orchestrator, strategies, records).
- Application Modules: `chat/`, `messaging/`, `discuss/`, `projects/`, `threshold/`.
- Cross‑cutting: `validation.rs`, `production.rs`, `health/`, `utils/`, `config.rs`, `error.rs`.

## Module Map (selected)
- Core exports live in `src/lib.rs`; add new modules there and keep names `snake_case`.
- Health endpoints: `health/` (Axum); metrics behind `metrics` default feature.
- PQC: `quantum_crypto/` exports saorsa‑pqc types and compatibility shims.

## Data Flow
```
[Apps: chat|messaging|projects]
          |        commands/events
          v
     [network]  <->  [dht_network_manager]  <->  [dht]
          |
      [transport (QUIC)]
          |
[placement] <-> [storage|persistence]
          ^
     [validation|security|secure_memory]
```

## Notes
- Four‑word encoding/decoding is handled by the `four-word-networking` crate and is used only for network endpoints. Messaging uses a separate `UserHandle` to represent users.
- IPv4+port encodes to 4 words; decoding returns both IP and port. IPv6 word count is decided by the crate.

## Concurrency & Errors
- Async with `tokio`; prefer `Send + Sync` types and bounded channels where applicable.
- Errors use `thiserror`/`anyhow` in tests; return precise errors in library code.
- Logging with `tracing`; avoid `unwrap/expect/panic` in lib paths (CI enforces).

## Observability & Testing
- Health: `health::HealthServer` (enable metrics with `--features metrics` or default).
- Tests: unit tests in modules, integration tests under `tests/`; property tests via `proptest`/`quickcheck`.
- Fuzz parsers/validators in `fuzz/` using `cargo-fuzz`.
- Mutation testing configured by `mutation-testing.toml` (use `cargo mutants`).

## Build Targets
- Library only; examples under `examples/`, benches under `benches/`.
- Use `./scripts/local_ci.sh` to run a safe, end‑to‑end local CI.
