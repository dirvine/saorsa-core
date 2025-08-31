# Production Guide

This guide outlines recommended settings and operational practices for running Saorsa Core in production.

- Resource Limits (`production.rs`)
  - Configure max connections, timeouts, health/metrics intervals
  - Enable performance tracking and auto‑cleanup

- Metrics & Health
  - Default bind: set via `SAORSA_METRICS_HOST` and `SAORSA_METRICS_PORT`
  - Expose behind auth/proxy; avoid public exposure by default
  - Monitor security counters (rate‑limit violations, eclipse detections)

- Networking
  - Prefer dual‑stack (IPv6 + IPv4); Happy Eyeballs dialing
  - Bootstrap discovery should point at trusted nodes

- Security
  - PQC‑only crypto (ML‑DSA signatures; ML‑KEM key exchange)
  - Enforce join identity verification and message signature checks
  - Configure IP diversity limits; plug in GeoIP/ASN provider

- Operations
  - Run `./scripts/local_ci.sh` before releases
  - Enable `cargo audit` and coverage in CI
  - Alert on sustained increases in error or latency metrics

- Troubleshooting
  - Inspect health endpoints and Prometheus metrics
  - Increase tracing level for targeted modules

