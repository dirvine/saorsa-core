# Migration to PQC-Only (saorsa-core)

This guide summarizes changes migrating from classical cryptography to PQC-only using `saorsa-pqc` and ant‑quic.

## Summary of Changes
- Signatures: classical → ML‑DSA (saorsa-pqc via ant‑quic integration)
- Key Exchange: classical ECDH → ML‑KEM (saorsa-pqc via ant‑quic integration)
- Symmetric Encryption: AES‑256‑GCM → ChaCha20‑Poly1305 (`saorsa-pqc`)
- HKDF: Use `saorsa_pqc::hkdf::Hkdf`

## Persistence Metadata
- Algorithm identifier `0x01` now denotes `ChaCha20Poly1305`.
- Legacy classical and hybrid enum variants removed from runtime config.

## Key Derivation
- `src/key_derivation.rs` now derives ML‑DSA keypairs deterministically via HKDF.
- Classical key derivations removed.

## Identity and Messaging
- `IdentityManager` ML‑DSA signing/verification.
- Messaging key exchange: PQC-only ML‑KEM skeleton; requires PQC pubkeys in DHT.

## Action Items for Integrators
- Update any code expecting classical signatures/keys to ML‑DSA.
- Ensure DHT publishes necessary PQC public keys for ML‑KEM.
- For persistence readers, recognize `0x01` as ChaCha20‑Poly1305 and parse nonce+ciphertext framing.
