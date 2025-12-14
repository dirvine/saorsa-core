# Phase 3: zkVM Integration Design

## Executive Summary

This document outlines the design for Phase 3 of the Entangled Attestation system:
integrating zero-knowledge proofs using the SP1 zkVM to prove correct EntangledId
derivation without revealing private inputs.

## zkVM Selection: SP1

### Why SP1 over RISC Zero?

| Criteria | SP1 | RISC Zero |
|----------|-----|-----------|
| **Performance** | 4-28x faster on benchmarks | Baseline |
| **Cryptography** | STARKs (post-quantum secure) | STARKs |
| **Proof wrapping** | STARK → Groth16/PLONK (optional) | Similar |
| **Off-chain verify** | `sp1-verifier` crate | Custom |
| **License** | MIT/Apache-2.0 | Apache-2.0 |
| **Maturity** | Production (Aug 2024) | Production |

**Key Decision**: SP1's STARK-based proofs provide **post-quantum security** at the
proof layer, aligning with our PQC-first mandate. The underlying proof system
doesn't rely on elliptic curve assumptions.

## Hardware Requirements & Proving Strategy

### Default: CPU-Only Proving (No GPU Required)

SP1 supports CPU-only proof generation using AVX (x86) or NEON (ARM) instruction
sets. **GPU is optional acceleration, not a requirement.**

| Proof Type | CPU Cores | RAM | GPU |
|------------|-----------|-----|-----|
| Core/Compress | 16+ | 16GB | **Optional** |
| Groth16/PLONK | 16+ | 16-32GB | **Optional** |

### Proof Caching Strategy

**Critical insight**: Proofs are generated **once per binary version**, not per
connection or message. This makes CPU-only proving entirely practical:

```
Node starts with binary v1.2.3
         │
         ▼
    Generate proof (ONCE)
    • CPU: 10-60 minutes
    • GPU: 1-5 minutes (if available)
         │
         ▼
    Cache proof to disk
    ~/.saorsa/attestation_proof.bin
         │
         ▼
    Reuse cached proof for ALL connections
    (valid until binary changes)
         │
         ▼
    Binary updates to v1.2.4
         │
         ▼
    Invalidate cache, generate NEW proof
```

### Node Startup Behavior

1. **Check cache**: Does `attestation_proof.bin` exist and match current binary?
2. **If valid**: Load cached proof, start immediately
3. **If invalid/missing**: Generate proof in background, operate in "pending" mode
4. **Pending mode**: Node can verify others' proofs but its own proof is marked as pending

This ensures:
- Nodes with capable hardware can self-prove
- Proof generation doesn't block node startup
- Network remains functional during proof generation

### Post-Quantum Security Analysis

Our attestation system maintains PQC security:

1. **Identity Binding**: ML-DSA-65 public key (PQC signature scheme)
2. **Derivation**: BLAKE3 hash (quantum-resistant)
3. **Proofs**: STARKs (post-quantum secure, no ECC)

**Note**: While SP1 offers Groth16/PLONK wrapping for EVM verification (which uses
BN254 curves), we will use **Core STARK proofs** for off-chain P2P verification,
maintaining post-quantum security throughout.

## Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          saorsa-attestation-guest                           │
│                        (SP1 Guest Program - RISC-V)                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  Private Inputs (witness):                                                  │
│    - public_key: [u8; 1952]  (ML-DSA-65)                                   │
│    - binary_hash: [u8; 32]                                                  │
│    - nonce: u64                                                             │
│    - allowed_binaries: Vec<[u8; 32]> (optional)                            │
│                                                                             │
│  Computation:                                                               │
│    1. entangled_id = derive_entangled_id(pk, binary_hash, nonce)           │
│    2. public_key_hash = BLAKE3(public_key)                                  │
│    3. if allowlist: verify_binary_allowlist(binary_hash, allowed)          │
│                                                                             │
│  Public Outputs (committed):                                                │
│    - entangled_id: [u8; 32]                                                 │
│    - binary_hash: [u8; 32]                                                  │
│    - public_key_hash: [u8; 32]                                              │
│    - proof_timestamp: u64                                                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ SP1 Proof
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              saorsa-core                                    │
│                        (Proof Generation & Verification)                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  AttestationProver:                                                         │
│    - generate_proof(witness) -> SP1CoreProof                               │
│    - uses ProverClient with Core proof type (STARK, PQ-secure)             │
│                                                                             │
│  AttestationVerifier:                                                       │
│    - verify_proof(proof, expected_id) -> bool                              │
│    - uses sp1-verifier for off-chain verification                          │
│    - checks freshness, binary allowlist, ID match                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Crate Structure

```
saorsa-attestation-guest/    # New crate - SP1 guest program
├── Cargo.toml
├── src/
│   └── main.rs              # Guest entrypoint
└── build.rs                 # ELF compilation

saorsa-logic/                # Existing - pure derivation logic
├── src/
│   ├── attestation.rs       # derive_entangled_id, verify_*, xor_distance
│   └── ...

saorsa-core/                 # Existing - host-side prover/verifier
├── src/
│   └── attestation/
│       ├── mod.rs
│       ├── zkvm.rs          # Proof structures (Phase 2)
│       ├── prover.rs        # NEW: AttestationProver
│       └── verifier.rs      # NEW: AttestationVerifier
```

## SP1 Guest Program

### Dependencies

```toml
# saorsa-attestation-guest/Cargo.toml
[package]
name = "saorsa-attestation-guest"
version = "0.1.0"
edition = "2021"

[dependencies]
sp1-zkvm = "4.0"
saorsa-logic = { version = "0.1", default-features = false, features = ["zkvm"] }
serde = { version = "1.0", default-features = false, features = ["derive", "alloc"] }
```

### Guest Program Code

```rust
// saorsa-attestation-guest/src/main.rs
#![no_main]
sp1_zkvm::entrypoint!(main);

use saorsa_logic::attestation::{derive_entangled_id, verify_binary_allowlist};
use serde::{Deserialize, Serialize};

/// Private inputs read from prover
#[derive(Deserialize)]
struct Witness {
    public_key: Vec<u8>,      // ML-DSA-65: 1952 bytes
    binary_hash: [u8; 32],
    nonce: u64,
    allowed_binaries: Vec<[u8; 32]>,
    timestamp: u64,
}

/// Public outputs committed to proof
#[derive(Serialize)]
struct PublicOutputs {
    entangled_id: [u8; 32],
    binary_hash: [u8; 32],
    public_key_hash: [u8; 32],
    proof_timestamp: u64,
}

pub fn main() {
    // Read private witness from prover
    let witness: Witness = sp1_zkvm::io::read();

    // 1. Derive entangled ID using saorsa-logic
    let entangled_id = derive_entangled_id(
        &witness.public_key,
        &witness.binary_hash,
        witness.nonce,
    );

    // 2. Hash the public key (commits to it without revealing)
    let public_key_hash = blake3_hash(&witness.public_key);

    // 3. Verify binary allowlist if provided
    if !witness.allowed_binaries.is_empty() {
        verify_binary_allowlist(&witness.binary_hash, &witness.allowed_binaries)
            .expect("binary not in allowlist");
    }

    // 4. Commit public outputs
    let outputs = PublicOutputs {
        entangled_id,
        binary_hash: witness.binary_hash,
        public_key_hash,
        proof_timestamp: witness.timestamp,
    };

    sp1_zkvm::io::commit(&outputs);
}

/// BLAKE3 hash helper (no_std compatible)
fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}
```

## Host-Side Implementation

### Proof Generation (saorsa-core)

```rust
// src/attestation/prover.rs
use sp1_sdk::{ProverClient, SP1Stdin, SP1CoreProof};

pub struct AttestationProver {
    client: ProverClient,
    pk: ProvingKey,
    vk: VerifyingKey,
}

impl AttestationProver {
    pub fn new() -> Result<Self, AttestationError> {
        let client = ProverClient::new();
        // ELF is embedded at compile time
        let (pk, vk) = client.setup(ATTESTATION_GUEST_ELF);
        Ok(Self { client, pk, vk })
    }

    pub fn generate_proof(
        &self,
        witness: &AttestationProofWitness,
    ) -> Result<AttestationProof, AttestationError> {
        let mut stdin = SP1Stdin::new();
        stdin.write(witness);

        // Generate Core STARK proof (post-quantum secure)
        let proof = self.client
            .prove(&self.pk, stdin)
            .core()  // STARK proof, not Groth16
            .run()?;

        Ok(AttestationProof {
            proof_bytes: proof.bytes(),
            public_values: proof.public_values,
            vkey_hash: self.vk.hash(),
        })
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.vk
    }
}
```

### Proof Verification (saorsa-core)

```rust
// src/attestation/verifier.rs
use sp1_verifier::CoreProofVerifier;

pub struct AttestationVerifier {
    vkey_hash: [u8; 32],
    allowed_binaries: Vec<[u8; 32]>,
    max_proof_age_secs: u64,
}

impl AttestationVerifier {
    pub fn verify(
        &self,
        proof: &AttestationProof,
        expected_entangled_id: &[u8; 32],
        current_time: u64,
    ) -> AttestationProofResult {
        // 1. Verify the SP1 proof cryptographically
        let result = CoreProofVerifier::verify(
            &proof.proof_bytes,
            &proof.public_values,
            &proof.vkey_hash,
        );

        if result.is_err() {
            return AttestationProofResult::InvalidProof;
        }

        // 2. Decode public outputs
        let outputs: PublicOutputs = decode(&proof.public_values)?;

        // 3. Check EntangledId matches
        if &outputs.entangled_id != expected_entangled_id {
            return AttestationProofResult::IdMismatch;
        }

        // 4. Check freshness
        if !is_fresh(outputs.proof_timestamp, current_time, self.max_proof_age_secs) {
            return AttestationProofResult::Stale;
        }

        // 5. Check binary allowlist
        if !self.allowed_binaries.is_empty()
            && !self.allowed_binaries.contains(&outputs.binary_hash) {
            return AttestationProofResult::BinaryNotAllowed;
        }

        AttestationProofResult::Valid
    }
}
```

## Security Considerations

### What the Proof Demonstrates

1. **Correct Derivation**: The prover knows inputs that hash to the claimed EntangledId
2. **Key Binding**: The proof is bound to a specific public key hash
3. **Binary Attestation**: Optionally proves the binary is in an allowlist
4. **Freshness**: Timestamp prevents replay of old proofs

### What the Proof Hides (Zero-Knowledge)

1. **Full Public Key**: Only the hash is revealed (saves 1952 bytes)
2. **Nonce**: The derivation nonce remains private
3. **Allowlist Choice**: Which specific binary from the allowlist (if any)

### Post-Quantum Security Properties

| Component | Algorithm | Post-Quantum? |
|-----------|-----------|---------------|
| Identity key | ML-DSA-65 | Yes (NIST Level 3) |
| Derivation | BLAKE3 | Yes (hash-based) |
| Proofs | STARKs | Yes (no ECC) |
| Verification | STARKs | Yes (no ECC) |

**Important**: We use Core STARK proofs, NOT Groth16/PLONK wrapping, to maintain
post-quantum security for P2P verification.

## Implementation Plan (TDD)

### Phase 3.1: Guest Program
1. Create `saorsa-attestation-guest` crate
2. Write guest program using saorsa-logic
3. Test compilation to RISC-V ELF
4. Verify deterministic execution

### Phase 3.2: Prover Integration
1. Write failing tests for proof generation
2. Add sp1-sdk dependency to saorsa-core
3. Implement AttestationProver
4. Test proof generation locally

### Phase 3.3: Verifier Integration
1. Write failing tests for proof verification
2. Add sp1-verifier dependency
3. Implement AttestationVerifier
4. Test full prove/verify cycle

### Phase 3.4: Protocol Integration
1. Add proof to handshake exchange
2. Implement soft enforcement (log invalid proofs)
3. Add metrics for proof timing
4. Integration tests with mock network

## Dependencies

### saorsa-attestation-guest

```toml
[dependencies]
sp1-zkvm = "4.0"
saorsa-logic = { version = "0.1", default-features = false }
serde = { version = "1.0", default-features = false, features = ["derive", "alloc"] }
```

### saorsa-core (additions)

```toml
[dependencies]
# SP1 SDK for proof generation (optional feature)
sp1-sdk = { version = "4.0", optional = true }

# SP1 verifier for off-chain verification
sp1-verifier = { version = "4.0", default-features = false }

[features]
zkvm-prover = ["dep:sp1-sdk"]  # Heavy dependency, optional
```

## Proof Size & Performance Estimates

| Proof Type | Size | Verification Time | PQ-Secure? |
|------------|------|-------------------|------------|
| Core STARK | ~1 MB | ~100ms | Yes |
| Compressed | ~200 KB | ~50ms | Yes |
| Groth16 | ~260 bytes | ~10ms | No (ECC) |

**Recommendation**: Use Compressed STARK proofs for P2P exchange (good balance of
size and PQ security). Core proofs if size is not a concern.

## References

- [SP1 Documentation](https://docs.succinct.xyz/docs/sp1/introduction)
- [SP1 GitHub](https://github.com/succinctlabs/sp1)
- [SP1 Off-chain Verification](https://docs.succinct.xyz/docs/sp1/generating-proofs/off-chain-verification)
- [saorsa-logic Phase 2](../src/attestation/zkvm.rs)
