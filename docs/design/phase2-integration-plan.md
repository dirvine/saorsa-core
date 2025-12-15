# Phase 2: saorsa-logic Integration Plan

## Executive Summary

Phase 2 integrates `saorsa-logic` v0.1.0 into `saorsa-core` and prepares the architecture for zkVM proof generation. The key insight is that **pure derivation logic** belongs in `saorsa-logic` (zkVM-compatible), while **networking, serialization, and identity management** remain in `saorsa-core`.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         saorsa-node                                  │
│        (Full node: storage, payment, upgrade verification)           │
├─────────────────────────────────────────────────────────────────────┤
│                         saorsa-core                                  │
│   (P2P networking, DHT, transport, identity management)              │
│                                                                      │
│   ┌───────────────────────────────────────────────────────────────┐ │
│   │ EntangledId (wrapper)              NodeIdentity               │ │
│   │ - Serialization (serde)            - Key management           │ │
│   │ - Display/Debug                    - Signing operations       │ │
│   │ - NodeId conversion                - Network identity         │ │
│   │ - XOR distance for DHT             - to_entangled_id()        │ │
│   │                                                               │ │
│   │         ▼ delegates derivation to ▼                           │ │
│   └───────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────────┤
│                        saorsa-logic                                  │
│              (Pure computation - no_std, zkVM ready)                 │
│                                                                      │
│   ┌───────────────────────────────────────────────────────────────┐ │
│   │ derive_entangled_id(pk, binary_hash, nonce) → [u8; 32]       │ │
│   │ verify_entangled_id(id, pk, binary_hash, nonce) → bool       │ │
│   │ verify_binary_allowlist(hash, allowlist) → Result            │ │
│   │ xor_distance(a, b) → [u8; 32]                                │ │
│   │                                                               │ │
│   │ compute_content_hash(data) → [u8; 32]                        │ │
│   │ verify_content_hash(data, hash) → Result                     │ │
│   │                                                               │ │
│   │ MerkleProof, build_tree_root, generate_proof, verify_proof   │ │
│   └───────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────────┤
│                      zkVM Guest (Phase 3)                            │
│                 (SP1 / RISC Zero proving environment)                │
│                                                                      │
│   Uses saorsa-logic to prove:                                        │
│   - EntangledId was correctly derived                                │
│   - Binary hash is in allowlist                                      │
│   - Content hashes match claimed values                              │
└─────────────────────────────────────────────────────────────────────┘
```

## Current State Analysis

### saorsa-core/src/attestation/entangled_id.rs

**Current Implementation:**
```rust
fn compute_id(public_key: &MlDsaPublicKey, binary_hash: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(public_key.as_bytes());  // Full PK (1952 bytes)
    hasher.update(binary_hash);             // 32 bytes
    hasher.update(&nonce.to_le_bytes());    // 8 bytes
    *hasher.finalize().as_bytes()
}
```

**saorsa-logic equivalent:**
```rust
// saorsa_logic::attestation::derive_entangled_id
pub fn derive_entangled_id(
    public_key: &[u8],           // Any length (will hash full bytes)
    binary_hash: &[u8; 32],
    nonce: u64
) -> [u8; 32]
```

**Key Observation:** The formulas are identical! Both compute `BLAKE3(PK || binary_hash || nonce)`.

### Hash Algorithm Inconsistency

| Component | Current | saorsa-logic | Action |
|-----------|---------|--------------|--------|
| EntangledId | BLAKE3 | BLAKE3 | ✅ Match |
| NodeId | SHA-256 | N/A | Keep as-is (legacy) |
| Binary manifest | SHA-256 (hex) | BLAKE3 | Consider migration |
| Content address | SHA-256 (XorName) | BLAKE3 | Consider migration |

**Decision:** Phase 2 focuses on EntangledId integration. Content addressing standardization deferred to Phase 3.

## Integration Tasks

### Task 1: Add saorsa-logic Dependency

**File:** `saorsa-core/Cargo.toml`

```toml
[dependencies]
# ... existing deps ...

# zkVM-compatible logic crate
saorsa-logic = { version = "0.1", features = ["std", "alloc"] }
```

### Task 2: Refactor EntangledId Derivation

**File:** `saorsa-core/src/attestation/entangled_id.rs`

**Before:**
```rust
use blake3;

impl EntangledId {
    fn compute_id(public_key: &MlDsaPublicKey, binary_hash: &[u8; 32], nonce: u64) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(public_key.as_bytes());
        hasher.update(binary_hash);
        hasher.update(&nonce.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    pub fn derive(public_key: &MlDsaPublicKey, binary_hash: &[u8; 32], nonce: u64) -> Self {
        let id = Self::compute_id(public_key, binary_hash, nonce);
        Self { id, binary_hash: *binary_hash, nonce }
    }
}
```

**After:**
```rust
use saorsa_logic::attestation::{
    derive_entangled_id as derive_id_raw,
    verify_entangled_id as verify_id_raw,
    xor_distance as compute_xor_distance,
    ENTANGLED_ID_SIZE,
    HASH_SIZE,
};

impl EntangledId {
    /// Derive an EntangledId from its components.
    ///
    /// Uses saorsa-logic for zkVM-compatible derivation.
    pub fn derive(public_key: &MlDsaPublicKey, binary_hash: &[u8; 32], nonce: u64) -> Self {
        let id = derive_id_raw(public_key.as_bytes(), binary_hash, nonce);
        Self {
            id,
            binary_hash: *binary_hash,
            nonce,
        }
    }

    /// Verify this EntangledId against a public key.
    pub fn verify(&self, public_key: &MlDsaPublicKey) -> bool {
        verify_id_raw(&self.id, public_key.as_bytes(), &self.binary_hash, self.nonce)
    }

    /// Compute XOR distance for DHT routing.
    pub fn xor_distance(&self, other: &Self) -> [u8; ENTANGLED_ID_SIZE] {
        compute_xor_distance(&self.id, &other.id)
    }
}
```

### Task 3: Update Binary Allowlist Verification

**File:** `saorsa-core/src/attestation/config.rs`

**Add integration:**
```rust
use saorsa_logic::attestation::verify_binary_allowlist;

impl AttestationConfig {
    /// Check if a binary hash is allowed.
    pub fn is_binary_allowed(&self, binary_hash: &[u8; 32]) -> bool {
        if self.allowed_binary_hashes.is_empty() {
            return true; // Empty allowlist = all allowed
        }
        verify_binary_allowlist(binary_hash, &self.allowed_binary_hashes).is_ok()
    }
}
```

### Task 4: Re-export Constants

**File:** `saorsa-core/src/attestation/mod.rs`

```rust
// Re-export saorsa-logic constants for consistency
pub use saorsa_logic::attestation::{
    ENTANGLED_ID_SIZE,
    HASH_SIZE,
    ML_DSA_65_PUBLIC_KEY_SIZE,
};
```

### Task 5: Update Tests to Use saorsa-logic Types

Ensure all existing tests pass with the new implementation:
- `test_derive_deterministic`
- `test_different_keys_different_ids`
- `test_different_binaries_different_ids`
- `test_verification`
- `test_verification_wrong_key`
- `test_serialization_roundtrip`

### Task 6: Document zkVM Proof Structure

**File:** `saorsa-core/src/attestation/zkvm.rs` (new file)

```rust
//! zkVM proof structures for Entangled Attestation.
//!
//! This module defines the public inputs/outputs for zkVM proofs.
//! Actual proof generation will be in Phase 3.

use saorsa_logic::attestation::{AttestationOutput, EntangledIdComponents};
use serde::{Deserialize, Serialize};

/// Public inputs committed to a zkVM attestation proof.
///
/// These values are visible to verifiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationProofPublicInputs {
    /// The derived EntangledId (output of derivation)
    pub entangled_id: [u8; 32],

    /// Hash of the binary (for allowlist checking)
    pub binary_hash: [u8; 32],

    /// Hash of the public key (binding without revealing full key)
    pub public_key_hash: [u8; 32],

    /// Timestamp when proof was generated
    pub proof_timestamp: u64,
}

/// Private witness data for proof generation.
///
/// These values are known only to the prover.
#[derive(Debug, Clone)]
pub struct AttestationProofWitness {
    /// Full public key bytes (1952 for ML-DSA-65)
    pub public_key: Vec<u8>,

    /// Nonce used in derivation
    pub nonce: u64,

    /// Binary allowlist for verification
    pub allowed_binaries: Vec<[u8; 32]>,
}

impl AttestationProofPublicInputs {
    /// Create from saorsa-logic output.
    pub fn from_logic_output(output: AttestationOutput, timestamp: u64) -> Self {
        Self {
            entangled_id: output.entangled_id,
            binary_hash: output.binary_hash,
            public_key_hash: output.public_key_hash,
            proof_timestamp: timestamp,
        }
    }
}

/// What the zkVM guest program proves:
///
/// 1. EntangledId = BLAKE3(public_key || binary_hash || nonce)
/// 2. binary_hash ∈ allowed_binaries (if allowlist provided)
/// 3. public_key_hash = BLAKE3(public_key)
///
/// The verifier learns:
/// - The EntangledId is correctly derived
/// - The binary is authorized (if allowlist checking enabled)
/// - The prover knows the full public key
///
/// The verifier does NOT learn:
/// - The full public key (only its hash)
/// - The nonce used
/// - Which specific binary from the allowlist
```

## Testing Strategy

### Unit Tests
- All existing tests must pass unchanged
- Add tests verifying saorsa-logic integration produces identical results

### Integration Tests
```rust
#[test]
fn test_saorsa_logic_derivation_matches_original() {
    let pk = MlDsaPublicKey::generate();
    let binary_hash = [42u8; 32];
    let nonce = 12345u64;

    // Old method (removed after verification)
    let old_id = old_compute_id(&pk, &binary_hash, nonce);

    // New method via saorsa-logic
    let new_id = saorsa_logic::attestation::derive_entangled_id(
        pk.as_bytes(),
        &binary_hash,
        nonce
    );

    assert_eq!(old_id, new_id, "derivation must be identical");
}
```

### Property-Based Tests
```rust
proptest! {
    #[test]
    fn prop_derivation_deterministic(
        pk_seed in any::<[u8; 32]>(),
        binary_hash in any::<[u8; 32]>(),
        nonce in any::<u64>()
    ) {
        let pk = MlDsaPublicKey::from_seed(&pk_seed);

        let id1 = EntangledId::derive(&pk, &binary_hash, nonce);
        let id2 = EntangledId::derive(&pk, &binary_hash, nonce);

        prop_assert_eq!(id1, id2);
    }
}
```

## Migration Path

### Phase 2A: Integration (This Phase)
1. Add saorsa-logic dependency
2. Refactor derivation to use saorsa-logic
3. Keep all existing APIs stable
4. 100% backward compatible

### Phase 2B: Documentation & Cleanup
1. Document zkVM proof structure
2. Remove duplicate blake3 direct usage where possible
3. Update architecture documentation

### Phase 3: zkVM Proof Generation (Future)
1. Create SP1/RISC Zero guest programs
2. Implement proof generation in saorsa-core
3. Add proof verification to network protocol
4. Transition to Hard enforcement mode

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Derivation mismatch | Low | Critical | Comprehensive testing, property-based tests |
| Performance regression | Low | Medium | Benchmark before/after |
| API breakage | None | N/A | Wrapper pattern preserves all APIs |
| Dependency conflicts | Low | Low | saorsa-logic has minimal deps |

## Success Criteria

- [ ] All 294 existing tests pass
- [ ] No API changes (backward compatible)
- [ ] EntangledId derivation uses saorsa-logic
- [ ] Binary allowlist uses saorsa-logic
- [ ] XOR distance uses saorsa-logic
- [ ] zkVM proof structure documented
- [ ] CI remains 100% green
- [ ] No performance regression (benchmark)

## Timeline Estimate

| Task | Effort |
|------|--------|
| Add dependency, basic integration | 1-2 hours |
| Refactor EntangledId | 2-3 hours |
| Update tests | 1-2 hours |
| Documentation | 1 hour |
| CI validation | 1 hour |
| **Total** | **6-9 hours** |

## Deferred to Phase 3

1. **Content addressing migration** - Moving from SHA-256 XorName to BLAKE3
2. **SP1/RISC Zero guest programs** - Actual proof generation
3. **Network protocol changes** - Proof exchange in handshake
4. **Hard enforcement mode** - Rejecting unattested nodes
5. **VDF heartbeats** - Continuous attestation proofs
