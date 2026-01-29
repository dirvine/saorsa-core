# Phase 5: Binary Encoding Migration

**Phase ID**: phase-5-binary-encoding-migration
**Milestone**: milestone-2-implementation
**Status**: executing
**Created**: 2026-01-29T15:30:00Z

---

## Overview

Migrate message serialization from JSON to bincode for 30-40% size reduction and 2-3x speed improvement.

**Design Document**: `.planning/solution-design/02-binary-encoding-migration.md`

**Key Constraints**:
- No backward compatibility needed (`no_backward_compatibility: true`)
- Breaking change acceptable
- Use bincode exclusively (already a dependency)

**Expected Impact**:
- Small messages: 60% size reduction
- Medium messages: 8-12% reduction
- Serialization: 2-3x faster
- Network bandwidth: 30-40% reduction

---

## Tasks

### Task 1: Create Encoding Module
**File**: `src/messaging/encoding.rs` (new)

**Requirements**:
- Create new module with bincode-only functions
- `encode<T: Serialize>(data: &T) -> Result<Vec<u8>>`
- `decode<T: Deserialize>(bytes: &[u8]) -> Result<T>`
- Proper error handling (no `.unwrap()`)
- Module-level documentation

**Tests Required**:
- Unit tests in same file (`#[cfg(test)]`)
- Roundtrip encode/decode test

**Acceptance Criteria**:
- Zero clippy warnings
- No `.unwrap()` in production code
- All tests pass

---

### Task 2: Update Encryption Module (encrypt_message)
**File**: `src/messaging/encryption.rs`

**Requirements**:
- Import encoding module: `use crate::messaging::encoding::encode;`
- Replace `serde_json::to_vec(message)?` with `encode(message)?`
- Update function at line ~70 (in `encrypt_message`)
- Preserve all other functionality

**Tests Required**:
- Existing tests must still pass
- Verify encrypted message uses bincode

**Acceptance Criteria**:
- Zero clippy warnings
- No test failures
- cargo check passes

---

### Task 3: Update Encryption Module (decrypt_message)
**File**: `src/messaging/encryption.rs`

**Requirements**:
- Import encoding module: `use crate::messaging::encoding::decode;`
- Replace `serde_json::from_slice::<RichMessage>(&plaintext)?` with `decode::<RichMessage>(&plaintext)?`
- Update function at line ~339 (in `decrypt_message`)
- Preserve all other functionality

**Tests Required**:
- Existing tests must still pass
- Verify decrypted message from bincode

**Acceptance Criteria**:
- Zero clippy warnings
- No test failures
- cargo check passes

---

### Task 4: Remove JSON from Message Paths
**Files**: Various in `src/messaging/`

**Requirements**:
- Grep for `serde_json::to_vec` in `src/messaging/`
- Grep for `serde_json::from_slice` in `src/messaging/`
- Remove any remaining JSON serialization in message hot paths
- Keep JSON in non-message contexts (config, etc.)

**Tests Required**:
- All existing tests pass
- No JSON in critical message paths

**Acceptance Criteria**:
- Zero uses of `serde_json::to_vec` for RichMessage
- Zero uses of `serde_json::from_slice` for RichMessage
- All tests pass

---

### Task 5: Add Unit Tests for Encoding
**File**: `src/messaging/encoding.rs`

**Requirements**:
- `test_encode_decode_roundtrip()` - RichMessage encode/decode
- `test_encode_empty_message()` - Edge case: empty message
- `test_decode_invalid_data()` - Error handling test
- `test_size_comparison()` - Measure bincode vs JSON size

**Tests Required**:
- All new tests pass
- Tests use property-based testing where applicable

**Acceptance Criteria**:
- 100% test coverage on encoding module
- All tests pass with `cargo test`

---

### Task 6: Add Integration Test for E2E Flow
**File**: `tests/binary_encoding_integration_test.rs` (new)

**Requirements**:
- Test full encrypt/decrypt flow with bincode
- Create RichMessage → Encrypt → Decrypt → Verify
- Test with various message sizes (small, medium, large)
- Verify data integrity throughout

**Tests Required**:
- E2E encryption/decryption with bincode
- Message integrity verification

**Acceptance Criteria**:
- Integration test passes
- No data corruption
- cargo test passes

---

### Task 7: Update Benchmark for Performance
**File**: `benches/encoding_benchmark.rs` (new or update existing)

**Requirements**:
- Benchmark bincode serialization speed
- Benchmark bincode deserialization speed
- Benchmark message size (bytes)
- Compare with JSON (if still available for comparison)

**Tests Required**:
- Benchmark compiles and runs
- Results show performance improvement

**Acceptance Criteria**:
- Benchmarks run: `cargo bench --bench encoding_benchmark`
- No compilation errors

---

### Task 8: Update API Documentation
**Files**: `src/messaging/encoding.rs`, `src/messaging/encryption.rs`

**Requirements**:
- Add module-level docs to `encoding.rs`
- Update function docs in `encryption.rs` to mention bincode
- Add examples showing bincode usage
- Document performance characteristics (30-40% smaller, 2-3x faster)

**Tests Required**:
- cargo doc compiles without warnings

**Acceptance Criteria**:
- Zero documentation warnings: `cargo doc --no-deps`
- All public items documented
- Examples compile

---

## Quality Gates (ALL tasks must pass)

**Build Quality**:
- ✅ `cargo check --all-features --all-targets` - Zero warnings
- ✅ `cargo clippy --all-features --all-targets -- -D warnings` - Zero violations
- ✅ `cargo fmt --check` - Proper formatting

**Test Quality**:
- ✅ `cargo test` - 100% pass rate
- ✅ No ignored or skipped tests
- ✅ Integration tests pass

**Code Quality**:
- ✅ No `.unwrap()` in production code
- ✅ No `.expect()` in production code
- ✅ Proper error handling with `Result<T>`

**Documentation Quality**:
- ✅ `cargo doc --no-deps` - Zero warnings
- ✅ All public APIs documented
- ✅ Examples compile

---

## Review Process (after EACH task)

1. Task complete → Update STATE.json
2. IMMEDIATELY run: `Skill("gsd-review", args: "--task")`
3. Parse review verdict (PASS/FAIL/BLOCKED)
4. If FAIL: Fix findings with code-fixer, re-review
5. If PASS: Commit, continue to next task
6. Maximum 3 review iterations per task

**DO NOT skip review. DO NOT batch tasks.**

---

## Success Criteria (Phase Complete)

1. ✅ All 8 tasks complete
2. ✅ All quality gates pass
3. ✅ Zero compilation errors or warnings
4. ✅ 100% test pass rate
5. ✅ Documentation complete and accurate
6. ✅ Bincode used exclusively for message serialization

---

**Next Phase**: Phase 6 - Integration & Cleanup
**Estimated Duration**: 2-3 hours (autonomous execution)
**Created**: 2026-01-29T15:30:00Z
