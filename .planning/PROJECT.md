# Message Encoding Optimization Project

## Problem Statement

Triple JSON encoding causes 3.6x message bloat (8KB → 29KB on wire).

### Current Pipeline
1. **RichMessage → JSON** (`src/messaging/service.rs:664`): 8KB → ~10KB
2. **EncryptedMessage → JSON** (`src/messaging/transport.rs:246`): 10KB → ~20KB  
3. **Protocol wrapper → JSON** (`src/network.rs:1645-1669`): 20KB → ~29KB

**Result**: 8KB payload becomes 29KB (3.6x overhead!)

### Root Cause (network.rs:1645-1669)

```rust
fn create_protocol_message(&self, protocol: &str, data: Vec<u8>) -> Result<Vec<u8>> {
    let message = json!({
        "protocol": protocol,
        "data": data,  // ❌ Vec<u8> as JSON array: [72,101,108,...]
        "from": self.peer_id,
        "timestamp": timestamp
    });
    serde_json::to_vec(&message)  // ❌ Encoding already-JSON data
}
```

## Goals

1. **Reduce wire overhead**: 8KB → 9KB (instead of 29KB) - **70%+ reduction**
2. **Use ant-quic PQC**: Leverage existing saorsa-pqc instead of double-encrypting
3. **Improve performance**: Faster serialization (bincode > JSON)
4. **Simplify stack**: Remove redundant encryption layers

## Success Criteria

- [ ] Benchmarks show 70%+ size reduction (8KB → 9KB)
- [ ] All tests pass
- [ ] Performance benchmarks show improvement
- [ ] Zero panics/unwraps in production code
- [ ] Using ant-quic's PQC (no redundant encryption)

## Solution Approach

### Phase 1: Baseline Measurement
- Measure current overhead at each layer
- Benchmark serialization performance
- Identify redundant encryption

### Phase 2: Simplify Encryption
- Remove application-layer encryption (use ant-quic's PQC)
- Keep only transport-level encryption via saorsa-pqc

### Phase 3: Replace JSON with Bincode
- Replace protocol wrapper JSON with binary framing
- Replace RichMessage JSON with bincode
- Direct binary serialization throughout

### Phase 4: Testing & Benchmarks
- Verify size reduction (70%+ target)
- Performance benchmarks
- Stress testing with large messages

## Non-Goals

- Backward compatibility (breaking change is acceptable)
- Version negotiation (not needed)
- Migration tooling (fresh deployment)

## Constraints

- Must use existing dependencies (bincode, saorsa-pqc already available)
- Zero tolerance for panics/unwraps
- Must pass all existing tests
- No performance regressions

## Architecture Notes

**ant-quic already provides**:
- PQC encryption via saorsa-pqc (ML-KEM-768)
- Post-quantum signatures (ML-DSA-65)
- Secure transport layer

**We should**:
- Use ant-quic's encryption (no redundant layers)
- Focus on efficient serialization only
- Binary framing for protocol messages
