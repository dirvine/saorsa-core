# Message Encoding Optimization Project

## Problem Statement

Triple JSON encoding causes 3.6x message bloat (8KB → 29KB on wire).

### Current Pipeline
1. **RichMessage → JSON** (service.rs:664): 8KB → ~10KB
2. **EncryptedMessage → JSON** (transport.rs:246): 10KB → ~20KB  
3. **Protocol wrapper → JSON** (network.rs:1645-1669): 20KB → ~29KB

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

When JSON encodes `Vec<u8>`:
- **As array**: `[72, 101, 108, 108, 111]` → ~4x overhead
- **As base64**: `"SGVsbG8="` → ~1.33x overhead

## Goals

1. **Reduce wire overhead**: 8KB → 9KB (instead of 29KB)
2. **Maintain compatibility**: Version protocol, support migration
3. **Improve performance**: Faster serialization (bincode > JSON)
4. **Preserve security**: Keep existing encryption
5. **Document changes**: Migration guide for other implementers

## Success Criteria

- [ ] Benchmarks show 60-70% size reduction
- [ ] Backward compatibility maintained (version negotiation)
- [ ] All tests pass
- [ ] Performance benchmarks included
- [ ] Migration guide written
- [ ] Zero panics/unwraps in production code

## Non-Goals

- Changing encryption layer (use existing ant-quic PQC)
- Rewriting entire messaging system
- Breaking existing deployments without migration path

## Constraints

- Must use existing dependencies (bincode already in Cargo.toml)
- Zero tolerance for panics/unwraps
- Must pass all existing tests
- No performance regressions

## Stakeholders

- Network layer maintainers
- Applications using saorsa-core messaging
- External contributors (like PR #6 author)

## Timeline

Flexible - prioritize correctness over speed.
