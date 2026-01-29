# Message Encoding Optimization - Milestones

## Milestone 1: Analysis & Baseline

**Goal**: Measure current overhead and design solution

### Phases
1. **Baseline Measurement**
   - Create benchmarks for current encoding (JSON)
   - Measure size overhead at each layer (3 layers)
   - Benchmark serialization/deserialization performance
   - Identify redundant encryption (app-layer vs transport)
   
2. **Architecture Analysis**
   - Document current message flow
   - Map ant-quic PQC integration points
   - Identify redundant encryption layers
   - Plan simplified stack

3. **Solution Design**
   - Design binary framing format
   - Plan bincode integration
   - Specify encryption strategy (ant-quic only)
   - Create migration checklist

**Deliverable**: Benchmark suite + design spec

---

## Milestone 2: Implementation

**Goal**: Replace JSON with bincode, remove redundant encryption

### Phases
1. **Remove Redundant Encryption**
   - Remove application-layer encryption
   - Use ant-quic's PQC exclusively (saorsa-pqc)
   - Simplify message types

2. **Binary Encoding Migration**
   - Replace protocol wrapper (JSON → binary framing)
   - Migrate RichMessage (JSON → bincode)
   - Update transport layer serialization

3. **Integration & Cleanup**
   - Update all call sites
   - Remove deprecated JSON code
   - Clean up types

**Deliverable**: Working bincode implementation

---

## Milestone 3: Validation

**Goal**: Verify size reduction and performance gains

### Phases
1. **Unit Testing**
   - Test bincode encoding/decoding
   - Test binary framing
   - Edge case coverage

2. **Integration Testing**
   - End-to-end message passing
   - Large message transfers (64KB+)
   - Stress testing

3. **Benchmarking**
   - Measure size reduction (target: 70%+)
   - Compare serialization speed (bincode vs JSON)
   - Validate no performance regression

**Deliverable**: Full test suite + performance report

---

## Milestone 4: Documentation

**Goal**: Document changes

### Phases
1. **Code Documentation**
   - Document binary framing format
   - Update API docs
   - Add inline comments

2. **Release Preparation**
   - Update CHANGELOG
   - Note breaking change
   - Prepare release notes

**Deliverable**: Complete documentation

---

## Timeline Estimate

- **Milestone 1**: 1-2 days (analysis & design)
- **Milestone 2**: 2-3 days (implementation)
- **Milestone 3**: 1-2 days (testing)
- **Milestone 4**: 1 day (docs)

**Total**: ~5-8 days

## Success Metrics

- ✅ 70%+ size reduction (8KB → 9KB max, vs current 29KB)
- ✅ All tests passing
- ✅ Benchmarks show performance improvement
- ✅ Zero panics/unwraps in production code
- ✅ Single encryption layer (ant-quic PQC only)
