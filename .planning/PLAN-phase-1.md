# Phase 1: Baseline Measurement

**Goal**: Measure current encoding overhead and identify redundant encryption layers

**Deliverable**: Benchmark suite + baseline measurements report

---

## Task 1: Create Encoding Benchmark Infrastructure

**Files**: `benches/encoding_baseline.rs` (new)

**Goal**: Set up criterion benchmarks for measuring encoding overhead at each layer

**Implementation**:
- Create benchmark harness with three groups:
  1. RichMessage encoding (RichMessage → JSON)
  2. EncryptedMessage encoding (EncryptedMessage → JSON)
  3. Protocol wrapper encoding (wrapper → JSON)
- Each group measures: serialization time, deserialization time, size overhead

**Test Data Sizes**:
- Small: 8KB payload (typical text message)
- Medium: 64KB payload (file attachment metadata)
- Large: 256KB payload (rich media message)

**Dependencies**: `src/messaging/types.rs`, `criterion`

**Verification**: `cargo bench --bench encoding_baseline` runs successfully

---

## Task 2: Benchmark RichMessage JSON Encoding

**Files**: `benches/encoding_baseline.rs`, `src/messaging/types.rs:82-193`

**Goal**: Measure RichMessage → JSON serialization overhead

**Test Scenarios**:
1. Minimal message: Text only
2. Rich message: Text + reactions + mentions + read receipts
3. Media message: Text + attachment metadata + thread info

**Measurements**:
- Serialization/deserialization time (nanoseconds)
- JSON output size (bytes)
- Overhead ratio: `json_size / payload_size`

**Verification**: Baseline metrics showing size overhead per scenario

---

## Task 3: Benchmark EncryptedMessage JSON Encoding

**Files**: `benches/encoding_baseline.rs`, `src/messaging/types.rs:362-368`

**Goal**: Measure EncryptedMessage → JSON overhead after encryption

**Test Flow**:
1. Create RichMessage (8KB, 64KB, 256KB)
2. Serialize to JSON
3. Encrypt with ChaCha20Poly1305
4. Wrap in EncryptedMessage
5. Serialize to JSON
6. Measure total size

**Measurements**:
- Encryption time
- EncryptedMessage serialization time
- Cumulative overhead: `encrypted_json_size / original_size`

**Verification**: Metrics showing "double wrapping" cost

---

## Task 4: Benchmark Protocol Wrapper JSON Encoding

**Files**: `benches/encoding_baseline.rs`, `src/network.rs:1645-1669`

**Goal**: Measure protocol wrapper → JSON overhead (third layer)

**Test Data**:
- Input: Serialized EncryptedMessage JSON
- Wrap with: protocol string, PeerId, timestamp
- Output: Final JSON payload

**Measurements**:
- Protocol wrapper serialization time
- Final JSON size
- Total overhead: `final_size / original_size`
- Per-layer breakdown showing cumulative growth

**Verification**: Complete 3-layer size analysis

---

## Task 5: Measure ant-quic Transport Overhead

**Files**: `benches/encoding_baseline.rs`, `src/transport/ant_quic_adapter.rs:1-80`

**Goal**: Measure ant-quic's PQC encryption overhead (ML-KEM-768)

**Test Setup**:
- Send protocol-wrapped JSON through ant-quic
- Measure final wire format size

**Measurements**:
- ant-quic encryption overhead (~1KB PQC)
- Total wire size
- Comparison: app ChaCha20 vs transport ML-KEM

**Verification**: Evidence that transport PQC makes app encryption redundant

---

## Task 6: Create Size Overhead Visualization

**Files**: `benches/encoding_baseline.rs`

**Goal**: Generate human-readable size comparison charts

**Visualizations**:
1. Layer-by-layer growth chart
2. Overhead percentage table
3. Scenario comparison

**Example Table**:
| Layer                  | 8KB      | 64KB     | 256KB    |
|------------------------|----------|----------|----------|
| Raw Payload            | 8KB      | 64KB     | 256KB    |
| + RichMessage JSON     | 12KB     | 80KB     | 300KB    |
| + EncryptedMessage JSON| 15KB     | 96KB     | 350KB    |
| + Protocol Wrapper JSON| 18KB     | 110KB    | 380KB    |
| + ant-quic PQC         | 19KB     | 111KB    | 381KB    |

**Verification**: Criterion HTML report with charts

---

## Task 7: Benchmark Serialization Performance

**Files**: `benches/encoding_baseline.rs`

**Goal**: Measure CPU time for encoding/decoding

**Metrics**:
- Serialization: Struct → JSON (nanoseconds)
- Deserialization: JSON → Struct (nanoseconds)
- Throughput: Messages per second

**Test Scenarios**:
- Single message (latency)
- Batch of 100 (throughput)
- Varying sizes (8KB, 64KB, 256KB)

**Comparison**:
Include bincode benchmarks for comparison (expected: 5-10x faster, 70% smaller)

**Verification**: Performance metrics showing JSON as bottleneck

---

## Task 8: Document Baseline Findings

**Files**: `.planning/baseline-measurements.md` (new)

**Goal**: Compile all measurements into comprehensive report

**Report Sections**:
1. Executive Summary (current overhead, issues found)
2. Size Overhead Analysis (per-layer breakdown)
3. Performance Analysis (serialization benchmarks)
4. Encryption Redundancy (app vs transport)
5. Recommendations for Milestone 2

**Verification**: Complete baseline report with actionable recommendations

---

## Execution Order

**Sequential**:
1. Task 1 (infrastructure)
2. Task 2 → 3 → 4 (encoding layers)
3. Task 5 (transport)
4. Task 6 (visualization)
5. Task 7 (performance)
6. Task 8 (documentation)

## Success Criteria

- ✅ All benchmarks compile without warnings
- ✅ Benchmarks run via `cargo bench`
- ✅ Results reproducible (±5% variance)
- ✅ HTML reports in `target/criterion/`
- ✅ No panics/unwraps in production code
- ✅ Complete baseline report with data

## Expected Findings

- **Size**: 8KB → ~18KB (2.25x overhead currently)
- **Redundancy**: 3 JSON layers + 2 encryption layers
- **Target**: 8KB → ~9KB with bincode (Milestone 2)
- **Performance**: JSON slowest, bincode 5-10x faster
