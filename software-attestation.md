# Decentralized Software Attestation in the Saorsa P2P Network

## Architecting Trustless Integrity via Cryptographic Proofs and Consensus

---

## 1. Introduction: The Integrity Crisis in Permissionless Networks

The proliferation of decentralized peer-to-peer (P2P) networks has fundamentally challenged the traditional paradigms of trust in computing. In conventional client-server architectures, trust is centralized; users trust the server operator to maintain software integrity. In permissioned distributed ledger technologies (DLTs), trust is federated among known, vetted validators. However, in a pure, permissionless P2P network like Saorsa—which aims for censorship resistance, autonomy, and privacy through a multi-layer approach devoid of central servers—the question of software integrity becomes an existential challenge.

The core dilemma lies in the adversarial nature of permissionless environments. Malicious actors are not merely hypothetical threats but active participants who may modify the open-source node software to subvert network goals. These modifications can range from subtle protocol deviations, such as ignoring Time-To-Live (TTL) parameters to induce network congestion, to overt malicious behaviors like Eclipse attacks, data exfiltration, or the injection of invalid data into the Distributed Hash Table (DHT).

If a significant fraction of nodes runs tampered software, the theoretical guarantees of the network—convergence, consistency, and partition tolerance—evaporate.

This report investigates a mechanism for **Decentralized Software Attestation** specifically tailored to the Saorsa network architecture. The objective is to ensure that nodes participating in the public network are running the specific, untampered software artifacts provided by the developers, without relying on centralized authorities, Public Key Infrastructure (PKI), or proprietary hardware attestation services (like Intel IAS) that introduce single points of failure and censorship risks.

The proposed framework, termed **"Entangled Attestation,"** leverages the unique topological properties of Saorsa's Kademlia-based Close Groups combined with cutting-edge cryptographic primitives. By synthesizing Zero-Knowledge Virtual Machines (zkVMs) for Proof of Execution (PoE), Verifiable Delay Functions (VDFs) for temporal bounding, and recursive Incrementally Verifiable Computation (IVC), we can construct a robust, self-policing network. This approach binds a node's cryptographic identity to the hash of its executing binary, ensuring that any deviation from the canonical software results in the forfeiture of network identity and reputation.

---

## 2. The Saorsa Network Architecture and Trust Constraints

To design an effective attestation mechanism, one must first deeply understand the substrate upon which it will operate. The Saorsa network is not a generic P2P mesh; it is a highly opinionated stack designed for post-quantum security and local-first data principles.

### 2.1 Core Components and Topology

The Saorsa ecosystem is built upon several interacting Rust crates that define its capabilities and constraints. Understanding these is crucial for identifying where attestation hooks can be inserted.

#### 2.1.1 The Overlay: S/Kademlia and Close Groups

At the heart of Saorsa is a Distributed Hash Table (DHT) based on S/Kademlia. Unlike unstructured P2P networks (like Gnutella), Kademlia imposes a strict geometry on the network using the XOR metric. Every node has a randomly generated 256-bit Node ID. The "distance" between two nodes, A and B, is defined as:

```
d(A, B) = A ⊕ B
```

This metric space allows for deterministic routing in O(log N) steps. Crucially for attestation, it defines the concept of **Close Groups**. For any given target key (or node ID), the k closest nodes in the network form a natural quorum. In Saorsa, these Close Groups are responsible for storing data and managing consensus for that region of the address space.

This topological feature is the linchpin of our proposed attestation model: instead of global consensus (which is slow and unscalable), we rely on **Local Consensus** within the Close Group to verify the integrity of its members.

#### 2.1.2 The Gossip Protocol: Plumtree and HyParView

Message dissemination in Saorsa utilizes a hybrid gossip protocol combining **HyParView** (Hybrid Partial View) for membership maintenance and **Plumtree** (Epidemic Broadcast Trees) for message broadcast.

- **HyParView** maintains a small "Active View" (TCP/QUIC connections) for high-reliability message pushing and a larger "Passive View" for failure recovery.
- **Plumtree** optimizes latency by building a spanning tree for "EAGER" message push, while using "LAZY" (IHAVE/IWANT) messages to repair broken branches.

This implies that attestation proofs must be **bandwidth-efficient**. A mechanism that requires exchanging megabytes of proof data for every handshake would saturate the gossip channels and degrade the <500ms broadcast latency target. Therefore, **succinctness** (as provided by zk-SNARKs/STARKs) is a non-negotiable requirement.

#### 2.1.3 Cryptographic Foundations: The Post-Quantum Imperative

Saorsa explicitly targets a post-quantum world. It utilizes **ML-DSA-65 (Dilithium)** for digital signatures and **ML-KEM-768 (Kyber)** for key encapsulation. This design choice disqualifies many traditional attestation schemes that rely on pre-quantum primitives (e.g., EPID signatures in Intel SGX or standard ECDSA in older zk-SNARKs).

Any proof system introduced for attestation must itself be **quantum-resistant**. This points strongly towards hash-based proof systems like **STARKs** (Scalable Transparent Arguments of Knowledge) over pairing-based SNARKs.

### 2.2 The Threat Landscape in Permissionless P2P

The absence of a central gatekeeper exposes Saorsa to specific attack vectors that software attestation must mitigate.

#### 2.2.1 The Sybil and Emulation Attack

In a basic Kademlia network, generating a Node ID is cheap. An attacker can spawn millions of virtual nodes on a single physical machine, flooding the network and taking over multiple Close Groups (**Eclipse Attack**). Even if we require a Proof of Work (PoW) to generate an ID, an attacker with a modified binary can optimize the mining process or bypass protocol checks (e.g., routing table limits).

Standard attestation assumes one hardware device = one vote. In a software-only context, we must differentiate between a legitimate node running the full, resource-intensive saorsa-node stack and a lightweight Python script that merely speaks the Kademlia protocol wire format to poison the routing table.

#### 2.2.2 The "Two-Face" Binary (Split-View Attack)

A sophisticated adversary might run a modified binary that contains both the honest code and malicious code. When challenged for an attestation (e.g., "hash your memory"), the binary runs the honest code or reads from a static image of the honest binary on disk. Once the proof is generated, it switches back to malicious behavior (e.g., dropping packets). This is known as the **"Time-of-Check to Time-of-Use" (TOCTOU)** problem in remote attestation.

Mitigating this requires **Proof of Execution (PoE)**—proving that the actual execution trace of the program logic over time corresponded to the honest binary, rather than just a static hash of the file.

#### 2.2.3 The Relay (Wormhole) Attack

An attacker controls a network of low-power, malicious nodes (e.g., compromised IoT devices) and one powerful supercomputer (or a compromised TEE). When the low-power nodes are challenged to attest, they forward (relay) the challenge to the supercomputer. The supercomputer generates the valid proof and sends it back. The network believes the IoT devices are trustworthy, honest nodes.

This undermines location-based and topology-based routing. The defense against this relies on **latency constraints** and **Verifiable Delay Functions (VDFs)** to bind the proof generation to the physical node's response window.

---

## 3. Theoretical Frameworks for Decentralized Attestation

Before detailing the specific mechanism for Saorsa, we must situate the solution within the broader theoretical landscape of remote attestation.

### 3.1 The Limits of Hardware-Based Attestation (TEEs)

Traditional Remote Attestation (RA) is heavily reliant on Trusted Execution Environments (TEEs) like Intel SGX, ARM TrustZone, or AMD SEV. In this model:

1. The hardware measures the binary during boot/load.
2. The hardware signs this measurement with a unique, manufacturer-provisioned key (Endorsement Key).
3. The verifier checks the signature against the manufacturer's certificate service (e.g., Intel Attestation Service - IAS).

While powerful, this model is antithetical to Saorsa's goals for several reasons:

- **Centralization**: It relies on Intel/AMD as a root of trust. If Intel decides to revoke keys or shutdown the IAS (as they have deprecated SGX features in consumer CPUs), the network functionality is impaired.
- **Privacy**: Standard RA schemes (like EPID) often require contacting the manufacturer's server, leaking participation data.
- **Availability**: Not all user hardware supports TEEs. Requiring SGX would drastically shrink the potential Saorsa node population.

However, the *concept* of TEEs is valid. We aim to replicate the guarantees of TEEs—integrity and isolation—using cryptographic proofs (zkVMs) and economic/temporal costs (VDFs) rather than closed silicon. Furthermore, emerging open hardware standards like **Sanctum** (RISC-V TEEs) offer a decentralized path forward that Saorsa should eventually adopt.

### 3.2 Swarm and Collaborative Attestation

Research into "Swarm Attestation" addresses the scalability of verifying large networks. In these protocols, nodes attest to their neighbors, forming a web of trust.

- **SEDA** (Scalable Embedded Device Attestation): Uses a spanning tree to aggregate reports.
- **P2P Attestation**: Nodes mutually verify each other. If Node A verifies Node B, and Node B verifies Node C, A can transitively trust C (with diminishing certainty).

Saorsa's Kademlia structure is naturally suited for this. The "Close Group" acts as a local swarm. If the 20 nodes closest to Node X agree that Node X is running valid software, the rest of the network respects this consensus without re-verifying.

### 3.3 Zero-Knowledge Virtual Machines (zkVMs)

The most significant breakthrough for software-based attestation is the advent of general-purpose **zkVMs**.

A zkVM allows a prover to run an arbitrary program (written in Rust, C++, etc.) and generate a succinct cryptographic proof that:

1. The program was executed correctly.
2. The execution started from a specific initial state and ended in a specific final state.
3. The execution used specific private inputs (optional).

Crucially, the verifier does not need to re-run the computation. They only verify the small proof.

- **RISC Zero**: Implements the RISC-V instruction set architecture (ISA) inside a STARK-based proving system. It allows developers to prove the execution of standard Rust code.
- **SP1** (Succinct Processor 1): Another high-performance RISC-V zkVM, optimized for precompiles and recursion, claiming significant speedups over RISC Zero for blockchain workloads.

For Saorsa, since `saorsa-node` is written in Rust, compiling core logic modules to RISC-V and running them inside SP1 or RISC Zero allows the node to "prove" it ran the code correctly. This constitutes a **Proof of Execution (PoE)**.

---

## 4. Mechanism Design: The Entangled Attestation Protocol

We propose a multi-layered attestation protocol for Saorsa, referred to as **"Entangled Attestation."** This name derives from the mechanism's core property: a node's Identity (in the Kademlia ID space) is mathematically entangled with the Hash of the Software Binary it executes. This entanglement ensures that any modification to the software forces a change in identity, preventing attackers from maintaining reputation or position while running malicious code.

The protocol consists of three interlocking mechanisms:

1. **Entangled Identity Generation** (Static Attestation)
2. **Proof of Unique Execution via zkVM** (Dynamic Logic Attestation)
3. **Verifiable Delay Heartbeats** (Temporal/Physical Attestation)

### 4.1 Mechanism A: Entangled Identity Generation

In standard Kademlia, a node ID is often random. In Saorsa, we redefine valid Node IDs to be derived from the software itself.

#### 4.1.1 The Entanglement Function

Let `B_canonical` be the Merkle Root or SHA-256 hash of the officially released `saorsa-node` binary (or the deterministic build of the source).

Let `PK` be the node's public key (ML-DSA-65).

The Node ID `N_ID` is valid if and only if:

```
N_ID = BLAKE3( PK | H(B_canonical) | η )
```

Where `η` is a nonce found via a moderate Proof-of-Work (PoW) to prevent ID grinding (spamming IDs to find one in a specific location).

#### 4.1.2 Joining the Network

When a node joins a Close Group, it presents its `N_ID`, `PK`, `η`, and a **Proof of Construction**.

This Proof of Construction is a zk-STARK (using SP1 or RISC Zero) that asserts:

> "I know a private key SK and a binary B such that H(B) matches the network's allowed version list, and N_ID is correctly derived from them."

**Implication**: If an attacker modifies the source code to ignore TTLs, the hash `H(B_malicious)` changes. To generate a valid zk-proof, they must use `H(B_malicious)` in the ID derivation. This results in a completely different `N_ID'`.

- The attacker cannot "patch" their existing node. They effectively become a new node in a different location in the XOR space.
- They lose all accumulated reputation (EigenTrust score) associated with the old ID.
- They cannot target a specific victim node (Eclipse attack) because they cannot choose their ID location arbitrarily; it is randomized by the hash of their code.

#### 4.1.3 Sunset Timestamps for Updates

To prevent attackers from running old, vulnerable versions of `saorsa-node` indefinitely (Replay Attack), the entanglement function must account for software versions.

- The network maintains a list of "active" binary hashes. Each hash has a **Sunset Timestamp**.
- Close Group nodes reject identities derived from expired binaries.
- **Version Migration**: When a node updates from v1 to v2, it must generate a transition proof (signed by PK) linking the old `N_ID` to the new `N_ID'` to migrate its reputation score.

### 4.2 Mechanism B: Proof of Unique Execution (PoUE) via zkVM

Static attestation (checking the binary hash) is insufficient because a node could simply claim to run the binary while actually running a malicious script (the "Two-Face" attack). We need to prove that the node's actions are *generated by* that binary.

We introduce **Incrementally Verifiable Computation (IVC)** to the node's event loop.

#### 4.2.1 The Trusted Core vs. Untrusted Host (State Machine Pattern)

Running the entire OS and networking stack inside a zkVM is impractical due to overhead and non-determinism (network I/O). The engineering solution is to refactor `saorsa-node` into a specific **Deterministic State Machine** pattern.

**The Host (Untrusted/Async)**: Handles all async I/O, TCP/QUIC sockets, disk reads, and the tokio runtime. It acts as the "driver."

**The Core (Trusted/Synchronous)**: A pure `no_std` Rust crate (`saorsa-logic`) that implements the protocol state machine.

- **Input**: Events (PacketReceived, TimerTick, UserCommand).
- **Process**: Updates internal state (Routing Table, K-Buckets, CRDTs).
- **Output**: Actions (SendPacket, StoreData).

**Crucially**: The Core contains no async code, no sockets, and no clocks. It is a pure function:

```rust
fn step(state, input) -> (new_state, output)
```

This purity allows it to be compiled to `riscv32im` and executed inside the zkVM (SP1) or a TEE (Sanctum) identically.

#### 4.2.2 The Recursive Proof Loop & Probation

The Core runs inside the zkVM (e.g., SP1).

For every batch of network messages (e.g., 100 packets):

1. The Host passes the input packets and current state to the Core.
2. The Core processes them, updates the internal state (e.g., Routing Table), and outputs response packets.
3. The zkVM generates a STARK proof `π_t`.
4. **Recursion**: `π_t` verifies the current batch *and* the validity of `π_{t-1}`.

**Probationary Mode**: Proof generation takes time. A new node joining the network cannot produce a proof instantly. It enters a "Probationary Period" where it can participate but with limited influence (cannot vote in consensus, cannot store critical data). Only once it submits its first valid recursive proof chain is it established as a full peer.

### 4.3 Mechanism C: The Temporal Anchor (VDFs)

zkVM proofs verify logic, but they do not verify *who* ran the logic or *when*. An attacker could offload the zkVM proof generation to a massive AWS cluster (Outsourcing Attack) or perform a Sybil attack by simulating 1000 nodes on one powerful machine.

To bind the execution to the specific P2P node instance, we use **Verifiable Delay Functions (VDFs)**. VDFs require sequential computation steps that cannot be parallelized.

#### 4.3.1 Wesolowski VDFs and Class Groups

We recommend utilizing **Wesolowski's VDF** over Pietrzak's due to its constant-sized proofs (crucial for gossip bandwidth).

- **Setup**: Use Class Groups of Imaginary Quadratic Fields. This avoids the "Trusted Setup" problem of RSA groups (no need for a ceremony to generate moduli).
- **Optimization**: The discriminant size of the Class Group is a critical tuning parameter. A 1024-bit discriminant offers faster verification but lower security against specialized hardware. We recommend starting with **2048-bit discriminants** for mainnet security, accepting slightly higher verification costs (approx 2-3ms per verification).

#### 4.3.2 Sybil Resistance via Sequential Work

Because the VDF is sequential, a single CPU core can only maintain one identity's heartbeat. If an attacker wants to run 1,000 Sybil nodes, they need 1,000 CPU cores to compute 1,000 separate VDFs simultaneously. This reintroduces a physical resource cost (CPU time) that scales linearly with the number of nodes, making Sybil attacks economically infeasible.

---

## 5. Integrating with Close Group Consensus

The technical proofs described above must be integrated into Saorsa's consensus layer to trigger network actions (e.g., eviction of malicious nodes).

### 5.1 The Witness Model

In Saorsa, the "Witnesses" for Node X are the members of its Close Group.

- **Gossip Integration**: Node X broadcasts its latest recursive proof `π` and VDF solution via the Plumtree gossip protocol.
- **Lightweight Verification**: Verifying a STARK proof and a VDF is computationally cheap (milliseconds). Every member of the Close Group performs this verification.

### 5.2 Consensus and Reputation

Saorsa uses OR-Set CRDTs for membership. We extend this to include an **Attestation Status**.

- **Good Standing**: Node provides valid proofs on time. Reputation increases.
- **Probation**: Node misses a VDF window or provides an invalid proof. The Close Group marks it as "Suspect" via the SWIM failure detector.
- **Eviction**: If a supermajority (e.g., >2/3) of the Close Group marks a node as Suspect, it is evicted from the topology. Its ID is effectively burned.

### 5.3 Behavior-Based Attestation (Network Behavior Analysis)

While cryptographic proofs cover code execution, **"Network Behavior Analysis" (NBA)** provides a defense-in-depth layer against unforeseen exploits or "unprovable" behaviors (like physical layer manipulation).

- **Metric Tracking**: Close Group nodes passively monitor metrics for their neighbors: Packet Drop Rate, Latency Jitter, Throughput, and Protocol Compliance (e.g., are they respecting EAGER push rules?).
- **Anomaly Detection**: If a node has a valid zk-proof but exhibits statistical anomalies (e.g., dropping 50% of messages), it suggests the existence of a bug or a side-channel attack. The NBA score is factored into the Reputation calculation, potentially triggering eviction even if the cryptographic proofs are valid.

---

## 6. Implementation Roadmap for Saorsa

Deploying this architecture requires a phased rollout, prioritizing the "Core" extraction logic.

### Phase 1: Soft Entangled Identity (v0.2.x)

**Objective**: Bind Node ID to software hash without breaking the network.

**Implementation**:
- Implement `N_ID` derivation.
- Add "Sunset" timestamps to binary metadata.
- Nodes log "Invalid ID" warnings but do not evict. This gathers telemetry on hash distribution and false positives.

### Phase 2: Core Logic Extraction & Unit Testing (v0.3.x)

**Objective**: Refactor `saorsa-node` to separate I/O from Logic.

**Implementation**:
- Create `saorsa-logic` (`no_std`) crate.
- Migrate K-Bucket and Routing Table logic into `saorsa-logic` as a Deterministic State Machine.
- **Action**: Heavy property-based testing (fuzzing) on this crate. Do not integrate SP1 yet. Focus on ensuring the state machine is truly deterministic and decoupled from the OS.

### Phase 3: zkVM Integration (v0.4.x - Devnet)

**Objective**: Enable nodes to generate execution proofs.

**Implementation**:
- Integrate `sp1-sdk` into the `saorsa-node` host.
- Run the `saorsa-logic` crate inside SP1 on a testnet.
- **Benchmark**: Measure proof generation time vs. gossip latency. Tune the "Batch Size" (e.g., 50 vs 100 packets) to fit within the heartbeat window.
- Implement "Probationary Mode" for nodes joining without proofs.

### Phase 4: VDF & Mainnet Enforcement (v0.5.x)

**Objective**: Full "Entangled Attestation."

**Implementation**:
- Integrate Wesolowski VDF (Class Groups) for the heartbeat.
- Update SWIM protocol to enforce eviction on invalid proofs.
- Activate the "Burn" logic for invalid Entangled Identities.

---

## 7. Challenges and Mitigations

### 7.1 Proof Overhead and Latency

**Challenge**: Generating STARK proofs is computationally intensive. It might take seconds or minutes to prove a batch of execution.

**Mitigation**:
- **Asynchronous Proving**: The node participates in the network in real-time (optimistically). It generates proofs in the background for past epochs. The Close Group validates these post facto. If a node was malicious 5 minutes ago, it is evicted now.
- **Hardware Acceleration**: SP1 and RISC Zero heavily utilize GPU acceleration (CUDA/Metal). Saorsa nodes with GPUs will have a significant advantage. For CPU-only nodes, we might rely on "delegated proving" where they pay a specialized prover node, though this reintroduces some centralization risk.

### 7.2 Software Updates

**Challenge**: If the binary changes (update), the hash changes, and thus the Entangled Node ID changes. This means every update wipes the network's reputation and routing table.

**Mitigation**:
- **Signed Upgrades**: The Entangled Identity formula can be modified to include the Issuer's Public Key (the Saorsa dev team or DAO) rather than the raw binary hash.

```
N_ID = Hash(PK_node | PK_dev)
```

- **Proof of Update**: When updating, the node generates a proof: "I moved state S from Binary v1 to Binary v2, and both are signed by `PK_dev`." This allows reputation migration.

### 7.3 Post-Quantum Signature Verification Cost

**Challenge**: Verifying ML-DSA-65 signatures inside a zkVM is expensive (thousands of cycles).

**Mitigation**:
- **Precompiles**: SP1 supports "precompiles" for specific operations. We can implement a RISC-V precompile for the Dilithium verification algorithm, drastically reducing the cycle count and proof generation time.

---

## 8. Future-Proofing: The Role of Open Hardware (Sanctum)

While the software-only solution (VDF + zkVM) is robust, it incurs high CPU overhead. The long-term optimization for Saorsa lies in **Open Hardware**.

**Sanctum** is a design for open-source TEEs on RISC-V. Unlike SGX, Sanctum's root of trust is the software measurement itself, not a secret key burned in by a fab.

### 8.1 Dual-Target Interface

By refactoring the core logic into the `saorsa-logic` (`no_std`) crate, we create a flexible interface that can target two environments:

| Mode | Execution Environment | Output |
|------|----------------------|--------|
| **Software Attestation** | `saorsa-logic` runs inside SP1 (zkVM) | Cryptographic Proof (STARK) |
| **Hardware Attestation** | `saorsa-logic` runs inside a Sanctum Enclave | Hardware Signature (Attestation Report) |

Saorsa should treat Sanctum-attested nodes as **"Gold Tier"** members. They provide the same integrity guarantees but with significantly lower latency and energy cost (no VDF grinding required), incentivizing the adoption of open RISC-V hardware.

---

## 9. Conclusion

The "Entangled Attestation" framework represents a paradigm shift for the Saorsa network. By moving away from "trusting the node" to "verifying the execution," we enable a level of integrity previously reserved for centralized systems.

The combination of **Software-Entangled Identities** (preventing identity spoofing), **zkVM Proof of Execution** (preventing logic tampering), and **VDF Heartbeats** (preventing Sybil/Relay attacks) creates a self-reinforcing mesh of security. While the engineering cost of refactoring `saorsa-node` for zkVM compatibility is high, the payoff is a truly autonomous, resilient, and tamper-proof P2P infrastructure capable of surviving in a hostile, zero-trust environment.

---

## Summary of Proposed Attestation Mechanisms

| Mechanism Component | Technology | Purpose | Threat Mitigated |
|---------------------|------------|---------|------------------|
| **Entangled Identity** | BLAKE3 Hash of (Key + Binary + Time) | Binds NodeID to Software Version | Eclipse Attack, Identity Spoofing |
| **Proof of Execution** | SP1 (RISC-V zkVM) | Proves correct Kademlia/CRDT logic | "Two-Face" Binary, Protocol Deviation |
| **Temporal Anchor** | Wesolowski VDF | Proves sequential work & local execution | Sybil Attack, Relay/Wormhole Attack |
| **Recursive Proofs** | IVC (Incrementally Verifiable Computation) | Compresses execution history into one proof | Long-range attacks, Bandwidth bloat |
| **Witness Consensus** | Kademlia Close Groups | Decentralized verification quorum | Centralized Verifier failure |
| **Behavioral Check** | NBA (Network Behavior Analysis) | Statistical anomaly detection | Unknown/Side-channel exploits |

---

## Recommendation

This report recommends the immediate investigation of **SP1** for the execution layer and **Wesolowski VDFs** using Class Groups for the temporal layer, targeting a prototype implementation in the `saorsa-core` v0.3.0 release cycle.

---

## Sources and References

### Remote Attestation and Trusted Computing
- [Attestation Types and Scenarios - Microsoft Learn](https://learn.microsoft.com/en-us/azure/confidential-computing/attestation-solutions)
- [Attestation in Confidential Computing - Red Hat](https://www.redhat.com/en/blog/attestation-confidential-computing)
- [Attestation Mechanisms for Trusted Execution Environments Demystified - arXiv](https://arxiv.org/pdf/2206.03780)
- [Attestation and Trusted Computing - University of Washington](https://courses.cs.washington.edu/courses/csep590/06wi/finalprojects/bare.pdf)
- [Trusted Computing - Wikipedia](https://en.wikipedia.org/wiki/Trusted_Computing)
- [Why is Attestation Required for Confidential Computing? - Confidential Computing Consortium](https://confidentialcomputing.io/2023/04/06/why-is-attestation-required-for-confidential-computing/)
- [Trusted Computing Base Recovery Attestation - Intel](https://www.intel.com/content/www/us/en/developer/topic-technology/software-security-guidance/trusted-computing-base-recovery-attestation.html)
- [TPM Remote Attestation: How Can I Trust You? - Infineon](https://community.infineon.com/t5/Blogs/TPM-remote-attestation-How-can-I-trust-you/ba-p/452729)
- [Trusted Computing - Stanford](https://cs.stanford.edu/people/eroberts/cs201/projects/trusted-computing/what.html)
- [Security Analysis of Remote Attestation - Stanford SecLab](https://seclab.stanford.edu/pcl/cs259/projects/cs259_final_lavina_jayesh/CS259_report_lavina_jayesh.pdf)

### Zero-Knowledge Virtual Machines (zkVMs)
- [RISC Zero](https://www.risczero.com/) - RISC-V zkVM with STARK-based proving
- [SP1 (Succinct Processor 1)](https://github.com/succinctlabs/sp1) - High-performance RISC-V zkVM

### Verifiable Delay Functions (VDFs)
- Wesolowski, B. "Efficient Verifiable Delay Functions" - Class Group based VDFs
- Pietrzak, K. "Simple Verifiable Delay Functions"

### Kademlia and DHT Systems
- Maymounkov, P. and Mazières, D. "Kademlia: A Peer-to-peer Information System Based on the XOR Metric"
- S/Kademlia: A Practicable Approach Towards Secure Key-Based Routing

### Swarm Attestation
- SEDA: Scalable Embedded Device Attestation
- Collective Remote Attestation in P2P Networks

### Open Hardware TEEs
- Sanctum: Minimal Hardware Extensions for Strong Software Isolation (RISC-V)

### Post-Quantum Cryptography
- ML-DSA (Dilithium) - NIST Post-Quantum Digital Signature Standard
- ML-KEM (Kyber) - NIST Post-Quantum Key Encapsulation Mechanism
