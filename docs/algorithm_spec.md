# Dynamic Path Verification Algorithm (DPVA) — Formal Specification

## 1. Notation

| Symbol | Meaning |
|--------|---------|
| $N = \{n_1, n_2, ..., n_k\}$ | Ordered path of network nodes |
| $K_i$ | Secret key of node $n_i$ |
| $ID_i = H(pk_i)$ | Public identity of node $n_i$ |
| $H(\cdot)$ | Cryptographic hash function (SHA-256) |
| $HMAC_{K}(\cdot)$ | Keyed-hash MAC using key $K$ |
| $\sigma_i(m)$ | Ed25519 signature by node $n_i$ over message $m$ |
| $C_{S,D}$ | Path claim from source $S$ to destination $D$ |
| $B_{t}$ | Count-Min Sketch snapshot at time $t$ |

---

## 2. Algorithm A: Proactive Path Validation (PPV)

**Purpose**: Verify the path before forwarding any data.

### 2.1 Claim Generation

$$C_{S,D} = (ID_{path}, [ID_1, ..., ID_k], t_{start}, ttl, n, \sigma_S(H(ID_{path} \| [ID_1..ID_k] \| t_{start} \| ttl \| n)))$$

Where $ID_{path} = H(ID_1 \| ... \| ID_k \| t_{start})$.

### 2.2 Probe Generation

Source generates probe:
$$probe = (ID_{path}, nonce, hop=1)$$

### 2.3 Per-hop Tagging (executed at each $n_i$)

$$tag_0 = 0$$
$$tag_i = HMAC_{K_i}(nonce \| tag_{i-1}) \quad \text{for } i = 1..k$$

Node $n_i$ forwards $(ID_{path}, nonce, hop=i+1, tag_i)$.

### 2.4 Verification at Destination

Destination $D$ receives final tag $tag_k$ and checks:

$$\forall i \in 1..k: tag_i \stackrel{?}{=} HMAC_{K_i}(nonce \| tag_{i-1})$$

Equivalently, $D$ recomputes the expected tag chain using the claimed path $[ID_1..ID_k]$ and the known public keys (retrieved from VA) to verify:

$$expected\_tag_k \stackrel{?}{=} received\_tag_k$$

If mismatch → **TAG_CHAIN_MISMATCH** anomaly.

### 2.5 Correctness Proof

**Theorem 1** (PPV Soundness): If a probe successfully verifies at destination $D$ with tag chain $T = [tag_1, ..., tag_k]$, then the probe traversed exactly the nodes $[n_1, ..., n_k]$ in that order, and each $n_i$ possessed $K_i$.

**Proof**: Assume an adversary $A$ controls a subset of nodes $N_A \subset N$. For any node $n_i \notin N_A$, $A$ cannot compute $HMAC_{K_i}(nonce \| tag_{i-1})$ without $K_i$. To produce a valid $tag_k$, $A$ must either:
1. Know all $K_i$ — impossible if at least one honest node exists.
2. Bypass a node — skipping $n_i$ means $tag_i$ cannot be produced correctly.
3. Reorder nodes — $tag_{i-1}$ is computed from $tag_{i-2}$ in sequence, so reordering breaks the chain.

By induction on $i$: if $tag_i$ is correct, then node $n_i$ computed it. $\square$

**Theorem 2** (Path Binding): A valid probe implies the data path will match the claimed path $C_{S,D}$.

**Proof**: The probe carries $(ID_{path}, nonce)$. $ID_{path}$ binds the probe to a unique path claim. The destination verifies the tag chain against the claimed node list. Any deviation from the claimed path produces a different tag chain. $\square$

---

## 3. Algorithm B: On-Path Continuous Verification (OPCV)

**Purpose**: Continuously verify that data packets follow the claimed path.

### 3.1 Data Structures

Each node $n_i$ maintains a **Count-Min Sketch** $CMS_i$ with:
- Width $w = 2^{16}$
- Depth $d = 4$
- Cell size: 4 bytes (32-bit counter)

Hash functions: $\{h_1, ..., h_d\}$ where $h_j(x) = SipHash(j, x) \bmod w$.

### 3.2 Sketch Update

For each sampled data packet with sequence number $seq$:

$$CMS_i[ j ][ h_j(ID_{path} \| seq) ] \texttt{ += } 1 \quad \forall j \in [1, d]$$

### 3.3 Challenge-Response Protocol

1. Destination $D$ periodically sends a **Challenge** to source $S$:
   $$Challenge = (ID_{path}, w_{start}, w_{end}, nonce_c)$$

2. Source $S$ exports its sketch for window $[w_{start}, w_{end}]$:
   $$B_S = export(CMS_S, w_{start}, w_{end})$$

3. Destination $D$ compares its sketch $B_D$ with $B_S$:

   $$deviation = \frac{|estimate(B_D) - estimate(B_S)|}{max(estimate(B_D), estimate(B_S))}$$

4. If $deviation > \theta$ (threshold, e.g., 0.05), an **SKETCH_DEVIATION** anomaly is raised. Source and destination then reconcile using **Invertible Bloom Filter (IBF)** subtraction to identify specific differing elements.

### 3.4 Security Analysis

**Theorem 3** (Path Compliance Detection): If a data packet traverses a path different from the claimed path, OPCV detects the deviation with probability $1 - \delta$, where $\delta$ is the false-positive rate of the Count-Min Sketch comparison.

**Proof Sketch**: Each node on the claimed path updates its sketch for packets it forwards. A packet that deviates will:
- Be processed by nodes not on the claimed path, causing their tags/identifiers to appear in the destination's sketch but not the source's.
- Miss nodes on the claimed path, causing their identifiers to appear in the source's sketch but not the destination's.

The Count-Min Sketch preserves the count of each unique (path, seq) pair within a factor of $\epsilon$ with probability $1 - \delta$ where $w = \lceil e/\epsilon \rceil$ and $d = \lceil \ln(1/\delta) \rceil$. With $w = 2^{16}, d = 4$, we have $\epsilon \approx 4.14 \times 10^{-5}$ and $\delta \approx 0.018$. $\square$

---

## 4. Algorithm C: Post-Facto Audit (PFA)

**Purpose**: Forensic analysis of historical forwarding behavior.

### 4.1 Audit Log Structure

Each node maintains a **Cuckoo Filter** $CF_i$ of capacity $M$ with:
- Bucket size $b = 4$
- Fingerprint length $f = 8$ bytes

For each sampled packet $(ID_{path}, seq, t)$:

$$entry = H(ID_{path} \| seq \| t) \bmod 2^{64}$$
$$CF_i.insert(entry)$$

### 4.2 Audit Submission

Periodically (every $T$ seconds), each node submits to the VA:

$$AuditReport_i = (ID_i, t_{start}, t_{end}, CF_i, \sigma_i(H(CF_i \| t_{start} \| t_{end})))$$

### 4.3 Consistency Check

VA performs cross-node verification:

For each claimed path $[n_1, ..., n_k]$ in window $[t_{start}, t_{end}]$:

$$\forall i \in [1, k]: \forall pkt \in window: CF_i.contains(H(ID_{path} \| seq \| t)) \stackrel{?}{=} true$$

If a packet appears in $CF_i$ but not in $CF_{i+1}$ (or vice versa), a **SEQUENCE_GAP** anomaly is logged.

### 4.4 Collusion Resistance

**Theorem 4** (Non-Repudiation): A node cannot deny having forwarded a packet, and cannot forge having forwarded a packet it did not.

**Proof**: Each audit report is signed by the node's private key. The cuckoo filter provides a compact, immutable record of forwarded packets. To forge a packet, an adversary would need to:
1. Find a fingerprint collision (probability $2^{-64}$ per insertion).
2. Produce a valid signature on the forged filter.

To deny a packet, the node would need to retroactively remove the fingerprint, which requires breaking the cuckoo filter's insertion invariant. $\square$

---

## 5. Integrated System Security

**Theorem 5** (Comprehensive Security): Under the assumption that at least one node on any given path is honest and the cryptographic primitives are secure, the DPVL system detects:
- Path deviation with probability $1 - \delta$ (OPCV)
- Node identity forgery with certainty (PPV)
- Historical path violations with probability $1 - 2^{-64}$ (PFA)

**Proof Sketch**: The three algorithms provide overlapping coverage:
- PPV ensures path establishment is secure.
- OPCV ensures ongoing path compliance during data transfer.
- PFA provides retrospective accountability.

Each algorithm relies on different cryptographic assumptions and data structures, so compromising any single algorithm does not compromise the others. $\square$

---

## 6. Complexity Analysis

| Algorithm | Communication | Computation | Storage (per node) |
|-----------|--------------|-------------|-------------------|
| PPV       | $O(k)$ per flow setup | $O(k)$ HMAC | None |
| OPCV      | $O(1)$ per challenge | $O(1)$ per packet | $O(w \cdot d)$ |
| PFA       | $O(|CF|)$ per interval | $O(1)$ per packet | $O(M)$ |

Where $k$ = path length, $w$ = sketch width, $d$ = sketch depth, $M$ = cuckoo filter capacity.
