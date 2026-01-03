# TLOS Security Model

## Overview

TLOS is a **compute-and-compare (point-function) obfuscator** using a four-layer security model:

1. **Topology layer** - structural mixing (heuristic)
2. **LWE layer** - control function hiding via standard LWE with Gaussian noise (σ=8, n=384, ~2^112 PQ)
3. **Wire binding layer** - full-rank linear hash for inter-gate consistency (algebraic binding)
4. **Planted LWE puzzle** - forces minimum 3^48 ≈ 2^76 brute-force search space (1.26M gas)

**What TLOS is:** Secret verification with 2^76 one-time puzzle barrier for low-entropy secrets, plus optional multi-bit payloads.

**What TLOS is NOT:** General circuit obfuscation or complex predicates on public data.

---

## Combined Security Model

Security relies on **both** topology and LWE working together:

| Layer | Hides | From |
|-------|-------|------|
| Topology | μ (control function bits) | Structural analysis |
| LWE | s (decryption key) | Cryptanalytic attacks |

**Critical insight:** The ~2^112 estimate assumes μ cannot be predicted from circuit structure. If an attacker predicts μ for n=384 gates via structural analysis, they can recover s via Gaussian elimination in O(n³).

### Why Structural Attacks Fail

TLOS circuits compute **point functions**: `C(x) = 1 iff x = secret`

- **No recognizable gadgets:** There are no adders, comparators, or hash rounds
- **Reversible gates ≠ standard logic:** Each gate computes `state[a] ^= cf(state[c1], state[c2])`
- **Random structure:** Topology layer uses non-pow2 distances, uniform wire usage

### Input-Dependent Key Derivation (White-Box Defense)

The decryption key `s = H(input || puzzleSolutionHash)` is derived at evaluation time.

**Why tracing doesn't help:**
```
Attacker traces with wrong input x':
  s(x') = H(x')                          // Wrong key
  diff = b - <a, s(x')>
       = <a, s_correct - s(x')> + e + μ*(q/2) // s_correct ≠ s(x')
       = random value                     // Reveals nothing about μ
```

**Traces are visible but useless without the correct input.**

The EVM is a white-box environment - we do NOT rely on hiding intermediate values. We rely on those values being **garbage** without the correct input key.

---

## TLOS vs Simple Keccak Commitment

### When to Use Keccak

```solidity
bytes32 commitment = keccak256(secret);
```

Use keccak when:
- Secret is random 256-bit (brute-force is 2^256)
- No multi-bit payload needed beyond TRUE/FALSE
- Gas efficiency is critical

### When to Use TLOS

Use TLOS when:
- **Low-entropy secrets**: passwords, phrases, small numeric ranges
- **Multi-bit payloads**: GPS coords, wallet seeds, URLs fused with verification
- **No salt UX**: human must remember only the phrase
- **Infrequent checks**: vault unlock, puzzle solve, rare admin action

### Attack Cost Comparison

| Secret Type | Keccak Attack | TLOS Attack (with Layer 4) |
|-------------|---------------|----------------------------|
| Random 256-bit | 2^256 hashes | min(2^256, 2^76) |
| Password "hunter2" | Milliseconds | 2^76 minimum |
| Range 0-100K | 0.1 seconds | 2^76 minimum |
| 4-word phrase | Seconds | 2^76 minimum |

**Key insight:** Layer 4 (planted LWE puzzle) forces minimum 3^48 ≈ 2^76 search space regardless of input entropy. At 436M guesses/sec (GH200 GPU), exhaustive search requires ~5.7 million years.

---

## Function Class: Point Functions Only

TLOS implements compute-and-compare semantics:

```
P(x) = payload    if x == secret
       garbage    otherwise
```

### Why Not Complex Predicates?

The key derivation `s = H(input)` means:
- Only `input == secret` produces the correct decryption key
- For any other input, control functions decrypt to garbage
- The circuit cannot evaluate correctly on multiple distinct inputs

**Cannot implement:** `price < threshold` where threshold is hidden but arbitrary prices work.

**Can implement:** "Is your input equal to my hidden secret?" with optional payload reveal.

---

## Wire Binding Purpose

Wire binding (inspired by SEH from Ma-Dai-Shi 2025) provides **inter-gate wire binding** to prevent mix-and-match attacks. Note: Our implementation uses a full-rank linear map providing algebraic binding, not cryptographic hiding.

---

## Layer 4: Planted LWE Puzzle

Layer 4 forces minimum brute-force work regardless of input entropy. Without this layer, low-entropy inputs could be cracked via GPU brute-force.

### Parameters (WeakLWEPuzzleV7 - Production)

| Parameter | Value |
|-----------|-------|
| Secret dimension n | 48 |
| Samples m | 72 |
| Modulus q | 2039 |
| Error range | {-2,-1,0,1,2} |
| Threshold | 300 |
| Search space | 3^48 ≈ 2^76 |
| Verification gas | 1.26M |

### GPU Brute-Force Resistance

| GPU | Rate | Exhaustive Search Time |
|-----|------|------------------------|
| GH200 | 436M guesses/sec | ~5.7 million years |
| 10,000 GPUs | 4.36T guesses/sec | ~570 years |

### How It Works (V4 Design)

1. At deployment, Alice:
   - Computes `plantedSecret = H("planted", secret)` → ternary {-1,0,1}^48
   - Generates puzzle matrix A from random `puzzleSeed`
   - Computes `b = A * plantedSecret + e` (small noise e)
   - Stores `(puzzleSeed, b)` in contract - NOT plantedSecret
2. Solver (Bob, who knows secret) computes `plantedSecret = H("planted", secret)` directly
3. Attacker (doesn't know secret) must solve ternary LWE: given (A, b), find s ∈ {-1,0,1}^48
4. Puzzle solution hash is combined with input to derive TLOS key: `s_tlos = H(input || H(puzzle_solution))`

**Key insight:** The puzzle is ONE per contract. After solving (2^76 work), attacker can test all inputs. But this still provides 2^76 minimum work floor regardless of input entropy.

### Integration with TLOS

```solidity
function revealWithPuzzle(bytes32 input, int8[48] calldata puzzleSolution) external {
    // Verify puzzle solution
    (bool puzzleValid, bytes32 sHash, ) = _verifyPuzzle(input, puzzleSolution);
    require(puzzleValid, "Invalid puzzle solution");
    
    // TLOS secret derived from BOTH input AND puzzle solution
    (bool circuitValid, ) = _evaluate(input, sHash);
    require(circuitValid, "Invalid circuit output");
    
    // Claim reward...
}
```

---

## Post-Quantum Profile

TLOS uses standard LWE with Gaussian noise (σ=8) for control function hiding:

| Property | Value |
|----------|-------|
| LWE dimension | n=384 |
| Modulus | q=65521 |
| Gaussian noise | σ=8 |
| Matrix size | 64×64 (full-rank, trivial kernel) |
| Security basis | Standard LWE hardness |
| Post-quantum security | ~2^112 (lattice estimator) |
| Gas cost | 1.8M-6M for 64-256 gates |
| Role | Primary CF hiding layer |

### Construction

The wire binding uses a **full-rank 64×64** matrix-vector product modulo q:

```
H(x) = A * x mod q
```

Where:
- A is a **64×64 matrix** derived from `circuitSeed` and `gateIdx`
- x is the wire state (64 bits)
- Output is 64 × u16 packed into 1024 bits (4 × uint256)

### Why Full-Rank 64×64?

An earlier design used an 8×64 matrix, which has a 56-dimensional nullspace—many inputs could produce the same output. A reviewer correctly noted this undermines binding. With a full-rank 64×64 matrix, the kernel is trivial (only the zero vector), so any two distinct 64-bit inputs produce distinct outputs—this provides **deterministic binding**, not collision resistance in the hash-function sense (the map is publicly invertible).

### Per-Batch Updates

Wire binding is updated after every 128 gates:
```solidity
uint256 combined = acc[0] ^ acc[1] ^ acc[2] ^ acc[3] ^ wires;
acc = _wireBindingHash(combined, batchEnd);
```

This provides inter-gate binding while maintaining gas efficiency.

### Wire Binding PRG Optimization

The `_wireBindingHash` function uses a PRG optimization: instead of calling keccak once per matrix coefficient (4096 calls per update), we derive 16 coefficients from each keccak output (320 calls per update). This reduces overhead by ~13×.

### Batch Wire Binding Tradeoff

**Design choice:** Wire binding at 128-gate batch granularity, not per-gate.

**Security implications:**
- Per-gate binding would bind every individual gate transition (closest to Ma-Dai-Shi ideal)
- With 128-gate batches, we bind the *aggregate* effect of each batch
- An attacker can only "mix-and-match" within a batch without being caught
- Across batch boundaries, all execution is bound by the chain

**Gas cost:**
- Full-rank 64×64 wire binding with n=384 LWE costs 1.8M-6M gas for 64-256 gates (3-10% of 60M block)
- 5 binding updates for 640 gates
- PRG optimization: 320 keccak calls per update (vs 4096 naive)

---

## Hybrid Security Analysis

The four-layer security model:

| Component | Security Basis | Post-Quantum | Level |
|-----------|----------------|--------------|-------|
| CF hiding (Layer 2) | Standard LWE with Gaussian noise (n=384, σ=8) | Yes | ~2^112 |
| Wire binding (Layer 3) | Full-rank linear binding | Yes | Algebraic binding |
| Planted puzzle (Layer 4) | Ternary LWE (n=48) | Yes | ~2^76 minimum |
| Unlock mechanism | Hash preimage | Conjectured* | ~256-bit |

*Assumes conservative Grover-style reduction for the hash component.

### Security Level

The overall system security is determined by the weakest component:
- **~2^76 minimum** from Layer 4 puzzle (one-time cost before any input testing)
- **~2^112 post-quantum** from LWE layer (with n=384, σ=8 parameters)

For low-entropy inputs, Layer 4 dominates: even a 1-bit secret requires 2^76 work to crack.
For high-entropy inputs (256-bit), LWE layer provides ~2^112 security.

---

## Attack Model

### What Wire Binding Prevents

1. **Mix-and-match attacks**: Adversary cannot combine outputs from different evaluation paths
2. **Gate substitution**: Each gate's output is bound to all previous computations
3. **Parallel evaluation attacks**: Binding chain prevents independent gate evaluation

### What Wire Binding Does NOT Prevent

1. **Black-box evaluation**: Anyone can evaluate with a valid secret
2. **Secret recovery**: Must rely on LWE hardness for CF hiding
3. **Side-channel attacks**: Not addressed at the cryptographic level

---

## Gas / Practicality Note

TLOS with n=384 and full-rank 64×64 wire binding costs **1.8M-6M gas** for 64-256 gates (3-10% of a 60M Ethereum L1 block). Layer 4 puzzle adds **~1.26M gas**. This is based on Tenderly benchmarks.

| Config | Circuit Gas | Puzzle Gas | Total Gas | % of 60M Block |
|--------|-------------|------------|-----------|----------------|
| 64 gates | 1.8M | 1.26M | 3.1M | 5% |
| 128 gates | 2.0M | 1.26M | 3.3M | 5.5% |
| 256 gates | 3.0M | 1.26M | 4.3M | 7% |

**Optimizations applied:**
- Wire binding PRG: 16 coefficients per keccak (320 calls vs 4096)
- Single mod at end of LWE inner product
- Batch size 128 (5 binding updates for 640 gates)
- Layer 4 puzzle: n=48, m=72, q=2039 for optimal gas/security tradeoff

This is practical for:
- Password-gated vaults and treasure hunts
- Low-frequency, high-value operations
- L1 deployment without requiring L2

---

## References

- Ma-Dai-Shi 2025: [Indistinguishability Obfuscation from Lattices](https://eprint.iacr.org/2025/307)
- TLO: [Topology-Lattice Obfuscation](https://github.com/igor53627/tlo) (archived)
- Hubacek-Wichs 2015: Somewhere Extractable Hash foundations
