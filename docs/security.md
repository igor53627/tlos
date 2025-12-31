# TLOS Security Model

## Overview

TLOS is a **compute-and-compare (point-function) obfuscator** using LWE + SEH.

**What TLOS is:** Expensive-per-guess secret verification for low-entropy secrets with optional multi-bit payloads.

**What TLOS is NOT:** General circuit obfuscation or complex predicates on public data.

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

| Secret Type | Keccak Attack | TLOS Attack |
|-------------|---------------|-------------|
| Random 256-bit | 2^256 hashes | 2^256 LWE evals |
| Password "hunter2" | Milliseconds | Hours/days |
| Range 0-100K | 0.1 seconds | 2.8+ hours |
| 4-word phrase | Seconds | Weeks |

**Key insight:** TLOS doesn't improve security for random secrets. It improves security for **low-entropy secrets** by making each guess expensive.

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

## SEH Purpose

SEH (Subspace-Evasive Hashing from Ma-Dai-Shi 2025) provides **inter-gate wire binding** to prevent mix-and-match attacks.

## Post-Quantum Profile

There are two SEH instantiations in this repository:

- **TLOSLWE (LWE SEH)** - The **only** SEH considered part of the **post-quantum TLOS profile**
- **TLOSKeccak (Keccak SEH)** - A **legacy, classical-only variant** kept for benchmarks and historical context. It is **NOT post-quantum secure** and is excluded from the PQ profile.

---

## Full-Rank SEH (PQ Variant - TLOSLWE)

| Property | Value |
|----------|-------|
| LWE dimension | n=128 |
| Matrix size | 64×64 (full-rank, trivial kernel) |
| Security basis | Binding via injective linear map (public, invertible) |
| Post-quantum security | ~98-bit |
| Gas cost | ~8.5M for 640 gates |
| Deployment | Deployable on L1 (28% of block) |
| Role | **Only SEH in the PQ TLOS profile** |

### Construction

The SEH uses a **full-rank 64×64** matrix-vector product modulo q:

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

SEH is updated after every 128 gates:
```solidity
uint256 combined = sehAcc[0] ^ sehAcc[1] ^ sehAcc[2] ^ sehAcc[3] ^ wires;
sehAcc = _sehHash(combined, batchEnd);
```

This provides inter-gate binding while maintaining gas efficiency.

### SEH PRG Optimization

The `_sehHash` function uses a PRG optimization: instead of calling keccak once per matrix coefficient (4096 calls per update), we derive 16 coefficients from each keccak output (320 calls per update). This reduces SEH overhead by ~13×.

### Batch SEH Tradeoff

**Design choice:** SEH binding at 128-gate batch granularity, not per-gate.

**Security implications:**
- Per-gate SEH would bind every individual gate transition (closest to Ma-Dai-Shi ideal)
- With 128-gate batches, we bind the *aggregate* effect of each batch
- An attacker can only "mix-and-match" within a batch without being caught by SEH
- Across batch boundaries, all execution is bound by the SEH chain

**Gas cost:**
- Full-rank 64×64 SEH with n=128 LWE costs ~8.5M gas for 640 gates (28% of block)
- 5 SEH updates for 640 gates
- PRG optimization: 320 keccak calls per update (vs 4096 naive)

---

## Keccak SEH (Legacy Classical Variant - TLOSKeccak)

**[DEPRECATED - Not post-quantum secure]**

| Property | Value |
|----------|-------|
| Security basis | Collision resistance of keccak256 |
| Classical security | ~128-bit |
| Post-quantum security | ~64-bit (Grover reduction, **NOT PQ**) |
| Gas cost | ~2.6M for 640 gates |
| Status | **Legacy / benchmarking only** |

This variant is **not** part of the post-quantum TLOS profile and may be removed in a future major release.

---

## Hybrid Security Analysis (PQ Profile)

For the **post-quantum TLOS profile**, only the LWE-based SEH is considered:

| Component | Security Basis | Post-Quantum | Level |
|-----------|----------------|--------------|-------|
| CF hiding | LWE hardness (n=128) | Yes | ~98-bit |
| SEH binding | LWE-based linear binding | Yes | ~98-bit |
| Unlock mechanism | Hash preimage | Conjectured* | ~256-bit |

*Assumes conservative Grover-style reduction for the hash component.

### Security Level

The overall system security is determined by the weakest component:
- **~98-bit post-quantum** (with n=128 LWE parameters)

This is suitable for production applications with moderate security requirements.

---

## Honest Post-Quantum Assessment

The **only** SEH instantiation that is post-quantum is the LWE-based SEH (TLOSLWE). The Keccak-based SEH (TLOSKeccak) is **not** post-quantum secure and is no longer part of the PQ TLOS profile.

With n=128, TLOSLWE provides **~98-bit PQ security**, which is:
- **Suitable for**: Production applications, medium-term secrets
- **Marginally below**: Standard 128-bit PQ security target

For ~128-bit PQ security, n>=256 would be needed, which requires either L2 deployment or future EVM optimizations.

---

## Attack Model

### What SEH Prevents

1. **Mix-and-match attacks**: Adversary cannot combine outputs from different evaluation paths
2. **Gate substitution**: Each gate's output is bound to all previous computations
3. **Parallel evaluation attacks**: SEH chain prevents independent gate evaluation

### What SEH Does NOT Prevent

1. **Black-box evaluation**: Anyone can evaluate with a valid secret
2. **Secret recovery**: Must rely on LWE hardness for CF hiding
3. **Side-channel attacks**: Not addressed at the cryptographic level

---

## Gas / Practicality Note

TLOSLWE with n=128 and full-rank 64×64 SEH costs **~8.5M gas** for a 64w/640g configuration (28% of an Ethereum L1 block). This is based on Tenderly benchmarks; the contract's `estimatedGas()` function returns a conservative upper bound for off-chain tooling.

**Optimizations applied:**
- SEH PRG: 16 coefficients per keccak (320 calls vs 4096)
- Single mod at end of LWE inner product
- Batch size 128 (5 SEH updates for 640 gates)

This is practical for:
- Password-gated vaults and treasure hunts
- Low-frequency, high-value operations
- L1 deployment without requiring L2

---

## References

- Ma-Dai-Shi 2025: [Indistinguishability Obfuscation from Lattices](https://eprint.iacr.org/2025/307)
- TLO: [Topology-Lattice Obfuscation](https://github.com/igor53627/tlo) (archived)
- Hubacek-Wichs 2015: Somewhere Extractable Hash foundations
