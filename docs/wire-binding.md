# TLO with SEH Wire Binding

## Overview

This document describes the addition of **Subspace-Evasive Hashing (SEH)** to TLO for inter-gate wire consistency. SEH is based on the Ma-Dai-Shi 2025 construction for quasi-linear iO.

## The Problem SEH Solves

### Without SEH: Gates Are Independent

In base TLO-CaC, each gate is evaluated independently:

```
Gate 0: inputs (w1, w2) -> output w0
Gate 1: inputs (w3, w4) -> output w1
Gate 2: inputs (w0, w5) -> output w2
```

An attacker could potentially:
1. Evaluate gate 0 with crafted inputs `(w1=0, w2=1)`
2. Evaluate gate 2 with *different* crafted inputs `(w0=1, w5=0)`
3. Combine outputs to learn about circuit structure

This is a **mix-and-match attack** - using inconsistent intermediate values to probe the circuit.

### With SEH: Execution Trace Is Bound

SEH creates a cryptographic chain linking all gate evaluations:

```
h_0 = H(seed || initial_wires)
h_1 = H(h_0 || gate_0_output)
h_2 = H(h_1 || gate_1_output)
...
h_N = H(h_{N-1} || gate_{N-1}_output)
```

Each gate MUST prove its inputs came from the correct predecessor state. Forged inputs fail verification.

## SEH Construction

### Ma-Dai-Shi Original (FHE-based)

The theoretical construction uses:
- FHE Merkle tree with encrypted path selectors
- LWE matrix-vector product: `H(x) = A*x mod q`
- Trapdoor extraction for specific bit positions

**Gas cost: Impractical (~44M gas for 256-wire circuit)**

### TLOS SEH Implementations

**LWE-based SEH (TLOSLWE - Post-Quantum):**

Uses a full-rank 64×64 matrix-vector product:

```solidity
// H(wires) = A * wires mod q  (64-element output, 1024 bits)
// A is derived from circuitSeed and batchIdx
sehAcc = _sehHash(wires, 0);  // Initialize

// Per-batch update (every 128 gates)
uint256 combined = sehAcc[0] ^ sehAcc[1] ^ sehAcc[2] ^ sehAcc[3] ^ wires;
sehAcc = _sehHash(combined, batchEnd);
```

**Gas cost: ~8.5M for 640 gates (28% of block)**

**Keccak-based SEH (TLOSKeccak - Legacy, NOT PQ-secure):**

```solidity
// Initialize
bytes32 sehAcc = keccak256(abi.encodePacked(input, "SEH-INIT", wires));

// Per-batch update (every 64 gates)
sehAcc = keccak256(abi.encodePacked(sehAcc, batchEnd, wires));
```

**Gas cost: ~2.6M for 640 gates (8.6% of block)**

## Security Properties

### What SEH Provides

| Property | Without SEH | With SEH |
|----------|-------------|----------|
| Mix-and-match attack | Possible | Prevented |
| Execution trace binding | None | Cryptographic |
| s-equivalence proof | Heuristic | Heuristic (aligned with Ma-Dai-Shi) |

### What SEH Does NOT Provide

1. **Full iO**: SEH alone is not indistinguishability obfuscation
2. **Semantic security**: Black-box evaluation is still possible
3. **Key extraction resistance**: Still relies on LWE layer

### Formal Property: Prefix Consistency

Given two evaluations with the same prefix of inputs:
```
Eval1: x[0..k] -> h_k
Eval2: x'[0..k] -> h'_k
```

If `x[0..k] == x'[0..k]`, then `h_k == h'_k`.

For LWE-SEH with full-rank matrix, this follows from injectivity (deterministic binding). For keccak-SEH, this relies on collision resistance of keccak256.

## Gas Comparison (Tenderly Measured)

| Scheme | Config | Gas | % of 30M Block | Notes |
|--------|--------|-----|----------------|-------|
| TLOSLWE (n=128) | 64w/640g | **~8.5M** | 28% | Full-rank 64x64 SEH, ~98-bit PQ |
| TLOSKeccak | 64w/640g | **~2.6M** | 8.6% | Keccak SEH, NOT PQ-secure |

### Key Findings

1. **TLOSLWE uses ~8.5M gas** - Deployable on L1 (28% of block)
2. **PRG optimization reduces overhead** - 320 keccak calls per SEH update (vs 4096 naive)
3. **Batch SEH (128 gates)** - 5 updates for 640 gates balances security and gas

### Why TLOSLWE Gas Increased?

Upgrade to n=128 LWE dimension for ~98-bit PQ security:
- 128-element inner products (vs 64)
- Full-rank 64x64 matrix (vs previous 8x64)

## Architecture

*Conceptual diagram (per-gate SEH); actual implementation uses 128-gate batches for gas efficiency.*

```
+------------------------------------------------------------------+
|                     TLOS Architecture                              |
+------------------------------------------------------------------+
|                                                                   |
|  Input x                                                          |
|     |                                                             |
|     v                                                             |
|  [SEH Init: h_0 = H(seed || x)]                                  |
|     |                                                             |
|     +---> Gate 0 ---> [SEH Update: h_1 = H(h_0 || out_0)]        |
|     |                                                             |
|     +---> Gate 1 ---> [SEH Update: h_2 = H(h_1 || out_1)]        |
|     |                                                             |
|     ...                                                           |
|     |                                                             |
|     +---> Gate N ---> [SEH Update: h_N = H(h_{N-1} || out_N)]    |
|     |                                                             |
|     v                                                             |
|  [Verify: h_N == expectedSehHash AND output == expectedOutput]   |
|     |                                                             |
|     v                                                             |
|  Result: true/false                                               |
|                                                                   |
+------------------------------------------------------------------+
```

## Contracts

### TLOSLWE.sol (Post-Quantum)

Located at: `contracts/TLOSLWE.sol`

Key features:
- `expectedSehOutput`: 4 x uint256 for 1024-bit SEH output
- `checkWithSeh()`: Returns both validity and SEH output (for debugging)
- 128-gate batch SEH updates for gas efficiency
- n=128 LWE dimension (~98-bit PQ security)

### TLOSKeccak.sol (Legacy, Deprecated)

Located at: `contracts/legacy/TLOSKeccak.sol`

Classical-only variant using keccak256 for SEH. **NOT post-quantum secure.**

### Deployment (TLOSLWE)

```solidity
constructor(
    address _circuitDataPointer,
    uint8 _numWires,
    uint32 _numGates,
    bytes32 _expectedOutputHash,
    bytes32 _circuitSeed,
    uint256[4] memory _expectedSehOutput,  // 64 x u16 packed into 4 x uint256
    uint256 _secretExpiry
) payable
```

## Attack Resistance

### Mix-and-Match Attack (Defeated)

**Attack**: Forge intermediate wire values to probe circuit structure.

**Defense**: SEH accumulator is a commitment to the entire execution history. Any forged value produces a different `h_i`, propagating to a wrong final hash.

### Replay Attack (Defeated)

**Attack**: Replay valid (input, output) pairs with different internal paths.

**Defense**: SEH binds the entire evaluation trace, not just endpoints. Different paths produce different SEH hashes.

### Observation Attack (NOT Defeated)

**Attack**: Observe `check(x)` for many inputs to build input/output table.

**Defense**: None. This is inherent to public evaluation. SEH does not provide semantic security.

## Comparison to Ma-Dai-Shi

| Aspect | Ma-Dai-Shi | TLOS |
|--------|------------|------|
| SEH construction | FHE Merkle + LWE matrix | LWE full-rank 64x64 (TLOSLWE) |
| Security proof | Formal (s-equivalence) | Heuristic + LWE hardness |
| Gas cost | Impractical | ~8.5M (practical on L1) |
| Trapdoor extraction | Yes (for debugging) | No (not needed on-chain) |
| iO claim | Yes (quasi-linear) | No (representation hiding only) |
| PQ Security | Yes | Yes (~98-bit with n=128) |

## Limitations

1. **Keccak-SEH is NOT post-quantum**: Relies on hash collision resistance (~64-bit PQ via Grover)
2. **SEH is binding, not hiding**: The linear map is publicly invertible
3. **No trapdoor mode**: Cannot extract specific bits without full evaluation
4. **Still point-function only**: SEH doesn't expand predicate expressiveness

## Open Questions for Reviewer

1. **Is keccak-SEH sufficient for mix-and-match prevention?** The attack model assumes adversary cannot find hash collisions.

2. **Should we implement partial LWE-SEH?** E.g., LWE for critical gates, keccak for others. Trade-off: complexity vs. security.

3. **Does SEH binding justify formal s-equivalence claims?** Or should we remain in "heuristic security" framing?

## Files

- PQ Contract: [TLOSLWE.sol](../contracts/TLOSLWE.sol)
- Legacy Contract: [TLOSKeccak.sol](../contracts/legacy/TLOSKeccak.sol)
- SEH module: [src/seh_lwe.rs](../src/seh_lwe.rs)
- LWE module: [src/lwe.rs](../src/lwe.rs)

---

*Document: SEH Wire Binding for TLO*
*Date: December 2025*
*Based on: Ma-Dai-Shi 2025 (eprint 2025/307)*
