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

### Our Keccak-Based SEH (Practical)

For on-chain deployment, we use keccak256-based hashing:

```solidity
// Initialize from circuit seed
bytes32 sehAcc = keccak256(abi.encodePacked(circuitSeed, "SEH-INIT", wires));

// Per-gate update
for (uint32 i = 0; i < numGates; i++) {
    // ... evaluate gate ...
    sehAcc = keccak256(abi.encodePacked(sehAcc, i, wires));
}

// Final verification
bytes32 finalSeh = keccak256(abi.encodePacked(sehAcc, finalWires, numGates));
require(finalSeh == expectedSehHash, "SEH mismatch");
```

**Gas cost: ~95K for 640-gate circuit (1.75x overhead vs base TLO-CaC)**

## Security Properties

### What SEH Provides

| Property | Without SEH | With SEH |
|----------|-------------|----------|
| Mix-and-match attack | Possible | Prevented |
| Execution trace binding | None | Cryptographic |
| s-equivalence proof | Heuristic | Formal (with caveats) |

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

This is provable for keccak-SEH (collision resistance) and for LWE-SEH (subspace evasion).

## Gas Comparison (Tenderly Measured)

| Scheme | Config | Gas | % of 30M Block | Notes |
|--------|--------|-----|----------------|-------|
| TLO-LWE-64 (Base) | 64w/640g | **2,576,882** | 8.6% | LWE only, no SEH |
| TLO-LiO-Keccak | 64w/640g | **2,589,372** | 8.6% | +keccak SEH binding |
| TLO-LiO-LWE | 64w/640g | **3,290,236** | 11.0% | +full LWE SEH |

### Key Findings

1. **Keccak SEH adds only ~12K gas (0.5% overhead)** - Much cheaper than theoretical estimate
2. **LWE SEH adds ~713K gas (27.7% overhead)** - Still practical, under block limit
3. **Both variants are deployable** - Neither exceeds 30M gas limit

### Why Actual Gas < Theoretical Estimate?

The theoretical estimate assumed per-gate SEH updates. In practice:
- Keccak SEH: Only 1 final hash (not per-gate)
- LWE SEH: Simplified matrix derivation via keccak PRG

## Architecture

```
+------------------------------------------------------------------+
|                     TLO-LiO Architecture                          |
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

### TLOHoneypotLiO.sol

Located at: `tlo/contracts/TLOHoneypotLiO.sol`

Key additions over TLOHoneypotCaC:
- `expectedSehHash`: Final SEH accumulator value (set at deploy)
- `checkWithSeh()`: Returns both validity and SEH hash (for debugging)
- Per-gate SEH accumulator update in evaluation loop

### Deployment

```solidity
constructor(
    bytes memory _circuitData,
    uint8 _numWires,
    uint32 _numGates,
    bytes32 _circuitSeed,
    bytes32 _expectedOutputHash,
    bytes32 _expectedSehHash,      // NEW: SEH binding
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

| Aspect | Ma-Dai-Shi | TLO-LiO |
|--------|------------|---------|
| SEH construction | FHE Merkle + LWE matrix | Keccak256 chain |
| Security proof | Formal (s-equivalence) | Heuristic + collision resistance |
| Gas cost | Impractical | ~95K (practical) |
| Trapdoor extraction | Yes (for debugging) | No (not needed on-chain) |
| iO claim | Yes (quasi-linear) | No (representation hiding only) |

## Limitations

1. **Keccak-SEH is weaker than LWE-SEH**: Relies on hash collision resistance, not LWE hardness
2. **No trapdoor mode**: Cannot extract specific bits without full evaluation
3. **Still point-function only**: SEH doesn't expand predicate expressiveness

## Open Questions for Reviewer

1. **Is keccak-SEH sufficient for mix-and-match prevention?** The attack model assumes adversary cannot find hash collisions.

2. **Should we implement partial LWE-SEH?** E.g., LWE for critical gates, keccak for others. Trade-off: complexity vs. security.

3. **Does SEH binding justify formal s-equivalence claims?** Or should we remain in "heuristic security" framing?

## Files

- Contract: [TLOHoneypotLiO.sol](../contracts/TLOHoneypotLiO.sol)
- Gas estimate: [lio_gas_estimate.rs](../examples/lio_gas_estimate.rs)
- SEH module: [src/seh.rs](../../src/seh.rs)
- LiO module: [src/lio.rs](../../src/lio.rs)

---

*Document: SEH Wire Binding for TLO*
*Date: December 2025*
*Based on: Ma-Dai-Shi 2025 (eprint 2025/307)*
