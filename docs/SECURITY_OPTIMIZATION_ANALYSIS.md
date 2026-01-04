# TLOS Security Optimization Analysis

## Executive Summary

This document analyzes security optimization opportunities for TLOS across all four layers, with focus on:
1. Gas efficiency (must fit 15M EVM gas limit)
2. Post-quantum security
3. Novel techniques towards iO
4. Layer composability

**Current Status**: TLOS uses 3.7M gas for 64-gate verification (~6% of 60M block, well under 15M limit).

## Layer-by-Layer Analysis

### Layer 1: Topology (Structural Mixing)

**Current Implementation**:
- 64 wires, 640 gates (10 per wire)
- Toffoli-like gates: `active ^= truth_table[c1, c2]`
- Heuristic security (no formal proof)

**Security Assessment**:
- Resists pattern analysis due to random gate placement
- No recognizable gadgets (adders, comparators)
- Per FINDINGS.md, uniform secret LWE gives higher-than-claimed security

**Optimization Opportunities**:

1. **Structured Randomness via Lattice Trapdoors**
   - Instead of pure random gates, derive structure from lattice trapdoors
   - Inspired by [NTRU-based iO (ePrint 2025/1129)](https://eprint.iacr.org/2025/1129)
   - Could provide formal security reduction

2. **Algebraic Mixing**
   - Replace boolean mixing with algebraic operations over Z_q
   - Better compatibility with LWE layer
   - Potentially more efficient on-chain

**Recommendation**: Layer 1 is heuristic. Consider whether the entropy mixing can be replaced with lattice-based mixing for provable security.

### Layer 2: LWE (Control Function Hiding)

**Current Implementation**:
- n=384, q=65521, σ=8
- ~2^112 post-quantum security (lattice estimator)
- Uniform secrets (hash-derived) - non-standard but secure

**Security Assessment**:
- Excellent: 2^112 PQ security exceeds most requirements
- Uniform secrets resist primal attacks better than small secrets
- Input-derived key makes traces garbage without correct input

**Optimization Opportunities**:

1. **RLWE for Efficiency** (NOT RECOMMENDED)
   - Ring-LWE would be more efficient but harder to verify on-chain
   - Would require NTT implementation
   - Gas savings ~50% but complexity increase significant

2. **Seed-derived `a` vectors** (ALREADY IMPLEMENTED)
   - 99.8% storage reduction already achieved
   - Current implementation is near-optimal

3. **Smaller n for Testing**
   - n=256 gives ~2^90 security, saves gas
   - n=128 gives ~2^60 security, testing only

**Recommendation**: Current parameters are well-tuned. No changes needed.

### Layer 3: Wire Binding (Algebraic Integrity)

**Current Implementation**:
- Full-rank 64×64 linear map over Z_q
- Batch updates every 128 gates with XOR chaining
- PRG-based coefficient derivation (320 vs 4096 keccak calls)

**Security Assessment**:
- Algebraic binding, not collision resistance
- Prevents mix-and-match attacks
- Full-rank ensures bijectivity

**Optimization Opportunities**:

1. **Lattice-Based Binding Hash**
   - Replace linear map with short-vector based binding
   - Provides collision resistance (if needed)
   - Gas cost: roughly equivalent

2. **Merkle-Based Binding** (NOT RECOMMENDED)
   - Tree structure for binding
   - Higher gas cost due to multiple hashes
   - Less compatible with algebraic layers

3. **Fiat-Shamir Binding**
   - Derive binding from transcript hash
   - Already implicit in the XOR chaining
   - Could be made explicit for formal proof

**Recommendation**: Current implementation is efficient. Consider formalizing the binding as a Fiat-Shamir transform for cleaner security proof.

### Layer 4: Planted LWE Puzzle

**Current Implementation**:
- n=48, m=72, q=2039, threshold=300
- 3^48 ≈ 2^76 brute-force resistance
- 1.26M gas

**Security Assessment**:
- Provides minimum work floor regardless of input entropy
- V4 derives puzzle from secret (secure), not input (V3 vulnerability)
- GPU benchmark: ~5.7M years at 436M guesses/sec

**Optimization Opportunities**:

1. **Reduced Dimension for Gas Savings**
   - n=40: ~2^63 security, saves ~20% gas
   - n=32: ~2^51 security (testing only)
   - Trade-off: security margin vs. gas

2. **Batched Puzzle Verification**
   - Verify multiple solutions in single call
   - Amortized gas savings
   - Use case: multi-party reveals

3. **VDF-Based Puzzle Alternative**
   - Verifiable Delay Functions instead of LWE
   - Fixed time instead of fixed work
   - More predictable economics

**Recommendation**: n=48 provides good security/gas balance. Consider VDF for future versions.

## Novel Techniques Towards iO

### Current State of Lattice-Based iO

Recent developments (2025):
- [Diamond iO](https://eprint.iacr.org/2025/236): Replaces FE bootstrapping with matrix operations
- [NTRU+Equivocal LWE](https://eprint.iacr.org/2025/1129): Primal trapdoors enable hint generation
- [Circular Security with Random Opening](https://eprint.iacr.org/2025/390): New LWE-with-hints assumption

**Key Insight**: True iO requires indistinguishable obfuscations of equivalent circuits. TLOS provides point-function obfuscation, which is weaker but practical.

### Proposed Enhancements Towards iO

1. **Equivocal Control Functions**
   - Instead of fixing truth tables, use trapdoor sampling
   - Allows "programming" the circuit after deployment
   - Inspired by NTRU trapdoors

2. **All-Product LWE Integration**
   - Diamond iO uses all-product LWE for efficiency
   - Could replace current gate structure
   - Requires careful gas analysis

3. **Pseudorandom Oracle Model**
   - Diamond iO proves security in PROM
   - TLOS already uses Keccak as PRO
   - Formalize this for cleaner reduction

### Incremental Path to iO

```
Current TLOS (Point-Function Obfuscation)
    ↓
+ Trapdoor-based control functions
    ↓
+ Equivocal LWE for hint generation
    ↓
+ Bootstrapping-free FE (Diamond iO technique)
    ↓
Full iO (if assumptions hold)
```

## Gas Optimization Analysis

**Target**: 15M gas limit (Ethereum mainnet)
**Current**: 3.7M gas (64 gates) → 6.2% of 60M block

### Scaling Projections

| Gates | Est. Gas | % of 15M | Status |
|-------|----------|----------|--------|
| 64    | 3.7M     | 25%      | ✓ Safe |
| 128   | 5.5M     | 37%      | ✓ Safe |
| 256   | 9.1M     | 61%      | ✓ Marginal |
| 512   | 16.3M    | 109%     | ✗ Exceeds |
| 640   | 19.8M    | 132%     | ✗ Exceeds |

### Optimization Levers

1. **Reduce LWE dimension** (highest impact)
   - n=256: ~30% gas reduction, still 2^90 security
   - Trade-off: reduced PQ margin

2. **Smaller ciphertexts**
   - Current: 770 bytes per ciphertext
   - With compression: potentially 50% reduction
   - Requires off-chain precomputation

3. **Batched decryption**
   - Process multiple truth table bits per inner product
   - Limited by assembly optimization already done

4. **Wire binding frequency**
   - Current: every 128 gates
   - Reduce to every 256 gates: ~5% gas savings
   - Trade-off: coarser integrity granularity

## Composability with Other Layers

### Current Composability

- Layer 2 (LWE) depends on Layer 1 (circuit structure)
- Layer 3 (binding) depends on Layer 1 wire state evolution
- Layer 4 (puzzle) is independent, gates Layer 2 secret derivation

### Enhancement: Modular Layer Interface

```solidity
interface ITLOSLayer {
    function processGateBatch(
        uint256 wires,
        bytes calldata gateData,
        bytes32 context
    ) external pure returns (uint256 newWires, bytes32 binding);
}
```

Benefits:
- Swap Layer 1 implementations (boolean vs algebraic)
- Upgrade Layer 2 LWE parameters
- Add new layers (e.g., range proofs)

## Recommendations

### Immediate (No Breaking Changes)

1. **Add n=256 LWE variant** for gas-sensitive deployments
2. **Document uniform-secret security** bonus in README
3. **Formalize Fiat-Shamir binding** in security proof

### Medium-Term (Breaking Changes)

1. **Explore algebraic mixing** for Layer 1 (replace boolean gates)
2. **Add VDF puzzle option** for time-based rate limiting
3. **Modular layer interface** for future extensibility

### Long-Term (Research)

1. **Trapdoor-based control functions** from NTRU
2. **Equivocal LWE hints** for programmable circuits
3. **Diamond iO matrix operations** for FE-free obfuscation

## Security Considerations

### Quantum Resistance

| Layer | PQ Status | Notes |
|-------|-----------|-------|
| 1 (Topology) | N/A | Heuristic, no PQ claim |
| 2 (LWE) | ✓ 2^112 | Lattice estimator confirmed |
| 3 (Binding) | ✓ | Linear algebra is PQ-safe |
| 4 (Puzzle) | ✓ 2^76 | Ternary LWE is PQ-safe |
| Keccak | Conjectured | 2^128 vs Grover's 2^64 |

### Attack Surface Summary

1. **Structural attacks** (Layer 1): Heuristic resistance
2. **Lattice attacks** (Layer 2): 2^112 security
3. **Mix-and-match** (Layer 3): Algebraic binding
4. **Brute-force** (Layer 4): 2^76 minimum work

### Residual Risks

- Layer 1 has no formal security proof
- Long-term secrets (>10 years) need larger parameters
- New lattice cryptanalysis could affect security estimates

## References

1. [Diamond iO (ePrint 2025/236)](https://eprint.iacr.org/2025/236)
2. [NTRU+Equivocal LWE (ePrint 2025/1129)](https://eprint.iacr.org/2025/1129)
3. [Circular Security with Random Opening (ePrint 2025/390)](https://eprint.iacr.org/2025/390)
4. TLOS Layer Documentation: `docs/layers/`
5. Attack Scripts: `scripts/attacks/`
