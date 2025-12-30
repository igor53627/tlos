# TLOS: Topology-Lattice Obfuscation with SEH

**TLO + Ma-Dai-Shi LiO wire binding for inter-gate consistency.**

## What is TLOS?

TLOS extends [TLO](https://github.com/igor53627/tlo) with Subspace-Evasive Hashing (SEH) from [Ma-Dai-Shi 2025](https://eprint.iacr.org/2025/307) to add inter-gate wire consistency proofs.

### Components

| Layer | Origin | Purpose |
|-------|--------|---------|
| **T**opology | TLO | SixSix anti-attack wire patterns |
| **L**attice | TLO | LWE for control function hiding |
| **O**bfuscation | TLO | Circuit representation hiding |
| **S**EH | Ma-Dai-Shi | Inter-gate wire binding |

### Architecture

```
+------------------------------------------------------------------+
|                     TLOS Architecture                             |
+------------------------------------------------------------------+
|                                                                   |
|  Input x                                                          |
|     |                                                             |
|     v                                                             |
|  [SEH Init: h_0 = H(seed || x)]                                  |
|     |                                                             |
|     +---> Gate 0 (LWE C&C) ---> [SEH Update: h_1]                |
|     |                                                             |
|     +---> Gate 1 (LWE C&C) ---> [SEH Update: h_2]                |
|     |                                                             |
|     ...                                                           |
|     |                                                             |
|     +---> Gate N (LWE C&C) ---> [SEH Update: h_N]                |
|     |                                                             |
|     v                                                             |
|  [Verify: h_N == expectedSehHash AND output == expectedOutput]   |
|                                                                   |
+------------------------------------------------------------------+
```

## Gas Costs (Tenderly Measured)

| Variant | Config | Gas | % of Block | Overhead |
|---------|--------|-----|------------|----------|
| TLO-LWE-64 (Base) | 64w/640g | 2,576,882 | 8.6% | - |
| TLOS-Keccak | 64w/640g | 2,589,372 | 8.6% | +0.5% |
| TLOS-LWE | 64w/640g | 3,290,236 | 11.0% | +27.7% |

## SEH Variants

### Keccak SEH (Practical)
- Uses keccak256 hash chain
- ~12K gas overhead
- Relies on collision resistance

### LWE SEH (Theoretical)
- Uses LWE matrix-vector product
- ~713K gas overhead
- Provides subspace evasion property

## Security Properties

### What SEH Adds
- **Mix-and-match prevention**: Gates cannot be evaluated with inconsistent inputs
- **Execution trace binding**: Full evaluation history is committed
- **Formal s-equivalence**: (with LWE SEH) provable consistency

### What SEH Does NOT Add
- **Semantic security**: Black-box evaluation is still possible
- **Full iO**: This is not indistinguishability obfuscation
- **Key extraction resistance**: Still relies on LWE layer

## Quick Start

```bash
# Clone
git clone https://github.com/igor53627/tlos.git
cd tlos

# Build contracts
forge build

# Run benchmarks on Tenderly
forge script script/BenchmarkTLOS.s.sol --rpc-url $TENDERLY_RPC
```

## Repository Structure

```
tlos/
├── contracts/           # Solidity contracts
│   ├── TLOSKeccak.sol  # Keccak-based SEH
│   └── TLOSLWE.sol     # Full LWE SEH
├── src/                 # Rust implementation
│   ├── seh.rs          # SEH module
│   ├── lio.rs          # LiO integration
│   └── six_six.rs      # Topology generation
├── docs/               # Documentation
│   └── security.md     # Security model
└── examples/           # Usage examples
```

## References

- [Ma-Dai-Shi 2025](https://eprint.iacr.org/2025/307) - Quasi-Linear iO
- [TLO](https://github.com/igor53627/tlo) - Base construction (archived)
- [Vitalik-Elaine Discussion](https://gist.github.com/igor53627/090846405c3b9479af00617c87464f80) - iO context

## License

MIT
