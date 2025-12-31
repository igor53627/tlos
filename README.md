# TLOS: Topology-Lattice Obfuscation for Smart Contracts

**Three-layer obfuscation with full-rank wire binding for inter-gate consistency.**

TLOS is a practical circuit obfuscation framework for EVM. It uses a noiseless LWE-like construction (LBLO) for control function hiding and full-rank linear hashing for wire binding. Security estimates are **heuristic** (not based on standard LWE reductions).

## What is TLOS?

TLOS provides three-layer security for on-chain circuit obfuscation:

1. **Topology layer**: Structural mixing defeats structural/statistical attacks (heuristic)
2. **LBLO layer**: Noiseless LWE-like inner products hide control functions (heuristic ~2^98 PQ)
3. **Wire binding layer**: Full-rank 64x64 public linear map binds wire values across gates (algebraic binding, not cryptographic hashing)

The wire binding construction is *inspired by* [Ma-Dai-Shi 2025](https://eprint.iacr.org/2025/307) but is **not** subspace-evasive in the formal sense - it is a public bijective linear map providing algebraic binding, not cryptographic hiding.

### Components

| Layer | Purpose | Security |
|-------|---------|----------|
| **T**opology | Anti-attack wire patterns (non-pow2 distances, uniform usage) | Heuristic (empirical) |
| **L**attice (LBLO) | Control function hiding via noiseless LWE-like inner products | Heuristic (~2^98 PQ LBLO) |
| **O**bfuscation | Circuit representation hiding | Heuristic |
| Wire **B**inding | Inter-gate wire consistency via full-rank linear hash | Algebraic binding |

### Architecture

```
+------------------------------------------------------------------+
|                       TLOS Architecture                           |
+------------------------------------------------------------------+
|                                                                   |
|  Input x                                                          |
|     |                                                             |
|     v                                                             |
|  [Wire Binding Init: acc_0 = H(seed || x)]                       |
|     |                                                             |
|     +---> Gate 0 (LBLO C&C) ---> [Binding Update: acc_1]         |
|     |                                                             |
|     +---> Gate 1 (LBLO C&C) ---> [Binding Update: acc_2]         |
|     |                                                             |
|     ...                                                           |
|     |                                                             |
|     +---> Gate N (LBLO C&C) ---> [Binding Update: acc_N]         |
|     |                                                             |
|     v                                                             |
|  [Verify: acc_N == expected AND output == expectedOutput]        |
|                                                                   |
+------------------------------------------------------------------+
```

## Gas Costs (Measured)

| Variant | Config | Gas | % of Block | Security (Heuristic) |
|---------|--------|-----|------------|----------------------|
| **TLOS (n=128, full-rank 64x64 binding)** | 64w/640g | ~8.5M | 28% | Heuristic ~2^98 PQ (LBLO) |

**Optimizations applied:**
- Wire binding PRG: 16 coefficients per keccak (320 calls vs 4096)
- Single mod at end of inner product (vs per-term mod)
- Batch size 128 (5 binding updates for 640 gates)
- n=128 LBLO dimension

## Advantage Over Simple Hash Commitments

Why use TLOS instead of `keccak256(secret)`? For random 256-bit secrets, keccak is simpler and sufficient. However, TLOS is **designed to help** for **low-entropy secrets** and **multi-bit payloads**, assuming the heuristic LBLO hardness holds.

| Secret Type | Keccak Attack (est.) | TLOS Attack (heuristic est.) |
|-------------|----------------------|------------------------------|
| Random 256-bit | ~2^256 hashes | min(2^256, ~2^98)* |
| Human password | Milliseconds | Hours-days* |
| Range 0-100K | ~0.1 seconds | 2.8+ hours* |
| 4-word phrase | Seconds | Weeks* |

*Heuristic estimates assuming LBLO has ~2^98 PQ work factor when modeled as LWE in standard lattice estimators. See **Security Disclaimer**.

**Key insight:** TLOS provides a practical way to make low-entropy secret verification expensive on EVM - no memory-hard KDF (Argon2/scrypt) exists as a precompile.

### Concrete Use Cases

- **Password-gated vaults:** Human phrase unlocks funds
- **On-chain treasure hunts:** Riddle answer reveals GPS coordinates or URL
- **Number guessing games:** Hide value in 0-100K range without enumeration
- **Multi-code access:** OR of N event codes (any code unlocks)
- **Hidden game parameters:** Tournament seeds revealed at game start

### When to Use Keccak Instead

For random 256-bit secrets with no payload beyond TRUE/FALSE, simple keccak commitments are better (cheaper, simpler, no security loss).

## Security Properties

**Important:** Security estimates are **heuristic**, not formal guarantees. Our LBLO construction is noiseless and lacks standard LWE reductions. See `paper/tlos-paper.pdf` for full analysis.

### What Wire Binding Provides
- **Mix-and-match prevention**: Gates cannot be evaluated with inconsistent inputs
- **Execution trace binding**: Full evaluation history is committed
- **Algebraic binding**: Full-rank 64x64 matrix provides unique preimage (bijective map)

### What Wire Binding Does NOT Provide
- **Cryptographic hiding**: The linear map is public and invertible
- **Collision resistance**: Trivial to find x given Ax = y
- **Key extraction resistance**: Still relies on LBLO layer for CF hiding

### What TLOS Does NOT Provide
- **iO security**: Obfuscations of equivalent circuits are not indistinguishable
- **VBB security**: Virtual black-box is impossible in general
- **Standard LWE security**: LBLO is noiseless; no reduction to worst-case lattice problems
- **Long-term secret protection**: Not recommended for secrets requiring decades of protection

## Quick Start

```bash
# Clone
git clone https://github.com/igor53627/tlos.git
cd tlos

# Build contracts
forge build

# Generate circuit data
cargo run --bin generate_tlos -- --secret 0x... --seed 42

# Run benchmarks on Tenderly
source ~/.zsh_secrets
forge script scripts/BenchmarkTLOS.s.sol --rpc-url "$TENDERLY_RPC" --broadcast --unlocked -vvv
```

## Repository Structure

```
tlos/
├── contracts/
│   ├── TLOSLWE.sol         # Main contract (LBLO + wire binding; legacy "LWE" name)
│   ├── interfaces/
│   └── legacy/
│       └── TLOSKeccak.sol  # Classical only, deprecated
├── src/                     # Rust implementation
│   ├── circuit.rs          # Circuit/gate structures
│   ├── lwe.rs              # LBLO (noiseless LWE-like) encoding
│   ├── seh_lwe.rs          # Wire binding implementation (legacy "SEH/LWE" filename)
│   ├── generator.rs        # Deployment generator
│   └── bin/
│       └── generate_tlos.rs # CLI binary
├── scripts/
│   ├── BenchmarkTLOS.s.sol # Tenderly benchmark
│   └── lblo_attack*.py     # LBLO attack analysis scripts
├── docs/
│   ├── security.md         # Security model
│   └── seh-wire-binding.md # Wire binding details (legacy "SEH" name)
├── paper/
│   ├── tlos-paper.pdf      # Full paper (source of truth)
│   └── tlos.pdf            # Short paper
└── examples/
```

## Security Disclaimer

TLOS security is based on the **conjectured hardness of the LBLO problem** (Learning with Binary Large Offset). This is a noiseless, LWE-like construction that lacks formal reductions to standard lattice problems.

- The ~2^98 PQ estimate is a **heuristic yardstick** based on modeling LBLO as LWE in lattice estimators
- We encourage **independent cryptanalysis** of the LBLO problem
- Attack scripts available in `scripts/lblo_attack.py`
- **Do not use for high-value, long-lived secrets** until further analysis is available

## References

- [Ma-Dai-Shi 2025](https://eprint.iacr.org/2025/307) - Quasi-Linear iO (wire binding inspiration)
- [TLO](https://github.com/igor53627/tlo) - Base construction (archived)
- [LWE Estimator](https://github.com/malb/lattice-estimator) - Security estimates

## License

MIT
