# TLOS: Post-Quantum Topology-Lattice Obfuscation with SEH

**TLO + Ma-Dai-Shi LiO wire binding for inter-gate consistency.**

TLOS is a **post-quantum (PQ) obfuscation prototype**. The only SEH construction is **LWE-based SEH (TLOSLWE.sol)**.

## What is TLOS?

TLOS extends [TLO](https://github.com/igor53627/tlo) with Subspace-Evasive Hashing (SEH) from [Ma-Dai-Shi 2025](https://eprint.iacr.org/2025/307) to add inter-gate wire consistency proofs.

### Components

| Layer | Origin | Purpose | PQ? |
|-------|--------|---------|-----|
| **T**opology | TLO | SixSix anti-attack wire patterns | N/A |
| **L**attice | TLO | LWE for control function hiding | Yes (~98-bit with n=128) |
| **O**bfuscation | TLO | Circuit representation hiding | Yes |
| **S**EH | Ma-Dai-Shi | Inter-gate wire binding (LWE) | Yes (~98-bit with n=128) |

### Architecture

```
+------------------------------------------------------------------+
|                     TLOS Architecture (PQ)                        |
+------------------------------------------------------------------+
|                                                                   |
|  Input x                                                          |
|     |                                                             |
|     v                                                             |
|  [SEH Init: h_0 = H_LWE(seed || x)]                              |
|     |                                                             |
|     +---> Gate 0 (LWE C&C) ---> [SEH Update: h_1 = H_LWE(h_0)]   |
|     |                                                             |
|     +---> Gate 1 (LWE C&C) ---> [SEH Update: h_2 = H_LWE(h_1)]   |
|     |                                                             |
|     ...                                                           |
|     |                                                             |
|     +---> Gate N (LWE C&C) ---> [SEH Update: h_N]                |
|     |                                                             |
|     v                                                             |
|  [Verify: h_N == expectedSehOutput AND output == expectedOutput] |
|                                                                   |
+------------------------------------------------------------------+
```

## Gas Costs (Measured)

| Variant | Config | Gas | % of Block | PQ Security |
|---------|--------|-----|------------|-------------|
| **TLOS-LWE (n=128, Full-rank 64x64 SEH)** | 64w/640g | ~8.5M | 28% | ~98-bit |

**Optimizations applied:**
- SEH PRG: 16 coefficients per keccak (320 calls vs 4096)
- Single mod at end of inner product (vs per-term mod)
- Batch size 128 (5 SEH updates for 640 gates)
- n=128 LWE dimension for ~98-bit PQ security

## Advantage Over Simple Hash Commitments

Why use TLOS instead of `keccak256(secret)`? For random 256-bit secrets, keccak is simpler and sufficient. However, TLOS excels for **low-entropy secrets** and **multi-bit payloads**.

| Secret Type | Keccak Attack | TLOS Attack |
|-------------|---------------|-------------|
| Random 256-bit | 2^256 hashes | 2^256 LWE evals |
| Human password | Milliseconds | Hours-days |
| Range 0-100K | 0.1 seconds | 2.8+ hours |
| 4-word phrase | Seconds | Weeks |

**Key insight:** TLOS brings tunable computational hardness to EVM where no memory-hard KDF (Argon2/scrypt) exists as a precompile.

### Concrete Use Cases

- **Password-gated vaults:** Human phrase unlocks funds without separate salt
- **On-chain treasure hunts:** Riddle answer reveals GPS coordinates or URL
- **Number guessing games:** Hide value in 0-100K range without enumeration
- **Multi-code access:** OR of N event codes (any code unlocks)
- **Secret wallet prizes:** Correct phrase reveals 24-word seed
- **Hidden game parameters:** Tournament seeds revealed at game start

### When to Use Keccak Instead

For random 256-bit secrets with no payload beyond TRUE/FALSE, simple keccak commitments are better (cheaper, simpler, no security loss).

## Security Properties

### What SEH Adds
- **Mix-and-match prevention**: Gates cannot be evaluated with inconsistent inputs
- **Execution trace binding**: Full evaluation history is committed
- **Post-quantum binding**: LWE-based SEH provides PQ security

### What SEH Does NOT Add
- **Semantic security**: Black-box evaluation is still possible
- **Full iO**: This is not indistinguishability obfuscation

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
│   ├── TLOSLWE.sol         # PQ SEH (LWE-based) - default
│   ├── interfaces/
│   └── legacy/
│       └── TLOSKeccak.sol  # Classical only, deprecated
├── src/                     # Rust implementation
│   ├── circuit.rs          # Circuit/gate structures
│   ├── lwe.rs              # LWE encoding
│   ├── seh_lwe.rs          # LWE SEH (matches Solidity)
│   ├── generator.rs        # Deployment generator
│   └── bin/
│       └── generate_tlos.rs # CLI binary
├── scripts/
│   └── BenchmarkTLOS.s.sol # Tenderly benchmark
├── docs/
│   ├── security.md         # Security model
│   └── seh-wire-binding.md # SEH details
├── paper/
│   └── tlos-paper.pdf      # Full paper
└── examples/
```

## References

- [Ma-Dai-Shi 2025](https://eprint.iacr.org/2025/307) - Quasi-Linear iO
- [TLO](https://github.com/igor53627/tlo) - Base construction (archived)

## License

MIT
