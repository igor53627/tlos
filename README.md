# TLOS: Topology-Lattice Obfuscation for Smart Contracts

**Four-layer obfuscation with planted LWE puzzle for minimum brute-force resistance.**

TLOS is a practical circuit obfuscation framework for EVM. It uses standard LWE with Gaussian noise (σ=8, n=384) for control function hiding, full-rank linear hashing for wire binding, and a planted LWE puzzle to force minimum 2^76 brute-force search space. Security is based on standard LWE hardness (~2^112 PQ).

## What is TLOS?

TLOS provides four-layer security for on-chain circuit obfuscation:

1. **Topology layer**: Structural mixing defeats structural/statistical attacks (heuristic)
2. **LWE layer**: Standard LWE with Gaussian noise (σ=8, n=384) hides control functions (~2^112 PQ)
3. **Wire binding layer**: Full-rank 64x64 public linear map binds wire values across gates (algebraic binding)
4. **Planted LWE puzzle**: Forces minimum 3^48 ≈ 2^76 brute-force search space regardless of input entropy (1.26M gas)

The wire binding construction is *inspired by* [Ma-Dai-Shi 2025](https://eprint.iacr.org/2025/307) but is **not** subspace-evasive in the formal sense - it is a public bijective linear map providing algebraic binding, not cryptographic hiding.

### Components

| Layer | Purpose | Security |
|-------|---------|----------|
| **T**opology | Anti-attack wire patterns (non-pow2 distances, uniform usage) | Heuristic (empirical) |
| **L**attice (LWE) | Control function hiding via LWE with Gaussian noise (σ=8) | ~2^112 PQ (n=384) |
| **O**bfuscation | Circuit representation hiding | Heuristic |
| Wire **B**inding | Inter-gate wire consistency via full-rank linear hash | Algebraic binding |
| **P**uzzle | Minimum brute-force work per guess | Computational (~2^76) |

### Architecture

```
+------------------------------------------------------------------------+
|                          TLOS Architecture                             |
+------------------------------------------------------------------------+
|                                                                        |
|  Input x + Puzzle Solution s                                           |
|     |                                                                  |
|     v                                                                  |
|  [Layer 4: Verify Puzzle ||As - b||^2 < threshold]                     |
|     |                                                                  |
|     v                                                                  |
|  [Wire Binding Init: acc_0 = H(seed || x || H(s))]                     |
|     |                                                                  |
|     +---> Gate 0 (LWE C&C) --> [Binding Update: acc_1]                 |
|     |                                                                  |
|     +---> Gate 1 (LWE C&C) --> [Binding Update: acc_2]                 |
|     |                                                                  |
|     ...                                                                |
|     |                                                                  |
|     +---> Gate N (LWE C&C) --> [Binding Update: acc_N]                 |
|     |                                                                  |
|     v                                                                  |
|  [Verify: acc_N == expected AND output == expectedOutput]              |
|                                                                        |
+------------------------------------------------------------------------+
```

## Gas Costs (Measured on Tenderly)

| Config (n=384) | Gates | Circuit Gas | Puzzle Gas | Total Gas | % of 60M Block |
|----------------|-------|-------------|------------|-----------|----------------|
| Conservative | 64 | 1.8M | 1.26M | 3.1M | 5% |
| Balanced | 128 | 2.0M | 1.26M | 3.3M | 5.5% |
| Full security | 256 | 3.0M | 1.26M | 4.3M | 7% |

**Optimizations applied:**
- **Seed-derived `a` vectors**: 99.8% storage reduction (11 bytes/gate vs 6155 bytes)
- Wire binding PRG: 16 coefficients per keccak (320 calls vs 4096)
- Single mod at end of inner product (vs per-term mod)
- Batch size 128 (binding updates every 128 gates)
- n=384 LWE dimension with Gaussian noise (σ=8) for ~2^112 PQ security
- Layer 4 puzzle: n=48, m=72, q=2039 for 2^76 minimum security

## Storage

TLOS uses **seed-derived `a` vectors** - the public LWE vectors are regenerated on-chain from a circuit seed instead of being stored.

| Config (n=384) | Gates | Storage | Old Format | Savings |
|----------------|-------|---------|------------|---------|
| Conservative | 64 | 704 bytes | 394 KB | 99.6% |
| Balanced | 128 | 1.4 KB | 788 KB | 99.6% |
| Full security | 256 | 2.8 KB | 1.58 MB | 99.6% |

**Deployment scheme:**
1. Deploy circuit data once via SSTORE2 (~615K gas for 256 gates)
2. Multiple contract instances reference the shared `circuitDataPointer`
3. Each instance deployment: ~100K gas (no data duplication)

**View vs Transaction costs:**
- `check(input)`: **Free** (view function, local simulation)
- `reveal(input)` / `mint()`: 1.8M-6M gas (state-changing, executes `_evaluate()`)

## Advantage Over Simple Hash Commitments

Why use TLOS instead of `keccak256(secret)`? For random 256-bit secrets, keccak is simpler and sufficient. However, TLOS provides significant advantage for **low-entropy secrets** and **multi-bit payloads**.

| Secret Type | Keccak Attack (est.) | TLOS Attack (est.) |
|-------------|----------------------|---------------------|
| Random 256-bit | ~2^256 hashes | min(2^256, ~2^112)* |
| Human password | Milliseconds | Weeks-months* |
| Range 0-100K | ~0.1 seconds | 2^76 minimum* |
| 4-word phrase | Seconds | 2^76 minimum* |

*Layer 4 puzzle forces minimum 3^48 ≈ 2^76 search space regardless of input entropy. At ~2M guesses/sec (RTX 4090), exhaustive search takes ~1.2 billion years. See **Security Disclaimer**.

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

Security is based on standard LWE hardness with Gaussian noise (σ=8). The lattice estimator confirms ~2^112 PQ security for n=384, q=65521, m=2560. See `paper/tlos-paper.pdf` for full analysis.

### Layer 4 Puzzle Parameters

| Parameter | Value |
|-----------|-------|
| Secret dimension n | 48 |
| Samples m | 72 |
| Modulus q | 2039 |
| Secret distribution | Ternary {-1,0,1} |
| Error distribution | Uniform {-2,-1,0,1,2} |
| Threshold | 300 |
| Search space | 3^48 ≈ 2^76 |
| Verification gas | 1.26M |

**GPU brute-force resistance:** At ~2M guesses/sec (RTX 4090), exhaustive search requires ~1.2 billion years.

### What Wire Binding Provides
- **Mix-and-match prevention**: Gates cannot be evaluated with inconsistent inputs
- **Execution trace binding**: Full evaluation history is committed
- **Algebraic binding**: Full-rank 64x64 matrix provides unique preimage (bijective map)

### What Wire Binding Does NOT Provide
- **Cryptographic hiding**: The linear map is public and invertible
- **Collision resistance**: Trivial to find x given Ax = y
- **Key extraction resistance**: Still relies on LWE layer for CF hiding

### What TLOS Does NOT Provide
- **iO security**: Obfuscations of equivalent circuits are not indistinguishable
- **VBB security**: Virtual black-box is impossible in general
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
│   ├── TLOS.sol              # Main contract (LWE + wire binding)
│   ├── TLOSWithPuzzleV2.sol  # TLOS + Layer 4 planted LWE puzzle
│   ├── WeakLWEPuzzleV7.sol   # Standalone puzzle (n=48, production)
│   ├── WeakLWEPuzzleV5.sol   # Puzzle variant (n=32, reduced)
│   ├── interfaces/
│   └── legacy/
│       └── TLOSKeccak.sol    # Classical only, deprecated
├── src/                       # Rust implementation
│   ├── circuit.rs            # Circuit/gate structures
│   ├── lwe.rs                # LWE encoding (Gaussian noise, σ=8)
│   ├── wire_binding.rs       # Wire binding implementation
│   ├── generator.rs          # Deployment generator
│   └── bin/
│       └── generate_tlos.rs  # CLI binary
├── scripts/
│   ├── BenchmarkTLOS.s.sol   # Tenderly benchmark
│   ├── tlos_attack.py        # LWE attack analysis scripts
│   └── lwe_puzzle_solver_v5.py # Off-chain puzzle solver
├── docs/
│   ├── security.md           # Security model
│   └── wire-binding.md       # Wire binding details
├── paper/
│   ├── tlos-paper.pdf        # Full paper (source of truth)
│   └── tlos.pdf              # Short paper
└── examples/
```

## Security Disclaimer

TLOS security is based on the **standard LWE problem with Gaussian noise** and the **planted LWE puzzle**.

- The ~2^112 PQ estimate (for n=384, σ=8) is confirmed by the lattice estimator
- Layer 4 puzzle provides **minimum 2^76 search space** regardless of input entropy
- GPU brute-force benchmark: ~2M guesses/sec on RTX 4090 (exhaustive search: ~1.2 billion years)
- We encourage **independent cryptanalysis**
- Attack scripts available in `scripts/tlos_attack.py` and `scripts/lwe_puzzle_solver_v5.py`
- **Do not use for high-value, long-lived secrets** until further analysis is available

## References

- [Ma-Dai-Shi 2025](https://eprint.iacr.org/2025/307) - Quasi-Linear iO (wire binding inspiration)
- [TLO](https://github.com/igor53627/tlo) - Base construction (archived)
- [LWE Estimator](https://github.com/malb/lattice-estimator) - Security estimates

## License

MIT
