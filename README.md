# TLOS: Topology-Lattice Obfuscation for Smart Contracts

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/igor53627/tlos)

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
| **P**uzzle | One-time brute-force barrier before input testing | Computational (~2^76) |

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

*Layer 4 puzzle forces minimum 3^48 ≈ 2^76 search space regardless of input entropy. At 1B guesses/sec (GH200 FP16, worst-case), exhaustive search takes ~2.5 million years. See **Security Disclaimer**.

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

**GPU brute-force resistance:** At 1B guesses/sec (GH200 FP16, worst-case), exhaustive search requires ~2.5 million years. Even 10,000 GPUs (~250 years) cannot crack in practical time.

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
│   ├── TLOSWithPuzzleV4.sol  # TLOS + Layer 4 planted LWE puzzle (PRODUCTION)
│   ├── WeakLWEPuzzleV7.sol   # Standalone puzzle (n=48, production)
│   ├── WeakLWEPuzzleV5.sol   # Puzzle variant (n=32, reduced)
│   ├── interfaces/
│   └── legacy/
│       └── TLOSKeccak.sol    # Classical only, deprecated
├── src/                       # Rust implementation
│   ├── circuit.rs            # Circuit/gate structures (Layer 1)
│   ├── lwe.rs                # LWE encoding (Layer 2, Gaussian noise, σ=8)
│   ├── wire_binding.rs       # Wire binding implementation (Layer 3)
│   ├── generator.rs          # Deployment generator
│   ├── security/             # Security estimation
│   │   └── lattice_estimator.rs  # lattice-estimator CLI wrapper
│   └── bin/
│       └── generate_tlos.rs  # CLI binary
├── test/                      # Foundry tests (215 tests)
│   ├── TLOSWithPuzzleV4.t.sol    # Production contract tests (61 tests)
│   ├── TLOSWithPuzzleV4Harness.sol  # Test harness for isolated testing
│   ├── PuzzleVariants.t.sol      # All puzzle versions (18 tests)
│   └── *.t.sol               # Additional test suites
├── scripts/
│   ├── BenchmarkTLOS.s.sol   # Tenderly benchmark
│   └── attacks/              # Attack scripts organized by layer
│       ├── layer1-topology/  # SAT/oracle-guided attacks (Rust)
│       ├── layer2-lwe/       # Lattice attacks (Python)
│       ├── layer3-binding/   # Mix-and-match attacks (Python)
│       ├── layer4-puzzle/    # Brute-force attacks (Python/GPU)
│       └── estimators/       # Security estimation tools
├── docs/
│   ├── layers/               # Per-layer technical documentation
│   │   ├── layer1-topology/  # Circuit mixing (heuristic)
│   │   ├── layer2-lwe/       # LWE encryption (~2^112 PQ)
│   │   ├── layer3-binding/   # Wire binding (algebraic)
│   │   └── layer4-puzzle/    # Planted LWE puzzle (2^76)
│   ├── security.md           # Security model
│   └── wire-binding.md       # Wire binding details
├── paper/
│   ├── tlos-paper.pdf        # Full paper (source of truth)
│   └── tlos.pdf              # Short paper
└── examples/
    ├── TLOSVault.sol         # DeFi: Hidden liquidation threshold (DEMO ONLY)
    ├── TLOSKitties.sol       # NFT: Hidden trait generation (n=128, reduced)
    ├── TLOSRecovery.sol      # Wallet: Phrase-based recovery with puzzle
    ├── TLOSTreasureHunt.sol  # Honeypot: Commit-reveal + puzzle (educational)
    ├── TLOSSealedAuction.sol # Gaming: Sealed-bid auction with puzzle
    ├── TLOSDeadManSwitch.sol # Inheritance: Heartbeat + hidden heir codes
    └── TLOSStopLoss.sol      # DeFi: Hidden stop-loss triggers
```

## Example Contracts

The `examples/` directory contains demonstration contracts showing TLOS integration patterns for various use cases. **These are for education only - see warnings in each file.**

| Example | Use Case | Layers Used | LWE n | Puzzle | Production Ready |
|---------|----------|-------------|-------|--------|------------------|
| TLOSWithPuzzleV4 | **Production** | 1-4 (all) | 384 | Yes | [OK] |
| TLOSVault | DeFi liquidation | 2 (LWE only) | - | No | [X] Economically broken |
| TLOSKitties | NFT traits | 2 (LWE only) | 128 | No | [X] Reduced security |
| TLOSRecovery | Wallet recovery | 4 (puzzle) | - | Yes | [X] Needs phrase entropy |
| TLOSTreasureHunt | Honeypot | 4 (puzzle) | - | Yes | [X] Educational |
| TLOSSealedAuction | Sealed-bid auction | 4 (puzzle) | - | Yes | [X] Demo only |
| TLOSDeadManSwitch | Inheritance | 4 (puzzle) | - | Yes | [X] Demo only |
| TLOSStopLoss | Stop-loss trigger | 2 (circuit) | - | No | [X] Demo only |

**Layer key:**
- Layer 1: Topology mixing (structural)
- Layer 2: LWE control function hiding (n=384, σ=8 for production)
- Layer 3: Wire binding (algebraic)
- Layer 4: Planted LWE puzzle (2^76 minimum search space)

## Testing

TLOS has comprehensive test coverage with 215 tests across all layers:

```bash
# Run all tests
forge test

# Run with gas reporting
forge test --gas-report

# Run specific test file
forge test --match-path test/TLOSWithPuzzleV4.t.sol
```

**Key test files:**
- `test/TLOSWithPuzzleV4.t.sol` - 61 tests for the production contract (deployment, puzzle, wire binding, cross-layer, commit-reveal, gas benchmarks)
- `test/PuzzleVariants.t.sol` - 18 tests comparing all puzzle versions (V2, V4, V5, V6, V7)
- `test/TLOSWithPuzzleV4Harness.sol` - Exposes internal functions for isolated layer testing

## Security Disclaimer

TLOS security is based on the **standard LWE problem with Gaussian noise** and the **planted LWE puzzle**.

- The ~2^112 PQ estimate (for n=384, σ=8) is confirmed by the lattice estimator
- Layer 4 puzzle provides **minimum 2^76 search space** regardless of input entropy
- GPU brute-force benchmark: ~2M guesses/sec on RTX 4090 (exhaustive search: ~1.2 billion years)
- We encourage **independent cryptanalysis**
- Attack scripts organized by layer in `scripts/attacks/` - see `scripts/attacks/README.md`
- **Do not use for high-value, long-lived secrets** until further analysis is available

## Development Dependencies

For programmatic security estimation, set up the [lattice-estimator](https://github.com/malb/lattice-estimator):

```bash
# Clone the estimator (requires SageMath)
git clone https://github.com/malb/lattice-estimator estimator
export PYTHONPATH="$PYTHONPATH:$(pwd)/estimator"

# Add the CLI to PATH
export PATH="$PATH:$(pwd)/scripts"

# Verify installation
lattice-estimator-cli 384 65521 \
    --s-dist '{"distribution":"uniform_mod"}' \
    --e-dist '{"distribution":"discrete_gaussian","stddev":8.0}' \
    --m 2560
```

Then run the ignored tests to validate security parameters:

```bash
cargo test -- --ignored
```

## References

- [Ma-Dai-Shi 2025](https://eprint.iacr.org/2025/307) - Quasi-Linear iO (wire binding inspiration)
- [TLO](https://github.com/igor53627/tlo) - Base construction (archived)
- [LWE Estimator](https://github.com/malb/lattice-estimator) - Security estimates

## License

MIT
