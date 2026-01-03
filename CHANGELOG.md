# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed
- `examples/TLOSKitties.sol` - Used deprecated n=128 LWE parameters (incompatible with production)
- `examples/TLOSVault.sol` - Used incompatible `ITLOSCircuit.check()` interface

### Changed
- Updated README.md and wiki.json to remove references to deleted example contracts
- Example contracts table simplified (removed obsolete entries)

## [0.5.2] - 2026-01-03

### Added
- **Comprehensive test coverage** for TLOSWithPuzzleV4 (issue #41)
  - `test/TLOSWithPuzzleV4.t.sol`: 61 tests covering deployment, puzzle, wire binding, cross-layer, commit-reveal, gas
  - `test/TLOSWithPuzzleV4Harness.sol`: Test harness exposing internal functions for isolated layer testing
  - `test/PuzzleVariants.t.sol`: 13 tests comparing puzzle versions (V5, V6, V7)
- **Per-layer technical documentation** in `docs/layers/`
  - `docs/layers/README.md`: 4-layer security model overview
  - `docs/layers/layer1-topology/`: Circuit mixing (heuristic, `src/circuit.rs`)
  - `docs/layers/layer2-lwe/`: LWE encryption (~2^112 PQ, `src/lwe.rs`)
  - `docs/layers/layer3-binding/`: Wire binding (algebraic integrity, `src/wire_binding.rs`)
  - `docs/layers/layer4-puzzle/`: Planted LWE puzzle (2^76 brute-force, `WeakLWEPuzzleV7.sol`)
- **Attack scripts reorganized by layer** in `scripts/attacks/`
  - `scripts/attacks/layer1-topology/`: SAT/oracle-guided attacks (copied from circuit-mixing-research)
  - `scripts/attacks/layer2-lwe/`: Lattice attacks (existing, moved)
  - `scripts/attacks/layer3-binding/`: Mix-and-match attack (`mix_and_match_attack.py`)
  - `scripts/attacks/layer4-puzzle/`: Brute-force attacks (existing, moved)
  - `scripts/attacks/estimators/`: Security analysis tools (existing, moved)
  - `scripts/attacks/README.md`: Index of all attack scripts with key results

### Fixed
- Test assertion in `test_Puzzle_ValidSolutionAccepted` (was passing without verification)
- Revert expectation in `test_Blockhash_DelayEnforced` (wrong error at commitBlock+2)

### Documentation
- README.md: Added DeepWiki badge, Testing section, updated repository structure
- AGENTS.md: Added docs/layers/ and scripts/attacks/ structure reference

## [0.5.1] - 2026-01-02

### Fixed
- **CRITICAL: Layer 4 puzzle integration vulnerability** - V3 had `getPlantedSecret(x)` that allowed anyone to compute puzzle solution for any input, bypassing 2^76 security entirely
- TLOSWithPuzzleV4.sol: Correct puzzle design where planted secret is derived from SECRET, not input
  - `plantedSecret = H("planted" || secret)` computed by deployer
  - `(puzzleSeed, b)` stored in contract, NOT the planted secret
  - Attacker must solve ternary LWE (2^76 work) to find solution
  - Honest solver computes plantedSecret directly from secret

### Changed
- TLOSWithPuzzleV3 marked as deprecated (insecure - puzzle derivable from input)
- TLOSWithPuzzleV2 marked as deprecated (uses n=128 LWE)
- Paper updated: puzzle is ONE per contract (one-time 2^76 cost), not per-guess
- Composition rule corrected: 2^76 + min(2^h, 2^112)

### Security
- V4 provides correct layer integration: puzzle must be solved BEFORE any input testing
- After solving (2^76 work), attacker can test inputs but still faces LWE layer (2^112)

## [0.5.0] - 2026-01-01

### Added
- **Layer 4: Planted LWE Puzzle** - Forces minimum 3^48 ≈ 2^76 brute-force search space
- WeakLWEPuzzleV7.sol: Production puzzle contract (n=48, m=72, q=2039, 1.26M gas)
- WeakLWEPuzzleV5.sol: Reduced puzzle variant (n=32, m=48, ~51-bit security)
- WeakLWEPuzzleV6.sol: Minimal puzzle variant (n=24, m=36, ~38-bit security)
- TLOSWithPuzzleV2.sol: Integrated TLOS + Layer 4 puzzle with double binding
- lwe_puzzle_solver_v5.py: Off-chain puzzle solver with pycryptodome

### Changed
- Security model upgraded from three-layer to **four-layer**
- TLOS secret derivation now combines input AND puzzle solution hash for double binding
- Updated papers (tlos.tex, tlos-paper.tex) with Layer 4 sections

### Security
- GPU brute-force benchmark: 436M guesses/sec on GH200
- Exhaustive puzzle search (n=48): ~5.7 million years single GPU, ~570 years with 10,000 GPUs
- Layer 4 protects low-entropy inputs from dictionary attacks

## [0.4.0] - 2025-12-31

### Changed
- Upgraded LWE dimension from n=128 to n=768 (~120-140 bit PQ security)
- Replaced stored a vectors with seed-derived generation for storage efficiency
- Gas range now ~10.5M-38.1M depending on circuit configuration (17-63% of 60M block)

### Added
- Seed-derived a vector generation using keccak256 PRG
- Updated documentation for n=768 parameters

## [0.3.0] - 2025-12-31

### Changed
- Upgraded LWE dimension from n=64 to n=128 (~98-bit PQ security)
- SEH batch size increased to 128 gates (5 updates for 640 gates)
- Added PRG optimization: 16 coefficients per keccak (320 calls vs 4096)
- Single mod at end of LWE inner product (gas reduction)

### Added
- `_deriveSecret128Array` for n=128 LWE secret derivation
- `checkWithSeh()` function for debugging SEH outputs

## [0.2.0] - 2025-12-30

### Added
- Full paper (tlos-paper.tex) with security analysis
- Short paper (tlos.tex) for conference submission
- SEH wire binding documentation (docs/seh-wire-binding.md)
- Security model documentation (docs/security.md)

### Changed
- Moved TLOSKeccak to `contracts/legacy/` (deprecated, not PQ-secure)
- Updated contract headers with deprecation warnings

## [0.1.0] - 2025-12-29

### Added
- Initial TLOS implementation: TLO + Ma-Dai-Shi SEH wire binding
- TLOSLWE.sol: Post-quantum SEH using LWE-based full-rank 64x64 matrix
- TLOSKeccak.sol: Classical SEH using keccak256 (now deprecated)
- Rust generator (`generate_tlos`) for deployment data
- Benchmark script for Tenderly (BenchmarkTLOS.s.sol)
- IHoneypot interface for commit-reveal pattern
