# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
