# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
