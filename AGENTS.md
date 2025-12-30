# TLOS Agent Instructions

## Project Overview

TLOS = TLO + SEH (Subspace-Evasive Hashing from Ma-Dai-Shi 2025)

Adds inter-gate wire binding to TLO for mix-and-match attack prevention.

## Key Commands

```bash
# Build contracts
forge build

# Run tests
forge test

# Benchmark on Tenderly
source ~/.zsh_secrets
forge script script/BenchmarkTLOS.s.sol --rpc-url "$TENDERLY_RPC" --broadcast --unlocked -vvv
```

## Repository Structure

- `contracts/` - Solidity contracts (TLOSKeccak.sol, TLOSLWE.sol)
- `src/` - Rust implementation (ported from circuit-mixing-research)
- `docs/` - Documentation
- `examples/` - Usage examples

## Gas Targets

| Variant | Target | Measured |
|---------|--------|----------|
| TLOS-Keccak | <3M gas | 2.59M |
| TLOS-LWE | <5M gas | 3.29M |

## Related Repos

- `igor53627/tlo` - Base TLO (archived)
- `igor53627/circuit-mixing-research` - Research codebase
- `ma-dai-shi-io` - Ma-Dai-Shi implementation reference
