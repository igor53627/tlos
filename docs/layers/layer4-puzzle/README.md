# Layer 4: Planted LWE Puzzle (Economic Rate-Limiting)

Layer 4 forces attackers to solve a ternary LWE puzzle, providing a minimum 2^76 brute-force work floor.

## Parameters (WeakLWEPuzzleV7 - Production)

| Parameter | Value | Notes |
|-----------|-------|-------|
| Secret dimension n | 48 | Ternary secret ∈ {-1,0,1}^48 |
| Samples m | 72 | Overconstrained |
| Modulus q | 2039 | Small prime |
| Error range | {-2,-1,0,1,2} | Small noise |
| Threshold | 300 | ‖As - b‖² must be < 300 |
| Search space | 3^48 | ≈ 2^76 |

## What is Layer 4?

The puzzle is a "planted" LWE instance where:
1. The secret `s` is derived from the actual TLOS secret
2. The public data `(A, b)` is stored on-chain
3. Verifying a solution checks if `‖As - b‖²` is small

```
Honest solver: knows secret → derives s → passes verification
Attacker: must brute-force 3^48 ternary vectors
```

## Key V4 Difference from V3

| Version | Puzzle Derivation | Security |
|---------|-------------------|----------|
| V3 (deprecated) | Derived from **input** | Insecure - puzzle solvable per-input |
| V4 (production) | Derived from **secret** | Secure - one puzzle per contract |

## Where is the Code?

### Contracts

| File | Purpose |
|------|---------|
| `contracts/WeakLWEPuzzleV7.sol` | Standalone puzzle (for testing) |
| `contracts/TLOSWithPuzzleV4.sol` | Integrated puzzle in `_verifyPuzzle()` |

```solidity
// TLOSWithPuzzleV4.sol
function _verifyPuzzle(int8[48] calldata solution) 
    internal view returns (bool valid, bytes32 sHash, uint256 normSq) 
{
    // Validate ternary constraint
    for (uint256 i = 0; i < N_WEAK; ++i) {
        if (solution[i] < -1 || solution[i] > 1) {
            return (false, bytes32(0), 0);
        }
    }
    
    // Compute ||As - b||²
    for (uint256 row = 0; row < M_WEAK; ++row) {
        int256 dotProduct = compute_row_dot_product(row, solution);
        int256 bRow = load_stored_b(row);
        int256 residual = (dotProduct - bRow) mod q;
        normSq += residual²;
    }
    
    valid = normSq < PUZZLE_THRESHOLD_SQ;
}
```

## Puzzle Variants

| Version | n | m | Security | Gas | Status |
|---------|---|---|----------|-----|--------|
| V6 | 24 | 36 | 2^38 | 348K | Testing |
| V5 | 32 | 48 | 2^51 | 540K | Testing |
| V2/V4 | 40 | 60 | 2^63 | 2.8M | Legacy |
| **V7** | **48** | **72** | **2^76** | **1.26M** | **Production** |

## Attack Economics

GPU brute-force benchmark (GH200):
- Throughput: 436M guesses/sec
- Time to exhaust 3^48: ~5500 years
- Cost at $3/GPU-hour: ~$145M

## Attack Scripts

See `scripts/attacks/layer4-puzzle/`:
- `lwe_puzzle_solver.py` - Off-chain solver
- `weak_lwe_gpu_benchmark.py` - GPU brute-force benchmark
- `gpu_puzzle_benchmark_remote.py` - Remote GPU testing

## Test Coverage

```bash
forge test --match-contract PuzzleVariants
forge test --match-test Puzzle
```

## Deployment

The puzzle data is stored separately from circuit data:

```solidity
constructor(
    // ... circuit params ...
    bytes32 _puzzleSeed,      // Seed for deriving A matrix
    address _puzzleBPointer   // SSTORE2 pointer to b vector (72 × u16)
)
```

## Related Files

- `contracts/WeakLWEPuzzleV7.sol` - Standalone puzzle
- `contracts/TLOSWithPuzzleV4.sol` - Integrated puzzle
- `test/PuzzleVariants.t.sol` - All puzzle variant tests
- `scripts/attacks/layer4-puzzle/` - Attack implementations
