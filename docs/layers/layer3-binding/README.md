# Layer 3: Wire Binding (Algebraic Integrity)

Layer 3 uses a full-rank 64×64 linear map over Z_q to bind intermediate wire states, preventing mix-and-match attacks.

## Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Matrix size | 64×64 | One row per wire |
| Field | Z_65521 | Same as LWE modulus |
| Property | Full-rank | Bijective (unique preimage) |

## What is Layer 3?

After each batch of gates, the wire state is hashed through a linear map:

```
binding_output = A × wire_state mod q
```

Where A is a 64×64 matrix derived from `circuitSeed` and `gateIdx`.

## Security Property

**Algebraic binding, NOT collision resistance.**

- The linear system `Ax = b` is trivially solvable (Gaussian elimination)
- But finding a valid `(input, puzzle_solution)` pair that produces a target binding is hard
- The binding ensures intermediate states can't be swapped between executions

## Where is the Code?

### Rust (Off-chain)

| File | Purpose |
|------|---------|
| `src/wire_binding.rs` | Binding computation, matrix derivation |

```rust
// src/wire_binding.rs
pub fn wire_binding_hash(input: u64, gate_idx: u32, seed: [u8; 32]) -> BindingOutput {
    let mut output = [[0u16; 16]; 4];
    
    for row in 0..64 {
        let row_seed = keccak256(seed, gate_idx, row);
        let sum = dot_product(input, row_seed);
        output[row / 16][row % 16] = sum;
    }
    output
}
```

### Solidity (On-chain)

| File | Function |
|------|----------|
| `contracts/TLOSWithPuzzleV4.sol` | `_wireBindingHash()` |

```solidity
function _wireBindingHash(uint256 input, uint256 gateIdx) 
    internal view returns (uint256[4] memory output) 
{
    for { let row := 0 } lt(row, 64) { row := add(row, 1) } {
        let rowSeed := keccak256(seed, gateIdx, row)
        let sum := 0
        
        for { let col := 0 } lt(col, nWires) { col := add(col, 1) } {
            let aij := derive_coefficient(rowSeed, col)
            let bitVal := and(shr(col, input), 1)
            if bitVal { sum := add(sum, aij) }
        }
        
        // Pack into output
    }
}
```

## Batch Processing

Binding is updated after each batch of 128 gates:

```solidity
for (uint256 batchStart = 0; batchStart < gateCount; batchStart += batchSize) {
    // ... process gates ...
    
    uint256 combined = bindingAcc[0] ^ bindingAcc[1] ^ bindingAcc[2] ^ bindingAcc[3] ^ wires;
    bindingAcc = _wireBindingHash(combined, batchEnd);
}
```

## Attack Model

| Attack | Result |
|--------|--------|
| Solve Ax = b | Trivial (linear algebra) |
| Forge valid binding | Requires valid (input, puzzle) pair |
| Swap intermediate states | Detected by binding mismatch |

## Attack Scripts

See `scripts/attacks/layer3-binding/`:
- `mix_and_match_attack.py` - Simulates intermediate state swapping

## Test Coverage

```bash
forge test --match-test WireBinding
```

Tests verify:
- Deterministic output
- Input sensitivity (diffusion)
- Gate index sensitivity
- Mix-and-match detection

## Related Files

- `src/wire_binding.rs` - Rust implementation
- `contracts/TLOSWithPuzzleV4.sol` - Solidity implementation
- `test/TLOSWithPuzzleV4.t.sol` - Wire binding tests
