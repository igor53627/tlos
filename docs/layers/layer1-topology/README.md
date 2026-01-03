# Layer 1: Topology (Structural Mixing)

Layer 1 provides structural obfuscation through reversible circuit mixing. Unlike Layers 2-4 which have concrete cryptographic security claims, Layer 1 is **heuristic** - it resists pattern attacks but has no proven bit-level security.

## What is Layer 1?

A reversible circuit with 64 wires and 640 gates that scrambles the input before LWE encryption. Each gate is a Toffoli-like operation:

```
active_wire ^= truth_table[control1_wire, control2_wire]
```

## Where is the Code?

### Rust (Off-chain Generation)

| File | Purpose |
|------|---------|
| `src/circuit.rs` | Circuit and Gate structs, evaluation logic |
| `src/generator.rs` | TLOS deployment generation (circuit + LWE + binding) |
| `src/bin/` | CLI tools for circuit generation |

### Key Structures

```rust
// src/circuit.rs
pub struct Gate {
    pub pins: [u8; 3],           // [active, control1, control2]
    pub control_function: u8,     // 4-bit truth table
}

pub struct Circuit {
    pub gates: Vec<Gate>,
    pub num_wires: usize,
}
```

### Circuit Generation

```rust
// src/generator.rs
pub fn generate_tlos(secret: [u8; 32], circuit_seed: u64) -> TLOSDeployment {
    let config = SixSixConfig::new(circuit_seed);
    let circuit = create_six_six_circuit(&config);  // Layer 1
    
    let lwe_secret = derive_secret(secret);
    // ... encode gates with LWE (Layer 2)
}
```

### Solidity (On-chain Evaluation)

| File | Purpose |
|------|---------|
| `contracts/TLOSWithPuzzleV4.sol` | `_evaluate()` function processes gates |

The circuit data is stored via SSTORE2 and passed as `circuitDataPointer` to the contract.

## Configuration

| Parameter | Value | Notes |
|-----------|-------|-------|
| Wires | 64 | Maximum for efficient EVM operations |
| Gates | 640 | 10 gates per wire (6x6 pattern) |
| Gate size | 3083 bytes | 3 + 4*770 (header + 4 ciphertexts) |
| Circuit data | ~1.97 MB | 640 * 3083 bytes |

## 6x6 Mixing Pattern

The circuit uses a "6x6" construction where each gate involves:
- 1 active wire (XORed with result)
- 2 control wires (select truth table entry)
- 4-bit truth table (one of 16 Boolean functions)

```rust
// src/circuit.rs
pub struct SixSixConfig {
    pub num_wires: usize,      // 64
    pub gates_per_wire: usize, // 10
    pub seed: u64,             // Deterministic generation
}
```

## Security Model

| Threat | Mitigation | Status |
|--------|------------|--------|
| Pattern analysis | Random gate placement | Heuristic |
| Circuit tracing | Control function hiding (Layer 2 LWE) | Cryptographic |
| SAT/SMT attacks | 640 gates, exponential blowup | Heuristic |
| Oracle-guided learning | Layer 4 puzzle rate-limits queries | Economic |

## Attack Scripts

See `scripts/attacks/layer1-topology/` for SAT/oracle-guided attack implementations from `circuit-mixing-research`.

## Data Flow

```
                 Off-chain (Rust)                    On-chain (Solidity)
                 ================                    ===================
                 
secret -----> [Circuit Gen] -----> circuit_data -----> SSTORE2
   |               |                                      |
   |               v                                      v
   +--------> [LWE Encode] ----------------> TLOSWithPuzzleV4._evaluate()
                   |                                      |
                   v                                      v
              expected_output_hash <----------- keccak256(final_wires)
```

## Building

```bash
# Generate TLOS deployment data
cargo run --bin generate_tlos -- --secret 0x1234... --seed 42 --output circuit.bin

# Run circuit tests
cargo test
```

## Related Files

- `src/lwe.rs` - Layer 2 LWE encryption of control functions
- `src/wire_binding.rs` - Layer 3 wire binding hash
- `scripts/attacks/layer1-topology/` - Attack implementations
