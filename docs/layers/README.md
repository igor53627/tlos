# TLOS 4-Layer Security Model

TLOS uses a defense-in-depth approach with 4 distinct security layers.

## Layer Overview

```
+------------------+------------------+------------------+------------------+
|    Layer 1       |    Layer 2       |    Layer 3       |    Layer 4       |
|    Topology      |    LWE           |    Wire Binding  |    Puzzle        |
+------------------+------------------+------------------+------------------+
| Structural       | Cryptographic    | Algebraic        | Economic         |
| mixing           | hiding           | integrity        | rate-limiting    |
+------------------+------------------+------------------+------------------+
| Heuristic        | ~2^112 PQ        | Bijective        | 2^76 brute-force |
+------------------+------------------+------------------+------------------+
| src/circuit.rs   | src/lwe.rs       | src/wire_binding | WeakLWEPuzzleV7  |
+------------------+------------------+------------------+------------------+
```

## Quick Reference

| Layer | Purpose | Security | Location |
|-------|---------|----------|----------|
| [Layer 1](layer1-topology/) | Defeat pattern attacks | Heuristic | `src/circuit.rs` |
| [Layer 2](layer2-lwe/) | Hide control functions | ~2^112 PQ | `src/lwe.rs` |
| [Layer 3](layer3-binding/) | Prevent mix-and-match | Algebraic binding | `src/wire_binding.rs` |
| [Layer 4](layer4-puzzle/) | Rate-limit attacks | 2^76 brute-force | `contracts/WeakLWEPuzzleV7.sol` |

## Attack Surface by Layer

| Attack Type | L1 | L2 | L3 | L4 |
|-------------|----|----|----|----|
| Pattern analysis | [x] | | | |
| Lattice attacks | | [x] | | [x] |
| Mix-and-match | | | [x] | |
| Brute-force | | | | [x] |
| Oracle-guided | [x] | | | [x] |

## Data Flow

```
Input --> [L1: Circuit] --> [L2: LWE Decrypt] --> [L3: Binding Check] --> Output
                ^                                          |
                |                                          v
           [L4: Puzzle] <--------------------------- Verification
```

## Attack Scripts

All attack implementations are in `scripts/attacks/`:

```
scripts/attacks/
+-- layer1-topology/   # SAT/oracle-guided (Rust + Python)
+-- layer2-lwe/        # Lattice attacks (Python)
+-- layer3-binding/    # Mix-and-match (Python)
+-- layer4-puzzle/     # Brute-force (Python + GPU)
+-- estimators/        # Security analysis tools
```
