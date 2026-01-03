# TLOS Attack Scripts

Attack and security analysis scripts organized by layer.

## Directory Structure

```
attacks/
+-- layer1-topology/  # Layer 1: Topology/structural attacks (from circuit-mixing-research)
+-- layer2-lwe/       # Layer 2: Standard LWE attacks (n=384)
+-- layer4-puzzle/    # Layer 4: Planted LWE puzzle attacks (n=48)
+-- estimators/       # Security estimators and benchmarks
```

## Layer 1: Topology Attacks (Structural Mixing)

Copied from `circuit-mixing-research/src/attacks/`. These are Rust modules for SAT/SMT-based attacks.

| File | Description |
|------|-------------|
| `key_recovery.rs` | Classic SAT attack to recover control function parameters |
| `oracle_guided.rs` | Learning attacks exploiting unlimited oracle access |
| `equivalence.rs` | SAT-based circuit synthesis for equivalent implementations |
| `input_recovery.rs` | Seed hiding and input recovery attacks |
| `local_mixing.rs` | Local reversibility and complexity gap attacks |
| `synthesis.rs` | Circuit synthesis attacks |
| `sixsix_detector.rs` | 6x6 S-box pattern detector |
| `sat_encoder.rs` | SAT formula encoding utilities |
| `benchmarks.rs` | Attack benchmarking framework |
| `break_tlo.py` | Python lattice attack script |
| `uniform_secret_estimator.py` | Secret uniformity estimator |

See `FINDINGS.md` for attack results summary.

## Layer 3: Wire Binding Attacks (Algebraic Integrity)

Mix-and-match attack simulation against the 64x64 full-rank binding layer.

| Script | Description |
|--------|-------------|
| `mix_and_match_attack.py` | Simulates intermediate wire swapping attacks |

**Key insight**: Binding is NOT collision-resistant (linear system), but provides
algebraic integrity - any wire modification is detected.

## Layer 2: LWE Attacks (n=384, ~2^112 security)

| Script | Description |
|--------|-------------|
| `tlos_attack.py` | Attack simulation (brute-force, statistical, lattice) |
| `tlos_attack_long.py` | Long-running exhaustive attack suite |
| `tlos_break.py` | Hybrid lattice + algebraic attack |
| `gpu_attack_benchmark.py` | GPU attack throughput benchmark |
| `gpu_attack_benchmark_torch.py` | PyTorch GPU benchmark |

## Layer 4: Puzzle Attacks (n=48, 3^48 ~ 2^76 brute-force)

| Script | Description |
|--------|-------------|
| `lwe_puzzle_solver.py` | Off-chain solver + GPU comparison |
| `lwe_puzzle_solver_v5.py` | V5 planted LWE puzzle solver |
| `weak_lwe_gpu_benchmark.py` | GPU brute-force benchmark |
| `gpu_puzzle_benchmark_remote.py` | Remote GPU benchmark |

## Security Estimators

| Script | Description |
|--------|-------------|
| `tlos_estimator.sage` | Lattice estimator (primal/dual/Arora-GB/hybrid) |
| `sage_lwe_estimator.sage` | SageMath LWE estimator |
| `lwe_security_estimator.py` | BDD/uSVP attack cost estimation |
| `lattice-estimator-cli` | CLI wrapper for lattice estimator |
| `tlos_estimator_binder.py` | Binder notebook for estimator |
| `comprehensive_gpu_tests.py` | Full GPU security analysis |

## Key Results

- **Layer 2**: ~2^112 post-quantum security (lattice estimator)
- **Layer 4**: 3^48 ~ 2^76 brute-force, 436M guesses/sec on GH200 ~ 5500 years
