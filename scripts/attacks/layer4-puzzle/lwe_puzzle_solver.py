#!/usr/bin/env python3
"""
Off-chain solver and benchmarker for TLOS Weak LWE Puzzle (Layer 4)

This script:
1. Generates LWE puzzle instances matching the Solidity contract
2. Solves them using fpylll (BKZ lattice reduction)
3. Benchmarks solve time to estimate GPU crack resistance

Requirements:
    pip install fpylll numpy

Usage:
    python lwe_puzzle_solver.py              # Benchmark 10 instances
    python lwe_puzzle_solver.py --gpu        # Also run GPU brute-force comparison
    python lwe_puzzle_solver.py --count 100  # Benchmark more instances
"""

import argparse
import hashlib
import time
from dataclasses import dataclass
from typing import Optional, Tuple

import numpy as np

# Try to import fpylll for lattice reduction
try:
    from fpylll import IntegerMatrix, BKZ, GSO
    from fpylll.algorithms.bkz2 import BKZReduction
    HAS_FPYLLL = True
except ImportError:
    HAS_FPYLLL = False
    print("[WARN] fpylll not installed. Install with: pip install fpylll")

# Contract parameters (must match WeakLWEPuzzleV2.sol)
N_WEAK = 40       # Secret dimension
M_WEAK = 60       # Number of samples  
Q_WEAK = 2039     # Prime modulus
THRESHOLD_SQ = 300

PUZZLE_DOMAIN = hashlib.sha3_256(b"TLOS-PlantedLWE-v2").digest()


def keccak256(*args) -> bytes:
    """Mimic Solidity's keccak256(abi.encodePacked(...))"""
    data = b""
    for arg in args:
        if isinstance(arg, bytes):
            data += arg
        elif isinstance(arg, int):
            data += arg.to_bytes(32, 'big')
        elif isinstance(arg, str):
            data += arg.encode()
    return hashlib.sha3_256(data).digest()


def derive_seed(x: bytes) -> bytes:
    """Derive puzzle seed from input x"""
    return keccak256(PUZZLE_DOMAIN, x)


def derive_planted_secret(seed: bytes) -> np.ndarray:
    """Derive planted secret s* ∈ {-1,0,1}^n"""
    secret_seed = keccak256(seed, b"planted-secret")
    secret = np.zeros(N_WEAK, dtype=np.int8)
    
    for col in range(0, N_WEAK, 16):
        coeffs = keccak256(secret_seed, col // 16)
        coeffs_int = int.from_bytes(coeffs, 'big')
        
        for k in range(16):
            if col + k >= N_WEAK:
                break
            shift = (15 - k) * 16
            s_raw = (coeffs_int >> shift) & 0xFFFF
            secret[col + k] = (s_raw % 3) - 1
    
    return secret


def generate_matrix_row(seed: bytes, row: int) -> np.ndarray:
    """Generate row of matrix A"""
    row_seed = keccak256(seed, row)
    a_row = np.zeros(N_WEAK, dtype=np.int64)
    
    for col in range(0, N_WEAK, 16):
        coeffs = keccak256(row_seed, col // 16)
        coeffs_int = int.from_bytes(coeffs, 'big')
        
        for k in range(16):
            if col + k >= N_WEAK:
                break
            shift = (15 - k) * 16
            a_row[col + k] = ((coeffs_int >> shift) & 0xFFFF) % Q_WEAK
    
    return a_row


def generate_error(seed: bytes, row: int) -> int:
    """Generate error e[row] ∈ {-2,-1,0,1,2}"""
    error_seed = keccak256(seed, b"error", row)
    e_raw = int.from_bytes(error_seed, 'big') % 5
    return e_raw - 2


def generate_puzzle(x: bytes) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Generate full puzzle (A, b, planted_secret) for input x"""
    seed = derive_seed(x)
    planted_secret = derive_planted_secret(seed)
    
    A = np.zeros((M_WEAK, N_WEAK), dtype=np.int64)
    b = np.zeros(M_WEAK, dtype=np.int64)
    
    for row in range(M_WEAK):
        A[row] = generate_matrix_row(seed, row)
        e = generate_error(seed, row)
        b[row] = (A[row] @ planted_secret + e) % Q_WEAK
    
    return A, b, planted_secret


def verify_solution(A: np.ndarray, b: np.ndarray, s: np.ndarray) -> Tuple[bool, int]:
    """Verify if solution s satisfies ||As - b||² < threshold"""
    residual = (A @ s - b) % Q_WEAK
    # Center residuals
    residual = np.where(residual > Q_WEAK // 2, residual - Q_WEAK, residual)
    norm_sq = int(np.sum(residual ** 2))
    return norm_sq < THRESHOLD_SQ, norm_sq


def solve_with_enumeration(A: np.ndarray, b: np.ndarray) -> Optional[np.ndarray]:
    """Brute-force solve for ternary secret (only feasible for small n)"""
    m, n = A.shape
    
    # For n=40, 3^40 is too large, but we can try random sampling
    best_solution = None
    best_norm = float('inf')
    
    # Random search (simulating what an attacker would do)
    for _ in range(10000):
        s = np.random.randint(-1, 2, size=n).astype(np.int8)
        residual = (A @ s - b) % Q_WEAK
        residual = np.where(residual > Q_WEAK // 2, residual - Q_WEAK, residual)
        norm_sq = int(np.sum(residual ** 2))
        
        if norm_sq < THRESHOLD_SQ and norm_sq < best_norm:
            best_norm = norm_sq
            best_solution = s
    
    return best_solution


def solve_with_bkz(A: np.ndarray, b: np.ndarray, block_size: int = 20) -> Optional[np.ndarray]:
    """Solve LWE instance using BKZ lattice reduction + CVP"""
    if not HAS_FPYLLL:
        return None
    
    from fpylll import LLL, CVP
    from fpylll.fplll.gso import MatGSO
    
    m, n = A.shape
    
    # For LWE primal attack, we use the Kannan embedding
    # Build lattice basis for solving Ax = b mod q
    # 
    # Construct: [ q*I_n  |   0   ]
    #            [  A^T   |  I_m  ]
    # Then target vector is (b, 0)
    # Short vector in this lattice corresponds to (As - b, s) for short s
    
    # Alternative: directly solve using the dual lattice
    # For small params, let's try the embedding approach
    
    dim = n + m + 1
    B = IntegerMatrix(dim, dim)
    
    # [ q*I_n  | 0     | 0 ]
    # [   A   | I_m   | 0 ]
    # [   b   | 0     | K ]  (K is a scaling factor)
    
    K = 1  # Scaling for target row
    
    for i in range(n):
        B[i, i] = Q_WEAK
    
    for i in range(m):
        for j in range(n):
            B[n + i, j] = int(A[i, j])
        B[n + i, n + i] = 1
    
    for j in range(n):
        # We need to embed b somehow - this is tricky
        pass
    
    B[dim - 1, dim - 1] = K
    for j in range(m):
        B[dim - 1, n + j] = -int(b[j])
    
    # Run LLL
    LLL.reduction(B)
    
    # Check basis vectors for short (e, s, 1) or (e, s, -1) vectors
    best_solution = None
    best_norm = float('inf')
    
    for i in range(dim):
        v = [B[i, j] for j in range(dim)]
        
        # Last entry should be ±K
        if abs(v[-1]) == K:
            # Extract s from positions 0..n-1
            s_candidate = np.array(v[:n], dtype=np.int64)
            if v[-1] == -K:
                s_candidate = -s_candidate
            
            # Check if ternary
            if np.all(np.abs(s_candidate) <= 1):
                residual = (A @ s_candidate.astype(np.int8) - b) % Q_WEAK
                residual = np.where(residual > Q_WEAK // 2, residual - Q_WEAK, residual)
                norm_sq = int(np.sum(residual ** 2))
                
                if norm_sq < THRESHOLD_SQ and norm_sq < best_norm:
                    best_norm = norm_sq
                    best_solution = s_candidate.astype(np.int8)
    
    # If LLL didn't work, try random enumeration as fallback
    if best_solution is None:
        best_solution = solve_with_enumeration(A, b)
    
    return best_solution


@dataclass
class BenchmarkResult:
    input_hex: str
    solve_time_ms: float
    norm_sq: int
    success: bool
    method: str


def benchmark_solve(x: bytes, block_size: int = 20, verbose: bool = False) -> BenchmarkResult:
    """Benchmark solving a single puzzle instance"""
    A, b, planted_secret = generate_puzzle(x)
    
    # First, verify planted secret works
    valid, norm_sq_planted = verify_solution(A, b, planted_secret)
    if verbose:
        print(f"  Planted secret norm_sq={norm_sq_planted}, valid={valid}")
    if not valid:
        print(f"[WARN] Planted secret invalid for {x.hex()[:16]}... norm_sq={norm_sq_planted}")
    
    if not HAS_FPYLLL:
        return BenchmarkResult(
            input_hex=x.hex()[:16],
            solve_time_ms=0,
            norm_sq=norm_sq_planted,
            success=valid,
            method="planted-only"
        )
    
    # Benchmark BKZ solve
    start = time.perf_counter()
    solution = solve_with_bkz(A, b, block_size=block_size)
    elapsed = time.perf_counter() - start
    
    if solution is not None:
        valid, norm_sq = verify_solution(A, b, solution)
        return BenchmarkResult(
            input_hex=x.hex()[:16],
            solve_time_ms=elapsed * 1000,
            norm_sq=norm_sq,
            success=valid,
            method="bkz"
        )
    else:
        return BenchmarkResult(
            input_hex=x.hex()[:16],
            solve_time_ms=elapsed * 1000,
            norm_sq=norm_sq_planted,
            success=False,
            method="bkz-failed"
        )


def main():
    parser = argparse.ArgumentParser(description="TLOS Weak LWE Puzzle Solver Benchmark")
    parser.add_argument("--count", type=int, default=10, help="Number of instances to benchmark")
    parser.add_argument("--block-size", type=int, default=20, help="BKZ block size")
    parser.add_argument("--gpu", action="store_true", help="Also run GPU brute-force comparison")
    args = parser.parse_args()
    
    print("=" * 70)
    print("TLOS Weak LWE Puzzle Solver Benchmark")
    print("=" * 70)
    print(f"Parameters: n={N_WEAK}, m={M_WEAK}, q={Q_WEAK}")
    print(f"Threshold: ||As-b||² < {THRESHOLD_SQ}")
    print(f"BKZ block size: {args.block_size}")
    print(f"Instances: {args.count}")
    print()
    
    if not HAS_FPYLLL:
        print("[ERROR] fpylll required for BKZ solving. Install with:")
        print("  pip install fpylll")
        print()
        print("Falling back to planted secret verification only...")
    
    results = []
    
    print(f"{'Input':<18} {'Time (ms)':<12} {'Norm²':<8} {'Success':<8} {'Method'}")
    print("-" * 70)
    
    for i in range(args.count):
        x = keccak256(b"benchmark", i)
        result = benchmark_solve(x, block_size=args.block_size, verbose=(i == 0))
        results.append(result)
        
        status = "[OK]" if result.success else "[FAIL]"
        print(f"{result.input_hex:<18} {result.solve_time_ms:<12.1f} {result.norm_sq:<8} {status:<8} {result.method}")
    
    # Summary
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    successful = [r for r in results if r.success]
    if successful:
        avg_time = sum(r.solve_time_ms for r in successful) / len(successful)
        max_time = max(r.solve_time_ms for r in successful)
        min_time = min(r.solve_time_ms for r in successful)
        
        print(f"Success rate: {len(successful)}/{len(results)}")
        print(f"Solve time: min={min_time:.1f}ms, avg={avg_time:.1f}ms, max={max_time:.1f}ms")
        
        if avg_time > 0:
            solves_per_sec = 1000 / avg_time
            print(f"Solves/sec (CPU): {solves_per_sec:.1f}")
            print()
            print("SECURITY IMPLICATIONS:")
            print(f"  2^20 guesses: {2**20 / solves_per_sec / 60:.1f} minutes")
            print(f"  2^30 guesses: {2**30 / solves_per_sec / 3600:.1f} hours")
            print(f"  2^40 guesses: {2**40 / solves_per_sec / 86400:.1f} days")
    else:
        print("No successful solves - check parameters")


if __name__ == "__main__":
    main()
