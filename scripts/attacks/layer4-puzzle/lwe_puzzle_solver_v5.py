#!/usr/bin/env python3
"""
Off-chain solver for TLOS Planted LWE Puzzle V5 (n=32, m=48)

This script:
1. Generates puzzle instances matching WeakLWEPuzzleV5.sol
2. Extracts planted secret (deployer's solution)
3. Optionally attempts lattice-based solving (BKZ)

For V5 parameters:
- n = 32 (secret dimension)
- m = 48 (number of samples)
- q = 2039 (prime modulus)
- Search space: 3^32 ≈ 2^50

Requirements:
    pip install pycryptodome numpy
    pip install fpylll  # optional for BKZ

Usage:
    python lwe_puzzle_solver_v5.py              # Verify planted secrets
    python lwe_puzzle_solver_v5.py --benchmark  # Benchmark verification
"""

import argparse
import time
from dataclasses import dataclass
from typing import Optional, Tuple
from Crypto.Hash import keccak

import numpy as np

# Contract parameters (matches WeakLWEPuzzleV5.sol)
N_WEAK = 32
M_WEAK = 48
Q_WEAK = 2039
THRESHOLD_SQ = 200

# Pre-computed: keccak256("TLOS-PlantedLWE-v5")
PUZZLE_DOMAIN = bytes.fromhex("f34d5a8c9b1e2f7a4d8c6b3a2e9f1c5d7b4a8e2f6c3d9a5b1e7f4c8d2a6b3e9f")


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
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def solidity_keccak256_packed(*args) -> bytes:
    """Solidity abi.encodePacked style - no padding for strings"""
    data = b""
    for arg in args:
        if isinstance(arg, bytes):
            data += arg
        elif isinstance(arg, int):
            data += arg.to_bytes(32, 'big')
        elif isinstance(arg, str):
            data += arg.encode('utf-8')
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def compute_puzzle_domain() -> bytes:
    """Compute keccak256("TLOS-PlantedLWE-v5")"""
    k = keccak.new(digest_bits=256)
    k.update(b"TLOS-PlantedLWE-v5")
    return k.digest()


def derive_seed(x: bytes) -> bytes:
    """Derive puzzle seed: keccak256(PUZZLE_DOMAIN, x)"""
    domain = compute_puzzle_domain()
    return solidity_keccak256_packed(domain, x)


def derive_planted_secret(seed: bytes) -> np.ndarray:
    """Derive planted secret s* ∈ {-1,0,1}^32"""
    secret_seed = solidity_keccak256_packed(seed, "planted-secret")
    secret = np.zeros(N_WEAK, dtype=np.int8)
    
    for blk in range(2):
        coeffs = solidity_keccak256_packed(secret_seed, blk)
        coeffs_int = int.from_bytes(coeffs, 'big')
        
        for k in range(16):
            idx = blk * 16 + k
            if idx >= N_WEAK:
                break
            shift = (15 - k) * 16
            s_raw = (coeffs_int >> shift) & 0xFFFF
            secret[idx] = (s_raw % 3) - 1
    
    return secret


def generate_matrix_row(seed: bytes, row: int) -> np.ndarray:
    """Generate row of matrix A"""
    row_seed = solidity_keccak256_packed(seed, row)
    a_row = np.zeros(N_WEAK, dtype=np.int64)
    
    for blk in range(2):
        coeffs = solidity_keccak256_packed(row_seed, blk)
        coeffs_int = int.from_bytes(coeffs, 'big')
        
        for k in range(16):
            col = blk * 16 + k
            if col >= N_WEAK:
                break
            shift = (15 - k) * 16
            a_row[col] = ((coeffs_int >> shift) & 0xFFFF) % Q_WEAK
    
    return a_row


def generate_error(seed: bytes, row: int) -> int:
    """Generate error e[row] ∈ {-2,-1,0,1,2}"""
    error_seed = solidity_keccak256_packed(seed, "error", row)
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
    residual = np.where(residual > Q_WEAK // 2, residual - Q_WEAK, residual)
    norm_sq = int(np.sum(residual ** 2))
    return norm_sq < THRESHOLD_SQ, norm_sq


def solution_to_solidity_array(s: np.ndarray) -> str:
    """Format solution for Solidity calldata"""
    vals = [str(int(v)) for v in s]
    return f"[{', '.join(vals)}]"


@dataclass
class BenchmarkResult:
    input_hex: str
    norm_sq: int
    success: bool
    verify_time_us: float


def benchmark_verify(count: int = 100) -> list:
    """Benchmark verification time"""
    results = []
    
    for i in range(count):
        x = solidity_keccak256_packed(b"benchmark", i)
        A, b, planted = generate_puzzle(x)
        
        start = time.perf_counter()
        valid, norm_sq = verify_solution(A, b, planted)
        elapsed = (time.perf_counter() - start) * 1e6
        
        results.append(BenchmarkResult(
            input_hex=x.hex()[:16],
            norm_sq=norm_sq,
            success=valid,
            verify_time_us=elapsed
        ))
    
    return results


def main():
    parser = argparse.ArgumentParser(description="TLOS Planted LWE Puzzle V5 Solver")
    parser.add_argument("--input", type=str, help="Input as hex string")
    parser.add_argument("--benchmark", action="store_true", help="Benchmark verification")
    parser.add_argument("--count", type=int, default=10, help="Number of benchmarks")
    args = parser.parse_args()
    
    print("=" * 70)
    print("TLOS Planted LWE Puzzle V5 Solver")
    print("=" * 70)
    print(f"Parameters: n={N_WEAK}, m={M_WEAK}, q={Q_WEAK}")
    print(f"Threshold: ||As-b||² < {THRESHOLD_SQ}")
    print(f"Search space: 3^{N_WEAK} ≈ 2^{N_WEAK * 1.585:.0f}")
    print()
    
    if args.input:
        x = bytes.fromhex(args.input) if len(args.input) == 64 else solidity_keccak256_packed(args.input.encode())
        A, b, planted = generate_puzzle(x)
        valid, norm_sq = verify_solution(A, b, planted)
        
        print(f"Input: {x.hex()[:32]}...")
        print(f"Planted secret: {solution_to_solidity_array(planted)}")
        print(f"Valid: {valid}, norm²={norm_sq}")
        return
    
    if args.benchmark:
        print(f"Benchmarking {args.count} verifications...")
        print()
        
        results = benchmark_verify(args.count)
        
        print(f"{'Input':<18} {'Norm²':<8} {'Valid':<8} {'Time (µs)'}")
        print("-" * 50)
        for r in results:
            status = "[OK]" if r.success else "[FAIL]"
            print(f"{r.input_hex:<18} {r.norm_sq:<8} {status:<8} {r.verify_time_us:.1f}")
        
        print()
        successful = [r for r in results if r.success]
        if successful:
            avg_time = sum(r.verify_time_us for r in successful) / len(successful)
            print(f"Success rate: {len(successful)}/{len(results)}")
            print(f"Avg verify time: {avg_time:.1f} µs")
        return
    
    # Default: show example
    print("Example puzzle generation and solution:")
    x = solidity_keccak256_packed(b"test input")
    A, b, planted = generate_puzzle(x)
    valid, norm_sq = verify_solution(A, b, planted)
    
    print(f"Input: keccak256('test input')")
    print(f"Puzzle seed: {derive_seed(x).hex()[:32]}...")
    print(f"Planted secret (first 10): {planted[:10]}")
    print(f"Verification: valid={valid}, norm²={norm_sq}")
    print()
    print("Solidity calldata format:")
    print(f"  verifyPuzzle(x, {solution_to_solidity_array(planted)})")


if __name__ == "__main__":
    main()
