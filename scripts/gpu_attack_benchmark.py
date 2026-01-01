#!/usr/bin/env python3
"""
GPU Attack Benchmark for TLOS Standard LWE Verification

This script measures realistic GPU attack throughput against TLOS parameters
using standard LWE with Gaussian noise. It simulates an attacker brute-forcing
secrets by computing inner products.

Requirements:
    pip install cupy-cuda12x numpy  # or cupy-cuda11x for CUDA 11

Usage:
    python gpu_attack_benchmark.py [--cpu-only]

Hardware tested: NVIDIA GH200, A100, RTX 4090
"""

import argparse
import time
import sys
from dataclasses import dataclass
from typing import Optional

import numpy as np

# Try to import CuPy for GPU support
try:
    import cupy as cp
    from cupyx.profiler import benchmark as cp_benchmark
    HAS_GPU = True
except ImportError:
    HAS_GPU = False
    print("[WARN] CuPy not available, running CPU-only benchmarks")


# TLOS parameters
Q = 65521  # 16-bit prime modulus
N_DIM = 768  # LWE dimension
GATE_COUNTS = [64, 128, 256, 512, 1024]  # Different security levels


@dataclass
class BenchmarkResult:
    """Result of a single benchmark run."""
    hardware: str
    n_dim: int
    n_gates: int
    n_samples: int  # n_gates * 4 (4 ciphertexts per gate)
    batch_size: int
    total_guesses: int
    total_time_sec: float
    guesses_per_sec: float
    bandwidth_gb_s: float
    
    def __str__(self):
        return (
            f"{self.hardware:12} | n={self.n_dim:4} | gates={self.n_gates:4} | "
            f"samples={self.n_samples:5} | {self.guesses_per_sec:,.0f} g/s | "
            f"{self.bandwidth_gb_s:.1f} GB/s"
        )


def expand_secret_cpu(guess: bytes, n: int) -> np.ndarray:
    """Expand a guess into an n-dimensional secret vector using SHA256."""
    import hashlib
    # Expand hash to fill n elements
    result = np.zeros(n, dtype=np.uint16)
    idx = 0
    counter = 0
    while idx < n:
        h = hashlib.sha256(guess + counter.to_bytes(4, 'little')).digest()
        for i in range(0, len(h) - 1, 2):
            if idx >= n:
                break
            val = int.from_bytes(h[i:i+2], 'little') % Q
            result[idx] = val
            idx += 1
        counter += 1
    return result


def generate_test_instance_cpu(n: int, m: int) -> tuple:
    """Generate a random TLOS instance for testing (CPU)."""
    # Random A matrix (public)
    A = np.random.randint(0, Q, size=(m, n), dtype=np.uint32)
    # Random secret
    s = np.random.randint(0, Q, size=n, dtype=np.uint32)
    # Random payload bits
    mu = np.random.randint(0, 2, size=m, dtype=np.uint8)
    # Compute b = A @ s + mu * (Q // 2) mod Q
    b = (A @ s + mu.astype(np.uint32) * (Q // 2)) % Q
    return A.astype(np.uint16), b.astype(np.uint16), s.astype(np.uint16), mu


def benchmark_cpu(n: int, n_gates: int, n_guesses: int = 10000) -> BenchmarkResult:
    """Benchmark CPU attack throughput."""
    m = n_gates * 4  # 4 ciphertexts per gate
    
    # Generate test instance
    A, b, s_true, mu_true = generate_test_instance_cpu(n, m)
    
    # Pre-generate random "guesses" (just random secrets for timing)
    secrets = np.random.randint(0, Q, size=(n_guesses, n), dtype=np.uint32)
    
    # Time the attack: compute A @ s for each guess
    start = time.perf_counter()
    for i in range(n_guesses):
        # Inner product computation (the core attack workload)
        inner_prods = (A.astype(np.uint32) @ secrets[i]) % Q
        # Check difference (simplified - real attack would check mu recovery)
        diff = (b.astype(np.uint32) - inner_prods) % Q
    elapsed = time.perf_counter() - start
    
    # Calculate bandwidth: each guess reads A matrix once
    bytes_per_guess = A.nbytes + n * 2  # A matrix + secret vector
    bandwidth = (bytes_per_guess * n_guesses) / elapsed / 1e9
    
    return BenchmarkResult(
        hardware="CPU",
        n_dim=n,
        n_gates=n_gates,
        n_samples=m,
        batch_size=1,
        total_guesses=n_guesses,
        total_time_sec=elapsed,
        guesses_per_sec=n_guesses / elapsed,
        bandwidth_gb_s=bandwidth,
    )


def benchmark_cpu_vectorized(n: int, n_gates: int, n_guesses: int = 100000, 
                              batch_size: int = 1000) -> BenchmarkResult:
    """Benchmark CPU attack throughput with vectorized batching."""
    m = n_gates * 4
    
    A, b, s_true, mu_true = generate_test_instance_cpu(n, m)
    
    # Pre-generate all secrets
    secrets = np.random.randint(0, Q, size=(n_guesses, n), dtype=np.uint32)
    
    start = time.perf_counter()
    for batch_start in range(0, n_guesses, batch_size):
        batch_end = min(batch_start + batch_size, n_guesses)
        batch_secrets = secrets[batch_start:batch_end]
        # Batched matrix-vector multiply: (batch, n) @ (m, n).T -> (batch, m)
        inner_prods = (batch_secrets @ A.T.astype(np.uint32)) % Q
        diff = (b.astype(np.uint32) - inner_prods) % Q
    elapsed = time.perf_counter() - start
    
    bytes_per_guess = A.nbytes + n * 2
    bandwidth = (bytes_per_guess * n_guesses) / elapsed / 1e9
    
    return BenchmarkResult(
        hardware="CPU-vec",
        n_dim=n,
        n_gates=n_gates,
        n_samples=m,
        batch_size=batch_size,
        total_guesses=n_guesses,
        total_time_sec=elapsed,
        guesses_per_sec=n_guesses / elapsed,
        bandwidth_gb_s=bandwidth,
    )


def benchmark_gpu(n: int, n_gates: int, n_guesses: int = 1000000,
                  batch_size: int = 65536) -> Optional[BenchmarkResult]:
    """Benchmark GPU attack throughput using CuPy."""
    if not HAS_GPU:
        return None
    
    m = n_gates * 4
    
    # Generate test instance on GPU
    A = cp.random.randint(0, Q, size=(m, n), dtype=cp.uint32)
    b = cp.random.randint(0, Q, size=m, dtype=cp.uint32)
    
    # Pre-generate secrets on GPU
    secrets = cp.random.randint(0, Q, size=(n_guesses, n), dtype=cp.uint32)
    
    # Warmup
    for _ in range(3):
        test_batch = secrets[:batch_size]
        inner_prods = (test_batch @ A.T) % Q
        cp.cuda.Stream.null.synchronize()
    
    # Timed run
    start = time.perf_counter()
    for batch_start in range(0, n_guesses, batch_size):
        batch_end = min(batch_start + batch_size, n_guesses)
        batch_secrets = secrets[batch_start:batch_end]
        # Core attack: batched matrix-vector multiply
        inner_prods = (batch_secrets @ A.T) % Q
        diff = (b - inner_prods) % Q
    cp.cuda.Stream.null.synchronize()
    elapsed = time.perf_counter() - start
    
    # Get GPU name
    gpu_name = cp.cuda.runtime.getDeviceProperties(0)['name'].decode()
    # Shorten common names
    if 'GH200' in gpu_name:
        gpu_name = 'GH200'
    elif 'A100' in gpu_name:
        gpu_name = 'A100'
    elif '4090' in gpu_name:
        gpu_name = 'RTX4090'
    elif 'H100' in gpu_name:
        gpu_name = 'H100'
    
    bytes_per_guess = A.nbytes + n * 4  # A matrix + secret (uint32)
    bandwidth = (bytes_per_guess * n_guesses) / elapsed / 1e9
    
    return BenchmarkResult(
        hardware=gpu_name,
        n_dim=n,
        n_gates=n_gates,
        n_samples=m,
        batch_size=batch_size,
        total_guesses=n_guesses,
        total_time_sec=elapsed,
        guesses_per_sec=n_guesses / elapsed,
        bandwidth_gb_s=bandwidth,
    )


def benchmark_gpu_cublas(n: int, n_gates: int, n_guesses: int = 1000000,
                         batch_size: int = 65536) -> Optional[BenchmarkResult]:
    """Benchmark using cuBLAS GEMM as upper bound on performance."""
    if not HAS_GPU:
        return None
    
    m = n_gates * 4
    
    # Use float32 for cuBLAS (it's optimized for this)
    A = cp.random.rand(m, n).astype(cp.float32)
    secrets = cp.random.rand(n_guesses, n).astype(cp.float32)
    
    # Warmup
    for _ in range(3):
        test_batch = secrets[:batch_size]
        result = test_batch @ A.T
        cp.cuda.Stream.null.synchronize()
    
    start = time.perf_counter()
    for batch_start in range(0, n_guesses, batch_size):
        batch_end = min(batch_start + batch_size, n_guesses)
        batch_secrets = secrets[batch_start:batch_end]
        result = batch_secrets @ A.T
    cp.cuda.Stream.null.synchronize()
    elapsed = time.perf_counter() - start
    
    gpu_name = cp.cuda.runtime.getDeviceProperties(0)['name'].decode()
    if 'GH200' in gpu_name:
        gpu_name = 'GH200-cuBLAS'
    elif 'A100' in gpu_name:
        gpu_name = 'A100-cuBLAS'
    else:
        gpu_name = f"{gpu_name[:10]}-cuBLAS"
    
    bytes_per_guess = A.nbytes + n * 4
    bandwidth = (bytes_per_guess * n_guesses) / elapsed / 1e9
    
    return BenchmarkResult(
        hardware=gpu_name,
        n_dim=n,
        n_gates=n_gates,
        n_samples=m,
        batch_size=batch_size,
        total_guesses=n_guesses,
        total_time_sec=elapsed,
        guesses_per_sec=n_guesses / elapsed,
        bandwidth_gb_s=bandwidth,
    )


def print_attack_implications(results: list[BenchmarkResult]):
    """Print implications for TLOS security based on benchmark results."""
    print("\n" + "=" * 80)
    print("ATTACK COST IMPLICATIONS FOR TLOS")
    print("=" * 80)
    
    # Find best GPU result for each gate count
    gpu_results = [r for r in results if 'GPU' in r.hardware or 'GH200' in r.hardware 
                   or 'A100' in r.hardware or 'RTX' in r.hardware or 'H100' in r.hardware]
    if not gpu_results:
        gpu_results = [r for r in results if 'vec' in r.hardware]
    
    if not gpu_results:
        print("No GPU results available")
        return
    
    entropy_levels = [20, 30, 40, 50, 64, 80]
    
    for n_gates in GATE_COUNTS:
        gate_results = [r for r in gpu_results if r.n_gates == n_gates]
        if not gate_results:
            continue
        
        best = max(gate_results, key=lambda r: r.guesses_per_sec)
        
        print(f"\n--- {n_gates} gates ({n_gates * 4} samples) ---")
        print(f"Best throughput: {best.guesses_per_sec:,.0f} guesses/sec ({best.hardware})")
        print()
        print(f"  {'Entropy':<12} {'Search Space':<15} {'Time (1 GPU)':<20} {'Time (100 GPUs)':<20}")
        print(f"  {'-'*12} {'-'*15} {'-'*20} {'-'*20}")
        
        for entropy in entropy_levels:
            space = 2 ** entropy
            time_1gpu = space / best.guesses_per_sec
            time_100gpu = time_1gpu / 100
            
            def format_time(seconds):
                if seconds < 1:
                    return f"{seconds*1000:.1f} ms"
                elif seconds < 60:
                    return f"{seconds:.1f} sec"
                elif seconds < 3600:
                    return f"{seconds/60:.1f} min"
                elif seconds < 86400:
                    return f"{seconds/3600:.1f} hours"
                elif seconds < 86400 * 365:
                    return f"{seconds/86400:.1f} days"
                else:
                    return f"{seconds/(86400*365):.1f} years"
            
            print(f"  2^{entropy:<10} {space:<15,.0f} {format_time(time_1gpu):<20} {format_time(time_100gpu):<20}")


def main():
    parser = argparse.ArgumentParser(description="TLOS GPU Attack Benchmark")
    parser.add_argument("--cpu-only", action="store_true", help="Run CPU benchmarks only")
    parser.add_argument("--quick", action="store_true", help="Quick run with fewer iterations")
    parser.add_argument("--gates", type=int, nargs="+", default=GATE_COUNTS,
                        help="Gate counts to test")
    args = parser.parse_args()
    
    n_guesses_cpu = 10000 if args.quick else 100000
    n_guesses_gpu = 100000 if args.quick else 2000000
    
    print("=" * 80)
    print("TLOS GPU ATTACK BENCHMARK")
    print("Standard LWE (Gaussian noise) Verification Throughput Measurement")
    print("=" * 80)
    print(f"\nParameters: n={N_DIM}, q={Q}")
    print(f"Gate counts: {args.gates}")
    
    if HAS_GPU and not args.cpu_only:
        props = cp.cuda.runtime.getDeviceProperties(0)
        print(f"\nGPU: {props['name'].decode()}")
        print(f"Memory: {props['totalGlobalMem'] / 1e9:.1f} GB")
    
    results = []
    
    print("\n" + "-" * 80)
    print(f"{'Hardware':<12} | {'n':>4} | {'gates':>5} | {'samples':>6} | {'Throughput':>15} | {'BW':>10}")
    print("-" * 80)
    
    for n_gates in args.gates:
        # CPU baseline (vectorized)
        result = benchmark_cpu_vectorized(N_DIM, n_gates, n_guesses_cpu)
        results.append(result)
        print(result)
        
        if HAS_GPU and not args.cpu_only:
            # GPU integer benchmark
            result = benchmark_gpu(N_DIM, n_gates, n_guesses_gpu)
            if result:
                results.append(result)
                print(result)
            
            # GPU cuBLAS benchmark (upper bound)
            result = benchmark_gpu_cublas(N_DIM, n_gates, n_guesses_gpu)
            if result:
                results.append(result)
                print(result)
        
        print()
    
    # Print attack implications
    print_attack_implications(results)
    
    # Output LaTeX table for paper
    print("\n" + "=" * 80)
    print("LATEX TABLE FOR PAPER")
    print("=" * 80)
    print(r"""
\begin{table}[h]
\centering
\begin{tabular}{@{}lcccc@{}}
\toprule
\textbf{Hardware} & \textbf{Gates} & \textbf{Samples} & \textbf{Guesses/sec} & \textbf{Bandwidth} \\
\midrule""")
    
    for r in results:
        if 'cuBLAS' not in r.hardware:  # Skip cuBLAS rows for cleaner table
            print(f"{r.hardware} & {r.n_gates} & {r.n_samples} & "
                  f"${r.guesses_per_sec/1e6:.2f} \\times 10^6$ & {r.bandwidth_gb_s:.0f} GB/s \\\\")
    
    print(r"""\bottomrule
\end{tabular}
\caption{Measured GPU attack throughput for TLOS ($n=768$, $q=65521$).}
\end{table}""")


if __name__ == "__main__":
    main()
