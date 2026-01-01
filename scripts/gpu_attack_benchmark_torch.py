#!/usr/bin/env python3
"""
GPU Attack Benchmark for TLOS LWE Verification (PyTorch version)

Measures realistic GPU attack throughput against standard LWE with Gaussian noise.
"""

import argparse
import time
import sys
from dataclasses import dataclass

import numpy as np

try:
    import torch
    HAS_GPU = torch.cuda.is_available()
    if HAS_GPU:
        GPU_NAME = torch.cuda.get_device_name(0)
        GPU_MEM = torch.cuda.get_device_properties(0).total_memory / 1e9
    else:
        GPU_NAME = "N/A"
        GPU_MEM = 0
except ImportError:
    HAS_GPU = False
    GPU_NAME = "N/A"
    GPU_MEM = 0

# TLOS parameters
Q = 65521  # 16-bit prime modulus
N_DIM = 768  # LWE dimension
GATE_COUNTS = [64, 128, 256, 512, 1024]


@dataclass
class BenchmarkResult:
    hardware: str
    n_dim: int
    n_gates: int
    n_samples: int
    batch_size: int
    total_guesses: int
    total_time_sec: float
    guesses_per_sec: float
    bandwidth_gb_s: float
    
    def __str__(self):
        return (
            f"{self.hardware:15} | n={self.n_dim:4} | gates={self.n_gates:4} | "
            f"samples={self.n_samples:5} | {self.guesses_per_sec:>12,.0f} g/s | "
            f"{self.bandwidth_gb_s:>6.1f} GB/s"
        )


def benchmark_cpu(n: int, n_gates: int, n_guesses: int = 100000, 
                  batch_size: int = 1000) -> BenchmarkResult:
    """CPU vectorized benchmark."""
    m = n_gates * 4
    
    A = np.random.randint(0, Q, size=(m, n), dtype=np.int32)
    secrets = np.random.randint(0, Q, size=(n_guesses, n), dtype=np.int32)
    b = np.random.randint(0, Q, size=m, dtype=np.int32)
    
    start = time.perf_counter()
    for batch_start in range(0, n_guesses, batch_size):
        batch_end = min(batch_start + batch_size, n_guesses)
        batch_secrets = secrets[batch_start:batch_end]
        inner_prods = (batch_secrets @ A.T) % Q
        diff = (b - inner_prods) % Q
    elapsed = time.perf_counter() - start
    
    bytes_per_guess = A.nbytes + n * 4
    bandwidth = (bytes_per_guess * n_guesses) / elapsed / 1e9
    
    return BenchmarkResult(
        hardware="CPU-numpy",
        n_dim=n,
        n_gates=n_gates,
        n_samples=m,
        batch_size=batch_size,
        total_guesses=n_guesses,
        total_time_sec=elapsed,
        guesses_per_sec=n_guesses / elapsed,
        bandwidth_gb_s=bandwidth,
    )


def benchmark_gpu_torch(n: int, n_gates: int, n_guesses: int = 2000000,
                        batch_size: int = 65536) -> BenchmarkResult:
    """GPU benchmark using PyTorch."""
    if not HAS_GPU:
        return None
    
    m = n_gates * 4
    device = torch.device('cuda')
    
    # Use int32 for modular arithmetic
    A = torch.randint(0, Q, (m, n), dtype=torch.int32, device=device)
    b = torch.randint(0, Q, (m,), dtype=torch.int32, device=device)
    secrets = torch.randint(0, Q, (n_guesses, n), dtype=torch.int32, device=device)
    
    # Warmup
    for _ in range(5):
        test_batch = secrets[:batch_size]
        # Use float32 matmul then convert (faster than int32 matmul)
        inner_prods = torch.mm(test_batch.float(), A.T.float()).int() % Q
        torch.cuda.synchronize()
    
    start = time.perf_counter()
    for batch_start in range(0, n_guesses, batch_size):
        batch_end = min(batch_start + batch_size, n_guesses)
        batch_secrets = secrets[batch_start:batch_end]
        inner_prods = torch.mm(batch_secrets.float(), A.T.float()).int() % Q
        diff = (b - inner_prods) % Q
    torch.cuda.synchronize()
    elapsed = time.perf_counter() - start
    
    bytes_per_guess = A.numel() * 4 + n * 4
    bandwidth = (bytes_per_guess * n_guesses) / elapsed / 1e9
    
    # Shorten GPU name
    hw_name = GPU_NAME
    if 'GH200' in hw_name:
        hw_name = 'GH200'
    elif 'A100' in hw_name:
        hw_name = 'A100'
    elif '4090' in hw_name:
        hw_name = 'RTX4090'
    elif 'H100' in hw_name:
        hw_name = 'H100'
    
    return BenchmarkResult(
        hardware=hw_name,
        n_dim=n,
        n_gates=n_gates,
        n_samples=m,
        batch_size=batch_size,
        total_guesses=n_guesses,
        total_time_sec=elapsed,
        guesses_per_sec=n_guesses / elapsed,
        bandwidth_gb_s=bandwidth,
    )


def print_attack_implications(results: list):
    """Print attack cost implications."""
    print("\n" + "=" * 80)
    print("ATTACK COST IMPLICATIONS FOR TLOS")
    print("=" * 80)
    
    gpu_results = [r for r in results if r and 'CPU' not in r.hardware]
    if not gpu_results:
        gpu_results = [r for r in results if r]
    
    entropy_levels = [20, 30, 40, 50, 64, 80]
    
    for n_gates in GATE_COUNTS:
        gate_results = [r for r in gpu_results if r.n_gates == n_gates]
        if not gate_results:
            continue
        
        best = max(gate_results, key=lambda r: r.guesses_per_sec)
        
        print(f"\n--- {n_gates} gates ({n_gates * 4} samples) ---")
        print(f"Best: {best.guesses_per_sec:,.0f} guesses/sec ({best.hardware})")
        print()
        print(f"  {'Entropy':<12} {'Search Space':<15} {'Time (1 GPU)':<18} {'Time (100 GPUs)':<18}")
        print(f"  {'-'*12} {'-'*15} {'-'*18} {'-'*18}")
        
        for entropy in entropy_levels:
            space = 2 ** entropy
            time_1gpu = space / best.guesses_per_sec
            time_100gpu = time_1gpu / 100
            
            def format_time(seconds):
                if seconds < 0.001:
                    return f"{seconds*1e6:.0f} us"
                elif seconds < 1:
                    return f"{seconds*1000:.1f} ms"
                elif seconds < 60:
                    return f"{seconds:.1f} sec"
                elif seconds < 3600:
                    return f"{seconds/60:.1f} min"
                elif seconds < 86400:
                    return f"{seconds/3600:.1f} hours"
                elif seconds < 86400 * 365:
                    return f"{seconds/86400:.1f} days"
                elif seconds < 86400 * 365 * 1000:
                    return f"{seconds/(86400*365):.1f} years"
                else:
                    return f"{seconds/(86400*365):.1e} years"
            
            print(f"  2^{entropy:<10} {space:<15,.0f} {format_time(time_1gpu):<18} {format_time(time_100gpu):<18}")


def print_latex_table(results: list):
    """Output LaTeX table for paper."""
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
        if r:
            gps = r.guesses_per_sec
            if gps >= 1e6:
                gps_str = f"${gps/1e6:.2f} \\times 10^6$"
            else:
                gps_str = f"${gps/1e3:.1f} \\times 10^3$"
            print(f"{r.hardware} & {r.n_gates} & {r.n_samples} & {gps_str} & {r.bandwidth_gb_s:.0f} GB/s \\\\")
    
    print(r"""\bottomrule
\end{tabular}
\caption{Measured GPU attack throughput for TLOS ($n=768$, $q=65521$).}
\end{table}""")


def main():
    parser = argparse.ArgumentParser(description="TLOS GPU Attack Benchmark (PyTorch)")
    parser.add_argument("--quick", action="store_true", help="Quick run")
    parser.add_argument("--gates", type=int, nargs="+", default=GATE_COUNTS)
    args = parser.parse_args()
    
    n_guesses_cpu = 10000 if args.quick else 100000
    n_guesses_gpu = 500000 if args.quick else 5000000
    
    print("=" * 80)
    print("TLOS GPU ATTACK BENCHMARK (PyTorch)")
    print("Standard LWE with Gaussian Noise - Verification Throughput")
    print("=" * 80)
    print(f"\nParameters: n={N_DIM}, q={Q}")
    print(f"Gate counts: {args.gates}")
    
    if HAS_GPU:
        print(f"\nGPU: {GPU_NAME}")
        print(f"Memory: {GPU_MEM:.1f} GB")
    else:
        print("\n[WARN] No GPU available, running CPU-only")
    
    results = []
    
    print("\n" + "-" * 90)
    print(f"{'Hardware':<15} | {'n':>5} | {'gates':>6} | {'samples':>7} | {'Throughput':>14} | {'Bandwidth':>10}")
    print("-" * 90)
    
    for n_gates in args.gates:
        # CPU baseline
        result = benchmark_cpu(N_DIM, n_gates, n_guesses_cpu)
        results.append(result)
        print(result)
        
        # GPU benchmark
        if HAS_GPU:
            result = benchmark_gpu_torch(N_DIM, n_gates, n_guesses_gpu)
            if result:
                results.append(result)
                print(result)
        
        print()
    
    print_attack_implications(results)
    print_latex_table(results)


if __name__ == "__main__":
    main()
