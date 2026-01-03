#!/usr/bin/env python3
"""
GPU Benchmark for TLOS Weak LWE Puzzle Brute-Force

This measures the GPU attack throughput when brute-forcing the ternary secret.
Unlike the main TLOS circuit evaluation, this tests the PUZZLE layer specifically.

The attack: try random ternary secrets s ∈ {-1,0,1}^n until ||As - b||² < threshold

Requirements:
    pip install torch numpy

Usage:
    python weak_lwe_gpu_benchmark.py
"""

import argparse
import time
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

# Puzzle parameters (matching WeakLWEPuzzleV2.sol)
N_WEAK = 40
M_WEAK = 60
Q_WEAK = 2039
THRESHOLD_SQ = 300


def benchmark_cpu(n_guesses: int = 100000, batch_size: int = 1000):
    """CPU benchmark for puzzle brute-force"""
    # Generate random puzzle instance
    A = np.random.randint(0, Q_WEAK, size=(M_WEAK, N_WEAK), dtype=np.int32)
    b = np.random.randint(0, Q_WEAK, size=M_WEAK, dtype=np.int32)
    
    found = 0
    start = time.perf_counter()
    
    for batch_start in range(0, n_guesses, batch_size):
        batch_end = min(batch_start + batch_size, n_guesses)
        actual_batch = batch_end - batch_start
        
        # Generate batch of random ternary secrets
        secrets = np.random.randint(-1, 2, size=(actual_batch, N_WEAK), dtype=np.int8)
        
        # Compute As for batch: (batch, m)
        # A is (m, n), secrets is (batch, n), result is (batch, m)
        As = (secrets.astype(np.int32) @ A.T) % Q_WEAK
        
        # Compute residual = As - b, centered
        residual = As - b
        residual = np.where(residual > Q_WEAK // 2, residual - Q_WEAK, residual)
        residual = np.where(residual < -Q_WEAK // 2, residual + Q_WEAK, residual)
        
        # Compute norm squared
        norm_sq = np.sum(residual ** 2, axis=1)
        
        # Check threshold
        found += np.sum(norm_sq < THRESHOLD_SQ)
    
    elapsed = time.perf_counter() - start
    guesses_per_sec = n_guesses / elapsed
    
    return {
        "hardware": "CPU-numpy",
        "n_guesses": n_guesses,
        "time_sec": elapsed,
        "guesses_per_sec": guesses_per_sec,
        "found": found,
    }


def benchmark_gpu(n_guesses: int = 1000000, batch_size: int = 65536):
    """GPU benchmark for puzzle brute-force"""
    if not HAS_GPU:
        return None
    
    device = torch.device('cuda')
    
    # Generate random puzzle instance
    A = torch.randint(0, Q_WEAK, (M_WEAK, N_WEAK), dtype=torch.int32, device=device)
    b = torch.randint(0, Q_WEAK, (M_WEAK,), dtype=torch.int32, device=device)
    
    found = 0
    
    # Warmup
    for _ in range(5):
        secrets = torch.randint(-1, 2, (batch_size, N_WEAK), dtype=torch.int32, device=device)
        As = torch.mm(secrets, A.T) % Q_WEAK
        torch.cuda.synchronize()
    
    start = time.perf_counter()
    
    for batch_start in range(0, n_guesses, batch_size):
        batch_end = min(batch_start + batch_size, n_guesses)
        actual_batch = batch_end - batch_start
        
        # Generate batch of random ternary secrets: {-1, 0, 1}
        # torch.randint doesn't support negative, so use 0,1,2 and subtract 1
        secrets = torch.randint(0, 3, (actual_batch, N_WEAK), dtype=torch.int32, device=device) - 1
        
        # Compute As for batch
        As = torch.mm(secrets, A.T) % Q_WEAK
        
        # Compute residual = As - b, centered
        residual = As - b
        residual = torch.where(residual > Q_WEAK // 2, residual - Q_WEAK, residual)
        residual = torch.where(residual < -Q_WEAK // 2, residual + Q_WEAK, residual)
        
        # Compute norm squared
        norm_sq = torch.sum(residual ** 2, dim=1)
        
        # Check threshold
        found += int(torch.sum(norm_sq < THRESHOLD_SQ).item())
    
    torch.cuda.synchronize()
    elapsed = time.perf_counter() - start
    guesses_per_sec = n_guesses / elapsed
    
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
    elif 'M1' in hw_name or 'M2' in hw_name or 'M3' in hw_name:
        hw_name = 'Apple-GPU'
    
    return {
        "hardware": hw_name,
        "n_guesses": n_guesses,
        "time_sec": elapsed,
        "guesses_per_sec": guesses_per_sec,
        "found": found,
    }


def estimate_crack_times(guesses_per_sec: float):
    """Estimate crack times for various secret sizes"""
    print(f"\nSECURITY ESTIMATES (at {guesses_per_sec:,.0f} guesses/sec)")
    print("=" * 60)
    
    # The ternary secret space is 3^n
    n = N_WEAK
    total_space = 3 ** n
    
    print(f"Secret dimension: n={n}")
    print(f"Total ternary space: 3^{n} ≈ 2^{np.log2(3**n):.1f}")
    print()
    
    # Expected guesses to find solution (assuming unique solution)
    # On average, need to try half the space
    expected_guesses = total_space / 2
    expected_time = expected_guesses / guesses_per_sec
    
    print(f"Expected time to crack (random search):")
    print(f"  1 GPU:    {format_time(expected_time)}")
    print(f"  100 GPUs: {format_time(expected_time / 100)}")
    print(f"  1000 GPUs: {format_time(expected_time / 1000)}")
    print()
    
    # Compare to simpler puzzles
    print("For comparison - if secret was smaller:")
    for test_n in [20, 24, 28, 32, 36, 40]:
        space = 3 ** test_n
        time_1gpu = (space / 2) / guesses_per_sec
        print(f"  n={test_n}: 3^{test_n} ≈ 2^{np.log2(space):.0f} → {format_time(time_1gpu)} (1 GPU)")


def format_time(seconds):
    if seconds < 0.001:
        return f"{seconds*1e6:.0f} µs"
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
        return f"{seconds/(86400*365):.2e} years"


def main():
    parser = argparse.ArgumentParser(description="TLOS Weak LWE Puzzle GPU Benchmark")
    parser.add_argument("--cpu-guesses", type=int, default=100000)
    parser.add_argument("--gpu-guesses", type=int, default=2000000)
    args = parser.parse_args()
    
    print("=" * 60)
    print("TLOS Weak LWE Puzzle Brute-Force Benchmark")
    print("=" * 60)
    print(f"Parameters: n={N_WEAK}, m={M_WEAK}, q={Q_WEAK}")
    print(f"Threshold: ||As-b||² < {THRESHOLD_SQ}")
    print(f"Secret space: 3^{N_WEAK} ≈ 2^{np.log2(3**N_WEAK):.1f}")
    print()
    
    if HAS_GPU:
        print(f"GPU: {GPU_NAME}")
        print(f"Memory: {GPU_MEM:.1f} GB")
    else:
        print("[WARN] No GPU available, running CPU-only")
    print()
    
    # CPU benchmark
    print("Benchmarking CPU...")
    cpu_result = benchmark_cpu(args.cpu_guesses)
    print(f"  CPU: {cpu_result['guesses_per_sec']:,.0f} guesses/sec")
    
    # GPU benchmark
    if HAS_GPU:
        print("Benchmarking GPU...")
        gpu_result = benchmark_gpu(args.gpu_guesses)
        print(f"  {gpu_result['hardware']}: {gpu_result['guesses_per_sec']:,.0f} guesses/sec")
        
        speedup = gpu_result['guesses_per_sec'] / cpu_result['guesses_per_sec']
        print(f"  GPU speedup: {speedup:.1f}x")
        
        estimate_crack_times(gpu_result['guesses_per_sec'])
    else:
        estimate_crack_times(cpu_result['guesses_per_sec'])


if __name__ == "__main__":
    main()
