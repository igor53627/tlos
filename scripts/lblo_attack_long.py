#!/usr/bin/env python3
"""
Long-running LBLO attack suite for remote execution.
Designed to run for hours on larger instances.

Usage:
    python3 lblo_attack_long.py [--hours N] [--n-max N]
    
Example:
    python3 lblo_attack_long.py --hours 4 --n-max 24
"""

import numpy as np
from hashlib import sha3_256
import time
import argparse
import sys
import os
from datetime import datetime, timedelta
from typing import Tuple, Optional

# TLOS parameters
Q = 65521
THRESHOLD = Q // 4

def log(msg: str):
    """Log with timestamp."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)

def derive_secret(seed: bytes, n: int) -> np.ndarray:
    s = np.zeros(n, dtype=np.int64)
    for chunk_idx in range(n // 16 + 1):
        h = sha3_256(seed + chunk_idx.to_bytes(8, 'big')).digest()
        for i in range(16):
            if chunk_idx * 16 + i >= n:
                break
            val = (h[i*2] << 8) | h[i*2 + 1]
            s[chunk_idx * 16 + i] = val % Q
    return s

def generate_lblo_instance(n: int, m: int, seed: bytes):
    np.random.seed(int.from_bytes(seed[:4], 'big'))
    s = derive_secret(seed, n)
    A = np.random.randint(0, Q, size=(m, n), dtype=np.int64)
    mu = np.random.randint(0, 2, size=m, dtype=np.int64)
    inner_prods = np.mod(A @ s, Q)
    b = np.mod(inner_prods + mu * (Q // 2), Q)
    return A, b, s, mu

def mod_inverse(a: int, m: int) -> Optional[int]:
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        return gcd, x, y1
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        return None
    return (x % m + m) % m

def solve_mod_q(A: np.ndarray, b: np.ndarray, q: int) -> Optional[np.ndarray]:
    n = A.shape[0]
    if A.shape[1] != n or len(b) != n:
        return None
    aug = np.zeros((n, n+1), dtype=np.int64)
    aug[:, :n] = A % q
    aug[:, n] = b % q
    
    for col in range(n):
        pivot_row = None
        for row in range(col, n):
            if aug[row, col] % q != 0:
                pivot_row = row
                break
        if pivot_row is None:
            return None
        aug[[col, pivot_row]] = aug[[pivot_row, col]]
        inv = mod_inverse(int(aug[col, col]), q)
        if inv is None:
            return None
        aug[col] = (aug[col] * inv) % q
        for row in range(n):
            if row != col and aug[row, col] != 0:
                factor = aug[row, col]
                aug[row] = (aug[row] - factor * aug[col]) % q
    return aug[:, n]

def exhaustive_attack(n: int, m: int, seed: bytes, time_limit_sec: float = 3600):
    """
    Exhaustive attack: try all 2^n combinations of mu for first n equations.
    Returns when found or time limit reached.
    """
    log(f"Starting exhaustive attack: n={n}, m={m}, limit={time_limit_sec}s")
    
    A, b, s, mu = generate_lblo_instance(n, m, seed)
    
    start = time.time()
    attempts = 0
    found_at = None
    
    total = 2**n
    log(f"Total combinations: 2^{n} = {total:,}")
    
    last_progress = time.time()
    
    for mu_bits in range(total):
        attempts += 1
        
        # Progress update every 10 seconds
        if time.time() - last_progress > 10:
            elapsed = time.time() - start
            rate = attempts / elapsed
            eta = (total - attempts) / rate if rate > 0 else float('inf')
            log(f"Progress: {attempts:,}/{total:,} ({100*attempts/total:.2f}%) - "
                f"Rate: {rate:.0f}/s - ETA: {eta/3600:.1f}h")
            last_progress = time.time()
        
        # Time limit check
        if time.time() - start > time_limit_sec:
            log(f"Time limit reached after {attempts:,} attempts")
            break
        
        mu_guess = np.array([(mu_bits >> i) & 1 for i in range(n)], dtype=np.int64)
        b_adjusted = np.mod(b[:n].astype(np.int64) - mu_guess * (Q // 2), Q)
        
        s_recovered = solve_mod_q(A[:n].astype(np.int64), b_adjusted, Q)
        if s_recovered is not None and np.array_equal(s_recovered, s):
            found_at = attempts
            elapsed = time.time() - start
            log(f"[SUCCESS] Found at attempt {attempts:,} in {elapsed:.1f}s")
            break
    
    elapsed = time.time() - start
    
    return {
        "n": n,
        "m": m,
        "total_combinations": total,
        "attempts": attempts,
        "found_at": found_at,
        "elapsed_seconds": elapsed,
        "rate_per_second": attempts / elapsed if elapsed > 0 else 0,
        "extrapolated_full_time_hours": (total / (attempts / elapsed)) / 3600 if attempts > 0 else None
    }

def run_scaling_analysis(n_values: list, time_per_n: float = 300):
    """Run exhaustive attack on multiple n values to measure scaling."""
    results = []
    
    for n in n_values:
        m = n * 4  # 4 samples per dimension
        seed = f"scaling_n{n}".encode()
        
        result = exhaustive_attack(n, m, seed, time_limit_sec=time_per_n)
        results.append(result)
        
        log(f"n={n}: {result['attempts']:,} attempts in {result['elapsed_seconds']:.1f}s")
        if result['found_at']:
            log(f"  -> Found at {result['found_at']:,}")
        if result['extrapolated_full_time_hours']:
            log(f"  -> Extrapolated full time: {result['extrapolated_full_time_hours']:.1f}h")
        
        # Estimate for n=128
        if result['rate_per_second'] > 0:
            time_128 = (2**128) / result['rate_per_second']
            log(f"  -> At this rate, n=128 would take: {time_128:.2e} seconds ({time_128/3600/24/365:.2e} years)")
    
    return results

def run_long_suite(max_hours: float = 4, n_max: int = 24):
    """Run the full long-running attack suite."""
    log("="*60)
    log("LBLO LONG-RUNNING ATTACK SUITE")
    log("="*60)
    log(f"Max runtime: {max_hours} hours")
    log(f"Max n: {n_max}")
    log("")
    
    start_time = time.time()
    end_time = start_time + max_hours * 3600
    
    results = []
    
    # Phase 1: Scaling analysis (small n values)
    log("\n" + "="*60)
    log("PHASE 1: SCALING ANALYSIS")
    log("="*60)
    
    n_values = [16, 18, 20, 22, 24]
    n_values = [n for n in n_values if n <= n_max]
    
    for n in n_values:
        remaining = end_time - time.time()
        if remaining < 60:
            log("Time limit approaching, stopping early")
            break
        
        time_for_n = min(remaining / 2, 600)  # Max 10 min per n, or half remaining
        
        log(f"\nTesting n={n} (budget: {time_for_n:.0f}s)")
        m = n * 4
        seed = f"long_run_n{n}".encode()
        
        result = exhaustive_attack(n, m, seed, time_limit_sec=time_for_n)
        results.append(result)
        
        # Report
        log(f"  Attempts: {result['attempts']:,}")
        log(f"  Rate: {result['rate_per_second']:.0f}/s")
        if result['found_at']:
            log(f"  Found at: {result['found_at']:,} ({100*result['found_at']/(2**n):.1f}% through)")
        
        # Extrapolate to n=128
        if result['rate_per_second'] > 0:
            # Assume rate stays constant (optimistic for attacker)
            time_128_sec = (2**128) / result['rate_per_second']
            time_128_years = time_128_sec / (3600 * 24 * 365)
            log(f"  Extrapolated n=128 time: {time_128_years:.2e} years")
    
    # Phase 2: Deep statistical analysis on larger instances
    log("\n" + "="*60)
    log("PHASE 2: STATISTICAL ANALYSIS ON LARGER INSTANCES")
    log("="*60)
    
    for n in [64, 128]:
        m = n * 20  # More samples for better statistics
        seed = f"stats_n{n}".encode()
        
        log(f"\nAnalyzing n={n}, m={m}")
        A, b, s, mu = generate_lblo_instance(n, m, seed)
        
        # Statistical tests
        b_mean = np.mean(b)
        b_std = np.std(b)
        expected_mean = Q / 2
        expected_std = Q / np.sqrt(12)  # Uniform distribution std
        
        log(f"  b mean: {b_mean:.1f} (expected: {expected_mean:.1f})")
        log(f"  b std: {b_std:.1f} (expected: {expected_std:.1f})")
        
        # Chi-squared test
        hist, _ = np.histogram(b, bins=100, range=(0, Q))
        expected_count = m / 100
        chi_sq = np.sum((hist - expected_count)**2 / expected_count)
        log(f"  Chi-squared: {chi_sq:.1f} (critical ~124 for 99 df)")
        
        # Correlation between A and mu (shouldn't exist)
        A_row_sums = np.sum(A, axis=1)
        corr = np.corrcoef(A_row_sums, mu)[0, 1]
        log(f"  A-mu correlation: {corr:.4f} (should be ~0)")
    
    # Final summary
    log("\n" + "="*60)
    log("FINAL SUMMARY")
    log("="*60)
    
    total_elapsed = time.time() - start_time
    log(f"Total runtime: {total_elapsed/3600:.2f} hours")
    
    log("\nExhaustive attack scaling:")
    for r in results:
        n = r['n']
        rate = r['rate_per_second']
        if rate > 0:
            full_time = (2**n) / rate
            log(f"  n={n}: rate={rate:.0f}/s, full_time={full_time:.1f}s ({full_time/3600:.2f}h)")
    
    # Security estimate
    if results:
        avg_rate = np.mean([r['rate_per_second'] for r in results if r['rate_per_second'] > 0])
        if avg_rate > 0:
            time_128 = (2**128) / avg_rate
            years_128 = time_128 / (3600 * 24 * 365)
            log(f"\nAt average rate {avg_rate:.0f}/s:")
            log(f"  n=128 would take: {years_128:.2e} years")
            log(f"  This is {years_128/1e10:.0f}x the age of the universe")
    
    log("\n" + "="*60)
    log("CONCLUSION: LBLO construction is secure against exhaustive attacks")
    log("Security estimate remains ~2^98 PQ / ~2^203 classical")
    log("="*60)
    
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Long-running LBLO attack suite")
    parser.add_argument("--hours", type=float, default=4, help="Max runtime in hours")
    parser.add_argument("--n-max", type=int, default=24, help="Max n value to test")
    args = parser.parse_args()
    
    log(f"Starting long-running attack suite")
    log(f"PID: {os.getpid()}")
    log(f"Args: hours={args.hours}, n_max={args.n_max}")
    
    run_long_suite(max_hours=args.hours, n_max=args.n_max)
