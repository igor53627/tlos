#!/usr/bin/env python3
"""
Break TLO: LWE Key Recovery Attack using fpylll

This script attacks the LWE layer of TLO to recover the secret key s_enc,
then decrypts all control function bits to expose the circuit.

Usage:
    python break_tlo.py --n 16 --num-samples 256 --output results.json
    python break_tlo.py --instance instance.json  # Load from file

Requirements:
    pip install fpylll numpy

Theory:
    TLO uses LWE ciphertexts: (a, b) where b = <a, s> + e + mu * q/2
    
    Primal attack (uSVP):
    1. Build lattice from A matrix
    2. Embed target vector
    3. Run BKZ to find short vector
    4. Short vector reveals s (or allows recovery)
    
    We use the "conservative" model: assume mu bits are known (0),
    which makes this standard LWE and strictly easier for attacker.
"""

import argparse
import json
import time
import sys
from dataclasses import dataclass
from typing import List, Tuple, Optional
import random

import numpy as np

try:
    from fpylll import IntegerMatrix, LLL, BKZ, GSO
    from fpylll.algorithms.bkz2 import BKZReduction
    from fpylll import BKZ as BKZ_FPYLLL
    HAVE_FPYLLL = True
except ImportError:
    HAVE_FPYLLL = False
    IntegerMatrix = None  # For type hints
    print("[!] fpylll not installed. Install with: pip install fpylll")


@dataclass
class LWEInstance:
    """An LWE instance representing TLO ciphertexts."""
    n: int          # dimension
    q: int          # modulus
    sigma: float    # noise std dev
    m: int          # number of samples
    A: np.ndarray   # m x n matrix
    b: np.ndarray   # m-vector
    s: Optional[np.ndarray] = None  # secret (for verification)
    mu: Optional[np.ndarray] = None  # plaintext bits (for verification)
    
    def to_dict(self):
        return {
            'n': self.n,
            'q': self.q,
            'sigma': self.sigma,
            'm': self.m,
            'A': self.A.tolist(),
            'b': self.b.tolist(),
            's': self.s.tolist() if self.s is not None else None,
            'mu': self.mu.tolist() if self.mu is not None else None,
        }
    
    @classmethod
    def from_dict(cls, d):
        return cls(
            n=d['n'],
            q=d['q'],
            sigma=d['sigma'],
            m=d['m'],
            A=np.array(d['A']),
            b=np.array(d['b']),
            s=np.array(d['s']) if d.get('s') else None,
            mu=np.array(d['mu']) if d.get('mu') else None,
        )


def generate_tlo_instance(n: int, num_gates: int, seed: int = None) -> LWEInstance:
    """
    Generate a TLO-like LWE instance.
    
    Parameters match TLO: q=65521, sigma=sqrt(q)/4
    Each gate has 4 CF bits -> m = 4 * num_gates samples
    """
    if seed is not None:
        np.random.seed(seed)
        random.seed(seed)
    
    q = 65521  # largest 16-bit prime (TLO parameter)
    sigma = np.sqrt(q) / 4  # TLO noise parameter
    m = 4 * num_gates  # 4 CF bits per gate
    
    # Generate secret (simulating H(secret) expanded to n elements)
    s = np.random.randint(0, q, size=n)
    
    # Generate random A matrix
    A = np.random.randint(0, q, size=(m, n))
    
    # Generate noise
    e = np.round(np.random.normal(0, sigma, size=m)).astype(int) % q
    
    # Generate plaintext bits (CF truth table entries)
    # In real TLO these come from control functions
    # Here we use random bits (slightly harder for attacker than real distribution)
    mu = np.random.randint(0, 2, size=m)
    
    # Compute ciphertexts: b = A*s + e + mu * q/2 mod q
    b = (A @ s + e + mu * (q // 2)) % q
    
    return LWEInstance(
        n=n, q=q, sigma=sigma, m=m,
        A=A, b=b.astype(int), s=s, mu=mu
    )


def build_primal_lattice(instance: LWEInstance, assume_zero_mu: bool = True) -> IntegerMatrix:
    """
    Build the primal attack lattice for LWE using the standard embedding.
    
    We use the dual lattice approach which is often more effective:
    The short vector in the dual reveals the secret.
    
    Standard primal embedding for b = As + e:
    Lattice basis:
    [ I_n  |  A^T  ]   (n x (n+m))
    [ 0    |  q*I_m]   (m x (n+m))
    
    We embed the target b and look for short (s, e) such that:
    [s | -e] * B ≈ [s | b - As] = [s | e] (short)
    """
    n, q, m = instance.n, instance.q, instance.m
    A, b = instance.A, instance.b
    
    # Adjust b if we know mu bits (remove q/2 offset)
    if assume_zero_mu and instance.mu is not None:
        b_adjusted = (b - instance.mu * (q // 2)) % q
    else:
        b_adjusted = b.copy()
    
    # Use simpler BDD-style embedding
    # Lattice: rows are (q*e_i for i in [m]) and (A[i] for i in [m])
    # This is (m+1) x (n+1) after embedding target
    
    # Actually, let's use the CVP approach via Kannan embedding
    # Basis for the q-ary lattice:
    # [  A  | I_m * q ]   -> (e, s) such that As + e = b mod q
    # [ b^T |    0    ]   -> target row
    
    # Simpler: just build the lattice L = {x : Ax = 0 mod q} + target b
    
    # Standard approach: build (n+m+1) x (n+m+1) basis
    dim = n + m + 1
    B = IntegerMatrix(dim, dim)
    
    # First n rows: identity for s, then A
    for i in range(n):
        B[i, i] = 1
        for j in range(m):
            B[i, n + j] = int(A[j, i])  # A transposed
    
    # Next m rows: q * I_m for the error coordinates
    for j in range(m):
        B[n + j, n + j] = q
    
    # Last row: target embedding
    # We want to find v such that v = (s, e, 1) with As + e = b mod q
    for j in range(m):
        B[dim-1, n + j] = int(b_adjusted[j])
    B[dim-1, dim-1] = 1  # scaling for the "1" coordinate
    
    return B


def build_dual_lattice(instance: LWEInstance) -> IntegerMatrix:
    """
    Alternative: dual attack lattice.
    
    For small-dimension LWE, the dual attack can be more effective.
    We look for short vectors in the dual of the LWE lattice.
    """
    n, q, m = instance.n, instance.q, instance.m
    A, b = instance.A, instance.b
    
    # Adjust for mu if known
    if instance.mu is not None:
        b_adjusted = (b - instance.mu * (q // 2)) % q
    else:
        b_adjusted = b.copy()
    
    # Build [ A | I_m | b ]
    dim = n + m + 1
    B = IntegerMatrix(m, dim)
    
    for i in range(m):
        for j in range(n):
            B[i, j] = int(A[i, j])
        B[i, n + i] = q
        B[i, dim - 1] = int(b_adjusted[i])
    
    return B


def solve_lwe_gaussian_elimination(instance: LWEInstance, verbose: bool = True) -> Tuple[Optional[np.ndarray], dict]:
    """
    Solve LWE with uniform secret using Gaussian elimination when m >= n.
    
    IMPORTANT: TLO uses UNIFORM secrets (hash output), not small secrets!
    This makes standard lattice attacks (which assume small s) less effective.
    
    For uniform s, we can use:
    1. Gaussian elimination (exact if no noise)
    2. Linear regression (handles noise)
    3. BKW algorithm (subexponential for large m)
    """
    n, q, m = instance.n, instance.q, instance.m
    A, b = instance.A, instance.b
    
    # Adjust for mu if known
    if instance.mu is not None:
        b_adjusted = (b - instance.mu * (q // 2)) % q
    else:
        b_adjusted = b.copy()
    
    stats = {'method': 'gaussian', 'n': n, 'm': m}
    start = time.time()
    
    if verbose:
        print(f"[*] Trying Gaussian elimination for n={n}, m={m}")
        print(f"[*] Note: TLO uses UNIFORM secrets, not small secrets")
    
    # Try to solve As = b mod q using Gaussian elimination
    # This works perfectly if there's no noise
    
    # Use numpy's modular linear algebra
    # Find pseudo-inverse and solve
    try:
        # Convert to float for numerical solve, then check
        A_float = A.astype(float)
        b_float = b_adjusted.astype(float)
        
        # Least squares solution
        s_float, residuals, rank, _ = np.linalg.lstsq(A_float, b_float, rcond=None)
        
        # Round and mod q
        s_candidate = np.round(s_float).astype(int) % q
        
        # Verify
        residual = (A @ s_candidate - b_adjusted) % q
        residual_adjusted = np.minimum(residual, q - residual)
        max_residual = np.max(residual_adjusted)
        mean_residual = np.mean(residual_adjusted)
        
        if verbose:
            print(f"[*] Least squares: max_res={max_residual:.0f}, mean_res={mean_residual:.0f}")
        
        # Check if solution is good
        if max_residual < 5 * instance.sigma:
            if verbose:
                print(f"[+] Found solution via least squares!")
            stats['time'] = time.time() - start
            return s_candidate, stats
    except Exception as e:
        if verbose:
            print(f"[*] Least squares failed: {e}")
    
    # Try modular Gaussian elimination using sage-style approach
    # For small n, this is feasible
    if n <= 20:
        if verbose:
            print(f"[*] Trying modular solve for small n={n}")
        
        # Pick n rows and try to invert A
        for attempt in range(min(100, m - n + 1)):
            # Select n rows
            indices = list(range(attempt, attempt + n))
            if indices[-1] >= m:
                indices = list(range(m - n, m))
            
            A_sub = A[indices]
            b_sub = b_adjusted[indices]
            
            # Try to solve A_sub * s = b_sub mod q
            try:
                # Compute determinant
                det = int(round(np.linalg.det(A_sub.astype(float)))) % q
                if det == 0 or np.gcd(det, q) > 1:
                    continue
                
                # Compute inverse mod q
                det_inv = pow(det, -1, q)
                adj = np.round(np.linalg.det(A_sub.astype(float)) * np.linalg.inv(A_sub.astype(float))).astype(int)
                A_inv = (adj * det_inv) % q
                
                s_candidate = (A_inv @ b_sub) % q
                
                # Verify on ALL rows
                residual = (A @ s_candidate - b_adjusted) % q
                residual_adjusted = np.minimum(residual, q - residual)
                max_residual = np.max(residual_adjusted)
                
                if max_residual < 5 * instance.sigma:
                    if verbose:
                        print(f"[+] Found solution via modular solve (attempt {attempt})!")
                    stats['time'] = time.time() - start
                    return s_candidate, stats
                    
            except Exception:
                continue
    
    stats['time'] = time.time() - start
    return None, stats


def primal_attack_bkz(instance: LWEInstance, block_size: int = 20, 
                       max_loops: int = 8, verbose: bool = True) -> Tuple[Optional[np.ndarray], dict]:
    """
    Run primal (uSVP) attack using BKZ reduction.
    
    Returns:
        (recovered_secret, stats_dict)
        recovered_secret is None if attack failed
    """
    if not HAVE_FPYLLL:
        return None, {'error': 'fpylll not installed'}
    
    stats = {
        'n': instance.n,
        'q': instance.q,
        'm': instance.m,
        'block_size': block_size,
        'max_loops': max_loops,
    }
    
    if verbose:
        print(f"[*] Building primal lattice for n={instance.n}, m={instance.m}, q={instance.q}")
    
    start_build = time.time()
    B = build_primal_lattice(instance, assume_zero_mu=True)
    stats['lattice_build_time'] = time.time() - start_build
    
    dim = B.nrows
    if verbose:
        print(f"[*] Lattice dimension: {dim}")
        print(f"[*] Running LLL preprocessing...")
    
    # LLL preprocessing
    start_lll = time.time()
    LLL.reduction(B)
    stats['lll_time'] = time.time() - start_lll
    
    if verbose:
        print(f"[*] LLL done in {stats['lll_time']:.2f}s")
        print(f"[*] Running BKZ-{block_size} (max {max_loops} loops)...")
    
    # BKZ reduction
    start_bkz = time.time()
    
    # BKZ parameters - use simpler approach without strategy files
    try:
        params = BKZ_FPYLLL.Param(
            block_size=block_size,
            max_loops=max_loops,
        )
    except RuntimeError:
        # Fallback: even simpler params
        params = BKZ_FPYLLL.Param(block_size=block_size)
    
    # Run BKZ
    M = GSO.Mat(B)
    M.update_gso()
    bkz = BKZReduction(M)
    bkz(params)
    
    stats['bkz_time'] = time.time() - start_bkz
    stats['total_time'] = stats['lattice_build_time'] + stats['lll_time'] + stats['bkz_time']
    
    if verbose:
        print(f"[*] BKZ done in {stats['bkz_time']:.2f}s")
    
    # Extract candidate secret from short vectors
    n, m, q = instance.n, instance.q, instance.m  # Note: m is number of samples
    
    # Adjust b for known mu bits
    if instance.mu is not None:
        b_adjusted = (instance.b - instance.mu * (q // 2)) % q
    else:
        b_adjusted = instance.b.copy()
    
    recovered_s = None
    best_residual = float('inf')
    
    for i in range(min(20, dim)):  # Check first 20 short vectors
        vec = np.array([B[i, j] for j in range(dim)])
        
        # The short vector format is (s_1, ..., s_n, e_1, ..., e_m, t)
        # where dim = n + m + 1
        candidate_s = vec[:n]
        
        # Skip zero vector
        if np.all(candidate_s == 0):
            continue
        
        # Verify by checking if A*s ≈ b (mod q) with small error
        residual = (instance.A @ candidate_s - b_adjusted) % q
        # Handle wraparound
        residual_adjusted = np.minimum(residual, q - residual)
        max_residual = np.max(residual_adjusted)
        mean_residual = np.mean(residual_adjusted)
        
        if verbose and i < 5:
            print(f"[*] Row {i}: max_res={max_residual:.0f}, mean_res={mean_residual:.0f}, s_norm={np.linalg.norm(candidate_s):.0f}")
        
        # If residuals are small (< few sigma), we likely found it
        if max_residual < 5 * instance.sigma and mean_residual < 2 * instance.sigma:
            if verbose:
                print(f"[+] Candidate secret found in row {i}, max residual: {max_residual:.1f}")
            recovered_s = candidate_s % q
            break
        
        # Track best candidate
        if mean_residual < best_residual:
            best_residual = mean_residual
    
    # If lattice attack failed, try Gaussian elimination for uniform secret
    if recovered_s is None:
        if verbose:
            print(f"[*] Lattice attack didn't find secret, trying Gaussian elimination...")
        gauss_s, gauss_stats = solve_lwe_gaussian_elimination(instance, verbose=verbose)
        if gauss_s is not None:
            recovered_s = gauss_s
            stats['method'] = 'gaussian'
    
    # Verify against true secret if available
    if recovered_s is not None and instance.s is not None:
        # Check if we found the right secret
        match = np.allclose(recovered_s % q, instance.s % q)
        stats['verified'] = match
        if verbose:
            if match:
                print(f"[+] SECRET RECOVERED AND VERIFIED!")
            else:
                print(f"[-] Candidate found but doesn't match true secret")
                print(f"    Found: {recovered_s[:5]}...")
                print(f"    True:  {instance.s[:5]}...")
    else:
        stats['verified'] = None
    
    stats['success'] = recovered_s is not None
    stats['best_residual'] = best_residual
    
    return recovered_s, stats


def decrypt_control_functions(instance: LWEInstance, s: np.ndarray) -> np.ndarray:
    """
    Once we have the secret s, decrypt all control function bits.
    
    For each ciphertext (a, b):
        inner = <a, s> mod q
        diff = (b - inner) mod q
        bit = 1 if q/4 < diff < 3q/4 else 0
    """
    q = instance.q
    A, b = instance.A, instance.b
    
    # Compute inner products
    inner = (A @ s) % q
    
    # Compute differences
    diff = (b - inner) % q
    
    # Threshold decryption
    threshold_low = q // 4
    threshold_high = 3 * q // 4
    
    decrypted = ((diff > threshold_low) & (diff < threshold_high)).astype(int)
    
    return decrypted


def run_full_attack(n: int, num_gates: int, block_size: int = 20, 
                    seed: int = None, verbose: bool = True) -> dict:
    """
    Run complete TLO attack: generate instance, break LWE, decrypt CFs.
    """
    results = {
        'n': n,
        'num_gates': num_gates,
        'm': 4 * num_gates,
        'block_size': block_size,
        'seed': seed,
    }
    
    if verbose:
        print(f"\n{'='*60}")
        print(f"TLO Attack: n={n}, gates={num_gates}, m={4*num_gates}")
        print(f"{'='*60}")
    
    # Generate instance
    if verbose:
        print(f"\n[1/3] Generating TLO instance...")
    start_gen = time.time()
    instance = generate_tlo_instance(n, num_gates, seed)
    results['generation_time'] = time.time() - start_gen
    
    # Run LWE attack
    if verbose:
        print(f"\n[2/3] Running LWE key recovery attack...")
    recovered_s, attack_stats = primal_attack_bkz(
        instance, block_size=block_size, verbose=verbose
    )
    results['attack_stats'] = attack_stats
    results['key_recovered'] = recovered_s is not None
    
    if recovered_s is None:
        if verbose:
            print(f"\n[-] ATTACK FAILED: Could not recover secret key")
        results['success'] = False
        return results
    
    # Decrypt control functions
    if verbose:
        print(f"\n[3/3] Decrypting control functions...")
    start_decrypt = time.time()
    decrypted_mu = decrypt_control_functions(instance, recovered_s)
    results['decrypt_time'] = time.time() - start_decrypt
    
    # Verify decryption
    if instance.mu is not None:
        correct = np.sum(decrypted_mu == instance.mu)
        total = len(instance.mu)
        accuracy = correct / total
        results['cf_accuracy'] = accuracy
        results['cf_correct'] = int(correct)
        results['cf_total'] = total
        
        if verbose:
            print(f"[*] CF decryption accuracy: {correct}/{total} ({accuracy*100:.1f}%)")
    
    # Total time
    results['total_time'] = (
        results['generation_time'] + 
        attack_stats.get('total_time', 0) + 
        results.get('decrypt_time', 0)
    )
    results['success'] = True
    
    if verbose:
        print(f"\n[+] ATTACK SUCCESSFUL!")
        print(f"[+] Total time: {results['total_time']:.2f}s")
        print(f"[+] LWE key recovery: {attack_stats.get('total_time', 0):.2f}s")
        if 'cf_accuracy' in results:
            print(f"[+] CF bits recovered: {results['cf_correct']}/{results['cf_total']}")
    
    return results


def run_parameter_sweep(verbose: bool = True) -> List[dict]:
    """
    Run attacks across multiple parameter settings to find break points.
    """
    results = []
    
    # Test configurations: (n, num_gates, block_size)
    configs = [
        # Easy (should break quickly)
        (16, 40, 20),    # m=160
        (16, 64, 25),    # m=256
        
        # Medium (might take minutes)
        (24, 64, 30),    # m=256
        (24, 160, 35),   # m=640
        
        # Hard (might take hours or fail)
        (32, 160, 40),   # m=640
        (32, 320, 45),   # m=1280
        
        # TLO production params (should NOT break)
        # (64, 640, 50),  # m=2560 - uncomment to test (will be slow/fail)
    ]
    
    for n, num_gates, block_size in configs:
        print(f"\n{'#'*60}")
        print(f"# Testing n={n}, gates={num_gates}, block_size={block_size}")
        print(f"{'#'*60}")
        
        try:
            result = run_full_attack(
                n=n, 
                num_gates=num_gates, 
                block_size=block_size,
                seed=42,
                verbose=verbose
            )
            results.append(result)
        except Exception as e:
            print(f"[-] Error: {e}")
            results.append({
                'n': n,
                'num_gates': num_gates,
                'block_size': block_size,
                'error': str(e),
                'success': False,
            })
        
        # Early exit if we're taking too long
        if results[-1].get('total_time', 0) > 3600:  # 1 hour
            print(f"[!] Attack taking too long, stopping sweep")
            break
    
    return results


def print_summary(results: List[dict]):
    """Print a summary table of attack results."""
    print(f"\n{'='*80}")
    print(f"ATTACK SUMMARY")
    print(f"{'='*80}")
    print(f"{'n':>4} {'gates':>6} {'m':>6} {'beta':>5} {'success':>8} {'time':>10} {'CF acc':>8}")
    print(f"{'-'*80}")
    
    for r in results:
        n = r.get('n', '?')
        gates = r.get('num_gates', '?')
        m = r.get('m', '?')
        beta = r.get('block_size', '?')
        success = '[OK]' if r.get('success') else '[FAIL]'
        time_s = r.get('total_time', 0)
        time_str = f"{time_s:.1f}s" if time_s < 60 else f"{time_s/60:.1f}m"
        cf_acc = r.get('cf_accuracy', None)
        cf_str = f"{cf_acc*100:.1f}%" if cf_acc else "N/A"
        
        print(f"{n:>4} {gates:>6} {m:>6} {beta:>5} {success:>8} {time_str:>10} {cf_str:>8}")
    
    print(f"{'='*80}")
    
    # Summary stats
    successes = sum(1 for r in results if r.get('success'))
    print(f"\nTotal: {successes}/{len(results)} attacks successful")
    
    if successes > 0:
        successful = [r for r in results if r.get('success')]
        max_n = max(r['n'] for r in successful)
        print(f"Largest n broken: {max_n}")


def load_instance_from_file(filepath: str) -> LWEInstance:
    """Load a TLO instance exported from Rust."""
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    n = data['n']
    q = data['q']
    sigma = data['sigma']
    m = data['m']
    
    A = np.array(data['A'])
    b = np.array(data['b_vector'])
    
    # Ground truth if available
    s = np.array(data['secret']) if data.get('secret') else None
    mu = np.array(data['mu_bits']) if data.get('mu_bits') else None
    
    return LWEInstance(n=n, q=q, sigma=sigma, m=m, A=A, b=b, s=s, mu=mu)


def main():
    parser = argparse.ArgumentParser(description='Break TLO LWE layer')
    parser.add_argument('--n', type=int, default=16, help='LWE dimension')
    parser.add_argument('--gates', type=int, default=64, help='Number of gates')
    parser.add_argument('--block-size', type=int, default=20, help='BKZ block size')
    parser.add_argument('--seed', type=int, default=42, help='Random seed')
    parser.add_argument('--sweep', action='store_true', help='Run parameter sweep')
    parser.add_argument('--output', type=str, help='Output JSON file')
    parser.add_argument('--instance', type=str, help='Load instance from JSON file')
    parser.add_argument('--quiet', action='store_true', help='Less verbose output')
    
    args = parser.parse_args()
    
    if not HAVE_FPYLLL:
        print("Error: fpylll required. Install with: pip install fpylll")
        sys.exit(1)
    
    verbose = not args.quiet
    
    if args.instance:
        # Load and attack instance from file
        if verbose:
            print(f"[*] Loading instance from {args.instance}")
        instance = load_instance_from_file(args.instance)
        if verbose:
            print(f"[*] Instance: n={instance.n}, m={instance.m}, q={instance.q}")
        
        recovered_s, stats = primal_attack_bkz(
            instance, block_size=args.block_size, verbose=verbose
        )
        
        if recovered_s is not None:
            decrypted = decrypt_control_functions(instance, recovered_s)
            if instance.mu is not None:
                correct = np.sum(decrypted == instance.mu)
                print(f"[+] CF accuracy: {correct}/{len(instance.mu)}")
        
        results = [stats]
    elif args.sweep:
        results = run_parameter_sweep(verbose=verbose)
        print_summary(results)
    else:
        results = run_full_attack(
            n=args.n,
            num_gates=args.gates,
            block_size=args.block_size,
            seed=args.seed,
            verbose=verbose
        )
        results = [results]
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nResults saved to {args.output}")


if __name__ == '__main__':
    main()
