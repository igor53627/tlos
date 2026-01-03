#!/usr/bin/env python3
"""
LWE Security Estimator for Uniform Secrets

TLO uses uniform secrets s = H(secret) ∈ Z_q^n, not small secrets.
This script estimates security using formulas from the literature.

Key insight: For uniform-secret LWE, we can use the "normal form" transformation:
- (A, As + e) with uniform s ≈ (A', A's' + e') with small s'
- But the transformation increases dimension or reduces security slightly

References:
- Albrecht et al. "On the concrete hardness of LWE" (2015)
- Lindner-Peikert model for LWE security
- BKZ cost models (Core-SVP)
"""

import math
from dataclasses import dataclass
from typing import Tuple

@dataclass
class LWEParams:
    n: int       # dimension
    q: int       # modulus
    sigma: float # noise std dev
    m: int       # number of samples
    secret_type: str = "uniform"  # "uniform" or "small"


def log2(x):
    return math.log2(x) if x > 0 else 0


def bkz_delta(beta: float) -> float:
    """Root Hermite factor for BKZ-beta."""
    if beta < 2:
        return 1.0
    return ((math.pi * beta) ** (1/beta) * beta / (2 * math.pi * math.e)) ** (1/(2*(beta-1)))


def bkz_cost_classical(beta: float) -> float:
    """BKZ-beta cost in log2 operations (Core-SVP model with sieving)."""
    # BDGL16 sieving: 2^(0.292 * beta)
    return 0.292 * beta + 16.4  # +16.4 for polynomial factors


def bkz_cost_quantum(beta: float) -> float:
    """BKZ-beta cost with quantum speedup."""
    # Quantum sieving: 2^(0.265 * beta)
    return 0.265 * beta + 16.4


def primal_attack_uniform(params: LWEParams) -> Tuple[float, float, int]:
    """
    Primal (uSVP) attack for uniform-secret LWE.
    
    For uniform secret, the standard embedding doesn't work well.
    We use a modified approach based on Lindner-Peikert analysis.
    
    Returns: (classical_bits, quantum_bits, optimal_beta)
    """
    n, q, sigma, m = params.n, params.q, params.sigma, params.m
    
    # For uniform secret, the primal attack is harder.
    # We search for optimal (d, beta) where d <= m + n
    
    best_cost = float('inf')
    best_quantum = float('inf')
    best_beta = 50
    
    # Try different lattice dimensions
    for d in range(n + 10, min(m + n + 1, 500)):
        # Target: find vector of norm ~ sigma * sqrt(d)
        target_norm = sigma * math.sqrt(d)
        
        for beta in range(20, min(d, 400)):
            delta = bkz_delta(beta)
            
            # Gaussian heuristic for q-ary lattice
            # det(L)^(1/d) ≈ q^(n/d) for the primal lattice
            log_det = n * log2(q) / d
            
            # Expected shortest vector: delta^d * det^(1/d)
            log_expected = d * log2(delta) + log_det
            log_target = log2(target_norm)
            
            # Success condition
            if log_expected <= log_target + 1:  # +1 for slack
                classical = bkz_cost_classical(beta)
                quantum = bkz_cost_quantum(beta)
                
                if classical < best_cost:
                    best_cost = classical
                    best_quantum = quantum
                    best_beta = beta
        
        # Early termination if we found something
        if best_cost < float('inf'):
            break
    
    return best_cost, best_quantum, best_beta


def dual_attack_uniform(params: LWEParams) -> Tuple[float, float, int]:
    """
    Dual attack for uniform-secret LWE.
    
    Find short vector w in dual lattice such that <w, b> reveals info about s.
    This attack works regardless of secret distribution.
    
    Returns: (classical_bits, quantum_bits, optimal_beta)
    """
    n, q, sigma, m = params.n, params.q, params.sigma, params.m
    
    # For dual attack, we need short vector w in dual lattice
    # such that <w, e> is distinguishable from uniform mod q
    
    # Advantage: exp(-pi * (||w|| * sigma)^2 / q^2)
    # Need ||w|| * sigma < q / sqrt(2*pi) for advantage
    
    best_cost = float('inf')
    best_quantum = float('inf')
    best_beta = 50
    
    # Try different dimensions (subset of samples)
    for d in range(n, min(m, 400)):
        # Target norm for distinguishing
        target_w_norm = q / (sigma * math.sqrt(2 * math.pi))
        log_target = log2(target_w_norm) if target_w_norm > 0 else 0
        
        for beta in range(20, min(d, 400)):
            delta = bkz_delta(beta)
            
            # Expected shortest vector in dual of q-ary lattice
            # det(dual) = 1/det(L) for unimodular, but q-ary has det ~ q^(d-n)
            # dual det ~ q^n for the relevant sublattice
            log_det = n * log2(q) / d
            
            # Expected norm of shortest vector
            log_expected = d * log2(delta) + log_det
            
            if log_expected <= log_target:
                classical = bkz_cost_classical(beta)
                quantum = bkz_cost_quantum(beta)
                
                if classical < best_cost:
                    best_cost = classical
                    best_quantum = quantum
                    best_beta = beta
        
        if best_cost < float('inf'):
            break
    
    return best_cost, best_quantum, best_beta


def arora_ge_attack(params: LWEParams) -> float:
    """
    Arora-Ge algebraic attack.
    
    Works when noise is small relative to q and we have many samples.
    Polynomial in n when sigma < sqrt(n) and m > n^(sigma^2).
    
    Returns: log2(cost) or inf if not applicable
    """
    n, q, sigma, m = params.n, params.q, params.sigma, params.m
    
    # Arora-Ge requires sigma < sqrt(n)
    if sigma >= math.sqrt(n):
        return float('inf')
    
    # Need m > n^(O(sigma^2)) samples
    required_m = n ** (sigma * sigma / 10)  # rough estimate
    if m < required_m:
        return float('inf')
    
    # Cost is polynomial: O(n^(sigma^2))
    return sigma * sigma * log2(n)


def estimate_security(params: LWEParams) -> dict:
    """
    Estimate security for LWE parameters.
    
    Returns dict with attack costs in log2.
    """
    results = {
        'params': params,
    }
    
    # Primal attack
    primal_c, primal_q, primal_beta = primal_attack_uniform(params)
    results['primal_classical'] = primal_c
    results['primal_quantum'] = primal_q
    results['primal_beta'] = primal_beta
    
    # Dual attack
    dual_c, dual_q, dual_beta = dual_attack_uniform(params)
    results['dual_classical'] = dual_c
    results['dual_quantum'] = dual_q
    results['dual_beta'] = dual_beta
    
    # Arora-Ge
    results['arora_ge'] = arora_ge_attack(params)
    
    # Best attack
    results['best_classical'] = min(primal_c, dual_c, results['arora_ge'])
    results['best_quantum'] = min(primal_q, dual_q)
    
    return results


def print_results(results: dict):
    """Pretty-print security estimates."""
    params = results['params']
    print(f"n={params.n:3d}, q={params.q}, σ={params.sigma:.0f}, m={params.m}")
    print(f"  Primal: {results['primal_classical']:.1f}-bit (β={results['primal_beta']})")
    print(f"  Dual:   {results['dual_classical']:.1f}-bit (β={results['dual_beta']})")
    if results['arora_ge'] < float('inf'):
        print(f"  Arora-Ge: {results['arora_ge']:.1f}-bit")
    print(f"  Best classical: {results['best_classical']:.1f}-bit")
    print(f"  Best quantum:   {results['best_quantum']:.1f}-bit")


def main():
    print("=" * 60)
    print("TLO LWE Security Estimates (Uniform Secret)")
    print("=" * 60)
    print()
    print("TLO uses s = H(secret) ∈ Z_q^n (uniform, not small)")
    print("Parameters: q=65521, σ=sqrt(q)/4≈64")
    print()
    
    q = 65521
    sigma = math.sqrt(q) / 4
    
    # TLO configurations
    configs = [
        (16, 4 * 64),    # 64 gates
        (32, 4 * 160),   # 160 gates  
        (64, 4 * 640),   # 640 gates (default)
        (128, 4 * 640),  # 640 gates, larger n
        (256, 4 * 640),  # 640 gates, even larger n
    ]
    
    print("-" * 60)
    
    all_results = []
    for n, m in configs:
        params = LWEParams(n=n, q=q, sigma=sigma, m=m, secret_type="uniform")
        results = estimate_security(params)
        print_results(results)
        print()
        all_results.append(results)
    
    # Summary table
    print("=" * 60)
    print("SUMMARY TABLE")
    print("=" * 60)
    print(f"{'n':>4} {'m':>5} {'Primal':>10} {'Dual':>10} {'Best':>10}")
    print("-" * 45)
    
    for r in all_results:
        p = r['params']
        print(f"{p.n:>4} {p.m:>5} {r['primal_classical']:>8.0f}-bit {r['dual_classical']:>8.0f}-bit {r['best_classical']:>8.0f}-bit")
    
    print()
    print("Note: These are heuristic estimates, not rigorous bounds.")
    print("The uniform-secret variant affects primal attack more than dual.")
    print()
    
    # Comparison with our Rust estimator
    print("=" * 60)
    print("COMPARISON WITH PREVIOUS ESTIMATES")
    print("=" * 60)
    print()
    print("Our Rust estimator (small-secret assumption):")
    print("  n=64: ~26-bit claimed")
    print()
    print("This estimator (uniform-secret, TLO actual):")
    n64_result = [r for r in all_results if r['params'].n == 64][0]
    print(f"  n=64: ~{n64_result['best_classical']:.0f}-bit")
    print()
    
    if n64_result['best_classical'] > 30:
        print("[+] Security may be HIGHER than previously claimed!")
    else:
        print("[!] Security is similar to or lower than claimed.")


if __name__ == '__main__':
    main()
