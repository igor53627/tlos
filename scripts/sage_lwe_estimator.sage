#!/usr/bin/env sage
"""
TLOS LWE/LWR Security Analysis using the Lattice Estimator

This script analyzes:
1. Deterministic LWE (broken by rescaling attack)
2. Standard LWE with Gaussian noise (current implementation)
3. LWR alternative

Run with: sage sage_lwe_estimator.sage
"""

import sys
sys.path.insert(0, "/root/lattice-estimator")

from estimator import *

print("="*70)
print("TLOS LWE/LWR Security Analysis - Lattice Estimator")
print("="*70)

# TLOS parameters
q_16bit = 65521
Q_32bit = 2**32
p_output = 65521
m_samples = 2560  # 4 ciphertexts * 640 gates

print("\n" + "="*70)
print("1. BROKEN: Deterministic LWE (after rescaling attack)")
print("="*70)
print("After rescaling: 2b = 2<a,s> - mu mod q")
print("Error becomes mu in {0, -1}, equivalent to sigma ~ 0.5")
print()

# The rescaled deterministic scheme has trivial error
for n in [768]:
    print(f"\n--- n={n}, q={q_16bit}, m={m_samples}, sigma=0.5 (rescaled deterministic) ---")
    try:
        # Model as LWE with very small error (mu in {0,-1})
        params = LWE.Parameters(
            n=n,
            q=q_16bit,
            Xs=ND.UniformMod(q_16bit),  # uniform secret
            Xe=ND.DiscreteGaussian(0.5),  # tiny error after rescaling
            m=m_samples
        )
        result = LWE.estimate(params, jobs=4)
        print(result)
    except Exception as e:
        print(f"Error: {e}")

print("\n" + "="*70)
print("2. FIXED: Standard LWE with Gaussian noise (current implementation)")
print("="*70)

# Test various sigma values with n=768
for sigma in [3.0, 5.0, 8.0, 16.0]:
    print(f"\n--- n=768, q={q_16bit}, m={m_samples}, sigma={sigma} ---")
    try:
        params = LWE.Parameters(
            n=768,
            q=q_16bit,
            Xs=ND.UniformMod(q_16bit),
            Xe=ND.DiscreteGaussian(sigma),
            m=m_samples
        )
        result = LWE.estimate(params, jobs=4)
        print(result)
    except Exception as e:
        print(f"Error: {e}")

# Also test smaller n to see if we can reduce dimension
print("\n--- Testing smaller dimensions with sigma=8 ---")
for n in [256, 384, 512, 768]:
    print(f"\n--- n={n}, q={q_16bit}, m={m_samples}, sigma=8 ---")
    try:
        params = LWE.Parameters(
            n=n,
            q=q_16bit,
            Xs=ND.UniformMod(q_16bit),
            Xe=ND.DiscreteGaussian(8.0),
            m=m_samples
        )
        result = LWE.estimate(params, jobs=4)
        print(result)
    except Exception as e:
        print(f"Error: {e}")

print("\n" + "="*70)
print("3. ALTERNATIVE: LWR (32-bit internal modulus)")
print("="*70)

# LWR with Q=2^32, p=65521
for n in [512, 768, 1024]:
    print(f"\n--- LWR: n={n}, Q=2^32, p={p_output}, m={m_samples} ---")
    try:
        params = LWR.Parameters(
            n=n,
            q=Q_32bit,
            p=p_output,
            Xs=ND.UniformMod(Q_32bit),
            m=m_samples
        )
        result = LWR.estimate(params, jobs=4)
        print(result)
    except Exception as e:
        print(f"Error: {e}")

print("\n" + "="*70)
print("4. COMPARISON TO LAYER 4 PUZZLE (target: 76 bits)")
print("="*70)
print("Layer 4 planted LWE puzzle provides ~2^76 minimum brute-force resistance.")
print("Control function hiding should provide AT LEAST comparable security.")
print()

# Minimum viable parameters
print("\nSearching for minimum n with sigma=8 that provides >= 76-bit security...")
for n in [128, 192, 256, 320, 384, 448, 512]:
    try:
        params = LWE.Parameters(
            n=n,
            q=q_16bit,
            Xs=ND.UniformMod(q_16bit),
            Xe=ND.DiscreteGaussian(8.0),
            m=m_samples
        )
        result = LWE.estimate(params, jobs=4)
        # Extract minimum rop
        min_rop = min(r.get("rop", float('inf')) for r in result.values() if hasattr(r, 'get'))
        print(f"n={n}: min rop = 2^{log(min_rop, 2):.1f}")
    except Exception as e:
        print(f"n={n}: Error - {e}")

print("\n" + "="*70)
print("SUMMARY")
print("="*70)
