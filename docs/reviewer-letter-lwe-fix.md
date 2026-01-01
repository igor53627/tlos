# Response to Rescaling Attack: Proposed Fix

Thank you for identifying the rescaling vulnerability in our BE-LWE construction. We've analyzed the issue and have a proposed fix. We'd appreciate your feedback before proceeding.

## Recap: The Vulnerability

Our current encoding:
```
b = <a, s> + μ * (q/2) mod q    where q = 65521, μ ∈ {0,1}
```

Your observation: multiplying by 2 gives
```
2b ≡ 2<a, s> - μ mod q
```

This transforms the "error" from μ*(q/2) to just -μ ∈ {0, -1}. The system becomes **trivial linear algebra** — an attacker can recover s via Gaussian elimination in polynomial time. Security drops to effectively zero.

## Proposed Fix: Add Independent Gaussian Noise

Modify encryption to include an independent error term:
```
b = <a, s> + μ * (q/2) + e mod q    where e ~ N(0, σ²), σ = 8
```

With σ = 8, after rescaling:
```
2b ≡ 2<a, s> - μ + 2e mod q
```

Because e is drawn from a probability distribution, the error term 2e cannot be algebraically eliminated via rescaling. The attacker must solve for s in the presence of noise — this is the definition of the **Learning With Errors** problem.

### Lattice Estimator Results (SageMath + malb/lattice-estimator)

| Parameters | Best Attack | Security |
|------------|-------------|----------|
| n=768, σ=8 | BDD | 2^226 |
| n=512, σ=8 | BDD | 2^149 |
| n=384, σ=8 | BDD | 2^112 |
| n=256, σ=8 | BDD | 2^77 |

### Decoding Correctness

Current threshold is q/4 = 16380. With σ=8:
- Per-sample error: |e| < 4σ = 32 with probability > 0.9999
- After rescaling: |2e - μ| < 65 with high probability
- Threshold 16380 >> 65, so decoding remains correct

**Verified:** Our Solidity uses inequality checks (`diff > threshold && diff < 3*threshold`), not exact equality. Fix works with NO Solidity changes.

### Implementation Impact

- **Solidity: NO CHANGES** — same inner product, same threshold logic
- **Rust generator: Add noise sampling** — straightforward modification
- **Gas: UNCHANGED**

## Alternative: Learning With Rounding (LWR)

As originally discussed:
```
b = round((p/Q) * (<a, s> + μ * Q/2)) mod p
```

Where Q = 2^32 (internal), p = 65521 (output).

**Pros:** Non-linear rounding, formal LWR reductions

**Cons:** Major Solidity rewrite, 32-bit elements, +30-50% gas

We believe the Gaussian noise fix provides equivalent security with far less complexity.

## Questions for Reviewer

1. **Is the Gaussian noise fix cryptographically sound?** Does adding e ~ N(0, 64) properly reduce to standard LWE?

2. **Are there other rescaling-type attacks** that might affect this fix?

3. **Is σ=8 appropriate?** Kyber uses σ~3, but our wide threshold (16380 vs noise ~65) allows us to use σ=8 or higher to ensure hardness, with zero risk of decryption failure.

4. **Do you see any advantage to LWR** that would justify the implementation complexity?

5. **Should we reduce n?** Currently n=768 gives 2^226 security, but Layer 4 only provides 2^76 brute-force resistance. Reducing to n=384 would give 2^112 security (still 36 bits above Layer 4) while cutting gas costs by ~50%.

## Summary & Recommendation

We will proceed with the **Gaussian Noise Fix** as it patches the vulnerability while requiring zero Solidity changes.

Our implementation plan:

1. **σ = 8** — conservative noise parameter with massive threshold margin
2. **n = 384** — provides 2^112 security (36 bits above Layer 4's 2^76 baseline) while cutting gas costs by ~50%

Please flag any concerns with this approach. Otherwise, we will begin implementation.

---

*Lattice estimator script: scripts/sage_lwe_estimator.sage*
