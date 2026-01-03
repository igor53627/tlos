# Layer 2: LWE (Control Function Hiding)

Layer 2 uses standard Learning With Errors (LWE) with Gaussian noise to hide the control functions of each gate.

## Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Dimension n | 384 | Post-quantum secure |
| Modulus q | 65521 | Largest 16-bit prime |
| Noise σ | 8 | Gaussian distribution |
| Security | ~2^112 | Lattice estimator |

## What is Layer 2?

Each gate has a 4-bit truth table (control function). Layer 2 encrypts each truth table entry as an LWE ciphertext:

```
ciphertext = (a, b) where:
  a ∈ Z_q^n  (random vector)
  b = <a, s> + e + m*(q/2)  (encrypted bit)
```

Where:
- `s` is the secret vector derived from input
- `e` is Gaussian noise (σ=8)
- `m ∈ {0,1}` is the truth table bit

## Where is the Code?

### Rust (Off-chain Encryption)

| File | Purpose |
|------|---------|
| `src/lwe.rs` | LWE encryption, secret derivation, gate encoding |

```rust
// src/lwe.rs
pub fn encode_gate(gate: &Gate, secret: &[u16; N], rng: &mut impl Rng) -> Vec<u8> {
    let mut data = vec![gate.active(), gate.control1(), gate.control2()];
    
    for tt_idx in 0..4 {
        let bit = (gate.control_function >> tt_idx) & 1 != 0;
        let (a, b) = encrypt_bit(bit, secret, rng);
        // ... encode ciphertext
    }
    data
}
```

### Solidity (On-chain Decryption)

| File | Function |
|------|----------|
| `contracts/TLOSWithPuzzleV4.sol` | `_evaluate()`, `_deriveSecret384Array()` |

```solidity
// Inner product: <a, s> mod q
for { let wordIdx := 0 } lt(wordIdx, 24) { wordIdx := add(wordIdx, 1) } {
    let a := mload(add(ctPtr, mul(wordIdx, 32)))
    let sv := mload(add(sPtr, mul(wordIdx, 32)))
    innerProd := add(innerProd, mul(and(shr(240, a), 0xFFFF), and(shr(240, sv), 0xFFFF)))
    // ... 16 multiplications per word
}

// Decrypt: check if b - <a,s> is closer to 0 or q/2
let diff := mod(add(sub(b, innerProd), q), q)
let cfBit := and(gt(diff, threshold), lt(diff, mul(3, threshold)))
```

## Security Analysis

Lattice estimator results (from `scripts/attacks/estimators/`):

```
Primal attack (uSVP): ~2^118 operations
Dual attack: ~2^115 operations
Combined: ~2^112 post-quantum security
```

## Ciphertext Format

Each gate: 3083 bytes = 3 (header) + 4 × 770 (ciphertexts)

```
[active:1][ctrl1:1][ctrl2:1][ct0:770][ct1:770][ct2:770][ct3:770]

Each ciphertext: 770 bytes = 384×2 (a vector) + 2 (b scalar)
```

## Attack Scripts

See `scripts/attacks/layer2-lwe/`:
- `tlos_attack.py` - Statistical and lattice attacks
- `gpu_attack_benchmark_torch.py` - GPU attack throughput

## Related Files

- `src/lwe.rs` - Rust encryption
- `contracts/TLOSWithPuzzleV4.sol` - Solidity decryption
- `scripts/attacks/estimators/tlos_estimator.sage` - Security estimation
