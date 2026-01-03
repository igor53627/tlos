//! Layer 2: LWE encryption for control function hiding.
//!
//! Uses standard LWE with Gaussian noise (n=384, q=65521, σ=8) providing
//! ~2^112 post-quantum security against lattice attacks.

use rand::Rng;
use rand_distr::{Distribution, Normal};
use sha3::{Digest, Keccak256};

use crate::circuit::Gate;

/// LWE modulus (largest prime < 2^16).
pub const Q: u16 = 65521;

/// LWE dimension (n=384 for ~2^112 PQ security).
pub const LWE_N: usize = 384;

/// Decryption threshold (q/4). Values below indicate bit=0, above indicate bit=1.
pub const THRESHOLD: u16 = Q / 4;

/// Gaussian noise standard deviation (σ=8).
pub const NOISE_SIGMA: f64 = 8.0;

/// Ciphertext size in bytes: n * 2 (for a vector) + 2 (for b scalar).
pub const CT_SIZE: usize = LWE_N * 2 + 2;

/// Encoded gate size: 3 bytes (indices) + 4 ciphertexts (truth table).
pub const GATE_SIZE: usize = 3 + 4 * CT_SIZE;

/// LWE ciphertext: a ∈ Z_q^n and b ∈ Z_q where b = ⟨a,s⟩ + e + m·(q/2).
#[derive(Clone, Debug)]
pub struct LweCiphertext {
    /// Public vector a ∈ Z_q^n.
    pub a: [u16; LWE_N],
    /// Ciphertext scalar b = ⟨a,s⟩ + e + m·(q/2) mod q.
    pub b: u16,
}

impl LweCiphertext {
    pub fn to_bytes(&self) -> [u8; CT_SIZE] {
        let mut bytes = [0u8; CT_SIZE];
        for (i, &val) in self.a.iter().enumerate() {
            bytes[i * 2] = (val >> 8) as u8;
            bytes[i * 2 + 1] = val as u8;
        }
        let b_offset = LWE_N * 2; // 768 for n=384
        bytes[b_offset] = (self.b >> 8) as u8;
        bytes[b_offset + 1] = self.b as u8;
        bytes
    }
}

const _: () = {
    assert!(CT_SIZE == LWE_N * 2 + 2);
};

/// Derives LWE secret s ∈ Z_q^n from a 32-byte seed using Keccak256.
pub fn derive_secret(input: [u8; 32]) -> [u16; LWE_N] {
    let mut secret = [0u16; LWE_N];
    let num_chunks = (LWE_N + 15) / 16;
    for chunk_idx in 0..num_chunks {
        let mut hasher = Keccak256::new();
        hasher.update(&input);
        hasher.update(&(chunk_idx as u64).to_be_bytes());
        let hash = hasher.finalize();
        for i in 0..16 {
            let idx = chunk_idx * 16 + i;
            if idx >= LWE_N {
                break;
            }
            let val = ((hash[i * 2] as u16) << 8) | (hash[i * 2 + 1] as u16);
            secret[idx] = val % Q;
        }
    }
    secret
}

/// Encrypts a single bit using LWE: b = ⟨a,s⟩ + e + bit·(q/2) mod q.
///
/// Gaussian noise e ~ N(0, σ²) masks the message while preserving decryptability.
pub fn encrypt_bit(
    bit: bool,
    a: &[u16; LWE_N],
    secret: &[u16; LWE_N],
    rng: &mut impl Rng,
) -> LweCiphertext {
    let mut inner_prod: u64 = 0;
    for i in 0..LWE_N {
        inner_prod += (a[i] as u64) * (secret[i] as u64);
    }
    inner_prod %= Q as u64;

    let msg_encoding: u64 = if bit { (Q / 2) as u64 } else { 0 };

    let normal = Normal::new(0.0, NOISE_SIGMA).unwrap();
    let noise: f64 = normal.sample(rng);
    let noise_int: i64 = noise.round() as i64;
    let noise_mod: u64 = ((noise_int % (Q as i64)) + (Q as i64)) as u64 % (Q as u64);

    let b = ((inner_prod + msg_encoding + noise_mod) % (Q as u64)) as u16;
    LweCiphertext { a: *a, b }
}

/// Encodes a gate as 3 index bytes + 4 LWE ciphertexts (one per truth table bit).
pub fn encode_gate(gate: &Gate, secret: &[u16; LWE_N], rng: &mut impl Rng) -> Vec<u8> {
    let mut data = Vec::with_capacity(GATE_SIZE);
    data.push(gate.active());
    data.push(gate.control1());
    data.push(gate.control2());

    for tt_idx in 0..4 {
        let bit = (gate.control_function >> tt_idx) & 1 != 0;
        let mut a = [0u16; LWE_N];
        for v in a.iter_mut() {
            *v = rng.gen_range(0..Q);
        }
        let ct = encrypt_bit(bit, &a, secret, rng);
        data.extend_from_slice(&ct.to_bytes());
    }

    debug_assert_eq!(data.len(), GATE_SIZE);
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_encrypt_decrypt_zero() {
        let input = [0u8; 32];
        let secret = derive_secret(input);
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let mut a = [0u16; LWE_N];
        for v in a.iter_mut() {
            *v = rng.gen_range(0..Q);
        }
        let ct = encrypt_bit(false, &a, &secret, &mut rng);
        let mut inner_prod: u64 = 0;
        for i in 0..LWE_N {
            inner_prod += (ct.a[i] as u64) * (secret[i] as u64);
        }
        inner_prod %= Q as u64;
        let diff = ((ct.b as u64 + Q as u64) - inner_prod) % (Q as u64);
        assert!(
            diff < THRESHOLD as u64 || diff > (3 * THRESHOLD) as u64,
            "Expected bit=0: diff={} should be near 0, THRESHOLD={}",
            diff,
            THRESHOLD
        );
    }

    #[test]
    fn test_encrypt_decrypt_one() {
        let input = [1u8; 32];
        let secret = derive_secret(input);
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let mut a = [0u16; LWE_N];
        for v in a.iter_mut() {
            *v = rng.gen_range(0..Q);
        }
        let ct = encrypt_bit(true, &a, &secret, &mut rng);
        let mut inner_prod: u64 = 0;
        for i in 0..LWE_N {
            inner_prod += (ct.a[i] as u64) * (secret[i] as u64);
        }
        inner_prod %= Q as u64;
        let diff = ((ct.b as u64 + Q as u64) - inner_prod) % (Q as u64);
        assert!(
            diff > THRESHOLD as u64 && diff < (3 * THRESHOLD) as u64,
            "Expected bit=1: diff={} should be near q/2={}, THRESHOLD={}",
            diff,
            Q / 2,
            THRESHOLD
        );
    }

    #[test]
    fn test_gate_encoding_size() {
        let gate = Gate::new(0, 1, 2, 0b1010);
        let secret = derive_secret([0u8; 32]);
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let encoded = encode_gate(&gate, &secret, &mut rng);
        assert_eq!(encoded.len(), GATE_SIZE);
    }

    #[test]
    fn test_noise_margin() {
        let input = [42u8; 32];
        let secret = derive_secret(input);
        let mut rng = ChaCha20Rng::seed_from_u64(12345);

        for _ in 0..100 {
            let mut a = [0u16; LWE_N];
            for v in a.iter_mut() {
                *v = rng.gen_range(0..Q);
            }

            let ct0 = encrypt_bit(false, &a, &secret, &mut rng);
            let ct1 = encrypt_bit(true, &a, &secret, &mut rng);

            let mut inner_prod: u64 = 0;
            for i in 0..LWE_N {
                inner_prod += (a[i] as u64) * (secret[i] as u64);
            }
            inner_prod %= Q as u64;

            let diff0 = ((ct0.b as u64 + Q as u64) - inner_prod) % (Q as u64);
            let diff1 = ((ct1.b as u64 + Q as u64) - inner_prod) % (Q as u64);

            assert!(
                diff0 < THRESHOLD as u64 || diff0 > (3 * THRESHOLD) as u64,
                "bit=0 decoding failed: diff0={}"
                , diff0
            );
            assert!(
                diff1 > THRESHOLD as u64 && diff1 < (3 * THRESHOLD) as u64,
                "bit=1 decoding failed: diff1={}"
                , diff1
            );
        }
    }

    fn decode_as_solidity(ct_bytes: &[u8; CT_SIZE], secret: &[u16; LWE_N]) -> u16 {
        let mut inner_prod: u64 = 0;
        for word_idx in 0..24 {
            let base = word_idx * 32;
            for k in 0..16 {
                let byte_idx = base + 2 * k;
                let a_ik = u16::from_be_bytes([ct_bytes[byte_idx], ct_bytes[byte_idx + 1]]);
                let s_idx = word_idx * 16 + k;
                inner_prod += (a_ik as u64) * (secret[s_idx] as u64);
            }
        }
        inner_prod %= Q as u64;

        let b_offset = LWE_N * 2;
        let b = u16::from_be_bytes([ct_bytes[b_offset], ct_bytes[b_offset + 1]]);

        let diff = ((b as u64 + Q as u64) - inner_prod) % (Q as u64);
        diff as u16
    }

    #[test]
    fn test_layout_matches_solidity_decoder() {
        let input = [7u8; 32];
        let secret = derive_secret(input);
        let mut rng = ChaCha20Rng::seed_from_u64(123);

        for &bit in &[false, true] {
            let mut a = [0u16; LWE_N];
            for v in a.iter_mut() {
                *v = rng.gen_range(0..Q);
            }
            let ct = encrypt_bit(bit, &a, &secret, &mut rng);
            let bytes = ct.to_bytes();

            let diff = decode_as_solidity(&bytes, &secret) as u64;

            if !bit {
                assert!(
                    diff < THRESHOLD as u64 || diff > (3 * THRESHOLD) as u64,
                    "bit=0 solidity decode failed: diff={}", diff
                );
            } else {
                assert!(
                    diff > THRESHOLD as u64 && diff < (3 * THRESHOLD) as u64,
                    "bit=1 solidity decode failed: diff={}", diff
                );
            }
        }
    }
}
