use rand::Rng;
use sha3::{Digest, Keccak256};

use crate::circuit::Gate;

pub const Q: u16 = 65521;
pub const LWE_N: usize = 128;
pub const THRESHOLD: u16 = Q / 4;
pub const CT_SIZE: usize = 258;
pub const GATE_SIZE: usize = 1035;

#[derive(Clone, Debug)]
pub struct LweCiphertext {
    pub a: [u16; LWE_N],
    pub b: u16,
}

impl LweCiphertext {
    pub fn to_bytes(&self) -> [u8; CT_SIZE] {
        let mut bytes = [0u8; CT_SIZE];
        for (i, &val) in self.a.iter().enumerate() {
            bytes[i * 2] = (val >> 8) as u8;
            bytes[i * 2 + 1] = val as u8;
        }
        bytes[256] = (self.b >> 8) as u8;
        bytes[257] = self.b as u8;
        bytes
    }
}

pub fn derive_secret(input: [u8; 32]) -> [u16; LWE_N] {
    let mut secret = [0u16; LWE_N];
    for chunk_idx in 0..8 {
        let mut hasher = Keccak256::new();
        hasher.update(&input);
        hasher.update(&(chunk_idx as u64).to_be_bytes());
        let hash = hasher.finalize();
        for i in 0..16 {
            let val = ((hash[i * 2] as u16) << 8) | (hash[i * 2 + 1] as u16);
            secret[chunk_idx * 16 + i] = val % Q;
        }
    }
    secret
}

pub fn encrypt_bit(bit: bool, a: &[u16; LWE_N], secret: &[u16; LWE_N]) -> LweCiphertext {
    let mut inner_prod: u32 = 0;
    for i in 0..LWE_N {
        inner_prod = (inner_prod + (a[i] as u32) * (secret[i] as u32)) % (Q as u32);
    }
    let msg_encoding: u32 = if bit { (Q / 2) as u32 } else { 0 };
    let b = ((inner_prod + msg_encoding) % (Q as u32)) as u16;
    LweCiphertext { a: *a, b }
}

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
        let ct = encrypt_bit(bit, &a, secret);
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
        let ct = encrypt_bit(false, &a, &secret);
        let mut inner_prod: u32 = 0;
        for i in 0..LWE_N {
            inner_prod = (inner_prod + (ct.a[i] as u32) * (secret[i] as u32)) % (Q as u32);
        }
        let diff = ((ct.b as u32 + Q as u32) - inner_prod) % (Q as u32);
        assert!(diff < THRESHOLD as u32 || diff > (3 * THRESHOLD) as u32);
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
        let ct = encrypt_bit(true, &a, &secret);
        let mut inner_prod: u32 = 0;
        for i in 0..LWE_N {
            inner_prod = (inner_prod + (ct.a[i] as u32) * (secret[i] as u32)) % (Q as u32);
        }
        let diff = ((ct.b as u32 + Q as u32) - inner_prod) % (Q as u32);
        assert!(diff > THRESHOLD as u32 && diff < (3 * THRESHOLD) as u32);
    }

    #[test]
    fn test_gate_encoding_size() {
        let gate = Gate::new(0, 1, 2, 0b1010);
        let secret = derive_secret([0u8; 32]);
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let encoded = encode_gate(&gate, &secret, &mut rng);
        assert_eq!(encoded.len(), GATE_SIZE);
    }
}
