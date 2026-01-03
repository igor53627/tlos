use sha3::{Digest, Keccak256};

/// LWE modulus (largest 16-bit prime), shared with Layer 2.
pub const Q: u32 = 65521;

/// Number of rows in the wire binding matrix (64 wires).
pub const BINDING_ROWS: usize = 64;

/// Compute full-rank wire binding hash H(x) = A * x mod q where A is 64x64
/// Mirrors TLOS.sol::_wireBindingHash exactly
///
/// - `input_bits`: lower `num_wires` bits contain the wire / combined state  
/// - `gate_idx`: gate index (0 for init, batchEnd for updates)
/// - `num_wires`: 1..=64
/// - `circuit_seed`: 32-byte seed matching Solidity `circuitSeed`
/// - Returns: `[U256; 4]` packed as 64 x u16 (1024 bits total, 16 x 16-bit per U256)
///
/// Optimized: derives 16 coefficients per keccak (320 calls vs 4096).
/// Note: We use `[u128; 2]` to represent each uint256 (low, high).
pub fn wire_binding_hash(
    input_bits: u64,
    gate_idx: u32,
    num_wires: u8,
    circuit_seed: [u8; 32],
) -> BindingOutput {
    let mut output = BindingOutput::default();

    for row in 0..BINDING_ROWS {
        // rowSeed = keccak256(seed, gateIdx, row)
        // Solidity packs: seed (32 bytes) + gateIdx (32 bytes) + row (32 bytes)
        let mut hasher = Keccak256::new();
        hasher.update(&circuit_seed);
        
        let mut gate_bytes = [0u8; 32];
        gate_bytes[28..32].copy_from_slice(&gate_idx.to_be_bytes());
        hasher.update(&gate_bytes);
        
        let mut row_bytes = [0u8; 32];
        row_bytes[28..32].copy_from_slice(&(row as u32).to_be_bytes());
        hasher.update(&row_bytes);
        
        let row_seed: [u8; 32] = hasher.finalize().into();

        let mut sum: u32 = 0;
        let mut col: u32 = 0;
        let mut block_idx: u32 = 0;
        
        // Process coefficients in blocks of 16 (each keccak gives 16 x u16)
        while col < (num_wires as u32) {
            // blockDigest = keccak256(rowSeed, blockIdx)
            let mut block_hasher = Keccak256::new();
            block_hasher.update(&row_seed);
            
            let mut block_bytes = [0u8; 32];
            block_bytes[28..32].copy_from_slice(&block_idx.to_be_bytes());
            block_hasher.update(&block_bytes);
            
            let block_digest: [u8; 32] = block_hasher.finalize().into();
            
            // Extract up to 16 coefficients from this block
            // Solidity treats keccak output as uint256 (big-endian bytes -> single 256-bit int)
            // shr(k*16, blockDigest) extracts the k-th u16 starting from low bits
            // bytes[0..16] = high 128 bits, bytes[16..32] = low 128 bits
            let low_u128 = u128::from_be_bytes(block_digest[16..32].try_into().unwrap());
            let high_u128 = u128::from_be_bytes(block_digest[0..16].try_into().unwrap());
            
            for k in 0..16u32 {
                if col >= (num_wires as u32) {
                    break;
                }
                
                // Extract u16 at position k (from the 256-bit value)
                // k=0..7 are in low_u128, k=8..15 are in high_u128
                let shift = (k % 8) * 16;
                let aij = if k < 8 {
                    ((low_u128 >> shift) & 0xFFFF) % (Q as u128)
                } else {
                    ((high_u128 >> shift) & 0xFFFF) % (Q as u128)
                };
                let aij = aij as u32;
                
                let bit_val = ((input_bits >> col) & 1) as u32;
                
                if bit_val == 1 {
                    sum += aij;
                    if sum >= Q {
                        sum -= Q;
                    }
                }
                
                col += 1;
            }
            
            block_idx += 1;
        }

        // Pack into output: 16 elements per uint256 (16 * 16 bits = 256 bits)
        // Each uint256 is stored as [low_u128, high_u128]
        let word_idx = row / 16;
        let elem_in_word = row % 16;
        let bit_pos = elem_in_word * 16;
        
        if bit_pos < 128 {
            output.words[word_idx].0 |= (sum as u128) << bit_pos;
        } else {
            output.words[word_idx].1 |= (sum as u128) << (bit_pos - 128);
        }
    }

    output
}

/// Represents 4 x uint256 (each as low/high u128 pair)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BindingOutput {
    pub words: [(u128, u128); 4],
}

impl BindingOutput {
    pub fn is_nonzero(&self) -> bool {
        self.words.iter().any(|(lo, hi)| *lo != 0 || *hi != 0)
    }
    
    pub fn xor_all(&self) -> u128 {
        let mut result = 0u128;
        for (lo, hi) in &self.words {
            result ^= lo ^ hi;
        }
        result
    }
}



/// Initialize wire binding accumulator with initial wire state
/// Mirrors: bindingAcc = _wireBindingHash(wires, 0)
pub fn wire_binding_init(
    wires: u64,
    num_wires: u8,
    circuit_seed: [u8; 32],
) -> BindingOutput {
    wire_binding_hash(wires, 0, num_wires, circuit_seed)
}

/// Update wire binding accumulator after a batch of gates
/// Mirrors Solidity: `combined = bindingAcc[0] ^ bindingAcc[1] ^ bindingAcc[2] ^ bindingAcc[3] ^ wires`
///                   bindingAcc = _wireBindingHash(combined, batchEnd)
pub fn wire_binding_update(
    acc: BindingOutput,
    batch_end: u32,
    wires: u64,
    num_wires: u8,
    circuit_seed: [u8; 32],
) -> BindingOutput {
    // XOR all uint256 words together, then XOR with wires
    let combined = acc.xor_all() ^ (wires as u128);
    // Use only the low 64 bits for the next hash input
    wire_binding_hash(combined as u64, batch_end, num_wires, circuit_seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_binding_init_deterministic() {
        let seed = [0x42u8; 32];
        let wires = 0x123456789ABCDEFu64;
        let h1 = wire_binding_init(wires, 64, seed);
        let h2 = wire_binding_init(wires, 64, seed);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_wire_binding_update_deterministic() {
        let seed = [0x55u8; 32];
        let acc = wire_binding_init(0x1234567890ABCDEFu64, 64, seed);
        let wires = 0xDEADBEEFCAFEBABEu64;
        let h1 = wire_binding_update(acc, 64, wires, 64, seed);
        let h2 = wire_binding_update(acc, 64, wires, 64, seed);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_wire_binding_chain() {
        let seed = [0x01u8; 32];
        let initial_wires = 0xFFFFu64;
        let acc = wire_binding_init(initial_wires, 64, seed);
        let acc = wire_binding_update(acc, 64, 0x1234, 64, seed);
        let acc = wire_binding_update(acc, 128, 0x5678, 64, seed);
        assert!(acc.is_nonzero());
    }

    #[test]
    fn test_wire_binding_hash_output_is_1024_bits() {
        let seed = [0xABu8; 32];
        let wires = 0xFFFFFFFFFFFFFFFFu64;
        let h = wire_binding_hash(wires, 0, 64, seed);
        // Result should have content across the 4 uint256 words (64 x 16-bit values)
        assert!(h.is_nonzero());
    }
}
