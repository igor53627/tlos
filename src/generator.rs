use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha3::{Digest, Keccak256};

use crate::circuit::{create_six_six_circuit, SixSixConfig};
use crate::lwe::{derive_secret, encode_gate};
use crate::wire_binding::{wire_binding_init, wire_binding_update, BindingOutput};

const BATCH_SIZE: u32 = 128;

/// All data needed to deploy a TLOS contract on-chain.
#[derive(Clone, Debug)]
pub struct TLOSDeployment {
    pub circuit_data: Vec<u8>,
    pub num_wires: u8,
    pub num_gates: u32,
    pub expected_output_hash: [u8; 32],
    pub circuit_seed: [u8; 32],
    /// Full-rank wire binding output: 64 x u16 = 1024 bits, stored as 4 x uint256
    pub expected_binding_output: BindingOutput,
}

/// Generates complete TLOS deployment data from a secret and seed.
pub fn generate_tlos(secret: [u8; 32], circuit_seed: u64) -> TLOSDeployment {
    let config = SixSixConfig::new(circuit_seed);
    let circuit = create_six_six_circuit(&config);

    let lwe_secret = derive_secret(secret);
    let mut rng = ChaCha20Rng::seed_from_u64(circuit_seed.wrapping_add(0x12345678));

    let mut circuit_data = Vec::new();
    for gate in &circuit.gates {
        let encoded = encode_gate(gate, &lwe_secret, &mut rng);
        circuit_data.extend_from_slice(&encoded);
    }

    // Convert circuit_seed u64 to bytes32 (big-endian, right-aligned)
    let mut circuit_seed_bytes = [0u8; 32];
    circuit_seed_bytes[24..32].copy_from_slice(&circuit_seed.to_be_bytes());

    let mask = if circuit.num_wires >= 64 {
        u64::MAX
    } else {
        (1u64 << circuit.num_wires) - 1
    };
    // Solidity: wires = uint256(input) & mask
    // input is bytes32, low bits are in the LAST 8 bytes (big-endian uint256)
    let initial_wires = u64::from_be_bytes(secret[24..32].try_into().unwrap()) & mask;

    let (final_wires, binding_output) =
        simulate_evaluation(&circuit, initial_wires, circuit_seed_bytes);

    // Solidity: keccak256(abi.encodePacked(wires))
    // wires is uint256, so we encode as 32-byte big-endian
    let expected_output_hash = {
        let mut hasher = Keccak256::new();
        let mut wires_bytes = [0u8; 32];
        wires_bytes[24..32].copy_from_slice(&final_wires.to_be_bytes());
        hasher.update(&wires_bytes);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    };

    TLOSDeployment {
        circuit_data,
        num_wires: circuit.num_wires as u8,
        num_gates: circuit.gates.len() as u32,
        expected_output_hash,
        circuit_seed: circuit_seed_bytes,
        expected_binding_output: binding_output,
    }
}

fn simulate_evaluation(
    circuit: &crate::circuit::Circuit,
    initial_wires: u64,
    circuit_seed: [u8; 32],
) -> (u64, BindingOutput) {
    let mut wires = initial_wires;
    let num_gates = circuit.gates.len() as u32;
    let num_wires = circuit.num_wires as u8;

    // Mirrors TLOS.sol: bindingAcc = _wireBindingHash(wires, 0)
    let mut binding_acc = wire_binding_init(wires, num_wires, circuit_seed);

    let mut batch_start = 0u32;
    while batch_start < num_gates {
        let batch_end = std::cmp::min(batch_start + BATCH_SIZE, num_gates);

        for gate_idx in batch_start..batch_end {
            let gate = &circuit.gates[gate_idx as usize];
            let c1_val = (wires >> gate.control1()) & 1 != 0;
            let c2_val = (wires >> gate.control2()) & 1 != 0;
            let tt_bit = gate.truth_table_bit(c1_val, c2_val);
            let active_bit = (wires >> gate.active()) & 1 != 0;
            let new_bit = active_bit ^ tt_bit;
            if new_bit {
                wires |= 1 << gate.active();
            } else {
                wires &= !(1 << gate.active());
            }
        }

        // Mirrors TLOS.sol: combined = bindingAcc[0..3] ^ wires; bindingAcc = _wireBindingHash(combined, batchEnd)
        binding_acc = wire_binding_update(binding_acc, batch_end, wires, num_wires, circuit_seed);
        batch_start = batch_end;
    }

    (wires, binding_acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_tlos() {
        use crate::lwe::GATE_SIZE;
        let secret = [0x42u8; 32];
        let deployment = generate_tlos(secret, 12345);
        assert_eq!(deployment.num_wires, 64);
        assert_eq!(deployment.num_gates, 640);
        assert_eq!(deployment.circuit_data.len(), 640 * GATE_SIZE);
        // Wire binding output should have content in at least one word
        assert!(deployment.expected_binding_output.is_nonzero());
    }

    #[test]
    fn test_deterministic_generation() {
        let secret = [0x55u8; 32];
        let d1 = generate_tlos(secret, 999);
        let d2 = generate_tlos(secret, 999);
        assert_eq!(d1.circuit_data, d2.circuit_data);
        assert_eq!(d1.expected_output_hash, d2.expected_output_hash);
        assert_eq!(d1.expected_binding_output, d2.expected_binding_output);
        assert_eq!(d1.circuit_seed, d2.circuit_seed);
    }

    #[test]
    fn test_binding_output_is_1024_bit() {
        let secret = [0xABu8; 32];
        let deployment = generate_tlos(secret, 42);
        // 1024-bit wire binding output: 4 x 256-bit words
        // At least one word should be non-zero
        assert!(deployment.expected_binding_output.is_nonzero());
    }
}
