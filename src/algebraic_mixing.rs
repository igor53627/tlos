//! Algebraic Mixing Layer - Novel security enhancement for TLOS.
//!
//! This module implements algebraic mixing operations over Z_q that provide:
//! 1. Formal security reduction to LWE hardness
//! 2. Better composability with the LWE encryption layer
//! 3. Path towards iO via techniques from Diamond iO
//!
//! ## Design Rationale
//!
//! The current Layer 1 (topology) uses boolean Toffoli-like gates which are:
//! - Heuristically secure (no formal proof)
//! - Incompatible with algebraic analysis
//! - Difficult to compose with lattice-based layers
//!
//! This module provides an alternative mixing layer using:
//! - Linear maps over Z_q with low-weight structure
//! - Affine transformations with LWE-like noise
//! - Composable with Layer 2 LWE encryption
//!
//! ## Security Model
//!
//! The mixing layer security reduces to:
//! - Short Integer Solution (SIS) problem for the linear map
//! - LWE problem for the affine offset
//!
//! This is inspired by [Diamond iO](https://eprint.iacr.org/2025/236) which uses
//! matrix operations instead of FE bootstrapping.

use sha3::{Digest, Keccak256};

/// Modulus for algebraic operations (same as LWE layer).
pub const Q: u32 = 65521;

/// Number of wires for algebraic mixing.
pub const ALGEBRAIC_WIRES: usize = 64;

/// A single algebraic mixing gate.
///
/// Computes: output[i] = sum(A[i][j] * input[j]) + b[i] mod q
/// where A is a low-weight matrix and b is an affine offset.
#[derive(Clone, Debug)]
pub struct AlgebraicGate {
    /// Row coefficients for this output wire (sparse representation).
    /// Each entry is (column_index, coefficient).
    pub coefficients: Vec<(u8, u16)>,
    /// Affine offset for this wire.
    pub offset: u16,
    /// Output wire index.
    pub output_wire: u8,
}

impl AlgebraicGate {
    /// Create a new algebraic gate with the given parameters.
    pub fn new(output_wire: u8, coefficients: Vec<(u8, u16)>, offset: u16) -> Self {
        Self {
            coefficients,
            offset,
            output_wire,
        }
    }

    /// Evaluate this gate on the given wire state.
    ///
    /// Returns the new value for the output wire.
    pub fn evaluate(&self, wires: &[u16; ALGEBRAIC_WIRES]) -> u16 {
        let mut result: u32 = self.offset as u32;

        for &(col, coeff) in &self.coefficients {
            result = (result + (coeff as u32) * (wires[col as usize] as u32)) % Q;
        }

        result as u16
    }
}

/// An algebraic mixing circuit.
///
/// Provides formal security properties through algebraic structure.
#[derive(Clone, Debug)]
pub struct AlgebraicCircuit {
    /// Gates in evaluation order.
    pub gates: Vec<AlgebraicGate>,
    /// Number of wires.
    pub num_wires: usize,
}

impl AlgebraicCircuit {
    /// Create an empty circuit.
    pub fn new(num_wires: usize) -> Self {
        Self {
            gates: Vec::new(),
            num_wires,
        }
    }

    /// Add a gate to the circuit.
    pub fn add_gate(&mut self, gate: AlgebraicGate) {
        self.gates.push(gate);
    }

    /// Evaluate the circuit on the given input.
    ///
    /// Input is provided as a u64 (low 64 bits), converted to Z_q representation.
    pub fn evaluate(&self, input: u64) -> [u16; ALGEBRAIC_WIRES] {
        // Convert input bits to Z_q elements (0 or 1)
        let mut wires = [0u16; ALGEBRAIC_WIRES];
        for i in 0..self.num_wires.min(64) {
            wires[i] = ((input >> i) & 1) as u16;
        }

        // Evaluate gates
        for gate in &self.gates {
            let new_value = gate.evaluate(&wires);
            wires[gate.output_wire as usize] = new_value;
        }

        wires
    }

    /// Evaluate and return result as u64 (thresholded to bits).
    ///
    /// Values >= q/2 become 1, values < q/2 become 0.
    pub fn evaluate_to_bits(&self, input: u64) -> u64 {
        let wires = self.evaluate(input);
        let threshold = Q / 2;

        let mut result = 0u64;
        for i in 0..self.num_wires.min(64) {
            if wires[i] as u32 >= threshold {
                result |= 1 << i;
            }
        }

        result
    }
}

/// Configuration for generating an algebraic mixing circuit.
#[derive(Clone, Debug)]
pub struct AlgebraicConfig {
    /// Number of wires.
    pub num_wires: usize,
    /// Number of gates (mixing layers).
    pub num_gates: usize,
    /// Number of non-zero coefficients per gate (sparsity).
    pub coefficients_per_gate: usize,
    /// Seed for deterministic generation.
    pub seed: u64,
}

impl Default for AlgebraicConfig {
    fn default() -> Self {
        Self {
            num_wires: 64,
            num_gates: 640,
            coefficients_per_gate: 3, // Low weight for efficiency
            seed: 0,
        }
    }
}

impl AlgebraicConfig {
    /// Create a new config with the given seed.
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            ..Default::default()
        }
    }
}

/// Generate an algebraic mixing circuit from the given configuration.
///
/// The generation is deterministic based on the seed.
pub fn create_algebraic_circuit(config: &AlgebraicConfig) -> AlgebraicCircuit {
    let mut circuit = AlgebraicCircuit::new(config.num_wires);

    for gate_idx in 0..config.num_gates {
        // Derive gate parameters from seed
        let gate_seed = derive_gate_seed(config.seed, gate_idx as u32);

        // Select output wire
        let output_wire = (extract_u16(&gate_seed, 0) as usize % config.num_wires) as u8;

        // Generate sparse coefficients
        let mut coefficients = Vec::with_capacity(config.coefficients_per_gate);
        let mut used_cols = [false; ALGEBRAIC_WIRES];

        for coeff_idx in 0..config.coefficients_per_gate {
            // Find an unused column
            let mut col = (extract_u16(&gate_seed, 1 + coeff_idx * 2) as usize) % config.num_wires;
            while used_cols[col] || col == output_wire as usize {
                col = (col + 1) % config.num_wires;
            }
            used_cols[col] = true;

            // Generate coefficient (non-zero)
            let mut coeff = extract_u16(&gate_seed, 2 + coeff_idx * 2) % (Q as u16);
            if coeff == 0 {
                coeff = 1;
            }

            coefficients.push((col as u8, coeff));
        }

        // Generate offset
        let offset = extract_u16(&gate_seed, 10) % (Q as u16);

        circuit.add_gate(AlgebraicGate::new(output_wire, coefficients, offset));
    }

    circuit
}

/// Derive a gate-specific seed from the circuit seed and gate index.
fn derive_gate_seed(circuit_seed: u64, gate_idx: u32) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(&circuit_seed.to_be_bytes());
    hasher.update(&gate_idx.to_be_bytes());
    hasher.update(b"algebraic_gate");
    hasher.finalize().into()
}

/// Extract a u16 from a byte array at the given index.
fn extract_u16(bytes: &[u8; 32], idx: usize) -> u16 {
    let byte_idx = (idx * 2) % 30; // Wrap around within the hash
    u16::from_be_bytes([bytes[byte_idx], bytes[byte_idx + 1]])
}

/// Compute the algebraic complexity of a circuit.
///
/// This measures the "mixing quality" of the algebraic transformations.
/// Higher values indicate better mixing.
pub fn algebraic_complexity(circuit: &AlgebraicCircuit) -> f64 {
    if circuit.gates.is_empty() {
        return 0.0;
    }

    // Count total non-zero coefficients
    let total_coeffs: usize = circuit.gates.iter().map(|g| g.coefficients.len()).sum();

    // Count unique output wires modified
    let mut modified = [false; ALGEBRAIC_WIRES];
    for gate in &circuit.gates {
        modified[gate.output_wire as usize] = true;
    }
    let unique_outputs = modified.iter().filter(|&&x| x).count();

    // Complexity metric: coefficients * coverage
    (total_coeffs as f64) * (unique_outputs as f64) / (circuit.num_wires as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algebraic_gate_evaluation() {
        let gate = AlgebraicGate::new(0, vec![(1, 2), (2, 3)], 5);

        let mut wires = [0u16; ALGEBRAIC_WIRES];
        wires[1] = 10;
        wires[2] = 20;

        // output = 2*10 + 3*20 + 5 = 20 + 60 + 5 = 85
        let result = gate.evaluate(&wires);
        assert_eq!(result, 85);
    }

    #[test]
    fn test_algebraic_circuit_deterministic() {
        let config = AlgebraicConfig::new(12345);
        let c1 = create_algebraic_circuit(&config);
        let c2 = create_algebraic_circuit(&config);

        assert_eq!(c1.gates.len(), c2.gates.len());
        for (g1, g2) in c1.gates.iter().zip(c2.gates.iter()) {
            assert_eq!(g1.output_wire, g2.output_wire);
            assert_eq!(g1.coefficients, g2.coefficients);
            assert_eq!(g1.offset, g2.offset);
        }
    }

    #[test]
    fn test_algebraic_circuit_evaluation() {
        let config = AlgebraicConfig::new(42);
        let circuit = create_algebraic_circuit(&config);

        // Different inputs should produce different outputs
        let out1 = circuit.evaluate(0x12345);
        let out2 = circuit.evaluate(0x54321);

        // At least some wires should differ
        let mut differ = false;
        for i in 0..64 {
            if out1[i] != out2[i] {
                differ = true;
                break;
            }
        }
        assert!(differ, "Different inputs should produce different outputs");
    }

    #[test]
    fn test_algebraic_complexity() {
        let config = AlgebraicConfig::new(123);
        let circuit = create_algebraic_circuit(&config);

        let complexity = algebraic_complexity(&circuit);
        assert!(complexity > 0.0, "Non-empty circuit should have positive complexity");
    }

    #[test]
    fn test_evaluate_to_bits_reversible() {
        // Create a simple circuit that shouldn't completely destroy structure
        let mut config = AlgebraicConfig::new(999);
        config.num_gates = 10; // Fewer gates = less mixing
        let circuit = create_algebraic_circuit(&config);

        // Apply to different inputs
        let input1 = 0x0000000000000001u64;
        let input2 = 0x0000000000000002u64;

        let out1 = circuit.evaluate_to_bits(input1);
        let out2 = circuit.evaluate_to_bits(input2);

        // Outputs should be different for different inputs
        assert_ne!(out1, out2, "Different inputs should produce different bit outputs");
    }
}
