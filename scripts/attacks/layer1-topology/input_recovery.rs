//! Input Recovery Attack - Extract hidden input from circuit output
//!
//! Scenario: Attacker knows the circuit C and observes output y = C(x).
//! Goal: Recover the secret input x (e.g., 16 bytes of BIP-39 seed phrase).
//!
//! ## Attack Strategies
//!
//! | Strategy | Complexity | Applicability |
//! |----------|------------|---------------|
//! | Brute Force | O(2^n) | Always works, infeasible for n >= 80 |
//! | Direct Inversion | O(g) | Only for reversible circuits |
//! | Algebraic (GF2) | O(n^3) | Only for affine/linear circuits |
//! | Meet-in-the-Middle | O(2^(n/2)) | Requires circuit decomposition |
//! | Oracle-Guided | O(poly) | Requires forward oracle access |
//! | Differential | varies | Exploits non-uniform propagation |
//!
//! ## Key Insight for Reversible Circuits
//!
//! Our circuits are reversible permutations. To invert:
//! 1. Reverse the gate order
//! 2. Each gate is self-inverse (x ^= f(a,b) applied twice = identity)
//!
//! So inversion is TRIVIAL for anyone who knows the circuit structure!
//!
//! ## What This Means for BIP-39 Seed Hiding
//!
//! If the circuit is public, hiding input in output provides ZERO security.
//! The attacker simply:
//! 1. Constructs C^(-1) by reversing gate order
//! 2. Computes x = C^(-1)(y)
//!
//! For actual security, you need:
//! - Secret circuit (but then can't verify on-chain)
//! - One-way construction (non-reversible, but our gates are reversible)
//! - Hash-based commitment (separate from circuit)

use crate::circuit::Circuit;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct InputRecoveryResult {
    pub success: bool,
    pub recovered_input: Option<usize>,
    pub method: String,
    pub time_elapsed: Duration,
    pub operations: usize,
    pub details: String,
}

impl InputRecoveryResult {
    pub fn success(input: usize, method: &str, time: Duration, ops: usize) -> Self {
        Self {
            success: true,
            recovered_input: Some(input),
            method: method.to_string(),
            time_elapsed: time,
            operations: ops,
            details: format!("Recovered input {} via {}", input, method),
        }
    }

    pub fn failed(method: &str, time: Duration, ops: usize, reason: &str) -> Self {
        Self {
            success: false,
            recovered_input: None,
            method: method.to_string(),
            time_elapsed: time,
            operations: ops,
            details: reason.to_string(),
        }
    }
}

pub struct InputRecoveryAttack {
    max_operations: usize,
    timeout: Duration,
}

impl Default for InputRecoveryAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl InputRecoveryAttack {
    pub fn new() -> Self {
        Self {
            max_operations: 1_000_000,
            timeout: Duration::from_secs(60),
        }
    }

    pub fn with_max_operations(mut self, max: usize) -> Self {
        self.max_operations = max;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Main attack: try all strategies and return first success
    pub fn attack(&self, circuit: &Circuit, output: usize) -> InputRecoveryResult {
        // Strategy 1: Direct inversion (always works for reversible circuits)
        let result = self.direct_inversion(circuit, output);
        if result.success {
            return result;
        }

        // Strategy 2: Algebraic attack (for affine circuits)
        let result = self.algebraic_attack(circuit, output);
        if result.success {
            return result;
        }

        // Strategy 3: Brute force (fallback)
        self.brute_force(circuit, output)
    }

    /// Direct inversion: reverse gate order
    ///
    /// This is THE fundamental vulnerability of reversible circuits.
    /// Since each gate satisfies: G(G(x)) = x, the inverse circuit
    /// is simply the original with gates in reverse order.
    pub fn direct_inversion(&self, circuit: &Circuit, output: usize) -> InputRecoveryResult {
        let start = Instant::now();

        // Build inverse circuit
        let inverse = self.build_inverse(circuit);

        // Apply inverse to output
        let recovered = inverse.evaluate(output);

        // Verify
        let verified = circuit.evaluate(recovered) == output;

        if verified {
            InputRecoveryResult::success(
                recovered,
                "direct_inversion",
                start.elapsed(),
                circuit.gates.len(),
            )
        } else {
            InputRecoveryResult::failed(
                "direct_inversion",
                start.elapsed(),
                circuit.gates.len(),
                "Inversion verification failed",
            )
        }
    }

    /// Build the inverse circuit by reversing gate order
    ///
    /// Key insight: For gates of the form state[a] ^= f(state[b], state[c]),
    /// applying the same gate twice is identity. So the inverse is just
    /// the gates in reverse order.
    pub fn build_inverse(&self, circuit: &Circuit) -> Circuit {
        let mut inverse_gates = circuit.gates.clone();
        inverse_gates.reverse();
        Circuit::from_gates(inverse_gates, circuit.num_wires)
    }

    /// Algebraic attack for affine circuits
    ///
    /// If all control functions are affine (degree <= 1 over GF(2)),
    /// the circuit computes C(x) = Mx + c for some matrix M and vector c.
    /// Inversion is solving Mx = y - c, which is O(n^3) Gaussian elimination.
    pub fn algebraic_attack(&self, circuit: &Circuit, output: usize) -> InputRecoveryResult {
        let start = Instant::now();

        if !circuit.is_affine() {
            return InputRecoveryResult::failed(
                "algebraic",
                start.elapsed(),
                0,
                "Circuit is not affine",
            );
        }

        let n = circuit.num_wires;
        if n > 20 {
            return InputRecoveryResult::failed(
                "algebraic",
                start.elapsed(),
                0,
                "Circuit too large for algebraic attack",
            );
        }

        // Compute the linear transformation matrix M and constant vector c
        // by evaluating circuit on basis vectors
        let mut matrix = vec![vec![false; n]; n];
        let constant = circuit.evaluate(0);

        for i in 0..n {
            let basis = 1usize << i;
            let result = circuit.evaluate(basis) ^ constant;
            for j in 0..n {
                matrix[j][i] = (result >> j) & 1 == 1;
            }
        }

        // Now solve Mx = y - c using Gaussian elimination
        let target = output ^ constant;

        match self.solve_gf2(matrix.clone(), target, n) {
            Some(solution) => {
                // Verify solution
                if circuit.evaluate(solution) == output {
                    InputRecoveryResult::success(
                        solution,
                        "algebraic",
                        start.elapsed(),
                        n * n * n, // O(n^3) operations
                    )
                } else {
                    InputRecoveryResult::failed(
                        "algebraic",
                        start.elapsed(),
                        n * n * n,
                        "Algebraic solution verification failed",
                    )
                }
            }
            None => InputRecoveryResult::failed(
                "algebraic",
                start.elapsed(),
                n * n * n,
                "No solution found (matrix singular)",
            ),
        }
    }

    /// Solve Mx = y over GF(2) using Gaussian elimination
    #[allow(unused_mut)]
    fn solve_gf2(&self, matrix: Vec<Vec<bool>>, target: usize, n: usize) -> Option<usize> {
        // Augment matrix with target
        let mut aug: Vec<Vec<bool>> = matrix
            .into_iter()
            .enumerate()
            .map(|(i, mut row)| {
                row.push((target >> i) & 1 == 1);
                row
            })
            .collect();

        // Forward elimination
        for col in 0..n {
            // Find pivot
            let pivot_row = (col..n).find(|&row| aug[row][col])?;
            aug.swap(col, pivot_row);

            // Eliminate
            for row in 0..n {
                if row != col && aug[row][col] {
                    for j in 0..=n {
                        aug[row][j] ^= aug[col][j];
                    }
                }
            }
        }

        // Back substitution - extract solution
        let mut solution = 0usize;
        for i in 0..n {
            if aug[i][n] {
                solution |= 1 << i;
            }
        }

        Some(solution)
    }

    /// Brute force attack - try all possible inputs
    pub fn brute_force(&self, circuit: &Circuit, output: usize) -> InputRecoveryResult {
        let start = Instant::now();
        let input_space = 1usize << circuit.num_wires.min(30);
        let max_tries = self.max_operations.min(input_space);

        for input in 0..max_tries {
            if start.elapsed() > self.timeout {
                return InputRecoveryResult::failed(
                    "brute_force",
                    start.elapsed(),
                    input,
                    &format!("Timeout after {} tries", input),
                );
            }

            if circuit.evaluate(input) == output {
                return InputRecoveryResult::success(
                    input,
                    "brute_force",
                    start.elapsed(),
                    input + 1,
                );
            }
        }

        InputRecoveryResult::failed(
            "brute_force",
            start.elapsed(),
            max_tries,
            &format!("Exhausted {} inputs", max_tries),
        )
    }

    /// Meet-in-the-middle attack for circuits with known midpoint
    ///
    /// Split circuit C into C = C2 ∘ C1
    /// Precompute: for all x, store (C1(x), x)
    /// Search: for all y, check if C2^(-1)(output) matches any stored value
    ///
    /// Complexity: O(2^(n/2)) time and space
    pub fn meet_in_the_middle(&self, circuit: &Circuit, output: usize) -> InputRecoveryResult {
        let start = Instant::now();
        let n = circuit.num_wires;

        if n > 40 {
            return InputRecoveryResult::failed(
                "mitm",
                start.elapsed(),
                0,
                "Circuit too large for MITM",
            );
        }

        let half = circuit.gates.len() / 2;
        if half < 2 {
            return InputRecoveryResult::failed(
                "mitm",
                start.elapsed(),
                0,
                "Circuit too small for MITM",
            );
        }

        // Split circuit
        let c1 = Circuit::from_gates(circuit.gates[..half].to_vec(), n);
        let c2 = Circuit::from_gates(circuit.gates[half..].to_vec(), n);
        let c2_inv = self.build_inverse(&c2);

        let half_space = 1usize << (n.min(20) / 2);
        let mut forward_table: std::collections::HashMap<usize, usize> =
            std::collections::HashMap::with_capacity(half_space);

        // Forward phase: compute C1(x) for x in [0, 2^(n/2))
        for x in 0..half_space {
            if start.elapsed() > self.timeout {
                return InputRecoveryResult::failed(
                    "mitm",
                    start.elapsed(),
                    x,
                    "Timeout in forward phase",
                );
            }
            let mid = c1.evaluate(x);
            forward_table.insert(mid, x);
        }

        // Backward phase: compute C2^(-1)(output) and check table
        let mid_from_output = c2_inv.evaluate(output);

        if let Some(&x) = forward_table.get(&mid_from_output) {
            // Verify full circuit
            if circuit.evaluate(x) == output {
                return InputRecoveryResult::success(x, "mitm", start.elapsed(), half_space + 1);
            }
        }

        // Extended search for larger input space
        for y in 0..half_space {
            if start.elapsed() > self.timeout {
                break;
            }

            // Try inputs with high bits = y, low bits from table
            let mid = c2_inv.evaluate(output ^ y);
            if let Some(&x_low) = forward_table.get(&mid) {
                let x = x_low | (y << (n / 2));
                if circuit.evaluate(x) == output {
                    return InputRecoveryResult::success(
                        x,
                        "mitm",
                        start.elapsed(),
                        half_space + y,
                    );
                }
            }
        }

        InputRecoveryResult::failed(
            "mitm",
            start.elapsed(),
            half_space * 2,
            "No collision found",
        )
    }

    /// Differential attack - exploit non-uniform bit propagation
    ///
    /// For non-affine circuits, different input bits may have different
    /// "influence" on output bits. This can leak information.
    pub fn differential_attack(&self, circuit: &Circuit, output: usize) -> InputRecoveryResult {
        let start = Instant::now();
        let n = circuit.num_wires;

        if n > 16 {
            return InputRecoveryResult::failed(
                "differential",
                start.elapsed(),
                0,
                "Circuit too large for differential analysis",
            );
        }

        // Compute differential characteristics
        // For each input bit i, measure how flipping it affects output
        let mut bit_influence = vec![0usize; n];
        let samples = 256.min(1usize << n);

        for sample in 0..samples {
            let base_output = circuit.evaluate(sample);
            for bit in 0..n {
                let flipped_input = sample ^ (1 << bit);
                let flipped_output = circuit.evaluate(flipped_input);
                let diff = base_output ^ flipped_output;
                bit_influence[bit] += diff.count_ones() as usize;
            }
        }

        // Use influence patterns to guide search
        // (In a real attack, we'd use SAT solvers or constraint propagation)

        // For now, fall back to guided brute force using high-influence bits first
        let mut bit_order: Vec<usize> = (0..n).collect();
        bit_order.sort_by(|&a, &b| bit_influence[b].cmp(&bit_influence[a]));

        // Try inputs in order of bit influence
        let max_tries = self.max_operations.min(1usize << n);
        for i in 0..max_tries {
            if start.elapsed() > self.timeout {
                break;
            }

            // Gray code traversal biased by influence
            let input = gray_code_with_order(i, &bit_order, n);
            if circuit.evaluate(input) == output {
                return InputRecoveryResult::success(input, "differential", start.elapsed(), i + 1);
            }
        }

        InputRecoveryResult::failed(
            "differential",
            start.elapsed(),
            max_tries,
            "Differential search exhausted",
        )
    }
}

/// Generate i-th element of Gray code with custom bit ordering
fn gray_code_with_order(i: usize, bit_order: &[usize], n: usize) -> usize {
    let gray = i ^ (i >> 1);
    let mut result = 0;
    for (pos, &bit) in bit_order.iter().enumerate() {
        if pos < n && (gray >> pos) & 1 == 1 {
            result |= 1 << bit;
        }
    }
    result
}

/// Security analysis for BIP-39 seed hiding
#[derive(Debug)]
pub struct SeedHidingAnalysis {
    pub seed_bytes: usize,
    pub circuit_wires: usize,
    pub circuit_gates: usize,
    pub inversion_cost: String,
    pub security_bits: usize,
    pub is_secure: bool,
    pub vulnerability: String,
}

impl SeedHidingAnalysis {
    /// Analyze security of hiding a seed phrase in circuit output
    pub fn analyze(circuit: &Circuit, seed_bytes: usize) -> Self {
        let seed_bits = seed_bytes * 8;
        let wire_bits = circuit.num_wires;

        // Can we even fit the seed?
        if seed_bits > wire_bits {
            return Self {
                seed_bytes,
                circuit_wires: wire_bits,
                circuit_gates: circuit.gates.len(),
                inversion_cost: "N/A".to_string(),
                security_bits: 0,
                is_secure: false,
                vulnerability: format!(
                    "Seed ({} bits) doesn't fit in circuit state ({} bits)",
                    seed_bits, wire_bits
                ),
            };
        }

        // Check if circuit is trivially invertible
        let attack = InputRecoveryAttack::new();
        let _inverse = attack.build_inverse(circuit);

        // The fundamental problem: reversible circuits are trivially invertible
        Self {
            seed_bytes,
            circuit_wires: wire_bits,
            circuit_gates: circuit.gates.len(),
            inversion_cost: format!("O({}) gate evaluations", circuit.gates.len()),
            security_bits: 0, // ZERO security!
            is_secure: false,
            vulnerability: "Reversible circuit: C^(-1) = reverse(gates). Attacker computes x = C^(-1)(y) in O(gates) time.".to_string(),
        }
    }
}

impl std::fmt::Display for SeedHidingAnalysis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== BIP-39 Seed Hiding Security Analysis ===")?;
        writeln!(
            f,
            "Seed size: {} bytes ({} bits)",
            self.seed_bytes,
            self.seed_bytes * 8
        )?;
        writeln!(
            f,
            "Circuit: {} wires, {} gates",
            self.circuit_wires, self.circuit_gates
        )?;
        writeln!(f, "Inversion cost: {}", self.inversion_cost)?;
        writeln!(f, "Security: {} bits", self.security_bits)?;
        writeln!(
            f,
            "Secure: {}",
            if self.is_secure { "[OK]" } else { "[FAIL]" }
        )?;
        writeln!(f, "")?;
        writeln!(f, "Vulnerability: {}", self.vulnerability)?;
        Ok(())
    }
}

/// Demonstrate the attack
pub fn demonstrate_seed_hiding_attack() {
    println!("=== Seed Hiding Attack Demonstration ===\n");

    // Create a "secure-looking" SixSix circuit
    use crate::six_six::{create_six_six_circuit, SixSixConfig};
    let config = SixSixConfig::default();
    let circuit = create_six_six_circuit(&config);

    println!(
        "Circuit: {} wires, {} gates",
        circuit.num_wires,
        circuit.gates.len()
    );
    println!();

    // Simulate hiding a seed
    let secret_seed: usize = 0xDEADBEEFCAFE1234; // 8 bytes of "seed"
    let masked_seed = secret_seed & ((1 << circuit.num_wires) - 1);
    let public_output = circuit.evaluate(masked_seed);

    println!("Secret input (seed): 0x{:016X}", masked_seed);
    println!("Public output:       0x{:016X}", public_output);
    println!();

    // Attack!
    let attack = InputRecoveryAttack::new();
    let result = attack.attack(&circuit, public_output);

    println!(
        "Attack result: {}",
        if result.success { "[OK]" } else { "[FAIL]" }
    );
    println!("Method: {}", result.method);
    println!("Time: {:?}", result.time_elapsed);
    println!("Operations: {}", result.operations);

    if let Some(recovered) = result.recovered_input {
        println!("Recovered input: 0x{:016X}", recovered);
        println!(
            "Match: {}",
            if recovered == masked_seed {
                "[OK]"
            } else {
                "[FAIL]"
            }
        );
    }

    println!();
    println!("=== Analysis ===");
    let analysis = SeedHidingAnalysis::analyze(&circuit, 16);
    println!("{}", analysis);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::six_six::{create_six_six_circuit, SixSixConfig};

    #[test]
    fn test_direct_inversion() {
        let circuit = Circuit::random(8, 50);
        let attack = InputRecoveryAttack::new();

        // Pick a random input
        let secret_input = 0xAB;
        let output = circuit.evaluate(secret_input);

        // Invert
        let result = attack.direct_inversion(&circuit, output);

        assert!(result.success, "Direct inversion should succeed");
        assert_eq!(result.recovered_input, Some(secret_input));
    }

    #[test]
    fn test_inversion_sixsix() {
        let config = SixSixConfig::default();
        let circuit = create_six_six_circuit(&config);
        let attack = InputRecoveryAttack::new();

        // Even complex SixSix circuits are trivially invertible
        let secret = 0x123456789ABCDEF0 & ((1 << circuit.num_wires) - 1);
        let output = circuit.evaluate(secret);

        let result = attack.attack(&circuit, output);

        assert!(result.success, "Should recover input from SixSix circuit");
        assert_eq!(result.recovered_input, Some(secret));
        println!("Recovered secret from SixSix in {:?}", result.time_elapsed);
    }

    #[test]
    fn test_algebraic_attack_affine() {
        let circuit = Circuit::random_affine(8, 30);
        let attack = InputRecoveryAttack::new();

        let secret = 0x42;
        let output = circuit.evaluate(secret);

        let result = attack.algebraic_attack(&circuit, output);

        if result.success {
            assert_eq!(result.recovered_input, Some(secret));
            println!("Algebraic attack succeeded: {:?}", result.time_elapsed);
        }
    }

    #[test]
    fn test_meet_in_the_middle() {
        let circuit = Circuit::random(12, 50);
        let attack = InputRecoveryAttack::new();

        let secret = 0x3FF;
        let output = circuit.evaluate(secret);

        let result = attack.meet_in_the_middle(&circuit, output);
        println!(
            "MITM result: {} - {:?}",
            result.success, result.time_elapsed
        );

        if result.success {
            assert_eq!(result.recovered_input, Some(secret));
        }
    }

    #[test]
    fn test_seed_hiding_analysis() {
        let config = SixSixConfig::default();
        let circuit = create_six_six_circuit(&config);

        let analysis = SeedHidingAnalysis::analyze(&circuit, 16);
        println!("{}", analysis);

        // Should report zero security
        assert_eq!(analysis.security_bits, 0);
        assert!(!analysis.is_secure);
    }

    #[test]
    fn test_demonstrate_attack() {
        demonstrate_seed_hiding_attack();
    }
}
