//! Local Mixing Attacks from Canetti et al. 2024
//!
//! Implements attack strategies from "Towards general-purpose program obfuscation
//! via local mixing" (ePrint 2024/006).
//!
//! ## Key Attacks
//!
//! 1. **ComplexityGap**: Measures the "complexity gap" CC(C) - the difference between
//!    actual circuit size and minimum equivalent circuit size. Well-mixed circuits
//!    should have large complexity gaps that are spread across neighborhoods.
//!
//! 2. **LocalReversibility**: Attempts to reverse the mixing by finding neighborhoods
//!    with detectable complexity gaps and shrinking them. This is the main attack
//!    the paper describes against naive local mixing.
//!
//! 3. **SubcircuitPseudorandomness**: Tests if subcircuits compute pseudorandom
//!    permutations. Based on Gowers conjecture that random reversible circuits
//!    of sufficient length are pseudorandom.
//!
//! 4. **SkeletonGraph**: Analyzes the skeleton graph structure to find convex
//!    neighborhoods amenable to attacks.
//!
//! ## Theoretical Background
//!
//! From the paper:
//! - "Local mixing = locally thermalizing a circuit while preserving functionality"
//! - Security relies on: pseudorandomness of random reversible circuits
//! - Attack: "search for neighborhoods with complexity gap, shrink them"
//! - Defense: "kneading stage" spreads complexity gap over larger neighborhoods

use crate::attacks::suite::AttackResult;
use crate::circuit::{Circuit, Gate};
use crate::control_function::ControlFunction;
use std::collections::{HashMap, HashSet};

/// Complexity Gap Attack
///
/// Measures the "reducibility" of a circuit - how much it can be shrunk
/// while preserving functionality. Well-obfuscated circuits should have
/// large irreducible cores.
///
/// From Canetti et al.: "CC(C) = minimum size of circuit equivalent to C"
/// Complexity gap = |C| - CC(C)
pub struct ComplexityGapAttack {
    /// Maximum subcircuit size to analyze
    pub max_subcircuit_size: usize,
    /// Number of random subcircuits to sample
    pub num_samples: usize,
}

impl Default for ComplexityGapAttack {
    fn default() -> Self {
        Self {
            max_subcircuit_size: 8,
            num_samples: 50,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ComplexityGapResult {
    /// Average complexity gap across sampled subcircuits
    pub avg_gap: f64,
    /// Maximum gap found in any subcircuit
    pub max_gap: usize,
    /// Fraction of subcircuits with gap > 0
    pub reducible_fraction: f64,
    /// Subcircuit sizes and their gaps
    pub gap_distribution: Vec<(usize, usize)>,
}

impl ComplexityGapAttack {
    pub fn new(max_subcircuit_size: usize, num_samples: usize) -> Self {
        Self {
            max_subcircuit_size,
            num_samples,
        }
    }

    /// Run the complexity gap attack
    pub fn run(&self, circuit: &Circuit) -> AttackResult {
        if circuit.gates.len() < 4 {
            return AttackResult::failed("Circuit too small for complexity gap analysis");
        }

        let result = self.analyze(circuit);

        let success = result.reducible_fraction > 0.1 || result.max_gap > 2;
        let confidence = result.reducible_fraction;
        let details = format!(
            "Avg gap: {:.2}, max gap: {}, reducible: {:.1}%",
            result.avg_gap,
            result.max_gap,
            result.reducible_fraction * 100.0
        );

        AttackResult::new(success, confidence, details)
    }

    /// Detailed analysis of complexity gaps
    pub fn analyze(&self, circuit: &Circuit) -> ComplexityGapResult {
        let mut gaps = Vec::new();
        let mut reducible_count = 0;

        for size in 2..=self.max_subcircuit_size.min(circuit.gates.len()) {
            let samples = self.num_samples.min(circuit.gates.len() - size + 1);

            for i in 0..samples {
                let start = (i * (circuit.gates.len() - size + 1)) / samples.max(1);
                let subcircuit = Circuit::from_gates(
                    circuit.gates[start..start + size].to_vec(),
                    circuit.num_wires,
                );

                let min_size = self.estimate_minimum_size(&subcircuit);
                let gap = size.saturating_sub(min_size);

                gaps.push((size, gap));
                if gap > 0 {
                    reducible_count += 1;
                }
            }
        }

        let avg_gap = if gaps.is_empty() {
            0.0
        } else {
            gaps.iter().map(|(_, g)| *g as f64).sum::<f64>() / gaps.len() as f64
        };

        let max_gap = gaps.iter().map(|(_, g)| *g).max().unwrap_or(0);
        let reducible_fraction = if gaps.is_empty() {
            0.0
        } else {
            reducible_count as f64 / gaps.len() as f64
        };

        ComplexityGapResult {
            avg_gap,
            max_gap,
            reducible_fraction,
            gap_distribution: gaps,
        }
    }

    /// Estimate minimum equivalent circuit size
    ///
    /// For small circuits, we can try to find smaller equivalents.
    /// This is related to MCSP (Minimum Circuit Size Problem).
    fn estimate_minimum_size(&self, subcircuit: &Circuit) -> usize {
        if subcircuit.gates.is_empty() {
            return 0;
        }

        // Check for identity (can be removed entirely)
        if self.is_identity(subcircuit) {
            return 0;
        }

        // Check for adjacent cancellations
        let mut compressed = subcircuit.clone();
        let mut i = 0;
        while i < compressed.gates.len().saturating_sub(1) {
            if compressed.gates[i].equals(&compressed.gates[i + 1]) {
                compressed.gates.drain(i..=i + 1);
                i = i.saturating_sub(1);
            } else {
                i += 1;
            }
        }

        // For very small circuits, try enumeration
        if subcircuit.gates.len() <= 4 && subcircuit.num_wires <= 6 {
            if let Some(smaller) = self.find_smaller_equivalent(subcircuit) {
                return smaller;
            }
        }

        compressed.gates.len()
    }

    /// Check if subcircuit computes identity
    fn is_identity(&self, circuit: &Circuit) -> bool {
        let num_inputs = 16.min(1 << circuit.num_wires.min(8));
        for i in 0..num_inputs {
            if circuit.evaluate(i) != i {
                return false;
            }
        }
        true
    }

    /// Try to find a smaller equivalent circuit by enumeration
    fn find_smaller_equivalent(&self, circuit: &Circuit) -> Option<usize> {
        let target_size = circuit.gates.len().saturating_sub(1);
        if target_size == 0 {
            return if self.is_identity(circuit) {
                Some(0)
            } else {
                None
            };
        }

        // Sample some smaller circuits and check equivalence
        let num_trials = 100;
        let nontrivial_cfs: Vec<ControlFunction> = (0..16)
            .map(ControlFunction::from_u8)
            .filter(|cf| {
                !matches!(
                    cf,
                    ControlFunction::F
                        | ControlFunction::A
                        | ControlFunction::B
                        | ControlFunction::T
                )
            })
            .collect();

        use rand::Rng;
        let mut rng = rand::thread_rng();

        for size in (1..target_size).rev() {
            for _ in 0..num_trials {
                let gates: Vec<Gate> = (0..size)
                    .map(|_| {
                        let a = rng.gen_range(0..circuit.num_wires) as u8;
                        let c1 = rng.gen_range(0..circuit.num_wires) as u8;
                        let c2 = rng.gen_range(0..circuit.num_wires) as u8;
                        let cf = nontrivial_cfs[rng.gen_range(0..nontrivial_cfs.len())];
                        Gate::new(a, c1, c2, cf)
                    })
                    .collect();

                let candidate = Circuit::from_gates(gates, circuit.num_wires);
                if self.circuits_equivalent(circuit, &candidate) {
                    return Some(size);
                }
            }
        }

        None
    }

    fn circuits_equivalent(&self, a: &Circuit, b: &Circuit) -> bool {
        let num_inputs = 16.min(1 << a.num_wires.min(8));
        for i in 0..num_inputs {
            if a.evaluate(i) != b.evaluate(i) {
                return false;
            }
        }
        true
    }
}

/// Local Reversibility Attack
///
/// Attempts to reverse the mixing process by:
/// 1. Finding neighborhoods with detectable complexity gaps
/// 2. Replacing them with minimal equivalents
/// 3. Repeating until no more reductions possible
///
/// From Canetti et al.: "Given a mixed circuit C, search for neighborhoods
/// C' of ℓ^in vertices such that CC(C') ≤ ℓ^out. Once found, replace with
/// shortest functionally equivalent C''."
pub struct LocalReversibilityAttack {
    /// Maximum neighborhood size to search
    pub max_neighborhood: usize,
    /// Maximum iterations of shrinking
    pub max_iterations: usize,
}

impl Default for LocalReversibilityAttack {
    fn default() -> Self {
        Self {
            max_neighborhood: 6,
            max_iterations: 100,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalReversibilityResult {
    /// Original circuit size
    pub original_size: usize,
    /// Final size after shrinking
    pub final_size: usize,
    /// Number of reductions performed
    pub num_reductions: usize,
    /// Reduction ratio (1.0 = fully reduced to identity)
    pub reduction_ratio: f64,
}

impl LocalReversibilityAttack {
    pub fn new(max_neighborhood: usize, max_iterations: usize) -> Self {
        Self {
            max_neighborhood,
            max_iterations,
        }
    }

    pub fn run(&self, circuit: &Circuit) -> AttackResult {
        let result = self.reverse(circuit);

        let success = result.reduction_ratio > 0.05;
        let confidence = result.reduction_ratio;
        let details = format!(
            "Reduced {} -> {} gates ({} reductions, {:.1}% reduction)",
            result.original_size,
            result.final_size,
            result.num_reductions,
            result.reduction_ratio * 100.0
        );

        AttackResult::new(success, confidence, details)
    }

    /// Attempt to reverse the mixing
    pub fn reverse(&self, circuit: &Circuit) -> LocalReversibilityResult {
        let original_size = circuit.gates.len();
        let mut current = circuit.clone();
        let mut num_reductions = 0;

        for _ in 0..self.max_iterations {
            let reduction = self.find_and_shrink(&current);
            match reduction {
                Some(reduced) => {
                    if reduced.gates.len() < current.gates.len() {
                        current = reduced;
                        num_reductions += 1;
                    } else {
                        break;
                    }
                }
                None => break,
            }
        }

        let final_size = current.gates.len();
        let reduction_ratio = if original_size > 0 {
            (original_size - final_size) as f64 / original_size as f64
        } else {
            0.0
        };

        LocalReversibilityResult {
            original_size,
            final_size,
            num_reductions,
            reduction_ratio,
        }
    }

    fn find_and_shrink(&self, circuit: &Circuit) -> Option<Circuit> {
        let gap_attack = ComplexityGapAttack::new(self.max_neighborhood, 20);

        for size in (2..=self.max_neighborhood.min(circuit.gates.len())).rev() {
            for start in 0..=(circuit.gates.len() - size) {
                let subcircuit = Circuit::from_gates(
                    circuit.gates[start..start + size].to_vec(),
                    circuit.num_wires,
                );

                let min_size = gap_attack.estimate_minimum_size(&subcircuit);
                if min_size < size {
                    // Found reducible neighborhood - replace with smaller
                    if let Some(replacement) = self.find_replacement(&subcircuit, min_size) {
                        let mut new_gates = circuit.gates[..start].to_vec();
                        new_gates.extend(replacement.gates);
                        new_gates.extend(circuit.gates[start + size..].iter().cloned());

                        return Some(Circuit::from_gates(new_gates, circuit.num_wires));
                    }
                }
            }
        }

        None
    }

    fn find_replacement(&self, subcircuit: &Circuit, target_size: usize) -> Option<Circuit> {
        if target_size == 0 {
            return Some(Circuit::from_gates(vec![], subcircuit.num_wires));
        }

        // For small targets, try enumeration
        let nontrivial_cfs: Vec<ControlFunction> = (0..16)
            .map(ControlFunction::from_u8)
            .filter(|cf| {
                !matches!(
                    cf,
                    ControlFunction::F
                        | ControlFunction::A
                        | ControlFunction::B
                        | ControlFunction::T
                )
            })
            .collect();

        use rand::Rng;
        let mut rng = rand::thread_rng();

        for _ in 0..200 {
            let gates: Vec<Gate> = (0..target_size)
                .map(|_| {
                    let a = rng.gen_range(0..subcircuit.num_wires) as u8;
                    let c1 = rng.gen_range(0..subcircuit.num_wires) as u8;
                    let c2 = rng.gen_range(0..subcircuit.num_wires) as u8;
                    let cf = nontrivial_cfs[rng.gen_range(0..nontrivial_cfs.len())];
                    Gate::new(a, c1, c2, cf)
                })
                .collect();

            let candidate = Circuit::from_gates(gates, subcircuit.num_wires);
            if self.circuits_equivalent(subcircuit, &candidate) {
                return Some(candidate);
            }
        }

        None
    }

    fn circuits_equivalent(&self, a: &Circuit, b: &Circuit) -> bool {
        let num_inputs = 32.min(1 << a.num_wires.min(8));
        for i in 0..num_inputs {
            if a.evaluate(i) != b.evaluate(i) {
                return false;
            }
        }
        true
    }
}

/// Subcircuit Pseudorandomness Test
///
/// Tests if subcircuits of a mixed circuit compute pseudorandom permutations.
/// Based on Gowers conjecture: random reversible circuits of sufficient length
/// are indistinguishable from random permutations.
///
/// A well-mixed circuit should have subcircuits that look random.
pub struct SubcircuitPseudorandomnessTest {
    /// Subcircuit length to test
    pub subcircuit_length: usize,
    /// Number of subcircuits to sample
    pub num_samples: usize,
}

impl Default for SubcircuitPseudorandomnessTest {
    fn default() -> Self {
        Self {
            subcircuit_length: 8,
            num_samples: 20,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PseudorandomnessResult {
    /// Average "randomness score" (0=structured, 1=random)
    pub avg_randomness: f64,
    /// Minimum randomness across samples
    pub min_randomness: f64,
    /// Fraction of subcircuits passing randomness threshold
    pub pass_fraction: f64,
}

impl SubcircuitPseudorandomnessTest {
    pub fn new(subcircuit_length: usize, num_samples: usize) -> Self {
        Self {
            subcircuit_length,
            num_samples,
        }
    }

    pub fn run(&self, circuit: &Circuit) -> AttackResult {
        let result = self.test(circuit);

        // Low randomness = attack succeeds (circuit has structure)
        let success = result.avg_randomness < 0.5;
        let confidence = 1.0 - result.avg_randomness;
        let details = format!(
            "Avg randomness: {:.2}, min: {:.2}, pass rate: {:.1}%",
            result.avg_randomness,
            result.min_randomness,
            result.pass_fraction * 100.0
        );

        AttackResult::new(success, confidence, details)
    }

    pub fn test(&self, circuit: &Circuit) -> PseudorandomnessResult {
        if circuit.gates.len() < self.subcircuit_length {
            return PseudorandomnessResult {
                avg_randomness: 0.0,
                min_randomness: 0.0,
                pass_fraction: 0.0,
            };
        }

        let mut scores = Vec::new();

        for i in 0..self
            .num_samples
            .min(circuit.gates.len() - self.subcircuit_length + 1)
        {
            let start =
                (i * (circuit.gates.len() - self.subcircuit_length + 1)) / self.num_samples.max(1);
            let subcircuit = Circuit::from_gates(
                circuit.gates[start..start + self.subcircuit_length].to_vec(),
                circuit.num_wires,
            );

            let score = self.measure_randomness(&subcircuit);
            scores.push(score);
        }

        let avg_randomness = if scores.is_empty() {
            0.0
        } else {
            scores.iter().sum::<f64>() / scores.len() as f64
        };

        let min_randomness = scores.iter().cloned().fold(1.0, f64::min);
        let pass_fraction =
            scores.iter().filter(|&&s| s > 0.7).count() as f64 / scores.len().max(1) as f64;

        PseudorandomnessResult {
            avg_randomness,
            min_randomness,
            pass_fraction,
        }
    }

    /// Measure how "random" a subcircuit's permutation appears
    fn measure_randomness(&self, circuit: &Circuit) -> f64 {
        let num_inputs = 32.min(1 << circuit.num_wires.min(8));
        let mut outputs = Vec::with_capacity(num_inputs);

        for i in 0..num_inputs {
            outputs.push(circuit.evaluate(i));
        }

        // Check several randomness properties:

        // 1. Bijectivity (should be 1-1 for reversible circuits)
        let unique_outputs: HashSet<_> = outputs.iter().collect();
        let bijectivity = unique_outputs.len() as f64 / num_inputs as f64;

        // 2. Hamming distance from identity
        let identity_distance: f64 = outputs
            .iter()
            .enumerate()
            .map(|(i, &o)| if i == o { 0.0 } else { 1.0 })
            .sum::<f64>()
            / num_inputs as f64;

        // 3. Bit mixing (output bits depend on multiple input bits)
        let bit_mixing = self.measure_bit_mixing(circuit, num_inputs);

        // 4. No simple pattern (not linear, not just bit permutation)
        let complexity = self.measure_complexity(circuit, num_inputs);

        // Combine scores
        (bijectivity * 0.2 + identity_distance * 0.3 + bit_mixing * 0.3 + complexity * 0.2)
            .clamp(0.0, 1.0)
    }

    fn measure_bit_mixing(&self, circuit: &Circuit, num_inputs: usize) -> f64 {
        let mut mixing_score = 0.0;
        let num_bits = circuit.num_wires.min(8);

        for bit in 0..num_bits {
            let mask = 1 << bit;
            let mut flips = 0;

            for i in 0..num_inputs / 2 {
                let o1 = circuit.evaluate(i);
                let o2 = circuit.evaluate(i ^ mask);
                if o1 != o2 {
                    flips += 1;
                }
            }

            // Good mixing: flipping one input bit changes multiple output bits
            mixing_score += flips as f64 / (num_inputs / 2) as f64;
        }

        mixing_score / num_bits as f64
    }

    fn measure_complexity(&self, circuit: &Circuit, num_inputs: usize) -> f64 {
        // Check if the permutation is "simple" (e.g., just XOR with constant)
        let o0 = circuit.evaluate(0);

        let mut xor_count = 0;
        for i in 1..num_inputs {
            if circuit.evaluate(i) == (i ^ o0) {
                xor_count += 1;
            }
        }

        // High xor_count = simple XOR pattern = low complexity
        1.0 - (xor_count as f64 / (num_inputs - 1) as f64)
    }
}

/// Skeleton Graph representation from Canetti et al.
///
/// The skeleton graph has gates as vertices, with edges representing
/// data dependencies (wire connections between gates).
pub struct SkeletonGraph {
    /// Adjacency list: gate_idx -> list of connected gate indices
    pub adjacency: Vec<Vec<usize>>,
    /// Gate index to active wire mapping
    pub active_wires: Vec<u8>,
}

impl SkeletonGraph {
    /// Build skeleton graph from circuit
    pub fn from_circuit(circuit: &Circuit) -> Self {
        let n = circuit.gates.len();
        let mut adjacency = vec![Vec::new(); n];
        let active_wires: Vec<u8> = circuit.gates.iter().map(|g| g.pins[0]).collect();

        // Track last gate that touched each wire
        let mut last_touch: HashMap<u8, usize> = HashMap::new();

        for (idx, gate) in circuit.gates.iter().enumerate() {
            // Connect to previous gates that touched our wires
            for &pin in &gate.pins {
                if let Some(&prev_idx) = last_touch.get(&pin) {
                    if prev_idx != idx {
                        adjacency[prev_idx].push(idx);
                        adjacency[idx].push(prev_idx);
                    }
                }
            }

            // Update last touch for active wire
            last_touch.insert(gate.pins[0], idx);
        }

        // Deduplicate adjacency lists
        for adj in &mut adjacency {
            adj.sort_unstable();
            adj.dedup();
        }

        Self {
            adjacency,
            active_wires,
        }
    }

    /// Find convex neighborhoods of given size
    ///
    /// A convex neighborhood is a set of gates where all gates on any
    /// "path" between two gates in the set are also in the set.
    pub fn find_convex_neighborhoods(&self, size: usize) -> Vec<Vec<usize>> {
        let mut neighborhoods = Vec::new();

        for start in 0..self.adjacency.len() {
            if let Some(neighborhood) = self.grow_convex_neighborhood(start, size) {
                neighborhoods.push(neighborhood);
            }
        }

        neighborhoods
    }

    fn grow_convex_neighborhood(&self, start: usize, target_size: usize) -> Option<Vec<usize>> {
        let mut neighborhood = vec![start];
        let mut candidates: HashSet<usize> = self.adjacency[start].iter().cloned().collect();

        while neighborhood.len() < target_size && !candidates.is_empty() {
            // Pick candidate that maintains convexity
            let next = *candidates.iter().next()?;
            candidates.remove(&next);

            neighborhood.push(next);

            // Add new candidates
            for &adj in &self.adjacency[next] {
                if !neighborhood.contains(&adj) {
                    candidates.insert(adj);
                }
            }
        }

        if neighborhood.len() == target_size {
            neighborhood.sort_unstable();
            Some(neighborhood)
        } else {
            None
        }
    }

    /// Analyze neighborhood connectivity
    pub fn neighborhood_stats(&self) -> NeighborhoodStats {
        if self.adjacency.is_empty() {
            return NeighborhoodStats::default();
        }

        let degrees: Vec<usize> = self.adjacency.iter().map(|adj| adj.len()).collect();
        let avg_degree = degrees.iter().sum::<usize>() as f64 / degrees.len() as f64;
        let max_degree = *degrees.iter().max().unwrap_or(&0);

        NeighborhoodStats {
            num_vertices: self.adjacency.len(),
            avg_degree,
            max_degree,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct NeighborhoodStats {
    pub num_vertices: usize,
    pub avg_degree: f64,
    pub max_degree: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::six_six::{create_six_six_circuit, SixSixConfig};

    #[test]
    fn test_complexity_gap_random() {
        let circuit = Circuit::random(8, 50);
        let attack = ComplexityGapAttack::default();
        let result = attack.run(&circuit);

        println!("ComplexityGap on random circuit: {:?}", result);
    }

    #[test]
    fn test_complexity_gap_sixsix() {
        let config = SixSixConfig::default();
        let circuit = create_six_six_circuit(&config);
        let attack = ComplexityGapAttack::new(6, 30);
        let result = attack.run(&circuit);

        println!("ComplexityGap on SixSix: {:?}", result);
        // SixSix should have low reducibility
        assert!(
            result.confidence < 0.5,
            "SixSix should be hard to reduce, got {:.2}",
            result.confidence
        );
    }

    #[test]
    fn test_local_reversibility_random() {
        let circuit = Circuit::random(8, 30);
        let attack = LocalReversibilityAttack::default();
        let result = attack.run(&circuit);

        println!("LocalReversibility on random: {:?}", result);
    }

    #[test]
    fn test_local_reversibility_identity() {
        // Identity circuit should be fully reducible
        let identity = Circuit::random_identity(6, 10);
        let attack = LocalReversibilityAttack::new(4, 50);
        let result = attack.run(&identity);

        println!("LocalReversibility on identity: {:?}", result);
        assert!(result.success, "Identity circuit should be reducible");
    }

    #[test]
    fn test_subcircuit_pseudorandomness() {
        let circuit = Circuit::random(8, 50);
        let test = SubcircuitPseudorandomnessTest::default();
        let result = test.run(&circuit);

        println!("Pseudorandomness on random: {:?}", result);
    }

    #[test]
    fn test_subcircuit_pseudorandomness_sixsix() {
        let config = SixSixConfig::default();
        let circuit = create_six_six_circuit(&config);
        let test = SubcircuitPseudorandomnessTest::new(10, 20);
        let result = test.run(&circuit);

        println!("Pseudorandomness on SixSix: {:?}", result);
        // SixSix subcircuits should look random (attack should fail)
    }

    #[test]
    fn test_skeleton_graph() {
        let circuit = Circuit::random(8, 20);
        let graph = SkeletonGraph::from_circuit(&circuit);

        let stats = graph.neighborhood_stats();
        println!("Skeleton graph stats: {:?}", stats);

        let neighborhoods = graph.find_convex_neighborhoods(4);
        println!(
            "Found {} convex neighborhoods of size 4",
            neighborhoods.len()
        );
    }

    #[test]
    fn test_all_local_mixing_attacks_on_sixsix() {
        let config = SixSixConfig::default();
        let circuit = create_six_six_circuit(&config);

        println!("\n=== Local Mixing Attacks on SixSix ===\n");

        let gap_attack = ComplexityGapAttack::new(6, 30);
        let gap_result = gap_attack.run(&circuit);
        println!(
            "ComplexityGap: success={}, conf={:.2}",
            gap_result.success, gap_result.confidence
        );

        let rev_attack = LocalReversibilityAttack::new(6, 50);
        let rev_result = rev_attack.run(&circuit);
        println!(
            "LocalReversibility: success={}, conf={:.2}",
            rev_result.success, rev_result.confidence
        );

        let pr_test = SubcircuitPseudorandomnessTest::new(10, 20);
        let pr_result = pr_test.run(&circuit);
        println!(
            "SubcircuitPseudorandomness: success={}, conf={:.2}",
            pr_result.success, pr_result.confidence
        );

        // Count how many attacks succeed
        let attacks_succeeded = [&gap_result, &rev_result, &pr_result]
            .iter()
            .filter(|r| r.success)
            .count();

        println!("\nAttacks succeeded: {}/3", attacks_succeeded);
        println!("Attacks blocked: {}/3", 3 - attacks_succeeded);

        // Note: SixSix defeats the original 6 attacks (Compression, PatternMatch, etc.)
        // but these LOCAL MIXING attacks from Canetti et al. are DIFFERENT:
        // - ComplexityGap: finds reducible subcircuits (related to RainbowTable)
        // - LocalReversibility: tries to shrink circuit (reversal attack)
        // - SubcircuitPseudorandomness: checks if subcircuits look random
        //
        // SixSix is designed for the original 6 attacks. The Canetti paper's
        // attacks require additional defenses (VDF time-locking or kneading stage).
        //
        // SubcircuitPseudorandomness should fail (SixSix subcircuits look random).
        assert!(
            !pr_result.success,
            "SixSix subcircuits should look pseudorandom"
        );
    }
}
