//! Program Synthesis Attack (CEGIS-style)
//!
//! Implements Counter-Example Guided Inductive Synthesis (CEGIS) attacks
//! inspired by Rosette/Sketch-style program synthesis tools.
//!
//! This is a more sophisticated attack than oracle-guided learning because:
//! 1. It uses symbolic search with pruning
//! 2. It employs component-based synthesis
//! 3. It can discover structural equivalences
//!
//! Based on:
//! - Solar-Lezama, "Program Synthesis by Sketching" (PhD thesis, 2008)
//! - Torlak & Bodik, "Growing Solver-Aided Languages with Rosette" (Onward 2013)

use crate::circuit::{Circuit, Gate};
use crate::control_function::ControlFunction;
use rand::prelude::*;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Result of a program synthesis attack
#[derive(Debug, Clone)]
pub struct SynthesisResult {
    pub success: bool,
    pub synthesized_circuit: Option<Circuit>,
    pub oracle_queries: usize,
    pub candidates_explored: usize,
    pub synthesis_time: Duration,
    pub counterexamples_used: usize,
    pub final_error_rate: f64,
    pub details: String,
}

impl SynthesisResult {
    pub fn failed(queries: usize, candidates: usize, time: Duration, reason: &str) -> Self {
        Self {
            success: false,
            synthesized_circuit: None,
            oracle_queries: queries,
            candidates_explored: candidates,
            synthesis_time: time,
            counterexamples_used: 0,
            final_error_rate: 1.0,
            details: reason.to_string(),
        }
    }
}

/// Component in component-based synthesis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GateComponent {
    pub active: u8,
    pub control1: u8,
    pub control2: u8,
    pub control_func: ControlFunction,
}

impl GateComponent {
    pub fn to_gate(&self) -> Gate {
        Gate::new(self.active, self.control1, self.control2, self.control_func)
    }
}

/// Sketch: a partial program with holes
#[derive(Debug, Clone)]
pub struct CircuitSketch {
    pub num_wires: usize,
    pub num_gates: usize,
    pub fixed_gates: HashMap<usize, Gate>,
    pub hole_constraints: HashMap<usize, Vec<GateComponent>>,
}

impl CircuitSketch {
    pub fn new(num_wires: usize, num_gates: usize) -> Self {
        Self {
            num_wires,
            num_gates,
            fixed_gates: HashMap::new(),
            hole_constraints: HashMap::new(),
        }
    }

    pub fn with_gate(mut self, idx: usize, gate: Gate) -> Self {
        self.fixed_gates.insert(idx, gate);
        self
    }

    pub fn with_hole_constraint(mut self, idx: usize, candidates: Vec<GateComponent>) -> Self {
        self.hole_constraints.insert(idx, candidates);
        self
    }
}

/// CEGIS-based program synthesis attack
pub struct SynthesisAttack {
    max_queries: usize,
    max_candidates: usize,
    max_gates: usize,
    timeout: Duration,
    use_pruning: bool,
    use_observational_equivalence: bool,
    use_component_enumeration: bool,
}

impl Default for SynthesisAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl SynthesisAttack {
    pub fn new() -> Self {
        Self {
            max_queries: 10000,
            max_candidates: 100000,
            max_gates: 20,
            timeout: Duration::from_secs(300),
            use_pruning: true,
            use_observational_equivalence: true,
            use_component_enumeration: true,
        }
    }

    pub fn with_max_queries(mut self, max: usize) -> Self {
        self.max_queries = max;
        self
    }

    pub fn with_max_candidates(mut self, max: usize) -> Self {
        self.max_candidates = max;
        self
    }

    pub fn with_max_gates(mut self, max: usize) -> Self {
        self.max_gates = max;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Main CEGIS synthesis loop
    pub fn cegis_synthesis<F>(&self, oracle: F, num_wires: usize) -> SynthesisResult
    where
        F: Fn(usize) -> usize,
    {
        let start = Instant::now();
        let mut queries = 0;
        let mut candidates_explored = 0;
        let mut rng = rand::thread_rng();

        let input_space = 1usize << num_wires;
        let mut counterexamples: Vec<(usize, usize)> = Vec::new();

        let initial_samples = 8.min(input_space);
        for i in 0..initial_samples {
            let output = oracle(i);
            counterexamples.push((i, output));
            queries += 1;
        }

        for num_gates in 1..=self.max_gates {
            if start.elapsed() > self.timeout {
                return SynthesisResult::failed(
                    queries,
                    candidates_explored,
                    start.elapsed(),
                    &format!("Timeout at {} gates", num_gates),
                );
            }

            let mut candidate_gen = CandidateGenerator::new(num_wires, num_gates);

            loop {
                if start.elapsed() > self.timeout {
                    break;
                }
                if queries >= self.max_queries {
                    break;
                }
                if candidates_explored >= self.max_candidates {
                    break;
                }

                let candidate = if self.use_component_enumeration {
                    candidate_gen.next_enumerated()
                } else {
                    candidate_gen.next_random(&mut rng)
                };

                let candidate = match candidate {
                    Some(c) => c,
                    None => break,
                };

                candidates_explored += 1;

                let consistent = counterexamples
                    .iter()
                    .all(|&(input, output)| candidate.evaluate(input) == output);

                if !consistent {
                    continue;
                }

                if let Some(cex) = self.find_counterexample(
                    &candidate,
                    &oracle,
                    num_wires,
                    &counterexamples,
                    &mut queries,
                ) {
                    counterexamples.push(cex);
                } else {
                    let verified =
                        self.verify_candidate(&candidate, &oracle, num_wires, 100, &mut queries);
                    if verified {
                        return SynthesisResult {
                            success: true,
                            synthesized_circuit: Some(candidate),
                            oracle_queries: queries,
                            candidates_explored,
                            synthesis_time: start.elapsed(),
                            counterexamples_used: counterexamples.len(),
                            final_error_rate: 0.0,
                            details: format!(
                                "CEGIS success: {} gates, {} queries, {} candidates, {} counterexamples",
                                num_gates, queries, candidates_explored, counterexamples.len()
                            ),
                        };
                    }
                }
            }
        }

        SynthesisResult::failed(
            queries,
            candidates_explored,
            start.elapsed(),
            &format!(
                "CEGIS failed: explored {} candidates with {} counterexamples",
                candidates_explored,
                counterexamples.len()
            ),
        )
    }

    /// Bottom-up enumerative synthesis (Sketch-style)
    pub fn enumerative_synthesis<F>(&self, oracle: F, num_wires: usize) -> SynthesisResult
    where
        F: Fn(usize) -> usize,
    {
        let start = Instant::now();
        let mut queries = 0;
        let mut candidates_explored = 0;

        let input_space = 1usize << num_wires;

        let mut io_pairs: Vec<(usize, usize)> = Vec::new();
        let sample_size = input_space.min(256);
        for i in 0..sample_size {
            if queries >= self.max_queries {
                break;
            }
            let output = oracle(i);
            io_pairs.push((i, output));
            queries += 1;
        }

        let mut observed_behaviors: HashMap<Vec<usize>, Circuit> = HashMap::new();

        for num_gates in 1..=self.max_gates {
            if start.elapsed() > self.timeout {
                break;
            }

            let mut gen = CandidateGenerator::new(num_wires, num_gates);

            while let Some(candidate) = gen.next_enumerated() {
                if start.elapsed() > self.timeout {
                    break;
                }
                if candidates_explored >= self.max_candidates {
                    break;
                }

                candidates_explored += 1;

                let behavior: Vec<usize> = io_pairs
                    .iter()
                    .map(|&(i, _)| candidate.evaluate(i))
                    .collect();

                if self.use_observational_equivalence {
                    if observed_behaviors.contains_key(&behavior) {
                        continue;
                    }
                    observed_behaviors.insert(behavior.clone(), candidate.clone());
                }

                let expected: Vec<usize> = io_pairs.iter().map(|&(_, o)| o).collect();
                if behavior == expected {
                    let verified =
                        self.verify_candidate(&candidate, &oracle, num_wires, 100, &mut queries);
                    if verified {
                        return SynthesisResult {
                            success: true,
                            synthesized_circuit: Some(candidate),
                            oracle_queries: queries,
                            candidates_explored,
                            synthesis_time: start.elapsed(),
                            counterexamples_used: io_pairs.len(),
                            final_error_rate: 0.0,
                            details: format!(
                                "Enumerative success: {} gates, {} unique behaviors observed",
                                num_gates,
                                observed_behaviors.len()
                            ),
                        };
                    }
                }
            }
        }

        SynthesisResult::failed(
            queries,
            candidates_explored,
            start.elapsed(),
            &format!(
                "Enumerative failed: {} unique behaviors in {} candidates",
                observed_behaviors.len(),
                candidates_explored
            ),
        )
    }

    /// Stochastic synthesis with fitness-guided search
    pub fn stochastic_synthesis<F>(&self, oracle: F, num_wires: usize) -> SynthesisResult
    where
        F: Fn(usize) -> usize,
    {
        let start = Instant::now();
        let mut queries = 0;
        let mut candidates_explored = 0;
        let mut rng = rand::thread_rng();

        let input_space = 1usize << num_wires;

        let sample_size = input_space.min(128);
        let mut io_pairs: Vec<(usize, usize)> = Vec::new();
        for i in 0..sample_size {
            let output = oracle(i);
            io_pairs.push((i, output));
            queries += 1;
        }

        let population_size = 100;
        let generations = 1000;
        let mutation_rate = 0.3;
        let crossover_rate = 0.5;

        let mut best_circuit: Option<Circuit> = None;
        let mut best_fitness = 0.0f64;

        for num_gates in 1..=self.max_gates {
            if start.elapsed() > self.timeout {
                break;
            }

            let mut population: Vec<Circuit> = (0..population_size)
                .map(|_| Circuit::random(num_wires, num_gates))
                .collect();

            for _gen in 0..generations {
                if start.elapsed() > self.timeout {
                    break;
                }

                let mut fitness: Vec<(usize, f64)> = population
                    .iter()
                    .enumerate()
                    .map(|(idx, c)| {
                        let correct = io_pairs
                            .iter()
                            .filter(|&&(i, o)| c.evaluate(i) == o)
                            .count();
                        (idx, correct as f64 / io_pairs.len() as f64)
                    })
                    .collect();

                fitness.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

                if fitness[0].1 > best_fitness {
                    best_fitness = fitness[0].1;
                    best_circuit = Some(population[fitness[0].0].clone());
                }

                if fitness[0].1 == 1.0 {
                    let candidate = population[fitness[0].0].clone();
                    let verified =
                        self.verify_candidate(&candidate, &oracle, num_wires, 100, &mut queries);
                    if verified {
                        return SynthesisResult {
                            success: true,
                            synthesized_circuit: Some(candidate),
                            oracle_queries: queries,
                            candidates_explored,
                            synthesis_time: start.elapsed(),
                            counterexamples_used: io_pairs.len(),
                            final_error_rate: 0.0,
                            details: format!(
                                "Stochastic success: {} gates, {} generations",
                                num_gates, _gen
                            ),
                        };
                    }
                }

                let elite_count = population_size / 10;
                let mut new_population: Vec<Circuit> = fitness
                    .iter()
                    .take(elite_count)
                    .map(|(idx, _)| population[*idx].clone())
                    .collect();

                while new_population.len() < population_size {
                    candidates_explored += 1;

                    let parent1_idx = fitness[rng.gen_range(0..elite_count * 2)].0;
                    let parent2_idx = fitness[rng.gen_range(0..elite_count * 2)].0;

                    let mut child = if rng.gen::<f64>() < crossover_rate {
                        self.crossover(&population[parent1_idx], &population[parent2_idx], &mut rng)
                    } else {
                        population[parent1_idx].clone()
                    };

                    if rng.gen::<f64>() < mutation_rate {
                        child = self.mutate(&child, &mut rng);
                    }

                    new_population.push(child);
                }

                population = new_population;
            }
        }

        SynthesisResult {
            success: false,
            synthesized_circuit: best_circuit,
            oracle_queries: queries,
            candidates_explored,
            synthesis_time: start.elapsed(),
            counterexamples_used: io_pairs.len(),
            final_error_rate: 1.0 - best_fitness,
            details: format!("Stochastic best fitness: {:.4}%", best_fitness * 100.0),
        }
    }

    /// Sketch-based synthesis with partial specification
    pub fn sketch_synthesis<F>(&self, oracle: F, sketch: &CircuitSketch) -> SynthesisResult
    where
        F: Fn(usize) -> usize,
    {
        let start = Instant::now();
        let mut queries = 0;
        let mut candidates_explored = 0;

        let input_space = 1usize << sketch.num_wires;
        let sample_size = input_space.min(64);
        let mut io_pairs: Vec<(usize, usize)> = Vec::new();
        for i in 0..sample_size {
            let output = oracle(i);
            io_pairs.push((i, output));
            queries += 1;
        }

        let hole_indices: Vec<usize> = (0..sketch.num_gates)
            .filter(|i| !sketch.fixed_gates.contains_key(i))
            .collect();

        if hole_indices.is_empty() {
            let gates: Vec<Gate> = (0..sketch.num_gates)
                .map(|i| sketch.fixed_gates[&i])
                .collect();
            let circuit = Circuit::from_gates(gates, sketch.num_wires);

            let matches = io_pairs.iter().all(|&(i, o)| circuit.evaluate(i) == o);
            return SynthesisResult {
                success: matches,
                synthesized_circuit: if matches { Some(circuit) } else { None },
                oracle_queries: queries,
                candidates_explored: 1,
                synthesis_time: start.elapsed(),
                counterexamples_used: io_pairs.len(),
                final_error_rate: if matches { 0.0 } else { 1.0 },
                details: "Sketch fully specified".to_string(),
            };
        }

        let components = self.generate_components(sketch.num_wires);

        let hole_options: Vec<Vec<GateComponent>> = hole_indices
            .iter()
            .map(|&idx| {
                sketch
                    .hole_constraints
                    .get(&idx)
                    .cloned()
                    .unwrap_or_else(|| components.clone())
            })
            .collect();

        let mut indices: Vec<usize> = vec![0; hole_indices.len()];

        loop {
            if start.elapsed() > self.timeout {
                break;
            }
            if candidates_explored >= self.max_candidates {
                break;
            }

            candidates_explored += 1;

            let mut gates: Vec<Gate> = Vec::with_capacity(sketch.num_gates);
            let mut hole_iter = 0;
            for i in 0..sketch.num_gates {
                if let Some(&gate) = sketch.fixed_gates.get(&i) {
                    gates.push(gate);
                } else {
                    gates.push(hole_options[hole_iter][indices[hole_iter]].to_gate());
                    hole_iter += 1;
                }
            }

            let circuit = Circuit::from_gates(gates, sketch.num_wires);

            if io_pairs.iter().all(|&(i, o)| circuit.evaluate(i) == o) {
                let verified =
                    self.verify_candidate(&circuit, &oracle, sketch.num_wires, 100, &mut queries);
                if verified {
                    return SynthesisResult {
                        success: true,
                        synthesized_circuit: Some(circuit),
                        oracle_queries: queries,
                        candidates_explored,
                        synthesis_time: start.elapsed(),
                        counterexamples_used: io_pairs.len(),
                        final_error_rate: 0.0,
                        details: format!("Sketch synthesis: {} holes filled", hole_indices.len()),
                    };
                }
            }

            let mut carry = true;
            for i in 0..indices.len() {
                if carry {
                    indices[i] += 1;
                    if indices[i] >= hole_options[i].len() {
                        indices[i] = 0;
                    } else {
                        carry = false;
                    }
                }
            }
            if carry {
                break;
            }
        }

        SynthesisResult::failed(
            queries,
            candidates_explored,
            start.elapsed(),
            "Sketch synthesis exhausted all hole combinations",
        )
    }

    fn find_counterexample<F>(
        &self,
        candidate: &Circuit,
        oracle: &F,
        num_wires: usize,
        existing: &[(usize, usize)],
        queries: &mut usize,
    ) -> Option<(usize, usize)>
    where
        F: Fn(usize) -> usize,
    {
        let existing_set: HashSet<usize> = existing.iter().map(|&(i, _)| i).collect();
        let input_space = 1usize << num_wires;
        let mut rng = rand::thread_rng();

        let samples = 32.min(input_space);
        for _ in 0..samples {
            if *queries >= self.max_queries {
                return None;
            }

            let input = rng.gen_range(0..input_space);
            if existing_set.contains(&input) {
                continue;
            }

            let expected = oracle(input);
            *queries += 1;

            if candidate.evaluate(input) != expected {
                return Some((input, expected));
            }
        }

        None
    }

    fn verify_candidate<F>(
        &self,
        candidate: &Circuit,
        oracle: &F,
        num_wires: usize,
        samples: usize,
        queries: &mut usize,
    ) -> bool
    where
        F: Fn(usize) -> usize,
    {
        let input_space = 1usize << num_wires;
        let mut rng = rand::thread_rng();

        for _ in 0..samples {
            if *queries >= self.max_queries {
                return false;
            }

            let input = rng.gen_range(0..input_space);
            let expected = oracle(input);
            *queries += 1;

            if candidate.evaluate(input) != expected {
                return false;
            }
        }

        true
    }

    fn generate_components(&self, num_wires: usize) -> Vec<GateComponent> {
        let mut components = Vec::new();

        for active in 0..num_wires as u8 {
            for c1 in 0..num_wires as u8 {
                if c1 == active {
                    continue;
                }
                for c2 in 0..num_wires as u8 {
                    if c2 == active || c2 == c1 {
                        continue;
                    }
                    for cf_idx in 0..16u8 {
                        components.push(GateComponent {
                            active,
                            control1: c1,
                            control2: c2,
                            control_func: ControlFunction::from_u8(cf_idx),
                        });
                    }
                }
            }
        }

        components
    }

    fn crossover(&self, parent1: &Circuit, parent2: &Circuit, rng: &mut impl Rng) -> Circuit {
        let crossover_point = rng.gen_range(0..=parent1.gates.len());
        let mut gates: Vec<Gate> = parent1.gates[..crossover_point].to_vec();
        gates.extend_from_slice(&parent2.gates[crossover_point..]);

        while gates.len() < parent1.gates.len() {
            gates.push(parent1.gates[gates.len()]);
        }
        gates.truncate(parent1.gates.len());

        Circuit::from_gates(gates, parent1.num_wires)
    }

    fn mutate(&self, circuit: &Circuit, rng: &mut impl Rng) -> Circuit {
        let mut gates = circuit.gates.clone();

        if gates.is_empty() {
            return circuit.clone();
        }

        let idx = rng.gen_range(0..gates.len());
        let mutation_type = rng.gen_range(0..4);

        match mutation_type {
            0 => {
                gates[idx].pins[0] = rng.gen_range(0..circuit.num_wires as u8);
            }
            1 => {
                let new_c1 = rng.gen_range(0..circuit.num_wires as u8);
                if new_c1 != gates[idx].pins[0] {
                    gates[idx].pins[1] = new_c1;
                }
            }
            2 => {
                let new_c2 = rng.gen_range(0..circuit.num_wires as u8);
                if new_c2 != gates[idx].pins[0] && new_c2 != gates[idx].pins[1] {
                    gates[idx].pins[2] = new_c2;
                }
            }
            _ => {
                gates[idx].control_function = ControlFunction::from_u8(rng.gen_range(0..16));
            }
        }

        Circuit::from_gates(gates, circuit.num_wires)
    }
}

/// Candidate circuit generator for enumeration
struct CandidateGenerator {
    num_wires: usize,
    num_gates: usize,
    current_structure: Vec<(u8, u8, u8)>,
    current_cfs: Vec<u8>,
    exhausted: bool,
    wire_combos: Vec<(u8, u8, u8)>,
}

impl CandidateGenerator {
    fn new(num_wires: usize, num_gates: usize) -> Self {
        let wire_combos: Vec<(u8, u8, u8)> = (0..num_wires as u8)
            .flat_map(|a| {
                (0..num_wires as u8)
                    .filter(move |&c1| c1 != a)
                    .flat_map(move |c1| {
                        (0..num_wires as u8)
                            .filter(move |&c2| c2 != a && c2 != c1)
                            .map(move |c2| (a, c1, c2))
                    })
            })
            .collect();

        let initial_structure = if wire_combos.is_empty() || num_gates == 0 {
            vec![]
        } else {
            vec![wire_combos[0]; num_gates]
        };

        Self {
            num_wires,
            num_gates,
            current_structure: initial_structure,
            current_cfs: vec![0; num_gates],
            exhausted: num_gates == 0 || wire_combos.is_empty(),
            wire_combos,
        }
    }

    fn next_enumerated(&mut self) -> Option<Circuit> {
        if self.exhausted || self.num_gates == 0 {
            return None;
        }

        let gates: Vec<Gate> = self
            .current_structure
            .iter()
            .zip(self.current_cfs.iter())
            .map(|(&(a, c1, c2), &cf)| Gate::new(a, c1, c2, ControlFunction::from_u8(cf)))
            .collect();

        let circuit = Circuit::from_gates(gates, self.num_wires);

        self.advance();

        Some(circuit)
    }

    fn next_random(&mut self, rng: &mut impl Rng) -> Option<Circuit> {
        if self.wire_combos.is_empty() || self.num_gates == 0 {
            return None;
        }

        let gates: Vec<Gate> = (0..self.num_gates)
            .map(|_| {
                let (a, c1, c2) = self.wire_combos[rng.gen_range(0..self.wire_combos.len())];
                let cf = ControlFunction::from_u8(rng.gen_range(0..16));
                Gate::new(a, c1, c2, cf)
            })
            .collect();

        Some(Circuit::from_gates(gates, self.num_wires))
    }

    fn advance(&mut self) {
        for i in 0..self.num_gates {
            self.current_cfs[i] += 1;
            if self.current_cfs[i] < 16 {
                return;
            }
            self.current_cfs[i] = 0;
        }

        for i in 0..self.num_gates {
            let current_idx = self
                .wire_combos
                .iter()
                .position(|&x| x == self.current_structure[i])
                .unwrap_or(0);

            if current_idx + 1 < self.wire_combos.len() {
                self.current_structure[i] = self.wire_combos[current_idx + 1];
                return;
            }
            self.current_structure[i] = self.wire_combos[0];
        }

        self.exhausted = true;
    }
}

/// Benchmark synthesis attacks against circuits of various sizes
pub fn benchmark_synthesis(
    wire_sizes: &[usize],
    gate_counts: &[usize],
) -> Vec<SynthesisBenchmarkResult> {
    let mut results = Vec::new();

    for &num_wires in wire_sizes {
        for &num_gates in gate_counts {
            let target = Circuit::random(num_wires, num_gates);
            let oracle = |input: usize| target.evaluate(input);

            let attack = SynthesisAttack::new()
                .with_max_queries(5000)
                .with_max_candidates(50000)
                .with_max_gates(num_gates + 3)
                .with_timeout(Duration::from_secs(30));

            let cegis_result = attack.cegis_synthesis(&oracle, num_wires);

            results.push(SynthesisBenchmarkResult {
                num_wires,
                num_gates,
                method: "CEGIS".to_string(),
                success: cegis_result.success,
                queries: cegis_result.oracle_queries,
                candidates: cegis_result.candidates_explored,
                time: cegis_result.synthesis_time,
            });

            let target = Circuit::random(num_wires, num_gates);
            let oracle = |input: usize| target.evaluate(input);

            let enum_result = attack.enumerative_synthesis(&oracle, num_wires);

            results.push(SynthesisBenchmarkResult {
                num_wires,
                num_gates,
                method: "Enumerative".to_string(),
                success: enum_result.success,
                queries: enum_result.oracle_queries,
                candidates: enum_result.candidates_explored,
                time: enum_result.synthesis_time,
            });

            let target = Circuit::random(num_wires, num_gates);
            let oracle = |input: usize| target.evaluate(input);

            let stoch_result = attack.stochastic_synthesis(&oracle, num_wires);

            results.push(SynthesisBenchmarkResult {
                num_wires,
                num_gates,
                method: "Stochastic".to_string(),
                success: stoch_result.success,
                queries: stoch_result.oracle_queries,
                candidates: stoch_result.candidates_explored,
                time: stoch_result.synthesis_time,
            });
        }
    }

    results
}

#[derive(Debug, Clone)]
pub struct SynthesisBenchmarkResult {
    pub num_wires: usize,
    pub num_gates: usize,
    pub method: String,
    pub success: bool,
    pub queries: usize,
    pub candidates: usize,
    pub time: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cegis_simple() {
        let target = Circuit::random(3, 2);
        let oracle = |input: usize| target.evaluate(input);

        let attack = SynthesisAttack::new()
            .with_max_queries(1000)
            .with_max_gates(5)
            .with_timeout(Duration::from_secs(10));

        let result = attack.cegis_synthesis(oracle, 3);

        println!(
            "CEGIS: success={}, queries={}, candidates={}, time={:?}",
            result.success,
            result.oracle_queries,
            result.candidates_explored,
            result.synthesis_time
        );
        println!("Details: {}", result.details);

        if result.success {
            let synth = result.synthesized_circuit.unwrap();
            for i in 0..8 {
                assert_eq!(target.evaluate(i), synth.evaluate(i));
            }
        }
    }

    #[test]
    fn test_enumerative_simple() {
        let target = Circuit::random(3, 1);
        let oracle = |input: usize| target.evaluate(input);

        let attack = SynthesisAttack::new()
            .with_max_queries(500)
            .with_max_gates(3);

        let result = attack.enumerative_synthesis(oracle, 3);

        println!(
            "Enumerative: success={}, queries={}, candidates={}",
            result.success, result.oracle_queries, result.candidates_explored
        );
    }

    #[test]
    fn test_stochastic_simple() {
        let target = Circuit::random(4, 3);
        let oracle = |input: usize| target.evaluate(input);

        let attack = SynthesisAttack::new()
            .with_max_queries(2000)
            .with_max_gates(5)
            .with_timeout(Duration::from_secs(10));

        let result = attack.stochastic_synthesis(oracle, 4);

        println!(
            "Stochastic: success={}, error={:.2}%, queries={}",
            result.success,
            result.final_error_rate * 100.0,
            result.oracle_queries
        );
    }

    #[test]
    fn test_sketch_synthesis() {
        let target = Circuit::random(3, 2);
        let oracle = |input: usize| target.evaluate(input);

        let sketch = CircuitSketch::new(3, 2).with_gate(0, target.gates[0]);

        let attack = SynthesisAttack::new()
            .with_max_queries(500)
            .with_max_candidates(10000);

        let result = attack.sketch_synthesis(oracle, &sketch);

        println!(
            "Sketch: success={}, queries={}, candidates={}",
            result.success, result.oracle_queries, result.candidates_explored
        );
    }

    #[test]
    fn test_synthesis_scaling() {
        let results = benchmark_synthesis(&[3, 4], &[1, 2, 3]);

        println!("\nSynthesis Attack Benchmark:");
        println!("Method      | Wires | Gates | Success | Queries | Candidates | Time");
        println!("------------|-------|-------|---------|---------|------------|--------");
        for r in &results {
            println!(
                "{:11} | {:5} | {:5} | {:7} | {:7} | {:10} | {:?}",
                r.method, r.num_wires, r.num_gates, r.success, r.queries, r.candidates, r.time
            );
        }
    }

    #[test]
    fn test_synthesis_fails_on_large_circuit() {
        let target = Circuit::random(8, 16);
        let oracle = |input: usize| target.evaluate(input);

        let attack = SynthesisAttack::new()
            .with_max_queries(1000)
            .with_max_candidates(10000)
            .with_max_gates(20)
            .with_timeout(Duration::from_secs(5));

        let result = attack.cegis_synthesis(oracle, 8);

        println!(
            "Large circuit CEGIS: success={}, queries={}, candidates={}",
            result.success, result.oracle_queries, result.candidates_explored
        );

        assert!(
            !result.success,
            "Synthesis should fail on 8-wire 16-gate circuits"
        );
    }
}
