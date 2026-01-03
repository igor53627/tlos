//! Oracle-Guided Learning Attack
//!
//! Implements the oracle-guided synthesis attack - identified as HIGH threat
//! in the SAT attacks literature review. This attack exploits the fact that
//! Ethereum smart contracts provide unlimited oracle queries.
//!
//! Based on:
//! - DIP-based learning from Subramanyan et al. (HOST 2015)
//! - Approximate attacks from Shamsi et al. (DAC 2017)

use crate::circuit::{Circuit, Gate};
use crate::control_function::ControlFunction;
use rand::prelude::*;
use std::collections::HashSet;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct OracleGuidedResult {
    pub attack_success: bool,
    pub queries_used: usize,
    pub candidate_circuits: usize,
    pub error_rate: f64,
    pub time_elapsed: Duration,
    pub learned_circuit: Option<Circuit>,
    pub details: String,
}

impl OracleGuidedResult {
    pub fn failed(queries: usize, time: Duration, details: String) -> Self {
        Self {
            attack_success: false,
            queries_used: queries,
            candidate_circuits: 0,
            error_rate: 1.0,
            time_elapsed: time,
            learned_circuit: None,
            details,
        }
    }
}

pub struct OracleGuidedAttack {
    max_queries: usize,
    max_circuit_size: usize,
    timeout: Duration,
    approximate_threshold: f64,
    adaptive_sampling: bool,
}

impl Default for OracleGuidedAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl OracleGuidedAttack {
    pub fn new() -> Self {
        Self {
            max_queries: 10000,
            max_circuit_size: 30,
            timeout: Duration::from_secs(300),
            approximate_threshold: 0.01,
            adaptive_sampling: true,
        }
    }

    pub fn with_max_queries(mut self, max: usize) -> Self {
        self.max_queries = max;
        self
    }

    pub fn with_max_circuit_size(mut self, max: usize) -> Self {
        self.max_circuit_size = max;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_approximate_threshold(mut self, threshold: f64) -> Self {
        self.approximate_threshold = threshold;
        self
    }

    pub fn exact_learning<F>(&self, oracle: F, num_wires: usize) -> OracleGuidedResult
    where
        F: Fn(usize) -> usize,
    {
        let start = Instant::now();
        let mut queries = 0;
        let mut rng = rand::thread_rng();

        let mut io_pairs: Vec<(usize, usize)> = Vec::new();
        let input_space = 1 << num_wires;

        let initial_samples = input_space.min(64);
        for input in 0..initial_samples {
            if start.elapsed() > self.timeout || queries >= self.max_queries {
                break;
            }
            let output = oracle(input);
            io_pairs.push((input, output));
            queries += 1;
        }

        for num_gates in 1..=self.max_circuit_size {
            if start.elapsed() > self.timeout {
                return OracleGuidedResult::failed(
                    queries,
                    start.elapsed(),
                    format!("Timeout at {} gates", num_gates),
                );
            }

            let mut candidates = self.enumerate_candidates(num_wires, num_gates, &io_pairs, 100);

            if candidates.is_empty() {
                continue;
            }

            loop {
                if start.elapsed() > self.timeout || queries >= self.max_queries {
                    break;
                }

                candidates.retain(|c| io_pairs.iter().all(|&(i, o)| c.evaluate(i) == o));

                if candidates.is_empty() {
                    break;
                }

                if candidates.len() == 1 {
                    let candidate = candidates.remove(0);

                    let mut verified = true;
                    let verify_samples = 100.min(input_space - io_pairs.len());
                    for _ in 0..verify_samples {
                        if queries >= self.max_queries {
                            break;
                        }
                        let input: usize = rng.gen_range(0..input_space);
                        if io_pairs.iter().any(|&(i, _)| i == input) {
                            continue;
                        }
                        let output = oracle(input);
                        queries += 1;
                        io_pairs.push((input, output));

                        if candidate.evaluate(input) != output {
                            verified = false;
                            break;
                        }
                    }

                    if verified {
                        return OracleGuidedResult {
                            attack_success: true,
                            queries_used: queries,
                            candidate_circuits: 1,
                            error_rate: 0.0,
                            time_elapsed: start.elapsed(),
                            learned_circuit: Some(candidate),
                            details: format!(
                                "Exact learning: {} gates, {} queries",
                                num_gates, queries
                            ),
                        };
                    }
                }

                if let Some(dip) = self.find_distinguishing_input(&candidates, &io_pairs, num_wires)
                {
                    let output = oracle(dip);
                    queries += 1;
                    io_pairs.push((dip, output));
                } else {
                    if !candidates.is_empty() {
                        let candidate = candidates[0].clone();
                        let error_rate = self.estimate_error_rate(
                            &candidate,
                            &oracle,
                            num_wires,
                            100,
                            &mut queries,
                        );

                        if error_rate <= self.approximate_threshold {
                            return OracleGuidedResult {
                                attack_success: true,
                                queries_used: queries,
                                candidate_circuits: candidates.len(),
                                error_rate,
                                time_elapsed: start.elapsed(),
                                learned_circuit: Some(candidate),
                                details: format!(
                                    "Approximate learning: {} gates, error={:.4}%, {} queries",
                                    num_gates,
                                    error_rate * 100.0,
                                    queries
                                ),
                            };
                        }
                    }
                    break;
                }
            }
        }

        OracleGuidedResult::failed(
            queries,
            start.elapsed(),
            format!(
                "Could not learn circuit up to {} gates",
                self.max_circuit_size
            ),
        )
    }

    pub fn approximate_learning<F>(&self, oracle: F, num_wires: usize) -> OracleGuidedResult
    where
        F: Fn(usize) -> usize,
    {
        let start = Instant::now();
        let mut queries = 0;
        let mut rng = rand::thread_rng();

        let input_space = 1 << num_wires;
        let sample_size = self.max_queries.min(input_space).min(1000);

        let mut io_pairs: Vec<(usize, usize)> = Vec::new();
        let mut sampled: HashSet<usize> = HashSet::new();

        for _ in 0..sample_size {
            if start.elapsed() > self.timeout {
                break;
            }

            let input = if sampled.len() < input_space {
                loop {
                    let i = rng.gen_range(0..input_space);
                    if !sampled.contains(&i) {
                        sampled.insert(i);
                        break i;
                    }
                }
            } else {
                break;
            };

            let output = oracle(input);
            io_pairs.push((input, output));
            queries += 1;
        }

        let mut best_candidate: Option<Circuit> = None;
        let mut best_error = 1.0f64;

        for num_gates in 1..=self.max_circuit_size {
            if start.elapsed() > self.timeout {
                break;
            }

            let candidates = self.enumerate_candidates(num_wires, num_gates, &io_pairs, 50);

            for candidate in candidates {
                let mut errors = 0;
                for &(input, output) in &io_pairs {
                    if candidate.evaluate(input) != output {
                        errors += 1;
                    }
                }

                let error_rate = errors as f64 / io_pairs.len() as f64;
                if error_rate < best_error {
                    best_error = error_rate;
                    best_candidate = Some(candidate);
                }

                if error_rate <= self.approximate_threshold {
                    return OracleGuidedResult {
                        attack_success: true,
                        queries_used: queries,
                        candidate_circuits: 1,
                        error_rate,
                        time_elapsed: start.elapsed(),
                        learned_circuit: best_candidate,
                        details: format!(
                            "Approximate match: {} gates, {:.4}% error, {} queries",
                            num_gates,
                            error_rate * 100.0,
                            queries
                        ),
                    };
                }
            }
        }

        if best_error <= self.approximate_threshold {
            OracleGuidedResult {
                attack_success: true,
                queries_used: queries,
                candidate_circuits: 1,
                error_rate: best_error,
                time_elapsed: start.elapsed(),
                learned_circuit: best_candidate,
                details: format!("Best approximate: {:.4}% error", best_error * 100.0),
            }
        } else {
            OracleGuidedResult::failed(
                queries,
                start.elapsed(),
                format!("Best error rate: {:.4}%", best_error * 100.0),
            )
        }
    }

    pub fn dip_attack<F>(
        &self,
        oracle: F,
        num_wires: usize,
        known_structure: &[(u8, u8, u8)],
    ) -> OracleGuidedResult
    where
        F: Fn(usize) -> usize,
    {
        let start = Instant::now();
        let mut queries = 0;

        let mut io_constraints: Vec<(usize, usize)> = Vec::new();
        let cf_options: Vec<ControlFunction> = (0..16).map(ControlFunction::from_u8).collect();

        loop {
            if start.elapsed() > self.timeout || queries >= self.max_queries {
                return OracleGuidedResult::failed(
                    queries,
                    start.elapsed(),
                    "Timeout or query limit reached".to_string(),
                );
            }

            let consistent = self.find_consistent_assignments(
                num_wires,
                known_structure,
                &cf_options,
                &io_constraints,
            );

            if consistent.is_empty() {
                return OracleGuidedResult::failed(
                    queries,
                    start.elapsed(),
                    "No consistent assignment found".to_string(),
                );
            }

            if consistent.len() == 1 {
                let gates: Vec<Gate> = known_structure
                    .iter()
                    .zip(consistent[0].iter())
                    .map(|(&(a, c1, c2), &cf)| Gate::new(a, c1, c2, cf))
                    .collect();
                let learned = Circuit::from_gates(gates, num_wires);

                return OracleGuidedResult {
                    attack_success: true,
                    queries_used: queries,
                    candidate_circuits: 1,
                    error_rate: 0.0,
                    time_elapsed: start.elapsed(),
                    learned_circuit: Some(learned),
                    details: format!(
                        "DIP attack: {} queries, {} DIPs",
                        queries,
                        io_constraints.len()
                    ),
                };
            }

            if let Some(dip) =
                self.find_dip_for_assignments(num_wires, known_structure, &consistent)
            {
                let output = oracle(dip);
                io_constraints.push((dip, output));
                queries += 1;
            } else {
                let gates: Vec<Gate> = known_structure
                    .iter()
                    .zip(consistent[0].iter())
                    .map(|(&(a, c1, c2), &cf)| Gate::new(a, c1, c2, cf))
                    .collect();
                let learned = Circuit::from_gates(gates, num_wires);

                return OracleGuidedResult {
                    attack_success: true,
                    queries_used: queries,
                    candidate_circuits: consistent.len(),
                    error_rate: 0.0,
                    time_elapsed: start.elapsed(),
                    learned_circuit: Some(learned),
                    details: format!(
                        "DIP converged: {} candidates, {} queries",
                        consistent.len(),
                        queries
                    ),
                };
            }
        }
    }

    fn enumerate_candidates(
        &self,
        num_wires: usize,
        num_gates: usize,
        io_pairs: &[(usize, usize)],
        max_candidates: usize,
    ) -> Vec<Circuit> {
        let mut candidates = Vec::new();
        let mut rng = rand::thread_rng();

        let attempts = max_candidates * 100;
        for _ in 0..attempts {
            if candidates.len() >= max_candidates {
                break;
            }

            let circuit = Circuit::random(num_wires, num_gates);

            let consistent = io_pairs.iter().all(|&(i, o)| circuit.evaluate(i) == o);

            if consistent {
                candidates.push(circuit);
            }
        }

        if candidates.is_empty() && num_gates <= 3 {
            candidates = self.exhaustive_enumerate(num_wires, num_gates, io_pairs, max_candidates);
        }

        candidates
    }

    fn exhaustive_enumerate(
        &self,
        num_wires: usize,
        num_gates: usize,
        io_pairs: &[(usize, usize)],
        max_candidates: usize,
    ) -> Vec<Circuit> {
        let mut candidates = Vec::new();

        if num_gates > 2 || num_wires > 4 {
            return candidates;
        }

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

        let cf_options: Vec<ControlFunction> = (0..16).map(ControlFunction::from_u8).collect();

        let mut gate_structures: Vec<Vec<(u8, u8, u8)>> = vec![vec![]];
        for _ in 0..num_gates {
            let mut new_structures = Vec::new();
            for structure in &gate_structures {
                for &combo in &wire_combos {
                    let mut new_struct = structure.clone();
                    new_struct.push(combo);
                    new_structures.push(new_struct);
                }
            }
            gate_structures = new_structures;
        }

        'outer: for structure in gate_structures {
            if candidates.len() >= max_candidates {
                break;
            }

            let cf_combinations = cf_options.len().pow(num_gates as u32);
            for cf_idx in 0..cf_combinations {
                if candidates.len() >= max_candidates {
                    break 'outer;
                }

                let mut cfs = Vec::with_capacity(num_gates);
                let mut idx = cf_idx;
                for _ in 0..num_gates {
                    cfs.push(cf_options[idx % cf_options.len()]);
                    idx /= cf_options.len();
                }

                let gates: Vec<Gate> = structure
                    .iter()
                    .zip(cfs.iter())
                    .map(|(&(a, c1, c2), &cf)| Gate::new(a, c1, c2, cf))
                    .collect();
                let circuit = Circuit::from_gates(gates, num_wires);

                let consistent = io_pairs.iter().all(|&(i, o)| circuit.evaluate(i) == o);

                if consistent {
                    candidates.push(circuit);
                }
            }
        }

        candidates
    }

    fn find_distinguishing_input(
        &self,
        candidates: &[Circuit],
        existing_ios: &[(usize, usize)],
        num_wires: usize,
    ) -> Option<usize> {
        if candidates.len() < 2 {
            return None;
        }

        let input_space = 1 << num_wires;
        let existing_inputs: HashSet<usize> = existing_ios.iter().map(|&(i, _)| i).collect();

        for input in 0..input_space {
            if existing_inputs.contains(&input) {
                continue;
            }

            let first_output = candidates[0].evaluate(input);
            for candidate in candidates.iter().skip(1) {
                if candidate.evaluate(input) != first_output {
                    return Some(input);
                }
            }
        }

        None
    }

    fn find_consistent_assignments(
        &self,
        num_wires: usize,
        structure: &[(u8, u8, u8)],
        cf_options: &[ControlFunction],
        ios: &[(usize, usize)],
    ) -> Vec<Vec<ControlFunction>> {
        let num_gates = structure.len();
        if num_gates > 5 {
            return Vec::new();
        }

        let mut consistent = Vec::new();
        let total = cf_options.len().pow(num_gates as u32);

        for combo_idx in 0..total {
            let mut cfs = Vec::with_capacity(num_gates);
            let mut idx = combo_idx;
            for _ in 0..num_gates {
                cfs.push(cf_options[idx % cf_options.len()]);
                idx /= cf_options.len();
            }

            let gates: Vec<Gate> = structure
                .iter()
                .zip(cfs.iter())
                .map(|(&(a, c1, c2), &cf)| Gate::new(a, c1, c2, cf))
                .collect();
            let circuit = Circuit::from_gates(gates, num_wires);

            if ios.iter().all(|&(i, o)| circuit.evaluate(i) == o) {
                consistent.push(cfs);
            }
        }

        consistent
    }

    fn find_dip_for_assignments(
        &self,
        num_wires: usize,
        structure: &[(u8, u8, u8)],
        assignments: &[Vec<ControlFunction>],
    ) -> Option<usize> {
        if assignments.len() < 2 {
            return None;
        }

        let circuits: Vec<Circuit> = assignments
            .iter()
            .take(10)
            .map(|cfs| {
                let gates: Vec<Gate> = structure
                    .iter()
                    .zip(cfs.iter())
                    .map(|(&(a, c1, c2), &cf)| Gate::new(a, c1, c2, cf))
                    .collect();
                Circuit::from_gates(gates, num_wires)
            })
            .collect();

        let input_space = 1 << num_wires.min(12);
        for input in 0..input_space {
            let first = circuits[0].evaluate(input);
            for c in circuits.iter().skip(1) {
                if c.evaluate(input) != first {
                    return Some(input);
                }
            }
        }

        None
    }

    fn estimate_error_rate<F>(
        &self,
        candidate: &Circuit,
        oracle: &F,
        num_wires: usize,
        samples: usize,
        queries: &mut usize,
    ) -> f64
    where
        F: Fn(usize) -> usize,
    {
        let mut rng = rand::thread_rng();
        let input_space = 1 << num_wires;
        let mut errors = 0;

        for _ in 0..samples {
            let input = rng.gen_range(0..input_space);
            let expected = oracle(input);
            *queries += 1;

            if candidate.evaluate(input) != expected {
                errors += 1;
            }
        }

        errors as f64 / samples as f64
    }
}

#[derive(Debug, Clone)]
pub struct QueryComplexityBenchmark {
    pub num_wires: usize,
    pub num_gates: usize,
    pub queries_to_learn: usize,
    pub time_to_learn: Duration,
    pub success: bool,
}

pub fn benchmark_query_complexity(
    wire_sizes: &[usize],
    gate_counts: &[usize],
) -> Vec<QueryComplexityBenchmark> {
    let mut results = Vec::new();

    for &num_wires in wire_sizes {
        for &num_gates in gate_counts {
            let target = Circuit::random(num_wires, num_gates);
            let oracle = |input: usize| target.evaluate(input);

            let attack = OracleGuidedAttack::new()
                .with_max_queries(10000)
                .with_max_circuit_size(num_gates + 5)
                .with_timeout(Duration::from_secs(30));

            let start = Instant::now();
            let result = attack.exact_learning(oracle, num_wires);

            results.push(QueryComplexityBenchmark {
                num_wires,
                num_gates,
                queries_to_learn: result.queries_used,
                time_to_learn: start.elapsed(),
                success: result.attack_success,
            });
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_learning_simple() {
        let target = Circuit::random_r57(3, 2);
        let oracle = |input: usize| target.evaluate(input);

        let attack = OracleGuidedAttack::new()
            .with_max_queries(1000)
            .with_max_circuit_size(5);

        let result = attack.exact_learning(oracle, 3);

        println!(
            "Exact learning: success={}, queries={}, time={:?}",
            result.attack_success, result.queries_used, result.time_elapsed
        );

        if result.attack_success {
            let learned = result.learned_circuit.unwrap();
            for input in 0..8 {
                assert_eq!(
                    target.evaluate(input),
                    learned.evaluate(input),
                    "Mismatch at input {}",
                    input
                );
            }
        }
    }

    #[test]
    fn test_approximate_learning() {
        let target = Circuit::random(4, 5);
        let oracle = |input: usize| target.evaluate(input);

        let attack = OracleGuidedAttack::new()
            .with_max_queries(500)
            .with_approximate_threshold(0.1);

        let result = attack.approximate_learning(oracle, 4);

        println!(
            "Approximate learning: success={}, error={:.2}%, queries={}",
            result.attack_success,
            result.error_rate * 100.0,
            result.queries_used
        );
    }

    #[test]
    fn test_dip_attack() {
        let target = Circuit::random(4, 3);
        let structure: Vec<(u8, u8, u8)> = target
            .gates
            .iter()
            .map(|g| (g.pins[0], g.pins[1], g.pins[2]))
            .collect();

        let oracle = |input: usize| target.evaluate(input);

        let attack = OracleGuidedAttack::new().with_max_queries(500);
        let result = attack.dip_attack(oracle, 4, &structure);

        println!(
            "DIP attack: success={}, queries={}, candidates={}",
            result.attack_success, result.queries_used, result.candidate_circuits
        );

        if result.attack_success {
            let learned = result.learned_circuit.unwrap();
            for input in 0..16 {
                assert_eq!(
                    target.evaluate(input),
                    learned.evaluate(input),
                    "Mismatch at input {}",
                    input
                );
            }
        }
    }

    #[test]
    fn test_query_complexity_scaling() {
        let results = benchmark_query_complexity(&[3, 4], &[1, 2, 3]);

        println!("\nQuery Complexity Benchmark:");
        println!("Wires | Gates | Queries | Time     | Success");
        println!("------|-------|---------|----------|--------");
        for r in &results {
            println!(
                "{:5} | {:5} | {:7} | {:8.2?} | {}",
                r.num_wires, r.num_gates, r.queries_to_learn, r.time_to_learn, r.success
            );
        }
    }
}
