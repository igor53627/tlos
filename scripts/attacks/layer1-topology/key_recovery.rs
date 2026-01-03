//! Key Recovery SAT Attack
//!
//! Simulates the classic SAT attack from Subramanyan et al. (HOST 2015).
//! For MinCore, this tests whether circuit parameters can be recovered
//! when modeled as "keys" to be discovered.

use super::sat_encoder::SatEncoder;
use crate::circuit::{Circuit, Gate};
use crate::control_function::ControlFunction;
use std::time::{Duration, Instant};
use varisat::{CnfFormula, ExtendFormula, Lit, Solver, Var};

#[derive(Debug, Clone)]
pub struct KeyRecoveryResult {
    pub success: bool,
    pub iterations: usize,
    pub dips_found: usize,
    pub time_elapsed: Duration,
    pub recovered_circuit: Option<Circuit>,
    pub details: String,
}

impl KeyRecoveryResult {
    pub fn failed(iterations: usize, time: Duration, details: String) -> Self {
        Self {
            success: false,
            iterations,
            dips_found: 0,
            time_elapsed: time,
            recovered_circuit: None,
            details,
        }
    }

    pub fn success(
        iterations: usize,
        dips: usize,
        time: Duration,
        circuit: Circuit,
        details: String,
    ) -> Self {
        Self {
            success: true,
            iterations,
            dips_found: dips,
            time_elapsed: time,
            recovered_circuit: Some(circuit),
            details,
        }
    }
}

pub struct KeyRecoveryAttack {
    max_iterations: usize,
    timeout: Duration,
}

impl Default for KeyRecoveryAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyRecoveryAttack {
    pub fn new() -> Self {
        Self {
            max_iterations: 1000,
            timeout: Duration::from_secs(60),
        }
    }

    pub fn with_max_iterations(mut self, max: usize) -> Self {
        self.max_iterations = max;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn attack_gate_parameters(
        &self,
        oracle: &Circuit,
        known_structure: &[(u8, u8, u8)],
    ) -> KeyRecoveryResult {
        let start = Instant::now();
        let num_gates = known_structure.len();
        let num_wires = oracle.num_wires;

        if num_gates == 0 {
            return KeyRecoveryResult::failed(
                0,
                start.elapsed(),
                "No gates to recover".to_string(),
            );
        }

        let mut collected_ios: Vec<(usize, usize)> = Vec::new();
        let mut iterations = 0;

        let cf_options: Vec<ControlFunction> = (0..16).map(ControlFunction::from_u8).collect();

        loop {
            if start.elapsed() > self.timeout {
                return KeyRecoveryResult::failed(
                    iterations,
                    start.elapsed(),
                    format!("Timeout after {} iterations", iterations),
                );
            }

            if iterations >= self.max_iterations {
                return KeyRecoveryResult::failed(
                    iterations,
                    start.elapsed(),
                    format!("Max iterations ({}) reached", self.max_iterations),
                );
            }

            let consistent_keys =
                self.find_consistent_keys(num_wires, known_structure, &cf_options, &collected_ios);

            if consistent_keys.is_empty() {
                return KeyRecoveryResult::failed(
                    iterations,
                    start.elapsed(),
                    "No consistent key found - contradiction".to_string(),
                );
            }

            if consistent_keys.len() == 1 {
                let gates: Vec<Gate> = known_structure
                    .iter()
                    .zip(consistent_keys[0].iter())
                    .map(|(&(a, c1, c2), &cf)| Gate::new(a, c1, c2, cf))
                    .collect();

                let recovered = Circuit::from_gates(gates, num_wires);

                let mut verified = true;
                for i in 0..(1 << num_wires.min(8)) {
                    if oracle.evaluate(i) != recovered.evaluate(i) {
                        verified = false;
                        break;
                    }
                }

                if verified {
                    return KeyRecoveryResult::success(
                        iterations,
                        collected_ios.len(),
                        start.elapsed(),
                        recovered,
                        format!(
                            "Recovered {} control functions with {} DIPs",
                            num_gates,
                            collected_ios.len()
                        ),
                    );
                }
            }

            if let Some(dip) = self.find_dip(
                num_wires,
                known_structure,
                &cf_options,
                &collected_ios,
                &consistent_keys,
            ) {
                let output = oracle.evaluate(dip);
                collected_ios.push((dip, output));
                iterations += 1;
            } else {
                if !consistent_keys.is_empty() {
                    let gates: Vec<Gate> = known_structure
                        .iter()
                        .zip(consistent_keys[0].iter())
                        .map(|(&(a, c1, c2), &cf)| Gate::new(a, c1, c2, cf))
                        .collect();
                    let recovered = Circuit::from_gates(gates, num_wires);

                    return KeyRecoveryResult::success(
                        iterations,
                        collected_ios.len(),
                        start.elapsed(),
                        recovered,
                        format!(
                            "Converged with {} candidate keys, {} DIPs",
                            consistent_keys.len(),
                            collected_ios.len()
                        ),
                    );
                }

                return KeyRecoveryResult::failed(
                    iterations,
                    start.elapsed(),
                    "No distinguishing input found".to_string(),
                );
            }
        }
    }

    fn find_consistent_keys(
        &self,
        num_wires: usize,
        structure: &[(u8, u8, u8)],
        cf_options: &[ControlFunction],
        ios: &[(usize, usize)],
    ) -> Vec<Vec<ControlFunction>> {
        let num_gates = structure.len();
        if num_gates > 4 {
            return self.find_consistent_keys_sat(num_wires, structure, ios);
        }

        let mut consistent = Vec::new();
        let total_combinations = cf_options.len().pow(num_gates as u32);

        for combo_idx in 0..total_combinations {
            let mut cf_assignment = Vec::with_capacity(num_gates);
            let mut idx = combo_idx;
            for _ in 0..num_gates {
                cf_assignment.push(cf_options[idx % cf_options.len()]);
                idx /= cf_options.len();
            }

            let gates: Vec<Gate> = structure
                .iter()
                .zip(cf_assignment.iter())
                .map(|(&(a, c1, c2), &cf)| Gate::new(a, c1, c2, cf))
                .collect();
            let test_circuit = Circuit::from_gates(gates, num_wires);

            let matches = ios
                .iter()
                .all(|&(input, output)| test_circuit.evaluate(input) == output);

            if matches {
                consistent.push(cf_assignment);
            }
        }

        consistent
    }

    fn find_consistent_keys_sat(
        &self,
        num_wires: usize,
        structure: &[(u8, u8, u8)],
        ios: &[(usize, usize)],
    ) -> Vec<Vec<ControlFunction>> {
        let num_gates = structure.len();
        let mut encoder = SatEncoder::new(num_wires);
        let mut cnf = CnfFormula::new();

        let cf_vars: Vec<Vec<Var>> = (0..num_gates).map(|_| encoder.fresh_vars(4)).collect();

        for &(input, output) in ios {
            let mut state_vars = encoder.fresh_vars(num_wires);

            for (w, var) in state_vars.iter().enumerate() {
                let bit = (input >> w) & 1 == 1;
                cnf.add_clause(&[if bit {
                    Lit::positive(*var)
                } else {
                    !Lit::positive(*var)
                }]);
            }

            for (gate_idx, &(active, c1, c2)) in structure.iter().enumerate() {
                let next_state = encoder.fresh_vars(num_wires);

                let ctrl_out = encoder.fresh_var();
                self.encode_parameterized_gate(
                    &mut encoder,
                    &mut cnf,
                    &cf_vars[gate_idx],
                    Lit::positive(state_vars[c1 as usize]),
                    Lit::positive(state_vars[c2 as usize]),
                    Lit::positive(ctrl_out),
                );

                encoder.encode_xor(
                    &mut cnf,
                    Lit::positive(state_vars[active as usize]),
                    Lit::positive(ctrl_out),
                    Lit::positive(next_state[active as usize]),
                );

                for w in 0..num_wires {
                    if w != active as usize {
                        cnf.add_clause(&[
                            !Lit::positive(state_vars[w]),
                            Lit::positive(next_state[w]),
                        ]);
                        cnf.add_clause(&[
                            Lit::positive(state_vars[w]),
                            !Lit::positive(next_state[w]),
                        ]);
                    }
                }

                state_vars = next_state;
            }

            for (w, var) in state_vars.iter().enumerate() {
                let bit = (output >> w) & 1 == 1;
                cnf.add_clause(&[if bit {
                    Lit::positive(*var)
                } else {
                    !Lit::positive(*var)
                }]);
            }
        }

        let mut solver = Solver::new();
        solver.add_formula(&cnf);

        let mut solutions = Vec::new();
        let max_solutions = 100;

        while solutions.len() < max_solutions {
            match solver.solve() {
                Ok(true) => {
                    let model = solver.model().unwrap();

                    let cf_assignment: Vec<ControlFunction> = cf_vars
                        .iter()
                        .map(|vars| {
                            let mut cf_val = 0u8;
                            for (bit, &var) in vars.iter().enumerate() {
                                if model
                                    .iter()
                                    .any(|&lit| lit.var() == var && lit.is_positive())
                                {
                                    cf_val |= 1 << bit;
                                }
                            }
                            ControlFunction::from_u8(cf_val)
                        })
                        .collect();

                    let blocking: Vec<Lit> = cf_vars
                        .iter()
                        .zip(cf_assignment.iter())
                        .flat_map(|(vars, &cf)| {
                            let cf_val = cf as u8;
                            vars.iter().enumerate().map(move |(bit, &var)| {
                                if (cf_val >> bit) & 1 == 1 {
                                    !Lit::positive(var)
                                } else {
                                    Lit::positive(var)
                                }
                            })
                        })
                        .collect();

                    let mut blocking_cnf = CnfFormula::new();
                    blocking_cnf.add_clause(&blocking);
                    solver.add_formula(&blocking_cnf);

                    solutions.push(cf_assignment);
                }
                Ok(false) => break,
                Err(_) => break,
            }
        }

        solutions
    }

    fn encode_parameterized_gate(
        &self,
        encoder: &mut SatEncoder,
        cnf: &mut CnfFormula,
        cf_bits: &[Var],
        a: Lit,
        b: Lit,
        out: Lit,
    ) {
        let mux_out = encoder.fresh_var();

        let sel0 = encoder.fresh_var();
        let sel1 = encoder.fresh_var();

        cnf.add_clause(&[!a, Lit::positive(sel1)]);
        cnf.add_clause(&[a, !Lit::positive(sel1)]);
        cnf.add_clause(&[!b, Lit::positive(sel0)]);
        cnf.add_clause(&[b, !Lit::positive(sel0)]);

        for i in 0..4 {
            let s0_lit = if i & 1 == 1 {
                Lit::positive(sel0)
            } else {
                !Lit::positive(sel0)
            };
            let s1_lit = if i & 2 == 2 {
                Lit::positive(sel1)
            } else {
                !Lit::positive(sel1)
            };

            cnf.add_clause(&[
                !s0_lit,
                !s1_lit,
                !Lit::positive(cf_bits[i]),
                Lit::positive(mux_out),
            ]);
            cnf.add_clause(&[
                !s0_lit,
                !s1_lit,
                Lit::positive(cf_bits[i]),
                !Lit::positive(mux_out),
            ]);
        }

        cnf.add_clause(&[!Lit::positive(mux_out), out]);
        cnf.add_clause(&[Lit::positive(mux_out), !out]);
    }

    fn find_dip(
        &self,
        num_wires: usize,
        structure: &[(u8, u8, u8)],
        cf_options: &[ControlFunction],
        _ios: &[(usize, usize)],
        consistent_keys: &[Vec<ControlFunction>],
    ) -> Option<usize> {
        if consistent_keys.len() < 2 {
            return None;
        }

        let circuits: Vec<Circuit> = consistent_keys
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

        let _ = cf_options;

        for input in 0..(1 << num_wires.min(12)) {
            let first_output = circuits[0].evaluate(input);
            for circuit in circuits.iter().skip(1) {
                if circuit.evaluate(input) != first_output {
                    return Some(input);
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_recovery_small_circuit() {
        let oracle = Circuit::random_r57(4, 2);
        let structure: Vec<(u8, u8, u8)> = oracle
            .gates
            .iter()
            .map(|g| (g.pins[0], g.pins[1], g.pins[2]))
            .collect();

        let attack = KeyRecoveryAttack::new().with_max_iterations(100);
        let result = attack.attack_gate_parameters(&oracle, &structure);

        println!("Key recovery result: {:?}", result);

        if result.success {
            let recovered = result.recovered_circuit.unwrap();
            for input in 0..16 {
                assert_eq!(
                    oracle.evaluate(input),
                    recovered.evaluate(input),
                    "Mismatch at input {}",
                    input
                );
            }
        }
    }

    #[test]
    fn test_key_recovery_varied_control_functions() {
        let oracle = Circuit::random(4, 3);
        let structure: Vec<(u8, u8, u8)> = oracle
            .gates
            .iter()
            .map(|g| (g.pins[0], g.pins[1], g.pins[2]))
            .collect();

        let attack = KeyRecoveryAttack::new().with_max_iterations(200);
        let result = attack.attack_gate_parameters(&oracle, &structure);

        println!(
            "Varied CF recovery: success={}, iterations={}, DIPs={}",
            result.success, result.iterations, result.dips_found
        );
    }

    #[test]
    fn test_dip_count_vs_circuit_size() {
        for num_gates in [2, 3, 4] {
            let oracle = Circuit::random_r57(4, num_gates);
            let structure: Vec<(u8, u8, u8)> = oracle
                .gates
                .iter()
                .map(|g| (g.pins[0], g.pins[1], g.pins[2]))
                .collect();

            let attack = KeyRecoveryAttack::new().with_max_iterations(500);
            let result = attack.attack_gate_parameters(&oracle, &structure);

            println!(
                "Gates={}: success={}, DIPs={}, time={:?}",
                num_gates, result.success, result.dips_found, result.time_elapsed
            );
        }
    }
}
