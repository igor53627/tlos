//! Circuit Equivalence Attack
//!
//! Tests whether SAT can find equivalent circuits without knowing the original
//! structure. This is the key security question for MinCore: can an attacker
//! synthesize a functionally equivalent circuit from I/O observations?

use super::sat_encoder::SatEncoder;
use crate::circuit::{Circuit, Gate};
use crate::control_function::ControlFunction;
use std::time::{Duration, Instant};
use varisat::{CnfFormula, ExtendFormula, Lit, Solver, Var};

#[derive(Debug, Clone)]
pub struct EquivalenceAttackResult {
    pub equivalent_found: bool,
    pub candidate_circuits: usize,
    pub queries_used: usize,
    pub time_elapsed: Duration,
    pub synthesis_successful: bool,
    pub synthesized_circuit: Option<Circuit>,
    pub details: String,
}

impl EquivalenceAttackResult {
    pub fn failed(queries: usize, time: Duration, details: String) -> Self {
        Self {
            equivalent_found: false,
            candidate_circuits: 0,
            queries_used: queries,
            time_elapsed: time,
            synthesis_successful: false,
            synthesized_circuit: None,
            details,
        }
    }
}

pub struct EquivalenceAttack {
    max_queries: usize,
    max_circuit_size: usize,
    timeout: Duration,
}

impl Default for EquivalenceAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl EquivalenceAttack {
    pub fn new() -> Self {
        Self {
            max_queries: 1000,
            max_circuit_size: 20,
            timeout: Duration::from_secs(120),
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

    pub fn check_equivalence(&self, c1: &Circuit, c2: &Circuit) -> Option<usize> {
        if c1.num_wires != c2.num_wires {
            return Some(0);
        }

        let mut encoder = SatEncoder::new(c1.num_wires);
        let mut cnf = CnfFormula::new();

        let (in1, out1) = encoder.encode_circuit(&mut cnf, c1);

        let in2 = in1.clone();
        let mut state2 = in2.clone();
        for (i, gate) in c2.gates.iter().enumerate() {
            let next = encoder.allocate_wire_vars(c1.gates.len() + i + 1);
            encoder.encode_gate(&mut cnf, gate, &state2, &next);
            state2 = next;
        }
        let out2 = state2;

        encoder.encode_not_equal(&mut cnf, &out1, &out2);

        let mut solver = Solver::new();
        solver.add_formula(&cnf);

        match solver.solve() {
            Ok(true) => {
                let model = solver.model().unwrap();
                let input = self.extract_value(&model, &in1);
                Some(input)
            }
            Ok(false) => None,
            Err(_) => Some(0),
        }
    }

    fn extract_value(&self, model: &[Lit], vars: &[Var]) -> usize {
        let mut value = 0usize;
        for (i, &var) in vars.iter().enumerate() {
            if model
                .iter()
                .any(|&lit| lit.var() == var && lit.is_positive())
            {
                value |= 1 << i;
            }
        }
        value
    }

    pub fn synthesize_equivalent(
        &self,
        oracle: impl Fn(usize) -> usize,
        num_wires: usize,
        max_gates: usize,
    ) -> EquivalenceAttackResult {
        let start = Instant::now();
        let mut queries = 0;

        let sample_size = (1 << num_wires.min(8)).min(self.max_queries);
        let mut io_samples: Vec<(usize, usize)> = Vec::with_capacity(sample_size);

        for input in 0..sample_size {
            if start.elapsed() > self.timeout {
                return EquivalenceAttackResult::failed(
                    queries,
                    start.elapsed(),
                    "Timeout during sampling".to_string(),
                );
            }
            let output = oracle(input);
            io_samples.push((input, output));
            queries += 1;
        }

        for num_gates in 1..=max_gates {
            if start.elapsed() > self.timeout {
                return EquivalenceAttackResult::failed(
                    queries,
                    start.elapsed(),
                    format!("Timeout at {} gates", num_gates),
                );
            }

            if let Some(circuit) = self.try_synthesize(num_wires, num_gates, &io_samples) {
                let mut all_match = true;
                for input in 0..(1 << num_wires.min(10)) {
                    if circuit.evaluate(input) != oracle(input) {
                        all_match = false;
                        break;
                    }
                    queries += 1;
                }

                if all_match {
                    return EquivalenceAttackResult {
                        equivalent_found: true,
                        candidate_circuits: 1,
                        queries_used: queries,
                        time_elapsed: start.elapsed(),
                        synthesis_successful: true,
                        synthesized_circuit: Some(circuit),
                        details: format!(
                            "Synthesized equivalent with {} gates, {} queries",
                            num_gates, queries
                        ),
                    };
                }
            }
        }

        EquivalenceAttackResult::failed(
            queries,
            start.elapsed(),
            format!(
                "Could not synthesize equivalent circuit up to {} gates",
                max_gates
            ),
        )
    }

    fn try_synthesize(
        &self,
        num_wires: usize,
        num_gates: usize,
        io_samples: &[(usize, usize)],
    ) -> Option<Circuit> {
        let mut encoder = SatEncoder::new(num_wires);
        let mut cnf = CnfFormula::new();

        let gate_params: Vec<GateParams> = (0..num_gates)
            .map(|_| GateParams {
                active: encoder.fresh_vars(log2_ceil(num_wires)),
                c1: encoder.fresh_vars(log2_ceil(num_wires)),
                c2: encoder.fresh_vars(log2_ceil(num_wires)),
                cf: encoder.fresh_vars(4),
            })
            .collect();

        for (input, output) in io_samples.iter().take(64) {
            self.encode_synthesis_constraint(
                &mut encoder,
                &mut cnf,
                num_wires,
                &gate_params,
                *input,
                *output,
            );
        }

        let mut solver = Solver::new();
        solver.add_formula(&cnf);

        match solver.solve() {
            Ok(true) => {
                let model = solver.model().unwrap();
                Some(self.extract_circuit(&model, num_wires, &gate_params))
            }
            _ => None,
        }
    }

    fn encode_synthesis_constraint(
        &self,
        encoder: &mut SatEncoder,
        cnf: &mut CnfFormula,
        num_wires: usize,
        gate_params: &[GateParams],
        input: usize,
        output: usize,
    ) {
        let mut state: Vec<Var> = encoder.fresh_vars(num_wires);

        for (w, var) in state.iter().enumerate() {
            let bit = (input >> w) & 1 == 1;
            cnf.add_clause(&[if bit {
                Lit::positive(*var)
            } else {
                !Lit::positive(*var)
            }]);
        }

        for params in gate_params {
            let next_state = encoder.fresh_vars(num_wires);

            for active_wire in 0..num_wires {
                let active_selected =
                    self.encode_wire_selected(encoder, cnf, &params.active, active_wire, num_wires);

                let c1_bits: Vec<Var> = (0..num_wires)
                    .map(|w| {
                        let selected =
                            self.encode_wire_selected(encoder, cnf, &params.c1, w, num_wires);
                        let result = encoder.fresh_var();
                        cnf.add_clause(&[
                            !Lit::positive(selected),
                            !Lit::positive(state[w]),
                            Lit::positive(result),
                        ]);
                        cnf.add_clause(&[
                            !Lit::positive(selected),
                            Lit::positive(state[w]),
                            !Lit::positive(result),
                        ]);
                        result
                    })
                    .collect();

                let c1_val = encoder.fresh_var();
                let c1_lits: Vec<Lit> = c1_bits.iter().map(|&v| Lit::positive(v)).collect();
                cnf.add_clause(
                    &c1_lits
                        .iter()
                        .chain(std::iter::once(&!Lit::positive(c1_val)))
                        .cloned()
                        .collect::<Vec<_>>(),
                );

                let c2_bits: Vec<Var> = (0..num_wires)
                    .map(|w| {
                        let selected =
                            self.encode_wire_selected(encoder, cnf, &params.c2, w, num_wires);
                        let result = encoder.fresh_var();
                        cnf.add_clause(&[
                            !Lit::positive(selected),
                            !Lit::positive(state[w]),
                            Lit::positive(result),
                        ]);
                        cnf.add_clause(&[
                            !Lit::positive(selected),
                            Lit::positive(state[w]),
                            !Lit::positive(result),
                        ]);
                        result
                    })
                    .collect();

                let c2_val = encoder.fresh_var();
                let c2_lits: Vec<Lit> = c2_bits.iter().map(|&v| Lit::positive(v)).collect();
                cnf.add_clause(
                    &c2_lits
                        .iter()
                        .chain(std::iter::once(&!Lit::positive(c2_val)))
                        .cloned()
                        .collect::<Vec<_>>(),
                );

                let ctrl_out = encoder.fresh_var();
                self.encode_mux_control_function(
                    encoder,
                    cnf,
                    &params.cf,
                    Lit::positive(c1_val),
                    Lit::positive(c2_val),
                    Lit::positive(ctrl_out),
                );

                let new_active_bit = encoder.fresh_var();
                encoder.encode_xor(
                    cnf,
                    Lit::positive(state[active_wire]),
                    Lit::positive(ctrl_out),
                    Lit::positive(new_active_bit),
                );

                cnf.add_clause(&[
                    !Lit::positive(active_selected),
                    !Lit::positive(new_active_bit),
                    Lit::positive(next_state[active_wire]),
                ]);
                cnf.add_clause(&[
                    !Lit::positive(active_selected),
                    Lit::positive(new_active_bit),
                    !Lit::positive(next_state[active_wire]),
                ]);

                for other_wire in 0..num_wires {
                    if other_wire != active_wire {
                        cnf.add_clause(&[
                            !Lit::positive(active_selected),
                            !Lit::positive(state[other_wire]),
                            Lit::positive(next_state[other_wire]),
                        ]);
                        cnf.add_clause(&[
                            !Lit::positive(active_selected),
                            Lit::positive(state[other_wire]),
                            !Lit::positive(next_state[other_wire]),
                        ]);
                    }
                }
            }

            state = next_state;
        }

        for (w, var) in state.iter().enumerate() {
            let bit = (output >> w) & 1 == 1;
            cnf.add_clause(&[if bit {
                Lit::positive(*var)
            } else {
                !Lit::positive(*var)
            }]);
        }
    }

    fn encode_wire_selected(
        &self,
        encoder: &mut SatEncoder,
        cnf: &mut CnfFormula,
        selector_bits: &[Var],
        target_wire: usize,
        num_wires: usize,
    ) -> Var {
        let result = encoder.fresh_var();

        if target_wire >= num_wires {
            cnf.add_clause(&[!Lit::positive(result)]);
            return result;
        }

        let mut clause = vec![Lit::positive(result)];
        for (bit_idx, &sel_var) in selector_bits.iter().enumerate() {
            let target_bit = (target_wire >> bit_idx) & 1 == 1;
            clause.push(if target_bit {
                !Lit::positive(sel_var)
            } else {
                Lit::positive(sel_var)
            });
        }
        cnf.add_clause(&clause);

        result
    }

    fn encode_mux_control_function(
        &self,
        encoder: &mut SatEncoder,
        cnf: &mut CnfFormula,
        cf_bits: &[Var],
        a: Lit,
        b: Lit,
        out: Lit,
    ) {
        for i in 0..4 {
            let a_lit = if i & 2 == 2 { a } else { !a };
            let b_lit = if i & 1 == 1 { b } else { !b };
            let cf_lit = Lit::positive(cf_bits[i]);

            cnf.add_clause(&[!a_lit, !b_lit, !cf_lit, out]);
            cnf.add_clause(&[!a_lit, !b_lit, cf_lit, !out]);
        }
    }

    fn extract_circuit(
        &self,
        model: &[Lit],
        num_wires: usize,
        gate_params: &[GateParams],
    ) -> Circuit {
        let gates: Vec<Gate> = gate_params
            .iter()
            .map(|params| {
                let active = self.extract_wire_value(model, &params.active) as u8 % num_wires as u8;
                let c1 = self.extract_wire_value(model, &params.c1) as u8 % num_wires as u8;
                let c2 = self.extract_wire_value(model, &params.c2) as u8 % num_wires as u8;
                let cf = self.extract_cf_value(model, &params.cf);

                let c1 = if c1 == active {
                    (c1 + 1) % num_wires as u8
                } else {
                    c1
                };
                let c2 = if c2 == active || c2 == c1 {
                    ((c2 + 1) % num_wires as u8).max((c1 + 1) % num_wires as u8)
                } else {
                    c2
                };

                Gate::new(active, c1, c2, cf)
            })
            .collect();

        Circuit::from_gates(gates, num_wires)
    }

    fn extract_wire_value(&self, model: &[Lit], bits: &[Var]) -> usize {
        let mut value = 0;
        for (i, &var) in bits.iter().enumerate() {
            if model
                .iter()
                .any(|&lit| lit.var() == var && lit.is_positive())
            {
                value |= 1 << i;
            }
        }
        value
    }

    fn extract_cf_value(&self, model: &[Lit], bits: &[Var]) -> ControlFunction {
        let mut value = 0u8;
        for (i, &var) in bits.iter().enumerate() {
            if model
                .iter()
                .any(|&lit| lit.var() == var && lit.is_positive())
            {
                value |= 1 << i;
            }
        }
        ControlFunction::from_u8(value)
    }
}

struct GateParams {
    active: Vec<Var>,
    c1: Vec<Var>,
    c2: Vec<Var>,
    cf: Vec<Var>,
}

fn log2_ceil(n: usize) -> usize {
    if n <= 1 {
        1
    } else {
        (usize::BITS - (n - 1).leading_zeros()) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_equivalence_identical() {
        let c1 = Circuit::random_r57(4, 5);
        let c2 = c1.clone();

        let attack = EquivalenceAttack::new();
        let counterexample = attack.check_equivalence(&c1, &c2);

        assert!(
            counterexample.is_none(),
            "Identical circuits should be equivalent"
        );
    }

    #[test]
    fn test_check_equivalence_different() {
        let c1 = Circuit::random_r57(4, 5);
        let c2 = Circuit::random_r57(4, 5);

        let attack = EquivalenceAttack::new();
        let counterexample = attack.check_equivalence(&c1, &c2);

        if let Some(ce) = counterexample {
            assert_ne!(
                c1.evaluate(ce),
                c2.evaluate(ce),
                "Counterexample should distinguish circuits"
            );
        }
    }

    #[test]
    fn test_check_equivalence_identity_variants() {
        let forward = Circuit::random_r57(4, 3);
        let mut identity1 = forward.clone();
        identity1.gates.extend(forward.gates.iter().rev().cloned());

        let identity2 = Circuit::new(4);

        let attack = EquivalenceAttack::new();
        let counterexample = attack.check_equivalence(&identity1, &identity2);

        assert!(
            counterexample.is_none(),
            "Identity circuit should equal empty circuit"
        );
    }

    #[test]
    fn test_synthesis_simple() {
        let target = Circuit::random_r57(3, 2);
        let oracle = |input: usize| target.evaluate(input);

        let attack = EquivalenceAttack::new()
            .with_max_circuit_size(5)
            .with_timeout(Duration::from_secs(10));

        let result = attack.synthesize_equivalent(oracle, 3, 5);

        println!(
            "Synthesis result: success={}, queries={}, time={:?}",
            result.synthesis_successful, result.queries_used, result.time_elapsed
        );

        if result.synthesis_successful {
            let synth = result.synthesized_circuit.unwrap();
            for input in 0..8 {
                assert_eq!(
                    target.evaluate(input),
                    synth.evaluate(input),
                    "Synthesized circuit mismatch at input {}",
                    input
                );
            }
        }
    }

    #[test]
    fn test_synthesis_complexity_scaling() {
        for num_gates in [1, 2, 3] {
            let target = Circuit::random_r57(3, num_gates);
            let oracle = |input: usize| target.evaluate(input);

            let attack = EquivalenceAttack::new()
                .with_max_circuit_size(num_gates + 2)
                .with_timeout(Duration::from_secs(5));

            let start = Instant::now();
            let result = attack.synthesize_equivalent(oracle, 3, num_gates + 2);
            let elapsed = start.elapsed();

            println!(
                "Gates={}: success={}, queries={}, time={:?}",
                num_gates, result.synthesis_successful, result.queries_used, elapsed
            );
        }
    }
}
