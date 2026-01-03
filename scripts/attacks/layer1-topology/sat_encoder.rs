//! SAT Encoder for Reversible Circuits
//!
//! Converts reversible circuits to CNF formulas for SAT-based attacks.
//! Based on the SAT attack literature (Subramanyan et al., HOST 2015).

use crate::circuit::{Circuit, Gate};
use crate::control_function::ControlFunction;
use varisat::{CnfFormula, ExtendFormula, Lit, Var};

#[derive(Debug, Clone)]
pub struct SatEncoder {
    next_var: usize,
    num_wires: usize,
}

impl SatEncoder {
    pub fn new(num_wires: usize) -> Self {
        Self {
            next_var: 1,
            num_wires,
        }
    }

    pub fn fresh_var(&mut self) -> Var {
        let v = Var::from_dimacs(self.next_var as isize);
        self.next_var += 1;
        v
    }

    pub fn fresh_vars(&mut self, count: usize) -> Vec<Var> {
        (0..count).map(|_| self.fresh_var()).collect()
    }

    pub fn allocate_wire_vars(&mut self, time_step: usize) -> Vec<Var> {
        let _ = time_step;
        self.fresh_vars(self.num_wires)
    }

    pub fn encode_control_function(
        &mut self,
        cnf: &mut CnfFormula,
        cf: ControlFunction,
        a: Lit,
        b: Lit,
        out: Lit,
    ) {
        for i in 0..4u8 {
            let a_val = (i >> 1) & 1 == 1;
            let b_val = i & 1 == 1;
            let out_val = cf.evaluate(a_val, b_val);

            let lit_a = if a_val { a } else { !a };
            let lit_b = if b_val { b } else { !b };

            if out_val {
                cnf.add_clause(&[!lit_a, !lit_b, out]);
            } else {
                cnf.add_clause(&[!lit_a, !lit_b, !out]);
            }
        }
    }

    pub fn encode_gate(
        &mut self,
        cnf: &mut CnfFormula,
        gate: &Gate,
        state_in: &[Var],
        state_out: &[Var],
    ) {
        let active = gate.pins[0] as usize;
        let c1 = gate.pins[1] as usize;
        let c2 = gate.pins[2] as usize;

        for w in 0..self.num_wires {
            if w == active {
                let ctrl_out = self.fresh_var();
                self.encode_control_function(
                    cnf,
                    gate.control_function,
                    Lit::positive(state_in[c1]),
                    Lit::positive(state_in[c2]),
                    Lit::positive(ctrl_out),
                );
                self.encode_xor(
                    cnf,
                    Lit::positive(state_in[active]),
                    Lit::positive(ctrl_out),
                    Lit::positive(state_out[active]),
                );
            } else {
                cnf.add_clause(&[!Lit::positive(state_in[w]), Lit::positive(state_out[w])]);
                cnf.add_clause(&[Lit::positive(state_in[w]), !Lit::positive(state_out[w])]);
            }
        }
    }

    pub fn encode_xor(&mut self, cnf: &mut CnfFormula, a: Lit, b: Lit, out: Lit) {
        cnf.add_clause(&[!a, !b, !out]);
        cnf.add_clause(&[!a, b, out]);
        cnf.add_clause(&[a, !b, out]);
        cnf.add_clause(&[a, b, !out]);
    }

    pub fn encode_circuit(
        &mut self,
        cnf: &mut CnfFormula,
        circuit: &Circuit,
    ) -> (Vec<Var>, Vec<Var>) {
        let mut state = self.allocate_wire_vars(0);
        let input_vars = state.clone();

        for (i, gate) in circuit.gates.iter().enumerate() {
            let next_state = self.allocate_wire_vars(i + 1);
            self.encode_gate(cnf, gate, &state, &next_state);
            state = next_state;
        }

        (input_vars, state)
    }

    pub fn encode_io_constraint(&mut self, cnf: &mut CnfFormula, vars: &[Var], values: usize) {
        for (i, &var) in vars.iter().enumerate() {
            let bit = (values >> i) & 1 == 1;
            let lit = if bit {
                Lit::positive(var)
            } else {
                !Lit::positive(var)
            };
            cnf.add_clause(&[lit]);
        }
    }

    pub fn encode_not_equal(&mut self, cnf: &mut CnfFormula, a: &[Var], b: &[Var]) {
        let diffs: Vec<Var> = a
            .iter()
            .zip(b.iter())
            .map(|(&va, &vb)| {
                let diff = self.fresh_var();
                self.encode_xor(
                    cnf,
                    Lit::positive(va),
                    Lit::positive(vb),
                    Lit::positive(diff),
                );
                diff
            })
            .collect();

        let diff_lits: Vec<Lit> = diffs.iter().map(|&v| Lit::positive(v)).collect();
        cnf.add_clause(&diff_lits);
    }
}

#[derive(Debug)]
pub struct CircuitSatFormula {
    pub cnf: CnfFormula,
    pub input_vars: Vec<Var>,
    pub output_vars: Vec<Var>,
    pub num_vars: usize,
    pub num_clauses: usize,
}

impl CircuitSatFormula {
    pub fn from_circuit(circuit: &Circuit) -> Self {
        let mut encoder = SatEncoder::new(circuit.num_wires);
        let mut cnf = CnfFormula::new();
        let (input_vars, output_vars) = encoder.encode_circuit(&mut cnf, circuit);

        Self {
            num_vars: encoder.next_var - 1,
            num_clauses: cnf.len(),
            cnf,
            input_vars,
            output_vars,
        }
    }

    pub fn with_io_constraints(circuit: &Circuit, input: usize, output: usize) -> Self {
        let mut encoder = SatEncoder::new(circuit.num_wires);
        let mut cnf = CnfFormula::new();
        let (input_vars, output_vars) = encoder.encode_circuit(&mut cnf, circuit);

        encoder.encode_io_constraint(&mut cnf, &input_vars, input);
        encoder.encode_io_constraint(&mut cnf, &output_vars, output);

        Self {
            num_vars: encoder.next_var - 1,
            num_clauses: cnf.len(),
            cnf,
            input_vars,
            output_vars,
        }
    }
}

#[derive(Debug)]
pub struct DipFormula {
    pub cnf: CnfFormula,
    pub input_vars: Vec<Var>,
    pub output1_vars: Vec<Var>,
    pub output2_vars: Vec<Var>,
    pub key1_vars: Vec<Var>,
    pub key2_vars: Vec<Var>,
    pub num_vars: usize,
}

impl DipFormula {
    pub fn new(circuit: &Circuit, key_bits: usize) -> Self {
        let mut encoder = SatEncoder::new(circuit.num_wires);
        let mut cnf = CnfFormula::new();

        let input_vars = encoder.fresh_vars(circuit.num_wires);
        let key1_vars = encoder.fresh_vars(key_bits);
        let key2_vars = encoder.fresh_vars(key_bits);

        let state1 = input_vars.clone();
        let mut current1 = state1.clone();
        for (i, gate) in circuit.gates.iter().enumerate() {
            let next = encoder.allocate_wire_vars(i + 1);
            encoder.encode_gate(&mut cnf, gate, &current1, &next);
            current1 = next;
        }
        let output1_vars = current1;

        let state2 = input_vars.clone();
        let mut current2 = state2;
        for (i, gate) in circuit.gates.iter().enumerate() {
            let next = encoder.allocate_wire_vars(circuit.gates.len() + i + 1);
            encoder.encode_gate(&mut cnf, gate, &current2, &next);
            current2 = next;
        }
        let output2_vars = current2;

        encoder.encode_not_equal(&mut cnf, &output1_vars, &output2_vars);
        encoder.encode_not_equal(&mut cnf, &key1_vars, &key2_vars);

        Self {
            num_vars: encoder.next_var - 1,
            cnf,
            input_vars,
            output1_vars,
            output2_vars,
            key1_vars,
            key2_vars,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use varisat::Solver;

    #[test]
    fn test_encode_simple_circuit() {
        let circuit = Circuit::random_r57(4, 3);
        let formula = CircuitSatFormula::from_circuit(&circuit);

        assert!(formula.num_vars > 0);
        assert!(formula.num_clauses > 0);
        assert_eq!(formula.input_vars.len(), 4);
        assert_eq!(formula.output_vars.len(), 4);
    }

    #[test]
    fn test_encode_with_io_constraints() {
        let circuit = Circuit::random_r57(4, 5);
        let input = 0b1010;
        let expected_output = circuit.evaluate(input);

        let formula = CircuitSatFormula::with_io_constraints(&circuit, input, expected_output);

        let mut solver = Solver::new();
        solver.add_formula(&formula.cnf);

        let result = solver.solve().unwrap();
        assert!(result, "SAT formula with correct I/O should be satisfiable");
    }

    #[test]
    fn test_incorrect_io_unsatisfiable() {
        let circuit = Circuit::random_r57(4, 5);
        let input = 0b1010;
        let expected_output = circuit.evaluate(input);
        let wrong_output = expected_output ^ 1;

        let formula = CircuitSatFormula::with_io_constraints(&circuit, input, wrong_output);

        let mut solver = Solver::new();
        solver.add_formula(&formula.cnf);

        let result = solver.solve().unwrap();
        assert!(
            !result,
            "SAT formula with wrong I/O should be unsatisfiable"
        );
    }

    #[test]
    fn test_xor_encoding() {
        for a_val in [false, true] {
            for b_val in [false, true] {
                let expected = a_val ^ b_val;

                let mut encoder = SatEncoder::new(4);
                let mut cnf = CnfFormula::new();

                let a = encoder.fresh_var();
                let b = encoder.fresh_var();
                let out = encoder.fresh_var();

                encoder.encode_xor(
                    &mut cnf,
                    Lit::positive(a),
                    Lit::positive(b),
                    Lit::positive(out),
                );

                cnf.add_clause(&[if a_val {
                    Lit::positive(a)
                } else {
                    !Lit::positive(a)
                }]);
                cnf.add_clause(&[if b_val {
                    Lit::positive(b)
                } else {
                    !Lit::positive(b)
                }]);
                cnf.add_clause(&[if expected {
                    Lit::positive(out)
                } else {
                    !Lit::positive(out)
                }]);

                let mut solver = Solver::new();
                solver.add_formula(&cnf);
                assert!(
                    solver.solve().unwrap(),
                    "XOR({}, {}) = {} should be satisfiable",
                    a_val,
                    b_val,
                    expected
                );
            }
        }
    }

    #[test]
    fn test_control_function_encoding() {
        let mut encoder = SatEncoder::new(4);

        for cf in [
            ControlFunction::And,
            ControlFunction::Or,
            ControlFunction::Xor,
            ControlFunction::OrNb,
        ] {
            for a_val in [false, true] {
                for b_val in [false, true] {
                    let expected = cf.evaluate(a_val, b_val);

                    let mut cnf = CnfFormula::new();
                    let a = encoder.fresh_var();
                    let b = encoder.fresh_var();
                    let out = encoder.fresh_var();

                    encoder.encode_control_function(
                        &mut cnf,
                        cf,
                        Lit::positive(a),
                        Lit::positive(b),
                        Lit::positive(out),
                    );

                    cnf.add_clause(&[if a_val {
                        Lit::positive(a)
                    } else {
                        !Lit::positive(a)
                    }]);
                    cnf.add_clause(&[if b_val {
                        Lit::positive(b)
                    } else {
                        !Lit::positive(b)
                    }]);
                    cnf.add_clause(&[if expected {
                        Lit::positive(out)
                    } else {
                        !Lit::positive(out)
                    }]);

                    let mut solver = Solver::new();
                    solver.add_formula(&cnf);
                    assert!(
                        solver.solve().unwrap(),
                        "{:?}({}, {}) = {} should be satisfiable",
                        cf,
                        a_val,
                        b_val,
                        expected
                    );
                }
            }
        }
    }
}
