use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[derive(Clone, Debug)]
pub struct Gate {
    pub pins: [u8; 3],
    pub control_function: u8,
}

impl Gate {
    pub fn new(active: u8, control1: u8, control2: u8, control_function: u8) -> Self {
        Self {
            pins: [active, control1, control2],
            control_function,
        }
    }

    pub fn active(&self) -> u8 {
        self.pins[0]
    }

    pub fn control1(&self) -> u8 {
        self.pins[1]
    }

    pub fn control2(&self) -> u8 {
        self.pins[2]
    }

    pub fn truth_table_bit(&self, c1_val: bool, c2_val: bool) -> bool {
        let idx = (c1_val as u8) | ((c2_val as u8) << 1);
        (self.control_function >> idx) & 1 != 0
    }
}

#[derive(Clone, Debug)]
pub struct Circuit {
    pub gates: Vec<Gate>,
    pub num_wires: usize,
}

impl Circuit {
    pub fn new(num_wires: usize) -> Self {
        Self {
            gates: Vec::new(),
            num_wires,
        }
    }

    pub fn add_gate(&mut self, gate: Gate) {
        self.gates.push(gate);
    }

    pub fn evaluate(&self, mut wires: u64) -> u64 {
        for gate in &self.gates {
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
        wires
    }
}

#[derive(Clone, Debug)]
pub struct SixSixConfig {
    pub num_wires: usize,
    pub gates_per_wire: usize,
    pub seed: u64,
}

impl Default for SixSixConfig {
    fn default() -> Self {
        Self {
            num_wires: 64,
            gates_per_wire: 10,
            seed: 0,
        }
    }
}

impl SixSixConfig {
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            ..Default::default()
        }
    }

    pub fn total_gates(&self) -> usize {
        self.num_wires * self.gates_per_wire
    }
}

pub fn create_six_six_circuit(config: &SixSixConfig) -> Circuit {
    let mut rng = ChaCha20Rng::seed_from_u64(config.seed);
    let mut circuit = Circuit::new(config.num_wires);

    for _ in 0..config.total_gates() {
        let active = rng.gen_range(0..config.num_wires as u8);
        let mut control1 = rng.gen_range(0..config.num_wires as u8);
        while control1 == active {
            control1 = rng.gen_range(0..config.num_wires as u8);
        }
        let mut control2 = rng.gen_range(0..config.num_wires as u8);
        while control2 == active || control2 == control1 {
            control2 = rng.gen_range(0..config.num_wires as u8);
        }
        let control_function = rng.gen_range(0..16u8);
        circuit.add_gate(Gate::new(active, control1, control2, control_function));
    }

    circuit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_deterministic() {
        let config1 = SixSixConfig::new(12345);
        let config2 = SixSixConfig::new(12345);
        let c1 = create_six_six_circuit(&config1);
        let c2 = create_six_six_circuit(&config2);
        assert_eq!(c1.gates.len(), c2.gates.len());
        for (g1, g2) in c1.gates.iter().zip(c2.gates.iter()) {
            assert_eq!(g1.pins, g2.pins);
            assert_eq!(g1.control_function, g2.control_function);
        }
    }

    #[test]
    fn test_circuit_size() {
        let config = SixSixConfig::new(0);
        let circuit = create_six_six_circuit(&config);
        assert_eq!(circuit.gates.len(), 640);
        assert_eq!(circuit.num_wires, 64);
    }
}
