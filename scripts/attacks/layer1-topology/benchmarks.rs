//! SAT Attack Benchmarks
//!
//! Systematic benchmarks to evaluate SAT attack effectiveness against
//! MinCore obfuscated circuits at various sizes (64, 128, 256 wires).

use super::equivalence::{EquivalenceAttack, EquivalenceAttackResult};
use super::key_recovery::{KeyRecoveryAttack, KeyRecoveryResult};
use super::oracle_guided::{OracleGuidedAttack, OracleGuidedResult};
use crate::circuit::Circuit;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub circuit_wires: usize,
    pub circuit_gates: usize,
    pub key_recovery: Option<KeyRecoveryResult>,
    pub equivalence: Option<EquivalenceAttackResult>,
    pub oracle_guided: Option<OracleGuidedResult>,
    pub total_time: Duration,
}

#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    pub wire_sizes: Vec<usize>,
    pub gate_multipliers: Vec<usize>,
    pub timeout_per_attack: Duration,
    pub max_queries: usize,
    pub run_key_recovery: bool,
    pub run_equivalence: bool,
    pub run_oracle_guided: bool,
    pub samples_per_config: usize,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            wire_sizes: vec![4, 8, 16],
            gate_multipliers: vec![2, 4, 8],
            timeout_per_attack: Duration::from_secs(30),
            max_queries: 10000,
            run_key_recovery: true,
            run_equivalence: true,
            run_oracle_guided: true,
            samples_per_config: 3,
        }
    }
}

impl BenchmarkConfig {
    pub fn quick() -> Self {
        Self {
            wire_sizes: vec![4, 6],
            gate_multipliers: vec![2, 4],
            timeout_per_attack: Duration::from_secs(10),
            max_queries: 1000,
            run_key_recovery: true,
            run_equivalence: false,
            run_oracle_guided: true,
            samples_per_config: 2,
        }
    }

    pub fn full() -> Self {
        Self {
            wire_sizes: vec![4, 8, 16, 32, 64],
            gate_multipliers: vec![2, 4, 8, 16],
            timeout_per_attack: Duration::from_secs(120),
            max_queries: 100000,
            run_key_recovery: true,
            run_equivalence: true,
            run_oracle_guided: true,
            samples_per_config: 5,
        }
    }

    pub fn mincore_threat_assessment() -> Self {
        Self {
            wire_sizes: vec![64, 128, 256],
            gate_multipliers: vec![4, 8, 16],
            timeout_per_attack: Duration::from_secs(300),
            max_queries: 1000000,
            run_key_recovery: false,
            run_equivalence: false,
            run_oracle_guided: true,
            samples_per_config: 3,
        }
    }
}

pub struct SatAttackBenchmarker {
    config: BenchmarkConfig,
}

impl SatAttackBenchmarker {
    pub fn new(config: BenchmarkConfig) -> Self {
        Self { config }
    }

    pub fn run_all(&self) -> Vec<BenchmarkResult> {
        let mut results = Vec::new();

        for &num_wires in &self.config.wire_sizes {
            for &gate_mult in &self.config.gate_multipliers {
                let num_gates = num_wires * gate_mult;

                for sample in 0..self.config.samples_per_config {
                    println!(
                        "Benchmarking: {} wires, {} gates (sample {}/{})",
                        num_wires,
                        num_gates,
                        sample + 1,
                        self.config.samples_per_config
                    );

                    let result = self.benchmark_single(num_wires, num_gates);
                    results.push(result);
                }
            }
        }

        results
    }

    pub fn benchmark_single(&self, num_wires: usize, num_gates: usize) -> BenchmarkResult {
        let start = Instant::now();
        let circuit = Circuit::random(num_wires, num_gates);

        let key_recovery = if self.config.run_key_recovery && num_gates <= 10 {
            Some(self.run_key_recovery(&circuit))
        } else {
            None
        };

        let equivalence = if self.config.run_equivalence && num_wires <= 8 {
            Some(self.run_equivalence(&circuit))
        } else {
            None
        };

        let oracle_guided = if self.config.run_oracle_guided {
            Some(self.run_oracle_guided(&circuit))
        } else {
            None
        };

        BenchmarkResult {
            circuit_wires: num_wires,
            circuit_gates: num_gates,
            key_recovery,
            equivalence,
            oracle_guided,
            total_time: start.elapsed(),
        }
    }

    fn run_key_recovery(&self, circuit: &Circuit) -> KeyRecoveryResult {
        let structure: Vec<(u8, u8, u8)> = circuit
            .gates
            .iter()
            .map(|g| (g.pins[0], g.pins[1], g.pins[2]))
            .collect();

        let attack = KeyRecoveryAttack::new()
            .with_max_iterations(1000)
            .with_timeout(self.config.timeout_per_attack);

        attack.attack_gate_parameters(circuit, &structure)
    }

    fn run_equivalence(&self, circuit: &Circuit) -> EquivalenceAttackResult {
        let oracle = |input: usize| circuit.evaluate(input);

        let attack = EquivalenceAttack::new()
            .with_max_queries(self.config.max_queries)
            .with_max_circuit_size(circuit.gates.len() + 5)
            .with_timeout(self.config.timeout_per_attack);

        attack.synthesize_equivalent(oracle, circuit.num_wires, circuit.gates.len() + 5)
    }

    fn run_oracle_guided(&self, circuit: &Circuit) -> OracleGuidedResult {
        let oracle = |input: usize| circuit.evaluate(input);

        let attack = OracleGuidedAttack::new()
            .with_max_queries(self.config.max_queries)
            .with_max_circuit_size(circuit.gates.len() + 10)
            .with_timeout(self.config.timeout_per_attack);

        attack.exact_learning(oracle, circuit.num_wires)
    }
}

#[derive(Debug, Clone)]
pub struct BenchmarkSummary {
    pub total_circuits: usize,
    pub key_recovery_attempts: usize,
    pub key_recovery_successes: usize,
    pub equivalence_attempts: usize,
    pub equivalence_successes: usize,
    pub oracle_guided_attempts: usize,
    pub oracle_guided_successes: usize,
    pub avg_key_recovery_time: Duration,
    pub avg_oracle_queries: f64,
}

impl BenchmarkSummary {
    pub fn from_results(results: &[BenchmarkResult]) -> Self {
        let total_circuits = results.len();

        let key_recovery_attempts = results.iter().filter(|r| r.key_recovery.is_some()).count();
        let key_recovery_successes = results
            .iter()
            .filter_map(|r| r.key_recovery.as_ref())
            .filter(|kr| kr.success)
            .count();

        let equivalence_attempts = results.iter().filter(|r| r.equivalence.is_some()).count();
        let equivalence_successes = results
            .iter()
            .filter_map(|r| r.equivalence.as_ref())
            .filter(|e| e.synthesis_successful)
            .count();

        let oracle_guided_attempts = results.iter().filter(|r| r.oracle_guided.is_some()).count();
        let oracle_guided_successes = results
            .iter()
            .filter_map(|r| r.oracle_guided.as_ref())
            .filter(|o| o.attack_success)
            .count();

        let key_recovery_times: Vec<Duration> = results
            .iter()
            .filter_map(|r| r.key_recovery.as_ref().map(|kr| kr.time_elapsed))
            .collect();
        let avg_key_recovery_time = if key_recovery_times.is_empty() {
            Duration::ZERO
        } else {
            key_recovery_times.iter().sum::<Duration>() / key_recovery_times.len() as u32
        };

        let oracle_queries: Vec<usize> = results
            .iter()
            .filter_map(|r| r.oracle_guided.as_ref().map(|o| o.queries_used))
            .collect();
        let avg_oracle_queries = if oracle_queries.is_empty() {
            0.0
        } else {
            oracle_queries.iter().sum::<usize>() as f64 / oracle_queries.len() as f64
        };

        Self {
            total_circuits,
            key_recovery_attempts,
            key_recovery_successes,
            equivalence_attempts,
            equivalence_successes,
            oracle_guided_attempts,
            oracle_guided_successes,
            avg_key_recovery_time,
            avg_oracle_queries,
        }
    }

    pub fn print(&self) {
        println!("\n========== SAT Attack Benchmark Summary ==========");
        println!("Total circuits tested: {}", self.total_circuits);
        println!();
        println!("Key Recovery Attack:");
        println!(
            "  Attempts: {}, Successes: {} ({:.1}%)",
            self.key_recovery_attempts,
            self.key_recovery_successes,
            if self.key_recovery_attempts > 0 {
                100.0 * self.key_recovery_successes as f64 / self.key_recovery_attempts as f64
            } else {
                0.0
            }
        );
        println!("  Avg time: {:?}", self.avg_key_recovery_time);
        println!();
        println!("Equivalence Attack:");
        println!(
            "  Attempts: {}, Successes: {} ({:.1}%)",
            self.equivalence_attempts,
            self.equivalence_successes,
            if self.equivalence_attempts > 0 {
                100.0 * self.equivalence_successes as f64 / self.equivalence_attempts as f64
            } else {
                0.0
            }
        );
        println!();
        println!("Oracle-Guided Attack:");
        println!(
            "  Attempts: {}, Successes: {} ({:.1}%)",
            self.oracle_guided_attempts,
            self.oracle_guided_successes,
            if self.oracle_guided_attempts > 0 {
                100.0 * self.oracle_guided_successes as f64 / self.oracle_guided_attempts as f64
            } else {
                0.0
            }
        );
        println!("  Avg queries: {:.0}", self.avg_oracle_queries);
        println!("==================================================\n");
    }
}

pub fn generate_csv_report(results: &[BenchmarkResult]) -> String {
    let mut csv = String::new();
    csv.push_str("wires,gates,kr_success,kr_iterations,kr_time_ms,eq_success,eq_queries,og_success,og_queries,og_error\n");

    for r in results {
        let kr_success = r
            .key_recovery
            .as_ref()
            .map(|kr| kr.success)
            .unwrap_or(false);
        let kr_iterations = r.key_recovery.as_ref().map(|kr| kr.iterations).unwrap_or(0);
        let kr_time = r
            .key_recovery
            .as_ref()
            .map(|kr| kr.time_elapsed.as_millis())
            .unwrap_or(0);

        let eq_success = r
            .equivalence
            .as_ref()
            .map(|e| e.synthesis_successful)
            .unwrap_or(false);
        let eq_queries = r.equivalence.as_ref().map(|e| e.queries_used).unwrap_or(0);

        let og_success = r
            .oracle_guided
            .as_ref()
            .map(|o| o.attack_success)
            .unwrap_or(false);
        let og_queries = r
            .oracle_guided
            .as_ref()
            .map(|o| o.queries_used)
            .unwrap_or(0);
        let og_error = r
            .oracle_guided
            .as_ref()
            .map(|o| o.error_rate)
            .unwrap_or(1.0);

        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{:.6}\n",
            r.circuit_wires,
            r.circuit_gates,
            kr_success,
            kr_iterations,
            kr_time,
            eq_success,
            eq_queries,
            og_success,
            og_queries,
            og_error
        ));
    }

    csv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quick_benchmark() {
        let config = BenchmarkConfig::quick();
        let benchmarker = SatAttackBenchmarker::new(config);
        let results = benchmarker.run_all();

        let summary = BenchmarkSummary::from_results(&results);
        summary.print();

        assert!(!results.is_empty(), "Should have benchmark results");
    }

    #[test]
    fn test_benchmark_single() {
        let config = BenchmarkConfig::default();
        let benchmarker = SatAttackBenchmarker::new(config);
        let result = benchmarker.benchmark_single(4, 8);

        println!("Single benchmark result:");
        println!(
            "  Wires: {}, Gates: {}",
            result.circuit_wires, result.circuit_gates
        );
        if let Some(ref kr) = result.key_recovery {
            println!(
                "  Key recovery: success={}, iterations={}",
                kr.success, kr.iterations
            );
        }
        if let Some(ref og) = result.oracle_guided {
            println!(
                "  Oracle-guided: success={}, queries={}",
                og.attack_success, og.queries_used
            );
        }
    }

    #[test]
    fn test_csv_report() {
        let config = BenchmarkConfig::quick();
        let benchmarker = SatAttackBenchmarker::new(config);
        let results = benchmarker.run_all();

        let csv = generate_csv_report(&results);
        println!("CSV Report:\n{}", csv);

        assert!(csv.contains("wires,gates"), "CSV should have header");
        assert!(csv.lines().count() > 1, "CSV should have data rows");
    }

    #[test]
    fn test_scaling_analysis() {
        println!("\n=== SAT Attack Scaling Analysis ===\n");

        for num_wires in [3, 4, 5, 6] {
            for gate_mult in [2, 4] {
                let num_gates = num_wires * gate_mult;
                let circuit = Circuit::random(num_wires, num_gates);
                let oracle = |input: usize| circuit.evaluate(input);

                let attack = OracleGuidedAttack::new()
                    .with_max_queries(5000)
                    .with_max_circuit_size(num_gates + 3)
                    .with_timeout(Duration::from_secs(10));

                let start = Instant::now();
                let result = attack.exact_learning(oracle, num_wires);
                let elapsed = start.elapsed();

                println!(
                    "{}w x {}g: success={}, queries={:5}, time={:8.2?}",
                    num_wires, num_gates, result.attack_success, result.queries_used, elapsed
                );
            }
        }
    }
}
