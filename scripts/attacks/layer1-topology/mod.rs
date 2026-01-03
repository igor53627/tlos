//! SAT/SMT Attack Suite for Circuit Obfuscation
//!
//! This module implements various attacks against obfuscated reversible circuits,
//! based on the SAT attack literature (Subramanyan et al., HOST 2015 and successors).
//!
//! # Attack Types
//!
//! - **Key Recovery**: Classic SAT attack to recover control function parameters
//! - **Equivalence**: SAT-based circuit synthesis to find equivalent implementations
//! - **Oracle-Guided**: Learning attacks exploiting unlimited oracle access (Ethereum model)
//!
//! # Threat Model (MinCore)
//!
//! | Attack Type | Threat Level | Notes |
//! |-------------|--------------|-------|
//! | Key Recovery | LOW | No recoverable key in MinCore (NTRU opaque) |
//! | Structural Analysis | MEDIUM | Mixing layers add complexity |
//! | Oracle-Guided Synthesis | HIGH | Unlimited queries in Ethereum |
//! | Approximate Attacks | MEDIUM | Binary predicates reduce effectiveness |
//!
//! # Example
//!
//! ```rust
//! use circuit_mixing_research::attacks::{
//!     OracleGuidedAttack, KeyRecoveryAttack, EquivalenceAttack
//! };
//! use circuit_mixing_research::circuit::Circuit;
//!
//! // Create a target circuit
//! let target = Circuit::random(4, 5);
//!
//! // Run oracle-guided attack
//! let attack = OracleGuidedAttack::new()
//!     .with_max_queries(1000)
//!     .with_max_circuit_size(10);
//!
//! let oracle = |input: usize| target.evaluate(input);
//! let result = attack.exact_learning(oracle, 4);
//!
//! println!("Attack success: {}, queries used: {}", result.attack_success, result.queries_used);
//! ```

pub mod benchmarks;
pub mod equivalence;
pub mod input_recovery;
pub mod key_recovery;
pub mod local_mixing;
pub mod oracle_guided;
pub mod sat_encoder;
pub mod sixsix_detector;
mod suite;
pub mod synthesis;

pub use benchmarks::{
    generate_csv_report, BenchmarkConfig, BenchmarkResult, BenchmarkSummary, SatAttackBenchmarker,
};
pub use equivalence::{EquivalenceAttack, EquivalenceAttackResult};
pub use input_recovery::{
    demonstrate_seed_hiding_attack, InputRecoveryAttack, InputRecoveryResult, SeedHidingAnalysis,
};
pub use key_recovery::{KeyRecoveryAttack, KeyRecoveryResult};
pub use local_mixing::{
    ComplexityGapAttack, ComplexityGapResult, LocalReversibilityAttack, LocalReversibilityResult,
    NeighborhoodStats, PseudorandomnessResult, SkeletonGraph, SubcircuitPseudorandomnessTest,
};
pub use oracle_guided::{benchmark_query_complexity, OracleGuidedAttack, OracleGuidedResult};
pub use sat_encoder::{CircuitSatFormula, DipFormula, SatEncoder};
pub use suite::{AttackResult, AttackSuite};
pub use synthesis::{
    benchmark_synthesis, CircuitSketch, GateComponent, SynthesisAttack, SynthesisBenchmarkResult,
    SynthesisResult,
};
