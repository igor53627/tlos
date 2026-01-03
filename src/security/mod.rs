//! Security estimation tools for TLOS.
//!
//! Provides interfaces to the lattice-estimator-cli for computing LWE security levels.
//! Includes pre-configured estimators for:
//! - Main LWE layer (n=384, ~2^112 post-quantum security)
//! - Puzzle layer (n=48, ~2^32 lattice but 2^76 brute-force search space)

mod lattice_estimator;

pub use lattice_estimator::{
    Distribution, EstimatorCliError, run_lattice_estimator_cli, run_lattice_estimator_cli_with_path,
    estimate_main_lwe_security, estimate_puzzle_lwe_security,
};
