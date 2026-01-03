use std::path::Path;
use std::process::Command;
use thiserror::Error;

/// Noise/secret distribution types for LWE security estimation.
/// Matches the lattice-estimator-cli JSON format.
#[derive(Clone, Debug)]
pub enum Distribution {
    /// Discrete Gaussian with standard deviation σ and optional mean.
    DiscreteGaussian {
        stddev: f64,
        mean: Option<f64>,
        n: Option<u64>,
    },
    /// Discrete Gaussian specified via α = σ/q.
    DiscreteGaussianAlpha {
        alpha: f64,
        mean: Option<f64>,
        n: Option<u64>,
    },
    /// Centered binomial distribution with parameter η.
    CenteredBinomial { eta: u64, n: Option<u64> },
    /// Uniform distribution over [a, b].
    Uniform { a: i64, b: i64, n: Option<u64> },
    /// Uniform mod q (secret distribution).
    UniformMod { n: Option<u64> },
    /// Sparse ternary: p values of +1, m values of -1, rest 0.
    SparseTernary { p: u64, m: u64, n: Option<u64> },
    /// Sparse binary with specified Hamming weight.
    SparseBinary { hw: u64, n: Option<u64> },
    /// Binary {0, 1}.
    Binary,
    /// Ternary {-1, 0, 1}.
    Ternary,
}

impl Distribution {
    /// Convert to JSON value for lattice-estimator-cli.
    pub fn to_json_value(&self) -> serde_json::Value {
        use serde_json::json;
        match self {
            Distribution::DiscreteGaussian { stddev, mean, n } => {
                let mut obj = json!({
                    "distribution": "discrete_gaussian",
                    "stddev": stddev
                });
                if let Some(m) = mean {
                    obj["mean"] = json!(m);
                }
                if let Some(dim) = n {
                    obj["n"] = json!(dim);
                }
                obj
            }
            Distribution::DiscreteGaussianAlpha { alpha, mean, n } => {
                let mut obj = json!({
                    "distribution": "discrete_gaussian_alpha",
                    "alpha": alpha
                });
                if let Some(m) = mean {
                    obj["mean"] = json!(m);
                }
                if let Some(dim) = n {
                    obj["n"] = json!(dim);
                }
                obj
            }
            Distribution::CenteredBinomial { eta, n } => {
                let mut obj = json!({
                    "distribution": "centered_binomial",
                    "eta": eta
                });
                if let Some(dim) = n {
                    obj["n"] = json!(dim);
                }
                obj
            }
            Distribution::Uniform { a, b, n } => {
                let mut obj = json!({
                    "distribution": "uniform",
                    "a": a,
                    "b": b
                });
                if let Some(dim) = n {
                    obj["n"] = json!(dim);
                }
                obj
            }
            Distribution::UniformMod { n } => {
                let mut obj = json!({
                    "distribution": "uniform_mod"
                });
                if let Some(dim) = n {
                    obj["n"] = json!(dim);
                }
                obj
            }
            Distribution::SparseTernary { p, m, n } => {
                let mut obj = json!({
                    "distribution": "sparse_ternary",
                    "p": p,
                    "m": m
                });
                if let Some(dim) = n {
                    obj["n"] = json!(dim);
                }
                obj
            }
            Distribution::SparseBinary { hw, n } => {
                let mut obj = json!({
                    "distribution": "sparse_binary",
                    "hw": hw
                });
                if let Some(dim) = n {
                    obj["n"] = json!(dim);
                }
                obj
            }
            Distribution::Binary => json!({ "distribution": "binary" }),
            Distribution::Ternary => json!({ "distribution": "ternary" }),
        }
    }

    /// Convert to compact JSON string for CLI args.
    pub fn to_json_string(&self) -> String {
        self.to_json_value().to_string()
    }
}

/// Errors from running the lattice-estimator-cli.
#[derive(Debug, Error)]
pub enum EstimatorCliError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("lattice-estimator-cli exited with code {0:?}. stdout: {1} stderr: {2}")]
    NonZeroExit(Option<i32>, String, String),

    #[error("parse int error: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
}

/// Run lattice-estimator-cli with a custom path.
///
/// # Arguments
/// * `cli_path` - Path to lattice-estimator-cli executable
/// * `ring_dim` - LWE dimension n (or ring dimension for RLWE)
/// * `q` - Modulus
/// * `s_dist` - Secret distribution
/// * `e_dist` - Error distribution
/// * `m` - Optional number of samples
/// * `exact` - Use exact (slower) estimation
///
/// # Returns
/// Security level in bits (e.g., 112 for ~2^112 security)
pub fn run_lattice_estimator_cli_with_path(
    cli_path: impl AsRef<Path>,
    ring_dim: u64,
    q: u64,
    s_dist: &Distribution,
    e_dist: &Distribution,
    m: Option<u64>,
    exact: bool,
) -> Result<u64, EstimatorCliError> {
    let mut cmd = Command::new(cli_path.as_ref());
    cmd.arg(ring_dim.to_string()).arg(q.to_string());

    cmd.arg("--s-dist").arg(s_dist.to_json_string());
    cmd.arg("--e-dist").arg(e_dist.to_json_string());

    if let Some(samples) = m {
        cmd.arg("--m").arg(samples.to_string());
    }

    if exact {
        cmd.arg("--exact");
    }

    let output = cmd.output()?;

    if !output.status.success() {
        let stdout = String::from_utf8(output.stdout)?;
        let stderr = String::from_utf8(output.stderr)?;
        return Err(EstimatorCliError::NonZeroExit(
            output.status.code(),
            stdout,
            stderr,
        ));
    }

    let stdout = String::from_utf8(output.stdout)?;
    let last_line = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .last()
        .unwrap_or("")
        .trim();

    Ok(last_line.parse()?)
}

/// Run lattice-estimator-cli from PATH.
///
/// See [`run_lattice_estimator_cli_with_path`] for details.
pub fn run_lattice_estimator_cli(
    ring_dim: u64,
    q: u64,
    s_dist: &Distribution,
    e_dist: &Distribution,
    m: Option<u64>,
    exact: bool,
) -> Result<u64, EstimatorCliError> {
    run_lattice_estimator_cli_with_path("lattice-estimator-cli", ring_dim, q, s_dist, e_dist, m, exact)
}

/// Estimate security for TLOS main LWE layer.
///
/// Parameters: n=384, q=65521, σ=8 (Gaussian noise), uniform secret.
/// Expected: ~112 bits post-quantum security (with exact mode).
pub fn estimate_main_lwe_security() -> Result<u64, EstimatorCliError> {
    run_lattice_estimator_cli(
        384,   // n
        65521, // q
        &Distribution::UniformMod { n: None }, // uniform secret mod q
        &Distribution::DiscreteGaussian {
            stddev: 8.0,
            mean: None,
            n: None,
        },
        Some(2560), // m = samples (typical circuit size)
        true, // exact mode for accurate estimate
    )
}

/// Estimate security for TLOS puzzle layer (Layer 4).
///
/// Parameters: n=48, q=2039, ternary secret, uniform error in [-2, 2].
/// Note: Lattice attacks give ~32 bits, but the security model is brute-force
/// search space: 3^48 ≈ 2^76. The puzzle is intentionally weak against lattice
/// attacks - its purpose is to force minimum work per guess.
pub fn estimate_puzzle_lwe_security() -> Result<u64, EstimatorCliError> {
    run_lattice_estimator_cli(
        48,   // n
        2039, // q
        &Distribution::Ternary, // ternary secret {-1, 0, 1}
        &Distribution::Uniform { a: -2, b: 2, n: None }, // error in [-2, 2]
        Some(72), // m = 72 samples
        true, // exact mode
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distribution_json_discrete_gaussian() {
        let d = Distribution::DiscreteGaussian {
            stddev: 8.0,
            mean: None,
            n: None,
        };
        let json = d.to_json_string();
        assert!(json.contains("discrete_gaussian"));
        assert!(json.contains("8"));
    }

    #[test]
    fn test_distribution_json_ternary() {
        let d = Distribution::Ternary;
        let json = d.to_json_string();
        assert_eq!(json, r#"{"distribution":"ternary"}"#);
    }

    #[test]
    fn test_distribution_json_uniform() {
        let d = Distribution::Uniform { a: -2, b: 2, n: None };
        let json = d.to_json_string();
        assert!(json.contains("uniform"));
        assert!(json.contains("-2"));
        assert!(json.contains("2"));
    }

    #[test]
    fn test_distribution_json_sparse_ternary() {
        let d = Distribution::SparseTernary { p: 32, m: 32, n: Some(128) };
        let json = d.to_json_string();
        assert!(json.contains("sparse_ternary"));
        assert!(json.contains("\"p\":32"));
        assert!(json.contains("\"m\":32"));
        assert!(json.contains("\"n\":128"));
    }

    #[test]
    #[ignore]
    fn test_main_lwe_security_estimate() {
        // Main LWE: n=384, q=65521, σ=8 should give ~112 bits (exact mode)
        let bits = estimate_main_lwe_security().expect("CLI should run");
        assert!(bits >= 110, "Expected >= 110 bits, got {}", bits);
        assert!(bits <= 130, "Expected <= 130 bits, got {}", bits);
    }

    #[test]
    #[ignore]
    fn test_puzzle_lwe_security_estimate() {
        // Puzzle LWE: n=48, q=2039, ternary secret
        // Lattice attacks give ~32 bits (expected), but security model is 3^48 search space
        let bits = estimate_puzzle_lwe_security().expect("CLI should run");
        assert!(bits >= 30, "Expected >= 30 bits (lattice), got {}", bits);
        assert!(bits <= 50, "Expected <= 50 bits (lattice), got {}", bits);
    }

    #[test]
    #[ignore]
    fn test_cli_with_exact_mode() {
        let bits = run_lattice_estimator_cli(
            256,
            65537,
            &Distribution::Ternary,
            &Distribution::DiscreteGaussian { stddev: 3.2, mean: None, n: None },
            Some(512), // provide m to avoid None error
            true, // exact mode
        ).expect("CLI should run with exact mode");
        assert!(bits > 0);
    }
}
