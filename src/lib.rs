//! # TLOS - Topology-Lattice Obfuscation for Smart contracts
//!
//! Four-layer security model for smart contract obfuscation:
//!
//! 1. **Topology layer** (`circuit`) - Structural mixing via circuit transformations (heuristic)
//! 2. **LWE layer** (`lwe`) - Control function hiding via standard LWE with Gaussian noise (~2^112 PQ)
//! 3. **Wire binding layer** (`wire_binding`) - Full-rank linear hash for inter-gate consistency
//! 4. **Planted LWE puzzle** - Forces minimum 3^48 ≈ 2^76 brute-force search space
//!
//! ## Modules
//!
//! - [`circuit`] - Layer 1: Circuit representation and topology mixing
//! - [`lwe`] - Layer 2: LWE encryption (n=384, σ=8, q=65521)
//! - [`wire_binding`] - Layer 3: Algebraic wire binding for integrity
//! - [`transcript`] - Fiat-Shamir transcript for formal security reduction
//! - [`generator`] - TLOS deployment generation for Solidity contracts
//!
//! ## Towards iO
//!
//! The transcript module provides a formal Fiat-Shamir binding structure that enables:
//! - Cleaner security reductions (extractability in the random oracle model)
//! - Composability with future layers (range proofs, ZK proofs)
//! - Path toward full iO via techniques from Diamond iO and NTRU-based constructions

pub mod circuit;
pub mod lwe;
pub mod wire_binding;
pub mod transcript;
pub mod algebraic_mixing;
pub mod generator;

pub use circuit::{Gate, Circuit, SixSixConfig, create_six_six_circuit};
pub use lwe::{LweCiphertext, derive_secret, encrypt_bit, encode_gate, Q, LWE_N};
pub use wire_binding::{wire_binding_init, wire_binding_update, wire_binding_hash};
pub use transcript::{Transcript, TranscriptBinding};
pub use algebraic_mixing::{AlgebraicGate, AlgebraicCircuit, AlgebraicConfig, create_algebraic_circuit};
pub use generator::{TLOSDeployment, generate_tlos};
