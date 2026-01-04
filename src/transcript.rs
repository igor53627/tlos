//! Transcript-based Fiat-Shamir binding for TLOS.
//!
//! This module provides a formal Fiat-Shamir transform for the wire binding layer,
//! enabling cleaner security reductions and better composability for future iO extensions.
//!
//! ## Security Model
//!
//! The transcript accumulates:
//! - Circuit seed (public)
//! - Gate evaluations (intermediate wire states)
//! - Batch boundaries
//!
//! This binding style is inspired by lattice-based iO constructions (Diamond iO, NTRU+Equivocal LWE)
//! where the transcript serves as a commitment to the entire execution trace.
//!
//! ## Properties
//!
//! - **Binding**: Changing any intermediate state changes the final transcript hash
//! - **Extractability**: Transcript can be "rewound" for security proofs
//! - **Composability**: Can be extended with additional layers (e.g., range proofs)

use sha3::{Digest, Keccak256};

/// Maximum transcript entries before forced finalization.
pub const MAX_TRANSCRIPT_ENTRIES: usize = 1024;

/// A Fiat-Shamir transcript for TLOS evaluation.
///
/// Accumulates cryptographic commitments during circuit evaluation,
/// providing a formal binding structure.
#[derive(Clone, Debug)]
pub struct Transcript {
    /// Running hash state
    state: [u8; 32],
    /// Number of entries absorbed
    entry_count: usize,
    /// Domain separator for this transcript
    domain: &'static [u8],
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new(b"TLOS-v1")
    }
}

impl Transcript {
    /// Create a new transcript with the given domain separator.
    ///
    /// The domain separator ensures transcripts from different contexts
    /// cannot be confused.
    pub fn new(domain: &'static [u8]) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(domain);
        let state: [u8; 32] = hasher.finalize().into();

        Self {
            state,
            entry_count: 0,
            domain,
        }
    }

    /// Initialize transcript with circuit seed.
    ///
    /// This binds the transcript to a specific circuit configuration.
    pub fn init_with_seed(&mut self, circuit_seed: [u8; 32]) {
        self.absorb_labeled(b"circuit_seed", &circuit_seed);
    }

    /// Absorb initial wire state into the transcript.
    pub fn absorb_initial_wires(&mut self, wires: u64) {
        self.absorb_labeled(b"initial_wires", &wires.to_be_bytes());
    }

    /// Absorb a gate evaluation result.
    ///
    /// # Arguments
    /// * `gate_idx` - Index of the gate being evaluated
    /// * `wires` - Wire state after gate evaluation
    pub fn absorb_gate(&mut self, gate_idx: u32, wires: u64) {
        let mut data = [0u8; 12];
        data[0..4].copy_from_slice(&gate_idx.to_be_bytes());
        data[4..12].copy_from_slice(&wires.to_be_bytes());
        self.absorb_labeled(b"gate", &data);
    }

    /// Absorb a batch boundary.
    ///
    /// Called after processing a batch of gates (e.g., every 128 gates).
    pub fn absorb_batch_boundary(&mut self, batch_end: u32, wires: u64) {
        let mut data = [0u8; 12];
        data[0..4].copy_from_slice(&batch_end.to_be_bytes());
        data[4..12].copy_from_slice(&wires.to_be_bytes());
        self.absorb_labeled(b"batch", &data);
    }

    /// Absorb labeled data into the transcript.
    fn absorb_labeled(&mut self, label: &[u8], data: &[u8]) {
        let mut hasher = Keccak256::new();
        hasher.update(&self.state);
        hasher.update(&(label.len() as u64).to_be_bytes());
        hasher.update(label);
        hasher.update(&(data.len() as u64).to_be_bytes());
        hasher.update(data);
        self.state = hasher.finalize().into();
        self.entry_count += 1;
    }

    /// Squeeze a challenge from the transcript.
    ///
    /// This is used to derive deterministic challenges for the Fiat-Shamir transform.
    pub fn squeeze_challenge(&mut self, label: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(&self.state);
        hasher.update(b"challenge");
        hasher.update(&(label.len() as u64).to_be_bytes());
        hasher.update(label);

        let challenge: [u8; 32] = hasher.finalize().into();

        // Update state to ensure challenges are chained
        self.absorb_labeled(b"squeezed", &challenge);

        challenge
    }

    /// Finalize the transcript and return the binding hash.
    ///
    /// This hash commits to the entire execution trace.
    pub fn finalize(self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(&self.state);
        hasher.update(b"finalize");
        hasher.update(&(self.entry_count as u64).to_be_bytes());
        hasher.finalize().into()
    }

    /// Get the current state (for debugging/testing).
    pub fn current_state(&self) -> [u8; 32] {
        self.state
    }

    /// Get the entry count.
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }
}

/// Transcript-based wire binding that mirrors the Solidity implementation.
///
/// This provides a formal Fiat-Shamir reduction while maintaining
/// compatibility with the existing on-chain verification.
pub struct TranscriptBinding {
    transcript: Transcript,
    batch_size: u32,
    current_batch_start: u32,
}

impl TranscriptBinding {
    /// Create a new transcript binding.
    pub fn new(circuit_seed: [u8; 32], batch_size: u32) -> Self {
        let mut transcript = Transcript::new(b"TLOS-binding-v1");
        transcript.init_with_seed(circuit_seed);

        Self {
            transcript,
            batch_size,
            current_batch_start: 0,
        }
    }

    /// Initialize with the starting wire state.
    pub fn init(&mut self, wires: u64) {
        self.transcript.absorb_initial_wires(wires);
    }

    /// Process a gate and update the transcript.
    ///
    /// Automatically handles batch boundaries.
    pub fn process_gate(&mut self, gate_idx: u32, wires: u64) {
        self.transcript.absorb_gate(gate_idx, wires);

        // Check for batch boundary
        let batch_end = self.current_batch_start + self.batch_size;
        if gate_idx + 1 == batch_end {
            self.transcript.absorb_batch_boundary(batch_end, wires);
            self.current_batch_start = batch_end;
        }
    }

    /// Finalize and return the binding commitment.
    pub fn finalize(mut self, final_wires: u64, total_gates: u32) -> [u8; 32] {
        // Ensure final batch boundary is recorded
        if total_gates > self.current_batch_start {
            self.transcript.absorb_batch_boundary(total_gates, final_wires);
        }

        self.transcript.finalize()
    }

    /// Derive a challenge for potential future extensions.
    ///
    /// This enables composability with additional layers (e.g., range proofs, ZK proofs).
    pub fn derive_challenge(&mut self, label: &[u8]) -> [u8; 32] {
        self.transcript.squeeze_challenge(label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transcript_deterministic() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");

        t1.absorb_labeled(b"data", &[1, 2, 3]);
        t2.absorb_labeled(b"data", &[1, 2, 3]);

        assert_eq!(t1.finalize(), t2.finalize());
    }

    #[test]
    fn test_transcript_different_domains() {
        let mut t1 = Transcript::new(b"domain1");
        let mut t2 = Transcript::new(b"domain2");

        t1.absorb_labeled(b"data", &[1, 2, 3]);
        t2.absorb_labeled(b"data", &[1, 2, 3]);

        assert_ne!(t1.finalize(), t2.finalize());
    }

    #[test]
    fn test_transcript_binding_deterministic() {
        let seed = [0x42u8; 32];

        let mut b1 = TranscriptBinding::new(seed, 128);
        let mut b2 = TranscriptBinding::new(seed, 128);

        b1.init(0x12345);
        b2.init(0x12345);

        for i in 0..256 {
            b1.process_gate(i, 0x12345 ^ (i as u64));
            b2.process_gate(i, 0x12345 ^ (i as u64));
        }

        assert_eq!(b1.finalize(0x12345, 256), b2.finalize(0x12345, 256));
    }

    #[test]
    fn test_transcript_binding_different_wires() {
        let seed = [0x42u8; 32];

        let mut b1 = TranscriptBinding::new(seed, 128);
        let mut b2 = TranscriptBinding::new(seed, 128);

        b1.init(0x12345);
        b2.init(0x12346); // Different initial wires

        for i in 0..256 {
            b1.process_gate(i, 0x12345);
            b2.process_gate(i, 0x12345);
        }

        assert_ne!(b1.finalize(0x12345, 256), b2.finalize(0x12345, 256));
    }

    #[test]
    fn test_challenge_derivation() {
        let seed = [0x42u8; 32];

        let mut b1 = TranscriptBinding::new(seed, 128);
        b1.init(0x12345);

        let c1 = b1.derive_challenge(b"round1");
        let c2 = b1.derive_challenge(b"round2");

        // Challenges should be different
        assert_ne!(c1, c2);

        // But deterministic
        let mut b2 = TranscriptBinding::new(seed, 128);
        b2.init(0x12345);

        assert_eq!(c1, b2.derive_challenge(b"round1"));
    }
}
