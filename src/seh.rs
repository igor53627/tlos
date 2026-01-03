use sha3::{Digest, Keccak256};

/// Initialize SEH accumulator (legacy, kept for compatibility).
pub fn seh_init(input: &[u8; 32], wires: u64) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    hasher.update(b"SEH-INIT");
    hasher.update(&wires.to_be_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Update SEH accumulator with new batch state (legacy, kept for compatibility).
pub fn seh_update(acc: [u8; 32], batch_end: u32, wires: u64) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(&acc);
    hasher.update(&batch_end.to_be_bytes());
    hasher.update(&wires.to_be_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seh_init_deterministic() {
        let input = [0x42u8; 32];
        let wires = 0x123456789ABCDEF0u64;
        let h1 = seh_init(&input, wires);
        let h2 = seh_init(&input, wires);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_seh_update_deterministic() {
        let acc = [0x55u8; 32];
        let batch_end = 64;
        let wires = 0xDEADBEEFCAFEBABEu64;
        let h1 = seh_update(acc, batch_end, wires);
        let h2 = seh_update(acc, batch_end, wires);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_seh_chain() {
        let input = [0x01u8; 32];
        let initial_wires = 0xFFFF;
        let acc = seh_init(&input, initial_wires);
        let acc = seh_update(acc, 64, 0x1234);
        let acc = seh_update(acc, 128, 0x5678);
        assert_ne!(acc, [0u8; 32]);
    }
}
