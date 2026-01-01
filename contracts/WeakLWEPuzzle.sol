// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title WeakLWEPuzzle - Layer 4: Brute-Force Resistance via Weak LWE
/// @notice Adds ~2^20 work per guess by requiring solution to a weak LWE instance
/// @dev Parameters chosen so solving requires BKZ lattice reduction (~2^20 ops)
///      but verification is cheap (O(n*m) = O(3072) operations)
///
/// Construction:
/// - For each guess x, generate deterministic LWE instance (A, b) from H(x)
/// - Solver must find ternary s ∈ {-1,0,1}^n such that ||As - b|| < threshold
/// - Solving requires ~2^20 work (BKZ, not GPU-friendly)
/// - Verification is O(n*m) ≈ 15-20K gas
///
/// Parameters (targeting ~2^20 solve cost):
/// - n = 48 (secret dimension)
/// - m = 64 (number of samples)  
/// - q = 2048 (small modulus, fits 16-bit)
/// - s ∈ {-1,0,1}^n (ternary secret)
/// - Error: centered binomial CB(2), values in [-4, 4]
/// - Threshold: ||As - b||² < 512
contract WeakLWEPuzzle {
    uint256 public constant N_WEAK = 48;      // Secret dimension
    uint256 public constant M_WEAK = 64;      // Number of samples
    uint256 public constant Q_WEAK = 2048;    // Small modulus (2^11)
    uint256 public constant THRESHOLD_SQ = 512; // ||As - b||² must be < this
    
    // Domain separator for puzzle generation
    bytes32 public constant PUZZLE_DOMAIN = keccak256("TLOS-WeakLWE-Puzzle-v1");
    
    /// @notice Verify a weak LWE puzzle solution (optimized with assembly)
    /// @param x The original input (puzzle is derived from H(x))
    /// @param solution The proposed solution s ∈ {-1,0,1}^48, packed as int8[48]
    /// @return valid True if solution is valid
    /// @return sHash Hash of solution (used as key for subsequent TLOS evaluation)
    function verifyPuzzle(bytes32 x, int8[48] calldata solution) 
        external 
        pure 
        returns (bool valid, bytes32 sHash) 
    {
        uint256 normSq;
        bytes32 puzzleDomain = PUZZLE_DOMAIN;
        
        // Copy solution to memory for assembly access
        int8[48] memory sol = solution;
        
        assembly {
            // Check solution is ternary 
            let solPtr := sol
            
            for { let i := 0 } lt(i, 48) { i := add(i, 1) } {
                let val := mload(add(solPtr, mul(i, 32)))
                // Check -1 <= val <= 1
                if or(slt(val, sub(0, 1)), sgt(val, 1)) {
                    mstore(0, 0) // valid = false
                    mstore(32, 0) // sHash = 0
                    return(0, 64)
                }
            }
            
            // Compute seed = keccak256(PUZZLE_DOMAIN, x)
            let freePtr := add(solPtr, 1536) // 48 * 32
            mstore(freePtr, puzzleDomain)
            mstore(add(freePtr, 32), x)
            let seed := keccak256(freePtr, 64)
            
            normSq := 0
            
            // Process each row
            for { let row := 0 } lt(row, 64) { row := add(row, 1) } {
                // rowSeed = keccak256(seed, row)
                mstore(freePtr, seed)
                mstore(add(freePtr, 32), row)
                let rowSeed := keccak256(freePtr, 64)
                
                let dotProduct := 0
                
                // Process 48 coefficients in 3 blocks of 16
                for { let blockIdx := 0 } lt(blockIdx, 3) { blockIdx := add(blockIdx, 1) } {
                    // coeffs = keccak256(rowSeed, blockIdx)
                    mstore(freePtr, rowSeed)
                    mstore(add(freePtr, 32), blockIdx)
                    let coeffs := keccak256(freePtr, 64)
                    
                    // Extract 16 u16 coefficients and multiply by solution
                    for { let k := 0 } lt(k, 16) { k := add(k, 1) } {
                        let colIdx := add(mul(blockIdx, 16), k)
                        if lt(colIdx, 48) {
                            // Extract u16 at position k, mod q
                            let aij := mod(and(shr(mul(sub(15, k), 16), coeffs), 0xFFFF), 2048)
                            // Get solution element
                            let sVal := mload(add(solPtr, mul(colIdx, 32)))
                            // Accumulate dot product
                            dotProduct := add(dotProduct, mul(aij, sVal))
                        }
                    }
                }
                
                // bVal = keccak256(seed, 0x62, row) mod q  (0x62 = 'b')
                mstore(freePtr, seed)
                mstore8(add(freePtr, 32), 0x62)
                mstore(add(freePtr, 33), row)
                let bVal := mod(keccak256(freePtr, 65), 2048)
                
                // Compute centered residual
                let residual := sub(dotProduct, bVal)
                // Center in [-q/2, q/2)
                residual := smod(residual, 2048)
                if sgt(residual, 1024) { residual := sub(residual, 2048) }
                if slt(residual, sub(0, 1024)) { residual := add(residual, 2048) }
                
                // Accumulate squared norm
                normSq := add(normSq, mul(residual, residual))
            }
        }
        
        // Check threshold
        valid = normSq < THRESHOLD_SQ;
        
        if (valid) {
            sHash = keccak256(abi.encodePacked(solution));
        }
    }
    
    /// @notice Generate puzzle parameters for off-chain solving
    /// @param x The input to generate puzzle for
    /// @return seed The seed for A and b generation
    /// @dev Off-chain solver uses this to reconstruct (A, b) and run BKZ
    function getPuzzleSeed(bytes32 x) external pure returns (bytes32 seed) {
        seed = keccak256(abi.encodePacked(PUZZLE_DOMAIN, x));
    }
    
    /// @notice Get a single row of matrix A (for debugging/testing)
    /// @param seed Puzzle seed from getPuzzleSeed
    /// @param row Row index (0 to M_WEAK-1)
    /// @return aRow The row as uint16[48]
    function getMatrixRow(bytes32 seed, uint256 row) 
        external 
        pure 
        returns (uint16[48] memory aRow) 
    {
        require(row < M_WEAK, "Row out of bounds");
        
        bytes32 rowSeed = keccak256(abi.encodePacked(seed, "row", row));
        
        for (uint256 col = 0; col < N_WEAK; col += 16) {
            bytes32 coeffs = keccak256(abi.encodePacked(rowSeed, col / 16));
            
            for (uint256 k = 0; k < 16 && col + k < N_WEAK; k++) {
                aRow[col + k] = uint16(uint256(uint16(bytes2(coeffs << (k * 16)))) % Q_WEAK);
            }
        }
    }
    
    /// @notice Get the b vector element (for debugging/testing)
    /// @param seed Puzzle seed from getPuzzleSeed
    /// @param row Row index (0 to M_WEAK-1)
    /// @return bVal The b[row] value
    function getBValue(bytes32 seed, uint256 row) 
        external 
        pure 
        returns (uint16 bVal) 
    {
        require(row < M_WEAK, "Row out of bounds");
        bytes32 bSeed = keccak256(abi.encodePacked(seed, "b", row));
        bVal = uint16(uint256(bSeed) % Q_WEAK);
    }
}
