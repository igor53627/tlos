// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title WeakLWEPuzzleV4 - Layer 4: Planted LWE Puzzle (Simpler Gas Optimization)
/// @notice Proper LWE construction with planted secret and error
/// @dev Gas optimization: fewer keccak calls, simpler Solidity code
///
/// Key insight: Verification only needs to compute ||As - b||² 
/// where b = A·s* + e is deterministically derived.
/// 
/// Optimization: Batch coefficient derivation (16 per keccak)
///
/// Parameters:
/// - n = 40 (secret dimension)
/// - m = 60 (number of samples, overdetermined)
/// - q = 2039 (prime near 2^11)
/// - s* ∈ {-1,0,1}^n (ternary planted secret)
/// - e ∈ {-2,-1,0,1,2}^m (small error)
/// - Threshold: ||As - b||² < 300
contract WeakLWEPuzzleV4 {
    uint256 public constant N_WEAK = 40;
    uint256 public constant M_WEAK = 60;
    uint256 public constant Q_WEAK = 2039;
    uint256 public constant THRESHOLD_SQ = 300;
    
    bytes32 public constant PUZZLE_DOMAIN = keccak256("TLOS-PlantedLWE-v4");
    
    /// @notice Verify a planted LWE puzzle solution
    /// @param x The original input (puzzle is derived from H(x))
    /// @param solution The proposed solution s ∈ {-1,0,1}^40
    /// @return valid True if solution is valid
    /// @return sHash Hash of solution
    function verifyPuzzle(bytes32 x, int8[40] calldata solution) 
        external 
        pure 
        returns (bool valid, bytes32 sHash) 
    {
        unchecked {
            // Check solution is ternary {-1, 0, 1}
            for (uint256 i = 0; i < N_WEAK; ++i) {
                if (solution[i] < -1 || solution[i] > 1) {
                    return (false, bytes32(0));
                }
            }
            
            bytes32 seed = keccak256(abi.encodePacked(PUZZLE_DOMAIN, x));
            
            // Derive planted secret (3 keccaks for 48 elements, use 40)
            int16[48] memory planted;
            bytes32 secretSeed = keccak256(abi.encodePacked(seed, "planted-secret"));
            
            for (uint256 blk = 0; blk < 3; ++blk) {
                bytes32 coeffs = keccak256(abi.encodePacked(secretSeed, blk));
                uint256 coeffsInt = uint256(coeffs);
                
                for (uint256 k = 0; k < 16; ++k) {
                    uint256 idx = blk * 16 + k;
                    if (idx >= N_WEAK) break;
                    
                    uint256 shift = (15 - k) * 16;
                    uint256 sRaw = (coeffsInt >> shift) & 0xFFFF;
                    planted[idx] = int16(int256(sRaw % 3) - 1);
                }
            }
            
            uint256 normSq = 0;
            
            for (uint256 row = 0; row < M_WEAK; ++row) {
                bytes32 rowSeed = keccak256(abi.encodePacked(seed, row));
                
                int256 dotCandidate = 0;
                int256 dotPlanted = 0;
                
                // 3 blocks of 16 coefficients
                for (uint256 blk = 0; blk < 3; ++blk) {
                    bytes32 coeffs = keccak256(abi.encodePacked(rowSeed, blk));
                    uint256 coeffsInt = uint256(coeffs);
                    
                    for (uint256 k = 0; k < 16; ++k) {
                        uint256 col = blk * 16 + k;
                        if (col >= N_WEAK) break;
                        
                        uint256 shift = (15 - k) * 16;
                        int256 aij = int256((coeffsInt >> shift) & 0xFFFF) % int256(Q_WEAK);
                        
                        dotCandidate += aij * int256(solution[col]);
                        dotPlanted += aij * int256(planted[col]);
                    }
                }
                
                // Error: e = (errorSeed % 5) - 2
                bytes32 errorSeed = keccak256(abi.encodePacked(seed, "error", row));
                int256 e = int256(uint256(errorSeed) % 5) - 2;
                
                // b = (dotPlanted + e) mod q
                int256 bRow = (dotPlanted + e) % int256(Q_WEAK);
                if (bRow < 0) bRow += int256(Q_WEAK);
                
                // Residual = (dotCandidate - bRow) mod q, centered
                int256 residual = (dotCandidate - bRow) % int256(Q_WEAK);
                if (residual > int256(Q_WEAK / 2)) {
                    residual -= int256(Q_WEAK);
                } else if (residual < -int256(Q_WEAK / 2)) {
                    residual += int256(Q_WEAK);
                }
                
                normSq += uint256(residual * residual);
            }
            
            valid = normSq < THRESHOLD_SQ;
            
            if (valid) {
                sHash = keccak256(abi.encodePacked(solution));
            }
        }
    }
    
    /// @notice Derive the planted secret s* from seed
    function _derivePlantedSecret(bytes32 seed) internal pure returns (int8[40] memory secret) {
        bytes32 secretSeed = keccak256(abi.encodePacked(seed, "planted-secret"));
        
        for (uint256 col = 0; col < N_WEAK; col += 16) {
            bytes32 coeffs = keccak256(abi.encodePacked(secretSeed, col / 16));
            
            for (uint256 k = 0; k < 16 && col + k < N_WEAK; ++k) {
                uint256 shift = (15 - k) * 16;
                uint256 sRaw = (uint256(coeffs) >> shift) & 0xFFFF;
                secret[col + k] = int8(int256(sRaw % 3) - 1);
            }
        }
    }
    
    /// @notice Get the planted secret for testing/solver
    function getPlantedSecret(bytes32 x) external pure returns (int8[40] memory) {
        bytes32 seed = keccak256(abi.encodePacked(PUZZLE_DOMAIN, x));
        return _derivePlantedSecret(seed);
    }
    
    /// @notice Get puzzle seed for off-chain solving
    function getPuzzleSeed(bytes32 x) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(PUZZLE_DOMAIN, x));
    }
}
