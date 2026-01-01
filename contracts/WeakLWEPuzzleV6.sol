// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title WeakLWEPuzzleV6 - Layer 4: Planted LWE Puzzle (Further Reduced)
/// @notice n=24, m=36 for ~380K gas while maintaining ~2^38 search space
/// @dev Parameters:
/// - n = 24 (secret dimension, 3^24 ≈ 2^38 search space)
/// - m = 36 (number of samples)
/// - q = 2039 (prime near 2^11)
/// - Threshold: ||As - b||² < 150
///
/// Security: 3^24 ≈ 2^38 search space
/// GPU brute-force: ~400M guesses/sec → ~11 minutes on 100 GPUs
/// Not secure alone, but combined with TLOS circuit it adds significant overhead
contract WeakLWEPuzzleV6 {
    uint256 public constant N_WEAK = 24;
    uint256 public constant M_WEAK = 36;
    uint256 public constant Q_WEAK = 2039;
    uint256 public constant THRESHOLD_SQ = 150;
    
    bytes32 public constant PUZZLE_DOMAIN = keccak256("TLOS-PlantedLWE-v6");
    
    /// @notice Verify a planted LWE puzzle solution
    function verifyPuzzle(bytes32 x, int8[24] calldata solution) 
        external 
        pure 
        returns (bool valid, bytes32 sHash) 
    {
        unchecked {
            for (uint256 i = 0; i < N_WEAK; ++i) {
                if (solution[i] < -1 || solution[i] > 1) {
                    return (false, bytes32(0));
                }
            }
            
            bytes32 seed = keccak256(abi.encodePacked(PUZZLE_DOMAIN, x));
            
            // Derive planted secret (2 keccaks, use 24 of 32)
            int16[32] memory planted;
            bytes32 secretSeed = keccak256(abi.encodePacked(seed, "planted-secret"));
            
            for (uint256 blk = 0; blk < 2; ++blk) {
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
                
                // 2 blocks of 16 coefficients (use 24)
                for (uint256 blk = 0; blk < 2; ++blk) {
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
                
                bytes32 errorSeed = keccak256(abi.encodePacked(seed, "error", row));
                int256 e = int256(uint256(errorSeed) % 5) - 2;
                
                int256 bRow = (dotPlanted + e) % int256(Q_WEAK);
                if (bRow < 0) bRow += int256(Q_WEAK);
                
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
    
    function _derivePlantedSecret(bytes32 seed) internal pure returns (int8[24] memory secret) {
        bytes32 secretSeed = keccak256(abi.encodePacked(seed, "planted-secret"));
        
        for (uint256 blk = 0; blk < 2; ++blk) {
            bytes32 coeffs = keccak256(abi.encodePacked(secretSeed, blk));
            
            for (uint256 k = 0; k < 16; ++k) {
                uint256 idx = blk * 16 + k;
                if (idx >= N_WEAK) break;
                uint256 shift = (15 - k) * 16;
                uint256 sRaw = (uint256(coeffs) >> shift) & 0xFFFF;
                secret[idx] = int8(int256(sRaw % 3) - 1);
            }
        }
    }
    
    function getPlantedSecret(bytes32 x) external pure returns (int8[24] memory) {
        bytes32 seed = keccak256(abi.encodePacked(PUZZLE_DOMAIN, x));
        return _derivePlantedSecret(seed);
    }
    
    function getPuzzleSeed(bytes32 x) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(PUZZLE_DOMAIN, x));
    }
}
