// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title WeakLWEPuzzleV7 - n=48 for ~76-bit security
/// @dev Parameters: n=48, m=72, q=2039, threshold=300
/// Search space: 3^48 ≈ 2^76
contract WeakLWEPuzzleV7 {
    uint256 public constant N_WEAK = 48;
    uint256 public constant M_WEAK = 72;
    uint256 public constant Q_WEAK = 2039;
    uint256 public constant THRESHOLD_SQ = 300; // E[||e||²] ≈ 72 * 2 = 144
    
    bytes32 public constant PUZZLE_DOMAIN = keccak256("TLOS-PlantedLWE-v7");
    
    function verifyPuzzle(bytes32 x, int8[48] calldata solution) 
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
    
    function getPlantedSecret(bytes32 x) external pure returns (int8[48] memory secret) {
        bytes32 seed = keccak256(abi.encodePacked(PUZZLE_DOMAIN, x));
        bytes32 secretSeed = keccak256(abi.encodePacked(seed, "planted-secret"));
        
        for (uint256 blk = 0; blk < 3; ++blk) {
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
}
