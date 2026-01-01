// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title WeakLWEPuzzleV2 - Layer 4: Planted LWE Puzzle
/// @notice Proper LWE construction with planted secret and error
/// @dev For each input x:
///   1. Derive A ∈ Z_q^{m×n} from seed
///   2. Derive planted secret s* ∈ {-1,0,1}^n from seed (SAME for all rows)
///   3. Derive small error e ∈ {-2,...,2}^m from seed
///   4. Compute b = A·s* + e mod q
///   5. Solver must find s with ||As - b|| small (s = s* works)
///
/// This ensures a solution EXISTS for every input x.
/// The deployer knows s* (can solve trivially) - fine for honeypots.
///
/// Parameters (targeting ~2^18-2^22 BKZ work based on LWE estimator):
/// - n = 40 (secret dimension)
/// - m = 60 (number of samples, overdetermined)
/// - q = 2039 (prime near 2^11)
/// - s* ∈ {-1,0,1}^n (ternary planted secret)
/// - e ∈ {-2,-1,0,1,2}^m (small error, σ ≈ 1.4)
/// - Threshold: ||As - b||² < 300 (allows for error norm ~√300 ≈ 17)
contract WeakLWEPuzzleV2 {
    uint256 public constant N_WEAK = 40;       // Secret dimension
    uint256 public constant M_WEAK = 60;       // Number of samples
    uint256 public constant Q_WEAK = 2039;     // Prime modulus
    uint256 public constant THRESHOLD_SQ = 300; // E[||e||²] ≈ m * σ² ≈ 60 * 2 = 120, threshold with slack
    
    bytes32 public constant PUZZLE_DOMAIN = keccak256("TLOS-PlantedLWE-v2");
    
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
        // Check solution is ternary {-1, 0, 1}
        for (uint256 i = 0; i < N_WEAK; i++) {
            if (solution[i] < -1 || solution[i] > 1) {
                return (false, bytes32(0));
            }
        }
        
        bytes32 seed = keccak256(abi.encodePacked(PUZZLE_DOMAIN, x));
        
        // Derive planted secret s* (ONCE, same for all rows)
        int8[40] memory plantedSecret = _derivePlantedSecret(seed);
        
        uint256 normSq = 0;
        
        for (uint256 row = 0; row < M_WEAK; row++) {
            // Generate row of A
            bytes32 rowSeed = keccak256(abi.encodePacked(seed, row));
            
            // Compute A[row]·s (candidate solution)
            int256 dotProductCandidate = 0;
            // Compute A[row]·s* (planted secret)
            int256 dotProductPlanted = 0;
            
            for (uint256 col = 0; col < N_WEAK; col += 16) {
                bytes32 coeffs = keccak256(abi.encodePacked(rowSeed, col / 16));
                
                for (uint256 k = 0; k < 16 && col + k < N_WEAK; k++) {
                    uint256 shift = (15 - k) * 16;
                    int256 aij = int256((uint256(coeffs) >> shift) & 0xFFFF) % int256(Q_WEAK);
                    
                    dotProductCandidate += aij * int256(solution[col + k]);
                    dotProductPlanted += aij * int256(plantedSecret[col + k]);
                }
            }
            
            // Generate error e[row] ∈ {-2,-1,0,1,2}
            bytes32 errorSeed = keccak256(abi.encodePacked(seed, "error", row));
            int256 e = int256(uint256(errorSeed) % 5) - 2;
            
            // b[row] = A[row]·s* + e[row] mod q
            int256 bRow = (dotProductPlanted + e) % int256(Q_WEAK);
            if (bRow < 0) bRow += int256(Q_WEAK);
            
            // Residual = A[row]·s - b[row] mod q, centered
            int256 residual = (dotProductCandidate - bRow) % int256(Q_WEAK);
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
    
    /// @notice Derive the planted secret s* from seed
    function _derivePlantedSecret(bytes32 seed) internal pure returns (int8[40] memory secret) {
        bytes32 secretSeed = keccak256(abi.encodePacked(seed, "planted-secret"));
        
        for (uint256 col = 0; col < N_WEAK; col += 16) {
            bytes32 coeffs = keccak256(abi.encodePacked(secretSeed, col / 16));
            
            for (uint256 k = 0; k < 16 && col + k < N_WEAK; k++) {
                uint256 shift = (15 - k) * 16;
                uint256 sRaw = (uint256(coeffs) >> shift) & 0xFFFF;
                secret[col + k] = int8(int256(sRaw % 3) - 1); // {-1, 0, 1}
            }
        }
    }
    
    /// @notice Get the planted secret for testing/solver
    /// @dev The deployer knows this; attackers must solve LWE
    function getPlantedSecret(bytes32 x) external pure returns (int8[40] memory) {
        bytes32 seed = keccak256(abi.encodePacked(PUZZLE_DOMAIN, x));
        return _derivePlantedSecret(seed);
    }
    
    /// @notice Get puzzle seed for off-chain solving
    function getPuzzleSeed(bytes32 x) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(PUZZLE_DOMAIN, x));
    }
    
    /// @notice Compute expected error norm for a given input (for testing)
    function getExpectedErrorNorm(bytes32 x) external pure returns (uint256 normSq) {
        bytes32 seed = keccak256(abi.encodePacked(PUZZLE_DOMAIN, x));
        
        for (uint256 row = 0; row < M_WEAK; row++) {
            bytes32 errorSeed = keccak256(abi.encodePacked(seed, "error", row));
            int256 e = int256(uint256(errorSeed) % 5) - 2;
            normSq += uint256(e * e);
        }
    }
}
