// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title TLOSRecovery - Wallet Recovery Protected by TLOS Puzzle
/// @author TLOS Project
/// @notice Demonstrates using TLOS for human-memorable phrase-based wallet recovery
///
/// CAUTION: Phrase Entropy Requirements
/// =====================================
/// Human-memorable phrases typically have LOW entropy (20-40 bits).
/// The TLOS puzzle adds ~76 bits of computational work, but this does NOT
/// compensate for weak phrases. Attackers can enumerate common phrases
/// and pre-solve puzzles for each.
///
/// Recommended minimum phrase entropy: 80+ bits (e.g., 6+ random Diceware words)
/// Consider: Time-locked recovery, multi-sig backup, or hardware wallet instead.
///
/// This contract is for DEMONSTRATION PURPOSES. Production deployments should
/// undergo thorough security review.

contract TLOSRecovery {
    uint256 public constant N_WEAK = 48;
    uint256 public constant M_WEAK = 72;
    uint256 public constant Q_WEAK = 2039;
    uint256 public constant PUZZLE_THRESHOLD_SQ = 300;
    bytes32 public constant PUZZLE_DOMAIN = keccak256("TLOS-PlantedLWE-v7");

    address public owner;
    bytes32 public phraseHash;
    uint256 public lastAttemptBlock;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event RecoveryAttempted(address indexed attemptedBy, bool success);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(bytes32 _phraseHash) {
        owner = msg.sender;
        phraseHash = _phraseHash;
    }

    /// @notice Recover wallet ownership using the correct phrase and puzzle solution
    /// @param phrase The raw recovery phrase as bytes32 (will be hashed internally to verify)
    /// @param puzzleSolution The ternary solution to the planted LWE puzzle
    function recover(bytes32 phrase, int8[48] calldata puzzleSolution) external {
        require(block.number > lastAttemptBlock, "Rate limited: 1 attempt per block");
        lastAttemptBlock = block.number;

        require(keccak256(abi.encodePacked(phrase)) == phraseHash, "Invalid phrase");

        (bool puzzleValid, ) = _verifyPuzzle(phrase, puzzleSolution);
        require(puzzleValid, "Invalid puzzle solution");

        address previousOwner = owner;
        owner = msg.sender;

        emit RecoveryAttempted(msg.sender, true);
        emit OwnershipTransferred(previousOwner, msg.sender);
    }

    /// @notice Check if a phrase and puzzle solution are valid without changing state
    function checkRecovery(bytes32 phrase, int8[48] calldata puzzleSolution) 
        external 
        view 
        returns (bool) 
    {
        if (keccak256(abi.encodePacked(phrase)) != phraseHash) {
            return false;
        }
        (bool puzzleValid, ) = _verifyPuzzle(phrase, puzzleSolution);
        return puzzleValid;
    }

    /// @notice Update the recovery phrase hash (only owner)
    function updatePhraseHash(bytes32 newPhraseHash) external onlyOwner {
        phraseHash = newPhraseHash;
    }

    /// @notice Get the planted secret for off-chain puzzle solving
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

    /// @notice Get the puzzle seed for a given input
    function getPuzzleSeed(bytes32 x) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(PUZZLE_DOMAIN, x));
    }

    function _verifyPuzzle(bytes32 x, int8[48] calldata solution) 
        internal 
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
            
            valid = normSq < PUZZLE_THRESHOLD_SQ;
            
            if (valid) {
                sHash = keccak256(abi.encodePacked(solution));
            }
        }
    }

    receive() external payable {}
}
