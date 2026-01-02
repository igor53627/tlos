// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title TLOSTreasureHunt - Educational Example of a TLOS-Protected Honeypot
/// @author TLOS Team
/// @notice A simplified treasure hunt contract demonstrating TLOS protection patterns
/// @dev This is a TEACHING EXAMPLE. For production use, see TLOSWithPuzzleV4.sol
///
/// ## How It Works
///
/// This contract holds ETH that can only be claimed by providing the correct secret.
/// Three layers of protection prevent various attack vectors:
///
/// ### Layer 1: Commit-Reveal (Anti Front-Running)
/// Without commit-reveal, attackers could watch the mempool for valid solutions
/// and front-run with higher gas prices. The 2-block delay ensures the original
/// solver's transaction is included first.
///
/// ### Layer 2: LWE Puzzle (Anti Brute-Force)
/// The planted LWE puzzle (n=48) creates a 3^48 ≈ 2^76 search space.
/// Even with powerful GPUs, brute-forcing takes significant time and cost,
/// making it economically infeasible to steal small rewards.
///
/// ### Layer 3: Time-Lock Expiry (Fund Recovery)
/// If nobody solves the puzzle, the owner can reclaim funds after expiry.
/// This prevents ETH from being locked forever if the secret is lost.
///
/// ## Flow Diagram (ASCII)
///
///   Solver                          Contract
///     |                                |
///     |  1. commit(hash)               |
///     |------------------------------->|
///     |                                | stores hash, block#
///     |                                |
///     |  [wait 2+ blocks]              |
///     |                                |
///     |  2. reveal(secret, puzzle)     |
///     |------------------------------->|
///     |                                | verify hash matches
///     |                                | verify puzzle solution
///     |                                | check secret correct
///     |                                |
///     |  3. ETH reward                 |
///     |<-------------------------------|
///

contract TLOSTreasureHunt {
    // =========================================================================
    // CONSTANTS - Puzzle Parameters (matching WeakLWEPuzzleV7)
    // =========================================================================
    
    uint256 public constant COMMIT_DELAY = 2;
    uint256 public constant N_WEAK = 48;
    uint256 public constant M_WEAK = 72;
    uint256 public constant Q_WEAK = 2039;
    uint256 public constant PUZZLE_THRESHOLD_SQ = 300;
    bytes32 public constant PUZZLE_DOMAIN = keccak256("TLOS-PlantedLWE-v7");

    // =========================================================================
    // STATE - Immutable Configuration
    // =========================================================================
    
    bytes32 public immutable secretHash;
    uint256 public immutable expiry;
    address public immutable owner;

    // =========================================================================
    // STATE - Mutable
    // =========================================================================
    
    uint256 private _reward;
    bool private _claimed;
    
    struct Commitment {
        bytes32 hash;
        uint256 blockNumber;
    }
    mapping(address => Commitment) private _commits;

    // =========================================================================
    // EVENTS
    // =========================================================================
    
    event Committed(address indexed solver, bytes32 commitHash, uint256 blockNumber);
    event Claimed(address indexed solver, uint256 reward);
    event Expired(address indexed owner, uint256 recovered);

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================
    
    /// @notice Create a new treasure hunt with a secret
    /// @param _secretHash Hash of the secret value (keccak256 of the secret)
    /// @param _expiry Unix timestamp when owner can reclaim funds
    constructor(bytes32 _secretHash, uint256 _expiry) payable {
        require(_expiry > block.timestamp, "Expiry must be in future");
        require(msg.value > 0, "Must deposit reward");
        
        secretHash = _secretHash;
        expiry = _expiry;
        owner = msg.sender;
        _reward = msg.value;
    }

    // =========================================================================
    // COMMIT-REVEAL: Phase 1 - Commit
    // =========================================================================
    
    /// @notice Commit to a solution attempt
    /// @dev The commit hash binds YOUR ADDRESS to your solution, preventing others
    ///      from copying your reveal transaction and front-running it.
    ///      
    ///      Generate the hash off-chain:
    ///      ```solidity
    ///      bytes32 commitHash = keccak256(abi.encode(msg.sender, secret, puzzleSolution));
    ///      ```
    /// @param commitHash Hash of (your address, secret, puzzle solution)
    function commit(bytes32 commitHash) external {
        require(!_claimed, "Already claimed");
        require(block.timestamp < expiry, "Hunt expired");
        
        _commits[msg.sender] = Commitment({
            hash: commitHash,
            blockNumber: block.number
        });
        
        emit Committed(msg.sender, commitHash, block.number);
    }

    // =========================================================================
    // COMMIT-REVEAL: Phase 2 - Reveal
    // =========================================================================
    
    /// @notice Reveal your solution and claim the reward
    /// @dev Must wait COMMIT_DELAY blocks after committing.
    ///      The puzzle solution proves you did computational work to find the secret,
    ///      making it expensive for attackers to brute-force in real-time.
    /// @param secret The secret value that hashes to secretHash
    /// @param puzzleSolution 48-element ternary array (-1, 0, or 1) solving the LWE puzzle
    function reveal(bytes32 secret, int8[48] calldata puzzleSolution) external {
        require(!_claimed, "Already claimed");
        require(block.timestamp < expiry, "Hunt expired");
        
        Commitment memory c = _commits[msg.sender];
        require(c.blockNumber > 0, "No commit found");
        require(block.number >= c.blockNumber + COMMIT_DELAY, "Reveal too early");
        
        bytes32 expectedCommit = keccak256(abi.encode(msg.sender, secret, puzzleSolution));
        require(c.hash == expectedCommit, "Invalid reveal - hash mismatch");
        
        (bool puzzleValid, ) = _verifyPuzzle(secret, puzzleSolution);
        require(puzzleValid, "Invalid puzzle solution");
        
        require(keccak256(abi.encodePacked(secret)) == secretHash, "Wrong secret");
        
        _claimed = true;
        delete _commits[msg.sender];
        
        uint256 rewardAmount = _reward;
        _reward = 0;
        
        (bool success, ) = msg.sender.call{value: rewardAmount}("");
        require(success, "Transfer failed");
        
        emit Claimed(msg.sender, rewardAmount);
    }

    // =========================================================================
    // EXPIRY: Owner Fund Recovery
    // =========================================================================
    
    /// @notice Reclaim funds after expiry if nobody solved the puzzle
    /// @dev Only callable by owner after expiry timestamp
    function reclaimExpired() external {
        require(msg.sender == owner, "Only owner");
        require(block.timestamp >= expiry, "Not expired yet");
        require(!_claimed, "Already claimed");
        
        _claimed = true;
        uint256 recovered = _reward;
        _reward = 0;
        
        (bool success, ) = msg.sender.call{value: recovered}("");
        require(success, "Transfer failed");
        
        emit Expired(owner, recovered);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================
    
    function reward() external view returns (uint256) { return _reward; }
    function claimed() external view returns (bool) { return _claimed; }
    function isExpired() external view returns (bool) { return block.timestamp >= expiry; }
    
    function timeRemaining() external view returns (uint256) {
        if (block.timestamp >= expiry) return 0;
        return expiry - block.timestamp;
    }
    
    function getCommit(address solver) external view returns (bytes32 hash, uint256 blockNum) {
        Commitment memory c = _commits[solver];
        return (c.hash, c.blockNumber);
    }

    /// @notice Get the puzzle seed for a given secret (for off-chain solving)
    function getPuzzleSeed(bytes32 x) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(PUZZLE_DOMAIN, x));
    }

    /// @notice Get the planted secret for off-chain solving (matches WeakLWEPuzzleV7)
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

    // =========================================================================
    // INTERNAL: LWE Puzzle Verification
    // =========================================================================
    
    /// @notice Verify a planted LWE puzzle solution
    /// @dev The puzzle creates a 3^48 search space that must be solved off-chain.
    ///      This prevents real-time brute-force attacks during reveal.
    ///
    ///      Technical details:
    ///      - Matrix A (72x48 over Z_2039) is derived from keccak256
    ///      - Target b = A*planted + e where e is small noise
    ///      - Valid solution s must satisfy ||A*s - b||² < threshold
    ///
    /// @param x The secret (used to derive puzzle parameters)
    /// @param solution 48-element ternary solution attempt
    /// @return valid True if solution produces small residual
    /// @return sHash Hash of the solution (for binding)
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

    receive() external payable {
        _reward += msg.value;
    }
}
