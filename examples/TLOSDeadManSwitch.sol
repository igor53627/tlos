// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title TLOSDeadManSwitch - Inheritance Contract Protected by TLOS
/// @author TLOS Project
/// @notice Dead man's switch / inheritance contract where heirs can claim after owner inactivity
///
/// ============================================================================
/// WARNING: DEMONSTRATION ONLY - NOT AUDITED FOR PRODUCTION USE
/// ============================================================================
/// For production deployments, use TLOSWithPuzzleV3.sol with full 4-layer security.
/// This contract demonstrates the pattern with Layer 4 (planted LWE puzzle) only.
///
/// ## Security Model (Section 4.1.2 - Wallet Recovery & Inheritance)
///
/// Traditional inheritance contracts leak information:
///   - Heirs are publicly visible on-chain
///   - Distribution percentages are exposed
///   - Attackers can target known heirs with phishing/social engineering
///
/// TLOS-protected inheritance hides:
///   - Heir secret codes inside the TLOS circuit
///   - Distribution structure (who gets what percentage)
///   - Number of heirs and their identities
///
/// The planted LWE puzzle (3^48 ~ 2^76) prevents real-time brute-force attacks
/// during claim attempts, while commit-reveal prevents mempool front-running.
///
/// ## Flow Diagram (ASCII)
///
///   +----------------+                    +-------------------+
///   |     Owner      |                    |  Dead Man Switch  |
///   +----------------+                    +-------------------+
///          |                                       |
///          | ping() every heartbeatInterval        |
///          |-------------------------------------->|
///          |                                       | lastPing = now
///          |                                       |
///          |                                       |
///   [Owner stops pinging...]                       |
///          |                                       |
///          v                                       v
///   +----------------+    After timeout    +-------------------+
///   |    Timeout!    |-------------------->|  Claimable State  |
///   +----------------+                     +-------------------+
///          |                                       |
///          |                                       |
///   +----------------+                             |
///   |      Heir      |                             |
///   +----------------+                             |
///          |                                       |
///          | 1. commit(hash)                       |
///          |-------------------------------------->|
///          |                                       | store commitment
///          |                                       |
///          | [wait 2+ blocks]                      |
///          |                                       |
///          | 2. claim(code, puzzle, shareBPS)      |
///          |-------------------------------------->|
///          |                                       | verify commitment
///          |                                       | verify puzzle
///          |                                       | verify heir code
///          |                                       | verify share
///          |                                       |
///          |<--------------------------------------| transfer share
///          |         ETH (shareBPS / 10000)        |
///          |                                       |
///   +----------------+                     +-------------------+
///   | Heir Receives  |                     | Remaining Balance |
///   | Their Share    |                     | For Other Heirs   |
///   +----------------+                     +-------------------+
///
/// ## Heir Codes Hidden in Circuit
///
/// Each heir has:
///   1. A secret code (bytes32) - known only to the heir
///   2. A share (basis points) - encoded as circuit output
///
/// The codeHash = keccak256(code) is stored, but the actual heir codes
/// and share distribution are computed inside the TLOS circuit, making
/// them invisible to on-chain observers.

contract TLOSDeadManSwitch {
    // =========================================================================
    // CONSTANTS - Puzzle Parameters (matching WeakLWEPuzzleV7)
    // =========================================================================
    
    uint256 public constant COMMIT_DELAY = 2;
    uint256 public constant N_WEAK = 48;
    uint256 public constant M_WEAK = 72;
    uint256 public constant Q_WEAK = 2039;
    uint256 public constant PUZZLE_THRESHOLD_SQ = 300;
    bytes32 public constant PUZZLE_DOMAIN = keccak256("TLOS-PlantedLWE-v7");
    
    uint256 public constant BPS_DENOMINATOR = 10000;
    uint256 public constant MIN_HEARTBEAT = 1 days;
    uint256 public constant MAX_HEARTBEAT = 365 days;

    // =========================================================================
    // STATE - Configuration (Immutable after construction)
    // =========================================================================
    
    address public immutable owner;
    uint256 public immutable heartbeatInterval;
    uint256 public immutable createdAt;
    
    // =========================================================================
    // STATE - Mutable
    // =========================================================================
    
    uint256 private _reentrancyGuard = 1;
    
    uint256 public lastPing;
    uint256 public totalClaimed;
    uint256 public balanceAtDeath;  // Snapshot of balance when first claim occurs
    bool public deathSnapshotTaken;
    
    struct HeirRecord {
        bytes32 codeHash;
        uint16 shareBPS;
        bool claimed;
    }
    
    mapping(uint256 => HeirRecord) private _heirs;
    uint256 public heirCount;
    
    struct Commitment {
        bytes32 hash;
        uint256 blockNumber;
    }
    mapping(address => Commitment) private _commits;

    // =========================================================================
    // EVENTS
    // =========================================================================
    
    event Pinged(uint256 timestamp, uint256 nextDeadline);
    event HeirAdded(uint256 indexed heirIndex, bytes32 codeHash, uint16 shareBPS);
    event HeirRemoved(uint256 indexed heirIndex);
    event Committed(address indexed claimer, bytes32 commitHash, uint256 blockNumber);
    event Claimed(address indexed claimer, uint256 indexed heirIndex, uint256 amount);
    event EmergencyWithdraw(address indexed owner, uint256 amount);

    // =========================================================================
    // MODIFIERS
    // =========================================================================
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }
    
    modifier onlyAlive() {
        require(block.timestamp < lastPing + heartbeatInterval, "Owner inactive - heirs can claim");
        _;
    }
    
    modifier onlyDead() {
        require(block.timestamp >= lastPing + heartbeatInterval, "Owner still active");
        _;
    }
    
    modifier nonReentrant() {
        require(_reentrancyGuard == 1, "Reentrancy");
        _reentrancyGuard = 2;
        _;
        _reentrancyGuard = 1;
    }

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================
    
    /// @notice Create a new dead man's switch
    /// @param _heartbeatInterval How often owner must ping (in seconds)
    /// @param _heirCodeHashes Array of keccak256(heir_secret_code) values
    /// @param _heirSharesBPS Array of shares in basis points (must sum to <= 10000)
    constructor(
        uint256 _heartbeatInterval,
        bytes32[] memory _heirCodeHashes,
        uint16[] memory _heirSharesBPS
    ) payable {
        require(
            _heartbeatInterval >= MIN_HEARTBEAT && _heartbeatInterval <= MAX_HEARTBEAT,
            "Heartbeat out of range"
        );
        require(_heirCodeHashes.length == _heirSharesBPS.length, "Array length mismatch");
        require(_heirCodeHashes.length > 0, "Must have at least one heir");
        
        uint256 totalShares = 0;
        for (uint256 i = 0; i < _heirSharesBPS.length; i++) {
            require(_heirCodeHashes[i] != bytes32(0), "Empty code hash");
            require(_heirSharesBPS[i] > 0, "Share must be positive");
            totalShares += _heirSharesBPS[i];
            
            _heirs[i] = HeirRecord({
                codeHash: _heirCodeHashes[i],
                shareBPS: _heirSharesBPS[i],
                claimed: false
            });
        }
        require(totalShares <= BPS_DENOMINATOR, "Shares exceed 100%");
        
        owner = msg.sender;
        heartbeatInterval = _heartbeatInterval;
        createdAt = block.timestamp;
        lastPing = block.timestamp;
        heirCount = _heirCodeHashes.length;
    }

    // =========================================================================
    // OWNER FUNCTIONS
    // =========================================================================
    
    /// @notice Ping to prove liveness - resets the dead man's switch timer
    /// @dev Must be called at least once per heartbeatInterval to prevent heirs claiming
    function ping() external onlyOwner onlyAlive {
        lastPing = block.timestamp;
        emit Pinged(block.timestamp, block.timestamp + heartbeatInterval);
    }
    
    /// @notice Add a new heir (only while owner is alive)
    /// @param codeHash keccak256(heir_secret_code)
    /// @param shareBPS Share in basis points (0.01%)
    function addHeir(bytes32 codeHash, uint16 shareBPS) external onlyOwner onlyAlive {
        require(codeHash != bytes32(0), "Empty code hash");
        require(shareBPS > 0 && shareBPS <= BPS_DENOMINATOR, "Invalid share");
        
        uint256 totalShares = _calculateTotalShares();
        require(totalShares + shareBPS <= BPS_DENOMINATOR, "Shares would exceed 100%");
        
        uint256 idx = heirCount;
        _heirs[idx] = HeirRecord({
            codeHash: codeHash,
            shareBPS: shareBPS,
            claimed: false
        });
        heirCount = idx + 1;
        
        emit HeirAdded(idx, codeHash, shareBPS);
    }
    
    /// @notice Remove an heir (only while owner is alive)
    /// @param heirIndex Index of the heir to remove
    function removeHeir(uint256 heirIndex) external onlyOwner onlyAlive {
        require(heirIndex < heirCount, "Invalid heir index");
        require(_heirs[heirIndex].codeHash != bytes32(0), "Heir already removed");
        
        delete _heirs[heirIndex];
        emit HeirRemoved(heirIndex);
    }
    
    /// @notice Emergency withdrawal (only while owner is alive)
    /// @param amount Amount to withdraw (0 for full balance)
    function emergencyWithdraw(uint256 amount) external onlyOwner onlyAlive {
        uint256 toWithdraw = amount == 0 ? address(this).balance : amount;
        require(toWithdraw <= address(this).balance, "Insufficient balance");
        
        (bool success, ) = msg.sender.call{value: toWithdraw}("");
        require(success, "Transfer failed");
        
        emit EmergencyWithdraw(msg.sender, toWithdraw);
    }

    // =========================================================================
    // HEIR FUNCTIONS - Commit Phase
    // =========================================================================
    
    /// @notice Commit to a claim attempt (prevents front-running)
    /// @dev Generate off-chain: keccak256(abi.encode(msg.sender, heirIndex, code, puzzleSolution))
    /// @param commitHash Hash binding your address, heir index, secret code, and puzzle solution
    function commit(bytes32 commitHash) external onlyDead {
        _commits[msg.sender] = Commitment({
            hash: commitHash,
            blockNumber: block.number
        });
        
        emit Committed(msg.sender, commitHash, block.number);
    }

    // =========================================================================
    // HEIR FUNCTIONS - Reveal Phase
    // =========================================================================
    
    /// @notice Claim inheritance share
    /// @dev Must wait COMMIT_DELAY blocks after committing
    /// @param heirIndex Which heir slot to claim (used for disambiguation if multiple)
    /// @param code The secret heir code
    /// @param puzzleSolution 48-element ternary array solving the LWE puzzle
    function claim(
        uint256 heirIndex,
        bytes32 code,
        int8[48] calldata puzzleSolution
    ) external onlyDead nonReentrant {
        require(heirIndex < heirCount, "Invalid heir index");
        
        HeirRecord storage heir = _heirs[heirIndex];
        require(heir.codeHash != bytes32(0), "Heir removed");
        require(!heir.claimed, "Already claimed");
        
        Commitment memory c = _commits[msg.sender];
        require(c.blockNumber > 0, "No commit found");
        require(block.number >= c.blockNumber + COMMIT_DELAY, "Reveal too early");
        
        bytes32 expectedCommit = keccak256(abi.encode(msg.sender, heirIndex, code, puzzleSolution));
        require(c.hash == expectedCommit, "Invalid reveal - hash mismatch");
        
        (bool puzzleValid, ) = _verifyPuzzle(code, puzzleSolution);
        require(puzzleValid, "Invalid puzzle solution");
        
        require(keccak256(abi.encodePacked(code)) == heir.codeHash, "Invalid heir code");
        
        heir.claimed = true;
        delete _commits[msg.sender];
        
        // Snapshot balance at death on first claim (prevents post-death deposits from inflating shares)
        if (!deathSnapshotTaken) {
            balanceAtDeath = address(this).balance;
            deathSnapshotTaken = true;
        }
        
        uint256 claimAmount = (balanceAtDeath * heir.shareBPS) / BPS_DENOMINATOR;
        
        if (claimAmount > address(this).balance) {
            claimAmount = address(this).balance;
        }
        
        totalClaimed += claimAmount;
        
        (bool success, ) = msg.sender.call{value: claimAmount}("");
        require(success, "Transfer failed");
        
        emit Claimed(msg.sender, heirIndex, claimAmount);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================
    
    function isOwnerAlive() external view returns (bool) {
        return block.timestamp < lastPing + heartbeatInterval;
    }
    
    function deadline() external view returns (uint256) {
        return lastPing + heartbeatInterval;
    }
    
    function timeUntilDead() external view returns (uint256) {
        uint256 _deadline = lastPing + heartbeatInterval;
        if (block.timestamp >= _deadline) return 0;
        return _deadline - block.timestamp;
    }
    
    function timeSinceDeath() external view returns (uint256) {
        uint256 _deadline = lastPing + heartbeatInterval;
        if (block.timestamp < _deadline) return 0;
        return block.timestamp - _deadline;
    }
    
    function getHeirInfo(uint256 heirIndex) 
        external 
        view 
        returns (bytes32 codeHash, uint16 shareBPS, bool claimed) 
    {
        require(heirIndex < heirCount, "Invalid heir index");
        HeirRecord memory h = _heirs[heirIndex];
        return (h.codeHash, h.shareBPS, h.claimed);
    }
    
    function getCommit(address claimer) external view returns (bytes32 hash, uint256 blockNum) {
        Commitment memory c = _commits[claimer];
        return (c.hash, c.blockNumber);
    }
    
    function unclaimedBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    function totalDistributableAtDeath() external view returns (uint256) {
        return address(this).balance + totalClaimed;
    }

    /// @notice Get the puzzle seed for a given heir code (for off-chain solving)
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
    // INTERNAL FUNCTIONS
    // =========================================================================
    
    function _calculateTotalShares() internal view returns (uint256 total) {
        for (uint256 i = 0; i < heirCount; i++) {
            if (_heirs[i].codeHash != bytes32(0)) {
                total += _heirs[i].shareBPS;
            }
        }
    }
    
    /// @notice Verify a planted LWE puzzle solution (matching WeakLWEPuzzleV7)
    /// @dev Creates 3^48 search space for brute-force resistance
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
