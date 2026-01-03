// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IHoneypot.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";

/// @title TLOSWithPuzzleV4 - 4-Layer TLOS with Properly Integrated Puzzle
/// @notice Puzzle solution is derived from SECRET, not input - attacker must solve 2^76 LWE
/// @dev Security model:
///   Layer 1 (Topology): Structural mixing defeats pattern attacks
///   Layer 2 (LWE): Standard LWE with Gaussian noise (~2^112 security, n=384)
///   Layer 3 (Wire Binding): Full-rank linear map prevents mix-and-match
///   Layer 4 (Planted LWE): 3^48 ≈ 2^76 brute-force resistance
///
/// KEY DIFFERENCE FROM V3: The planted secret is derived from the ACTUAL SECRET,
/// not from each candidate input. This means:
///   - Honest solver (who knows secret) can compute plantedSecret = H("planted", secret)
///   - Attacker must solve ternary LWE to find plantedSecret from stored (A, b)
///   - Puzzle is ONE per contract, providing 2^76 minimum work floor
///
/// LWE Parameters: n=384, q=65521, σ=8 (Gaussian noise added off-chain)
/// Puzzle Parameters: n=48, m=72, q=2039, threshold=300
contract TLOSWithPuzzleV4 is IHoneypot {
    uint256 public constant COMMIT_DELAY = 2;
    uint256 public constant Q = 65521;
    uint256 public constant LBLO_N = 384;
    uint256 public constant THRESHOLD = Q / 4;
    uint256 public constant BINDING_ROWS = 64;
    
    // Planted LWE Puzzle parameters (Layer 4)
    uint256 public constant N_WEAK = 48;
    uint256 public constant M_WEAK = 72;
    uint256 public constant Q_WEAK = 2039;
    uint256 public constant PUZZLE_THRESHOLD_SQ = 300;
    
    address public immutable circuitDataPointer;
    uint8 public immutable numWires;
    uint32 public immutable numGates;
    bytes32 public immutable expectedOutputHash;
    bytes32 public immutable circuitSeed;
    uint256 public immutable secretExpiry;
    
    uint256 public immutable expectedBindingOutput0;
    uint256 public immutable expectedBindingOutput1;
    uint256 public immutable expectedBindingOutput2;
    uint256 public immutable expectedBindingOutput3;
    
    // Puzzle storage: seed for A matrix, pointer to b vector
    bytes32 public immutable puzzleSeed;
    address public immutable puzzleBPointer;
    
    uint256 private _reward;
    bool private _claimed;
    address public immutable owner;
    
    struct Commitment { bytes32 hash; uint256 blockNumber; }
    mapping(address => Commitment) private _commits;
    
    uint256 private constant CT_SIZE = 770;
    uint256 private constant GATE_SIZE = 3083;
    
    event PuzzleSolved(address indexed solver, bytes32 indexed solutionHash, uint256 normSq);
    
    /// @param _puzzleSeed Seed for deriving A matrix (public)
    /// @param _puzzleBPointer SSTORE2 pointer to b vector (72 x u16, computed as A*plantedSecret + e)
    constructor(
        address _circuitDataPointer,
        uint8 _numWires,
        uint32 _numGates,
        bytes32 _expectedOutputHash,
        bytes32 _circuitSeed,
        uint256[4] memory _expectedBindingOutput,
        uint256 _secretExpiry,
        bytes32 _puzzleSeed,
        address _puzzleBPointer
    ) payable {
        require(_numWires > 0 && _numWires <= 64, "Wires must be 1-64");
        require(_numGates > 0, "Must have gates");
        require(_circuitDataPointer != address(0), "Invalid circuit pointer");
        require(_puzzleBPointer != address(0), "Invalid puzzle pointer");
        require(_secretExpiry > block.timestamp, "Expiry must be in future");
        
        circuitDataPointer = _circuitDataPointer;
        numWires = _numWires;
        numGates = _numGates;
        expectedOutputHash = _expectedOutputHash;
        circuitSeed = _circuitSeed;
        expectedBindingOutput0 = _expectedBindingOutput[0];
        expectedBindingOutput1 = _expectedBindingOutput[1];
        expectedBindingOutput2 = _expectedBindingOutput[2];
        expectedBindingOutput3 = _expectedBindingOutput[3];
        secretExpiry = _secretExpiry;
        puzzleSeed = _puzzleSeed;
        puzzleBPointer = _puzzleBPointer;
        owner = msg.sender;
        _reward = msg.value;
    }
    
    function commit(bytes32 commitHash) external override {
        require(block.timestamp < secretExpiry, "Secret expired");
        _commits[msg.sender] = Commitment({hash: commitHash, blockNumber: block.number});
        emit Committed(msg.sender, commitHash, block.number);
    }
    
    /// @notice Reveal with puzzle solution
    /// @dev The puzzleSolution should be computed off-chain as H("planted", secret) → ternary
    ///      For honest solver who knows secret, this is trivial.
    ///      For attacker, must solve ternary LWE from stored (A, b).
    function revealWithPuzzle(bytes32 input, int8[48] calldata puzzleSolution) external {
        require(!_claimed, "Already claimed");
        require(block.timestamp < secretExpiry, "Secret expired");
        
        Commitment memory c = _commits[msg.sender];
        require(c.blockNumber > 0, "No commit found");
        require(block.number >= c.blockNumber + COMMIT_DELAY, "Reveal too early");
        require(
            keccak256(abi.encode(msg.sender, input, puzzleSolution)) == c.hash, 
            "Invalid reveal"
        );
        
        (bool puzzleValid, bytes32 sHash, uint256 normSq) = _verifyPuzzle(puzzleSolution);
        require(puzzleValid, "Invalid puzzle solution");
        emit PuzzleSolved(msg.sender, sHash, normSq);
        
        (bool circuitValid, ) = _evaluate(input, sHash);
        require(circuitValid, "Invalid circuit output");
        
        _claimed = true;
        delete _commits[msg.sender];
        uint256 rewardAmount = _reward;
        _reward = 0;
        (bool success, ) = msg.sender.call{value: rewardAmount}("");
        require(success, "Transfer failed");
        emit Claimed(msg.sender, c.hash, rewardAmount);
    }
    
    function reveal(bytes32) external pure override {
        revert("Use revealWithPuzzle instead");
    }
    
    function checkWithPuzzle(bytes32 input, int8[48] calldata puzzleSolution) 
        external 
        view 
        returns (bool) 
    {
        (bool puzzleValid, bytes32 sHash, ) = _verifyPuzzle(puzzleSolution);
        if (!puzzleValid) return false;
        
        (bool circuitValid, ) = _evaluate(input, sHash);
        return circuitValid;
    }
    
    function check(bytes32) external pure override returns (bool) {
        return false;
    }
    
    function reclaimExpired() external {
        require(msg.sender == owner, "Only owner");
        require(block.timestamp >= secretExpiry, "Not expired yet");
        require(!_claimed, "Already claimed");
        _claimed = true;
        uint256 rewardAmount = _reward;
        _reward = 0;
        (bool success, ) = msg.sender.call{value: rewardAmount}("");
        require(success, "Transfer failed");
    }
    
    function getCommit(address committer) external view override returns (bytes32, uint256) {
        Commitment memory c = _commits[committer];
        return (c.hash, c.blockNumber);
    }
    
    function commitDelay() external pure override returns (uint256) { return COMMIT_DELAY; }
    function reward() external view override returns (uint256) { return _reward; }
    function scheme() external pure override returns (string memory) { return "tlos-lwe-puzzleV4"; }
    function encryptedGates() external pure override returns (uint256) { return 640; }
    function estimatedGas() external pure override returns (uint256) { return 9_000_000; }
    function isExpired() external view returns (bool) { return block.timestamp >= secretExpiry; }
    function timeRemaining() external view returns (uint256) {
        if (block.timestamp >= secretExpiry) return 0;
        return secretExpiry - block.timestamp;
    }
    
    /// @notice Verify puzzle solution against stored (A, b)
    /// @dev A is derived from puzzleSeed, b is stored in puzzleBPointer
    ///      Attacker must solve: given (A, b), find s ∈ {-1,0,1}^48 s.t. ||As - b|| is small
    ///      This is ternary LWE with 3^48 ≈ 2^76 search space
    function _verifyPuzzle(int8[48] calldata solution) 
        internal 
        view 
        returns (bool valid, bytes32 sHash, uint256 normSq) 
    {
        unchecked {
            // Validate ternary constraint
            for (uint256 i = 0; i < N_WEAK; ++i) {
                if (solution[i] < -1 || solution[i] > 1) {
                    return (false, bytes32(0), 0);
                }
            }
            
            // Load stored b vector (72 x u16 = 144 bytes)
            bytes memory bData = SSTORE2.read(puzzleBPointer);
            require(bData.length >= M_WEAK * 2, "Invalid puzzle data");
            
            bytes32 seed = puzzleSeed;
            normSq = 0;
            
            for (uint256 row = 0; row < M_WEAK; ++row) {
                // Derive A row from seed
                bytes32 rowSeed = keccak256(abi.encodePacked(seed, row));
                
                int256 dotProduct = 0;
                
                for (uint256 blk = 0; blk < 3; ++blk) {
                    bytes32 coeffs = keccak256(abi.encodePacked(rowSeed, blk));
                    uint256 coeffsInt = uint256(coeffs);
                    
                    for (uint256 k = 0; k < 16; ++k) {
                        uint256 col = blk * 16 + k;
                        if (col >= N_WEAK) break;
                        uint256 shift = (15 - k) * 16;
                        int256 aij = int256((coeffsInt >> shift) & 0xFFFF) % int256(Q_WEAK);
                        
                        dotProduct += aij * int256(solution[col]);
                    }
                }
                
                // Load b[row] from stored data (big-endian u16)
                uint256 bOffset = row * 2;
                int256 bRow = int256(uint256(uint8(bData[bOffset])) << 8 | uint256(uint8(bData[bOffset + 1])));
                
                // Compute residual
                int256 residual = (dotProduct - bRow) % int256(Q_WEAK);
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
    
    function _wireBindingHash(uint256 input, uint256 gateIdx) internal view returns (uint256[4] memory output) {
        uint256 q = Q;
        uint256 nWires = numWires;
        bytes32 seed = circuitSeed;
        
        assembly {
            let outPtr := output
            
            for { let row := 0 } lt(row, 64) { row := add(row, 1) } {
                let freePtr := mload(0x40)
                mstore(freePtr, seed)
                mstore(add(freePtr, 32), gateIdx)
                mstore(add(freePtr, 64), row)
                let rowSeed := keccak256(freePtr, 96)
                
                let sum := 0
                let col := 0
                
                for { let blockIdx := 0 } lt(col, nWires) { blockIdx := add(blockIdx, 1) } {
                    mstore(freePtr, rowSeed)
                    mstore(add(freePtr, 32), blockIdx)
                    let blockDigest := keccak256(freePtr, 64)
                    
                    for { let k := 0 } and(lt(k, 16), lt(col, nWires)) { k := add(k, 1) } {
                        let aij := mod(and(shr(mul(k, 16), blockDigest), 0xFFFF), q)
                        let bitVal := and(shr(col, input), 1)
                        
                        if bitVal {
                            sum := add(sum, aij)
                            if iszero(lt(sum, q)) { sum := sub(sum, q) }
                        }
                        
                        col := add(col, 1)
                    }
                }
                
                let wordIdx := div(row, 16)
                let bitPos := mul(mod(row, 16), 16)
                let wordPtr := add(outPtr, mul(wordIdx, 32))
                let existing := mload(wordPtr)
                mstore(wordPtr, or(existing, shl(bitPos, and(sum, 0xFFFF))))
            }
        }
    }
    
    function _evaluate(bytes32 input, bytes32 puzzleSolutionHash) 
        internal 
        view 
        returns (bool valid, uint256[4] memory bindingOutput) 
    {
        uint256 wires = uint256(input) & ((1 << numWires) - 1);
        bytes memory cd = SSTORE2.read(circuitDataPointer);
        
        uint256[24] memory s = _deriveSecret384Array(input, puzzleSolutionHash);
        
        uint256[4] memory bindingAcc = _wireBindingHash(wires, 0);
        
        uint256 gateCount = numGates;
        uint256 q = Q;
        uint256 threshold = THRESHOLD;
        uint256 batchSize = 128;
        
        for (uint256 batchStart = 0; batchStart < gateCount; batchStart += batchSize) {
            uint256 batchEnd = batchStart + batchSize;
            if (batchEnd > gateCount) batchEnd = gateCount;
            
            assembly {
                let sPtr := s
                let gateSize := 3083
                let ctSize := 770
                let dataPtr := add(add(cd, 32), mul(batchStart, gateSize))
                let endPtr := add(add(cd, 32), mul(batchEnd, gateSize))
                
                for { } lt(dataPtr, endPtr) { dataPtr := add(dataPtr, gateSize) } {
                    let gateData := mload(dataPtr)
                    let active := and(shr(248, gateData), 0x3F)
                    let c1 := and(shr(240, gateData), 0x3F)
                    let c2 := and(shr(232, gateData), 0x3F)
                    
                    let c1Val := and(shr(c1, wires), 1)
                    let c2Val := and(shr(c2, wires), 1)
                    let ttIdx := or(c1Val, shl(1, c2Val))
                    
                    let ctPtr := add(dataPtr, add(3, mul(ttIdx, ctSize)))
                    
                    let innerProd := 0
                    
                    for { let wordIdx := 0 } lt(wordIdx, 24) { wordIdx := add(wordIdx, 1) } {
                        let a := mload(add(ctPtr, mul(wordIdx, 32)))
                        let sv := mload(add(sPtr, mul(wordIdx, 32)))
                        
                        innerProd := add(innerProd, mul(and(shr(240, a), 0xFFFF), and(shr(240, sv), 0xFFFF)))
                        innerProd := add(innerProd, mul(and(shr(224, a), 0xFFFF), and(shr(224, sv), 0xFFFF)))
                        innerProd := add(innerProd, mul(and(shr(208, a), 0xFFFF), and(shr(208, sv), 0xFFFF)))
                        innerProd := add(innerProd, mul(and(shr(192, a), 0xFFFF), and(shr(192, sv), 0xFFFF)))
                        innerProd := add(innerProd, mul(and(shr(176, a), 0xFFFF), and(shr(176, sv), 0xFFFF)))
                        innerProd := add(innerProd, mul(and(shr(160, a), 0xFFFF), and(shr(160, sv), 0xFFFF)))
                        innerProd := add(innerProd, mul(and(shr(144, a), 0xFFFF), and(shr(144, sv), 0xFFFF)))
                        innerProd := add(innerProd, mul(and(shr(128, a), 0xFFFF), and(shr(128, sv), 0xFFFF)))
                        innerProd := add(innerProd, mul(and(shr(112, a), 0xFFFF), and(shr(112, sv), 0xFFFF)))
                        innerProd := add(innerProd, mul(and(shr(96, a), 0xFFFF), and(shr(96, sv), 0xFFFF)))
                        innerProd := add(innerProd, mul(and(shr(80, a), 0xFFFF), and(shr(80, sv), 0xFFFF)))
                        innerProd := add(innerProd, mul(and(shr(64, a), 0xFFFF), and(shr(64, sv), 0xFFFF)))
                        innerProd := add(innerProd, mul(and(shr(48, a), 0xFFFF), and(shr(48, sv), 0xFFFF)))
                        innerProd := add(innerProd, mul(and(shr(32, a), 0xFFFF), and(shr(32, sv), 0xFFFF)))
                        innerProd := add(innerProd, mul(and(shr(16, a), 0xFFFF), and(shr(16, sv), 0xFFFF)))
                        innerProd := add(innerProd, mul(and(a, 0xFFFF), and(sv, 0xFFFF)))
                    }
                    
                    let bWord := mload(add(ctPtr, 768))
                    let b := and(shr(240, bWord), 0xFFFF)
                    
                    innerProd := mod(innerProd, q)
                    
                    let diff := mod(add(sub(b, innerProd), q), q)
                    let cfBit := and(gt(diff, threshold), lt(diff, mul(3, threshold)))
                    
                    let newVal := xor(and(shr(active, wires), 1), cfBit)
                    let bitMask := shl(active, 1)
                    wires := or(and(wires, not(bitMask)), mul(newVal, bitMask))
                }
            }
            
            uint256 combined = bindingAcc[0] ^ bindingAcc[1] ^ bindingAcc[2] ^ bindingAcc[3] ^ wires;
            bindingAcc = _wireBindingHash(combined, batchEnd);
        }
        
        bindingOutput = bindingAcc;
        
        bytes32 outputHash = keccak256(abi.encodePacked(wires));
        valid = (outputHash == expectedOutputHash) && 
                (bindingOutput[0] == expectedBindingOutput0) &&
                (bindingOutput[1] == expectedBindingOutput1) &&
                (bindingOutput[2] == expectedBindingOutput2) &&
                (bindingOutput[3] == expectedBindingOutput3);
    }
    
    function _deriveSecret384Array(bytes32 input, bytes32 puzzleSolutionHash) 
        internal 
        pure 
        returns (uint256[24] memory s) 
    {
        bytes32 combined = keccak256(abi.encodePacked(input, puzzleSolutionHash));
        uint256 q = Q;
        
        assembly {
            let sPtr := s
            for { let j := 0 } lt(j, 24) { j := add(j, 1) } {
                mstore(0x00, combined)
                mstore(0x20, j)
                let hVal := keccak256(0x00, 0x40)
                
                let sVal := 0
                for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                    let shift := mul(sub(15, i), 16)
                    sVal := or(sVal, shl(shift, mod(and(shr(shift, hVal), 0xFFFF), q)))
                }
                mstore(add(sPtr, mul(j, 32)), sVal)
            }
        }
    }
    
    receive() external payable { _reward += msg.value; }
}
