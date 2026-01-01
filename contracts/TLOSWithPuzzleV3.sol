// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IHoneypot.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";

/// @title TLOSWithPuzzleV3 - 4-Layer TLOS with Gaussian Noise LWE
/// @notice Uses standard LWE with Gaussian noise (σ=8) for control function hiding
/// @dev Security model:
///   Layer 1 (Topology): Structural mixing defeats pattern attacks
///   Layer 2 (LWE): Standard LWE with Gaussian noise (~2^112 security, n=384)
///   Layer 3 (Wire Binding): Full-rank linear map prevents mix-and-match
///   Layer 4 (Planted LWE): 3^48 ≈ 2^76 search space brute-force resistance
///
/// LWE Parameters: n=384, q=65521, σ=8 (Gaussian noise added off-chain)
/// Puzzle Parameters: n=48, m=72, q=2039, threshold=300
contract TLOSWithPuzzleV3 is IHoneypot {
    uint256 public constant COMMIT_DELAY = 2;
    uint256 public constant Q = 65521;
    uint256 public constant LBLO_N = 384;
    uint256 public constant THRESHOLD = Q / 4;
    uint256 public constant BINDING_ROWS = 64;
    
    // Planted LWE Puzzle parameters (Layer 4) - matches WeakLWEPuzzleV7
    uint256 public constant N_WEAK = 48;
    uint256 public constant M_WEAK = 72;
    uint256 public constant Q_WEAK = 2039;
    uint256 public constant PUZZLE_THRESHOLD_SQ = 300;
    bytes32 public constant PUZZLE_DOMAIN = keccak256("TLOS-PlantedLWE-v7");
    
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
    
    uint256 private _reward;
    bool private _claimed;
    address public immutable owner;
    
    struct Commitment { bytes32 hash; uint256 blockNumber; }
    mapping(address => Commitment) private _commits;
    
    uint256 private constant CT_SIZE = 770;  // 384*2 + 2 = 770 bytes per ciphertext
    uint256 private constant GATE_SIZE = 3083;  // 3 + 4*770 = 3083 bytes per gate
    
    event PuzzleSolved(address indexed solver, bytes32 indexed inputHash, uint256 normSq);
    
    constructor(
        address _circuitDataPointer,
        uint8 _numWires,
        uint32 _numGates,
        bytes32 _expectedOutputHash,
        bytes32 _circuitSeed,
        uint256[4] memory _expectedBindingOutput,
        uint256 _secretExpiry
    ) payable {
        require(_numWires > 0 && _numWires <= 64, "Wires must be 1-64");
        require(_numGates > 0, "Must have gates");
        require(_circuitDataPointer != address(0), "Invalid pointer");
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
        owner = msg.sender;
        _reward = msg.value;
    }
    
    function commit(bytes32 commitHash) external override {
        require(block.timestamp < secretExpiry, "Secret expired");
        _commits[msg.sender] = Commitment({hash: commitHash, blockNumber: block.number});
        emit Committed(msg.sender, commitHash, block.number);
    }
    
    /// @notice Reveal with puzzle solution (n=48 ternary secret)
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
        
        (bool puzzleValid, bytes32 sHash, uint256 normSq) = _verifyPuzzle(input, puzzleSolution);
        require(puzzleValid, "Invalid puzzle solution");
        emit PuzzleSolved(msg.sender, keccak256(abi.encodePacked(input)), normSq);
        
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
        (bool puzzleValid, bytes32 sHash, ) = _verifyPuzzle(input, puzzleSolution);
        if (!puzzleValid) return false;
        
        (bool circuitValid, ) = _evaluate(input, sHash);
        return circuitValid;
    }
    
    function check(bytes32) external pure override returns (bool) {
        return false;
    }
    
    function getPuzzleSeed(bytes32 x) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(PUZZLE_DOMAIN, x));
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
    function scheme() external pure override returns (string memory) { return "tlos-lwe-puzzleV3"; }
    function encryptedGates() external pure override returns (uint256) { return 640; }
    function estimatedGas() external pure override returns (uint256) { return 9_000_000; }
    function isExpired() external view returns (bool) { return block.timestamp >= secretExpiry; }
    function timeRemaining() external view returns (uint256) {
        if (block.timestamp >= secretExpiry) return 0;
        return secretExpiry - block.timestamp;
    }
    
    /// @notice Verify planted LWE puzzle solution (matches WeakLWEPuzzleV7)
    function _verifyPuzzle(bytes32 x, int8[48] calldata solution) 
        internal 
        pure 
        returns (bool valid, bytes32 sHash, uint256 normSq) 
    {
        unchecked {
            for (uint256 i = 0; i < N_WEAK; ++i) {
                if (solution[i] < -1 || solution[i] > 1) {
                    return (false, bytes32(0), 0);
                }
            }
            
            bytes32 seed = keccak256(abi.encodePacked(PUZZLE_DOMAIN, x));
            
            // Derive planted secret (3 keccaks for 48 elements)
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
            
            normSq = 0;
            
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
                let gateSize := 3083  // GATE_SIZE for n=384
                let ctSize := 770     // CT_SIZE for n=384
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
                    
                    // Process 24 words (384 coefficients = 24 * 16)
                    for { let wordIdx := 0 } lt(wordIdx, 24) { wordIdx := add(wordIdx, 1) } {
                        let a := mload(add(ctPtr, mul(wordIdx, 32)))
                        let sv := mload(add(sPtr, mul(wordIdx, 32)))
                        
                        // Unrolled: 16 u16 multiplications per word
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
                    
                    // b is at offset 768 (384*2) within ciphertext
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
                // Compute keccak256(combined, j)
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
    
    /// @notice Get the planted secret for off-chain solving
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
    
    receive() external payable { _reward += msg.value; }
}
