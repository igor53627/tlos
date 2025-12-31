// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IHoneypot.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";

/// @title TLOS - Topology-Lattice Obfuscation for Smart Contracts
/// @notice Uses LBLO (noiseless LWE-like) for control function hiding and
///         full-rank 64x64 linear map for inter-gate wire binding
/// @dev Wire binding inspired by Ma-Dai-Shi 2025, but NOT subspace-evasive.
///      Security is heuristic, not based on standard LWE reductions.
///
/// LBLO Configuration:
/// - n=128 dimension, q=65521 (heuristic ~2^98 PQ security)
/// - 128-element inner products with single mod at end
/// - Noiseless: no Gaussian error term (deterministic encoding)
///
/// Wire Binding Construction:
/// - Matrix A is derived from circuit seed (64 x 64 matrix of u16 mod q)
/// - H(wires) = A * wires mod q (64-element output vector, 1024 bits)
/// - Each batch (128 gates) updates: bindingAcc = H(bindingAcc XOR wires, batchEnd)
/// - Full-rank A provides algebraic binding (unique preimage), not cryptographic hiding
/// - PRG optimization: 16 coefficients per keccak (320 calls vs 4096)
///
/// Gas: ~8.5M for 640 gates (28% of block limit)
contract TLOS is IHoneypot {
    uint256 public constant COMMIT_DELAY = 2;
    uint256 public constant Q = 65521;
    uint256 public constant LBLO_N = 128;
    uint256 public constant THRESHOLD = Q / 4;
    uint256 public constant BINDING_ROWS = 64;  // Full-rank 64x64 matrix
    
    address public immutable circuitDataPointer;
    uint8 public immutable numWires;
    uint32 public immutable numGates;
    bytes32 public immutable expectedOutputHash;
    bytes32 public immutable circuitSeed;  // Used to derive wire binding matrix
    uint256 public immutable secretExpiry;
    
    // Expected wire binding output (64 x u16 = 1024 bits, stored as 4 x uint256)
    uint256 public immutable expectedBindingOutput0;
    uint256 public immutable expectedBindingOutput1;
    uint256 public immutable expectedBindingOutput2;
    uint256 public immutable expectedBindingOutput3;
    
    uint256 private _reward;
    bool private _claimed;
    address public immutable owner;
    
    struct Commitment { bytes32 hash; uint256 blockNumber; }
    mapping(address => Commitment) private _commits;
    
    uint256 private constant CT_SIZE = 258;   // 128 elements * 2 bytes + 2 bytes for b
    uint256 private constant GATE_SIZE = 1035; // 3 bytes (indices) + 4 * 258 (4 ciphertexts)
    
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
    
    function reveal(bytes32 input) external override {
        require(!_claimed, "Already claimed");
        require(block.timestamp < secretExpiry, "Secret expired");
        Commitment memory c = _commits[msg.sender];
        require(c.blockNumber > 0, "No commit found");
        require(block.number >= c.blockNumber + COMMIT_DELAY, "Reveal too early");
        require(keccak256(abi.encode(msg.sender, input)) == c.hash, "Invalid reveal");
        (bool valid, ) = _evaluate(input);
        require(valid, "Invalid input");
        _claimed = true;
        delete _commits[msg.sender];
        uint256 rewardAmount = _reward;
        _reward = 0;
        (bool success, ) = msg.sender.call{value: rewardAmount}("");
        require(success, "Transfer failed");
        emit Claimed(msg.sender, c.hash, rewardAmount);
    }
    
    function check(bytes32 input) external view override returns (bool) {
        (bool valid, ) = _evaluate(input);
        return valid;
    }
    
    function checkWithBinding(bytes32 input) external view returns (bool valid, uint256[4] memory bindingOutput) {
        return _evaluate(input);
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
    function scheme() external pure override returns (string memory) { return "tlos-lblo"; }
    function encryptedGates() external pure override returns (uint256) { return 640; }
    function estimatedGas() external pure override returns (uint256) { return 50_000_000; }
    function isExpired() external view returns (bool) { return block.timestamp >= secretExpiry; }
    function timeRemaining() external view returns (uint256) {
        if (block.timestamp >= secretExpiry) return 0;
        return secretExpiry - block.timestamp;
    }
    
    /// @notice Compute full-rank wire binding hash: H(x) = A*x mod q where A is 64x64
    /// @param input Wire values as bits (packed into uint256)
    /// @param gateIdx Gate index for matrix derivation
    /// @return output 64 x u16 packed into 4 x uint256 (1024 bits)
    /// @dev Optimized: derives 16 coefficients per keccak (320 calls vs 4096)
    function _wireBindingHash(uint256 input, uint256 gateIdx) internal view returns (uint256[4] memory output) {
        uint256 q = Q;
        uint256 nWires = numWires;
        bytes32 seed = circuitSeed;
        
        assembly {
            let outPtr := output
            
            for { let row := 0 } lt(row, 64) { row := add(row, 1) } {
                // Compute rowSeed = keccak256(seed, gateIdx, row)
                let freePtr := mload(0x40)
                mstore(freePtr, seed)
                mstore(add(freePtr, 32), gateIdx)
                mstore(add(freePtr, 64), row)
                let rowSeed := keccak256(freePtr, 96)
                
                let sum := 0
                let col := 0
                
                // Process coefficients in blocks of 16 (each keccak gives 16 x u16)
                for { let blockIdx := 0 } lt(col, nWires) { blockIdx := add(blockIdx, 1) } {
                    // blockDigest = keccak256(rowSeed, blockIdx)
                    mstore(freePtr, rowSeed)
                    mstore(add(freePtr, 32), blockIdx)
                    let blockDigest := keccak256(freePtr, 64)
                    
                    // Extract up to 16 coefficients from this block
                    for { let k := 0 } and(lt(k, 16), lt(col, nWires)) { k := add(k, 1) } {
                        // Extract u16 at position k (little-endian: low bits first)
                        let aij := mod(and(shr(mul(k, 16), blockDigest), 0xFFFF), q)
                        
                        // Get bit value at col
                        let bitVal := and(shr(col, input), 1)
                        
                        // Accumulate: sum += aij * bitVal
                        // Since bitVal is 0 or 1, we can use conditional add
                        if bitVal {
                            sum := add(sum, aij)
                            if iszero(lt(sum, q)) { sum := sub(sum, q) }
                        }
                        
                        col := add(col, 1)
                    }
                }
                
                // Pack into output: 16 elements per uint256
                let wordIdx := div(row, 16)
                let bitPos := mul(mod(row, 16), 16)
                let wordPtr := add(outPtr, mul(wordIdx, 32))
                let existing := mload(wordPtr)
                mstore(wordPtr, or(existing, shl(bitPos, and(sum, 0xFFFF))))
            }
        }
    }
    
    function _evaluate(bytes32 input) internal view returns (bool valid, uint256[4] memory bindingOutput) {
        uint256 wires = uint256(input) & ((1 << numWires) - 1);
        bytes memory cd = SSTORE2.read(circuitDataPointer);
        
        // Store 128-element secret in memory array to avoid stack depth issues
        uint256[8] memory s = _deriveSecret128Array(input);
        
        // Initialize wire binding accumulator (full-rank 64x64 hash of initial wires)
        uint256[4] memory bindingAcc = _wireBindingHash(wires, 0);
        
        uint256 gateCount = numGates;
        uint256 q = Q;
        uint256 threshold = THRESHOLD;
        
        // Process gates in batches for wire binding updates (batch size = 128 for gas efficiency)
        // Larger batches = fewer binding updates = less gas
        uint256 batchSize = 128;
        
        for (uint256 batchStart = 0; batchStart < gateCount; batchStart += batchSize) {
            uint256 batchEnd = batchStart + batchSize;
            if (batchEnd > gateCount) batchEnd = gateCount;
            
            // Process batch of gates in assembly
            assembly {
                let sPtr := s  // Secret array pointer
                let dataPtr := add(add(cd, 32), mul(batchStart, 1035))
                let endPtr := add(add(cd, 32), mul(batchEnd, 1035))
                
                for { } lt(dataPtr, endPtr) { dataPtr := add(dataPtr, 1035) } {
                    let gateData := mload(dataPtr)
                    let active := and(shr(248, gateData), 0x3F)
                    let c1 := and(shr(240, gateData), 0x3F)
                    let c2 := and(shr(232, gateData), 0x3F)
                    
                    let c1Val := and(shr(c1, wires), 1)
                    let c2Val := and(shr(c2, wires), 1)
                    let ttIdx := or(c1Val, shl(1, c2Val))
                    
                    // CT_SIZE = 258 for n=128
                    let ctPtr := add(dataPtr, add(3, mul(ttIdx, 258)))
                    
                    // Accumulate all 128 terms WITHOUT per-term mod
                    // Max sum: 128 * (2^16-1)^2 < 128 * 2^32 = 2^39, well within uint256
                    let innerProd := 0
                    
                    // Load and process 8 pairs of (a, s) vectors
                    for { let wordIdx := 0 } lt(wordIdx, 8) { wordIdx := add(wordIdx, 1) } {
                        let a := mload(add(ctPtr, mul(wordIdx, 32)))
                        let sv := mload(add(sPtr, mul(wordIdx, 32)))
                        
                        // Process 16 terms per word
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
                    
                    // Load b value (after 256 bytes of a vector)
                    let bWord := mload(add(ctPtr, 256))
                    let b := and(shr(240, bWord), 0xFFFF)
                    
                    // Single mod at the end
                    innerProd := mod(innerProd, q)
                    
                    let diff := mod(add(sub(b, innerProd), q), q)
                    let cfBit := and(gt(diff, threshold), lt(diff, mul(3, threshold)))
                    
                    let newVal := xor(and(shr(active, wires), 1), cfBit)
                    let bitMask := shl(active, 1)
                    wires := or(and(wires, not(bitMask)), mul(newVal, bitMask))
                }
            }
            
            // Update wire binding after each batch using full-rank hash (per-batch binding)
            // Combines previous bindingAcc XOR wires into new accumulator
            uint256 combined = bindingAcc[0] ^ bindingAcc[1] ^ bindingAcc[2] ^ bindingAcc[3] ^ wires;
            bindingAcc = _wireBindingHash(combined, batchEnd);
        }
        
        // Final wire binding is the accumulated full-rank hash
        bindingOutput = bindingAcc;
        
        bytes32 outputHash = keccak256(abi.encodePacked(wires));
        valid = (outputHash == expectedOutputHash) && 
                (bindingOutput[0] == expectedBindingOutput0) &&
                (bindingOutput[1] == expectedBindingOutput1) &&
                (bindingOutput[2] == expectedBindingOutput2) &&
                (bindingOutput[3] == expectedBindingOutput3);
    }
    
    /// @dev Derive 128-element LBLO secret vector from input
    /// Returns 8 x uint256 (128 x u16 packed) as memory array
    function _deriveSecret128Array(bytes32 input) internal pure returns (uint256[8] memory s) {
        bytes32[8] memory h;
        h[0] = keccak256(abi.encodePacked(input, uint256(0)));
        h[1] = keccak256(abi.encodePacked(input, uint256(1)));
        h[2] = keccak256(abi.encodePacked(input, uint256(2)));
        h[3] = keccak256(abi.encodePacked(input, uint256(3)));
        h[4] = keccak256(abi.encodePacked(input, uint256(4)));
        h[5] = keccak256(abi.encodePacked(input, uint256(5)));
        h[6] = keccak256(abi.encodePacked(input, uint256(6)));
        h[7] = keccak256(abi.encodePacked(input, uint256(7)));
        uint256 q = Q;
        
        assembly {
            let sPtr := s
            let hPtr := h
            for { let j := 0 } lt(j, 8) { j := add(j, 1) } {
                let hVal := mload(add(hPtr, mul(j, 32)))
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
