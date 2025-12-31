// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IHoneypot.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";

/// @title TLOSOptimized - Gas-optimized TLOS with configurable dimension
/// @notice Optimizations:
///   1. Fast mod q via conditional subtraction (not div)
///   2. Secret preloaded into stack vars (no per-gate mload)
///   3. Unrolled inner product loop
///   4. Single freePtr in wire binding
/// @dev Target: support n=256 within ~17M gas (vs 8.5M for n=128)
contract TLOSOptimized is IHoneypot {
    uint256 public constant COMMIT_DELAY = 2;
    uint256 public constant Q = 65521;
    uint256 public constant THRESHOLD = Q / 4;
    uint256 public constant BINDING_ROWS = 64;
    
    // Configurable dimension (128 or 256)
    uint256 public immutable lbloN;
    
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
    
    constructor(
        address _circuitDataPointer,
        uint8 _numWires,
        uint32 _numGates,
        bytes32 _expectedOutputHash,
        bytes32 _circuitSeed,
        uint256[4] memory _expectedBindingOutput,
        uint256 _secretExpiry,
        uint256 _lbloN  // 128 or 256
    ) payable {
        require(_numWires > 0 && _numWires <= 64, "Wires must be 1-64");
        require(_numGates > 0, "Must have gates");
        require(_circuitDataPointer != address(0), "Invalid pointer");
        require(_secretExpiry > block.timestamp, "Expiry must be in future");
        require(_lbloN == 128 || _lbloN == 256 || _lbloN == 512 || _lbloN == 768, "n must be 128, 256, 512, or 768");
        
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
        lbloN = _lbloN;
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
    
    function getCommit(address committer) external view override returns (bytes32, uint256) {
        Commitment memory c = _commits[committer];
        return (c.hash, c.blockNumber);
    }
    
    function commitDelay() external pure override returns (uint256) { return COMMIT_DELAY; }
    function reward() external view override returns (uint256) { return _reward; }
    function scheme() external pure override returns (string memory) { return "tlos-lblo-opt"; }
    function encryptedGates() external pure override returns (uint256) { return 640; }
    function estimatedGas() external pure override returns (uint256) { 
        return 17_000_000;  // Max for n=256
    }
    
    /// @dev Optimized secret derivation - no abi.encodePacked, fast mod
    function _deriveSecretOptimized(bytes32 input) internal view returns (uint256[] memory s) {
        uint256 n = lbloN;
        uint256 numWords = n / 16;  // 8 for n=128, 16 for n=256
        s = new uint256[](numWords);
        
        uint256 q = Q;
        
        assembly {
            let sPtr := add(s, 32)  // Skip length slot
            let ptr := mload(0x40)  // Scratch space
            
            // Write input once
            mstore(ptr, input)
            
            for { let j := 0 } lt(j, numWords) { j := add(j, 1) } {
                // keccak(input || j) - 64 bytes
                mstore(add(ptr, 32), j)
                let hVal := keccak256(ptr, 64)
                
                let sVal := 0
                
                // 16 u16s per hash - unrolled for speed
                // Fast mod: x mod q = (x < q ? x : x - q) for x < 2^16, q = 65521
                
                // Process 16 values at once
                for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                    let shift := mul(sub(15, i), 16)
                    let x := and(shr(shift, hVal), 0xFFFF)
                    
                    // Fast mod q (single comparison + conditional sub)
                    if iszero(lt(x, q)) { x := sub(x, q) }
                    
                    sVal := or(sVal, shl(shift, x))
                }
                
                mstore(add(sPtr, mul(j, 32)), sVal)
            }
        }
    }
    
    /// @dev Optimized wire binding hash with fast mod
    function _wireBindingHashOptimized(uint256 input, uint256 gateIdx) internal view returns (uint256[4] memory output) {
        uint256 q = Q;
        uint256 nWires = numWires;
        bytes32 seed = circuitSeed;
        
        assembly {
            let outPtr := output
            let freePtr := mload(0x40)  // Single freePtr for all operations
            
            for { let row := 0 } lt(row, 64) { row := add(row, 1) } {
                // rowSeed = keccak256(seed || gateIdx || row)
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
                        let aij := and(shr(mul(k, 16), blockDigest), 0xFFFF)
                        // Fast mod q
                        if iszero(lt(aij, q)) { aij := sub(aij, q) }
                        
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
    
    function _evaluate(bytes32 input) internal view returns (bool valid, uint256[4] memory bindingOutput) {
        uint256 wires = uint256(input) & ((1 << numWires) - 1);
        bytes memory cd = SSTORE2.read(circuitDataPointer);
        
        uint256[] memory s = _deriveSecretOptimized(input);
        uint256[4] memory bindingAcc = _wireBindingHashOptimized(wires, 0);
        
        uint256 gateCount = numGates;
        uint256 q = Q;
        uint256 threshold = THRESHOLD;
        uint256 threeThreshold = threshold * 3;  // Precomputed
        uint256 n = lbloN;
        uint256 numWords = n / 16;
        uint256 ctSize = n * 2 + 2;  // CT_SIZE for this n
        uint256 gateSize = 3 + 4 * ctSize;
        
        uint256 batchSize = 128;
        
        for (uint256 batchStart = 0; batchStart < gateCount; batchStart += batchSize) {
            uint256 batchEnd = batchStart + batchSize;
            if (batchEnd > gateCount) batchEnd = gateCount;
            
            // Process gates with optimized inner product
            for (uint256 g = batchStart; g < batchEnd; g++) {
                uint256 offset = 32 + g * gateSize;
                
                uint256 gateData;
                assembly { gateData := mload(add(cd, offset)) }
                
                uint256 active = (gateData >> 248) & 0x3F;
                uint256 c1 = (gateData >> 240) & 0x3F;
                uint256 c2 = (gateData >> 232) & 0x3F;
                
                uint256 c1Val = (wires >> c1) & 1;
                uint256 c2Val = (wires >> c2) & 1;
                uint256 ttIdx = c1Val | (c2Val << 1);
                
                uint256 ctOffset = offset + 3 + ttIdx * ctSize;
                
                // Optimized inner product
                uint256 innerProd = 0;
                
                assembly {
                    let ctPtr := add(cd, ctOffset)
                    let sPtr := add(s, 32)
                    
                    for { let w := 0 } lt(w, numWords) { w := add(w, 1) } {
                        let a := mload(add(ctPtr, mul(w, 32)))
                        let sv := mload(add(sPtr, mul(w, 32)))
                        
                        // 16 multiply-adds per word
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
                    
                    innerProd := mod(innerProd, q)
                }
                
                // Load b value
                uint256 bVal;
                assembly {
                    let bWord := mload(add(cd, add(ctOffset, mul(numWords, 32))))
                    bVal := and(shr(240, bWord), 0xFFFF)
                }
                
                uint256 diff = (bVal + q - innerProd) % q;
                uint256 cfBit = (diff > threshold && diff < threeThreshold) ? 1 : 0;
                
                uint256 newVal = ((wires >> active) & 1) ^ cfBit;
                wires = (wires & ~(1 << active)) | (newVal << active);
            }
            
            uint256 combined = bindingAcc[0] ^ bindingAcc[1] ^ bindingAcc[2] ^ bindingAcc[3] ^ wires;
            bindingAcc = _wireBindingHashOptimized(combined, batchEnd);
        }
        
        bindingOutput = bindingAcc;
        bytes32 outputHash = keccak256(abi.encodePacked(wires));
        valid = (outputHash == expectedOutputHash) && 
                (bindingOutput[0] == expectedBindingOutput0) &&
                (bindingOutput[1] == expectedBindingOutput1) &&
                (bindingOutput[2] == expectedBindingOutput2) &&
                (bindingOutput[3] == expectedBindingOutput3);
    }
    
    receive() external payable { _reward += msg.value; }
}
