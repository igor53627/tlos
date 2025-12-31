// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IHoneypot.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";

/// @title TLOSSeedA - TLOS with seed-derived `a` vectors
/// @notice Key optimization: LWE `a` vectors derived on-chain from seed
///   Storage: only 11 bytes per gate (3 wire indices + 4 * 2-byte `b` values)
///   vs 6155 bytes per gate when storing full ciphertexts for n=768
/// @dev Deployment scheme:
///   1. Circuit data (topology + b values) stored via SSTORE2 - shared across users
///   2. Each honeypot instance references shared circuit data
///   3. `a` vectors regenerated deterministically during evaluation
contract TLOSSeedA is IHoneypot {
    uint256 public constant COMMIT_DELAY = 2;
    uint256 public constant Q = 65521;
    uint256 public constant THRESHOLD = Q / 4;
    uint256 public constant BINDING_ROWS = 64;
    
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
    
    /// @notice Gate data format: 3 bytes wire indices + 4 * 2 bytes b values = 11 bytes/gate
    /// @dev Storage calculation for 256 gates @ n=768:
    ///   Old: 256 * 6155 = 1.58 MB
    ///   New: 256 * 11 = 2,816 bytes (fits in single SSTORE2!)
    constructor(
        address _circuitDataPointer,
        uint8 _numWires,
        uint32 _numGates,
        bytes32 _expectedOutputHash,
        bytes32 _circuitSeed,
        uint256[4] memory _expectedBindingOutput,
        uint256 _secretExpiry,
        uint256 _lbloN
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
    function scheme() external pure override returns (string memory) { return "tlos-seed-a"; }
    function encryptedGates() external pure override returns (uint256) { return 256; }
    function estimatedGas() external pure override returns (uint256) { return 20_000_000; }
    
    /// @dev Derive secret vector from input
    function _deriveSecret(bytes32 input) internal view returns (uint256[] memory s) {
        uint256 n = lbloN;
        uint256 numWords = n / 16;
        s = new uint256[](numWords);
        uint256 q = Q;
        
        assembly {
            let sPtr := add(s, 32)
            let ptr := mload(0x40)
            mstore(ptr, input)
            
            for { let j := 0 } lt(j, numWords) { j := add(j, 1) } {
                mstore(add(ptr, 32), j)
                let hVal := keccak256(ptr, 64)
                let sVal := 0
                
                for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                    let shift := mul(sub(15, i), 16)
                    let x := and(shr(shift, hVal), 0xFFFF)
                    if iszero(lt(x, q)) { x := sub(x, q) }
                    sVal := or(sVal, shl(shift, x))
                }
                mstore(add(sPtr, mul(j, 32)), sVal)
            }
        }
    }
    
    /// @dev Derive `a` vector for a specific gate and truth table index
    /// @param gateIdx Gate index
    /// @param ttIdx Truth table index (0-3)
    /// @return Packed a coefficients as uint256 array (16 coefficients per word)
    function _deriveA(uint256 gateIdx, uint256 ttIdx) internal view returns (uint256[] memory) {
        uint256 n = lbloN;
        uint256 numWords = n / 16;
        uint256[] memory a = new uint256[](numWords);
        bytes32 seed = circuitSeed;
        uint256 q = Q;
        
        assembly {
            let aPtr := add(a, 32)
            let ptr := mload(0x40)
            
            // Seed for this gate's a vector: keccak(circuitSeed || "A" || gateIdx || ttIdx)
            mstore(ptr, seed)
            mstore(add(ptr, 32), 0x41)  // "A"
            mstore(add(ptr, 64), gateIdx)
            mstore(add(ptr, 96), ttIdx)
            let baseSeed := keccak256(ptr, 128)
            
            for { let w := 0 } lt(w, numWords) { w := add(w, 1) } {
                // Generate 32 bytes (16 coefficients) per word
                mstore(ptr, baseSeed)
                mstore(add(ptr, 32), w)
                let hVal := keccak256(ptr, 64)
                
                let aVal := 0
                for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                    let shift := mul(sub(15, i), 16)
                    let x := and(shr(shift, hVal), 0xFFFF)
                    if iszero(lt(x, q)) { x := sub(x, q) }
                    aVal := or(aVal, shl(shift, x))
                }
                mstore(add(aPtr, mul(w, 32)), aVal)
            }
        }
        return a;
    }
    
    /// @dev Compute inner product <a, s> mod q
    function _innerProduct(uint256[] memory a, uint256[] memory s) internal view returns (uint256) {
        uint256 numWords = a.length;
        uint256 q = Q;
        uint256 result;
        
        assembly {
            let aPtr := add(a, 32)
            let sPtr := add(s, 32)
            result := 0
            
            for { let w := 0 } lt(w, numWords) { w := add(w, 1) } {
                let aWord := mload(add(aPtr, mul(w, 32)))
                let sWord := mload(add(sPtr, mul(w, 32)))
                
                // 16 multiply-adds per word (unrolled)
                result := add(result, mul(and(shr(240, aWord), 0xFFFF), and(shr(240, sWord), 0xFFFF)))
                result := add(result, mul(and(shr(224, aWord), 0xFFFF), and(shr(224, sWord), 0xFFFF)))
                result := add(result, mul(and(shr(208, aWord), 0xFFFF), and(shr(208, sWord), 0xFFFF)))
                result := add(result, mul(and(shr(192, aWord), 0xFFFF), and(shr(192, sWord), 0xFFFF)))
                result := add(result, mul(and(shr(176, aWord), 0xFFFF), and(shr(176, sWord), 0xFFFF)))
                result := add(result, mul(and(shr(160, aWord), 0xFFFF), and(shr(160, sWord), 0xFFFF)))
                result := add(result, mul(and(shr(144, aWord), 0xFFFF), and(shr(144, sWord), 0xFFFF)))
                result := add(result, mul(and(shr(128, aWord), 0xFFFF), and(shr(128, sWord), 0xFFFF)))
                result := add(result, mul(and(shr(112, aWord), 0xFFFF), and(shr(112, sWord), 0xFFFF)))
                result := add(result, mul(and(shr(96, aWord), 0xFFFF), and(shr(96, sWord), 0xFFFF)))
                result := add(result, mul(and(shr(80, aWord), 0xFFFF), and(shr(80, sWord), 0xFFFF)))
                result := add(result, mul(and(shr(64, aWord), 0xFFFF), and(shr(64, sWord), 0xFFFF)))
                result := add(result, mul(and(shr(48, aWord), 0xFFFF), and(shr(48, sWord), 0xFFFF)))
                result := add(result, mul(and(shr(32, aWord), 0xFFFF), and(shr(32, sWord), 0xFFFF)))
                result := add(result, mul(and(shr(16, aWord), 0xFFFF), and(shr(16, sWord), 0xFFFF)))
                result := add(result, mul(and(aWord, 0xFFFF), and(sWord, 0xFFFF)))
            }
            result := mod(result, q)
        }
        return result;
    }
    
    /// @dev Wire binding hash
    function _wireBindingHash(uint256 input, uint256 gateIdx) internal view returns (uint256[4] memory output) {
        uint256 q = Q;
        uint256 nWires = numWires;
        bytes32 seed = circuitSeed;
        
        assembly {
            let outPtr := output
            let freePtr := mload(0x40)
            
            for { let row := 0 } lt(row, 64) { row := add(row, 1) } {
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
    
    /// @dev Main evaluation function
    /// @notice Circuit data format: per gate = [active:1][c1:1][c2:1][b0:2][b1:2][b2:2][b3:2] = 11 bytes
    function _evaluate(bytes32 input) internal view returns (bool valid, uint256[4] memory bindingOutput) {
        uint256 wires = uint256(input) & ((1 << numWires) - 1);
        bytes memory cd = SSTORE2.read(circuitDataPointer);
        
        uint256[] memory s = _deriveSecret(input);
        uint256[4] memory bindingAcc = _wireBindingHash(wires, 0);
        
        uint256 gateCount = numGates;
        uint256 q = Q;
        uint256 threshold = THRESHOLD;
        uint256 threeThreshold = threshold * 3;
        
        uint256 batchSize = 128;
        uint256 gateSize = 11;  // 3 bytes wire indices + 4 * 2 bytes b values
        
        for (uint256 batchStart = 0; batchStart < gateCount; batchStart += batchSize) {
            uint256 batchEnd = batchStart + batchSize;
            if (batchEnd > gateCount) batchEnd = gateCount;
            
            for (uint256 g = batchStart; g < batchEnd; g++) {
                uint256 offset = 32 + g * gateSize;
                
                // Load gate header and b values
                uint256 gateData;
                assembly { gateData := mload(add(cd, offset)) }
                
                uint256 active = (gateData >> 248) & 0x3F;
                uint256 c1 = (gateData >> 240) & 0x3F;
                uint256 c2 = (gateData >> 232) & 0x3F;
                
                uint256 c1Val = (wires >> c1) & 1;
                uint256 c2Val = (wires >> c2) & 1;
                uint256 ttIdx = c1Val | (c2Val << 1);
                
                // Extract b value for selected truth table entry
                // b values are at bytes 3-4, 5-6, 7-8, 9-10 (0-indexed)
                uint256 bShift = 224 - (ttIdx * 16);  // 224, 208, 192, 176
                uint256 bVal = (gateData >> bShift) & 0xFFFF;
                
                // Derive a vector and compute inner product
                uint256[] memory a = _deriveA(g, ttIdx);
                uint256 innerProd = _innerProduct(a, s);
                
                uint256 diff = (bVal + q - innerProd) % q;
                uint256 cfBit = (diff > threshold && diff < threeThreshold) ? 1 : 0;
                
                uint256 newVal = ((wires >> active) & 1) ^ cfBit;
                wires = (wires & ~(1 << active)) | (newVal << active);
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
    
    receive() external payable { _reward += msg.value; }
}
