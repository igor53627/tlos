// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IHoneypot.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";

/// @title TLOHoneypotLiOLWE - LiO with full LWE-based SEH (theoretical)
/// @notice Uses LWE matrix-vector product for inter-gate consistency
/// @dev Based on Ma-Dai-Shi 2025 SEH. WARNING: Very gas expensive!
///
/// SEH Construction:
/// - Matrix A is derived from circuit seed (8 x numWires matrix of u16 mod q)
/// - H(wires) = A * wires mod q (8-element output vector)
/// - Each gate updates: sehAcc = H(sehAcc || gateOutput)
///
/// Gas estimate: ~10-50M for 640 gates (likely exceeds block limit)
contract TLOHoneypotLiOLWE is IHoneypot {
    uint256 public constant COMMIT_DELAY = 2;
    uint256 public constant Q = 65521;
    uint256 public constant LWE_N = 64;
    uint256 public constant THRESHOLD = Q / 4;
    uint256 public constant SEH_DIM = 8;  // Output dimension of SEH hash
    
    address public immutable circuitDataPointer;
    uint8 public immutable numWires;
    uint32 public immutable numGates;
    bytes32 public immutable expectedOutputHash;
    bytes32 public immutable circuitSeed;  // Used to derive SEH matrix
    uint256 public immutable secretExpiry;
    
    // Expected SEH output (8 x u16 packed into 128 bits)
    uint128 public immutable expectedSehOutput;
    
    uint256 private _reward;
    bool private _claimed;
    address public immutable owner;
    
    struct Commitment { bytes32 hash; uint256 blockNumber; }
    mapping(address => Commitment) private _commits;
    
    uint256 private constant CT_SIZE = 130;
    uint256 private constant GATE_SIZE = 523;
    
    constructor(
        address _circuitDataPointer,
        uint8 _numWires,
        uint32 _numGates,
        bytes32 _expectedOutputHash,
        bytes32 _circuitSeed,
        uint128 _expectedSehOutput,
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
        expectedSehOutput = _expectedSehOutput;
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
    
    function checkWithSeh(bytes32 input) external view returns (bool valid, uint128 sehOutput) {
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
    function scheme() external pure override returns (string memory) { return "tlo-lio-lwe"; }
    function encryptedGates() external pure override returns (uint256) { return 640; }
    function estimatedGas() external pure override returns (uint256) { return 50_000_000; }
    function isExpired() external view returns (bool) { return block.timestamp >= secretExpiry; }
    function timeRemaining() external view returns (uint256) {
        if (block.timestamp >= secretExpiry) return 0;
        return secretExpiry - block.timestamp;
    }
    
    /// @notice Compute LWE-based SEH hash: H(x) = A*x mod q
    /// @param input Wire values as bits (packed into uint256)
    /// @param gateIdx Gate index for matrix derivation
    /// @return output 8 x u16 packed into uint128
    function _sehHash(uint256 input, uint256 gateIdx) internal view returns (uint128 output) {
        uint256 q = Q;
        uint256 nWires = numWires;
        bytes32 seed = circuitSeed;
        
        // For each of SEH_DIM output elements
        for (uint256 row = 0; row < SEH_DIM; row++) {
            uint256 sum = 0;
            
            // Matrix row derived from seed + gateIdx + row
            bytes32 rowSeed = keccak256(abi.encodePacked(seed, gateIdx, row));
            
            // Inner product with input bits
            for (uint256 col = 0; col < nWires; col++) {
                // Derive A[row][col] from rowSeed
                uint16 aij = uint16(uint256(keccak256(abi.encodePacked(rowSeed, col))) % q);
                
                // Get bit value
                uint256 bitVal = (input >> col) & 1;
                
                // Accumulate
                sum = (sum + uint256(aij) * bitVal) % q;
            }
            
            // Pack into output (each element is 16 bits)
            output |= uint128(uint16(sum)) << (row * 16);
        }
    }
    
    function _evaluate(bytes32 input) internal view returns (bool valid, uint128 sehOutput) {
        uint256 wires = uint256(input) & ((1 << numWires) - 1);
        bytes memory cd = SSTORE2.read(circuitDataPointer);
        
        (uint256 s0, uint256 s1, uint256 s2, uint256 s3) = _deriveSecret64(input);
        
        // Initialize SEH accumulator (LWE hash of initial wires)
        uint128 sehAcc = _sehHash(wires, 0);
        
        uint256 gateCount = numGates;
        uint256 q = Q;
        uint256 threshold = THRESHOLD;
        
        assembly {
            let dataPtr := add(cd, 32)
            let endPtr := add(dataPtr, mul(gateCount, 523))
            
            for { } lt(dataPtr, endPtr) { dataPtr := add(dataPtr, 523) } {
                let gateData := mload(dataPtr)
                let active := and(shr(248, gateData), 0x3F)
                let c1 := and(shr(240, gateData), 0x3F)
                let c2 := and(shr(232, gateData), 0x3F)
                
                let c1Val := and(shr(c1, wires), 1)
                let c2Val := and(shr(c2, wires), 1)
                let ttIdx := or(c1Val, shl(1, c2Val))
                
                let ctPtr := add(dataPtr, add(3, mul(ttIdx, 130)))
                
                let a0 := mload(ctPtr)
                let a1 := mload(add(ctPtr, 32))
                let a2 := mload(add(ctPtr, 64))
                let a3 := mload(add(ctPtr, 96))
                let bWord := mload(add(ctPtr, 128))
                let b := and(shr(240, bWord), 0xFFFF)
                
                let innerProd := 0
                
                // a0 x s0 (16 terms)
                innerProd := mod(add(innerProd, mul(and(shr(240, a0), 0xFFFF), and(shr(240, s0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(224, a0), 0xFFFF), and(shr(224, s0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(208, a0), 0xFFFF), and(shr(208, s0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(192, a0), 0xFFFF), and(shr(192, s0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(176, a0), 0xFFFF), and(shr(176, s0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(160, a0), 0xFFFF), and(shr(160, s0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(144, a0), 0xFFFF), and(shr(144, s0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(128, a0), 0xFFFF), and(shr(128, s0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(112, a0), 0xFFFF), and(shr(112, s0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(96, a0), 0xFFFF), and(shr(96, s0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(80, a0), 0xFFFF), and(shr(80, s0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(64, a0), 0xFFFF), and(shr(64, s0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(48, a0), 0xFFFF), and(shr(48, s0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(32, a0), 0xFFFF), and(shr(32, s0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(16, a0), 0xFFFF), and(shr(16, s0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(a0, 0xFFFF), and(s0, 0xFFFF))), q)
                
                // a1 x s1 (16 terms)
                innerProd := mod(add(innerProd, mul(and(shr(240, a1), 0xFFFF), and(shr(240, s1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(224, a1), 0xFFFF), and(shr(224, s1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(208, a1), 0xFFFF), and(shr(208, s1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(192, a1), 0xFFFF), and(shr(192, s1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(176, a1), 0xFFFF), and(shr(176, s1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(160, a1), 0xFFFF), and(shr(160, s1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(144, a1), 0xFFFF), and(shr(144, s1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(128, a1), 0xFFFF), and(shr(128, s1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(112, a1), 0xFFFF), and(shr(112, s1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(96, a1), 0xFFFF), and(shr(96, s1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(80, a1), 0xFFFF), and(shr(80, s1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(64, a1), 0xFFFF), and(shr(64, s1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(48, a1), 0xFFFF), and(shr(48, s1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(32, a1), 0xFFFF), and(shr(32, s1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(16, a1), 0xFFFF), and(shr(16, s1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(a1, 0xFFFF), and(s1, 0xFFFF))), q)
                
                // a2 x s2 (16 terms)
                innerProd := mod(add(innerProd, mul(and(shr(240, a2), 0xFFFF), and(shr(240, s2), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(224, a2), 0xFFFF), and(shr(224, s2), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(208, a2), 0xFFFF), and(shr(208, s2), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(192, a2), 0xFFFF), and(shr(192, s2), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(176, a2), 0xFFFF), and(shr(176, s2), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(160, a2), 0xFFFF), and(shr(160, s2), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(144, a2), 0xFFFF), and(shr(144, s2), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(128, a2), 0xFFFF), and(shr(128, s2), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(112, a2), 0xFFFF), and(shr(112, s2), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(96, a2), 0xFFFF), and(shr(96, s2), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(80, a2), 0xFFFF), and(shr(80, s2), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(64, a2), 0xFFFF), and(shr(64, s2), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(48, a2), 0xFFFF), and(shr(48, s2), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(32, a2), 0xFFFF), and(shr(32, s2), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(16, a2), 0xFFFF), and(shr(16, s2), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(a2, 0xFFFF), and(s2, 0xFFFF))), q)
                
                // a3 x s3 (16 terms)
                innerProd := mod(add(innerProd, mul(and(shr(240, a3), 0xFFFF), and(shr(240, s3), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(224, a3), 0xFFFF), and(shr(224, s3), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(208, a3), 0xFFFF), and(shr(208, s3), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(192, a3), 0xFFFF), and(shr(192, s3), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(176, a3), 0xFFFF), and(shr(176, s3), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(160, a3), 0xFFFF), and(shr(160, s3), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(144, a3), 0xFFFF), and(shr(144, s3), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(128, a3), 0xFFFF), and(shr(128, s3), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(112, a3), 0xFFFF), and(shr(112, s3), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(96, a3), 0xFFFF), and(shr(96, s3), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(80, a3), 0xFFFF), and(shr(80, s3), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(64, a3), 0xFFFF), and(shr(64, s3), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(48, a3), 0xFFFF), and(shr(48, s3), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(32, a3), 0xFFFF), and(shr(32, s3), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(16, a3), 0xFFFF), and(shr(16, s3), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(a3, 0xFFFF), and(s3, 0xFFFF))), q)
                
                let diff := mod(add(sub(b, innerProd), q), q)
                let cfBit := and(gt(diff, threshold), lt(diff, mul(3, threshold)))
                
                let newVal := xor(and(shr(active, wires), 1), cfBit)
                let bitMask := shl(active, 1)
                wires := or(and(wires, not(bitMask)), mul(newVal, bitMask))
            }
        }
        
        // Compute final LWE SEH hash (VERY EXPENSIVE - O(numGates * SEH_DIM * numWires))
        sehOutput = _sehHash(wires, numGates);
        
        bytes32 outputHash = keccak256(abi.encodePacked(wires));
        valid = (outputHash == expectedOutputHash) && (sehOutput == expectedSehOutput);
    }
    
    function _deriveSecret64(bytes32 input) internal pure returns (uint256 s0, uint256 s1, uint256 s2, uint256 s3) {
        bytes32 h0 = keccak256(abi.encodePacked(input, uint256(0)));
        bytes32 h1 = keccak256(abi.encodePacked(input, uint256(1)));
        bytes32 h2 = keccak256(abi.encodePacked(input, uint256(2)));
        bytes32 h3 = keccak256(abi.encodePacked(input, uint256(3)));
        uint256 q = Q;
        
        assembly {
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let shift := mul(sub(15, i), 16)
                s0 := or(s0, shl(shift, mod(and(shr(shift, h0), 0xFFFF), q)))
                s1 := or(s1, shl(shift, mod(and(shr(shift, h1), 0xFFFF), q)))
                s2 := or(s2, shl(shift, mod(and(shr(shift, h2), 0xFFFF), q)))
                s3 := or(s3, shl(shift, mod(and(shr(shift, h3), 0xFFFF), q)))
            }
        }
    }
    
    receive() external payable { _reward += msg.value; }
}
