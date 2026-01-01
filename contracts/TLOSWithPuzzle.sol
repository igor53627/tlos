// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IHoneypot.sol";
import "./WeakLWEPuzzle.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";

/// @title TLOSWithPuzzle - 4-Layer TLOS with Weak LWE Brute-Force Resistance
/// @notice Adds Layer 4 (Weak LWE Puzzle) to existing 3-layer TLOS
/// @dev Security model:
///   Layer 1 (Topology): Structural mixing defeats pattern attacks
///   Layer 2 (LBLO): Binary-Error LWE hides control functions (~2^120 PQ)
///   Layer 3 (Wire Binding): Full-rank linear map prevents mix-and-match
///   Layer 4 (Weak LWE Puzzle): ~2^20 work per guess (not GPU-friendly)
///
/// Flow:
///   1. Solver finds puzzle solution s for input x (off-chain, ~2^20 work)
///   2. Contract verifies ||As - b|| < threshold (cheap, ~20K gas)
///   3. Contract uses H(s) as key to evaluate TLOS circuit
///   4. Contract checks output matches expected
///
/// Security effect:
///   - Current: 25M guesses/sec on GH200
///   - With puzzle: ~10-100 guesses/sec (BKZ is memory-bound, not GPU-friendly)
///   - 2^30 crack time: 43 sec -> 4-40 months
contract TLOSWithPuzzle is IHoneypot {
    uint256 public constant COMMIT_DELAY = 2;
    uint256 public constant Q = 65521;           // TLOS modulus
    uint256 public constant LBLO_N = 128;        // TLOS dimension
    uint256 public constant THRESHOLD = Q / 4;
    uint256 public constant BINDING_ROWS = 64;
    
    // Weak LWE Puzzle parameters (Layer 4)
    uint256 public constant N_WEAK = 48;
    uint256 public constant M_WEAK = 64;
    uint256 public constant Q_WEAK = 2048;
    uint256 public constant PUZZLE_THRESHOLD_SQ = 512;
    bytes32 public constant PUZZLE_DOMAIN = keccak256("TLOS-WeakLWE-Puzzle-v1");
    
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
    
    uint256 private constant CT_SIZE = 258;
    uint256 private constant GATE_SIZE = 1035;
    
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
    
    /// @notice Commit hash for front-running protection
    /// @param commitHash Hash of (sender, input, puzzleSolution)
    function commit(bytes32 commitHash) external override {
        require(block.timestamp < secretExpiry, "Secret expired");
        _commits[msg.sender] = Commitment({hash: commitHash, blockNumber: block.number});
        emit Committed(msg.sender, commitHash, block.number);
    }
    
    /// @notice Reveal with puzzle solution (Layer 4 integrated)
    /// @param input The secret input x
    /// @param puzzleSolution The weak LWE solution s ∈ {-1,0,1}^48
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
        
        // Layer 4: Verify puzzle solution
        (bool puzzleValid, bytes32 sHash, uint256 normSq) = _verifyPuzzle(input, puzzleSolution);
        require(puzzleValid, "Invalid puzzle solution");
        emit PuzzleSolved(msg.sender, keccak256(abi.encodePacked(input)), normSq);
        
        // Layers 1-3: Evaluate TLOS circuit using puzzle solution hash as additional entropy
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
    
    /// @notice Legacy reveal (for backwards compatibility, puzzle solution required)
    function reveal(bytes32) external pure override {
        revert("Use revealWithPuzzle instead");
    }
    
    /// @notice Check if input + puzzle solution is valid (view function)
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
    
    /// @notice Legacy check (always returns false - need puzzle solution)
    function check(bytes32) external pure override returns (bool) {
        return false; // Cannot check without puzzle solution
    }
    
    /// @notice Get puzzle seed for off-chain solving
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
    function scheme() external pure override returns (string memory) { return "tlos-lblo-puzzle"; }
    function encryptedGates() external pure override returns (uint256) { return 640; }
    function estimatedGas() external pure override returns (uint256) { return 55_000_000; }
    function isExpired() external view returns (bool) { return block.timestamp >= secretExpiry; }
    function timeRemaining() external view returns (uint256) {
        if (block.timestamp >= secretExpiry) return 0;
        return secretExpiry - block.timestamp;
    }
    
    /// @notice Verify weak LWE puzzle solution (Layer 4)
    /// @return valid Whether solution satisfies ||As - b||² < threshold
    /// @return sHash Hash of solution (used as additional key material)
    /// @return normSq The computed squared norm
    function _verifyPuzzle(bytes32 x, int8[48] calldata solution) 
        internal 
        pure 
        returns (bool valid, bytes32 sHash, uint256 normSq) 
    {
        // Check solution is ternary {-1, 0, 1}
        for (uint256 i = 0; i < N_WEAK; i++) {
            if (solution[i] < -1 || solution[i] > 1) {
                return (false, bytes32(0), 0);
            }
        }
        
        bytes32 seed = keccak256(abi.encodePacked(PUZZLE_DOMAIN, x));
        normSq = 0;
        
        for (uint256 row = 0; row < M_WEAK; row++) {
            bytes32 rowSeed = keccak256(abi.encodePacked(seed, "row", row));
            int256 dotProduct = 0;
            
            // Process 16 coefficients at a time
            for (uint256 col = 0; col < N_WEAK; col += 16) {
                bytes32 coeffs = keccak256(abi.encodePacked(rowSeed, col / 16));
                
                for (uint256 k = 0; k < 16 && col + k < N_WEAK; k++) {
                    uint256 aij = uint256(uint16(bytes2(coeffs << (k * 16)))) % Q_WEAK;
                    dotProduct += int256(aij) * int256(solution[col + k]);
                }
            }
            
            bytes32 bSeed = keccak256(abi.encodePacked(seed, "b", row));
            uint256 bRow = uint256(bSeed) % Q_WEAK;
            
            // Compute centered residual
            int256 residual = dotProduct - int256(bRow);
            residual = residual % int256(Q_WEAK);
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
    
    /// @notice Compute wire binding hash (Layer 3)
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
    
    /// @notice Evaluate TLOS circuit (Layers 1-3) with puzzle-derived key material
    function _evaluate(bytes32 input, bytes32 puzzleSolutionHash) 
        internal 
        view 
        returns (bool valid, uint256[4] memory bindingOutput) 
    {
        uint256 wires = uint256(input) & ((1 << numWires) - 1);
        bytes memory cd = SSTORE2.read(circuitDataPointer);
        
        // Derive secret combining input AND puzzle solution (double binding)
        uint256[8] memory s = _deriveSecret128Array(input, puzzleSolutionHash);
        
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
                    
                    let ctPtr := add(dataPtr, add(3, mul(ttIdx, 258)))
                    
                    let innerProd := 0
                    
                    for { let wordIdx := 0 } lt(wordIdx, 8) { wordIdx := add(wordIdx, 1) } {
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
                    
                    let bWord := mload(add(ctPtr, 256))
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
    
    /// @notice Derive LBLO secret from input AND puzzle solution hash
    /// @dev Double binding: attacker must solve puzzle AND have correct input
    function _deriveSecret128Array(bytes32 input, bytes32 puzzleSolutionHash) 
        internal 
        pure 
        returns (uint256[8] memory s) 
    {
        // Combine input with puzzle solution for double binding
        bytes32 combined = keccak256(abi.encodePacked(input, puzzleSolutionHash));
        
        bytes32[8] memory h;
        h[0] = keccak256(abi.encodePacked(combined, uint256(0)));
        h[1] = keccak256(abi.encodePacked(combined, uint256(1)));
        h[2] = keccak256(abi.encodePacked(combined, uint256(2)));
        h[3] = keccak256(abi.encodePacked(combined, uint256(3)));
        h[4] = keccak256(abi.encodePacked(combined, uint256(4)));
        h[5] = keccak256(abi.encodePacked(combined, uint256(5)));
        h[6] = keccak256(abi.encodePacked(combined, uint256(6)));
        h[7] = keccak256(abi.encodePacked(combined, uint256(7)));
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
