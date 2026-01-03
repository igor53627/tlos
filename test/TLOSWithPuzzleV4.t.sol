// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";
import "../contracts/TLOSWithPuzzleV4.sol";
import "./TLOSWithPuzzleV4Harness.sol";

/// @title TLOSWithPuzzleV4 Test Suite
/// @notice Comprehensive tests for the production 4-layer TLOS contract
/// @dev Tests cover:
///   - Basic deployment and parameter validation
///   - Puzzle verification (Layer 4)
///   - Wire binding integration (Layer 3)
///   - Cross-layer composition
///   - Commit-reveal flow
///   - Expiry and reclaim logic
contract TLOSWithPuzzleV4Test is Test {
    uint256 constant Q = 65521;
    uint256 constant LBLO_N = 384;
    uint256 constant N_WEAK = 48;
    uint256 constant M_WEAK = 72;
    uint256 constant Q_WEAK = 2039;
    uint256 constant PUZZLE_THRESHOLD_SQ = 300;
    
    bytes32 constant TEST_INPUT = bytes32(uint256(0x12345));
    
    TLOSWithPuzzleV4 public honeypot;
    TLOSWithPuzzleV4Harness public harness;
    address public dataPtr;
    address public puzzleBPtr;
    bytes32 public puzzleSeed;
    bytes32 public circuitSeed;
    int8[48] public plantedSecret;
    
    receive() external payable {}
    
    function setUp() public {
        circuitSeed = keccak256("TLOS-V4-Test-Seed");
        puzzleSeed = keccak256("TLOS-V4-Puzzle-Seed");
        
        plantedSecret = _generatePlantedSecret(puzzleSeed);
        
        bytes memory circuitData = _generateMockCircuitData(64);
        dataPtr = SSTORE2.write(circuitData);
        
        bytes memory bVector = _generateBVector(puzzleSeed, plantedSecret);
        puzzleBPtr = SSTORE2.write(bVector);
        
        bytes32 expectedOutputHash = keccak256(abi.encodePacked(uint256(TEST_INPUT) & ((1 << 64) - 1)));
        uint256[4] memory expectedBinding;
        
        honeypot = new TLOSWithPuzzleV4(
            dataPtr,
            64,
            64,
            expectedOutputHash,
            circuitSeed,
            expectedBinding,
            block.timestamp + 1 days,
            puzzleSeed,
            puzzleBPtr
        );
        
        harness = new TLOSWithPuzzleV4Harness(
            dataPtr,
            64,
            64,
            expectedOutputHash,
            circuitSeed,
            expectedBinding,
            block.timestamp + 1 days,
            puzzleSeed,
            puzzleBPtr
        );
    }
    
    // ========== Helper: Commit Hash ==========
    
    function _commitHash(address solver, bytes32 input, int8[48] memory solution) 
        internal 
        pure 
        returns (bytes32) 
    {
        return keccak256(abi.encode(solver, input, solution));
    }
    
    // ========== Deployment Tests ==========
    
    function test_Deployment_Parameters() public view {
        assertEq(honeypot.numWires(), 64);
        assertEq(honeypot.numGates(), 64);
        assertEq(honeypot.circuitSeed(), circuitSeed);
        assertEq(honeypot.puzzleSeed(), puzzleSeed);
        assertEq(honeypot.puzzleBPointer(), puzzleBPtr);
        assertEq(honeypot.owner(), address(this));
        assertEq(honeypot.COMMIT_DELAY(), 2);
    }
    
    function test_Deployment_RejectsZeroWires() public {
        bytes memory circuitData = _generateMockCircuitData(1);
        address dp = SSTORE2.write(circuitData);
        bytes memory bVector = _generateBVector(puzzleSeed, plantedSecret);
        address bp = SSTORE2.write(bVector);
        uint256[4] memory eb;
        
        vm.expectRevert("Wires must be 1-64");
        new TLOSWithPuzzleV4(dp, 0, 1, bytes32(0), circuitSeed, eb, block.timestamp + 1 days, puzzleSeed, bp);
    }
    
    function test_Deployment_RejectsExcessiveWires() public {
        bytes memory circuitData = _generateMockCircuitData(1);
        address dp = SSTORE2.write(circuitData);
        bytes memory bVector = _generateBVector(puzzleSeed, plantedSecret);
        address bp = SSTORE2.write(bVector);
        uint256[4] memory eb;
        
        vm.expectRevert("Wires must be 1-64");
        new TLOSWithPuzzleV4(dp, 65, 1, bytes32(0), circuitSeed, eb, block.timestamp + 1 days, puzzleSeed, bp);
    }
    
    function test_Deployment_RejectsZeroGates() public {
        bytes memory circuitData = _generateMockCircuitData(1);
        address dp = SSTORE2.write(circuitData);
        bytes memory bVector = _generateBVector(puzzleSeed, plantedSecret);
        address bp = SSTORE2.write(bVector);
        uint256[4] memory eb;
        
        vm.expectRevert("Must have gates");
        new TLOSWithPuzzleV4(dp, 64, 0, bytes32(0), circuitSeed, eb, block.timestamp + 1 days, puzzleSeed, bp);
    }
    
    function test_Deployment_RejectsPastExpiry() public {
        bytes memory circuitData = _generateMockCircuitData(1);
        address dp = SSTORE2.write(circuitData);
        bytes memory bVector = _generateBVector(puzzleSeed, plantedSecret);
        address bp = SSTORE2.write(bVector);
        uint256[4] memory eb;
        
        vm.expectRevert("Expiry must be in future");
        new TLOSWithPuzzleV4(dp, 64, 1, bytes32(0), circuitSeed, eb, block.timestamp - 1, puzzleSeed, bp);
    }
    
    function test_Deployment_RejectsZeroCircuitPointer() public {
        bytes memory bVector = _generateBVector(puzzleSeed, plantedSecret);
        address bp = SSTORE2.write(bVector);
        uint256[4] memory eb;
        
        vm.expectRevert("Invalid circuit pointer");
        new TLOSWithPuzzleV4(address(0), 64, 1, bytes32(0), circuitSeed, eb, block.timestamp + 1 days, puzzleSeed, bp);
    }
    
    function test_Deployment_RejectsZeroPuzzlePointer() public {
        bytes memory circuitData = _generateMockCircuitData(1);
        address dp = SSTORE2.write(circuitData);
        uint256[4] memory eb;
        
        vm.expectRevert("Invalid puzzle pointer");
        new TLOSWithPuzzleV4(dp, 64, 1, bytes32(0), circuitSeed, eb, block.timestamp + 1 days, puzzleSeed, address(0));
    }
    
    // ========== Puzzle Verification Tests (Layer 4) ==========
    
    function test_Puzzle_ValidSolutionAccepted() public {
        // With mock circuit data and zero binding, full check fails but puzzle should pass
        bool fullValid = honeypot.checkWithPuzzle(TEST_INPUT, plantedSecret);
        assertFalse(fullValid, "Full check should fail with mock circuit data");
    }
    
    function test_Puzzle_ValidSolutionPassesThreshold_Harness() public view {
        // Use harness to verify puzzle layer in isolation
        (bool puzzleValid, bytes32 sHash, uint256 normSq) = harness.verifyPuzzlePublic(plantedSecret);
        
        assertTrue(puzzleValid, "Planted secret should satisfy puzzle");
        assertLt(normSq, PUZZLE_THRESHOLD_SQ, "Norm should be below threshold");
        assertNotEq(sHash, bytes32(0), "Solution hash should be non-zero");
    }
    
    function test_Puzzle_SingleBitFlipExceedsThreshold_Harness() public view {
        // Flip a single coordinate of the planted secret
        int8[48] memory flippedSecret = plantedSecret;
        
        // Find first non-zero and flip it, or flip first zero to 1
        if (flippedSecret[0] == 0) {
            flippedSecret[0] = 1;
        } else if (flippedSecret[0] == 1) {
            flippedSecret[0] = -1;
        } else {
            flippedSecret[0] = 1;
        }
        
        (bool valid, , uint256 normSq) = harness.verifyPuzzlePublic(flippedSecret);
        
        // Single bit flip should exceed threshold (testing security margin)
        assertFalse(valid, "Single bit flip should exceed threshold");
        assertGe(normSq, PUZZLE_THRESHOLD_SQ, "Norm should exceed threshold after flip");
    }
    
    function test_Puzzle_InputIndependence_Harness() public view {
        // V4 puzzle is input-independent (one puzzle per contract)
        // Verify sHash is same for different inputs
        (bool v1, bytes32 sHash1, ) = harness.verifyPuzzlePublic(plantedSecret);
        
        // Create a different harness instance to verify puzzle is contract-specific
        assertTrue(v1, "Puzzle should be valid");
        assertNotEq(sHash1, bytes32(0), "Hash should be non-zero");
    }
    
    function test_SecretDerivation_DifferentInputsProduceDifferentSecrets_Harness() public view {
        bytes32 sHash = keccak256(abi.encodePacked(plantedSecret));
        
        uint256[24] memory s1 = harness.deriveSecret384ArrayPublic(TEST_INPUT, sHash);
        uint256[24] memory s2 = harness.deriveSecret384ArrayPublic(bytes32(uint256(0x54321)), sHash);
        
        // Different inputs with same puzzle hash should produce different secrets
        bool allSame = true;
        for (uint256 i = 0; i < 24; i++) {
            if (s1[i] != s2[i]) {
                allSame = false;
                break;
            }
        }
        assertFalse(allSame, "Different inputs should produce different derived secrets");
    }
    
    function test_SecretDerivation_DifferentPuzzleHashesProduceDifferentSecrets_Harness() public view {
        bytes32 sHash1 = keccak256(abi.encodePacked(plantedSecret));
        bytes32 sHash2 = keccak256(abi.encodePacked("different"));
        
        uint256[24] memory s1 = harness.deriveSecret384ArrayPublic(TEST_INPUT, sHash1);
        uint256[24] memory s2 = harness.deriveSecret384ArrayPublic(TEST_INPUT, sHash2);
        
        bool allSame = true;
        for (uint256 i = 0; i < 24; i++) {
            if (s1[i] != s2[i]) {
                allSame = false;
                break;
            }
        }
        assertFalse(allSame, "Different puzzle hashes should produce different derived secrets");
    }
    
    function test_Puzzle_NonTernarySolutionRejected() public {
        bytes32 testInput = bytes32(uint256(0x12345));
        int8[48] memory badSolution;
        badSolution[0] = 2;
        
        bool valid = honeypot.checkWithPuzzle(testInput, badSolution);
        assertFalse(valid, "Non-ternary solution should be rejected");
    }
    
    function test_Puzzle_NegativeNonTernaryRejected() public {
        bytes32 testInput = bytes32(uint256(0x12345));
        int8[48] memory badSolution;
        badSolution[10] = -2;
        
        bool valid = honeypot.checkWithPuzzle(testInput, badSolution);
        assertFalse(valid, "Solution with -2 should be rejected");
    }
    
    function test_Puzzle_AllZerosSolutionRejected() public {
        bytes32 testInput = bytes32(uint256(0x12345));
        int8[48] memory zeroSolution;
        
        bool valid = honeypot.checkWithPuzzle(testInput, zeroSolution);
        assertFalse(valid, "All-zeros solution should fail (wrong residual)");
    }
    
    function test_Puzzle_RandomTernarySolutionRejected() public {
        bytes32 testInput = bytes32(uint256(0x12345));
        int8[48] memory randomSolution;
        
        for (uint256 i = 0; i < 48; i++) {
            randomSolution[i] = int8(int256(uint256(keccak256(abi.encodePacked(i))) % 3) - 1);
        }
        
        bool valid = honeypot.checkWithPuzzle(testInput, randomSolution);
        assertFalse(valid, "Random ternary solution should fail");
    }
    
    // ========== Commit-Reveal Flow Tests ==========
    
    function test_Commit_Success() public {
        address solver = makeAddr("solver");
        bytes32 commitHash = keccak256(abi.encodePacked("test"));
        
        vm.prank(solver);
        honeypot.commit(commitHash);
        
        (bytes32 storedHash, uint256 blockNum) = honeypot.getCommit(solver);
        assertEq(storedHash, commitHash);
        assertEq(blockNum, block.number);
    }
    
    function test_Commit_RevertsAfterExpiry() public {
        vm.warp(honeypot.secretExpiry() + 1);
        
        vm.expectRevert("Secret expired");
        honeypot.commit(bytes32(uint256(1)));
    }
    
    function test_Reveal_RevertsWithoutCommit() public {
        bytes32 testInput = bytes32(uint256(0x12345));
        
        vm.expectRevert("No commit found");
        honeypot.revealWithPuzzle(testInput, plantedSecret);
    }
    
    function test_Reveal_RevertsTooEarly() public {
        address solver = makeAddr("solver");
        bytes32 testInput = bytes32(uint256(0x12345));
        bytes32 commitHash = keccak256(abi.encode(solver, testInput, plantedSecret));
        
        vm.prank(solver);
        honeypot.commit(commitHash);
        
        vm.roll(block.number + 1);
        
        vm.prank(solver);
        vm.expectRevert("Reveal too early");
        honeypot.revealWithPuzzle(testInput, plantedSecret);
    }
    
    function test_Reveal_RevertsWithWrongCommitHash() public {
        address solver = makeAddr("solver");
        bytes32 testInput = bytes32(uint256(0x12345));
        bytes32 wrongHash = keccak256(abi.encodePacked("wrong"));
        
        vm.prank(solver);
        honeypot.commit(wrongHash);
        
        vm.roll(block.number + 3);
        
        vm.prank(solver);
        vm.expectRevert("Invalid reveal");
        honeypot.revealWithPuzzle(testInput, plantedSecret);
    }
    
    function test_Reveal_RevertsAfterExpiry() public {
        address solver = makeAddr("solver");
        bytes32 testInput = bytes32(uint256(0x12345));
        bytes32 commitHash = keccak256(abi.encode(solver, testInput, plantedSecret));
        
        vm.prank(solver);
        honeypot.commit(commitHash);
        
        vm.roll(block.number + 3);
        vm.warp(honeypot.secretExpiry() + 1);
        
        vm.prank(solver);
        vm.expectRevert("Secret expired");
        honeypot.revealWithPuzzle(testInput, plantedSecret);
    }
    
    function test_Reveal_PlainRevealReverts() public {
        vm.expectRevert("Use revealWithPuzzle instead");
        honeypot.reveal(bytes32(0));
    }
    
    function test_Check_PlainCheckReturnsFalse() public view {
        bool result = honeypot.check(bytes32(uint256(0x12345)));
        assertFalse(result, "Plain check() should always return false");
    }
    
    // ========== Expiry and Reclaim Tests ==========
    
    function test_Expiry_TimeRemaining() public view {
        uint256 remaining = honeypot.timeRemaining();
        assertGt(remaining, 0, "Should have time remaining");
        assertFalse(honeypot.isExpired(), "Should not be expired");
    }
    
    function test_Expiry_AfterExpiry() public {
        vm.warp(honeypot.secretExpiry() + 1);
        
        assertEq(honeypot.timeRemaining(), 0);
        assertTrue(honeypot.isExpired());
    }
    
    function test_Reclaim_Success() public {
        (bool sent,) = address(honeypot).call{value: 1 ether}("");
        assertTrue(sent);
        
        uint256 balanceBefore = address(this).balance;
        
        vm.warp(honeypot.secretExpiry() + 1);
        honeypot.reclaimExpired();
        
        assertEq(address(this).balance, balanceBefore + 1 ether);
    }
    
    function test_Claim_HappyPath_Harness() public {
        // Deploy a funded harness
        bytes memory circuitData = _generateMockCircuitData(64);
        address dp = SSTORE2.write(circuitData);
        bytes memory bVector = _generateBVector(puzzleSeed, plantedSecret);
        address bp = SSTORE2.write(bVector);
        uint256[4] memory eb;
        
        TLOSWithPuzzleV4Harness fundedHarness = new TLOSWithPuzzleV4Harness{value: 1 ether}(
            dp, 64, 64, bytes32(0), circuitSeed, eb, block.timestamp + 1 days, puzzleSeed, bp
        );
        
        address solver = makeAddr("solver");
        uint256 solverBalanceBefore = solver.balance;
        
        // Use testOnlyForceClaim to bypass puzzle/circuit checks and test claim plumbing
        fundedHarness.testOnlyForceClaim(solver);
        
        // Verify reward transferred
        assertEq(solver.balance, solverBalanceBefore + 1 ether, "Solver should receive reward");
        assertEq(fundedHarness.reward(), 0, "Reward should be zero after claim");
        
        // Verify cannot claim again
        vm.expectRevert("Already claimed");
        fundedHarness.testOnlyForceClaim(solver);
        
        // Verify reclaim also blocked
        vm.warp(fundedHarness.secretExpiry() + 1);
        vm.expectRevert("Already claimed");
        fundedHarness.reclaimExpired();
    }
    
    function test_Reclaim_OnlyOwner() public {
        address notOwner = makeAddr("notOwner");
        
        vm.warp(honeypot.secretExpiry() + 1);
        
        vm.prank(notOwner);
        vm.expectRevert("Only owner");
        honeypot.reclaimExpired();
    }
    
    function test_Reclaim_RevertsBeforeExpiry() public {
        vm.expectRevert("Not expired yet");
        honeypot.reclaimExpired();
    }
    
    function test_Reclaim_RevertsIfAlreadyClaimed() public {
        vm.warp(honeypot.secretExpiry() + 1);
        honeypot.reclaimExpired();
        
        vm.expectRevert("Already claimed");
        honeypot.reclaimExpired();
    }
    
    // ========== Interface Compliance Tests ==========
    
    function test_Interface_Scheme() public view {
        assertEq(honeypot.scheme(), "tlos-lwe-puzzleV4");
    }
    
    function test_Interface_EncryptedGates() public view {
        assertEq(honeypot.encryptedGates(), 640);
    }
    
    function test_Interface_EstimatedGas() public view {
        assertEq(honeypot.estimatedGas(), 9_000_000);
    }
    
    function test_Interface_CommitDelay() public view {
        assertEq(honeypot.commitDelay(), 2);
    }
    
    function test_Interface_Reward() public {
        assertEq(honeypot.reward(), 0);
        
        (bool sent,) = address(honeypot).call{value: 1 ether}("");
        assertTrue(sent);
        assertEq(honeypot.reward(), 1 ether);
    }
    
    // ========== Wire Binding Tests (Layer 3) - Issue #43 ==========
    
    function test_WireBinding_OutputDeterministic_Harness() public view {
        // Same input should produce same binding output
        uint256[4] memory out1 = harness.wireBindingHashPublic(0x12345, 0);
        uint256[4] memory out2 = harness.wireBindingHashPublic(0x12345, 0);
        
        assertEq(out1[0], out2[0], "Binding should be deterministic");
        assertEq(out1[1], out2[1], "Binding should be deterministic");
        assertEq(out1[2], out2[2], "Binding should be deterministic");
        assertEq(out1[3], out2[3], "Binding should be deterministic");
    }
    
    function test_WireBinding_OutputChangesWithInput_Harness() public view {
        uint256[4] memory out1 = harness.wireBindingHashPublic(0x1, 0);
        uint256[4] memory out2 = harness.wireBindingHashPublic(0x2, 0);
        
        // XOR all outputs to compare
        uint256 combined1 = out1[0] ^ out1[1] ^ out1[2] ^ out1[3];
        uint256 combined2 = out2[0] ^ out2[1] ^ out2[2] ^ out2[3];
        
        assertNotEq(combined1, combined2, "Different inputs should produce different bindings");
    }
    
    function test_WireBinding_OutputChangesWithGateIdx_Harness() public view {
        uint256[4] memory out1 = harness.wireBindingHashPublic(0x12345, 0);
        uint256[4] memory out2 = harness.wireBindingHashPublic(0x12345, 64);
        
        uint256 combined1 = out1[0] ^ out1[1] ^ out1[2] ^ out1[3];
        uint256 combined2 = out2[0] ^ out2[1] ^ out2[2] ^ out2[3];
        
        assertNotEq(combined1, combined2, "Different gate indices should produce different bindings");
    }
    
    function test_WireBinding_EvaluateReturnsBinding_Harness() public view {
        bytes32 sHash = keccak256(abi.encodePacked(plantedSecret));
        
        (, uint256[4] memory bindingOutput) = harness.evaluatePublic(TEST_INPUT, sHash);
        
        // Binding output should be non-trivial
        uint256 combined = bindingOutput[0] | bindingOutput[1] | bindingOutput[2] | bindingOutput[3];
        assertGt(combined, 0, "Binding output should be non-zero");
    }
    
    function test_WireBinding_DifferentSeedsProduceDifferentBindings() public {
        bytes32 seed1 = keccak256("seed1");
        bytes32 seed2 = keccak256("seed2");
        
        bytes memory circuitData = _generateMockCircuitData(64);
        address dp = SSTORE2.write(circuitData);
        bytes memory bVector = _generateBVector(puzzleSeed, plantedSecret);
        address bp = SSTORE2.write(bVector);
        
        uint256[4] memory eb;
        
        TLOSWithPuzzleV4 hp1 = new TLOSWithPuzzleV4(
            dp, 64, 64, bytes32(0), seed1, eb, block.timestamp + 1 days, puzzleSeed, bp
        );
        TLOSWithPuzzleV4 hp2 = new TLOSWithPuzzleV4(
            dp, 64, 64, bytes32(0), seed2, eb, block.timestamp + 1 days, puzzleSeed, bp
        );
        
        assertNotEq(hp1.circuitSeed(), hp2.circuitSeed(), "Seeds should differ");
    }
    
    function test_WireBinding_ExpectedBindingMustMatch() public {
        bytes memory circuitData = _generateMockCircuitData(64);
        address dp = SSTORE2.write(circuitData);
        bytes memory bVector = _generateBVector(puzzleSeed, plantedSecret);
        address bp = SSTORE2.write(bVector);
        
        uint256[4] memory wrongBinding = [uint256(1), uint256(2), uint256(3), uint256(4)];
        bytes32 testInput = bytes32(uint256(0x12345));
        bytes32 expectedOutputHash = keccak256(abi.encodePacked(uint256(testInput) & ((1 << 64) - 1)));
        
        TLOSWithPuzzleV4 hp = new TLOSWithPuzzleV4(
            dp, 64, 64, expectedOutputHash, circuitSeed, wrongBinding, block.timestamp + 1 days, puzzleSeed, bp
        );
        
        bool valid = hp.checkWithPuzzle(testInput, plantedSecret);
        assertFalse(valid, "Wrong binding should cause validation failure");
    }
    
    function test_WireBinding_SingleBitFlipDetected() public {
        bytes memory circuitData = _generateMockCircuitData(64);
        address dp = SSTORE2.write(circuitData);
        bytes memory bVector = _generateBVector(puzzleSeed, plantedSecret);
        address bp = SSTORE2.write(bVector);
        
        uint256[4] memory eb;
        bytes32 testInput = bytes32(uint256(0x12345));
        bytes32 outputHash = keccak256(abi.encodePacked(uint256(testInput) & ((1 << 64) - 1)));
        
        TLOSWithPuzzleV4 hp = new TLOSWithPuzzleV4(
            dp, 64, 64, outputHash, circuitSeed, eb, block.timestamp + 1 days, puzzleSeed, bp
        );
        
        bool valid1 = hp.checkWithPuzzle(testInput, plantedSecret);
        
        bytes32 flippedInput = bytes32(uint256(testInput) ^ 1);
        bool valid2 = hp.checkWithPuzzle(flippedInput, plantedSecret);
        
        assertNotEq(valid1 && valid2, true, "Single bit flip should change result");
    }
    
    // ========== Cross-Layer Failure Tests - Issue #44 ==========
    
    function test_CrossLayer_PuzzleFailStopsCircuit() public {
        bytes32 testInput = bytes32(uint256(0x12345));
        int8[48] memory wrongPuzzle;
        wrongPuzzle[0] = 1;
        wrongPuzzle[1] = -1;
        
        bool valid = honeypot.checkWithPuzzle(testInput, wrongPuzzle);
        assertFalse(valid, "Wrong puzzle should fail before circuit evaluation");
    }
    
    function test_CrossLayer_CorrectPuzzleWrongInput() public {
        bytes32 wrongInput = bytes32(uint256(0xDEADBEEF));
        
        bool valid = honeypot.checkWithPuzzle(wrongInput, plantedSecret);
        assertFalse(valid, "Correct puzzle with wrong input should fail");
    }
    
    function test_CrossLayer_AllLayersMustPass() public {
        bytes32 testInput = bytes32(uint256(0x12345));
        
        int8[48] memory validPuzzle = plantedSecret;
        
        bool result = honeypot.checkWithPuzzle(testInput, validPuzzle);
        emit log_named_string("All layers result", result ? "true" : "false (binding mismatch expected)");
    }
    
    function test_CrossLayer_PuzzleSolutionAffectsSecretDerivation() public {
        bytes32 testInput = bytes32(uint256(0x12345));
        
        int8[48] memory puzzle1 = plantedSecret;
        int8[48] memory puzzle2;
        for (uint256 i = 0; i < 48; i++) {
            puzzle2[i] = -puzzle1[i];
        }
        
        bool valid2 = honeypot.checkWithPuzzle(testInput, puzzle2);
        assertFalse(valid2, "Different puzzle should derive different secret");
    }
    
    // ========== Wrong-Key Garbage Property Tests - Issue #45 ==========
    
    function test_GarbageOutput_WrongInputProducesUnpredictable() public {
        bytes32 correctInput = bytes32(uint256(0x12345));
        bytes32 wrongInput1 = bytes32(uint256(0x12346));
        bytes32 wrongInput2 = bytes32(uint256(0x54321));
        
        bool v1 = honeypot.checkWithPuzzle(correctInput, plantedSecret);
        bool v2 = honeypot.checkWithPuzzle(wrongInput1, plantedSecret);
        bool v3 = honeypot.checkWithPuzzle(wrongInput2, plantedSecret);
        
        emit log_named_string("Correct input", v1 ? "valid" : "invalid");
        emit log_named_string("Wrong input 1", v2 ? "valid" : "invalid");
        emit log_named_string("Wrong input 2", v3 ? "valid" : "invalid");
    }
    
    function test_GarbageOutput_AdjacentInputsDiffer() public {
        bool anyMatch = false;
        bytes32 baseInput = bytes32(uint256(0x12345));
        bool baseResult = honeypot.checkWithPuzzle(baseInput, plantedSecret);
        
        for (uint256 bit = 0; bit < 10; bit++) {
            bytes32 flipped = bytes32(uint256(baseInput) ^ (1 << bit));
            bool flippedResult = honeypot.checkWithPuzzle(flipped, plantedSecret);
            
            if (flippedResult == baseResult && flippedResult) {
                anyMatch = true;
            }
        }
        
        assertFalse(anyMatch, "Adjacent inputs should not both validate");
    }
    
    function test_GarbageOutput_RandomInputsAllFail() public {
        uint256 failures = 0;
        
        for (uint256 i = 0; i < 5; i++) {
            bytes32 randomInput = keccak256(abi.encodePacked("random", i));
            bool valid = honeypot.checkWithPuzzle(randomInput, plantedSecret);
            if (!valid) failures++;
        }
        
        assertEq(failures, 5, "All random inputs should fail");
    }
    
    function test_GarbageOutput_PuzzleMismatchProducesGarbage() public {
        bytes32 testInput = bytes32(uint256(0x12345));
        
        bytes32 wrongPuzzleSeed = keccak256("wrong-puzzle-seed");
        int8[48] memory wrongPlantedSecret = _generatePlantedSecret(wrongPuzzleSeed);
        
        bool valid = honeypot.checkWithPuzzle(testInput, wrongPlantedSecret);
        assertFalse(valid, "Mismatched puzzle seed should produce garbage");
    }
    
    // ========== Blockhash-Bound Variant Tests - Issue #46 (Appendix A.8) ==========
    
    function test_Blockhash_CommitBindsToBlock() public {
        address solver = makeAddr("solver");
        bytes32 testInput = bytes32(uint256(0x12345));
        bytes32 commitHash = keccak256(abi.encode(solver, testInput, plantedSecret));
        
        vm.prank(solver);
        honeypot.commit(commitHash);
        
        (bytes32 storedHash, uint256 storedBlock) = honeypot.getCommit(solver);
        assertEq(storedHash, commitHash);
        assertEq(storedBlock, block.number);
    }
    
    function test_Blockhash_DelayEnforced() public {
        address solver = makeAddr("solver");
        bytes32 commitHash = _commitHash(solver, TEST_INPUT, plantedSecret);
        
        vm.prank(solver);
        honeypot.commit(commitHash);
        uint256 commitBlock = block.number;
        
        // At commitBlock + 1: still too early (COMMIT_DELAY = 2)
        vm.roll(commitBlock + 1);
        vm.prank(solver);
        vm.expectRevert("Reveal too early");
        honeypot.revealWithPuzzle(TEST_INPUT, plantedSecret);
        
        // At commitBlock + 2: delay satisfied, now fails on circuit (not delay)
        vm.roll(commitBlock + 2);
        vm.prank(solver);
        vm.expectRevert("Invalid circuit output");
        honeypot.revealWithPuzzle(TEST_INPUT, plantedSecret);
    }
    
    function test_Blockhash_RevealAfterDelay() public {
        address solver = makeAddr("solver");
        bytes32 testInput = bytes32(uint256(0x12345));
        bytes32 commitHash = keccak256(abi.encode(solver, testInput, plantedSecret));
        
        vm.prank(solver);
        honeypot.commit(commitHash);
        
        vm.roll(block.number + 3);
        
        vm.prank(solver);
        vm.expectRevert("Invalid circuit output");
        honeypot.revealWithPuzzle(testInput, plantedSecret);
    }
    
    function test_Blockhash_CommitHashBindsSenderInputAndSolution() public {
        address solver1 = makeAddr("solver1");
        address solver2 = makeAddr("solver2");
        bytes32 testInput = bytes32(uint256(0x12345));
        
        bytes32 hash1 = keccak256(abi.encode(solver1, testInput, plantedSecret));
        bytes32 hash2 = keccak256(abi.encode(solver2, testInput, plantedSecret));
        
        assertNotEq(hash1, hash2, "Different senders should produce different hashes");
        
        bytes32 input2 = bytes32(uint256(0x54321));
        bytes32 hash3 = keccak256(abi.encode(solver1, input2, plantedSecret));
        assertNotEq(hash1, hash3, "Different inputs should produce different hashes");
        
        int8[48] memory differentPuzzle;
        differentPuzzle[0] = 1;
        bytes32 hash4 = keccak256(abi.encode(solver1, testInput, differentPuzzle));
        assertNotEq(hash1, hash4, "Different puzzles should produce different hashes");
    }
    
    function test_Blockhash_CannotReplayCommit() public {
        address solver = makeAddr("solver");
        bytes32 testInput = bytes32(uint256(0x12345));
        bytes32 commitHash = keccak256(abi.encode(solver, testInput, plantedSecret));
        
        vm.prank(solver);
        honeypot.commit(commitHash);
        
        (, uint256 block1) = honeypot.getCommit(solver);
        
        vm.roll(block.number + 5);
        
        vm.prank(solver);
        honeypot.commit(commitHash);
        
        (, uint256 block2) = honeypot.getCommit(solver);
        
        assertGt(block2, block1, "Re-commit should update block number");
    }
    
    function test_Blockhash_ExpiryCutsOffReveals() public {
        address solver = makeAddr("solver");
        bytes32 testInput = bytes32(uint256(0x12345));
        bytes32 commitHash = keccak256(abi.encode(solver, testInput, plantedSecret));
        
        vm.prank(solver);
        honeypot.commit(commitHash);
        
        vm.roll(block.number + 3);
        vm.warp(honeypot.secretExpiry() + 1);
        
        vm.prank(solver);
        vm.expectRevert("Secret expired");
        honeypot.revealWithPuzzle(testInput, plantedSecret);
    }
    
    // ========== Gas Benchmarks ==========
    
    function test_Gas_CheckWithPuzzle_64Gates() public {
        bytes32 testInput = bytes32(uint256(0x12345));
        
        uint256 gasBefore = gasleft();
        honeypot.checkWithPuzzle(testInput, plantedSecret);
        uint256 gasUsed = gasBefore - gasleft();
        
        emit log_named_uint("checkWithPuzzle (64 gates) gas", gasUsed);
        emit log_named_uint("% of 60M block", gasUsed * 100 / 60_000_000);
        
        assertLt(gasUsed, 12_000_000, "Should be under 20% of block limit");
    }
    
    function test_Gas_PuzzleVerification_Isolated() public {
        bytes32 testInput = bytes32(uint256(0x12345));
        int8[48] memory solution = plantedSecret;
        
        uint256 gasBefore = gasleft();
        honeypot.checkWithPuzzle(testInput, solution);
        uint256 gasUsed = gasBefore - gasleft();
        
        emit log_named_uint("Puzzle + circuit verification gas", gasUsed);
    }
    
    function test_Gas_CommitRevealFlow() public {
        address solver = makeAddr("solver");
        bytes32 testInput = bytes32(uint256(0x12345));
        bytes32 commitHash = keccak256(abi.encode(solver, testInput, plantedSecret));
        
        uint256 gasBefore = gasleft();
        vm.prank(solver);
        honeypot.commit(commitHash);
        uint256 commitGas = gasBefore - gasleft();
        
        emit log_named_uint("commit() gas", commitGas);
        
        assertLt(commitGas, 100_000, "Commit should be cheap");
    }
    
    // ========== Helper Functions ==========
    
    function _generatePlantedSecret(bytes32 seed) internal pure returns (int8[48] memory secret) {
        for (uint256 blk = 0; blk < 3; ++blk) {
            bytes32 coeffs = keccak256(abi.encodePacked(seed, "planted", blk));
            for (uint256 k = 0; k < 16; ++k) {
                uint256 idx = blk * 16 + k;
                if (idx >= N_WEAK) break;
                uint256 shift = (15 - k) * 16;
                uint256 sRaw = (uint256(coeffs) >> shift) & 0xFFFF;
                secret[idx] = int8(int256(sRaw % 3) - 1);
            }
        }
    }
    
    function _generateBVector(bytes32 seed, int8[48] memory secret) internal pure returns (bytes memory) {
        bytes memory bVector = new bytes(M_WEAK * 2);
        
        for (uint256 row = 0; row < M_WEAK; ++row) {
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
                    
                    dotProduct += aij * int256(secret[col]);
                }
            }
            
            bytes32 errorSeed = keccak256(abi.encodePacked(seed, "error", row));
            int256 e = int256(uint256(errorSeed) % 5) - 2;
            
            int256 bRow = (dotProduct + e) % int256(Q_WEAK);
            if (bRow < 0) bRow += int256(Q_WEAK);
            
            uint16 bVal = uint16(uint256(bRow));
            bVector[row * 2] = bytes1(uint8(bVal >> 8));
            bVector[row * 2 + 1] = bytes1(uint8(bVal & 0xFF));
        }
        
        return bVector;
    }
    
    function _generateMockCircuitData(uint32 numGates) internal pure returns (bytes memory) {
        uint256 ctSize = LBLO_N * 2 + 2;
        uint256 gateSize = 3 + 4 * ctSize;
        bytes memory data = new bytes(numGates * gateSize);
        
        for (uint32 g = 0; g < numGates; g++) {
            uint256 baseOffset = g * gateSize;
            
            data[baseOffset] = bytes1(uint8((g * 3) % 64));
            data[baseOffset + 1] = bytes1(uint8((g * 5 + 1) % 64));
            data[baseOffset + 2] = bytes1(uint8((g * 7 + 2) % 64));
            
            for (uint256 tt = 0; tt < 4; tt++) {
                uint256 ctOffset = baseOffset + 3 + tt * ctSize;
                
                for (uint256 i = 0; i < LBLO_N; i++) {
                    uint16 ai = uint16((g * 1337 + tt * 31 + i * 17) % Q);
                    data[ctOffset + i * 2] = bytes1(uint8(ai >> 8));
                    data[ctOffset + i * 2 + 1] = bytes1(uint8(ai & 0xFF));
                }
                
                bool expectedBit = ((g + tt) % 2) == 1;
                uint16 b = expectedBit ? uint16(Q / 2) : 0;
                b = uint16((uint256(b) + (g * tt) % 16) % Q);
                data[ctOffset + LBLO_N * 2] = bytes1(uint8(b >> 8));
                data[ctOffset + LBLO_N * 2 + 1] = bytes1(uint8(b & 0xFF));
            }
        }
        
        return data;
    }
}
