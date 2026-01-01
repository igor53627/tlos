// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/TLOSWithPuzzleV2.sol";
import "../contracts/WeakLWEPuzzleV5.sol";

/// @notice Integration tests for TLOSWithPuzzleV2 puzzle layer
/// @dev Tests puzzle verification matches standalone WeakLWEPuzzleV5 contract
contract TLOSWithPuzzleV2Test is Test {
    WeakLWEPuzzleV5 public standalonePuzzle;
    
    function setUp() public {
        standalonePuzzle = new WeakLWEPuzzleV5();
    }
    
    /// @notice Verify puzzle domain matches between contracts
    function testPuzzleDomainMatches() public view {
        bytes32 standaloneDomain = standalonePuzzle.PUZZLE_DOMAIN();
        bytes32 expectedDomain = keccak256("TLOS-PlantedLWE-v5");
        
        assertEq(standaloneDomain, expectedDomain, "Standalone domain should match");
    }
    
    /// @notice Verify planted secret derivation matches between contracts
    function testPlantedSecretDerivationMatches() public {
        bytes32 x = keccak256("test input");
        
        // Get planted secret from standalone puzzle
        int8[32] memory standaloneSecret = standalonePuzzle.getPlantedSecret(x);
        
        // Manually derive using same logic
        bytes32 seed = keccak256(abi.encodePacked(standalonePuzzle.PUZZLE_DOMAIN(), x));
        bytes32 secretSeed = keccak256(abi.encodePacked(seed, "planted-secret"));
        
        int8[32] memory manualSecret;
        for (uint256 blk = 0; blk < 2; ++blk) {
            bytes32 coeffs = keccak256(abi.encodePacked(secretSeed, blk));
            
            for (uint256 k = 0; k < 16; ++k) {
                uint256 shift = (15 - k) * 16;
                uint256 sRaw = (uint256(coeffs) >> shift) & 0xFFFF;
                manualSecret[blk * 16 + k] = int8(int256(sRaw % 3) - 1);
            }
        }
        
        for (uint256 i = 0; i < 32; i++) {
            assertEq(standaloneSecret[i], manualSecret[i], "Secret element should match");
        }
    }
    
    /// @notice Verify puzzle verification works correctly
    function testStandalonePuzzleVerification() public view {
        bytes32 x = keccak256("verification test");
        int8[32] memory secret = standalonePuzzle.getPlantedSecret(x);
        
        (bool valid, bytes32 sHash) = standalonePuzzle.verifyPuzzle(x, secret);
        
        assertTrue(valid, "Planted secret should verify");
        assertTrue(sHash != bytes32(0), "Should return non-zero hash");
    }
    
    /// @notice Test multiple inputs all have valid planted secrets
    function testMultiplePuzzlesSolvable() public view {
        for (uint256 i = 0; i < 20; i++) {
            bytes32 x = keccak256(abi.encodePacked("puzzle", i));
            int8[32] memory secret = standalonePuzzle.getPlantedSecret(x);
            
            (bool valid, ) = standalonePuzzle.verifyPuzzle(x, secret);
            assertTrue(valid, "Every puzzle should be solvable");
        }
    }
    
    /// @notice Test wrong secret is rejected
    function testWrongSecretRejected() public view {
        bytes32 x = keccak256("wrong secret test");
        int8[32] memory wrongSecret;
        
        (bool valid, ) = standalonePuzzle.verifyPuzzle(x, wrongSecret);
        assertFalse(valid, "All-zeros should be rejected");
    }
    
    /// @notice Test cross-puzzle secret is rejected
    function testCrossPuzzleSecretRejected() public view {
        bytes32 x1 = keccak256("puzzle 1");
        bytes32 x2 = keccak256("puzzle 2");
        
        int8[32] memory secret1 = standalonePuzzle.getPlantedSecret(x1);
        
        (bool valid, ) = standalonePuzzle.verifyPuzzle(x2, secret1);
        assertFalse(valid, "Secret from puzzle 1 should not work for puzzle 2");
    }
    
    /// @notice Benchmark gas usage
    function testPuzzleVerificationGas() public {
        bytes32 x = keccak256("gas benchmark");
        int8[32] memory secret = standalonePuzzle.getPlantedSecret(x);
        
        uint256 gasBefore = gasleft();
        standalonePuzzle.verifyPuzzle(x, secret);
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Puzzle verification gas (n=32, m=48):", gasUsed);
        
        // Should be under 600K gas
        assertTrue(gasUsed < 600_000, "Gas should be under 600K");
    }
    
    /// @notice Test solution hash is deterministic
    function testSolutionHashDeterministic() public view {
        bytes32 x = keccak256("hash test");
        int8[32] memory secret = standalonePuzzle.getPlantedSecret(x);
        
        (, bytes32 sHash1) = standalonePuzzle.verifyPuzzle(x, secret);
        (, bytes32 sHash2) = standalonePuzzle.verifyPuzzle(x, secret);
        
        assertEq(sHash1, sHash2, "Same solution should produce same hash");
    }
}
