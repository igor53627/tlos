// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/WeakLWEPuzzleV2.sol";

contract WeakLWEPuzzleV2Test is Test {
    WeakLWEPuzzleV2 public puzzle;
    
    function setUp() public {
        puzzle = new WeakLWEPuzzleV2();
    }
    
    function testPlantedSecretIsTernary() public view {
        bytes32 x = keccak256("test input");
        int8[40] memory secret = puzzle.getPlantedSecret(x);
        
        for (uint256 i = 0; i < 40; i++) {
            assertTrue(secret[i] >= -1 && secret[i] <= 1, "Secret must be ternary");
        }
    }
    
    function testPlantedSecretIsValid() public view {
        bytes32 x = keccak256("test planted secret");
        int8[40] memory secret = puzzle.getPlantedSecret(x);
        
        (bool valid, bytes32 sHash) = puzzle.verifyPuzzle(x, secret);
        
        assertTrue(valid, "Planted secret should always be valid");
        assertTrue(sHash != bytes32(0), "Should return non-zero hash");
    }
    
    function testMultipleInputsAllSolvable() public view {
        for (uint256 i = 0; i < 10; i++) {
            bytes32 x = keccak256(abi.encodePacked("input", i));
            int8[40] memory secret = puzzle.getPlantedSecret(x);
            
            (bool valid, ) = puzzle.verifyPuzzle(x, secret);
            assertTrue(valid, "Every input should be solvable");
        }
    }
    
    function testWrongSecretRejected() public view {
        bytes32 x = keccak256("test wrong secret");
        int8[40] memory wrongSecret;
        
        // All zeros - unlikely to be correct
        (bool valid, ) = puzzle.verifyPuzzle(x, wrongSecret);
        assertFalse(valid, "Wrong secret should be rejected");
    }
    
    function testDifferentInputsDifferentSecrets() public view {
        bytes32 x1 = keccak256("input 1");
        bytes32 x2 = keccak256("input 2");
        
        int8[40] memory secret1 = puzzle.getPlantedSecret(x1);
        int8[40] memory secret2 = puzzle.getPlantedSecret(x2);
        
        bool different = false;
        for (uint256 i = 0; i < 40; i++) {
            if (secret1[i] != secret2[i]) {
                different = true;
                break;
            }
        }
        assertTrue(different, "Different inputs should have different secrets");
    }
    
    function testCrossInputSecretRejected() public view {
        bytes32 x1 = keccak256("input 1");
        bytes32 x2 = keccak256("input 2");
        
        int8[40] memory secret1 = puzzle.getPlantedSecret(x1);
        
        // Try to use secret1 for x2
        (bool valid, ) = puzzle.verifyPuzzle(x2, secret1);
        assertFalse(valid, "Secret from one input should not work for another");
    }
    
    function testErrorNormReasonable() public view {
        bytes32 x = keccak256("error norm test");
        uint256 normSq = puzzle.getExpectedErrorNorm(x);
        
        // E[||e||²] ≈ m * E[e²] = 60 * 2 = 120
        // Should be roughly in range [50, 200] with high probability
        console.log("Error norm squared:", normSq);
        assertTrue(normSq < 300, "Error norm should be below threshold");
    }
    
    function testGasEstimate() public {
        bytes32 x = keccak256("gas test");
        int8[40] memory secret = puzzle.getPlantedSecret(x);
        
        uint256 gasBefore = gasleft();
        puzzle.verifyPuzzle(x, secret);
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Gas used for puzzle verification:", gasUsed);
        
        // V2 uses n=40, m=60 which is ~2.8M gas. Use V5 (n=32, m=48) for lower gas.
        assertTrue(gasUsed < 3_000_000, "Verification should be under 3M gas");
    }
    
    function testNonTernaryRejected() public view {
        bytes32 x = keccak256("test");
        int8[40] memory badSolution;
        badSolution[0] = 2; // Invalid
        
        (bool valid, ) = puzzle.verifyPuzzle(x, badSolution);
        assertFalse(valid, "Non-ternary should be rejected");
    }
}
