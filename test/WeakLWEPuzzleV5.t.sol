// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/WeakLWEPuzzleV5.sol";

contract WeakLWEPuzzleV5Test is Test {
    WeakLWEPuzzleV5 public puzzle;
    
    function setUp() public {
        puzzle = new WeakLWEPuzzleV5();
    }
    
    function testPlantedSecretIsTernary() public view {
        bytes32 x = keccak256("test input");
        int8[32] memory secret = puzzle.getPlantedSecret(x);
        
        for (uint256 i = 0; i < 32; i++) {
            assertTrue(secret[i] >= -1 && secret[i] <= 1, "Secret must be ternary");
        }
    }
    
    function testPlantedSecretIsValid() public view {
        bytes32 x = keccak256("test planted secret");
        int8[32] memory secret = puzzle.getPlantedSecret(x);
        
        (bool valid, bytes32 sHash) = puzzle.verifyPuzzle(x, secret);
        
        assertTrue(valid, "Planted secret should always be valid");
        assertTrue(sHash != bytes32(0), "Should return non-zero hash");
    }
    
    function testGasEstimate() public {
        bytes32 x = keccak256("gas test");
        int8[32] memory secret = puzzle.getPlantedSecret(x);
        
        uint256 gasBefore = gasleft();
        puzzle.verifyPuzzle(x, secret);
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("V5 Gas used (n=32, m=48):", gasUsed);
        
        // Target: under 600K gas (n=32 provides 2^50 search space)
        assertTrue(gasUsed < 600_000, "Verification should be under 600K gas");
    }
    
    function testMultipleInputsAllSolvable() public view {
        for (uint256 i = 0; i < 10; i++) {
            bytes32 x = keccak256(abi.encodePacked("input", i));
            int8[32] memory secret = puzzle.getPlantedSecret(x);
            
            (bool valid, ) = puzzle.verifyPuzzle(x, secret);
            assertTrue(valid, "Every input should be solvable");
        }
    }
    
    function testWrongSecretRejected() public view {
        bytes32 x = keccak256("test wrong secret");
        int8[32] memory wrongSecret;
        
        (bool valid, ) = puzzle.verifyPuzzle(x, wrongSecret);
        assertFalse(valid, "Wrong secret should be rejected");
    }
    
    function testNonTernaryRejected() public view {
        bytes32 x = keccak256("test");
        int8[32] memory badSolution;
        badSolution[0] = 2;
        
        (bool valid, ) = puzzle.verifyPuzzle(x, badSolution);
        assertFalse(valid, "Non-ternary should be rejected");
    }
    
    function testCrossInputSecretRejected() public view {
        bytes32 x1 = keccak256("input 1");
        bytes32 x2 = keccak256("input 2");
        
        int8[32] memory secret1 = puzzle.getPlantedSecret(x1);
        
        (bool valid, ) = puzzle.verifyPuzzle(x2, secret1);
        assertFalse(valid, "Secret from one input should not work for another");
    }
}
