// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/WeakLWEPuzzleV6.sol";

contract WeakLWEPuzzleV6Test is Test {
    WeakLWEPuzzleV6 public puzzle;
    
    function setUp() public {
        puzzle = new WeakLWEPuzzleV6();
    }
    
    function testPlantedSecretIsValid() public view {
        bytes32 x = keccak256("test");
        int8[24] memory secret = puzzle.getPlantedSecret(x);
        (bool valid, ) = puzzle.verifyPuzzle(x, secret);
        assertTrue(valid, "Planted secret should be valid");
    }
    
    function testGasEstimate() public {
        bytes32 x = keccak256("gas test");
        int8[24] memory secret = puzzle.getPlantedSecret(x);
        
        uint256 gasBefore = gasleft();
        puzzle.verifyPuzzle(x, secret);
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("V6 Gas used (n=24, m=36):", gasUsed);
        assertTrue(gasUsed < 400_000, "Should be under 400K gas");
    }
    
    function testMultipleInputsAllSolvable() public view {
        for (uint256 i = 0; i < 10; i++) {
            bytes32 x = keccak256(abi.encodePacked("input", i));
            int8[24] memory secret = puzzle.getPlantedSecret(x);
            (bool valid, ) = puzzle.verifyPuzzle(x, secret);
            assertTrue(valid, "Every input should be solvable");
        }
    }
}
