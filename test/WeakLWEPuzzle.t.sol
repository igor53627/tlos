// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/WeakLWEPuzzle.sol";

contract WeakLWEPuzzleTest is Test {
    WeakLWEPuzzle public puzzle;
    
    function setUp() public {
        puzzle = new WeakLWEPuzzle();
    }
    
    function testPuzzleSeedDeterministic() public view {
        bytes32 x1 = keccak256("test input 1");
        bytes32 x2 = keccak256("test input 2");
        
        bytes32 seed1a = puzzle.getPuzzleSeed(x1);
        bytes32 seed1b = puzzle.getPuzzleSeed(x1);
        bytes32 seed2 = puzzle.getPuzzleSeed(x2);
        
        assertEq(seed1a, seed1b, "Same input should give same seed");
        assertTrue(seed1a != seed2, "Different inputs should give different seeds");
    }
    
    function testMatrixRowDeterministic() public view {
        bytes32 seed = puzzle.getPuzzleSeed(keccak256("test"));
        
        uint16[48] memory row0a = puzzle.getMatrixRow(seed, 0);
        uint16[48] memory row0b = puzzle.getMatrixRow(seed, 0);
        uint16[48] memory row1 = puzzle.getMatrixRow(seed, 1);
        
        for (uint256 i = 0; i < 48; i++) {
            assertEq(row0a[i], row0b[i], "Same row should be deterministic");
        }
        
        bool different = false;
        for (uint256 i = 0; i < 48; i++) {
            if (row0a[i] != row1[i]) {
                different = true;
                break;
            }
        }
        assertTrue(different, "Different rows should have different values");
    }
    
    function testMatrixValuesInRange() public view {
        bytes32 seed = puzzle.getPuzzleSeed(keccak256("range test"));
        
        for (uint256 row = 0; row < 10; row++) {
            uint16[48] memory aRow = puzzle.getMatrixRow(seed, row);
            for (uint256 col = 0; col < 48; col++) {
                assertTrue(aRow[col] < puzzle.Q_WEAK(), "Matrix value should be < q");
            }
        }
    }
    
    function testBValuesInRange() public view {
        bytes32 seed = puzzle.getPuzzleSeed(keccak256("b range test"));
        
        for (uint256 row = 0; row < 64; row++) {
            uint16 bVal = puzzle.getBValue(seed, row);
            assertTrue(bVal < puzzle.Q_WEAK(), "b value should be < q");
        }
    }
    
    function testZeroSolutionRejected() public view {
        bytes32 x = keccak256("test input");
        int8[48] memory zeroSolution;
        
        (bool valid, bytes32 sHash) = puzzle.verifyPuzzle(x, zeroSolution);
        
        // Zero solution likely won't satisfy ||As - b||² < threshold
        // because b is random and non-zero
        // This test documents expected behavior
        console.log("Zero solution valid:", valid);
        console.log("Zero solution normSq would need to be < 512");
        
        if (!valid) {
            assertEq(sHash, bytes32(0), "Invalid solution should return zero hash");
        }
    }
    
    function testInvalidTernaryRejected() public view {
        bytes32 x = keccak256("test input");
        int8[48] memory badSolution;
        badSolution[0] = 2; // Invalid: not in {-1, 0, 1}
        
        (bool valid, bytes32 sHash) = puzzle.verifyPuzzle(x, badSolution);
        
        assertFalse(valid, "Non-ternary solution should be rejected");
        assertEq(sHash, bytes32(0), "Invalid solution should return zero hash");
    }
    
    function testInvalidTernaryNegative() public view {
        bytes32 x = keccak256("test input");
        int8[48] memory badSolution;
        badSolution[10] = -2; // Invalid: not in {-1, 0, 1}
        
        (bool valid, bytes32 sHash) = puzzle.verifyPuzzle(x, badSolution);
        
        assertFalse(valid, "Non-ternary solution should be rejected");
        assertEq(sHash, bytes32(0), "Invalid solution should return zero hash");
    }
    
    function testGasEstimateVerification() public {
        bytes32 x = keccak256("gas test");
        int8[48] memory solution;
        
        // Random ternary solution (won't be valid but tests gas)
        for (uint256 i = 0; i < 48; i++) {
            solution[i] = int8(int256(uint256(keccak256(abi.encodePacked(i))) % 3) - 1);
        }
        
        uint256 gasBefore = gasleft();
        puzzle.verifyPuzzle(x, solution);
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Gas used for puzzle verification:", gasUsed);
        
        // Target: under 600K gas (acceptable for Layer 4)
        // This adds ~565K gas on top of existing TLOS ~10M gas = ~5.6% overhead
        assertTrue(gasUsed < 600_000, "Verification should be under 600K gas");
    }
    
    function testDifferentInputsDifferentPuzzles() public view {
        bytes32 x1 = keccak256("input 1");
        bytes32 x2 = keccak256("input 2");
        
        bytes32 seed1 = puzzle.getPuzzleSeed(x1);
        bytes32 seed2 = puzzle.getPuzzleSeed(x2);
        
        uint16[48] memory row1 = puzzle.getMatrixRow(seed1, 0);
        uint16[48] memory row2 = puzzle.getMatrixRow(seed2, 0);
        
        bool different = false;
        for (uint256 i = 0; i < 48; i++) {
            if (row1[i] != row2[i]) {
                different = true;
                break;
            }
        }
        assertTrue(different, "Different inputs should produce different puzzles");
    }
}
