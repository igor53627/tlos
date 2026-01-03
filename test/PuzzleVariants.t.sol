// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/WeakLWEPuzzleV5.sol";
import "../contracts/WeakLWEPuzzleV6.sol";
import "../contracts/WeakLWEPuzzleV7.sol";

/// @title Puzzle Variants Test
/// @notice Tests puzzle versions V5, V6, V7 for correctness and gas benchmarking
/// @dev V7 (n=48) is production, V5/V6 are for testing with lower security
contract PuzzleVariantsTest is Test {
    WeakLWEPuzzleV5 public puzzleV5;
    WeakLWEPuzzleV6 public puzzleV6;
    WeakLWEPuzzleV7 public puzzleV7;
    
    bytes32 constant TEST_X = keccak256("test-puzzle-input");
    
    function setUp() public {
        puzzleV5 = new WeakLWEPuzzleV5();
        puzzleV6 = new WeakLWEPuzzleV6();
        puzzleV7 = new WeakLWEPuzzleV7();
    }
    
    // ========== V5 Tests (n=32, m=48, q=2039) ==========
    
    function test_V5_Parameters() public view {
        assertEq(puzzleV5.N_WEAK(), 32);
        assertEq(puzzleV5.M_WEAK(), 48);
        assertEq(puzzleV5.Q_WEAK(), 2039);
        assertEq(puzzleV5.THRESHOLD_SQ(), 200);
    }
    
    function test_V5_PlantedSecretValid() public {
        int8[32] memory secret = puzzleV5.getPlantedSecret(TEST_X);
        _assertTernary32(secret);
        
        uint256 gasBefore = gasleft();
        (bool valid,) = puzzleV5.verifyPuzzle(TEST_X, secret);
        uint256 gasUsed = gasBefore - gasleft();
        
        assertTrue(valid, "V5: Planted secret should be valid");
        emit log_named_uint("V5 (n=32, m=48) gas", gasUsed);
    }
    
    function test_V5_RandomSecretInvalid() public view {
        int8[32] memory randomSecret = _randomTernary32(3);
        (bool valid,) = puzzleV5.verifyPuzzle(TEST_X, randomSecret);
        assertFalse(valid, "V5: Random secret should be invalid");
    }
    
    // ========== V6 Tests (n=24, m=36, q=2039) ==========
    
    function test_V6_Parameters() public view {
        assertEq(puzzleV6.N_WEAK(), 24);
        assertEq(puzzleV6.M_WEAK(), 36);
        assertEq(puzzleV6.Q_WEAK(), 2039);
        assertEq(puzzleV6.THRESHOLD_SQ(), 150);
    }
    
    function test_V6_PlantedSecretValid() public {
        int8[24] memory secret = puzzleV6.getPlantedSecret(TEST_X);
        _assertTernary24(secret);
        
        uint256 gasBefore = gasleft();
        (bool valid,) = puzzleV6.verifyPuzzle(TEST_X, secret);
        uint256 gasUsed = gasBefore - gasleft();
        
        assertTrue(valid, "V6: Planted secret should be valid");
        emit log_named_uint("V6 (n=24, m=36) gas", gasUsed);
    }
    
    function test_V6_RandomSecretInvalid() public view {
        int8[24] memory randomSecret = _randomTernary24(4);
        (bool valid,) = puzzleV6.verifyPuzzle(TEST_X, randomSecret);
        assertFalse(valid, "V6: Random secret should be invalid");
    }
    
    // ========== V7 Tests (n=48, m=72, q=2039) - Production ==========
    
    function test_V7_Parameters() public view {
        assertEq(puzzleV7.N_WEAK(), 48);
        assertEq(puzzleV7.M_WEAK(), 72);
        assertEq(puzzleV7.Q_WEAK(), 2039);
        assertEq(puzzleV7.THRESHOLD_SQ(), 300);
    }
    
    function test_V7_PlantedSecretValid() public {
        int8[48] memory secret = puzzleV7.getPlantedSecret(TEST_X);
        _assertTernary48(secret);
        
        uint256 gasBefore = gasleft();
        (bool valid,) = puzzleV7.verifyPuzzle(TEST_X, secret);
        uint256 gasUsed = gasBefore - gasleft();
        
        assertTrue(valid, "V7: Planted secret should be valid");
        emit log_named_uint("V7 (n=48, m=72) gas", gasUsed);
    }
    
    function test_V7_RandomSecretInvalid() public view {
        int8[48] memory randomSecret = _randomTernary48(5);
        (bool valid,) = puzzleV7.verifyPuzzle(TEST_X, randomSecret);
        assertFalse(valid, "V7: Random secret should be invalid");
    }
    
    function test_V7_AllZerosInvalid() public view {
        int8[48] memory zeroSecret;
        (bool valid,) = puzzleV7.verifyPuzzle(TEST_X, zeroSecret);
        assertFalse(valid, "V7: All-zeros secret should be invalid");
    }
    
    function test_V7_NonTernaryRejected() public view {
        int8[48] memory badSecret;
        badSecret[0] = 2;
        (bool valid,) = puzzleV7.verifyPuzzle(TEST_X, badSecret);
        assertFalse(valid, "V7: Non-ternary secret should be rejected");
    }
    
    // ========== Comparative Benchmarks ==========
    
    function test_AllVersions_GasBenchmark() public {
        emit log("=== Puzzle Variants Gas Benchmark ===");
        
        // V6 (n=24, ~2^38 security)
        {
            int8[24] memory s6 = puzzleV6.getPlantedSecret(TEST_X);
            uint256 g = gasleft();
            puzzleV6.verifyPuzzle(TEST_X, s6);
            emit log_named_uint("V6 (n=24, 2^38 security) gas", g - gasleft());
        }
        
        // V5 (n=32, ~2^51 security)
        {
            int8[32] memory s5 = puzzleV5.getPlantedSecret(TEST_X);
            uint256 g = gasleft();
            puzzleV5.verifyPuzzle(TEST_X, s5);
            emit log_named_uint("V5 (n=32, 2^51 security) gas", g - gasleft());
        }
        
        // V7 (n=48, ~2^76 security) - PRODUCTION
        {
            int8[48] memory s7 = puzzleV7.getPlantedSecret(TEST_X);
            uint256 g = gasleft();
            puzzleV7.verifyPuzzle(TEST_X, s7);
            emit log_named_uint("V7 (n=48, 2^76 security) gas", g - gasleft());
        }
    }
    
    function test_SecurityLevels() public pure {
        // V6: 3^24 = 2^38.03
        // V5: 3^32 = 2^50.72
        // V7: 3^48 = 2^76.08
        
        uint256 v6_bits = 38;
        uint256 v5_bits = 51;
        uint256 v7_bits = 76;
        
        assert(v6_bits < v5_bits);
        assert(v5_bits < v7_bits);
    }
    
    // ========== Helper Functions ==========
    
    function _assertTernary24(int8[24] memory s) internal pure {
        for (uint256 i = 0; i < 24; i++) {
            require(s[i] >= -1 && s[i] <= 1, "Not ternary");
        }
    }
    
    function _assertTernary32(int8[32] memory s) internal pure {
        for (uint256 i = 0; i < 32; i++) {
            require(s[i] >= -1 && s[i] <= 1, "Not ternary");
        }
    }
    
    function _assertTernary48(int8[48] memory s) internal pure {
        for (uint256 i = 0; i < 48; i++) {
            require(s[i] >= -1 && s[i] <= 1, "Not ternary");
        }
    }
    
    function _randomTernary24(uint256 seed) internal pure returns (int8[24] memory s) {
        for (uint256 i = 0; i < 24; i++) {
            s[i] = int8(int256(uint256(keccak256(abi.encodePacked(seed, i))) % 3) - 1);
        }
    }
    
    function _randomTernary32(uint256 seed) internal pure returns (int8[32] memory s) {
        for (uint256 i = 0; i < 32; i++) {
            s[i] = int8(int256(uint256(keccak256(abi.encodePacked(seed, i))) % 3) - 1);
        }
    }
    
    function _randomTernary48(uint256 seed) internal pure returns (int8[48] memory s) {
        for (uint256 i = 0; i < 48; i++) {
            s[i] = int8(int256(uint256(keccak256(abi.encodePacked(seed, i))) % 3) - 1);
        }
    }
}
