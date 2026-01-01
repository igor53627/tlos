// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";
import "../contracts/TLOSWithPuzzleV3.sol";

contract TLOSWithPuzzleV3Test is Test {
    uint256 constant Q = 65521;
    uint256 constant LBLO_N = 384;
    
    function setUp() public {}
    
    function test_GasBenchmark_64Gates() public {
        _benchmarkGates(64);
    }
    
    function test_GasBenchmark_128Gates() public {
        _benchmarkGates(128);
    }
    
    function test_GasBenchmark_256Gates() public {
        _benchmarkGates(256);
    }
    
    function _benchmarkGates(uint32 numGates) internal {
        bytes memory circuitData = _generateData(numGates);
        address dataPtr = SSTORE2.write(circuitData);
        
        bytes32 testInput = bytes32(uint256(0x12345));
        bytes32 circuitSeed = keccak256(abi.encodePacked("TLOS-V3-Seed"));
        bytes32 expectedOutputHash = keccak256(abi.encodePacked(uint256(testInput) & ((1 << 64) - 1)));
        uint256[4] memory expectedBindingOutput;
        
        TLOSWithPuzzleV3 honeypot = new TLOSWithPuzzleV3(
            dataPtr,
            64,
            numGates,
            expectedOutputHash,
            circuitSeed,
            expectedBindingOutput,
            block.timestamp + 1 days
        );
        
        // Generate valid puzzle solution (planted secret)
        int8[48] memory puzzleSolution = honeypot.getPlantedSecret(testInput);
        
        uint256 gasBefore = gasleft();
        bool valid = honeypot.checkWithPuzzle(testInput, puzzleSolution);
        uint256 gasUsed = gasBefore - gasleft();
        
        emit log_named_uint("Gates", numGates);
        emit log_named_uint("Circuit data (bytes)", circuitData.length);
        emit log_named_uint("Gas used", gasUsed);
        emit log_named_uint("% of 60M block", gasUsed * 100 / 60_000_000);
        emit log_named_string("Valid", valid ? "true" : "false (expected - test data)");
    }
    
    function _generateData(uint32 numGates) internal pure returns (bytes memory) {
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
