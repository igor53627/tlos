// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";
import "../contracts/TLOSSeedA.sol";

/// @title Benchmark TLOSSeedA with seed-derived `a` vectors
/// @notice Tests n=768 with 256 gates - now fits in single SSTORE2!
contract BenchmarkTLOSSeedA is Script {
    uint256 constant Q = 65521;
    address deployer = 0x05c84d05844bAc8bA8C535C3110ea3CFBA424bE9;
    
    function run() external {
        vm.startBroadcast(deployer);
        
        console.log("=== TLOSSeedA Gas Benchmark (Seed-derived A vectors) ===");
        console.log("Block gas limit: 60,000,000");
        console.log("");
        console.log("Storage optimization: 11 bytes/gate vs 6155 bytes/gate");
        console.log("");
        
        // Test configurations
        _benchmarkConfig(768, 64);   // Conservative
        _benchmarkConfig(768, 128);  // Balanced
        _benchmarkConfig(768, 256);  // Full security
        
        vm.stopBroadcast();
    }
    
    function _benchmarkConfig(uint256 n, uint32 numGates) internal {
        console.log("==============================================");
        console.log("Testing n =", n, "gates =", numGates);
        console.log("==============================================");
        
        // New format: 11 bytes per gate (3 wire indices + 4 * 2 bytes b values)
        uint256 gateSize = 11;
        uint256 dataSize = numGates * gateSize;
        
        console.log("Circuit data size:", dataSize, "bytes");
        console.log("Old format would be:", numGates * (3 + 4 * (n * 2 + 2)), "bytes");
        console.log("Savings: ", (numGates * (3 + 4 * (n * 2 + 2)) - dataSize) * 100 / (numGates * (3 + 4 * (n * 2 + 2))), "%");
        
        bytes memory circuitData = _generateCompactData(numGates);
        
        address dataPtr = SSTORE2.write(circuitData);
        console.log("Data stored at:", dataPtr);
        
        bytes32 testInput = bytes32(uint256(0x12345));
        bytes32 circuitSeed = keccak256(abi.encodePacked("TLOS-SeedA-Test"));
        bytes32 expectedOutputHash = keccak256(abi.encodePacked(uint256(testInput) & ((1 << 64) - 1)));
        uint256[4] memory expectedBindingOutput;
        
        TLOSSeedA honeypot;
        try new TLOSSeedA(
            dataPtr,
            64,
            numGates,
            expectedOutputHash,
            circuitSeed,
            expectedBindingOutput,
            block.timestamp + 1 days,
            n
        ) returns (TLOSSeedA h) {
            honeypot = h;
        } catch {
            console.log("[FAIL] Deployment failed");
            console.log("");
            return;
        }
        
        console.log("Deployed at:", address(honeypot));
        
        uint256 gasBefore = gasleft();
        try honeypot.check(testInput) returns (bool) {
            uint256 gasUsed = gasBefore - gasleft();
            console.log("check() gas:", gasUsed);
            console.log("% of 60M:", gasUsed * 100 / 60_000_000, "%");
            
            if (gasUsed > 60_000_000) {
                console.log("[FAIL] Exceeds block gas limit!");
            } else {
                console.log("[OK] Within 60M block gas limit");
            }
            
            // Security estimates for n=768
            uint256 samples = numGates * 4;
            console.log("LWE samples (m):", samples);
            if (numGates <= 64) console.log("Security: ~140+ bits");
            else if (numGates <= 128) console.log("Security: ~130+ bits");
            else if (numGates <= 256) console.log("Security: ~120+ bits");
            else console.log("Security: ~115+ bits");
            
        } catch {
            console.log("[FAIL] check() reverted - out of gas or error");
        }
        
        console.log("");
    }
    
    /// @dev Generate compact circuit data: 11 bytes per gate
    /// Format: [active:1][c1:1][c2:1][b0:2][b1:2][b2:2][b3:2]
    function _generateCompactData(uint32 numGates) internal pure returns (bytes memory) {
        bytes memory data = new bytes(numGates * 11);
        
        for (uint32 g = 0; g < numGates; g++) {
            uint256 baseOffset = g * 11;
            
            // Wire indices (same as before)
            data[baseOffset] = bytes1(uint8((g * 3) % 64));      // active
            data[baseOffset + 1] = bytes1(uint8((g * 5 + 1) % 64)); // c1
            data[baseOffset + 2] = bytes1(uint8((g * 7 + 2) % 64)); // c2
            
            // b values for 4 truth table entries
            for (uint256 tt = 0; tt < 4; tt++) {
                bool expectedBit = ((g + tt) % 2) == 1;
                uint16 b = expectedBit ? uint16(Q / 2) : 0;
                uint256 bOffset = baseOffset + 3 + tt * 2;
                data[bOffset] = bytes1(uint8(b >> 8));
                data[bOffset + 1] = bytes1(uint8(b & 0xFF));
            }
        }
        
        return data;
    }
}
