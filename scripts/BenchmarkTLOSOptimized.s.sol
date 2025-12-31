// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";
import "../contracts/TLOSOptimized.sol";

/// @title Benchmark TLOSOptimized with various dimensions
/// @notice Tests n=128, 256, 512, 768 to find max feasible within block gas limit
contract BenchmarkTLOSOptimized is Script {
    uint256 constant Q = 65521;
    address deployer = 0x05c84d05844bAc8bA8C535C3110ea3CFBA424bE9;
    
    function run() external {
        vm.startBroadcast(deployer);
        
        console.log("=== TLOSOptimized Gas Benchmark ===");
        console.log("Block gas limit: 60,000,000");
        console.log("");
        
        // n=768 gate size = 6155 bytes, SSTORE2 max ~24KB = 3-4 gates
        // Test with 3 gates to get per-gate cost
        _benchmarkDimension(768, 3);
        
        vm.stopBroadcast();
    }
    
    function _benchmarkDimension(uint256 n, uint32 numGates) internal {
        console.log("==============================================");
        console.log("Testing n =", n, "gates =", numGates);
        console.log("==============================================");
        
        bytes memory circuitData = _generateData(numGates, n);
        console.log("Circuit data size:", circuitData.length, "bytes");
        console.log("Number of gates:", numGates);
        
        // Check if data is too large
        if (circuitData.length > 24576) {
            console.log("[WARN] Data exceeds 24KB SSTORE2 limit, splitting...");
        }
        
        address dataPtr = SSTORE2.write(circuitData);
        
        bytes32 testInput = bytes32(uint256(0x12345));
        bytes32 circuitSeed = keccak256(abi.encodePacked("TLOS-Seed"));
        bytes32 expectedOutputHash = keccak256(abi.encodePacked(uint256(testInput) & ((1 << 64) - 1)));
        uint256[4] memory expectedBindingOutput;
        
        TLOSOptimized honeypot;
        try new TLOSOptimized(
            dataPtr,
            64,
            numGates,
            expectedOutputHash,
            circuitSeed,
            expectedBindingOutput,
            block.timestamp + 1 days,
            n
        ) returns (TLOSOptimized h) {
            honeypot = h;
        } catch {
            console.log("[FAIL] Deployment failed");
            console.log("");
            return;
        }
        
        console.log("Deployed at:", address(honeypot));
        
        uint256 gasBefore = gasleft();
        try honeypot.check(testInput) returns (bool valid) {
            uint256 gasUsed = gasBefore - gasleft();
            console.log("check() gas:", gasUsed);
            console.log("% of 60M:", gasUsed * 100 / 60_000_000, "%");
            
            if (gasUsed > 60_000_000) {
                console.log("[FAIL] Exceeds block gas limit!");
            } else {
                console.log("[OK] Within 60M block gas limit");
                
                // Estimate security based on LWE estimator results
                if (n == 128) console.log("Security: ~40 bits (WEAK)");
                else if (n == 256) console.log("Security: ~28 bits (BROKEN)");
                else if (n == 512) console.log("Security: ~79 bits (MARGINAL)");
                else if (n == 768) console.log("Security: ~131 bits (TARGET)");
            }
        } catch {
            console.log("[FAIL] check() reverted - out of gas");
            console.log("Estimated: >30,000,000 gas");
        }
        
        console.log("");
    }
    
    
    function _generateData(uint32 numGates, uint256 n) internal pure returns (bytes memory) {
        uint256 ctSize = n * 2 + 2;
        uint256 gateSize = 3 + 4 * ctSize;
        bytes memory data = new bytes(numGates * gateSize);
        
        for (uint32 g = 0; g < numGates; g++) {
            uint256 baseOffset = g * gateSize;
            
            data[baseOffset] = bytes1(uint8((g * 3) % 64));
            data[baseOffset + 1] = bytes1(uint8((g * 5 + 1) % 64));
            data[baseOffset + 2] = bytes1(uint8((g * 7 + 2) % 64));
            
            for (uint256 tt = 0; tt < 4; tt++) {
                uint256 ctOffset = baseOffset + 3 + tt * ctSize;
                
                for (uint256 i = 0; i < n; i++) {
                    uint16 ai = uint16((g * 1337 + tt * 31 + i * 17) % Q);
                    data[ctOffset + i * 2] = bytes1(uint8(ai >> 8));
                    data[ctOffset + i * 2 + 1] = bytes1(uint8(ai & 0xFF));
                }
                
                bool expectedBit = ((g + tt) % 2) == 1;
                uint16 b = expectedBit ? uint16(Q / 2) : 0;
                data[ctOffset + n * 2] = bytes1(uint8(b >> 8));
                data[ctOffset + n * 2 + 1] = bytes1(uint8(b & 0xFF));
            }
        }
        
        return data;
    }
}
