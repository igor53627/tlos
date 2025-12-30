// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";
import "../contracts/TLOSLWE.sol";

/// @title Benchmark TLOS-LWE (Post-Quantum SEH) on Tenderly
/// @notice The only PQ variant - measures full-rank 64x64 SEH gas costs with n=128 LWE
contract BenchmarkTLOS is Script {
    uint256 constant Q = 65521;
    address deployer = 0x05c84d05844bAc8bA8C535C3110ea3CFBA424bE9;
    
    function run() external {
        vm.startBroadcast(deployer);
        
        console.log("=== TLOS-LWE Gas Benchmark (n=128 LWE, Full-rank 64x64 SEH, 640 gates) ===");
        console.log("");
        
        bytes memory circuitData = _generateData(640, 128);
        console.log("Circuit data size:", circuitData.length, "bytes");
        
        address dataPtr = SSTORE2.write(circuitData);
        console.log("Data pointer:", dataPtr);
        console.log("");
        
        console.log("--- TLOS-LWE (Full-rank SEH, ~49-bit PQ) ---");
        _benchmarkTLOSLWE(dataPtr);
        
        vm.stopBroadcast();
        
        console.log("");
        console.log("=== Summary ===");
        console.log("Block gas limit: 30,000,000");
        console.log("LWE Dimension: n=128 (~98-bit PQ security)");
        console.log("SEH Matrix: 64x64 (full-rank, trivial kernel)");
    }
    
    function _benchmarkTLOSLWE(address dataPtr) internal {
        bytes32 testInput = bytes32(uint256(0x12345));
        bytes32 circuitSeed = keccak256(abi.encodePacked("TLOS-LWE-Seed"));
        
        bytes32 expectedOutputHash = keccak256(abi.encodePacked(uint256(testInput) & ((1 << 64) - 1)));
        uint256[4] memory expectedSehOutput;
        
        TLOSLWE honeypot = new TLOSLWE(
            dataPtr,
            64,
            640,
            expectedOutputHash,
            circuitSeed,
            expectedSehOutput,
            block.timestamp + 1 days
        );
        
        console.log("Deployed at:", address(honeypot));
        console.log("Scheme:", honeypot.scheme());
        
        uint256 gasBefore = gasleft();
        try honeypot.check(testInput) returns (bool valid) {
            uint256 gasUsed = gasBefore - gasleft();
            console.log("check() gas:", gasUsed);
            console.log("% of 30M:", gasUsed * 100 / 30_000_000);
            console.log("Valid:", valid ? "true" : "false");
            
            if (gasUsed > 30_000_000) {
                console.log("[FAIL] Exceeds block gas limit!");
            } else {
                console.log("[OK] Within block gas limit");
            }
        } catch {
            console.log("[FAIL] check() reverted - likely out of gas");
            console.log("Estimated gas: >30,000,000 (exceeds block limit)");
        }
        
        // Also test checkWithSeh
        console.log("");
        console.log("--- checkWithSeh() ---");
        uint256 gasBefore2 = gasleft();
        try honeypot.checkWithSeh(testInput) returns (bool valid2, uint256[4] memory sehOutput) {
            uint256 gasUsed2 = gasBefore2 - gasleft();
            console.log("checkWithSeh() gas:", gasUsed2);
            console.log("SEH output[0]:", sehOutput[0]);
            console.log("Valid:", valid2 ? "true" : "false");
        } catch {
            console.log("[FAIL] checkWithSeh() reverted");
        }
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
