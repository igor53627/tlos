// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";
import "../contracts/TLOSWithPuzzleV3.sol";

/// @title Benchmark TLOSWithPuzzleV3 (n=384 LWE with Gaussian noise)
/// @notice Measures gas costs for the fixed LWE construction
contract BenchmarkTLOSV3 is Script {
    uint256 constant Q = 65521;
    uint256 constant LWE_N = 384;
    address deployer = 0x05c84d05844bAc8bA8C535C3110ea3CFBA424bE9;
    
    function run() external {
        vm.startBroadcast(deployer);
        
        console.log("=== TLOSWithPuzzleV3 Gas Benchmark ===");
        console.log("LWE: n=384, sigma=8 (Gaussian noise)");
        console.log("Security: ~2^112 (lattice estimator)");
        console.log("");
        
        // Test different gate counts
        uint32[] memory gateCounts = new uint32[](4);
        gateCounts[0] = 64;
        gateCounts[1] = 128;
        gateCounts[2] = 256;
        gateCounts[3] = 640;
        
        for (uint256 i = 0; i < gateCounts.length; i++) {
            uint32 numGates = gateCounts[i];
            console.log("--- Gates:", numGates, "---");
            
            bytes memory circuitData = _generateData(numGates);
            console.log("Circuit data size:", circuitData.length, "bytes");
            
            address dataPtr = SSTORE2.write(circuitData);
            
            _benchmarkV3(dataPtr, numGates);
            console.log("");
        }
        
        vm.stopBroadcast();
        
        console.log("=== Summary ===");
        console.log("Block gas limit: 60,000,000");
        console.log("LWE Dimension: n=384 (standard LWE with Gaussian noise)");
        console.log("Security: ~2^112 post-quantum");
        console.log("Wire Binding: 64x64 full-rank matrix");
        console.log("Layer 4 Puzzle: n=48 planted LWE (~2^76 brute-force)");
    }
    
    function _benchmarkV3(address dataPtr, uint32 numGates) internal {
        bytes32 testInput = bytes32(uint256(0x12345));
        bytes32 circuitSeed = keccak256(abi.encodePacked("TLOS-V3-Seed"));
        
        bytes32 expectedOutputHash = keccak256(abi.encodePacked(uint256(testInput) & ((1 << 64) - 1)));
        uint256[4] memory expectedBindingOutput;
        
        TLOSWithPuzzleV3 honeypot = new TLOSWithPuzzleV3(
            dataPtr,
            64,  // numWires
            numGates,
            expectedOutputHash,
            circuitSeed,
            expectedBindingOutput,
            block.timestamp + 1 days
        );
        
        console.log("Deployed at:", address(honeypot));
        
        // Create a dummy puzzle solution (all zeros for benchmark)
        int8[48] memory puzzleSolution;
        
        uint256 gasBefore = gasleft();
        try honeypot.checkWithPuzzle(testInput, puzzleSolution) returns (bool valid) {
            uint256 gasUsed = gasBefore - gasleft();
            console.log("checkWithPuzzle() gas:", gasUsed);
            console.log("% of 60M block:", gasUsed * 100 / 60_000_000);
            console.log("Valid:", valid ? "true" : "false");
            
            if (gasUsed > 60_000_000) {
                console.log("[FAIL] Exceeds block gas limit!");
            } else {
                console.log("[OK] Within 60M block limit");
            }
        } catch Error(string memory reason) {
            uint256 gasUsed = gasBefore - gasleft();
            console.log("Reverted with:", reason);
            console.log("Gas used before revert:", gasUsed);
        } catch {
            uint256 gasUsed = gasBefore - gasleft();
            console.log("[FAIL] checkWithPuzzle() reverted (unknown)");
            console.log("Gas used before revert:", gasUsed);
        }
    }
    
    function _generateData(uint32 numGates) internal pure returns (bytes memory) {
        uint256 ctSize = LWE_N * 2 + 2;  // 770 bytes
        uint256 gateSize = 3 + 4 * ctSize;  // 3083 bytes
        bytes memory data = new bytes(numGates * gateSize);
        
        for (uint32 g = 0; g < numGates; g++) {
            uint256 baseOffset = g * gateSize;
            
            // Gate header: active, c1, c2
            data[baseOffset] = bytes1(uint8((g * 3) % 64));
            data[baseOffset + 1] = bytes1(uint8((g * 5 + 1) % 64));
            data[baseOffset + 2] = bytes1(uint8((g * 7 + 2) % 64));
            
            // 4 ciphertexts per gate
            for (uint256 tt = 0; tt < 4; tt++) {
                uint256 ctOffset = baseOffset + 3 + tt * ctSize;
                
                // a vector (384 u16 values)
                for (uint256 i = 0; i < LWE_N; i++) {
                    uint16 ai = uint16((g * 1337 + tt * 31 + i * 17) % Q);
                    data[ctOffset + i * 2] = bytes1(uint8(ai >> 8));
                    data[ctOffset + i * 2 + 1] = bytes1(uint8(ai & 0xFF));
                }
                
                // b value (with simulated noise for realistic benchmark)
                bool expectedBit = ((g + tt) % 2) == 1;
                uint16 b = expectedBit ? uint16(Q / 2) : 0;
                // Add small noise (simulating σ=8)
                b = uint16((uint256(b) + (g * tt) % 16) % Q);
                data[ctOffset + LWE_N * 2] = bytes1(uint8(b >> 8));
                data[ctOffset + LWE_N * 2 + 1] = bytes1(uint8(b & 0xFF));
            }
        }
        
        return data;
    }
}
