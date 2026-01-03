// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../contracts/TLOSWithPuzzleV4.sol";

/// @title TLOSWithPuzzleV4Harness - Test harness exposing internal functions
/// @notice For testing only - exposes internal functions for unit testing
/// @dev DO NOT DEPLOY TO PRODUCTION
contract TLOSWithPuzzleV4Harness is TLOSWithPuzzleV4 {
    constructor(
        address _circuitDataPointer,
        uint8 _numWires,
        uint32 _numGates,
        bytes32 _expectedOutputHash,
        bytes32 _circuitSeed,
        uint256[4] memory _expectedBindingOutput,
        uint256 _secretExpiry,
        bytes32 _puzzleSeed,
        address _puzzleBPointer
    ) payable TLOSWithPuzzleV4(
        _circuitDataPointer,
        _numWires,
        _numGates,
        _expectedOutputHash,
        _circuitSeed,
        _expectedBindingOutput,
        _secretExpiry,
        _puzzleSeed,
        _puzzleBPointer
    ) {}

    /// @notice Expose _verifyPuzzle for isolated Layer-4 testing
    function verifyPuzzlePublic(int8[48] calldata solution) 
        external 
        view 
        returns (bool valid, bytes32 sHash, uint256 normSq) 
    {
        return _verifyPuzzle(solution);
    }

    /// @notice Expose _wireBindingHash for isolated Layer-3 testing
    function wireBindingHashPublic(uint256 input, uint256 gateIdx) 
        external 
        view 
        returns (uint256[4] memory) 
    {
        return _wireBindingHash(input, gateIdx);
    }

    /// @notice Expose _evaluate for testing circuit + binding logic
    function evaluatePublic(bytes32 input, bytes32 puzzleSolutionHash) 
        external 
        view 
        returns (bool valid, uint256[4] memory bindingOutput) 
    {
        return _evaluate(input, puzzleSolutionHash);
    }

    /// @notice Expose _deriveSecret384Array for testing secret derivation
    function deriveSecret384ArrayPublic(bytes32 input, bytes32 puzzleSolutionHash) 
        external 
        pure 
        returns (uint256[24] memory) 
    {
        return _deriveSecret384Array(input, puzzleSolutionHash);
    }

    /// @notice Force claim for testing - bypasses puzzle/circuit checks
    /// @dev Only for testing happy-path claim logic
    /// Storage layout: _reward at slot 0, _claimed at slot 1 (immutables don't use slots)
    function testOnlyForceClaim(address solver) external {
        require(!_isClaimedInternal(), "Already claimed");
        _setClaimedInternal();
        uint256 rewardAmount = _getRewardInternal();
        _setRewardInternal(0);
        (bool success, ) = solver.call{value: rewardAmount}("");
        require(success, "Transfer failed");
    }

    // Internal state accessors for testing
    // Note: immutable variables don't take storage slots
    // _reward is slot 0, _claimed is slot 1
    function _isClaimedInternal() internal view returns (bool) {
        bool claimed;
        assembly {
            claimed := sload(1)
        }
        return claimed;
    }

    function _setClaimedInternal() internal {
        assembly {
            sstore(1, 1)
        }
    }

    function _getRewardInternal() internal view returns (uint256) {
        uint256 reward;
        assembly {
            reward := sload(0)
        }
        return reward;
    }

    function _setRewardInternal(uint256 value) internal {
        assembly {
            sstore(0, value)
        }
    }
}
