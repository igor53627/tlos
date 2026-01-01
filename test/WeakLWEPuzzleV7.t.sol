// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../contracts/WeakLWEPuzzleV7.sol";
contract V7GasTest is Test {
    WeakLWEPuzzleV7 public puzzle;
    function setUp() public { puzzle = new WeakLWEPuzzleV7(); }
    function testGasV7() public {
        bytes32 x = keccak256("gas");
        int8[48] memory s = puzzle.getPlantedSecret(x);
        uint256 g = gasleft();
        (bool v,) = puzzle.verifyPuzzle(x, s);
        console.log("V7 Gas (n=48, m=72):", g - gasleft());
        assertTrue(v);
    }
}
