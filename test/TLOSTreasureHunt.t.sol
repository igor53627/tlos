// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../examples/TLOSTreasureHunt.sol";

contract TLOSTreasureHuntTest is Test {
    TLOSTreasureHunt public hunt;
    
    bytes32 constant SECRET = keccak256("treasure-secret-2024");
    bytes32 constant SECRET_HASH = keccak256(abi.encodePacked(SECRET));
    uint256 constant REWARD = 1 ether;
    uint256 constant EXPIRY_DURATION = 7 days;
    
    address owner = address(this);
    address solver = address(0xBEEF);
    address attacker = address(0xDEAD);

    function setUp() public {
        hunt = new TLOSTreasureHunt{value: REWARD}(
            SECRET_HASH,
            block.timestamp + EXPIRY_DURATION
        );
        vm.deal(solver, 10 ether);
        vm.deal(attacker, 10 ether);
    }

    function testConstructor() public view {
        assertEq(hunt.secretHash(), SECRET_HASH);
        assertEq(hunt.expiry(), block.timestamp + EXPIRY_DURATION);
        assertEq(hunt.owner(), owner);
        assertEq(hunt.reward(), REWARD);
        assertEq(hunt.claimed(), false);
        assertEq(hunt.isExpired(), false);
    }

    function testCommit() public {
        int8[48] memory puzzleSolution = hunt.getPlantedSecret(SECRET);
        bytes32 commitHash = keccak256(abi.encode(solver, SECRET, puzzleSolution));
        
        vm.prank(solver);
        hunt.commit(commitHash);
        
        (bytes32 storedHash, uint256 blockNum) = hunt.getCommit(solver);
        assertEq(storedHash, commitHash);
        assertEq(blockNum, block.number);
    }

    function testCommitAfterExpiry() public {
        vm.warp(block.timestamp + EXPIRY_DURATION + 1);
        
        bytes32 commitHash = keccak256("dummy");
        
        vm.prank(solver);
        vm.expectRevert("Hunt expired");
        hunt.commit(commitHash);
    }

    function testRevealSuccess() public {
        int8[48] memory puzzleSolution = hunt.getPlantedSecret(SECRET);
        bytes32 commitHash = keccak256(abi.encode(solver, SECRET, puzzleSolution));
        
        vm.prank(solver);
        hunt.commit(commitHash);
        
        vm.roll(block.number + hunt.COMMIT_DELAY());
        
        uint256 balanceBefore = solver.balance;
        
        vm.prank(solver);
        hunt.reveal(SECRET, puzzleSolution);
        
        assertEq(solver.balance, balanceBefore + REWARD);
        assertEq(hunt.claimed(), true);
        assertEq(hunt.reward(), 0);
    }

    function testRevealWrongSecret() public {
        bytes32 wrongSecret = keccak256("wrong-secret");
        int8[48] memory puzzleSolution = hunt.getPlantedSecret(wrongSecret);
        bytes32 commitHash = keccak256(abi.encode(solver, wrongSecret, puzzleSolution));
        
        vm.prank(solver);
        hunt.commit(commitHash);
        
        vm.roll(block.number + hunt.COMMIT_DELAY());
        
        vm.prank(solver);
        vm.expectRevert("Wrong secret");
        hunt.reveal(wrongSecret, puzzleSolution);
    }

    function testRevealWrongPuzzle() public {
        int8[48] memory wrongSolution;
        for (uint256 i = 0; i < 48; i++) {
            wrongSolution[i] = 0;
        }
        bytes32 commitHash = keccak256(abi.encode(solver, SECRET, wrongSolution));
        
        vm.prank(solver);
        hunt.commit(commitHash);
        
        vm.roll(block.number + hunt.COMMIT_DELAY());
        
        vm.prank(solver);
        vm.expectRevert("Invalid puzzle solution");
        hunt.reveal(SECRET, wrongSolution);
    }

    function testRevealTooEarly() public {
        int8[48] memory puzzleSolution = hunt.getPlantedSecret(SECRET);
        bytes32 commitHash = keccak256(abi.encode(solver, SECRET, puzzleSolution));
        
        vm.prank(solver);
        hunt.commit(commitHash);
        
        vm.prank(solver);
        vm.expectRevert("Reveal too early");
        hunt.reveal(SECRET, puzzleSolution);
    }

    function testRevealHashMismatch() public {
        int8[48] memory puzzleSolution = hunt.getPlantedSecret(SECRET);
        bytes32 commitHash = keccak256(abi.encode(solver, SECRET, puzzleSolution));
        
        vm.prank(solver);
        hunt.commit(commitHash);
        
        vm.roll(block.number + hunt.COMMIT_DELAY());
        
        bytes32 differentSecret = keccak256("different");
        int8[48] memory differentSolution = hunt.getPlantedSecret(differentSecret);
        
        vm.prank(solver);
        vm.expectRevert("Invalid reveal - hash mismatch");
        hunt.reveal(differentSecret, differentSolution);
    }

    function testReclaimExpired() public {
        vm.warp(block.timestamp + EXPIRY_DURATION);
        
        uint256 balanceBefore = owner.balance;
        
        hunt.reclaimExpired();
        
        assertEq(owner.balance, balanceBefore + REWARD);
        assertEq(hunt.claimed(), true);
        assertEq(hunt.reward(), 0);
    }

    function testReclaimBeforeExpiry() public {
        vm.expectRevert("Not expired yet");
        hunt.reclaimExpired();
    }

    function testReclaimNotOwner() public {
        vm.warp(block.timestamp + EXPIRY_DURATION);
        
        vm.prank(attacker);
        vm.expectRevert("Only owner");
        hunt.reclaimExpired();
    }

    function testDoubleReveal() public {
        int8[48] memory puzzleSolution = hunt.getPlantedSecret(SECRET);
        bytes32 commitHash = keccak256(abi.encode(solver, SECRET, puzzleSolution));
        
        vm.prank(solver);
        hunt.commit(commitHash);
        
        vm.roll(block.number + hunt.COMMIT_DELAY());
        
        vm.prank(solver);
        hunt.reveal(SECRET, puzzleSolution);
        
        assertEq(hunt.claimed(), true);
        
        vm.prank(solver);
        vm.expectRevert("Already claimed");
        hunt.commit(commitHash);
    }

    function testCommitAfterClaimed() public {
        int8[48] memory puzzleSolution = hunt.getPlantedSecret(SECRET);
        bytes32 commitHash = keccak256(abi.encode(solver, SECRET, puzzleSolution));
        
        vm.prank(solver);
        hunt.commit(commitHash);
        vm.roll(block.number + hunt.COMMIT_DELAY());
        vm.prank(solver);
        hunt.reveal(SECRET, puzzleSolution);
        
        vm.prank(attacker);
        vm.expectRevert("Already claimed");
        hunt.commit(keccak256("attacker"));
    }

    function testNoCommitFound() public {
        int8[48] memory puzzleSolution = hunt.getPlantedSecret(SECRET);
        
        vm.roll(block.number + hunt.COMMIT_DELAY());
        
        vm.prank(solver);
        vm.expectRevert("No commit found");
        hunt.reveal(SECRET, puzzleSolution);
    }

    function testGasMeasurement() public {
        int8[48] memory puzzleSolution = hunt.getPlantedSecret(SECRET);
        bytes32 commitHash = keccak256(abi.encode(solver, SECRET, puzzleSolution));
        
        vm.prank(solver);
        hunt.commit(commitHash);
        
        vm.roll(block.number + hunt.COMMIT_DELAY());
        
        uint256 gasBefore = gasleft();
        vm.prank(solver);
        hunt.reveal(SECRET, puzzleSolution);
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("TLOSTreasureHunt reveal() gas:", gasUsed);
    }

    function testTimeRemaining() public {
        assertEq(hunt.timeRemaining(), EXPIRY_DURATION);
        
        vm.warp(block.timestamp + 1 days);
        assertEq(hunt.timeRemaining(), EXPIRY_DURATION - 1 days);
        
        vm.warp(block.timestamp + EXPIRY_DURATION);
        assertEq(hunt.timeRemaining(), 0);
    }

    function testReceiveAdditionalReward() public {
        uint256 additional = 0.5 ether;
        (bool success,) = address(hunt).call{value: additional}("");
        assertTrue(success);
        assertEq(hunt.reward(), REWARD + additional);
    }

    function testConstructorRevertNoValue() public {
        vm.expectRevert("Must deposit reward");
        new TLOSTreasureHunt(SECRET_HASH, block.timestamp + EXPIRY_DURATION);
    }

    function testConstructorRevertPastExpiry() public {
        vm.expectRevert("Expiry must be in future");
        new TLOSTreasureHunt{value: REWARD}(SECRET_HASH, block.timestamp - 1);
    }

    receive() external payable {}
}
