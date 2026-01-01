// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../examples/TLOSDeadManSwitch.sol";

contract TLOSDeadManSwitchTest is Test {
    TLOSDeadManSwitch public dms;
    
    address public owner = address(this);
    
    receive() external payable {}
    address public heir1 = address(0x1111);
    address public heir2 = address(0x2222);
    address public heir3 = address(0x3333);
    
    bytes32 public code1 = keccak256("heir1-secret-code");
    bytes32 public code2 = keccak256("heir2-secret-code");
    bytes32 public code3 = keccak256("heir3-secret-code");
    
    bytes32 public codeHash1;
    bytes32 public codeHash2;
    bytes32 public codeHash3;
    
    uint256 public constant HEARTBEAT = 30 days;
    uint256 public constant INITIAL_BALANCE = 10 ether;
    
    function setUp() public {
        codeHash1 = keccak256(abi.encodePacked(code1));
        codeHash2 = keccak256(abi.encodePacked(code2));
        codeHash3 = keccak256(abi.encodePacked(code3));
        
        bytes32[] memory heirHashes = new bytes32[](2);
        heirHashes[0] = codeHash1;
        heirHashes[1] = codeHash2;
        
        uint16[] memory shares = new uint16[](2);
        shares[0] = 5000;
        shares[1] = 3000;
        
        dms = new TLOSDeadManSwitch{value: INITIAL_BALANCE}(
            HEARTBEAT,
            heirHashes,
            shares
        );
    }
    
    function testOwnerCanPing() public {
        uint256 initialLastPing = dms.lastPing();
        
        vm.warp(block.timestamp + 1 days);
        dms.ping();
        
        assertGt(dms.lastPing(), initialLastPing);
        assertEq(dms.lastPing(), block.timestamp);
    }
    
    function testOwnerAliveWithinInterval() public {
        assertTrue(dms.isOwnerAlive());
        
        vm.warp(block.timestamp + HEARTBEAT - 1);
        assertTrue(dms.isOwnerAlive());
    }
    
    function testOwnerDeadAfterInterval() public {
        assertTrue(dms.isOwnerAlive());
        
        vm.warp(block.timestamp + HEARTBEAT);
        assertFalse(dms.isOwnerAlive());
        
        vm.warp(block.timestamp + HEARTBEAT + 1 days);
        assertFalse(dms.isOwnerAlive());
    }
    
    function testAddHeir() public {
        uint256 countBefore = dms.heirCount();
        
        dms.addHeir(codeHash3, 1000);
        
        assertEq(dms.heirCount(), countBefore + 1);
        
        (bytes32 storedHash, uint16 share, bool claimed) = dms.getHeirInfo(countBefore);
        assertEq(storedHash, codeHash3);
        assertEq(share, 1000);
        assertFalse(claimed);
    }
    
    function testRemoveHeir() public {
        (bytes32 hashBefore, , ) = dms.getHeirInfo(0);
        assertEq(hashBefore, codeHash1);
        
        dms.removeHeir(0);
        
        (bytes32 hashAfter, uint16 shareAfter, ) = dms.getHeirInfo(0);
        assertEq(hashAfter, bytes32(0));
        assertEq(shareAfter, 0);
    }
    
    function testHeirCannotClaimWhileAlive() public {
        assertTrue(dms.isOwnerAlive());
        
        int8[48] memory solution = dms.getPlantedSecret(code1);
        bytes32 commitHash = keccak256(abi.encode(heir1, uint256(0), code1, solution));
        
        vm.prank(heir1);
        vm.expectRevert("Owner still active");
        dms.commit(commitHash);
    }
    
    function testHeirCommitReveal() public {
        vm.warp(block.timestamp + HEARTBEAT);
        assertFalse(dms.isOwnerAlive());
        
        int8[48] memory solution = dms.getPlantedSecret(code1);
        bytes32 commitHash = keccak256(abi.encode(heir1, uint256(0), code1, solution));
        
        vm.prank(heir1);
        dms.commit(commitHash);
        
        (bytes32 storedHash, uint256 blockNum) = dms.getCommit(heir1);
        assertEq(storedHash, commitHash);
        assertEq(blockNum, block.number);
        
        vm.roll(block.number + 1);
        vm.prank(heir1);
        vm.expectRevert("Reveal too early");
        dms.claim(0, code1, solution);
        
        vm.roll(block.number + 2);
    }
    
    function testHeirClaimWithCorrectPuzzle() public {
        vm.warp(block.timestamp + HEARTBEAT);
        
        int8[48] memory solution = dms.getPlantedSecret(code1);
        bytes32 commitHash = keccak256(abi.encode(heir1, uint256(0), code1, solution));
        
        vm.prank(heir1);
        dms.commit(commitHash);
        
        vm.roll(block.number + 3);
        
        uint256 heir1BalanceBefore = heir1.balance;
        uint256 expectedAmount = (INITIAL_BALANCE * 5000) / 10000;
        
        vm.prank(heir1);
        dms.claim(0, code1, solution);
        
        assertEq(heir1.balance - heir1BalanceBefore, expectedAmount);
        
        (, , bool claimed) = dms.getHeirInfo(0);
        assertTrue(claimed);
    }
    
    function testHeirClaimWithWrongPuzzle() public {
        vm.warp(block.timestamp + HEARTBEAT);
        
        int8[48] memory wrongSolution;
        for (uint256 i = 0; i < 48; i++) {
            wrongSolution[i] = 1;
        }
        
        bytes32 commitHash = keccak256(abi.encode(heir1, uint256(0), code1, wrongSolution));
        
        vm.prank(heir1);
        dms.commit(commitHash);
        
        vm.roll(block.number + 3);
        
        vm.prank(heir1);
        vm.expectRevert("Invalid puzzle solution");
        dms.claim(0, code1, wrongSolution);
    }
    
    function testMultipleHeirsClaim() public {
        vm.warp(block.timestamp + HEARTBEAT);
        
        int8[48] memory solution1 = dms.getPlantedSecret(code1);
        bytes32 commitHash1_ = keccak256(abi.encode(heir1, uint256(0), code1, solution1));
        
        vm.roll(100);
        vm.prank(heir1);
        dms.commit(commitHash1_);
        
        vm.roll(103);
        
        uint256 heir1BalanceBefore = heir1.balance;
        uint256 expectedAmount1 = (INITIAL_BALANCE * 5000) / 10000;
        
        vm.prank(heir1);
        dms.claim(0, code1, solution1);
        
        assertEq(heir1.balance - heir1BalanceBefore, expectedAmount1);
        
        int8[48] memory solution2 = dms.getPlantedSecret(code2);
        bytes32 commitHash2_ = keccak256(abi.encode(heir2, uint256(1), code2, solution2));
        
        vm.roll(200);
        vm.prank(heir2);
        dms.commit(commitHash2_);
        
        vm.roll(203);
        
        uint256 heir2BalanceBefore = heir2.balance;
        uint256 expectedAmount2 = (INITIAL_BALANCE * 3000) / 10000;
        
        vm.prank(heir2);
        dms.claim(1, code2, solution2);
        
        assertEq(heir2.balance - heir2BalanceBefore, expectedAmount2);
        
        (, , bool claimed1) = dms.getHeirInfo(0);
        (, , bool claimed2) = dms.getHeirInfo(1);
        assertTrue(claimed1);
        assertTrue(claimed2);
    }
    
    function testEmergencyWithdraw() public {
        assertTrue(dms.isOwnerAlive());
        
        uint256 ownerBalanceBefore = owner.balance;
        uint256 contractBalance = address(dms).balance;
        
        dms.emergencyWithdraw(0);
        
        assertEq(owner.balance - ownerBalanceBefore, contractBalance);
        assertEq(address(dms).balance, 0);
    }
    
    function testEmergencyWithdrawPartial() public {
        uint256 ownerBalanceBefore = owner.balance;
        
        dms.emergencyWithdraw(1 ether);
        
        assertEq(owner.balance - ownerBalanceBefore, 1 ether);
        assertEq(address(dms).balance, INITIAL_BALANCE - 1 ether);
    }
    
    function testEmergencyWithdrawFailsWhenDead() public {
        vm.warp(block.timestamp + HEARTBEAT);
        
        vm.expectRevert("Owner inactive - heirs can claim");
        dms.emergencyWithdraw(0);
    }
    
    function testGasMeasurement() public {
        vm.warp(block.timestamp + HEARTBEAT);
        
        int8[48] memory solution = dms.getPlantedSecret(code1);
        bytes32 commitHash = keccak256(abi.encode(heir1, uint256(0), code1, solution));
        
        vm.prank(heir1);
        dms.commit(commitHash);
        
        vm.roll(block.number + 3);
        
        uint256 gasStart = gasleft();
        vm.prank(heir1);
        dms.claim(0, code1, solution);
        uint256 gasUsed = gasStart - gasleft();
        
        console.log("DeadManSwitch claim() gas (with puzzle verification):", gasUsed);
        
        assertGt(gasUsed, 0);
    }
    
    function testCannotClaimTwice() public {
        vm.warp(block.timestamp + HEARTBEAT);
        
        int8[48] memory solution = dms.getPlantedSecret(code1);
        bytes32 commitHash = keccak256(abi.encode(heir1, uint256(0), code1, solution));
        
        vm.prank(heir1);
        dms.commit(commitHash);
        
        vm.roll(block.number + 3);
        
        vm.prank(heir1);
        dms.claim(0, code1, solution);
        
        vm.prank(heir1);
        dms.commit(commitHash);
        
        vm.roll(block.number + 3);
        
        vm.prank(heir1);
        vm.expectRevert("Already claimed");
        dms.claim(0, code1, solution);
    }
    
    function testCannotClaimWithWrongCode() public {
        vm.warp(block.timestamp + HEARTBEAT);
        
        bytes32 wrongCode = keccak256("wrong-code");
        int8[48] memory solution = dms.getPlantedSecret(wrongCode);
        bytes32 commitHash = keccak256(abi.encode(heir1, uint256(0), wrongCode, solution));
        
        vm.prank(heir1);
        dms.commit(commitHash);
        
        vm.roll(block.number + 3);
        
        vm.prank(heir1);
        vm.expectRevert("Invalid heir code");
        dms.claim(0, wrongCode, solution);
    }
    
    function testPingResetsDeadline() public {
        uint256 initialDeadline = dms.deadline();
        
        vm.warp(block.timestamp + 10 days);
        dms.ping();
        
        uint256 newDeadline = dms.deadline();
        assertGt(newDeadline, initialDeadline);
        assertEq(newDeadline, block.timestamp + HEARTBEAT);
    }
    
    function testTimeUntilDead() public {
        assertEq(dms.timeUntilDead(), HEARTBEAT);
        
        vm.warp(block.timestamp + 10 days);
        assertEq(dms.timeUntilDead(), HEARTBEAT - 10 days);
        
        vm.warp(block.timestamp + HEARTBEAT);
        assertEq(dms.timeUntilDead(), 0);
    }
    
    function testTimeSinceDeath() public {
        assertEq(dms.timeSinceDeath(), 0);
        
        vm.warp(block.timestamp + HEARTBEAT + 5 days);
        assertEq(dms.timeSinceDeath(), 5 days);
    }
    
    function testOnlyOwnerCanPing() public {
        vm.prank(heir1);
        vm.expectRevert("Only owner");
        dms.ping();
    }
    
    function testOnlyOwnerCanAddHeir() public {
        vm.prank(heir1);
        vm.expectRevert("Only owner");
        dms.addHeir(codeHash3, 1000);
    }
    
    function testOnlyOwnerCanRemoveHeir() public {
        vm.prank(heir1);
        vm.expectRevert("Only owner");
        dms.removeHeir(0);
    }
    
    function testAddHeirExceedsShares() public {
        vm.expectRevert("Shares would exceed 100%");
        dms.addHeir(codeHash3, 3000);
    }
    
    function testReceiveEther() public {
        uint256 balanceBefore = address(dms).balance;
        
        (bool success, ) = address(dms).call{value: 1 ether}("");
        assertTrue(success);
        
        assertEq(address(dms).balance, balanceBefore + 1 ether);
    }
}
