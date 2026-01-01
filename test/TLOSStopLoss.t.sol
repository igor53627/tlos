// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../examples/TLOSStopLoss.sol";

contract MockOracle is IOracle {
    uint256 public price;

    function setPrice(uint256 _price) external {
        price = _price;
    }

    function getPrice() external view override returns (uint256) {
        return price;
    }
}

contract MockTLOSCircuit is ITLOSCircuit {
    bool public shouldReturn;

    function setResult(bool _result) external {
        shouldReturn = _result;
    }

    function check(bytes32) external view override returns (bool) {
        return shouldReturn;
    }
}

contract TLOSStopLossTest is Test {
    TLOSStopLoss public vault;
    MockOracle public oracle;
    MockTLOSCircuit public circuit;

    address public alice = address(0x1);
    address public bob = address(0x2);
    address public keeper = address(0x3);

    function setUp() public {
        oracle = new MockOracle();
        oracle.setPrice(1000e18);
        vault = new TLOSStopLoss(address(oracle));
        circuit = new MockTLOSCircuit();

        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
    }

    function testDeposit() public {
        vm.prank(alice);
        vault.deposit{value: 1 ether}();

        (uint256 collateral,,,) = vault.getPosition(alice);
        assertEq(collateral, 1 ether);
        assertEq(vault.totalDeposits(), 1 ether);
    }

    function testWithdraw() public {
        vm.startPrank(alice);
        vault.deposit{value: 5 ether}();
        vault.withdraw(2 ether);
        vm.stopPrank();

        (uint256 collateral,,,) = vault.getPosition(alice);
        assertEq(collateral, 3 ether);
        assertEq(vault.totalDeposits(), 3 ether);
    }

    function testSetStopLossCircuit() public {
        bytes32 userCode = keccak256("alice-secret");

        vm.startPrank(alice);
        vault.deposit{value: 1 ether}();
        vault.setStopLossCircuit(address(circuit), userCode);
        vm.stopPrank();

        (, address circuitAddr, bytes32 storedCode, bool active) = vault.getPosition(alice);
        assertEq(circuitAddr, address(circuit));
        assertEq(storedCode, userCode);
        assertTrue(active);
    }

    function testCancelStopLoss() public {
        bytes32 userCode = keccak256("alice-secret");

        vm.startPrank(alice);
        vault.deposit{value: 1 ether}();
        vault.setStopLossCircuit(address(circuit), userCode);
        vault.cancelStopLoss();
        vm.stopPrank();

        (, address circuitAddr, bytes32 storedCode, bool active) = vault.getPosition(alice);
        assertEq(circuitAddr, address(0));
        assertEq(storedCode, bytes32(0));
        assertFalse(active);
    }

    function testTriggerStopLossSuccess() public {
        bytes32 userCode = keccak256("alice-secret");
        circuit.setResult(true);

        vm.startPrank(alice);
        vault.deposit{value: 5 ether}();
        vault.setStopLossCircuit(address(circuit), userCode);
        vm.stopPrank();

        uint256 aliceBalanceBefore = alice.balance;

        vm.prank(keeper);
        vault.triggerStopLoss(alice);

        assertEq(alice.balance, aliceBalanceBefore + 5 ether);
        (uint256 collateral,, , bool active) = vault.getPosition(alice);
        assertEq(collateral, 0);
        assertFalse(active);
    }

    function testTriggerStopLossFails() public {
        bytes32 userCode = keccak256("alice-secret");
        circuit.setResult(false);

        vm.startPrank(alice);
        vault.deposit{value: 5 ether}();
        vault.setStopLossCircuit(address(circuit), userCode);
        vm.stopPrank();

        vm.prank(keeper);
        vm.expectRevert("Stop-loss condition not met");
        vault.triggerStopLoss(alice);
    }

    function testTriggerStopLossNoCircuit() public {
        vm.prank(alice);
        vault.deposit{value: 1 ether}();

        vm.prank(keeper);
        vm.expectRevert("No active stop-loss");
        vault.triggerStopLoss(alice);
    }

    function testWouldTrigger() public {
        bytes32 userCode = keccak256("alice-secret");

        vm.startPrank(alice);
        vault.deposit{value: 1 ether}();
        vault.setStopLossCircuit(address(circuit), userCode);
        vm.stopPrank();

        circuit.setResult(false);
        assertFalse(vault.wouldTrigger(alice));

        circuit.setResult(true);
        assertTrue(vault.wouldTrigger(alice));
    }

    function testMultipleUsers() public {
        MockTLOSCircuit aliceCircuit = new MockTLOSCircuit();
        MockTLOSCircuit bobCircuit = new MockTLOSCircuit();
        bytes32 aliceCode = keccak256("alice");
        bytes32 bobCode = keccak256("bob");

        vm.startPrank(alice);
        vault.deposit{value: 3 ether}();
        vault.setStopLossCircuit(address(aliceCircuit), aliceCode);
        vm.stopPrank();

        vm.startPrank(bob);
        vault.deposit{value: 7 ether}();
        vault.setStopLossCircuit(address(bobCircuit), bobCode);
        vm.stopPrank();

        (uint256 aliceCol, address aliceCircAddr,,) = vault.getPosition(alice);
        (uint256 bobCol, address bobCircAddr,,) = vault.getPosition(bob);

        assertEq(aliceCol, 3 ether);
        assertEq(bobCol, 7 ether);
        assertEq(aliceCircAddr, address(aliceCircuit));
        assertEq(bobCircAddr, address(bobCircuit));
        assertEq(vault.totalDeposits(), 10 ether);

        aliceCircuit.setResult(true);
        bobCircuit.setResult(false);

        vm.prank(keeper);
        vault.triggerStopLoss(alice);

        vm.prank(keeper);
        vm.expectRevert("Stop-loss condition not met");
        vault.triggerStopLoss(bob);

        (aliceCol,,,) = vault.getPosition(alice);
        (bobCol,,,) = vault.getPosition(bob);
        assertEq(aliceCol, 0);
        assertEq(bobCol, 7 ether);
    }

    function testCannotWithdrawMoreThanBalance() public {
        vm.startPrank(alice);
        vault.deposit{value: 1 ether}();
        vm.expectRevert("Insufficient collateral");
        vault.withdraw(2 ether);
        vm.stopPrank();
    }

    function testCannotWithdrawWithActiveStopLoss() public {
        vm.startPrank(alice);
        vault.deposit{value: 1 ether}();
        vault.setStopLossCircuit(address(circuit), keccak256("test"));
        vm.expectRevert("Cancel stop-loss first");
        vault.withdraw(1 ether);
        vm.stopPrank();
    }

    function testCannotSetCircuitWithoutDeposit() public {
        vm.prank(alice);
        vm.expectRevert("Deposit first");
        vault.setStopLossCircuit(address(circuit), keccak256("test"));
    }

    function testReceiveDeposit() public {
        vm.prank(alice);
        (bool success,) = address(vault).call{value: 2 ether}("");
        assertTrue(success);

        (uint256 collateral,,,) = vault.getPosition(alice);
        assertEq(collateral, 2 ether);
    }
}
