// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../examples/TLOSRecovery.sol";

contract TLOSRecoveryTest is Test {
    TLOSRecovery public recovery;
    
    bytes32 constant PHRASE = bytes32("my-secret-recovery-phrase");
    bytes32 phraseHash;
    
    address deployer = address(this);
    address attacker = address(0xBEEF);
    address newOwner = address(0xCAFE);

    function setUp() public {
        phraseHash = keccak256(abi.encodePacked(PHRASE));
        recovery = new TLOSRecovery(phraseHash);
    }

    function testConstructor() public view {
        assertEq(recovery.owner(), deployer);
        assertEq(recovery.phraseHash(), phraseHash);
    }

    function testRecoverSuccess() public {
        int8[48] memory solution = recovery.getPlantedSecret(PHRASE);
        
        vm.prank(newOwner);
        recovery.recover(PHRASE, solution);
        
        assertEq(recovery.owner(), newOwner);
    }

    function testRecoverWrongPhrase() public {
        bytes32 wrongPhrase = bytes32("wrong-phrase");
        int8[48] memory solution = recovery.getPlantedSecret(PHRASE);
        
        vm.prank(attacker);
        vm.expectRevert("Invalid phrase");
        recovery.recover(wrongPhrase, solution);
        
        assertEq(recovery.owner(), deployer);
    }

    function testRecoverWrongPuzzle() public {
        int8[48] memory wrongSolution;
        for (uint256 i = 0; i < 48; i++) {
            wrongSolution[i] = 0;
        }
        
        vm.roll(block.number + 1);
        vm.prank(attacker);
        vm.expectRevert("Invalid puzzle solution");
        recovery.recover(PHRASE, wrongSolution);
        
        assertEq(recovery.owner(), deployer);
    }

    function testCheckRecoveryView() public view {
        int8[48] memory solution = recovery.getPlantedSecret(PHRASE);
        
        assertTrue(recovery.checkRecovery(PHRASE, solution));
        
        bytes32 wrongPhrase = bytes32("wrong");
        assertFalse(recovery.checkRecovery(wrongPhrase, solution));
        
        int8[48] memory wrongSolution;
        assertFalse(recovery.checkRecovery(PHRASE, wrongSolution));
    }

    function testUpdatePhraseHash() public {
        bytes32 newPhraseHash = keccak256(abi.encodePacked(bytes32("new-phrase")));
        
        recovery.updatePhraseHash(newPhraseHash);
        
        assertEq(recovery.phraseHash(), newPhraseHash);
    }

    function testUpdatePhraseHashNotOwner() public {
        bytes32 newPhraseHash = keccak256(abi.encodePacked(bytes32("new-phrase")));
        
        vm.prank(attacker);
        vm.expectRevert("Not owner");
        recovery.updatePhraseHash(newPhraseHash);
        
        assertEq(recovery.phraseHash(), phraseHash);
    }

    function testRateLimiting() public {
        int8[48] memory solution = recovery.getPlantedSecret(PHRASE);
        
        vm.prank(newOwner);
        recovery.recover(PHRASE, solution);
        assertEq(recovery.owner(), newOwner);
        
        bytes32 newPhrase = bytes32("another-phrase");
        bytes32 newHash = keccak256(abi.encodePacked(newPhrase));
        vm.prank(newOwner);
        recovery.updatePhraseHash(newHash);
        
        int8[48] memory newSolution = recovery.getPlantedSecret(newPhrase);
        
        vm.prank(attacker);
        vm.expectRevert("Rate limited: 1 attempt per block");
        recovery.recover(newPhrase, newSolution);
        
        vm.roll(block.number + 1);
        vm.prank(attacker);
        recovery.recover(newPhrase, newSolution);
        assertEq(recovery.owner(), attacker);
    }

    function testOwnershipTransfer() public {
        int8[48] memory solution = recovery.getPlantedSecret(PHRASE);
        
        vm.prank(newOwner);
        recovery.recover(PHRASE, solution);
        assertEq(recovery.owner(), newOwner);
        
        bytes32 newPhraseHash = keccak256(abi.encodePacked(bytes32("new-phrase")));
        vm.prank(newOwner);
        recovery.updatePhraseHash(newPhraseHash);
        assertEq(recovery.phraseHash(), newPhraseHash);
        
        vm.prank(deployer);
        vm.expectRevert("Not owner");
        recovery.updatePhraseHash(phraseHash);
    }

    function testGasMeasurement() public {
        int8[48] memory solution = recovery.getPlantedSecret(PHRASE);
        
        uint256 gasStart = gasleft();
        recovery.checkRecovery(PHRASE, solution);
        uint256 gasUsed = gasStart - gasleft();
        
        console.log("TLOSRecovery puzzle verification gas:", gasUsed);
        
        assertTrue(gasUsed < 2_000_000, "Gas should be under 2M");
    }

    function testGetPuzzleSeed() public view {
        bytes32 seed = recovery.getPuzzleSeed(PHRASE);
        bytes32 expected = keccak256(abi.encodePacked(recovery.PUZZLE_DOMAIN(), PHRASE));
        assertEq(seed, expected);
    }

    function testGetPlantedSecretDeterministic() public view {
        int8[48] memory s1 = recovery.getPlantedSecret(PHRASE);
        int8[48] memory s2 = recovery.getPlantedSecret(PHRASE);
        
        for (uint256 i = 0; i < 48; i++) {
            assertEq(s1[i], s2[i]);
            assertTrue(s1[i] >= -1 && s1[i] <= 1, "Secret must be ternary");
        }
    }

    function testReceiveEther() public {
        vm.deal(attacker, 1 ether);
        vm.prank(attacker);
        (bool success,) = address(recovery).call{value: 0.5 ether}("");
        assertTrue(success);
        assertEq(address(recovery).balance, 0.5 ether);
    }
}
