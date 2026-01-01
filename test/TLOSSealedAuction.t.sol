// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../examples/TLOSSealedAuction.sol";

contract TLOSSealedAuctionTest is Test {
    TLOSSealedAuction public auction;
    
    address owner = address(this);
    address bidder1 = address(0x1);
    address bidder2 = address(0x2);
    address bidder3 = address(0x3);
    
    uint256 constant BIDDING_DURATION = 1 hours;
    uint256 constant REVEAL_DURATION = 1 hours;
    uint256 constant MIN_BID = 0.1 ether;

    receive() external payable {}

    function setUp() public {
        auction = new TLOSSealedAuction(
            "Test NFT",
            BIDDING_DURATION,
            REVEAL_DURATION,
            MIN_BID
        );
        vm.deal(bidder1, 100 ether);
        vm.deal(bidder2, 100 ether);
        vm.deal(bidder3, 100 ether);
    }

    function testAuctionPhases() public {
        assertEq(uint256(auction.getPhase()), uint256(TLOSSealedAuction.AuctionPhase.BIDDING));
        
        vm.warp(auction.biddingEnd());
        assertEq(uint256(auction.getPhase()), uint256(TLOSSealedAuction.AuctionPhase.REVEAL));
        
        vm.warp(auction.revealEnd());
        assertEq(uint256(auction.getPhase()), uint256(TLOSSealedAuction.AuctionPhase.FINALIZED));
    }

    function testPlaceBidDuringBidding() public {
        uint256 bidAmount = 1 ether;
        bytes32 salt = keccak256("salt1");
        int8[48] memory puzzleSolution = _getPuzzleSolution(bidder1, bidAmount);
        bytes32 commitHash = keccak256(abi.encode(bidder1, bidAmount, puzzleSolution, salt));
        
        vm.prank(bidder1);
        auction.placeBid{value: 2 ether}(commitHash);
        
        (bytes32 storedHash, uint256 commitBlock, uint256 deposit, , bool revealed) = auction.getBid(bidder1);
        assertEq(storedHash, commitHash);
        assertEq(commitBlock, block.number);
        assertEq(deposit, 2 ether);
        assertFalse(revealed);
        assertEq(auction.getBidderCount(), 1);
    }

    function testPlaceBidFailsAfterBidding() public {
        vm.warp(auction.biddingEnd());
        assertEq(uint256(auction.getPhase()), uint256(TLOSSealedAuction.AuctionPhase.REVEAL));
        
        bytes32 commitHash = keccak256("late bid");
        vm.prank(bidder1);
        vm.expectRevert("Wrong auction phase");
        auction.placeBid{value: 1 ether}(commitHash);
    }

    function testRevealBid() public {
        uint256 bidAmount = 1 ether;
        bytes32 salt = keccak256("salt1");
        int8[48] memory puzzleSolution = _getPuzzleSolution(bidder1, bidAmount);
        bytes32 commitHash = keccak256(abi.encode(bidder1, bidAmount, puzzleSolution, salt));
        
        vm.prank(bidder1);
        auction.placeBid{value: 2 ether}(commitHash);
        
        vm.roll(block.number + 3);
        vm.warp(auction.biddingEnd());
        
        vm.prank(bidder1);
        auction.revealBid(bidAmount, puzzleSolution, salt);
        
        (, , , uint256 revealedAmount, bool revealed) = auction.getBid(bidder1);
        assertTrue(revealed);
        assertEq(revealedAmount, bidAmount);
        assertEq(auction.highestBidder(), bidder1);
        assertEq(auction.highestBid(), bidAmount);
    }

    function testRevealBidWrongPuzzle() public {
        uint256 bidAmount = 1 ether;
        bytes32 salt = keccak256("salt1");
        int8[48] memory puzzleSolution = _getPuzzleSolution(bidder1, bidAmount);
        bytes32 commitHash = keccak256(abi.encode(bidder1, bidAmount, puzzleSolution, salt));
        
        vm.prank(bidder1);
        auction.placeBid{value: 2 ether}(commitHash);
        
        vm.roll(block.number + 3);
        vm.warp(auction.biddingEnd());
        
        int8[48] memory wrongSolution;
        for (uint256 i = 0; i < 48; i++) {
            wrongSolution[i] = 0;
        }
        
        vm.prank(bidder1);
        vm.expectRevert("Invalid reveal - hash mismatch");
        auction.revealBid(bidAmount, wrongSolution, salt);
    }

    function testRevealBidCommitDelay() public {
        uint256 bidAmount = 1 ether;
        bytes32 salt = keccak256("salt1");
        int8[48] memory puzzleSolution = _getPuzzleSolution(bidder1, bidAmount);
        bytes32 commitHash = keccak256(abi.encode(bidder1, bidAmount, puzzleSolution, salt));
        
        vm.prank(bidder1);
        auction.placeBid{value: 2 ether}(commitHash);
        
        vm.warp(auction.biddingEnd());
        
        vm.prank(bidder1);
        vm.expectRevert("Reveal too early");
        auction.revealBid(bidAmount, puzzleSolution, salt);
    }

    function testHighestBidderWins() public {
        uint256 bidAmount1 = 1 ether;
        uint256 bidAmount2 = 2 ether;
        bytes32 salt1 = keccak256("salt1");
        bytes32 salt2 = keccak256("salt2");
        
        int8[48] memory puzzle1 = _getPuzzleSolution(bidder1, bidAmount1);
        int8[48] memory puzzle2 = _getPuzzleSolution(bidder2, bidAmount2);
        
        bytes32 commit1 = keccak256(abi.encode(bidder1, bidAmount1, puzzle1, salt1));
        bytes32 commit2 = keccak256(abi.encode(bidder2, bidAmount2, puzzle2, salt2));
        
        vm.prank(bidder1);
        auction.placeBid{value: 3 ether}(commit1);
        
        vm.prank(bidder2);
        auction.placeBid{value: 3 ether}(commit2);
        
        vm.roll(block.number + 3);
        vm.warp(auction.biddingEnd());
        
        vm.prank(bidder1);
        auction.revealBid(bidAmount1, puzzle1, salt1);
        assertEq(auction.highestBidder(), bidder1);
        assertEq(auction.highestBid(), bidAmount1);
        
        vm.prank(bidder2);
        auction.revealBid(bidAmount2, puzzle2, salt2);
        assertEq(auction.highestBidder(), bidder2);
        assertEq(auction.highestBid(), bidAmount2);
    }

    function testFinalize() public {
        uint256 bidAmount = 5 ether;
        bytes32 salt = keccak256("salt1");
        int8[48] memory puzzleSolution = _getPuzzleSolution(bidder1, bidAmount);
        bytes32 commitHash = keccak256(abi.encode(bidder1, bidAmount, puzzleSolution, salt));
        
        vm.prank(bidder1);
        auction.placeBid{value: 10 ether}(commitHash);
        
        vm.roll(block.number + 3);
        vm.warp(auction.biddingEnd());
        
        vm.prank(bidder1);
        auction.revealBid(bidAmount, puzzleSolution, salt);
        
        vm.warp(auction.revealEnd());
        
        uint256 ownerBalanceBefore = owner.balance;
        auction.finalize();
        uint256 ownerBalanceAfter = owner.balance;
        
        assertTrue(auction.finalized());
        assertEq(ownerBalanceAfter - ownerBalanceBefore, bidAmount);
    }

    function testClaimRefund() public {
        uint256 bidAmount1 = 1 ether;
        uint256 bidAmount2 = 2 ether;
        bytes32 salt1 = keccak256("salt1");
        bytes32 salt2 = keccak256("salt2");
        
        int8[48] memory puzzle1 = _getPuzzleSolution(bidder1, bidAmount1);
        int8[48] memory puzzle2 = _getPuzzleSolution(bidder2, bidAmount2);
        
        bytes32 commit1 = keccak256(abi.encode(bidder1, bidAmount1, puzzle1, salt1));
        bytes32 commit2 = keccak256(abi.encode(bidder2, bidAmount2, puzzle2, salt2));
        
        vm.prank(bidder1);
        auction.placeBid{value: 3 ether}(commit1);
        
        vm.prank(bidder2);
        auction.placeBid{value: 5 ether}(commit2);
        
        vm.roll(block.number + 3);
        vm.warp(auction.biddingEnd());
        
        vm.prank(bidder1);
        auction.revealBid(bidAmount1, puzzle1, salt1);
        
        vm.prank(bidder2);
        auction.revealBid(bidAmount2, puzzle2, salt2);
        
        vm.warp(auction.revealEnd());
        auction.finalize();
        
        uint256 bidder1BalanceBefore = bidder1.balance;
        vm.prank(bidder1);
        auction.claimRefund();
        uint256 bidder1BalanceAfter = bidder1.balance;
        assertEq(bidder1BalanceAfter - bidder1BalanceBefore, 3 ether);
        
        uint256 bidder2BalanceBefore = bidder2.balance;
        vm.prank(bidder2);
        auction.claimRefund();
        uint256 bidder2BalanceAfter = bidder2.balance;
        assertEq(bidder2BalanceAfter - bidder2BalanceBefore, 3 ether);
    }

    function testGasMeasurement() public {
        uint256 bidAmount = 1 ether;
        bytes32 salt = keccak256("salt1");
        int8[48] memory puzzleSolution = _getPuzzleSolution(bidder1, bidAmount);
        bytes32 commitHash = keccak256(abi.encode(bidder1, bidAmount, puzzleSolution, salt));
        
        vm.prank(bidder1);
        auction.placeBid{value: 2 ether}(commitHash);
        
        vm.roll(block.number + 3);
        vm.warp(auction.biddingEnd());
        
        uint256 gasBefore = gasleft();
        vm.prank(bidder1);
        auction.revealBid(bidAmount, puzzleSolution, salt);
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("revealBid gas (includes puzzle verification):", gasUsed);
        assertTrue(gasUsed > 0);
    }

    function testPlaceBidBelowMinimum() public {
        bytes32 commitHash = keccak256("bid");
        
        vm.prank(bidder1);
        vm.expectRevert("Deposit below minimum bid");
        auction.placeBid{value: 0.05 ether}(commitHash);
    }

    function testCannotBidTwice() public {
        bytes32 commitHash = keccak256("bid");
        
        vm.prank(bidder1);
        auction.placeBid{value: 1 ether}(commitHash);
        
        vm.prank(bidder1);
        vm.expectRevert("Already placed bid");
        auction.placeBid{value: 1 ether}(commitHash);
    }

    function testUnrevealedBidForfeitsDeposit() public {
        uint256 bidAmount = 1 ether;
        bytes32 salt = keccak256("salt1");
        int8[48] memory puzzle = _getPuzzleSolution(bidder1, bidAmount);
        bytes32 commit = keccak256(abi.encode(bidder1, bidAmount, puzzle, salt));
        
        vm.prank(bidder1);
        auction.placeBid{value: 3 ether}(commit);
        
        vm.prank(bidder2);
        auction.placeBid{value: 2 ether}(keccak256("unrevealed"));
        
        vm.roll(block.number + 3);
        vm.warp(auction.biddingEnd());
        
        vm.prank(bidder1);
        auction.revealBid(bidAmount, puzzle, salt);
        
        vm.warp(auction.revealEnd());
        auction.finalize();
        
        uint256 bidder2BalanceBefore = bidder2.balance;
        vm.prank(bidder2);
        auction.claimRefund();
        uint256 bidder2BalanceAfter = bidder2.balance;
        assertEq(bidder2BalanceAfter, bidder2BalanceBefore);
    }

    function testOnlyOwnerCanFinalize() public {
        uint256 bidAmount = 1 ether;
        bytes32 salt = keccak256("salt1");
        int8[48] memory puzzle = _getPuzzleSolution(bidder1, bidAmount);
        bytes32 commit = keccak256(abi.encode(bidder1, bidAmount, puzzle, salt));
        
        vm.prank(bidder1);
        auction.placeBid{value: 2 ether}(commit);
        
        vm.roll(block.number + 3);
        vm.warp(auction.biddingEnd());
        
        vm.prank(bidder1);
        auction.revealBid(bidAmount, puzzle, salt);
        
        vm.warp(auction.revealEnd());
        
        vm.prank(bidder1);
        vm.expectRevert("Only owner");
        auction.finalize();
    }

    function _getPuzzleSolution(address bidder, uint256 bidAmount) internal view returns (int8[48] memory) {
        bytes32 seed = auction.getBidPuzzleSeed(bidder, bidAmount);
        return auction.getPlantedSecret(seed);
    }
}
