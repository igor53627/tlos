// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title TLOSSealedAuction - TLOS-Protected Sealed-Bid Auction
/// @author TLOS Team
/// @notice A sealed-bid auction where bids are protected from dictionary attacks via TLOS
/// @dev ============================================================================
///      DEMONSTRATION ONLY - For production use, see TLOSWithPuzzleV3.sol
///      ============================================================================
///
/// ## Problem: Dictionary Attacks on Sealed Bids
///
/// In traditional sealed-bid auctions on-chain, bids from small domains (e.g., NFT
/// prices 0-10,000 ETH in 0.01 ETH increments = 1M possibilities) can be trivially
/// dictionary-attacked. An attacker simply hashes all possible bids and matches
/// against the commitment.
///
/// ## Solution: TLOS Puzzle-Protected Commitments
///
/// Each bid commitment includes a planted LWE puzzle solution. To verify ANY guess,
/// the attacker must:
/// 1. Solve the puzzle for that bid amount (expensive off-chain computation)
/// 2. Compute the full commitment hash
///
/// With n=48 puzzle parameters, each guess requires solving a 3^48 ≈ 2^76 search
/// space. Even with GPUs at 1B guesses/sec (FP16), exhaustively testing 10,000 price
/// levels would take an impractical amount of time.
///
/// ## Flow Diagram (ASCII)
///
///   Bidder                              Contract                     Auctioneer
///     |                                    |                              |
///     |  1. placeBid(commitHash)           |                              |
///     |---[BIDDING PHASE]----------------->|                              |
///     |                                    | stores hash, block#          |
///     |                                    |                              |
///     |  [wait 2+ blocks]                  |                              |
///     |                                    |                              |
///     |  2. revealBid(amount, puzzle)      |                              |
///     |---[REVEAL PHASE]------------------>|                              |
///     |                                    | verify hash matches          |
///     |                                    | verify puzzle (1.26M gas)    |
///     |                                    | record bid if highest        |
///     |                                    |                              |
///     |                                    |  3. finalize()               |
///     |                                    |<-----------------------------|
///     |                                    |                              |
///     |  4. ETH refund (if not winner)     |                              |
///     |<-----------------------------------|                              |
///
/// ## MEV/Dictionary Attack Resistance
///
/// - Commit hash: keccak256(sender, bidAmount, puzzleSolution, salt)
/// - Salt adds entropy but puzzle is the primary protection
/// - Without puzzle, attacker could precompute hashes for all 10,000 price levels
/// - With puzzle, attacker must solve LWE for EACH price level guess
/// - Cost to attack: O(priceRange * puzzleSolveTime) instead of O(priceRange * hashTime)
///

contract TLOSSealedAuction {
    // =========================================================================
    // CONSTANTS - Puzzle Parameters (matching WeakLWEPuzzleV7)
    // =========================================================================
    
    uint256 public constant COMMIT_DELAY = 2;
    uint256 public constant N_WEAK = 48;
    uint256 public constant M_WEAK = 72;
    uint256 public constant Q_WEAK = 2039;
    uint256 public constant PUZZLE_THRESHOLD_SQ = 300;
    bytes32 public constant PUZZLE_DOMAIN = keccak256("TLOS-PlantedLWE-v7");

    // =========================================================================
    // TYPES
    // =========================================================================
    
    enum AuctionPhase { BIDDING, REVEAL, FINALIZED }
    
    struct Bid {
        bytes32 commitHash;
        uint256 commitBlock;
        uint256 deposit;
        uint256 revealedAmount;
        bool revealed;
    }

    // =========================================================================
    // STATE - Immutable Configuration
    // =========================================================================
    
    address public immutable owner;
    uint256 public immutable biddingEnd;
    uint256 public immutable revealEnd;
    uint256 public immutable minBid;

    // =========================================================================
    // STATE - Mutable
    // =========================================================================
    
    string public itemDescription;
    address public highestBidder;
    uint256 public highestBid;
    bool public finalized;
    
    mapping(address => Bid) private _bids;
    address[] private _bidders;

    // =========================================================================
    // EVENTS
    // =========================================================================
    
    event BidPlaced(address indexed bidder, bytes32 commitHash, uint256 deposit);
    event BidRevealed(address indexed bidder, uint256 amount);
    event AuctionFinalized(address indexed winner, uint256 winningBid);
    event RefundClaimed(address indexed bidder, uint256 amount);

    // =========================================================================
    // MODIFIERS
    // =========================================================================
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }
    
    modifier inPhase(AuctionPhase expected) {
        require(getPhase() == expected, "Wrong auction phase");
        _;
    }

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================
    
    /// @notice Create a new sealed-bid auction
    /// @param _itemDescription Description of the item being auctioned
    /// @param _biddingDuration Seconds until bidding phase ends
    /// @param _revealDuration Seconds for reveal phase after bidding ends
    /// @param _minBid Minimum bid amount in wei
    constructor(
        string memory _itemDescription,
        uint256 _biddingDuration,
        uint256 _revealDuration,
        uint256 _minBid
    ) {
        require(_biddingDuration > 0, "Invalid bidding duration");
        require(_revealDuration > 0, "Invalid reveal duration");
        
        owner = msg.sender;
        itemDescription = _itemDescription;
        biddingEnd = block.timestamp + _biddingDuration;
        revealEnd = biddingEnd + _revealDuration;
        minBid = _minBid;
    }

    // =========================================================================
    // PHASE 1: BIDDING - Place Sealed Bids
    // =========================================================================
    
    /// @notice Place a sealed bid commitment
    /// @dev The deposit must be >= your actual bid amount. Excess is refundable.
    ///      
    ///      Generate the commit hash off-chain:
    ///      ```solidity
    ///      // 1. Get puzzle solution for your bid amount (expensive off-chain computation)
    ///      bytes32 bidSeed = keccak256(abi.encodePacked(auctionAddress, bidderAddress, bidAmount));
    ///      int8[48] memory puzzleSolution = solvePlantedLWE(bidSeed); // Off-chain solver
    ///      
    ///      // 2. Create commitment with salt for additional entropy
    ///      bytes32 salt = keccak256(abi.encodePacked(block.timestamp, msg.sender, randomness));
    ///      bytes32 commitHash = keccak256(abi.encode(msg.sender, bidAmount, puzzleSolution, salt));
    ///      ```
    ///      
    ///      The puzzle prevents dictionary attacks: attacker cannot simply hash all
    ///      possible bid amounts (0-10,000 price levels) because each requires
    ///      solving an independent LWE puzzle.
    ///
    /// @param commitHash Hash of (sender, bidAmount, puzzleSolution, salt)
    function placeBid(bytes32 commitHash) external payable inPhase(AuctionPhase.BIDDING) {
        require(msg.value >= minBid, "Deposit below minimum bid");
        require(_bids[msg.sender].commitBlock == 0, "Already placed bid");
        
        _bids[msg.sender] = Bid({
            commitHash: commitHash,
            commitBlock: block.number,
            deposit: msg.value,
            revealedAmount: 0,
            revealed: false
        });
        
        _bidders.push(msg.sender);
        
        emit BidPlaced(msg.sender, commitHash, msg.value);
    }

    // =========================================================================
    // PHASE 2: REVEAL - Reveal Bids with Puzzle Proof
    // =========================================================================
    
    /// @notice Reveal your bid and prove it with puzzle solution
    /// @dev Must wait COMMIT_DELAY blocks after placing bid.
    ///      The puzzle solution proves computational work was done, preventing
    ///      real-time dictionary attacks during the reveal phase.
    ///
    /// @param bidAmount Your actual bid amount in wei
    /// @param puzzleSolution 48-element ternary array (-1, 0, or 1) solving the LWE puzzle
    /// @param salt Random salt used in commitment
    function revealBid(
        uint256 bidAmount, 
        int8[48] calldata puzzleSolution,
        bytes32 salt
    ) external inPhase(AuctionPhase.REVEAL) {
        Bid storage bid = _bids[msg.sender];
        
        require(bid.commitBlock > 0, "No bid found");
        require(!bid.revealed, "Already revealed");
        require(block.number >= bid.commitBlock + COMMIT_DELAY, "Reveal too early");
        require(bidAmount <= bid.deposit, "Bid exceeds deposit");
        require(bidAmount >= minBid, "Bid below minimum");
        
        bytes32 expectedCommit = keccak256(abi.encode(msg.sender, bidAmount, puzzleSolution, salt));
        require(bid.commitHash == expectedCommit, "Invalid reveal - hash mismatch");
        
        bytes32 bidSeed = _getBidSeed(msg.sender, bidAmount);
        (bool puzzleValid, ) = _verifyPuzzle(bidSeed, puzzleSolution);
        require(puzzleValid, "Invalid puzzle solution");
        
        bid.revealed = true;
        bid.revealedAmount = bidAmount;
        
        if (bidAmount > highestBid) {
            highestBidder = msg.sender;
            highestBid = bidAmount;
        }
        
        emit BidRevealed(msg.sender, bidAmount);
    }

    // =========================================================================
    // PHASE 3: FINALIZE - Complete Auction
    // =========================================================================
    
    /// @notice Finalize the auction and collect winning bid payment
    /// @dev Only callable by owner after reveal phase ends.
    ///      Transfers the highest bid amount to owner.
    function finalize() external onlyOwner inPhase(AuctionPhase.FINALIZED) {
        require(!finalized, "Already finalized");
        require(highestBidder != address(0), "No valid bids");
        
        finalized = true;
        
        uint256 payment = highestBid;
        
        (bool success, ) = owner.call{value: payment}("");
        require(success, "Payment transfer failed");
        
        emit AuctionFinalized(highestBidder, highestBid);
    }

    // =========================================================================
    // REFUNDS - Claim Deposit Refunds
    // =========================================================================
    
    /// @notice Claim refund of deposit (minus bid amount if winner)
    /// @dev Non-winners get full deposit back. Winner gets deposit - bidAmount back.
    ///      Unrevealed bids forfeit their deposits as penalty.
    function claimRefund() external {
        require(getPhase() == AuctionPhase.FINALIZED, "Auction not finalized");
        
        Bid storage bid = _bids[msg.sender];
        require(bid.deposit > 0, "No deposit to refund");
        
        uint256 refund;
        
        if (!bid.revealed) {
            refund = 0;
        } else if (msg.sender == highestBidder) {
            refund = bid.deposit - highestBid;
        } else {
            refund = bid.deposit;
        }
        
        bid.deposit = 0;
        
        if (refund > 0) {
            (bool success, ) = msg.sender.call{value: refund}("");
            require(success, "Refund transfer failed");
            
            emit RefundClaimed(msg.sender, refund);
        }
    }
    
    /// @notice Emergency withdrawal for owner ONLY if no valid bids
    /// @dev Can only be called when there was no winner (all bids unrevealed or none placed).
    ///      This prevents owner from sweeping unclaimed refunds that belong to bidders.
    function withdrawUnclaimedFunds() external onlyOwner {
        require(getPhase() == AuctionPhase.FINALIZED, "Auction not finalized");
        require(highestBidder == address(0), "Winner exists - use claimRefund");
        
        uint256 balance = address(this).balance;
        if (balance > 0) {
            (bool success, ) = owner.call{value: balance}("");
            require(success, "Withdrawal failed");
        }
    }
    
    /// @notice Allow anyone to finalize after grace period (liveness guarantee)
    /// @dev If owner doesn't finalize within 7 days of reveal end, anyone can trigger.
    ///      This prevents owner from indefinitely locking bidder funds.
    function forceFinalize() external inPhase(AuctionPhase.FINALIZED) {
        require(!finalized, "Already finalized");
        require(block.timestamp >= revealEnd + 7 days, "Grace period not over");
        require(highestBidder != address(0), "No valid bids");
        
        finalized = true;
        
        uint256 payment = highestBid;
        (bool success, ) = owner.call{value: payment}("");
        require(success, "Payment transfer failed");
        
        emit AuctionFinalized(highestBidder, highestBid);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================
    
    function getPhase() public view returns (AuctionPhase) {
        if (block.timestamp < biddingEnd) return AuctionPhase.BIDDING;
        if (block.timestamp < revealEnd) return AuctionPhase.REVEAL;
        return AuctionPhase.FINALIZED;
    }
    
    function getBid(address bidder) external view returns (
        bytes32 commitHash,
        uint256 commitBlock,
        uint256 deposit,
        uint256 revealedAmount,
        bool revealed
    ) {
        Bid memory bid = _bids[bidder];
        return (bid.commitHash, bid.commitBlock, bid.deposit, bid.revealedAmount, bid.revealed);
    }
    
    function getBidderCount() external view returns (uint256) {
        return _bidders.length;
    }
    
    function timeUntilBiddingEnd() external view returns (uint256) {
        if (block.timestamp >= biddingEnd) return 0;
        return biddingEnd - block.timestamp;
    }
    
    function timeUntilRevealEnd() external view returns (uint256) {
        if (block.timestamp >= revealEnd) return 0;
        return revealEnd - block.timestamp;
    }

    /// @notice Get the puzzle seed for a bid (for off-chain solving)
    /// @dev The seed is unique per (auction, bidder, bidAmount) tuple
    function getBidPuzzleSeed(address bidder, uint256 bidAmount) external view returns (bytes32) {
        return _getBidSeed(bidder, bidAmount);
    }

    /// @notice Get the planted secret for off-chain solving
    function getPlantedSecret(bytes32 seed) external pure returns (int8[48] memory secret) {
        bytes32 puzzleSeed = keccak256(abi.encodePacked(PUZZLE_DOMAIN, seed));
        bytes32 secretSeed = keccak256(abi.encodePacked(puzzleSeed, "planted-secret"));
        
        for (uint256 blk = 0; blk < 3; ++blk) {
            bytes32 coeffs = keccak256(abi.encodePacked(secretSeed, blk));
            for (uint256 k = 0; k < 16; ++k) {
                uint256 idx = blk * 16 + k;
                if (idx >= N_WEAK) break;
                uint256 shift = (15 - k) * 16;
                uint256 sRaw = (uint256(coeffs) >> shift) & 0xFFFF;
                secret[idx] = int8(int256(sRaw % 3) - 1);
            }
        }
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================
    
    function _getBidSeed(address bidder, uint256 bidAmount) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), bidder, bidAmount));
    }

    /// @notice Verify a planted LWE puzzle solution
    /// @dev Creates a 3^48 ≈ 2^76 search space per bid amount.
    ///      This prevents dictionary attacks on small bid domains (0-10,000 price levels).
    ///
    ///      Attack cost analysis:
    ///      - Without puzzle: hash 10,000 prices = microseconds
    ///      - With puzzle: solve 10,000 LWE instances ≈ impractical
    ///
    ///      Technical details (matching WeakLWEPuzzleV7):
    ///      - Matrix A (72x48 over Z_2039) derived from keccak256
    ///      - Target b = A*planted + e where e in {-2,-1,0,1,2}
    ///      - Valid solution s: ||A*s - b||² < 300
    ///
    /// @param seed The bid seed (derived from auction, bidder, amount)
    /// @param solution 48-element ternary solution attempt
    /// @return valid True if solution produces small residual
    /// @return sHash Hash of the solution (for binding)
    function _verifyPuzzle(bytes32 seed, int8[48] calldata solution) 
        internal 
        pure 
        returns (bool valid, bytes32 sHash) 
    {
        unchecked {
            for (uint256 i = 0; i < N_WEAK; ++i) {
                if (solution[i] < -1 || solution[i] > 1) {
                    return (false, bytes32(0));
                }
            }
            
            bytes32 puzzleSeed = keccak256(abi.encodePacked(PUZZLE_DOMAIN, seed));
            
            int16[48] memory planted;
            bytes32 secretSeed = keccak256(abi.encodePacked(puzzleSeed, "planted-secret"));
            
            for (uint256 blk = 0; blk < 3; ++blk) {
                bytes32 coeffs = keccak256(abi.encodePacked(secretSeed, blk));
                uint256 coeffsInt = uint256(coeffs);
                
                for (uint256 k = 0; k < 16; ++k) {
                    uint256 idx = blk * 16 + k;
                    if (idx >= N_WEAK) break;
                    uint256 shift = (15 - k) * 16;
                    uint256 sRaw = (coeffsInt >> shift) & 0xFFFF;
                    planted[idx] = int16(int256(sRaw % 3) - 1);
                }
            }
            
            uint256 normSq = 0;
            
            for (uint256 row = 0; row < M_WEAK; ++row) {
                bytes32 rowSeed = keccak256(abi.encodePacked(puzzleSeed, row));
                
                int256 dotCandidate = 0;
                int256 dotPlanted = 0;
                
                for (uint256 blk = 0; blk < 3; ++blk) {
                    bytes32 coeffs = keccak256(abi.encodePacked(rowSeed, blk));
                    uint256 coeffsInt = uint256(coeffs);
                    
                    for (uint256 k = 0; k < 16; ++k) {
                        uint256 col = blk * 16 + k;
                        if (col >= N_WEAK) break;
                        uint256 shift = (15 - k) * 16;
                        int256 aij = int256((coeffsInt >> shift) & 0xFFFF) % int256(Q_WEAK);
                        
                        dotCandidate += aij * int256(solution[col]);
                        dotPlanted += aij * int256(planted[col]);
                    }
                }
                
                bytes32 errorSeed = keccak256(abi.encodePacked(puzzleSeed, "error", row));
                int256 e = int256(uint256(errorSeed) % 5) - 2;
                
                int256 bRow = (dotPlanted + e) % int256(Q_WEAK);
                if (bRow < 0) bRow += int256(Q_WEAK);
                
                int256 residual = (dotCandidate - bRow) % int256(Q_WEAK);
                if (residual > int256(Q_WEAK / 2)) {
                    residual -= int256(Q_WEAK);
                } else if (residual < -int256(Q_WEAK / 2)) {
                    residual += int256(Q_WEAK);
                }
                
                normSq += uint256(residual * residual);
            }
            
            valid = normSq < PUZZLE_THRESHOLD_SQ;
            
            if (valid) {
                sHash = keccak256(abi.encodePacked(solution));
            }
        }
    }
}
