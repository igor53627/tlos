// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// ##############################################################################
/// #                                                                            #
/// #   ██████╗  ██████╗     ███╗   ██╗ ██████╗ ████████╗    ██████╗ ███████╗   #
/// #   ██╔══██╗██╔═══██╗    ████╗  ██║██╔═══██╗╚══██╔══╝    ██╔══██╗██╔════╝   #
/// #   ██║  ██║██║   ██║    ██╔██╗ ██║██║   ██║   ██║       ██║  ██║█████╗     #
/// #   ██║  ██║██║   ██║    ██║╚██╗██║██║   ██║   ██║       ██║  ██║██╔══╝     #
/// #   ██████╔╝╚██████╔╝    ██║ ╚████║╚██████╔╝   ██║       ██████╔╝███████╗   #
/// #   ╚═════╝  ╚═════╝     ╚═╝  ╚═══╝ ╚═════╝    ╚═╝       ╚═════╝ ╚══════╝   #
/// #                                                                            #
/// #   ██████╗ ███████╗██████╗ ██╗      ██████╗ ██╗   ██╗██╗                   #
/// #   ██╔══██╗██╔════╝██╔══██╗██║     ██╔═══██╗╚██╗ ██╔╝██║                   #
/// #   ██║  ██║█████╗  ██████╔╝██║     ██║   ██║ ╚████╔╝ ██║                   #
/// #   ██║  ██║██╔══╝  ██╔═══╝ ██║     ██║   ██║  ╚██╔╝  ╚═╝                   #
/// #   ██████╔╝███████╗██║     ███████╗╚██████╔╝   ██║   ██╗                   #
/// #   ╚═════╝ ╚══════╝╚═╝     ╚══════╝ ╚═════╝    ╚═╝   ╚═╝                   #
/// #                                                                            #
/// ##############################################################################
///
/// @title TLOSStopLoss - Hidden Stop-Loss Vault with MEV Protection
/// @author TLOS Project
///
/// @dev CRITICAL: This contract is for DEMONSTRATION ONLY!
///
/// Known issues that make this unsafe for production:
///   1. No real token integration (simplified ETH-only collateral)
///   2. No access control on oracle/circuit addresses
///   3. No price feed validation or staleness checks
///   4. No slippage protection on stop-loss execution
///   5. Simplified trigger logic - production needs more conditions
///   6. No keeper incentives or gas cost reimbursement
///
/// This example ONLY demonstrates the TLOS integration pattern for MEV-resistant
/// stop-loss threshold hiding. For production DeFi, integrate with real DEXs.
///
/// For production TLOS usage, see: contracts/TLOSWithPuzzleV4.sol
///
/// @notice Demonstrates hidden stop-loss triggers using TLOS obfuscation
///
/// ## How This Prevents MEV Front-Running (Paper Section 4.1.1)
///
/// Traditional stop-loss implementations expose trigger prices:
///   - Stop-loss price stored on-chain or derivable from position data
///   - MEV bots monitor price feeds and pending transactions
///   - When price approaches threshold, bots front-run to extract value
///   - Users get worse execution or their stop-loss fails entirely
///
/// TLOS-protected stop-loss hides the trigger inside an obfuscated circuit:
///   - The stop-loss condition is encrypted using LWE-based obfuscation
///   - Attackers cannot determine WHEN a stop-loss will trigger
///   - The circuit takes (oracle_price, user_code) and outputs true/false
///   - Even with full contract access, the threshold remains hidden
///
/// ## Flow Diagram (ASCII)
///
///   User                              Contract                         Oracle
///     |                                  |                               |
///     |  1. deposit(ETH)                 |                               |
///     |--------------------------------->|                               |
///     |                                  |                               |
///     |  2. setStopLossCircuit(addr,code)|                               |
///     |--------------------------------->| stores circuit + userCode     |
///     |                                  |                               |
///     |  [price moves]                   |                               |
///     |                                  |                               |
///     |              Anyone: triggerStopLoss(user)                       |
///     |                                  |-------- getPrice() ---------->|
///     |                                  |<-------- price ---------------|
///     |                                  |                               |
///     |                                  | circuit.check(price, userCode)|
///     |                                  | if true -> return collateral  |
///     |<---------------------------------|                               |
///     |  ETH returned                    |                               |
///
/// Security layers (from full TLOS):
///   1. Topology layer: Structural mixing defeats pattern analysis
///   2. LWE layer: Control function hiding (~2^112 post-quantum security)
///   3. Wire binding: Full-rank linear hash for inter-gate consistency
///   4. Planted LWE puzzle: Forces minimum 2^76 brute-force search

interface IOracle {
    function getPrice() external view returns (uint256);
}

interface ITLOSCircuit {
    function check(bytes32 input) external view returns (bool);
}

contract TLOSStopLoss {
    // =========================================================================
    // STATE - Immutable Configuration
    // =========================================================================
    
    IOracle public immutable oracle;
    address public immutable owner;

    // =========================================================================
    // STATE - Mutable
    // =========================================================================
    
    uint256 private _reentrancyGuard = 1;
    
    struct StopLossPosition {
        uint256 collateral;
        ITLOSCircuit circuit;
        bytes32 userCode;
        bool active;
    }
    
    mapping(address => StopLossPosition) public positions;
    
    uint256 public totalDeposits;
    
    // =========================================================================
    // MODIFIERS
    // =========================================================================
    
    modifier nonReentrant() {
        require(_reentrancyGuard == 1, "Reentrancy");
        _reentrancyGuard = 2;
        _;
        _reentrancyGuard = 1;
    }

    // =========================================================================
    // EVENTS
    // =========================================================================
    
    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event StopLossSet(address indexed user, address circuit, bytes32 userCode);
    event StopLossTriggered(address indexed user, address indexed triggeredBy, uint256 oraclePrice, uint256 collateralReturned);
    event StopLossCancelled(address indexed user);

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================
    
    constructor(address _oracle) {
        require(_oracle != address(0), "Invalid oracle");
        oracle = IOracle(_oracle);
        owner = msg.sender;
    }

    // =========================================================================
    // DEPOSIT / WITHDRAW
    // =========================================================================
    
    function deposit() external payable nonReentrant {
        _deposit(msg.sender, msg.value);
    }
    
    function _deposit(address user, uint256 amount) internal {
        require(amount > 0, "Zero deposit");
        positions[user].collateral += amount;
        totalDeposits += amount;
        emit Deposit(user, amount);
    }
    
    function withdraw(uint256 amount) external nonReentrant {
        StopLossPosition storage pos = positions[msg.sender];
        require(pos.collateral >= amount, "Insufficient collateral");
        require(!pos.active, "Cancel stop-loss first");
        
        pos.collateral -= amount;
        totalDeposits -= amount;
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        emit Withdraw(msg.sender, amount);
    }

    // =========================================================================
    // STOP-LOSS CONFIGURATION
    // =========================================================================
    
    /// @notice Set up a hidden stop-loss condition
    /// @dev The circuit encodes the stop-loss trigger price using TLOS obfuscation.
    ///      The userCode is a secret that, combined with the oracle price,
    ///      determines if the stop-loss should trigger.
    ///
    ///      To create the circuit off-chain:
    ///      1. Define your trigger condition: "trigger if price < $X"
    ///      2. Compile to a TLOS circuit using the compiler
    ///      3. Deploy the circuit and set it here with your userCode
    ///
    /// @param _circuit Address of the deployed TLOS circuit
    /// @param _userCode Secret code that parameterizes the circuit
    function setStopLossCircuit(address _circuit, bytes32 _userCode) external {
        require(_circuit != address(0), "Invalid circuit");
        StopLossPosition storage pos = positions[msg.sender];
        require(pos.collateral > 0, "Deposit first");
        
        pos.circuit = ITLOSCircuit(_circuit);
        pos.userCode = _userCode;
        pos.active = true;
        
        emit StopLossSet(msg.sender, _circuit, _userCode);
    }
    
    /// @notice Cancel an active stop-loss
    /// @dev Allows user to withdraw collateral after cancelling
    function cancelStopLoss() external {
        StopLossPosition storage pos = positions[msg.sender];
        require(pos.active, "No active stop-loss");
        
        pos.active = false;
        pos.circuit = ITLOSCircuit(address(0));
        pos.userCode = bytes32(0);
        
        emit StopLossCancelled(msg.sender);
    }

    // =========================================================================
    // STOP-LOSS TRIGGER
    // =========================================================================
    
    /// @notice Trigger a user's stop-loss if conditions are met
    /// @dev ANYONE can call this - they cannot know if it will succeed.
    ///      The TLOS circuit hides the exact trigger price.
    ///      MEV searchers cannot predict when positions become triggerable.
    ///
    ///      The circuit evaluates: check(keccak256(price, userCode))
    ///      - If true: stop-loss triggers, collateral returned to user
    ///      - If false: transaction reverts, no state change
    ///
    /// @param user The address of the position to trigger
    function triggerStopLoss(address user) external nonReentrant {
        StopLossPosition storage pos = positions[user];
        require(pos.active, "No active stop-loss");
        require(pos.collateral > 0, "No collateral");
        
        uint256 price = oracle.getPrice();
        bytes32 circuitInput = _encodeCircuitInput(price, pos.userCode);
        
        bool shouldTrigger = pos.circuit.check(circuitInput);
        require(shouldTrigger, "Stop-loss condition not met");
        
        uint256 collateralToReturn = pos.collateral;
        
        pos.collateral = 0;
        pos.active = false;
        pos.circuit = ITLOSCircuit(address(0));
        pos.userCode = bytes32(0);
        totalDeposits -= collateralToReturn;
        
        (bool success, ) = user.call{value: collateralToReturn}("");
        require(success, "Transfer failed");
        
        emit StopLossTriggered(user, msg.sender, price, collateralToReturn);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================
    
    /// @notice Check if a stop-loss would trigger at current price
    /// @dev WARNING: This reveals the circuit output! In production,
    ///      users should only call this via eth_call (off-chain).
    ///      MEV bots monitoring this on-chain could front-run.
    function wouldTrigger(address user) external view returns (bool) {
        StopLossPosition storage pos = positions[user];
        if (!pos.active || pos.collateral == 0) return false;
        
        uint256 price = oracle.getPrice();
        bytes32 circuitInput = _encodeCircuitInput(price, pos.userCode);
        return pos.circuit.check(circuitInput);
    }
    
    function getPosition(address user) external view returns (
        uint256 collateral,
        address circuit,
        bytes32 userCode,
        bool active
    ) {
        StopLossPosition storage pos = positions[user];
        return (
            pos.collateral,
            address(pos.circuit),
            pos.userCode,
            pos.active
        );
    }
    
    function getOraclePrice() external view returns (uint256) {
        return oracle.getPrice();
    }

    // =========================================================================
    // INTERNAL
    // =========================================================================
    
    /// @notice Encode price and user code for circuit input
    /// @dev The circuit expects a single bytes32 input.
    ///      This binding ensures the circuit evaluates at the current price.
    function _encodeCircuitInput(uint256 price, bytes32 userCode) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(price, userCode));
    }

    // =========================================================================
    // RECEIVE
    // =========================================================================
    
    receive() external payable {
        _deposit(msg.sender, msg.value);
    }
}
