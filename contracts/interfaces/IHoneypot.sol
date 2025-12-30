// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IHoneypot - Common interface for all obfuscation honeypots
/// @notice Defines the standard interface for circuit obfuscation honeypots
/// @dev Uses commit-reveal pattern to prevent front-running by block builders
interface IHoneypot {
    /// @notice Emitted when a commitment is made
    event Committed(address indexed committer, bytes32 indexed commitHash, uint256 blockNumber);
    
    /// @notice Emitted when the honeypot is successfully claimed
    event Claimed(address indexed claimer, bytes32 indexed commitHash, uint256 reward);

    /// @notice Commit to a claim attempt (phase 1 of commit-reveal)
    /// @dev The commit hash MUST be keccak256(abi.encode(msg.sender, input))
    ///      This binds the commitment to your address, preventing front-running
    /// @param commitHash Hash of (sender address, secret input)
    function commit(bytes32 commitHash) external;

    /// @notice Reveal and claim the reward (phase 2 of commit-reveal)
    /// @dev Must wait COMMIT_DELAY blocks after commit before revealing
    ///      Verifies: keccak256(abi.encode(msg.sender, input)) == commitHash
    /// @param input The secret value that satisfies the obfuscated circuit
    function reveal(bytes32 input) external;

    /// @notice Check if input matches the obfuscated secret (view only)
    /// @dev Evaluates the obfuscated circuit with the given input
    ///      WARNING: Do not use this on-chain before committing!
    /// @param input The candidate value (e.g., private key, preimage)
    /// @return success True if input matches the embedded secret
    function check(bytes32 input) external view returns (bool success);

    /// @notice Get commitment info for an address
    /// @param committer The address to check
    /// @return commitHash The committed hash (0 if none)
    /// @return blockNumber The block when committed (0 if none)
    function getCommit(address committer) external view returns (bytes32 commitHash, uint256 blockNumber);

    /// @notice Get the minimum blocks between commit and reveal
    /// @return Number of blocks to wait
    function commitDelay() external pure returns (uint256);

    /// @notice Get the current reward amount
    /// @return The ETH reward in wei
    function reward() external view returns (uint256);

    /// @notice Get the obfuscation scheme identifier
    /// @return Scheme name (e.g., "min-core", "multi-gate-16")
    function scheme() external pure returns (string memory);

    /// @notice Get the number of encrypted gates in this honeypot
    /// @return Number of NTRU/LWE encrypted gates
    function encryptedGates() external pure returns (uint256);

    /// @notice Get estimated gas cost for reveal() call
    /// @return Approximate gas units needed
    function estimatedGas() external pure returns (uint256);
}
