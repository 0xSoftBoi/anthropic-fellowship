// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title WormholeStyleBridge — Simplified Wormhole pattern
/// @notice Reproduces the vulnerability pattern from the Feb 2022 Wormhole
///         exploit ($320M lost). The bridge accepted a user-supplied
///         verification contract address without checking it was the
///         legitimate guardian verifier. Attacker deployed a contract
///         that always returned true.
///
///         Bugs:
///           1. submitVAA accepts arbitrary verificationContract
///           2. withdraw has reentrancy risk (call before full state settle)
contract WormholeStyleBridge {
    address public guardian;
    mapping(bytes32 => bool) public consumedVAAs;
    mapping(address => uint256) public wrappedBalances;

    event VAAProcessed(bytes32 indexed vaaHash, address recipient, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor(address _guardian) {
        guardian = _guardian;
    }

    /// @dev BUG: No validation that verificationContract is the trusted verifier
    function submitVAA(bytes memory vaa, address verificationContract) external {
        (bool valid,) =
            verificationContract.staticcall(abi.encodeWithSignature("verify(bytes)", vaa));
        require(valid, "Invalid VAA");

        bytes32 vaaHash = keccak256(vaa);
        require(!consumedVAAs[vaaHash], "Already consumed");
        consumedVAAs[vaaHash] = true;

        (address recipient, uint256 amount) = abi.decode(vaa, (address, uint256));
        wrappedBalances[recipient] += amount;

        emit VAAProcessed(vaaHash, recipient, amount);
    }

    /// @dev BUG: External call before state is fully settled in broader context
    function withdraw(uint256 amount) external {
        require(wrappedBalances[msg.sender] >= amount, "Insufficient balance");
        wrappedBalances[msg.sender] -= amount;
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        emit Withdrawal(msg.sender, amount);
    }

    receive() external payable {}
}
