// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title NomadStyleReplica — Simplified Nomad Bridge pattern
/// @notice Reproduces the vulnerability pattern from the Aug 2022 Nomad Bridge
///         exploit ($190M lost). A routine upgrade set the trusted Merkle root
///         to 0x00. Since default mapping values are 0, ANY message hash was
///         treated as confirmed. 1175+ copycat txs drained the bridge.
///
///         Bugs:
///           1. initialize() has no access control
///           2. initialize() can be called multiple times (no guard)
///           3. Setting root to 0x00 makes confirmAt[0x00] = 1, so
///              acceptableRoot(0x00) == true, and any unproven message
///              maps to the zero root
///           4. update() has no signature verification
///           5. process() doesn't check that prove() was called first
contract NomadStyleReplica {
    bytes32 public committedRoot;
    mapping(bytes32 => uint256) public confirmAt;
    mapping(bytes32 => bool) public processed;

    uint256 public constant PROCESS_DELAY = 30 minutes;
    address public updater;

    event Initialized(bytes32 root);
    event Updated(bytes32 oldRoot, bytes32 newRoot);
    event Processed(bytes32 messageHash, address recipient, uint256 amount);

    /// @dev BUG 1: No access control — anyone can call
    /// @dev BUG 2: No initializer guard — can be called repeatedly
    /// @dev BUG 3: If _root == 0x00, confirmAt[0x00] = 1, making zero root "confirmed"
    function initialize(bytes32 _root) external {
        committedRoot = _root;
        confirmAt[_root] = 1; // Immediately confirmed
        emit Initialized(_root);
    }

    /// @dev BUG 4: No signature verification on _sig
    function update(bytes32 _oldRoot, bytes32 _newRoot, bytes memory _sig) external {
        require(committedRoot == _oldRoot, "Not current root");
        committedRoot = _newRoot;
        confirmAt[_newRoot] = block.timestamp + PROCESS_DELAY;
        emit Updated(_oldRoot, _newRoot);
    }

    function acceptableRoot(bytes32 _root) public view returns (bool) {
        uint256 _time = confirmAt[_root];
        if (_time == 0) return false;
        return block.timestamp >= _time;
    }

    function prove(
        bytes32 _leaf,
        bytes32[32] calldata _proof,
        uint256 _index
    ) external returns (bool) {
        bytes32 _calc = _leaf;
        for (uint256 i = 0; i < 32; i++) {
            if (_index % 2 == 0) {
                _calc = keccak256(abi.encodePacked(_calc, _proof[i]));
            } else {
                _calc = keccak256(abi.encodePacked(_proof[i], _calc));
            }
            _index /= 2;
        }
        require(acceptableRoot(_calc), "Root not confirmed");
        return true;
    }

    /// @dev BUG 5: No check that prove() was called for this message
    function process(
        bytes32 _messageHash,
        address payable _recipient,
        uint256 _amount
    ) external {
        require(!processed[_messageHash], "Already processed");
        processed[_messageHash] = true;

        (bool success,) = _recipient.call{value: _amount}("");
        require(success, "Transfer failed");
        emit Processed(_messageHash, _recipient, _amount);
    }

    receive() external payable {}
}
