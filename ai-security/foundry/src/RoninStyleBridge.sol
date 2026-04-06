// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title RoninStyleBridge — Simplified Ronin Bridge pattern
/// @notice Reproduces the vulnerability pattern from the Mar 2022 Ronin Bridge
///         exploit ($625M lost). 5 of 9 validator keys compromised via social
///         engineering. Low threshold + no duplicate signer check + no rate
///         limiting + unprotected admin function.
///
///         Bugs:
///           1. No minimum threshold requirement
///           2. No duplicate signer check in withdraw
///           3. No withdrawal rate limiting
///           4. updateValidators has no access control
///           5. No withdrawal delay / timelock
contract RoninStyleBridge {
    address[] public validators;
    uint256 public threshold;
    uint256 public nonce;

    mapping(uint256 => bool) public processedNonces;

    event Withdrawal(address recipient, uint256 amount, uint256 nonce);
    event ValidatorsUpdated(uint256 newCount, uint256 newThreshold);

    /// @dev BUG 1: No minimum threshold check (could be 1)
    constructor(address[] memory _validators, uint256 _threshold) {
        require(_threshold <= _validators.length, "Invalid threshold");
        validators = _validators;
        threshold = _threshold;
    }

    function withdraw(
        address payable recipient,
        uint256 amount,
        uint256 _nonce,
        bytes[] memory signatures
    ) external {
        require(!processedNonces[_nonce], "Already processed");
        require(signatures.length >= threshold, "Not enough signatures");

        bytes32 message = keccak256(abi.encodePacked(recipient, amount, _nonce));
        bytes32 ethSignedMessage =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));

        uint256 validCount = 0;

        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = recoverSigner(ethSignedMessage, signatures[i]);

            // BUG 2: No check for duplicate signers — same key can sign multiple times
            if (isValidator(signer)) {
                validCount++;
            }
        }

        require(validCount >= threshold, "Insufficient valid signatures");

        processedNonces[_nonce] = true;

        // BUG 3: No rate limiting — single tx drains entire bridge
        (bool success,) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
        emit Withdrawal(recipient, amount, _nonce);
    }

    /// @dev BUG 4: No access control — anyone can replace all validators
    function updateValidators(address[] memory _newValidators, uint256 _newThreshold) external {
        validators = _newValidators;
        threshold = _newThreshold;
        emit ValidatorsUpdated(_newValidators.length, _newThreshold);
    }

    function isValidator(address _addr) public view returns (bool) {
        for (uint256 i = 0; i < validators.length; i++) {
            if (validators[i] == _addr) return true;
        }
        return false;
    }

    function recoverSigner(bytes32 _hash, bytes memory _sig) internal pure returns (address) {
        require(_sig.length == 65, "Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(_sig, 32))
            s := mload(add(_sig, 64))
            v := byte(0, mload(add(_sig, 96)))
        }
        return ecrecover(_hash, v, r, s);
    }

    function validatorCount() external view returns (uint256) {
        return validators.length;
    }

    receive() external payable {}
}
