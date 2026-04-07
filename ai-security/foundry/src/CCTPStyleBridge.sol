// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title CCTPStyleBridge — Simplified Circle CCTP pattern
 * @notice Models Circle's Cross-Chain Transfer Protocol architecture.
 *         CCTP burns USDC on source chain, attests via off-chain service,
 *         then mints on destination chain.
 *
 *         The Drift exploit ($285M, Apr 2026) exposed operational weaknesses:
 *         $232M in stolen USDC bridged via CCTP while Circle had 6 hours to freeze.
 *
 *         Smart contract-level issues we model:
 *           1. Centralized attester — single point of failure
 *           2. No transfer amount limits / rate limiting
 *           3. No freeze-on-suspicious-activity hook
 *           4. No cooldown between burn and mint
 *           5. Attester rotation has no timelock
 */

interface IERC20Burnable {
    function burn(uint256 amount) external;
    function mint(address to, uint256 amount) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract CCTPStyleBridge {
    // ── State ────────────────────────────────────────────────────

    address public attester;              // Signs attestations (centralized)
    address public tokenController;       // Can pause/unpause minting
    IERC20Burnable public usdc;

    uint32 public localDomain;            // Chain identifier
    uint64 public nextNonce;

    mapping(bytes32 => bool) public usedNonces;  // Replay protection
    mapping(uint32 => bool) public enabledDomains; // Supported destination chains

    bool public paused;

    // ── Events ──────────────────────────────────────────────────

    event MessageSent(bytes message);
    event MessageReceived(uint32 sourceDomain, uint64 nonce, address recipient, uint256 amount);
    event AttesterRotated(address oldAttester, address newAttester);

    // ── Constructor ─────────────────────────────────────────────

    constructor(address _usdc, address _attester, uint32 _domain) {
        usdc = IERC20Burnable(_usdc);
        attester = _attester;
        tokenController = msg.sender;
        localDomain = _domain;
    }

    // ── Source chain: burn + emit message ────────────────────────

    /// @notice Burn USDC and emit a cross-chain transfer message
    /// @dev BUG 1: No per-transfer or per-address rate limiting
    ///      The Drift attacker bridged $232M in rapid succession
    function depositForBurn(
        uint256 amount,
        uint32 destinationDomain,
        address mintRecipient
    ) external returns (uint64 nonce) {
        require(!paused, "Paused");
        require(amount > 0, "Zero amount");
        require(enabledDomains[destinationDomain], "Domain not enabled");

        // BUG: No maximum transfer amount
        // BUG: No per-address cooldown
        // BUG: No aggregate volume limit

        usdc.transferFrom(msg.sender, address(this), amount);
        usdc.burn(amount);

        nonce = nextNonce++;

        bytes memory message = abi.encode(
            localDomain,
            destinationDomain,
            nonce,
            msg.sender,
            mintRecipient,
            amount
        );

        emit MessageSent(message);
        return nonce;
    }

    // ── Destination chain: verify attestation + mint ────────────

    /// @notice Receive a message attested by the off-chain service and mint USDC
    /// @dev BUG 2: Single attester — if compromised, all bridges are vulnerable
    ///      BUG 3: No secondary verification or challenge period
    function receiveMessage(
        bytes calldata message,
        bytes calldata attestation
    ) external {
        require(!paused, "Paused");

        // Decode message
        (
            uint32 sourceDomain,
            uint32 destDomain,
            uint64 nonce,
            address sender,
            address recipient,
            uint256 amount
        ) = abi.decode(message, (uint32, uint32, uint64, address, address, uint256));

        require(destDomain == localDomain, "Wrong domain");

        // Replay protection
        bytes32 nonceKey = keccak256(abi.encodePacked(sourceDomain, nonce));
        require(!usedNonces[nonceKey], "Already received");
        usedNonces[nonceKey] = true;

        // BUG: Single attester signature — no threshold, no multisig
        bytes32 messageHash = keccak256(message);
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );

        address signer = _recoverSigner(ethSignedHash, attestation);
        require(signer == attester, "Invalid attestation");

        // BUG: No cooldown/delay between attestation and minting
        // BUG: No amount sanity check (could mint billions)
        usdc.mint(recipient, amount);

        emit MessageReceived(sourceDomain, nonce, recipient, amount);
    }

    // ── Admin functions ─────────────────────────────────────────

    /// @dev BUG 4: No timelock on attester rotation
    ///      If admin key is compromised, attacker can rotate to their own attester
    ///      and forge attestations for arbitrary mints
    function rotateAttester(address newAttester) external {
        require(msg.sender == tokenController, "Not controller");
        // BUG: Takes effect immediately — no timelock
        // BUG: No multisig required for such a critical operation
        emit AttesterRotated(attester, newAttester);
        attester = newAttester;
    }

    function enableDomain(uint32 domain) external {
        require(msg.sender == tokenController, "Not controller");
        enabledDomains[domain] = true;
    }

    function pause() external {
        require(msg.sender == tokenController, "Not controller");
        paused = true;
    }

    function unpause() external {
        require(msg.sender == tokenController, "Not controller");
        paused = false;
    }

    // ── Internal ────────────────────────────────────────────────

    function _recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
