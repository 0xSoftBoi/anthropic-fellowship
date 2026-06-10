// CrossCurve (EYWA) ReceiverAxelar — verified source, Ethereum mainnet
// Address: 0xB2185950F5A0A46687ac331916508aadA202e063
// Exploit 2026-01-31: permissionless expressExecute() reached _execute without
// Axelar Gateway origin validation; spoofed cross-chain messages unlocked PortalV2.
// Source fetched from Blockscout (eth.blockscout.com), flattened to vulnerable path.

// ===== FILE: project/contracts/bridge/receive/ReceiverAxelar.sol =====
// SPDX-License-Identifier: UNLICENSED
// Copyright (c) Eywa.Fi, 2021-2025 - all rights reserved
pragma solidity ^0.8.20;

import { AxelarExpressExecutable } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/express/AxelarExpressExecutable.sol";
import { StringToAddress } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/libs/AddressString.sol";
import "../../interfaces/IReceiver.sol";
import "@openzeppelin/contracts/access/AccessControlEnumerable.sol";


contract ReceiverAxelar is AxelarExpressExecutable, AccessControlEnumerable {

    using StringToAddress for string;
    
    /// @dev address of main receiver, that stores data and hashes
    address public immutable receiver;
    /// @dev operator role id
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    /// @dev approved peers
    mapping(string sourceChain => address peer) public peers;

    event PeerSet(string sourceChain, address peer);


    constructor(address gateway_, address gasService_, address receiver_) AxelarExpressExecutable(gateway_) {
        require(gateway_ != address(0), "ReceiverAxelar: zero address");
        require(gasService_ != address(0), "ReceiverAxelar: zero address");
        require(receiver_ != address(0), "ReceiverAxelar: zero address");
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        receiver = receiver_;
    }

    /**
     * @dev Set peer for source chain
     * 
     * @param sourceChain_ source chain
     * @param peer_ source peer address
     */
    function setPeer(string calldata sourceChain_, address peer_) public onlyRole(OPERATOR_ROLE) {
        peers[sourceChain_] = peer_;
        emit PeerSet(sourceChain_, peer_);
    }

    /**
     * @dev Receive payload from Axelar bridge
     * 
     * @param sourceChain source chain
     * @param sourceAddress  source address, which calls axelar gateway
     * @param payload_ received payload
     */
    function _execute(
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes calldata payload_
    ) internal override {
        require(peers[sourceChain] == sourceAddress.toAddress(), "ReceiverAxelar: wrong peer");
        bytes32 requestId;
        bytes32 sender;
        uint256 chainIdFrom;
        uint256 length = payload_.length - 1;
        bytes memory data = new bytes(length);
        for (uint i; i < length; ++i) {
            data[i] = payload_[i];
        }

        if (payload_[payload_.length - 1] == 0x01) {
            require(data.length == 128, "ReceiverAxelar: Invalid message length");
            bytes32 payload;
            (payload, sender, chainIdFrom, requestId) = abi.decode(data, (bytes32, bytes32, uint256, bytes32));
            IReceiver(receiver).receiveHash(sender, uint64(chainIdFrom), payload, requestId);
        } else if (payload_[payload_.length - 1] == 0x00) {
            bytes memory payload;
            (payload, sender, chainIdFrom, requestId) = abi.decode(data, (bytes, bytes32, uint256, bytes32));
            IReceiver(receiver).receiveData(sender, uint64(chainIdFrom), payload, requestId);
        } else {
            revert("ReceiverAxelar: wrong message");
        }
    }
}

// ===== FILE: npm/@axelar-network/axelar-gmp-sdk-solidity@5.10.0/contracts/express/AxelarExpressExecutable.sol =====
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import { IAxelarGateway } from '../interfaces/IAxelarGateway.sol';
import { ExpressExecutorTracker } from './ExpressExecutorTracker.sol';

import { SafeTokenTransferFrom, SafeTokenTransfer } from '../libs/SafeTransfer.sol';
import { IERC20 } from '../interfaces/IERC20.sol';

contract AxelarExpressExecutable is ExpressExecutorTracker {
    using SafeTokenTransfer for IERC20;
    using SafeTokenTransferFrom for IERC20;

    IAxelarGateway public immutable gateway;

    constructor(address gateway_) {
        if (gateway_ == address(0)) revert InvalidAddress();

        gateway = IAxelarGateway(gateway_);
    }

    function execute(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes calldata payload
    ) external {
        bytes32 payloadHash = keccak256(payload);

        if (!gateway.validateContractCall(commandId, sourceChain, sourceAddress, payloadHash))
            revert NotApprovedByGateway();

        address expressExecutor = _popExpressExecutor(commandId, sourceChain, sourceAddress, payloadHash);

        if (expressExecutor != address(0)) {
            // slither-disable-next-line reentrancy-events
            emit ExpressExecutionFulfilled(commandId, sourceChain, sourceAddress, payloadHash, expressExecutor);
        } else {
            _execute(sourceChain, sourceAddress, payload);
        }
    }

    function executeWithToken(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes calldata payload,
        string calldata tokenSymbol,
        uint256 amount
    ) external {
        bytes32 payloadHash = keccak256(payload);
        if (
            !gateway.validateContractCallAndMint(
                commandId,
                sourceChain,
                sourceAddress,
                payloadHash,
                tokenSymbol,
                amount
            )
        ) revert NotApprovedByGateway();

        address expressExecutor = _popExpressExecutorWithToken(
            commandId,
            sourceChain,
            sourceAddress,
            payloadHash,
            tokenSymbol,
            amount
        );

        if (expressExecutor != address(0)) {
            // slither-disable-next-line reentrancy-events
            emit ExpressExecutionWithTokenFulfilled(
                commandId,
                sourceChain,
                sourceAddress,
                payloadHash,
                tokenSymbol,
                amount,
                expressExecutor
            );

            address gatewayToken = gateway.tokenAddresses(tokenSymbol);
            IERC20(gatewayToken).safeTransfer(expressExecutor, amount);
        } else {
            _executeWithToken(sourceChain, sourceAddress, payload, tokenSymbol, amount);
        }
    }

    function expressExecute(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes calldata payload
    ) external payable virtual {
        if (gateway.isCommandExecuted(commandId)) revert AlreadyExecuted();

        address expressExecutor = msg.sender;
        bytes32 payloadHash = keccak256(payload);

        emit ExpressExecuted(commandId, sourceChain, sourceAddress, payloadHash, expressExecutor);

        _setExpressExecutor(commandId, sourceChain, sourceAddress, payloadHash, expressExecutor);

        _execute(sourceChain, sourceAddress, payload);
    }

    function expressExecuteWithToken(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes calldata payload,
        string calldata symbol,
        uint256 amount
    ) external payable virtual {
        if (gateway.isCommandExecuted(commandId)) revert AlreadyExecuted();

        address expressExecutor = msg.sender;
        address gatewayToken = gateway.tokenAddresses(symbol);
        bytes32 payloadHash = keccak256(payload);

        emit ExpressExecutedWithToken(
            commandId,
            sourceChain,
            sourceAddress,
            payloadHash,
            symbol,
            amount,
            expressExecutor
        );

        _setExpressExecutorWithToken(
            commandId,
            sourceChain,
            sourceAddress,
            payloadHash,
            symbol,
            amount,
            expressExecutor
        );

        IERC20(gatewayToken).safeTransferFrom(expressExecutor, address(this), amount);

        _executeWithToken(sourceChain, sourceAddress, payload, symbol, amount);
    }

    function _execute(
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes calldata payload
    ) internal virtual {}

    function _executeWithToken(
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes calldata payload,
        string calldata tokenSymbol,
        uint256 amount
    ) internal virtual {}
}

// ===== FILE: npm/@axelar-network/axelar-gmp-sdk-solidity@5.10.0/contracts/express/ExpressExecutorTracker.sol =====
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import { IAxelarExpressExecutable } from '../interfaces/IAxelarExpressExecutable.sol';

abstract contract ExpressExecutorTracker is IAxelarExpressExecutable {
    bytes32 internal constant PREFIX_EXPRESS_EXECUTE = keccak256('express-execute');
    bytes32 internal constant PREFIX_EXPRESS_EXECUTE_WITH_TOKEN = keccak256('express-execute-with-token');

    function _expressExecuteSlot(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash
    ) internal pure returns (bytes32 slot) {
        slot = keccak256(abi.encode(PREFIX_EXPRESS_EXECUTE, commandId, sourceChain, sourceAddress, payloadHash));
    }

    function _expressExecuteWithTokenSlot(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash,
        string calldata symbol,
        uint256 amount
    ) internal pure returns (bytes32 slot) {
        slot = keccak256(
            abi.encode(
                PREFIX_EXPRESS_EXECUTE_WITH_TOKEN,
                commandId,
                sourceChain,
                sourceAddress,
                payloadHash,
                symbol,
                amount
            )
        );
    }

    function getExpressExecutor(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash
    ) external view returns (address expressExecutor) {
        bytes32 slot = _expressExecuteSlot(commandId, sourceChain, sourceAddress, payloadHash);

        assembly {
            expressExecutor := sload(slot)
        }
    }

    function getExpressExecutorWithToken(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash,
        string calldata symbol,
        uint256 amount
    ) external view returns (address expressExecutor) {
        bytes32 slot = _expressExecuteWithTokenSlot(commandId, sourceChain, sourceAddress, payloadHash, symbol, amount);

        assembly {
            expressExecutor := sload(slot)
        }
    }

    function _setExpressExecutor(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash,
        address expressExecutor
    ) internal {
        bytes32 slot = _expressExecuteSlot(commandId, sourceChain, sourceAddress, payloadHash);
        address currentExecutor;

        assembly {
            currentExecutor := sload(slot)
        }

        if (currentExecutor != address(0)) revert ExpressExecutorAlreadySet();

        assembly {
            sstore(slot, expressExecutor)
        }
    }

    function _setExpressExecutorWithToken(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash,
        string calldata symbol,
        uint256 amount,
        address expressExecutor
    ) internal {
        bytes32 slot = _expressExecuteWithTokenSlot(commandId, sourceChain, sourceAddress, payloadHash, symbol, amount);
        address currentExecutor;

        assembly {
            currentExecutor := sload(slot)
        }

        if (currentExecutor != address(0)) revert ExpressExecutorAlreadySet();

        assembly {
            sstore(slot, expressExecutor)
        }
    }

    function _popExpressExecutor(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash
    ) internal returns (address expressExecutor) {
        bytes32 slot = _expressExecuteSlot(commandId, sourceChain, sourceAddress, payloadHash);

        assembly {
            expressExecutor := sload(slot)
            if expressExecutor {
                sstore(slot, 0)
            }
        }
    }

    function _popExpressExecutorWithToken(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash,
        string calldata symbol,
        uint256 amount
    ) internal returns (address expressExecutor) {
        bytes32 slot = _expressExecuteWithTokenSlot(commandId, sourceChain, sourceAddress, payloadHash, symbol, amount);

        assembly {
            expressExecutor := sload(slot)
            if expressExecutor {
                sstore(slot, 0)
            }
        }
    }
}

// ===== FILE: npm/@axelar-network/axelar-gmp-sdk-solidity@5.10.0/contracts/interfaces/IAxelarExpressExecutable.sol =====
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import { IAxelarExecutable } from './IAxelarExecutable.sol';

/**
 * @title IAxelarExpressExecutable
 * @notice Interface for the Axelar Express Executable contract.
 */
interface IAxelarExpressExecutable is IAxelarExecutable {
    // Custom errors
    error AlreadyExecuted();
    error InsufficientValue();
    error ExpressExecutorAlreadySet();

    /**
     * @notice Emitted when an express execution is successfully performed.
     * @param commandId The unique identifier for the command.
     * @param sourceChain The source chain.
     * @param sourceAddress The source address.
     * @param payloadHash The hash of the payload.
     * @param expressExecutor The address of the express executor.
     */
    event ExpressExecuted(
        bytes32 indexed commandId,
        string sourceChain,
        string sourceAddress,
        bytes32 payloadHash,
        address indexed expressExecutor
    );

    /**
     * @notice Emitted when an express execution with a token is successfully performed.
     * @param commandId The unique identifier for the command.
     * @param sourceChain The source chain.
     * @param sourceAddress The source address.
     * @param payloadHash The hash of the payload.
     * @param symbol The token symbol.
     * @param amount The amount of tokens.
     * @param expressExecutor The address of the express executor.
     */
    event ExpressExecutedWithToken(
        bytes32 indexed commandId,
        string sourceChain,
        string sourceAddress,
        bytes32 payloadHash,
        string symbol,
        uint256 indexed amount,
        address indexed expressExecutor
    );

    /**
     * @notice Emitted when an express execution is fulfilled.
     * @param commandId The commandId for the contractCall.
     * @param sourceChain The source chain.
     * @param sourceAddress The source address.
     * @param payloadHash The hash of the payload.
     * @param expressExecutor The address of the express executor.
     */
    event ExpressExecutionFulfilled(
        bytes32 indexed commandId,
        string sourceChain,
        string sourceAddress,
        bytes32 payloadHash,
        address indexed expressExecutor
    );

    /**
     * @notice Emitted when an express execution with a token is fulfilled.
     * @param commandId The commandId for the contractCallWithToken.
     * @param sourceChain The source chain.
     * @param sourceAddress The source address.
     * @param payloadHash The hash of the payload.
     * @param symbol The token symbol.
     * @param amount The amount of tokens.
     * @param expressExecutor The address of the express executor.
     */
    event ExpressExecutionWithTokenFulfilled(
        bytes32 indexed commandId,
        string sourceChain,
        string sourceAddress,
        bytes32 payloadHash,
        string symbol,
        uint256 indexed amount,
        address indexed expressExecutor
    );

    /**
     * @notice Returns the express executor for a given command.
     * @param commandId The commandId for the contractCall.
     * @param sourceChain The source chain.
     * @param sourceAddress The source address.
     * @param payloadHash The hash of the payload.
     * @return expressExecutor The address of the express executor.
     */
    function getExpressExecutor(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash
    ) external view returns (address expressExecutor);

    /**
     * @notice Returns the express executor with token for a given command.
     * @param commandId The commandId for the contractCallWithToken.
     * @param sourceChain The source chain.
     * @param sourceAddress The source address.
     * @param payloadHash The hash of the payload.
     * @param symbol The token symbol.
     * @param amount The amount of tokens.
     * @return expressExecutor The address of the express executor.
     */
    function getExpressExecutorWithToken(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash,
        string calldata symbol,
        uint256 amount
    ) external view returns (address expressExecutor);

    /**
     * @notice Express executes a contract call.
     * @param commandId The commandId for the contractCall.
     * @param sourceChain The source chain.
     * @param sourceAddress The source address.
     * @param payload The payload data.
     */
    function expressExecute(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes calldata payload
    ) external payable;

    /**
     * @notice Express executes a contract call with token.
     * @param commandId The commandId for the contractCallWithToken.
     * @param sourceChain The source chain.
     * @param sourceAddress The source address.
     * @param payload The payload data.
     * @param symbol The token symbol.
     * @param amount The amount of token.
     */
    function expressExecuteWithToken(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes calldata payload,
        string calldata symbol,
        uint256 amount
    ) external payable;
}

// ===== FILE: npm/@axelar-network/axelar-gmp-sdk-solidity@5.10.0/contracts/interfaces/IAxelarGateway.sol =====
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import { IGovernable } from './IGovernable.sol';
import { IImplementation } from './IImplementation.sol';

interface IAxelarGateway is IImplementation, IGovernable {
    /**********\
    |* Errors *|
    \**********/

    error NotSelf();
    error InvalidCodeHash();
    error SetupFailed();
    error InvalidAuthModule();
    error InvalidTokenDeployer();
    error InvalidAmount();
    error InvalidChainId();
    error InvalidCommands();
    error TokenDoesNotExist(string symbol);
    error TokenAlreadyExists(string symbol);
    error TokenDeployFailed(string symbol);
    error TokenContractDoesNotExist(address token);
    error BurnFailed(string symbol);
    error MintFailed(string symbol);
    error InvalidSetMintLimitsParams();
    error ExceedMintLimit(string symbol);

    /**********\
    |* Events *|
    \**********/

    event TokenSent(
        address indexed sender,
        string destinationChain,
        string destinationAddress,
        string symbol,
        uint256 amount
    );

    event ContractCall(
        address indexed sender,
        string destinationChain,
        string destinationContractAddress,
        bytes32 indexed payloadHash,
        bytes payload
    );

    event ContractCallWithToken(
        address indexed sender,
        string destinationChain,
        string destinationContractAddress,
        bytes32 indexed payloadHash,
        bytes payload,
        string symbol,
        uint256 amount
    );

    event Executed(bytes32 indexed commandId);

    event TokenDeployed(string symbol, address tokenAddresses);

    event ContractCallApproved(
        bytes32 indexed commandId,
        string sourceChain,
        string sourceAddress,
        address indexed contractAddress,
        bytes32 indexed payloadHash,
        bytes32 sourceTxHash,
        uint256 sourceEventIndex
    );

    event ContractCallApprovedWithMint(
        bytes32 indexed commandId,
        string sourceChain,
        string sourceAddress,
        address indexed contractAddress,
        bytes32 indexed payloadHash,
        string symbol,
        uint256 amount,
        bytes32 sourceTxHash,
        uint256 sourceEventIndex
    );

    event ContractCallExecuted(bytes32 indexed commandId);

    event TokenMintLimitUpdated(string symbol, uint256 limit);

    event OperatorshipTransferred(bytes newOperatorsData);

    event Upgraded(address indexed implementation);

    /********************\
    |* Public Functions *|
    \********************/

    function sendToken(
        string calldata destinationChain,
        string calldata destinationAddress,
        string calldata symbol,
        uint256 amount
    ) external;

    function callContract(
        string calldata destinationChain,
        string calldata contractAddress,
        bytes calldata payload
    ) external;

    function callContractWithToken(
        string calldata destinationChain,
        string calldata contractAddress,
        bytes calldata payload,
        string calldata symbol,
        uint256 amount
    ) external;

    function isContractCallApproved(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        address contractAddress,
        bytes32 payloadHash
    ) external view returns (bool);

    function isContractCallAndMintApproved(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        address contractAddress,
        bytes32 payloadHash,
        string calldata symbol,
        uint256 amount
    ) external view returns (bool);

    function validateContractCall(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash
    ) external returns (bool);

    function validateContractCallAndMint(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash,
        string calldata symbol,
        uint256 amount
    ) external returns (bool);

    /***********\
    |* Getters *|
    \***********/

    function authModule() external view returns (address);

    function tokenDeployer() external view returns (address);

    function tokenMintLimit(string memory symbol) external view returns (uint256);

    function tokenMintAmount(string memory symbol) external view returns (uint256);

    function allTokensFrozen() external view returns (bool);

    function implementation() external view returns (address);

    function tokenAddresses(string memory symbol) external view returns (address);

    function tokenFrozen(string memory symbol) external view returns (bool);

    function isCommandExecuted(bytes32 commandId) external view returns (bool);

    /************************\
    |* Governance Functions *|
    \************************/

    function setTokenMintLimits(string[] calldata symbols, uint256[] calldata limits) external;

    function upgrade(
        address newImplementation,
        bytes32 newImplementationCodeHash,
        bytes calldata setupParams
    ) external;

    /**********************\
    |* External Functions *|
    \**********************/

    function execute(bytes calldata input) external;
}

// ===== FILE: npm/@axelar-network/axelar-gmp-sdk-solidity@5.10.0/contracts/libs/AddressString.sol =====
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

library StringToAddress {
    error InvalidAddressString();

    function toAddress(string memory addressString) internal pure returns (address) {
        bytes memory stringBytes = bytes(addressString);
        uint160 addressNumber = 0;
        uint8 stringByte;

        if (stringBytes.length != 42 || stringBytes[0] != '0' || stringBytes[1] != 'x') revert InvalidAddressString();

        for (uint256 i = 2; i < 42; ++i) {
            stringByte = uint8(stringBytes[i]);

            if ((stringByte >= 97) && (stringByte <= 102)) stringByte -= 87;
            else if ((stringByte >= 65) && (stringByte <= 70)) stringByte -= 55;
            else if ((stringByte >= 48) && (stringByte <= 57)) stringByte -= 48;
            else revert InvalidAddressString();

            addressNumber |= uint160(uint256(stringByte) << ((41 - i) << 2));
        }

        return address(addressNumber);
    }
}

library AddressToString {
    function toString(address address_) internal pure returns (string memory) {
        bytes memory addressBytes = abi.encodePacked(address_);
        bytes memory characters = '0123456789abcdef';
        bytes memory stringBytes = new bytes(42);

        stringBytes[0] = '0';
        stringBytes[1] = 'x';

        for (uint256 i; i < 20; ++i) {
            stringBytes[2 + i * 2] = characters[uint8(addressBytes[i] >> 4)];
            stringBytes[3 + i * 2] = characters[uint8(addressBytes[i] & 0x0f)];
        }

        return string(stringBytes);
    }
}

// ===== FILE: project/contracts/interfaces/IReceiver.sol =====
// SPDX-License-Identifier: UNLICENSED
// Copyright (c) Eywa.Fi, 2021-2025 - all rights reserved
pragma solidity ^0.8.20;


interface IReceiver {
    function receiveData(bytes32 sender, uint64 chainIdFrom, bytes memory receivedData, bytes32 requestId) external;
    function receiveHash(bytes32 sender, uint64 chainIdFrom, bytes32 receivedHash, bytes32 requestId) external;
}
