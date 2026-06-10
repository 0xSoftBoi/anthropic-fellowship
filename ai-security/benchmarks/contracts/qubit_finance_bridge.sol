// Qubit QBridgeHandler (ETH-side handler; deposit() zero-address bug) — verified, Ethereum
// Address: 0x80D1486eF600cc56d4df9ed33bAF53C60D5A629b
// Exploit 2022-01-28 (~$80M): deposit() used safeTransferFrom on tokenAddress that did not revert
// for the zero/whitelisted address, so a 0-value deposit minted qXETH on BSC.

// ===== FILE: contracts/bridge/QBridgeHandler.sol =====
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;
pragma experimental ABIEncoderV2;

/*
      ___       ___       ___       ___       ___
     /\  \     /\__\     /\  \     /\  \     /\  \
    /::\  \   /:/ _/_   /::\  \   _\:\  \    \:\  \
    \:\:\__\ /:/_/\__\ /::\:\__\ /\/::\__\   /::\__\
     \::/  / \:\/:/  / \:\::/  / \::/\/__/  /:/\/__/
     /:/  /   \::/  /   \::/  /   \:\__\    \/__/
     \/__/     \/__/     \/__/     \/__/

*
* MIT License
* ===========
*
* Copyright (c) 2021 QubitFinance
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/math/SafeMath.sol";
import "../interfaces/IQBridgeHandler.sol";
import "../interfaces/IQBridgeDelegator.sol";
import "../library/SafeToken.sol";
import "./QBridgeToken.sol";


contract QBridgeHandler is IQBridgeHandler, OwnableUpgradeable {
    using SafeMath for uint;
    using SafeToken for address;

    /* ========== CONSTANT VARIABLES ========== */

    uint public constant OPTION_QUBIT_BNB_NONE = 100;
    uint public constant OPTION_QUBIT_BNB_0100 = 110;
    uint public constant OPTION_QUBIT_BNB_0050 = 105;
    uint public constant OPTION_BUNNY_XLP_0150 = 215;

    address public constant ETH = 0x0000000000000000000000000000000000000000;

    /* ========== STATE VARIABLES ========== */

    address public _bridgeAddress;

    mapping(bytes32 => address) public resourceIDToTokenContractAddress; // resourceID => token contract address
    mapping(address => bytes32) public tokenContractAddressToResourceID; // token contract address => resourceID

    mapping(address => bool) public burnList; // token contract address => is burnable
    mapping(address => bool) public contractWhitelist; // token contract address => is whitelisted
    mapping(uint => address) public delegators; // option => delegator contract address
    mapping(bytes32 => uint) public withdrawalFees; // resourceID => withdraw fee
    mapping(bytes32 => mapping(uint => uint)) public minAmounts; // [resourceID][option] => minDepositAmount

    /* ========== INITIALIZER ========== */

    receive() external payable {}

    function initialize(address bridgeAddress) external initializer {
        __Ownable_init();
        _bridgeAddress = bridgeAddress;
    }

    /* ========== MODIFIERS ========== */

    modifier onlyBridge() {
        require(msg.sender == _bridgeAddress, "QBridgeHandler: caller is not the bridge contract");
        _;
    }

    /* ========== RESTRICTED FUNCTIONS ========== */

    function setResource(bytes32 resourceID, address contractAddress) external override onlyBridge {
        resourceIDToTokenContractAddress[resourceID] = contractAddress;
        tokenContractAddressToResourceID[contractAddress] = resourceID;
        contractWhitelist[contractAddress] = true;
    }

    function setBurnable(address contractAddress) external override onlyBridge {
        require(contractWhitelist[contractAddress], "QBridgeHandler: contract address is not whitelisted");
        burnList[contractAddress] = true;
    }

    function setDelegator(uint option, address newDelegator) external onlyOwner {
        delegators[option] = newDelegator;
    }

    function setWithdrawalFee(bytes32 resourceID, uint withdrawalFee) external onlyOwner {
        withdrawalFees[resourceID] = withdrawalFee;
    }

    function setMinDepositAmount(bytes32 resourceID, uint option, uint minAmount) external onlyOwner {
        minAmounts[resourceID][option] = minAmount;
    }

    /**
        @notice A deposit is initiated by making a deposit in the Bridge contract.
        @param resourceID ResourceID used to find address of token to be used for deposit.
        @param depositer Address of account making the deposit in the Bridge contract.
        @param data passed into the function should be constructed as follows:
        option                                 uint256     bytes  0 - 32
        amount                                 uint256     bytes  32 - 64
     */
    function deposit(bytes32 resourceID, address depositer, bytes calldata data) external override onlyBridge {
        uint option;
        uint amount;
        (option, amount) = abi.decode(data, (uint, uint));

        address tokenAddress = resourceIDToTokenContractAddress[resourceID];
        require(contractWhitelist[tokenAddress], "provided tokenAddress is not whitelisted");

        if (burnList[tokenAddress]) {
            require(amount >= withdrawalFees[resourceID], "less than withdrawal fee");
            QBridgeToken(tokenAddress).burnFrom(depositer, amount);
        } else {
            require(amount >= minAmounts[resourceID][option], "less than minimum amount");
            tokenAddress.safeTransferFrom(depositer, address(this), amount);
        }
    }

    function depositETH(bytes32 resourceID, address depositer, bytes calldata data) external payable override onlyBridge {
        uint option;
        uint amount;
        (option, amount) = abi.decode(data, (uint, uint));
        require(amount == msg.value);

        address tokenAddress = resourceIDToTokenContractAddress[resourceID];
        require(contractWhitelist[tokenAddress], "provided tokenAddress is not whitelisted");

        require(amount >= minAmounts[resourceID][option], "less than minimum amount");
    }

    /**
        @notice Proposal execution should be initiated by a relayer on the deposit's destination chain.
        @param data passed into the function should be constructed as follows:
        option                                 uint256
        amount                                 uint256
        destinationRecipientAddress            address
     */
    function executeProposal(bytes32 resourceID, bytes calldata data) external override onlyBridge {
        uint option;
        uint amount;
        address recipientAddress;
        (option, amount, recipientAddress) = abi.decode(data, (uint, uint, address));

        address tokenAddress = resourceIDToTokenContractAddress[resourceID];

        require(contractWhitelist[tokenAddress], "provided tokenAddress is not whitelisted");

        if (burnList[tokenAddress]) {
            address delegatorAddress = delegators[option];
            if (delegatorAddress == address(0)) {
                QBridgeToken(tokenAddress).mint(recipientAddress, amount);
            } else {
                QBridgeToken(tokenAddress).mint(delegatorAddress, amount);
                IQBridgeDelegator(delegatorAddress).delegate(tokenAddress, recipientAddress, option, amount);
            }
        } else if (tokenAddress == ETH) {
            SafeToken.safeTransferETH(recipientAddress, amount.sub(withdrawalFees[resourceID]));
        } else {
            tokenAddress.safeTransfer(recipientAddress, amount.sub(withdrawalFees[resourceID]));
        }
    }

    function withdraw(address tokenAddress, address recipient, uint amount) external override onlyBridge {
        if (tokenAddress == ETH)
            SafeToken.safeTransferETH(recipient, amount);
        else
            tokenAddress.safeTransfer(recipient, amount);
    }

}

// ===== FILE: contracts/bridge/QBridgeToken.sol =====
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

/*
      ___       ___       ___       ___       ___
     /\  \     /\__\     /\  \     /\  \     /\  \
    /::\  \   /:/ _/_   /::\  \   _\:\  \    \:\  \
    \:\:\__\ /:/_/\__\ /::\:\__\ /\/::\__\   /::\__\
     \::/  / \:\/:/  / \:\::/  / \::/\/__/  /:/\/__/
     /:/  /   \::/  /   \::/  /   \:\__\    \/__/
     \/__/     \/__/     \/__/     \/__/

*
* MIT License
* ===========
*
* Copyright (c) 2021 QubitFinance
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

import "../library/BEP20Upgradeable.sol";


contract QBridgeToken is BEP20Upgradeable {

    /* ========== STATE VARIABLES ========== */

    mapping(address => bool) private _minters;

    /* ========== MODIFIERS ========== */

    modifier onlyMinter() {
        require(isMinter(msg.sender), "QBridgeToken: caller is not the minter");
        _;
    }

    /* ========== INITIALIZER ========== */

    function initialize(string memory name, string memory symbol, uint8 decimals) external initializer {
        __BEP20__init(name, symbol, decimals);
    }

    /* ========== RESTRICTED FUNCTIONS ========== */

    function setMinter(address minter, bool canMint) external onlyOwner {
        _minters[minter] = canMint;
    }

    function mint(address _to, uint _amount) public onlyMinter {
        _mint(_to, _amount);
    }

    function burnFrom(address account, uint amount) public onlyMinter {
        uint decreasedAllowance = allowance(account, msg.sender).sub(amount, "BEP20: burn amount exceeds allowance");
        _approve(account, _msgSender(), decreasedAllowance);
        _burn(account, amount);
    }

    /* ========== VIEWS ========== */

    function isMinter(address account) public view returns (bool) {
        return _minters[account];
    }
}

// ===== FILE: contracts/interfaces/IQBridgeDelegator.sol =====
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;
pragma experimental ABIEncoderV2;


interface IQBridgeDelegator {

    function delegate(address xToken, address account, uint option, uint amount) external;
}

// ===== FILE: contracts/interfaces/IQBridgeHandler.sol =====
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;
pragma experimental ABIEncoderV2;


interface IQBridgeHandler {
    /**
        @notice Correlates {resourceID} with {contractAddress}.
        @param resourceID ResourceID to be used when making deposits.
        @param contractAddress Address of contract to be called when a deposit is made and a deposited is executed.
     */
    function setResource(bytes32 resourceID, address contractAddress) external;

    /**
        @notice Marks {contractAddress} as mintable/burnable.
        @param contractAddress Address of contract to be used when making or executing deposits.
     */
    function setBurnable(address contractAddress) external;

    /**
        @notice It is intended that deposit are made using the Bridge contract.
        @param depositer Address of account making the deposit in the Bridge contract.
        @param data Consists of additional data needed for a specific deposit.
     */
    function deposit(bytes32 resourceID, address depositer, bytes calldata data) external;
    function depositETH(bytes32 resourceID, address depositer, bytes calldata data) external payable;

    /**
        @notice It is intended that proposals are executed by the Bridge contract.
        @param data Consists of additional data needed for a specific deposit execution.
     */
    function executeProposal(bytes32 resourceID, bytes calldata data) external;

    /**
        @notice Used to manually release funds from ERC safes.
        @param tokenAddress Address of token contract to release.
        @param recipient Address to release tokens to.
        @param amount the amount of ERC20 tokens to release.
     */
    function withdraw(address tokenAddress, address recipient, uint amount) external;
}

// ===== FILE: contracts/library/BEP20Upgradeable.sol =====
// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;

import "@pancakeswap/pancake-swap-lib/contracts/token/BEP20/IBEP20.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/math/SafeMath.sol";

abstract contract BEP20Upgradeable is IBEP20, OwnableUpgradeable {
    using SafeMath for uint;

    mapping(address => uint) private _balances;
    mapping(address => mapping(address => uint)) private _allowances;
    uint private _totalSupply;
    string private _name;
    string private _symbol;
    uint8 private _decimals;

    uint[50] private __gap;

    /**
     * @dev sets initials supply and the owner
     */
    function __BEP20__init(
        string memory name,
        string memory symbol,
        uint8 decimals
    ) internal initializer {
        __Ownable_init();
        _name = name;
        _symbol = symbol;
        _decimals = decimals;
    }

    /**
     * @dev Returns the bep token owner.
     */
    function getOwner() external view override returns (address) {
        return owner();
    }

    /**
     * @dev Returns the token decimals.
     */
    function decimals() external view override returns (uint8) {
        return _decimals;
    }

    /**
     * @dev Returns the token symbol.
     */
    function symbol() external view override returns (string memory) {
        return _symbol;
    }

    /**
     * @dev Returns the token name.
     */
    function name() external view override returns (string memory) {
        return _name;
    }

    /**
     * @dev See {BEP20-totalSupply}.
     */
    function totalSupply() public view override returns (uint) {
        return _totalSupply;
    }

    /**
     * @dev See {BEP20-balanceOf}.
     */
    function balanceOf(address account) public view override returns (uint) {
        return _balances[account];
    }

    /**
     * @dev See {BEP20-transfer}.
     *
     * Requirements:
     *
     * - `recipient` cannot be the zero address.
     * - the caller must have a balance of at least `amount`.
     */
    function transfer(address recipient, uint amount) external override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    /**
     * @dev See {BEP20-allowance}.
     */
    function allowance(address owner, address spender) public view override returns (uint) {
        return _allowances[owner][spender];
    }

    /**
     * @dev See {BEP20-approve}.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function approve(address spender, uint amount) public override returns (bool) {
        _approve(_msgSender(), spender, amount);
        return true;
    }

    /**
     * @dev See {BEP20-transferFrom}.
     *
     * Emits an {Approval} event indicating the updated allowance. This is not
     * required by the EIP. See the note at the beginning of {BEP20};
     *
     * Requirements:
     * - `sender` and `recipient` cannot be the zero address.
     * - `sender` must have a balance of at least `amount`.
     * - the caller must have allowance for `sender`'s tokens of at least
     * `amount`.
     */
    function transferFrom(
        address sender,
        address recipient,
        uint amount
    ) external override returns (bool) {
        _transfer(sender, recipient, amount);
        _approve(
            sender,
            _msgSender(),
            _allowances[sender][_msgSender()].sub(amount, "BEP20: transfer amount exceeds allowance")
        );
        return true;
    }

    /**
     * @dev Atomically increases the allowance granted to `spender` by the caller.
     *
     * This is an alternative to {approve} that can be used as a mitigation for
     * problems described in {BEP20-approve}.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function increaseAllowance(address spender, uint addedValue) public returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].add(addedValue));
        return true;
    }

    /**
     * @dev Atomically decreases the allowance granted to `spender` by the caller.
     *
     * This is an alternative to {approve} that can be used as a mitigation for
     * problems described in {BEP20-approve}.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     * - `spender` must have allowance for the caller of at least
     * `subtractedValue`.
     */
    function decreaseAllowance(address spender, uint subtractedValue) public returns (bool) {
        _approve(
            _msgSender(),
            spender,
            _allowances[_msgSender()][spender].sub(subtractedValue, "BEP20: decreased allowance below zero")
        );
        return true;
    }

    /**
     * @dev Burn `amount` tokens and decreasing the total supply.
     */
    function burn(uint amount) public returns (bool) {
        _burn(_msgSender(), amount);
        return true;
    }

    /**
     * @dev Moves tokens `amount` from `sender` to `recipient`.
     *
     * This is internal function is equivalent to {transfer}, and can be used to
     * e.g. implement automatic token fees, slashing mechanisms, etc.
     *
     * Emits a {Transfer} event.
     *
     * Requirements:
     *
     * - `sender` cannot be the zero address.
     * - `recipient` cannot be the zero address.
     * - `sender` must have a balance of at least `amount`.
     */
    function _transfer(
        address sender,
        address recipient,
        uint amount
    ) internal {
        require(sender != address(0), "BEP20: transfer from the zero address");
        require(recipient != address(0), "BEP20: transfer to the zero address");

        _balances[sender] = _balances[sender].sub(amount, "BEP20: transfer amount exceeds balance");
        _balances[recipient] = _balances[recipient].add(amount);
        emit Transfer(sender, recipient, amount);
    }

    /** @dev Creates `amount` tokens and assigns them to `account`, increasing
     * the total supply.
     *
     * Emits a {Transfer} event with `from` set to the zero address.
     *
     * Requirements
     *
     * - `to` cannot be the zero address.
     */
    function _mint(address account, uint amount) internal {
        require(account != address(0), "BEP20: mint to the zero address");

        _totalSupply = _totalSupply.add(amount);
        _balances[account] = _balances[account].add(amount);
        emit Transfer(address(0), account, amount);
    }

    /**
     * @dev Destroys `amount` tokens from `account`, reducing the
     * total supply.
     *
     * Emits a {Transfer} event with `to` set to the zero address.
     *
     * Requirements
     *
     * - `account` cannot be the zero address.
     * - `account` must have at least `amount` tokens.
     */
    function _burn(address account, uint amount) internal {
        require(account != address(0), "BEP20: burn from the zero address");

        _balances[account] = _balances[account].sub(amount, "BEP20: burn amount exceeds balance");
        _totalSupply = _totalSupply.sub(amount);
        emit Transfer(account, address(0), amount);
    }

    /**
     * @dev Sets `amount` as the allowance of `spender` over the `owner`s tokens.
     *
     * This is internal function is equivalent to `approve`, and can be used to
     * e.g. set automatic allowances for certain subsystems, etc.
     *
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `owner` cannot be the zero address.
     * - `spender` cannot be the zero address.
     */
    function _approve(
        address owner,
        address spender,
        uint amount
    ) internal {
        require(owner != address(0), "BEP20: approve from the zero address");
        require(spender != address(0), "BEP20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    /**
     * @dev Destroys `amount` tokens from `account`.`amount` is then deducted
     * from the caller's allowance.
     *
     * See {_burn} and {_approve}.
     */
    function _burnFrom(address account, uint amount) internal {
        _burn(account, amount);
        _approve(
            account,
            _msgSender(),
            _allowances[account][_msgSender()].sub(amount, "BEP20: burn amount exceeds allowance")
        );
    }
}

// ===== FILE: contracts/library/SafeToken.sol =====
// SPDX-License-Identifier: MIT

pragma solidity ^0.6.12;

interface ERC20Interface {
    function balanceOf(address user) external view returns (uint);
}

library SafeToken {
    function myBalance(address token) internal view returns (uint) {
        return ERC20Interface(token).balanceOf(address(this));
    }

    function balanceOf(address token, address user) internal view returns (uint) {
        return ERC20Interface(token).balanceOf(user);
    }

    function safeApprove(
        address token,
        address to,
        uint value
    ) internal {
        // bytes4(keccak256(bytes('approve(address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x095ea7b3, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), "!safeApprove");
    }

    function safeTransfer(
        address token,
        address to,
        uint value
    ) internal {
        // bytes4(keccak256(bytes('transfer(address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), "!safeTransfer");
    }

    function safeTransferFrom(
        address token,
        address from,
        address to,
        uint value
    ) internal {
        // bytes4(keccak256(bytes('transferFrom(address,address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x23b872dd, from, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), "!safeTransferFrom");
    }

    function safeTransferETH(address to, uint value) internal {
        (bool success, ) = to.call{ value: value }(new bytes(0));
        require(success, "!safeTransferETH");
    }
}
