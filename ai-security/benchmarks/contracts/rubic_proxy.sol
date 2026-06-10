// Rubic RubicProxy — verified source, Ethereum
// Address: 0x3332241a5a4eCb4c28239A9731ad45De7f000333
// Exploit 2022-12 (~$1.4M): router whitelist mistakenly included token contracts; unvalidated
// arbitrary call to whitelisted target let attacker transferFrom approved user tokens.

// ===== FILE: contracts/RubicProxy.sol =====
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.10;

/**

  ██████╗ ██╗   ██╗██████╗ ██╗ ██████╗    ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗
  ██╔══██╗██║   ██║██╔══██╗██║██╔════╝    ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝
  ██████╔╝██║   ██║██████╔╝██║██║         ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝
  ██╔══██╗██║   ██║██╔══██╗██║██║         ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝
  ██║  ██║╚██████╔╝██████╔╝██║╚██████╗    ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝ ╚═════╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝

*/

import 'rubic-bridge-base/contracts/architecture/OnlySourceFunctionality.sol';
import 'rubic-bridge-base/contracts/libraries/SmartApprove.sol';

error DifferentAmountSpent();
error RouterNotAvailable();

/**
    @title RubicProxy
    @author Vladislav Yaroshuk t.me/grgred
    @author George Eliseev
    @notice Universal proxy contract to Symbiosis, LiFi, deBridge and other cross-chain solutions
 */
contract RubicProxy is OnlySourceFunctionality {
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    constructor(
        uint256 _fixedCryptoFee,
        uint256 _RubicPlatformFee,
        address[] memory _routers,
        address[] memory _tokens,
        uint256[] memory _minTokenAmounts,
        uint256[] memory _maxTokenAmounts
    ) {
        initialize(_fixedCryptoFee, _RubicPlatformFee, _routers, _tokens, _minTokenAmounts, _maxTokenAmounts);
    }

    function initialize(
        uint256 _fixedCryptoFee,
        uint256 _RubicPlatformFee,
        address[] memory _routers,
        address[] memory _tokens,
        uint256[] memory _minTokenAmounts,
        uint256[] memory _maxTokenAmounts
    ) private initializer {
        __OnlySourceFunctionalityInit(
            _fixedCryptoFee,
            _RubicPlatformFee,
            _routers,
            _tokens,
            _minTokenAmounts,
            _maxTokenAmounts
        );
    }

    function routerCall(
        BaseCrossChainParams calldata _params,
        address _gateway,
        bytes calldata _data
    ) external payable nonReentrant whenNotPaused eventEmitter(_params) {
        if (!(availableRouters.contains(_params.router) && availableRouters.contains(_gateway))) {
            revert RouterNotAvailable();
        }
        IERC20Upgradeable(_params.srcInputToken).safeTransferFrom(msg.sender, address(this), _params.srcInputAmount);

        IntegratorFeeInfo memory _info = integratorToFeeInfo[_params.integrator];

        uint256 _amountIn = accrueTokenFees(
            _params.integrator,
            _info,
            _params.srcInputAmount,
            0,
            _params.srcInputToken
        );

        SmartApprove.smartApprove(_params.srcInputToken, _amountIn, _gateway);

        uint256 balanceBefore = IERC20Upgradeable(_params.srcInputToken).balanceOf(address(this));

        AddressUpgradeable.functionCallWithValue(
            _params.router,
            _data,
            accrueFixedCryptoFee(_params.integrator, _info)
        );

        if (balanceBefore - IERC20Upgradeable(_params.srcInputToken).balanceOf(address(this)) != _amountIn) {
            revert DifferentAmountSpent();
        }
    }

    function routerCallNative(BaseCrossChainParams calldata _params, bytes calldata _data)
        external
        payable
        nonReentrant
        whenNotPaused
        eventEmitter(_params)
    {
        if (!availableRouters.contains(_params.router)) {
            revert RouterNotAvailable();
        }

        IntegratorFeeInfo memory _info = integratorToFeeInfo[_params.integrator];

        uint256 _amountIn = accrueTokenFees(
            _params.integrator,
            _info,
            accrueFixedCryptoFee(_params.integrator, _info),
            0,
            address(0)
        );

        AddressUpgradeable.functionCallWithValue(_params.router, _data, _amountIn);
    }

    function sweepTokens(address _token, uint256 _amount) external onlyAdmin {
        sendToken(_token, _amount, msg.sender);
    }
}

// ===== FILE: rubic-bridge-base/contracts/BridgeBase.sol =====
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import '@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol';
import '@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol';
import '@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol';
import '@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol';
import '@openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol';
import '@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol';

import './libraries/FullMath.sol';

import './errors/Errors.sol';

contract BridgeBase is AccessControlUpgradeable, PausableUpgradeable, ReentrancyGuardUpgradeable {
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Denominator for setting fees
    uint256 internal constant DENOMINATOR = 1e6;

    bytes32 public constant MANAGER_ROLE = keccak256('MANAGER_ROLE');

    // Struct with all info about integrator fees
    mapping(address => IntegratorFeeInfo) public integratorToFeeInfo;
    // Amount of collected fees in native token integrator -> native fees
    mapping(address => uint256) public availableIntegratorCryptoFee;

    // token -> minAmount for swap
    mapping(address => uint256) public minTokenAmount;
    // token -> maxAmount for swap
    mapping(address => uint256) public maxTokenAmount;

    // token -> rubic collected fees
    mapping(address => uint256) public availableRubicTokenFee;
    // token -> integrator collected fees
    mapping(address => mapping(address => uint256)) public availableIntegratorTokenFee;

    // Rubic token fee
    uint256 public RubicPlatformFee;
    // Rubic fixed fee for swap
    uint256 public fixedCryptoFee;
    // Collected rubic fees in native token
    uint256 public availableRubicCryptoFee;

    // AddressSet of whitelisted addresses
    EnumerableSetUpgradeable.AddressSet internal availableRouters;

    event FixedCryptoFee(uint256 RubicPart, uint256 integratorPart, address indexed integrator);
    event FixedCryptoFeeCollected(uint256 amount, address collector);
    event TokenFee(uint256 RubicPart, uint256 integratorPart, address indexed integrator, address token);
    event IntegratorTokenFeeCollected(uint256 amount, address indexed integrator, address token);
    event RubicTokenFeeCollected(uint256 amount, address token);

    struct IntegratorFeeInfo {
        bool isIntegrator; // flag for setting 0 fees for integrator      - 1 byte
        uint32 tokenFee; // total fee percent gathered from user          - 4 bytes
        uint32 RubicTokenShare; // token share of platform commission     - 4 bytes
        uint32 RubicFixedCryptoShare; // native share of fixed commission - 4 bytes
        uint128 fixedFeeAmount; // custom fixed fee amount                - 16 bytes
    } //                                                            total - 29 bytes <= 32 bytes

    struct BaseCrossChainParams {
        address srcInputToken;
        uint256 srcInputAmount;
        uint256 dstChainID;
        address dstOutputToken;
        uint256 dstMinOutputAmount;
        address recipient;
        address integrator;
        address router;
    }

    // reference to https://github.com/OpenZeppelin/openzeppelin-contracts/pull/3347/
    modifier onlyAdmin() {
        checkIsAdmin();
        _;
    }

    modifier onlyManagerOrAdmin() {
        checkIsManagerOrAdmin();
        _;
    }

    modifier onlyEOA() {
        if (msg.sender != tx.origin) {
            revert OnlyEOA();
        }
        _;
    }

    function __BridgeBaseInit(
        uint256 _fixedCryptoFee,
        uint256 _RubicPlatformFee,
        address[] memory _routers,
        address[] memory _tokens,
        uint256[] memory _minTokenAmounts,
        uint256[] memory _maxTokenAmounts
    ) internal onlyInitializing {
        __Pausable_init_unchained();

        fixedCryptoFee = _fixedCryptoFee;

        if (_RubicPlatformFee > DENOMINATOR) {
            revert FeeTooHigh();
        }

        RubicPlatformFee = _RubicPlatformFee;

        uint256 routerLength = _routers.length;
        for (uint256 i; i < routerLength; ) {
            availableRouters.add(_routers[i]);
            unchecked {
                ++i;
            }
        }

        uint256 tokensLength = _tokens.length;
        for (uint256 i; i < tokensLength; ) {
            if (_minTokenAmounts[i] > _maxTokenAmounts[i]) {
                revert MinMustBeLowerThanMax();
            }
            minTokenAmount[_tokens[i]] = _minTokenAmounts[i];
            maxTokenAmount[_tokens[i]] = _maxTokenAmounts[i];
            unchecked {
                ++i;
            }
        }

        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @dev Calculates and accrues fixed crypto fee
     * @param _integrator Integrator's address if there is one
     * @param _info A struct with integrator fee info
     * @return The msg.value without fixedCryptoFee
     */
    function accrueFixedCryptoFee(address _integrator, IntegratorFeeInfo memory _info) internal returns (uint256) {
        uint256 _fixedCryptoFee;
        uint256 _RubicPart;
        if (_info.fixedFeeAmount > 0 && _info.isIntegrator) {
            _fixedCryptoFee = uint256(_info.fixedFeeAmount);
            _RubicPart = (_fixedCryptoFee * _info.RubicFixedCryptoShare) / DENOMINATOR;

            availableIntegratorCryptoFee[_integrator] += _fixedCryptoFee - _RubicPart;

            emit FixedCryptoFee(_RubicPart, _fixedCryptoFee - _RubicPart, _integrator);
        } else {
            _fixedCryptoFee = fixedCryptoFee;

            emit FixedCryptoFee(_fixedCryptoFee, 0, address(0));
        }

        availableRubicCryptoFee += _RubicPart;

        // Underflow is prevented by sol 0.8
        return (msg.value - _fixedCryptoFee);
    }

    /**
     * @dev Calculates token fees and accrues them
     * @param _integrator Integrator's address if there is one
     * @param _info A struct with fee info about integrator
     * @param _amountWithFee Total amount passed by the user
     * @param _token The token in which the fees are collected
     * @param _initBlockchainNum Used if the _calculateFee is overriden by
     * WithDestinationFunctionality, otherwise is ignored
     * @return Amount of tokens without fee
     */
    function accrueTokenFees(
        address _integrator,
        IntegratorFeeInfo memory _info,
        uint256 _amountWithFee,
        uint256 _initBlockchainNum,
        address _token
    ) internal returns (uint256) {
        (uint256 _totalFees, uint256 _RubicFee) = _calculateFee(_info, _amountWithFee, _initBlockchainNum);

        if (_integrator != address(0)) {
            availableIntegratorTokenFee[_token][_integrator] += _totalFees - _RubicFee;
        }
        availableRubicTokenFee[_token] += _RubicFee;

        emit TokenFee(_RubicFee, _totalFees - _RubicFee, _integrator, _token);

        return _amountWithFee - _totalFees;
    }

    /**
     * @dev Calculates fee amount for integrator and rubic, used in architecture
     * @param _amountWithFee the users initial amount
     * @param _info the struct with data about integrator
     * @return _totalFee the amount of Rubic + integrator fee
     * @return _RubicFee the amount of Rubic fee only
     */
    function _calculateFeeWithIntegrator(uint256 _amountWithFee, IntegratorFeeInfo memory _info)
        internal
        pure
        returns (uint256 _totalFee, uint256 _RubicFee)
    {
        if (_info.tokenFee > 0) {
            _totalFee = FullMath.mulDiv(_amountWithFee, _info.tokenFee, DENOMINATOR);

            _RubicFee = FullMath.mulDiv(_totalFee, _info.RubicTokenShare, DENOMINATOR);
        }
    }

    function _calculateFee(
        IntegratorFeeInfo memory _info,
        uint256 _amountWithFee,
        uint256
    ) internal view returns (uint256 _totalFee, uint256 _RubicFee) {
        if (_info.isIntegrator) {
            (_totalFee, _RubicFee) = _calculateFeeWithIntegrator(_amountWithFee, _info);
        } else {
            _totalFee = FullMath.mulDiv(_amountWithFee, RubicPlatformFee, DENOMINATOR);

            _RubicFee = _totalFee;
        }
    }

    /// COLLECT FUNCTIONS ///

    function _collectIntegrator(address _integrator, address _token) private {
        uint256 _amount;

        if (_token == address(0)) {
            _amount = availableIntegratorCryptoFee[_integrator];
            availableIntegratorCryptoFee[_integrator] = 0;
            emit FixedCryptoFeeCollected(_amount, _integrator);
        }

        _amount += availableIntegratorTokenFee[_token][_integrator];

        if (_amount == 0) {
            revert ZeroAmount();
        }

        availableIntegratorTokenFee[_token][_integrator] = 0;

        sendToken(_token, _amount, _integrator);

        emit IntegratorTokenFeeCollected(_amount, _integrator, _token);
    }

    /**
     * @dev Integrator can collect fees calling this function
     * @param _token The token to collect fees in
     */
    function collectIntegratorFee(address _token) external nonReentrant {
        _collectIntegrator(msg.sender, _token);
    }

    /**
     * @dev Managers can collect integrator's fees calling this function
     * Fees go to the integrator
     * @param _integrator Address of the integrator
     * @param _token The token to collect fees in
     */
    function collectIntegratorFee(address _integrator, address _token) external onlyManagerOrAdmin {
        _collectIntegrator(_integrator, _token);
    }

    /**
     * @dev Calling this function managers can collect Rubic's token fee
     * @param _token The token to collect fees in
     */
    function collectRubicFee(address _token) external onlyManagerOrAdmin {
        uint256 _amount = availableRubicTokenFee[_token];
        if (_amount == 0) {
            revert ZeroAmount();
        }

        availableRubicTokenFee[_token] = 0;
        sendToken(_token, _amount, msg.sender);

        emit RubicTokenFeeCollected(_amount, _token);
    }

    /**
     * @dev Calling this function managers can collect Rubic's fixed crypto fee
     */
    function collectRubicCryptoFee() external onlyManagerOrAdmin {
        uint256 _cryptoFee = availableRubicCryptoFee;
        availableRubicCryptoFee = 0;

        sendToken(address(0), _cryptoFee, msg.sender);

        emit FixedCryptoFeeCollected(_cryptoFee, msg.sender);
    }

    /// CONTROL FUNCTIONS ///

    function pauseExecution() external onlyManagerOrAdmin {
        _pause();
    }

    function unpauseExecution() external onlyManagerOrAdmin {
        _unpause();
    }

    /**
     * @dev Sets fee info associated with an integrator
     * @param _integrator Address of the integrator
     * @param _info Struct with fee info
     */
    function setIntegratorInfo(address _integrator, IntegratorFeeInfo memory _info) external onlyManagerOrAdmin {
        if (_info.tokenFee > DENOMINATOR) {
            revert FeeTooHigh();
        }
        if (_info.RubicTokenShare > DENOMINATOR || _info.RubicFixedCryptoShare > DENOMINATOR) {
            revert ShareTooHigh();
        }

        integratorToFeeInfo[_integrator] = _info;
    }

    /**
     * @dev Sets fixed crypto fee
     * @param _fixedCryptoFee Fixed crypto fee
     */
    function setFixedCryptoFee(uint256 _fixedCryptoFee) external onlyManagerOrAdmin {
        fixedCryptoFee = _fixedCryptoFee;
    }

    function setRubicPlatformFee(uint256 _platformFee) external onlyManagerOrAdmin {
        if (_platformFee > DENOMINATOR) {
            revert FeeTooHigh();
        }

        RubicPlatformFee = _platformFee;
    }

    /**
     * @dev Changes requirement for minimal token amount on transfers
     * @param _token The token address to setup
     * @param _minTokenAmount Amount of tokens
     */
    function setMinTokenAmount(address _token, uint256 _minTokenAmount) external onlyManagerOrAdmin {
        if (_minTokenAmount > maxTokenAmount[_token]) {
            // can be equal in case we want them to be zero
            revert MinMustBeLowerThanMax();
        }
        minTokenAmount[_token] = _minTokenAmount;
    }

    /**
     * @dev Changes requirement for maximum token amount on transfers
     * @param _token The token address to setup
     * @param _maxTokenAmount Amount of tokens
     */
    function setMaxTokenAmount(address _token, uint256 _maxTokenAmount) external onlyManagerOrAdmin {
        if (_maxTokenAmount < minTokenAmount[_token]) {
            // can be equal in case we want them to be zero
            revert MaxMustBeBiggerThanMin();
        }
        maxTokenAmount[_token] = _maxTokenAmount;
    }

    /**
     * @dev Appends new available router
     * @param _router Router's address to add
     */
    function addAvailableRouter(address _router) external onlyManagerOrAdmin {
        if (_router == address(0)) {
            revert ZeroAddress();
        }
        // Check that router exists is performed inside the library
        availableRouters.add(_router);
    }

    /**
     * @dev Removes existing available router
     * @param _router Router's address to remove
     */
    function removeAvailableRouter(address _router) external onlyManagerOrAdmin {
        // Check that router exists is performed inside the library
        availableRouters.remove(_router);
    }

    /**
     * @dev Transfers admin role
     * @param _newAdmin New admin's address
     */
    function transferAdmin(address _newAdmin) external onlyAdmin {
        _revokeRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(DEFAULT_ADMIN_ROLE, _newAdmin);
    }

    /// VIEW FUNCTIONS ///

    /**
     * @return Available routers
     */
    function getAvailableRouters() external view returns (address[] memory) {
        return availableRouters.values();
    }

    /**
     * @notice Used in modifiers
     * @dev Function to check if address is belongs to manager or admin role
     */
    function checkIsManagerOrAdmin() internal view {
        if (!(hasRole(MANAGER_ROLE, msg.sender) || hasRole(DEFAULT_ADMIN_ROLE, msg.sender))) {
            revert NotAManager();
        }
    }

    /**
     * @notice Used in modifiers
     * @dev Function to check if address is belongs to default admin role
     */
    function checkIsAdmin() internal view {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotAnAdmin();
        }
    }

    function sendToken(
        address _token,
        uint256 _amount,
        address _receiver
    ) internal virtual {
        if (_token == address(0)) {
            AddressUpgradeable.sendValue(payable(_receiver), _amount);
        } else {
            IERC20Upgradeable(_token).safeTransfer(_receiver, _amount);
        }
    }

    /**
     * @dev Plain fallback function to receive native
     */
    receive() external payable {}

    /**
     * @dev Plain fallback function
     */
    fallback() external {}
}

// ===== FILE: rubic-bridge-base/contracts/architecture/OnlySourceFunctionality.sol =====
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import '../BridgeBase.sol';

contract OnlySourceFunctionality is BridgeBase {
    event RequestSent(BaseCrossChainParams parameters);

    modifier eventEmitter(BaseCrossChainParams calldata _params) {
        _;
        emit RequestSent(_params);
    }

    function __OnlySourceFunctionalityInit(
        uint256 _fixedCryptoFee,
        uint256 _RubicPlatformFee,
        address[] memory _routers,
        address[] memory _tokens,
        uint256[] memory _minTokenAmounts,
        uint256[] memory _maxTokenAmounts
    ) internal onlyInitializing {
        __BridgeBaseInit(_fixedCryptoFee, _RubicPlatformFee, _routers, _tokens, _minTokenAmounts, _maxTokenAmounts);
    }
}

// ===== FILE: rubic-bridge-base/contracts/errors/Errors.sol =====
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

error NotAnAdmin();
error NotAManager();
error NotARelayer();
error OnlyEOA();
error FeeTooHigh();
error ShareTooHigh();
error ZeroAddress();
error ZeroAmount();
error InefficientFixedFee();
error ApproveFailed();
error MinMustBeLowerThanMax();
error MaxMustBeBiggerThanMin();
error CantSetToNull();
error Unchangeable();
error LengthMismatch();

// ===== FILE: rubic-bridge-base/contracts/libraries/FullMath.sol =====
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

/// @title Contains 512-bit math functions
/// @notice Facilitates multiplication and division that can have overflow of an intermediate value without any loss of precision
/// @dev Handles "phantom overflow" i.e., allows multiplication and division where an intermediate value overflows 256 bits
library FullMath {
    /// @notice Calculates floor(a×b÷denominator) with full precision. Throws if result overflows a uint256 or denominator == 0
    /// @param a The multiplicand
    /// @param b The multiplier
    /// @param denominator The divisor
    /// @return result The 256-bit result
    /// @dev Credit to Remco Bloemen under MIT license https://xn--2-umb.com/21/muldiv
    function mulDiv(
        uint256 a,
        uint256 b,
        uint256 denominator
    ) internal pure returns (uint256 result) {
        unchecked {
            // 512-bit multiply [prod1 prod0] = a * b
            // Compute the product mod 2**256 and mod 2**256 - 1
            // then use the Chinese Remainder Theorem to reconstruct
            // the 512 bit result. The result is stored in two 256
            // variables such that product = prod1 * 2**256 + prod0
            uint256 prod0; // Least significant 256 bits of the product
            uint256 prod1; // Most significant 256 bits of the product
            assembly {
                let mm := mulmod(a, b, not(0))
                prod0 := mul(a, b)
                prod1 := sub(sub(mm, prod0), lt(mm, prod0))
            }

            // Handle non-overflow cases, 256 by 256 division
            if (prod1 == 0) {
                require(denominator > 0);
                assembly {
                    result := div(prod0, denominator)
                }
                return result;
            }

            // Make sure the result is less than 2**256.
            // Also prevents denominator == 0
            require(denominator > prod1);

            ///////////////////////////////////////////////
            // 512 by 256 division.
            ///////////////////////////////////////////////

            // Make division exact by subtracting the remainder from [prod1 prod0]
            // Compute remainder using mulmod
            uint256 remainder;
            assembly {
                remainder := mulmod(a, b, denominator)
            }
            // Subtract 256 bit number from 512 bit number
            assembly {
                prod1 := sub(prod1, gt(remainder, prod0))
                prod0 := sub(prod0, remainder)
            }

            // Factor powers of two out of denominator
            // Compute largest power of two divisor of denominator.
            // Always >= 1.
            uint256 twos = (0 - denominator) & denominator;
            // Divide denominator by power of two
            assembly {
                denominator := div(denominator, twos)
            }

            // Divide [prod1 prod0] by the factors of two
            assembly {
                prod0 := div(prod0, twos)
            }
            // Shift in bits from prod1 into prod0. For this we need
            // to flip `twos` such that it is 2**256 / twos.
            // If twos is zero, then it becomes one
            assembly {
                twos := add(div(sub(0, twos), twos), 1)
            }
            prod0 |= prod1 * twos;

            // Invert denominator mod 2**256
            // Now that denominator is an odd number, it has an inverse
            // modulo 2**256 such that denominator * inv = 1 mod 2**256.
            // Compute the inverse by starting with a seed that is correct
            // correct for four bits. That is, denominator * inv = 1 mod 2**4
            uint256 inv = (3 * denominator) ^ 2;
            // Now use Newton-Raphson iteration to improve the precision.
            // Thanks to Hensel's lifting lemma, this also works in modular
            // arithmetic, doubling the correct bits in each step.
            inv *= 2 - denominator * inv; // inverse mod 2**8
            inv *= 2 - denominator * inv; // inverse mod 2**16
            inv *= 2 - denominator * inv; // inverse mod 2**32
            inv *= 2 - denominator * inv; // inverse mod 2**64
            inv *= 2 - denominator * inv; // inverse mod 2**128
            inv *= 2 - denominator * inv; // inverse mod 2**256

            // Because the division is now exact we can divide by multiplying
            // with the modular inverse of denominator. This will give us the
            // correct result modulo 2**256. Since the precoditions guarantee
            // that the outcome is less than 2**256, this is the final result.
            // We don't need to compute the high bits of the result and prod1
            // is no longer required.
            result = prod0 * inv;
            return result;
        }
    }
}

// ===== FILE: rubic-bridge-base/contracts/libraries/SmartApprove.sol =====
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import '@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol';
import '@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol';

import '../errors/Errors.sol';

library SmartApprove {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    function smartApprove(
        address _tokenIn,
        uint256 _amount,
        address _to
    ) internal {
        IERC20Upgradeable tokenIn = IERC20Upgradeable(_tokenIn);
        uint256 _allowance = tokenIn.allowance(address(this), _to);
        if (_allowance < _amount) {
            if (_allowance == 0) {
                tokenIn.safeApprove(_to, type(uint256).max);
            } else {
                try tokenIn.approve(_to, type(uint256).max) returns (bool res) {
                    if (!res) {
                        revert ApproveFailed();
                    }
                } catch {
                    tokenIn.safeApprove(_to, 0);
                    tokenIn.safeApprove(_to, type(uint256).max);
                }
            }
        }
    }
}
