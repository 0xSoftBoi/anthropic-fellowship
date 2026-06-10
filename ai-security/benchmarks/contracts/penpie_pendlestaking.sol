// Penpie PendleStaking (impl behind proxy 0x6E79...3652) — verified source, Ethereum
// Address: 0x86A499D84E355D2Cb41851d91425c86Eb2758627
// Exploit 2024-09-03 (~$27M): reentrancy in batchHarvestMarketRewards via attacker-registered
// Pendle market with malicious SY token re-entering depositMarket; reward accounting inflated.

// ===== FILE: contracts/pendle/PendleStaking.sol =====
// SPDX-License-Identifier: MIT
pragma solidity =0.8.19;
pragma abicoder v2;

import { IERC20, ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import { PendleStakingBaseUpg } from "./PendleStakingBaseUpg.sol";
import { IPVotingEscrowMainchain } from "../interfaces/pendle/IPVotingEscrowMainchain.sol";
import { IPFeeDistributorV2 } from "../interfaces/pendle/IPFeeDistributorV2.sol";
import { IPVoteController } from "../interfaces/pendle/IPVoteController.sol";

import "../interfaces/IConvertor.sol";
import "../libraries/ERC20FactoryLib.sol";
import "../libraries/WeekMath.sol";

/// @title PendleStaking
/// @notice PendleStaking is the main contract that holds vePendle position on behalf on user to get boosted yield and vote.
///         PendleStaking is the main contract interacting with Pendle Finance side
/// @author Magpie Team

contract PendleStaking is PendleStakingBaseUpg {
    using SafeERC20 for IERC20;

    uint256 public lockPeriod;

    /* ============ Events ============ */
    event SetLockDays(uint256 _oldLockDays, uint256 _newLockDays);

    constructor() {_disableInitializers();}

    function __PendleStaking_init(
        address _pendle,
        address _WETH,
        address _vePendle,
        address _distributorETH,
        address _pendleRouter,
        address _masterPenpie
    ) public initializer {
        __PendleStakingBaseUpg_init(
            _pendle,
            _WETH,
            _vePendle,
            _distributorETH,
            _pendleRouter,
            _masterPenpie
        );
        lockPeriod = 720 * 86400;
    }

    /// @notice get the penpie claimable revenue share in ETH
    function totalUnclaimedETH() external view returns (uint256) {
        return distributorETH.getProtocolTotalAccrued(address(this));
    }

    /* ============ VePendle Related Functions ============ */

    function vote(
        address[] calldata _pools,
        uint64[] calldata _weights
    ) external override nonReentrant {
        if (msg.sender != voteManager) revert OnlyVoteManager();
        if (_pools.length != _weights.length) revert LengthMismatch();

        IPVoteController(pendleVote).vote(_pools, _weights);
    }

    function bootstrapVePendle(uint256[] calldata chainId) payable external onlyOwner returns( uint256 ) {
        uint256 amount = IERC20(PENDLE).balanceOf(address(this));
        IERC20(PENDLE).safeApprove(address(vePendle), amount);
        uint128 lockTime = _getIncreaseLockTime();
        return IPVotingEscrowMainchain(vePendle).increaseLockPositionAndBroadcast{value:msg.value}(uint128(amount), lockTime, chainId);
    }

    /// @notice convert PENDLE to mPendle
    /// @param _amount the number of Pendle to convert
    /// @dev the Pendle must already be in the contract
    function convertPendle(
        uint256 _amount,
        uint256[] calldata chainId
    ) public payable override nonReentrant whenNotPaused returns (uint256) {
        uint256 preVePendleAmount = accumulatedVePendle();
        if (_amount == 0) revert ZeroNotAllowed();

        IERC20(PENDLE).safeTransferFrom(msg.sender, address(this), _amount);
        IERC20(PENDLE).safeApprove(address(vePendle), _amount);

        uint128 unlockTime = _getIncreaseLockTime();
        IPVotingEscrowMainchain(vePendle).increaseLockPositionAndBroadcast{value:msg.value}(uint128(_amount), unlockTime, chainId);

        uint256 mintedVePendleAmount = accumulatedVePendle() -
            preVePendleAmount;
        emit PendleLocked(_amount, lockPeriod, mintedVePendleAmount);

        return mintedVePendleAmount;
    }

    function increaseLockTime(uint256 _unlockTime) external nonReentrant {
        uint128 unlockTime = WeekMath.getWeekStartTimestamp(
            uint128(block.timestamp + _unlockTime)
        );
        IPVotingEscrowMainchain(vePendle).increaseLockPosition(0, unlockTime);
    }

    function harvestVePendleReward(address[] calldata _pools) external nonReentrant {
        if (this.totalUnclaimedETH() == 0) {
            revert NoVePendleReward();
        }

        if (
            (protocolFee != 0 && feeCollector == address(0)) ||
            bribeManagerEOA == address(0)
        ) revert InvalidFeeDestination();

        (uint256 totalAmountOut, uint256[] memory amountsOut) = distributorETH
            .claimProtocol(address(this), _pools);
        // for protocol
        uint256 fee = (totalAmountOut * protocolFee) / DENOMINATOR;
        IERC20(WETH).safeTransfer(feeCollector, fee);

        // for caller
        uint256 callerFeeAmount = (totalAmountOut * vePendleHarvestCallerFee) /
            DENOMINATOR;
        IERC20(WETH).safeTransfer(msg.sender, callerFeeAmount);

        uint256 left = totalAmountOut - fee - callerFeeAmount;
        IERC20(WETH).safeTransfer(bribeManagerEOA, left);

        emit VePendleHarvested(
            totalAmountOut,
            _pools,
            amountsOut,
            fee,
            callerFeeAmount,
            left
        );
    }

    /* ============ Admin Functions ============ */

    function setLockDays(uint256 _newLockPeriod) external onlyOwner {
        uint256 oldLockPeriod = lockPeriod;
        lockPeriod = _newLockPeriod;

        emit SetLockDays(oldLockPeriod, lockPeriod);
    }

    /* ============ Internal Functions ============ */

    function _getIncreaseLockTime() internal view returns (uint128) {
        return
            WeekMath.getWeekStartTimestamp(
                uint128(block.timestamp + lockPeriod)
            );
    }
}

// ===== FILE: contracts/interfaces/IBribeRewardDistributor.sol =====
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IBribeRewardDistributor {
    struct Claimable {
        address token;
        uint256 amount;
    }

    struct Claim {
        address token;
        address account;
        uint256 amount;
        bytes32[] merkleProof;
    }

    function getClaimable(Claim[] calldata _claims) external view returns(Claimable[] memory);

    function claim(Claim[] calldata _claims) external;
}
// ===== FILE: contracts/libraries/VeBalanceLib.sol =====
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.19;

import "./math/Math.sol";
import "./Errors.sol";

struct VeBalance {
    uint128 bias;
    uint128 slope;
}

struct LockedPosition {
    uint128 amount;
    uint128 expiry;
}

library VeBalanceLib {
    using Math for uint256;
    uint128 internal constant MAX_LOCK_TIME = 104 weeks;
    uint256 internal constant USER_VOTE_MAX_WEIGHT = 10 ** 18;

    function add(
        VeBalance memory a,
        VeBalance memory b
    ) internal pure returns (VeBalance memory res) {
        res.bias = a.bias + b.bias;
        res.slope = a.slope + b.slope;
    }

    function sub(
        VeBalance memory a,
        VeBalance memory b
    ) internal pure returns (VeBalance memory res) {
        res.bias = a.bias - b.bias;
        res.slope = a.slope - b.slope;
    }

    function sub(
        VeBalance memory a,
        uint128 slope,
        uint128 expiry
    ) internal pure returns (VeBalance memory res) {
        res.slope = a.slope - slope;
        res.bias = a.bias - slope * expiry;
    }

    function isExpired(VeBalance memory a) internal view returns (bool) {
        return a.slope * uint128(block.timestamp) >= a.bias;
    }

    function getCurrentValue(VeBalance memory a) internal view returns (uint128) {
        if (isExpired(a)) return 0;
        return getValueAt(a, uint128(block.timestamp));
    }

    function getValueAt(VeBalance memory a, uint128 t) internal pure returns (uint128) {
        if (a.slope * t > a.bias) {
            return 0;
        }
        return a.bias - a.slope * t;
    }

    function getExpiry(VeBalance memory a) internal pure returns (uint128) {
        if (a.slope == 0) revert Errors.VEZeroSlope(a.bias, a.slope);
        return a.bias / a.slope;
    }

    function convertToVeBalance(
        LockedPosition memory position
    ) internal pure returns (VeBalance memory res) {
        res.slope = position.amount / MAX_LOCK_TIME;
        res.bias = res.slope * position.expiry;
    }

    function convertToVeBalance(
        LockedPosition memory position,
        uint256 weight
    ) internal pure returns (VeBalance memory res) {
        res.slope = ((position.amount * weight) / MAX_LOCK_TIME / USER_VOTE_MAX_WEIGHT).Uint128();
        res.bias = res.slope * position.expiry;
    }

    function convertToVeBalance(
        uint128 amount,
        uint128 expiry
    ) internal pure returns (uint128, uint128) {
        VeBalance memory balance = convertToVeBalance(LockedPosition(amount, expiry));
        return (balance.bias, balance.slope);
    }
}

// ===== FILE: contracts/interfaces/pendle/IPSwapAggregator.sol =====
// SPDX-License-Identifier: MIT
pragma solidity =0.8.19;

struct SwapData {
    SwapType swapType;
    address extRouter;
    bytes extCalldata;
    bool needScale;
}

enum SwapType {
    NONE,
    KYBERSWAP,
    ONE_INCH,
    // ETH_WETH not used in Aggregator
    ETH_WETH
}

interface IPSwapAggregator {
    function swap(address tokenIn, uint256 amountIn, SwapData calldata swapData) external payable;
}

// ===== FILE: contracts/rewards/PenpieReceiptToken.sol =====
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (token/ERC20/ERC20.sol)
pragma solidity ^0.8.19;

import { ERC20, IERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { IMasterPenpie } from "../interfaces/IMasterPenpie.sol";

/// @title PenpieReceiptToken is to represent a Pendle Market deposited to penpie posistion. PenpieReceiptToken is minted to user who deposited Market token
///        on pendle staking to increase defi lego
///         
///         Reward from Magpie and on BaseReward should be updated upon every transfer.
///
/// @author Magpie Team
/// @notice Mater penpie emit `PNP` reward token based on Time. For a pool, 

contract PenpieReceiptToken is ERC20, Ownable {
    using SafeERC20 for IERC20Metadata;
    using SafeERC20 for IERC20;

    address public underlying;
    address public immutable masterPenpie;


    /* ============ Errors ============ */

    /* ============ Events ============ */

    constructor(address _underlying, address _masterPenpie, string memory name, string memory symbol) ERC20(name, symbol) {
        underlying = _underlying;
        masterPenpie = _masterPenpie;
    } 

    // should only be called by 1. pendleStaking for Pendle Market deposits 2. masterPenpie for other general staking token such as mPendleOFT or PNP-ETH Lp tokens
    function mint(address account, uint256 amount) external virtual onlyOwner {
        _mint(account, amount);
    }

    // should only be called by 1. pendleStaking for Pendle Market deposits 2. masterPenpie for other general staking token such as mPendleOFT or PNP-ETH Lp tokens
    function burn(address account, uint256 amount) external virtual onlyOwner {
        _burn(account, amount);
    }

    // rewards are calculated based on user's receipt token balance, so reward should be updated on master penpie before transfer
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        IMasterPenpie(masterPenpie).beforeReceiptTokenTransfer(from, to, amount);
    }

    // rewards are calculated based on user's receipt token balance, so balance should be updated on master penpie before transfer
    function _afterTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        IMasterPenpie(masterPenpie).afterReceiptTokenTransfer(from, to, amount);
    }

}
// ===== FILE: contracts/libraries/math/LogExpMath.sol =====
// SPDX-License-Identifier: GPL-3.0-or-later
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the “Software”), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.

// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

pragma solidity 0.8.19;

/* solhint-disable */

/**
 * @dev Exponentiation and logarithm functions for 18 decimal fixed point numbers (both base and exponent/argument).
 *
 * Exponentiation and logarithm with arbitrary bases (x^y and log_x(y)) are implemented by conversion to natural
 * exponentiation and logarithm (where the base is Euler's number).
 *
 * @author Fernando Martinelli - @fernandomartinelli
 * @author Sergio Yuhjtman - @sergioyuhjtman
 * @author Daniel Fernandez - @dmf7z
 */
library LogExpMath {
    // All fixed point multiplications and divisions are inlined. This means we need to divide by ONE when multiplying
    // two numbers, and multiply by ONE when dividing them.

    // All arguments and return values are 18 decimal fixed point numbers.
    int256 constant ONE_18 = 1e18;

    // Internally, intermediate values are computed with higher precision as 20 decimal fixed point numbers, and in the
    // case of ln36, 36 decimals.
    int256 constant ONE_20 = 1e20;
    int256 constant ONE_36 = 1e36;

    // The domain of natural exponentiation is bound by the word size and number of decimals used.
    //
    // Because internally the result will be stored using 20 decimals, the largest possible result is
    // (2^255 - 1) / 10^20, which makes the largest exponent ln((2^255 - 1) / 10^20) = 130.700829182905140221.
    // The smallest possible result is 10^(-18), which makes largest negative argument
    // ln(10^(-18)) = -41.446531673892822312.
    // We use 130.0 and -41.0 to have some safety margin.
    int256 constant MAX_NATURAL_EXPONENT = 130e18;
    int256 constant MIN_NATURAL_EXPONENT = -41e18;

    // Bounds for ln_36's argument. Both ln(0.9) and ln(1.1) can be represented with 36 decimal places in a fixed point
    // 256 bit integer.
    int256 constant LN_36_LOWER_BOUND = ONE_18 - 1e17;
    int256 constant LN_36_UPPER_BOUND = ONE_18 + 1e17;

    uint256 constant MILD_EXPONENT_BOUND = 2 ** 254 / uint256(ONE_20);

    // 18 decimal constants
    int256 constant x0 = 128000000000000000000; // 2ˆ7
    int256 constant a0 = 38877084059945950922200000000000000000000000000000000000; // eˆ(x0) (no decimals)
    int256 constant x1 = 64000000000000000000; // 2ˆ6
    int256 constant a1 = 6235149080811616882910000000; // eˆ(x1) (no decimals)

    // 20 decimal constants
    int256 constant x2 = 3200000000000000000000; // 2ˆ5
    int256 constant a2 = 7896296018268069516100000000000000; // eˆ(x2)
    int256 constant x3 = 1600000000000000000000; // 2ˆ4
    int256 constant a3 = 888611052050787263676000000; // eˆ(x3)
    int256 constant x4 = 800000000000000000000; // 2ˆ3
    int256 constant a4 = 298095798704172827474000; // eˆ(x4)
    int256 constant x5 = 400000000000000000000; // 2ˆ2
    int256 constant a5 = 5459815003314423907810; // eˆ(x5)
    int256 constant x6 = 200000000000000000000; // 2ˆ1
    int256 constant a6 = 738905609893065022723; // eˆ(x6)
    int256 constant x7 = 100000000000000000000; // 2ˆ0
    int256 constant a7 = 271828182845904523536; // eˆ(x7)
    int256 constant x8 = 50000000000000000000; // 2ˆ-1
    int256 constant a8 = 164872127070012814685; // eˆ(x8)
    int256 constant x9 = 25000000000000000000; // 2ˆ-2
    int256 constant a9 = 128402541668774148407; // eˆ(x9)
    int256 constant x10 = 12500000000000000000; // 2ˆ-3
    int256 constant a10 = 113314845306682631683; // eˆ(x10)
    int256 constant x11 = 6250000000000000000; // 2ˆ-4
    int256 constant a11 = 106449445891785942956; // eˆ(x11)

    /**
     * @dev Natural exponentiation (e^x) with signed 18 decimal fixed point exponent.
     *
     * Reverts if `x` is smaller than MIN_NATURAL_EXPONENT, or larger than `MAX_NATURAL_EXPONENT`.
     */
    function exp(int256 x) internal pure returns (int256) {
        unchecked {
            require(x >= MIN_NATURAL_EXPONENT && x <= MAX_NATURAL_EXPONENT, "Invalid exponent");

            if (x < 0) {
                // We only handle positive exponents: e^(-x) is computed as 1 / e^x. We can safely make x positive since it
                // fits in the signed 256 bit range (as it is larger than MIN_NATURAL_EXPONENT).
                // Fixed point division requires multiplying by ONE_18.
                return ((ONE_18 * ONE_18) / exp(-x));
            }

            // First, we use the fact that e^(x+y) = e^x * e^y to decompose x into a sum of powers of two, which we call x_n,
            // where x_n == 2^(7 - n), and e^x_n = a_n has been precomputed. We choose the first x_n, x0, to equal 2^7
            // because all larger powers are larger than MAX_NATURAL_EXPONENT, and therefore not present in the
            // decomposition.
            // At the end of this process we will have the product of all e^x_n = a_n that apply, and the remainder of this
            // decomposition, which will be lower than the smallest x_n.
            // exp(x) = k_0 * a_0 * k_1 * a_1 * ... + k_n * a_n * exp(remainder), where each k_n equals either 0 or 1.
            // We mutate x by subtracting x_n, making it the remainder of the decomposition.

            // The first two a_n (e^(2^7) and e^(2^6)) are too large if stored as 18 decimal numbers, and could cause
            // intermediate overflows. Instead we store them as plain integers, with 0 decimals.
            // Additionally, x0 + x1 is larger than MAX_NATURAL_EXPONENT, which means they will not both be present in the
            // decomposition.

            // For each x_n, we test if that term is present in the decomposition (if x is larger than it), and if so deduct
            // it and compute the accumulated product.

            int256 firstAN;
            if (x >= x0) {
                x -= x0;
                firstAN = a0;
            } else if (x >= x1) {
                x -= x1;
                firstAN = a1;
            } else {
                firstAN = 1; // One with no decimal places
            }

            // We now transform x into a 20 decimal fixed point number, to have enhanced precision when computing the
            // smaller terms.
            x *= 100;

            // `product` is the accumulated product of all a_n (except a0 and a1), which starts at 20 decimal fixed point
            // one. Recall that fixed point multiplication requires dividing by ONE_20.
            int256 product = ONE_20;

            if (x >= x2) {
                x -= x2;
                product = (product * a2) / ONE_20;
            }
            if (x >= x3) {
                x -= x3;
                product = (product * a3) / ONE_20;
            }
            if (x >= x4) {
                x -= x4;
                product = (product * a4) / ONE_20;
            }
            if (x >= x5) {
                x -= x5;
                product = (product * a5) / ONE_20;
            }
            if (x >= x6) {
                x -= x6;
                product = (product * a6) / ONE_20;
            }
            if (x >= x7) {
                x -= x7;
                product = (product * a7) / ONE_20;
            }
            if (x >= x8) {
                x -= x8;
                product = (product * a8) / ONE_20;
            }
            if (x >= x9) {
                x -= x9;
                product = (product * a9) / ONE_20;
            }

            // x10 and x11 are unnecessary here since we have high enough precision already.

            // Now we need to compute e^x, where x is small (in particular, it is smaller than x9). We use the Taylor series
            // expansion for e^x: 1 + x + (x^2 / 2!) + (x^3 / 3!) + ... + (x^n / n!).

            int256 seriesSum = ONE_20; // The initial one in the sum, with 20 decimal places.
            int256 term; // Each term in the sum, where the nth term is (x^n / n!).

            // The first term is simply x.
            term = x;
            seriesSum += term;

            // Each term (x^n / n!) equals the previous one times x, divided by n. Since x is a fixed point number,
            // multiplying by it requires dividing by ONE_20, but dividing by the non-fixed point n values does not.

            term = ((term * x) / ONE_20) / 2;
            seriesSum += term;

            term = ((term * x) / ONE_20) / 3;
            seriesSum += term;

            term = ((term * x) / ONE_20) / 4;
            seriesSum += term;

            term = ((term * x) / ONE_20) / 5;
            seriesSum += term;

            term = ((term * x) / ONE_20) / 6;
            seriesSum += term;

            term = ((term * x) / ONE_20) / 7;
            seriesSum += term;

            term = ((term * x) / ONE_20) / 8;
            seriesSum += term;

            term = ((term * x) / ONE_20) / 9;
            seriesSum += term;

            term = ((term * x) / ONE_20) / 10;
            seriesSum += term;

            term = ((term * x) / ONE_20) / 11;
            seriesSum += term;

            term = ((term * x) / ONE_20) / 12;
            seriesSum += term;

            // 12 Taylor terms are sufficient for 18 decimal precision.

            // We now have the first a_n (with no decimals), and the product of all other a_n present, and the Taylor
            // approximation of the exponentiation of the remainder (both with 20 decimals). All that remains is to multiply
            // all three (one 20 decimal fixed point multiplication, dividing by ONE_20, and one integer multiplication),
            // and then drop two digits to return an 18 decimal value.

            return (((product * seriesSum) / ONE_20) * firstAN) / 100;
        }
    }

    /**
     * @dev Natural logarithm (ln(a)) with signed 18 decimal fixed point argument.
     */
    function ln(int256 a) internal pure returns (int256) {
        unchecked {
            // The real natural logarithm is not defined for negative numbers or zero.
            require(a > 0, "out of bounds");
            if (LN_36_LOWER_BOUND < a && a < LN_36_UPPER_BOUND) {
                return _ln_36(a) / ONE_18;
            } else {
                return _ln(a);
            }
        }
    }

    /**
     * @dev Exponentiation (x^y) with unsigned 18 decimal fixed point base and exponent.
     *
     * Reverts if ln(x) * y is smaller than `MIN_NATURAL_EXPONENT`, or larger than `MAX_NATURAL_EXPONENT`.
     */
    function pow(uint256 x, uint256 y) internal pure returns (uint256) {
        unchecked {
            if (y == 0) {
                // We solve the 0^0 indetermination by making it equal one.
                return uint256(ONE_18);
            }

            if (x == 0) {
                return 0;
            }

            // Instead of computing x^y directly, we instead rely on the properties of logarithms and exponentiation to
            // arrive at that r`esult. In particular, exp(ln(x)) = x, and ln(x^y) = y * ln(x). This means
            // x^y = exp(y * ln(x)).

            // The ln function takes a signed value, so we need to make sure x fits in the signed 256 bit range.
            require(x < 2 ** 255, "x out of bounds");
            int256 x_int256 = int256(x);

            // We will compute y * ln(x) in a single step. Depending on the value of x, we can either use ln or ln_36. In
            // both cases, we leave the division by ONE_18 (due to fixed point multiplication) to the end.

            // This prevents y * ln(x) from overflowing, and at the same time guarantees y fits in the signed 256 bit range.
            require(y < MILD_EXPONENT_BOUND, "y out of bounds");
            int256 y_int256 = int256(y);

            int256 logx_times_y;
            if (LN_36_LOWER_BOUND < x_int256 && x_int256 < LN_36_UPPER_BOUND) {
                int256 ln_36_x = _ln_36(x_int256);

                // ln_36_x has 36 decimal places, so multiplying by y_int256 isn't as straightforward, since we can't just
                // bring y_int256 to 36 decimal places, as it might overflow. Instead, we perform two 18 decimal
                // multiplications and add the results: one with the first 18 decimals of ln_36_x, and one with the
                // (downscaled) last 18 decimals.
                logx_times_y = ((ln_36_x / ONE_18) *
                    y_int256 +
                    ((ln_36_x % ONE_18) * y_int256) /
                    ONE_18);
            } else {
                logx_times_y = _ln(x_int256) * y_int256;
            }
            logx_times_y /= ONE_18;

            // Finally, we compute exp(y * ln(x)) to arrive at x^y
            require(
                MIN_NATURAL_EXPONENT <= logx_times_y && logx_times_y <= MAX_NATURAL_EXPONENT,
                "product out of bounds"
            );

            return uint256(exp(logx_times_y));
        }
    }

    /**
     * @dev Internal natural logarithm (ln(a)) with signed 18 decimal fixed point argument.
     */
    function _ln(int256 a) private pure returns (int256) {
        unchecked {
            if (a < ONE_18) {
                // Since ln(a^k) = k * ln(a), we can compute ln(a) as ln(a) = ln((1/a)^(-1)) = - ln((1/a)). If a is less
                // than one, 1/a will be greater than one, and this if statement will not be entered in the recursive call.
                // Fixed point division requires multiplying by ONE_18.
                return (-_ln((ONE_18 * ONE_18) / a));
            }

            // First, we use the fact that ln^(a * b) = ln(a) + ln(b) to decompose ln(a) into a sum of powers of two, which
            // we call x_n, where x_n == 2^(7 - n), which are the natural logarithm of precomputed quantities a_n (that is,
            // ln(a_n) = x_n). We choose the first x_n, x0, to equal 2^7 because the exponential of all larger powers cannot
            // be represented as 18 fixed point decimal numbers in 256 bits, and are therefore larger than a.
            // At the end of this process we will have the sum of all x_n = ln(a_n) that apply, and the remainder of this
            // decomposition, which will be lower than the smallest a_n.
            // ln(a) = k_0 * x_0 + k_1 * x_1 + ... + k_n * x_n + ln(remainder), where each k_n equals either 0 or 1.
            // We mutate a by subtracting a_n, making it the remainder of the decomposition.

            // For reasons related to how `exp` works, the first two a_n (e^(2^7) and e^(2^6)) are not stored as fixed point
            // numbers with 18 decimals, but instead as plain integers with 0 decimals, so we need to multiply them by
            // ONE_18 to convert them to fixed point.
            // For each a_n, we test if that term is present in the decomposition (if a is larger than it), and if so divide
            // by it and compute the accumulated sum.

            int256 sum = 0;
            if (a >= a0 * ONE_18) {
                a /= a0; // Integer, not fixed point division
                sum += x0;
            }

            if (a >= a1 * ONE_18) {
                a /= a1; // Integer, not fixed point division
                sum += x1;
            }

            // All other a_n and x_n are stored as 20 digit fixed point numbers, so we convert the sum and a to this format.
            sum *= 100;
            a *= 100;

            // Because further a_n are  20 digit fixed point numbers, we multiply by ONE_20 when dividing by them.

            if (a >= a2) {
                a = (a * ONE_20) / a2;
                sum += x2;
            }

            if (a >= a3) {
                a = (a * ONE_20) / a3;
                sum += x3;
            }

            if (a >= a4) {
                a = (a * ONE_20) / a4;
                sum += x4;
            }

            if (a >= a5) {
                a = (a * ONE_20) / a5;
                sum += x5;
            }

            if (a >= a6) {
                a = (a * ONE_20) / a6;
                sum += x6;
            }

            if (a >= a7) {
                a = (a * ONE_20) / a7;
                sum += x7;
            }

            if (a >= a8) {
                a = (a * ONE_20) / a8;
                sum += x8;
            }

            if (a >= a9) {
                a = (a * ONE_20) / a9;
                sum += x9;
            }

            if (a >= a10) {
                a = (a * ONE_20) / a10;
                sum += x10;
            }

            if (a >= a11) {
                a = (a * ONE_20) / a11;
                sum += x11;
            }

            // a is now a small number (smaller than a_11, which roughly equals 1.06). This means we can use a Taylor series
            // that converges rapidly for values of `a` close to one - the same one used in ln_36.
            // Let z = (a - 1) / (a + 1).
            // ln(a) = 2 * (z + z^3 / 3 + z^5 / 5 + z^7 / 7 + ... + z^(2 * n + 1) / (2 * n + 1))

            // Recall that 20 digit fixed point division requires multiplying by ONE_20, and multiplication requires
            // division by ONE_20.
            int256 z = ((a - ONE_20) * ONE_20) / (a + ONE_20);
            int256 z_squared = (z * z) / ONE_20;

            // num is the numerator of the series: the z^(2 * n + 1) term
            int256 num = z;

            // seriesSum holds the accumulated sum of each term in the series, starting with the initial z
            int256 seriesSum = num;

            // In each step, the numerator is multiplied by z^2
            num = (num * z_squared) / ONE_20;
            seriesSum += num / 3;

            num = (num * z_squared) / ONE_20;
            seriesSum += num / 5;

            num = (num * z_squared) / ONE_20;
            seriesSum += num / 7;

            num = (num * z_squared) / ONE_20;
            seriesSum += num / 9;

            num = (num * z_squared) / ONE_20;
            seriesSum += num / 11;

            // 6 Taylor terms are sufficient for 36 decimal precision.

            // Finally, we multiply by 2 (non fixed point) to compute ln(remainder)
            seriesSum *= 2;

            // We now have the sum of all x_n present, and the Taylor approximation of the logarithm of the remainder (both
            // with 20 decimals). All that remains is to sum these two, and then drop two digits to return a 18 decimal
            // value.

            return (sum + seriesSum) / 100;
        }
    }

    /**
     * @dev Intrnal high precision (36 decimal places) natural logarithm (ln(x)) with signed 18 decimal fixed point argument,
     * for x close to one.
     *
     * Should only be used if x is between LN_36_LOWER_BOUND and LN_36_UPPER_BOUND.
     */
    function _ln_36(int256 x) private pure returns (int256) {
        unchecked {
            // Since ln(1) = 0, a value of x close to one will yield a very small result, which makes using 36 digits
            // worthwhile.

            // First, we transform x to a 36 digit fixed point value.
            x *= ONE_18;

            // We will use the following Taylor expansion, which converges very rapidly. Let z = (x - 1) / (x + 1).
            // ln(x) = 2 * (z + z^3 / 3 + z^5 / 5 + z^7 / 7 + ... + z^(2 * n + 1) / (2 * n + 1))

            // Recall that 36 digit fixed point division requires multiplying by ONE_36, and multiplication requires
            // division by ONE_36.
            int256 z = ((x - ONE_36) * ONE_36) / (x + ONE_36);
            int256 z_squared = (z * z) / ONE_36;

            // num is the numerator of the series: the z^(2 * n + 1) term
            int256 num = z;

            // seriesSum holds the accumulated sum of each term in the series, starting with the initial z
            int256 seriesSum = num;

            // In each step, the numerator is multiplied by z^2
            num = (num * z_squared) / ONE_36;
            seriesSum += num / 3;

            num = (num * z_squared) / ONE_36;
            seriesSum += num / 5;

            num = (num * z_squared) / ONE_36;
            seriesSum += num / 7;

            num = (num * z_squared) / ONE_36;
            seriesSum += num / 9;

            num = (num * z_squared) / ONE_36;
            seriesSum += num / 11;

            num = (num * z_squared) / ONE_36;
            seriesSum += num / 13;

            num = (num * z_squared) / ONE_36;
            seriesSum += num / 15;

            // 8 Taylor terms are sufficient for 36 decimal precision.

            // All that remains is multiplying by 2 (non fixed point).
            return seriesSum * 2;
        }
    }
}

// ===== FILE: contracts/interfaces/pendle/IPInterestManagerYT.sol =====
// SPDX-License-Identifier: MIT
pragma solidity =0.8.19;

interface IPInterestManagerYT {
    function userInterest(
        address user
    ) external view returns (uint128 lastPYIndex, uint128 accruedInterest);
}

// ===== FILE: contracts/libraries/MarketApproxLib.sol =====
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "./math/Math.sol";
import "./math/MarketMathCore.sol";

struct ApproxParams {
    uint256 guessMin;
    uint256 guessMax;
    uint256 guessOffchain; // pass 0 in to skip this variable
    uint256 maxIteration; // every iteration, the diff between guessMin and guessMax will be divided by 2
    uint256 eps; // the max eps between the returned result & the correct result, base 1e18. Normally this number will be set
    // to 1e15 (1e18/1000 = 0.1%)

    /// Further explanation of the eps. Take swapExactSyForPt for example. To calc the corresponding amount of Pt to swap out,
    /// it's necessary to run an approximation algorithm, because by default there only exists the Pt to Sy formula
    /// To approx, the 5 values above will have to be provided, and the approx process will run as follows:
    /// mid = (guessMin + guessMax) / 2 // mid here is the current guess of the amount of Pt out
    /// netSyNeed = calcSwapSyForExactPt(mid)
    /// if (netSyNeed > exactSyIn) guessMax = mid - 1 // since the maximum Sy in can't exceed the exactSyIn
    /// else guessMin = mid (1)
    /// For the (1), since netSyNeed <= exactSyIn, the result might be usable. If the netSyNeed is within eps of
    /// exactSyIn (ex eps=0.1% => we have used 99.9% the amount of Sy specified), mid will be chosen as the final guess result

    /// for guessOffchain, this is to provide a shortcut to guessing. The offchain SDK can precalculate the exact result
    /// before the tx is sent. When the tx reaches the contract, the guessOffchain will be checked first, and if it satisfies the
    /// approximation, it will be used (and save all the guessing). It's expected that this shortcut will be used in most cases
    /// except in cases that there is a trade in the same market right before the tx
}

library MarketApproxPtInLib {
    using MarketMathCore for MarketState;
    using PYIndexLib for PYIndex;
    using Math for uint256;
    using Math for int256;
    using LogExpMath for int256;

    /**
     * @dev algorithm:
        - Bin search the amount of PT to swap in
        - Try swapping & get netSyOut
        - Stop when netSyOut greater & approx minSyOut
        - guess & approx is for netPtIn
     */
    function approxSwapPtForExactSy(
        MarketState memory market,
        PYIndex index,
        uint256 minSyOut,
        uint256 blockTime,
        ApproxParams memory approx
    ) internal pure returns (uint256 /*netPtIn*/, uint256 /*netSyOut*/, uint256 /*netSyFee*/) {
        MarketPreCompute memory comp = market.getMarketPreCompute(index, blockTime);
        if (approx.guessOffchain == 0) {
            // no limit on min
            approx.guessMax = Math.min(approx.guessMax, calcMaxPtIn(market, comp));
            validateApprox(approx);
        }

        for (uint256 iter = 0; iter < approx.maxIteration; ++iter) {
            uint256 guess = nextGuess(approx, iter);
            (uint256 netSyOut, uint256 netSyFee, ) = calcSyOut(market, comp, index, guess);

            if (netSyOut >= minSyOut) {
                if (Math.isAGreaterApproxB(netSyOut, minSyOut, approx.eps))
                    return (guess, netSyOut, netSyFee);
                approx.guessMax = guess;
            } else {
                approx.guessMin = guess;
            }
        }
        revert Errors.ApproxFail();
    }

    /**
     * @dev algorithm:
        - Bin search the amount of PT to swap in
        - Flashswap the corresponding amount of SY out
        - Pair those amount with exactSyIn SY to tokenize into PT & YT
        - PT to repay the flashswap, YT transferred to user
        - Stop when the amount of SY to be pulled to tokenize PT to repay loan approx the exactSyIn
        - guess & approx is for netYtOut (also netPtIn)
     */
    function approxSwapExactSyForYt(
        MarketState memory market,
        PYIndex index,
        uint256 exactSyIn,
        uint256 blockTime,
        ApproxParams memory approx
    ) internal pure returns (uint256 /*netYtOut*/, uint256 /*netSyFee*/) {
        MarketPreCompute memory comp = market.getMarketPreCompute(index, blockTime);
        if (approx.guessOffchain == 0) {
            approx.guessMin = Math.max(approx.guessMin, index.syToAsset(exactSyIn));
            approx.guessMax = Math.min(approx.guessMax, calcMaxPtIn(market, comp));
            validateApprox(approx);
        }

        // at minimum we will flashswap exactSyIn since we have enough SY to payback the PT loan

        for (uint256 iter = 0; iter < approx.maxIteration; ++iter) {
            uint256 guess = nextGuess(approx, iter);

            (uint256 netSyOut, uint256 netSyFee, ) = calcSyOut(market, comp, index, guess);

            uint256 netSyToTokenizePt = index.assetToSyUp(guess);

            // for sure netSyToTokenizePt >= netSyOut since we are swapping PT to SY
            uint256 netSyToPull = netSyToTokenizePt - netSyOut;

            if (netSyToPull <= exactSyIn) {
                if (Math.isASmallerApproxB(netSyToPull, exactSyIn, approx.eps))
                    return (guess, netSyFee);
                approx.guessMin = guess;
            } else {
                approx.guessMax = guess - 1;
            }
        }
        revert Errors.ApproxFail();
    }

    /**
     * @dev algorithm:
        - Bin search the amount of PT to swap to SY
        - Swap PT to SY
        - Pair the remaining PT with the SY to add liquidity
        - Stop when the ratio of PT / totalPt & SY / totalSy is approx
        - guess & approx is for netPtSwap
     */
    function approxSwapPtToAddLiquidity(
        MarketState memory market,
        PYIndex index,
        uint256 totalPtIn,
        uint256 blockTime,
        ApproxParams memory approx
    )
        internal
        pure
        returns (uint256 /*netPtSwap*/, uint256 /*netSyFromSwap*/, uint256 /*netSyFee*/)
    {
        MarketPreCompute memory comp = market.getMarketPreCompute(index, blockTime);
        if (approx.guessOffchain == 0) {
            // no limit on min
            approx.guessMax = Math.min(approx.guessMax, calcMaxPtIn(market, comp));
            approx.guessMax = Math.min(approx.guessMax, totalPtIn);
            validateApprox(approx);
            require(market.totalLp != 0, "no existing lp");
        }

        for (uint256 iter = 0; iter < approx.maxIteration; ++iter) {
            uint256 guess = nextGuess(approx, iter);

            (
                uint256 syNumerator,
                uint256 ptNumerator,
                uint256 netSyOut,
                uint256 netSyFee,

            ) = calcNumerators(market, index, totalPtIn, comp, guess);

            if (Math.isAApproxB(syNumerator, ptNumerator, approx.eps))
                return (guess, netSyOut, netSyFee);

            if (syNumerator <= ptNumerator) {
                // needs more SY --> swap more PT
                approx.guessMin = guess + 1;
            } else {
                // needs less SY --> swap less PT
                approx.guessMax = guess - 1;
            }
        }
        revert Errors.ApproxFail();
    }

    function calcNumerators(
        MarketState memory market,
        PYIndex index,
        uint256 totalPtIn,
        MarketPreCompute memory comp,
        uint256 guess
    )
        internal
        pure
        returns (
            uint256 syNumerator,
            uint256 ptNumerator,
            uint256 netSyOut,
            uint256 netSyFee,
            uint256 netSyToReserve
        )
    {
        (netSyOut, netSyFee, netSyToReserve) = calcSyOut(market, comp, index, guess);

        uint256 newTotalPt = uint256(market.totalPt) + guess;
        uint256 newTotalSy = (uint256(market.totalSy) - netSyOut - netSyToReserve);

        // it is desired that
        // netSyOut / newTotalSy = netPtRemaining / newTotalPt
        // which is equivalent to
        // netSyOut * newTotalPt = netPtRemaining * newTotalSy

        syNumerator = netSyOut * newTotalPt;
        ptNumerator = (totalPtIn - guess) * newTotalSy;
    }

    struct Args7 {
        MarketState market;
        PYIndex index;
        uint256 exactPtIn;
        uint256 blockTime;
    }

    /**
     * @dev algorithm:
        - Bin search the amount of PT to swap to SY
        - Flashswap the corresponding amount of SY out
        - Tokenize all the SY into PT + YT
        - PT to repay the flashswap, YT transferred to user
        - Stop when the additional amount of PT to pull to repay the loan approx the exactPtIn
        - guess & approx is for totalPtToSwap
     */
    function approxSwapExactPtForYt(
        MarketState memory market,
        PYIndex index,
        uint256 exactPtIn,
        uint256 blockTime,
        ApproxParams memory approx
    )
        internal
        pure
        returns (uint256 /*netYtOut*/, uint256 /*totalPtToSwap*/, uint256 /*netSyFee*/)
    {
        MarketPreCompute memory comp = market.getMarketPreCompute(index, blockTime);
        if (approx.guessOffchain == 0) {
            approx.guessMin = Math.max(approx.guessMin, exactPtIn);
            approx.guessMax = Math.min(approx.guessMax, calcMaxPtIn(market, comp));
            validateApprox(approx);
        }

        for (uint256 iter = 0; iter < approx.maxIteration; ++iter) {
            uint256 guess = nextGuess(approx, iter);

            (uint256 netSyOut, uint256 netSyFee, ) = calcSyOut(market, comp, index, guess);

            uint256 netAssetOut = index.syToAsset(netSyOut);

            // guess >= netAssetOut since we are swapping PT to SY
            uint256 netPtToPull = guess - netAssetOut;

            if (netPtToPull <= exactPtIn) {
                if (Math.isASmallerApproxB(netPtToPull, exactPtIn, approx.eps))
                    return (netAssetOut, guess, netSyFee);
                approx.guessMin = guess;
            } else {
                approx.guessMax = guess - 1;
            }
        }
        revert Errors.ApproxFail();
    }

    ////////////////////////////////////////////////////////////////////////////////

    function calcSyOut(
        MarketState memory market,
        MarketPreCompute memory comp,
        PYIndex index,
        uint256 netPtIn
    ) internal pure returns (uint256 netSyOut, uint256 netSyFee, uint256 netSyToReserve) {
        (int256 _netSyOut, int256 _netSyFee, int256 _netSyToReserve) = market.calcTrade(
            comp,
            index,
            -int256(netPtIn)
        );
        netSyOut = uint256(_netSyOut);
        netSyFee = uint256(_netSyFee);
        netSyToReserve = uint256(_netSyToReserve);
    }

    function nextGuess(ApproxParams memory approx, uint256 iter) internal pure returns (uint256) {
        if (iter == 0 && approx.guessOffchain != 0) return approx.guessOffchain;
        if (approx.guessMin <= approx.guessMax) return (approx.guessMin + approx.guessMax) / 2;
        revert Errors.ApproxFail();
    }

    /// INTENDED TO BE CALLED BY WHEN GUESS.OFFCHAIN == 0 ONLY ///

    function validateApprox(ApproxParams memory approx) internal pure {
        if (approx.guessMin > approx.guessMax || approx.eps > Math.ONE)
            revert Errors.ApproxParamsInvalid(approx.guessMin, approx.guessMax, approx.eps);
    }

    function calcMaxPtIn(
        MarketState memory market,
        MarketPreCompute memory comp
    ) internal pure returns (uint256) {
        uint256 low = 0;
        uint256 hi = uint256(comp.totalAsset) - 1;

        while (low != hi) {
            uint256 mid = (low + hi + 1) / 2;
            if (calcSlope(comp, market.totalPt, int256(mid)) < 0) hi = mid - 1;
            else low = mid;
        }
        return low;
    }

    function calcSlope(
        MarketPreCompute memory comp,
        int256 totalPt,
        int256 ptToMarket
    ) internal pure returns (int256) {
        int256 diffAssetPtToMarket = comp.totalAsset - ptToMarket;
        int256 sumPt = ptToMarket + totalPt;

        require(diffAssetPtToMarket > 0 && sumPt > 0, "invalid ptToMarket");

        int256 part1 = (ptToMarket * (totalPt + comp.totalAsset)).divDown(
            sumPt * diffAssetPtToMarket
        );

        int256 part2 = sumPt.divDown(diffAssetPtToMarket).ln();
        int256 part3 = Math.IONE.divDown(comp.rateScalar);

        return comp.rateAnchor - (part1 - part2).mulDown(part3);
    }
}

library MarketApproxPtOutLib {
    using MarketMathCore for MarketState;
    using PYIndexLib for PYIndex;
    using Math for uint256;
    using Math for int256;
    using LogExpMath for int256;

    /**
     * @dev algorithm:
        - Bin search the amount of PT to swapExactOut
        - Calculate the amount of SY needed
        - Stop when the netSyIn is smaller approx exactSyIn
        - guess & approx is for netSyIn
     */
    function approxSwapExactSyForPt(
        MarketState memory market,
        PYIndex index,
        uint256 exactSyIn,
        uint256 blockTime,
        ApproxParams memory approx
    ) internal pure returns (uint256 /*netPtOut*/, uint256 /*netSyFee*/) {
        MarketPreCompute memory comp = market.getMarketPreCompute(index, blockTime);
        if (approx.guessOffchain == 0) {
            // no limit on min
            approx.guessMax = Math.min(approx.guessMax, calcMaxPtOut(comp, market.totalPt));
            validateApprox(approx);
        }

        for (uint256 iter = 0; iter < approx.maxIteration; ++iter) {
            uint256 guess = nextGuess(approx, iter);

            (uint256 netSyIn, uint256 netSyFee, ) = calcSyIn(market, comp, index, guess);

            if (netSyIn <= exactSyIn) {
                if (Math.isASmallerApproxB(netSyIn, exactSyIn, approx.eps))
                    return (guess, netSyFee);
                approx.guessMin = guess;
            } else {
                approx.guessMax = guess - 1;
            }
        }

        revert Errors.ApproxFail();
    }

    /**
     * @dev algorithm:
        - Bin search the amount of PT to swapExactOut
        - Flashswap that amount of PT & pair with YT to redeem SY
        - Use the SY to repay the flashswap debt and the remaining is transferred to user
        - Stop when the netSyOut is greater approx the minSyOut
        - guess & approx is for netSyOut
     */
    function approxSwapYtForExactSy(
        MarketState memory market,
        PYIndex index,
        uint256 minSyOut,
        uint256 blockTime,
        ApproxParams memory approx
    ) internal pure returns (uint256 /*netYtIn*/, uint256 /*netSyOut*/, uint256 /*netSyFee*/) {
        MarketPreCompute memory comp = market.getMarketPreCompute(index, blockTime);
        if (approx.guessOffchain == 0) {
            // no limit on min
            approx.guessMax = Math.min(approx.guessMax, calcMaxPtOut(comp, market.totalPt));
            validateApprox(approx);
        }

        for (uint256 iter = 0; iter < approx.maxIteration; ++iter) {
            uint256 guess = nextGuess(approx, iter);

            (uint256 netSyOwed, uint256 netSyFee, ) = calcSyIn(market, comp, index, guess);

            uint256 netAssetToRepay = index.syToAssetUp(netSyOwed);
            uint256 netSyOut = index.assetToSy(guess - netAssetToRepay);

            if (netSyOut >= minSyOut) {
                if (Math.isAGreaterApproxB(netSyOut, minSyOut, approx.eps))
                    return (guess, netSyOut, netSyFee);
                approx.guessMax = guess;
            } else {
                approx.guessMin = guess + 1;
            }
        }
        revert Errors.ApproxFail();
    }

    struct Args6 {
        MarketState market;
        PYIndex index;
        uint256 totalSyIn;
        uint256 blockTime;
        ApproxParams approx;
    }

    /**
     * @dev algorithm:
        - Bin search the amount of PT to swapExactOut
        - Swap that amount of PT out
        - Pair the remaining PT with the SY to add liquidity
        - Stop when the ratio of PT / totalPt & SY / totalSy is approx
        - guess & approx is for netPtFromSwap
     */
    function approxSwapSyToAddLiquidity(
        MarketState memory _market,
        PYIndex _index,
        uint256 _totalSyIn,
        uint256 _blockTime,
        ApproxParams memory _approx
    )
        internal
        pure
        returns (uint256 /*netPtFromSwap*/, uint256 /*netSySwap*/, uint256 /*netSyFee*/)
    {
        Args6 memory a = Args6(_market, _index, _totalSyIn, _blockTime, _approx);

        MarketPreCompute memory comp = a.market.getMarketPreCompute(a.index, a.blockTime);
        if (a.approx.guessOffchain == 0) {
            // no limit on min
            a.approx.guessMax = Math.min(a.approx.guessMax, calcMaxPtOut(comp, a.market.totalPt));
            validateApprox(a.approx);
            require(a.market.totalLp != 0, "no existing lp");
        }

        for (uint256 iter = 0; iter < a.approx.maxIteration; ++iter) {
            uint256 guess = nextGuess(a.approx, iter);

            (uint256 netSyIn, uint256 netSyFee, uint256 netSyToReserve) = calcSyIn(
                a.market,
                comp,
                a.index,
                guess
            );

            if (netSyIn > a.totalSyIn) {
                a.approx.guessMax = guess - 1;
                continue;
            }

            uint256 syNumerator;
            uint256 ptNumerator;

            {
                uint256 newTotalPt = uint256(a.market.totalPt) - guess;
                uint256 netTotalSy = uint256(a.market.totalSy) + netSyIn - netSyToReserve;

                // it is desired that
                // netPtFromSwap / newTotalPt = netSyRemaining / netTotalSy
                // which is equivalent to
                // netPtFromSwap * netTotalSy = netSyRemaining * newTotalPt

                ptNumerator = guess * netTotalSy;
                syNumerator = (a.totalSyIn - netSyIn) * newTotalPt;
            }

            if (Math.isAApproxB(ptNumerator, syNumerator, a.approx.eps))
                return (guess, netSyIn, netSyFee);

            if (ptNumerator <= syNumerator) {
                // needs more PT
                a.approx.guessMin = guess + 1;
            } else {
                // needs less PT
                a.approx.guessMax = guess - 1;
            }
        }
        revert Errors.ApproxFail();
    }

    /**
     * @dev algorithm:
        - Bin search the amount of PT to swapExactOut
        - Flashswap that amount of PT out
        - Pair all the PT with the YT to redeem SY
        - Use the SY to repay the flashswap debt
        - Stop when the amount of YT required to pair with PT is approx exactYtIn
        - guess & approx is for netPtFromSwap
     */
    function approxSwapExactYtForPt(
        MarketState memory market,
        PYIndex index,
        uint256 exactYtIn,
        uint256 blockTime,
        ApproxParams memory approx
    )
        internal
        pure
        returns (uint256 /*netPtOut*/, uint256 /*totalPtSwapped*/, uint256 /*netSyFee*/)
    {
        MarketPreCompute memory comp = market.getMarketPreCompute(index, blockTime);
        if (approx.guessOffchain == 0) {
            approx.guessMin = Math.max(approx.guessMin, exactYtIn);
            approx.guessMax = Math.min(approx.guessMax, calcMaxPtOut(comp, market.totalPt));
            validateApprox(approx);
        }

        for (uint256 iter = 0; iter < approx.maxIteration; ++iter) {
            uint256 guess = nextGuess(approx, iter);

            (uint256 netSyOwed, uint256 netSyFee, ) = calcSyIn(market, comp, index, guess);

            uint256 netYtToPull = index.syToAssetUp(netSyOwed);

            if (netYtToPull <= exactYtIn) {
                if (Math.isASmallerApproxB(netYtToPull, exactYtIn, approx.eps))
                    return (guess - netYtToPull, guess, netSyFee);
                approx.guessMin = guess;
            } else {
                approx.guessMax = guess - 1;
            }
        }
        revert Errors.ApproxFail();
    }

    ////////////////////////////////////////////////////////////////////////////////

    function calcSyIn(
        MarketState memory market,
        MarketPreCompute memory comp,
        PYIndex index,
        uint256 netPtOut
    ) internal pure returns (uint256 netSyIn, uint256 netSyFee, uint256 netSyToReserve) {
        (int256 _netSyIn, int256 _netSyFee, int256 _netSyToReserve) = market.calcTrade(
            comp,
            index,
            int256(netPtOut)
        );

        // all safe since totalPt and totalSy is int128
        netSyIn = uint256(-_netSyIn);
        netSyFee = uint256(_netSyFee);
        netSyToReserve = uint256(_netSyToReserve);
    }

    function calcMaxPtOut(
        MarketPreCompute memory comp,
        int256 totalPt
    ) internal pure returns (uint256) {
        int256 logitP = (comp.feeRate - comp.rateAnchor).mulDown(comp.rateScalar).exp();
        int256 proportion = logitP.divDown(logitP + Math.IONE);
        int256 numerator = proportion.mulDown(totalPt + comp.totalAsset);
        int256 maxPtOut = totalPt - numerator;
        // only get 99.9% of the theoretical max to accommodate some precision issues
        return (uint256(maxPtOut) * 999) / 1000;
    }

    function nextGuess(ApproxParams memory approx, uint256 iter) internal pure returns (uint256) {
        if (iter == 0 && approx.guessOffchain != 0) return approx.guessOffchain;
        if (approx.guessMin <= approx.guessMax) return (approx.guessMin + approx.guessMax) / 2;
        revert Errors.ApproxFail();
    }

    function validateApprox(ApproxParams memory approx) internal pure {
        if (approx.guessMin > approx.guessMax || approx.eps > Math.ONE)
            revert Errors.ApproxParamsInvalid(approx.guessMin, approx.guessMax, approx.eps);
    }
}

// ===== FILE: contracts/libraries/MiniHelpers.sol =====
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

library MiniHelpers {
    function isCurrentlyExpired(uint256 expiry) internal view returns (bool) {
        return (expiry <= block.timestamp);
    }

    function isExpired(uint256 expiry, uint256 blockTime) internal pure returns (bool) {
        return (expiry <= blockTime);
    }

    function isTimeInThePast(uint256 timestamp) internal view returns (bool) {
        return (timestamp <= block.timestamp); // same definition as isCurrentlyExpired
    }
}

// ===== FILE: contracts/libraries/ERC20FactoryLib.sol =====
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { MintableERC20 } from "./MintableERC20.sol";
import { PenpieReceiptToken } from "../rewards/PenpieReceiptToken.sol";
import { BaseRewardPoolV2 } from "../rewards/BaseRewardPoolV2.sol";

library ERC20FactoryLib {
    function createERC20(string memory name_, string memory symbol_) public returns(address) 
    {
        ERC20 token = new MintableERC20(name_, symbol_);
        return address(token);
    }

    function createReceipt(address _stakeToken, address _masterPenpie, string memory _name, string memory _symbol) public returns(address)
    {
        ERC20 token = new PenpieReceiptToken(_stakeToken, _masterPenpie, _name, _symbol);
        return address(token);
    }

    function createRewarder(
        address _receiptToken,
        address mainRewardToken,
        address _masterRadpie,
        address _rewardQueuer
    ) external returns (address) {
        BaseRewardPoolV2 _rewarder = new BaseRewardPoolV2(
            _receiptToken,
            mainRewardToken,
            _masterRadpie,
            _rewardQueuer
        );
        return address(_rewarder);
    }    
}
// ===== FILE: contracts/rewards/BaseRewardPoolV2.sol =====
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import  { IMasterPenpie } from "../interfaces/IMasterPenpie.sol";

import "../interfaces/IBaseRewardPool.sol";

/// @title A contract for managing rewards for a pool
/// @author Magpie Team
/// @notice You can use this contract for getting informations about rewards for a specific pools
contract BaseRewardPoolV2 is Ownable, ReentrancyGuard, IBaseRewardPool {
    using SafeERC20 for IERC20Metadata;
    using SafeERC20 for IERC20;

    /* ============ State Variables ============ */

    address public immutable receiptToken;
    address public immutable operator;          // master Penpie
    uint256 public immutable receiptTokenDecimals;

    address[] public rewardTokens;

    struct Reward {
        address rewardToken;
        uint256 rewardPerTokenStored;
        uint256 queuedRewards;
    }

    struct UserInfo {
        uint256 userRewardPerTokenPaid;
        uint256 userRewards;
    }

    mapping(address => Reward) public rewards;                           // [rewardToken]
    // amount by [rewardToken][account], 
    mapping(address => mapping(address => UserInfo)) public userInfos;
    mapping(address => bool) public isRewardToken;
    mapping(address => bool) public rewardQueuers;

    /* ============ Events ============ */

    event RewardAdded(uint256 _reward, address indexed _token);
    event Staked(address indexed _user, uint256 _amount);
    event Withdrawn(address indexed _user, uint256 _amount);
    event RewardPaid(address indexed _user, address indexed _receiver, uint256 _reward, address indexed _token);
    event RewardQueuerUpdated(address indexed _manager, bool _allowed);

    /* ============ Errors ============ */

    error OnlyRewardQueuer();
    error OnlyMasterPenpie();
    error NotAllowZeroAddress();
    error MustBeRewardToken();

    /* ============ Constructor ============ */

    constructor(
        address _receiptToken,
        address _rewardToken,
        address _masterPenpie,
        address _rewardQueuer
    ) {
        if(
            _receiptToken == address(0) ||
            _masterPenpie  == address(0) ||
            _rewardQueuer  == address(0)
        ) revert NotAllowZeroAddress();

        receiptToken = _receiptToken;
        receiptTokenDecimals = IERC20Metadata(receiptToken).decimals();
        operator = _masterPenpie;

        if (_rewardToken != address(0)) {
            rewards[_rewardToken] = Reward({
                rewardToken: _rewardToken,
                rewardPerTokenStored: 0,
                queuedRewards: 0
            });
            rewardTokens.push(_rewardToken);
            isRewardToken[_rewardToken] = true;
        }

        rewardQueuers[_rewardQueuer] = true;
    }

    /* ============ Modifiers ============ */

    modifier onlyRewardQueuer() {
        if (!rewardQueuers[msg.sender])
            revert OnlyRewardQueuer();
        _;
    }

    modifier onlyMasterPenpie() {
        if (msg.sender != operator)
            revert OnlyMasterPenpie();
        _;
    }

    modifier updateReward(address _account) {
        _updateFor(_account);
        _;
    }

    modifier updateRewards(address _account, address[] memory _rewards) {
        uint256 length = _rewards.length;
        uint256 userShare = balanceOf(_account);
        
        for (uint256 index = 0; index < length; ++index) {
            address rewardToken = _rewards[index];
            UserInfo storage userInfo = userInfos[rewardToken][_account];
            // if a reward stopped queuing, no need to recalculate to save gas fee
            if (userInfo.userRewardPerTokenPaid == rewardPerToken(rewardToken))
                continue;
            userInfo.userRewards = _earned(_account, rewardToken, userShare);
            userInfo.userRewardPerTokenPaid = rewardPerToken(rewardToken);
        }
        _;
    }    

    /* ============ External Getters ============ */

    /// @notice Returns current amount of staked tokens
    /// @return Returns current amount of staked tokens
    function totalStaked() public override virtual view returns (uint256) {
        return IERC20(receiptToken).totalSupply();
    }

    /// @notice Returns amount of staked tokens in master Penpie by account
    /// @param _account Address account
    /// @return Returns amount of staked tokens by account
    function balanceOf(address _account) public override virtual view returns (uint256) {
        return IERC20(receiptToken).balanceOf(_account);
    }

    function stakingDecimals() external override virtual view returns (uint256) {
        return receiptTokenDecimals;
    }

    /// @notice Returns amount of reward token per staking tokens in pool
    /// @param _rewardToken Address reward token
    /// @return Returns amount of reward token per staking tokens in pool
    function rewardPerToken(address _rewardToken)
        public
        override
        view
        returns (uint256)
    {
        return rewards[_rewardToken].rewardPerTokenStored;
    }

    function rewardTokenInfos()
        override
        external
        view
        returns
        (
            address[] memory bonusTokenAddresses,
            string[] memory bonusTokenSymbols
        )
    {
        uint256 rewardTokensLength = rewardTokens.length;
        bonusTokenAddresses = new address[](rewardTokensLength);
        bonusTokenSymbols = new string[](rewardTokensLength);
        for (uint256 i; i < rewardTokensLength; i++) {
            bonusTokenAddresses[i] = rewardTokens[i];
            bonusTokenSymbols[i] = IERC20Metadata(address(bonusTokenAddresses[i])).symbol();
        }
    }

    /// @notice Returns amount of reward token earned by a user
    /// @param _account Address account
    /// @param _rewardToken Address reward token
    /// @return Returns amount of reward token earned by a user
    function earned(address _account, address _rewardToken)
        public
        override
        view
        returns (uint256)
    {
        return _earned(_account, _rewardToken, balanceOf(_account));
    }

    /// @notice Returns amount of all reward tokens
    /// @param _account Address account
    /// @return pendingBonusRewards as amounts of all rewards.
    function allEarned(address _account)
        external
        override
        view
        returns (
            uint256[] memory pendingBonusRewards
        )
    {
        uint256 length = rewardTokens.length;
        pendingBonusRewards = new uint256[](length);
        for (uint256 i = 0; i < length; i++) {
            pendingBonusRewards[i] = earned(_account, rewardTokens[i]);
        }

        return pendingBonusRewards;
    }

    function getRewardLength() external view returns(uint256) {
        return rewardTokens.length;
    }    

    /* ============ External Functions ============ */

    /// @notice Updates the reward information for one account
    /// @param _account Address account
    function updateFor(address _account) override external nonReentrant {
        _updateFor(_account);
    }

    function getReward(address _account, address _receiver)
        public
        onlyMasterPenpie
        nonReentrant
        updateReward(_account)
        returns (bool)
    {
        uint256 length = rewardTokens.length;

        for (uint256 index = 0; index < length; ++index) {
                address rewardToken = rewardTokens[index];
                _sendReward(rewardToken, _account, _receiver);
            }
        return true;
    }

    function getRewards(address _account, address _receiver, address[] memory _rewardTokens) override
        external
        onlyMasterPenpie
        nonReentrant
        updateRewards(_account, _rewardTokens)
    {
       uint256 length = _rewardTokens.length;
        
        for (uint256 index = 0; index < length; ++index) {
            address rewardToken = _rewardTokens[index];
            _sendReward(rewardToken, _account, _receiver);
        }
    }

    /// @notice Sends new rewards to be distributed to the users staking. Only possible to donate already registered token
    /// @param _amountReward Amount of reward token to be distributed
    /// @param _rewardToken Address reward token
    function donateRewards(uint256 _amountReward, address _rewardToken) external nonReentrant {
        if (!isRewardToken[_rewardToken])
            revert MustBeRewardToken();

        _provisionReward(_amountReward, _rewardToken);
    }

    /* ============ Admin Functions ============ */

    function updateRewardQueuer(address _rewardManager, bool _allowed) external onlyOwner {
        rewardQueuers[_rewardManager] = _allowed;

        emit RewardQueuerUpdated(_rewardManager, rewardQueuers[_rewardManager]);
    }

    /// @notice Sends new rewards to be distributed to the users staking. Only callable by manager
    /// @param _amountReward Amount of reward token to be distributed
    /// @param _rewardToken Address reward token
    function queueNewRewards(uint256 _amountReward, address _rewardToken)
        override
        external
        nonReentrant
        onlyRewardQueuer
        returns (bool)
    {
        if (!isRewardToken[_rewardToken]) {
            rewardTokens.push(_rewardToken);
            isRewardToken[_rewardToken] = true;
        }

        _provisionReward(_amountReward, _rewardToken);
        return true;
    }

    /* ============ Internal Functions ============ */

    function _provisionReward(uint256 _amountReward, address _rewardToken) internal {
        IERC20(_rewardToken).safeTransferFrom(
            msg.sender,
            address(this),
            _amountReward
        );
        Reward storage rewardInfo = rewards[_rewardToken];

        uint256 totalStake = totalStaked();
        if (totalStake == 0) {
            rewardInfo.queuedRewards += _amountReward;
        } else {
            if (rewardInfo.queuedRewards > 0) {
                _amountReward += rewardInfo.queuedRewards;
                rewardInfo.queuedRewards = 0;
            }
            rewardInfo.rewardPerTokenStored =
                rewardInfo.rewardPerTokenStored +
                (_amountReward * 10**receiptTokenDecimals) /
                totalStake;
        }
        emit RewardAdded(_amountReward, _rewardToken);
    }

    function _earned(address _account, address _rewardToken, uint256 _userShare) internal view returns (uint256) {
        UserInfo storage userInfo = userInfos[_rewardToken][_account];
        return ((_userShare *
                (rewardPerToken(_rewardToken) -
                    userInfo.userRewardPerTokenPaid)) /
                10**receiptTokenDecimals) + userInfo.userRewards;
    }

    function _sendReward(address _rewardToken, address _account, address _receiver) internal {
        uint256 _amount = userInfos[_rewardToken][_account].userRewards;
        if (_amount != 0) {
            userInfos[_rewardToken][_account].userRewards = 0;
            IERC20(_rewardToken).safeTransfer(_receiver, _amount);
            emit RewardPaid(_account, _receiver, _amount, _rewardToken);
        }
    }

    function _updateFor(address _account) internal {
        uint256 length = rewardTokens.length;
        for (uint256 index = 0; index < length; ++index) {
            address rewardToken = rewardTokens[index];
            UserInfo storage userInfo = userInfos[rewardToken][_account];
            // if a reward stopped queuing, no need to recalculate to save gas fee
            if (userInfo.userRewardPerTokenPaid == rewardPerToken(rewardToken))
                continue;

            userInfo.userRewards = earned(_account, rewardToken);
            userInfo.userRewardPerTokenPaid = rewardPerToken(rewardToken);
        }
    }
}
// ===== FILE: contracts/libraries/math/MarketMathCore.sol =====
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "./Math.sol";
import "./LogExpMath.sol";

import "../PYIndex.sol";
import "../MiniHelpers.sol";
import "../Errors.sol";

struct MarketState {
    int256 totalPt;
    int256 totalSy;
    int256 totalLp;
    address treasury;
    /// immutable variables ///
    int256 scalarRoot;
    uint256 expiry;
    /// fee data ///
    uint256 lnFeeRateRoot;
    uint256 reserveFeePercent; // base 100
    /// last trade data ///
    uint256 lastLnImpliedRate;
}

// params that are expensive to compute, therefore we pre-compute them
struct MarketPreCompute {
    int256 rateScalar;
    int256 totalAsset;
    int256 rateAnchor;
    int256 feeRate;
}

// solhint-disable ordering
library MarketMathCore {
    using Math for uint256;
    using Math for int256;
    using LogExpMath for int256;
    using PYIndexLib for PYIndex;

    int256 internal constant MINIMUM_LIQUIDITY = 10 ** 3;
    int256 internal constant PERCENTAGE_DECIMALS = 100;
    uint256 internal constant DAY = 86400;
    uint256 internal constant IMPLIED_RATE_TIME = 365 * DAY;

    int256 internal constant MAX_MARKET_PROPORTION = (1e18 * 96) / 100;

    using Math for uint256;
    using Math for int256;

    /*///////////////////////////////////////////////////////////////
                UINT FUNCTIONS TO PROXY TO CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function addLiquidity(
        MarketState memory market,
        uint256 syDesired,
        uint256 ptDesired,
        uint256 blockTime
    )
        internal
        pure
        returns (uint256 lpToReserve, uint256 lpToAccount, uint256 syUsed, uint256 ptUsed)
    {
        (
            int256 _lpToReserve,
            int256 _lpToAccount,
            int256 _syUsed,
            int256 _ptUsed
        ) = addLiquidityCore(market, syDesired.Int(), ptDesired.Int(), blockTime);

        lpToReserve = _lpToReserve.Uint();
        lpToAccount = _lpToAccount.Uint();
        syUsed = _syUsed.Uint();
        ptUsed = _ptUsed.Uint();
    }

    function removeLiquidity(
        MarketState memory market,
        uint256 lpToRemove
    ) internal pure returns (uint256 netSyToAccount, uint256 netPtToAccount) {
        (int256 _syToAccount, int256 _ptToAccount) = removeLiquidityCore(market, lpToRemove.Int());

        netSyToAccount = _syToAccount.Uint();
        netPtToAccount = _ptToAccount.Uint();
    }

    function swapExactPtForSy(
        MarketState memory market,
        PYIndex index,
        uint256 exactPtToMarket,
        uint256 blockTime
    ) internal pure returns (uint256 netSyToAccount, uint256 netSyFee, uint256 netSyToReserve) {
        (int256 _netSyToAccount, int256 _netSyFee, int256 _netSyToReserve) = executeTradeCore(
            market,
            index,
            exactPtToMarket.neg(),
            blockTime
        );

        netSyToAccount = _netSyToAccount.Uint();
        netSyFee = _netSyFee.Uint();
        netSyToReserve = _netSyToReserve.Uint();
    }

    function swapSyForExactPt(
        MarketState memory market,
        PYIndex index,
        uint256 exactPtToAccount,
        uint256 blockTime
    ) internal pure returns (uint256 netSyToMarket, uint256 netSyFee, uint256 netSyToReserve) {
        (int256 _netSyToAccount, int256 _netSyFee, int256 _netSyToReserve) = executeTradeCore(
            market,
            index,
            exactPtToAccount.Int(),
            blockTime
        );

        netSyToMarket = _netSyToAccount.neg().Uint();
        netSyFee = _netSyFee.Uint();
        netSyToReserve = _netSyToReserve.Uint();
    }

    /*///////////////////////////////////////////////////////////////
                    CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function addLiquidityCore(
        MarketState memory market,
        int256 syDesired,
        int256 ptDesired,
        uint256 blockTime
    )
        internal
        pure
        returns (int256 lpToReserve, int256 lpToAccount, int256 syUsed, int256 ptUsed)
    {
        /// ------------------------------------------------------------
        /// CHECKS
        /// ------------------------------------------------------------
        if (syDesired == 0 || ptDesired == 0) revert Errors.MarketZeroAmountsInput();
        if (MiniHelpers.isExpired(market.expiry, blockTime)) revert Errors.MarketExpired();

        /// ------------------------------------------------------------
        /// MATH
        /// ------------------------------------------------------------
        if (market.totalLp == 0) {
            lpToAccount = Math.sqrt((syDesired * ptDesired).Uint()).Int() - MINIMUM_LIQUIDITY;
            lpToReserve = MINIMUM_LIQUIDITY;
            syUsed = syDesired;
            ptUsed = ptDesired;
        } else {
            int256 netLpByPt = (ptDesired * market.totalLp) / market.totalPt;
            int256 netLpBySy = (syDesired * market.totalLp) / market.totalSy;
            if (netLpByPt < netLpBySy) {
                lpToAccount = netLpByPt;
                ptUsed = ptDesired;
                syUsed = (market.totalSy * lpToAccount) / market.totalLp;
            } else {
                lpToAccount = netLpBySy;
                syUsed = syDesired;
                ptUsed = (market.totalPt * lpToAccount) / market.totalLp;
            }
        }

        if (lpToAccount <= 0) revert Errors.MarketZeroAmountsOutput();

        /// ------------------------------------------------------------
        /// WRITE
        /// ------------------------------------------------------------
        market.totalSy += syUsed;
        market.totalPt += ptUsed;
        market.totalLp += lpToAccount + lpToReserve;
    }

    function removeLiquidityCore(
        MarketState memory market,
        int256 lpToRemove
    ) internal pure returns (int256 netSyToAccount, int256 netPtToAccount) {
        /// ------------------------------------------------------------
        /// CHECKS
        /// ------------------------------------------------------------
        if (lpToRemove == 0) revert Errors.MarketZeroAmountsInput();

        /// ------------------------------------------------------------
        /// MATH
        /// ------------------------------------------------------------
        netSyToAccount = (lpToRemove * market.totalSy) / market.totalLp;
        netPtToAccount = (lpToRemove * market.totalPt) / market.totalLp;

        if (netSyToAccount == 0 && netPtToAccount == 0) revert Errors.MarketZeroAmountsOutput();

        /// ------------------------------------------------------------
        /// WRITE
        /// ------------------------------------------------------------
        market.totalLp = market.totalLp.subNoNeg(lpToRemove);
        market.totalPt = market.totalPt.subNoNeg(netPtToAccount);
        market.totalSy = market.totalSy.subNoNeg(netSyToAccount);
    }

    function executeTradeCore(
        MarketState memory market,
        PYIndex index,
        int256 netPtToAccount,
        uint256 blockTime
    ) internal pure returns (int256 netSyToAccount, int256 netSyFee, int256 netSyToReserve) {
        /// ------------------------------------------------------------
        /// CHECKS
        /// ------------------------------------------------------------
        if (MiniHelpers.isExpired(market.expiry, blockTime)) revert Errors.MarketExpired();
        if (market.totalPt <= netPtToAccount)
            revert Errors.MarketInsufficientPtForTrade(market.totalPt, netPtToAccount);

        /// ------------------------------------------------------------
        /// MATH
        /// ------------------------------------------------------------
        MarketPreCompute memory comp = getMarketPreCompute(market, index, blockTime);

        (netSyToAccount, netSyFee, netSyToReserve) = calcTrade(
            market,
            comp,
            index,
            netPtToAccount
        );

        /// ------------------------------------------------------------
        /// WRITE
        /// ------------------------------------------------------------
        _setNewMarketStateTrade(
            market,
            comp,
            index,
            netPtToAccount,
            netSyToAccount,
            netSyToReserve,
            blockTime
        );
    }

    function getMarketPreCompute(
        MarketState memory market,
        PYIndex index,
        uint256 blockTime
    ) internal pure returns (MarketPreCompute memory res) {
        if (MiniHelpers.isExpired(market.expiry, blockTime)) revert Errors.MarketExpired();

        uint256 timeToExpiry = market.expiry - blockTime;

        res.rateScalar = _getRateScalar(market, timeToExpiry);
        res.totalAsset = index.syToAsset(market.totalSy);

        if (market.totalPt == 0 || res.totalAsset == 0)
            revert Errors.MarketZeroTotalPtOrTotalAsset(market.totalPt, res.totalAsset);

        res.rateAnchor = _getRateAnchor(
            market.totalPt,
            market.lastLnImpliedRate,
            res.totalAsset,
            res.rateScalar,
            timeToExpiry
        );
        res.feeRate = _getExchangeRateFromImpliedRate(market.lnFeeRateRoot, timeToExpiry);
    }

    function calcTrade(
        MarketState memory market,
        MarketPreCompute memory comp,
        PYIndex index,
        int256 netPtToAccount
    ) internal pure returns (int256 netSyToAccount, int256 netSyFee, int256 netSyToReserve) {
        int256 preFeeExchangeRate = _getExchangeRate(
            market.totalPt,
            comp.totalAsset,
            comp.rateScalar,
            comp.rateAnchor,
            netPtToAccount
        );

        int256 preFeeAssetToAccount = netPtToAccount.divDown(preFeeExchangeRate).neg();
        int256 fee = comp.feeRate;

        if (netPtToAccount > 0) {
            int256 postFeeExchangeRate = preFeeExchangeRate.divDown(fee);
            if (postFeeExchangeRate < Math.IONE)
                revert Errors.MarketExchangeRateBelowOne(postFeeExchangeRate);

            fee = preFeeAssetToAccount.mulDown(Math.IONE - fee);
        } else {
            fee = ((preFeeAssetToAccount * (Math.IONE - fee)) / fee).neg();
        }

        int256 netAssetToReserve = (fee * market.reserveFeePercent.Int()) / PERCENTAGE_DECIMALS;
        int256 netAssetToAccount = preFeeAssetToAccount - fee;

        netSyToAccount = netAssetToAccount < 0
            ? index.assetToSyUp(netAssetToAccount)
            : index.assetToSy(netAssetToAccount);
        netSyFee = index.assetToSy(fee);
        netSyToReserve = index.assetToSy(netAssetToReserve);
    }

    function _setNewMarketStateTrade(
        MarketState memory market,
        MarketPreCompute memory comp,
        PYIndex index,
        int256 netPtToAccount,
        int256 netSyToAccount,
        int256 netSyToReserve,
        uint256 blockTime
    ) internal pure {
        uint256 timeToExpiry = market.expiry - blockTime;

        market.totalPt = market.totalPt.subNoNeg(netPtToAccount);
        market.totalSy = market.totalSy.subNoNeg(netSyToAccount + netSyToReserve);

        market.lastLnImpliedRate = _getLnImpliedRate(
            market.totalPt,
            index.syToAsset(market.totalSy),
            comp.rateScalar,
            comp.rateAnchor,
            timeToExpiry
        );

        if (market.lastLnImpliedRate == 0) revert Errors.MarketZeroLnImpliedRate();
    }

    function _getRateAnchor(
        int256 totalPt,
        uint256 lastLnImpliedRate,
        int256 totalAsset,
        int256 rateScalar,
        uint256 timeToExpiry
    ) internal pure returns (int256 rateAnchor) {
        int256 newExchangeRate = _getExchangeRateFromImpliedRate(lastLnImpliedRate, timeToExpiry);

        if (newExchangeRate < Math.IONE) revert Errors.MarketExchangeRateBelowOne(newExchangeRate);

        {
            int256 proportion = totalPt.divDown(totalPt + totalAsset);

            int256 lnProportion = _logProportion(proportion);

            rateAnchor = newExchangeRate - lnProportion.divDown(rateScalar);
        }
    }

    /// @notice Calculates the current market implied rate.
    /// @return lnImpliedRate the implied rate
    function _getLnImpliedRate(
        int256 totalPt,
        int256 totalAsset,
        int256 rateScalar,
        int256 rateAnchor,
        uint256 timeToExpiry
    ) internal pure returns (uint256 lnImpliedRate) {
        // This will check for exchange rates < Math.IONE
        int256 exchangeRate = _getExchangeRate(totalPt, totalAsset, rateScalar, rateAnchor, 0);

        // exchangeRate >= 1 so its ln >= 0
        uint256 lnRate = exchangeRate.ln().Uint();

        lnImpliedRate = (lnRate * IMPLIED_RATE_TIME) / timeToExpiry;
    }

    /// @notice Converts an implied rate to an exchange rate given a time to expiry. The
    /// formula is E = e^rt
    function _getExchangeRateFromImpliedRate(
        uint256 lnImpliedRate,
        uint256 timeToExpiry
    ) internal pure returns (int256 exchangeRate) {
        uint256 rt = (lnImpliedRate * timeToExpiry) / IMPLIED_RATE_TIME;

        exchangeRate = LogExpMath.exp(rt.Int());
    }

    function _getExchangeRate(
        int256 totalPt,
        int256 totalAsset,
        int256 rateScalar,
        int256 rateAnchor,
        int256 netPtToAccount
    ) internal pure returns (int256 exchangeRate) {
        int256 numerator = totalPt.subNoNeg(netPtToAccount);

        int256 proportion = (numerator.divDown(totalPt + totalAsset));

        if (proportion > MAX_MARKET_PROPORTION)
            revert Errors.MarketProportionTooHigh(proportion, MAX_MARKET_PROPORTION);

        int256 lnProportion = _logProportion(proportion);

        exchangeRate = lnProportion.divDown(rateScalar) + rateAnchor;

        if (exchangeRate < Math.IONE) revert Errors.MarketExchangeRateBelowOne(exchangeRate);
    }

    function _logProportion(int256 proportion) internal pure returns (int256 res) {
        if (proportion == Math.IONE) revert Errors.MarketProportionMustNotEqualOne();

        int256 logitP = proportion.divDown(Math.IONE - proportion);

        res = logitP.ln();
    }

    function _getRateScalar(
        MarketState memory market,
        uint256 timeToExpiry
    ) internal pure returns (int256 rateScalar) {
        rateScalar = (market.scalarRoot * IMPLIED_RATE_TIME.Int()) / timeToExpiry.Int();
        if (rateScalar <= 0) revert Errors.MarketRateScalarBelowZero(rateScalar);
    }

    function setInitialLnImpliedRate(
        MarketState memory market,
        PYIndex index,
        int256 initialAnchor,
        uint256 blockTime
    ) internal pure {
        /// ------------------------------------------------------------
        /// CHECKS
        /// ------------------------------------------------------------
        if (MiniHelpers.isExpired(market.expiry, blockTime)) revert Errors.MarketExpired();

        /// ------------------------------------------------------------
        /// MATH
        /// ------------------------------------------------------------
        int256 totalAsset = index.syToAsset(market.totalSy);
        uint256 timeToExpiry = market.expiry - blockTime;
        int256 rateScalar = _getRateScalar(market, timeToExpiry);

        /// ------------------------------------------------------------
        /// WRITE
        /// ------------------------------------------------------------
        market.lastLnImpliedRate = _getLnImpliedRate(
            market.totalPt,
            totalAsset,
            rateScalar,
            initialAnchor,
            timeToExpiry
        );
    }
}

// ===== FILE: contracts/interfaces/pendle/IPendleMarket.sol =====
// SPDX-License-Identifier: MIT
pragma solidity =0.8.19;

import "./IPPrincipalToken.sol";
import "./IStandardizedYield.sol";
import "./IPYieldToken.sol";

import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";


interface IPendleMarket is IERC20Metadata {

    function readTokens() external view returns (
        IStandardizedYield _SY,
        IPPrincipalToken _PT,
        IPYieldToken _YT
    );

    function rewardState(address _rewardToken) external view returns (
        uint128 index,
        uint128 lastBalance
    );

    function userReward(address token, address user) external view returns (
        uint128 index, uint128 accrued
    );

    function redeemRewards(address user) external returns (uint256[] memory);

    function getRewardTokens() external view returns (address[] memory);
}
// ===== FILE: contracts/interfaces/pendle/IPendleRouter.sol =====
// SPDX-License-Identifier:MIT
pragma solidity =0.8.19;

interface IPendleRouter {
    struct SwapData {
        SwapType swapType;
        address extRouter;
        bytes extCalldata;
        bool needScale;
    }

    enum SwapType {
        NONE,
        KYBERSWAP,
        ONE_INCH,
        // ETH_WETH not used in Aggregator
        ETH_WETH
    }

    struct ApproxParams {
        uint256 guessMin;
        uint256 guessMax;
        uint256 guessOffchain;
        uint256 maxIteration;
        uint256 eps;
    }

    struct TokenInput {
        // Token/Sy data
        address tokenIn;
        uint256 netTokenIn;
        address tokenMintSy;
        address bulk;
        // aggregator data
        address pendleSwap;
        SwapData swapData;
    }

    struct TokenOutput {
        // Token/Sy data
        address tokenOut;
        uint256 minTokenOut;
        address tokenRedeemSy;
        address bulk;
        // aggregator data
        address pendleSwap;
        SwapData swapData;
    }

    function addLiquiditySingleToken(
        address receiver,
        address market,
        uint256 minLpOut,
        ApproxParams calldata guessPtReceivedFromSy,
        TokenInput calldata input
    ) external payable returns (uint256 netLpOut, uint256 netSyFee);

    function redeemDueInterestAndRewards(
        address user,
        address[] calldata sys,
        address[] calldata yts,
        address[] calldata markets
    ) external;

    function removeLiquiditySingleToken(
        address receiver,
        address market,
        uint256 netLpToRemove,
        TokenOutput calldata output
    ) external returns (uint256 netTokenOut, uint256 netSyFee);
}

// ===== FILE: contracts/libraries/TokenHelper.sol =====
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../interfaces/IWETH.sol";

abstract contract TokenHelper {
    using SafeERC20 for IERC20;
    address internal constant NATIVE = address(0);
    uint256 internal constant LOWER_BOUND_APPROVAL = type(uint96).max / 2; // some tokens use 96 bits for approval

    function _transferIn(address token, address from, uint256 amount) internal {
        if (token == NATIVE) require(msg.value == amount, "eth mismatch");
        else if (amount != 0) IERC20(token).safeTransferFrom(from, address(this), amount);
    }

    function _transferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        if (amount != 0) token.safeTransferFrom(from, to, amount);
    }

    function _transferOut(address token, address to, uint256 amount) internal {
        if (amount == 0) return;
        if (token == NATIVE) {
            (bool success, ) = to.call{ value: amount }("");
            require(success, "eth send failed");
        } else {
            IERC20(token).safeTransfer(to, amount);
        }
    }

    function _transferOut(address[] memory tokens, address to, uint256[] memory amounts) internal {
        uint256 numTokens = tokens.length;
        require(numTokens == amounts.length, "length mismatch");
        for (uint256 i = 0; i < numTokens; ) {
            _transferOut(tokens[i], to, amounts[i]);
            unchecked {
                i++;
            }
        }
    }

    function _selfBalance(address token) internal view returns (uint256) {
        return (token == NATIVE) ? address(this).balance : IERC20(token).balanceOf(address(this));
    }

    function _selfBalance(IERC20 token) internal view returns (uint256) {
        return token.balanceOf(address(this));
    }

    /// @notice Approves the stipulated contract to spend the given allowance in the given token
    /// @dev PLS PAY ATTENTION to tokens that requires the approval to be set to 0 before changing it
    function _safeApprove(address token, address to, uint256 value) internal {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(IERC20.approve.selector, to, value)
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))), "Safe Approve");
    }

    function _safeApproveInf(address token, address to) internal {
        if (token == NATIVE) return;
        if (IERC20(token).allowance(address(this), to) < LOWER_BOUND_APPROVAL) {
            _safeApprove(token, to, 0);
            _safeApprove(token, to, type(uint256).max);
        }
    }

    function _wrap_unwrap_ETH(address tokenIn, address tokenOut, uint256 netTokenIn) internal {
        if (tokenIn == NATIVE) IWETH(tokenOut).deposit{ value: netTokenIn }();
        else IWETH(tokenIn).withdraw(netTokenIn);
    }
}

// ===== FILE: contracts/libraries/BulkSellerMathCore.sol =====
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "./TokenHelper.sol";
import "./math/Math.sol";
import "./Errors.sol";

struct BulkSellerState {
    uint256 rateTokenToSy;
    uint256 rateSyToToken;
    uint256 totalToken;
    uint256 totalSy;
    uint256 feeRate;
}

library BulkSellerMathCore {
    using Math for uint256;

    function swapExactTokenForSy(
        BulkSellerState memory state,
        uint256 netTokenIn
    ) internal pure returns (uint256 netSyOut) {
        netSyOut = calcSwapExactTokenForSy(state, netTokenIn);
        state.totalToken += netTokenIn;
        state.totalSy -= netSyOut;
    }

    function swapExactSyForToken(
        BulkSellerState memory state,
        uint256 netSyIn
    ) internal pure returns (uint256 netTokenOut) {
        netTokenOut = calcSwapExactSyForToken(state, netSyIn);
        state.totalSy += netSyIn;
        state.totalToken -= netTokenOut;
    }

    function calcSwapExactTokenForSy(
        BulkSellerState memory state,
        uint256 netTokenIn
    ) internal pure returns (uint256 netSyOut) {
        uint256 postFeeRate = state.rateTokenToSy.mulDown(Math.ONE - state.feeRate);
        assert(postFeeRate != 0);

        netSyOut = netTokenIn.mulDown(postFeeRate);
        if (netSyOut > state.totalSy)
            revert Errors.BulkInsufficientSyForTrade(state.totalSy, netSyOut);
    }

    function calcSwapExactSyForToken(
        BulkSellerState memory state,
        uint256 netSyIn
    ) internal pure returns (uint256 netTokenOut) {
        uint256 postFeeRate = state.rateSyToToken.mulDown(Math.ONE - state.feeRate);
        assert(postFeeRate != 0);

        netTokenOut = netSyIn.mulDown(postFeeRate);
        if (netTokenOut > state.totalToken)
            revert Errors.BulkInsufficientTokenForTrade(state.totalToken, netTokenOut);
    }

    function getTokenProp(BulkSellerState memory state) internal pure returns (uint256) {
        uint256 totalToken = state.totalToken;
        uint256 totalTokenFromSy = state.totalSy.mulDown(state.rateSyToToken);
        return totalToken.divDown(totalToken + totalTokenFromSy);
    }

    function getReBalanceParams(
        BulkSellerState memory state,
        uint256 targetTokenProp
    ) internal pure returns (uint256 netTokenToDeposit, uint256 netSyToRedeem) {
        uint256 currentTokenProp = getTokenProp(state);

        if (currentTokenProp > targetTokenProp) {
            netTokenToDeposit = state
                .totalToken
                .mulDown(currentTokenProp - targetTokenProp)
                .divDown(currentTokenProp);
        } else {
            uint256 currentSyProp = Math.ONE - currentTokenProp;
            netSyToRedeem = state.totalSy.mulDown(targetTokenProp - currentTokenProp).divDown(
                currentSyProp
            );
        }
    }

    function reBalanceTokenToSy(
        BulkSellerState memory state,
        uint256 netTokenToDeposit,
        uint256 netSyFromToken,
        uint256 maxDiff
    ) internal pure {
        uint256 rate = netSyFromToken.divDown(netTokenToDeposit);

        if (!Math.isAApproxB(rate, state.rateTokenToSy, maxDiff))
            revert Errors.BulkBadRateTokenToSy(rate, state.rateTokenToSy, maxDiff);

        state.totalToken -= netTokenToDeposit;
        state.totalSy += netSyFromToken;
    }

    function reBalanceSyToToken(
        BulkSellerState memory state,
        uint256 netSyToRedeem,
        uint256 netTokenFromSy,
        uint256 maxDiff
    ) internal pure {
        uint256 rate = netTokenFromSy.divDown(netSyToRedeem);

        if (!Math.isAApproxB(rate, state.rateSyToToken, maxDiff))
            revert Errors.BulkBadRateSyToToken(rate, state.rateSyToToken, maxDiff);

        state.totalToken += netTokenFromSy;
        state.totalSy -= netSyToRedeem;
    }

    function setRate(
        BulkSellerState memory state,
        uint256 rateSyToToken,
        uint256 rateTokenToSy,
        uint256 maxDiff
    ) internal pure {
        if (
            state.rateTokenToSy != 0 &&
            !Math.isAApproxB(rateTokenToSy, state.rateTokenToSy, maxDiff)
        ) {
            revert Errors.BulkBadRateTokenToSy(rateTokenToSy, state.rateTokenToSy, maxDiff);
        }

        if (
            state.rateSyToToken != 0 &&
            !Math.isAApproxB(rateSyToToken, state.rateSyToToken, maxDiff)
        ) {
            revert Errors.BulkBadRateSyToToken(rateSyToToken, state.rateSyToToken, maxDiff);
        }

        state.rateTokenToSy = rateTokenToSy;
        state.rateSyToToken = rateSyToToken;
    }
}

// ===== FILE: contracts/libraries/WeekMath.sol =====
// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity 0.8.19;

library WeekMath {
    uint128 internal constant WEEK = 7 days;

    function getWeekStartTimestamp(uint128 timestamp) internal pure returns (uint128) {
        return (timestamp / WEEK) * WEEK;
    }

    function getCurrentWeekStart() internal view returns (uint128) {
        return getWeekStartTimestamp(uint128(block.timestamp));
    }

    function isValidWTime(uint256 time) internal pure returns (bool) {
        return time % WEEK == 0;
    }
}

// ===== FILE: contracts/interfaces/pendle/IRewardManager.sol =====
// SPDX-License-Identifier: MIT
pragma solidity =0.8.19;

interface IRewardManager {
    function userReward(
        address token,
        address user
    ) external view returns (uint128 index, uint128 accrued);
}

// ===== FILE: contracts/interfaces/ISmartPendleConvert.sol =====
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

interface ISmartPendleConvert {
    
    function maxSwapAmount() external view returns (uint256);

    function estimateTotalConversion(uint256 _amount,uint256 _convertRatio) external view returns (uint256 minimumEstimatedTotal);

    function smartConvert(
        uint256 _amountIn,
        uint256 _mode
    ) external returns (uint256 obtainedMPendleAmount) ;

    function router() external view returns (address);

    function masterPenpie() external view returns (address);

    function pendleMPendlePool() external view returns (address);
    
    function currentRatio() external view returns (uint256);

    function buybackThreshold() external view returns (uint256);

}

// ===== FILE: contracts/interfaces/IPenpieBribeManager.sol =====
// SPDX-License-Identifier: MIT
pragma solidity =0.8.19;

interface IPenpieBribeManager {
    struct Pool {
        address _market;
        bool _active;
        uint256 _chainId;
    }

    function pools(uint256) external view returns(Pool memory);
    function marketToPid(address _market) external view returns(uint256);
    function exactCurrentEpoch() external view returns(uint256);
    function getEpochEndTime(uint256 _epoch) external view returns(uint256 endTime);
    function addBribeERC20(uint256 _batch, uint256 _pid, address _token, uint256 _amount, bool _forPreviousEpoch) external;
    function newPool(address _market, uint16 _chainId) external;
    function addBribeNative(uint256 _batch, uint256 _pid, bool _forPreviousEpoch) external payable;
    function getPoolLength() external view returns(uint256);
}
// ===== FILE: contracts/interfaces/pendle/IPendleMarketDepositHelper.sol =====
// SPDX-License-Identifier: MIT
pragma solidity =0.8.19;

import "../../libraries/MarketApproxLib.sol";
import "../../libraries/ActionBaseMintRedeem.sol";

interface IPendleMarketDepositHelper {
    function totalStaked(address _market) external view returns (uint256);
    function balance(address _market, address _address) external view returns (uint256);
    function depositMarket(address _market, uint256 _amount) external;
    function depositMarketFor(address _market, address _for, uint256 _amount) external;
    function withdrawMarket(address _market, uint256 _amount) external;
    function withdrawMarketWithClaim(address _market, uint256 _amount, bool _doClaim) external;
    function harvest(address _market, uint256 _minEthToRecieve) external;
    function setPoolInfo(address poolAddress, address rewarder, bool isActive) external;
    function removePoolInfo(address market) external;
    function setOperator(address _address, bool _value) external;
    function setmasterPenpie(address _masterPenpie) external;
}

// ===== FILE: contracts/interfaces/IPendleStaking.sol =====
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../libraries/MarketApproxLib.sol";
import "../libraries/ActionBaseMintRedeem.sol";

interface IPendleStaking {

    function WETH() external view returns (address);

    function convertPendle(uint256 amount, uint256[] calldata chainid) external payable returns (uint256);

    function registerPool(address _market, uint256 _allocPoints, string memory name, string memory symbol) external;

    function vote(address[] calldata _pools, uint64[] calldata _weights) external;

    function depositMarket(address _market, address _for, address _from, uint256 _amount) external;

    function withdrawMarket(address _market,  address _for, uint256 _amount) external;

    function emergencyWithdraw(address _market,  address _for, uint256 _amount) external;

    function harvestMarketReward(address _lpAddress, address _callerAddress, uint256 _minEthRecive) external;
}

// ===== FILE: contracts/interfaces/pendle/IPVeToken.sol =====
// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity =0.8.19;

interface IPVeToken {
    // ============= USER INFO =============

    function balanceOf(address user) external view returns (uint128);

    function positionData(address user) external view returns (uint128 amount, uint128 expiry);

    // ============= META DATA =============

    function totalSupplyStored() external view returns (uint128);

    function totalSupplyCurrent() external returns (uint128);

    function totalSupplyAndBalanceCurrent(address user) external returns (uint128, uint128);
}
// ===== FILE: contracts/pendle/PendleStakingBaseUpg.sol =====
// SPDX-License-Identifier: MIT
pragma solidity =0.8.19;
pragma abicoder v2;

import { IERC20, ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { OwnableUpgradeable } from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";

import { IPendleMarketDepositHelper } from "../interfaces/pendle/IPendleMarketDepositHelper.sol";
import { IPVotingEscrowMainchain } from "../interfaces/pendle/IPVotingEscrowMainchain.sol";
import { IPFeeDistributorV2 } from "../interfaces/pendle/IPFeeDistributorV2.sol";
import { IPVoteController } from "../interfaces/pendle/IPVoteController.sol";
import { IPendleRouter } from "../interfaces/pendle/IPendleRouter.sol";
import { IMasterPenpie } from "../interfaces/IMasterPenpie.sol";
import { IETHZapper } from "../interfaces/IETHZapper.sol";

import "../interfaces/ISmartPendleConvert.sol";
import "../interfaces/IBaseRewardPool.sol";
import "../interfaces/IMintableERC20.sol";
import "../interfaces/IWETH.sol";
import "../interfaces/IPendleStaking.sol";
import "../interfaces/pendle/IPendleMarket.sol";
import "../interfaces/IPenpieBribeManager.sol";

import "../interfaces/IConvertor.sol";
import "../libraries/ERC20FactoryLib.sol";
import "../libraries/WeekMath.sol";

/// @title PendleStakingBaseUpg
/// @notice PendleStaking is the main contract that holds vePendle position on behalf on user to get boosted yield and vote.
///         PendleStaking is the main contract interacting with Pendle Finance side
/// @author Magpie Team

abstract contract PendleStakingBaseUpg is
    Initializable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    IPendleStaking
{
    using SafeERC20 for IERC20;

    /* ============ Structs ============ */

    struct Pool {
        address market;
        address rewarder;
        address helper;
        address receiptToken;
        uint256 lastHarvestTime;
        bool isActive;
    }

    struct Fees {
        uint256 value; // allocation denominated by DENOMINATOR
        address to;
        bool isMPENDLE;
        bool isAddress;
        bool isActive;
    }

    /* ============ State Variables ============ */
    // Addresses
    address public PENDLE;
    address public WETH;
    address public mPendleConvertor;
    address public mPendleOFT;
    address public marketDepositHelper;
    address public masterPenpie;
    address public voteManager;
    uint256 public harvestTimeGap;

    address internal constant NATIVE = address(0);

    //Pendle Finance addresses
    IPVotingEscrowMainchain public vePendle;
    IPFeeDistributorV2 public distributorETH;
    IPVoteController public pendleVote;
    IPendleRouter public pendleRouter;

    mapping(address => Pool) public pools;
    address[] public poolTokenList;

    // Lp Fees
    uint256 constant DENOMINATOR = 10000;
    uint256 public totalPendleFee; // total fee percentage for PENDLE reward
    Fees[] public pendleFeeInfos; // infor of fee and destination
    uint256 public autoBribeFee; // fee for any reward other than PENDLE

    // vePendle Fees
    uint256 public vePendleHarvestCallerFee;
    uint256 public protocolFee; // fee charged by penpie team for operation
    address public feeCollector; // penpie team fee destination
    address public bribeManagerEOA; // An EOA address to later user vePendle harvested reward as bribe

    /* ===== 1st upgrade ===== */
    address public bribeManager;
    address public smartPendleConvert;
    address public ETHZapper;
    uint256 public harvestCallerPendleFee;

    /* ===== 2nd upgrade ===== */
    address public mgpBlackHole;
    uint256 public mPendleBurnRatio;

    /* ===== 3rd upgrade ===== */
    address public pendleMarketRegisterHelper;

    /* ===== 4th upgrade ===== */
    mapping(address => uint256) public affectedMarketWithdrawRatio;
    mapping(address => bool) public allowedPauser;

    /* ===== 5th upgrade ===== */
    mapping(address => bool) public ismPendleRewardMarket;

    /* ===== 6th upgrade ===== */
    mapping(address => bool) public nonHarvestablePools;

    uint256[39] private __gap;

    /* ============ Events ============ */

    // Admin
    event PoolAdded(address _market, address _rewarder, address _receiptToken);
    event PoolRemoved(address indexed _market);

    event SetMPendleConvertor(address _oldmPendleConvertor, address _newmPendleConvertor);
    event PendleMarketRegisterHelperSet(address _pendleMarketRegisterHelper);

    // Fee
    event AddPendleFee(address _to, uint256 _value, bool _isMPENDLE, bool _isAddress);
    event SetPendleFee(address _to, uint256 _value);
    event RemovePendleFee(uint256 value, address to, bool _isMPENDLE, bool _isAddress);
    event RewardPaidTo(address _market, address _to, address _rewardToken, uint256 _feeAmount);
    event VePendleHarvested(
        uint256 _total,
        address[] _pool,
        uint256[] _totalAmounts,
        uint256 _protocolFee,
        uint256 _callerFee,
        uint256 _rest
    );

    event NewMarketDeposit(
        address indexed _user,
        address indexed _market,
        uint256 _lpAmount,
        address indexed _receptToken,
        uint256 _receptAmount
    );
    event NewMarketWithdraw(
        address indexed _user,
        address indexed _market,
        uint256 _lpAmount,
        address indexed _receptToken,
        uint256 _receptAmount
    );
    event PendleLocked(uint256 _amount, uint256 _lockDays, uint256 _vePendleAccumulated);

    // Vote Manager
    event VoteSet(
        address _voter,
        uint256 _vePendleHarvestCallerFee,
        uint256 _harvestCallerPendleFee,
        uint256 _voteProtocolFee,
        address _voteFeeCollector
    );
    event VoteManagerUpdated(address _oldVoteManager, address _voteManager);
    event BribeManagerUpdated(address _oldBribeManager, address _bribeManager);
    event BribeManagerEOAUpdated(address _oldBribeManagerEOA, address _bribeManagerEOA);

    event SmartPendleConvertUpdated(address _OldSmartPendleConvert, address _smartPendleConvert);

    event PoolHelperUpdated(address _market);
    event MgpBlackHoleSet(address indexed _mgpBlackHole, uint256 _mPendleBurnRatio);
    event AffectedMarketWithdrawRatioSet(address indexed _market, uint256 _withdrawRatio);
    event MPendleBurn(address indexed _mgpBlackHole, uint256 _burnAmount);
    event EmergencyWithdraw(address indexed _for, uint256 _withdrawAmount);
    event UpdatePauserStatus(address indexed _pauser, bool _allowed);
    event UpdateMPendleRewardMarketStatus(address indexed _market, bool _allowed);
    event UpdateNonHarvestableMarketStatus(address indexed _market, bool _allowed);
    event MasterPenpieSet(address indexed _masterPenpie);
    event MPendleOFTSet(address indexed _mPendleOFT);
    event ETHZapperSet(address indexed _ETHZapper);
    event MarketDepositHelperSet(address indexed _helper);
    event HarvestTimeGapSet(uint256 _period);
    event AutoBribeFeeSet(uint256 _autoBribeFee);

    /* ============ Errors ============ */

    error OnlyPoolHelper();
    error OnlyPoolRegisterHelper();
    error OnlyActivePool();
    error PoolOccupied();
    error InvalidFee();
    error LengthMismatch();
    error OnlyVoteManager();
    error TimeGapTooMuch();
    error NoVePendleReward();
    error InvalidFeeDestination();
    error ZeroNotAllowed();
    error InvalidAddress();
    error OnlyPauser();
    error InvalidWithdrawAmount();
    error OnlyDeactivatePool();
    error InvalidWithdrawRatio();
    error InvalidIndex();

    /* ============ Constructor ============ */

    function __PendleStakingBaseUpg_init(
        address _pendle,
        address _WETH,
        address _vePendle,
        address _distributorETH,
        address _pendleRouter,
        address _masterPenpie
    ) public  onlyInitializing {
        __Ownable_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        PENDLE = _pendle;
        WETH = _WETH;
        masterPenpie = _masterPenpie;
        vePendle = IPVotingEscrowMainchain(_vePendle);
        distributorETH = IPFeeDistributorV2(_distributorETH);
        pendleRouter = IPendleRouter(_pendleRouter);
    }

    /* ============ Modifiers ============ */

    modifier _onlyActivePool(address _market) {
        Pool storage poolInfo = pools[_market];

        if (!poolInfo.isActive) revert OnlyActivePool();
        _;
    }

    modifier _onlyActivePoolHelper(address _market) {
        Pool storage poolInfo = pools[_market];

        if (msg.sender != poolInfo.helper) revert OnlyPoolHelper();
        if (!poolInfo.isActive) revert OnlyActivePool();
        _;
    }

    modifier _onlyInactivePoolHelper(address _market) {
        Pool storage poolInfo = pools[_market];

        if (msg.sender != poolInfo.helper) revert OnlyPoolHelper();
        if (poolInfo.isActive) revert OnlyDeactivatePool();
        _;
    }

    modifier _onlyPoolRegisterHelper() {
        if (msg.sender != pendleMarketRegisterHelper) revert OnlyPoolRegisterHelper();
        _;
    }

    modifier onlyPauser() {
        if (!allowedPauser[msg.sender]) revert OnlyPauser();
        _;
    }    

    /* ============ External Getters ============ */

    receive() external payable {
        // Deposit ETH to WETH
        IWETH(WETH).deposit{ value: msg.value }();
    }

    /// @notice get the number of vePendle of this contract
    function accumulatedVePendle() public view returns (uint256) {
        return IPVotingEscrowMainchain(vePendle).balanceOf(address(this));
    }

    function getPoolLength() external view returns (uint256) {
        return poolTokenList.length;
    }

    /* ============ External Functions ============ */

    function depositMarket(
        address _market,
        address _for,
        address _from,
        uint256 _amount
    ) external override nonReentrant whenNotPaused _onlyActivePoolHelper(_market) {
        Pool storage poolInfo = pools[_market];
        _harvestMarketRewards(poolInfo.market, false);

        IERC20(poolInfo.market).safeTransferFrom(_from, address(this), _amount);

        // mint the receipt to the user driectly
        IMintableERC20(poolInfo.receiptToken).mint(_for, _amount);

        emit NewMarketDeposit(_for, _market, _amount, poolInfo.receiptToken, _amount);
    }

    function withdrawMarket(
        address _market,
        address _for,
        uint256 _amount
    ) external override nonReentrant whenNotPaused _onlyActivePoolHelper(_market) {
        Pool storage poolInfo = pools[_market];
        _harvestMarketRewards(poolInfo.market, false);

        IMintableERC20(poolInfo.receiptToken).burn(_for, _amount);

        IERC20(poolInfo.market).safeTransfer(_for, _amount);
        // emit New withdraw
        emit NewMarketWithdraw(_for, _market, _amount, poolInfo.receiptToken, _amount);
    }

    /// @notice harvest a Rewards from Pendle Liquidity Pool
    /// @param _market Pendle Pool lp as helper identifier
    function harvestMarketReward(
        address _market,
        address _caller,
        uint256 _minEthRecive
    ) external nonReentrant whenNotPaused {
        address[] memory _markets = new address[](1);
        _markets[0] = _market;
        _harvestBatchMarketRewards(_markets, _caller, _minEthRecive); // triggers harvest from Pendle finance
    }

    function batchHarvestMarketRewards(
        address[] calldata _markets,
        uint256 minEthToRecieve
    ) external nonReentrant whenNotPaused {
        _harvestBatchMarketRewards(_markets, msg.sender, minEthToRecieve);
    }

    function emergencyWithdraw(
        address _market,
        address _for,
        uint256 _receiptAmount
    ) external nonReentrant whenNotPaused _onlyInactivePoolHelper(_market) {
        Pool storage poolInfo = pools[_market];
        _harvestMarketRewards(poolInfo.market, false);
        uint256 withdrawAmount = (_receiptAmount * affectedMarketWithdrawRatio[_market]) / DENOMINATOR;

        if (withdrawAmount == 0) revert InvalidWithdrawAmount();

        IMintableERC20(poolInfo.receiptToken).burn(_for, _receiptAmount);
        IERC20(poolInfo.market).safeTransfer(_for, withdrawAmount);

        emit EmergencyWithdraw(_for, withdrawAmount);
    }

    /* ============ Admin Functions ============ */

    function registerPool(
        address _market,
        uint256 _allocPoints,
        string memory name,
        string memory symbol
    ) external onlyOwner {
        if (pools[_market].market != address(0)) {
            revert PoolOccupied();
        }

        IERC20 newToken = IERC20(
            ERC20FactoryLib.createReceipt(_market, masterPenpie, name, symbol)
        );

        address rewarder = IMasterPenpie(masterPenpie).createRewarder(
            address(newToken),
            address(PENDLE)
        );

        IPendleMarketDepositHelper(marketDepositHelper).setPoolInfo(_market, rewarder, true);

        IMasterPenpie(masterPenpie).add(
            _allocPoints,
            address(_market),
            address(newToken),
            address(rewarder)
        );

        pools[_market] = Pool({
            isActive: true,
            market: _market,
            receiptToken: address(newToken),
            rewarder: address(rewarder),
            helper: marketDepositHelper,
            lastHarvestTime: block.timestamp
        });
        poolTokenList.push(_market);

        emit PoolAdded(_market, address(rewarder), address(newToken));
    }

    function updateAllowedPauser(address _pauser, bool _allowed) external onlyOwner {
        allowedPauser[_pauser] = _allowed;

        emit UpdatePauserStatus(_pauser, _allowed);
    }

    // This function is only for removing malicious pool in this incident, once clean up, this function shall be deleted
    function batchRemovePools(address[] memory _addresses) nonReentrant onlyOwner external {
        for (uint256 i = 0; i < _addresses.length; i++) {
            _removePool(_addresses[i]);
        }
    }

    function _removePool(address _market) internal {
        uint256 length = poolTokenList.length;
        for (uint i = length; i > 0; i--) {
            if (poolTokenList[i-1] == _market) {
                if ((i - 1) != (length - 1)) {
                    poolTokenList[i - 1] = poolTokenList[length - 1];
                }
                poolTokenList.pop();
                break;
            }
        }
        
        delete pools[_market];

        IPendleMarketDepositHelper(marketDepositHelper).removePoolInfo(_market);
        IMasterPenpie(masterPenpie).removePool(_market);

        emit PoolRemoved(_market);
    }

    // /// @notice set the mPendleConvertor address
    // /// @param _mPendleConvertor the mPendleConvertor address
    // function setMPendleConvertor(address _mPendleConvertor) external onlyOwner {
    //     address oldMPendleConvertor = mPendleConvertor;
    //     mPendleConvertor = _mPendleConvertor;

    //     emit SetMPendleConvertor(oldMPendleConvertor, mPendleConvertor);
    // }

    // function setVoteManager(address _voteManager) external onlyOwner {
    //     address oldVoteManager = voteManager;
    //     voteManager = _voteManager;

    //     emit VoteManagerUpdated(oldVoteManager, voteManager);
    // }

    function setAffectedMarketWithdrawRatio(address _market, uint256 _withdrawRatio) external onlyOwner {
        if (_market == address(0)) revert InvalidAddress();
        if(_withdrawRatio > DENOMINATOR) revert InvalidWithdrawRatio();

        affectedMarketWithdrawRatio[_market] = _withdrawRatio;
        emit AffectedMarketWithdrawRatioSet(_market, _withdrawRatio);
    }

    // function setMGPBlackHole(address _mgpBlackHole, uint256 _mPendleBurnRatio) external onlyOwner {
    //     if (_mgpBlackHole == address(0)) revert InvalidAddress();
    //     require(_mPendleBurnRatio <= DENOMINATOR, "mPendle Burn Ratio cannot be greater than 100%.");
    //     mgpBlackHole = _mgpBlackHole;
    //     mPendleBurnRatio = _mPendleBurnRatio;
    //     emit MgpBlackHoleSet(_mgpBlackHole, _mPendleBurnRatio);
    // }

    function updateMPendleRewardMarket(address _market, bool _allowed) external onlyOwner {
        ismPendleRewardMarket[_market] = _allowed;

        emit UpdateMPendleRewardMarketStatus(_market, _allowed);
    }

    function updateNonHarvestableMarket(address _market, bool _allowed) external onlyOwner {
        nonHarvestablePools[_market] = _allowed;

        emit UpdateNonHarvestableMarketStatus(_market, _allowed);
    }

    // function setBribeManager(address _bribeManager, address _bribeManagerEOA) external onlyOwner {
    //     address oldBribeManager = bribeManager;
    //     bribeManager = _bribeManager;

    //     address oldBribeManagerEOA = bribeManagerEOA;
    //     bribeManagerEOA = _bribeManagerEOA;

    //     emit BribeManagerUpdated(oldBribeManager, bribeManager);
    //     emit BribeManagerEOAUpdated(oldBribeManagerEOA, bribeManagerEOA);
    // }

    // function setmasterPenpie(address _masterPenpie) external onlyOwner {
    //     masterPenpie = _masterPenpie;

    //     emit MasterPenpieSet(_masterPenpie);
    // }

    // function setPendleMarketRegisterHelper(address _pendleMarketRegisterHelper) external onlyOwner {
    //     if (_pendleMarketRegisterHelper == address(0)) revert InvalidAddress();
    //     pendleMarketRegisterHelper = _pendleMarketRegisterHelper;

    //     emit PendleMarketRegisterHelperSet(_pendleMarketRegisterHelper);
    // }

    // function setMPendleOFT(address _setMPendleOFT) external onlyOwner {
    //     mPendleOFT = _setMPendleOFT;

    //     emit MPendleOFTSet(_setMPendleOFT);
    // }

    // function setETHZapper(address _ETHZapper) external onlyOwner {
    //     ETHZapper = _ETHZapper;

    //     emit ETHZapperSet(_ETHZapper);
    // }

    /**
     * @notice pause Pendle staking, restricting certain operations
     */
    function pause() external onlyPauser {
        _pause();
    }

    /**
     * @notice unpause Pendle staking, enabling certain operations
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice This function adds a fee to the magpie protocol
    /// @param _value the initial value for that fee
    /// @param _to the address or contract that receives the fee
    /// @param _isMPENDLE true if the fee is sent as MPENDLE, otherwise it will be PENDLE
    /// @param _isAddress true if the receiver is an address, otherwise it's a BaseRewarder
    function addPendleFee(
        uint256 _value,
        address _to,
        bool _isMPENDLE,
        bool _isAddress
    ) external onlyOwner {
        if (_value >= DENOMINATOR) revert InvalidFee();

        pendleFeeInfos.push(
            Fees({
                value: _value,
                to: _to,
                isMPENDLE: _isMPENDLE,
                isAddress: _isAddress,
                isActive: true
            })
        );
        totalPendleFee += _value;

        emit AddPendleFee(_to, _value, _isMPENDLE, _isAddress);
    }

    /**
     * @dev Set the Pendle fee.
     * @param _index The index of the fee.
     * @param _value The value of the fee.
     * @param _to The address to which the fee is sent.
     * @param _isMPENDLE Boolean indicating if the fee is in MPENDLE.
     * @param _isAddress Boolean indicating if the fee is in an external token.
     * @param _isActive Boolean indicating if the fee is active.
     */
    function setPendleFee(
        uint256 _index,
        uint256 _value,
        address _to,
        bool _isMPENDLE,
        bool _isAddress,
        bool _isActive
    ) external onlyOwner {
        if (_value >= DENOMINATOR) revert InvalidFee();
        if (_index >= pendleFeeInfos.length) revert InvalidIndex();

        Fees storage fee = pendleFeeInfos[_index];
        fee.to = _to;
        fee.isMPENDLE = _isMPENDLE;
        fee.isAddress = _isAddress;
        fee.isActive = _isActive;

        totalPendleFee = totalPendleFee - fee.value + _value;
        fee.value = _value;
        if(totalPendleFee > DENOMINATOR) revert InvalidFee();

        emit SetPendleFee(fee.to, _value);
    }

    /// @notice remove some fee
    /// @param _index the index of the fee in the fee list
    function removePendleFee(uint256 _index) external onlyOwner {
        if (_index >= pendleFeeInfos.length) revert InvalidIndex();
        Fees memory feeToRemove = pendleFeeInfos[_index];

        for (uint i = _index; i < pendleFeeInfos.length - 1; i++) {
            pendleFeeInfos[i] = pendleFeeInfos[i + 1];
        }
        pendleFeeInfos.pop();
        totalPendleFee -= feeToRemove.value;

        emit RemovePendleFee(
            feeToRemove.value,
            feeToRemove.to,
            feeToRemove.isMPENDLE,
            feeToRemove.isAddress
        );
    }

    function setVote(
        address _pendleVote,
        uint256 _vePendleHarvestCallerFee,
        uint256 _harvestCallerPendleFee,
        uint256 _protocolFee,
        address _feeCollector
    ) external onlyOwner {
        if ((_vePendleHarvestCallerFee + _protocolFee) > DENOMINATOR) revert InvalidFee();

        if ((_harvestCallerPendleFee + _protocolFee) > DENOMINATOR) revert InvalidFee();

        pendleVote = IPVoteController(_pendleVote);
        vePendleHarvestCallerFee = _vePendleHarvestCallerFee;
        harvestCallerPendleFee = _harvestCallerPendleFee;
        protocolFee = _protocolFee;
        feeCollector = _feeCollector;

        emit VoteSet(
            _pendleVote,
            vePendleHarvestCallerFee,
            harvestCallerPendleFee,
            protocolFee,
            feeCollector
        );
    }

    // function setMarketDepositHelper(address _helper) external onlyOwner {
    //     marketDepositHelper = _helper;

    //     emit MarketDepositHelperSet(_helper);
    // }

    // function setHarvestTimeGap(uint256 _period) external onlyOwner {
    //     if (_period > 4 hours) revert TimeGapTooMuch();

    //     harvestTimeGap = _period;

    //     emit HarvestTimeGapSet(_period);
    // }

    // function setSmartConvert(address _smartPendleConvert) external onlyOwner {
    //     if (_smartPendleConvert == address(0)) revert InvalidAddress();
    //     address oldSmartPendleConvert = smartPendleConvert;
    //     smartPendleConvert = _smartPendleConvert;

    //     emit SmartPendleConvertUpdated(oldSmartPendleConvert, smartPendleConvert);
    // }

    // function setAutoBribeFee(uint256 _autoBribeFee) external onlyOwner {
    //     if (_autoBribeFee > DENOMINATOR) revert InvalidFee();
    //     autoBribeFee = _autoBribeFee;

    //     emit AutoBribeFeeSet(_autoBribeFee);
    // }

    function updateMarketRewards(address _market, uint256[] memory amounts) external onlyOwner {
        Pool storage poolInfo = pools[_market];
        address[] memory bonusTokens = IPendleMarket(_market).getRewardTokens();
        require(bonusTokens.length == amounts.length, "...");
        if (nonHarvestablePools[_market]) return;

        uint256 pendleBefore = IERC20(PENDLE).balanceOf(address(this));
        uint256 pendleToSend;
        for (uint256 i; i < bonusTokens.length; i++) {
            if (bonusTokens[i] == NATIVE) bonusTokens[i] = address(WETH);
            uint256 leftAmounts = amounts[i];
            if(bonusTokens[i] == PENDLE)
                pendleToSend = amounts[i];
            _sendRewards(_market, bonusTokens[i], poolInfo.rewarder, amounts[i], leftAmounts);
        }
        // pendleToSend will always be > the pendle bal diff before and after
        uint256 pendleForMPendleFee = pendleToSend - (pendleBefore - IERC20(PENDLE).balanceOf(address(this)));
        _sendMPendleFees(pendleForMPendleFee);
    }

    function updatePoolHelper(
        address _market,
        address _helper,
        bool _isActive,
        uint256 _allocPoints
    ) external onlyOwner {
        if (_helper == address(0) || _market == address(0)) revert InvalidAddress();

        Pool storage poolInfo = pools[_market];
        poolInfo.helper = _helper;
        poolInfo.isActive = _isActive;

        IPendleMarketDepositHelper(_helper).setPoolInfo(
            _market,
            poolInfo.rewarder,
            _isActive
        );

        IMasterPenpie(masterPenpie).set(
            address(_market),
            _allocPoints,
            poolInfo.rewarder,
            _isActive
        );

        emit PoolHelperUpdated(_market);
    }

    /* ============ Internal Functions ============ */

    function _harvestMarketRewards(address _market, bool _force) internal {
        if (nonHarvestablePools[_market]) return;

        Pool storage poolInfo = pools[_market];
        if (!_force && (block.timestamp - poolInfo.lastHarvestTime) < harvestTimeGap) return;
        uint256 pendleBefore = IERC20(PENDLE).balanceOf(address(this));

        poolInfo.lastHarvestTime = block.timestamp;

        address[] memory bonusTokens = IPendleMarket(_market).getRewardTokens();
        uint256[] memory amountsBefore = new uint256[](bonusTokens.length);

        for (uint256 i; i < bonusTokens.length; i++) {
            if (bonusTokens[i] == NATIVE) bonusTokens[i] = address(WETH);
            amountsBefore[i] = IERC20(bonusTokens[i]).balanceOf(address(this));
        }

        IPendleMarket(_market).redeemRewards(address(this));

        for (uint256 i; i < bonusTokens.length; i++) {
            uint256 amountAfter = IERC20(bonusTokens[i]).balanceOf(address(this));
            uint256 bonusBalance = amountAfter - amountsBefore[i];
            uint256 leftBonusBalance = bonusBalance;
            if (bonusBalance > 0) {
                _sendRewards(
                    _market,
                    bonusTokens[i],
                    poolInfo.rewarder,
                    bonusBalance,
                    leftBonusBalance
                );
            }
        }

        uint256 pendleForMPendleFee = IERC20(PENDLE).balanceOf(address(this)) - pendleBefore;
        _sendMPendleFees(pendleForMPendleFee);
    }

    function _harvestBatchMarketRewards(
        address[] memory _markets,
        address _caller,
        uint256 _minEthToRecieve
    ) internal {
        uint256 harvestCallerTotalPendleReward;
        uint256 pendleBefore = IERC20(PENDLE).balanceOf(address(this));

        for (uint256 i = 0; i < _markets.length; i++) {
            if (!pools[_markets[i]].isActive) revert OnlyActivePool();
            if (nonHarvestablePools[_markets[i]]) continue;

            Pool storage poolInfo = pools[_markets[i]];

            poolInfo.lastHarvestTime = block.timestamp;

            address[] memory bonusTokens = IPendleMarket(_markets[i]).getRewardTokens();
            uint256[] memory amountsBefore = new uint256[](bonusTokens.length);

            for (uint256 j; j < bonusTokens.length; j++) {
                if (bonusTokens[j] == NATIVE) bonusTokens[j] = address(WETH);

                amountsBefore[j] = IERC20(bonusTokens[j]).balanceOf(address(this));
            }

            IPendleMarket(_markets[i]).redeemRewards(address(this));

            for (uint256 j; j < bonusTokens.length; j++) {
                uint256 amountAfter = IERC20(bonusTokens[j]).balanceOf(address(this));

                uint256 originalBonusBalance = amountAfter - amountsBefore[j];
                uint256 leftBonusBalance = originalBonusBalance;
                uint256 currentMarketHarvestPendleReward;

                if (originalBonusBalance == 0) continue;

                if (bonusTokens[j] == PENDLE) {
                    currentMarketHarvestPendleReward =
                        (originalBonusBalance * harvestCallerPendleFee) /
                        DENOMINATOR;
                    leftBonusBalance = originalBonusBalance - currentMarketHarvestPendleReward;
                }
                harvestCallerTotalPendleReward += currentMarketHarvestPendleReward;

                _sendRewards(
                    _markets[i],
                    bonusTokens[j],
                    poolInfo.rewarder,
                    originalBonusBalance,
                    leftBonusBalance
                );
            }
        }

        uint256 pendleForMPendleFee = IERC20(PENDLE).balanceOf(address(this)) - pendleBefore - harvestCallerTotalPendleReward;
        _sendMPendleFees(pendleForMPendleFee);

        if (harvestCallerTotalPendleReward > 0) {
            IERC20(PENDLE).approve(ETHZapper, harvestCallerTotalPendleReward);

            IETHZapper(ETHZapper).swapExactTokensToETH(
                PENDLE,
                harvestCallerTotalPendleReward,
                _minEthToRecieve,
                _caller
            );
        }
    }

    function _sendMPendleFees(uint256 _pendleAmount) internal {
        uint256 totalmPendleFees;
        uint256 mPendleFeesToSend;

        if (_pendleAmount > 0) {
            mPendleFeesToSend = _convertPendleTomPendle(_pendleAmount);
        } else {
            return; // no need to send mPendle
        }

        for (uint256 i = 0; i < pendleFeeInfos.length; i++) {
            Fees storage feeInfo = pendleFeeInfos[i];
            if (feeInfo.isActive && feeInfo.isMPENDLE){
                totalmPendleFees+=feeInfo.value;
            }
        }
        if(totalmPendleFees == 0) return;

        for (uint256 i = 0; i < pendleFeeInfos.length; i++) {
            Fees storage feeInfo = pendleFeeInfos[i];
            if (feeInfo.isActive && feeInfo.isMPENDLE) {
                uint256 amount = mPendleFeesToSend * feeInfo.value / totalmPendleFees;
                if(amount > 0){
                    if (!feeInfo.isAddress) {
                        IERC20(mPendleOFT).safeApprove(feeInfo.to, amount);
                        IBaseRewardPool(feeInfo.to).queueNewRewards(amount, mPendleOFT);
                    } else {
                        IERC20(mPendleOFT).safeTransfer(feeInfo.to, amount);
                    }
                }
            }
        }
    }

    function _convertPendleTomPendle(uint256 _pendleAmount) internal returns(uint256 mPendleToSend) {
        uint256 mPendleBefore = IERC20(mPendleOFT).balanceOf(address(this));

        if (smartPendleConvert != address(0)) {
            IERC20(PENDLE).safeApprove(smartPendleConvert, _pendleAmount);
            ISmartPendleConvert(smartPendleConvert).smartConvert(_pendleAmount, 0);
            mPendleToSend = IERC20(mPendleOFT).balanceOf(address(this)) - mPendleBefore;
        } else {
            IERC20(PENDLE).safeApprove(mPendleConvertor, _pendleAmount);
            IConvertor(mPendleConvertor).convert(address(this), _pendleAmount, 0);
            mPendleToSend = IERC20(mPendleOFT).balanceOf(address(this)) - mPendleBefore;
        }
    }

    /// @notice Send rewards to the rewarders
    /// @param _market the PENDLE market
    /// @param _rewardToken the address of the reward token to send
    /// @param _rewarder the rewarder for PENDLE lp that will get the rewards
    /// @param _originalRewardAmount  the initial amount of rewards after harvest
    /// @param _leftRewardAmount the intial amount - harvest caller rewardfee amount after harvest
    function _sendRewards(
        address _market,
        address _rewardToken,
        address _rewarder,
        uint256 _originalRewardAmount,
        uint256 _leftRewardAmount
    ) internal {
        if (_leftRewardAmount == 0) return;

        if (_rewardToken == address(PENDLE)) {
            for (uint256 i = 0; i < pendleFeeInfos.length; i++) {
                Fees storage feeInfo = pendleFeeInfos[i];

                if (feeInfo.isActive) {
                    uint256 feeAmount = (_originalRewardAmount * feeInfo.value) / DENOMINATOR;
                    _leftRewardAmount -= feeAmount;
                    uint256 feeTosend = feeAmount;

                    if (!feeInfo.isMPENDLE) {
                        if (!feeInfo.isAddress) {
                            IERC20(_rewardToken).safeApprove(feeInfo.to, feeTosend);
                            IBaseRewardPool(feeInfo.to).queueNewRewards(feeTosend, _rewardToken);
                        } else {
                            IERC20(_rewardToken).safeTransfer(feeInfo.to, feeTosend);
                        }
                    }
                    emit RewardPaidTo(_market, feeInfo.to, _rewardToken, feeTosend);
                }
            }
        } else {
            // other than PENDLE reward token.
            // if auto Bribe fee is 0, then all go to LP rewarder
            if (autoBribeFee > 0 && bribeManager != address(0)) {
                uint256 bribePid = IPenpieBribeManager(bribeManager).marketToPid(_market);
                if (IPenpieBribeManager(bribeManager).pools(bribePid)._active) {
                    uint256 autoBribeAmount = (_originalRewardAmount * autoBribeFee) / DENOMINATOR;
                    _leftRewardAmount -= autoBribeAmount;
                    IERC20(_rewardToken).safeApprove(bribeManager, autoBribeAmount);
                    IPenpieBribeManager(bribeManager).addBribeERC20(
                        1,
                        bribePid,
                        _rewardToken,
                        autoBribeAmount,
                        false
                    );

                    emit RewardPaidTo(_market, bribeManager, _rewardToken, autoBribeAmount);
                }
            }
        }

        _queueRewarder(_market, _rewardToken, _rewarder, _leftRewardAmount);
    }

    function _queueRewarder(address _market, address _rewardToken, address _rewarder, uint256 _leftRewardAmount) internal {
        if(ismPendleRewardMarket[_market] && _rewardToken == address(PENDLE)){
            uint256 mPendleToSend;
            if(_leftRewardAmount == 0) return;
            mPendleToSend = _convertPendleTomPendle(_leftRewardAmount);
            
            uint256 mPendleToMgpBlackHole = (mPendleToSend * mPendleBurnRatio) / DENOMINATOR;
            uint256 mPendleToQueue = mPendleToSend - mPendleToMgpBlackHole;
            _rewardToken = mPendleOFT;
            _leftRewardAmount = mPendleToQueue;
            IERC20(mPendleOFT).safeTransfer(mgpBlackHole, mPendleToMgpBlackHole);
            emit MPendleBurn(mgpBlackHole, mPendleToMgpBlackHole);
        }
        IERC20(_rewardToken).safeApprove(_rewarder, 0);
        IERC20(_rewardToken).safeApprove(_rewarder, _leftRewardAmount);
        IBaseRewardPool(_rewarder).queueNewRewards(_leftRewardAmount, _rewardToken);
        emit RewardPaidTo(_market, _rewarder, _rewardToken, _leftRewardAmount);
    }
}
// ===== FILE: contracts/interfaces/IConvertor.sol =====
// SPDX-License-Identifier: MIT
pragma solidity =0.8.19;

interface IConvertor {
    function convert(address _for, uint256 _amount, uint256 _mode) external;

    function convertFor(
        uint256 _amountIn,
        uint256 _convertRatio,
        uint256 _minRec,
        address _for,
        uint256 _mode
    ) external;

    function smartConvertFor(uint256 _amountIn, uint256 _mode, address _for) external returns (uint256 obtainedmWomAmount);

    function mPendleSV() external returns (address);

    function mPendleConvertor() external returns (address);
}
// ===== FILE: contracts/libraries/MintableERC20.sol =====
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (token/ERC20/ERC20.sol)
pragma solidity ^0.8.0;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

contract MintableERC20 is ERC20, Ownable {
    /*
    The ERC20 deployed will be owned by the others contracts of the protocol, specifically by
    MasterMagpie and WombatStaking, forbidding the misuse of these functions for nefarious purposes
    */
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {} 

    function mint(address account, uint256 amount) external virtual onlyOwner {
        _mint(account, amount);
    }

    function burn(address account, uint256 amount) external virtual onlyOwner {
        _burn(account, amount);
    }
}
// ===== FILE: contracts/libraries/math/Math.sol =====
// SPDX-License-Identifier: GPL-3.0-or-later
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

pragma solidity 0.8.19;

/* solhint-disable private-vars-leading-underscore, reason-string */

library Math {
    uint256 internal constant ONE = 1e18; // 18 decimal places
    int256 internal constant IONE = 1e18; // 18 decimal places

    function subMax0(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            return (a >= b ? a - b : 0);
        }
    }

    function subNoNeg(int256 a, int256 b) internal pure returns (int256) {
        require(a >= b, "negative");
        return a - b; // no unchecked since if b is very negative, a - b might overflow
    }

    function mulDown(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 product = a * b;
        unchecked {
            return product / ONE;
        }
    }

    function mulDown(int256 a, int256 b) internal pure returns (int256) {
        int256 product = a * b;
        unchecked {
            return product / IONE;
        }
    }

    function divDown(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 aInflated = a * ONE;
        unchecked {
            return aInflated / b;
        }
    }

    function divDown(int256 a, int256 b) internal pure returns (int256) {
        int256 aInflated = a * IONE;
        unchecked {
            return aInflated / b;
        }
    }

    function rawDivUp(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a + b - 1) / b;
    }

    // @author Uniswap
    function sqrt(uint256 y) internal pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }

    function abs(int256 x) internal pure returns (uint256) {
        return uint256(x > 0 ? x : -x);
    }

    function neg(int256 x) internal pure returns (int256) {
        return x * (-1);
    }

    function neg(uint256 x) internal pure returns (int256) {
        return Int(x) * (-1);
    }

    function max(uint256 x, uint256 y) internal pure returns (uint256) {
        return (x > y ? x : y);
    }

    function max(int256 x, int256 y) internal pure returns (int256) {
        return (x > y ? x : y);
    }

    function min(uint256 x, uint256 y) internal pure returns (uint256) {
        return (x < y ? x : y);
    }

    function min(int256 x, int256 y) internal pure returns (int256) {
        return (x < y ? x : y);
    }

    /*///////////////////////////////////////////////////////////////
                               SIGNED CASTS
    //////////////////////////////////////////////////////////////*/

    function Int(uint256 x) internal pure returns (int256) {
        require(x <= uint256(type(int256).max));
        return int256(x);
    }

    function Int128(int256 x) internal pure returns (int128) {
        require(type(int128).min <= x && x <= type(int128).max);
        return int128(x);
    }

    function Int128(uint256 x) internal pure returns (int128) {
        return Int128(Int(x));
    }

    /*///////////////////////////////////////////////////////////////
                               UNSIGNED CASTS
    //////////////////////////////////////////////////////////////*/

    function Uint(int256 x) internal pure returns (uint256) {
        require(x >= 0);
        return uint256(x);
    }

    function Uint32(uint256 x) internal pure returns (uint32) {
        require(x <= type(uint32).max);
        return uint32(x);
    }

    function Uint112(uint256 x) internal pure returns (uint112) {
        require(x <= type(uint112).max);
        return uint112(x);
    }

    function Uint96(uint256 x) internal pure returns (uint96) {
        require(x <= type(uint96).max);
        return uint96(x);
    }

    function Uint128(uint256 x) internal pure returns (uint128) {
        require(x <= type(uint128).max);
        return uint128(x);
    }

    function isAApproxB(uint256 a, uint256 b, uint256 eps) internal pure returns (bool) {
        return mulDown(b, ONE - eps) <= a && a <= mulDown(b, ONE + eps);
    }

    function isAGreaterApproxB(uint256 a, uint256 b, uint256 eps) internal pure returns (bool) {
        return a >= b && a <= mulDown(b, ONE + eps);
    }

    function isASmallerApproxB(uint256 a, uint256 b, uint256 eps) internal pure returns (bool) {
        return a <= b && a >= mulDown(b, ONE - eps);
    }
}

// ===== FILE: contracts/libraries/Errors.sol =====
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

library Errors {
    // BulkSeller
    error BulkInsufficientSyForTrade(uint256 currentAmount, uint256 requiredAmount);
    error BulkInsufficientTokenForTrade(uint256 currentAmount, uint256 requiredAmount);
    error BulkInSufficientSyOut(uint256 actualSyOut, uint256 requiredSyOut);
    error BulkInSufficientTokenOut(uint256 actualTokenOut, uint256 requiredTokenOut);
    error BulkInsufficientSyReceived(uint256 actualBalance, uint256 requiredBalance);
    error BulkNotMaintainer();
    error BulkNotAdmin();
    error BulkSellerAlreadyExisted(address token, address SY, address bulk);
    error BulkSellerInvalidToken(address token, address SY);
    error BulkBadRateTokenToSy(uint256 actualRate, uint256 currentRate, uint256 eps);
    error BulkBadRateSyToToken(uint256 actualRate, uint256 currentRate, uint256 eps);

    // APPROX
    error ApproxFail();
    error ApproxParamsInvalid(uint256 guessMin, uint256 guessMax, uint256 eps);
    error ApproxBinarySearchInputInvalid(
        uint256 approxGuessMin,
        uint256 approxGuessMax,
        uint256 minGuessMin,
        uint256 maxGuessMax
    );

    // MARKET + MARKET MATH CORE
    error MarketExpired();
    error MarketZeroAmountsInput();
    error MarketZeroAmountsOutput();
    error MarketZeroLnImpliedRate();
    error MarketInsufficientPtForTrade(int256 currentAmount, int256 requiredAmount);
    error MarketInsufficientPtReceived(uint256 actualBalance, uint256 requiredBalance);
    error MarketInsufficientSyReceived(uint256 actualBalance, uint256 requiredBalance);
    error MarketZeroTotalPtOrTotalAsset(int256 totalPt, int256 totalAsset);
    error MarketExchangeRateBelowOne(int256 exchangeRate);
    error MarketProportionMustNotEqualOne();
    error MarketRateScalarBelowZero(int256 rateScalar);
    error MarketScalarRootBelowZero(int256 scalarRoot);
    error MarketProportionTooHigh(int256 proportion, int256 maxProportion);

    error OracleUninitialized();
    error OracleTargetTooOld(uint32 target, uint32 oldest);
    error OracleZeroCardinality();

    error MarketFactoryExpiredPt();
    error MarketFactoryInvalidPt();
    error MarketFactoryMarketExists();

    error MarketFactoryLnFeeRateRootTooHigh(uint80 lnFeeRateRoot, uint256 maxLnFeeRateRoot);
    error MarketFactoryReserveFeePercentTooHigh(
        uint8 reserveFeePercent,
        uint8 maxReserveFeePercent
    );
    error MarketFactoryZeroTreasury();
    error MarketFactoryInitialAnchorTooLow(int256 initialAnchor, int256 minInitialAnchor);

    // ROUTER
    error RouterInsufficientLpOut(uint256 actualLpOut, uint256 requiredLpOut);
    error RouterInsufficientSyOut(uint256 actualSyOut, uint256 requiredSyOut);
    error RouterInsufficientPtOut(uint256 actualPtOut, uint256 requiredPtOut);
    error RouterInsufficientYtOut(uint256 actualYtOut, uint256 requiredYtOut);
    error RouterInsufficientPYOut(uint256 actualPYOut, uint256 requiredPYOut);
    error RouterInsufficientTokenOut(uint256 actualTokenOut, uint256 requiredTokenOut);
    error RouterExceededLimitSyIn(uint256 actualSyIn, uint256 limitSyIn);
    error RouterExceededLimitPtIn(uint256 actualPtIn, uint256 limitPtIn);
    error RouterExceededLimitYtIn(uint256 actualYtIn, uint256 limitYtIn);
    error RouterInsufficientSyRepay(uint256 actualSyRepay, uint256 requiredSyRepay);
    error RouterInsufficientPtRepay(uint256 actualPtRepay, uint256 requiredPtRepay);
    error RouterNotAllSyUsed(uint256 netSyDesired, uint256 netSyUsed);

    error RouterTimeRangeZero();
    error RouterCallbackNotPendleMarket(address caller);
    error RouterInvalidAction(bytes4 selector);
    error RouterInvalidFacet(address facet);

    error RouterKyberSwapDataZero();

    // YIELD CONTRACT
    error YCExpired();
    error YCNotExpired();
    error YieldContractInsufficientSy(uint256 actualSy, uint256 requiredSy);
    error YCNothingToRedeem();
    error YCPostExpiryDataNotSet();
    error YCNoFloatingSy();

    // YieldFactory
    error YCFactoryInvalidExpiry();
    error YCFactoryYieldContractExisted();
    error YCFactoryZeroExpiryDivisor();
    error YCFactoryZeroTreasury();
    error YCFactoryInterestFeeRateTooHigh(uint256 interestFeeRate, uint256 maxInterestFeeRate);
    error YCFactoryRewardFeeRateTooHigh(uint256 newRewardFeeRate, uint256 maxRewardFeeRate);

    // SY
    error SYInvalidTokenIn(address token);
    error SYInvalidTokenOut(address token);
    error SYZeroDeposit();
    error SYZeroRedeem();
    error SYInsufficientSharesOut(uint256 actualSharesOut, uint256 requiredSharesOut);
    error SYInsufficientTokenOut(uint256 actualTokenOut, uint256 requiredTokenOut);

    // SY-specific
    error SYQiTokenMintFailed(uint256 errCode);
    error SYQiTokenRedeemFailed(uint256 errCode);
    error SYQiTokenRedeemRewardsFailed(uint256 rewardAccruedType0, uint256 rewardAccruedType1);
    error SYQiTokenBorrowRateTooHigh(uint256 borrowRate, uint256 borrowRateMax);

    error SYCurveInvalidPid();
    error SYCurve3crvPoolNotFound();

    error SYApeDepositAmountTooSmall(uint256 amountDeposited);
    error SYBalancerInvalidPid();
    error SYInvalidRewardToken(address token);

    error SYStargateRedeemCapExceeded(uint256 amountLpDesired, uint256 amountLpRedeemable);

    error SYBalancerReentrancy();

    // Liquidity Mining
    error VCInactivePool(address pool);
    error VCPoolAlreadyActive(address pool);
    error VCZeroVePendle(address user);
    error VCExceededMaxWeight(uint256 totalWeight, uint256 maxWeight);
    error VCEpochNotFinalized(uint256 wTime);
    error VCPoolAlreadyAddAndRemoved(address pool);

    error VEInvalidNewExpiry(uint256 newExpiry);
    error VEExceededMaxLockTime();
    error VEInsufficientLockTime();
    error VENotAllowedReduceExpiry();
    error VEZeroAmountLocked();
    error VEPositionNotExpired();
    error VEZeroPosition();
    error VEZeroSlope(uint128 bias, uint128 slope);
    error VEReceiveOldSupply(uint256 msgTime);

    error GCNotPendleMarket(address caller);
    error GCNotVotingController(address caller);

    error InvalidWTime(uint256 wTime);
    error ExpiryInThePast(uint256 expiry);
    error ChainNotSupported(uint256 chainId);

    error FDTotalAmountFundedNotMatch(uint256 actualTotalAmount, uint256 expectedTotalAmount);
    error FDEpochLengthMismatch();
    error FDInvalidPool(address pool);
    error FDPoolAlreadyExists(address pool);
    error FDInvalidNewFinishedEpoch(uint256 oldFinishedEpoch, uint256 newFinishedEpoch);
    error FDInvalidStartEpoch(uint256 startEpoch);
    error FDInvalidWTimeFund(uint256 lastFunded, uint256 wTime);
    error FDFutureFunding(uint256 lastFunded, uint256 currentWTime);

    error BDInvalidEpoch(uint256 epoch, uint256 startTime);

    // Cross-Chain
    error MsgNotFromSendEndpoint(uint16 srcChainId, bytes path);
    error MsgNotFromReceiveEndpoint(address sender);
    error InsufficientFeeToSendMsg(uint256 currentFee, uint256 requiredFee);
    error ApproxDstExecutionGasNotSet();
    error InvalidRetryData();

    // GENERIC MSG
    error ArrayLengthMismatch();
    error ArrayEmpty();
    error ArrayOutOfBounds();
    error ZeroAddress();
    error FailedToSendEther();
    error InvalidMerkleProof();

    error OnlyLayerZeroEndpoint();
    error OnlyYT();
    error OnlyYCFactory();
    error OnlyWhitelisted();

    // Swap Aggregator
    error SAInsufficientTokenIn(address tokenIn, uint256 amountExpected, uint256 amountActual);
    error UnsupportedSelector(uint256 aggregatorType, bytes4 selector);
}
// ===== FILE: contracts/libraries/VeHistoryLib.sol =====
// SPDX-License-Identifier: GPL-3.0-or-later
// Forked from OpenZeppelin (v4.5.0) (utils/Checkpoints.sol)
pragma solidity ^0.8.19;

import "./math/Math.sol";
import "./VeBalanceLib.sol";
import "./WeekMath.sol";

struct Checkpoint {
    uint128 timestamp;
    VeBalance value;
}

library CheckpointHelper {
    function assignWith(Checkpoint memory a, Checkpoint memory b) internal pure {
        a.timestamp = b.timestamp;
        a.value = b.value;
    }
}

library Checkpoints {
    struct History {
        Checkpoint[] _checkpoints;
    }

    function length(History storage self) internal view returns (uint256) {
        return self._checkpoints.length;
    }

    function get(History storage self, uint256 index) internal view returns (Checkpoint memory) {
        return self._checkpoints[index];
    }

    function push(History storage self, VeBalance memory value) internal {
        uint256 pos = self._checkpoints.length;
        if (pos > 0 && self._checkpoints[pos - 1].timestamp == WeekMath.getCurrentWeekStart()) {
            self._checkpoints[pos - 1].value = value;
        } else {
            self._checkpoints.push(
                Checkpoint({ timestamp: WeekMath.getCurrentWeekStart(), value: value })
            );
        }
    }
}

// ===== FILE: contracts/interfaces/pendle/IPPrincipalToken.sol =====
// SPDX-License-Identifier: MIT
pragma solidity =0.8.19;
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

interface IPPrincipalToken is IERC20Metadata {
    function burnByYT(address user, uint256 amount) external;

    function mintByYT(address user, uint256 amount) external;

    function initialize(address _YT) external;

    function SY() external view returns (address);

    function YT() external view returns (address);

    function factory() external view returns (address);

    function expiry() external view returns (uint256);

    function isExpired() external view returns (bool);

    function symbol() external view returns (string memory);
}

// ===== FILE: contracts/interfaces/pendle/IPVotingEscrowMainchain.sol =====
// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity =0.8.19;

import "./IPVeToken.sol";
import "../../libraries/VeBalanceLib.sol";
import "../../libraries/VeHistoryLib.sol";

interface IPVotingEscrowMainchain is IPVeToken {
    event NewLockPosition(address indexed user, uint128 amount, uint128 expiry);

    event Withdraw(address indexed user, uint128 amount);

    event BroadcastTotalSupply(VeBalance newTotalSupply, uint256[] chainIds);

    event BroadcastUserPosition(address indexed user, uint256[] chainIds);

    // ============= ACTIONS =============

    function increaseLockPosition(
        uint128 additionalAmountToLock,
        uint128 expiry
    ) external returns (uint128);

    function increaseLockPositionAndBroadcast(
        uint128 additionalAmountToLock,
        uint128 newExpiry,
        uint256[] calldata chainIds
    ) external payable returns (uint128 newVeBalance);

    function withdraw() external returns (uint128);

    function totalSupplyAt(uint128 timestamp) external view returns (uint128);

    function getUserHistoryLength(address user) external view returns (uint256);

    function getUserHistoryAt(
        address user,
        uint256 index
    ) external view returns (Checkpoint memory);

    function broadcastUserPosition(address user, uint256[] calldata chainIds) external payable;
    
    function getBroadcastPositionFee(uint256[] calldata chainIds) external view returns (uint256 fee);

}

// ===== FILE: contracts/interfaces/IBaseRewardPool.sol =====
// SPDX-License-Identifier: MIT
pragma solidity =0.8.19;

interface IBaseRewardPool {
    function stakingDecimals() external view returns (uint256);

    function totalStaked() external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);

    function rewardPerToken(address token) external view returns (uint256);

    function rewardTokenInfos()
        external
        view
        returns
        (
            address[] memory bonusTokenAddresses,
            string[] memory bonusTokenSymbols
        );

    function earned(address account, address token)
        external
        view
        returns (uint256);

    function allEarned(address account)
        external
        view
        returns (uint256[] memory pendingBonusRewards);

    function queueNewRewards(uint256 _rewards, address token)
        external
        returns (bool);

    function getReward(address _account, address _receiver) external returns (bool);

    function getRewards(address _account, address _receiver, address[] memory _rewardTokens) external;

    function updateFor(address account) external;

    function updateRewardQueuer(address _rewardManager, bool _allowed) external;
}
// ===== FILE: contracts/libraries/ActionBaseMintRedeem.sol =====
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "./TokenHelper.sol";
import "../interfaces/pendle/IStandardizedYield.sol";
import "../interfaces/pendle/IPYieldToken.sol";
import "../interfaces/pendle/IPBulkSeller.sol";

import "./Errors.sol";
import "../interfaces/pendle/IPSwapAggregator.sol";

struct TokenInput {
    // Token/Sy data
    address tokenIn;
    uint256 netTokenIn;
    address tokenMintSy;
    address bulk;
    // aggregator data
    address pendleSwap;
    SwapData swapData;
}

struct TokenOutput {
    // Token/Sy data
    address tokenOut;
    uint256 minTokenOut;
    address tokenRedeemSy;
    address bulk;
    // aggregator data
    address pendleSwap;
    SwapData swapData;
}

// solhint-disable no-empty-blocks
abstract contract ActionBaseMintRedeem is TokenHelper {
    bytes internal constant EMPTY_BYTES = abi.encode();

    function _mintSyFromToken(
        address receiver,
        address SY,
        uint256 minSyOut,
        TokenInput calldata inp
    ) internal returns (uint256 netSyOut) {
        SwapType swapType = inp.swapData.swapType;

        uint256 netTokenMintSy;

        if (swapType == SwapType.NONE) {
            _transferIn(inp.tokenIn, msg.sender, inp.netTokenIn);
            netTokenMintSy = inp.netTokenIn;
        } else if (swapType == SwapType.ETH_WETH) {
            _transferIn(inp.tokenIn, msg.sender, inp.netTokenIn);
            _wrap_unwrap_ETH(inp.tokenIn, inp.tokenMintSy, inp.netTokenIn);
            netTokenMintSy = inp.netTokenIn;
        } else {
            if (inp.tokenIn == NATIVE) _transferIn(NATIVE, msg.sender, inp.netTokenIn);
            else _transferFrom(IERC20(inp.tokenIn), msg.sender, inp.pendleSwap, inp.netTokenIn);

            IPSwapAggregator(inp.pendleSwap).swap{
                value: inp.tokenIn == NATIVE ? inp.netTokenIn : 0
            }(inp.tokenIn, inp.netTokenIn, inp.swapData);
            netTokenMintSy = _selfBalance(inp.tokenMintSy);
        }

        // outcome of all branches: satisfy pre-condition of __mintSy

        netSyOut = __mintSy(receiver, SY, netTokenMintSy, minSyOut, inp);
    }

    /// @dev pre-condition: having netTokenMintSy of tokens in this contract
    function __mintSy(
        address receiver,
        address SY,
        uint256 netTokenMintSy,
        uint256 minSyOut,
        TokenInput calldata inp
    ) private returns (uint256 netSyOut) {
        uint256 netNative = inp.tokenMintSy == NATIVE ? netTokenMintSy : 0;

        if (inp.bulk != address(0)) {
            netSyOut = IPBulkSeller(inp.bulk).swapExactTokenForSy{ value: netNative }(
                receiver,
                netTokenMintSy,
                minSyOut
            );
        } else {
            netSyOut = IStandardizedYield(SY).deposit{ value: netNative }(
                receiver,
                inp.tokenMintSy,
                netTokenMintSy,
                minSyOut
            );
        }
    }

    function _redeemSyToToken(
        address receiver,
        address SY,
        uint256 netSyIn,
        TokenOutput calldata out,
        bool doPull
    ) internal returns (uint256 netTokenOut) {
        SwapType swapType = out.swapData.swapType;

        if (swapType == SwapType.NONE) {
            netTokenOut = __redeemSy(receiver, SY, netSyIn, out, doPull);
        } else if (swapType == SwapType.ETH_WETH) {
            netTokenOut = __redeemSy(address(this), SY, netSyIn, out, doPull); // ETH:WETH is 1:1

            _wrap_unwrap_ETH(out.tokenRedeemSy, out.tokenOut, netTokenOut);

            _transferOut(out.tokenOut, receiver, netTokenOut);
        } else {
            uint256 netTokenRedeemed = __redeemSy(out.pendleSwap, SY, netSyIn, out, doPull);

            IPSwapAggregator(out.pendleSwap).swap(
                out.tokenRedeemSy,
                netTokenRedeemed,
                out.swapData
            );

            netTokenOut = _selfBalance(out.tokenOut);

            _transferOut(out.tokenOut, receiver, netTokenOut);
        }

        // outcome of all branches: netTokenOut of tokens goes back to receiver

        if (netTokenOut < out.minTokenOut) {
            revert Errors.RouterInsufficientTokenOut(netTokenOut, out.minTokenOut);
        }
    }

    function __redeemSy(
        address receiver,
        address SY,
        uint256 netSyIn,
        TokenOutput calldata out,
        bool doPull
    ) private returns (uint256 netTokenRedeemed) {
        if (doPull) {
            _transferFrom(IERC20(SY), msg.sender, _syOrBulk(SY, out), netSyIn);
        }

        if (out.bulk != address(0)) {
            netTokenRedeemed = IPBulkSeller(out.bulk).swapExactSyForToken(
                receiver,
                netSyIn,
                0,
                true
            );
        } else {
            netTokenRedeemed = IStandardizedYield(SY).redeem(
                receiver,
                netSyIn,
                out.tokenRedeemSy,
                0,
                true
            );
        }
    }

    function _mintPyFromSy(
        address receiver,
        address SY,
        address YT,
        uint256 netSyIn,
        uint256 minPyOut,
        bool doPull
    ) internal returns (uint256 netPyOut) {
        if (doPull) {
            _transferFrom(IERC20(SY), msg.sender, YT, netSyIn);
        }

        netPyOut = IPYieldToken(YT).mintPY(receiver, receiver);
        if (netPyOut < minPyOut) revert Errors.RouterInsufficientPYOut(netPyOut, minPyOut);
    }

    function _redeemPyToSy(
        address receiver,
        address YT,
        uint256 netPyIn,
        uint256 minSyOut
    ) internal returns (uint256 netSyOut) {
        address PT = IPYieldToken(YT).PT();

        _transferFrom(IERC20(PT), msg.sender, YT, netPyIn);

        bool needToBurnYt = (!IPYieldToken(YT).isExpired());
        if (needToBurnYt) _transferFrom(IERC20(YT), msg.sender, YT, netPyIn);

        netSyOut = IPYieldToken(YT).redeemPY(receiver);
        if (netSyOut < minSyOut) revert Errors.RouterInsufficientSyOut(netSyOut, minSyOut);
    }

    function _syOrBulk(address SY, TokenOutput calldata output)
        internal
        pure
        returns (address addr)
    {
        return output.bulk != address(0) ? output.bulk : SY;
    }
}

// ===== FILE: contracts/interfaces/pendle/IPYieldToken.sol =====
// SPDX-License-Identifier: MIT
pragma solidity =0.8.19;

import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "./IRewardManager.sol";
import "./IPInterestManagerYT.sol";

interface IPYieldToken is IERC20Metadata, IRewardManager, IPInterestManagerYT {
    event NewInterestIndex(uint256 indexed newIndex);

    event Mint(
        address indexed caller,
        address indexed receiverPT,
        address indexed receiverYT,
        uint256 amountSyToMint,
        uint256 amountPYOut
    );

    event Burn(
        address indexed caller,
        address indexed receiver,
        uint256 amountPYToRedeem,
        uint256 amountSyOut
    );

    event RedeemRewards(address indexed user, uint256[] amountRewardsOut);

    event RedeemInterest(address indexed user, uint256 interestOut);

    event WithdrawFeeToTreasury(uint256[] amountRewardsOut, uint256 syOut);

    function mintPY(address receiverPT, address receiverYT) external returns (uint256 amountPYOut);

    function redeemPY(address receiver) external returns (uint256 amountSyOut);

    function redeemPYMulti(
        address[] calldata receivers,
        uint256[] calldata amountPYToRedeems
    ) external returns (uint256[] memory amountSyOuts);

    function redeemDueInterestAndRewards(
        address user,
        bool redeemInterest,
        bool redeemRewards
    ) external returns (uint256 interestOut, uint256[] memory rewardsOut);

    function rewardIndexesCurrent() external returns (uint256[] memory);

    function pyIndexCurrent() external returns (uint256);

    function pyIndexStored() external view returns (uint256);

    function getRewardTokens() external view returns (address[] memory);

    function SY() external view returns (address);

    function PT() external view returns (address);

    function factory() external view returns (address);

    function expiry() external view returns (uint256);

    function isExpired() external view returns (bool);

    function doCacheIndexSameBlock() external view returns (bool);
}

// ===== FILE: contracts/libraries/PYIndex.sol =====
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "../interfaces/pendle/IPYieldToken.sol";
import "../interfaces/pendle/IPPrincipalToken.sol";

import "./SYUtils.sol";
import "./math/Math.sol";

type PYIndex is uint256;

library PYIndexLib {
    using Math for uint256;
    using Math for int256;

    function newIndex(IPYieldToken YT) internal returns (PYIndex) {
        return PYIndex.wrap(YT.pyIndexCurrent());
    }

    function syToAsset(PYIndex index, uint256 syAmount) internal pure returns (uint256) {
        return SYUtils.syToAsset(PYIndex.unwrap(index), syAmount);
    }

    function assetToSy(PYIndex index, uint256 assetAmount) internal pure returns (uint256) {
        return SYUtils.assetToSy(PYIndex.unwrap(index), assetAmount);
    }

    function assetToSyUp(PYIndex index, uint256 assetAmount) internal pure returns (uint256) {
        return SYUtils.assetToSyUp(PYIndex.unwrap(index), assetAmount);
    }

    function syToAssetUp(PYIndex index, uint256 syAmount) internal pure returns (uint256) {
        uint256 _index = PYIndex.unwrap(index);
        return SYUtils.syToAssetUp(_index, syAmount);
    }

    function syToAsset(PYIndex index, int256 syAmount) internal pure returns (int256) {
        int256 sign = syAmount < 0 ? int256(-1) : int256(1);
        return sign * (SYUtils.syToAsset(PYIndex.unwrap(index), syAmount.abs())).Int();
    }

    function assetToSy(PYIndex index, int256 assetAmount) internal pure returns (int256) {
        int256 sign = assetAmount < 0 ? int256(-1) : int256(1);
        return sign * (SYUtils.assetToSy(PYIndex.unwrap(index), assetAmount.abs())).Int();
    }

    function assetToSyUp(PYIndex index, int256 assetAmount) internal pure returns (int256) {
        int256 sign = assetAmount < 0 ? int256(-1) : int256(1);
        return sign * (SYUtils.assetToSyUp(PYIndex.unwrap(index), assetAmount.abs())).Int();
    }
}

// ===== FILE: contracts/libraries/SYUtils.sol =====
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

library SYUtils {
    uint256 internal constant ONE = 1e18;

    function syToAsset(uint256 exchangeRate, uint256 syAmount) internal pure returns (uint256) {
        return (syAmount * exchangeRate) / ONE;
    }

    function syToAssetUp(uint256 exchangeRate, uint256 syAmount) internal pure returns (uint256) {
        return (syAmount * exchangeRate + ONE - 1) / ONE;
    }

    function assetToSy(uint256 exchangeRate, uint256 assetAmount) internal pure returns (uint256) {
        return (assetAmount * ONE) / exchangeRate;
    }

    function assetToSyUp(
        uint256 exchangeRate,
        uint256 assetAmount
    ) internal pure returns (uint256) {
        return (assetAmount * ONE + exchangeRate - 1) / exchangeRate;
    }
}

// ===== FILE: contracts/interfaces/IWETH.sol =====
// SPDX-License-Identifier: MIT
pragma solidity =0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IWETH is IERC20 {
    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);

    function deposit() external payable;

    function withdraw(uint256 wad) external;
}
// ===== FILE: contracts/interfaces/pendle/IStandardizedYield.sol =====
// SPDX-License-Identifier: MIT

pragma solidity =0.8.19;
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

interface IStandardizedYield is IERC20Metadata {
    /// @dev Emitted when any base tokens is deposited to mint shares
    event Deposit(
        address indexed caller,
        address indexed receiver,
        address indexed tokenIn,
        uint256 amountDeposited,
        uint256 amountSyOut
    );

    /// @dev Emitted when any shares are redeemed for base tokens
    event Redeem(
        address indexed caller,
        address indexed receiver,
        address indexed tokenOut,
        uint256 amountSyToRedeem,
        uint256 amountTokenOut
    );

    /// @dev check `assetInfo()` for more information
    enum AssetType {
        TOKEN,
        LIQUIDITY
    }

    /// @dev Emitted when (`user`) claims their rewards
    event ClaimRewards(address indexed user, address[] rewardTokens, uint256[] rewardAmounts);

    /**
     * @notice mints an amount of shares by depositing a base token.
     * @param receiver shares recipient address
     * @param tokenIn address of the base tokens to mint shares
     * @param amountTokenToDeposit amount of base tokens to be transferred from (`msg.sender`)
     * @param minSharesOut reverts if amount of shares minted is lower than this
     * @return amountSharesOut amount of shares minted
     * @dev Emits a {Deposit} event
     *
     * Requirements:
     * - (`tokenIn`) must be a valid base token.
     */
    function deposit(
        address receiver,
        address tokenIn,
        uint256 amountTokenToDeposit,
        uint256 minSharesOut
    ) external payable returns (uint256 amountSharesOut);

    /**
     * @notice redeems an amount of base tokens by burning some shares
     * @param receiver recipient address
     * @param amountSharesToRedeem amount of shares to be burned
     * @param tokenOut address of the base token to be redeemed
     * @param minTokenOut reverts if amount of base token redeemed is lower than this
     * @param burnFromInternalBalance if true, burns from balance of `address(this)`, otherwise burns from `msg.sender`
     * @return amountTokenOut amount of base tokens redeemed
     * @dev Emits a {Redeem} event
     *
     * Requirements:
     * - (`tokenOut`) must be a valid base token.
     */
    function redeem(
        address receiver,
        uint256 amountSharesToRedeem,
        address tokenOut,
        uint256 minTokenOut,
        bool burnFromInternalBalance
    ) external returns (uint256 amountTokenOut);

    /**
     * @notice exchangeRate * syBalance / 1e18 must return the asset balance of the account
     * @notice vice-versa, if a user uses some amount of tokens equivalent to X asset, the amount of sy
     he can mint must be X * exchangeRate / 1e18
     * @dev SYUtils's assetToSy & syToAsset should be used instead of raw multiplication
     & division
     */
    function exchangeRate() external view returns (uint256 res);

    /**
     * @notice claims reward for (`user`)
     * @param user the user receiving their rewards
     * @return rewardAmounts an array of reward amounts in the same order as `getRewardTokens`
     * @dev
     * Emits a `ClaimRewards` event
     * See {getRewardTokens} for list of reward tokens
     */
    function claimRewards(address user) external returns (uint256[] memory rewardAmounts);

    /**
     * @notice get the amount of unclaimed rewards for (`user`)
     * @param user the user to check for
     * @return rewardAmounts an array of reward amounts in the same order as `getRewardTokens`
     */
    function accruedRewards(address user) external view returns (uint256[] memory rewardAmounts);

    function rewardIndexesCurrent() external returns (uint256[] memory indexes);

    function rewardIndexesStored() external view returns (uint256[] memory indexes);

    /**
     * @notice returns the list of reward token addresses
     */
    function getRewardTokens() external view returns (address[] memory);

    /**
     * @notice returns the address of the underlying yield token
     */
    function yieldToken() external view returns (address);

    /**
     * @notice returns all tokens that can mint this SY
     */
    function getTokensIn() external view returns (address[] memory res);

    /**
     * @notice returns all tokens that can be redeemed by this SY
     */
    function getTokensOut() external view returns (address[] memory res);

    function isValidTokenIn(address token) external view returns (bool);

    function isValidTokenOut(address token) external view returns (bool);

    function previewDeposit(
        address tokenIn,
        uint256 amountTokenToDeposit
    ) external view returns (uint256 amountSharesOut);

    function previewRedeem(
        address tokenOut,
        uint256 amountSharesToRedeem
    ) external view returns (uint256 amountTokenOut);

    /**
     * @notice This function contains information to interpret what the asset is
     * @return assetType the type of the asset (0 for ERC20 tokens, 1 for AMM liquidity tokens)
     * @return assetAddress the address of the asset
     * @return assetDecimals the decimals of the asset
     */
    function assetInfo()
        external
        view
        returns (AssetType assetType, address assetAddress, uint8 assetDecimals);
}

// ===== FILE: contracts/interfaces/pendle/IPVoteController.sol =====
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity =0.8.19;

import "../../libraries/VeBalanceLib.sol";

interface IPVoteController {
    struct UserPoolData {
        uint64 weight;
        VeBalance vote;
    }

    struct UserData {
        uint64 totalVotedWeight;
        mapping(address => UserPoolData) voteForPools;
    }

    function getUserData(
        address user,
        address[] calldata pools
    )
        external
        view
        returns (uint64 totalVotedWeight, UserPoolData[] memory voteForPools);

    function getUserPoolVote(
        address user,
        address pool
    ) external view returns (UserPoolData memory);

    function getAllActivePools() external view returns (address[] memory);

    function vote(address[] calldata pools, uint64[] calldata weights) external;

    function broadcastResults(uint64 chainId) external payable;
}

// ===== FILE: contracts/interfaces/IETHZapper.sol =====
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IETHZapper {
    function swapExactTokensToETH(
        address tokenIn,
        uint tokenAmountIn,
        uint256 _amountOutMin,
        address amountReciever
    ) external;
}

// ===== FILE: contracts/interfaces/IMasterPenpie.sol =====
// SPDX-License-Identifier: MIT

pragma solidity =0.8.19;
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import "./IBribeRewardDistributor.sol";

interface IMasterPenpie {
    function poolLength() external view returns (uint256);

    function setPoolManagerStatus(address _address, bool _bool) external;

    function add(uint256 _allocPoint, address _stakingTokenToken, address _receiptToken, address _rewarder) external;

    function set(address _stakingToken, uint256 _allocPoint, address _rewarder, bool _isActive) external;

    function removePool(address _stakingToken) external;

    function createRewarder(address _stakingTokenToken, address mainRewardToken) external
        returns (address);

    // View function to see pending GMPs on frontend.
    function getPoolInfo(address token) external view
        returns (
            uint256 emission,
            uint256 allocpoint,
            uint256 sizeOfPool,
            uint256 totalPoint
        );

    function pendingTokens(address _stakingToken, address _user, address token) external view
        returns (
            uint256 _pendingGMP,
            address _bonusTokenAddress,
            string memory _bonusTokenSymbol,
            uint256 _pendingBonusToken
        );
    
    function allPendingTokensWithBribe(
        address _stakingToken,
        address _user,
        IBribeRewardDistributor.Claim[] calldata _proof
    )
        external
        view
        returns (
            uint256 pendingPenpie,
            address[] memory bonusTokenAddresses,
            string[] memory bonusTokenSymbols,
            uint256[] memory pendingBonusRewards
        );

    function allPendingTokens(address _stakingToken, address _user) external view
        returns (
            uint256 pendingPenpie,
            address[] memory bonusTokenAddresses,
            string[] memory bonusTokenSymbols,
            uint256[] memory pendingBonusRewards
        );

    function massUpdatePools() external;

    function updatePool(address _stakingToken) external;

    function deposit(address _stakingToken, uint256 _amount) external;

    function depositFor(address _stakingToken, address _for, uint256 _amount) external;

    function withdraw(address _stakingToken, uint256 _amount) external;

    function beforeReceiptTokenTransfer(address _from, address _to, uint256 _amount) external;

    function afterReceiptTokenTransfer(address _from, address _to, uint256 _amount) external;

    function depositVlPenpieFor(uint256 _amount, address sender) external;

    function withdrawVlPenpieFor(uint256 _amount, address sender) external;

    function depositMPendleSVFor(uint256 _amount, address sender) external;

    function withdrawMPendleSVFor(uint256 _amount, address sender) external;    

    function multiclaimFor(address[] calldata _stakingTokens, address[][] calldata _rewardTokens, address user_address) external;

    function multiclaimOnBehalf(address[] memory _stakingTokens, address[][] calldata _rewardTokens, address user_address, bool _isClaimPNP) external;

    function multiclaim(address[] calldata _stakingTokens) external;

    function emergencyWithdraw(address _stakingToken, address sender) external;

    function updateEmissionRate(uint256 _gmpPerSec) external;

    function stakingInfo(address _stakingToken, address _user)
        external
        view
        returns (uint256 depositAmount, uint256 availableAmount);
    
    function totalTokenStaked(address _stakingToken) external view returns (uint256);

    function getRewarder(address _stakingToken) external view returns (address rewarder);

}
// ===== FILE: contracts/interfaces/pendle/IPBulkSeller.sol =====
// SPDX-License-Identifier: MIT
pragma solidity =0.8.19;

import "../../libraries/BulkSellerMathCore.sol";

interface IPBulkSeller {
    event SwapExactTokenForSy(address receiver, uint256 netTokenIn, uint256 netSyOut);
    event SwapExactSyForToken(address receiver, uint256 netSyIn, uint256 netTokenOut);
    event RateUpdated(
        uint256 newRateTokenToSy,
        uint256 newRateSyToToken,
        uint256 oldRateTokenToSy,
        uint256 oldRateSyToToken
    );
    event ReBalanceTokenToSy(
        uint256 netTokenDeposit,
        uint256 netSyFromToken,
        uint256 newTokenProp,
        uint256 oldTokenProp
    );
    event ReBalanceSyToToken(
        uint256 netSyRedeem,
        uint256 netTokenFromSy,
        uint256 newTokenProp,
        uint256 oldTokenProp
    );
    event ReserveUpdated(uint256 totalToken, uint256 totalSy);
    event FeeRateUpdated(uint256 newFeeRate, uint256 oldFeeRate);

    function swapExactTokenForSy(
        address receiver,
        uint256 netTokenIn,
        uint256 minSyOut
    ) external payable returns (uint256 netSyOut);

    function swapExactSyForToken(
        address receiver,
        uint256 exactSyIn,
        uint256 minTokenOut,
        bool swapFromInternalBalance
    ) external returns (uint256 netTokenOut);

    function SY() external view returns (address);

    function token() external view returns (address);

    function readState() external view returns (BulkSellerState memory);
}

// ===== FILE: contracts/interfaces/IMintableERC20.sol =====
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (token/ERC20/IERC20.sol)

pragma solidity =0.8.19;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IMintableERC20 {
    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount)
        external
        returns (bool);

    function symbol() external view returns (string memory);

    function decimals() external view returns (uint8);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender)
        external
        view
        returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);

    function mint(address, uint256) external;
    function faucet(uint256) external;

    function burn(address, uint256) external;

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );
}
// ===== FILE: contracts/interfaces/pendle/IPFeeDistributorV2.sol =====
// SPDX-License-Identifier: MIT
pragma solidity =0.8.19;

interface IPFeeDistributorV2 {
    event SetMerkleRootAndFund(bytes32 indexed merkleRoot, uint256 amountFunded);

    event Claimed(address indexed user, uint256 amountOut);

    event UpdateProtocolClaimable(address indexed user, uint256 sumTopUp);

    struct UpdateProtocolStruct {
        address user;
        bytes32[] proof;
        address[] pools;
        uint256[] topUps;
    }

    /**
     * @notice submit total ETH accrued & proof to claim the outstanding amount. Intended to be
     used by retail users
     */
    function claimRetail(
        address receiver,
        uint256 totalAccrued,
        bytes32[] calldata proof
    ) external returns (uint256 amountOut);

    /**
     * @notice Protocols that require the use of this function & feeData should contact the Pendle team.
     * @notice Protocols should NOT EVER use claimRetail. Using it will make getProtocolFeeData unreliable.
     */
    function claimProtocol(address receiver, address[] calldata pools)
        external
        returns (uint256 totalAmountOut, uint256[] memory amountsOut);

    /**
    * @notice returns the claimable fees per pool. Only available if the Pendle team has specifically
    set up the data
     */
    function getProtocolClaimables(address user, address[] calldata pools)
        external
        view
        returns (uint256[] memory claimables);

    function getProtocolTotalAccrued(address user) external view returns (uint256);
}