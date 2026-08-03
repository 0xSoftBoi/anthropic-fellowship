// Polymarket — NegRiskAdapter
// Source: Blockscout(polygon) @ polygon, 0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296

// ===== NegRiskAdapter (primary source) =====
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {ERC1155TokenReceiver} from "lib/solmate/src/tokens/ERC1155.sol";
import {ERC20} from "lib/solmate/src/tokens/ERC20.sol";
import {SafeTransferLib} from "lib/solmate/src/utils/SafeTransferLib.sol";
import {WrappedCollateral} from "src/WrappedCollateral.sol";
import {MarketData, MarketStateManager, IMarketStateManagerEE} from "src/modules/MarketDataManager.sol";
import {CTHelpers} from "src/libraries/CTHelpers.sol";
import {Helpers} from "src/libraries/Helpers.sol";
import {NegRiskIdLib} from "src/libraries/NegRiskIdLib.sol";
import {IConditionalTokens} from "src/interfaces/IConditionalTokens.sol";
import {Auth} from "src/modules/Auth.sol";
import {IAuthEE} from "src/modules/interfaces/IAuth.sol";

/// @title INegRiskAdapterEE
/// @notice NegRiskAdapter Errors and Events
interface INegRiskAdapterEE is IMarketStateManagerEE, IAuthEE {
    error InvalidIndexSet();
    error LengthMismatch();
    error UnexpectedCollateralToken();
    error NoConvertiblePositions();
    error NotApprovedForAll();

    event MarketPrepared(bytes32 indexed marketId, address indexed oracle, uint256 feeBips, bytes data);
    event QuestionPrepared(bytes32 indexed marketId, bytes32 indexed questionId, uint256 index, bytes data);
    event OutcomeReported(bytes32 indexed marketId, bytes32 indexed questionId, bool outcome);
    event PositionSplit(address indexed stakeholder, bytes32 indexed conditionId, uint256 amount);
    event PositionsMerge(address indexed stakeholder, bytes32 indexed conditionId, uint256 amount);
    event PositionsConverted(
        address indexed stakeholder, bytes32 indexed marketId, uint256 indexed indexSet, uint256 amount
    );
    event PayoutRedemption(address indexed redeemer, bytes32 indexed conditionId, uint256[] amounts, uint256 payout);
}

/// @title NegRiskAdapter
/// @notice Adapter for the CTF enabling the linking of a set binary markets where only one can resolve true
/// @notice The adapter prevents more than one question in the same multi-outcome market from resolving true
/// @notice And the adapter allows for the conversion of a set of no positions, to collateral plus the set of
/// complementary yes positions
/// @author Mike Shrieve (mike@polymarket.com)
contract NegRiskAdapter is ERC1155TokenReceiver, MarketStateManager, INegRiskAdapterEE, Auth {
    using SafeTransferLib for ERC20;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    IConditionalTokens public immutable ctf;
    ERC20 public immutable col;
    WrappedCollateral public immutable wcol;
    address public immutable vault;

    address public constant NO_TOKEN_BURN_ADDRESS = address(bytes20(bytes32(keccak256("NO_TOKEN_BURN_ADDRESS"))));
    uint256 public constant FEE_DENOMINATOR = 10_000;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param _ctf        - ConditionalTokens address
    /// @param _collateral - collateral address
    constructor(address _ctf, address _collateral, address _vault) {
        ctf = IConditionalTokens(_ctf);
        col = ERC20(_collateral);
        vault = _vault;

        wcol = new WrappedCollateral(_collateral, col.decimals());
        // approve the ctf to transfer wcol on our behalf
        wcol.approve(_ctf, type(uint256).max);
        // approve wcol to transfer collateral on our behalf
        col.approve(address(wcol), type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                                  IDS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the conditionId for a given questionId
    /// @param _questionId  - the questionId
    /// @return conditionId - the corresponding conditionId
    function getConditionId(bytes32 _questionId) public view returns (bytes32) {
        return CTHelpers.getConditionId(
            address(this), // oracle
            _questionId,
            2 // outcomeCount
        );
    }

    /// @notice Returns the positionId for a given questionId and outcome
    /// @param _questionId  - the questionId
    /// @param _outcome     - the boolean outcome
    /// @return positionId  - the corresponding positionId
    function getPositionId(bytes32 _questionId, bool _outcome) public view returns (uint256) {
        bytes32 collectionId = CTHelpers.getCollectionId(
            bytes32(0),
            getConditionId(_questionId),
            _outcome ? 1 : 2 // 1 (0b01) is yes, 2 (0b10) is no
        );

        uint256 positionId = CTHelpers.getPositionId(address(wcol), collectionId);
        return positionId;
    }

    /*//////////////////////////////////////////////////////////////
                             SPLIT POSITION
    //////////////////////////////////////////////////////////////*/

    /// @notice Splits collateral to a complete set of conditional tokens for a single question
    /// @notice This function signature is the same as the CTF's splitPosition
    /// @param _collateralToken - the collateral token, must be the same as the adapter's collateral token
    /// @param _conditionId - the conditionId for the question
    /// @param _amount - the amount of collateral to split
    function splitPosition(address _collateralToken, bytes32, bytes32 _conditionId, uint256[] calldata, uint256 _amount)
        external
    {
        if (_collateralToken != address(col)) revert UnexpectedCollateralToken();
        splitPosition(_conditionId, _amount);
    }

    /// @notice Splits collateral to a complete set of conditional tokens for a single question
    /// @param _conditionId - the conditionId for the question
    /// @param _amount      - the amount of collateral to split
    function splitPosition(bytes32 _conditionId, uint256 _amount) public {
        col.safeTransferFrom(msg.sender, address(this), _amount);
        wcol.wrap(address(this), _amount);
        ctf.splitPosition(address(wcol), bytes32(0), _conditionId, Helpers.partition(), _amount);
        ctf.safeBatchTransferFrom(
            address(this), msg.sender, Helpers.positionIds(address(wcol), _conditionId), Helpers.values(2, _amount), ""
        );

        emit PositionSplit(msg.sender, _conditionId, _amount);
    }

    /*//////////////////////////////////////////////////////////////
                            MERGE POSITIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Merges a complete set of conditional tokens for a single question to collateral
    /// @notice This function signature is the same as the CTF's mergePositions
    /// @param _collateralToken - the collateral token, must be the same as the adapter's collateral token
    /// @param _conditionId     - the conditionId for the question
    /// @param _amount          - the amount of collateral to merge
    function mergePositions(
        address _collateralToken,
        bytes32,
        bytes32 _conditionId,
        uint256[] calldata,
        uint256 _amount
    ) external {
        if (_collateralToken != address(col)) revert UnexpectedCollateralToken();
        mergePositions(_conditionId, _amount);
    }

    /// @notice Merges a complete set of conditional tokens for a single question to collateral
    /// @param _conditionId - the conditionId for the question
    /// @param _amount      - the amount of collateral to merge
    function mergePositions(bytes32 _conditionId, uint256 _amount) public {
        uint256[] memory positionIds = Helpers.positionIds(address(wcol), _conditionId);

        // get conditional tokens from sender
        ctf.safeBatchTransferFrom(msg.sender, address(this), positionIds, Helpers.values(2, _amount), "");
        ctf.mergePositions(address(wcol), bytes32(0), _conditionId, Helpers.partition(), _amount);
        wcol.unwrap(msg.sender, _amount);

        emit PositionsMerge(msg.sender, _conditionId, _amount);
    }

    /*//////////////////////////////////////////////////////////////
                           ERC1155 OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Proxies ERC1155 balanceOf to the CTF
    /// @param _owner   - the owner of the tokens
    /// @param _id      - the positionId
    /// @return balance - the owner's balance
    function balanceOf(address _owner, uint256 _id) external view returns (uint256) {
        return ctf.balanceOf(_owner, _id);
    }

    /// @notice Proxies ERC1155 balanceOfBatch to the CTF
    /// @param _owners   - the owners of the tokens
    /// @param _ids      - the positionIds
    /// @return balances - the owners' balances
    function balanceOfBatch(address[] memory _owners, uint256[] memory _ids) external view returns (uint256[] memory) {
        return ctf.balanceOfBatch(_owners, _ids);
    }

    /// @notice Proxies ERC1155 safeTransferFrom to the CTF
    /// @notice Can only be called by an admin
    /// @notice Requires this contract to be approved for all
    /// @notice Requires the sender to be approved for all
    /// @param _from  - the owner of the tokens
    /// @param _to    - the recipient of the tokens
    /// @param _id    - the positionId
    /// @param _value - the amount of tokens to transfer
    /// @param _data  - the data to pass to the recipient
    function safeTransferFrom(address _from, address _to, uint256 _id, uint256 _value, bytes calldata _data)
        external
        onlyAdmin
    {
        if (!ctf.isApprovedForAll(_from, msg.sender)) {
            revert NotApprovedForAll();
        }

        return ctf.safeTransferFrom(_from, _to, _id, _value, _data);
    }

    /*//////////////////////////////////////////////////////////////
                            REDEEM POSITION
    //////////////////////////////////////////////////////////////*/

    /// @notice Redeem a set of conditional tokens for collateral
    /// @param _conditionId - conditionId of the conditional tokens to redeem
    /// @param _amounts     - amounts of conditional tokens to redeem
    /// _amounts should always have length 2, with the first element being the amount of yes tokens to redeem and the
    /// second element being the amount of no tokens to redeem
    function redeemPositions(bytes32 _conditionId, uint256[] calldata _amounts) public {
        uint256[] memory positionIds = Helpers.positionIds(address(wcol), _conditionId);

        // get conditional tokens from sender
        ctf.safeBatchTransferFrom(msg.sender, address(this), positionIds, _amounts, "");
        ctf.redeemPositions(address(wcol), bytes32(0), _conditionId, Helpers.partition());

        uint256 payout = wcol.balanceOf(address(this));
        if (payout > 0) {
            wcol.unwrap(msg.sender, payout);
        }

        emit PayoutRedemption(msg.sender, _conditionId, _amounts, payout);
    }

    /*//////////////////////////////////////////////////////////////
                            CONVERT POSITIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Convert a set of no positions to the complementary set of yes positions plus collateral proportional to
    /// (# of no positions - 1)
    /// @notice If the market has a fee, the fee is taken from both collateral and the yes positions
    /// @param _marketId - the marketId
    /// @param _indexSet - the set of positions to convert, expressed as an index set where the least significant bit is
    /// the first question (index zero)
    /// @param _amount   - the amount of tokens to convert
    function convertPositions(bytes32 _marketId, uint256 _indexSet, uint256 _amount) external {
        MarketData md = getMarketData(_marketId);
        uint256 questionCount = md.questionCount();

        if (md.oracle() == address(0)) revert MarketNotPrepared();
        if (questionCount <= 1) revert NoConvertiblePositions();
        if (_indexSet == 0) revert InvalidIndexSet();
        if ((_indexSet >> questionCount) > 0) revert InvalidIndexSet();

        // if _amount is 0, return early
        if (_amount == 0) {
            return;
        }

        uint256 index = 0;
        uint256 noPositionCount;

        // count number of no positions
        while (index < questionCount) {
            unchecked {
                if ((_indexSet & (1 << index)) > 0) {
                    ++noPositionCount;
                }
                ++index;
            }
        }

        uint256 yesPositionCount = questionCount - noPositionCount;
        uint256[] memory noPositionIds = new uint256[](noPositionCount);
        uint256[] memory yesPositionIds = new uint256[](yesPositionCount);
        uint256[] memory accumulatedNoPositionIds = new uint256[](yesPositionCount);

        // mint the amount of wcol required
        wcol.mint(yesPositionCount * _amount);

        // populate noPositionIds and yesPositionIds
        // split yes positions
        {
            uint256 noIndex;
            uint256 yesIndex;
            index = 0;

            while (index < questionCount) {
                bytes32 questionId = NegRiskIdLib.getQuestionId(_marketId, uint8(index));

                if ((_indexSet & (1 << index)) > 0) {
                    // NO
                    noPositionIds[noIndex] = getPositionId(questionId, false);

                    unchecked {
                        ++noIndex;
                    }
                } else {
                    // YES
                    yesPositionIds[yesIndex] = getPositionId(questionId, true);
                    accumulatedNoPositionIds[yesIndex] = getPositionId(questionId, false);

                    // split position to get yes and no tokens
                    // the no tokens will be discarded
                    _splitPosition(getConditionId(questionId), _amount);

                    unchecked {
                        ++yesIndex;
                    }
                }
                unchecked {
                    ++index;
                }
            }
        }

        // transfer the caller's no tokens _and_ accumulated no tokens to the burn address
        // these must never be redeemed
        {
            ctf.safeBatchTransferFrom(
                msg.sender, NO_TOKEN_BURN_ADDRESS, noPositionIds, Helpers.values(noPositionIds.length, _amount), ""
            );
            ctf.safeBatchTransferFrom(
                address(this),
                NO_TOKEN_BURN_ADDRESS,
                accumulatedNoPositionIds,
                Helpers.values(yesPositionCount, _amount),
                ""
            );
        }

        uint256 feeAmount = (_amount * md.feeBips()) / FEE_DENOMINATOR;
        uint256 amountOut = _amount - feeAmount;

        if (noPositionIds.length > 1) {
            // collateral out is always proportional to the number of no positions minus 1
            uint256 multiplier = noPositionIds.length - 1;
            // transfer collateral fees to vault
            if (feeAmount > 0) {
                wcol.release(vault, multiplier * feeAmount);
            }
            // transfer collateral to sender
            wcol.release(msg.sender, multiplier * amountOut);
        }

        if (yesPositionIds.length > 0) {
            if (feeAmount > 0) {
                // transfer yes token fees to vault
                ctf.safeBatchTransferFrom(
                    address(this), vault, yesPositionIds, Helpers.values(yesPositionIds.length, feeAmount), ""
                );
            }

            // transfer yes tokens to sender
            ctf.safeBatchTransferFrom(
                address(this), msg.sender, yesPositionIds, Helpers.values(yesPositionIds.length, amountOut), ""
            );
        }

        emit PositionsConverted(msg.sender, _marketId, _indexSet, _amount);
    }

    /*//////////////////////////////////////////////////////////////
                             PREPARE MARKET
    //////////////////////////////////////////////////////////////*/

    /// @notice Prepare a multi-outcome market
    /// @param _feeBips  - the fee for the market, out of 10_000
    /// @param _metadata     - metadata for the market
    /// @return marketId - the marketId
    function prepareMarket(uint256 _feeBips, bytes calldata _metadata) external returns (bytes32) {
        bytes32 marketId = _prepareMarket(_feeBips, _metadata);

        emit MarketPrepared(marketId, msg.sender, _feeBips, _metadata);

        return marketId;
    }

    /*//////////////////////////////////////////////////////////////
                            PREPARE QUESTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Prepare a question for a given market
    /// @param _marketId   - the id of the market for which to prepare the question
    /// @param _metadata   - the question metadata
    /// @return questionId - the id of the resulting question
    function prepareQuestion(bytes32 _marketId, bytes calldata _metadata) external returns (bytes32) {
        (bytes32 questionId, uint256 questionIndex) = _prepareQuestion(_marketId);
        bytes32 conditionId = getConditionId(questionId);

        // check to see if the condition has already been prepared on the ctf
        if (ctf.getOutcomeSlotCount(conditionId) == 0) {
            ctf.prepareCondition(address(this), questionId, 2);
        }

        emit QuestionPrepared(_marketId, questionId, questionIndex, _metadata);

        return questionId;
    }

    /*//////////////////////////////////////////////////////////////
                             REPORT OUTCOME
    //////////////////////////////////////////////////////////////*/

    /// @notice Report the outcome of a question
    /// @param _questionId - the questionId to report
    /// @param _outcome    - the outcome of the question
    function reportOutcome(bytes32 _questionId, bool _outcome) external {
        _reportOutcome(_questionId, _outcome);

        ctf.reportPayouts(_questionId, Helpers.payouts(_outcome));

        emit OutcomeReported(NegRiskIdLib.getMarketId(_questionId), _questionId, _outcome);
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @dev internal function to avoid stack too deep in convertPositions
    function _splitPosition(bytes32 _conditionId, uint256 _amount) internal {
        ctf.splitPosition(address(wcol), bytes32(0), _conditionId, Helpers.partition(), _amount);
    }
}


// ===== lib/solmate/src/tokens/ERC1155.sol =====
// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

/// @notice Minimalist and gas efficient standard ERC1155 implementation.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC1155.sol)
abstract contract ERC1155 {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event TransferSingle(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256 id,
        uint256 amount
    );

    event TransferBatch(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256[] ids,
        uint256[] amounts
    );

    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    event URI(string value, uint256 indexed id);

    /*//////////////////////////////////////////////////////////////
                             ERC1155 STORAGE
    //////////////////////////////////////////////////////////////*/

    mapping(address => mapping(uint256 => uint256)) public balanceOf;

    mapping(address => mapping(address => bool)) public isApprovedForAll;

    /*//////////////////////////////////////////////////////////////
                             METADATA LOGIC
    //////////////////////////////////////////////////////////////*/

    function uri(uint256 id) public view virtual returns (string memory);

    /*//////////////////////////////////////////////////////////////
                              ERC1155 LOGIC
    //////////////////////////////////////////////////////////////*/

    function setApprovalForAll(address operator, bool approved) public virtual {
        isApprovedForAll[msg.sender][operator] = approved;

        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) public virtual {
        require(msg.sender == from || isApprovedForAll[from][msg.sender], "NOT_AUTHORIZED");

        balanceOf[from][id] -= amount;
        balanceOf[to][id] += amount;

        emit TransferSingle(msg.sender, from, to, id, amount);

        require(
            to.code.length == 0
                ? to != address(0)
                : ERC1155TokenReceiver(to).onERC1155Received(msg.sender, from, id, amount, data) ==
                    ERC1155TokenReceiver.onERC1155Received.selector,
            "UNSAFE_RECIPIENT"
        );
    }

    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) public virtual {
        require(ids.length == amounts.length, "LENGTH_MISMATCH");

        require(msg.sender == from || isApprovedForAll[from][msg.sender], "NOT_AUTHORIZED");

        // Storing these outside the loop saves ~15 gas per iteration.
        uint256 id;
        uint256 amount;

        for (uint256 i = 0; i < ids.length; ) {
            id = ids[i];
            amount = amounts[i];

            balanceOf[from][id] -= amount;
            balanceOf[to][id] += amount;

            // An array can't have a total length
            // larger than the max uint256 value.
            unchecked {
                ++i;
            }
        }

        emit TransferBatch(msg.sender, from, to, ids, amounts);

        require(
            to.code.length == 0
                ? to != address(0)
                : ERC1155TokenReceiver(to).onERC1155BatchReceived(msg.sender, from, ids, amounts, data) ==
                    ERC1155TokenReceiver.onERC1155BatchReceived.selector,
            "UNSAFE_RECIPIENT"
        );
    }

    function balanceOfBatch(address[] calldata owners, uint256[] calldata ids)
        public
        view
        virtual
        returns (uint256[] memory balances)
    {
        require(owners.length == ids.length, "LENGTH_MISMATCH");

        balances = new uint256[](owners.length);

        // Unchecked because the only math done is incrementing
        // the array index counter which cannot possibly overflow.
        unchecked {
            for (uint256 i = 0; i < owners.length; ++i) {
                balances[i] = balanceOf[owners[i]][ids[i]];
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                              ERC165 LOGIC
    //////////////////////////////////////////////////////////////*/

    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return
            interfaceId == 0x01ffc9a7 || // ERC165 Interface ID for ERC165
            interfaceId == 0xd9b67a26 || // ERC165 Interface ID for ERC1155
            interfaceId == 0x0e89341c; // ERC165 Interface ID for ERC1155MetadataURI
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL MINT/BURN LOGIC
    //////////////////////////////////////////////////////////////*/

    function _mint(
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) internal virtual {
        balanceOf[to][id] += amount;

        emit TransferSingle(msg.sender, address(0), to, id, amount);

        require(
            to.code.length == 0
                ? to != address(0)
                : ERC1155TokenReceiver(to).onERC1155Received(msg.sender, address(0), id, amount, data) ==
                    ERC1155TokenReceiver.onERC1155Received.selector,
            "UNSAFE_RECIPIENT"
        );
    }

    function _batchMint(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual {
        uint256 idsLength = ids.length; // Saves MLOADs.

        require(idsLength == amounts.length, "LENGTH_MISMATCH");

        for (uint256 i = 0; i < idsLength; ) {
            balanceOf[to][ids[i]] += amounts[i];

            // An array can't have a total length
            // larger than the max uint256 value.
            unchecked {
                ++i;
            }
        }

        emit TransferBatch(msg.sender, address(0), to, ids, amounts);

        require(
            to.code.length == 0
                ? to != address(0)
                : ERC1155TokenReceiver(to).onERC1155BatchReceived(msg.sender, address(0), ids, amounts, data) ==
                    ERC1155TokenReceiver.onERC1155BatchReceived.selector,
            "UNSAFE_RECIPIENT"
        );
    }

    function _batchBurn(
        address from,
        uint256[] memory ids,
        uint256[] memory amounts
    ) internal virtual {
        uint256 idsLength = ids.length; // Saves MLOADs.

        require(idsLength == amounts.length, "LENGTH_MISMATCH");

        for (uint256 i = 0; i < idsLength; ) {
            balanceOf[from][ids[i]] -= amounts[i];

            // An array can't have a total length
            // larger than the max uint256 value.
            unchecked {
                ++i;
            }
        }

        emit TransferBatch(msg.sender, from, address(0), ids, amounts);
    }

    function _burn(
        address from,
        uint256 id,
        uint256 amount
    ) internal virtual {
        balanceOf[from][id] -= amount;

        emit TransferSingle(msg.sender, from, address(0), id, amount);
    }
}

/// @notice A generic interface for a contract which properly accepts ERC1155 tokens.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC1155.sol)
abstract contract ERC1155TokenReceiver {
    function onERC1155Received(
        address,
        address,
        uint256,
        uint256,
        bytes calldata
    ) external virtual returns (bytes4) {
        return ERC1155TokenReceiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    ) external virtual returns (bytes4) {
        return ERC1155TokenReceiver.onERC1155BatchReceived.selector;
    }
}


// ===== lib/solmate/src/tokens/ERC20.sol =====
// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

/// @notice Modern and gas efficient ERC20 + EIP-2612 implementation.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC20.sol)
/// @author Modified from Uniswap (https://github.com/Uniswap/uniswap-v2-core/blob/master/contracts/UniswapV2ERC20.sol)
/// @dev Do not manually set balances without updating totalSupply, as the sum of all user balances must not exceed it.
abstract contract ERC20 {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event Transfer(address indexed from, address indexed to, uint256 amount);

    event Approval(address indexed owner, address indexed spender, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                            METADATA STORAGE
    //////////////////////////////////////////////////////////////*/

    string public name;

    string public symbol;

    uint8 public immutable decimals;

    /*//////////////////////////////////////////////////////////////
                              ERC20 STORAGE
    //////////////////////////////////////////////////////////////*/

    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;

    mapping(address => mapping(address => uint256)) public allowance;

    /*//////////////////////////////////////////////////////////////
                            EIP-2612 STORAGE
    //////////////////////////////////////////////////////////////*/

    uint256 internal immutable INITIAL_CHAIN_ID;

    bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;

    mapping(address => uint256) public nonces;

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        string memory _name,
        string memory _symbol,
        uint8 _decimals
    ) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;

        INITIAL_CHAIN_ID = block.chainid;
        INITIAL_DOMAIN_SEPARATOR = computeDomainSeparator();
    }

    /*//////////////////////////////////////////////////////////////
                               ERC20 LOGIC
    //////////////////////////////////////////////////////////////*/

    function approve(address spender, uint256 amount) public virtual returns (bool) {
        allowance[msg.sender][spender] = amount;

        emit Approval(msg.sender, spender, amount);

        return true;
    }

    function transfer(address to, uint256 amount) public virtual returns (bool) {
        balanceOf[msg.sender] -= amount;

        // Cannot overflow because the sum of all user
        // balances can't exceed the max uint256 value.
        unchecked {
            balanceOf[to] += amount;
        }

        emit Transfer(msg.sender, to, amount);

        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public virtual returns (bool) {
        uint256 allowed = allowance[from][msg.sender]; // Saves gas for limited approvals.

        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;

        balanceOf[from] -= amount;

        // Cannot overflow because the sum of all user
        // balances can't exceed the max uint256 value.
        unchecked {
            balanceOf[to] += amount;
        }

        emit Transfer(from, to, amount);

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                             EIP-2612 LOGIC
    //////////////////////////////////////////////////////////////*/

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public virtual {
        require(deadline >= block.timestamp, "PERMIT_DEADLINE_EXPIRED");

        // Unchecked because the only math done is incrementing
        // the owner's nonce which cannot realistically overflow.
        unchecked {
            address recoveredAddress = ecrecover(
                keccak256(
                    abi.encodePacked(
                        "\x19\x01",
                        DOMAIN_SEPARATOR(),
                        keccak256(
                            abi.encode(
                                keccak256(
                                    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
                                ),
                                owner,
                                spender,
                                value,
                                nonces[owner]++,
                                deadline
                            )
                        )
                    )
                ),
                v,
                r,
                s
            );

            require(recoveredAddress != address(0) && recoveredAddress == owner, "INVALID_SIGNER");

            allowance[recoveredAddress][spender] = value;
        }

        emit Approval(owner, spender, value);
    }

    function DOMAIN_SEPARATOR() public view virtual returns (bytes32) {
        return block.chainid == INITIAL_CHAIN_ID ? INITIAL_DOMAIN_SEPARATOR : computeDomainSeparator();
    }

    function computeDomainSeparator() internal view virtual returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    keccak256(bytes(name)),
                    keccak256("1"),
                    block.chainid,
                    address(this)
                )
            );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL MINT/BURN LOGIC
    //////////////////////////////////////////////////////////////*/

    function _mint(address to, uint256 amount) internal virtual {
        totalSupply += amount;

        // Cannot overflow because the sum of all user
        // balances can't exceed the max uint256 value.
        unchecked {
            balanceOf[to] += amount;
        }

        emit Transfer(address(0), to, amount);
    }

    function _burn(address from, uint256 amount) internal virtual {
        balanceOf[from] -= amount;

        // Cannot underflow because a user's balance
        // will never be larger than the total supply.
        unchecked {
            totalSupply -= amount;
        }

        emit Transfer(from, address(0), amount);
    }
}


// ===== lib/solmate/src/utils/SafeTransferLib.sol =====
// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

import {ERC20} from "../tokens/ERC20.sol";

/// @notice Safe ETH and ERC20 transfer library that gracefully handles missing return values.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/SafeTransferLib.sol)
/// @dev Use with caution! Some functions in this library knowingly create dirty bits at the destination of the free memory pointer.
/// @dev Note that none of the functions in this library check that a token has code at all! That responsibility is delegated to the caller.
library SafeTransferLib {
    /*//////////////////////////////////////////////////////////////
                             ETH OPERATIONS
    //////////////////////////////////////////////////////////////*/

    function safeTransferETH(address to, uint256 amount) internal {
        bool success;

        /// @solidity memory-safe-assembly
        assembly {
            // Transfer the ETH and store if it succeeded or not.
            success := call(gas(), to, amount, 0, 0, 0, 0)
        }

        require(success, "ETH_TRANSFER_FAILED");
    }

    /*//////////////////////////////////////////////////////////////
                            ERC20 OPERATIONS
    //////////////////////////////////////////////////////////////*/

    function safeTransferFrom(
        ERC20 token,
        address from,
        address to,
        uint256 amount
    ) internal {
        bool success;

        /// @solidity memory-safe-assembly
        assembly {
            // Get a pointer to some free memory.
            let freeMemoryPointer := mload(0x40)

            // Write the abi-encoded calldata into memory, beginning with the function selector.
            mstore(freeMemoryPointer, 0x23b872dd00000000000000000000000000000000000000000000000000000000)
            mstore(add(freeMemoryPointer, 4), and(from, 0xffffffffffffffffffffffffffffffffffffffff)) // Append and mask the "from" argument.
            mstore(add(freeMemoryPointer, 36), and(to, 0xffffffffffffffffffffffffffffffffffffffff)) // Append and mask the "to" argument.
            mstore(add(freeMemoryPointer, 68), amount) // Append the "amount" argument. Masking not required as it's a full 32 byte type.

            success := and(
                // Set success to whether the call reverted, if not we check it either
                // returned exactly 1 (can't just be non-zero data), or had no return data.
                or(and(eq(mload(0), 1), gt(returndatasize(), 31)), iszero(returndatasize())),
                // We use 100 because the length of our calldata totals up like so: 4 + 32 * 3.
                // We use 0 and 32 to copy up to 32 bytes of return data into the scratch space.
                // Counterintuitively, this call must be positioned second to the or() call in the
                // surrounding and() call or else returndatasize() will be zero during the computation.
                call(gas(), token, 0, freeMemoryPointer, 100, 0, 32)
            )
        }

        require(success, "TRANSFER_FROM_FAILED");
    }

    function safeTransfer(
        ERC20 token,
        address to,
        uint256 amount
    ) internal {
        bool success;

        /// @solidity memory-safe-assembly
        assembly {
            // Get a pointer to some free memory.
            let freeMemoryPointer := mload(0x40)

            // Write the abi-encoded calldata into memory, beginning with the function selector.
            mstore(freeMemoryPointer, 0xa9059cbb00000000000000000000000000000000000000000000000000000000)
            mstore(add(freeMemoryPointer, 4), and(to, 0xffffffffffffffffffffffffffffffffffffffff)) // Append and mask the "to" argument.
            mstore(add(freeMemoryPointer, 36), amount) // Append the "amount" argument. Masking not required as it's a full 32 byte type.

            success := and(
                // Set success to whether the call reverted, if not we check it either
                // returned exactly 1 (can't just be non-zero data), or had no return data.
                or(and(eq(mload(0), 1), gt(returndatasize(), 31)), iszero(returndatasize())),
                // We use 68 because the length of our calldata totals up like so: 4 + 32 * 2.
                // We use 0 and 32 to copy up to 32 bytes of return data into the scratch space.
                // Counterintuitively, this call must be positioned second to the or() call in the
                // surrounding and() call or else returndatasize() will be zero during the computation.
                call(gas(), token, 0, freeMemoryPointer, 68, 0, 32)
            )
        }

        require(success, "TRANSFER_FAILED");
    }

    function safeApprove(
        ERC20 token,
        address to,
        uint256 amount
    ) internal {
        bool success;

        /// @solidity memory-safe-assembly
        assembly {
            // Get a pointer to some free memory.
            let freeMemoryPointer := mload(0x40)

            // Write the abi-encoded calldata into memory, beginning with the function selector.
            mstore(freeMemoryPointer, 0x095ea7b300000000000000000000000000000000000000000000000000000000)
            mstore(add(freeMemoryPointer, 4), and(to, 0xffffffffffffffffffffffffffffffffffffffff)) // Append and mask the "to" argument.
            mstore(add(freeMemoryPointer, 36), amount) // Append the "amount" argument. Masking not required as it's a full 32 byte type.

            success := and(
                // Set success to whether the call reverted, if not we check it either
                // returned exactly 1 (can't just be non-zero data), or had no return data.
                or(and(eq(mload(0), 1), gt(returndatasize(), 31)), iszero(returndatasize())),
                // We use 68 because the length of our calldata totals up like so: 4 + 32 * 2.
                // We use 0 and 32 to copy up to 32 bytes of return data into the scratch space.
                // Counterintuitively, this call must be positioned second to the or() call in the
                // surrounding and() call or else returndatasize() will be zero during the computation.
                call(gas(), token, 0, freeMemoryPointer, 68, 0, 32)
            )
        }

        require(success, "APPROVE_FAILED");
    }
}


// ===== src/WrappedCollateral.sol =====
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {ERC20} from "lib/solmate/src/tokens/ERC20.sol";
import {SafeTransferLib} from "lib/solmate/src/utils/SafeTransferLib.sol";

/// @title IWrappedCollateralEE
/// @notice WrappedCollateral Errors and Events
interface IWrappedCollateralEE {
    error OnlyOwner();
}

string constant NAME = "Wrapped Collateral";
string constant SYMBOL = "WCOL";

/// @title WrappedCollateral
/// @author Mike Shrieve (mike@polymarket.com)
/// @notice Wraps an ERC20 token to be used as collateral in the CTF
contract WrappedCollateral is IWrappedCollateralEE, ERC20 {
    using SafeTransferLib for ERC20;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    address public immutable owner;
    address public immutable underlying;

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param _underlying The address of the underlying ERC20 token
    /// @param _decimals The number of decimals of the underlying ERC20 token
    constructor(address _underlying, uint8 _decimals) ERC20(NAME, SYMBOL, _decimals) {
        owner = msg.sender;
        underlying = _underlying;
    }

    /*//////////////////////////////////////////////////////////////
                                 UNWRAP
    //////////////////////////////////////////////////////////////*/

    /// @notice Unwraps the specified amount of tokens
    /// @param _to The address to send the unwrapped tokens to
    /// @param _amount The amount of tokens to unwrap
    function unwrap(address _to, uint256 _amount) external {
        _burn(msg.sender, _amount);
        ERC20(underlying).safeTransfer(_to, _amount);
    }

    /*//////////////////////////////////////////////////////////////
                                 ADMIN
    //////////////////////////////////////////////////////////////*/

    /// @notice Wraps the specified amount of tokens
    /// @notice Can only be called by the owner
    /// @param _to     - the address to send the wrapped tokens to
    /// @param _amount - the amount of tokens to wrap
    function wrap(address _to, uint256 _amount) external onlyOwner {
        ERC20(underlying).safeTransferFrom(msg.sender, address(this), _amount);
        _mint(_to, _amount);
    }

    /// @notice Burns the specified amount of tokens
    /// @notice Can only be called by the owner
    /// @param _amount - the amount of tokens to burn
    function burn(uint256 _amount) external onlyOwner {
        _burn(msg.sender, _amount);
    }

    /// @notice Mints the specified amount of tokens
    /// @notice Can only be called by the owner
    /// @param _amount - the amount of tokens to mint
    function mint(uint256 _amount) external onlyOwner {
        _mint(msg.sender, _amount);
    }

    /// @notice Releases the specified amount of the underlying token
    /// @notice Can only be called by the owner
    /// @param _to     - the address to send the released tokens to
    /// @param _amount - the amount of tokens to release
    function release(address _to, uint256 _amount) external onlyOwner {
        ERC20(underlying).safeTransfer(_to, _amount);
    }
}


// ===== src/interfaces/IConditionalTokens.sol =====
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

/// @notice references to IERC20 are replaced by address

/// @notice Interface for Gnosis Conditional Tokens
interface IERC1155 {
    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);

    event TransferBatch(
        address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values
    );

    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    event URI(string value, uint256 indexed id);

    function balanceOf(address owner, uint256 id) external view returns (uint256);

    function balanceOfBatch(address[] memory owners, uint256[] memory ids) external view returns (uint256[] memory);

    function setApprovalForAll(address operator, bool approved) external;

    function isApprovedForAll(address owner, address operator) external view returns (bool);

    function safeTransferFrom(address from, address to, uint256 id, uint256 value, bytes calldata data) external;

    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external;
}

interface IConditionalTokensEE {
    event ConditionPreparation(
        bytes32 indexed conditionId, address indexed oracle, bytes32 indexed questionId, uint256 outcomeSlotCount
    );

    event ConditionResolution(
        bytes32 indexed conditionId,
        address indexed oracle,
        bytes32 indexed questionId,
        uint256 outcomeSlotCount,
        uint256[] payoutNumerators
    );

    /// @dev Emitted when a position is successfully split.
    event PositionSplit(
        address indexed stakeholder,
        address collateralToken,
        bytes32 indexed parentCollectionId,
        bytes32 indexed conditionId,
        uint256[] partition,
        uint256 amount
    );
    /// @dev Emitted when positions are successfully merged.
    event PositionsMerge(
        address indexed stakeholder,
        address collateralToken,
        bytes32 indexed parentCollectionId,
        bytes32 indexed conditionId,
        uint256[] partition,
        uint256 amount
    );
    event PayoutRedemption(
        address indexed redeemer,
        address indexed collateralToken,
        bytes32 indexed parentCollectionId,
        bytes32 conditionId,
        uint256[] indexSets,
        uint256 payout
    );
}

interface IConditionalTokens is IConditionalTokensEE, IERC1155 {
    function payoutNumerators(bytes32 conditionId, uint256 index) external view returns (uint256);

    function payoutDenominator(bytes32 conditionId) external view returns (uint256);

    /// @dev This function prepares a condition by initializing a payout vector associated with the
    /// condition.
    /// @param oracle The account assigned to report the result for the prepared condition.
    /// @param questionId An identifier for the question to be answered by the oracle.
    /// @param outcomeSlotCount The number of outcome slots which should be used for this condition.
    /// Must not exceed 256.
    function prepareCondition(address oracle, bytes32 questionId, uint256 outcomeSlotCount) external;

    /// @dev Called by the oracle for reporting results of conditions. Will set the payout vector
    /// for the condition with the ID ``keccak256(abi.encodePacked(oracle, questionId,
    /// outcomeSlotCount))``, where oracle is the message sender, questionId is one of the
    /// parameters of this function, and outcomeSlotCount is the length of the payouts parameter,
    /// which contains the payoutNumerators for each outcome slot of the condition.
    /// @param questionId The question ID the oracle is answering for
    /// @param payouts The oracle's answer
    function reportPayouts(bytes32 questionId, uint256[] calldata payouts) external;

    /// @dev This function splits a position. If splitting from the collateral, this contract will
    /// attempt to transfer `amount` collateral from the message sender to itself. Otherwise, this
    /// contract will burn `amount` stake held by the message sender in the position being split
    /// worth of EIP 1155 tokens. Regardless, if successful, `amount` stake will be minted in the
    /// split target positions. If any of the transfers, mints, or burns fail, the transaction will
    /// revert. The transaction will also revert if the given partition is trivial, invalid, or
    /// refers to more slots than the condition is prepared with.
    /// @param collateralToken The address of the positions' backing collateral token.
    /// @param parentCollectionId The ID of the outcome collections common to the position being
    /// split and the split target positions. May be null, in which only the collateral is shared.
    /// @param conditionId The ID of the condition to split on.
    /// @param partition An array of disjoint index sets representing a nontrivial partition of the
    /// outcome slots of the given condition. E.g. A|B and C but not A|B and B|C (is not disjoint).
    /// Each element's a number which, together with the condition, represents the outcome
    /// collection. E.g. 0b110 is A|B, 0b010 is B, etc.
    /// @param amount The amount of collateral or stake to split.
    function splitPosition(
        address collateralToken,
        bytes32 parentCollectionId,
        bytes32 conditionId,
        uint256[] calldata partition,
        uint256 amount
    ) external;

    function mergePositions(
        address collateralToken,
        bytes32 parentCollectionId,
        bytes32 conditionId,
        uint256[] calldata partition,
        uint256 amount
    ) external;

    function redeemPositions(
        address collateralToken,
        bytes32 parentCollectionId,
        bytes32 conditionId,
        uint256[] calldata indexSets
    ) external;

    /// @dev Gets the outcome slot count of a condition.
    /// @param conditionId ID of the condition.
    /// @return Number of outcome slots associated with a condition, or zero if condition has not
    /// been prepared yet.
    function getOutcomeSlotCount(bytes32 conditionId) external view returns (uint256);

    /// @dev Constructs a condition ID from an oracle, a question ID, and the outcome slot count for
    /// the question.
    /// @param oracle The account assigned to report the result for the prepared condition.
    /// @param questionId An identifier for the question to be answered by the oracle.
    /// @param outcomeSlotCount The number of outcome slots which should be used for this condition.
    /// Must not exceed 256.
    function getConditionId(address oracle, bytes32 questionId, uint256 outcomeSlotCount)
        external
        pure
        returns (bytes32);

    /// @dev Constructs an outcome collection ID from a parent collection and an outcome collection.
    /// @param parentCollectionId Collection ID of the parent outcome collection, or bytes32(0) if
    /// there's no parent.
    /// @param conditionId Condition ID of the outcome collection to combine with the parent outcome
    /// collection.
    /// @param indexSet Index set of the outcome collection to combine with the parent outcome
    /// collection.
    function getCollectionId(bytes32 parentCollectionId, bytes32 conditionId, uint256 indexSet)
        external
        view
        returns (bytes32);

    /// @dev Constructs a position ID from a collateral token and an outcome collection. These IDs
    /// are used as the ERC-1155 ID for this contract.
    /// @param collateralToken Collateral token which backs the position.
    /// @param collectionId ID of the outcome collection associated with this position.
    function getPositionId(address collateralToken, bytes32 collectionId) external pure returns (uint256);
}


// ===== src/libraries/CTHelpers.sol =====
// SPDX-License-Identifier: LGPL-3.0-or-later
pragma solidity >=0.5.1;

// forked from Gnosis Condtional Tokens
library CTHelpers {
    /// @dev Constructs a condition ID from an oracle, a question ID, and the outcome slot count for
    /// the question.
    /// @param oracle The account assigned to report the result for the prepared condition.
    /// @param questionId An identifier for the question to be answered by the oracle.
    /// @param outcomeSlotCount The number of outcome slots which should be used for this condition.
    /// Must not exceed 256.
    function getConditionId(address oracle, bytes32 questionId, uint256 outcomeSlotCount)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(oracle, questionId, outcomeSlotCount));
    }

    uint256 constant P =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant B = 3;

    function sqrt(uint256 x) private pure returns (uint256 y) {
        uint256 p = P;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            // add chain generated via https://crypto.stackexchange.com/q/27179/71252
            // and transformed to the following program:

            // x=1; y=x+x; z=y+y; z=z+z; y=y+z; x=x+y; y=y+x; z=y+y; t=z+z; t=z+t; t=t+t;
            // t=t+t; z=z+t; x=x+z; z=x+x; z=z+z; y=y+z; z=y+y; z=z+z; z=z+z; z=y+z; x=x+z;
            // z=x+x; z=z+z; z=z+z; z=x+z; y=y+z; x=x+y; z=x+x; z=z+z; y=y+z; z=y+y; t=z+z;
            // t=t+t; t=t+t; z=z+t; x=x+z; y=y+x; z=y+y; z=z+z; z=z+z; x=x+z; z=x+x; z=z+z;
            // z=x+z; z=z+z; z=z+z; z=x+z; y=y+z; z=y+y; t=z+z; t=t+t; t=z+t; t=y+t; t=t+t;
            // t=t+t; t=t+t; t=t+t; z=z+t; x=x+z; z=x+x; z=x+z; y=y+z; z=y+y; z=y+z; z=z+z;
            // t=z+z; t=z+t; w=t+t; w=w+w; w=w+w; w=w+w; w=w+w; t=t+w; z=z+t; x=x+z; y=y+x;
            // z=y+y; x=x+z; y=y+x; x=x+y; y=y+x; x=x+y; z=x+x; z=x+z; z=z+z; y=y+z; z=y+y;
            // z=z+z; x=x+z; y=y+x; z=y+y; z=y+z; x=x+z; y=y+x; x=x+y; y=y+x; z=y+y; z=z+z;
            // z=y+z; x=x+z; z=x+x; z=x+z; y=y+z; x=x+y; y=y+x; x=x+y; y=y+x; z=y+y; z=y+z;
            // z=z+z; x=x+z; y=y+x; z=y+y; z=y+z; z=z+z; x=x+z; z=x+x; t=z+z; t=t+t; t=z+t;
            // t=x+t; t=t+t; t=t+t; t=t+t; t=t+t; z=z+t; y=y+z; x=x+y; y=y+x; x=x+y; z=x+x;
            // z=x+z; z=z+z; z=z+z; z=z+z; z=x+z; y=y+z; z=y+y; z=y+z; z=z+z; x=x+z; z=x+x;
            // z=x+z; y=y+z; x=x+y; z=x+x; z=z+z; y=y+z; x=x+y; z=x+x; y=y+z; x=x+y; y=y+x;
            // z=y+y; z=y+z; x=x+z; y=y+x; z=y+y; z=y+z; z=z+z; z=z+z; x=x+z; z=x+x; z=z+z;
            // z=z+z; z=x+z; y=y+z; x=x+y; z=x+x; t=x+z; t=t+t; t=t+t; z=z+t; y=y+z; z=y+y;
            // x=x+z; y=y+x; x=x+y; y=y+x; x=x+y; y=y+x; z=y+y; t=y+z; z=y+t; z=z+z; z=z+z;
            // z=t+z; x=x+z; y=y+x; x=x+y; y=y+x; x=x+y; z=x+x; z=x+z; y=y+z; x=x+y; x=x+x;
            // x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x;
            // x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x;
            // x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x;
            // x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x;
            // x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x;
            // x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x;
            // x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x;
            // x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x;
            // x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x;
            // x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x;
            // x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x; x=x+x;
            // x=x+x; x=x+x; x=x+x; x=x+x; res=y+x
            // res == (P + 1) // 4

            y := mulmod(x, x, p)
            {
                let z := mulmod(y, y, p)
                z := mulmod(z, z, p)
                y := mulmod(y, z, p)
                x := mulmod(x, y, p)
                y := mulmod(y, x, p)
                z := mulmod(y, y, p)
                {
                    let t := mulmod(z, z, p)
                    t := mulmod(z, t, p)
                    t := mulmod(t, t, p)
                    t := mulmod(t, t, p)
                    z := mulmod(z, t, p)
                    x := mulmod(x, z, p)
                    z := mulmod(x, x, p)
                    z := mulmod(z, z, p)
                    y := mulmod(y, z, p)
                    z := mulmod(y, y, p)
                    z := mulmod(z, z, p)
                    z := mulmod(z, z, p)
                    z := mulmod(y, z, p)
                    x := mulmod(x, z, p)
                    z := mulmod(x, x, p)
                    z := mulmod(z, z, p)
                    z := mulmod(z, z, p)
                    z := mulmod(x, z, p)
                    y := mulmod(y, z, p)
                    x := mulmod(x, y, p)
                    z := mulmod(x, x, p)
                    z := mulmod(z, z, p)
                    y := mulmod(y, z, p)
                    z := mulmod(y, y, p)
                    t := mulmod(z, z, p)
                    t := mulmod(t, t, p)
                    t := mulmod(t, t, p)
                    z := mulmod(z, t, p)
                    x := mulmod(x, z, p)
                    y := mulmod(y, x, p)
                    z := mulmod(y, y, p)
                    z := mulmod(z, z, p)
                    z := mulmod(z, z, p)
                    x := mulmod(x, z, p)
                    z := mulmod(x, x, p)
                    z := mulmod(z, z, p)
                    z := mulmod(x, z, p)
                    z := mulmod(z, z, p)
                    z := mulmod(z, z, p)
                    z := mulmod(x, z, p)
                    y := mulmod(y, z, p)
                    z := mulmod(y, y, p)
                    t := mulmod(z, z, p)
                    t := mulmod(t, t, p)
                    t := mulmod(z, t, p)
                    t := mulmod(y, t, p)
                    t := mulmod(t, t, p)
                    t := mulmod(t, t, p)
                    t := mulmod(t, t, p)
                    t := mulmod(t, t, p)
                    z := mulmod(z, t, p)
                    x := mulmod(x, z, p)
                    z := mulmod(x, x, p)
                    z := mulmod(x, z, p)
                    y := mulmod(y, z, p)
                    z := mulmod(y, y, p)
                    z := mulmod(y, z, p)
                    z := mulmod(z, z, p)
                    t := mulmod(z, z, p)
                    t := mulmod(z, t, p)
                    {
                        let w := mulmod(t, t, p)
                        w := mulmod(w, w, p)
                        w := mulmod(w, w, p)
                        w := mulmod(w, w, p)
                        w := mulmod(w, w, p)
                        t := mulmod(t, w, p)
                    }
                    z := mulmod(z, t, p)
                    x := mulmod(x, z, p)
                    y := mulmod(y, x, p)
                    z := mulmod(y, y, p)
                    x := mulmod(x, z, p)
                    y := mulmod(y, x, p)
                    x := mulmod(x, y, p)
                    y := mulmod(y, x, p)
                    x := mulmod(x, y, p)
                    z := mulmod(x, x, p)
                    z := mulmod(x, z, p)
                    z := mulmod(z, z, p)
                    y := mulmod(y, z, p)
                    z := mulmod(y, y, p)
                    z := mulmod(z, z, p)
                    x := mulmod(x, z, p)
                    y := mulmod(y, x, p)
                    z := mulmod(y, y, p)
                    z := mulmod(y, z, p)
                    x := mulmod(x, z, p)
                    y := mulmod(y, x, p)
                    x := mulmod(x, y, p)
                    y := mulmod(y, x, p)
                    z := mulmod(y, y, p)
                    z := mulmod(z, z, p)
                    z := mulmod(y, z, p)
                    x := mulmod(x, z, p)
                    z := mulmod(x, x, p)
                    z := mulmod(x, z, p)
                    y := mulmod(y, z, p)
                    x := mulmod(x, y, p)
                    y := mulmod(y, x, p)
                    x := mulmod(x, y, p)
                    y := mulmod(y, x, p)
                    z := mulmod(y, y, p)
                    z := mulmod(y, z, p)
                    z := mulmod(z, z, p)
                    x := mulmod(x, z, p)
                    y := mulmod(y, x, p)
                    z := mulmod(y, y, p)
                    z := mulmod(y, z, p)
                    z := mulmod(z, z, p)
                    x := mulmod(x, z, p)
                    z := mulmod(x, x, p)
                    t := mulmod(z, z, p)
                    t := mulmod(t, t, p)
                    t := mulmod(z, t, p)
                    t := mulmod(x, t, p)
                    t := mulmod(t, t, p)
                    t := mulmod(t, t, p)
                    t := mulmod(t, t, p)
                    t := mulmod(t, t, p)
                    z := mulmod(z, t, p)
                    y := mulmod(y, z, p)
                    x := mulmod(x, y, p)
                    y := mulmod(y, x, p)
                    x := mulmod(x, y, p)
                    z := mulmod(x, x, p)
                    z := mulmod(x, z, p)
                    z := mulmod(z, z, p)
                    z := mulmod(z, z, p)
                    z := mulmod(z, z, p)
                    z := mulmod(x, z, p)
                    y := mulmod(y, z, p)
                    z := mulmod(y, y, p)
                    z := mulmod(y, z, p)
                    z := mulmod(z, z, p)
                    x := mulmod(x, z, p)
                    z := mulmod(x, x, p)
                    z := mulmod(x, z, p)
                    y := mulmod(y, z, p)
                    x := mulmod(x, y, p)
                    z := mulmod(x, x, p)
                    z := mulmod(z, z, p)
                    y := mulmod(y, z, p)
                    x := mulmod(x, y, p)
                    z := mulmod(x, x, p)
                    y := mulmod(y, z, p)
                    x := mulmod(x, y, p)
                    y := mulmod(y, x, p)
                    z := mulmod(y, y, p)
                    z := mulmod(y, z, p)
                    x := mulmod(x, z, p)
                    y := mulmod(y, x, p)
                    z := mulmod(y, y, p)
                    z := mulmod(y, z, p)
                    z := mulmod(z, z, p)
                    z := mulmod(z, z, p)
                    x := mulmod(x, z, p)
                    z := mulmod(x, x, p)
                    z := mulmod(z, z, p)
                    z := mulmod(z, z, p)
                    z := mulmod(x, z, p)
                    y := mulmod(y, z, p)
                    x := mulmod(x, y, p)
                    z := mulmod(x, x, p)
                    t := mulmod(x, z, p)
                    t := mulmod(t, t, p)
                    t := mulmod(t, t, p)
                    z := mulmod(z, t, p)
                    y := mulmod(y, z, p)
                    z := mulmod(y, y, p)
                    x := mulmod(x, z, p)
                    y := mulmod(y, x, p)
                    x := mulmod(x, y, p)
                    y := mulmod(y, x, p)
                    x := mulmod(x, y, p)
                    y := mulmod(y, x, p)
                    z := mulmod(y, y, p)
                    t := mulmod(y, z, p)
                    z := mulmod(y, t, p)
                    z := mulmod(z, z, p)
                    z := mulmod(z, z, p)
                    z := mulmod(t, z, p)
                }
                x := mulmod(x, z, p)
                y := mulmod(y, x, p)
                x := mulmod(x, y, p)
                y := mulmod(y, x, p)
                x := mulmod(x, y, p)
                z := mulmod(x, x, p)
                z := mulmod(x, z, p)
                y := mulmod(y, z, p)
            }
            x := mulmod(x, y, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            x := mulmod(x, x, p)
            y := mulmod(y, x, p)
        }
    }

    /// @dev Constructs an outcome collection ID from a parent collection and an outcome collection.
    /// @param parentCollectionId Collection ID of the parent outcome collection, or bytes32(0) if
    /// there's no parent.
    /// @param conditionId Condition ID of the outcome collection to combine with the parent outcome
    /// collection.
    /// @param indexSet Index set of the outcome collection to combine with the parent outcome
    /// collection.
    function getCollectionId(bytes32 parentCollectionId, bytes32 conditionId, uint256 indexSet)
        internal
        view
        returns (bytes32)
    {
        uint256 x1 = uint256(keccak256(abi.encodePacked(conditionId, indexSet)));
        bool odd = x1 >> 255 != 0;
        uint256 y1;
        uint256 yy;
        do {
            x1 = addmod(x1, 1, P);
            yy = addmod(mulmod(x1, mulmod(x1, x1, P), P), B, P);
            y1 = sqrt(yy);
        } while (mulmod(y1, y1, P) != yy);
        if ((odd && y1 % 2 == 0) || (!odd && y1 % 2 == 1)) y1 = P - y1;

        uint256 x2 = uint256(parentCollectionId);
        if (x2 != 0) {
            odd = x2 >> 254 != 0;
            x2 = (x2 << 2) >> 2;
            yy = addmod(mulmod(x2, mulmod(x2, x2, P), P), B, P);
            uint256 y2 = sqrt(yy);
            if ((odd && y2 % 2 == 0) || (!odd && y2 % 2 == 1)) y2 = P - y2;
            require(mulmod(y2, y2, P) == yy, "invalid parent collection ID");

            (bool success, bytes memory ret) = address(6).staticcall(abi.encode(x1, y1, x2, y2));
            require(success, "ecadd failed");
            (x1, y1) = abi.decode(ret, (uint256, uint256));
        }

        if (y1 % 2 == 1) x1 ^= 1 << 254;

        return bytes32(x1);
    }

    /// @dev Constructs a position ID from a collateral token and an outcome collection. These IDs
    /// are used as the ERC-1155 ID for this contract.
    /// @param collateralToken Collateral token which backs the position.
    /// @param collectionId ID of the outcome collection associated with this position.
    function getPositionId(address collateralToken, bytes32 collectionId)
        internal
        pure
        returns (uint256)
    {
        return uint256(keccak256(abi.encodePacked(collateralToken, collectionId)));
    }
}


// ===== src/libraries/Helpers.sol =====
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {CTHelpers} from "./CTHelpers.sol";

/// @title Helpers
/// @notice Helper functions for the NegRiskAdapter
/// @author Mike Shrieve (mike@polymarket.com)
library Helpers {
    /// @notice Returns the positionIds corresponding to _conditionId
    /// @param _collateral  - the collateral address
    /// @param _conditionId - the conditionId
    /// @return positionIds - length 2 array of position ids
    function positionIds(address _collateral, bytes32 _conditionId) internal view returns (uint256[] memory) {
        uint256[] memory positionIds_ = new uint256[](2);

        // YES
        positionIds_[0] = CTHelpers.getPositionId(_collateral, CTHelpers.getCollectionId(bytes32(0), _conditionId, 1));
        // NO
        positionIds_[1] = CTHelpers.getPositionId(_collateral, CTHelpers.getCollectionId(bytes32(0), _conditionId, 2));

        return positionIds_;
    }

    /// @notice Returns an array with each element set to the same value
    /// @param _length  - the length of the array
    /// @param _value   - the value of each element
    /// @return values_ - the array of values
    function values(uint256 _length, uint256 _value) internal pure returns (uint256[] memory) {
        uint256[] memory values_ = new uint256[](_length);
        uint256 i;

        while (i < _length) {
            values_[i] = _value;
            unchecked {
                ++i;
            }
        }
        return values_;
    }

    /// @notice returns the partition for a binary conditional token
    /// @return partition - the partition [1,2] = [0b01, 0b10]
    function partition() internal pure returns (uint256[] memory) {
        uint256[] memory partition_ = new uint256[](2);
        // YES
        partition_[0] = 1;
        // NO
        partition_[1] = 2;
        return partition_;
    }

    /// @notice returns the payouts for a binary conditional token
    /// @notice payouts are [1,0] if _outcome is true and [0,1] otherwise
    /// @param _outcome - the boolean outcome
    /// @return payouts - the payouts
    function payouts(bool _outcome) internal pure returns (uint256[] memory) {
        uint256[] memory payouts_ = new uint256[](2);
        // YES
        payouts_[0] = _outcome ? 1 : 0;
        // NO
        payouts_[1] = _outcome ? 0 : 1;
        return payouts_;
    }
}


// ===== src/libraries/NegRiskIdLib.sol =====
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

/// @title NegRiskIdLib
/// @notice Functions for the NegRiskAdapter Market and QuestionIds
/// @notice MarketIds are the keccak256 hash of the oracle, feeBips, and metadata, with the final 8 bits set to 0
/// @notice QuestionIds share the first 31 bytes with their corresponding MarketId, and the final byte consists of the
/// questionIndex
/// @author Mike Shrieve (mike@polymarket.com)
library NegRiskIdLib {
    bytes32 private constant MASK = bytes32(type(uint256).max) << 8;

    /// @notice Returns the MarketId for a given oracle, feeBips, and metadata
    /// @param _oracle   - the oracle address
    /// @param _feeBips  - the feeBips, out of 10_000
    /// @param _metadata - the market metadata
    /// @return marketId - the marketId
    function getMarketId(address _oracle, uint256 _feeBips, bytes memory _metadata) internal pure returns (bytes32) {
        return keccak256(abi.encode(_oracle, _feeBips, _metadata)) & MASK;
    }

    /// @notice Returns the MarketId for a given QuestionId
    /// @param _questionId - the questionId
    /// @return marketId   - the marketId
    function getMarketId(bytes32 _questionId) internal pure returns (bytes32) {
        return _questionId & MASK;
    }

    /// @notice Returns the QuestionId for a given MarketId and questionIndex
    /// @param _marketId      - the marketId
    /// @param _questionIndex - the questionIndex
    /// @return questionId    - the questionId
    function getQuestionId(bytes32 _marketId, uint8 _questionIndex) internal pure returns (bytes32) {
        unchecked {
            return bytes32(uint256(_marketId) + _questionIndex);
        }
    }

    /// @notice Returns the questionIndex for a given QuestionId
    /// @param _questionId - the questionId
    /// @return questionIndex - the questionIndex
    function getQuestionIndex(bytes32 _questionId) internal pure returns (uint8) {
        return uint8(uint256(_questionId));
    }
}


// ===== src/modules/Auth.sol =====
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {IAuth} from "./interfaces/IAuth.sol";

/// @title Auth
/// @author Jon Amenechi (jon@polymarket.com)
/// @notice Provides access control modifiers
abstract contract Auth is IAuth {
    /// @notice Auth
    mapping(address => uint256) public admins;

    modifier onlyAdmin() {
        if (admins[msg.sender] != 1) revert NotAdmin();
        _;
    }

    constructor() {
        admins[msg.sender] = 1;
    }

    /// @notice Adds an Admin
    /// @param admin - The address of the admin
    function addAdmin(address admin) external onlyAdmin {
        admins[admin] = 1;
        emit NewAdmin(msg.sender, admin);
    }

    /// @notice Removes an admin
    /// @param admin - The address of the admin to be removed
    function removeAdmin(address admin) external onlyAdmin {
        admins[admin] = 0;
        emit RemovedAdmin(msg.sender, admin);
    }

    /// @notice Renounces Admin privileges from the caller
    function renounceAdmin() external onlyAdmin {
        admins[msg.sender] = 0;
        emit RemovedAdmin(msg.sender, msg.sender);
    }

    /// @notice Checks if an address is an admin
    /// @param addr - The address to be checked
    function isAdmin(address addr) external view returns (bool) {
        return admins[addr] == 1;
    }
}


// ===== src/modules/MarketDataManager.sol =====
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {MarketData, MarketDataLib} from "src/types/MarketData.sol";
import {NegRiskIdLib} from "src/libraries/NegRiskIdLib.sol";

interface IMarketStateManagerEE {
    error IndexOutOfBounds();
    error OnlyOracle();
    error MarketNotPrepared();
    error MarketAlreadyPrepared();
    error MarketAlreadyDetermined();
    error FeeBipsOutOfBounds();
}

/// @title MarketStateManager
/// @notice Manages market state on behalf of the NegRiskAdapter
/// @author Mike Shrieve(mike@polymarket.com)
abstract contract MarketStateManager is IMarketStateManagerEE {
    mapping(bytes32 _marketId => MarketData) internal marketData;

    /*//////////////////////////////////////////////////////////////
                                GETTERS
    //////////////////////////////////////////////////////////////*/

    function getMarketData(bytes32 _marketId) public view returns (MarketData) {
        return marketData[_marketId];
    }

    function getOracle(bytes32 _marketId) external view returns (address) {
        return marketData[_marketId].oracle();
    }

    function getQuestionCount(bytes32 _marketId) external view returns (uint256) {
        return marketData[_marketId].questionCount();
    }

    function getDetermined(bytes32 _marketId) external view returns (bool) {
        return marketData[_marketId].determined();
    }

    function getResult(bytes32 _marketId) external view returns (uint256) {
        return marketData[_marketId].result();
    }

    function getFeeBips(bytes32 _marketId) external view returns (uint256) {
        return marketData[_marketId].feeBips();
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Prepares market data
    /// @notice The market id depends on the oracle address, feeBips, and market metadata
    /// @param _feeBips  - feeBips out of 10_000
    /// @param _metadata - market metadata
    /// @return marketId - the market id
    function _prepareMarket(uint256 _feeBips, bytes memory _metadata) internal returns (bytes32 marketId) {
        address oracle = msg.sender;
        marketId = NegRiskIdLib.getMarketId(oracle, _feeBips, _metadata);
        MarketData md = marketData[marketId];

        if (md.oracle() != address(0)) revert MarketAlreadyPrepared();
        if (_feeBips > 10_000) revert FeeBipsOutOfBounds();

        marketData[marketId] = MarketDataLib.initialize(oracle, _feeBips);
    }

    /// @notice Prepares a new question for the given market
    /// @param _marketId   - the market for which to prepare a new question
    /// @return questionId - the resulting question id
    /// @return index      - the resulting question index
    function _prepareQuestion(bytes32 _marketId) internal returns (bytes32 questionId, uint256 index) {
        MarketData md = marketData[_marketId];
        address oracle = marketData[_marketId].oracle();

        if (oracle == address(0)) revert MarketNotPrepared();
        if (oracle != msg.sender) revert OnlyOracle();

        index = md.questionCount();
        questionId = NegRiskIdLib.getQuestionId(_marketId, uint8(index));
        marketData[_marketId] = md.incrementQuestionCount();
    }

    /// @notice Reports the outcome of a question
    /// @notice State is only modified if the outcome is true
    /// @notice Reverts if the market is not prepared
    /// @notice Reverts if msg.sender is not the market's oracle
    /// @notice Reverts if the question index is out of bounds
    /// @notice Reverts if the outcome is true, and the market has already been determined
    function _reportOutcome(bytes32 _questionId, bool _outcome) internal {
        bytes32 marketId = NegRiskIdLib.getMarketId(_questionId);
        uint256 questionIndex = NegRiskIdLib.getQuestionIndex(_questionId);

        MarketData data = marketData[marketId];
        address oracle = data.oracle();

        if (oracle == address(0)) revert MarketNotPrepared();
        if (oracle != msg.sender) revert OnlyOracle();
        if (questionIndex >= data.questionCount()) revert IndexOutOfBounds();

        if (_outcome == true) {
            if (data.determined()) revert MarketAlreadyDetermined();
            marketData[marketId] = data.determine(questionIndex);
        }
    }
}


// ===== src/modules/interfaces/IAuth.sol =====
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

interface IAuthEE {
    error NotAdmin();

    /// @notice Emitted when a new admin is added
    event NewAdmin(address indexed admin, address indexed newAdminAddress);

    /// @notice Emitted when an admin is removed
    event RemovedAdmin(address indexed admin, address indexed removedAdmin);
}

interface IAuth is IAuthEE {
    function isAdmin(address) external view returns (bool);

    function addAdmin(address) external;

    function removeAdmin(address) external;

    function renounceAdmin() external;
}


// ===== src/types/MarketData.sol =====
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

/// @notice the MarketData user-defined type, a zero-cost abstraction over bytes32
type MarketData is bytes32;

// md[0] = questionCount
// md[1] = determined
// md[2] = result
// md[3:4] = feeBips
// md[12:32] = oracle

using MarketDataLib for MarketData global;

/// @title MarketDataLib
/// @notice Library for dealing with the MarketData user-defined bytes32 type
/// @author Mike Shrieve (mike@polymarket.com)
library MarketDataLib {
    error DeterminedFlagAlreadySet();

    /// @notice used to increment the questionCount
    uint256 constant INCREMENT = uint256(bytes32(bytes1(0x01)));

    /// @notice extracts the oracle address from MarketData
    /// @return oracle - the address of the oracle
    function oracle(MarketData _data) internal pure returns (address) {
        return address(uint160(uint256(MarketData.unwrap(_data))));
    }

    /// @notice extracts the questionCount from MarketData
    /// @return questionCount - the number of questions in the market
    function questionCount(MarketData _data) internal pure returns (uint256) {
        return uint256(uint8(MarketData.unwrap(_data)[0]));
    }

    /// @notice increments the questionCount
    /// @notice does _not_ check to see if the questionCount is already at the maximum value
    /// @return marketData - the modified MarketData
    function incrementQuestionCount(MarketData _data) internal pure returns (MarketData) {
        bytes32 data = MarketData.unwrap(_data);
        data = bytes32(uint256(data) + INCREMENT);
        return MarketData.wrap(data);
    }

    /// @notice extracts the determined flag from MarketData
    /// @return determined - true if the market has been determined, i.e. if one of the questions was resolved true
    function determined(MarketData _data) internal pure returns (bool) {
        return MarketData.unwrap(_data)[1] == 0x00 ? false : true;
    }

    /// @notice marks the market as determined
    /// @param _result - the result of the market, i.e., the index of the question that was resolved true
    /// @return marketData - the modified MarketData
    function determine(MarketData _data, uint256 _result) internal pure returns (MarketData) {
        bytes32 data = MarketData.unwrap(_data);

        if (data[1] != 0x00) revert DeterminedFlagAlreadySet();
        data |= bytes32(bytes1(0x01)) >> 8;
        data |= bytes32(bytes1(uint8(_result))) >> 16;

        return MarketData.wrap(data);
    }

    /// @notice initializes the MarketData type
    /// @param _oracle - the address of the oracle
    /// @param _feeBips - the feeBips, out of 10_000
    /// @return marketData - the initialized MarketData
    function initialize(address _oracle, uint256 _feeBips) internal pure returns (MarketData) {
        bytes32 data;
        data |= bytes32(bytes2(uint16(_feeBips))) >> 24;
        data |= bytes32(uint256(uint160(_oracle)));
        return MarketData.wrap(data);
    }

    /// @notice extracts the result from MarketData, i.e., the index of the question that was resolved true
    /// @notice if the market has not been determined, returns zero
    /// @return result - the index of the question that was resolved true, or zero
    function result(MarketData _data) internal pure returns (uint256) {
        return uint256(uint8(MarketData.unwrap(_data)[2]));
    }

    /// @notice extracts the feeBips from MarketData, out of 10_000
    /// @return feeBips - the feeBips
    function feeBips(MarketData _data) internal pure returns (uint256) {
        return uint256(uint16(bytes2(MarketData.unwrap(_data) << 24)));
    }
}
