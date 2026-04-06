// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

/// @title OracleManipulableBridge — Flash loan oracle manipulation pattern
/// @notice Reproduces the common DeFi oracle manipulation pattern seen in
///         Allbridge ($570K), Mango Markets ($114M), and many others.
///         Uses spot AMM reserves instead of TWAP, trivially manipulable
///         via flash loan within a single transaction.
///
///         Bugs:
///           1. getPrice() uses spot reserves, not TWAP
///           2. Collateral check uses manipulable price
///           3. Liquidation uses manipulable price
contract OracleManipulableBridge {
    IUniswapV2Pair public priceFeed;
    address public token;
    mapping(address => uint256) public deposits;

    event Deposited(address indexed user, uint256 tokenAmount, uint256 collateral);
    event Liquidated(address indexed user, address indexed liquidator);

    constructor(address _pair, address _token) {
        priceFeed = IUniswapV2Pair(_pair);
        token = _token;
    }

    /// @dev BUG: Spot price from current reserves — manipulable via flash loan
    function getPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = priceFeed.getReserves();
        return (uint256(reserve0) * 1e18) / uint256(reserve1);
    }

    function depositWithCollateral(uint256 tokenAmount) external payable {
        uint256 price = getPrice();
        uint256 ethValue = (tokenAmount * price) / 1e18;
        require(msg.value >= ethValue / 2, "Insufficient collateral");
        deposits[msg.sender] += tokenAmount;
        emit Deposited(msg.sender, tokenAmount, msg.value);
    }

    function liquidate(address user) external {
        uint256 price = getPrice();
        uint256 deposited = deposits[user];
        uint256 ethValue = (deposited * price) / 1e18;
        require(ethValue > deposits[user] * 2, "Not liquidatable");
        deposits[user] = 0;
        (bool success,) = msg.sender.call{value: address(this).balance}("");
        require(success);
        emit Liquidated(user, msg.sender);
    }

    receive() external payable {}
}
