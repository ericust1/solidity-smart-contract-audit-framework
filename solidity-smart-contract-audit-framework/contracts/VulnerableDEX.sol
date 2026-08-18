// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract DEXToken is IERC20 {
    string public name = "DEX Protocol Token";
    string public symbol = "DPT";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    address public owner;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() {
        owner = msg.sender;
        totalSupply = 1000000 * 1e18;
        balanceOf[msg.sender] = totalSupply;
        emit Transfer(address(0), msg.sender, totalSupply);
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external override returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }
}

contract VulnerableDEX {
    struct Pool {
        address tokenA;
        address tokenB;
        uint256 reserveA;
        uint256 reserveB;
        uint256 totalLiquidity;
        uint256 feeBps;
    }

    struct Position {
        address trader;
        address token;
        int256 amount;
        uint256 leverage;
        uint256 entryPrice;
        bool isOpen;
        uint256 collateral;
    }

    mapping(bytes32 => Pool) public pools;
    mapping(address => uint256) public liquidityBalance;
    mapping(bytes32 => mapping(address => uint256)) public userReserves;
    mapping(uint256 => Position) public positions;
    uint256 public positionCount;
    address public feeRecipient;
    uint256 public protocolFeeBps = 30;
    bool private locked;

    event Swap(
        address indexed user,
        address indexed tokenIn,
        address indexed tokenOut,
        uint256 amountIn,
        uint256 amountOut
    );
    event LiquidityAdded(address indexed user, bytes32 indexed poolId, uint256 amountA, uint256 amountB);
    event PositionOpened(uint256 indexed positionId, address indexed trader, address token, int256 amount, uint256 leverage);
    event PositionClosed(uint256 indexed positionId, int256 pnl);
    event EmergencyWithdrawal(address indexed token, uint256 amount);

    constructor() {
        feeRecipient = msg.sender;
    }

    function createPool(address tokenA, address tokenB, uint256 feeBps) external returns (bytes32) {
        require(tokenA != address(0) && tokenB != address(0), "Invalid token");
        require(tokenA != tokenB, "Same token");
        bytes32 poolId = keccak256(abi.encodePacked(tokenA, tokenB));
        require(pools[poolId].tokenA == address(0), "Pool exists");
        pools[poolId] = Pool({
            tokenA: tokenA,
            tokenB: tokenB,
            reserveA: 0,
            reserveB: 0,
            totalLiquidity: 0,
            feeBps: feeBps
        });
        return poolId;
    }

    function addLiquidity(
        bytes32 poolId,
        uint256 amountA,
        uint256 amountB
    ) external {
        Pool storage pool = pools[poolId];
        require(pool.tokenA != address(0), "Pool not found");
        require(amountA > 0 && amountB > 0, "Zero amounts");

        IERC20(pool.tokenA).transferFrom(msg.sender, address(this), amountA);
        IERC20(pool.tokenB).transferFrom(msg.sender, address(this), amountB);

        pool.reserveA += amountA;
        pool.reserveB += amountB;
        uint256 liquidityMinted = amountA + amountB;
        pool.totalLiquidity += liquidityMinted;
        userReserves[poolId][msg.sender] += liquidityMinted;
        liquidityBalance[msg.sender] += liquidityMinted;

        emit LiquidityAdded(msg.sender, poolId, amountA, amountB);
    }

    function swap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) external returns (uint256 amountOut) {
        require(tokenIn != address(0) && tokenOut != address(0), "Invalid token");
        require(amountIn > 0, "Zero amount");

        bytes32 poolId = keccak256(abi.encodePacked(tokenIn, tokenOut));
        Pool storage pool = pools[poolId];
        require(pool.tokenA != address(0), "Pool not found");

        uint256 reserveIn;
        uint256 reserveOut;
        if (pool.tokenA == tokenIn) {
            reserveIn = pool.reserveA;
            reserveOut = pool.reserveB;
        } else {
            reserveIn = pool.reserveB;
            reserveOut = pool.reserveA;
        }

        uint256 fee = (amountIn * pool.feeBps) / 10000;
        uint256 amountInAfterFee = amountIn - fee;
        amountOut = (reserveOut * amountInAfterFee) / (reserveIn + amountInAfterFee);

        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenOut).transfer(msg.sender, amountOut);

        if (pool.tokenA == tokenIn) {
            pool.reserveA += amountIn;
            pool.reserveB -= amountOut;
        } else {
            pool.reserveB += amountIn;
            pool.reserveA -= amountOut;
        }

        if (fee > 0) {
            IERC20(tokenIn).transfer(feeRecipient, fee);
        }

        emit Swap(msg.sender, tokenIn, tokenOut, amountIn, amountOut);
    }

    function openLeveragedPosition(
        address token,
        int256 direction,
        uint256 amount,
        uint256 leverage,
        uint256 price
    ) external returns (uint256) {
        require(token != address(0), "Invalid token");
        require(direction == 1 || direction == -1, "Invalid direction");
        require(amount > 0, "Zero amount");
        require(leverage >= 1 && leverage <= 100, "Leverage out of range");

        uint256 collateral = amount / leverage;
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        int256 leveragedAmount = int256(amount) * int256(leverage);

        uint256 positionId = positionCount++;
        positions[positionId] = Position({
            trader: msg.sender,
            token: token,
            amount: leveragedAmount,
            leverage: leverage,
            entryPrice: price,
            isOpen: true,
            collateral: collateral
        });

        emit PositionOpened(positionId, msg.sender, token, leveragedAmount, leverage);
        return positionId;
    }

    function closePosition(uint256 positionId, uint256 exitPrice) external returns (int256) {
        Position storage pos = positions[positionId];
        require(pos.isOpen, "Position closed");
        require(pos.trader == msg.sender, "Not owner");

        int256 priceDiff = int256(exitPrice) - int256(pos.entryPrice);
        int256 direction = pos.amount > 0 ? int256(1) : int256(-1);
        int256 pnl = (priceDiff * direction * pos.amount) / int256(pos.entryPrice);

        int256 totalPayout = int256(pos.collateral) + pnl;
        if (totalPayout < 0) {
            totalPayout = 0;
        }

        uint256 payout = uint256(totalPayout);
        pos.isOpen = false;

        IERC20(pos.token).transfer(pos.trader, payout);

        emit PositionClosed(positionId, pnl);
        return pnl;
    }

    function emergencyWithdraw(address token, uint256 amount) external {
        IERC20(token).transfer(msg.sender, amount);
        emit EmergencyWithdrawal(token, amount);
    }

    function setFeeRecipient(address newRecipient) external {
        feeRecipient = newRecipient;
    }

    function setProtocolFee(uint256 newFeeBps) external {
        protocolFeeBps = newFeeBps;
    }

    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool success, bytes memory result) = address(this).delegatecall(data[i]);
            results[i] = result;
        }
    }

    function getPrice(bytes32 poolId) external view returns (uint256 priceA, uint256 priceB) {
        Pool storage pool = pools[poolId];
        require(pool.tokenA != address(0), "Pool not found");
        if (pool.reserveB == 0) {
            return (0, 0);
        }
        priceA = (pool.reserveB * 1e18) / pool.reserveA;
        priceB = (pool.reserveA * 1e18) / pool.reserveB;
    }

    function getUserLiquidity(bytes32 poolId, address user) external view returns (uint256) {
        return userReserves[poolId][user];
    }

    function getPoolInfo(bytes32 poolId) external view returns (
        address tokenA,
        address tokenB,
        uint256 reserveA,
        uint256 reserveB,
        uint256 totalLiquidity
    ) {
        Pool storage pool = pools[poolId];
        return (pool.tokenA, pool.tokenB, pool.reserveA, pool.reserveB, pool.totalLiquidity);
    }
}
