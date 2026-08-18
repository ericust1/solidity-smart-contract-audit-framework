import pytest
from src.modules.contract_analyzer import StaticContractAnalyzer


REENTRANCY_SNIPPET = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VulnerableDEX {
    mapping(bytes32 => uint256) public reserves;
    address public feeRecipient;

    function swap(address tokenIn, address tokenOut, uint256 amountIn) external returns (uint256 amountOut) {
        uint256 fee = (amountIn * 30) / 10000;
        uint256 amountInAfterFee = amountIn - fee;
        amountOut = (reserves[tokenOut] * amountInAfterFee) / (reserves[tokenIn] + amountInAfterFee);
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenOut).transfer(msg.sender, amountOut);
        reserves[tokenIn] += amountIn;
        reserves[tokenOut] -= amountOut;
    }

    function emergencyWithdraw(address token, uint256 amount) external {
        IERC20(token).transfer(msg.sender, amount);
    }

    function setFeeRecipient(address newRecipient) external {
        feeRecipient = newRecipient;
    }

    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool success, bytes memory result) = address(this).delegatecall(data[i]);
            results[i] = result;
        }
    }
}
"""

INTEGER_SNIPPET = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract FuturesContract {
    struct Position {
        address trader;
        int256 amount;
        uint256 leverage;
    }

    mapping(uint256 => Position) public positions;
    uint256 public positionCount;

    function openLeveragedPosition(
        address token,
        int256 direction,
        uint256 amount,
        uint256 leverage,
        uint256 price
    ) external returns (uint256) {
        uint256 collateral = amount / leverage;
        int256 leveragedAmount = int256(amount) * int256(leverage);
        uint256 positionId = positionCount++;
        positions[positionId] = Position(trader, token, leveragedAmount, leverage);
        return positionId;
    }

    function closePosition(uint256 positionId, uint256 exitPrice) external returns (int256) {
        Position storage pos = positions[positionId];
        int256 priceDiff = int256(exitPrice) - int256(pos.entryPrice);
        int256 pnl = (priceDiff * pos.amount) / int256(pos.entryPrice);
        return pnl;
    }

    function swap(address tokenA, address tokenB, uint256 amountIn) external returns (uint256) {
        uint256 amountOut = (1000 * amountIn) / 2000;
        return amountOut;
    }
}
"""

HARDENED_SNIPPET = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SafeDEX {
    address public owner;
    bool private _locked;
    mapping(bytes32 => uint256) public reserves;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier nonReentrant() {
        require(!_locked, "Locked");
        _locked = true;
        _;
        _locked = false;
    }

    function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
        _locked = true;
        (bool success, ) = address(token).call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, amount));
        require(success, "Transfer failed");
        _locked = false;
    }

    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}
"""


@pytest.fixture
def analyzer():
    return StaticContractAnalyzer()


class TestParseSolidity:

    def test_extracts_pragma(self, analyzer):
        ast = analyzer.parse_solidity(REENTRANCY_SNIPPET)
        assert len(ast["pragmas"]) > 0
        assert "0.8" in ast["pragmas"][0]

    def test_extracts_contracts(self, analyzer):
        ast = analyzer.parse_solidity(REENTRANCY_SNIPPET)
        names = [c["name"] for c in ast["contracts"]]
        assert "VulnerableDEX" in names

    def test_extracts_functions(self, analyzer):
        ast = analyzer.parse_solidity(REENTRANCY_SNIPPET)
        names = [f["name"] for f in ast["functions"]]
        assert "swap" in names
        assert "emergencyWithdraw" in names
        assert "multicall" in names

    def test_extracts_state_variables(self, analyzer):
        ast = analyzer.parse_solidity(REENTRANCY_SNIPPET)
        assert "feeRecipient" in ast["state_variables"]

    def test_empty_source(self, analyzer):
        ast = analyzer.parse_solidity("")
        assert ast["functions"] == []
        assert ast["contracts"] == []


class TestDetectReentrancy:

    def test_detects_no_guard(self, analyzer):
        ast = analyzer.parse_solidity(REENTRANCY_SNIPPET)
        findings = analyzer.detect_reentrancy(ast)
        titles = [f["title"] for f in findings]
        assert any("No Reentrancy Guard" in t for t in titles)

    def test_detects_swap_reentrancy(self, analyzer):
        ast = analyzer.parse_solidity(REENTRANCY_SNIPPET)
        findings = analyzer.detect_reentrancy(ast)
        titles = [f["title"] for f in findings]
        assert any("swap" in t.lower() and "reentrancy" in t.lower() for t in titles)

    def test_reentrancy_severity(self, analyzer):
        ast = analyzer.parse_solidity(REENTRANCY_SNIPPET)
        findings = analyzer.detect_reentrancy(ast)
        for f in findings:
            if "No Reentrancy Guard" in f["title"]:
                assert f["severity"] == "High"

    def test_guarded_contract_clean(self, analyzer):
        ast = analyzer.parse_solidity(HARDENED_SNIPPET)
        findings = analyzer.detect_reentrancy(ast)
        titles = [f["title"] for f in findings]
        assert not any("No Reentrancy Guard" in t for t in titles)


class TestDetectIntegerIssues:

    def test_detects_leverage_overflow(self, analyzer):
        ast = analyzer.parse_solidity(INTEGER_SNIPPET)
        findings = analyzer.detect_integer_issues(ast)
        titles = [f["title"] for f in findings]
        assert any("overflow" in t.lower() or "integer" in t.lower() for t in titles)

    def test_detects_swap_precision(self, analyzer):
        ast = analyzer.parse_solidity(INTEGER_SNIPPET)
        findings = analyzer.detect_integer_issues(ast)
        titles = [f["title"] for f in findings]
        assert any("precision" in t.lower() or "division" in t.lower() for t in titles)

    def test_integer_finding_has_recommendation(self, analyzer):
        ast = analyzer.parse_solidity(INTEGER_SNIPPET)
        findings = analyzer.detect_integer_issues(ast)
        assert len(findings) > 0
        assert all(f["recommendation"] for f in findings)


class TestDetectAccessControl:

    def test_detects_missing_access_control(self, analyzer):
        ast = analyzer.parse_solidity(REENTRANCY_SNIPPET)
        findings = analyzer.detect_access_control(ast)
        assert len(findings) > 0
        titles = [f["title"] for f in findings]
        assert any("emergencyWithdraw" in t for t in titles)
        assert any("setFeeRecipient" in t for t in titles)

    def test_access_control_severity(self, analyzer):
        ast = analyzer.parse_solidity(REENTRANCY_SNIPPET)
        findings = analyzer.detect_access_control(ast)
        for f in findings:
            assert f["severity"] == "High"

    def test_guarded_contract_has_access_control(self, analyzer):
        ast = analyzer.parse_solidity(HARDENED_SNIPPET)
        findings = analyzer.detect_access_control(ast)
        titles = [f["title"] for f in findings]
        assert not any("emergencyWithdraw" in t for t in titles)


class TestDetectUncheckedReturns:

    def test_detects_unchecked_erc20(self, analyzer):
        ast = analyzer.parse_solidity(REENTRANCY_SNIPPET)
        findings = analyzer.detect_unchecked_returns(ast)
        titles = [f["title"] for f in findings]
        assert any("Unchecked ERC20" in t for t in titles)

    def test_detects_unchecked_delegatecall(self, analyzer):
        ast = analyzer.parse_solidity(REENTRANCY_SNIPPET)
        findings = analyzer.detect_unchecked_returns(ast)
        titles = [f["title"] for f in findings]
        assert any("Delegatecall" in t for t in titles)

    def test_unchecked_delegatecall_severity(self, analyzer):
        ast = analyzer.parse_solidity(REENTRANCY_SNIPPET)
        findings = analyzer.detect_unchecked_returns(ast)
        for f in findings:
            if "Delegatecall" in f["title"]:
                assert f["severity"] == "High"


class TestFullAnalysis:

    def test_full_analysis_returns_findings(self, analyzer):
        result = analyzer.analyze(REENTRANCY_SNIPPET)
        assert "ast" in result
        assert "findings" in result
        assert len(result["findings"]) > 0

    def test_full_analysis_finds_reentrancy(self, analyzer):
        result = analyzer.analyze(REENTRANCY_SNIPPET)
        all_titles = " ".join(f["title"] for f in result["findings"]).lower()
        assert "reentrancy" in all_titles

    def test_full_analysis_finds_access_control(self, analyzer):
        result = analyzer.analyze(REENTRANCY_SNIPPET)
        all_titles = " ".join(f["title"] for f in result["findings"]).lower()
        assert "access control" in all_titles

    def test_hardened_has_fewer_findings(self, analyzer):
        vuln_result = analyzer.analyze(REENTRANCY_SNIPPET)
        safe_result = analyzer.analyze(HARDENED_SNIPPET)
        assert len(safe_result["findings"]) < len(vuln_result["findings"])
