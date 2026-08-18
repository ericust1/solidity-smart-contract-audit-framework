import json
import pytest
from pathlib import Path
from src.modules.contract_analyzer import StaticContractAnalyzer
from src.core.audit_aggregator import AuditAggregator

VULNERABLE_DEX_SOURCE = Path(__file__).parent.parent.parent / "contracts" / "VulnerableDEX.sol"
HARDENED_DEX_SOURCE = Path(__file__).parent.parent.parent / "contracts" / "HardenedDEX.sol"


class TestAuditPipeline:

    def test_vulnerable_dex_detected(self):
        if not VULNERABLE_DEX_SOURCE.exists():
            pytest.skip("VulnerableDEX.sol not found")

        source = VULNERABLE_DEX_SOURCE.read_text()
        analyzer = StaticContractAnalyzer()
        result = analyzer.analyze(source)

        titles = [f["title"].lower() for f in result["findings"]]
        assert any("reentrancy" in t for t in titles), f"No reentrancy found in: {titles}"
        assert any("access control" in t for t in titles), f"No access control found in: {titles}"

    def test_hardened_dex_cleaner(self):
        if not HARDENED_DEX_SOURCE.exists():
            pytest.skip("HardenedDEX.sol not found")

        analyzer = StaticContractAnalyzer()

        vuln_source = VULNERABLE_DEX_SOURCE.read_text() if VULNERABLE_DEX_SOURCE.exists() else ""
        safe_source = HARDENED_DEX_SOURCE.read_text()

        vuln_result = analyzer.analyze(vuln_source)
        safe_result = analyzer.analyze(safe_source)

        if vuln_result["findings"]:
            assert len(safe_result["findings"]) <= len(vuln_result["findings"])

    def test_aggregate_and_report(self, tmp_path):
        if not VULNERABLE_DEX_SOURCE.exists():
            pytest.skip("VulnerableDEX.sol not found")

        source = VULNERABLE_DEX_SOURCE.read_text()
        analyzer = StaticContractAnalyzer()
        result = analyzer.analyze(source)

        aggregator = AuditAggregator()
        aggregator.add_source("static_analyzer", result["findings"])

        mock_slither = [
            {
                "title": "Reentrancy in swap()",
                "severity": "High",
                "file": "VulnerableDEX.sol",
                "line": 112,
                "description": "External call before state update",
                "recommendation": "Add nonReentrant",
            },
            {
                "title": "Unchecked return value in multicall()",
                "severity": "High",
                "file": "VulnerableDEX.sol",
                "line": 180,
                "description": "delegatecall return not checked",
                "recommendation": "Check success",
            },
        ]

        mock_mythril = [
            {
                "title": "Reentrancy in swap()",
                "severity": "High",
                "file": "VulnerableDEX.sol",
                "line": 115,
                "description": "Token transfer before balance update",
                "recommendation": "Use mutex",
            },
        ]

        aggregator.add_source("slither", mock_slither)
        aggregator.add_source("mythril", mock_mythril)

        report_path = tmp_path / "audit_report.md"
        report_result = aggregator.generate_combined_report(str(report_path))

        assert Path(report_result["report_path"]).exists()
        assert report_result["high_count"] > 0

        content = report_path.read_text()
        assert "Executive Summary" in content
        assert "Tool Comparison Matrix" in content
        assert "Remediation Priority Queue" in content

        json_path = Path(report_result["json_path"])
        assert json_path.exists()
        json_data = json.loads(json_path.read_text())
        assert json_data["total_unique"] > 0

        shared = [f for f in json_data["findings"] if f.get("detection_tools", 0) > 1]
        assert len(shared) > 0, "Should have at least one cross-tool confirmed finding"

    def test_finding_severity_distribution(self):
        if not VULNERABLE_DEX_SOURCE.exists():
            pytest.skip("VulnerableDEX.sol not found")

        source = VULNERABLE_DEX_SOURCE.read_text()
        analyzer = StaticContractAnalyzer()
        result = analyzer.analyze(source)

        severities = {}
        for f in result["findings"]:
            sev = f["severity"]
            severities[sev] = severities.get(sev, 0) + 1

        assert "High" in severities, "Vulnerable DEX should have High severity findings"

    def test_pipeline_with_embedded_source(self):
        embedded = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SimpleVault {
    mapping(address => uint256) public balances;
    address public admin;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    function setAdmin(address newAdmin) external {
        admin = newAdmin;
    }
}
        """

        analyzer = StaticContractAnalyzer()
        result = analyzer.analyze(embedded)

        titles = [f["title"].lower() for f in result["findings"]]
        assert any("reentrancy" in t for t in titles), f"Expected reentrancy in: {titles}"
        assert any("access control" in t for t in titles), f"Expected access control in: {titles}"

        aggregator = AuditAggregator()
        aggregator.add_source("pipeline", result["findings"])
        all_f = aggregator.get_all_findings()
        assert len(all_f) > 0

        high = aggregator.get_by_severity("High")
        assert len(high) > 0

        unique = aggregator.get_unique_findings()
        assert len(unique) > 0
