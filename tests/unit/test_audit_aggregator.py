import json
import pytest
from pathlib import Path
from src.core.audit_aggregator import AuditAggregator


SLITHER_FINDINGS = [
    {"title": "Reentrancy in swap()", "severity": "High", "file": "VulnerableDEX.sol", "line": 112, "description": "External call before state update", "recommendation": "Add reentrancy guard", "tool": "slither"},
    {"title": "Missing access control on mint()", "severity": "High", "file": "VulnerableDEX.sol", "line": 55, "description": "Anyone can mint tokens", "recommendation": "Add onlyOwner", "tool": "slither"},
    {"title": "Unchecked return in multicall()", "severity": "High", "file": "VulnerableDEX.sol", "line": 180, "description": "Delegatecall return not checked", "recommendation": "Check return value", "tool": "slither"},
    {"title": "Pragma version not locked", "severity": "Low", "file": "VulnerableDEX.sol", "line": 1, "description": "Use locked pragma", "recommendation": "Lock pragma", "tool": "slither"},
]

MYTHRIL_FINDINGS = [
    {"title": "Reentrancy in swap()", "severity": "High", "file": "VulnerableDEX.sol", "line": 115, "description": "Token transfer before balance update", "recommendation": "Use mutex", "tool": "mythril"},
    {"title": "Unprotected withdrawal", "severity": "Medium", "file": "VulnerableDEX.sol", "line": 166, "description": "emergencyWithdraw has no access control", "recommendation": "Add onlyOwner", "tool": "mythril"},
    {"title": "Integer underflow risk", "severity": "Low", "file": "VulnerableDEX.sol", "line": 155, "description": "Leverage multiplication edge case", "recommendation": "Add bounds checks", "tool": "mythril"},
]

ANALYZER_FINDINGS = [
    {"title": "No Reentrancy Guard Detected", "severity": "High", "file": "VulnerableDEX.sol", "line": 0, "description": "Contract lacks reentrancy protection", "recommendation": "Implement nonReentrant", "tool": "static_analyzer"},
    {"title": "Missing Access Control on mint()", "severity": "High", "file": "VulnerableDEX.sol", "line": 0, "description": "Public mint function", "recommendation": "Restrict to owner", "tool": "static_analyzer"},
    {"title": "Potential Integer Overflow in openLeveragedPosition()", "severity": "High", "file": "VulnerableDEX.sol", "line": 0, "description": "int256 multiplication risk", "recommendation": "Cap leverage", "tool": "static_analyzer"},
]


@pytest.fixture
def aggregator():
    return AuditAggregator()


@pytest.fixture
def full_aggregator(aggregator):
    aggregator.add_source("slither", SLITHER_FINDINGS)
    aggregator.add_source("mythril", MYTHRIL_FINDINGS)
    aggregator.add_source("static_analyzer", ANALYZER_FINDINGS)
    return aggregator


class TestAddSource:

    def test_add_single_source(self, aggregator):
        aggregator.add_source("slither", SLITHER_FINDINGS)
        assert "slither" in aggregator.sources
        assert len(aggregator.sources["slither"]) == 4

    def test_rejects_non_list(self, aggregator):
        with pytest.raises(TypeError):
            aggregator.add_source("bad", {"not": "a list"})

    def test_add_empty_findings(self, aggregator):
        aggregator.add_source("empty", [])
        assert aggregator.sources["empty"] == []


class TestGetAllFindings:

    def test_all_findings_with_source(self, full_aggregator):
        all_f = full_aggregator.get_all_findings()
        assert len(all_f) == 10

        sources = {f["source"] for f in all_f}
        assert "slither" in sources
        assert "mythril" in sources
        assert "static_analyzer" in sources

    def test_empty_aggregator(self, aggregator):
        assert aggregator.get_all_findings() == []


class TestGetBySeverity:

    def test_filter_high(self, full_aggregator):
        high = full_aggregator.get_by_severity("High")
        assert all(f["severity"] == "High" for f in high)
        assert len(high) == 7

    def test_filter_medium(self, full_aggregator):
        medium = full_aggregator.get_by_severity("Medium")
        assert len(medium) == 1
        assert medium[0]["title"] == "Unprotected withdrawal"

    def test_filter_nonexistent(self, full_aggregator):
        result = full_aggregator.get_by_severity("Critical")
        assert result == []


class TestGetUniqueFindings:

    def test_deduplicates_across_tools(self, full_aggregator):
        unique = full_aggregator.get_unique_findings()
        titles = [f["title"].lower() for f in unique]
        assert len(titles) == len(set(titles))

    def test_shared_finding_preserved(self, full_aggregator):
        unique = full_aggregator.get_unique_findings()
        shared = [f for f in unique if "reentrancy" in f["title"].lower() and "swap" in f["title"].lower()]
        assert len(shared) >= 1

    def test_fewer_unique_than_total(self, full_aggregator):
        unique = full_aggregator.get_unique_findings()
        all_f = full_aggregator.get_all_findings()
        assert len(unique) < len(all_f)


class TestGenerateCombinedReport:

    def test_creates_markdown_report(self, full_aggregator, tmp_path):
        output = tmp_path / "reports" / "combined.md"
        result = full_aggregator.generate_combined_report(str(output))

        assert Path(result["report_path"]).exists()
        content = output.read_text()
        assert "Combined Smart Contract Audit Report" in content
        assert "Executive Summary" in content

    def test_creates_json_report(self, full_aggregator, tmp_path):
        output = tmp_path / "reports" / "combined.md"
        result = full_aggregator.generate_combined_report(str(output))

        json_path = Path(result["json_path"])
        assert json_path.exists()
        data = json.loads(json_path.read_text())
        assert data["total_unique"] > 0
        assert "findings" in data

    def test_executive_summary_has_high_count(self, full_aggregator, tmp_path):
        output = tmp_path / "report.md"
        result = full_aggregator.generate_combined_report(str(output))

        assert result["high_count"] > 0
        content = Path(result["report_path"]).read_text()
        assert "CRITICAL" in content

    def test_tool_comparison_matrix(self, full_aggregator, tmp_path):
        output = tmp_path / "report.md"
        full_aggregator.generate_combined_report(str(output))
        content = (tmp_path / "report.md").read_text()
        assert "Tool Comparison Matrix" in content
        assert "slither" in content.lower()
        assert "mythril" in content.lower()

    def test_priority_queue_ordered(self, full_aggregator, tmp_path):
        output = tmp_path / "report.md"
        full_aggregator.generate_combined_report(str(output))
        content = (tmp_path / "report.md").read_text()
        assert "Remediation Priority Queue" in content

    def test_matched_sources_on_enriched_findings(self, full_aggregator, tmp_path):
        output = tmp_path / "report.md"
        result = full_aggregator.generate_combined_report(str(output))
        json_data = json.loads(Path(result["json_path"]).read_text())
        enriched = json_data["findings"]
        multi_tool = [f for f in enriched if f.get("detection_tools", 0) > 1]
        assert len(multi_tool) > 0

    def test_creates_parent_dirs(self, full_aggregator, tmp_path):
        output = tmp_path / "a" / "b" / "c" / "report.md"
        result = full_aggregator.generate_combined_report(str(output))
        assert Path(result["report_path"]).exists()
