import json
import pytest
from src.core.mythril_runner import MythrilRunner


SAMPLE_MYTHRIL_JSON = json.dumps([
    {
        "title": "External Call To User-Supplied Address",
        "severity": "High",
        "description": "The contract delegates execution to an address provided as a function argument. This can be used to execute arbitrary code.",
        "swc_id": "SWC-107",
        "source": {
            "file": "contracts/VulnerableDEX.sol",
            "line": 181
        },
        "recommendation": "Remove the delegatecall or restrict the target addresses."
    },
    {
        "title": "Reentrancy Vulnerability",
        "severity": "High",
        "description": "The function swap performs an external call to transfer tokens before updating its state. An attacker can reenter swap before balances are updated.",
        "swc_id": "SWC-107",
        "source": {
            "file": "contracts/VulnerableDEX.sol",
            "line": 117
        },
        "recommendation": "Implement a reentrancy guard."
    },
    {
        "title": "Unprotected Ether Withdrawal",
        "severity": "Medium",
        "description": "Anyone can withdraw tokens without authorization through the emergencyWithdraw function.",
        "swc_id": "SWC-105",
        "source": {
            "file": "contracts/VulnerableDEX.sol",
            "line": 166
        },
        "recommendation": "Add access control."
    },
])

SAMPLE_MYTHRIL_TEXT = """Mythril analysis report
========================

==== Unchecked Return Value ====
Severity: Medium
SWC ID: SWC-104
File: contracts/VulnerableDEX.sol:181

A delegatecall return value is not checked.

==== Integer Underflow ====
Severity: Low
SWC ID: SWC-120
File: contracts/VulnerableDEX.sol:155

Potential integer underflow in leveraged position calculation.
"""


@pytest.fixture
def runner():
    return MythrilRunner()


@pytest.fixture
def json_output():
    return {"stdout": SAMPLE_MYTHRIL_JSON, "stderr": "", "returncode": 0}


@pytest.fixture
def text_output():
    return {"stdout": SAMPLE_MYTHRIL_TEXT, "stderr": "", "returncode": 0}


class TestParseFindingsJSON:

    def test_parses_json_array(self, runner, json_output):
        findings = runner.parse_findings(json_output)
        assert len(findings) == 3

    def test_finding_structure(self, runner, json_output):
        findings = runner.parse_findings(json_output)
        f = findings[0]
        assert f["title"] == "External Call To User-Supplied Address"
        assert f["severity"] == "High"
        assert f["file"] == "contracts/VulnerableDEX.sol"
        assert f["line"] == 181
        assert f["tool"] == "mythril"

    def test_severity_mapping(self, runner):
        critical_output = {
            "stdout": json.dumps([{"title": "T", "severity": "Critical", "description": "D"}]),
            "stderr": "",
            "returncode": 0,
        }
        findings = runner.parse_findings(critical_output)
        assert findings[0]["severity"] == "High"

    def test_extras_preserved(self, runner, json_output):
        findings = runner.parse_findings(json_output)
        f = findings[0]
        assert "extras" in f
        assert f["extras"]["swc_id"] == "SWC-107"

    def test_recommendation_fallback(self, runner):
        output = {
            "stdout": json.dumps([{
                "title": "Reentrancy in swap",
                "severity": "High",
                "description": "Reentrancy detected",
            }]),
            "stderr": "",
            "returncode": 0,
        }
        findings = runner.parse_findings(output)
        assert "reentrancy guard" in findings[0]["recommendation"].lower()


class TestParseFindingsText:

    def test_parses_text_format(self, runner, text_output):
        findings = runner.parse_findings(text_output)
        assert len(findings) == 2

    def test_severity_from_text(self, runner, text_output):
        findings = runner.parse_findings(text_output)
        assert findings[0]["severity"] == "Medium"
        assert findings[1]["severity"] == "Low"

    def test_file_from_text(self, runner, text_output):
        findings = runner.parse_findings(text_output)
        assert "VulnerableDEX.sol" in findings[0]["file"]

    def test_empty_output(self, runner):
        findings = runner.parse_findings({"stdout": "", "stderr": "", "returncode": 0})
        assert findings == []


class TestCompareWithSlither:

    def test_full_overlap(self, runner, json_output):
        slither_findings = [
            {"title": "Reentrancy Vulnerability", "severity": "High", "file": "a.sol"},
            {"title": "External Call To User-Supplied Address", "severity": "High", "file": "a.sol"},
        ]
        mythril_findings = runner.parse_findings(json_output)

        comparison = runner.compare_with_slither(slither_findings, mythril_findings)
        assert comparison["overlap_count"] == 2
        assert comparison["slither_only_count"] == 0
        assert comparison["mythril_only_count"] == 1

    def test_no_overlap(self, runner):
        slither_findings = [{"title": "Something else", "severity": "Low", "file": "b.sol"}]
        mythril_findings = [{"title": "Completely different", "severity": "High", "file": "a.sol"}]

        comparison = runner.compare_with_slither(slither_findings, mythril_findings)
        assert comparison["overlap_count"] == 0
        assert comparison["slither_only_count"] == 1
        assert comparison["mythril_only_count"] == 1

    def test_empty_sources(self, runner):
        comparison = runner.compare_with_slither([], [])
        assert comparison["total_slither"] == 0
        assert comparison["total_mythril"] == 0
        assert comparison["overlap_count"] == 0

    def test_case_insensitive_comparison(self, runner):
        slither = [{"title": "REENTRANCY", "severity": "High", "file": "a.sol"}]
        mythril = [{"title": "reentrancy", "severity": "High", "file": "a.sol"}]

        comparison = runner.compare_with_slither(slither, mythril)
        assert comparison["overlap_count"] == 1


class TestIsAddress:

    def test_valid_address(self, runner):
        assert runner._is_address("0x" + "12" * 20)

    def test_short_address(self, runner):
        assert not runner._is_address("0x1234")

    def test_non_hex(self, runner):
        assert not runner._is_address("0x" + "gg" * 20)

    def test_missing_prefix(self, runner):
        assert not runner._is_address("12" * 20)
