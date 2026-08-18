import json
import pytest
import tempfile
from pathlib import Path
from src.core.slither_runner import SlitherRunner, SEVERITY_ORDER


SAMPLE_SLITHER_JSON = json.dumps({
    "results": {
        "detectors": [
            {
                "check": "reentrancy-eth",
                "severity": "High",
                "confidence": "Medium",
                "first_markdown_element": "Reentrancy in VulnerableDEX.swap()",
                "description": "External call in swap() executes before state update.",
                "markdown": "### Recommendation\nUse checks-effects-interactions pattern.",
                "elements": [
                    {
                        "source_mapping": {
                            "filename": "contracts/VulnerableDEX.sol",
                            "lines": [112, 115]
                        }
                    }
                ]
            },
            {
                "check": "unchecked-lowlevel",
                "severity": "High",
                "confidence": "Medium",
                "first_markdown_element": "Unchecked return value in multicall()",
                "description": "Delegatecall return value is not checked.",
                "markdown": "### Recommendation\nCheck the boolean return.",
                "elements": [
                    {
                        "source_mapping": {
                            "filename": "contracts/VulnerableDEX.sol",
                            "lines": [180, 183]
                        }
                    }
                ]
            },
            {
                "check": "arbitrary-send-erc20",
                "severity": "Medium",
                "confidence": "High",
                "first_markdown_element": "Arbitrary ERC20 token send in emergencyWithdraw()",
                "description": "Anyone can call emergencyWithdraw to drain tokens.",
                "markdown": "### Recommendation\nAdd access control.",
                "elements": [
                    {
                        "source_mapping": {
                            "filename": "contracts/VulnerableDEX.sol",
                            "lines": [165]
                        }
                    }
                ]
            },
            {
                "check": "pragma-version",
                "severity": "Low",
                "confidence": "Medium",
                "first_markdown_element": "Pragma version ^0.8.19",
                "description": "Consider locking pragma to specific version.",
                "markdown": "### Recommendation\nLock pragma.",
                "elements": [
                    {
                        "source_mapping": {
                            "filename": "contracts/VulnerableDEX.sol",
                            "lines": [1]
                        }
                    }
                ]
            },
        ]
    }
})


@pytest.fixture
def runner():
    return SlitherRunner()


@pytest.fixture
def sample_output():
    return {
        "stdout": SAMPLE_SLITHER_JSON,
        "stderr": "",
        "returncode": 0,
    }


class TestParseFindings:

    def test_parses_valid_json(self, runner, sample_output):
        findings = runner.parse_findings(sample_output)
        assert len(findings) == 4

    def test_finding_structure(self, runner, sample_output):
        findings = runner.parse_findings(sample_output)
        f = findings[0]
        assert "title" in f
        assert "severity" in f
        assert "file" in f
        assert "line" in f
        assert "description" in f
        assert "recommendation" in f
        assert f["tool"] == "slither"

    def test_high_severity_detected(self, runner, sample_output):
        findings = runner.parse_findings(sample_output)
        high = [f for f in findings if f["severity"] == "High"]
        assert len(high) == 2

    def test_medium_severity_detected(self, runner, sample_output):
        findings = runner.parse_findings(sample_output)
        medium = [f for f in findings if f["severity"] == "Medium"]
        assert len(medium) == 1

    def test_low_severity_detected(self, runner, sample_output):
        findings = runner.parse_findings(sample_output)
        low = [f for f in findings if f["severity"] == "Low"]
        assert len(low) == 1

    def test_file_and_line_extracted(self, runner, sample_output):
        findings = runner.parse_findings(sample_output)
        f = findings[0]
        assert f["file"] == "contracts/VulnerableDEX.sol"
        assert f["line"] == 112

    def test_empty_output(self, runner):
        output = {"stdout": "", "stderr": "", "returncode": 0}
        findings = runner.parse_findings(output)
        assert findings == []

    def test_invalid_json(self, runner):
        output = {"stdout": "not json at all", "stderr": "", "returncode": 0}
        findings = runner.parse_findings(output)
        assert findings == []


class TestTriageFindings:

    def test_groups_by_severity(self, runner, sample_output):
        findings = runner.parse_findings(sample_output)
        triage = runner.triage_findings(findings)

        assert "by_severity" in triage
        assert "by_file" in triage
        assert "summary" in triage

        assert triage["summary"]["High"] == 2
        assert triage["summary"]["Medium"] == 1
        assert triage["summary"]["Low"] == 1

    def test_groups_by_file(self, runner, sample_output):
        findings = runner.parse_findings(sample_output)
        triage = runner.triage_findings(findings)

        assert "contracts/VulnerableDEX.sol" in triage["by_file"]
        assert len(triage["by_file"]["contracts/VulnerableDEX.sol"]) == 4

    def test_severity_ordering(self, runner, sample_output):
        findings = runner.parse_findings(sample_output)
        triage = runner.triage_findings(findings)

        ordered_keys = list(triage["by_severity"].keys())
        for i in range(len(ordered_keys) - 1):
            idx_a = SEVERITY_ORDER.index(ordered_keys[i])
            idx_b = SEVERITY_ORDER.index(ordered_keys[i + 1])
            assert idx_a < idx_b


class TestWriteReport:

    def test_creates_report_file(self, runner, sample_output, tmp_path):
        findings = runner.parse_findings(sample_output)
        output_file = tmp_path / "report.md"

        path = runner.write_report(findings, str(output_file))

        assert Path(path).exists()
        content = Path(path).read_text()
        assert "Slither Static Analysis Report" in content
        assert "High Severity" in content
        assert "Medium Severity" in content

    def test_report_contains_findings(self, runner, sample_output, tmp_path):
        findings = runner.parse_findings(sample_output)
        output_file = tmp_path / "report.md"

        runner.write_report(findings, str(output_file))
        content = output_file.read_text()

        assert "reentrancy-eth" in content
        assert "VulnerableDEX.sol" in content

    def test_creates_parent_directories(self, runner, sample_output, tmp_path):
        findings = runner.parse_findings(sample_output)
        output_file = tmp_path / "deep" / "nested" / "report.md"

        runner.write_report(findings, str(output_file))
        assert output_file.exists()

    def test_empty_findings_report(self, runner, tmp_path):
        output_file = tmp_path / "empty_report.md"
        path = runner.write_report([], str(output_file))
        content = Path(path).read_text()
        assert "**Total Findings:** 0" in content


class TestSlitherRunnerInit:

    def test_custom_binary(self):
        runner = SlitherRunner(slither_bin="/usr/local/bin/slither")
        assert runner.slither_bin == "/usr/local/bin/slither"

    def test_target_not_found(self, runner):
        with pytest.raises(FileNotFoundError):
            runner.run_analysis("/nonexistent/path.sol")
