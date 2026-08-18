import subprocess
import json
import re
import sys
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict

SEVERITY_MAP = {
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Informational": "Informational",
    "Critical": "High",
}
SEVERITY_ORDER = ["High", "Medium", "Low", "Informational"]


class MythrilRunner:

    def __init__(self, mythril_bin="myth"):
        self.mythril_bin = mythril_bin

    def _is_address(self, target):
        if target.startswith("0x") and len(target) == 42:
            try:
                int(target, 16)
                return True
            except ValueError:
                pass
        return False

    def run_analysis(self, contract_address_or_path, timeout=300):
        cmd = [
            self.mythril_bin,
            "analyze",
            contract_address_or_path,
            "--max-depth", "12",
            "--solver-timeout", str(min(timeout, 300)),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 60,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Mythril analysis timed out after {timeout + 60}s")
        except FileNotFoundError:
            raise RuntimeError(
                f"Mythril not found at '{self.mythril_bin}'. Install with: pip install mythril"
            )

        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }

    def parse_findings(self, mythril_output):
        raw = mythril_output.get("stdout", "")
        if not raw.strip():
            return []

        findings = []

        if self._is_json_output(raw):
            return self._parse_json(raw)

        return self._parse_text(raw)

    def _is_json_output(self, raw):
        stripped = raw.strip()
        if stripped.startswith("[") or stripped.startswith("{"):
            try:
                json.loads(stripped)
                return True
            except json.JSONDecodeError:
                pass
        return False

    def _parse_json(self, raw):
        data = json.loads(raw.strip())
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("issues", data.get("findings", []))
        else:
            return []

        findings = []
        for item in items:
            severity = item.get("severity", "Medium")
            mapped = SEVERITY_MAP.get(severity, "Medium")

            findings.append({
                "title": item.get("title", item.get("description", "Unknown Finding").split("\n")[0][:100]),
                "severity": mapped,
                "file": item.get("source", {}).get("file", ""),
                "line": item.get("source", {}).get("line", 0),
                "description": item.get("description", ""),
                "recommendation": self._extract_recommendation(item),
                "tool": "mythril",
                "extras": {
                    "transaction_count": item.get("transaction_count"),
                    "gas_cost": item.get("gas_cost"),
                    "swc_id": item.get("swc_id", ""),
                },
            })

        return findings

    def _parse_text(self, raw):
        findings = []
        current = None

        for line in raw.split("\n"):
            title_match = re.match(r"^====+\s+(.+?)\s+====+$", line)
            if title_match:
                if current:
                    findings.append(current)
                current = {
                    "title": title_match.group(1).strip(),
                    "severity": "Medium",
                    "file": "",
                    "line": 0,
                    "description": "",
                    "recommendation": "",
                    "tool": "mythril",
                }
                continue

            if current is None:
                continue

            sev_match = re.search(r"Severity\s*:\s*(\w+)", line, re.IGNORECASE)
            if sev_match:
                raw_sev = sev_match.group(1)
                current["severity"] = SEVERITY_MAP.get(raw_sev, raw_sev)
                continue

            swc_match = re.search(r"SWC-\d+", line)
            if swc_match:
                current["swc_id"] = swc_match.group(0)
                continue

            file_match = re.search(r"File[:\s]+(\S+)", line)
            if file_match and not current["file"]:
                raw_file = file_match.group(1)
                if ':' in raw_file:
                    parts = raw_file.rsplit(':', 1)
                    if parts[-1].isdigit():
                        current["file"] = parts[0]
                        current["line"] = int(parts[-1])
                    else:
                        current["file"] = raw_file
                else:
                    current["file"] = raw_file
                continue

            current["description"] += line + "\n"

        if current:
            findings.append(current)

        for f in findings:
            f["description"] = f["description"].strip()
            if not f["recommendation"]:
                f["recommendation"] = self._generate_recommendation(f)

        return findings

    def _extract_recommendation(self, item):
        rec = item.get("recommendation", "")
        if rec:
            return rec[:500]
        return self._generate_recommendation(item)

    def _generate_recommendation(self, finding):
        title = finding.get("title", "").lower()
        desc = finding.get("description", "").lower()
        combined = title + " " + desc

        if "reentrancy" in combined:
            return "Implement a reentrancy guard (mutex pattern) and follow the checks-effects-interactions pattern."
        if "integer" in combined or "overflow" in combined:
            return "Use Solidity 0.8+ checked arithmetic or OpenZeppelin SafeMath. Validate bounds on all arithmetic operations."
        if "access" in combined or "unauthorized" in combined:
            return "Add appropriate access control modifiers (onlyOwner, onlyRole) to sensitive functions."
        if "unchecked" in combined or "return value" in combined:
            return "Check return values of all external calls. Use SafeERC20 for token transfers."
        return "Review the finding carefully and apply appropriate security mitigations."

    def compare_with_slither(self, slither_findings, mythril_findings):
        slither_titles = {f["title"].lower().strip() for f in slither_findings}
        mythril_titles = {f["title"].lower().strip() for f in mythril_findings}

        overlap = slither_titles & mythril_titles

        slither_only = []
        for f in slither_findings:
            if f["title"].lower().strip() not in mythril_titles:
                slither_only.append(f)

        mythril_only = []
        for f in mythril_findings:
            if f["title"].lower().strip() not in slither_titles:
                mythril_only.append(f)

        return {
            "total_slither": len(slither_findings),
            "total_mythril": len(mythril_findings),
            "overlapping_titles": list(overlap),
            "overlap_count": len(overlap),
            "slither_only_count": len(slither_only),
            "mythril_only_count": len(mythril_only),
            "slither_only": slither_only,
            "mythril_only": mythril_only,
            "detection_rate": {
                "slither_unique": len(slither_only),
                "mythril_unique": len(mythril_only),
                "shared": len(overlap),
            },
        }


def main():
    parser = argparse.ArgumentParser(description="Run Mythril symbolic analysis on Solidity contracts")
    parser.add_argument("target", help="Path to Solidity file or contract address")
    parser.add_argument("--timeout", "-t", type=int, default=300, help="Analysis timeout in seconds")
    parser.add_argument("--output", "-o", default="reports/mythril_report.md", help="Output report path")
    parser.add_argument("--compare-slither", help="Path to Slither JSON output for comparison")
    args = parser.parse_args()

    runner = MythrilRunner()
    print(f"Running Mythril on {args.target}...")

    output = runner.run_analysis(args.target, timeout=args.timeout)
    findings = runner.parse_findings(output)

    print(f"\nAnalysis complete: {len(findings)} findings")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")

    if args.compare_slither:
        with open(args.compare_slither, "r") as fh:
            slither_data = json.load(fh)
        comparison = runner.compare_with_slither(slither_data.get("findings", []), findings)
        print(f"\nComparison with Slither:")
        print(f"  Overlapping: {comparison['overlap_count']}")
        print(f"  Slither only: {comparison['slither_only_count']}")
        print(f"  Mythril only: {comparison['mythril_only_count']}")

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Mythril Symbolic Analysis Report",
        "",
        f"**Generated:** {timestamp}",
        f"**Total Findings:** {len(findings)}",
        "",
        "## Findings",
        "",
    ]

    for idx, f in enumerate(findings, 1):
        lines.append(f"### {idx}. [{f['severity']}] {f['title']}")
        lines.append("")
        if f["file"]:
            lines.append(f"- **File:** `{f['file']}`")
        if f["line"]:
            lines.append(f"- **Line:** {f['line']}")
        lines.append("")
        lines.append(f["description"])
        lines.append("")
        if f["recommendation"]:
            lines.append(f"**Recommendation:** {f['recommendation']}")
            lines.append("")
        lines.append("---")
        lines.append("")

    report_path = Path(args.output)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Report written to {report_path}")

    high_count = sum(1 for f in findings if f["severity"] == "High")
    if high_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
