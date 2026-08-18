import subprocess
import json
import sys
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict

SEVERITY_ORDER = ["High", "Medium", "Low", "Informational", "Optimization"]


class SlitherRunner:

    def __init__(self, slither_bin="slither"):
        self.slither_bin = slither_bin

    def run_analysis(self, target_path, filters=None):
        target = Path(target_path)
        if not target.exists():
            raise FileNotFoundError(f"Target not found: {target_path}")

        cmd = [
            self.slither_bin,
            str(target),
            "--json", "-",
            "--disable-color",
        ]

        if filters:
            for f in filters:
                cmd.extend(["--filter", f])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Slither analysis timed out after 300s")
        except FileNotFoundError:
            raise RuntimeError(
                f"Slither not found at '{self.slither_bin}'. Install with: pip install slither-analyzer"
            )

        if result.returncode != 0 and not result.stdout.strip():
            raise RuntimeError(f"Slither failed: {result.stderr}")

        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }

    def parse_findings(self, slither_output):
        raw = slither_output.get("stdout", "")
        if not raw.strip():
            return []

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings = []
        detector_results = data.get("results", {}).get("detectors", [])

        for detector in detector_results:
            first_elem = detector.get("first_markdown_element", "")
            description = detector.get("description", "")
            if not description and first_elem:
                description = first_elem
            elif first_elem:
                description = first_elem + "\n" + description

            severity = detector.get("severity", "Unknown")
            if severity not in SEVERITY_ORDER:
                severity = "Informational"

            finding = {
                "title": detector.get("check", "Unknown Finding"),
                "severity": severity,
                "confidence": detector.get("confidence", "Medium"),
                "file": "",
                "line": 0,
                "description": description.strip(),
                "recommendation": self._extract_recommendation(detector),
                "tool": "slither",
            }

            elements = detector.get("elements", [])
            if elements:
                first = elements[0]
                source_mapping = first.get("source_mapping", {})
                finding["file"] = source_mapping.get("filename", "")
                finding["line"] = source_mapping.get("lines", [0])[0] if source_mapping.get("lines") else 0

            findings.append(finding)

        return findings

    def _extract_recommendation(self, detector):
        md = detector.get("markdown", "")
        if "###" in md:
            sections = md.split("###")
            for section in sections:
                if "recommend" in section.lower():
                    lines = section.strip().split("\n")
                    return " ".join(lines[1:]).strip()[:500]
        return "Review the finding and apply appropriate security measures."

    def triage_findings(self, findings):
        by_severity = defaultdict(list)
        by_file = defaultdict(list)

        for f in findings:
            by_severity[f["severity"]].append(f)
            file_key = f["file"] or "unknown"
            by_file[file_key].append(f)

        ordered = {}
        for sev in SEVERITY_ORDER:
            if sev in by_severity:
                ordered[sev] = sorted(
                    by_severity[sev],
                    key=lambda x: (x["file"], x["line"]),
                )

        return {
            "by_severity": ordered,
            "by_file": dict(by_file),
            "summary": {sev: len(by_severity[sev]) for sev in ordered},
        }

    def write_report(self, findings, output_path):
        triage = self.triage_findings(findings)
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        lines = [
            "# Slither Static Analysis Report",
            "",
            f"**Generated:** {timestamp}",
            f"**Total Findings:** {len(findings)}",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]

        for sev in SEVERITY_ORDER:
            count = triage["summary"].get(sev, 0)
            if count > 0:
                lines.append(f"| {sev} | {count} |")

        lines.append("")

        for sev in SEVERITY_ORDER:
            items = triage["by_severity"].get(sev, [])
            if not items:
                continue
            lines.append(f"## {sev} Severity")
            lines.append("")
            for idx, f in enumerate(items, 1):
                lines.append(f"### {idx}. {f['title']}")
                lines.append("")
                lines.append(f"- **File:** `{f['file']}`")
                lines.append(f"- **Line:** {f['line']}")
                lines.append(f"- **Confidence:** {f['confidence']}")
                lines.append("")
                lines.append(f["description"])
                lines.append("")
                if f["recommendation"]:
                    lines.append(f"**Recommendation:** {f['recommendation']}")
                    lines.append("")
                lines.append("---")
                lines.append("")

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("\n".join(lines), encoding="utf-8")
        return str(output)


def main():
    parser = argparse.ArgumentParser(description="Run Slither analysis on Solidity contracts")
    parser.add_argument("target", help="Path to Solidity file or project directory")
    parser.add_argument("--output", "-o", default="reports/slither_report.md", help="Output report path")
    parser.add_argument("--filter", "-f", action="append", help="Filter detectors (repeatable)")
    parser.add_argument("--fail-on-high", action="store_true", help="Exit with code 1 if high-severity findings")
    args = parser.parse_args()

    runner = SlitherRunner()
    print(f"Running Slither on {args.target}...")

    output = runner.run_analysis(args.target, filters=args.filter)
    findings = runner.parse_findings(output)
    report_path = runner.write_report(findings, args.output)

    triage = runner.triage_findings(findings)
    print(f"\nAnalysis complete: {len(findings)} findings")
    for sev, count in triage["summary"].items():
        print(f"  {sev}: {count}")
    print(f"Report written to {report_path}")

    if args.fail_on_high and triage["summary"].get("High", 0) > 0:
        print("\nHigh-severity findings detected, exiting with code 1")
        sys.exit(1)


if __name__ == "__main__":
    main()
