import json
import sys
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict

SEVERITY_ORDER = ["High", "Medium", "Low", "Informational", "Optimization"]
SEVERITY_SCORES = {"High": 4, "Medium": 3, "Low": 2, "Informational": 1, "Optimization": 0}


class AuditAggregator:

    def __init__(self):
        self.sources = {}

    def add_source(self, name, findings):
        if not isinstance(findings, list):
            raise TypeError("Findings must be a list")
        self.sources[name] = findings

    def get_all_findings(self):
        all_findings = []
        for source, findings in self.sources.items():
            for f in findings:
                entry = dict(f)
                entry["source"] = source
                all_findings.append(entry)
        return all_findings

    def get_by_severity(self, severity):
        all_f = self.get_all_findings()
        return [f for f in all_f if f.get("severity", "").lower() == severity.lower()]

    def get_unique_findings(self):
        all_f = self.get_all_findings()
        seen = set()
        unique = []
        for f in all_f:
            title = f.get("title", "").strip().lower()
            file_key = f.get("file", "").strip()
            dedup_key = f"{title}|{file_key}"
            if dedup_key not in seen:
                seen.add(dedup_key)
                unique.append(f)
        return unique

    def _compute_priority_score(self, finding):
        sev_score = SEVERITY_SCORES.get(finding.get("severity", "Informational"), 1)
        tool_count = 1
        sources = finding.get("matched_sources", [])
        if sources:
            tool_count = len(sources)
        return sev_score * 10 + tool_count

    def generate_combined_report(self, output_path):
        all_findings = self.get_all_findings()
        unique_findings = self.get_unique_findings()
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        enriched = []
        for uf in unique_findings:
            title = uf.get("title", "").strip().lower()
            file_key = uf.get("file", "").strip()
            matched_sources = []
            all_descriptions = []

            for source, findings in self.sources.items():
                for f in findings:
                    if f.get("title", "").strip().lower() == title and f.get("file", "").strip() == file_key:
                        matched_sources.append(source)
                        if f.get("description"):
                            all_descriptions.append(f.get("description", ""))

            entry = dict(uf)
            entry["matched_sources"] = matched_sources
            entry["detection_tools"] = len(matched_sources)
            entry["priority_score"] = self._compute_priority_score(entry)

            combined_desc = "\n\n".join(all_descriptions) if all_descriptions else uf.get("description", "")
            entry["description"] = combined_desc

            if not entry.get("recommendation"):
                for f in all_findings:
                    if f.get("title", "").strip().lower() == title and f.get("recommendation"):
                        entry["recommendation"] = f["recommendation"]
                        break

            enriched.append(entry)

        enriched.sort(key=lambda x: x["priority_score"], reverse=True)

        by_severity = defaultdict(list)
        for f in enriched:
            sev = f.get("severity", "Informational")
            by_severity[sev].append(f)

        high_count = len(by_severity.get("High", []))
        medium_count = len(by_severity.get("Medium", []))
        low_count = len(by_severity.get("Low", []))
        info_count = len(by_severity.get("Informational", []))

        tool_matrix = {}
        for source in self.sources:
            tool_matrix[source] = {sev: 0 for sev in SEVERITY_ORDER}
            for f in self.sources[source]:
                sev = f.get("severity", "Informational")
                if sev in tool_matrix[source]:
                    tool_matrix[source][sev] += 1

        lines = [
            "# Combined Smart Contract Audit Report",
            "",
            f"**Generated:** {timestamp}",
            f"**Analysis Sources:** {', '.join(self.sources.keys())}",
            f"**Total Raw Findings:** {len(all_findings)}",
            f"**Unique Findings (Deduplicated):** {len(unique_findings)}",
            "",
        ]

        lines.append("## Executive Summary")
        lines.append("")

        if high_count > 0:
            lines.append(f"> **CRITICAL:** {high_count} high-severity issue{'s' if high_count != 1 else ''} detected. Immediate remediation required before deployment.")
        elif medium_count > 0:
            lines.append(f"> **WARNING:** {medium_count} medium-severity issue{'s' if medium_count != 1 else ''} detected. Review and address before mainnet deployment.")
        else:
            lines.append("> No critical or high-severity issues detected. Contract passes baseline security assessment.")

        lines.append("")
        lines.append("### Findings Overview")
        lines.append("")
        lines.append("| Severity | Unique Findings |")
        lines.append("|----------|----------------:|")
        for sev in SEVERITY_ORDER:
            count = len(by_severity.get(sev, []))
            if count > 0:
                lines.append(f"| {sev} | {count} |")
        lines.append("")

        lines.append("### Tool Comparison Matrix")
        lines.append("")
        header = "| Tool | " + " | ".join(SEVERITY_ORDER) + " | Total |"
        sep = "|------|" + "|".join(["------" for _ in SEVERITY_ORDER]) + "|-------|"
        lines.append(header)
        lines.append(sep)

        for tool, counts in tool_matrix.items():
            total = sum(counts.values())
            row = f"| {tool} | " + " | ".join(str(counts[s]) for s in SEVERITY_ORDER) + f" | {total} |"
            lines.append(row)
        lines.append("")

        lines.append("## Remediation Priority Queue")
        lines.append("")
        lines.append("Findings ordered by severity and cross-tool confirmation:")
        lines.append("")
        lines.append("| # | Severity | Finding | Tools | File |")
        lines.append("|---|----------|---------|-------|------|")

        for idx, f in enumerate(enriched, 1):
            title_short = f["title"][:70]
            tools_str = ", ".join(f.get("matched_sources", [f.get("source", "?")]))
            file_short = f.get("file", "unknown")[:40]
            lines.append(f"| {idx} | {f['severity']} | {title_short} | {tools_str} | `{file_short}` |")

        lines.append("")

        lines.append("## Detailed Findings")
        lines.append("")

        for sev in SEVERITY_ORDER:
            items = by_severity.get(sev, [])
            if not items:
                continue
            lines.append(f"### {sev} Severity")
            lines.append("")
            for idx, f in enumerate(items, 1):
                lines.append(f"#### {idx}. {f['title']}")
                lines.append("")
                lines.append(f"- **Severity:** {f['severity']}")
                lines.append(f"- **File:** `{f.get('file', 'N/A')}`")
                if f.get("line"):
                    lines.append(f"- **Line:** {f['line']}")
                detected_by = f.get("matched_sources", [f.get("source", "?")])
                lines.append(f"- **Detected by:** {', '.join(detected_by)}")
                lines.append(f"- **Priority Score:** {f.get('priority_score', 'N/A')}")
                lines.append("")
                if f.get("description"):
                    desc_lines = f["description"].split("\n")[:10]
                    lines.extend(desc_lines)
                    lines.append("")
                if f.get("recommendation"):
                    lines.append(f"**Recommendation:** {f['recommendation']}")
                    lines.append("")
                lines.append("---")
                lines.append("")

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("\n".join(lines), encoding="utf-8")

        report_data = {
            "timestamp": timestamp,
            "sources": list(self.sources.keys()),
            "total_raw": len(all_findings),
            "total_unique": len(unique_findings),
            "summary": {
                "High": high_count,
                "Medium": medium_count,
                "Low": low_count,
                "Informational": info_count,
            },
            "tool_matrix": tool_matrix,
            "findings": enriched,
        }

        json_path = output.with_suffix(".json")
        json_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")

        return {
            "report_path": str(output),
            "json_path": str(json_path),
            "high_count": high_count,
            "medium_count": medium_count,
        }


def main():
    parser = argparse.ArgumentParser(description="Aggregate findings from multiple audit tools")
    parser.add_argument("--slither", help="Path to Slither findings JSON")
    parser.add_argument("--mythril", help="Path to Mythril findings JSON")
    parser.add_argument("--analyzer", help="Path to custom analyzer findings JSON")
    parser.add_argument("--output", "-o", default="reports/combined_audit_report.md", help="Output report path")
    args = parser.parse_args()

    aggregator = AuditAggregator()

    for name, path in [("slither", args.slither), ("mythril", args.mythril), ("custom_analyzer", args.analyzer)]:
        if path:
            with open(path, "r") as fh:
                findings = json.load(fh)
            if not isinstance(findings, list):
                findings = findings.get("findings", [])
            aggregator.add_source(name, findings)
            print(f"Loaded {len(findings)} findings from {name}")

    if not aggregator.sources:
        parser.error("At least one findings source is required")

    result = aggregator.generate_combined_report(args.output)

    print(f"\nCombined report generated:")
    print(f"  Markdown: {result['report_path']}")
    print(f"  JSON: {result['json_path']}")
    print(f"  High severity: {result['high_count']}")
    print(f"  Medium severity: {result['medium_count']}")

    if result["high_count"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
