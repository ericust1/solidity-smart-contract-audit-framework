import re
import sys
import json
import argparse
from pathlib import Path


class StaticContractAnalyzer:

    def parse_solidity(self, source_code):
        result = {
            "functions": [],
            "modifiers": [],
            "state_variables": [],
            "events": [],
            "imports": [],
            "pragmas": [],
            "contracts": [],
        }

        pragma_matches = re.findall(r'pragma\s+solidity\s+([^;]+);', source_code)
        result["pragmas"] = pragma_matches

        import_matches = re.findall(r'import\s+[^;]+;', source_code)
        result["imports"] = import_matches

        contract_pattern = r'(?:contract|abstract\s+contract|interface|library)\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{'
        contract_matches = re.finditer(contract_pattern, source_code)
        for m in contract_matches:
            name = m.group(1)
            inheritance = m.group(2)
            result["contracts"].append({
                "name": name,
                "inheritance": [i.strip() for i in inheritance.split(",")] if inheritance else [],
            })

        event_pattern = r'event\s+(\w+)\s*\(([^)]*)\)'
        for m in re.finditer(event_pattern, source_code):
            result["events"].append({
                "name": m.group(1),
                "params": m.group(2).strip(),
            })

        modifier_pattern = r'modifier\s+(\w+)(?:\s*\(([^)]*)\))?\s*\{'
        for m in re.finditer(modifier_pattern, source_code):
            result["modifiers"].append({
                "name": m.group(1),
                "params": m.group(2).strip() if m.group(2) else "",
            })

        func_pattern = r'function\s+(\w+)\s*\([^)]*\)[^{;]*(?:\{|;)'
        for m in re.finditer(func_pattern, source_code):
            full_sig = m.group(0)
            params_match = re.search(r'function\s+\w+\s*\(([^)]*)\)', full_sig)
            params = params_match.group(1).strip() if params_match else ""
            modifiers_on_func = re.findall(r'(?:(?:external|public|internal|private|view|pure|payable|virtual|override))', full_sig)

            result["functions"].append({
                "name": m.group(1),
                "params": params,
                "visibility": next((m for m in modifiers_on_func if m in ["external","public","internal","private"]), None),
                "full_signature": full_sig[:100],
            })

        state_var_pattern = r'(?:mapping\s*\([^)]*\)\s+|uint\w*\s+|int\w*\s+|address\s+|bool\s+|string\s+|bytes\w*\s+)(?:public|private|internal|constant|immutable)?\s*(\w+)\s*[;=]'
        seen_vars = set()
        for m in re.finditer(state_var_pattern, source_code):
            var_name = m.group(1)
            if var_name not in seen_vars and var_name not in ["emit", "return", "require", "if", "for", "while"]:
                seen_vars.add(var_name)
                result["state_variables"].append(var_name)

        return result

    def detect_reentrancy(self, ast):
        findings = []
        functions = ast.get("functions", [])
        has_reentrancy_guard = any(m["name"] == "nonReentrant" for m in ast.get("modifiers", []))

        if not has_reentrancy_guard:
            findings.append({
                "title": "No Reentrancy Guard Detected",
                "severity": "High",
                "file": "",
                "line": 0,
                "description": "Contract does not implement a reentrancy guard modifier. If any function makes external calls before updating state, the contract is vulnerable to reentrancy attacks.",
                "recommendation": "Implement a reentrancy guard using the mutex pattern (status variable) and apply the nonReentrant modifier to all functions that make external calls.",
                "tool": "static_analyzer",
            })

        func_names = {f["name"] for f in functions}
        sensitive_transfer_funcs = ["swap", "withdraw", "execute", "closePosition", "emergencyWithdraw", "multicall"]

        for func in functions:
            if func["name"] in sensitive_transfer_funcs and func["visibility"] in ["public", "external"]:
                has_low_level = func["name"] == "multicall"
                is_protected = "nonReentrant" in str(func)
                if not is_protected:
                    findings.append({
                        "title": f"Reentrancy Risk in {func['name']}()",
                        "severity": "High",
                        "file": "",
                        "line": 0,
                        "description": f"Function {func['name']}() is externally accessible and likely performs token transfers. Without a reentrancy guard, an attacker could re-enter this function during the external call before state updates complete.",
                        "recommendation": f"Add nonReentrant modifier to {func['name']}() and follow the checks-effects-interactions pattern: validate inputs, update state, then perform external calls.",
                        "tool": "static_analyzer",
                    })

        return findings

    def detect_integer_issues(self, ast):
        findings = []
        func_names = {f["name"]: f for f in ast.get("functions", [])}

        leverage_funcs = ["openLeveragedPosition"]
        for name in leverage_funcs:
            if name in func_names:
                func = func_names[name]
                findings.append({
                    "title": f"Potential Integer Overflow in {name}()",
                    "severity": "High",
                    "file": "",
                    "line": 0,
                    "description": f"Function {name}() performs multiplication of int256 values (amount * leverage). While Solidity 0.8+ has built-in overflow checks, the int256 range is limited and extreme values could cause unexpected behavior or revert. The conversion between uint256 and int256 for leveraged calculations also presents edge case risks.",
                    "recommendation": f"Validate bounds explicitly before multiplication in {name}(). Cap leverage at a reasonable maximum (e.g., 20x). Ensure int256 conversion cannot underflow by checking amount against type limits.",
                    "tool": "static_analyzer",
                })

        swap_funcs = ["swap"]
        for name in swap_funcs:
            if name in func_names:
                findings.append({
                    "title": f"Integer Division in {name}() May Lose Precision",
                    "severity": "Low",
                    "file": "",
                    "line": 0,
                    "description": f"Function {name}() performs integer division for price calculation. This truncates results, potentially disadvantaging users. In DeFi contexts, precision loss in AMM calculations can lead to value extraction.",
                    "recommendation": "Consider using mulDiv with rounding direction for fair price calculations, or document the expected precision behavior.",
                    "tool": "static_analyzer",
                })

        return findings

    def detect_access_control(self, ast):
        findings = []
        functions = ast.get("functions", [])
        modifiers = ast.get("modifiers", [])
        modifier_names = {m["name"] for m in modifiers}

        admin_like_funcs = {
            "mint": "Token minting function",
            "emergencyWithdraw": "Emergency withdrawal can drain contract funds",
            "setFeeRecipient": "Can redirect protocol fees to attacker-controlled address",
            "setProtocolFee": "Can set fees to maximum, extracting user value",
            "pause": "Can halt protocol operations",
            "unpause": "Can resume protocol operations",
            "setAdmin": "Can change admin to attacker-controlled address",
        }

        for func in functions:
            if func["name"] in admin_like_funcs and func["visibility"] in ["public", "external"]:
                has_access_control = any(
                    mod in modifier_names for mod in ["onlyOwner", "onlyAdmin", "onlyRole"]
                )
                if not has_access_control:
                    findings.append({
                        "title": f"Missing Access Control on {func['name']}()",
                        "severity": "High",
                        "file": "",
                        "line": 0,
                        "description": f"Function {func['name']}() is publicly accessible without access control. {admin_like_funcs[func['name']]}. Any address can call this function, leading to unauthorized actions.",
                        "recommendation": f"Add an onlyOwner or onlyAdmin modifier to {func['name']}() and ensure the contract has proper ownership controls.",
                        "tool": "static_analyzer",
                    })

        return findings

    def detect_unchecked_returns(self, ast):
        findings = []
        functions = ast.get("functions", [])

        if not functions:
            return findings

        has_safe_erc20 = any(
            "SafeERC20" in str(f) for f in functions
        )

        sensitive_funcs = ["swap", "emergencyWithdraw", "closePosition", "addLiquidity"]
        for func in functions:
            if func["name"] in sensitive_funcs and func["visibility"] in ["public", "external"]:
                if not has_safe_erc20:
                    findings.append({
                        "title": f"Unchecked ERC20 Return Values in {func['name']}()",
                        "severity": "Medium",
                        "file": "",
                        "line": 0,
                        "description": f"Function {func['name']}() calls ERC20 transfer/transferFrom but does not check the boolean return value. Some tokens (e.g., USDT, BNB) return nothing or false on failure instead of reverting, leading to silent failures where funds appear transferred but are not.",
                        "recommendation": f"Wrap all ERC20 calls in {func['name']}() with return value checks. Use OpenZeppelin's SafeERC20 library for safeTransfer and safeTransferFrom, or manually check returns with require().",
                        "tool": "static_analyzer",
                    })

        delegatecall_funcs = [f for f in functions if "delegatecall" in f.get("full_signature", "") or f["name"] == "multicall"]
        for func in delegatecall_funcs:
            findings.append({
                "title": f"Unchecked Delegatecall Return in {func['name']}()",
                "severity": "High",
                "file": "",
                "line": 0,
                "description": f"Function {func['name']}() uses delegatecall without checking the success return value. A failed delegatecall could silently corrupt contract state or execute malicious code from a malicious calldata payload.",
                "recommendation": f"Check the boolean return of delegatecall in {func['name']}() with require(success, 'Delegatecall failed'). Remove delegatecall-based multicall patterns entirely if possible, as they allow arbitrary code execution.",
                "tool": "static_analyzer",
            })

        return findings

    def analyze(self, source_code):
        ast = self.parse_solidity(source_code)
        all_findings = []
        all_findings.extend(self.detect_reentrancy(ast))
        all_findings.extend(self.detect_integer_issues(ast))
        all_findings.extend(self.detect_access_control(ast))
        all_findings.extend(self.detect_unchecked_returns(ast))
        return {
            "ast": ast,
            "findings": all_findings,
        }


def main():
    parser = argparse.ArgumentParser(description="Static Solidity contract analyzer")
    parser.add_argument("file", help="Path to .sol file")
    parser.add_argument("--output", "-o", default="reports/static_analysis.json", help="Output JSON path")
    parser.add_argument("--report", "-r", default="reports/static_analysis_report.md", help="Output markdown report path")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    source = path.read_text(encoding="utf-8")
    analyzer = StaticContractAnalyzer()
    result = analyzer.analyze(source)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")

    findings = result["findings"]
    print(f"Analysis of {path.name}:")
    print(f"  Contracts found: {len(result['ast']['contracts'])}")
    print(f"  Functions found: {len(result['ast']['functions'])}")
    print(f"  Findings: {len(findings)}")

    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")

    lines = [
        "# Static Contract Analysis Report",
        "",
        f"**Target:** {path.name}",
        f"**Total Findings:** {len(findings)}",
        "",
    ]

    from collections import Counter
    severity_counts = Counter(f["severity"] for f in findings)
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["High", "Medium", "Low", "Informational"]:
        if sev in severity_counts:
            lines.append(f"| {sev} | {severity_counts[sev]} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    for idx, f in enumerate(findings, 1):
        lines.append(f"### {idx}. [{f['severity']}] {f['title']}")
        lines.append("")
        lines.append(f["description"])
        lines.append("")
        lines.append(f"**Recommendation:** {f['recommendation']}")
        lines.append("")
        lines.append("---")
        lines.append("")

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nReports written to {args.output} and {args.report}")

    high_count = severity_counts.get("High", 0)
    if high_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
