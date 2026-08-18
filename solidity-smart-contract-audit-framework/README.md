# Solidity Smart Contract Audit Framework

Automated security audit pipeline for Solidity smart contracts combining static analysis, symbolic execution, and custom AST-level pattern detection.

```
┌─────────────────────┐
│  Solidity Contracts │
│  (VulnerableDEX.sol) │
└──────────┬──────────┘
           │
     ┌─────┼──────┬──────────────┐
     ▼     ▼      ▼              ▼
┌─────────┐ ┌────────┐ ┌──────────────────┐
│ Slither │ │Mythril │ │ Static Analyzer  │
│ Runner  │ │ Runner │ │ (AST Pattern)    │
└────┬────┘ └───┬────┘ └────────┬─────────┘
     │          │               │
     └──────────┼───────────────┘
                ▼
        ┌──────────────┐
        │  Aggregator  │
        │ (Dedup/Triage)│
        └──────┬───────┘
               ▼
        ┌──────────────┐
        │  Report      │
        │ (MD + JSON)  │
        └──────────────┘
```

## Features

- **Slither Integration**: Runs Slither static analysis, parses JSON output, triages by severity and file
- **Mythril Integration**: Runs Mythril symbolic execution, parses JSON and text output, cross-compares with Slither
- **Custom Static Analyzer**: Lightweight AST-based pattern detection for reentrancy, integer issues, access control, and unchecked returns
- **Audit Aggregator**: Combines findings from all tools, deduplicates, scores by priority, generates comprehensive reports
- **Hardhat Integration**: Compile contracts and deploy to local/testnet via Web3.py
- **Docker Lab**: Containerized environment with Ethereum node, Slither, and Mythril
- **CI Pipeline**: GitHub Actions workflow that runs full audit pipeline and fails on high-severity findings
- **Infrastructure as Code**: Terraform for AWS EC2 Ethereum node + S3 report storage

## Quick Start

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
python src/modules/contract_analyzer.py contracts/VulnerableDEX.sol
```

## Running Audits

```bash
python src/modules/contract_analyzer.py contracts/VulnerableDEX.sol --output reports/static.json
python src/core/slither_runner.py contracts/ --output reports/slither.md --fail-on-high
python src/core/mythril_runner.py contracts/VulnerableDEX.sol --output reports/mythril.md
python src/core/audit_aggregator.py --slither slither_findings.json --mythril mythril_findings.json --analyzer reports/static.json --output reports/combined.md
```

## Adding Contracts

1. Place `.sol` files in the `contracts/` directory
2. Run the static analyzer first for quick feedback:
   ```bash
   python src/modules/contract_analyzer.py contracts/YourContract.sol
   ```
3. Run Slither and Mythril for deeper analysis
4. Aggregate results into a combined report

## Remediation Workflow

1. Run the full audit pipeline on your contract
2. Review findings starting from the **Remediation Priority Queue** in the combined report
3. Cross-reference with `HardenedDEX.sol` for example security patterns
4. Apply fixes following the **Recommendation** field in each finding
5. Re-run the pipeline to confirm fixes
6. The combined report scores findings by severity and cross-tool confirmation, so address multi-tool-confirmed high-severity issues first

## Project Structure

```
├── contracts/              # Solidity contracts
│   ├── VulnerableDEX.sol   # Vulnerable DEX with known issues
│   └── HardenedDEX.sol     # Patched version with security annotations
├── src/
│   ├── core/               # Core audit runners
│   │   ├── slither_runner.py
│   │   ├── mythril_runner.py
│   │   └── audit_aggregator.py
│   └── modules/            # Analysis modules
│       ├── contract_analyzer.py
│       └── hardhat_integration.py
├── tests/
│   ├── unit/               # Unit tests
│   └── integration/        # Integration tests
├── lab/
│   ├── docker-compose.yml  # Docker lab environment
│   └── terraform/main.tf   # AWS infrastructure
├── scripts/
│   ├── setup.sh            # Setup script
│   └── package_project.py  # Packaging utility
├── .github/workflows/ci.yml
├── docs/setup-guide.md
├── requirements.txt
└── README.md
```

## Vulnerabilities Demonstrated

| Vulnerability | Location | Severity |
|--------------|----------|----------|
| Reentrancy in swap() | VulnerableDEX.sol:117 | High |
| Unchecked delegatecall in multicall() | VulnerableDEX.sol:181 | High |
| Missing access control on mint() | VulnerableDEX.sol:56 | High |
| Missing access control on emergencyWithdraw() | VulnerableDEX.sol:166 | High |
| Missing access control on setFeeRecipient() | VulnerableDEX.sol:171 | High |
| Integer edge case in leveraged positions | VulnerableDEX.sol:155 | High |
| Unchecked ERC20 return values | VulnerableDEX.sol:117 | Medium |

## License

MIT
