# Setup Guide

## Prerequisites

- **Node.js** 18+ (LTS recommended)
- **Python** 3.10+
- **solc** 0.8.x (0.8.19+ for project contracts)

## Installation

### Node.js and npm

```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### Solidity Compiler

```bash
sudo add-apt-repository ppa:ethereum/ethereum
sudo apt-get update
sudo apt-get install -y solc
solc --version
```

Or via npm:

```bash
npm install -g solc@0.8.19
```

### Hardhat

```bash
npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
npx hardhat init
```

### Slither

```bash
pip install slither-analyzer
slither --version
```

### Mythril

```bash
pip install mythril
myth version
```

### Python Dependencies

```bash
pip install -r requirements.txt
```

## Compiling Contracts

```bash
npx hardhat compile
```

Artifacts are generated in `artifacts/contracts/`.

## Running Audit Scripts

### Static Contract Analyzer

Lightweight Solidity AST analysis that runs without external tools:

```bash
python src/modules/contract_analyzer.py contracts/VulnerableDEX.sol --output reports/static.json --report reports/static.md
```

### Slither Runner

```bash
python src/core/slither_runner.py contracts/ --output reports/slither_report.md
```

To fail CI on high-severity findings:

```bash
python src/core/slither_runner.py contracts/ --output reports/slither_report.md --fail-on-high
```

### Mythril Runner

```bash
python src/core/mythril_runner.py contracts/VulnerableDEX.sol --timeout 300 --output reports/mythril_report.md
```

### Combined Report

First, save individual tool outputs as JSON, then aggregate:

```bash
python src/core/slither_runner.py contracts/ --output reports/slither_report.md
python src/core/mythril_runner.py contracts/VulnerableDEX.sol --output reports/mythril_report.md
python src/core/audit_aggregator.py --slither reports/slither_findings.json --mythril reports/mythril_findings.json --output reports/combined_audit_report.md
```

### Running Tests

```bash
python -m pytest tests/ -v
```

### Docker Lab Environment

```bash
cd lab/docker
docker-compose up -d
```

### Terraform Infrastructure

```bash
cd lab/terraform
terraform init
terraform plan
terraform apply
```
