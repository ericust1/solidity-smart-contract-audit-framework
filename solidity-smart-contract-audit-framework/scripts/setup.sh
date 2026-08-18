#!/usr/bin/env bash
set -euo pipefail

echo "=== Solidity Audit Framework Setup ==="
echo ""

if command -v node &> /dev/null; then
    echo "[OK] Node.js $(node --version)"
else
    echo "[INSTALL] Node.js 18..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

if command -v npm &> /dev/null; then
    echo "[OK] npm $(npm --version)"
else
    echo "[ERROR] npm not found"; exit 1
fi

if command -v solc &> /dev/null; then
    echo "[OK] solc $(solc --version | head -1)"
else
    echo "[INSTALL] solc..."
    sudo add-apt-repository -y ppa:ethereum/ethereum 2>/dev/null || true
    sudo apt-get update -qq
    sudo apt-get install -y solc
fi

if [ -f "node_modules/hardhat/package.json" ]; then
    echo "[OK] Hardhat"
else
    echo "[INSTALL] Hardhat..."
    npm init -y 2>/dev/null || true
    npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
fi

if command -v slither &> /dev/null; then
    echo "[OK] Slither"
else
    echo "[INSTALL] Slither..."
    pip install slither-analyzer
fi

if command -v myth &> /dev/null; then
    echo "[OK] Mythril"
else
    echo "[INSTALL] Mythril..."
    pip install mythril
fi

echo "[INSTALL] Python dependencies..."
pip install -r requirements.txt 2>/dev/null || pip install web3 pytest

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Run tests:           python -m pytest tests/ -v"
echo "  2. Analyze a contract:  python src/modules/contract_analyzer.py contracts/VulnerableDEX.sol"
echo "  3. Run Slither:         python src/core/slither_runner.py contracts/"
echo "  4. Run Mythril:         python src/core/mythril_runner.py contracts/VulnerableDEX.sol"
