import subprocess
import json
import sys
import argparse
from pathlib import Path


class HardhatIntegration:

    def __init__(self, project_path=".", hardhat_bin="npx hardhat"):
        self.project_path = Path(project_path)
        self.hardhat_bin = hardhat_bin
        self._artifacts_cache = {}

    def compile_contracts(self, project_path=None):
        target = project_path or str(self.project_path)
        cmd = ["npx", "hardhat", "compile"]

        try:
            result = subprocess.run(
                cmd,
                cwd=target,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Hardhat compile timed out")
        except FileNotFoundError:
            raise RuntimeError("Hardhat/npx not found. Ensure Node.js and Hardhat are installed.")

        if result.returncode != 0:
            raise RuntimeError(f"Hardhat compile failed: {result.stderr}")

        artifacts_dir = Path(target) / "artifacts" / "contracts"
        compiled = []
        if artifacts_dir.exists():
            for sol_file in artifacts_dir.rglob("*.sol"):
                for json_file in sol_file.glob("*.json"):
                    if json_file.name == f"{sol_file.stem}.json":
                        compiled.append(str(json_file))

        return {
            "success": True,
            "stdout": result.stdout,
            "artifacts": compiled,
        }

    def _get_abi(self, contract_name):
        artifacts_dir = self.project_path / "artifacts" / "contracts"
        if not artifacts_dir.exists():
            raise FileNotFoundError(f"Artifacts not found at {artifacts_dir}. Run compile first.")

        for json_file in artifacts_dir.rglob(f"{contract_name}.json"):
            data = json.loads(json_file.read_text())
            if "abi" in data:
                return data["abi"], data.get("bytecode", "")

        raise FileNotFoundError(f"Could not find artifact for {contract_name}")

    def deploy_contract(self, contract_name, network="localhost", constructor_args=None):
        try:
            from web3 import Web3
        except ImportError:
            raise ImportError("web3 is required. Install with: pip install web3")

        abi, bytecode = self._get_abi(contract_name)
        self._artifacts_cache[contract_name] = {"abi": abi, "bytecode": bytecode}

        if network == "localhost":
            w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
        else:
            w3 = Web3(Web3.HTTPProvider(network))

        if not w3.is_connected():
            raise ConnectionError(f"Cannot connect to Ethereum node at {network}")

        deployer = w3.eth.accounts[0]

        contract = w3.eth.contract(abi=abi, bytecode=bytecode)
        args = constructor_args or []

        tx_hash = contract.constructor(*args).transact({"from": deployer})
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        address = tx_receipt["contractAddress"]

        return {
            "address": address,
            "tx_hash": tx_hash.hex(),
            "block_number": tx_receipt["blockNumber"],
            "gas_used": tx_receipt["gasUsed"],
            "deployer": deployer,
            "abi": abi,
        }

    def call_function(self, contract_address, abi, function_name, args=None, from_address=None):
        try:
            from web3 import Web3
        except ImportError:
            raise ImportError("web3 is required. Install with: pip install web3")

        w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
        contract = w3.eth.contract(address=contract_address, abi=abi)

        func_args = args or []
        call_kwargs = {}
        if from_address:
            call_kwargs["from"] = from_address
        elif w3.eth.accounts:
            call_kwargs["from"] = w3.eth.accounts[0]

        func = getattr(contract.functions, function_name)
        result = func(*func_args).call(call_kwargs)

        return {
            "function": function_name,
            "result": result,
        }

    def get_storage_slot(self, contract_address, slot, provider=None):
        try:
            from web3 import Web3
        except ImportError:
            raise ImportError("web3 is required. Install with: pip install web3")

        url = provider or "http://127.0.0.1:8545"
        w3 = Web3(Web3.HTTPProvider(url))

        if isinstance(slot, int):
            slot_hex = hex(slot)
        elif isinstance(slot, str):
            if slot.startswith("0x"):
                slot_hex = slot
            else:
                slot_hex = hex(int(slot))
        else:
            slot_hex = hex(int(slot))

        if len(slot_hex) < 66:
            slot_hex = "0x" + slot_hex[2:].zfill(64)

        data = w3.eth.get_storage_at(contract_address, slot)

        return {
            "slot": slot_hex,
            "value": data.hex(),
            "value_int": int.from_bytes(data, "big"),
        }


def main():
    parser = argparse.ArgumentParser(description="Hardhat integration utilities")
    subparsers = parser.add_subparsers(dest="command")

    compile_parser = subparsers.add_parser("compile", help="Compile contracts")
    compile_parser.add_argument("--project", "-p", default=".", help="Project path")

    deploy_parser = subparsers.add_parser("deploy", help="Deploy a contract")
    deploy_parser.add_argument("contract", help="Contract name")
    deploy_parser.add_argument("--network", "-n", default="localhost", help="Network URL")
    deploy_parser.add_argument("--project", "-p", default=".", help="Project path")

    call_parser = subparsers.add_parser("call", help="Call a contract function")
    call_parser.add_argument("address", help="Contract address")
    call_parser.add_argument("--abi-file", required=True, help="Path to ABI JSON file")
    call_parser.add_argument("--function", "-f", required=True, help="Function name")
    call_parser.add_argument("--args", "-a", nargs="*", help="Function arguments")

    storage_parser = subparsers.add_parser("storage", help="Read storage slot")
    storage_parser.add_argument("address", help="Contract address")
    storage_parser.add_argument("slot", help="Storage slot (int or hex)")
    storage_parser.add_argument("--provider", default="http://127.0.0.1:8545", help="RPC provider URL")

    args = parser.parse_args()

    if args.command == "compile":
        integration = HardhatIntegration(project_path=args.project)
        result = integration.compile_contracts()
        print(f"Compiled successfully. {len(result['artifacts'])} artifacts found.")
        for a in result["artifacts"]:
            print(f"  {a}")

    elif args.command == "deploy":
        integration = HardhatIntegration(project_path=args.project)
        result = integration.deploy_contract(args.contract, network=args.network)
        print(f"Deployed {args.contract}:")
        print(f"  Address: {result['address']}")
        print(f"  TX: {result['tx_hash']}")
        print(f"  Gas: {result['gas_used']}")

    elif args.command == "call":
        with open(args.abi_file, "r") as fh:
            abi = json.load(fh)
        integration = HardhatIntegration()
        result = integration.call_function(args.address, abi, args.function, args.args)
        print(f"{args.function}() => {result['result']}")

    elif args.command == "storage":
        integration = HardhatIntegration()
        result = integration.get_storage_slot(args.address, args.slot, args.provider)
        print(f"Slot {result['slot']}: {result['value']} (int: {result['value_int']})")

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
