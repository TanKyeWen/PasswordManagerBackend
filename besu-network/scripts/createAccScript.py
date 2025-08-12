from web3 import Web3
import json, os

def create_account():
    w3 = Web3()
    account = w3.eth.account.create()
    os.makedirs("besu-network/accounts", exist_ok=True)
    filepath = f"besu-network/accounts/{account.address}.json"
    with open(filepath, "w") as f:
        json.dump({
            "address": account.address,
            "private_key": account.key.hex()
        }, f, indent=2)
    print(f"Address: {account.address}")
    print(f"Private key: {account.key.hex()}")
    print(f"Saved to {filepath}")
    return account.address

if __name__ == "__main__":
    create_account()
