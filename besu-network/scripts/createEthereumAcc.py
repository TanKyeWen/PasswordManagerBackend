from web3 import Web3
import os
import json

def create_ethereum_account():
    """Create a new Ethereum account and save the details"""
    
    # Create a new account
    w3 = Web3()
    account = w3.eth.account.create()
    
    print("=== NEW ETHEREUM ACCOUNT CREATED ===")
    print(f"Address: {account.address}")
    print(f"Private Key: {account.privateKey.hex()}")
    print("=====================================")
    print("\n⚠️  IMPORTANT SECURITY NOTICE:")
    print("- NEVER share your private key with anyone!")
    print("- Store your private key securely!")
    print("- The private key gives full control over your account!")
    print("=====================================\n")
    
    # Save account details to file
    account_data = {
        "address": account.address,
        "private_key": account.privateKey.hex()
    }
    
    # Create accounts directory if it doesn't exist
    os.makedirs("besu-network/accounts", exist_ok=True)
    
    # Save to file
    filename = f"besu-network/accounts/account_{account.address.lower()}.json"
    with open(filename, 'w') as f:
        json.dump(account_data, f, indent=2)
    
    print(f"Account details saved to: {filename}")
    print(f"Address for mining setup: {account.address}")
    
    return account.address, account.privateKey.hex()

if __name__ == "__main__":
    create_ethereum_account()