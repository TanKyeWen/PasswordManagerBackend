# ============ bcc.py ============
from web3 import Web3
import json
import os
import logging

logger = logging.getLogger(__name__)

# Configuration
BESU_URL = "http://localhost:8545"
CHAIN_ID = 1337

# Initialize Web3
w3 = Web3(Web3.HTTPProvider(BESU_URL))

def load_account(accounts_dir="besu-network/accounts"):
    """
    Load account from file and return the values
    
    Args:
        accounts_dir (str): Directory containing account files
        
    Returns:
        tuple: (account_address, private_key) or (None, None) if failed
    """
    if not os.path.exists(accounts_dir):
        logger.error("No accounts found. Please create an account first.")
        return None, None
    
    # Find the first account file
    for filename in os.listdir(accounts_dir):
        if filename.endswith('.json'):
            try:
                with open(os.path.join(accounts_dir, filename), 'r') as f:
                    account_data = json.load(f)
                    account_address = account_data['address']
                    private_key = account_data['private_key']
                    logger.info(f"Account loaded: {account_address}")
                    return account_address, private_key
            except Exception as e:
                logger.error(f"Error loading account from {filename}: {e}")
                continue
    
    logger.error("No valid account found")
    return None, None

def load_contract(contract_file="besu-network/contracts/ActivityLogContract.json"):
    """
    Load deployed contract and return the contract object
    
    Args:
        contract_file (str): Path to contract JSON file
        
    Returns:
        Contract object or None if failed
    """
    if not os.path.exists(contract_file):
        logger.error("Contract not found. Please deploy the contract first.")
        return None
    
    try:
        with open(contract_file, 'r') as f:
            contract_data = json.load(f)
        
        contract = w3.eth.contract(
            address=contract_data['address'],
            abi=contract_data['abi']
        )
        
        logger.info(f"Contract loaded: {contract_data['address']}")
        return contract
        
    except Exception as e:
        logger.error(f"Error loading contract: {e}")
        return None

def get_web3_instance():
    """
    Get the Web3 instance
    
    Returns:
        Web3: The Web3 instance
    """
    return w3

def get_chain_config():
    """
    Get blockchain configuration
    
    Returns:
        dict: Configuration settings
    """
    return {
        'besu_url': BESU_URL,
        'chain_id': CHAIN_ID
    }

def validate_connection():
    """
    Validate blockchain connection
    
    Returns:
        bool: True if connected, False otherwise
    """
    try:
        return w3.is_connected()
    except Exception as e:
        logger.error(f"Connection validation failed: {e}")
        return False

def get_account_balance(account_address):
    """
    Get account balance
    
    Args:
        account_address (str): Ethereum address
        
    Returns:
        float: Balance in ETH, 0 if error
    """
    try:
        if not account_address:
            return 0
        
        balance = w3.eth.get_balance(account_address)
        return float(w3.from_wei(balance, 'ether'))
        
    except Exception as e:
        logger.error(f"Error getting balance for {account_address}: {e}")
        return 0

def create_account_file(address, private_key, accounts_dir="besu-network/accounts"):
    """
    Create account file with given credentials
    
    Args:
        address (str): Account address
        private_key (str): Private key
        accounts_dir (str): Directory to save account file
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        os.makedirs(accounts_dir, exist_ok=True)
        
        account_data = {
            "address": address,
            "private_key": private_key
        }
        
        account_file = os.path.join(accounts_dir, "account.json")
        with open(account_file, 'w') as f:
            json.dump(account_data, f, indent=2)
        
        logger.info(f"Account file created: {account_file}")
        return True
        
    except Exception as e:
        logger.error(f"Error creating account file: {e}")
        return False

def sign_transaction(transaction, private_key):
    """
    Sign a transaction with private key
    
    Args:
        transaction: Transaction dictionary
        private_key (str): Private key to sign with
        
    Returns:
        Signed transaction or None if failed
    """
    try:
        return w3.eth.account.sign_transaction(transaction, private_key)
    except Exception as e:
        logger.error(f"Error signing transaction: {e}")
        return None

def send_signed_transaction(signed_txn):
    """
    Send a signed transaction
    
    Args:
        signed_txn: Signed transaction
        
    Returns:
        Transaction hash or None if failed
    """
    try:
        return w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    except Exception as e:
        logger.error(f"Error sending transaction: {e}")
        return None

def wait_for_receipt(tx_hash, timeout=300):
    """
    Wait for transaction receipt
    
    Args:
        tx_hash: Transaction hash
        timeout (int): Timeout in seconds
        
    Returns:
        Transaction receipt or None if failed
    """
    try:
        return w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
    except Exception as e:
        logger.error(f"Error waiting for receipt: {e}")
        return None