from web3 import Web3
import uuid
from datetime import datetime
import os
from dotenv import load_dotenv
from typing import List, Dict, Any
import init_audit_trail as init

load_dotenv()  # Load environment variables from .env file

# Blockchain Configuration
HARDHAT_URL = os.getenv("HARDHAT_URL", "http://127.0.0.1:8545")
CHAIN_ID = int(os.getenv("CHAIN_ID", "31337"))
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")

# Updated Contract ABI for new structure
CONTRACT_ABI = [
    {
        "inputs": [],
        "stateMutability": "nonpayable",
        "type": "constructor"
    },
    {
        "inputs": [
            {"internalType": "string", "name": "_logID", "type": "string"},
            {"internalType": "string", "name": "_userID", "type": "string"},
            {"internalType": "string", "name": "_credID", "type": "string"},
            {"internalType": "string", "name": "_activityName", "type": "string"},
            {"internalType": "string", "name": "_date", "type": "string"},
            {"internalType": "string", "name": "_ip", "type": "string"},
            {"internalType": "string", "name": "_timestamp", "type": "string"}
        ],
        "name": "addAuditEntry",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "_userID", "type": "string"}],
        "name": "getUserAuditEntries",
        "outputs": [
            {
                "components": [
                    {"internalType": "string", "name": "logID", "type": "string"},
                    {"internalType": "string", "name": "userID", "type": "string"},
                    {"internalType": "string", "name": "credID", "type": "string"},
                    {"internalType": "string", "name": "activityName", "type": "string"},
                    {"internalType": "string", "name": "date", "type": "string"},
                    {"internalType": "string", "name": "ip", "type": "string"},
                    {"internalType": "string", "name": "timestamp", "type": "string"}
                ],
                "internalType": "struct AuditTrail.AuditEntry[]",
                "name": "",
                "type": "tuple[]"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
]

class BlockchainService:
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(HARDHAT_URL))
        
        # Check connection
        if not self.w3.is_connected():
            raise Exception("Failed to connect to Hardhat network")
        
        # Get default account (first account from Hardhat)
        self.account = self.w3.eth.accounts[0]
        self.w3.eth.default_account = self.account
        
        # Initialize contract
        if CONTRACT_ADDRESS != "YOUR_CONTRACT_ADDRESS_HERE":
            self.contract = self.w3.eth.contract(
                address=CONTRACT_ADDRESS,
                abi=CONTRACT_ABI
            )
        else:
            self.contract = None
            print("Warning: Contract address not set!")

    def generate_log_id(self):
        """Generate a unique log ID"""
        return f"log_{uuid.uuid4().hex[:4]}"

    def get_current_timestamp(self):
        """Get current timestamp as string"""
        return str(datetime.now().time())

    def get_current_date(self):
        """Get current date as string (YYYY-MM-DD)"""
        return datetime.now().strftime("%Y-%m-%d")

    def add_audit_entry(self, user_id, cred_id, activity_name, ip_address=None, log_id=None, date=None, timestamp=None):
        """Add a new audit entry to the blockchain"""
        if not self.contract:
            raise Exception("Contract not initialized")
        
        # Generate defaults if not provided
        if not log_id:
            log_id = self.generate_log_id()
        if not date:
            date = self.get_current_date()
        if not timestamp:
            timestamp = self.get_current_timestamp()
        if not ip_address:
            ip_address = "unknown"
        if not cred_id:
            cred_id = ""
        
        # Send transaction
        tx_hash = self.contract.functions.addAuditEntry(
            log_id, user_id, cred_id, activity_name, date, ip_address, timestamp
        ).transact({'from': self.account})
        
        # Wait for transaction receipt
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        init.add_audit_entry(
            log_id, user_id, cred_id, activity_name, date, ip_address, timestamp
        )
        
        return {
            'success': True,
            'log_id': log_id,
            'transaction_hash': tx_hash.hex(),
            'block_number': receipt.blockNumber,
            'user_id': user_id,
            'activity_name': activity_name,
            'date': date,
            'timestamp': timestamp
        }

    def get_user_audit_entries(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all audit entries for a specific user"""
        if not self.contract:
            raise Exception("Contract not initialized")
        
        try:
            entries = self.contract.functions.getUserAuditEntries(user_id).call()
            result = []
            
            for (logID, userID, credID, activityName, date, ip, timestamp) in entries:
                result.append({
                    "log_id": logID,
                    "user_id": userID,
                    "cred_id": credID,
                    "activity_name": activityName,
                    "date": date,
                    "ip": ip,
                    "timestamp": timestamp,
                })
            return result
        
        except Exception as e:
            print(f"Error getting user audit entries: {str(e)}")
            return []

    def is_connected(self):
        """Check if connected to blockchain"""
        return self.w3.is_connected()

    def get_latest_block(self):
        """Get latest block number"""
        try:
            return self.w3.eth.block_number if self.is_connected() else None
        except Exception as e:
            print(f"Error getting latest block: {str(e)}")
            return None