from flask import Flask, request, jsonify
from web3 import Web3
import json
import hashlib
from datetime import datetime
import os
from functools import wraps
import uuid

app = Flask(__name__)

# Blockchain Configuration
HARDHAT_URL = "http://127.0.0.1:8545"
CONTRACT_ADDRESS = "YOUR_CONTRACT_ADDRESS_HERE"  # Replace after deployment

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
        "inputs": [{"internalType": "string", "name": "_logID", "type": "string"}],
        "name": "getAuditEntry",
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
                "internalType": "struct AuditTrail.AuditEntry",
                "name": "",
                "type": "tuple"
            }
        ],
        "stateMutability": "view",
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
    {
        "inputs": [{"internalType": "string", "name": "_userID", "type": "string"}],
        "name": "getUserLogIDs",
        "outputs": [{"internalType": "string[]", "name": "", "type": "string[]"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getTotalAuditEntries",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "_logID", "type": "string"}],
        "name": "auditEntryExists",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "_activityName", "type": "string"}],
        "name": "getAuditEntriesByActivity",
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
    }
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
        return f"log_{uuid.uuid4().hex[:12]}"
    
    def get_current_timestamp(self):
        """Get current timestamp as string"""
        return str(int(datetime.now().timestamp()))
    
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
    
    def get_audit_entry(self, log_id):
        """Get a specific audit entry by LogID"""
        if not self.contract:
            raise Exception("Contract not initialized")
        
        try:
            entry = self.contract.functions.getAuditEntry(log_id).call()
            return {
                'log_id': entry[0],
                'user_id': entry[1],
                'cred_id': entry[2],
                'activity_name': entry[3],
                'date': entry[4],
                'ip': entry[5],
                'timestamp': entry[6]
            }
        except Exception as e:
            return None
    
    def get_user_audit_entries(self, user_id):
        """Get all audit entries for a specific user"""
        if not self.contract:
            raise Exception("Contract not initialized")
        
        try:
            entries = self.contract.functions.getUserAuditEntries(user_id).call()
            result = []
            
            for entry in entries:
                result.append({
                    'log_id': entry[0],
                    'user_id': entry[1],
                    'cred_id': entry[2],
                    'activity_name': entry[3],
                    'date': entry[4],
                    'ip': entry[5],
                    'timestamp': entry[6]
                })
            
            return result
        except Exception as e:
            print(f"Error getting user audit entries: {str(e)}")
            return []
    
    def get_user_log_ids(self, user_id):
        """Get all log IDs for a specific user"""
        if not self.contract:
            raise Exception("Contract not initialized")
        
        try:
            log_ids = self.contract.functions.getUserLogIDs(user_id).call()
            return log_ids
        except Exception as e:
            print(f"Error getting user log IDs: {str(e)}")
            return []
    
    def audit_entry_exists(self, log_id):
        """Check if audit entry exists"""
        if not self.contract:
            raise Exception("Contract not initialized")
        
        try:
            return self.contract.functions.auditEntryExists(log_id).call()
        except Exception as e:
            return False
    
    def get_audit_entries_by_activity(self, activity_name):
        """Get all audit entries for a specific activity"""
        if not self.contract:
            raise Exception("Contract not initialized")
        
        try:
            entries = self.contract.functions.getAuditEntriesByActivity(activity_name).call()
            result = []
            
            for entry in entries:
                result.append({
                    'log_id': entry[0],
                    'user_id': entry[1],
                    'cred_id': entry[2],
                    'activity_name': entry[3],
                    'date': entry[4],
                    'ip': entry[5],
                    'timestamp': entry[6]
                })
            
            return result
        except Exception as e:
            print(f"Error getting audit entries by activity: {str(e)}")
            return []

# Initialize blockchain service
blockchain = BlockchainService()

def require_auth(f):
    """Simple auth decorator (implement your actual auth logic)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Implement your authentication logic here
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'No authorization header'}), 401
        
        # For demo purposes, we'll accept any token starting with 'Bearer '
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Invalid authorization format'}), 401
        
        # In production, verify the token properly
        request.user_id = 'demo_user'  # Set from decoded token
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/audit-trail', methods=['POST'])
@require_auth
def create_activity_log():
    """Create a new audit trail entry"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['user_id', 'activity_name']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Extract client IP
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        
        # Add to blockchain
        result = blockchain.add_audit_entry(
            user_id=data['user_id'],
            cred_id=data.get('cred_id', ''),
            activity_name=data['activity_name'],
            ip_address=client_ip,
            log_id=data.get('log_id'),
            date=data.get('date'),
            timestamp=data.get('timestamp')
        )
        
        return jsonify({
            'success': True,
            'message': 'Audit entry created successfully',
            'data': result
        }), 201
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/activity/<user_id>', methods=['GET'])
@require_auth
def get_activity_log_by_user(user_id):
    """Get all audit trail entries for a specific user"""
    try:
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 10, type=int)
        
        # Get all audit entries for user
        entries = blockchain.get_user_audit_entries(user_id)
        
        # Sort by timestamp (newest first)
        entries.sort(key=lambda x: int(x['timestamp']) if x['timestamp'].isdigit() else 0, reverse=True)
        
        # Apply pagination
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        paginated_entries = entries[start_idx:end_idx]
        
        return jsonify({
            'success': True,
            'data': {
                'user_id': user_id,
                'total_entries': len(entries),
                'page': page,
                'limit': limit,
                'entries': paginated_entries
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/audit/<log_id>', methods=['GET'])
@require_auth
def get_audit_entry(log_id):
    """Get a specific audit entry by LogID"""
    try:
        entry = blockchain.get_audit_entry(log_id)
        
        if not entry:
            return jsonify({
                'success': False,
                'error': 'Audit entry not found'
            }), 404
        
        return jsonify({
            'success': True,
            'data': entry
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/activity/by-activity/<activity_name>', methods=['GET'])
@require_auth
def get_audit_entries_by_activity(activity_name):
    """Get all audit entries for a specific activity"""
    try:
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 10, type=int)
        
        # Get all audit entries for activity
        entries = blockchain.get_audit_entries_by_activity(activity_name)
        
        # Sort by timestamp (newest first)
        entries.sort(key=lambda x: int(x['timestamp']) if x['timestamp'].isdigit() else 0, reverse=True)
        
        # Apply pagination
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        paginated_entries = entries[start_idx:end_idx]
        
        return jsonify({
            'success': True,
            'data': {
                'activity_name': activity_name,
                'total_entries': len(entries),
                'page': page,
                'limit': limit,
                'entries': paginated_entries
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Check if the service is running and blockchain is connected"""
    try:
        is_connected = blockchain.w3.is_connected()
        latest_block = blockchain.w3.eth.block_number if is_connected else None
        total_entries = blockchain.contract.functions.getTotalAuditEntries().call() if blockchain.contract else 0
        
        return jsonify({
            'success': True,
            'blockchain_connected': is_connected,
            'latest_block': latest_block,
            'contract_address': CONTRACT_ADDRESS,
            'network': 'Hardhat Local',
            'total_audit_entries': total_entries
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Example usage endpoints
@app.route('/api/example/login', methods=['POST'])
@require_auth
def example_login():
    """Example: Log a user login event"""
    try:
        data = request.get_json() or {}
        user_id = data.get('user_id', request.user_id)
        cred_id = data.get('cred_id', '')
        
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        
        result = blockchain.add_audit_entry(
            user_id=user_id,
            cred_id=cred_id,
            activity_name="LOGIN",
            ip_address=client_ip
        )
        
        return jsonify({
            'success': True,
            'message': 'Login event logged',
            'data': result
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/example/logout', methods=['POST'])
@require_auth
def example_logout():
    """Example: Log a user logout event"""
    try:
        data = request.get_json() or {}
        user_id = data.get('user_id', request.user_id)
        cred_id = data.get('cred_id', '')
        
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        
        result = blockchain.add_audit_entry(
            user_id=user_id,
            cred_id=cred_id,
            activity_name="LOGOUT",
            ip_address=client_ip
        )
        
        return jsonify({
            'success': True,
            'message': 'Logout event logged',
            'data': result
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    print("🚀 Starting Flask Audit Trail API...")
    print(f"Blockchain URL: {HARDHAT_URL}")
    print(f"Contract Address: {CONTRACT_ADDRESS}")
    
    if CONTRACT_ADDRESS == "YOUR_CONTRACT_ADDRESS_HERE":
        print("⚠️  Warning: Please update CONTRACT_ADDRESS after deploying the smart contract")
    
    app.run(debug=True, host='0.0.0.0', port=5000)