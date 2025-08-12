from web3 import Web3
from solcx import compile_source, install_solc, set_solc_version
import json
import os
import time

# Install Solidity compiler
try:
    install_solc('0.8.19')
    set_solc_version('0.8.19')
except:
    print("Solidity compiler already installed or installation failed")

# Besu connection
BESU_URL = "http://localhost:8545"
CHAIN_ID = 1337

# Connect to Besu
w3 = Web3(Web3.HTTPProvider(BESU_URL))

def load_account():
    """Load account from file"""
    accounts_dir = "besu-network/accounts"
    if not os.path.exists(accounts_dir):
        print("No accounts found. Please create an account first.")
        return None, None
    
    # Find the first account file
    for filename in os.listdir(accounts_dir):
        if filename.endswith('.json'):
            with open(os.path.join(accounts_dir, filename), 'r') as f:
                account_data = json.load(f)
                return account_data['address'], account_data['private_key']
    
    return None, None

def compile_contract():
    """Compile the ActivityLog contract"""
    
    # Read the Solidity contract from file
    contract_source = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ActivityLogContract {
    // Structure representing an activity log entry
    struct ActivityLog {
        string logID;
        string userID;
        string credID;
        string activityName;
        string date;
        string ip;
        uint256 timestamp;
        bool exists;
    }
    
    // Mapping to store activity logs by ID
    mapping(string => ActivityLog) private activityLogs;
    
    // Mapping to track logs by user (for querying)
    mapping(string => string[]) private userLogs;
    
    // Array to store all log IDs for enumeration
    string[] private allLogIDs;
    
    // Events
    event ActivityLogCreated(string indexed logID, string indexed userID, string activityName);
    event ActivityLogRead(string indexed logID, string indexed userID);
    
    // Generate a simple UUID-like string
    function generateLogID(string memory userID, string memory credID) private view returns (string memory) {
        return string(abi.encodePacked(
            "log_",
            uint2str(block.timestamp),
            "_",
            uint2str(uint(keccak256(abi.encodePacked(userID, credID))) % 10000)
        ));
    }
    
    // Helper function to convert uint to string
    function uint2str(uint _i) private pure returns (string memory) {
        if (_i == 0) {
            return "0";
        }
        uint j = _i;
        uint len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len;
        while (_i != 0) {
            k = k-1;
            uint8 temp = (48 + uint8(_i - _i / 10 * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }
    
    // Create a new activity log entry
    function createActivityLog(
        string memory userID,
        string memory credID,
        string memory activityName,
        string memory date,
        string memory ip
    ) public returns (string memory) {
        // Check if activity log with this credID already exists
        require(!activityLogs[credID].exists, "Activity log with this credID already exists");
        
        // Generate unique log ID
        string memory logID = generateLogID(userID, credID);
        
        // Create the activity log
        ActivityLog memory newLog = ActivityLog({
            logID: logID,
            userID: userID,
            credID: credID,
            activityName: activityName,
            date: date,
            ip: ip,
            timestamp: block.timestamp,
            exists: true
        });
        
        // Store the log
        activityLogs[credID] = newLog;
        userLogs[userID].push(credID);
        allLogIDs.push(credID);
        
        // Emit event
        emit ActivityLogCreated(logID, userID, activityName);
        
        return logID;
    }
    
    // Read an activity log by credID
    function readActivityLog(string memory credID) public view returns (
        string memory logID,
        string memory userID,
        string memory _credID,
        string memory activityName,
        string memory date,
        string memory ip,
        uint256 timestamp
    ) {
        ActivityLog memory log = activityLogs[credID];
        require(log.exists, "Activity log does not exist");
        
        return (
            log.logID,
            log.userID,
            log.credID,
            log.activityName,
            log.date,
            log.ip,
            log.timestamp
        );
    }
    
    // Check if an activity log exists
    function activityLogExists(string memory credID) public view returns (bool) {
        return activityLogs[credID].exists;
    }
    
    // Get all activity log credIDs for a specific user
    function getActivityLogsByUser(string memory userID) public view returns (string[] memory) {
        return userLogs[userID];
    }
    
    // Get activity log details by user (returns arrays)
    function getActivityLogDetailsByUser(string memory userID) public view returns (
        string[] memory logIDs,
        string[] memory credIDs,
        string[] memory activityNames,
        string[] memory dates,
        string[] memory ips,
        uint256[] memory timestamps
    ) {
        string[] memory userCredIDs = userLogs[userID];
        uint256 length = userCredIDs.length;
        
        logIDs = new string[](length);
        credIDs = new string[](length);
        activityNames = new string[](length);
        dates = new string[](length);
        ips = new string[](length);
        timestamps = new uint256[](length);
        
        for (uint256 i = 0; i < length; i++) {
            ActivityLog memory log = activityLogs[userCredIDs[i]];
            logIDs[i] = log.logID;
            credIDs[i] = log.credID;
            activityNames[i] = log.activityName;
            dates[i] = log.date;
            ips[i] = log.ip;
            timestamps[i] = log.timestamp;
        }
    }
    
    // Get total number of logs
    function getTotalLogs() public view returns (uint256) {
        return allLogIDs.length;
    }
}
'''
    
    print("Compiling contract...")
    compiled_sol = compile_source(contract_source)
    contract_interface = compiled_sol['<stdin>:ActivityLogContract']
    
    return contract_interface

def deploy_contract(contract_interface, account_address, private_key):
    """Deploy the compiled contract"""
    
    print("Deploying contract...")
    
    # Get contract
    contract = w3.eth.contract(
        abi=contract_interface['abi'],
        bytecode=contract_interface['bin']
    )
    
    # Build constructor transaction
    constructor_txn = contract.constructor().build_transaction({
        'chainId': CHAIN_ID,
        'gas': 3000000,
        'gasPrice': w3.to_wei('20', 'gwei'),
        'nonce': w3.eth.get_transaction_count(account_address),
    })
    
    # Sign and send transaction
    signed_txn = w3.eth.account.sign_transaction(constructor_txn, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    
    print(f"Deployment transaction sent: {tx_hash.hex()}")
    print("Waiting for transaction receipt...")
    
    # Wait for transaction receipt
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    
    contract_address = tx_receipt.contractAddress
    print(f"Contract deployed successfully!")
    print(f"Contract Address: {contract_address}")
    print(f"Block Number: {tx_receipt.blockNumber}")
    print(f"Gas Used: {tx_receipt.gasUsed}")
    
    # Save contract details
    contract_details = {
        "address": contract_address,
        "abi": contract_interface['abi'],
        "deployment_tx": tx_hash.hex(),
        "block_number": tx_receipt.blockNumber
    }
    
    os.makedirs("besu-network/contracts", exist_ok=True)
    with open("besu-network/contracts/ActivityLogContract.json", 'w') as f:
        json.dump(contract_details, f, indent=2)
    
    print("Contract details saved to: besu-network/contracts/ActivityLogContract.json")
    
    return contract_address

def main():
    # Check connection
    if not w3.is_connected():
        print("Error: Cannot connect to Besu network. Make sure Besu is running.")
        return
    
    print(f"Connected to Besu network (Chain ID: {w3.eth.chain_id})")
    
    # Load account
    account_address, private_key = load_account()
    if not account_address:
        print("Please create an account first using the create_account_script.py")
        return
    
    print(f"Using account: {account_address}")
    
    # Check account balance
    balance = w3.eth.get_balance(account_address)
    print(f"Account balance: {w3.from_wei(balance, 'ether')} ETH")
    
    if balance == 0:
        print("⚠️  Warning: Account has no ETH. You may need to fund it or set up mining.")
    
    # Compile contract
    try:
        contract_interface = compile_contract()
        print("Contract compiled successfully!")
    except Exception as e:
        print(f"Error compiling contract: {e}")
        return
    
    # Deploy contract
    try:
        contract_address = deploy_contract(contract_interface, account_address, private_key)
        
        print("\n=== DEPLOYMENT SUCCESSFUL ===")
        print(f"Contract Address: {contract_address}")
        print(f"Account Address: {account_address}")
        print("=============================")
        
    except Exception as e:
        print(f"Error deploying contract: {e}")
        print("This might be due to insufficient balance or network issues.")

if __name__ == "__main__":
    main()