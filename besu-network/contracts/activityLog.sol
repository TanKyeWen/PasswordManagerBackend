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