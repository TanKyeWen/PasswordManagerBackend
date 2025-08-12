package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/google/uuid"
)

// SmartContract provides functions for managing activity logs
type SmartContract struct {
	contractapi.Contract
}

// ActivityLog represents an activity log entry
type ActivityLog struct {
	LogID		 string `json:"log_id`
	UserID       string `json:"user_id"`
	CredID       string `json:"cred_id,omitempty"`
	ActivityName string `json:"activity_name"`
	Date         string `json:"date"`
	IP           string `json:"ip"`
	Timestamp    string `json:"timestamp"`
}

// CreateActivityLog creates a new activity log entry
func (s *SmartContract) CreateActivityLog(ctx contractapi.TransactionContextInterface, userID string, id, activityName string, date string, ip string) error {
	// Check if the activity log already exists
	exists, err := s.ActivityLogExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the activity log %s already exists", id)
	}

	// Create timestamp
	timestamp := time.Now().UTC().Format(time.RFC3339)

	activityLog := ActivityLog{
		LogID:			uuid.New().String(),
		UserID:       userID,
		CredID:           id,
		ActivityName: activityName,
		Date:         date,
		IP:           ip,
		Timestamp:    timestamp,
	}

	activityLogJSON, err := json.Marshal(activityLog)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, activityLogJSON)
}

// ReadActivityLog reads an activity log from the world state
func (s *SmartContract) ReadActivityLog(ctx contractapi.TransactionContextInterface, id string) (*ActivityLog, error) {
	activityLogJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if activityLogJSON == nil {
		return nil, fmt.Errorf("the activity log %s does not exist", id)
	}

	var activityLog ActivityLog
	err = json.Unmarshal(activityLogJSON, &activityLog)
	if err != nil {
		return nil, err
	}

	return &activityLog, nil
}

// ActivityLogExists returns true when activity log with given ID exists in world state
func (s *SmartContract) ActivityLogExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	activityLogJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	return activityLogJSON != nil, nil
}

// GetActivityLogsByUser returns all activity logs for a specific user
func (s *SmartContract) GetActivityLogsByUser(ctx contractapi.TransactionContextInterface, userID string) ([]*ActivityLog, error) {
	queryString := fmt.Sprintf(`{"selector":{"user_id":"%s"}}`, userID)
	return s.getQueryResultForQueryString(ctx, queryString)
}

// Helper function to execute rich queries
func (s *SmartContract) getQueryResultForQueryString(ctx contractapi.TransactionContextInterface, queryString string) ([]*ActivityLog, error) {
	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var activityLogs []*ActivityLog
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var activityLog ActivityLog
		err = json.Unmarshal(queryResponse.Value, &activityLog)
		if err != nil {
			return nil, err
		}
		activityLogs = append(activityLogs, &activityLog)
	}

	return activityLogs, nil
}

func main() {
	activityLogChaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		fmt.Printf("Error creating activity log chaincode: %v", err)
		return
	}

	if err := activityLogChaincode.Start(); err != nil {
		fmt.Printf("Error starting activity log chaincode: %v", err)
	}
}