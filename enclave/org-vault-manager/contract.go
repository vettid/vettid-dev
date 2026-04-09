package main

import (
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
)

// ContractManager manages the org vault's access contract.
// The contract defines roles and their permissions for accessing credentials.
type ContractManager struct {
	ownerSpace string
	storage    *EncryptedStorage
}

// NewContractManager creates a new contract manager.
func NewContractManager(ownerSpace string, storage *EncryptedStorage) *ContractManager {
	return &ContractManager{
		ownerSpace: ownerSpace,
		storage:    storage,
	}
}

// GetContract retrieves the current contract.
func (cm *ContractManager) GetContract() (*OrgVaultContract, error) {
	var contract OrgVaultContract
	if err := cm.storage.GetJSON(KeyContractCurrent, &contract); err != nil {
		return nil, err
	}
	return &contract, nil
}

// GetRoleDefinition looks up a role in the current contract.
func (cm *ContractManager) GetRoleDefinition(role string) (*RoleDefinition, error) {
	contract, err := cm.GetContract()
	if err != nil {
		// No contract = no restrictions (for initial setup / demo)
		return nil, nil
	}

	for _, rd := range contract.Roles {
		if rd.Role == role {
			return &rd, nil
		}
	}
	return nil, nil
}

// --- Message Handlers ---

// HandleGetContract returns the current contract.
func (cm *ContractManager) HandleGetContract(msg *IncomingMessage) (*OutgoingMessage, error) {
	contract, err := cm.GetContract()
	if err != nil {
		return successResponse(msg.GetID(), map[string]interface{}{
			"success":  true,
			"contract": nil,
			"message":  "no contract configured",
		})
	}

	return successResponse(msg.GetID(), map[string]interface{}{
		"success":  true,
		"contract": contract,
	})
}

// HandleUpdateContract updates the access contract.
func (cm *ContractManager) HandleUpdateContract(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		Roles []RoleDefinition `json:"roles"`
	}

	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error())
	}

	if len(req.Roles) == 0 {
		return errorResponse(msg.GetID(), "at least one role is required")
	}

	// Get current version
	version := 1
	existing, err := cm.GetContract()
	if err == nil && existing != nil {
		version = existing.Version + 1
	}

	now := time.Now()
	contract := &OrgVaultContract{
		ContractID: generateID(),
		OrgVaultID: cm.ownerSpace,
		Version:    version,
		Roles:      req.Roles,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := cm.storage.PutJSON(KeyContractCurrent, contract); err != nil {
		return errorResponse(msg.GetID(), "failed to store contract: "+err.Error())
	}

	log.Info().
		Int("version", version).
		Int("roles", len(req.Roles)).
		Msg("Contract updated")

	return successResponse(msg.GetID(), map[string]interface{}{
		"success":     true,
		"contract_id": contract.ContractID,
		"version":     version,
	})
}
