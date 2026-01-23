package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// ContractManager manages the service's data contract.
// The contract defines what data the service can request and what permissions it has.
// When the contract is updated, all connected users are notified.
type ContractManager struct {
	ownerSpace string
	storage    *EncryptedStorage
	sendFn     func(msg *OutgoingMessage) error
}

// NewContractManager creates a new contract manager
func NewContractManager(
	ownerSpace string,
	storage *EncryptedStorage,
	sendFn func(msg *OutgoingMessage) error,
) *ContractManager {
	return &ContractManager{
		ownerSpace: ownerSpace,
		storage:    storage,
		sendFn:     sendFn,
	}
}

// --- Request/Response Types ---

// GetContractRequest is the payload for contract.get
type GetContractRequest struct{}

// GetContractResponse is the response for contract.get
type GetContractResponse struct {
	Contract *ServiceDataContract `json:"contract,omitempty"`
	Message  string               `json:"message,omitempty"`
}

// UpdateContractRequest is the payload for contract.update
type UpdateContractRequest struct {
	Title           string      `json:"title"`
	Description     string      `json:"description"`
	TermsURL        string      `json:"terms_url,omitempty"`
	PrivacyURL      string      `json:"privacy_url,omitempty"`
	RequiredFields  []FieldSpec `json:"required_fields,omitempty"`
	OptionalFields  []FieldSpec `json:"optional_fields,omitempty"`
	OnDemandFields  []string    `json:"on_demand_fields,omitempty"`
	ConsentFields   []string    `json:"consent_fields,omitempty"`
	CanStoreData    bool        `json:"can_store_data"`
	StorageCategories []string  `json:"storage_categories,omitempty"`
	CanSendMessages    bool     `json:"can_send_messages"`
	CanRequestAuth     bool     `json:"can_request_auth"`
	CanRequestPayment  bool     `json:"can_request_payment"`
	CanRequestVoiceCall bool    `json:"can_request_voice_call"`
	CanRequestVideoCall bool    `json:"can_request_video_call"`
	MaxRequestsPerHour int      `json:"max_requests_per_hour,omitempty"`
	MaxNotificationsPerHour int `json:"max_notifications_per_hour,omitempty"`
	MaxStorageMB       int      `json:"max_storage_mb,omitempty"`
	ExpiresAt   *time.Time      `json:"expires_at,omitempty"`
}

// UpdateContractResponse is the response for contract.update
type UpdateContractResponse struct {
	Success         bool   `json:"success"`
	ContractID      string `json:"contract_id"`
	Version         int    `json:"version"`
	UsersNotified   int    `json:"users_notified"`
	Message         string `json:"message,omitempty"`
}

// GetHistoryRequest is the payload for contract.history
type GetHistoryRequest struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// GetHistoryResponse is the response for contract.history
type GetHistoryResponse struct {
	Versions []ContractVersion `json:"versions"`
	Total    int               `json:"total"`
}

// --- Handlers ---

// HandleGetContract returns the current contract
func (cm *ContractManager) HandleGetContract(msg *IncomingMessage) (*OutgoingMessage, error) {
	contract, err := cm.GetCurrentContract()
	if err != nil {
		return cm.errorResponse(msg.GetID(), "failed to get contract")
	}

	if contract == nil {
		return cm.successResponse(msg.GetID(), GetContractResponse{
			Message: "No contract published yet",
		})
	}

	return cm.successResponse(msg.GetID(), GetContractResponse{
		Contract: contract,
	})
}

// HandleUpdateContract publishes a new version of the contract
func (cm *ContractManager) HandleUpdateContract(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req UpdateContractRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return cm.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Get current contract to determine new version
	currentContract, _ := cm.GetCurrentContract()
	newVersion := 1
	if currentContract != nil {
		newVersion = currentContract.Version + 1

		// Archive current contract to history
		if err := cm.archiveContract(currentContract); err != nil {
			log.Warn().Err(err).Msg("Failed to archive current contract")
		}
	}

	// Create new contract
	contract := &ServiceDataContract{
		ContractID:      generateID(),
		ServiceGUID:     cm.ownerSpace,
		Version:         newVersion,
		Title:           req.Title,
		Description:     req.Description,
		TermsURL:        req.TermsURL,
		PrivacyURL:      req.PrivacyURL,
		RequiredFields:  req.RequiredFields,
		OptionalFields:  req.OptionalFields,
		OnDemandFields:  req.OnDemandFields,
		ConsentFields:   req.ConsentFields,
		CanStoreData:    req.CanStoreData,
		StorageCategories: req.StorageCategories,
		CanSendMessages:    req.CanSendMessages,
		CanRequestAuth:     req.CanRequestAuth,
		CanRequestPayment:  req.CanRequestPayment,
		CanRequestVoiceCall: req.CanRequestVoiceCall,
		CanRequestVideoCall: req.CanRequestVideoCall,
		MaxRequestsPerHour: req.MaxRequestsPerHour,
		MaxNotificationsPerHour: req.MaxNotificationsPerHour,
		MaxStorageMB:       req.MaxStorageMB,
		CreatedAt:          time.Now(),
		ExpiresAt:          req.ExpiresAt,
	}

	// Store as current contract
	if err := cm.storage.PutJSON(KeyContractCurrent, contract); err != nil {
		return cm.errorResponse(msg.GetID(), "failed to store contract")
	}

	// Notify all connected users
	usersNotified := cm.notifyUsersOfContractUpdate(contract)

	log.Info().
		Str("contract_id", contract.ContractID).
		Int("version", contract.Version).
		Int("users_notified", usersNotified).
		Msg("Contract updated")

	return cm.successResponse(msg.GetID(), UpdateContractResponse{
		Success:       true,
		ContractID:    contract.ContractID,
		Version:       contract.Version,
		UsersNotified: usersNotified,
		Message:       "Contract published successfully",
	})
}

// HandleGetHistory returns contract version history
func (cm *ContractManager) HandleGetHistory(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetHistoryRequest
	if msg.Payload != nil {
		if err := json.Unmarshal(msg.Payload, &req); err != nil {
			return cm.errorResponse(msg.GetID(), "invalid request payload")
		}
	}

	// Set defaults
	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 20
	}

	// List history keys
	historyKeys, err := cm.storage.List(KeyContractHistoryPrefix)
	if err != nil {
		return cm.errorResponse(msg.GetID(), "failed to list history")
	}

	var versions []ContractVersion
	for _, key := range historyKeys {
		var cv ContractVersion
		if err := cm.storage.GetJSON(key, &cv); err != nil {
			continue
		}
		versions = append(versions, cv)
	}

	// Add current contract if exists
	current, _ := cm.GetCurrentContract()
	if current != nil {
		versions = append([]ContractVersion{{
			Version:     current.Version,
			Contract:    *current,
			PublishedAt: current.CreatedAt,
		}}, versions...)
	}

	// Apply pagination
	total := len(versions)
	start := req.Offset
	end := start + req.Limit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	versions = versions[start:end]

	return cm.successResponse(msg.GetID(), GetHistoryResponse{
		Versions: versions,
		Total:    total,
	})
}

// --- Public Methods ---

// GetCurrentContract returns the current active contract
func (cm *ContractManager) GetCurrentContract() (*ServiceDataContract, error) {
	data, err := cm.storage.Get(KeyContractCurrent)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}

	var contract ServiceDataContract
	if err := json.Unmarshal(data, &contract); err != nil {
		return nil, err
	}
	return &contract, nil
}

// ValidateFieldsForRequest checks if requested fields are allowed by the contract
func (cm *ContractManager) ValidateFieldsForRequest(fields []string, contract *ServiceDataContract) error {
	// Build set of allowed fields
	allowedFields := make(map[string]bool)

	// Required fields are always allowed
	for _, f := range contract.RequiredFields {
		allowedFields[f.Field] = true
	}
	// Optional fields are allowed
	for _, f := range contract.OptionalFields {
		allowedFields[f.Field] = true
	}
	// On-demand fields are allowed
	for _, f := range contract.OnDemandFields {
		allowedFields[f] = true
	}

	// Check requested fields
	for _, field := range fields {
		if !allowedFields[field] {
			// Check if it's a consent field (requires separate consent request)
			isConsentField := false
			for _, cf := range contract.ConsentFields {
				if cf == field {
					isConsentField = true
					break
				}
			}
			if isConsentField {
				return fmt.Errorf("field %s requires explicit consent request", field)
			}
			return fmt.Errorf("field %s not allowed by contract", field)
		}
	}

	return nil
}

// EnforceContract validates a request against the contract
// This is called before sending any request to a user
func (cm *ContractManager) EnforceContract(requestType string, contract *ServiceDataContract) error {
	switch requestType {
	case "auth":
		if !contract.CanRequestAuth {
			return fmt.Errorf("contract does not allow auth requests")
		}
	case "payment":
		if !contract.CanRequestPayment {
			return fmt.Errorf("contract does not allow payment requests")
		}
	case "voice_call":
		if !contract.CanRequestVoiceCall {
			return fmt.Errorf("contract does not allow voice calls")
		}
	case "video_call":
		if !contract.CanRequestVideoCall {
			return fmt.Errorf("contract does not allow video calls")
		}
	case "message":
		if !contract.CanSendMessages {
			return fmt.Errorf("contract does not allow messages")
		}
	case "store":
		if !contract.CanStoreData {
			return fmt.Errorf("contract does not allow data storage")
		}
	}
	return nil
}

// --- Helper Methods ---

func (cm *ContractManager) archiveContract(contract *ServiceDataContract) error {
	now := time.Now()
	cv := ContractVersion{
		Version:      contract.Version,
		Contract:     *contract,
		PublishedAt:  contract.CreatedAt,
		SupersededAt: &now,
	}

	key := fmt.Sprintf("%s%d", KeyContractHistoryPrefix, contract.Version)
	return cm.storage.PutJSON(key, cv)
}

func (cm *ContractManager) notifyUsersOfContractUpdate(contract *ServiceDataContract) int {
	// Get all connections
	connIDs, err := cm.storage.GetIndex(KeyConnectionIndex)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get connection index")
		return 0
	}

	notified := 0
	for _, connID := range connIDs {
		var conn UserConnectionRecord
		connKey := KeyConnectionPrefix + connID
		if err := cm.storage.GetJSON(connKey, &conn); err != nil {
			continue
		}

		// Only notify active connections
		if conn.Status != "active" {
			continue
		}

		// Send update notification
		payload := map[string]interface{}{
			"type":            "contract_update",
			"service_id":      cm.ownerSpace,
			"new_version":     contract.Version,
			"current_version": conn.ContractVersion,
			"title":           contract.Title,
			"description":     contract.Description,
			"requires_action": true, // User must accept or reject
		}
		data, _ := json.Marshal(payload)

		msg := &OutgoingMessage{
			Type:    MessageTypeNATSPublish,
			Subject: fmt.Sprintf("OwnerSpace.%s.fromService.%s.contract.update", conn.UserGUID, cm.ownerSpace),
			Payload: data,
		}

		if err := cm.sendFn(msg); err != nil {
			log.Warn().Err(err).Str("user_guid", conn.UserGUID).Msg("Failed to notify user of contract update")
			continue
		}
		notified++
	}

	return notified
}

func (cm *ContractManager) errorResponse(requestID, message string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshal(map[string]interface{}{"success": false, "error": message}),
	}, nil
}

func (cm *ContractManager) successResponse(requestID string, payload interface{}) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshal(payload),
	}, nil
}
