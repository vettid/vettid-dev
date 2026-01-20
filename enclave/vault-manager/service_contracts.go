package main

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// ServiceContractsHandler handles contract management for service connections.
// Contracts define what data services can access and what permissions they have.
// Key principles:
// - User controls contracts (can reject updates which terminates connection)
// - Clean break on rejection (service loses all access)
// - Contract enforcement on every data request
type ServiceContractsHandler struct {
	ownerSpace        string
	storage           *EncryptedStorage
	eventHandler      *EventHandler
	connectionHandler *ServiceConnectionHandler
	profileHandler    *ProfileHandler
}

// NewServiceContractsHandler creates a new service contracts handler
func NewServiceContractsHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	eventHandler *EventHandler,
	connectionHandler *ServiceConnectionHandler,
	profileHandler *ProfileHandler,
) *ServiceContractsHandler {
	return &ServiceContractsHandler{
		ownerSpace:        ownerSpace,
		storage:           storage,
		eventHandler:      eventHandler,
		connectionHandler: connectionHandler,
		profileHandler:    profileHandler,
	}
}

// --- Request/Response Types ---

// GetContractRequest is the payload for service.contract.get
type GetContractRequest struct {
	ConnectionID string `json:"connection_id"`
}

// GetContractResponse is the response for service.contract.get
type GetContractResponse struct {
	Contract             ServiceDataContract `json:"contract"`
	AcceptedAt           time.Time           `json:"accepted_at"`
	PendingUpdate        *ContractUpdate     `json:"pending_update,omitempty"`
	RequiredFieldsStatus []FieldStatus       `json:"required_fields_status"`
}

// FieldStatus shows if a required field exists in user's profile
type FieldStatus struct {
	Field     string `json:"field"`
	Available bool   `json:"available"`
	Purpose   string `json:"purpose"`
}

// AcceptContractUpdateRequest is the payload for service.contract.accept
type AcceptContractUpdateRequest struct {
	ConnectionID string `json:"connection_id"`
	Version      int    `json:"version"` // Version to accept
}

// AcceptContractUpdateResponse is the response for service.contract.accept
type AcceptContractUpdateResponse struct {
	Success         bool      `json:"success"`
	ContractVersion int       `json:"contract_version"`
	AcceptedAt      time.Time `json:"accepted_at"`
	Message         string    `json:"message,omitempty"`
}

// RejectContractUpdateRequest is the payload for service.contract.reject
type RejectContractUpdateRequest struct {
	ConnectionID string `json:"connection_id"`
	Version      int    `json:"version"` // Version being rejected
	Reason       string `json:"reason,omitempty"`
}

// RejectContractUpdateResponse is the response for service.contract.reject
type RejectContractUpdateResponse struct {
	Success           bool   `json:"success"`
	ConnectionRevoked bool   `json:"connection_revoked"`
	Message           string `json:"message"`
}

// ContractHistoryRequest is the payload for service.contract.history
type ContractHistoryRequest struct {
	ConnectionID string `json:"connection_id"`
}

// ContractHistoryEntry represents a historical contract version
type ContractHistoryEntry struct {
	Version    int                 `json:"version"`
	Contract   ServiceDataContract `json:"contract"`
	AcceptedAt time.Time           `json:"accepted_at"`
	Status     string              `json:"status"` // "accepted", "rejected", "superseded"
}

// ContractHistoryResponse is the response for service.contract.history
type ContractHistoryResponse struct {
	History        []ContractHistoryEntry `json:"history"`
	CurrentVersion int                    `json:"current_version"`
}

// NotifyContractUpdateRequest is sent by services when they update contracts
type NotifyContractUpdateRequest struct {
	ConnectionID    string          `json:"connection_id"`
	ServiceGUID     string          `json:"service_guid"`
	PreviousVersion int             `json:"previous_version"`
	NewVersion      int             `json:"new_version"`
	NewContract     ServiceDataContract `json:"new_contract"`
	Changes         ContractChanges `json:"changes"`
	Reason          string          `json:"reason"`
	RequiredBy      *time.Time      `json:"required_by,omitempty"`
}

// --- Handler Methods ---

func (h *ServiceContractsHandler) errorResponse(requestID, message string) (*OutgoingMessage, error) {
	resp := map[string]interface{}{
		"success": false,
		"error":   message,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGetContract handles service.contract.get
// Returns the current contract for a connection with field availability status
func (h *ServiceContractsHandler) HandleGetContract(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetContractRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	// Get the connection record
	conn, err := h.connectionHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	if conn.Status == "revoked" {
		return h.errorResponse(msg.GetID(), "Connection has been revoked")
	}

	// Get contract from the service profile
	contract := conn.ServiceProfile.CurrentContract

	// Check required field availability
	fieldStatus := h.checkFieldsAvailability(contract.RequiredFields)

	// Build pending update if one exists
	var pendingUpdate *ContractUpdate
	if conn.PendingContractVersion != nil {
		// Load the pending contract from storage
		pendingContractData, err := h.storage.Get("service-contracts/" + req.ConnectionID + "/pending")
		if err == nil {
			var pending ContractUpdate
			if json.Unmarshal(pendingContractData, &pending) == nil {
				pendingUpdate = &pending
			}
		}
	}

	resp := GetContractResponse{
		Contract:             contract,
		AcceptedAt:           conn.ContractAcceptedAt,
		PendingUpdate:        pendingUpdate,
		RequiredFieldsStatus: fieldStatus,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleAcceptUpdate handles service.contract.accept
// Accepts a pending contract update
func (h *ServiceContractsHandler) HandleAcceptUpdate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AcceptContractUpdateRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	// Get the connection record
	conn, err := h.connectionHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	if conn.Status == "revoked" {
		return h.errorResponse(msg.GetID(), "Connection has been revoked")
	}

	// Verify there's a pending update
	if conn.PendingContractVersion == nil {
		return h.errorResponse(msg.GetID(), "No pending contract update")
	}

	if *conn.PendingContractVersion != req.Version {
		return h.errorResponse(msg.GetID(), "Version mismatch - expected version "+string(rune(*conn.PendingContractVersion)))
	}

	// Load the pending contract
	pendingContractData, err := h.storage.Get("service-contracts/" + req.ConnectionID + "/pending")
	if err != nil {
		return h.errorResponse(msg.GetID(), "Pending contract not found")
	}

	var pendingUpdate ContractUpdate
	if err := json.Unmarshal(pendingContractData, &pendingUpdate); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read pending contract")
	}

	// Load full contract if stored separately
	newContractData, err := h.storage.Get("service-contracts/" + req.ConnectionID + "/v" + strconv.Itoa(req.Version))
	var newContract ServiceDataContract
	if err == nil {
		json.Unmarshal(newContractData, &newContract)
	} else {
		// Try loading from the connection's service profile (for initial connection)
		newContract = conn.ServiceProfile.CurrentContract
		newContract.Version = req.Version
	}

	// Check required fields for new contract
	fieldStatus := h.checkFieldsAvailability(newContract.RequiredFields)
	missingFields := []string{}
	for _, fs := range fieldStatus {
		if !fs.Available {
			missingFields = append(missingFields, fs.Field)
		}
	}

	if len(missingFields) > 0 {
		return h.errorResponse(msg.GetID(), "Missing required fields: cannot accept contract")
	}

	// Archive current contract
	currentVersion := conn.ContractVersion
	archiveEntry := ContractHistoryEntry{
		Version:    currentVersion,
		Contract:   conn.ServiceProfile.CurrentContract,
		AcceptedAt: conn.ContractAcceptedAt,
		Status:     "superseded",
	}
	archiveData, _ := json.Marshal(archiveEntry)
	h.storage.Put("service-contracts/"+req.ConnectionID+"/history/v"+strconv.Itoa(currentVersion), archiveData)

	// Update connection with new contract
	now := time.Now()
	conn.ContractVersion = req.Version
	conn.ContractAcceptedAt = now
	conn.PendingContractVersion = nil
	conn.ServiceProfile.CurrentContract = newContract

	// Save updated connection
	connData, _ := json.Marshal(conn)
	if err := h.storage.Put("service-connections/"+req.ConnectionID, connData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update connection")
	}

	// Clean up pending contract
	h.storage.Delete("service-contracts/" + req.ConnectionID + "/pending")

	// Log event
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(
			context.Background(),
			EventTypeServiceContractAccepted,
			req.ConnectionID,
			conn.ServiceGUID,
			"Contract updated to version "+strconv.Itoa(req.Version),
		)
	}

	log.Info().
		Str("connection_id", req.ConnectionID).
		Int("new_version", req.Version).
		Msg("Contract update accepted")

	resp := AcceptContractUpdateResponse{
		Success:         true,
		ContractVersion: req.Version,
		AcceptedAt:      now,
		Message:         "Contract updated successfully",
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRejectUpdate handles service.contract.reject
// Rejecting a contract update terminates the connection (clean break)
func (h *ServiceContractsHandler) HandleRejectUpdate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req RejectContractUpdateRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	// Get the connection record
	conn, err := h.connectionHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	if conn.Status == "revoked" {
		return h.errorResponse(msg.GetID(), "Connection already revoked")
	}

	// Verify there's a pending update to reject
	if conn.PendingContractVersion == nil {
		return h.errorResponse(msg.GetID(), "No pending contract update to reject")
	}

	if *conn.PendingContractVersion != req.Version {
		return h.errorResponse(msg.GetID(), "Version mismatch")
	}

	// Archive rejection
	rejectionEntry := ContractHistoryEntry{
		Version:    req.Version,
		Contract:   ServiceDataContract{Version: req.Version}, // Minimal info
		AcceptedAt: time.Now(),
		Status:     "rejected",
	}
	rejectionData, _ := json.Marshal(rejectionEntry)
	h.storage.Put("service-contracts/"+req.ConnectionID+"/history/v"+strconv.Itoa(req.Version), rejectionData)

	// Revoke the connection - clean break
	conn.Status = "revoked"
	conn.PendingContractVersion = nil

	connData, _ := json.Marshal(conn)
	if err := h.storage.Put("service-connections/"+req.ConnectionID, connData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update connection")
	}

	// Remove from active index
	h.connectionHandler.removeFromConnectionIndex(req.ConnectionID)

	// Clean up pending contract
	h.storage.Delete("service-contracts/" + req.ConnectionID + "/pending")

	// Log event
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(
			context.Background(),
			EventTypeServiceContractRejected,
			req.ConnectionID,
			conn.ServiceGUID,
			"Contract v"+strconv.Itoa(req.Version)+" rejected - connection revoked",
		)
	}

	log.Info().
		Str("connection_id", req.ConnectionID).
		Int("rejected_version", req.Version).
		Str("reason", req.Reason).
		Msg("Contract update rejected - connection revoked")

	resp := RejectContractUpdateResponse{
		Success:           true,
		ConnectionRevoked: true,
		Message:           "Contract rejected. Connection has been revoked. You must reconnect to use this service again.",
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleContractHistory handles service.contract.history
// Returns history of contract versions for a connection
func (h *ServiceContractsHandler) HandleContractHistory(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ContractHistoryRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	// Get the connection record
	conn, err := h.connectionHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	// Build history - we look for stored versions
	var history []ContractHistoryEntry

	// Try to load historical versions (v1, v2, v3, etc.)
	for version := 1; version <= conn.ContractVersion+10; version++ {
		historyData, err := h.storage.Get("service-contracts/" + req.ConnectionID + "/history/v" + strconv.Itoa(version))
		if err != nil {
			continue
		}

		var entry ContractHistoryEntry
		if json.Unmarshal(historyData, &entry) == nil {
			history = append(history, entry)
		}
	}

	// Add current contract as the latest entry
	currentEntry := ContractHistoryEntry{
		Version:    conn.ContractVersion,
		Contract:   conn.ServiceProfile.CurrentContract,
		AcceptedAt: conn.ContractAcceptedAt,
		Status:     "accepted",
	}

	// Only add if not already in history
	found := false
	for _, h := range history {
		if h.Version == currentEntry.Version {
			found = true
			break
		}
	}
	if !found {
		history = append(history, currentEntry)
	}

	resp := ContractHistoryResponse{
		History:        history,
		CurrentVersion: conn.ContractVersion,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleContractUpdateNotification handles incoming contract update from service
// This is called when a service publishes a new contract version
func (h *ServiceContractsHandler) HandleContractUpdateNotification(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req NotifyContractUpdateRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid notification format")
	}

	// Get the connection
	conn, err := h.connectionHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	if conn.Status == "revoked" {
		return h.errorResponse(msg.GetID(), "Connection has been revoked")
	}

	// Verify service GUID matches
	if conn.ServiceGUID != req.ServiceGUID {
		return h.errorResponse(msg.GetID(), "Service GUID mismatch")
	}

	// Verify version increment
	if req.NewVersion <= conn.ContractVersion {
		return h.errorResponse(msg.GetID(), "New version must be greater than current version")
	}

	// Store the pending update
	pendingUpdate := ContractUpdate{
		PreviousVersion: req.PreviousVersion,
		NewVersion:      req.NewVersion,
		Changes:         req.Changes,
		Reason:          req.Reason,
		PublishedAt:     time.Now(),
		RequiredBy:      req.RequiredBy,
	}

	pendingData, _ := json.Marshal(pendingUpdate)
	if err := h.storage.Put("service-contracts/"+req.ConnectionID+"/pending", pendingData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store pending update")
	}

	// Store the full new contract
	contractData, _ := json.Marshal(req.NewContract)
	h.storage.Put("service-contracts/"+req.ConnectionID+"/v"+strconv.Itoa(req.NewVersion), contractData)

	// Update connection with pending version
	conn.PendingContractVersion = &req.NewVersion
	connData, _ := json.Marshal(conn)
	h.storage.Put("service-connections/"+req.ConnectionID, connData)

	// Log event and notify user
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(
			context.Background(),
			EventTypeServiceContractUpdatePublished,
			req.ConnectionID,
			req.ServiceGUID,
			conn.ServiceProfile.ServiceName+" published contract update v"+strconv.Itoa(req.NewVersion),
		)
	}

	log.Info().
		Str("connection_id", req.ConnectionID).
		Str("service_guid", req.ServiceGUID).
		Int("new_version", req.NewVersion).
		Msg("Contract update notification received")

	resp := map[string]interface{}{
		"success": true,
		"message": "Contract update notification received",
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// --- Contract Validation and Enforcement ---

// ValidateContract validates a contract structure
func (h *ServiceContractsHandler) ValidateContract(contract *ServiceDataContract) error {
	if contract.ContractID == "" {
		return &ValidationError{Field: "contract_id", Message: "contract_id is required"}
	}
	if contract.ServiceGUID == "" {
		return &ValidationError{Field: "service_guid", Message: "service_guid is required"}
	}
	if contract.Version <= 0 {
		return &ValidationError{Field: "version", Message: "version must be positive"}
	}
	if contract.Title == "" {
		return &ValidationError{Field: "title", Message: "title is required"}
	}

	// Validate field specs have required properties
	for i, field := range contract.RequiredFields {
		if field.Field == "" {
			return &ValidationError{Field: "required_fields", Message: "field name required at index " + strconv.Itoa(i)}
		}
	}

	return nil
}

// ValidationError represents a contract validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Field + ": " + e.Message
}

// CheckRequiredFields checks if user has all required fields for a contract
func (h *ServiceContractsHandler) CheckRequiredFields(contract *ServiceDataContract) (missing []string, err error) {
	fieldStatus := h.checkFieldsAvailability(contract.RequiredFields)
	for _, fs := range fieldStatus {
		if !fs.Available {
			missing = append(missing, fs.Field)
		}
	}
	return missing, nil
}

// EnforceContract validates a field access request against the contract
// Returns true if access is allowed, false otherwise
func (h *ServiceContractsHandler) EnforceContract(connectionID string, requestedFields []string, accessType string) (allowed bool, denied []string, err error) {
	conn, err := h.connectionHandler.GetConnection(connectionID)
	if err != nil {
		return false, nil, err
	}

	if conn.Status != "active" {
		return false, requestedFields, &ValidationError{Field: "connection", Message: "connection is not active"}
	}

	contract := conn.ServiceProfile.CurrentContract

	// Build allowed field set based on access type
	allowedFields := make(map[string]bool)

	// On-demand fields are always accessible
	for _, f := range contract.OnDemandFields {
		allowedFields[f] = true
	}

	// Required fields that were accepted are accessible
	for _, fs := range contract.RequiredFields {
		allowedFields[fs.Field] = true
	}

	// Optional fields that exist are accessible
	for _, fs := range contract.OptionalFields {
		allowedFields[fs.Field] = true
	}

	// Check each requested field
	for _, field := range requestedFields {
		if !allowedFields[field] {
			// Check if it's a consent field
			isConsentField := false
			for _, cf := range contract.ConsentFields {
				if cf == field {
					isConsentField = true
					break
				}
			}
			if isConsentField {
				// Consent fields require per-request approval - mark as denied for now
				denied = append(denied, field)
			} else {
				// Not in contract at all - definitely denied
				denied = append(denied, field)
			}
		}
	}

	return len(denied) == 0, denied, nil
}

// --- Helper Methods ---

// checkFieldsAvailability checks which profile fields the user has
func (h *ServiceContractsHandler) checkFieldsAvailability(fields []FieldSpec) []FieldStatus {
	var status []FieldStatus

	for _, field := range fields {
		// Check if field exists in user's profile
		profileKey := "profile/" + field.Field
		_, err := h.storage.Get(profileKey)

		status = append(status, FieldStatus{
			Field:     field.Field,
			Available: err == nil,
			Purpose:   field.Purpose,
		})
	}

	return status
}

