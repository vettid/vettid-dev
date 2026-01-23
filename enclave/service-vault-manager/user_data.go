package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// UserDataHandler handles storing data in a user's sandbox.
// Services can store data in the user's vault under their namespace.
// The user can view/delete this data at any time.
type UserDataHandler struct {
	ownerSpace         string
	storage            *EncryptedStorage
	sendFn             func(msg *OutgoingMessage) error
	connectionsHandler *UserConnectionsHandler
	contractManager    *ContractManager
}

// NewUserDataHandler creates a new user data handler
func NewUserDataHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	sendFn func(msg *OutgoingMessage) error,
	connectionsHandler *UserConnectionsHandler,
	contractManager *ContractManager,
) *UserDataHandler {
	return &UserDataHandler{
		ownerSpace:         ownerSpace,
		storage:            storage,
		sendFn:             sendFn,
		connectionsHandler: connectionsHandler,
		contractManager:    contractManager,
	}
}

// --- Request/Response Types ---

// StoreDataRequest is the payload for user.data.store
type StoreDataRequest struct {
	ConnectionID string          `json:"connection_id"`
	Category     string          `json:"category"`     // Must be in contract's storage_categories
	Key          string          `json:"key"`          // Unique key within category
	Data         json.RawMessage `json:"data"`         // Data to store
	Encrypted    bool            `json:"encrypted"`    // Whether data is E2E encrypted
}

// StoreDataResponse is the response for user.data.store
type StoreDataResponse struct {
	Success  bool   `json:"success"`
	DataID   string `json:"data_id"`
	Message  string `json:"message,omitempty"`
}

// DeleteDataRequest is the payload for user.data.delete
type DeleteDataRequest struct {
	ConnectionID string `json:"connection_id"`
	Category     string `json:"category"`
	Key          string `json:"key"`
}

// DeleteDataResponse is the response for user.data.delete
type DeleteDataResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// --- Handlers ---

// HandleStoreData stores data in a user's sandbox via their vault
func (h *UserDataHandler) HandleStoreData(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req StoreDataRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Get connection
	conn, err := h.connectionsHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "connection not found")
	}
	if conn.Status != "active" {
		return h.errorResponse(msg.GetID(), "connection is not active")
	}

	// Validate against contract
	contract, err := h.contractManager.GetCurrentContract()
	if err != nil || contract == nil {
		return h.errorResponse(msg.GetID(), "no active contract")
	}

	if !contract.CanStoreData {
		return h.errorResponse(msg.GetID(), "contract does not allow data storage")
	}

	// Validate category is allowed
	categoryAllowed := false
	for _, cat := range contract.StorageCategories {
		if cat == req.Category {
			categoryAllowed = true
			break
		}
	}
	if !categoryAllowed {
		return h.errorResponse(msg.GetID(), fmt.Sprintf("category %s not allowed by contract", req.Category))
	}

	// Generate data ID
	dataID := generateID()

	// Send store request to user's vault
	payload := map[string]interface{}{
		"data_id":    dataID,
		"service_id": h.ownerSpace,
		"category":   req.Category,
		"key":        req.Key,
		"data":       req.Data,
		"encrypted":  req.Encrypted,
		"stored_at":  time.Now(),
	}

	if err := h.sendToUser(conn.UserGUID, "data.store", payload); err != nil {
		return h.errorResponse(msg.GetID(), "failed to send store request to user")
	}

	// Update connection activity
	h.connectionsHandler.UpdateLastActivity(req.ConnectionID)

	log.Info().
		Str("data_id", dataID).
		Str("user_guid", conn.UserGUID).
		Str("category", req.Category).
		Str("key", req.Key).
		Msg("Data store request sent to user vault")

	return h.successResponse(msg.GetID(), StoreDataResponse{
		Success: true,
		DataID:  dataID,
		Message: "Data store request sent",
	})
}

// HandleDeleteData deletes data from a user's sandbox
func (h *UserDataHandler) HandleDeleteData(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req DeleteDataRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Get connection
	conn, err := h.connectionsHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "connection not found")
	}
	if conn.Status != "active" {
		return h.errorResponse(msg.GetID(), "connection is not active")
	}

	// Send delete request to user's vault
	payload := map[string]interface{}{
		"service_id": h.ownerSpace,
		"category":   req.Category,
		"key":        req.Key,
	}

	if err := h.sendToUser(conn.UserGUID, "data.delete", payload); err != nil {
		return h.errorResponse(msg.GetID(), "failed to send delete request to user")
	}

	// Update connection activity
	h.connectionsHandler.UpdateLastActivity(req.ConnectionID)

	log.Info().
		Str("user_guid", conn.UserGUID).
		Str("category", req.Category).
		Str("key", req.Key).
		Msg("Data delete request sent to user vault")

	return h.successResponse(msg.GetID(), DeleteDataResponse{
		Success: true,
		Message: "Data delete request sent",
	})
}

// --- Helper Methods ---

func (h *UserDataHandler) sendToUser(userGUID, operation string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	msg := &OutgoingMessage{
		Type:    MessageTypeNATSPublish,
		Subject: fmt.Sprintf("OwnerSpace.%s.fromService.%s.%s", userGUID, h.ownerSpace, operation),
		Payload: data,
	}

	return h.sendFn(msg)
}

func (h *UserDataHandler) errorResponse(requestID, message string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshal(map[string]interface{}{"success": false, "error": message}),
	}, nil
}

func (h *UserDataHandler) successResponse(requestID string, payload interface{}) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshal(payload),
	}, nil
}
