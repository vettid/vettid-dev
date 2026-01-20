package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// CapabilityHandler handles capability requests between connections.
// Capabilities represent permissions that one vault can request from another.
type CapabilityHandler struct {
	ownerSpace   string
	storage      *EncryptedStorage
	publisher    *VsockPublisher
	eventHandler *EventHandler
}

// NewCapabilityHandler creates a new capability handler
func NewCapabilityHandler(ownerSpace string, storage *EncryptedStorage, publisher *VsockPublisher, eventHandler *EventHandler) *CapabilityHandler {
	return &CapabilityHandler{
		ownerSpace:   ownerSpace,
		storage:      storage,
		publisher:    publisher,
		eventHandler: eventHandler,
	}
}

// --- Storage types ---

// CapabilityRequest represents a stored capability request
type CapabilityRequest struct {
	RequestID      string     `json:"request_id"`
	ConnectionID   string     `json:"connection_id"`
	CapabilityType string     `json:"capability_type"` // "payment", "identity", "document", "credential"
	CredentialID   string     `json:"credential_id,omitempty"`
	Status         string     `json:"status"` // "pending", "approved", "denied", "expired"
	RequestedAt    time.Time  `json:"requested_at"`
	RespondedAt    *time.Time `json:"responded_at,omitempty"`
	ExpiresAt      time.Time  `json:"expires_at"`
	Reason         string     `json:"reason,omitempty"` // Optional reason for request
	DenialReason   string     `json:"denial_reason,omitempty"`
}

// --- Request/Response types ---

// CapabilityRequestPayload is the payload for capability.request
type CapabilityRequestPayload struct {
	ConnectionID   string `json:"connection_id"`
	CapabilityType string `json:"capability_type"`
	CredentialID   string `json:"credential_id,omitempty"`
	Reason         string `json:"reason,omitempty"`
	ExpiresInHours int    `json:"expires_in_hours,omitempty"`
}

// CapabilityRequestResponse is the response for capability.request
type CapabilityRequestResponse struct {
	Success   bool   `json:"success"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	ExpiresAt string `json:"expires_at"`
}

// CapabilityRequestListPayload is the payload for capability.request.list
type CapabilityRequestListPayload struct {
	ConnectionID   string `json:"connection_id,omitempty"`
	Status         string `json:"status,omitempty"`
	CapabilityType string `json:"capability_type,omitempty"`
	Limit          int    `json:"limit,omitempty"`
	Offset         int    `json:"offset,omitempty"`
}

// CapabilityRequestInfo represents a capability request in list response
type CapabilityRequestInfo struct {
	RequestID      string `json:"request_id"`
	ConnectionID   string `json:"connection_id"`
	CapabilityType string `json:"capability_type"`
	CredentialID   string `json:"credential_id,omitempty"`
	Status         string `json:"status"`
	RequestedAt    string `json:"requested_at"`
	RespondedAt    string `json:"responded_at,omitempty"`
	ExpiresAt      string `json:"expires_at"`
	Reason         string `json:"reason,omitempty"`
	DenialReason   string `json:"denial_reason,omitempty"`
}

// CapabilityRequestListResponse is the response for capability.request.list
type CapabilityRequestListResponse struct {
	Requests []CapabilityRequestInfo `json:"requests"`
	Total    int                     `json:"total"`
}

// CapabilityRespondPayload is the payload for capability.respond
type CapabilityRespondPayload struct {
	RequestID    string `json:"request_id"`
	Approved     bool   `json:"approved"`
	DenialReason string `json:"denial_reason,omitempty"`
}

// --- Handler methods ---

// HandleRequest handles capability.request messages
func (h *CapabilityHandler) HandleRequest(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CapabilityRequestPayload
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}
	if req.CapabilityType == "" {
		return h.errorResponse(msg.GetID(), "capability_type is required")
	}

	// Validate capability type
	validTypes := map[string]bool{
		"payment":    true,
		"identity":   true,
		"document":   true,
		"credential": true,
		"messaging":  true,
		"calling":    true,
	}
	if !validTypes[req.CapabilityType] {
		return h.errorResponse(msg.GetID(), "Invalid capability_type")
	}

	// Verify connection exists
	connData, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var connRecord ConnectionRecord
	if err := json.Unmarshal(connData, &connRecord); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	if connRecord.Status != "active" {
		return h.errorResponse(msg.GetID(), "Connection is not active")
	}

	// Set expiration (default 24 hours)
	expiresInHours := req.ExpiresInHours
	if expiresInHours <= 0 {
		expiresInHours = 24
	}

	// Create capability request
	requestID := h.generateRequestID()
	capRequest := CapabilityRequest{
		RequestID:      requestID,
		ConnectionID:   req.ConnectionID,
		CapabilityType: req.CapabilityType,
		CredentialID:   req.CredentialID,
		Status:         "pending",
		RequestedAt:    time.Now(),
		ExpiresAt:      time.Now().Add(time.Duration(expiresInHours) * time.Hour),
		Reason:         req.Reason,
	}

	data, err := json.Marshal(capRequest)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to create request")
	}

	if err := h.storage.Put("capability_requests/"+requestID, data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store request")
	}

	h.addToRequestIndex(requestID)

	// Log event
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(
			context.Background(),
			EventType("capability_requested"),
			req.ConnectionID,
			connRecord.PeerGUID,
			fmt.Sprintf("Capability request: %s", req.CapabilityType),
		)
	}

	log.Info().
		Str("request_id", requestID).
		Str("connection_id", req.ConnectionID).
		Str("capability_type", req.CapabilityType).
		Msg("Capability request created")

	resp := CapabilityRequestResponse{
		Success:   true,
		RequestID: requestID,
		Status:    "pending",
		ExpiresAt: capRequest.ExpiresAt.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRequestList handles capability.request.list messages
func (h *CapabilityHandler) HandleRequestList(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CapabilityRequestListPayload
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		// Allow empty payload
		req = CapabilityRequestListPayload{}
	}

	// Get request index
	indexData, err := h.storage.Get("capability_requests/_index")
	var requestIDs []string
	if err == nil {
		json.Unmarshal(indexData, &requestIDs)
	}

	requests := make([]CapabilityRequestInfo, 0)
	for _, reqID := range requestIDs {
		data, err := h.storage.Get("capability_requests/" + reqID)
		if err != nil {
			continue
		}

		var record CapabilityRequest
		if json.Unmarshal(data, &record) != nil {
			continue
		}

		// Check if expired and update status
		if record.Status == "pending" && time.Now().After(record.ExpiresAt) {
			record.Status = "expired"
			newData, _ := json.Marshal(record)
			h.storage.Put("capability_requests/"+reqID, newData)
		}

		// Apply filters
		if req.ConnectionID != "" && record.ConnectionID != req.ConnectionID {
			continue
		}
		if req.Status != "" && record.Status != req.Status {
			continue
		}
		if req.CapabilityType != "" && record.CapabilityType != req.CapabilityType {
			continue
		}

		info := CapabilityRequestInfo{
			RequestID:      record.RequestID,
			ConnectionID:   record.ConnectionID,
			CapabilityType: record.CapabilityType,
			CredentialID:   record.CredentialID,
			Status:         record.Status,
			RequestedAt:    record.RequestedAt.Format(time.RFC3339),
			ExpiresAt:      record.ExpiresAt.Format(time.RFC3339),
			Reason:         record.Reason,
			DenialReason:   record.DenialReason,
		}

		if record.RespondedAt != nil {
			info.RespondedAt = record.RespondedAt.Format(time.RFC3339)
		}

		requests = append(requests, info)
	}

	// Apply pagination
	total := len(requests)
	if req.Offset > 0 && req.Offset < len(requests) {
		requests = requests[req.Offset:]
	} else if req.Offset >= len(requests) {
		requests = []CapabilityRequestInfo{}
	}
	if req.Limit > 0 && req.Limit < len(requests) {
		requests = requests[:req.Limit]
	}

	resp := CapabilityRequestListResponse{
		Requests: requests,
		Total:    total,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRespond handles capability.respond messages (approve or deny a request)
func (h *CapabilityHandler) HandleRespond(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CapabilityRespondPayload
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.RequestID == "" {
		return h.errorResponse(msg.GetID(), "request_id is required")
	}

	storageKey := "capability_requests/" + req.RequestID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Request not found")
	}

	var capRequest CapabilityRequest
	if err := json.Unmarshal(data, &capRequest); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read request")
	}

	if capRequest.Status != "pending" {
		return h.errorResponse(msg.GetID(), "Request is no longer pending")
	}

	// Check if expired
	if time.Now().After(capRequest.ExpiresAt) {
		capRequest.Status = "expired"
		newData, _ := json.Marshal(capRequest)
		h.storage.Put(storageKey, newData)
		return h.errorResponse(msg.GetID(), "Request has expired")
	}

	// Update status
	now := time.Now()
	capRequest.RespondedAt = &now
	if req.Approved {
		capRequest.Status = "approved"
	} else {
		capRequest.Status = "denied"
		capRequest.DenialReason = req.DenialReason
	}

	newData, _ := json.Marshal(capRequest)
	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update request")
	}

	// Log event
	if h.eventHandler != nil {
		eventType := EventType("capability_approved")
		if !req.Approved {
			eventType = EventType("capability_denied")
		}
		h.eventHandler.LogConnectionEvent(
			context.Background(),
			eventType,
			capRequest.ConnectionID,
			"",
			fmt.Sprintf("Capability %s: %s", capRequest.Status, capRequest.CapabilityType),
		)
	}

	log.Info().
		Str("request_id", req.RequestID).
		Str("status", capRequest.Status).
		Msg("Capability request responded")

	resp := map[string]interface{}{
		"success":    true,
		"request_id": req.RequestID,
		"status":     capRequest.Status,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGet handles capability.get messages
func (h *CapabilityHandler) HandleGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.RequestID == "" {
		return h.errorResponse(msg.GetID(), "request_id is required")
	}

	data, err := h.storage.Get("capability_requests/" + req.RequestID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Request not found")
	}

	var record CapabilityRequest
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read request")
	}

	// Check if expired
	if record.Status == "pending" && time.Now().After(record.ExpiresAt) {
		record.Status = "expired"
		newData, _ := json.Marshal(record)
		h.storage.Put("capability_requests/"+req.RequestID, newData)
	}

	info := CapabilityRequestInfo{
		RequestID:      record.RequestID,
		ConnectionID:   record.ConnectionID,
		CapabilityType: record.CapabilityType,
		CredentialID:   record.CredentialID,
		Status:         record.Status,
		RequestedAt:    record.RequestedAt.Format(time.RFC3339),
		ExpiresAt:      record.ExpiresAt.Format(time.RFC3339),
		Reason:         record.Reason,
		DenialReason:   record.DenialReason,
	}

	if record.RespondedAt != nil {
		info.RespondedAt = record.RespondedAt.Format(time.RFC3339)
	}

	respBytes, _ := json.Marshal(info)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// --- Helper methods ---

func (h *CapabilityHandler) generateRequestID() string {
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	return fmt.Sprintf("capreq-%x", idBytes)
}

func (h *CapabilityHandler) addToRequestIndex(requestID string) {
	var index []string
	indexData, err := h.storage.Get("capability_requests/_index")
	if err == nil {
		json.Unmarshal(indexData, &index)
	}

	for _, id := range index {
		if id == requestID {
			return
		}
	}

	index = append(index, requestID)
	newIndexData, _ := json.Marshal(index)
	h.storage.Put("capability_requests/_index", newIndexData)
}

func (h *CapabilityHandler) errorResponse(id string, message string) (*OutgoingMessage, error) {
	resp := map[string]interface{}{
		"success": false,
		"error":   message,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: id,
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}
